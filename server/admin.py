#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""私服后台管理界面  https://<你的服务器IP>:38443

安全：高强度随机密码(bcrypt) + 签名会话 + CSRF + 登录失败限流 + 安全响应头 + 审计日志。
功能：管理所有用户(任意字段，含 G币/蓝V) 与 动态(编辑/删除/清空)；新增/删除用户。
数据：全部经 store.py 共享层（flock + 原子写），与 server(HTTP)/agentsrv(WS) 实时一致。
"""
import os, sys, json, time, secrets, hmac, html, re, functools, base64, subprocess
sys.path.insert(0, '/opt/privsrv')
import store
import review
import features as F
from flask import Flask, request, session, redirect, abort, Response
import bcrypt

# ---- 后台时间统一按北京时间(UTC+8)显示：仅影响展示，不改系统时钟、不改落库数据 ----
CN_OFFSET = 8 * 3600

def cn_fmt(epoch, fmt='%F %T'):
    """epoch秒 -> 北京时间字符串"""
    try:
        return time.strftime(fmt, time.localtime(float(epoch) + CN_OFFSET))
    except Exception:
        return str(epoch)

def cn_iso(s):
    """'2026-11-21T10:04:16'(UTC) -> '2026-11-21 18:04:16'(北京时间)"""
    try:
        import datetime as _dt
        d = _dt.datetime.strptime(str(s)[:19], '%Y-%m-%dT%H:%M:%S')
        return (d + _dt.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return s

BASE = '/opt/privsrv'
AUTH_FILE = os.path.join(BASE, 'data', 'admin_auth.json')
AUDIT = os.path.join(BASE, 'logs', 'admin.log')
KICK_FILE = os.path.join(BASE, 'data', 'kick.jsonl')
CERT = os.path.join(BASE, 'certs', 'admin.crt')
KEY = os.path.join(BASE, 'certs', 'admin.key')
PORT = int(os.environ.get('ADMIN_PORT', '38443'))


def h(s):
    return html.escape(str(s), quote=True)


def _load_auth():
    d = json.load(open(AUTH_FILE, encoding='utf8'))
    if not d.get('pw_hash') or not d.get('secret'):
        raise RuntimeError('admin_auth.json 不完整')
    return d


_auth = _load_auth()
app = Flask(__name__)
app.secret_key = _auth['secret']
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

# ---------------- 限流 / 审计 / CSRF ----------------
_fails = {}   # ip -> [fail_count, lock_until]


def _queue_kick(uid, reason=''):
    """下发实时踢线指令：agentsrv 轮询 kick.jsonl 后断开该 uid 所有 WS 连接。"""
    try:
        rec = {'uid': str(uid), 'reason': str(reason or '')[:120],
               'ts': int(time.time() * 1000)}
        with open(KICK_FILE, 'a', encoding='utf8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        return True
    except Exception as e:
        audit('KICK_QUEUE_ERR', repr(e))
        return False


def audit(action, detail=''):
    try:
        ua = (request.headers.get('User-Agent') or '')[:120]
        with open(AUDIT, 'a', encoding='utf8') as f:
            f.write('%s  %s  %s  %s  UA[%s]\n' % (
                time.strftime('%F %T', time.localtime(time.time() + CN_OFFSET)), request.remote_addr, action,
                str(detail).replace('\n', ' ')[:220], ua))
    except Exception:
        pass


def rate_locked(ip):
    c, until = _fails.get(ip, [0, 0])
    return time.time() < until


def rate_fail(ip):
    c, until = _fails.get(ip, [0, 0])
    c += 1
    if c >= 5:
        until, c = time.time() + 900, 0
    _fails[ip] = [c, until]


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']


def csrf_ok():
    return hmac.compare_digest(str(request.form.get('_csrf', '')),
                               str(session.get('csrf', '')))


def origin_ok():
    """同源校验：放行 无Origin / 'null'（手机浏览器、隐私模式常发 null）/ 同源；
    仅拦截明确的外站 Origin。真正的跨站防护仍由 CSRF token 承担。"""
    o = (request.headers.get('Origin') or '').strip()
    if not o or o.lower() in ('null', 'none'):
        return True
    return o.rstrip('/') == request.host_url.rstrip('/')


@app.before_request
def guard():
    ep = request.endpoint or ''
    if ep in ('login', 'static'):
        return
    if not session.get('ok'):
        return redirect('/login')
    if request.method == 'POST':
        if not csrf_ok():
            audit('CSRF_REJECT', request.path)
            abort(403)
        if not origin_ok():
            audit('ORIGIN_REJECT', (request.headers.get('Origin') or '')[:120])
            abort(403)


@app.after_request
def sec_headers(r):
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['Referrer-Policy'] = 'no-referrer'
    r.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
    r.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    r.headers['Pragma'] = 'no-cache'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    r.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
    r.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    r.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    r.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    return r


@app.errorhandler(403)
def e403(e):
    return Response('403 禁止访问（CSRF 校验失败或越权）', status=403, mimetype='text/plain; charset=utf-8')


@app.errorhandler(404)
def e404(e):
    return Response('404 页面不存在', status=404, mimetype='text/plain; charset=utf-8')


@app.errorhandler(500)
def e500(e):
    audit('ERROR', repr(e))
    return Response('500 请求处理失败，请返回重试（详情见审计日志）', status=500,
                    mimetype='text/plain; charset=utf-8')


# ---------------- 页面骨架 ----------------
CSS = """
*{box-sizing:border-box}
:root{
 --bg:#fafbfc; --panel:#ffffff; --ink:#1f2329; --ink2:#5f6672; --ink3:#9098a4;
 --line:#e8eaed; --line2:#f2f3f5; --brand:#2f6fed; --brand-soft:#eef4ff;
 --red:#e5484d; --red-soft:#fdecec; --green:#2fa866; --green-soft:#eaf7f0;
 --amber:#b8860b; --amber-soft:#fbf3dd; --shadow:0 1px 2px rgba(16,24,40,.04),0 4px 16px rgba(16,24,40,.05);
 --r:10px;
}
body{margin:0;background:var(--bg);color:var(--ink);
 font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
 -webkit-font-smoothing:antialiased}
a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
/* ===== 布局骨架：左侧固定侧边栏 + 右侧顶栏/内容区 ===== */
.app{display:flex;min-height:100vh}
.side{width:220px;flex:0 0 220px;background:var(--panel);border-right:1px solid var(--line);
 display:flex;flex-direction:column;position:sticky;top:0;height:100vh;z-index:20}
.side .logo{height:66px;display:flex;align-items:center;gap:10px;padding:0 20px;
 font-size:16px;font-weight:700;color:var(--ink);border-bottom:1px solid var(--line);white-space:nowrap}
.side .logo::before{content:'';width:10px;height:10px;border-radius:3px;background:var(--brand);flex:0 0 auto}
.side nav{flex:1;overflow-y:auto;padding:14px 10px}
.side nav a{display:flex;align-items:center;gap:10px;padding:10px 13px;margin:2px 0;
 border-radius:8px;color:var(--ink2);font-size:13.5px;white-space:nowrap}
.side nav a svg{width:17px;height:17px;flex:0 0 auto;stroke:currentColor;fill:none;
 stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;opacity:.7}
.side nav a:hover{background:var(--line2);color:var(--ink);text-decoration:none}
.side nav a.on{background:var(--brand-soft);color:var(--brand);font-weight:600}
.side nav a.on svg{opacity:1}
.side .foot{padding:12px 20px;border-top:1px solid var(--line);font-size:11px;color:var(--ink3)}
.main{flex:1;min-width:0}
.topbar{height:66px;display:flex;align-items:center;gap:14px;padding:0 26px;
 background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
.topbar .crumb{font-size:13px;color:var(--ink3)}
.topbar .crumb b{color:var(--ink);font-weight:600}
.topbar .sp{flex:1}
.topbar .who{font-size:12px;color:var(--ink3)}
.content{max-width:1240px;margin:0 auto;padding:24px 26px 60px}
h1{font-size:21px;margin:0 0 18px;font-weight:700;letter-spacing:.2px}
h2{font-size:15px;margin:24px 0 12px;color:var(--ink2);font-weight:600}
/* ===== 登录页：整屏居中卡片 ===== */
body.login{display:flex;align-items:center;justify-content:center;min-height:100vh;
 background:radial-gradient(1200px 500px at 50% -10%,#eef4ff 0%,var(--bg) 55%)}
body.login .loginwrap{max-width:420px;width:calc(100% - 32px);margin:0;background:var(--panel);
 border:1px solid var(--line);border-radius:14px;padding:30px 28px;box-shadow:var(--shadow)}
body.login .loginwrap h1{text-align:center;font-size:22px;margin:0 0 8px}
body.login .loginwrap .box{border:0;box-shadow:none;padding:0;margin:0}
body.login .loginwrap .frow{display:block}
body.login .loginwrap .frow label{display:block;width:auto;padding:0 0 6px}
body.login .loginwrap .frow input{width:100%;display:block}
.side nav .navgrp{margin:2px 0}
.side nav .navgrp>summary{display:flex;align-items:center;justify-content:space-between;
 padding:10px 13px;border-radius:8px;color:var(--ink3);font-size:11.5px;font-weight:600;
 letter-spacing:.5px;cursor:pointer;list-style:none;user-select:none;transition:background .15s,color .15s}
.side nav .navgrp>summary::-webkit-details-marker{display:none}
.side nav .navgrp>summary:hover{background:var(--line2);color:var(--ink2)}
.side nav .navgrp .caret{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2.2;
 transition:transform .18s;opacity:.7}
.side nav .navgrp[open]>.caret,.side nav .navgrp[open]>summary .caret{transform:rotate(0deg)}
.side nav .navgrp[open]>summary{color:var(--brand)}
.side nav .navgrp>summary .caret{transform:rotate(-90deg)}
.side nav .navitems{padding:3px 0 6px 0}
.side nav .navitems a{display:flex;align-items:center;gap:10px;padding:8px 13px 8px 18px;margin:1px 0;
 border-radius:8px;color:var(--ink2);font-size:13.5px;white-space:nowrap;text-decoration:none}
.side nav .navitems a svg{width:16px;height:16px;flex:0 0 auto;stroke:currentColor;fill:none;
 stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;opacity:.85}
.side nav .navitems a:hover{background:var(--line2);color:var(--ink);text-decoration:none}
.side nav .navitems a.on{background:var(--brand-soft);color:var(--brand);font-weight:600}
.side nav .navitems a.on svg{opacity:1}
@media(max-width:820px){.side{width:64px;flex-basis:64px}.side .logo{font-size:0;padding:0;justify-content:center}
 .side .logo::before{width:12px;height:12px}.side nav a{justify-content:center;padding:12px 0}
 .side nav a span,.side nav .gname,.side nav .caret{display:none}.side nav a svg{width:20px;height:20px;opacity:1} .side nav .navgrp>summary{justify-content:center;padding:12px 0} .side nav .navitems a{justify-content:center;padding:10px 0}
 .side .foot{display:none}.content{padding:18px 14px 40px}.topbar{padding:0 14px}}

.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;box-shadow:var(--shadow)}
.card b{display:block;font-size:26px;color:var(--brand);margin-top:4px;font-weight:700;line-height:1.15}
.card span{color:var(--ink3);font-size:12px}
table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);
 border-radius:var(--r);overflow:hidden;box-shadow:var(--shadow);font-size:13px}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:13px;vertical-align:top}
th{background:#fafbfc;color:var(--ink2);font-weight:600;white-space:nowrap}
tbody tr:hover td{background:#fbfcff}
tr:last-child td{border-bottom:none}
input,select,textarea{background:#fff;color:var(--ink);border:1px solid var(--line);border-radius:7px;
 padding:8px 10px;font:inherit;max-width:100%;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
input[type=text]{width:100%}
.btn{display:inline-block;background:var(--brand);color:#fff;border:1px solid transparent;border-radius:7px;
 padding:8px 15px;cursor:pointer;font:inherit;margin:2px 5px 2px 0;transition:filter .15s,transform .05s}
.btn:hover{filter:brightness(1.06);text-decoration:none}
.btn:active{transform:translateY(1px)}
.btn.gray{background:#fff;color:var(--ink2);border-color:var(--line)}
.btn.gray:hover{background:var(--line2)}
.btn.red{background:var(--red)}
.btn.green{background:var(--green)}
.btn.sm{padding:5px 10px;font-size:12px}
.btn.bigbtn{padding:13px 28px;font-size:15px}
.dot.on{color:var(--green);font-weight:600}.dot.off{color:var(--red);font-weight:600}
.box{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:20px;
 margin-bottom:18px;box-shadow:var(--shadow)}
.frow{display:flex;gap:12px;align-items:flex-start;margin:9px 0}
.frow label{width:250px;color:var(--ink2);flex-shrink:0;word-break:break-all;line-height:1.45;padding-top:7px}
.frow label b{color:var(--ink);font-weight:600}
.frow input{flex:1}
.fkey{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--ink3)}
.ftip{font-size:11px;color:var(--ink3);font-weight:400}
.grp{font-size:14px;color:var(--ink);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);font-weight:600}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#0b7a52}
.muted{color:var(--ink3);font-size:12px}
.tag{display:inline-block;padding:2px 8px;border-radius:5px;font-size:12px;font-weight:600}.tag.ok{background:var(--green-soft,#eaf7f0);color:#12734a}.tag.off{background:#fdecec;color:#c0392b}.badge{background:var(--amber-soft);color:#8a6500;border:1px solid #f0e0b0;border-radius:5px;
 padding:1px 7px;font-size:11px;font-weight:500}
.talk{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;
 margin-bottom:12px;box-shadow:var(--shadow)}
.talk .t{font-weight:600;color:var(--ink)}.talk .m{color:var(--ink3);font-size:12px;margin:3px 0 9px}
.loginwrap{max-width:400px;margin:9vh auto}
.msg{background:var(--red-soft);border:1px solid #f5cccc;color:#b4232a;padding:11px 14px;border-radius:9px;margin-bottom:14px}
.tip{background:var(--brand-soft);border:1px solid #dbe7ff;color:#2b5bbf;padding:11px 14px;border-radius:9px;
 margin-bottom:16px;font-size:13px}
@media(max-width:760px){.wrap{padding:0 12px 40px}.frow label{width:110px}nav a{padding:5px 8px;font-size:12px}}
"""


# 菜单内联 SVG 图标（ stroke=currentColor，跟随文字高亮变色；无外链、离线可用、符合 CSP）
_IC = {
 'home': '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V20a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9.5"/><path d="M9 21v-6h6v6"/>',
 'users': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
 'talks': '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
 'reviews': '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
 'goods': '<path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><path d="M3 6h18"/><path d="M16 10a4 4 0 0 1-8 0"/>',
 'comments': '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>',
 'reports': '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>',
 'feat': '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
 'works': '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
 'tokens': '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.5 12.5 8-8"/><path d="m15 5 3 3"/><path d="m17.5 2.5 3 3"/>',
 'server': '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
 'sensitive': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
 'loginlog': '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 'online': '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
 'player': '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/><path d="M12 2v2M2 12h2M20 12h2"/>',
}


def ico(key):
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' + _IC.get(key, _IC.get('server', '')) + '</svg>'


# 分组菜单：(板块名, [(key, href, label), ...])
NAV_GROUPS = [
    ('总览', [('home', '/', '概览'), ('online', '/online', '实时在线')]),
    ('用户与审核', [('users', '/users', '用户'), ('player', '/player', '玩家档案'), ('reviews', '/reviews', '头像审核')]),
    ('内容管理', [('talks', '/talks', '动态'), ('works', '/works', '作品'),
               ('goods', '/goods', '商品'), ('comments', '/comments', '评论'),
               ('notice', '/notice', '公告'), ('feat', '/feat', '互动数据')]),
    ('安全与系统', [('reports', '/reports', '举报'), ('sensitive', '/sensitive', '敏感词'),
                ('senshits', '/senshits', '命中看板'),
                ('loginlog', '/loginlog', '登录审计'), ('ipban', '/ipban', 'IP风控'), ('tokens', '/tokens', '会话令牌'),
                ('status', '/status', '服务状态'), ('oplog', '/oplog', '操作审计'),
                ('backup', '/backup', '备份回滚'), ('health', '/health', '数据体检'), ('server', '/server', '服务器')]),
]
NAV = [item for _, items in NAV_GROUPS for item in items]


def page(title, body, nav=''):
    head = ('<!doctype html><html lang="zh"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>' + h(title) + ' - 私服后台</title><style>' + CSS + '</style></head>')
    if not nav:  # 登录/独立页：整屏居中，无侧边栏
        return head + '<body class="login">' + body + '</body></html>'
    groups_html = []
    for gname, items in NAV_GROUPS:
        opened = any(k == nav for k, _, _ in items)
        links = ''.join('<a href="' + href + '" class="' + ('on' if key == nav else '') +
                        '">' + ico(key) + '<span>' + label + '</span></a>'
                        for key, href, label in items)
        groups_html.append(
            '<details class="navgrp"' + (' open' if opened else '') + '>'
            '<summary><span class="gname">' + h(gname) + '</span>'
            '<svg class="caret" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary>'
            '<div class="navitems">' + links + '</div></details>')
    links = ''.join(groups_html)
    return (head + '<body><div class="app">'
            '<aside class="side"><div class="logo">创游私服 · 管理后台</div>'
            '<nav>' + links + '</nav>'
            '<div class="foot">PRIVSRV ADMIN</div></aside>'
            '<div class="main"><div class="topbar">'
            '<div class="crumb">管理后台 / <b>' + h(title) + '</b></div>'
            '<div class="sp"></div><a href="/logout">退出登录</a></div>'
            '<div class="content">' + body + '</div></div></div></body></html>')


def csrf_hidden():
    return '<input type="hidden" name="_csrf" value="' + h(csrf_token()) + '">'


# ---------------- 登录 ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr or '?'
    msg = ''
    if request.method == 'POST':
        if not origin_ok():
            audit('ORIGIN_REJECT_LOGIN', (request.headers.get('Origin') or '')[:120])
            abort(403)
        if rate_locked(ip):
            msg = '失败次数过多，已锁定 15 分钟'
            audit('LOGIN_LOCKED', ip)
        elif not csrf_ok():
            msg = '表单校验失败，请刷新重试'
        else:
            pw = request.form.get('password', '')
            okpw = False
            try:
                okpw = bcrypt.checkpw(pw.encode('utf8'), _auth['pw_hash'].encode('utf8'))
            except Exception:
                okpw = False
            if okpw:
                _fails.pop(ip, None)
                session.clear()
                session['ok'] = True
                session.permanent = True
                session['csrf'] = secrets.token_hex(16)
                audit('LOGIN_OK')
                return redirect('/')
            rate_fail(ip)
            audit('LOGIN_FAIL', ip)
            time.sleep(min(0.5 * (1 + _fails.get(ip, [0, 0])[0]), 2.0))
            msg = '密码错误'
    tok = csrf_token()
    body = ('<div class="loginwrap"><h1>私服管理后台</h1>'
            '<div class="tip">高强度随机密码保护 · 全程 HTTPS · 登录失败 5 次锁定 15 分钟</div>'
            + ('<div class="msg">' + h(msg) + '</div>' if msg else '') +
            '<form method="post" action="/login" class="box">'
            '<input type="hidden" name="_csrf" value="' + h(tok) + '">'
            '<div class="frow"><label>管理密码</label>'
            '<input type="password" name="password" autofocus required style="flex:1"></div>'
            '<div style="margin-top:14px"><button class="btn" type="submit">登 录</button></div>'
            '</form></div>')
    return Response(page('登录', body), mimetype='text/html; charset=utf-8')


@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    return redirect('/login')


# ---------------- 概览 ----------------
@app.route('/')
def index():
    db = store.load_db()
    talks = store.load_talks()
    gm = store.gm_ids()
    cur = store.current_user()
    ft = db.get('feat') if isinstance(db.get('feat'), dict) else {}
    def _n(k):
        v = ft.get(k)
        return len(v) if isinstance(v, (list, dict)) else 0
    _reports = ft.get('reports', []) if isinstance(ft.get('reports'), list) else []
    pending = sum(1 for r in _reports if isinstance(r, dict) and not r.get('status'))
    cards = ('<div class="cards">'
             '<div class="card"><span>用户总数</span><b>' + str(len(db['users'])) + '</b></div>'
             '<div class="card"><span>动态总数</span><b>' + str(len(talks)) + '</b></div>'
             '<div class="card"><span>蓝V认证数</span><b>' + str(len(gm) // 2) + '</b></div>'
             '<div class="card"><span>会话/令牌</span><b>' + str(len(db['tokens'])) + '</b></div>'
             '<div class="card"><span>待审头像</span><b>' +
             str(sum(1 for r in db.get('reviews', []) if r.get('status') == review.INREVIEW)) +
             '</b></div>'
             '<div class="card"><span>商城商品</span><b>' +
             str(len(_seed_goods()) + _n('goods')) + '</b></div>'
             '<div class="card"><span>社区评论</span><b>' + str(_n('comments')) + '</b></div>'
             '<div class="card"><span>待处理举报</span><b>' + str(pending) + '</b></div>'
             '<div class="card"><span>消息通知</span><b>' + str(_n('msgs')) + '</b></div></div>')
    curtxt = (h(cur.get('userName')) + ' (ID ' + h(cur.get('userId')) + ', G币 ' +
              h(cur.get('coin')) + ')') if isinstance(cur, dict) else '（无，等待客户端登录）'
    body = ('<h1>概览</h1>' + cards +
            '<div class="box"><h2 style="margin-top:0">当前游戏会话账号</h2>' + curtxt +
            '<div class="muted" style="margin-top:6px">客户端用手机号登录后，'
            'game_login 与「我的」页会自动读取此账号的全部字段。</div></div>' +
            '<div class="box"><h2 style="margin-top:0">蓝V（官方认证）名单</h2>' +
            (('<span class="mono">' + h(json.dumps(gm, ensure_ascii=False)) + '</span>')
             if gm else '<span class="muted">无。在「用户」里把某账号的 <b>蓝V官方认证（authed）</b> 填 <b>true</b> 即授予蓝V（服务端生效）。</span>') +
            '</div>' +
            '<div class="tip">提示：本后台与游戏服务端共用同一份数据（store.py，带文件锁 + 原子写）。'
            '在这里改动 G币 / 等级 / 蓝V / 动态后，客户端重新登录 game_login 即读到新值，无需重启服务。</div>')
    return Response(page('概览', body, 'home'), mimetype='text/html; charset=utf-8')


# ---------------- 服务器开关 ----------------
# 只控制游戏业务进程；后台 privsrv-admin 自身绝不停，否则关服后进不来。
GAME_SERVICES = ('privsrv', 'agentsrv')


def _svc_state(name):
    try:
        r = subprocess.run(['systemctl', 'is-active', name],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=6)
        return (r.stdout or '').strip() or 'unknown'
    except Exception:
        return 'unknown'


@app.route('/oplog')
def oplog_page():
    """操作审计：解析 logs/admin.log。格式: '时间  IP  动作  详情  UA[...]'"""
    import re as _re
    q = request.args.get('q', '').strip()
    recs = []
    try:
        with open(os.path.join(BASE, 'logs', 'admin.log'), encoding='utf8', errors='ignore') as f:
            for ln in f:
                ln = ln.rstrip('\n')
                if not ln:
                    continue
                # 拆出 UA[...]
                ua = ''
                m = _re.search(r'\sUA\[(.*)\]\s*$', ln)
                if m:
                    ua = m.group(1)
                    ln = ln[:m.start()]
                parts = _re.split(r'\s{2,}', ln.strip())
                ts = parts[0] if len(parts) > 0 else ''
                ip = parts[1] if len(parts) > 1 else ''
                act = parts[2] if len(parts) > 2 else ''
                detail = parts[3] if len(parts) > 3 else ''
                recs.append({'ts': ts, 'ip': ip, 'act': act, 'detail': detail, 'ua': ua})
    except Exception:
        pass
    recs.reverse()  # 最新在前
    if q:
        ql = q.lower()
        recs = [r for r in recs if ql in r['ts'].lower() or ql in r['ip'].lower()
                or ql in r['act'].lower() or ql in r['detail'].lower() or ql in r['ua'].lower()]
    total = len(recs)
    PER = 30
    pages = max(1, (total + PER - 1) // PER)
    try:
        pageno = int(request.args.get('page', '1'))
    except Exception:
        pageno = 1
    pageno = max(1, min(pageno, pages))
    cur = recs[(pageno - 1) * PER:pageno * PER]

    from urllib.parse import urlencode
    def purl(pn):
        params = {}
        if q: params['q'] = q
        params['page'] = pn
        return '/oplog?' + urlencode(params)
    def navbtn(label, pn, dis=False):
        if dis:
            return '<span class="btn gray" style="opacity:.5;pointer-events:none">' + label + '</span>'
        return '<a class="btn gray" href="' + h(purl(pn)) + '">' + label + '</a>'

    rows = ''
    def act_cls(a):
        if any(k in a for k in ('REJECT', 'BAD', 'FAIL', 'DENY')):
            return 'tag off'
        if any(k in a for k in ('OK', 'APPROVE', 'START', 'SAVE')):
            return 'tag ok'
        return 'badge'
    for r in cur:
        ipbad = r['ip'] and not r['ip'].startswith(('127.', '10.', '192.168.', '172.'))
        iphtml = '<span class="tag off">' + h(r['ip']) + '</span>' if ipbad else (h(r['ip']) or '-')
        rows += ('<tr><td class="mono">' + h(r['ts']) + '</td>'
                 '<td>' + iphtml + '</td>'
                 '<td><span class="' + act_cls(r['act']) + '">' + h(r['act']) + '</span></td>'
                 '<td>' + (h(r['detail']) or '<span class="muted">-</span>') + '</td>'
                 '<td class="muted" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + h(r['ua']) + '">' + h(r['ua'][:40]) + '</td></tr>')

    pager = ('<div class="box" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
             + navbtn('首页', 1, pageno <= 1) + navbtn('上一页', pageno - 1, pageno <= 1)
             + '<span class="muted" style="margin:0 6px">第 ' + str(pageno) + ' / ' + str(pages)
             + ' 页 · 共 ' + str(total) + ' 条</span>'
             + navbtn('下一页', pageno + 1, pageno >= pages) + navbtn('末页', pages, pageno >= pages)
             + '</div>') if total else ''
    body = ('<h1>操作审计</h1>'
            '<div class="tip">记录后台的所有敏感操作（登录、封禁、审核、改配置等）及来源 IP/设备。'
            '红色标签为被拒绝/异常操作，绿色为成功操作。时间为北京时间(UTC+8)。</div>'
            '<div class="box"><form method="get" action="/oplog" style="display:flex;gap:8px;align-items:center">'
            '<input name="q" value="' + h(q) + '" placeholder="搜索动作 / IP / 详情 / 设备" style="flex:1">'
            '<button class="btn" type="submit">筛选</button>'
            '<a class="btn gray" href="/oplog">清除</a></form></div>'
            + pager +
            '<div class="box"><h2 style="margin-top:0">操作记录 <span class="muted">共 ' + str(total) + ' 条</span></h2>'
            + ('<table><thead><tr><th>时间</th><th>来源IP</th><th>动作</th><th>详情</th><th>设备(UA)</th></tr></thead><tbody>'
               + rows + '</tbody></table>' if rows else '<span class="muted">暂无记录。</span>') + '</div>'
            + pager)
    return Response(page('操作审计', body, 'oplog'), mimetype='text/html; charset=utf-8')





# ============ IP 归属地（在线查询 + 磁盘缓存，失败放行不影响页面） ============
_IPREG_CACHE = None           # {ip: 地区字符串}
_IPREG_FILE = os.path.join(BASE, 'data', 'ip_region.json')
_IPREG_LOCK = __import__('threading').Lock()

def _ipreg_load():
    global _IPREG_CACHE
    if _IPREG_CACHE is None:
        try:
            with open(_IPREG_FILE, encoding='utf8') as f:
                d = json.load(f)
            _IPREG_CACHE = d if isinstance(d, dict) else {}
        except Exception:
            _IPREG_CACHE = {}
    return _IPREG_CACHE

def _ipreg_save():
    try:
        with open(_IPREG_FILE, 'w', encoding='utf8') as f:
            json.dump(_IPREG_CACHE, f, ensure_ascii=False)
    except Exception:
        pass

def ip_region(ip):
    """返回 '省市 运营商' 或 ''。内网/本地/保留地址返回固定标记。"""
    ip = str(ip or '').strip()
    if not ip:
        return ''
    cache = _ipreg_load()
    if ip in cache:
        return cache[ip]
    # 内网 / 本地
    if ip in ('127.0.0.1', '::1') or ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.2', '172.3', '169.254.', '0.')):
        cache[ip] = '内网/本地'; _ipreg_save(); return cache[ip]
    result = ''
    try:
        import requests as _rq
        r = _rq.get('https://whois.pconline.com.cn/ipJson.jsp',
                    params={'ip': ip, 'json': 'true'}, timeout=4)
        d = json.loads(r.text)
        if isinstance(d, dict) and not d.get('err'):
            parts = [str(d.get('pro') or ''), str(d.get('city') or '')]
            region = ''.join(x for x in parts if x and x != d.get('pro'))
            # 上面去重生硬，改为：省 + 市(若市不等于省)
            pro = str(d.get('pro') or '')
            city = str(d.get('city') or '')
            loc = pro if pro else ''
            if city and city != pro.replace('省', '').replace('市', ''):
                loc = (loc + city) if loc else city
            isp = str(d.get('addr') or '')
            if isp and (' ' in isp):
                isp = isp.split()[-1]  # 末尾通常是运营商
            result = (loc + ' ' + isp).strip()
    except Exception:
        result = ''
    cache[ip] = result  # 失败也缓存空串，避免反复请求
    _ipreg_save()
    return result

# ============ 玩家档案（只读聚合查询） ============
_LOGIN_IDX = {'ts': 0, 'by_uid': {}}   # uid -> [ (北京时间字符串, ip, 设备, 事件) ] 最新在前
_LOGIN_IDX_LOCK = __import__('threading').Lock()

def _build_login_index(force=False):
    """扫描 requests.jsonl，按 platformId(pf_xxx) 聚合登录事件与真实IP。
    60 秒缓存一次，避免每次点击都全扫日志。"""
    now = time.time()
    if (not force) and (now - _LOGIN_IDX.get('ts', 0) < 60) and _LOGIN_IDX.get('by_uid'):
        return _LOGIN_IDX['by_uid']
    with _LOGIN_IDX_LOCK:
        if (not force) and (now - _LOGIN_IDX.get('ts', 0) < 60) and _LOGIN_IDX.get('by_uid'):
            return _LOGIN_IDX['by_uid']
        by_uid = {}
        try:
            path = os.path.join(BASE, 'logs', 'requests.jsonl')
            with open(path, encoding='utf8', errors='ignore') as f:
                for ln in f:
                    if 'platformId' not in ln and 'accountId' not in ln:
                        continue
                    try:
                        d = json.loads(ln)
                    except Exception:
                        continue
                    jj = d.get('json') if isinstance(d.get('json'), dict) else {}
                    pid = str(jj.get('platformId') or d.get('platformId') or '')
                    if not pid.startswith('pf_'):
                        continue
                    uid = pid[3:]
                    evs = jj.get('logs') if isinstance(jj.get('logs'), list) else []
                    evt_names = [str(e.get('eventName', '')) for e in evs if isinstance(e, dict)]
                    is_login = any(x in ('login', 'user_login', 'game_login') for x in evt_names)
                    if not is_login:
                        continue
                    ci = jj.get('clientInfo') if isinstance(jj.get('clientInfo'), dict) else {}
                    dev = ('%s %s' % (ci.get('brand', ''), ci.get('model', ''))).strip()
                    ip = str(d.get('ip') or (d.get('headers') or {}).get('X-Real-Ip') or '')
                    ts = cn_iso(d.get('ts', ''))
                    by_uid.setdefault(uid, []).append((ts, ip, dev, ','.join(evt_names[:3])))
        except Exception:
            pass
        # 每个 uid 只留最近 30 条
        for uid in by_uid:
            by_uid[uid] = by_uid[uid][-30:][::-1]
        _LOGIN_IDX['ts'] = now
        _LOGIN_IDX['by_uid'] = by_uid
        return by_uid


@app.route('/player')
def player_page():
    """玩家档案：按 UID 或昵称查询，聚合展示该玩家的全部可读信息。只读。"""
    db = store.load_db()
    users = db.get('users', {}) if isinstance(db.get('users'), dict) else {}
    ft = db.get('feat', {}) if isinstance(db.get('feat'), dict) else {}
    q = (request.args.get('uid') or request.args.get('q') or '').strip()

    # 搜索框 + 结果提示
    search = ('<div class="box"><h2 style="margin-top:0">查找玩家</h2>'
              '<form method="get" action="/player" style="display:flex;gap:8px;flex-wrap:wrap">'
              '<input type="text" name="q" value="' + h(q) + '" placeholder="输入 UID 或昵称（如 1000026 / 人）" '
              'style="flex:1;min-width:240px">'
              '<button class="btn" type="submit">查询</button></form>'
              '<div class="muted" style="margin-top:8px">支持精确 UID 或昵称模糊匹配；数据全部只读。</div></div>')

    if not q:
        # 默认列出所有用户，带档案链接
        rows = ''
        for uid, u in sorted(users.items(), key=lambda x: str(x[0])):
            if not isinstance(u, dict):
                continue
            rows += ('<tr><td class="mono">' + h(uid) + '</td><td>' + h(u.get('userName', '')) + '</td>'
                     '<td class="mono">' + h(u.get('phone', '')) + '</td>'
                     '<td><a class="btn sm" href="/player?uid=' + h(uid) + '">查看档案</a></td></tr>')
        listing = ('<div class="box"><h2 style="margin-top:0">全部玩家 <span class="muted">共 ' +
                   str(len(users)) + ' 个</span></h2>'
                   '<table><thead><tr><th>UID</th><th>昵称</th><th>手机号</th><th>操作</th></tr></thead><tbody>'
                   + rows + '</tbody></table></div>')
        return Response(page('玩家档案', '<h1>玩家档案</h1>' + search + listing, 'player'),
                        mimetype='text/html; charset=utf-8')

    # 解析目标 uid
    target = None
    if q in users:
        target = q
    elif q.startswith('pf_') and q[3:] in users:
        target = q[3:]
    else:
        matches = [uid for uid, u in users.items()
                   if isinstance(u, dict) and (q.lower() in str(u.get('userName', '')).lower()
                                               or q in str(u.get('phone', '')))]
        if len(matches) == 1:
            target = matches[0]
        elif len(matches) > 1:
            rows = ''.join('<tr><td class="mono">' + h(uid) + '</td><td>' +
                           h(users[uid].get('userName', '')) + '</td><td>' +
                           '<a class="btn sm" href="/player?uid=' + h(uid) + '">查看档案</a></td></tr>'
                           for uid in matches)
            listing = ('<div class="box"><h2>匹配到 ' + str(len(matches)) + ' 个玩家，请选择</h2>'
                       '<table><thead><tr><th>UID</th><th>昵称</th><th>操作</th></tr></thead><tbody>' +
                       rows + '</tbody></table></div>')
            return Response(page('玩家档案', '<h1>玩家档案</h1>' + search + listing, 'player'),
                            mimetype='text/html; charset=utf-8')

    if not target:
        return Response(page('玩家档案', '<h1>玩家档案</h1>' + search +
                             '<div class="msg">未找到匹配 "' + h(q) + '" 的玩家</div>', 'player'),
                        mimetype='text/html; charset=utf-8')

    u = users.get(target, {})
    if not isinstance(u, dict):
        u = {}

    def box(title, rows_html):
        return ('<div class="box"><h2 style="margin-top:0">' + h(title) + '</h2>' +
                '<table><tbody>' + rows_html + '</tbody></table></div>')

    def r(label, val, mono=False):
        v = val if isinstance(val, str) else json.dumps(val, ensure_ascii=False) if val not in (None, '') else '-'
        return '<tr><th style="width:150px">' + h(label) + '</th><td' + (' class="mono"' if mono else '') + '>' + h(v) + '</td></tr>'

    # 头像
    img = u.get('userImg', '')
    avatar = ''
    if img:
        src = img if img.startswith('/') else '/uploads/cover/' + img
        avatar = ('<div style="margin-bottom:12px"><img src="' + h(src) +
                  '" style="width:64px;height:64px;border-radius:8px;object-fit:cover;border:1px solid #ccc" '
                  'onerror="this.style.display=\'none\'"></div>')

    # 基本信息
    basic = box('基本信息 ' + avatar, ''.join([
        r('UID', target, True), r('昵称', u.get('userName', '')), r('手机号', u.get('phone', '')),
        r('等级 / 经验', '%s / %s' % (u.get('level', ''), u.get('exp', ''))),
        r('G币 / 钻石', '%s / %s' % (u.get('coin', ''), u.get('diamond', ''))),
        r('简介', u.get('userIntro') or u.get('sign', '')),
        r('蓝V认证', '是' if u.get('authed') else '否'),
        r('实名', '是' if (u.get('isRealName') or u.get('realName')) else '否'),
        r('注册时间戳', cn_fmt(u.get('timestamp', 0)) if u.get('timestamp') else '-'),
        r('作品数(展示)', u.get('workCount', '')),
    ]))

    # 信誉分
    credit = ft.get('credit', {}).get(target, {})
    credit_html = box('信誉分', ''.join([
        r('当前分数', credit.get('score', '-')),
        r('记录数', len(credit.get('list', [])) if isinstance(credit.get('list'), list) else 0),
    ]))

    # 登录历史（真实IP）
    idx = _build_login_index()
    logins = idx.get(target, [])
    log_rows = ''
    seen = set()
    # 先按 IP 去重查归属地（带缓存），避免逐条重复查询
    for ts, ip, dev, evt in logins:
        if ip and ip not in seen:
            ip_region(ip)
        seen.add(ip)
    seen = set()
    for ts, ip, dev, evt in logins:
        key = (ts, ip, dev)
        if key in seen:
            continue
        seen.add(key)
        region = ip_region(ip)
        region_html = ('<br><span class="muted" style="font-size:11px">' + h(region) + '</span>') if region else ''
        log_rows += ('<tr><td>' + h(ts) + '</td><td class="mono">' + h(ip or '-') + region_html +
                     '</td><td>' + h(dev or '-') + '</td><td>' + h(evt or '-') + '</td></tr>')
    login_box = ('<div class="box"><h2 style="margin-top:0">登录历史 <span class="muted">最近 %d 条 · 真实IP</span></h2>'
                 '<table><thead><tr><th>时间(北京)</th><th>真实IP / 归属地</th><th>设备</th><th>事件</th></tr></thead><tbody>'
                 '%s</tbody></table></div>') % (len(logins),
                     log_rows or '<tr><td colspan="4" class="muted">暂无登录记录（或日志已轮转）</td></tr>')

    # 令牌与设备
    tokens = [t for t, v in db.get('tokens', {}).items() if str(v) == target]
    devices = [d for d, v in db.get('deviceMap', {}).items() if str(v) == target]
    tok_rows = ''.join([
        '<tr><th style="width:150px">令牌数</th><td>' + str(len(tokens)) + '</td></tr>',
        '<tr><th>令牌(前8位)</th><td class="mono">' + h(', '.join(t[:8] for t in tokens[:12])) + '</td></tr>',
        '<tr><th>设备数</th><td>' + str(len(devices)) + '</td></tr>',
        '<tr><th>设备ID</th><td class="mono">' + h(', '.join(devices[:12])) + '</td></tr>',
    ])
    tok_box = box('令牌与设备', tok_rows)

    # 动态
    try:
        talks = store.load_talks()
    except Exception:
        talks = []
    my_talks = [t for t in talks if str(t.get('playerId', t.get('uId', ''))) == target]
    talk_rows = ''
    for t in my_talks[-20:][::-1]:
        content = str(t.get('content', t.get('text', '')))[:120]
        ts = t.get('stamp', t.get('timestamp', 0))
        ts_show = cn_fmt(ts / 1000 if ts and ts > 1e12 else ts) if ts else '-'
        talk_rows += ('<tr><td class="mono">' + h(str(t.get('talkId', ''))) + '</td><td>' +
                      h(content) + '</td><td>' + h(ts_show) + '</td></tr>')
    talk_box = ('<div class="box"><h2 style="margin-top:0">动态 <span class="muted">共 %d 条</span></h2>'
                '<table><thead><tr><th>ID</th><th>内容</th><th>时间</th></tr></thead><tbody>%s</tbody></table></div>'
                ) % (len(my_talks), talk_rows or '<tr><td colspan="3" class="muted">无动态</td></tr>')

    # 评论
    comments = ft.get('comments', []) if isinstance(ft.get('comments'), list) else []
    my_comments = [c for c in comments if str(c.get('playerId', '')) == target]
    cmt_rows = ''
    for c in my_comments[-20:][::-1]:
        ts = c.get('stamp', 0)
        ts_show = cn_fmt(ts / 1000 if ts and ts > 1e12 else ts) if ts else '-'
        cmt_rows += ('<tr><td class="mono">' + h(str(c.get('id', ''))) + '</td><td>' +
                     h(str(c.get('content', c.get('text', '')))[:120]) + '</td><td>' + h(ts_show) + '</td></tr>')
    cmt_box = ('<div class="box"><h2 style="margin-top:0">评论 <span class="muted">共 %d 条</span></h2>'
               '<table><thead><tr><th>ID</th><th>内容</th><th>时间</th></tr></thead><tbody>%s</tbody></table></div>'
               ) % (len(my_comments), cmt_rows or '<tr><td colspan="3" class="muted">无评论</td></tr>')

    # 作品
    games = ft.get('games', []) if isinstance(ft.get('games'), list) else []
    editor = ft.get('editor', {}) if isinstance(ft.get('editor'), dict) else {}
    my_games = [g for g in games if str(g.get('playerId', g.get('uid', ''))) == target]
    ed = editor.get(target, {})
    ed_games = list((ed.get('gamedata', {}) or {}).values()) if isinstance(ed, dict) else []
    work_rows = ''
    for g in my_games[:30]:
        work_rows += ('<tr><td class="mono">' + h(str(g.get('id', ''))) + '</td><td>' +
                      h(str(g.get('name', ''))) + '</td><td>' +
                      h('玩%s 赞%s 藏%s' % (g.get('playCnt', 0), g.get('thumbCnt', 0), g.get('collectionCnt', 0))) +
                      '</td></tr>')
    for g in ed_games:
        if isinstance(g, dict):
            work_rows += ('<tr><td class="mono">' + h(str(g.get('id', ''))) + '</td><td>' +
                          h(str(g.get('name', ''))) + ' <span class="muted">(编辑器草稿)</span></td><td>-</td></tr>')
    work_box = ('<div class="box"><h2 style="margin-top:0">作品 <span class="muted">发布 %d · 草稿 %d</span></h2>'
                '<table><thead><tr><th>ID</th><th>名称</th><th>数据</th></tr></thead><tbody>%s</tbody></table></div>'
                ) % (len(my_games), len(ed_games),
                     work_rows or '<tr><td colspan="3" class="muted">无作品</td></tr>')

    # 商品
    goods = ft.get('goods', []) if isinstance(ft.get('goods'), list) else []
    my_goods = [g for g in goods if str(g.get('playerId', '')) == target]
    goods_rows = ''.join('<tr><td class="mono">' + h(str(g.get('id', ''))) + '</td><td>' +
                         h(str(g.get('name', ''))) + '</td><td>' + h(str(g.get('price', ''))) + '</td></tr>'
                         for g in my_goods[:30])
    goods_box = ('<div class="box"><h2 style="margin-top:0">商品 <span class="muted">共 %d 件</span></h2>'
                 '<table><thead><tr><th>ID</th><th>名称</th><th>价格</th></tr></thead><tbody>%s</tbody></table></div>'
                 ) % (len(my_goods), goods_rows or '<tr><td colspan="3" class="muted">无商品</td></tr>')

    head = ('<h1>玩家档案 · ' + h(u.get('userName', target)) + ' <span class="mono muted">' + h(target) + '</span></h1>'
            '<div class="tip">数据来自 db.json / talks.json / requests.jsonl，全部只读。登录历史为最近缓存(60秒刷新)。</div>')
    body = (head + search + basic + credit_html + login_box + tok_box + talk_box + cmt_box + work_box + goods_box
            + '<div class="box"><a class="btn" href="/users">返回用户列表</a> '
            '<a class="btn" href="/user/' + h(target) + '">编辑该用户字段</a></div>')
    return Response(page('玩家档案', body, 'player'), mimetype='text/html; charset=utf-8')


@app.route('/online')
def online_page():
    """实时在线：读 agentsrv 写出的连接快照，按 uid 汇总，并从请求日志补真实IP。纯只读。"""
    import datetime as _dt
    snap = {'ts': 0, 'connections': {}}
    try:
        with open(os.path.join(BASE, 'data', 'online.json'), encoding='utf8') as f:
            snap = json.load(f)
    except Exception:
        pass
    conns = snap.get('connections', {}) if isinstance(snap, dict) else {}

    # 按 uid 汇总（同一玩家可能多连接：重连期新旧并存）
    by_uid = {}
    now = time.time()
    for cid, info in conns.items():
        if not isinstance(info, dict):
            continue
        uid = str(info.get('uid', '') or '')
        last = float(info.get('last_ts', 0) or 0)
        cts = float(info.get('connect_ts', 0) or 0)
        key = uid or ('(未识别)%s' % str(cid)[:10])
        rec = by_uid.setdefault(key, {'uid': uid, 'ip': str(info.get('ip', '') or ''),
                                       'conns': 0, 'connect_ts': cts, 'last_ts': last})
        rec['conns'] += 1
        if cts and cts < rec['connect_ts']:
            rec['connect_ts'] = cts
        if last > rec['last_ts']:
            rec['last_ts'] = last

    # 用户名映射
    try:
        users = (store.load_db().get('users', {}) if hasattr(store, 'load_db') else {})
    except Exception:
        users = {}
    if not isinstance(users, dict):
        users = {}

    # 从请求日志补每个 uid 的最近真实IP（回溯尾部）
    ip_by_uid = {}
    try:
        tail = []
        with open(os.path.join(BASE, 'logs', 'requests.jsonl'), encoding='utf8', errors='ignore') as f:
            for ln in f:
                tail.append(ln)
                if len(tail) > 6000:
                    tail.pop(0)
        import re as _re
        for ln in reversed(tail):
            try:
                dd = json.loads(ln)
            except Exception:
                continue
            jj = dd.get('json') if isinstance(dd.get('json'), dict) else {}
            aa = dd.get('args') if isinstance(dd.get('args'), dict) else {}
            pid = jj.get('platformId') or aa.get('platformId') or ''
            if not pid:
                continue
            num = str(pid).replace('pf_', '')
            if num in by_uid and num not in ip_by_uid:
                hd = dd.get('headers') or {}
                ip_by_uid[num] = str(dd.get('ip') or hd.get('X-Real-Ip') or '')
            if len(ip_by_uid) >= len(by_uid):
                break
    except Exception:
        pass

    def ago(ts):
        try:
            d = int(now - float(ts))
            if d < 5: return '刚刚'
            if d < 60: return '%d 秒前' % d
            if d < 3600: return '%d 分钟前' % (d // 60)
            return '%d 小时前' % (d // 3600)
        except Exception:
            return '-'

    rows = ''
    for uid, rec in sorted(by_uid.items(), key=lambda x: -x[1]['last_ts']):
        uname = ''
        uv = users.get(uid) if uid else None
        if isinstance(uv, dict):
            uname = uv.get('userName') or uv.get('nickName') or ''
        real_ip = ip_by_uid.get(uid, '')
        ip_show = real_ip or rec['ip'] or '-'
        conn_note = ('%d 个连接' % rec['conns']) if rec['conns'] > 1 else '在线'
        rows += ('<tr><td class="mono">' + (h(uname) or '<span class="muted">游客/未知</span>') + '</td>'
                 '<td class="mono">' + h(uid or '-') + '</td>'
                 '<td class="mono">' + h(ip_show) + '</td>'
                 '<td>' + h(cn_fmt(rec['connect_ts']) if rec['connect_ts'] else '-') + '</td>'
                 '<td>' + h(ago(rec['last_ts'])) + '</td>'
                 '<td><span class="dot on">● ' + conn_note + '</span></td></tr>')

    snap_bj = cn_fmt(snap.get('ts', 0)) if snap.get('ts') else '-'
    online_n = len(by_uid)
    conn_n = len(conns)
    body = (
        '<h1>实时在线</h1>'
        '<div class="tip">每 10 秒自动刷新。数据来自游戏长连接（agentsrv），只读不改。</div>'
        '<div class="box"><h2 style="margin-top:0">在线概况</h2>'
        '<table><thead><tr><th>指标</th><th>数值</th></tr></thead><tbody>'
        '<tr><td>在线玩家数</td><td><span class="dot on">● ' + str(online_n) + ' 人</span></td></tr>'
        '<tr><td>活跃连接数</td><td>' + str(conn_n) + ' 个</td></tr>'
        '<tr><td>快照时间</td><td class="muted">' + h(snap_bj) + ' (北京时间)</td></tr>'
        '</tbody></table></div>'
        '<div class="box"><h2 style="margin-top:0">在线玩家</h2>'
        '<table><thead><tr><th>玩家</th><th>UID</th><th>IP</th><th>上线时间</th><th>最后活跃</th><th>状态</th></tr></thead><tbody>'
        + (rows or '<tr><td colspan="6" class="muted">当前没有在线玩家</td></tr>') +
        '</tbody></table></div>'
        '<meta http-equiv="refresh" content="10">'
    )
    return Response(page('实时在线', body, 'online'), mimetype='text/html; charset=utf-8')


@app.route('/status')
def status_page():
    """服务状态监控：三个服务 active、在线连接数、磁盘、日志大小。纯读取，不改任何东西。"""
    import datetime as _dt

    def gb(n):
        try:
            return '%.1f GB' % (float(n) / (1024 ** 3))
        except Exception:
            return str(n)

    def mb(n):
        try:
            return '%.1f MB' % (float(n) / (1024 ** 2))
        except Exception:
            return str(n)

    # --- 服务状态 ---
    svc_rows = ''
    bad = 0
    for name in ('privsrv', 'agentsrv', 'privsrv-admin'):
        st = _svc_state(name)
        ok = (st == 'active')
        if not ok:
            bad += 1
        cls = 'on' if ok else 'off'
        label = '运行中' if ok else ('已停止' if st == 'inactive' else h(st))
        svc_rows += ('<tr><td class="mono">' + h(name) + '</td>'
                     '<td><span class="dot ' + cls + '">● ' + label + '</span></td>'
                     '<td class="muted">' + ('正常' if ok else '异常，请检查 systemctl') + '</td></tr>')

    # --- 在线连接数（8443 业务 + 38443 后台）---
    def conn_count(port):
        try:
            r = subprocess.run(['sh', '-c',
                                "ss -tn 2>/dev/null | grep -c ':%d '" % port],
                               stdout=subprocess.PIPE, universal_newlines=True, timeout=6)
            return int((r.stdout or '0').strip() or 0)
        except Exception:
            return -1

    c_game = conn_count(8443)
    c_admin = conn_count(38443)

    # --- 近5分钟活跃IP（从 requests.jsonl 尾部抽样）---
    active_ip = 0
    try:
        cutoff = time.time() - 300
        ips = set()
        with open(os.path.join(BASE, 'logs', 'requests.jsonl'), encoding='utf8', errors='ignore') as f:
            for ln in f:
                try:
                    d = json.loads(ln)
                    ts = str(d.get('ts', ''))
                    dt = _dt.datetime.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S')
                    epoch = dt.timestamp()
                    if epoch >= cutoff:
                        ips.add(str(d.get('ip', '')))
                except Exception:
                    continue
        active_ip = len([x for x in ips if x])
    except Exception:
        active_ip = -1

    # --- 磁盘 ---
    disk_rows = ''
    try:
        st = os.statvfs(BASE)
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        used = total - free
        pct = (used / total * 100) if total else 0
        dcls = 'off' if pct > 90 else ('on' if pct < 80 else '')
        disk_rows = ('<tr><td>系统盘</td><td>' + gb(used) + ' / ' + gb(total) + '</td>'
                     '<td><span class="dot ' + dcls + '">● 已用 ' + ('%.0f%%' % pct) + '</span></td></tr>')
    except Exception as e:
        disk_rows = '<tr><td>系统盘</td><td colspan="2" class="muted">读取失败 ' + h(repr(e)) + '</td></tr>'

    # --- 日志大小 ---
    log_rows = ''
    for lname, path in (('请求日志', 'logs/requests.jsonl'), ('敏感词命中', 'logs/agent.log'),
                        ('后台审计', 'logs/admin.log')):
        fp = os.path.join(BASE, path)
        try:
            sz = os.path.getsize(fp)
            big = sz > 50 * 1024 * 1024
            note = ('<span class="dot off">● 偏大,建议清理</span>' if big else '<span class="muted">正常</span>')
            log_rows += ('<tr><td>' + h(lname) + '</td><td class="mono">' + h(path) + '</td>'
                         '<td>' + mb(sz) + '</td><td>' + note + '</td></tr>')
        except Exception:
            log_rows += ('<tr><td>' + h(lname) + '</td><td class="mono">' + h(path) + '</td>'
                         '<td class="muted">无</td><td></td></tr>')

    now_bj = time.strftime('%F %T', time.localtime(time.time() + CN_OFFSET))
    overall = ('<span class="dot off">● 有服务异常</span>' if bad else
               '<span class="dot on">● 全部正常</span>')
    body = (
        '<h1>服务状态</h1>'
        '<div class="tip">实时读取，只读不改。时间为北京时间(UTC+8)。刷新页面即可更新数据。</div>'
        '<div class="box"><h2 style="margin-top:0">总体：' + overall + '</h2>'
        '<div class="muted">检查时间：' + h(now_bj) + '</div></div>'
        '<div class="box"><h2 style="margin-top:0">服务进程</h2>'
        '<table><thead><tr><th>服务</th><th>状态</th><th>说明</th></tr></thead><tbody>'
        + svc_rows + '</tbody></table></div>'
        '<div class="box"><h2 style="margin-top:0">在线情况</h2>'
        '<table><thead><tr><th>指标</th><th>数值</th><th>说明</th></tr></thead><tbody>'
        '<tr><td>游戏业务连接(8443)</td><td>' + str(c_game) + '</td><td class="muted">当前 TCP 连接数</td></tr>'
        '<tr><td>后台连接(38443)</td><td>' + str(c_admin) + '</td><td class="muted">当前 TCP 连接数</td></tr>'
        '<tr><td>近5分钟活跃IP</td><td>' + str(active_ip) + '</td><td class="muted">从请求日志统计(近似)</td></tr>'
        '</tbody></table></div>'
        '<div class="box"><h2 style="margin-top:0">磁盘占用</h2>'
        '<table><thead><tr><th>项</th><th>用量</th><th>状态</th></tr></thead><tbody>'
        + disk_rows + '</tbody></table></div>'
        '<div class="box"><h2 style="margin-top:0">日志文件</h2>'
        '<table><thead><tr><th>名称</th><th>路径</th><th>大小</th><th>状态</th></tr></thead><tbody>'
        + log_rows + '</tbody></table></div>'
    )
    return Response(page('服务状态', body, 'status'), mimetype='text/html; charset=utf-8')


@app.route('/server')
def server_page():
    rows, all_on, any_on = '', True, False
    for name in GAME_SERVICES:
        st = _svc_state(name)
        if st == 'active':
            any_on = True
        else:
            all_on = False
        cls = 'on' if st == 'active' else 'off'
        label = '运行中' if st == 'active' else ('已停止' if st == 'inactive' else h(st))
        rows += ('<tr><td class="mono">' + h(name) + '</td>'
                 '<td><span class="dot ' + cls + '">● ' + label + '</span></td>'
                 '<td class="muted">' + ('客户端可连接' if st == 'active' else '客户端无法连接') + '</td></tr>')
    overall = ('<span class="dot on">● 开服中</span>' if all_on else
               ('<span class="dot off">● 已关服</span>' if not any_on else
                '<span class="badge">部分服务未运行</span>'))
    done = request.args.get('done', '')
    msg = ''
    if done == '1':
        msg = ('<div class="tip" style="background:#eaf7f0;border-color:#c4e8d3;'
               'color:#12734a">操作成功，状态已刷新。</div>')
    elif done == '0':
        msg = '<div class="msg">操作失败，请查看审计日志 / 服务器 systemctl 状态。</div>'
    body = (
        '<h1>服务器开关</h1>' + msg +
        '<div class="box"><h2 style="margin-top:0">当前状态：' + overall + '</h2>'
        '<table><thead><tr><th>服务</th><th>状态</th><th>说明</th></tr></thead><tbody>' +
        rows + '</tbody></table></div>'
        '<div class="box"><h2 style="margin-top:0">一键操作</h2>'
        '<div class="tip">关服只会停止 <b>privsrv</b>（业务接口 8443）和 <b>agentsrv</b>（游戏 WebSocket），'
        '客户端将全部掉线、无法登录。<b>本管理后台（38443）不会被停止</b>，你随时可以回来开服。'
        'DNS / 代理 / 下载服务保持运行，不影响恢复。</div>'
        '<form method="post" action="/server/toggle" style="display:inline">' + csrf_hidden() +
        '<input type="hidden" name="action" value="stop">'
        '<button class="btn red bigbtn" type="submit"' + (' disabled' if not any_on else '') + '>一键关服</button></form>'
        '<form method="post" action="/server/toggle" style="display:inline">' + csrf_hidden() +
        '<input type="hidden" name="action" value="start">'
        '<button class="btn green bigbtn" type="submit"' + (' disabled' if all_on else '') + '>一键开服</button></form>'
        '<div class="muted" style="margin-top:10px">状态为实时读取；操作通常 1–3 秒完成，点完会自动刷新本页。</div>'
        '</div>'
        '<div class="tip">提示：关服期间玩家数据不会丢失，账号与作品都保存在 '
        '<span class="mono">data/db.json</span>，重新开服后原样恢复。</div>'
    )
    return Response(page('服务器', body, 'server'), mimetype='text/html; charset=utf-8')


@app.route('/server/toggle', methods=['POST'])
def server_toggle():
    act = request.form.get('action', '')
    if act not in ('start', 'stop'):
        audit('SERVER_BAD_ACTION', act)
        abort(400)
    cmd = ['systemctl', act] + list(GAME_SERVICES)
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=45)
        ok = (r.returncode == 0)
        detail = ((r.stdout or '') + (r.stderr or '')).strip()[:220]
    except Exception as ex:
        ok, detail = False, repr(ex)[:220]
    audit('SERVER_' + act.upper(), detail)
    return redirect('/server?done=' + ('1' if ok else '0'))


# ---------------- 用户 ----------------
# 字段中英对照：编辑页 label 主显中文，英文原名以小字附在下方（name=f_xxx 不变，保证保存逻辑不受影响）
FIELD_CN = {
    'userId': '用户ID', 'uniqueId': '唯一标识', 'userName': '昵称',
    'phone': '登录手机号', 'coin': 'G币（金币）', 'gCoin': 'G币（同步字段）',
    'g币': 'G币（同步·中文键）', 'diamond': '钻石', 'level': '等级',
    'exp': '经验值', 'userImg': '头像地址', 'userIntro': '个人简介',
    'userSex': '性别', 'city': '城市', 'province': '省份',
    'birthday': '生日', 'brithDay': '生日（客户端字段）',
    'isRealName': '是否已实名', 'authed': '蓝V官方认证',
    'realName': '已实名标记', 'realNamed': '已实名标记',
    'isAdult': '是否成年', 'age': '年龄',
    'shareCode': '邀请码 / 分享码', 'sign': '个性签名',
    'gameId': '游戏ID', 'loginPlatform': '登录平台',
    'deviceID': '设备ID', 'timestamp': '注册时间戳',
    'userPlatforms': '绑定平台', 'hortorChannel': '渠道标识',
    'qqUnionId': 'QQ互联ID', 'dict': '扩展数据',
    'followCount': '关注数', 'fansCount': '粉丝数', 'workCount': '作品数',
}

# 关键字段的填写提示（直接显示在字段下方，不用再查表）
FIELD_TIP = {
    'coin': '填一个即可，coin / gCoin / g币 自动同步',
    'gCoin': '与 coin 自动同步，改哪个都行',
    'g币': '与 coin 自动同步，改哪个都行',
    'authed': 'true = 授予蓝V；false = 取消',
    'level': '数字，如 10（发动态需 ≥5）',
    'diamond': '数字，如 100',
    'exp': '数字，经验值',
    'userName': '游戏内显示的昵称',
    'userIntro': '个人简介，可留空',
    'sign': '个性签名，可留空',
    'userImg': '头像图片地址，可留空',
    'phone': '登录用手机号（任意验证码）',
    'userSex': '0=未知  1=男  2=女',
    'isRealName': '保持 true，改 false 会弹实名框',
    'realName': '保持 true，改 false 会弹实名框',
    'realNamed': '保持 true，改 false 会弹实名框',
    'isAdult': '保持 true（成年）',
    'userPlatforms': '保持 ["app-mobile"]，清空会变游客',
    'brithDay': '客户端原字段名就是这个拼写，勿改名',
    'birthday': '格式 1990-01-01',
    'userId': '账号唯一ID，不建议修改',
    'uniqueId': '账号唯一标识，不建议修改',
    'dict': 'JSON 对象，如 {}',
    'timestamp': 'Unix 秒级时间戳',
}

# 分组：常用字段置顶，避免一屏英文无从下手
FIELD_GROUPS = [
    ('① 常用设置（改这些就够了）',
     ['userName', 'phone', 'coin', 'gCoin', 'g币', 'diamond', 'level', 'exp',
      'authed', 'userIntro', 'sign', 'userImg', 'userSex', 'age',
      'city', 'province', 'birthday', 'brithDay', 'shareCode']),
    ('② 账号与状态（谨慎修改）',
     ['userId', 'uniqueId', 'isRealName', 'realName', 'realNamed', 'isAdult',
      'userPlatforms', 'loginPlatform', 'gameId', 'hortorChannel',
      'deviceID', 'qqUnionId', 'dict']),
    ('③ 统计数据（一般不用改）',
     ['fansCount', 'followCount', 'workCount', 'timestamp']),
    ('④ 其他 / 自定义字段', None),
]

KEY_RE = re.compile(r'^[A-Za-z0-9_\u4e00-\u9fa5]{1,40}$')


def valid_key(k):
    return bool(KEY_RE.match(k)) and not k.startswith('__')


def coerce(s):
    s = s.strip()
    if s == '':
        return ''
    low = s.lower()
    if low == 'true':
        return True
    if low == 'false':
        return False
    if low in ('null', 'none'):
        return None
    if re.fullmatch(r'-?\d+', s):
        try:
            return int(s)
        except Exception:
            pass
    if re.fullmatch(r'-?\d+\.\d+', s):
        try:
            return float(s)
        except Exception:
            pass
    if s[:1] in ('{', '['):
        try:
            return json.loads(s)
        except Exception:
            pass
    return s[:2000]


@app.route('/users')
def users():
    db = store.load_db()
    rows = []
    for uid, u in sorted(db['users'].items(), key=lambda x: str(x[0])):
        blue = ' <span class="badge">蓝V</span>' if u.get('authed') else ''
        rows.append('<tr><td class="mono">' + h(uid) + '</td>'
                    '<td>' + h(u.get('userName', '')) + blue + '</td>'
                    '<td>' + h(u.get('phone', '')) + '</td>'
                    '<td class="mono">' + h(u.get('coin', '')) + '</td>'
                    '<td>' + h(u.get('level', '')) + '</td>'
                    '<td>' + h(u.get('diamond', '')) + '</td>'
                    '<td><a class="btn sm" href="/player?uid=' + h(uid) + '">档案</a> '
                    '<a class="btn sm" href="/user/' + h(uid) + '">编辑字段</a>'
                    '<form method="post" action="/user/' + h(uid) + '/delete" style="display:inline" '
                    'onsubmit="return confirm(\'确认删除该用户？\')">' + csrf_hidden() +
                    '<button class="btn sm red" type="submit">删除</button></form></td></tr>')
    table = ('<table><tr><th>ID</th><th>昵称</th><th>手机号</th><th>G币(coin)</th>'
             '<th>等级</th><th>钻石</th><th>操作</th></tr>' +
             (''.join(rows) if rows else '<tr><td colspan="7" class="muted">暂无用户（客户端用手机号登录会自动创建）</td></tr>') +
             '</table>')
    add = ('<div class="box"><h2 style="margin-top:0">新增用户</h2>'
           '<form method="post" action="/user/add">' + csrf_hidden() +
           '<div class="frow"><label>手机号（留空自动生成）</label><input type="text" name="phone"></div>'
           '<div class="frow"><label>昵称</label><input type="text" name="name"></div>'
           '<button class="btn" type="submit" style="margin-top:10px">创建用户</button></form></div>')
    return Response(page('用户管理', '<h1>用户管理 <span class="muted">共 ' +
                         str(len(db['users'])) + ' 个</span></h1>' + table + add, 'users'),
                    mimetype='text/html; charset=utf-8')


@app.route('/user/<uid>')
def user_edit(uid):
    db = store.load_db()
    u = db['users'].get(uid)
    if not isinstance(u, dict):
        return Response('用户不存在', status=404, mimetype='text/plain; charset=utf-8')
    def row(k, v):
        vs = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        cn = FIELD_CN.get(k, '')
        if cn:
            lab = '<label><b>' + h(cn) + '</b><br><span class="fkey">' + h(k) + '</span>'
        else:
            lab = '<label><b>' + h(k) + '</b>'
        tip = FIELD_TIP.get(k, '')
        if tip:
            lab += '<br><span class="ftip">' + h(tip) + '</span>'
        lab += '</label>'
        # name="f_<原字段名>" 保持不变，保存逻辑完全不动
        return ('<div class="frow">' + lab + '<input type="text" name="f_' + h(k) +
                '" value="' + h(vs) + '"></div>')

    keys = sorted(u.keys())
    used = set()
    parts = []
    for title, ks in FIELD_GROUPS:
        group = [k for k in keys if k not in used] if ks is None else [k for k in ks if k in u]
        used.update(group)
        if not group:
            continue
        parts.append('<h2 class="grp">' + h(title) + '</h2>')
        for k in group:
            parts.append(row(k, u[k]))

    body = ('<h1>编辑用户 <span class="mono">' + h(uid) + '</span></h1>'
            '<div class="tip"><b>怎么填（每个字段下方都标了中文名和填写说明）</b><br>'
            '· 想加钱：改 <b>G币（coin）</b> 或 <b>钻石（diamond）</b>，填数字；G币三个字段自动同步<br>'
            '· 想给蓝V：把 <b>蓝V官方认证（authed）</b> 填 <span class="mono">true</span>，取消填 <span class="mono">false</span><br>'
            '· 想改昵称/等级：改 <b>昵称（userName）</b> / <b>等级（level）</b>（发动态需 ≥5）<br>'
            '· 布尔值统一填小写 <span class="mono">true</span> / <span class="mono">false</span>；'
            '列表或对象填 JSON，如 <span class="mono">["app-mobile"]</span>、<span class="mono">{}</span>；留空 = 空字符串<br>'
            '· 改完点「保存全部」，客户端重新登录即生效，无需重启服务</div>'
            '<form method="post" action="/user/' + h(uid) + '/save" class="box">' + csrf_hidden() +
            ''.join(parts) +
            '<h2 class="grp">⑤ 新增自定义字段（可选）</h2>'
            '<div class="frow"><label><b>字段名</b><br><span class="fkey">new_key</span></label>'
            '<input type="text" name="new_key" placeholder="英文或中文，如 vipLevel"></div>'
            '<div class="frow"><label><b>值</b><br><span class="fkey">new_val</span></label>'
            '<input type="text" name="new_val" placeholder="数字 / true / false / JSON"></div>'
            '<div style="margin-top:16px"><button class="btn" type="submit">保存全部</button>'
            '<a class="btn gray" href="/users">返回</a></div></form>'
            + credit_admin_box(uid))
    return Response(page('编辑用户', body, 'users'), mimetype='text/html; charset=utf-8')


def credit_admin_box(uid):
    """用户详情页内的信誉分管理表单：后台手动加/扣信誉分并填理由。"""
    return ('<h2 class="grp">信誉分管理</h2>'
            '<div class="tip">对当前用户手动 <b>加 / 扣</b> 信誉分（等级点），并填写理由。理由会显示在 APP 的「信誉分」'
            '界面（CreditScene）。分值区间 <b>0–3</b>：满 3 全绿叶子，每扣 1 点掉 1 片叶子，扣到 0 即封号。'
            '改完客户端重新登录即生效，无需重启。</div>'
            '<form method="post" action="/user/' + h(uid) + '/credit" class="box">' + csrf_hidden() +
            '<div class="frow"><label><b>操作</b><br><span class="fkey">op</span></label>'
            '<select name="op"><option value="inc">加分</option><option value="dec">扣分</option></select></div>'
            '<div class="frow"><label><b>分值</b><br><span class="fkey">score</span></label>'
            '<input type="text" name="score" value="1"></div>'
            '<div class="frow"><label><b>理由</b><br><span class="fkey">reason</span></label>'
            '<input type="text" name="reason" placeholder="如：发布违规内容 / 优质创作奖励" value=""></div>'
            '<div style="margin-top:12px"><button class="btn" type="submit">提交</button></div></form>')


def adjust_credit(db, uid, delta, reason):
    """后台手动调整信誉分（0~3 等级点）：改 ft.credit[uid].score 并留一条 UserCreditMsg 明细，同步 db.users[uid].creditScore。"""
    uid = str(uid)
    feat = db.setdefault('feat', {})
    rec = feat.setdefault('credit', {}).setdefault(uid, {'score': 3, 'list': []})
    old = F.as_int(rec.get('score'), 3)
    new = max(0, min(3, old + delta))   # 信誉分等级点区间 0–3（3=满，0=封号）
    rec['score'] = new
    rec.setdefault('list', []).append({
        'score': delta, 'reason': reason, 'stamp': int(time.time() * 1000),
    })
    rec['list'] = rec['list'][-50:]
    u = db['users'].get(uid)
    if isinstance(u, dict):
        u['creditScore'] = new
    store.save_db(db)
    return new


@app.route('/user/<uid>/credit', methods=['POST'])
def user_credit(uid):
    db = store.load_db()
    u = db['users'].get(uid)
    if not isinstance(u, dict):
        return Response('用户不存在', status=404, mimetype='text/plain; charset=utf-8')
    op = request.form.get('op', 'inc')
    try:
        score = max(0, min(3, int(float(request.form.get('score', '0') or 0))))
    except Exception:
        score = 0
    if op == 'inc':
        delta, label = score, '加分'
    else:
        delta, label = -score, '扣分'
    reason = (request.form.get('reason', '') or '').strip()[:200] or ('后台' + label)
    new = adjust_credit(db, uid, delta, reason)
    if new <= 0:
        _queue_kick(uid, reason or '信誉归零封号')
    audit('USER_CREDIT', uid + ' op=' + op + ' score=' + str(score) +
          ' delta=' + str(delta) + ' -> ' + str(new))
    return redirect('/user/' + uid)


@app.route('/user/<uid>/save', methods=['POST'])
def user_save(uid):
    db = store.load_db()
    u = db['users'].get(uid)
    if not isinstance(u, dict):
        return Response('用户不存在', status=404, mimetype='text/plain; charset=utf-8')
    changed = []
    for key, val in request.form.items():
        if key.startswith('f_'):
            k = key[2:]
            if valid_key(k):
                nv = coerce(val)
                if u.get(k) != nv:
                    changed.append(k)
                u[k] = nv
    nk = request.form.get('new_key', '').strip()
    if nk and valid_key(nk):
        u[nk] = coerce(request.form.get('new_val', ''))
        changed.append('+' + nk)
    # coin / gCoin / g币 三者同步（取被改的那个）
    coin_val = None
    for k in ('coin', 'gCoin', 'g币'):
        if k in changed:
            coin_val = u.get(k)
            break
    if coin_val is not None:
        for k in ('coin', 'gCoin', 'g币'):
            u[k] = coin_val
    store.save_db(db)
    audit('USER_SAVE', uid + ' ' + ','.join(changed[:20]))
    return redirect('/user/' + uid)


@app.route('/user/add', methods=['POST'])
def user_add():
    phone = request.form.get('phone', '').strip() or ('admin_%d' % int(time.time()))
    name = request.form.get('name', '').strip() or None
    before = store.load_db().get('currentUid', '')
    u, is_new = store.register_or_login(phone, name)
    if before:
        store.set_current(before)   # 不因后台新增用户改变客户端当前会话
    audit('USER_ADD', str(u.get('userId')) + ' new=' + str(is_new))
    return redirect('/users')


@app.route('/user/<uid>/delete', methods=['POST'])
def user_delete(uid):
    db = store.load_db()
    db['users'].pop(uid, None)
    db['tokens'] = {t: v for t, v in db['tokens'].items() if str(v) != str(uid)}
    db['phoneMap'] = {p: v for p, v in db['phoneMap'].items() if str(v) != str(uid)}
    if str(db.get('lastUser')) == str(uid):
        db['lastUser'] = ''
    if str(db.get('currentUid')) == str(uid):
        db['currentUid'] = ''
    store.save_db(db)
    audit('USER_DELETE', uid)
    return redirect('/users')


# ---------------- 会话与令牌 ----------------
@app.route('/tokens')
def tokens_page():
    db = store.load_db()
    users = db.get('users', {}) if isinstance(db.get('users'), dict) else {}
    toks = db.get('tokens', {}) if isinstance(db.get('tokens'), dict) else {}
    devmap = db.get('deviceMap', {}) if isinstance(db.get('deviceMap'), dict) else {}
    cur = str(db.get('currentUid') or '')
    last = str(db.get('lastUser') or '')

    def _who(uid):
        u = users.get(str(uid)) if isinstance(users, dict) else None
        if not isinstance(u, dict):
            return '（账号已不存在）', ''
        return h(u.get('userName', '')), h(u.get('phone', ''))

    rows = []
    for tok, uid in sorted(toks.items(), key=lambda x: str(x[0])):
        name, phone = _who(uid)
        mark = ' <span class="badge">当前</span>' if str(uid) == cur else ''
        mark += ' <span class="badge">最近</span>' if str(uid) == last else ''
        rows.append('<tr><td class="fkey">' + h(str(tok)) + '</td>'
                    '<td class="mono">' + h(str(uid)) + '</td>'
                    '<td>' + name + mark + '</td>'
                    '<td>' + phone + '</td>'
                    '<td><form method="post" action="/token/' + h(str(tok)) + '/revoke" '
                    'style="display:inline" onsubmit="return confirm(\'吊销后该设备需重新登录，确认？\')">' +
                    csrf_hidden() +
                    '<button class="btn sm red" type="submit">吊销</button></form></td></tr>')
    ttable = ('<table><tr><th>令牌(token)</th><th>归属账号ID</th><th>昵称/标记</th>'
              '<th>手机号</th><th>操作</th></tr>' +
              (''.join(rows) if rows else
               '<tr><td colspan="5" class="muted">暂无令牌（客户端登录后自动生成）</td></tr>') +
              '</table>')

    drows = []
    for dev, uid in sorted(devmap.items(), key=lambda x: str(x[0])):
        name, phone = _who(uid)
        drows.append('<tr><td class="fkey">' + h(str(dev)) + '</td>'
                     '<td class="mono">' + h(str(uid)) + '</td>'
                     '<td>' + name + '</td><td>' + phone + '</td></tr>')
    dtable = ('<table><tr><th>设备ID(deviceId)</th><th>归属账号ID</th><th>昵称</th>'
              '<th>手机号</th></tr>' +
              (''.join(drows) if drows else
               '<tr><td colspan="4" class="muted">暂无设备绑定</td></tr>') +
              '</table>')

    sess = ('<div class="box"><h2 style="margin-top:0">当前游戏会话</h2>'
            '<div class="frow"><label>当前账号 currentUid</label><b class="mono">' +
            (h(cur) if cur else '（无）') + '</b></div>'
            '<div class="frow"><label>最近登录 lastUser</label><b class="mono">' +
            (h(last) if last else '（无）') + '</b></div></div>')

    clear = ('<div class="box"><h2 style="margin-top:0">批量操作</h2>'
             '<div class="muted" style="margin-bottom:10px">吊销令牌只是让对应设备下次请求需重新登录，'
             '不会删除账号、动态等任何数据。</div>'
             '<form method="post" action="/tokens/clear" '
             'onsubmit="return confirm(\'确认吊销全部令牌？所有设备需重新登录。\')">' +
             csrf_hidden() +
             '<button class="btn red" type="submit">吊销全部令牌</button></form></div>')

    body = ('<h1>会话与令牌 <span class="muted">共 ' + str(len(toks)) +
            ' 个令牌 · ' + str(len(devmap)) + ' 个设备绑定</span></h1>' + sess +
            '<div class="box"><h2 style="margin-top:0">令牌列表(token → 账号)</h2>' + ttable + '</div>' +
            '<div class="box"><h2 style="margin-top:0">设备绑定(deviceId → 账号)</h2>' + dtable + '</div>' +
            clear +
            '<div class="tip">令牌是客户端登录凭据，指向某个账号。发现异常可单独吊销或全部吊销，'
            '设备重新登录后自动获得新令牌。WebSocket 游戏会话是连接级的，不在此列表；'
            '此页展示的是落盘的登录令牌与设备绑定。</div>')
    return Response(page('会话令牌', body, 'tokens'), mimetype='text/html; charset=utf-8')


@app.route('/token/<tok>/revoke', methods=['POST'])
def token_revoke(tok):
    db = store.load_db()
    if isinstance(db.get('tokens'), dict):
        db['tokens'].pop(tok, None)
        store.save_db(db)
        audit('TOKEN_REVOKE', tok)
    return redirect('/tokens')


@app.route('/tokens/clear', methods=['POST'])
def tokens_clear():
    db = store.load_db()
    n = len(db.get('tokens', {})) if isinstance(db.get('tokens'), dict) else 0
    db['tokens'] = {}
    store.save_db(db)
    audit('TOKENS_CLEAR', '吊销 %d 个令牌' % n)
    return redirect('/tokens')


# ---------------- 动态 ----------------
@app.route('/talks')
def talks():
    ts = store.load_talks()[::-1]
    blocks = []
    for t in ts:
        tid = str(t.get('talkId', ''))
        title = str(t.get('title', ''))
        sc = t.get('simpleContent')
        text = sc.get('text', '') if isinstance(sc, dict) else str(sc or '')
        author = str(t.get('userName', ''))
        stamp = t.get('createStamp', 0)
        try:
            ts_str = cn_fmt(int(stamp) / 1000)
        except Exception:
            ts_str = str(stamp)
        blocks.append(
            '<div class="talk"><div class="t">' + h(title) + '</div>'
            '<div class="m">作者 ' + h(author) + ' · ' + h(ts_str) +
            ' · 点赞 ' + h(t.get('upCnt', 0)) + ' · ID <span class="mono">' + h(tid) + '</span></div>'
            '<form method="post" action="/talk/' + h(tid) + '/save">' + csrf_hidden() +
            '<div class="frow"><label>标题</label><input type="text" name="title" value="' + h(title) + '"></div>'
            '<div class="frow"><label>正文</label><input type="text" name="text" value="' + h(text) + '"></div>'
            '<button class="btn sm" type="submit">保存</button></form>'
            '<form method="post" action="/talk/' + h(tid) + '/delete" style="display:inline" '
            'onsubmit="return confirm(\'确认删除该动态？\')">' + csrf_hidden() +
            '<button class="btn sm red" type="submit">删除动态</button></form></div>')
    clear = ('<form method="post" action="/talks/clear" '
             'onsubmit="return confirm(\'确认清空全部动态？不可恢复\')">' + csrf_hidden() +
             '<button class="btn red" type="submit">清空全部动态</button></form>')
    body = ('<h1>动态管理 <span class="muted">共 ' + str(len(ts)) + ' 条</span></h1>'
            '<div class="tip">客户端「发动态」会写入这里，删除即时生效（game_loadtalk 读到更新后的列表）。</div>'
            + clear + '<div style="height:14px"></div>'
            + (''.join(blocks) if blocks else '<div class="box muted">暂无动态</div>'))
    return Response(page('动态管理', body, 'talks'), mimetype='text/html; charset=utf-8')


@app.route('/talk/<tid>/save', methods=['POST'])
def talk_save(tid):
    title = request.form.get('title', '')[:120]
    text = request.form.get('text', '')[:1000]
    store.patch_talk(tid, {'title': title, 'simpleContent': {'text': text}})
    audit('TALK_SAVE', tid)
    return redirect('/talks')


@app.route('/talk/<tid>/delete', methods=['POST'])
def talk_delete(tid):
    n = store.del_talk(tid)
    audit('TALK_DELETE', tid + ' removed=' + str(n))
    return redirect('/talks')


@app.route('/talks/clear', methods=['POST'])
def talks_clear():
    store.save_talks([])
    audit('TALK_CLEAR')
    return redirect('/talks')


# ---------------- 头像审核 ----------------
def _review_thumb(url):
    """把 /uploads/cover/xxx.png 读成 data URI 缩略图（CSP img-src 允许 data:）。"""
    rel = str(url or '').lstrip('/')
    if rel.startswith('uploads/'):
        p = os.path.join(BASE, 'uploads', rel[len('uploads/'):])
    else:
        p = os.path.join(BASE, 'uploads', 'cover', rel)
    try:
        raw = open(p, 'rb').read()
        if not raw or len(raw) > 2 * 1024 * 1024:
            return ''
        return 'data:image/png;base64,' + base64.b64encode(raw).decode('ascii')
    except Exception:
        return ''


@app.route('/reviews')
def reviews():
    db = store.load_db()
    rs = sorted(db.get('reviews', []), key=lambda r: r.get('createStamp', 0), reverse=True)
    n_pending = sum(1 for r in rs if r.get('status') == review.INREVIEW)
    cards = ('<div class="cards">'
             '<div class="card"><span>待审核</span><b>' + str(n_pending) + '</b></div>'
             '<div class="card"><span>总记录</span><b>' + str(len(rs)) + '</b></div>'
             '<div class="card"><span>自动通过</span><b>' +
             ('开' if review.auto_enabled() else '关') + '</b></div></div>')
    tip = ('<div class="tip">用户换头像 → 服务端把图片存到 '
           '<span class="mono">/opt/privsrv/uploads/cover/</span> 并生成一条待审核记录。'
           '点「通过」后该账号 <b>userImg</b> 更新为新头像、状态置为「已通过」，'
           'APP <b>重新登录</b>即正常显示，不再提示「新头像审核中」。'
           '「拒绝」则保留旧头像并显示审核失败。</div>')
    auto = ('<div class="box"><h2 style="margin-top:0">自动通过</h2>'
            '<div class="muted" style="margin-bottom:10px">开启后新头像上传即自动通过，无需手动审核。'
            '客户端当前会话仍会短暂显示「审核中」，重新登录生效。</div>'
            '<form method="post" action="/reviews/auto">' + csrf_hidden() +
            '<button class="btn" type="submit" name="auto" value="1">开启自动通过</button>'
            '<button class="btn gray" type="submit" name="auto" value="0">关闭自动通过</button>'
            '</form></div>')
    clear = ('<form method="post" action="/reviews/clear_done" style="margin-bottom:18px">'
             + csrf_hidden() +
             '<button class="btn gray sm" type="submit">清空已处理记录</button></form>')
    blocks = []
    for r in rs:
        st = r.get('status', 0)
        img = _review_thumb(r.get('url'))
        thumb = (('<img src="' + img + '" style="width:76px;height:76px;object-fit:cover;'
                  'border-radius:8px;border:1px solid #e6e8eb;flex-shrink:0">')
                 if img else '<div class="muted" style="width:76px;flex-shrink:0">无预览</div>')
        badge = {
            '1': '<span class="badge" style="background:#eaf7f0;color:#12734a">已通过</span>',
            '2': '<span class="badge">待审核</span>',
            '3': '<span class="badge" style="background:#fdecec;color:#b4232a">已拒绝</span>',
        }.get(str(st), '<span class="muted">已作废</span>')
        ts = cn_fmt((r.get('createStamp') or 0) / 1000, '%m-%d %H:%M')
        ops = ''
        if st == review.INREVIEW:
            ops = ('<form method="post" action="/review/' + h(r['rid']) + '/approve" style="display:inline">'
                   + csrf_hidden() + '<button class="btn sm" type="submit">通过</button></form>'
                   '<form method="post" action="/review/' + h(r['rid']) + '/reject" style="display:inline">'
                   + csrf_hidden() + '<button class="btn sm red" type="submit">拒绝</button></form>')
        ops += ('<form method="post" action="/review/' + h(r['rid']) + '/delete" style="display:inline">'
                + csrf_hidden() + '<button class="btn sm gray" type="submit">删除</button></form>')
        blocks.append(
            '<div class="talk" style="display:flex;gap:14px;align-items:center">' + thumb +
            '<div style="flex:1;min-width:0"><div class="t">' +
            h(r.get('userName') or ('用户 ' + str(r.get('uid')))) + ' ' + badge + '</div>' +
            '<div class="m">ID ' + h(r.get('uid')) + ' · ' + h(ts) + ' · ' +
            h(r.get('url')) + '</div>' +
            '<div class="muted">' + h(r.get('reason') or '') + '</div>' +
            '<div style="margin-top:8px">' + ops + '</div></div></div>')
    body = ('<h1>头像审核 <span class="muted">共 ' + str(len(rs)) + ' 条</span></h1>' +
            cards + tip + auto + clear +
            (''.join(blocks) if blocks else
             '<div class="box muted">暂无审核记录。用户在 APP 里换一次头像，记录就会出现在这里。</div>'))
    return Response(page('头像审核', body, 'reviews'), mimetype='text/html; charset=utf-8')


@app.route('/review/<rid>/approve', methods=['POST'])
def review_approve(rid):
    db = store.load_db()
    r = review.approve(db, rid)
    store.save_db(db)
    audit('REVIEW_APPROVE', rid + ' uid=' + str((r or {}).get('uid')))
    return redirect('/reviews')


@app.route('/review/<rid>/reject', methods=['POST'])
def review_reject(rid):
    db = store.load_db()
    r = review.reject(db, rid, '后台审核未通过')
    store.save_db(db)
    audit('REVIEW_REJECT', rid + ' uid=' + str((r or {}).get('uid')))
    return redirect('/reviews')


@app.route('/review/<rid>/delete', methods=['POST'])
def review_delete(rid):
    db = store.load_db()
    n = review.delete(db, rid)
    store.save_db(db)
    audit('REVIEW_DELETE', rid + ' removed=' + str(n))
    return redirect('/reviews')


@app.route('/reviews/clear_done', methods=['POST'])
def review_clear_done():
    db = store.load_db()
    n = review.clear_done(db)
    store.save_db(db)
    audit('REVIEW_CLEAR_DONE', 'removed=' + str(n))
    return redirect('/reviews')


@app.route('/reviews/auto', methods=['POST'])
def review_auto():
    v = request.form.get('auto') == '1'
    review.set_auto(v)
    audit('REVIEW_AUTO', 'on' if v else 'off')
    return redirect('/reviews')


# ---------------- 功能层数据管理：商品 / 评论 / 举报 / 互动数据 ----------------
# 数据来自 db.json 顶层 feat 键（与 agentsrv 的 features.py 共用同一份文件 + 同一把 flock 锁）。
def _feat(db=None):
    db = db if isinstance(db, dict) else store.load_db()
    ft = db.get('feat')
    if not isinstance(ft, dict):
        ft = {}
        db['feat'] = ft
    return db, ft


def _seed_goods():
    """内置商品由 feat_shop.py 提供（代码里，清库后仍在）。"""
    try:
        import feat_shop
        return list(feat_shop.SEED_GOODS)
    except Exception:
        return []


def _lst(ft, k):
    v = ft.get(k)
    return v if isinstance(v, list) else []


def _dct(ft, k):
    v = ft.get(k)
    return v if isinstance(v, dict) else {}


def _stamp(v):
    try:
        return cn_fmt(int(v) / 1000, '%m-%d %H:%M')
    except Exception:
        return '-'


def _save(db, action, detail=''):
    store.save_db(db)
    audit(action, detail)


def _card(label, num):
    return '<div class="card"><span>' + h(label) + '</span><b>' + h(num) + '</b></div>'


# ---- 商品 ----
@app.route('/goods')
def goods():
    db, ft = _feat(store.load_db())
    custom = _lst(ft, 'goods')
    seed = _seed_goods()
    blocks = []
    for g in seed:
        blocks.append('<div class="talk"><div class="t">' + h(g.get('name')) +
                      ' <span class="badge">内置</span></div><div class="m">ID ' + h(g.get('id')) +
                      ' · 价格 ' + h(g.get('price')) + ' G币 · 类型 ' + h(g.get('goodsType')) +
                      ' · 销量 ' + h(g.get('saleCnt')) + '</div></div>')
    for g in custom:
        gid = str(g.get('id', ''))
        blocks.append('<div class="talk"><div class="t">' + h(g.get('name')) +
                      ' <span class="badge">自定义</span></div><div class="m">ID ' + h(gid) +
                      ' · 价格 ' + h(g.get('price', 0)) + ' G币 · 类型 ' + h(g.get('goodsType', 0)) +
                      ' · ' + h(_stamp(g.get('upStamp'))) + '</div>' +
                      '<form method="post" action="/goods/' + h(gid) + '/delete" style="margin-top:8px">' +
                      csrf_hidden() + '<button class="btn gray" type="submit">删除该商品</button></form></div>')
    form = ('<div class="box"><h2 style="margin-top:0">新增自定义商品</h2>' +
            '<div class="tip">内置 ' + str(len(seed)) + ' 件商品由服务端代码提供（清库后依然存在），不可在此删除。'
            '此处新增的商品会叠加进商城列表，客户端重进商城即可看到；购买时按填写的价格<b>真实扣除 G币</b>。</div>' +
            '<form method="post" action="/goods/add">' + csrf_hidden() +
            '<div class="frow"><label>商品名称</label><input type="text" name="name" required placeholder="如：限定皮肤"></div>' +
            '<div class="frow"><label>价格（G币）</label><input type="number" name="price" value="100" min="0"></div>' +
            '<div class="frow"><label>商品类型（数字）</label><input type="number" name="goodsType" value="1" min="0"></div>' +
            '<div class="frow"><label>图标文件名</label><input type="text" name="icon" value="demo1.png"></div>' +
            '<div style="margin-top:14px"><button class="btn" type="submit">添加商品</button></div></form></div>')
    body = ('<h1>商品管理 <span class="muted">共 ' + str(len(seed) + len(custom)) + ' 件</span></h1>' +
            '<div class="tip">商城列表 = 内置商品 + 自定义商品。客户端 <span class="mono">game_getgoodsinfos</span> / '
            '<span class="mono">game_buygoods</span> 直接读这份数据。</div>' + ''.join(blocks) + form)
    return Response(page('商品管理', body, 'goods'), mimetype='text/html; charset=utf-8')


@app.route('/goods/add', methods=['POST'])
def goods_add():
    db, ft = _feat(store.load_db())
    name = request.form.get('name', '').strip()[:40]
    if not name:
        return redirect('/goods')
    try:
        price = max(0, int(request.form.get('price', 0)))
    except Exception:
        price = 0
    try:
        gtype = max(0, int(request.form.get('goodsType', 1)))
    except Exception:
        gtype = 1
    icon = request.form.get('icon', '').strip()[:60] or 'demo1.png'
    ids = []
    for g in _lst(ft, 'goods') + _seed_goods():
        try:
            ids.append(int(g.get('id', 0)))
        except Exception:
            pass
    new_id = max(ids + [9000]) + 1
    gl = _lst(ft, 'goods')
    gl.append({'id': new_id, 'name': name, 'price': price, 'goodsType': gtype,
               'iconTextureName': icon, 'playerId': 1000001, 'saleCnt': 0,
               'upStamp': int(time.time() * 1000), 'goodsContentCnt': 1, 'advert': ''})
    ft['goods'] = gl
    _save(db, 'GOODS_ADD', '%s id=%s price=%s' % (name, new_id, price))
    return redirect('/goods')


@app.route('/goods/<gid>/delete', methods=['POST'])
def goods_delete(gid):
    db, ft = _feat(store.load_db())
    ft['goods'] = [g for g in _lst(ft, 'goods') if str(g.get('id')) != str(gid)]
    _save(db, 'GOODS_DELETE', gid)
    return redirect('/goods')


# ---- 评论 ----
@app.route('/comments')
def comments():
    db, ft = _feat(store.load_db())
    cs = _lst(ft, 'comments')
    blocks = []
    for c in cs[::-1][:120]:
        cid = str(c.get('id', ''))
        blocks.append('<div class="talk"><div class="t">#' + h(cid) + ' · ' + h(c.get('userName')) +
                      ' <span class="muted">' + h(_stamp(c.get('stamp'))) + '</span></div>' +
                      '<div class="m">目标 ' + h(c.get('_kind')) + ' / ' + h(c.get('_target')) +
                      ' · 父评论 ' + h(c.get('_parent')) + '</div>' +
                      '<div>' + h(str(c.get('content') or '')) + '</div>' +
                      '<form method="post" action="/comments/' + h(cid) + '/delete" style="margin-top:8px">' +
                      csrf_hidden() + '<button class="btn gray" type="submit">删除此评论</button></form></div>')
    if not blocks:
        blocks.append('<div class="box"><span class="muted">暂无评论。客户端在动态/作品下发表评论后会出现在这里。</span></div>')
    clear = ('<div class="box"><form method="post" action="/comments/clear">' + csrf_hidden() +
             '<button class="btn gray" type="submit">清空全部评论（' + str(len(cs)) + ' 条）</button></form></div>')
    body = ('<h1>评论管理 <span class="muted">共 ' + str(len(cs)) + ' 条</span></h1>' +
            '<div class="tip">对应客户端 <span class="mono">game_commenttalk</span> / '
            '<span class="mono">game_replytalkcomment</span> 等命令写入的数据，删除后客户端列表立即不再显示。</div>' +
            ''.join(blocks) + clear)
    return Response(page('评论管理', body, 'comments'), mimetype='text/html; charset=utf-8')


@app.route('/comments/<cid>/delete', methods=['POST'])
def comment_delete(cid):
    db, ft = _feat(store.load_db())
    ft['comments'] = [c for c in _lst(ft, 'comments') if str(c.get('id')) != str(cid)]
    _save(db, 'COMMENT_DELETE', cid)
    return redirect('/comments')


@app.route('/comments/clear', methods=['POST'])
def comments_clear():
    db, ft = _feat(store.load_db())
    n = len(_lst(ft, 'comments'))
    ft['comments'] = []
    _save(db, 'COMMENT_CLEAR', 'removed=' + str(n))
    return redirect('/comments')


# ---- 举报（全类型分类 + 处罚） ----
_KIND_LABEL = {
    'game': '作品', 'goods': '商品', 'player': '用户',
    'talk': '动态', 'comment': '评论', 'gamecomment': '作品评论',
    'talkcomment': '动态评论',
}

def _report_kind(r):
    k = str((r or {}).get('kind') or 'other')
    return _KIND_LABEL.get(k, k)

def _report_target_summary(r):
    """按类型给出被举报目标的摘要文字。"""
    r = r or {}
    kind = str(r.get('kind') or '')
    tid = str(r.get('targetId') or '')
    try:
        db, ft = _feat(store.load_db())
        if kind == 'game':
            for g in _lst(ft, 'games'):
                if str(g.get('id')) == tid:
                    return h(g.get('name') or '') + '（作者 ' + h(g.get('_uid') or '?') + '）'
            return '作品 #' + h(tid)
        if kind == 'goods':
            for g in _lst(ft, 'goods'):
                if str(g.get('id')) == tid:
                    return h(g.get('name') or '') + '（卖家 ' + h(g.get('playerId') or '?') + '）'
            return '商品 #' + h(tid)
        if kind == 'player':
            u = db.get('users', {}).get(tid, {})
            return h(u.get('userName') or ('玩家' + tid[-4:])) + '（UID ' + h(tid) + '）'
        if kind in ('comment', 'talkcomment', 'gamecomment'):
            for c in _lst(ft, 'comments'):
                if str(c.get('id')) == tid:
                    return '评论「' + h(str(c.get('content') or '')[:60]) + '」（' + h(c.get('userName') or '?') + '）'
            return '评论 #' + h(tid)
        if kind == 'talk':
            return '动态 #' + h(tid)
    except Exception:
        pass
    return h(tid)

@app.route('/reports')
def reports():
    db, ft = _feat(store.load_db())
    rs = _lst(ft, 'reports')
    cur = (request.args.get('kind') or 'all').strip()
    kinds = ['all', 'game', 'goods', 'player', 'talk', 'comment']
    tabs = []
    for k in kinds:
        cnt = len(rs) if k == 'all' else sum(1 for r in rs if str(r.get('kind')) == k or
                                             (k == 'comment' and str(r.get('kind')) in ('talkcomment', 'gamecomment')))
        label = '全部' if k == 'all' else _KIND_LABEL.get(k, k)
        cls = 'btn sm' + ('' if cur == k else ' gray')
        tabs.append('<a class="' + cls + '" style="text-decoration:none;display:inline-block;margin-right:6px" '
                    'href="/reports?kind=' + k + '">' + h(label) + ' ' + str(cnt) + '</a>')
    filtered = rs if cur == 'all' else [r for r in rs if str(r.get('kind')) == cur or
                                        (cur == 'comment' and str(r.get('kind')) in ('talkcomment', 'gamecomment'))]
    blocks = []
    for r in filtered[::-1][:150]:
        rid = str(r.get('id', ''))
        kind = str(r.get('kind') or '')
        done = bool(r.get('status'))
        target = _report_target_summary(r)
        reason = str(r.get('reason') or '')
        # 处罚动作按类型给
        acts = []
        def form(action, label, cls='btn sm', extra=''):
            return ('<form method="post" action="/reports/' + h(rid) + '/punish" style="display:inline;margin-right:6px">' +
                    csrf_hidden() + '<input type="hidden" name="action" value="' + h(action) + '">' + extra +
                    '<button class="' + cls + '" type="submit">' + h(label) + '</button></form>')
        score_sel = ('<select name="score" style="width:auto;padding:2px"><option value="1">扣1片</option>'
                     '<option value="2">扣2片</option><option value="3">扣3片</option></select>')
        reason_in = ('<input name="reason" placeholder="处罚原因" style="width:120px">')
        if kind == 'game':
            acts.append(form('off_game', '下架作品'))
            acts.append(form('del_game', '删除作品', 'btn sm red'))
            acts.append(form('credit_author', '扣作者叶子', extra=score_sel))
        elif kind == 'goods':
            acts.append(form('off_goods', '下架商品'))
            acts.append(form('del_goods', '删除商品', 'btn sm red'))
            acts.append(form('credit_author', '扣卖家叶子', extra=score_sel))
        elif kind == 'player':
            acts.append(form('credit_target', '扣被举报人叶子', extra=score_sel))
        elif kind == 'talk':
            acts.append(form('del_talk', '删除动态', 'btn sm red'))
            acts.append(form('credit_author', '扣作者叶子', extra=score_sel))
        elif kind in ('comment', 'talkcomment', 'gamecomment'):
            acts.append(form('del_comment', '删除评论', 'btn sm red'))
            acts.append(form('credit_author', '扣评论者叶子', extra=score_sel))
        else:
            acts.append(form('credit_author', '扣作者叶子', extra=score_sel))
        acts.append(form('done', '仅标记处理', 'btn sm gray'))
        acts.append(form('delete', '删举报', 'btn sm gray'))
        blocks.append(
            '<div class="talk"><div class="t">#' + h(rid) + ' · <b>' + h(_report_kind(r)) + '</b> ' +
            ('<span class="badge">已处理</span>' if done else '<span class="badge">待处理</span>') + '</div>' +
            '<div class="m">目标：<b>' + target + '</b></div>' +
            '<div class="m">举报人 ' + h(r.get('userName')) + ' (' + h(r.get('uid')) + ') · ' + h(_stamp(r.get('stamp'))) + '</div>' +
            ('<div class="m">理由：' + h(reason) + '</div>' if reason else '') +
            '<div style="margin-top:8px">' + reason_in + ''.join(acts) + '</div></div>')
    if not blocks:
        blocks.append('<div class="box"><span class="muted">该分类暂无举报记录。</span></div>')
    body = ('<h1>举报管理 <span class="muted">共 ' + str(len(rs)) + ' 条 · 按类型分类处理</span></h1>' +
            '<div class="tip">客户端 game_reporttalk / game_reportgame / game_reportplayer / game_reportgoods '
            '及评论举报入队。选择分类后，按类型执行下架、删除或扣叶子（扣叶子走信誉分 0-3，留明细）。</div>' +
            '<div style="margin:12px 0">' + ''.join(tabs) + '</div>' + ''.join(blocks))
    return Response(page('举报管理', body, 'reports'), mimetype='text/html; charset=utf-8')

@app.route('/reports/<rid>/punish', methods=['POST'])
def report_punish(rid):
    db, ft = _feat(store.load_db())
    action = (request.form.get('action') or '').strip()
    reason = (request.form.get('reason') or '').strip()[:200]
    rep = None
    for r in _lst(ft, 'reports'):
        if str(r.get('id')) == str(rid):
            rep = r
            break
    if rep is None:
        return redirect('/reports')
    kind = str(rep.get('kind') or '')
    tid = str(rep.get('targetId') or '')
    try:
        score = max(1, min(3, int(float(request.form.get('score', '1') or 1))))
    except Exception:
        score = 1
    detail = 'rid=' + str(rid) + ' kind=' + kind + ' action=' + action
    # 找被处罚目标作者 uid
    author_uid = str(rep.get('uid') or '')
    if action in ('credit_author', 'off_game', 'del_game', 'off_goods', 'del_goods', 'del_talk', 'del_comment'):
        if kind == 'game':
            for g in _lst(ft, 'games'):
                if str(g.get('id')) == tid:
                    author_uid = str(g.get('_uid') or author_uid); break
        elif kind == 'goods':
            for g in _lst(ft, 'goods'):
                if str(g.get('id')) == tid:
                    author_uid = str(g.get('playerId') or author_uid); break
        elif kind == 'talk':
            for t in store.load_talks():
                if str(t.get('id')) == tid:
                    author_uid = str(t.get('playerId') or t.get('uId') or author_uid); break
        elif kind in ('comment', 'talkcomment', 'gamecomment'):
            for c in _lst(ft, 'comments'):
                if str(c.get('id')) == tid:
                    author_uid = str(c.get('playerId') or author_uid); break
    if action == 'off_game':
        off = ft.setdefault('offGames', [])
        if tid not in set(str(x) for x in off):
            off.append(tid)
    elif action == 'del_game':
        ft['games'] = [g for g in _lst(ft, 'games') if str(g.get('id')) != tid]
        ft['offGames'] = [x for x in _lst(ft, 'offGames') if str(x) != tid]
    elif action == 'off_goods':
        off = ft.setdefault('offGoods', [])
        if tid not in set(str(x) for x in off):
            off.append(tid)
    elif action == 'del_goods':
        ft['goods'] = [g for g in _lst(ft, 'goods') if str(g.get('id')) != tid]
        ft['offGoods'] = [x for x in _lst(ft, 'offGoods') if str(x) != tid]
    elif action == 'del_talk':
        try:
            store.del_talk(tid)
        except Exception:
            pass
    elif action == 'del_comment':
        ft['comments'] = [c for c in _lst(ft, 'comments') if str(c.get('id')) != tid]
    elif action == 'credit_author':
        if author_uid and author_uid != '0':
            _new = adjust_credit(db, author_uid, -score, reason or ('举报处罚 ' + _report_kind(rep)))
            detail += ' uid=' + author_uid + ' score=-' + str(score)
            if _new <= 0:
                _queue_kick(author_uid, reason or '举报处罚信誉归零')
    elif action == 'credit_target':
        if tid and tid != '0':
            _new = adjust_credit(db, tid, -score, reason or ('举报处罚 ' + _report_kind(rep)))
            detail += ' uid=' + tid + ' score=-' + str(score)
            if _new <= 0:
                _queue_kick(tid, reason or '举报处罚信誉归零')
    elif action == 'done':
        rep['status'] = 1
    elif action == 'delete':
        ft['reports'] = [r for r in _lst(ft, 'reports') if str(r.get('id')) != str(rid)]
        _save(db, 'REPORT_DELETE', detail)
        return redirect('/reports')
    if action != 'done':
        rep['status'] = 1
        rep['punish'] = action
    _save(db, 'REPORT_PUNISH', detail)
    return redirect('/reports')

@app.route('/reports/<rid>/done', methods=['POST'])
def report_done(rid):
    db, ft = _feat(store.load_db())
    for r in _lst(ft, 'reports'):
        if str(r.get('id')) == str(rid):
            r['status'] = 1
    _save(db, 'REPORT_DONE', rid)
    return redirect('/reports')

@app.route('/reports/<rid>/delete', methods=['POST'])
def report_delete(rid):
    db, ft = _feat(store.load_db())
    ft['reports'] = [r for r in _lst(ft, 'reports') if str(r.get('id')) != str(rid)]
    _save(db, 'REPORT_DELETE', rid)
    return redirect('/reports')


# ---- 互动数据 ----
# ==================== 作品管理 ====================
def _builtin_games():
    try:
        import agentsrv
        return [dict(x) for x in agentsrv.GAMES]
    except Exception:
        return []


def _off_ids(ft):
    return set(str(x) for x in _lst(ft, 'offGames'))


def _cover_img(g):
    ic = str(g.get('iconTextureName') or '')
    if not ic:
        return '<span class="muted">无封面</span>'
    return ('<img src="/asset/' + h(ic) + '" style="width:52px;height:52px;object-fit:cover;'
            'border-radius:6px;border:1px solid #e6e8eb" alt="">')


def _work_status(gid, off):
    return ('<span class="badge">已下架</span>' if str(gid) in off
            else '<span class="mono">正常</span>')


@app.route('/asset/<name>')
def asset(name):
    """本地封面/资源代理：CSP img-src 'self'，把 uploads/cover 下的图暴露给后台。"""
    name = os.path.basename(str(name))
    if not name or '/' in name or '\\' in name or '..' in name:
        abort(404)
    p = os.path.join(BASE, 'uploads', 'cover', name)
    if not os.path.isfile(p):
        abort(404)
    import mimetypes
    mt = mimetypes.guess_type(p)[0] or 'application/octet-stream'
    return Response(open(p, 'rb').read(), mimetype=mt)


@app.route('/works')
def works():
    db, ft = _feat(store.load_db())
    games = _lst(ft, 'games')
    builtin = _builtin_games()
    off = _off_ids(ft)
    with_pack = sum(1 for g in games if str(g.get('gameDataCdnUrl') or ''))
    stats = ('<div class="cards">' + _card('玩家发布作品', len(games)) +
             _card('内置测试作品', len(builtin)) +
             _card('已下架(含内置)', len(off)) +
             _card('带可玩包', with_pack) + '</div>')
    tip = ('<div class="tip">作品 = 玩家在编辑器里发布的内容（存 <span class="mono">db.json → feat.games</span>）'
           '+ 12 个内置测试作品（写在 agentsrv.GAMES，只读）。'
           '「可玩包」是发布时上传的 <span class="mono">.bin</span> 工程文件（存 uploads/cover/），'
           '客户端点「开始游戏」时会下载它。<b>改名/换封面/改可玩包/上下架/删除即时生效</b>，'
           '客户端下次刷新即可看到。</div>')

    rows = []
    for g in games[::-1]:
        gid = str(g.get('id'))
        cdn = str(g.get('gameDataCdnUrl') or '')
        pack = ('<span class="mono">' + h(cdn) + '</span>' if cdn
                else '<span class="muted">无</span>')
        cnt = (h(g.get('thumbCnt', 0)) + '/' + h(g.get('collectionCnt', 0)) + '/' +
               h(g.get('playCnt', 0)) + '/' + h(g.get('hurryCnt', 0)))
        offbtn = ('<form method="post" action="/work/' + h(gid) + '/on" style="display:inline">' +
                  csrf_hidden() + '<button class="btn sm gray" type="submit">上架</button></form>'
                  if str(gid) in off else
                  '<form method="post" action="/work/' + h(gid) + '/off" style="display:inline">' +
                  csrf_hidden() + '<button class="btn sm" type="submit">下架</button></form>')
        rows.append(
            '<tr><td>' + _cover_img(g) + '</td>'
            '<td class="mono">' + h(gid) + '</td>'
            '<td><a href="/work/' + h(gid) + '"><b>' + h(g.get('name')) + '</b></a>'
            '<div class="fkey">作者 ' + h(g.get('_uid', '-')) + '</div></td>'
            '<td>' + pack + '</td>'
            '<td class="mono">' + cnt + '</td>'
            '<td class="muted">' + h(_stamp(g.get('_stamp'))) + '</td>'
            '<td>' + _work_status(gid, off) + '</td>'
            '<td><a class="btn sm" href="/work/' + h(gid) + '">编辑</a>' + offbtn +
            '<form method="post" action="/work/' + h(gid) + '/delete" style="display:inline">' + csrf_hidden() +
            '<button class="btn sm red" type="submit">删除</button></form></td></tr>')
    if not rows:
        rows.append('<tr><td colspan="8"><span class="muted">暂无玩家发布的作品。</span></td></tr>')
    table = ('<table><thead><tr><th>封面</th><th>ID</th><th>名称/作者</th><th>可玩包</th>'
             '<th>赞/藏/玩/催</th><th>发布时间</th><th>状态</th><th>操作</th></tr></thead><tbody>' +
             ''.join(rows) + '</tbody></table>')

    brows = []
    for g in builtin:
        gid = str(g.get('id'))
        offbtn = ('<form method="post" action="/work/' + h(gid) + '/on" style="display:inline">' +
                  csrf_hidden() + '<button class="btn sm gray" type="submit">上架</button></form>'
                  if str(gid) in off else
                  '<form method="post" action="/work/' + h(gid) + '/off" style="display:inline">' +
                  csrf_hidden() + '<button class="btn sm" type="submit">下架</button></form>')
        brows.append(
            '<tr><td>' + _cover_img(g) + '</td><td class="mono">' + h(gid) + '</td>'
            '<td><b>' + h(g.get('name')) + '</b></td><td class="mono">' + h(g.get('rank', '-')) + '</td>'
            '<td>' + _work_status(gid, off) + '</td><td>' + offbtn + '</td></tr>')
    btable = ('<table><thead><tr><th>封面</th><th>ID</th><th>名称</th><th>排名</th>'
              '<th>状态</th><th>操作</th></tr></thead><tbody>' + ''.join(brows) + '</tbody></table>')

    # 可玩包下拉候选（uploads/cover 下的 .bin）
    try:
        import glob
        bins = sorted(os.path.basename(x) for x in glob.glob(os.path.join(BASE, 'uploads', 'cover', '*.bin')))
    except Exception:
        bins = []
    dl = ('<datalist id="packlist">' + ''.join(['<option value="' + h(b) + '">' for b in bins]) + '</datalist>')
    addform = ('<div class="box"><h2 style="margin-top:0">新增测试作品</h2>'
               '<form method="post" action="/work/add">'
               '<div class="frow"><label>作品名称</label><input type="text" name="name" value="测试作品"></div>'
               '<div class="frow"><label>封面文件名</label><input type="text" name="icon" value="demo1.png" '
               'placeholder="如 demo1.png，文件需放到 uploads/cover/"></div>'
               '<div class="frow"><label>可玩包(.bin)</label><input type="text" name="cdn" list="packlist" '
               'placeholder="留空则暂不可玩">' + dl + '</div>'
               '<div class="frow"><label>作者UID</label><input type="text" name="uid" value="1000001"></div>'
               '<div class="frow"><label>广告语</label><input type="text" name="advert" value=""></div>' +
               csrf_hidden() + '<button class="btn" type="submit">新增作品</button></form></div>')

    body = ('<h1>作品管理</h1>' + tip + stats +
            '<h2 class="grp">玩家发布的作品</h2>' + table +
            '<h2 class="grp">新增</h2>' + addform +
            '<h2 class="grp">内置测试作品（只读，可下架隐藏）</h2>' + btable)
    return Response(page('作品管理', body, 'works'), mimetype='text/html; charset=utf-8')


@app.route('/work/<gid>')
def work_edit(gid):
    db, ft = _feat(store.load_db())
    rec = None
    for g in _lst(ft, 'games'):
        if str(g.get('id')) == str(gid):
            rec = g
            break
    if not rec:
        return Response('作品不存在（仅玩家作品可编辑，内置作品只读）', status=404, mimetype='text/plain; charset=utf-8')
    off = str(gid) in _off_ids(ft)
    def row(label, name, val, extra=''):
        return ('<div class="frow"><label>' + h(label) + '</label>'
                '<input type="text" name="' + name + '" value="' + h(val) + '">' + extra + '</div>')
    try:
        import glob
        bins = sorted(os.path.basename(x) for x in glob.glob(os.path.join(BASE, 'uploads', 'cover', '*.bin')))
    except Exception:
        bins = []
    dl = '<datalist id="packlist">' + ''.join(['<option value="' + h(b) + '">' for b in bins]) + '</datalist>'
    body = ('<h1>编辑作品 <span class="mono">' + h(gid) + '</span></h1>'
            '<div class="box"><form method="post" action="/work/' + h(gid) + '/save">'
            '<h2 class="grp" style="margin-top:0">基本信息</h2>'
            + row('作品名称', 'name', rec.get('name', ''))
            + row('封面文件名 iconTextureName', 'icon', rec.get('iconTextureName', ''),
                  '<span class="ftip">纯文件名，放 uploads/cover/</span>')
            + row('可玩包 gameDataCdnUrl', 'cdn', rec.get('gameDataCdnUrl', ''),
                  '<span class="ftip">.bin 文件名，留空则点开始游戏无反应</span>' + dl)
            + row('广告语 advert', 'advert', rec.get('advert', ''))
            + row('作者UID', 'uid', rec.get('_uid', ''))
            + '<h2 class="grp">运营数据</h2>'
            + row('排序 rank', 'rank', rec.get('rank', 0))
            + row('点赞 thumbCnt', 'thumbCnt', rec.get('thumbCnt', 0))
            + row('收藏 collectionCnt', 'collectionCnt', rec.get('collectionCnt', 0))
            + row('游玩 playCnt', 'playCnt', rec.get('playCnt', 0))
            + row('催促 hurryCnt', 'hurryCnt', rec.get('hurryCnt', 0))
            + row('状态 status（1=正常）', 'status', rec.get('status', 1))
            + '<div style="margin-top:16px"><button class="btn" type="submit">保存</button>'
            '<a class="btn gray" href="/works">返回作品列表</a></div>'
            + csrf_hidden() + '</form></div>'
            '<div class="tip">当前状态：<b>' + ('已下架' if off else '正常上架') +
            '</b>。上下架请回列表操作（写入 offGames，全客户端即时生效）。</div>')
    return Response(page('编辑作品', body, 'works'), mimetype='text/html; charset=utf-8')


@app.route('/work/<gid>/save', methods=['POST'])
def work_save(gid):
    db, ft = _feat(store.load_db())
    rec = None
    for g in _lst(ft, 'games'):
        if str(g.get('id')) == str(gid):
            rec = g
            break
    if not rec:
        abort(404)
    rec['name'] = request.form.get('name', '')[:80]
    rec['iconTextureName'] = request.form.get('icon', '').strip()[:120]
    rec['gameDataCdnUrl'] = request.form.get('cdn', '').strip()[:160]
    rec['advert'] = request.form.get('advert', '')[:200]
    rec['_uid'] = request.form.get('uid', '').strip()[:40]
    for k in ('rank', 'thumbCnt', 'collectionCnt', 'playCnt', 'hurryCnt', 'status'):
        try:
            rec[k] = int(request.form.get(k, rec.get(k, 0)))
        except Exception:
            pass
    _save(db, 'WORK_SAVE', str(gid) + ' name=' + str(rec['name']))
    return redirect('/works')


@app.route('/work/add', methods=['POST'])
def work_add():
    db, ft = _feat(store.load_db())
    games = ft.setdefault('games', [])
    ids = [F.as_int(g.get('id'), 0) for g in games]
    nid = max(ids + [6000]) + 1
    rec = {
        'id': nid,
        'name': request.form.get('name', '').strip()[:80] or ('测试作品' + str(nid)),
        'iconTextureName': request.form.get('icon', '').strip()[:120] or 'demo1.png',
        'gameDataCdnUrl': request.form.get('cdn', '').strip()[:160],
        'advert': request.form.get('advert', '')[:200],
        '_uid': request.form.get('uid', '').strip()[:40] or '1000001',
        'rank': len(games) + 13, 'thumbCnt': 0, 'collectionCnt': 0,
        'playCnt': 0, 'hurryCnt': 0, 'openCreativeGame': False,
        'lastPublishTime': int(time.time() * 1000), '_stamp': int(time.time() * 1000),
        'status': 1,
    }
    games.append(rec)
    # 同步作者作品数
    try:
        db.setdefault('users', {})
        u = str(rec['_uid'])
        if u in db['users'] and isinstance(db['users'][u], dict):
            db['users'][u]['workCount'] = sum(1 for g in games if str(g.get('_uid')) == u)
    except Exception:
        pass
    _save(db, 'WORK_ADD', str(nid) + ' ' + rec['name'])
    return redirect('/works')


@app.route('/work/<gid>/off', methods=['POST'])
def work_off(gid):
    db, ft = _feat(store.load_db())
    off = ft.setdefault('offGames', [])
    if str(gid) not in set(str(x) for x in off):
        off.append(str(gid))
    _save(db, 'WORK_OFF', str(gid))
    return redirect('/works')


@app.route('/work/<gid>/on', methods=['POST'])
def work_on(gid):
    db, ft = _feat(store.load_db())
    ft['offGames'] = [x for x in _lst(ft, 'offGames') if str(x) != str(gid)]
    _save(db, 'WORK_ON', str(gid))
    return redirect('/works')


@app.route('/work/<gid>/delete', methods=['POST'])
def work_delete(gid):
    db, ft = _feat(store.load_db())
    before = len(_lst(ft, 'games'))
    ft['games'] = [g for g in _lst(ft, 'games') if str(g.get('id')) != str(gid)]
    after = len(ft['games'])
    ft['offGames'] = [x for x in _lst(ft, 'offGames') if str(x) != str(gid)]
    _save(db, 'WORK_DELETE', str(gid) + ' removed=' + str(before - after))
    return redirect('/works')


@app.route('/feat')
def feat_page():
    db, ft = _feat(store.load_db())
    thumbs = _dct(ft, 'thumbs')
    follows = _dct(ft, 'follows')
    fans = _dct(ft, 'fans')
    colls = _dct(ft, 'collections')
    msgs = _lst(ft, 'msgs')
    games = _lst(ft, 'games')
    stats = ('<div class="cards">' + _card('点赞/顶踩记录', len(thumbs)) +
             _card('关注关系', sum(len(v) if isinstance(v, list) else 0 for v in follows.values())) +
             _card('粉丝关系', sum(len(v) if isinstance(v, list) else 0 for v in fans.values())) +
             _card('收藏用户', len(colls)) + _card('评论', len(_lst(ft, 'comments'))) +
             _card('举报', len(_lst(ft, 'reports'))) + _card('消息', len(msgs)) +
             _card('玩家作品', len(games)) + _card('礼物记录', len(_lst(ft, 'gifts'))) +
             _card('编辑器存档用户', len(_dct(ft, 'editor'))) + '</div>')
    mblocks = []
    for m in msgs[::-1][:15]:
        mblocks.append('<div class="talk"><div class="m">' + h(_stamp(m.get('_stamp'))) +
                       ' · 类型 ' + h(m.get('type')) + ' · ' + h(m.get('userName')) +
                       '</div><div>' + h(str(m.get('_text') or '')) + '</div></div>')
    if not mblocks:
        mblocks.append('<div class="box"><span class="muted">暂无消息通知。</span></div>')
    gblocks = []
    for g in games[::-1][:15]:
        gblocks.append('<div class="talk"><div class="t">' + h(g.get('name')) +
                       '</div><div class="m">ID ' + h(g.get('id')) + ' · ' +
                       h(_stamp(g.get('_stamp'))) + ' · 点赞 ' + h(g.get('thumbCnt', 0)) + '</div></div>')
    if not gblocks:
        gblocks.append('<div class="box"><span class="muted">暂无玩家发布的作品（内置测试作品在 agentsrv.GAMES，不在此列）。</span></div>')
    ops = ('<div class="box"><h2 style="margin-top:0">数据维护</h2>' +
           '<form method="post" action="/feat/msgs_clear" style="display:inline-block;margin-right:10px">' +
           csrf_hidden() + '<button class="btn gray" type="submit">清空消息通知</button></form>' +
           '<form method="post" action="/feat/reset" style="display:inline-block">' +
           csrf_hidden() + '<button class="btn gray" type="submit">重置全部互动数据</button></form>' +
           '<div class="muted" style="margin-top:10px">「重置全部互动数据」会清空点赞、关注/粉丝、收藏、评论、'
           '举报、消息、作品、礼物、背包、编辑器存档，<b>保留商品库与用户账号</b>。'
           '仅用于清理测试数据，客户端需重新进入对应页面刷新。</div></div>')
    body = ('<h1>互动数据</h1>' +
            '<div class="tip">这里是功能层 <span class="mono">db.json → feat</span> 的实时快照，'
            '与 WS 服务（agentsrv）共用同一份数据，此处修改后客户端立即读到。</div>' +
            stats + '<h2 class="grp">最近消息通知</h2>' + ''.join(mblocks) +
            '<h2 class="grp">玩家发布的作品</h2>' + ''.join(gblocks) + ops)
    return Response(page('互动数据', body, 'feat'), mimetype='text/html; charset=utf-8')


@app.route('/feat/msgs_clear', methods=['POST'])
def feat_msgs_clear():
    db, ft = _feat(store.load_db())
    n = len(_lst(ft, 'msgs'))
    ft['msgs'] = []
    _save(db, 'FEAT_MSGS_CLEAR', 'removed=' + str(n))
    return redirect('/feat')


@app.route('/feat/reset', methods=['POST'])
def feat_reset():
    db, ft = _feat(store.load_db())
    dict_keys = ('thumbs', 'follows', 'fans', 'newFans', 'collections', 'ranks',
                 'editor', 'inventory', 'flags', 'stats')
    list_keys = ('comments', 'msgs', 'reports', 'games', 'gifts')
    for k in dict_keys:
        ft[k] = {}
    for k in list_keys:
        ft[k] = []
    _save(db, 'FEAT_RESET')
    return redirect('/feat')



# ================= 敏感词管理 =================
SENS_CFG = os.path.join(BASE, 'data', 'sensitive_cfg.json')
SENS_DEFAULT = {
    'enabled': True, 'pear_enabled': True, 'timeout': 2.0,
    'blacklist': ['傻逼', '操你妈', '草泥马', '妈的', '尼玛', 'fuck', 'shit',
                  '裸照', '艳照', '做爱', '奸', '色情', 'AV',
                  '杀人', '自杀', '赌博', '毒品', '法轮', '发票'],
    'whitelist': ['领取', '奖励', '福利', '免费', '签到', '礼包', '活动', '金币', '积分',
                  '皮肤', '攻略', '更新', '版本', '下载', '兑换', '抽奖', '抽卡',
                  '上线', '新手', '登录', '分享', '充值', '返利', '红包', ' reward',
                  '测试', '标题', '内容', '玩家', '游戏', '编辑器', '作品', '发布',
                  '价格', '加我微', '牛逼', '牛B', '厉害'],
}

def sens_load_cfg():
    try:
        d = json.load(open(SENS_CFG, encoding='utf8'))
        if isinstance(d, dict):
            cfg = dict(SENS_DEFAULT); cfg.update(d)
            return cfg
    except Exception:
        pass
    return dict(SENS_DEFAULT)

def sens_save_cfg(cfg):
    tmp = SENS_CFG + '.tmp'
    with open(tmp, 'w', encoding='utf8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    os.replace(tmp, SENS_CFG)

def sens_hits(limit=200):
    """解析 agent.log 里的敏感词命中记录，返回 [(时间, 原文, 命中词)]，最新在前。"""
    out = []
    try:
        with open(os.path.join(BASE, 'logs', 'agent.log'), encoding='utf8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return out
    import re as _re
    for ln in reversed(lines[-4000:]):
        m = _re.search(r'^(\S+)\s+SENSITIVE HIT\s+(\[[^\]]*\])\s+text=\s*(.*)$', ln.rstrip())
        if not m:
            continue
        ts, words, text = m.group(1), m.group(2), m.group(3).strip()
        try:
            wl = ', '.join(json.loads(words.replace("'", '"')))
        except Exception:
            wl = words
        out.append((ts, text[:120], wl))
        if len(out) >= limit:
            break
    return out

@app.route('/sensitive', methods=['GET'])
def sensitive_page():
    cfg = sens_load_cfg()
    hits = sens_hits()
    eb = '<span class="tag ok">开启</span>' if cfg.get('enabled') else '<span class="tag off">关闭</span>'
    pb = '<span class="tag ok">开启</span>' if cfg.get('pear_enabled') else '<span class="tag off">关闭</span>'
    blocks = []
    blocks.append('<div class="cards">'
                  '<div class="card"><span>拦截开关</span><b>' + eb + '</b></div>'
                  '<div class="card"><span>pearapi 并集</span><b>' + pb + '</b></div>'
                  '<div class="card"><span>本地黑名单词</span><b>' + str(len(cfg.get('blacklist', []))) + '</b></div>'
                  '<div class="card"><span>白名单词</span><b>' + str(len(cfg.get('whitelist', []))) + '</b></div>'
                  '</div>')
    blocks.append('<div class="tip">改动配置后即时生效（ agentsrv 每次检测都重新读配置，无需重启）。'
                  '被误杀的正常词加进白名单即可放行；要新增拦截词加进黑名单。'
                  '纯谐音词（如沙雕/啥逼）需手动加入黑名单。</div>')
    # 配置表单
    blocks.append('<div class="box"><h2 style="margin-top:0">检测配置</h2>'
                  '<form method="post" action="/sensitive/save">'
                  + csrf_hidden() +
                  '<div class="frow" style="gap:6px"><label style="width:auto">开启拦截</label><input type="checkbox" name="enabled" value="1" '
                  + ('checked' if cfg.get('enabled') else '') + '></div>'
                  '<div class="frow" style="gap:6px"><label style="width:auto">pearapi 并集</label><input type="checkbox" name="pear_enabled" value="1" '
                  + ('checked' if cfg.get('pear_enabled') else '') + '></div>'
                  '<div class="frow"><label>超时(秒)</label><input name="timeout" type="number" step="0.5" min="0.5" max="10" value="' + h(cfg.get('timeout', 2.0)) + '"></div>'
                  '<div class="frow"><label>黑名单<br><span class="muted">每行一个词</span></label>'
                  '<textarea name="blacklist" rows="6" style="flex:1">' + h('\n'.join(cfg.get('blacklist', []))) + '</textarea></div>'
                  '<div class="frow"><label>白名单<br><span class="muted">每行一个词</span></label>'
                  '<textarea name="whitelist" rows="8" style="flex:1">' + h('\n'.join(cfg.get('whitelist', []))) + '</textarea></div>'
                  '<div style="margin-top:12px"><button class="btn" type="submit">保存配置</button></div>'
                  '</form></div>')
    # 命中记录
    rows = []
    for ts, text, words in hits:
        rows.append('<tr><td class="mono">' + h(ts) + '</td><td>' + h(text) +
                    '</td><td><span class="tag off">' + h(words) + '</span></td></tr>')
    blocks.append('<div class="box"><h2 style="margin-top:0">最近命中记录 <span class="muted">（最新在前）</span></h2>'
                  + ('<table><tr><th>时间</th><th>原文</th><th>命中词</th></tr>' + ''.join(rows) + '</table>'
                     if rows else '<span class="muted">暂无命中记录。</span>') + '</div>')
    body = ''.join(blocks)
    return Response(page('敏感词', body, 'sensitive'), mimetype='text/html; charset=utf-8')

@app.route('/sensitive/save', methods=['POST'])
def sensitive_save():
    cfg = sens_load_cfg()
    cfg['enabled'] = request.form.get('enabled') == '1'
    cfg['pear_enabled'] = request.form.get('pear_enabled') == '1'
    try:
        cfg['timeout'] = float(request.form.get('timeout', 2.0))
    except Exception:
        cfg['timeout'] = 2.0
    cfg['blacklist'] = [w.strip() for w in request.form.get('blacklist', '').splitlines() if w.strip()]
    cfg['whitelist'] = [w.strip() for w in request.form.get('whitelist', '').splitlines() if w.strip()]
    sens_save_cfg(cfg)
    audit('SENSITIVE_SAVE', 'black=%d white=%d enabled=%s' % (
        len(cfg['blacklist']), len(cfg['whitelist']), cfg['enabled']))
    return redirect('/sensitive')

# ================= 敏感词命中看板 =================
@app.route('/senshits')
def senshits_page():
    """解析 agent.log 的 SENSITIVE HIT 行，聚合统计；支持加白名单。"""
    import re as _re
    from collections import OrderedDict
    agg = OrderedDict()   # word -> {'cnt':n,'last':ts,'sample':text}
    try:
        with open(os.path.join(BASE, 'logs', 'agent.log'), encoding='utf8', errors='ignore') as f:
            for ln in f:
                if 'SENSITIVE HIT' not in ln:
                    continue
                # 形如: 2026-11-21T10:05:40 SENSITIVE HIT ['傻逼'] text= '傻逼真啊'
                ts = ln[:19].strip()
                m = _re.search(r"SENSITIVE HIT (\[.*?\])\s+text=\s*(.*)$", ln.strip())
                words, text = [], ''
                if m:
                    try:
                        import ast
                        words = ast.literal_eval(m.group(1))
                        if isinstance(words, str): words = [words]
                    except Exception:
                        words = [m.group(1).strip('[]\'")')]
                    text = m.group(2).strip().strip("'")
                for w in words:
                    w = str(w).strip()
                    if not w:
                        continue
                    if w not in agg:
                        agg[w] = {'cnt': 0, 'last': ts, 'sample': text}
                    agg[w]['cnt'] += 1
                    agg[w]['last'] = ts
                    if text and not agg[w]['sample']:
                        agg[w]['sample'] = text
    except Exception:
        pass

    cfg = sens_load_cfg()
    wl = set(str(x).strip() for x in cfg.get('whitelist', []) if str(x).strip())
    items = sorted(agg.items(), key=lambda kv: kv[1]['cnt'], reverse=True)
    rows = ''
    for w, info in items:
        in_wl = w in wl
        if in_wl:
            btn = '<span class="tag ok">已在白名单</span>'
        else:
            btn = ('<form method="post" action="/senshits/whitelist" style="display:inline">' +
                   csrf_hidden() + '<input type="hidden" name="word" value="' + h(w) + '">' +
                   '<button class="btn sm" type="submit">加白名单</button></form>')
        rows += ('<tr><td>' + h(w) + '</td><td>' + str(info['cnt']) + '</td>'
                 '<td class="mono">' + h(info['last']) + '</td>'
                 '<td>' + (h(info['sample'][:40]) or '<span class="muted">-</span>') + '</td>'
                 '<td>' + btn + '</td></tr>')
    total_hits = sum(v['cnt'] for _, v in items)
    body = ('<h1>敏感词命中看板</h1>'
            '<div class="tip">统计历史命中记录，用于发现误判。点「加白名单」后该词立即放行（热加载，无需重启），'
            '并自动跳转到敏感词配置页确认。命中时间来自 agent.log，为 UTC 时间。</div>'
            '<div class="box"><h2 style="margin-top:0">共 ' + str(len(items)) + ' 个词 · 累计 '
            + str(total_hits) + ' 次命中</h2>'
            + ('<table><thead><tr><th>命中词</th><th>次数</th><th>最近时间(UTC)</th><th>样例文本</th><th>操作</th></tr></thead><tbody>'
               + rows + '</tbody></table>' if rows else '<span class="muted">暂无命中记录。</span>') + '</div>')
    return Response(page('敏感词命中看板', body, 'senshits'), mimetype='text/html; charset=utf-8')


@app.route('/senshits/whitelist', methods=['POST'])
def senshits_whitelist():
    word = (request.form.get('word') or '').strip()
    if word:
        cfg = sens_load_cfg()
        wl = [str(x).strip() for x in cfg.get('whitelist', []) if str(x).strip()]
        if word not in wl:
            wl.append(word)
            cfg['whitelist'] = wl
            sens_save_cfg(cfg)
            audit('SENS_WHITELIST_ADD', word)
    return redirect('/senshits')

# ================= 数据备份与回滚 =================
BACKUP_DIR = os.path.join(BASE, 'data', 'backups')
BACKUP_FILES = {
    'db.json': os.path.join(BASE, 'data', 'db.json'),
    'talks.json': os.path.join(BASE, 'data', 'talks.json'),
    'sensitive_cfg.json': os.path.join(BASE, 'data', 'sensitive_cfg.json'),
}

# 滚动保留：只保留最新的 BACKUP_KEEP 份快照，更早的自动删除（省磁盘）
BACKUP_KEEP = 2

def _prune_backups(keep=None):
    """按目录修改时间排序，保留最新 keep 份，删除更早的。返回被删目录名列表。"""
    keep = BACKUP_KEEP if keep is None else int(keep)
    removed = []
    try:
        entries = []
        for name in os.listdir(BACKUP_DIR):
            d = os.path.join(BACKUP_DIR, name)
            if os.path.isdir(d):
                entries.append((os.path.getmtime(d), name, d))
        entries.sort(reverse=True)   # 最新在前
        for _, name, d in entries[keep:]:
            try:
                import shutil
                shutil.rmtree(d)
                removed.append(name)
            except Exception:
                pass
    except Exception:
        pass
    return removed

def _backup_list():
    out = []
    try:
        for name in sorted(os.listdir(BACKUP_DIR), reverse=True):
            d = os.path.join(BACKUP_DIR, name)
            if not os.path.isdir(d):
                continue
            files = {}
            for fn in BACKUP_FILES:
                fp = os.path.join(d, fn)
                if os.path.exists(fp):
                    files[fn] = os.path.getsize(fp)
            out.append({'name': name, 'files': files,
                        'mtime': os.path.getmtime(d)})
    except Exception:
        pass
    return out

@app.route('/backup')
def backup_page():
    snaps = _backup_list()
    rows = ''
    for sp in snaps:
        fl = ', '.join(sp['files'].keys()) or '<span class="muted">空</span>'
        ts = time.strftime('%F %T', time.localtime(sp['mtime'] + CN_OFFSET))
        rows += ('<tr><td class="mono">' + h(sp['name']) + '</td>'
                 '<td class="muted">' + ts + '</td>'
                 '<td>' + fl + '</td>'
                 '<td>'
                 '<form method="post" action="/backup/restore" style="display:inline" '
                 'onsubmit="return confirm(\'确定回滚到此快照？当前数据会先自动备份一次。\')">' +
                 csrf_hidden() + '<input type="hidden" name="snap" value="' + h(sp['name']) + '">' +
                 '<button class="btn sm" type="submit">回滚</button></form>'
                 '<a class="btn sm gray" href="/backup/download?snap=' + h(sp['name']) + '">下载</a>'
                 '</td></tr>')
    body = ('<h1>备份与回滚</h1>'
            '<div class="tip">快照会完整保存账号/作品/动态/敏感词配置。回滚前系统会<b>自动再备份一次当前数据</b>，'
            '可随时反悔。回滚采用原子写入，不会损坏数据文件。<b>系统自动只保留最新 2 份快照（最新+上次），更早的会删除以节省磁盘。</b>时间为北京时间(UTC+8)。</div>'
            '<div class="box"><h2 style="margin-top:0">立即备份</h2>'
            '<form method="post" action="/backup/create">' + csrf_hidden() +
            '<button class="btn green" type="submit">创建快照</button></form>'
            '<div class="muted" style="margin-top:8px">备份 db.json / talks.json / sensitive_cfg.json 到 '
            '<span class="mono">data/backups/时间戳/</span>。</div></div>'
            '<div class="box"><h2 style="margin-top:0">历史快照 <span class="muted">共 ' + str(len(snaps)) + ' 个</span></h2>'
            + ('<table><thead><tr><th>快照</th><th>创建时间</th><th>包含文件</th><th>操作</th></tr></thead><tbody>'
               + rows + '</tbody></table>' if rows else '<span class="muted">暂无快照，点上方「创建快照」开始。</span>') + '</div>')
    return Response(page('备份回滚', body, 'backup'), mimetype='text/html; charset=utf-8')

@app.route('/backup/create', methods=['POST'])
def backup_create():
    name = time.strftime('%Y%m%d_%H%M%S') + '_' + secrets.token_hex(2)
    d = os.path.join(BACKUP_DIR, name)
    try:
        os.makedirs(d, exist_ok=True)
        import shutil
        made = []
        for fn, src in BACKUP_FILES.items():
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(d, fn))
                made.append(fn)
        pruned = _prune_backups()
        audit('BACKUP_CREATE', name + ' files=' + ','.join(made) +
              (' pruned=' + ','.join(pruned) if pruned else ''))
        return redirect('/backup?done=1')
    except Exception as e:
        audit('BACKUP_FAIL', repr(e)[:200])
        return redirect('/backup?done=0')

@app.route('/backup/download')
def backup_download():
    import io, zipfile
    name = request.args.get('snap', '')
    if not name or '..' in name or '/' in name or '\\' in name:
        abort(400)
    d = os.path.join(BACKUP_DIR, name)
    if not os.path.isdir(d):
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for fn in BACKUP_FILES:
            fp = os.path.join(d, fn)
            if os.path.exists(fp):
                z.write(fp, fn)
    buf.seek(0)
    return Response(buf.getvalue(), mimetype='application/zip',
                    headers={'Content-Disposition': 'attachment; filename="backup_' + name + '.zip"'})

@app.route('/backup/restore', methods=['POST'])
def backup_restore():
    name = (request.form.get('snap') or '').strip()
    if not name or '..' in name or '/' in name or '\\' in name:
        abort(400)
    d = os.path.join(BACKUP_DIR, name)
    if not os.path.isdir(d):
        abort(404)
    try:
        # 回滚前先自动备份当前数据
        pre = os.path.join(BACKUP_DIR, 'pre_restore_' + time.strftime('%Y%m%d_%H%M%S'))
        os.makedirs(pre, exist_ok=True)
        import shutil
        for fn, src in BACKUP_FILES.items():
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(pre, fn))
        # 用原子写入恢复每个快照文件
        done = []
        for fn, dst in BACKUP_FILES.items():
            fp = os.path.join(d, fn)
            if not os.path.exists(fp):
                continue
            obj = json.load(open(fp, encoding='utf8'))
            store._atomic(dst, obj)
            done.append(fn)
        audit('BACKUP_RESTORE', name + ' restored=' + ','.join(done) + ' pre=' + os.path.basename(pre))
        _prune_backups()
        return redirect('/backup?done=1')
    except Exception as e:
        audit('BACKUP_RESTORE_FAIL', repr(e)[:200])
        return redirect('/backup?done=0')

# ================= 全服公告 =================
def _notice_list():
    try:
        db = store.load_db()
        lst = (db.get('feat') or {}).get('notice_list')
        return [x for x in lst if isinstance(x, dict)] if isinstance(lst, list) else []
    except Exception:
        return []

def _notice_save(lst):
    db = store.load_db()
    db.setdefault('feat', {})['notice_list'] = lst
    store.save_db(db)

@app.route('/notice')
def notice_page():
    lst = _notice_list()
    rows = ''
    for i, n in enumerate(lst):
        status = '启用' if str(n.get('status', 1)) != '0' else '停用'
        rows += ('<tr><td class="mono">' + h(n.get('id', i + 1)) + '</td>'
                 '<td>' + h(n.get('title', '')) + '</td>'
                 '<td>' + h(str(n.get('content', ''))[:60]) + '</td>'
                 '<td>' + status + '</td>'
                 '<td><a class="btn sm gray" href="/notice/edit/' + str(i) + '">编辑</a>'
                 '<form method="post" action="/notice/delete" style="display:inline" '
                 'onsubmit="return confirm(\'确定删除此公告？\')">' + csrf_hidden() +
                 '<input type="hidden" name="idx" value="' + str(i) + '">' +
                 '<button class="btn sm" type="submit">删除</button></form></td></tr>')
    body = ('<h1>全服公告</h1>'
            '<div class="tip">公告会在玩家下次进入游戏/刷新配置时显示（非实时推送）。'
            '停服维护前可提前发一条。当前 agentsrv 已支持从此处动态读取。</div>'
            '<div class="box"><h2 style="margin-top:0">新增公告</h2>'
            '<form method="post" action="/notice/add">' + csrf_hidden() +
            '<div style="display:flex;gap:8px;margin-bottom:8px">'
            '<input name="title" placeholder="公告标题" style="flex:1" required>'
            '<input name="content" placeholder="公告内容" style="flex:2" required></div>'
            '<label><input type="checkbox" name="enabled" checked> 启用</label> '
            '<button class="btn green" type="submit" style="margin-left:12px">发布公告</button>'
            '</form></div>'
            '<div class="box"><h2 style="margin-top:0">公告列表 <span class="muted">共 ' + str(len(lst)) + ' 条</span></h2>'
            + ('<table><thead><tr><th>ID</th><th>标题</th><th>内容</th><th>状态</th><th>操作</th></tr></thead><tbody>'
               + rows + '</tbody></table>' if rows else '<span class="muted">暂无公告。</span>') + '</div>')
    return Response(page('全服公告', body, 'notice'), mimetype='text/html; charset=utf-8')

@app.route('/notice/add', methods=['POST'])
def notice_add():
    title = (request.form.get('title') or '').strip()[:100]
    content = (request.form.get('content') or '').strip()[:2000]
    if not title or not content:
        return redirect('/notice')
    lst = _notice_list()
    new_id = max([int(n.get('id', 0) or 0) for n in lst] + [0]) + 1
    lst.append({'id': new_id, 'title': title, 'content': content,
                'type': 1, 'status': 1 if request.form.get('enabled') else 0,
                'sort': new_id, 'startTime': 0, 'endTime': 0})
    _notice_save(lst)
    audit('NOTICE_ADD', str(new_id) + ' ' + title[:40])
    return redirect('/notice')

@app.route('/notice/delete', methods=['POST'])
def notice_delete():
    try:
        idx = int(request.form.get('idx', '-1'))
    except Exception:
        idx = -1
    lst = _notice_list()
    if 0 <= idx < len(lst):
        removed = lst.pop(idx)
        _notice_save(lst)
        audit('NOTICE_DELETE', str(removed.get('id')))
    return redirect('/notice')

@app.route('/notice/edit/<int:idx>', methods=['GET', 'POST'])
def notice_edit(idx):
    lst = _notice_list()
    if not (0 <= idx < len(lst)):
        abort(404)
    n = lst[idx]
    if request.method == 'POST':
        n['title'] = (request.form.get('title') or '').strip()[:100]
        n['content'] = (request.form.get('content') or '').strip()[:2000]
        n['status'] = 1 if request.form.get('enabled') else 0
        _notice_save(lst)
        audit('NOTICE_EDIT', str(n.get('id')) + ' ' + n['title'][:40])
        return redirect('/notice')
    body = ('<h1>编辑公告</h1><div class="box"><form method="post">' + csrf_hidden() +
            '<p>标题：<input name="title" value="' + h(n.get('title', '')) + '" style="width:60%"></p>'
            '<p>内容：<br><textarea name="content" rows="6" style="width:90%">' + h(n.get('content', '')) + '</textarea></p>'
            '<p><label><input type="checkbox" name="enabled"' + (' checked' if str(n.get('status', 1)) != '0' else '') + '> 启用</label></p>'
            '<button class="btn" type="submit">保存</button> '
            '<a class="btn gray" href="/notice">返回</a></form></div>')
    return Response(page('编辑公告', body, 'notice'), mimetype='text/html; charset=utf-8')

# ================= 数据体检 =================# ================= 数据体检 =================
def _health_scan():
    """返回问题列表 [{code,title,detail,fixable,count}]，只读。"""
    issues = []
    try:
        db = store.load_db()
        ft = F.load_feat() if F else {}
    except Exception as e:
        return [{'code': 'err', 'title': '读取失败', 'detail': repr(e), 'fixable': False, 'count': 0}]
    users = db.get('users', {}) or {}
    user_ids = set(str(k) for k in users.keys())
    follows = ft.get('follows', {}) or {}
    fans = ft.get('fans', {}) or {}

    # 1) 自关注
    self_follow, self_fan = [], []
    for uid, lst in follows.items():
        if str(uid) in [str(x) for x in (lst or [])]:
            self_follow.append(str(uid))
    for uid, lst in fans.items():
        if str(uid) in [str(x) for x in (lst or [])]:
            self_fan.append(str(uid))
    if self_follow or self_fan:
        issues.append({'code': 'self', 'title': '自己关注自己',
                       'detail': '关注侧: ' + (','.join(self_follow[:12]) or '无') +
                                 ' | 粉丝侧: ' + (','.join(self_fan[:12]) or '无') +
                                 (' ...' if len(self_follow) + len(self_fan) > 12 else ''),
                       'fixable': True, 'count': len(self_follow) + len(self_fan)})

    # 2) 游客ID 0 污染
    zero_ids = []
    for uid, lst in list(follows.items()) + list(fans.items()):
        if '0' in [str(x) for x in (lst or [])]:
            zero_ids.append(str(uid))
    zero_ids = sorted(set(zero_ids))
    if zero_ids:
        issues.append({'code': 'zero', 'title': '关注/粉丝混入游客ID(0)',
                       'detail': '涉及账号: ' + ','.join(zero_ids[:15]) + (' ...' if len(zero_ids) > 15 else ''),
                       'fixable': True, 'count': len(zero_ids)})

    # 3) 无效引用（指向不存在的账号）
    invalid = set()
    for lst in list(follows.values()) + list(fans.values()):
        for x in (lst or []):
            xs = str(x)
            if xs not in user_ids and xs != '0':
                invalid.add(xs)
    if invalid:
        issues.append({'code': 'invalid', 'title': '关注/粉丝指向不存在的账号',
                       'detail': '无效ID: ' + ','.join(sorted(invalid)[:15]) + (' ...' if len(invalid) > 15 else ''),
                       'fixable': True, 'count': len(invalid)})

    # 4) 重复手机号
    phones = {}
    for uid, u in users.items():
        ph = str((u or {}).get('phone') or '').strip()
        if ph and ph != '0':
            phones.setdefault(ph, []).append(str(uid))
    dups = {ph: uids for ph, uids in phones.items() if len(uids) > 1}
    if dups:
        detail = '; '.join((ph[:3] + '****' + ph[-4:]) + '→' + ','.join(uids)
                           for ph, uids in list(dups.items())[:8])
        issues.append({'code': 'dupphone', 'title': '重复手机号',
                       'detail': detail, 'fixable': False, 'count': len(dups)})

    # 5) 作品作者集中度（信息项）
    works = db.get('works', []) or []
    authors = {}
    for w in works:
        a = str((w or {}).get('authorId') or '')
        authors[a] = authors.get(a, 0) + 1
    if authors:
        top = sorted(authors.items(), key=lambda kv: kv[1], reverse=True)[0]
        issues.append({'code': 'works', 'title': '作品作者分布（信息项）',
                       'detail': '共 %d 个作品；作者 %s 占 %d 个。若其他账号「暂无作品」属正常。' % (
                           len(works), top[0] or '(空)', top[1]),
                       'fixable': False, 'count': len(works)})

    # 6) ID 跳号（信息项）
    nums = sorted(int(x) for x in user_ids if x.isdigit())
    if nums:
        missing = [n for n in range(min(nums), max(nums) + 1) if n not in set(nums)]
        issues.append({'code': 'idgap', 'title': '账号ID连续性（信息项）',
                       'detail': '范围 %d–%d，缺失 %d 个%s' % (
                           min(nums), max(nums), len(missing),
                           ('：' + ','.join(str(x) for x in missing[:10])) if missing else ''),
                       'fixable': False, 'count': len(missing)})
    return issues

@app.route('/health')
def health_page():
    issues = _health_scan()
    fixable = sum(1 for x in issues if x['fixable'])
    rows = ''
    for it in issues:
        if it['fixable']:
            btn = ('<form method="post" action="/health/fix" style="display:inline" '
                   'onsubmit="return confirm(\'确定修复「' + h(it['title']) + '」？将先自动备份数据。\')">' +
                   csrf_hidden() + '<input type="hidden" name="code" value="' + h(it['code']) + '">' +
                   '<button class="btn sm" type="submit">修复</button></form>')
        else:
            btn = '<span class="muted">仅提示</span>'
        cls = 'tag off' if it['fixable'] else 'badge'
        rows += ('<tr><td><span class="' + cls + '">' + h(it['title']) + '</span></td>'
                 '<td>' + str(it['count']) + '</td>'
                 '<td>' + h(it['detail']) + '</td>'
                 '<td>' + btn + '</td></tr>')
    ok = ('<div class="tip" style="background:#eaf7f0;border-color:#c4e8d3;color:#12734a">'
          '未发现可修复的异常，数据状态良好。</div>') if fixable == 0 else ''
    body = ('<h1>数据体检</h1>'
            '<div class="tip">只读扫描账号/关注/粉丝/作品的一致性。点「修复」前系统会自动创建数据快照，'
            '可随时在「备份回滚」页还原。信息项仅作说明，不影响使用。</div>'
            + ok +
            '<div class="box"><h2 style="margin-top:0">扫描结果 <span class="muted">共 ' + str(len(issues)) + ' 项，'
            + str(fixable) + ' 项可修复</span></h2>'
            + ('<table><thead><tr><th>问题</th><th>数量</th><th>详情</th><th>操作</th></tr></thead><tbody>'
               + rows + '</tbody></table>' if rows else '<span class="muted">无数据。</span>') + '</div>')
    return Response(page('数据体检', body, 'health'), mimetype='text/html; charset=utf-8')

@app.route('/health/fix', methods=['POST'])
def health_fix():
    code = (request.form.get('code') or '').strip()
    if code not in ('self', 'zero', 'invalid'):
        audit('HEALTH_FIX_BAD', code)
        abort(400)
    # 修复前自动备份
    try:
        name = 'pre_health_' + time.strftime('%Y%m%d_%H%M%S')
        d = os.path.join(BACKUP_DIR, name)
        os.makedirs(d, exist_ok=True)
        import shutil
        for fn, src in BACKUP_FILES.items():
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(d, fn))
        _prune_backups()
    except Exception:
        pass
    db = store.load_db()
    ft = F.load_feat() if F else {}
    follows = ft.get('follows', {}) or {}
    fans = ft.get('fans', {}) or {}
    user_ids = set(str(k) for k in (db.get('users', {}) or {}).keys())
    changed = 0
    if code == 'self':
        for uid in list(follows.keys()):
            before = len(follows.get(uid) or [])
            follows[uid] = [x for x in (follows.get(uid) or []) if str(x) != str(uid)]
            changed += before - len(follows[uid])
        for uid in list(fans.keys()):
            before = len(fans.get(uid) or [])
            fans[uid] = [x for x in (fans.get(uid) or []) if str(x) != str(uid)]
            changed += before - len(fans[uid])
    elif code == 'zero':
        for src in (follows, fans):
            for uid in list(src.keys()):
                before = len(src.get(uid) or [])
                src[uid] = [x for x in (src.get(uid) or []) if str(x) != '0']
                changed += before - len(src[uid])
    elif code == 'invalid':
        for src in (follows, fans):
            for uid in list(src.keys()):
                before = len(src.get(uid) or [])
                src[uid] = [x for x in (src.get(uid) or []) if (str(x) == '0' or str(x) in user_ids)]
                changed += before - len(src[uid])
    ft['follows'] = follows
    ft['fans'] = fans
    try:
        db['feat'] = ft
        store.save_db(db)
    except Exception as e:
        audit('HEALTH_FIX_FAIL', repr(e)[:200])
        return redirect('/health?done=0')
    audit('HEALTH_FIX', code + ' removed=' + str(changed))
    return redirect('/health?done=1')

# ================= IP 风控 =================
IPBAN_FILE = os.path.join(BASE, 'data', 'ip_blacklist.json')

def _ipban_load():
    try:
        d = json.load(open(IPBAN_FILE, encoding='utf8'))
        ips = d.get('ips') if isinstance(d, dict) else d
        return [str(x).strip() for x in (ips or []) if str(x).strip()]
    except Exception:
        return []

def _ipban_save(ips):
    tmp = IPBAN_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf8') as f:
        json.dump({'ips': ips, '_note': '后台拉黑的公网IP，登录审计页可管理'}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, IPBAN_FILE)

@app.route('/ipban')
def ipban_page():
    ips = _ipban_load()
    rows = ''
    for ip in ips:
        rows += ('<tr><td class="mono">' + h(ip) + '</td>'
                 '<td><form method="post" action="/ipban/remove" style="display:inline">' +
                 csrf_hidden() + '<input type="hidden" name="ip" value="' + h(ip) + '">' +
                 '<button class="btn sm" type="submit">移除</button></form></td></tr>')
    body = ('<h1>IP 风控</h1>'
            '<div class="tip">黑名单用于记录需要重点关注的公网 IP。当前后台展示层已对公网 IP 标红；'
            '如需在登录层真正拦截，需服务端配合（此处先做记录与管理，不误伤正常玩家）。'
            '同时可在此将违规账号叶子（信誉分）扣至 0（即封号，在线立即掉线）。</div>'
            '<div class="box"><h2 style="margin-top:0">加入黑名单</h2>'
            '<form method="post" action="/ipban/add" style="display:flex;gap:8px;align-items:center">' +
            csrf_hidden() + '<input name="ip" placeholder="如 1.2.3.4" style="flex:1">' +
            '<button class="btn" type="submit">加入</button></form></div>'
            '<div class="box"><h2 style="margin-top:0">封禁账号 <span class="muted">叶子扣至0即封号并立即掉线</span></h2>'
            '<form method="post" action="/ipban/ban" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
            csrf_hidden() + '<input name="uid" placeholder="用户ID 如 1000008" style="flex:1">' +
            '<input name="reason" placeholder="封号原因(可选)" style="flex:1">' +
            '<button class="btn red" type="submit" onclick="return confirm(\'确定封号？该账号叶子将扣至0并立即掉线。\')">封号</button>'
            '</form></div>'
            '<div class="box"><h2 style="margin-top:0">IP 黑名单 <span class="muted">共 ' + str(len(ips)) + ' 条</span></h2>'
            + ('<table><thead><tr><th>IP</th><th>操作</th></tr></thead><tbody>' + rows + '</tbody></table>'
               if rows else '<span class="muted">暂无黑名单 IP。</span>') + '</div>')
    return Response(page('IP风控', body, 'ipban'), mimetype='text/html; charset=utf-8')

@app.route('/ipban/add', methods=['POST'])
def ipban_add():
    ip = (request.form.get('ip') or '').strip()
    if not re.match(r'^[0-9a-fA-F:.]{4,45}$', ip):
        audit('IPBAN_BAD', ip)
        return redirect('/ipban')
    ips = _ipban_load()
    if ip not in ips:
        ips.append(ip)
        _ipban_save(ips)
        audit('IPBAN_ADD', ip)
    return redirect('/ipban')

@app.route('/ipban/remove', methods=['POST'])
def ipban_remove():
    ip = (request.form.get('ip') or '').strip()
    ips = [x for x in _ipban_load() if x != ip]
    _ipban_save(ips)
    audit('IPBAN_REMOVE', ip)
    return redirect('/ipban')

@app.route('/ipban/ban', methods=['POST'])
def ipban_ban():
    uid = (request.form.get('uid') or '').strip()
    reason = (request.form.get('reason') or '').strip()[:200] or '后台封号'
    db = store.load_db()
    if uid not in db.get('users', {}):
        return redirect('/ipban?done=0')
    rec = db.setdefault('feat', {}).setdefault('credit', {}).setdefault(uid, {'score': 3, 'list': []})
    rec['score'] = 0
    u = db['users'][uid]
    if isinstance(u, dict):
        u['creditScore'] = 0
    rec.setdefault('list', []).append({'score': -3, 'reason': reason,
                                       'stamp': int(time.time() * 1000)})
    rec['list'] = rec['list'][-50:]
    store.save_db(db)
    _queue_kick(uid, reason)
    audit('IPBAN_BAN', uid + ' reason=' + reason)
    return redirect('/ipban?done=1')

# ================= 登录审计 =================# ================= 登录审计 =================
LOGIN_PATHS = ('v4/login', 'login/token', 'v3/login', 'authusersingle', 'verify/code')

def login_records():
    """从 requests.jsonl 提取登录请求，按时间倒序。先按路径字符串预筛，避免逐行 json.loads。"""
    recs = []
    try:
        with open(os.path.join(BASE, 'logs', 'requests.jsonl'), encoding='utf8', errors='ignore') as f:
            for ln in f:
                if not any(k in ln for k in LOGIN_PATHS):
                    continue
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                p = r.get('path', '')
                if not any(k in p for k in LOGIN_PATHS):
                    continue
                js = r.get('json') or {}
                if not isinstance(js, dict):
                    js = {}
                phone = str(js.get('phoneNumber') or js.get('mobile') or js.get('accountNum') or '')
                dev = str(js.get('deviceId') or '')
                ip = str(r.get('ip') or '')
                recs.append({'ts': cn_iso(r.get('ts', '')), 'phone': phone, 'ip': ip,
                             'dev': dev, 'path': p.split('?')[0],
                             'sys': str(js.get('sysInfo') or '')[:60]})
    except Exception:
        pass
    recs.reverse()
    return recs

@app.route('/loginlog')
def loginlog_page():
    from urllib.parse import urlencode
    q = request.args.get('q', '').strip()
    recs = login_records()
    if q:
        ql = q.lower()
        recs = [r for r in recs if ql in r['phone'].lower() or ql in r['ip'].lower()
                or ql in r['dev'].lower()]
    total = len(recs)
    PER_PAGE = 30
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    try:
        pageno = int(request.args.get('page', '1'))
    except Exception:
        pageno = 1
    if pageno < 1: pageno = 1
    if pageno > pages: pageno = pages
    start = (pageno - 1) * PER_PAGE
    cur = recs[start:start + PER_PAGE]

    def purl(pn):
        params = {}
        if q: params['q'] = q
        params['page'] = pn
        return '/loginlog?' + urlencode(params)

    def navbtn(label, pn, disabled=False):
        if disabled:
            return '<span class="btn gray" style="opacity:.5;pointer-events:none">' + label + '</span>'
        return '<a class="btn gray" href="' + h(purl(pn)) + '">' + label + '</a>'

    rows = []
    blackset = set(_ipban_load())
    for r in cur:
        ipbad = r['ip'] and not r['ip'].startswith(('127.', '10.', '192.168.', '172.'))
        iphtml = '<span class="tag off">' + h(r['ip']) + '</span>' if ipbad else (h(r['ip']) or '<span class="muted">-</span>')
        if r['ip'] in blackset:
            iphtml += ' <span class="tag off">已拉黑</span>'
        elif ipbad:
            iphtml += (' <form method="post" action="/ipban/add" style="display:inline">' +
                       csrf_hidden() + '<input type="hidden" name="ip" value="' + h(r['ip']) + '">' +
                       '<button class="btn sm" type="submit" title="拉黑此IP">拉黑</button></form>')
        rows.append('<tr><td class="mono">' + h(r['ts']) + '</td>'
                    '<td>' + (h(r['phone']) or '<span class="muted">-</span>') + '</td>'
                    '<td>' + iphtml + '</td>'
                    '<td class="mono">' + (h(r['dev'][-18:]) if r['dev'] else '<span class="muted">-</span>') + '</td>'
                    '<td>' + h(r['path']) + '</td></tr>')

    pager = ('<div class="box" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
             + navbtn('首页', 1, pageno <= 1)
             + navbtn('上一页', pageno - 1, pageno <= 1)
             + '<span class="muted" style="margin:0 6px">第 ' + str(pageno) + ' / ' + str(pages)
             + ' 页 · 共 ' + str(total) + ' 条</span>'
             + navbtn('下一页', pageno + 1, pageno >= pages)
             + navbtn('末页', pages, pageno >= pages)
             + '</div>') if total else ''

    body = ('<h1>登录审计</h1>'
            '<div class="tip">来源：客户端登录请求日志（含真实公网 IP）。时间均为北京时间(UTC+8)。红色 IP 为公网来源，请留意陌生地址。'
            '设备号取后 18 位便于辨认。点击手机号登录的 v4/login 记录才带账号，令牌刷新记录可能不带账号。'
            '每页 ' + str(PER_PAGE) + ' 条，分页加载更快。</div>'
            '<div class="box"><form method="get" action="/loginlog" style="display:flex;gap:8px;align-items:center">'
            '<input name="q" value="' + h(q) + '" placeholder="搜索手机号 / IP / 设备号" style="flex:1">'
            '<button class="btn" type="submit">筛选</button>'
            '<a class="btn gray" href="/loginlog">清除</a></form></div>'
            + pager +
            '<div class="box"><h2 style="margin-top:0">登录记录 <span class="muted">共 ' + str(total) + ' 条</span></h2>'
            + ('<table><tr><th>时间</th><th>账号(手机号)</th><th>公网IP</th><th>设备</th><th>接口</th></tr>'
               + ''.join(rows) + '</table>' if rows else '<span class="muted">暂无记录。</span>') + '</div>'
            + pager)
    return Response(page('登录审计', body, 'loginlog'), mimetype='text/html; charset=utf-8')

if __name__ == '__main__':
    import ssl
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = 'privsrv-admin'
    WSGIRequestHandler.sys_version = ''
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    print('[admin] HTTPS 0.0.0.0:%d' % PORT, flush=True)
    app.run(host='0.0.0.0', port=PORT, ssl_context=ctx, threaded=True, debug=False)
