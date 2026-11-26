#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
私服 HTTP CONNECT 代理 —— 分流版（放行第三方 SDK 域名）
=========================================================
用法：手机（WiFi 代理 或 Postern 一类 VPN 工具）填 <你的服务器IP>:8080

分流规则
--------
1) 私服域名 (*.hortorgames.com / *.hortorinteractive.com) 或私服 IP
   -> 连本机 nginx:443（按 SNI 分发）/ nginx:80（明文 ws）。全程不解析域名。
2) 第三方 SDK 域名（腾讯 / 阿里 / 字节 / Google / 广告聚合 … 白名单）
   -> 直连真实互联网：用本机 DNS 解析真实 IP，建立纯 TCP 隧道，
      TLS 端到端不解密，SDK 证书校验正常通过。
      目的：此前这些域名被 403 拒绝，导致 InitAppSDK() 里的第三方 SDK
      半初始化 + 疯狂重试 -> native 崩溃 -> 进程反复重启（用户看到的闪屏）。
3) 其余域名 -> 403（仍避免变成公网开放代理）

注意：只放行「知名大厂后缀」这一份白名单，且仅做 TCP 转发，不做 MITM。
"""

import socket, threading, sys, os, logging, select, re, ipaddress, time

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
TARGET_HTTPS = ('127.0.0.1', 443)    # nginx，按 SNI 分发
TARGET_HTTP = ('127.0.0.1', 8443)    # Flask 后端
WS_TARGET   = ('127.0.0.1', 80)      # /agent WebSocket (经 nginx 80)

# ---- 私服域名：走本机 nginx（绝不解析真实域名） ----
LOCAL_SUFFIX = ('hortorgames.com', 'hortorinteractive.com')
# 本机公网 IP 从 conf/privsrv.env 注入，不写死任何特定地址。
ALLOW_EXACT = {'127.0.0.1', 'localhost'}
_my_ip = os.environ.get('PRIVSRV_IP', '').strip()
if _my_ip:
    ALLOW_EXACT.add(_my_ip)
_LOCAL_SRC = ALLOW_EXACT | {'::1'}

# ---- 域名严格模式（默认开）----
#   只放行与私服/游戏「有关」的域名（LOCAL 私服域名），其余 CONNECT 一律拒绝，
#   从根上掐掉把本机当成免费开放代理的滥用（境外受限站点、Google/GitHub、广告聚合等）。
#   关闭方法：PROXY_STRICT=0   —— 退回「放行全部第三方」的宽松旧行为。
PROXY_STRICT = os.environ.get('PROXY_STRICT', 'true').lower() not in (
    '0', 'false', 'no', 'off')

# 严格模式下，若确有少量第三方域名需放行，用 PROXY_REMOTE_ALLOW 填写（逗号分隔后缀），默认空。
REMOTE_ALLOW = {x.strip().lower() for x in os.environ.get('PROXY_REMOTE_ALLOW', '').split(',') if x.strip()}

# ---- 第三方域名后缀白名单 ----
# 来源：APK 原生库(.so/dex/xml)硬编码域名 + 线上 requests/代理日志里
#       实际被拒 CONNECT 的域名统计（腾讯/阿里/字节/Google/广告聚合等）。
PASSTHRU_SUFFIX = (
    # 腾讯（h.trace.qq.com / cgi.connect.qq.com / rmonitor.qq.com / gdt / yyb / 微云 …）
    'qq.com', 'gtimg.com', 'gdtimg.com', 'qpic.cn', 'wechat.com',
    'weixinbridge.com', 'qcloud.com', 'myqcloud.com', 'tencent.com',
    'tenpay.com', 'qzone.com', 'soso.com', 'tencentcloudapi.com',
    # 字节 / 穿山甲 / 抖音 / 豆包
    'snssdk.com', 'ctobsnssdk.com', 'amemv.com', 'zijieapi.com',
    'pstatp.com', 'doubao.com', 'bytegecko.com', 'bytedance.com',
    'toutiao.com', 'ixigua.com', 'huoshan.com', 'volces.com',
    'pangolin-sdk-toutiao-b.com', 'chengzijianzhan.com',
    # 阿里 / 支付宝 / 淘宝 / 高德 / 友盟
    'alipay.com', 'alipayobjects.com', 'taobao.com', 'tmall.com',
    'alibaba.com', 'aliyuncs.com', 'aliyun.com', 'amap.com',
    'goofish.com', 'alibaba-inc.com', 'umeng.com', 'umengcloud.com',
    'aliapp.org', 'taobaocdn.com', 'alicdn.com', 'aliexpress.com',
    # Google / Firebase / GMS
    'google.com', 'googleapis.com', 'gstatic.com', 'gvt1.com',
    'gvt2.com', 'gvt3.com', 'googleusercontent.com', 'ggpht.com',
    'firebaseio.com', 'crashlytics.com', 'google-analytics.com',
    'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
    # 广告聚合 / 统计 / 推送（AnyThink-TopOn、UC、搜狗、魅族、B站、快手 …）
    'anythinktech.com', 'rayjump.com', 'ucweb.com', 'sogou.com',
    'meizu.com', 'bilibili.com', 'biliapi.com', 'hdslb.com',
    'gifshow.com', 'kuaishou.com', 'adnxs.com', 'appcenter.ms',
    'office365.com', 'office.com', 'live.com', 'microsoft.com',
    # 国内常见厂商 / 统计 / 下载
    'baidu.com', 'sina.com', 'weibo.com', 'jd.com', '360.cn',
    'qihoo.com', 'xiaomi.com', 'mi.com', 'oppo.com', 'heytap.com',
    'vivo.com', 'honor.com', 'huawei.com', 'samsung.com',
    'flyme.cn', 'lenovo.com', 'gionee.com', 'coolpad.com',
    'applovin.com', 'appsflyer.com', 'adjust.com', 'talkingdata.com',
    'jiguang.cn', 'jpush.cn', 'getui.com', 'igexin.com',
    # 长尾 SDK / CDN 补充（代理日志里出现过、非启动期密集重试）
    'bytednsdoc.com', 'ecombdapi.com', 'douyin.com', 'qishui.com',
    'feishu.cn', 'ttwebview.com', 'uc.cn', 'bilivideo.com',
    'ksapisrv.com', 'bdurl.net', 'bdimg.com', 'bdstatic.com', 'so.com',
    'qlogo.cn', 'gtimg.cn', 'cdn-go.cn', 'ugsdk.cn', 'xiaomi.net',
    'microsoftonline.com', 'bing.com', 'alibabachengdun.com',
    'alibabausercontent.com', 'github.com', 'githubusercontent.com',
    'fbcdn.net', 'nel.goog', 'hoopchina.com.cn', 'httpbin.org',
    'jsonsilo.com', 'ip-api.com', 'myip.la', 'viayoo.com',
)


def _norm(h):
    return h.lower().strip().rstrip('.')


def _match(h, suffixes):
    return any(h == s or h.endswith('.' + s) for s in suffixes)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def is_local(host):
    h = _norm(host)
    return h in ALLOW_EXACT or _match(h, LOCAL_SUFFIX)


def is_passthru(host):
    """第三方域名 / 裸 IP：走真实互联网直连"""
    h = _norm(host)
    return is_ip(h) or _match(h, PASSTHRU_SUFFIX)


def allowed(host):
    """返回 (是否放行, 原因)。域名严格模式只放行「有关域名」。"""
    h = _norm(host)
    if is_local(h):
        return True, 'LOCAL'
    if not PROXY_STRICT:                 # 宽松兼容：放行全部第三方
        return is_passthru(h), 'PASSTHRU'
    if h in REMOTE_ALLOW:                # 严格模式下的极小放行例外
        return True, 'REMOTE_ALLOW'
    return False, 'DENY'

# 拒绝日志节流：同一被拒域名每 300 秒最多记一条 warning，避免 syslog 被刷爆
_deny_ts = {}

def _throttled_deny(host, src):
    now = time.time()
    if now - _deny_ts.get(host, 0) > 300:
        _deny_ts[host] = now
        log.warning('拒绝 CONNECT %s (来自 %s) —— 非有关域名（严格模式）' % (host, src))


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('proxy')


def tunnel(a, b):
    """双向转发"""
    socks = [a, b]
    try:
        while True:
            r, _, e = select.select(socks, [], socks, 300)
            if e or not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except Exception:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


_WL_CACHE = {'t': 0, 'ips': set(), 'strict': False}


def _load_wl():
    """授信设备 IP 白名单（5 秒缓存）。
    strict=false（默认）：只登记/标记，不改变放行行为，避免手机 IP 变动后断连；
    strict=true：仅允许名单内 IP + 本机访问代理。
    """
    import time as _t
    if _t.time() - _WL_CACHE['t'] < 5:
        return _WL_CACHE['ips'], _WL_CACHE['strict']
    try:
        import json as _j
        d = _j.load(open('/opt/privsrv/data/ip_whitelist.json', encoding='utf8'))
        _WL_CACHE['ips'] = set(str(x) for x in d.get('allow', []))
        _WL_CACHE['strict'] = bool(d.get('strict', False))
    except Exception:
        _WL_CACHE['ips'], _WL_CACHE['strict'] = set(), False   # 文件缺失/损坏 -> 退回现状
    _WL_CACHE['t'] = _t.time()
    return _WL_CACHE['ips'], _WL_CACHE['strict']


def handle(client, addr):
    _ips, _strict = _load_wl()
    _src = addr[0]
    if _strict and _src not in _ips and _src not in _LOCAL_SRC:
        log.warning('拒绝来源 IP %s —— 不在授信白名单' % _src)
        try:
            client.close()
        except Exception:
            pass
        return
    if _src in _ips:
        log.info('授信设备 %s 接入' % _src)
    buf = b''
    try:
        while b'\r\n\r\n' not in buf:
            chunk = client.recv(8192)
            if not chunk:
                client.close()
                return
            buf += chunk
        head = buf.split(b'\r\n\r\n')[0].decode('latin-1')
        line = head.split('\r\n')[0]
        method, target, _ = (line.split(' ') + ['', ''])[:3]

        if method.upper() == 'CONNECT':
            host = target.split(':')[0]
            try:
                port = int(target.split(':')[1])
            except Exception:
                port = 443

            ok, why = allowed(host)
            if not ok:
                _throttled_deny(host, addr[0])
                client.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                client.close()
                return

            if is_local(host):
                # 私服：按端口映射到本机对应服务
                #   80    -> nginx 明文 / ws（/agent WebSocket）
                #   443   -> nginx HTTPS（按 SNI 分发到 agentsrv）
                #   38443 -> 后台管理面板（privsrv-admin，HTTPS 自签）
                #   其它  -> nginx:443（默认）
                # 443 走专用 9443(proxy_protocol)，把真实公网IP在TCP层交给nginx
                _use_pp = (port == 443)
                _lp = {80: 80, 443: 9443, 38443: 38443}.get(port, 443)
                log.info('LOCAL     CONNECT %s:%d (来自 %s) -> 127.0.0.1:%d pp=%s'
                         % (host, port, addr[0], _lp, _use_pp))
                try:
                    remote = socket.create_connection(('127.0.0.1', _lp), timeout=15)
                    if _use_pp:
                        try:
                            _cport = addr[1] if len(addr) > 1 else 0
                            _pp = 'PROXY TCP4 %s 127.0.0.1 %d 9443\r\n' % (addr[0], _cport)
                            remote.sendall(_pp.encode('ascii'))
                        except Exception as _ppe:
                            log.warning('PP头发送失败: %s' % _ppe)
                except Exception as e:
                    if _use_pp:
                        try:
                            remote = socket.create_connection(('127.0.0.1', 443), timeout=15)
                            log.warning('9443不可用,回退443(无PP)')
                        except Exception as e2:
                            log.warning('连私服后端失败: %s' % e2)
                            client.close()
                            return
                    else:
                        log.warning('连私服后端失败: %s' % e)
                        client.close()
                        return
            else:
                # 第三方：直连真实 IP，纯 TCP 隧道，TLS 端到端不解密
                log.info('PASSTHRU  CONNECT %s:%d (来自 %s) -> 真实互联网' % (host, port, addr[0]))
                try:
                    remote = socket.create_connection((host, port), timeout=15)
                except Exception as e:
                    log.warning('连第三方失败 %s: %s' % (host, e))
                    client.close()
                    return

            client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        else:
            # 明文请求：优先 WS 握手 -> agent；私服 -> Flask；第三方 -> 真实 80
            is_ws = 'upgrade: websocket' in head.lower()
            m = re.search(r'(?im)^Host:\s*([^\s:]+)', head)
            hhost = m.group(1) if m else ''
            # 绝对 URL 目标（GET http://host/path）里的域名也要参与判定
            t_host = ''
            _m2 = re.match(r'(?i)^https?://([^/:]+)', target)
            if _m2:
                t_host = _m2.group(1).lower()
            # 严格模式对明文 HTTP 同样生效：复用 allowed()（与 CONNECT 分支同源判定），
            # 非有关域名一律 403，堵住「CONNECT 被挡后改用明文 HTTP 继续当免费代理」的绕过口子。
            # Host 头与绝对 URL 里的域名都要校验，防止二者不一致时绕过。
            if PROXY_STRICT:
                for _bad in (t_host, hhost):
                    if _bad and not allowed(_bad)[0]:
                        _throttled_deny(_bad, addr[0])
                        client.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                        client.close()
                        return

            if is_ws:
                log.info('WS  %s %s  (来自 %s)' % (method, target[:60], addr[0]))
                try:
                    remote = socket.create_connection(WS_TARGET, timeout=15)
                except Exception as e:
                    log.warning('连 agent 失败: %s' % e)
                    client.close()
                    return
            elif hhost and not is_local(hhost) and (
                (hhost in REMOTE_ALLOW or t_host in REMOTE_ALLOW) or
                (not PROXY_STRICT and is_passthru(hhost))
            ):
                _dst = t_host or hhost
                log.info('PASSTHRU  HTTP %s %s (来自 %s) -> 真实互联网'
                         % (method, target[:50], addr[0]))
                try:
                    remote = socket.create_connection((_dst, 80), timeout=15)
                except Exception as e:
                    log.warning('连第三方 HTTP 失败 %s: %s' % (_dst, e))
                    client.close()
                    return
            else:
                log.info('%s %s  (来自 %s)' % (method, target[:60], addr[0]))
                try:
                    remote = socket.create_connection(TARGET_HTTP, timeout=15)
                except Exception as e:
                    log.warning('连后端失败: %s' % e)
                    client.close()
                    return
            # === [IPLOG] 注入真实来源 IP 供后端登录日志使用 ===
            try:
                if is_ws or is_local(hhost) or is_local(t_host):
                    _h, _s, _b = buf.partition(b'\r\n\r\n')
                    if _s and _h:
                        _ls = [x for x in _h.split(b'\r\n')
                               if not x.lower().startswith((b'x-real-ip:', b'x-forwarded-for:'))]
                        _ipb = addr[0].encode('ascii', 'ignore')
                        _ls = [_ls[0], b'X-Real-IP: ' + _ipb,
                               b'X-Forwarded-For: ' + _ipb] + _ls[1:]
                        buf = b'\r\n'.join(_ls) + b'\r\n\r\n' + _b
            except Exception:
                pass
            # === [/IPLOG] ===
            remote.sendall(buf)
        tunnel(client, remote)
    except Exception as e:
        log.debug('连接结束 %s: %s' % (addr[0], e))
        try:
            client.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', LISTEN_PORT))
    srv.listen(256)
    log.info('代理启动 0.0.0.0:%d  LOCAL->nginx  PASSTHRU->真实互联网  白名单后缀=%d'
             % (LISTEN_PORT, len(PASSTHRU_SUFFIX)))
    while True:
        try:
            c, addr = srv.accept()
            threading.Thread(target=handle, args=(c, addr), daemon=True).start()
        except Exception as e:
            log.warning('accept 失败: %s' % e)


if __name__ == '__main__':
    main()
