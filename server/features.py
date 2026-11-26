#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""私服统一功能层（core）—— 社交/内容/编辑器/商城共用的数据层与命令分发框架。

设计原则（用户明确要求「不要因为急而做出 bug」）：
1. 不修改 store.py / server.py 的任何现有逻辑；所有新数据放 db.json 顶层键 ``feat``，
   与 store 共用同一把 flock 锁 + 原子替换，跨进程（privsrv/agentsrv/admin）一致。
2. **schema 驱动回包**：客户端 orange.DataBase.setValue 只认「注册字段」，且按注册类型处理
   （0=标量 1=对象 2=数组 3/5=Map 4=Date）。类型给错会让 setValue 抛异常 -> sendAsync
   的 Promise 永远 pending -> 界面卡住。因此每个命令的 payload 先按 protocol.json 里
   该响应类的字段类型生成默认值，业务值覆盖时再强制类型对齐，从根上杜绝这类 bug。
3. 分发完全隔离：agentsrv 只在最后的 else 兜底里调用 dispatch()；未命中返回 None，
   走原有兜底，已跑通的 20 个分支一行都不动。
4. 任何 handler 抛异常都记录日志并回一个 schema 合规的安全 payload，绝不让 WS 连接断掉。
"""
import os, sys, json, time, uuid, copy, traceback, fcntl, tempfile

BASE = '/opt/privsrv'
if BASE not in sys.path:
    sys.path.insert(0, BASE)
DATA = os.path.join(BASE, 'data')
DB_FILE = os.path.join(DATA, 'db.json')
LOCK = os.path.join(DATA, '.store.lock')       # 与 store.py 共用同一把锁
PROTO = os.path.join(DATA, 'protocol.json')
DATA_SCHEMA = os.path.join(DATA, 'data_schema.json')
LOG = os.path.join(BASE, 'logs', 'features.log')

# feat 数据结构（新增字段时只加默认值，不删已有键）
FEAT_DEFAULT = {
    'thumbs': {},        # key "<kind>|<id>" -> {'up':[uid], 'down':[uid], 'like':[uid]}
    'follows': {},       # uid -> [followId,...]
    'fans': {},          # uid -> [fanUid,...]  (反向冗余，便于 getfans)
    'newFans': {},       # uid -> [fanUid,...]  (未读新粉丝)
    'collections': {},   # uid -> {'talk':[], 'games':[], 'goods':[]}
    'comments': [],      # 统一评论表
    'msgs': [],          # 消息/通知
    'reports': [],       # 举报队列
    'ranks': {},         # rankKey -> [score dict]
    'goods': [],         # 商城商品库
    'inventory': {},     # uid -> [goodsId]
    'gifts': [],         # 送礼记录
    'editor': {},        # uid -> {confType: {id: conf}}
    'games': [],         # 用户发布/上传的作品
    'counters': {'comment': 1000, 'goods': 2000, 'game': 3000,
                 'report': 4000, 'msg': 5000, 'conf': 6000, 'talk': 7000,
                 'oim': 8000},
    'flags': {},         # 置顶/精选/开关等杂项
    'stats': {},         # 计数缓存
    # ---- 阶段A/B/C 新增（只加默认值，绝不删已有键；setdefault 语义，清库/旧库均安全）----
    'items': {},         # uid -> [itemId]  道具背包（game_additem）
    'coinDaily': {},     # uid -> {date: cnt}  分享/视频得币每日计数（防刷）
    'gamePlay': {},      # gid -> {playCnt, clickCnt, showCnt, hurryCnt}  作品运营统计
    'offGames': [],      # 已下架作品 id 列表
    'offGoods': [],      # 已下架商品 id 列表
    'gameTags': {},      # gid -> [tag]  作品标签
    'credit': {},        # uid -> {'score': int, 'list': [UserCreditMsg]}  信用分
    'sensitiveWords': [],  # 敏感词库（game_sensitivemsg / 文本校验）
    'commentTop': {},    # "<kind>|<target>" -> [commentId]  置顶评论
    'bindRole': {},      # uid -> 绑定角色信息
    'examScore': {},     # uid -> {'score','best','cnt','stamp'}  考试分数
    # ---- OIM 私聊（只加默认值，setdefault 语义，旧库/清库均安全）----
    'oimMsgs': [],       # OIMMsg 全量消息（双方共用，按 from.id / oppId 过滤）
    'oimBots': [],       # 会自动回复的测试账号 id 列表
    'oimHidden': {},     # uid -> [已删除会话的 oppId]
}

# ------------------------------ 日志 ------------------------------
def log(*a):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, 'a', encoding='utf8') as f:
            f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'),
                                ' '.join(str(x) for x in a)))
    except Exception:
        pass

# ------------------------------ 原子数据读写 ------------------------------
def _lock():
    f = open(LOCK, 'a+')
    fcntl.flock(f, fcntl.LOCK_EX)
    return f

def _unlock(f):
    try: fcntl.flock(f, fcntl.LOCK_UN)
    finally: f.close()

def _atomic(path, obj):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp_', suffix='.json')
    try:
        with os.fdopen(fd, 'w', encoding='utf8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except Exception: pass

def _read(path, default):
    try:
        with open(path, 'r', encoding='utf8') as f:
            return json.load(f)
    except Exception:
        return copy.deepcopy(default)

def _fresh_db():
    db = _read(DB_FILE, {})
    if not isinstance(db, dict): db = {}
    return db

def load_feat():
    """读 feat 快照（加锁，返回深拷贝）。事务内直接返回当前 ft 的拷贝，避免二次加锁。"""
    if _CTX.get('ft') is not None:
        return copy.deepcopy(_CTX['ft'])
    f = _lock()
    try:
        db = _fresh_db()
        ft = db.get('feat') if isinstance(db.get('feat'), dict) else {}
        for k, v in FEAT_DEFAULT.items():
            ft.setdefault(k, copy.deepcopy(v))
        return copy.deepcopy(ft)
    finally:
        _unlock(f)

def save_feat(ft):
    """只更新 db.json 的 feat 键，其它键原样保留（原子替换）。"""
    f = _lock()
    try:
        db = _fresh_db()
        db['feat'] = ft
        _atomic(DB_FILE, db)
    finally:
        _unlock(f)

# 事务上下文：mutate 持锁期间，uid()/coin()/load_feat() 等直接复用已加载的 db，
# 绝不再次 _lock()（flock 同进程不同 fd 也会互相阻塞 -> 自死锁）。
_CTX = {'db': None, 'ft': None}

def ctx_db():
    return _CTX.get('db')

def mutate(fn):
    """在排他锁内完成 读 feat -> fn(ft, db) -> 写回，返回 fn 的返回值。跨进程安全。"""
    f = _lock()
    global _CTX
    prev = dict(_CTX)
    try:
        db = _fresh_db()
        ft = db.get('feat') if isinstance(db.get('feat'), dict) else {}
        for k, v in FEAT_DEFAULT.items():
            ft.setdefault(k, copy.deepcopy(v))
        _CTX = {'db': db, 'ft': ft}
        r = fn(ft, db)
        db['feat'] = ft
        _atomic(DB_FILE, db)
        return r
    finally:
        _CTX = prev
        _unlock(f)

def next_id(ft, kind):
    """自增 ID（数字），保证不与已有数据冲突。"""
    c = ft.setdefault('counters', {})
    n = int(c.get(kind, 1000)) + 1
    c[kind] = n
    return n

def now_ms():
    return int(time.time() * 1000)

def _cur_user():
    """当前会话用户 dict。事务内直接读已加载的 db（不加锁）；否则走 store.current_user。"""
    db = _CTX.get('db')
    try:
        import store
        _suid = store.get_session_uid()
    except Exception:
        _suid = ''
    if isinstance(db, dict):
        cid = str(_suid or db.get('currentUid') or db.get('lastUser') or '')
        u = db.get('users', {}).get(cid) if cid else None
        if isinstance(u, dict): return u
        return {}
    try:
        import store
        u = store.current_user()
        return u if isinstance(u, dict) else {}
    except Exception:
        return {}

def uid(req=None):
    """当前游戏会话用户 id（字符串），取不到返回 ''。优先用本连接绑定 uid。"""
    try:
        import store
        _suid = store.get_session_uid()
        if _suid: return str(_suid)
    except Exception:
        pass
    db = _CTX.get('db')
    if isinstance(db, dict):
        return str(db.get('currentUid') or db.get('lastUser') or '')
    u = _cur_user()
    if u: return str(u.get('userId') or '')
    try:
        import store
        d = store.load_db()
        return str(d.get('currentUid') or d.get('lastUser') or '')
    except Exception:
        return ''

def uname():
    return str(_cur_user().get('userName') or '玩家')

def uimg():
    return str(_cur_user().get('userImg') or '')

def ulevel():
    return _cur_user().get('level', 10)

def coin():
    """当前账号 G币。"""
    return _cur_user().get('coin', 0)

# ------------------------------ 请求参数 ------------------------------
def param(req, name, default=None):
    """从 WS 请求的多个层级取参数（客户端可能把 params 放顶层/body/data/body.params）。"""
    if not isinstance(req, dict): return default
    srcs = [req]
    for k in ('body', 'params', 'data'):
        v = req.get(k)
        if isinstance(v, dict):
            srcs.append(v)
            if isinstance(v.get('params'), dict): srcs.append(v['params'])
            if isinstance(v.get('data'), dict): srcs.append(v['data'])
    for s in srcs:
        if name in s and s[name] not in (None, ''):
            return s[name]
    return default

def first(req, default, *names):
    """按多个候选名依次取参数。"""
    for n in names:
        v = param(req, n)
        if v not in (None, ''): return v
    return default

def as_list(v):
    """把客户端传来的 ids / id 统一成字符串列表。"""
    if v is None: return []
    if isinstance(v, (list, tuple)): return [str(x) for x in v]
    if isinstance(v, dict): return [str(x) for x in v.keys()]
    return [str(v)]

def as_int(v, default=0):
    try: return int(v)
    except Exception: return default

# ------------------------------ 协议表 / schema 驱动 ------------------------------
_PROTO = None
_DSCHEMA = None

def proto():
    global _PROTO
    if _PROTO is None:
        _PROTO = _read(PROTO, {})
    return _PROTO

def data_schema():
    global _DSCHEMA
    if _DSCHEMA is None:
        _DSCHEMA = _read(DATA_SCHEMA, {})
    return _DSCHEMA

def fields_of(cmd):
    """该命令响应类的字段类型表 {field: type}。"""
    p = proto().get(cmd)
    if not p: return {}
    return p.get('fields', {}) or {}

def resp_name(cmd):
    p = proto().get(cmd)
    return p.get('resp', '') if p else ''

# se 类型 -> 默认 Python 值（严格遵守 orange.DataBase.setValue 的类型要求）
_T0 = 0            # 标量：数值最安全（客户端常做算术/比较）
_T1 = dict         # 对象
_T2 = list         # 数组
_T3 = dict         # Map（数字键）
_T4 = int          # Date（时间戳）
_T5 = dict         # Map

def _default_for(t):
    if t == 1: return {}
    if t == 2: return []
    if t in (3, 5): return {}
    if t == 4: return 0
    return 0

def _coerce(value, t):
    """把业务值强制对齐到 schema 类型，避免 setValue 抛异常。"""
    if t == 1:
        return value if isinstance(value, dict) else {}
    if t == 2:
        if isinstance(value, (list, tuple)): return list(value)
        if isinstance(value, dict): return list(value.values())
        return [] if value in (None, 0, '', False) else [value]
    if t in (3, 5):
        return value if isinstance(value, dict) else {}
    if t == 4:
        return as_int(value, 0)
    # t == 0 标量：橙子 setValue 是 r[n]=c 直接赋值，传 dict/list 也合法
    # （例如 TalkData.simpleContent 注册为标量但实际传 {'text':...}）。
    # 因此原样返回，绝不能把容器压成 0，否则评论/动态内容会丢失。
    return value if value is not None else 0

def payload(cmd, **overrides):
    """按协议表生成 schema 合规 payload，业务值覆盖时自动做类型对齐。"""
    fs = fields_of(cmd)
    out = {}
    for f, t in fs.items():
        out[f] = copy.deepcopy(_default_for(t))
    for k, v in overrides.items():
        t = fs.get(k)
        out[k] = _coerce(v, t) if t is not None else v
    # 通用字段（未被响应类注册 -> setValue 跳过，无害；但 make_reply 外层会用）
    out.setdefault('code', 0)
    out.setdefault('msg', 'ok')
    out.setdefault('result', True)
    out.setdefault('success', True)
    out.setdefault('total', 0)
    if 'data' not in out: out['data'] = {}
    if 'list' not in out: out['list'] = []
    return out

def data_obj(kind, **overrides):
    """按客户端数据类 schema 生成一个 UI 可渲染的 dict（未给字段用安全默认值）。"""
    spec = data_schema().get(kind)
    fs = spec.get('fields', {}) if spec else {}
    out = {}
    for f, t in fs.items():
        out[f] = copy.deepcopy(_default_for(t))
    for k, v in overrides.items():
        t = fs.get(k)
        out[k] = _coerce(v, t) if t is not None else v
    return out

# ------------------------------ 命令注册 / 分发 ------------------------------
# 客户端的 Game_RClearNewComment / Game_RClearNewFans / Game_RClearNewMsg 是
# 「空响应类」(class extends re {}，无任何 schema 字段)。它们的回包 body 必须是
# 干净的裸 BON 空对象；若混入 code/msg/data/list 等通用字段，客户端 DecodeMsg
# 会异常 -> SendCmdAsync 完不成 -> 消息中心 refresh() 卡在清红点，后面的列表
# 加载代码永远不执行。handler 返回本哨兵对象时，dispatch 直接返回 {}。
EMPTY_RESP = {}

HANDLERS = {}
_LOADED = False

def register(*cmds):
    """装饰器：把命令绑定到 handler。handler 签名 (req) -> payload dict。"""
    def deco(fn):
        for c in cmds: HANDLERS[c] = fn
        return fn
    return deco

def handles(cmd):
    return cmd in HANDLERS or cmd in proto()

def _load_modules():
    global _LOADED
    if _LOADED: return
    _LOADED = True
    for m in ('feat_social', 'feat_content', 'feat_editor', 'feat_shop', 'feat_oim'):
        try:
            __import__(m)
        except Exception as e:
            log('MODULE_LOAD_FAIL', m, repr(e), traceback.format_exc()[-500:])

def dispatch(cmd, req):
    """返回 payload dict；未注册返回 None（调用方走原兜底）。绝不抛异常。"""
    try:
        _load_modules()
    except Exception as e:
        log('LOAD_FAIL', repr(e))
    # 注入命令名，供 handler 内部分支判断（req 本身可能没带 cmd / 被多层包裹）
    if isinstance(req, dict):
        try: req['_cmd'] = cmd
        except Exception: pass
    fn = HANDLERS.get(cmd)
    if fn is None:
        # 没有专门 handler，但协议表认识这个命令 -> 给一个 schema 合规的空成功回包
        if cmd in proto():
            return payload(cmd)
        return None
    try:
        p = fn(req)
        if p is EMPTY_RESP:
            return {}
        base = payload(cmd)          # schema 全字段默认值（保证不缺字段、类型正确）
        if isinstance(p, dict): base.update(p)
        # 最终保险：所有 schema 字段类型对齐
        for k, t in fields_of(cmd).items():
            if k in base: base[k] = _coerce(base[k], t)
        return base
    except Exception as e:
        log('HANDLER_ERR', cmd, repr(e), traceback.format_exc()[-800:])
        return payload(cmd)

def post_process_all(cmd, payload, req):
    """make_reply 生成 payload 后、bon_encode 之前调用：补强已实现分支的互动数据。
    每个模块的 post_process 自己 try/except，绝不抛到 WS 层。"""
    if not isinstance(payload, dict): return payload
    if not payload: return payload   # 空响应体（EMPTY_RESP）不再被任何模块补字段
    try:
        _load_modules()
    except Exception:
        return payload
    for name in ('feat_social', 'feat_content', 'feat_editor', 'feat_shop', 'feat_oim'):
        m = sys.modules.get(name)
        fn = getattr(m, 'post_process', None) if m else None
        if fn:
            try: fn(cmd, payload, req)
            except Exception as e: log('POST_ERR', name, cmd, repr(e))
    return payload

# ------------------------------ 公共业务工具 ------------------------------
def thumb_key(kind, tid):
    return '%s|%s' % (kind, str(tid))

def thumb_state(ft, kind, tid, myuid):
    """返回 (upCnt, isUp, isDown, likeCnt)。"""
    d = ft.get('thumbs', {}).get(thumb_key(kind, tid), {})
    up = d.get('up', []); down = d.get('down', []); like = d.get('like', [])
    s = str(myuid)
    return max(0, len(up) - len(down)), (s in up), (s in down), len(like)

def set_thumb(ft, kind, tid, myuid, field, on):
    k = thumb_key(kind, tid)
    d = ft.setdefault('thumbs', {}).setdefault(k, {'up': [], 'down': [], 'like': []})
    for f in ('up', 'down', 'like'): d.setdefault(f, [])
    s = str(myuid)
    lst = d[field]
    if on:
        if s not in lst: lst.append(s)
        # 顶/踩互斥
        other = 'down' if field == 'up' else 'up'
        if field in ('up', 'down') and s in d[other]: d[other].remove(s)
    else:
        if s in lst: lst.remove(s)
    return d

def collection_of(ft, myuid, kind):
    return ft.setdefault('collections', {}).setdefault(str(myuid), {}).setdefault(kind, [])

def comment_list(ft, kind, tid, parent=0):
    """取某目标的一级/子评论（parent=0 为一级）。一级评论按「置顶优先 + 时间倒序」。"""
    out = []
    for c in ft.get('comments', []):
        if (str(c.get('_kind')) == str(kind) and str(c.get('_target')) == str(tid)
                and as_int(c.get('_parent'), 0) == as_int(parent, 0)):
            out.append(c)
    out.sort(key=lambda x: as_int(x.get('stamp'), 0), reverse=True)
    # 置顶优先：仅对一级评论生效（子评论保持时间序），commentTop 的 key 为 "<kind>|<target>"
    if as_int(parent, 0) == 0:
        try:
            tops = ft.get('commentTop', {}).get('%s|%s' % (kind, str(tid)), [])
            topset = set(str(x) for x in tops)
            out.sort(key=lambda x: 0 if str(x.get('id')) in topset else 1)
        except Exception:
            pass
    return out

def comment_obj(ft, c, kind, _depth=0):
    """把内部评论记录转成客户端 TalkComment / GameComment 结构。"""
    subs = comment_list(ft, kind, c.get('_target'), c.get('id'))
    base = dict(c)
    base.pop('_kind', None); base.pop('_target', None); base.pop('_parent', None)
    base['comments'] = ([comment_obj(ft, x, kind, _depth + 1) for x in subs[:20]]
                        if _depth < 2 else [])
    base['commentIds'] = [as_int(x.get('id'), 0) for x in subs]
    base['subCommentsCnt'] = len(subs)
    # ★ 详情页 TalkCommentCell.setData 读 e.content.msg（content 是对象）；
    #   内部存储是字符串，直接发字符串会渲染成 undefined。
    #   TalkComment.content 是 se(0) 标量，BON 可直接传 dict，
    #   客户端 setValue 对标量是 r[n]=c 直接赋值，e.content.msg 即可读。
    raw = base.get('content')
    if isinstance(raw, str):
        base['content'] = {'msg': raw}
    elif not isinstance(raw, dict):
        base['content'] = {'msg': '' if raw is None else str(raw)}
    elif 'msg' not in raw:
        base['content'] = dict(raw, msg='')
    # 兼容 CommentMeCell / GameComment 直接读 msg 字段的路径
    base.setdefault('msg', raw if isinstance(raw, str) else
                    (raw.get('msg') if isinstance(raw, dict) else '') or '')
    # ★ TalkCommentCell 的点赞/回复/长按都读 this.data.talkId，并拿它去
    #   loadTalkDetail / sendComment。它必须等于动态唯一主键(hash)，
    #   否则评论点赞、回复、复制场景都会关联到找不到的动态上。
    if kind == 'talk':
        base['talkId'] = str(c.get('_target') or c.get('talkId') or '')
        return data_obj('TalkComment', **base)
    base['gameId'] = str(c.get('_target') or c.get('gameId') or '')
    return data_obj('GameComment', **base)

def find_talk(tid):
    """从 store 动态库找一条动态（用于更新计数），找不到返回 None。
    迁移后 uId == talkId；同时兼容按 uId 传参的历史数据。"""
    try:
        import store
        talks = store.load_talks()
        for t in talks:
            if str(t.get('talkId')) == str(tid) or str(t.get('uId')) == str(tid):
                return t
    except Exception:
        pass
    return None

def patch_talk(tid, patch):
    try:
        import store
        return store.patch_talk(tid, patch)
    except Exception:
        return None

def game_cell(g):
    """把内部作品记录转成 GameCellData。"""
    return data_obj('GameCellData', **g)

def goods_cell(g):
    return data_obj('GoodsCellData', **g)

def user_simple(u, is_follow=False):
    return data_obj('UserSimpleMsg', **{
        'playerId': as_int(u.get('userId'), 0),
        'userName': str(u.get('userName') or ''),
        'userImg': str(u.get('userImg') or ''),
        'userIntro': str(u.get('userIntro') or ''),
        'level': as_int(u.get('level'), 0),
        'isFollow': bool(is_follow),
    })

def add_msg(ft, mtype, from_uid, text='', **kw):
    m = data_obj('MsgData', **{
        'playerId': as_int(from_uid, 0), 'type': as_int(mtype, 0),
        'userName': kw.get('userName', ''), 'userImg': kw.get('userImg', ''),
        'userLevel': kw.get('userLevel', 0),
        'gameId': kw.get('gameId', 0), 'goodsId': kw.get('goodsId', 0),
    })
    m['_id'] = next_id(ft, 'msg')
    m['_text'] = text
    m['_stamp'] = now_ms()
    m['_read'] = False
    ft.setdefault('msgs', []).append(m)
    ft['msgs'] = ft['msgs'][-200:]
    return m
