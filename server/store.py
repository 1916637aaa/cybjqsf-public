import contextvars
# 每个 WebSocket 连接绑定的会话用户 id（asyncio 任务/协程隔离），修复多人串号
SESSION_UID = contextvars.ContextVar('privsrv_session_uid', default='')
def set_session_uid(uid): return SESSION_UID.set(str(uid) if uid else '')
def get_session_uid(): return SESSION_UID.get('')
def clear_session_uid(token=None):
    try: SESSION_UID.reset(token) if token is not None else SESSION_UID.set('')
    except Exception: SESSION_UID.set('')
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""私服共享数据层：用户库 / 动态库 / 会话。跨进程安全（flock + 原子替换）。

server.py(HTTP 8443) / agentsrv.py(WS 8765) / admin.py(后台 HTTPS 38443)
都通过本模块读写，保证「后台改 G币 -> 游戏内 game_login 生效」、
「删用户/动态即时生效」。数据契约见 /opt/privsrv/ARCHITECTURE.md

设计要点：所有读取都每次从文件 load（不缓存），所有写入 flock 排他锁 +
os.replace 原子替换；同一进程内不嵌套加锁，避免死锁。
"""
import os, json, time, uuid, hashlib, tempfile, fcntl, copy

BASE = '/opt/privsrv'
DATA = os.path.join(BASE, 'data')
LOCK = os.path.join(DATA, '.store.lock')
DB_FILE = os.path.join(DATA, 'db.json')
TALK_FILE = os.path.join(DATA, 'talks.json')
os.makedirs(DATA, exist_ok=True)

TOKEN_TTL = 7 * 24 * 3600   # token 有效期 7 天（秒）

DEFAULT_DB = {
    'users': {},        # userId -> user dict
    'tokens': {},       # token  -> userId
    'tokenTimes': {},   # token  -> 签发时间戳(秒)，用于 7 天过期校验；旧token无记录则视为长期有效
    'phoneMap': {},     # phone  -> userId
    'lastUser': '',     # 最近登录 userId
    'currentUid': '',   # 当前游戏会话 userId（authusersingle 时写，agentsrv 读）
    'works': [], 'uploads': [], 'comments': [], 'notices': [],
    'reviews': [],      # 头像审核队列（后台审核 / WS 上传共用）
}

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
    db = _read(DB_FILE, DEFAULT_DB)
    if not isinstance(db, dict): db = copy.deepcopy(DEFAULT_DB)
    for k, v in DEFAULT_DB.items():
        db.setdefault(k, copy.deepcopy(v))
    return db

# ============================ 用户库 ============================
def load_db():
    """每次从文件读（不缓存），保证拿到后台最新改动。"""
    f = _lock()
    try: db = _fresh_db()
    finally: _unlock(f)
    return db

def save_db(db):
    f = _lock()
    try: _atomic(DB_FILE, db)
    finally: _unlock(f)

def default_user(uid, phone='', name=None):
    """新用户默认字段（对齐 server.make_user + coin 统一为 G币）。
    authed 默认 False：蓝V 由后台按需开启，不再有硬编码蓝V账号。"""
    now = int(time.time())
    s = str(uid)
    return {
        'userId': s, 'uniqueId': 'pf_%s' % s,
        'userName': name or ('创游玩家%s' % s[-4:]),
        'phone': phone,
        'coin': 9999, 'gCoin': 9999, 'g币': 9999,   # G币：游戏内 role.coin 取 coin
        'diamond': 100, 'level': 10, 'exp': 500,
        'userImg': '/uploads/cover/avatar.png', 'userIntro': '',
        'userSex': 0, 'city': '', 'province': '',
        'birthday': '1990-01-01', 'isRealName': True, 'authed': False,
        'realName': True, 'realNamed': True, 'brithDay': '1990-01-01',
        'isAdult': True, 'age': 30,
        'shareCode': s[-6:], 'sign': '这个人很懒，什么都没写',
        'gameId': 'cybjq', 'loginPlatform': 1, 'deviceID': '',
        'timestamp': now, 'userPlatforms': ['app-mobile'],
        'hortorChannel': 'hortorTest', 'qqUnionId': '', 'dict': {},
        'followCount': 0, 'fansCount': 0, 'workCount': 0,
    }

# [guest-no-record] 游客虚拟 uid：不入库、不占正式账号 ID；客户端 role 需数字 id，用 0 表示无账号。
GUEST_UID = '0'

def guest_user():
    """游客临时账号（纯内存对象，不写 users 表、不分配 new_user_id）。"""
    u = default_user(GUEST_UID, '__guest_placeholder__', '游客')
    u['userId'] = GUEST_UID
    u['uniqueId'] = 'pf_' + GUEST_UID
    return u


def new_user_id(db):
    n = 1000000
    for k in db['users']:
        try: n = max(n, int(k))
        except Exception: pass
    return str(n + 1)

def issue_token(uid):
    tok = hashlib.md5(('%s|%s|%s' % (uid, time.time(), uuid.uuid4())).encode()).hexdigest()
    f = _lock()
    try:
        db = _fresh_db()
        db['tokens'][tok] = str(uid)
        db.setdefault('tokenTimes', {})[tok] = time.time()   # 记录签发时间，7天有效期
        # 顺带清理已过期的 token（惰性清理，避免无限累积）
        _purge_expired_tokens(db)
        _atomic(DB_FILE, db)
    finally: _unlock(f)
    return tok

def _purge_expired_tokens(db):
    """删除超过 TOKEN_TTL 的 token；无时间记录的旧 token 不动（向后兼容）。"""
    try:
        now = time.time()
        tt = db.get('tokenTimes') or {}
        expired = [t for t, ts in tt.items()
                   if isinstance(ts, (int, float)) and (now - float(ts)) > TOKEN_TTL]
        for t in expired:
            db['tokens'].pop(t, None)
            tt.pop(t, None)
    except Exception:
        pass

def user_by_token(tok):
    db = load_db()
    uid = db['tokens'].get(tok, '')
    if not uid:
        return '', None
    # 7 天有效期校验：有签发记录且超期 -> 视为无效
    ts = (db.get('tokenTimes') or {}).get(tok)
    if isinstance(ts, (int, float)) and (time.time() - float(ts)) > TOKEN_TTL:
        return '', None
    # [guest-no-record] 游客虚拟 uid 不在 users 表，返回内存游客对象
    if str(uid) == GUEST_UID:
        return uid, guest_user()
    return uid, (db['users'].get(uid) if uid else None)

def register_or_login(phone, name=None):
    """任务2 核心：手机号不存在 -> 自动注册新账号；存在 -> 返回该账号。
    返回 (user_dict, is_new)。验证码不在此校验（调用方任意放行）。"""
    f = _lock()
    try:
        db = _fresh_db()
        uid = db['phoneMap'].get(phone, '')
        is_new = False
        if not uid or uid not in db['users']:
            uid = new_user_id(db)
            db['users'][uid] = default_user(uid, phone, name)
            db['phoneMap'][phone] = uid
            is_new = True
        user = db['users'][uid]
        # 强制已实名/正式账号（不弹框），但保留后台改过的 authed(蓝V)/coin 等
        user['isRealName'] = True; user['realNamed'] = True
        user['userPlatforms'] = ['app-mobile']
        user.setdefault('authed', False)
        db['lastUser'] = uid
        db['currentUid'] = uid
        _atomic(DB_FILE, db)
        return dict(user), is_new
    finally:
        _unlock(f)

def user_by_device(dev):
    """按 deviceId 找绑定账号，找不到返回 None。"""
    if not dev:
        return None
    db = load_db()
    uid = (db.get('deviceMap') or {}).get(str(dev), '')
    return db['users'].get(uid) if uid else None

def bind_device(uid, dev):
    """把 deviceId 绑定到账号(仅首次，不覆盖已有绑定)。"""
    if not dev:
        return
    f = _lock()
    try:
        db = _fresh_db()
        dm = db.setdefault('deviceMap', {})
        dm.setdefault(str(dev), str(uid))
        _atomic(DB_FILE, db)
    finally:
        _unlock(f)

def set_current(uid):
    """authusersingle 成功时设定当前游戏会话用户。"""
    f = _lock()
    try:
        db = _fresh_db()
        db['currentUid'] = str(uid); db['lastUser'] = str(uid)
        _atomic(DB_FILE, db)
    finally: _unlock(f)

def current_user():
    """当前会话用户：优先用本连接的 SESSION_UID，回退全局 currentUid。"""
    try:
        db = load_db()
        suid = get_session_uid()
        uid = suid or db.get('currentUid') or db.get('lastUser')
        # [guest-no-record] 游客虚拟 uid 不在 users 表，返回内存游客对象
        if str(uid) == GUEST_UID:
            return guest_user()
        return db['users'].get(uid) if uid else None
    except Exception:
        return None

def gm_ids():
    """蓝V/GM 名单：所有 authed=True 用户 id（数字+字符串），动态生成；
    清空数据后为空数组 = 无蓝V账号。"""
    try:
        db = load_db(); out = []
        for uid, u in db['users'].items():
            if u.get('authed'):
                try: out.append(int(uid))
                except Exception: pass
                out.append(str(uid))
        return out
    except Exception:
        return []

# ============================ 动态库 ============================
def load_talks():
    f = _lock()
    try: d = _read(TALK_FILE, {'talks': []})
    finally: _unlock(f)
    return d.get('talks', []) if isinstance(d, dict) else []

def save_talks(talks):
    f = _lock()
    try: _atomic(TALK_FILE, {'talks': talks[-200:]})
    finally: _unlock(f)

def add_talk(t):
    talks = load_talks()
    t.setdefault('talkId', uuid.uuid4().hex[:12])
    t.setdefault('createStamp', int(time.time() * 1000))
    # ★ 客户端 TalkData 里没有 talkId 字段，uId 才是动态唯一主键：
    #   列表点击 -> TalkScene.setData(this.data.uId) -> loadTalkDetail(uId)
    #   -> game_loadtalkdetail {talkId: uId}。旧实现把 uId 写成作者 uid，
    #   多条动态撞主键，详情永远查不到（正文/评论/点赞/作者全空）。
    #   统一 uId = talkId(hash)，评论 _target / 点赞 key 也用这个 hash。
    t['uId'] = t['talkId']
    talks.append(t); save_talks(talks)
    return t

def del_talk(talk_id):
    talks = load_talks(); n = len(talks)
    talks = [t for t in talks if str(t.get('talkId')) != str(talk_id)]
    save_talks(talks)
    return n - len(talks)

def patch_talk(talk_id, patch):
    talks = load_talks()
    for t in talks:
        if str(t.get('talkId')) == str(talk_id):
            t.update(patch); save_talks(talks); return t
    return None

# ============================ 清空（任务1）============================
def clear_all():
    """删除所有用户 + 动态 + 会话 + token + 蓝V名单，回到干净状态。"""
    f = _lock()
    try:
        _atomic(DB_FILE, copy.deepcopy(DEFAULT_DB))
        _atomic(TALK_FILE, {'talks': []})
        try: _atomic(os.path.join(BASE, 'user_talks.json'), [])   # 兼容旧动态文件
        except Exception: pass
    finally: _unlock(f)
    # 清理会话/序号辅助文件（不影响服务）
    for p in (os.path.join(BASE, 'lx_seq'), os.path.join(BASE, 'lx_mode')):
        pass
    return True
