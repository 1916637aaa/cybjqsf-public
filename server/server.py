#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
创游编辑器（com.hortor.creator v0.8.10）私服
================================================
从 APK 逆向还原的服务端实现，用于复活已停服的「创游编辑器」。

还原依据（全部来自 APK 静态分析）：
  * 包名        : com.hortor.creator  版本 0.8.10  渠道 hortorTest
  * 引擎        : Cocos Creator 2.4.2 (cocos2d-js)
  * 域名族      : platform / ucenter-app-server / pay-app-server /
                  anti / speech-recognize-server .hortorgames.com
  * 统一响应体  : {"meta":{"errCode":0,"errMsg":"ok"},"data":{...}}
  * 数据模型    : LoginData / UserInfo / NoticeInfo / SwitchData /
                  AntiAddictionData / HeartBeatData（字段名取自 SDK beans）

设计要点：
  1. 通配路由兜底 —— 未知接口一律返回结构合法的成功响应，保证客户端不崩溃
  2. 全量请求日志 —— 记录 method/host/path/参数，用于把未知业务接口逐个补全
  3. 已知接口精确实现 —— 登录、配置、公告、开关、防沉迷、日志上报
"""

import os, json, time, uuid, hashlib, datetime, traceback, base64, zlib, struct, random
from flask import Flask, request, jsonify, send_from_directory, Response

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, 'data')
LOG_DIR = os.path.join(BASE, 'logs')
STATIC_DIR = os.path.join(BASE, 'uploads')
for d in (DATA_DIR, LOG_DIR, STATIC_DIR):
    os.makedirs(d, exist_ok=True)

REQ_LOG = os.path.join(LOG_DIR, 'requests.jsonl')
DB_FILE = os.path.join(DATA_DIR, 'db.json')

# 共享数据层：用户/动态/会话统一经 store.py（flock + 原子写），
# server(HTTP) / agentsrv(WS) / admin(后台) 三进程实时一致。
import store

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# ---------------------------------------------------------------- 数据层

DEFAULT_DB = {
    'users': {},        # userId -> user
    'tokens': {},       # token -> userId
    'works': [],        # 作品列表
    'uploads': [],      # 上传记录
    'comments': [],     # 评论
    'notices': [],      # 公告
}

def load_db():
    # 委托共享层：每次从 db.json 读最新快照（后台改动即时可见）
    return store.load_db()


def save_db(db):
    # 委托共享层：flock 排他锁 + os.replace 原子写，避免并发写坏
    return store.save_db(db)

# 首次启动植入一批示例数据，让客户端有内容可看（"怀念"用）
def seed(db):
    if db['works']:
        return
    now = int(time.time())
    samples = [
        ('像素冒险：勇者传说', 'RPG冒险', 'demo1'),
        ('二次元校园物语', '剧情', 'demo2'),
        ('机关陷阱大挑战', '闯关', 'demo3'),
        ('我的世界：方块生存', '沙盒', 'demo4'),
        ('弹幕射击：星际迷航', '射击', 'demo5'),
    ]
    for i, (name, cat, icon) in enumerate(samples):
        db['works'].append({
            'id': 10000 + i,
            'workId': 10000 + i,
            'name': name,
            'title': name,
            'desc': f'这是一个由私服恢复的示例作品《{name}》',
            'category': cat,
            'coverUrl': f'/uploads/cover/{icon}.png',
            'iconUrl': f'/uploads/cover/{icon}.png',
            'authorId': '1000001',
            'authorName': '创游小助手',
            'authorAvatar': '/uploads/cover/avatar.png',
            'playCount': 1000 - i * 37,
            'likeCount': 100 - i * 3,
            'starCount': 50 - i,
            'commentCount': 5,
            'createTime': now - i * 86400,
            'updateTime': now - i * 3600,
            'status': 1,
            'isPublished': True,
            'tags': [cat, '示例'],
        })
    db['notices'] = [{
        'id': 1, 'title': '欢迎回到创游编辑器',
        'content': '这是由私服恢复的公告。服务器已停服，本内容仅供怀念。',
        'type': 1, 'status': 1,
        'startTime': now - 86400, 'endTime': now + 86400 * 365,
        'sort': 1, 'interval': 0, 'speed': 0, 'param1': '', 'param2': '', 'param3': '',
        'gameId': 'cybjq', 'originData': '',
    }]
    save_db(db)

db = load_db()
seed(db)

# ---------------------------------------------------------------- 响应封装

# 本机公网 IP 从 conf/privsrv.env 注入，不写死任何特定地址。
GAME_HOSTS = ('cysj.hortorgames.com', 'localhost', '127.0.0.1')
_my_ip = os.environ.get('PRIVSRV_IP', '').strip()
if _my_ip:
    GAME_HOSTS = GAME_HOSTS + (_my_ip,)

def _is_game_host():
    """判断当前请求是否来自游戏自身域名/IP。
    手机把所有流量导给我们的代理：游戏走 cysj.hortorgames.com（或直连 IP），
    第三方 SDK（amdc / 微信 / 阿里 等）走各自的 Host。
    游戏接口必须返回 lz4(bon) 流；第三方接口若返回 lz4 二进制会被 SDK 当成
    非法 JSON 反复重试 -> 初始化卡死。因此按 Host 区分编码方式。"""
    h = (request.host or '').split(':')[0].lower()
    return h in GAME_HOSTS or h == ''


def ok(data=None, **kw):
    """业务成功响应。
    游戏 Host -> lx(lz4) 编码（与客户端 decodeMsg 一致）；
    第三方 Host -> 明文 JSON（避免 SDK 解析失败死循环）。"""
    body = {'meta': {'errCode': 0, 'errMsg': 'ok'}, 'data': data if data is not None else {}}
    body.update(kw)
    if _is_game_host():
        return lx_frame_response(body)
    return jsonify(body)


def ok_json(data=None, **kw):
    """调试/管理接口用：明文 JSON（不被客户端业务层消费）。"""
    body = {'meta': {'errCode': 0, 'errMsg': 'ok'}, 'data': data if data is not None else {}}
    body.update(kw)
    return jsonify(body)


# ---------------------------------------------------------------- lx 编码
# 客户端 cysj 业务层使用自定义 LZ 编码（请求头 Encoding: lx）。
# 从 APK 抓包样本逆出的字面量语法：
#   0x05 <len> <len 个原始字节>          —— 字面量段
#   0x00 00 00 00                        —— 结束标记
# 仅用字面量段即可构成合法的 lx 流（不产生匹配引用），因此服务端只需要编码器。
LX_LIT = 0x05
LX_END = b'\x00\x00\x00\x00'
LX_CHUNK = 100          # 单段最大长度，保证长度字段只占 1 字节


def lx_encode(text):
    b = text.encode('utf8') if isinstance(text, str) else text
    out = bytearray()
    for i in range(0, len(b), LX_CHUNK):
        seg = b[i:i + LX_CHUNK]
        out.append(LX_LIT)
        out.append(len(seg))
        out += seg
    out += LX_END
    return bytes(out)


def lx_response(obj):
    """按 lx 编码返回 JSON 对象（Content-Type/Encoding 与客户端约定一致）"""
    body = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    raw = lx_encode(body)
    resp = Response(raw, status=200, mimetype='application/octet-stream')
    resp.headers['Encoding'] = 'lx'
    resp.headers['X-Lx-Plain-Len'] = str(len(body))
    print('  [lx] 明文 %d 字节 -> 编码 %d 字节' % (len(body), len(raw)), flush=True)
    return resp



# ---------------------------------------------------------------- LZ4 frame
# 客户端 lz4XorDecode -> lz4.decompress(buffer)：期望标准 LZ4 frame。
# 这里构造"未压缩块"帧（合法且不受字典影响）：
#   magic(4) + FLG(1) + BD(1) + HC(1) + [blockSize|0x80000000](4) + 原始数据 + EndMark(4)
_XXP1, _XXP2, _XXP3, _XXP4, _XXP5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
_M32 = 0xFFFFFFFF


def _xxh32(data, seed=0):
    def rl(x, r):
        return ((x << r) | (x >> (32 - r))) & _M32
    n = len(data)
    i = 0
    if n >= 16:
        v1 = (seed + _XXP1 + _XXP2) & _M32
        v2 = (seed + _XXP2) & _M32
        v3 = seed & _M32
        v4 = (seed - _XXP1) & _M32
        vs = [v1, v2, v3, v4]
        while i <= n - 16:
            for k in range(4):
                lane = int.from_bytes(data[i:i + 4], 'little')
                i += 4
                vs[k] = (rl((vs[k] + lane * _XXP2) & _M32, 13) * _XXP1) & _M32
        h = (rl(vs[0], 1) + rl(vs[1], 7) + rl(vs[2], 12) + rl(vs[3], 18)) & _M32
    else:
        h = (seed + _XXP5) & _M32
    h = (h + n) & _M32
    while i <= n - 4:
        h = (h + int.from_bytes(data[i:i + 4], 'little') * _XXP3) & _M32
        h = (rl(h, 17) * _XXP4) & _M32
        i += 4
    while i < n:
        h = (h + data[i] * _XXP5) & _M32
        h = (rl(h, 11) * _XXP1) & _M32
        i += 1
    h ^= h >> 15
    h = (h * _XXP2) & _M32
    h ^= h >> 13
    h = (h * _XXP3) & _M32
    h ^= h >> 16
    return h


def lz4_frame(data):
    b = data.encode('utf8') if isinstance(data, str) else data
    out = bytearray(b'\x04\x22\x4d\x18')
    out.append(0x60)   # FLG: version=01, block independent, 无 checksum/contentSize
    out.append(0x70)   # BD : 4MB 块
    # HC = (XXH32(descriptor, 0) >> 8) & 0xFF —— 真实客户端帧头实测为 0x73
    out.append((_xxh32(bytes([0x60, 0x70])) >> 8) & 0xFF)
    n = len(b)
    out += struct.pack('<I', n | 0x80000000)
    out += b
    out += b'\x00\x00\x00\x00'
    return bytes(out)


# --------------------------------------------------- bon 二进制序列化（逆向确认）
# 客户端 orange.decodeMsg 末尾是 bon.decode(a)，不是 JSON！
# 实测格式：00 null / 01 int32(LE4) / 02 int64(LE8) / 04 double(LE8)
#          05 string(varint len + utf8) / 06 bool(1B)
#          08 object(varint count + kv) / 09 array(varint count)
#          63 + varint idx = 字符串表引用（同一字符串第二次起用引用）
# 长度/计数一律 7bit varint (LEB128)。
class _BonEnc(object):
    def __init__(self):
        self.b = bytearray()
        self.idx = {}
        self.n = 0

    def w7(self, v):
        while True:
            c = v & 0x7f
            v >>= 7
            if v:
                self.b.append(c | 0x80)
            else:
                self.b.append(c)
                return

    def wstr(self, s):
        if s in self.idx:
            self.b.append(0x63)
            self.w7(self.idx[s])
            return
        self.idx[s] = self.n
        self.n += 1
        e = s.encode('utf8')
        self.b.append(5)
        self.w7(len(e))
        self.b += e

    def enc(self, v):
        if v is None:
            self.b.append(0)
        elif v is True:
            self.b += b'\x06\x01'
        elif v is False:
            self.b += b'\x06\x00'
        elif isinstance(v, int):
            if -2147483648 <= v <= 2147483647:
                self.b.append(1)
                self.b += struct.pack('<i', v)
            else:
                self.b.append(2)
                self.b += struct.pack('<q', v)
        elif isinstance(v, float):
            self.b.append(4)
            self.b += struct.pack('<d', v)
        elif isinstance(v, str):
            self.wstr(v)
        elif isinstance(v, (bytearray, bytes)):
            # 实测：0x07 = 二进制块，varint 长度 + 原始字节
            self.b.append(7)
            self.w7(len(v))
            self.b += bytes(v)
        elif isinstance(v, (list, tuple)):
            self.b.append(9)
            self.w7(len(v))
            for x in v:
                self.enc(x)
        elif isinstance(v, dict):
            self.b.append(8)
            self.w7(len(v))
            for k, val in v.items():
                self.wstr(str(k))
                self.enc(val)
        else:
            self.b.append(0)


def bon_encode(v):
    e = _BonEnc()
    e.enc(v)
    return bytes(e.b)


# ------------------------------------------------------- lx 编码（已逆向确认）
# 客户端 orange.lz4XorEncode 算法：
#   e = lz4.compress(data)                      标准 LZ4 frame
#   t = 2..249 随机密钥
#   e[0..min(100,len)-1] ^= t
#   e[0]='p'(112); e[1]='l'(108)
#   e[2] = (e[2]&0xAA) | t 的高 4 位（放在 bit6/4/2/0）
#   e[3] = (e[3]&0xAA) | t 的低 4 位
def lz4_xor_encode(data, key=None):
    import subprocess as _sp
    data = bytes(data)
    # 主路径：用 node + lz4js 复刻客户端 lz4XorEncode，与 App 原生解码 100% 兼容
    try:
        p = _sp.run(['/usr/local/node/bin/node', '/opt/privsrv/lx_lz4.js'],
                    input=data.hex().encode('ascii'),
                    capture_output=True, timeout=30)
        if p.returncode == 0 and p.stdout:
            return bytes.fromhex(p.stdout.decode('ascii').strip())
    except Exception:
        pass
    # 兜底：手写 frame（未压缩 block），保证服务不崩
    b = bytearray(lz4_frame(data))
    t = key if key is not None else random.randint(2, 249)
    n = min(100, len(b))
    for i in range(n):
        b[i] ^= t
    b[0] = 112; b[1] = 108
    b[2] = (0xAA & b[2]) | ((t >> 7 & 1) << 6) | ((t >> 6 & 1) << 4) | ((t >> 5 & 1) << 2) | ((t >> 4 & 1) << 0)
    b[3] = (0xAA & b[3]) | ((t >> 3 & 1) << 6) | ((t >> 2 & 1) << 4) | ((t >> 1 & 1) << 2) | ((t >> 0 & 1) << 0)
    return bytes(b)


def lx_lit_response(obj):
    """纯字面量 lx 流：70 6c ('pl') + [05 len data]* + 00000000"""
    body = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf8')
    out = bytearray(b'pl')
    i = 0
    while i < len(body):
        chunk = body[i:i + 200]
        out.append(0x05)
        out.append(len(chunk))
        out += chunk
        i += len(chunk)
    out += b'\x00\x00\x00\x00'
    resp = Response(bytes(out), status=200, mimetype='application/octet-stream')
    resp.headers['Encoding'] = 'lx'
    print('  [lxlit] 明文 %d -> %d' % (len(body), len(out)), flush=True)
    return resp

def lx_frame_response(obj, key=None):
    # 第三方 Host（amdc / 微信 / 阿里 等 SDK）必须返回明文 JSON，否则 SDK 解析
    # 失败会反复重试，导致 App 初始化卡死。游戏 Host 才走 lz4(bon) 流。
    if not _is_game_host():
        r = jsonify(obj)
        r.headers.pop('Encoding', None)
        return r
    try:
        plain = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    except Exception:
        def _t(v):
            if isinstance(v, (bytes, bytearray)):
                return '<bin %d B>' % len(v)
            if isinstance(v, dict):
                return {k: _t(x) for k, x in v.items()}
            return v
        plain = json.dumps(_t(obj), ensure_ascii=False, separators=(',', ':'))
    payload = bon_encode(obj)
    raw = lz4_xor_encode(payload, key)
    try:
        open(os.path.join(BASE, 'logs', 'last_lx.bin'), 'wb').write(raw)
        open(os.path.join(BASE, 'logs', 'last_lx.txt'), 'w').write(plain)
    except Exception:
        pass
    resp = Response(raw, status=200, mimetype='application/octet-stream')
    resp.headers['Encoding'] = 'lx'
    print('  [lx] bon %d 字节 -> 编码 %d 字节  head=%s' % (len(payload), len(raw), raw[:4].hex()), flush=True)
    return resp

LX_SEQ_FILE = '/opt/privsrv/lx_seq'

def next_seq():
    try:
        n = int((open(LX_SEQ_FILE).read().strip() or '0'))
    except Exception:
        n = 0
    try:
        with open(LX_SEQ_FILE, 'w') as f:
            f.write(str(n + 1))
    except Exception:
        pass
    return n

LX_MODE_FILE = '/opt/privsrv/lx_mode'

def lx_mode():
    """响应策略开关，改文件即时生效、不用重启：echo / result / plain / obj"""
    try:
        with open(LX_MODE_FILE, 'r') as f:
            v = f.read().strip()
        return v or 'obj'
    except Exception:
        return 'obj'

def ok_list(items, total=None, **kw):
    return ok({'list': items, 'total': total if total is not None else len(items),
               'hasMore': False, 'page': 1, 'pageSize': len(items)}, **kw)

# ---------------------------------------------------------------- 用户 / 登录

def new_user_id():
    # 注册 ID 规则：第一个用户 1000001，之后每个新用户 = 当前最大 ID + 1。
    # 纯十进制递增，满 10 自然进位（1000009 -> 1000010），与 store.new_user_id 完全一致。
    # 用 max 而不是 len(users)，删号/插号也不会撞 ID。
    n = 1000000
    for k in (db.get('users') or {}):
        try:
            n = max(n, int(k))
        except Exception:
            pass
    return str(n + 1)

def make_user(uid=None, name=None, platform=0):
    uid = uid or new_user_id()
    name = name or ('创游玩家%s' % uid[-4:])
    now = int(time.time())
    return {
        # —— 字段严格对齐 com.hortorgames.gamesdk.common.beans.UserInfo ——
        'userId': uid,
        'uniqueId': 'pf_%s' % uid,
        'userName': name,
        'userImg': '/uploads/cover/avatar.png',
        'userSex': 0,                 # 0=未知 1=男 2=女
        'city': '', 'province': '', 'birthday': '1990-01-01',
        # 私服：直接标记已实名/成年（SDK 原生层据此决定要不要弹实名框）
        'isRealName': True, 'authed': True,
        'realName': True, 'realNamed': True, 'brithDay': '1990-01-01',
        'isAdult': True, 'age': 30,
        'shareCode': uid[-6:],
        'sign': '这个人很懒，什么都没写',
        'gameId': 'cybjq',
        'loginPlatform': platform,
        'deviceID': '',
        'timestamp': now,
        'userPlatforms': ['app-mobile'],
        'hortorChannel': 'hortorTest',
        'qqUnionId': '', 'dict': {},
        # 扩展字段（社区常见）
        'gCoin': 9999, 'g币': 9999, 'level': 10, 'exp': 500,
        'followCount': 0, 'fansCount': 0, 'workCount': 0,
    }

def ensure_user(uid=None, name=None, platform=0):
    uid = uid or new_user_id()
    if uid not in db['users']:
        db['users'][uid] = make_user(uid, name, platform)
        save_db(db)
    user = db['users'][uid]
    # 私服：无论新老用户都强制为「已实名 + 正式账号」，SDK 不再弹实名/绑定框
    user.update({
        'isRealName': True, 'authed': True,
        'realName': True, 'realNamed': True,
        'birthday': user.get('birthday') or '1990-01-01',
        'brithDay': user.get('brithDay') or '1990-01-01',
        'isAdult': True, 'age': 30,
        'userPlatforms': ['app-mobile'],
        'loginPlatform': 1,
    })
    return user

def issue_token(uid):
    tok = hashlib.md5(('%s|%s|%s' % (uid, time.time(), uuid.uuid4())).encode()).hexdigest()
    db['tokens'][tok] = uid
    save_db(db)
    return tok

def login_payload(user, token):
    """组装 LoginData（对齐 com.hortorgames...beans.LoginData）"""
    return {
        'token': token,
        'userInfo': user,
        'isNewUser': False,
        'needLogin': False,
        'openPayLimit': False,
        'openRealName': False,
        'loginRealName': False,
        # 私服：登录即已实名，platformLogin() 的返回带这些字段，
        # roleLogin 里 C.Ins.realNamed = o.realName / C.Ins.birthDay = o.brithDay
        'realName': True, 'realNamed': True,
        'isRealName': True, 'authed': True,
        'brithDay': '1990-01-01', 'birthDay': '1990-01-01',
        'birthday': '1990-01-01', 'isAdult': True,
        'pingDurationSec': 60,
    }

# ---------------------------------------------------------------- 请求日志

def try_decode(raw_bytes):
    """对 application/octet-stream 请求体尝试常见压缩/编码，返回(算法名, 明文)"""
    if not raw_bytes:
        return None, None
    cands = []
    # 裸 deflate / zlib / gzip / bz2 / lzma
    for name, fn in (('zlib', lambda b: zlib.decompress(b)),
                     ('deflate_raw', lambda b: zlib.decompress(b, -15)),
                     ('gzip', lambda b: zlib.decompress(b, 47))):
        try:
            cands.append((name, fn(raw_bytes)))
        except Exception:
            pass
    try:
        import gzip as _gz
        cands.append(('gzip_mod', _gz.decompress(raw_bytes)))
    except Exception:
        pass
    try:
        import bz2
        cands.append(('bz2', bz2.decompress(raw_bytes)))
    except Exception:
        pass
    try:
        import lzma
        cands.append(('lzma', lzma.decompress(raw_bytes)))
    except Exception:
        pass
    for mod, nm in (('brotli', 'brotli'), ('zstandard', 'zstd'), ('lz4.frame', 'lz4')):
        try:
            m = __import__(mod)
            cands.append((nm, m.decompress(raw_bytes)))
        except Exception:
            pass
    for nm, data in cands:
        try:
            txt = data.decode('utf8')
            if txt.strip()[:1] in '{[':
                return nm, txt
        except Exception:
            pass
    return None, None


def decode_lx_body(raw_bytes):
    """解客户端 lz4XorEncode 请求体（'pl' 头 + 异或密钥藏在前4字节），返回明文；失败返回 ''。"""
    if not raw_bytes or len(raw_bytes) < 8 or bytes(raw_bytes[:2]) != b'pl':
        return ''
    try:
        e = bytearray(raw_bytes)
        t = (((e[2] >> 6) & 1) << 7) | (((e[2] >> 4) & 1) << 6) | \
            (((e[2] >> 2) & 1) << 5) | ((e[2] & 1) << 4) | \
            (((e[3] >> 6) & 1) << 3) | (((e[3] >> 4) & 1) << 2) | \
            (((e[3] >> 2) & 1) << 1) | (e[3] & 1)
        b = bytearray(b'\x04\x22\x4d\x18')
        n = min(100, len(e))
        for i in range(4, n):
            b.append(e[i] ^ t)
        b.extend(e[n:])
        import lz4.frame
        return lz4.frame.decompress(bytes(b)).decode('utf8', 'replace')
    except Exception:
        return ''


def lx_body_fields(raw_bytes):
    """从 authusersingle 的 lx 体里提取本次登录的 userId / phone / visitorUId / token。"""
    import re as _re
    out = {}
    txt = decode_lx_body(raw_bytes)
    if not txt:
        return out
    m = _re.search(r'"userId"\s*:\s*"?(\d{4,10})"?', txt)
    if m:
        out['userId'] = m.group(1)
    m = _re.search(r'"phone"\s*:\s*"([^"]{1,40})"|"phone"\s*:\s*(\d{6,20})', txt)
    if m:
        out['phone'] = m.group(1) or m.group(2)
    m = _re.search(r'(UD-[0-9a-fA-F-]{20,})', txt)
    if m:
        out['deviceId'] = m.group(1)
    m = _re.search(r'(?i)"?token"?\s*[:=]\s*"?([0-9a-f]{32})"?', txt)
    if m:
        out['token'] = m.group(1)
    return out


def log_req(handled_by):
    try:
        raw_b = request.get_data(cache=True) or b''
    except Exception:
        raw_b = b''
    ct = (request.content_type or '').lower()
    algo, decoded = (None, None)
    if raw_b and 'octet-stream' in ct:
        algo, decoded = try_decode(raw_b)
    try:
        # 探针 dump 的源码/节点树分片较大，之前截到 800 导致日志里看不到完整
        # 客户端源码（曾误判 checkUpdateApp 没有兜底 resolve）。放宽到 4000。
        raw = raw_b.decode('utf8', 'replace')[:4000]
    except Exception:
        raw = ''
    b64 = base64.b64encode(raw_b[:16000]).decode() if raw_b else None
    # 记录有信息量的头：token / uid / 自定义字段通常在里面
    keep = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in ('host', 'content-length', 'accept-encoding', 'connection',
                  'user-agent', 'accept', 'accept-language'):
            continue
        keep[k] = v[:200]
    # [IPLOG] 真实来源 IP：代理注入的 X-Real-IP / X-Forwarded-For，兜底 remote_addr
    _xr = (request.headers.get('X-Real-IP') or '').strip()
    _xff = [x.strip() for x in (request.headers.get('X-Forwarded-For') or '').split(',')
            if x.strip() and x.strip() not in ('127.0.0.1', '::1')]
    _cip = (_xr if _xr and _xr not in ('127.0.0.1', '::1') else None) \
           or (_xff[-1] if _xff else None) or request.remote_addr or '?'
    rec = {
        'ts': datetime.datetime.now().isoformat(timespec='seconds'),
        'ip': _cip,
        'host': request.host,
        'method': request.method,
        'path': request.path,
        'handler': handled_by,
        'args': dict(request.args),
        'form': dict(request.form) if request.form else None,
        'json': request.get_json(silent=True),
        'headers': keep,
        'raw': raw or None,
        'raw_b64': b64,
        'decode_algo': algo,
        'decoded': (decoded or '')[:600] or None,
    }
    try:
        with open(REQ_LOG, 'a', encoding='utf8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    flag = '  [已知]' if handled_by != 'fallback' else '  [未知→兜底]'
    print('%-6s %-40s %s%s' % (request.method, request.path, request.host.split(':')[0], flag), flush=True)

# ---------------------------------------------------------------- 路由分发

def get_param(*names, default=''):
    """从 json/form/args 任一处取参数"""
    j = request.get_json(silent=True) or {}
    for n in names:
        for src in (j, request.form, request.args):
            if n in src and src[n] not in (None, ''):
                return src[n]
    return default

# ===== 已知接口 =====

def h_login(path):
    """登录相关：token 登录 / 验证码 / 绑定"""
    global db
    if 'verify/code' in path or 'sms' in path or 'verifyCode' in path:
        # 私服：任意手机号都放行，验证码任意（客户端输 123456 即可）。
        # SDK 判定成功只看 meta.errCode==0，ok() 已保证；再多给常见字段兜底。
        phone_vc = str(get_param('accountNum', 'phoneNumber', 'mobile', 'phone', default='') or '')
        return ok({'sent': True, 'success': True, 'result': True,
                   'code': '123456', 'verifyCode': '123456', 'smsCode': '123456',
                   'interval': 60, 'accountNum': phone_vc,
                   'errCode': 0, 'msg': 'ok'})
    # ===== 实名认证：任意提交/查询都直接判「已实名成年」=====
    # 真实路径 /ucenter-app-server/api/v1/account/name/verification
    # （含 "login"/"verify" 子串会被 h_login 抢先命中，因此必须在这里精确拦截）
    if ('verification' in path or 'realname' in path or 'idcard' in path
            or 'name/check' in path or 'name/auth' in path):
        j = request.get_json(silent=True) or {}
        info = {'isRealName': True, 'realName': True, 'realNamed': True, 'authed': True, 'isAdult': True, 'valid': True, 'birthday': '1990-01-01', 'brithDay': '1990-01-01', 'birthDay': '1990-01-01', 'result': True, 'success': True, 'code': 0, 'errCode': 0, 'msg': 'ok'}
        info.update({'name': str(j.get('name') or ''),
                     'idCard': str(j.get('idCard') or ''),
                     'uniqueId': str(j.get('uniqueId') or '')})
        return ok(info, isRealName=True, realName=True, realNamed=True,
                  authed=True, success=True, result=True)
    uid = str(get_param('userId', 'uid', 'openId', 'uniqueId', default='') or '')
    name = get_param('nickName', 'userName', 'name', default=None)
    phone = str(get_param('phoneNumber', 'accountNum', 'mobile', 'phone', default='') or '')
    is_authuser = ('authusersingle' in path or 'authuser' in path)
    # 验证码一律放行：本私服不校验 smsCode / verifyCode，随便填即可登录。

    # ===== 任务2：手机号 + 任意验证码登录 =====
    #   * 手机号存在 -> 未注册则自动注册新账号，已注册则登录该账号（同一 userId）
    #   * authusersingle（二进制压缩流，取不到参数）-> 用 token / 当前会话定位账号
    if phone:
        user, _is_new = store.register_or_login(phone, name)
        uid = str(user['userId'])
        db = store.load_db()
    elif is_authuser:
        # [multiuser-fix-v3] authusersingle 的凭据在 lz4Xor 编码的二进制 body 里，
        # get_param 取不到；此前一律回退到写死的 13800000000(=账号1000020)，
        # 导致所有人无论输什么手机号都登成 1000020 —— 这是本次串号根因。
        # 现在解开 body，用本次登录服务端刚下发的 info.userId/phone 定位账号。
        raw_body = request.get_data(cache=True) or b''
        fields = lx_body_fields(raw_body)
        tok = str(get_param('token', 'accessToken', 'roleToken', default='') or fields.get('token', ''))
        _tid, tu = store.user_by_token(tok) if tok else ('', None)
        if not tu and fields.get('userId'):
            tu = store.load_db()['users'].get(str(fields['userId']))
        if not tu and fields.get('phone'):
            _uid = store.load_db().get('phoneMap', {}).get(str(fields['phone']), '')
            tu = store.load_db()['users'].get(_uid) if _uid else None
        _dev = fields.get('deviceId') or str(get_param('deviceId', 'deviceID', 'udid', default='') or '')
        if not tu and _dev:
            tu = store.user_by_device(_dev)
        if tu:
            uid = str(tu['userId'])
            store.set_current(uid)
            if _dev:
                store.bind_device(uid, _dev)
            user = dict(store.load_db()['users'].get(uid) or tu)
        else:
            # [guest-no-record] 完全身份不明的静默登录 -> 内存游客 uid=0，不写账号表、
            # 不占正式 ID。真人手机号登录走 phone 分支拿真实账号，有设备绑定者走上面 tu 分支。
            user = store.guest_user()
            uid = str(user['userId'])
            store.set_current(uid)
        db = store.load_db()
    else:
        # [multiuser-fix-v2] login/token：token 有效就用它；失效时用 deviceId 建/找独立账号，
        # 绝不回退全局 current_user()(那会把每个设备都登成最后登录的人 = 串号根因)。
        tok = str(get_param('token', 'accessToken', 'roleToken', default='') or '')
        _tid, tu = store.user_by_token(tok) if tok else ('', None)
        _dev = str(get_param('deviceId', 'deviceID', 'udid', default='') or '')
        if not tu and _dev:
            tu = store.user_by_device(_dev)
        if tu:
            uid = str(tu['userId'])
            user = dict(store.load_db()['users'].get(uid) or tu)
        else:
            # [guest-no-record] token 失效且设备未绑定 -> 内存游客 uid=0，不写账号表、
            # 不占正式 ID。真人登录走 v4/login 的 phone 分支拿真实账号。
            user = store.guest_user()
            uid = str(user['userId'])
        db = store.load_db()
    token = store.issue_token(uid)

    # 业务服务单点登录：用 ucenter 的 token 换业务 session（参数是二进制压缩流）
    if 'authusersingle' in path or 'authuser' in path:
        mode = lx_mode()
        raw_body = request.get_data()
        # [guest-no-formal-flag] 游客占位号（身份不明兜底）不发放正式账号标识。
        # 判定依据：只有兜底游客号用固定 phone __guest_placeholder__，真人号均为真实手机号。
        _is_guest = (str(user.get('phone', '')) == '__guest_placeholder__')
        payload = dict(user)
        payload.update({
            'token': token, 'sessionId': token, 'accessToken': token,
            # 客户端随后用 roleToken 建立 /agent 的 WebSocket 连接
            'roleToken': token, 'roleId': user['userId'],
            'isNew': False, 'isNewUser': False,
            # 游客号保持 needBind=True，让客户端认作游客、引导去绑定/登录；真人号 False。
            'needBind': _is_guest,
            # 正式账号标记：仅真人号发放；游客号去掉，避免冒充正式账号。
            'bindInfo': ({} if _is_guest else {'bindType': 'app-mobile', 'bindPlatformUId': user['uniqueId']}),
            'bindPlatformUId': ('' if _is_guest else user['uniqueId']),
            'isAppVisitor': _is_guest,
            # 私服：已实名成年（SDK 原生实名框不再弹）
            'realName': True, 'realNamed': True, 'isRealName': True,
            'authed': True, 'isAdult': True,
            'birthDay': '1990-01-01', 'brithDay': '1990-01-01',
            'birthday': '1990-01-01',
        })
        if mode == 'echo' and raw_body:
            resp = Response(raw_body, status=200, mimetype='application/octet-stream')
            resp.headers['Encoding'] = 'lx'
            print('  [lx] echo %d' % len(raw_body), flush=True)
            return resp

        def plain(obj):
            r = jsonify(obj)
            r.headers.pop('Encoding', None)
            return r

        if mode == 'seq':
            idx = next_seq() % 7
            tag = 'seq#%d' % idx
        else:
            idx = {'frame': 0, 'frame_code': 0, 'plain_meta': 1, 'plain_code': 5, 'plain_all': 2,
                   'frame_meta': 2, 'frame_bare': 3, 'lxlit': 6}.get(mode, 0)
            tag = mode

        # ★ 关键修复：客户端 orange.HttpDelegate.sendHttpAsync 是
        #     decBody = msg.body && bon.decode(msg.body)
        #   即 body(07 二进制块) 的内容必须是【裸 bon 字节】，不能再套 lz4/lx。
        #   此前误用 lz4_xor_encode(bon_encode(payload))，客户端 bon.decode 解不开，
        #   roleToken 取不到 -> loginFlow 里 connect(t.roleToken) 拿不到 token
        #   -> 不建 WebSocket / 卡「登录中」。一直靠注入探针 fillDecBody 逐层剥 lz4
        #   补 token 掩盖；重装修复版 APK 后探针不再注入，缺陷暴露。
        inner = bon_encode(payload)

        full = {'code': 0, 'body': inner, 'decBody': payload,
                'meta': {'errCode': 0, 'errMsg': 'ok'}, 'data': payload}

        if idx == 0:
            print(' [%s] lx 帧 code/裸bon body' % tag, flush=True)
            return lx_frame_response({'code': 0, 'body': inner, 'decBody': payload})
        if idx == 1:
            print(' [%s] lx 帧 全字段' % tag, flush=True)
            return lx_frame_response(full)
        if idx == 2:
            print(' [%s] lx 帧 meta/data' % tag, flush=True)
            return lx_frame_response({'code': 0, 'body': inner, 'meta': {'errCode': 0, 'errMsg': 'ok'}, 'data': payload})
        if idx == 3:
            print(' [%s] lx 帧 裸用户对象' % tag, flush=True)
            return lx_frame_response(payload)
        if idx == 4:
            print(' [%s] 明文 meta/data' % tag, flush=True)
            return plain({'meta': {'errCode': 0, 'errMsg': 'ok'}, 'data': payload})
        if idx == 5:
            print(' [%s] 明文 code/decBody' % tag, flush=True)
            return plain({'code': 0, 'decBody': payload, 'msg': 'ok'})
        if idx == 6:
            print(' [%s] lx 字面量流 全字段' % tag, flush=True)
            return lx_lit_response(full)
        return lx_frame_response({'code': 0, 'body': inner, 'decBody': payload})
        if idx == 4:
            print(' [%s] lz4 帧 meta/data' % tag, flush=True)
            return lx_frame_response({'meta': {'errCode': 0, 'errMsg': 'ok'}, 'data': payload})
        if idx == 5:
            print(' [%s] lx 字面量流（含 pl 头）全字段' % tag, flush=True)
            return lx_lit_response(full)
        if idx == 6:
            print(' [%s] lz4 帧 code/decBody' % tag, flush=True)
            return lx_frame_response({'code': 0, 'decBody': payload})
        return lx_frame_response(full)

    db['lastUser'] = user['userId']
    save_db(db)

    # ===== 账号绑定（游客 -> 正式账号）=====
    # 客户端 BindSocialPanel.bindSocial() 判定：
    #   var t = yield HAPP.bindPlatform({bindType});
    #   if (t.isExist)        -> toast「此账号已被绑定」= 失败
    #   else if (t.userInfo)  -> socialBinded=true, 关面板 = 成功
    #   else                  -> toast「绑定失败」
    # 因此必须 isExist 为假 + userInfo 非空。此前回 isExist:true 正是绑定失败根因。
    if path.rstrip('/').endswith('bind/try') or 'bind' in path:
        j = request.get_json(silent=True) or {}
        mobile = str(j.get('mobile') or j.get('phoneNumber') or
                     get_param('accountNum', 'mobile', 'phone', default='') or '')
        sms   = str(j.get('smsCode') or j.get('verifyCode') or '')
        tp    = str(j.get('tp') or 'app-mobile')
        # 任意手机号 / 任意验证码都接受；把手机号记为已绑定账号（持久化）
        user['mobile'] = mobile
        user['authed'] = True
        user['isRealName'] = True
        user['loginPlatform'] = 1
        db.setdefault('binds', {})[mobile or user['uniqueId']] = {
            'mobile': mobile, 'uniqueId': user['uniqueId'],
            'userId': user['userId'], 'tp': tp, 'smsCode': sms,
        }
        save_db(db)
        payload = login_payload(user, token)
        payload.update({
            # —— 关键成功字段 ——
            'isExist': False,          # ★ 必须 false，否则判「已被绑定」失败
            'userInfo': user,          # ★ 必须非空
            'success': True, 'result': True, 'code': 0, 'errCode': 0, 'msg': 'ok',
            'bindSuccess': True, 'isBind': True, 'binded': True,
            'currentUniqueId': user['uniqueId'],
            'uniqueId': user['uniqueId'], 'userId': user['userId'],
            'oldUniqueId': '', 'oldTp': 0,
            'tp': tp, 'bindType': tp, 'mobile': mobile,
            'bindPlatformUId': user['uniqueId'],
            'token': token, 'accessToken': token, 'sessionId': token,
            'roleToken': token,
        })
        print('  [bind] OK mobile=%s sms=%s uid=%s' % (mobile, sms, user['userId']), flush=True)
        # 明文 JSON（第三方 Host），SDK 直接读 data
        return ok(payload, isExist=False, userInfo=user, success=True,
                  result=True, code=0, errCode=0, msg='ok', bindSuccess=True)

    data = login_payload(user, token)
    # 私服：所有登录类响应（appLoginSwitch / login/token 等）都声明已实名成年，
    # roleLogin() 里 C.Ins.realNamed = o.realName，发动态/发布作品门禁由此放行。
    # [guest-no-formal-flag] 游客号不冒充正式账号。
    _is_guest_data = (str(user.get('phone', '')) == '__guest_placeholder__')
    data.update({
        'realName': True, 'realNamed': True, 'isRealName': True,
        'authed': True, 'isAdult': True,
        'brithDay': '1990-01-01', 'birthDay': '1990-01-01',
        'birthday': '1990-01-01', 'isAppVisitor': _is_guest_data, 'needBind': _is_guest_data,
    })
    data.setdefault('userInfo', user)   # login_payload 已带，双保险
    return ok(data, realName=True, realNamed=True, isRealName=True,
              authed=True, isAdult=True, success=True, result=True)

def h_user(path):
    tok = get_param('token', default='')
    uid = db['tokens'].get(tok) or (list(db['users'])[0] if db['users'] else None)
    user = ensure_user(uid)
    if 'name/check' in path or 'name/verification' in path:
        # 私服：任意查询都返回已实名成年，SDK 不再弹实名认证框
        return ok({'isRealName': True, 'realName': True, 'realNamed': True,
                   'authed': True, 'isAdult': True,
                   'birthday': '1990-01-01', 'brithDay': '1990-01-01',
                   'valid': True, 'code': 0},
                  isRealName=True, realName=True, realNamed=True,
                  authed=True, isAdult=True, success=True, result=True)
    return ok(user)

def h_gameconfigs(path):
    return ok({
        'gameId': 'cybjq',
        'gameName': '创游编辑器',
        'serverTime': int(time.time()),
        'openRealName': False,
        'isRealName': True, 'realName': True, 'isAdult': True,
        'openPay': False,
        'hotUpdateUrl': '',
        'noticeUrl': '',
        'privacyUrl': 'https://ios-app.hortorgames.com/cysj-user-policy',
        'customerService': '',
        'configs': {},
    })

def h_switches(path):
    """自定义开关：真服格式 {"data":{"rlt":[bool,...]}}，顺序与请求里的 switches 一致"""
    body = request.get_json(silent=True) or {}
    n = len(body.get('switches') or [])
    return ok({'rlt': [False] * n})

def h_scheme(path):
    return ok({'list': [], 'schemes': [], 'all': []})

def h_notice(path):
    return ok({'list': db['notices'], 'total': len(db['notices'])})

def h_anti(path):
    if 'ping' in path:
        return ok({'antiAddiction': False, 'delay': 0, 'alertInfo': None})
    return ok({'antiAddiction': False, 'delay': 0, 'openRealName': False,
               'needRealName': False, 'isRealName': True, 'realName': True,
               'isAdult': True, 'tip': ''})

def h_log(path):
    """日志上报：接收并丢弃"""
    return ok({'result': True})

def h_ping(path):
    return ok({'result': True, 'serverTime': int(time.time())})

def h_pay(path):
    return ok({'orderId': '', 'money': 0, 'status': 0, 'payInfo': None})

def h_chat_room(path):
    return ok({'token': '', 'sign': '', 'expire': 0})

def h_pkg_info(path):
    return ok({'versionName': '0.8.10', 'versionCode': 99, 'updateUrl': '',
               'forceUpdate': False, 'desc': ''})

def h_policy(path):
    return ok({'url': 'https://ios-app.hortorgames.com/cysj-user-policy', 'content': ''})

# ===== 业务接口（社区 / 作品 / 素材）=====

# 动作类关键字：POST 且命中这些词 → 视为"写操作"而非列表查询
ACTION_KW = ('publish', 'save', 'create', 'update', 'delete', 'remove', 'edit',
             'like', 'star', 'collect', 'favor', 'follow', 'unfollow', 'report',
             'submit', 'send', 'post', 'add', 'set', 'bind', 'check')

def is_action(method, path):
    if method == 'GET':
        return False
    p = path.lower()
    return any(k in p for k in ACTION_KW)

def h_works(path):
    """作品：列表 / 详情 / 榜单 / 发布保存"""
    # —— 写操作：真正落库，让"发布作品"可用 ——
    if is_action(request.method, path):
        p = request.get_json(silent=True) or dict(request.form) or {}
        now = int(time.time())
        wid = p.get('id') or p.get('workId')
        if wid:                                    # 更新已有作品
            for w in db['works']:
                if str(w['id']) == str(wid):
                    w.update({k: v for k, v in p.items() if k in w})
                    w['updateTime'] = now
                    save_db(db)
                    return ok({'id': w['id'], 'workId': w['id'], 'result': True})
        item = {                                   # 新建作品
            'id': 20000 + len(db['works']),
            'workId': 20000 + len(db['works']),
            'name': p.get('name') or p.get('title') or '未命名作品',
            'title': p.get('title') or p.get('name') or '未命名作品',
            'desc': p.get('desc') or p.get('description') or '',
            'category': p.get('category') or p.get('type') or '自由',
            'coverUrl': p.get('coverUrl') or '/uploads/cover/avatar.png',
            'iconUrl': p.get('iconUrl') or p.get('coverUrl') or '/uploads/cover/avatar.png',
            'authorId': p.get('authorId') or p.get('userId') or '1000001',
            'authorName': p.get('authorName') or '我',
            'authorAvatar': '/uploads/cover/avatar.png',
            'playCount': 0, 'likeCount': 0, 'starCount': 0, 'commentCount': 0,
            'createTime': now, 'updateTime': now,
            'status': 1, 'isPublished': True,
            'tags': p.get('tags') or [],
        }
        db['works'].append(item)
        save_db(db)
        return ok({'id': item['id'], 'workId': item['workId'], 'result': True,
                   'success': True})

    # —— 读操作 ——
    kw = str(get_param('keyword', 'key', default='')).lower()
    cat = str(get_param('category', 'type', default=''))
    items = db['works']
    if kw:
        items = [w for w in items if kw in str(w.get('name', '')).lower()]
    if cat:
        items = [w for w in items if cat in str(w.get('category', ''))]
    if 'rank' in path or 'hot' in path or 'top' in path or 'recommend' in path:
        items = sorted(items, key=lambda w: -w.get('playCount', 0))
    if 'detail' in path or 'info' in path:
        wid = get_param('workId', 'id', default=None)
        for w in items:
            if str(w['id']) == str(wid):
                return ok(w)
        return ok(items[0] if items else {})
    return ok_list(items)

def h_upload(path):
    """上传：接收文件并落盘"""
    saved = []
    for key, f in request.files.items():
        ext = os.path.splitext(f.filename or '')[1] or '.bin'
        name = '%s%s' % (uuid.uuid4().hex, ext)
        sub = os.path.join(STATIC_DIR, datetime.date.today().isoformat())
        os.makedirs(sub, exist_ok=True)
        p = os.path.join(sub, name)
        f.save(p)
        url = '/uploads/%s/%s' % (datetime.date.today().isoformat(), name)
        saved.append({'key': key, 'url': url, 'size': os.path.getsize(p)})
        db['uploads'].append({'url': url, 'path': p, 'ts': int(time.time())})
    if saved:
        save_db(db)
        return ok({'urls': [s['url'] for s in saved], 'files': saved, 'url': saved[0]['url']})
    return ok({'urls': [], 'url': ''})

def h_comments(path):
    return ok_list([])

# 路由表：(关键字匹配, 处理函数)
ROUTES = [
    ('login',                      h_login),
    ('verify',                     h_login),
    ('bind',                       h_login),
    ('user',                       h_user),
    ('account/name',               h_user),
    ('gameconfig',                 h_gameconfigs),
    ('switch',                     h_switches),
    ('scheme',                     h_scheme),
    ('notice',                     h_notice),
    ('anti',                       h_anti),
    ('log',                        h_log),
    ('ping',                       h_ping),
    ('lifecycle',                  h_ping),
    ('pay',                        h_pay),
    ('order',                      h_pay),
    ('chat_room',                  h_chat_room),
    ('pkg_info',                   h_pkg_info),
    ('policy',                     h_policy),
    ('upload',                     h_upload),
    ('comment',                    h_comments),
    ('work',                       h_works),
    ('game',                       h_works),
    ('rank',                       h_works),
    ('material',                   h_works),
    ('feed',                       h_works),
    ('home',                       h_works),
    ('recommend',                  h_works),
    ('discover',                   h_works),
    ('bbs',                        h_works),
]

def h_getappupdate(path):
    """App 启动版本检查（Login_GetAppUpdateInfo）。

    客户端 LoginScene.checkUpdateApp 的真实逻辑：
        let i = (yield NetIns.sendHttpAsync({cmd: Login_GetAppUpdateInfo})).decBody;
        if (i) { i.isForceUpdate ? 下载面板 : compareVersion(i.version,...) > 0 ? 新版本弹窗 : ... }
    i 为空时 if 整块跳过，而 new Promise 只有 resolve、没有 reject 也没有兜底
    e()，这个 Promise 会永远 pending。此前本接口被 ('login', h_login) 子串误抓，
    返回 ok(login_payload)（顶层无 decBody 字段），必然 i 为 undefined。
    这里让顶层 decBody 直接携带版本信息对象（无需更新），使分支正常 resolve。
    body 用与 authusersingle 相同的内层 lx 字节流，兼容框架从 body 二次解码的实现。
    """
    info = {
        'find': False,
        'isForceUpdate': False,
        'version': '0.0.0',
        'url': '',
        'desc': '',
        'channel': 'hortor',
    }
    # ★ 关键：客户端 orange.HttpDelegate.sendAsync 收包后执行
    #     i = decodeMsg(response, LX);         // 解开整个 lx 帧 -> frame 对象
    #     i.decBody = i.body && bon.decode(i.body);   // 对 frame.body 「裸 bon」解码
    #   所以 frame.body 必须是「裸 bon 字节」bon_encode(info)，不能是再裹一层的
    #   lz4 流——否则 bon.decode 抛异常（正是之前 WS 回包踩过的坑），decBody 取不到，
    #   checkUpdateApp 里 i 为 undefined -> compareVersion 抛错 -> 卡在登录中。
    inner = bon_encode(info)
    frame = {
        'code': 0,
        'meta': {'errCode': 0, 'errMsg': 'ok'},
        'decBody': info,      # 顶层对象：部分框架/探针直接读
        'body': inner,        # ★ 裸 bon 字节：客户端 bon.decode(body) -> info
        'data': info,         # 冗余，兼容读 data 的实现
        'list': [],
        'total': 0,
    }
    if _is_game_host():
        return lx_frame_response(frame)
    d = dict(frame)
    d.pop('body', None)       # jsonify 不能序列化 bytes
    return jsonify(d)


def dispatch(path):
    p = path.lower()
    # ★ 精确路由优先：/login/getappupdateinfo 含 "login" 子串，若走子串匹配会被
    #   ('login', h_login) 误抓，返回「用户对象」（无 version），导致客户端
    #   LoginScene.checkUpdateApp 里 compareVersion(undefined,...) 抛 TypeError，
    #   而 checkUpdateApp 是 new Promise(e=>...)（无 reject），异常使 Promise 永久
    #   pending -> 卡在"登录中"。此分支只在本地存过登录态(KeyLoginType)时触发，
    #   正是「清数据后才能进」的原因。必须在通用子串匹配前精确拦截。
    if 'getappupdateinfo' in p:
        return h_getappupdate, 'getappupdate'
    for kw, fn in ROUTES:
        if kw in p:
            return fn, kw
    return None, 'fallback'

def fallback(path):
    """
    兜底：未知接口返回结构合法的成功响应。
    列表类 GET 返回空列表，操作类 POST 返回成功，避免客户端解析崩溃。
    """
    if 'verification' in path.lower() or 'realname' in path.lower() or 'idcard' in path.lower():
        return ok({'isRealName': True, 'realName': True, 'realNamed': True, 'authed': True, 'isAdult': True, 'valid': True, 'birthday': '1990-01-01', 'brithDay': '1990-01-01', 'birthDay': '1990-01-01', 'result': True, 'success': True, 'code': 0, 'errCode': 0, 'msg': 'ok'}, isRealName=True, realName=True, authed=True)
    if request.method == 'GET':
        return ok({'list': [], 'total': 0, 'hasMore': False, 'page': 1, 'pageSize': 0})
    return ok({'result': True, 'success': True})

# ---------------------------------------------------------------- HTTP 入口

@app.before_request
def _hook():
    # 每请求刷新全局 db：后台(admin.py)改动用户/动态后，HTTP 端立即读到最新数据
    global db
    try:
        db = store.load_db()
    except Exception:
        pass

@app.route('/', defaults={'p': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/<path:p>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def catch_all(p):
    path = '/' + p
    try:
        fn, tag = dispatch(path)
        resp = fn(path) if fn else fallback(path)
    except Exception:
        traceback.print_exc()
        resp = ok({})
        tag = 'error'
    log_req(tag)
    return resp

@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(STATIC_DIR, filename)


@app.route('/jsdump', methods=['POST', 'GET'])
def jsdump():
    """接收客户端探针上报（动态调试用）"""
    log_req('jsdump')
    return ok_json({'ok': True})



@app.route('/cmd')
def cmd_js():
    """远程调试指令：服务器上改 cmd.js，客户端 10 秒内自动执行"""
    pth = os.path.join(BASE, 'cmd.js')
    body = open(pth, 'rb').read() if os.path.exists(pth) else b'NONE'
    r = Response(body, mimetype='application/javascript')
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return r


@app.route('/sample')
def sample_bin():
    """回放最近一次 lx 响应的原始字节，供客户端自检解码"""
    import base64 as _b64
    p = os.path.join(BASE, 'logs', 'last_lx.bin')
    try:
        raw = open(p, 'rb').read()
    except Exception:
        raw = b''
    txt = ''
    try:
        txt = open(os.path.join(BASE, 'logs', 'last_lx.txt')).read()
    except Exception:
        pass
    out = {'len': len(raw), 'b64': _b64.b64encode(raw).decode(), 'plain': txt[:1200]}
    r = Response(json.dumps(out), mimetype='application/json')
    r.headers['Cache-Control'] = 'no-store'
    return r


@app.route('/probe.js')
def probe_js():
    """动态调试探针：客户端启动时拉取并执行，改这里无需重装 APK"""
    p = os.path.join(BASE, 'probe.js')
    body = open(p, 'rb').read() if os.path.exists(p) else b'/* none */'
    r = Response(body, mimetype='application/javascript')
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return r

@app.route('/_admin/requests')
def admin_requests():
    """查看客户端实际调用了哪些接口 —— 用于把未知接口逐个补全"""
    lines = []
    if os.path.exists(REQ_LOG):
        with open(REQ_LOG, 'r', encoding='utf8') as f:
            lines = f.readlines()[-500:]
    rows = []
    for ln in lines:
        try:
            r = json.loads(ln)
        except Exception:
            continue
        rows.append(r)
    return Response(json.dumps(rows, ensure_ascii=False, indent=1), mimetype='application/json')

@app.route('/_admin/paths')
def admin_paths():
    """
    汇总客户端实际请求过的去重路径 —— 这是补全业务接口的关键依据。
    带 ?host=xxx 可按域名过滤；带 ?all=1 输出完整记录。
    """
    rows = []
    if os.path.exists(REQ_LOG):
        with open(REQ_LOG, 'r', encoding='utf8') as f:
            for ln in f:
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    pass
    host = request.args.get('host')
    if host:
        rows = [r for r in rows if host in r.get('host', '')]
    agg = {}
    for r in rows:
        k = (r['host'], r['method'], r['path'], r['handler'])
        agg.setdefault(k, {'count': 0, 'sample': r})
        agg[k]['count'] += 1
    out = [{'host': k[0], 'method': k[1], 'path': k[2],
            'handler': k[3], 'count': v['count'],
            'sample': v['sample']} for k, v in agg.items()]
    out.sort(key=lambda x: (x['handler'] != 'fallback', -x['count']))
    return Response(json.dumps(out, ensure_ascii=False, indent=1),
                    mimetype='application/json')

@app.route('/_admin/state')
def admin_state():
    return jsonify({'users': len(db['users']), 'works': len(db['works']),
                    'uploads': len(db['uploads'])})

@app.route('/hf')
def hf_report():
    """v3 APK 状态上报：写独立日志，方便按 m= 追踪客户端每一步"""
    m = request.args.get('m', '')
    try:
        with open(os.path.join(BASE, 'logs', 'hotfix.log'), 'a', encoding='utf8') as f:
            f.write('%s\n' % m[:300])
    except Exception:
        pass
    return Response('ok', mimetype='text/plain')


@app.route('/hotfix.js')
def hotfix_js():
    """v3 APK 远程热修：改本文件即刻生效，无需重装 APK"""
    try:
        code = open(os.path.join(BASE, 'hotfix.js'), encoding='utf8').read()
    except Exception:
        code = '/* no hotfix */'
    resp = Response(code, mimetype='application/javascript')
    # 禁止缓存：改 hotfix.js 后客户端重开 App 必须拿到新版本，不能命中本地缓存
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp


def run(host='0.0.0.0', port=443, https=True):
    import ssl
    cert = os.path.join(BASE, 'certs', 'server.crt')
    key = os.path.join(BASE, 'certs', 'server.key')
    kw = dict(host=host, port=port, threaded=True)
    if https and os.path.exists(cert) and os.path.exists(key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        kw['ssl_context'] = ctx
        print('[私服] HTTPS 监听 %s:%d (SAN 证书)' % (host, port))
    else:
        kw['port'] = port if port != 443 else 8080
        print('[私服] HTTP 监听 %s:%d（未找到证书，已降级）' % (host, kw['port']))
    print('[私服] 请求日志: %s' % REQ_LOG)
    print('[私服] 管理面板: /_admin/requests  /_admin/state')
    app.run(**kw)

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    https = '--http' not in sys.argv
    run(port=port, https=https)
