"""私服 /agent 长连接。

客户端 connect() 成功后用 sendAsync 发 game_login，并等待服务端回带 resp 的帧。
doReceive 里只有 ~~n.resp > 0 才会 resolve _asyncList，缺 resp -> 登录永久挂起。
另外客户端每 ~20s 发单字节 0x00 心跳，服务端必须回一个字节让 addResp 重置超时。
"""
import asyncio
import os
import json
import struct
import sys
import time
import traceback
import threading

import websockets

sys.path.insert(0, '/opt/privsrv')
import store   # noqa: E402  共享数据层（当前用户/动态/蓝V名单）
import review  # noqa: E402  头像审核队列（上传/通过/拒绝）
try:
    import features   # noqa: E402  统一功能层（社交/内容/编辑器/商城）
except Exception as _fe:
    features = None
    print('  [warn] features import failed:', _fe, flush=True)
from server import bon_encode, lz4_xor_encode   # noqa: E402

LOG = '/opt/privsrv/logs/agent.log'


def log(*a):
    line = time.strftime('%Y-%m-%dT%H:%M:%S') + ' ' + ' '.join(str(x) for x in a)
    try:
        with open(LOG, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass
    print(line, flush=True)


# ---------------- 在线连接注册表（供后台 /online 实时查看）----------------
# 只在本进程内存维护，周期写快照到 data/online.json；不参与业务逻辑，不影响游戏。
ONLINE = {}                 # key=connId -> {uid, ip, connect_ts, last_ts}
ONLINE_LOCK = threading.Lock()
ONLINE_SNAP = '/opt/privsrv/data/online.json'
_last_snap_write = [0.0]
# ---- 封号实时踢线：uid -> set(ws对象)，仅本进程内存，不落盘 ----
WS_BY_UID = {}              # key=uid(str) -> set of websocket
WS_LOCK = threading.Lock()
KICK_FILE = '/opt/privsrv/data/kick.jsonl'
_kick_offset = [0]          # 已处理到的 kick.jsonl 字节偏移


def online_add(cid, uid, ip):
    try:
        with ONLINE_LOCK:
            ONLINE[str(cid)] = {'uid': str(uid or ''), 'ip': str(ip or ''),
                                'connect_ts': time.time(), 'last_ts': time.time()}
        online_maybe_flush(force=True)
    except Exception as e:
        log('  ONLINE_ADD_ERR', repr(e))


def online_touch(cid):
    try:
        with ONLINE_LOCK:
            if str(cid) in ONLINE:
                ONLINE[str(cid)]['last_ts'] = time.time()
    except Exception:
        pass


def online_remove(cid):
    try:
        with ONLINE_LOCK:
            ONLINE.pop(str(cid), None)
        online_maybe_flush(force=True)
    except Exception as e:
        log('  ONLINE_RM_ERR', repr(e))


def online_maybe_flush(force=False):
    """节流写快照：默认最多每 2 秒写一次，强制时立即写。"""
    try:
        now = time.time()
        if not force and now - _last_snap_write[0] < 2.0:
            return
        with ONLINE_LOCK:
            snapshot = dict(ONLINE)
        tmp = ONLINE_SNAP + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'ts': now, 'connections': snapshot}, f, ensure_ascii=False)
        os.replace(tmp, ONLINE_SNAP)
        _last_snap_write[0] = now
    except Exception as e:
        log('  ONLINE_FLUSH_ERR', repr(e))


# ---------------- 封号实时踢线（内存映射 + 指令轮询）----------------
def ws_bind(uid, websocket):
    uid = str(uid or '')
    if not uid:
        return
    try:
        with WS_LOCK:
            WS_BY_UID.setdefault(uid, set()).add(websocket)
    except Exception as e:
        log('  WS_BIND_ERR', repr(e))


def ws_unbind(uid, websocket):
    uid = str(uid or '')
    try:
        with WS_LOCK:
            s = WS_BY_UID.get(uid)
            if s is not None:
                s.discard(websocket)
                if not s:
                    WS_BY_UID.pop(uid, None)
    except Exception:
        pass


def _is_banned(uid):
    """信誉分为 0 视为封号。重连时据此拒绝。"""
    try:
        _f = features.load_feat()
        _rec = _f.get('credit', {}).get(str(uid), {}) or {}
        return features.as_int(_rec.get('score'), 3) <= 0
    except Exception:
        return False

# 封号写操作黑名单：信誉叶子=0 的玩家，这些命令在服务端被拦截、不落库。
# 只含「产生内容/社交互动/改资料资产」的写命令；登录/读取/生命周期/心跳一律放行。
BANNED_WRITE_CMDS = frozenset([
    # 发布/作品/商品
    'game_publishgame', 'game_uploadgoods', 'game_uploadreleasegame',
    'game_offgame', 'game_offgoods', 'game_ownoffgame',
    # 评论/动态
    'game_commentgame', 'game_commenttalk', 'game_replytalkcomment',
    'game_delgamecomment', 'game_deltalkcomment', 'game_modifytalk',
    'game_modifytalkcomment', 'game_modifyofficialtalk', 'game_deletetalk',
    'game_officialdeletetalk', 'game_createtalk', 'game_createofficialtalk',
    'game_uptalk', 'game_uptalkcomment', 'game_deltalktop', 'game_deltalkcommenttop',
    'game_deltalkchosen', 'game_settalkchosen', 'game_settalktop',
    'game_settalkcommenttop', 'game_clearnewcomment',
    # 点赞/收藏/关注
    'game_thumbgames', 'game_cancelthumbgames', 'game_thumbgamecomment',
    'game_cancelthumbgamecomment', 'game_thumbtalk', 'game_cancelthumbtalk',
    'game_thumbtalkcomment', 'game_cancelthumbtalkcomment',
    'game_collectiongames', 'game_cancelcollectiongames', 'game_collectionggoods',
    'game_cancelcollectiongoods', 'game_collectiontalk', 'game_cancelcollectiontalk',
    'game_followuser', 'game_cancelfollowuser',
    # 举报/撤销
    'game_reportgame', 'game_reportgoods', 'game_reportplayer', 'game_reporttalk',
    'game_reporttalkcomment', 'game_reportgamecomment', 'game_revokereportgame',
    'game_revokereportgoods', 'game_revokereportplayer', 'game_revokereportgamecomment',
    'game_clearreportgame', 'game_clearreportgoods', 'game_clearreportplayer',
    'game_clearreporttalk', 'game_clearreporttalkcomment', 'game_clearreportgamecomment',
    # 送礼/购买/花费
    'game_sendgift', 'game_buygoods', 'game_costcoiningame', 'game_costcoinrecommendgame',
    # 改资料/传图
    'game_updateuserinfo', 'game_updateuserimg', 'game_uploadimage',
    # 加币/道具（作弊类也一并拦）
    'game_addcoinbyadvert', 'game_addcoinbyadvertv2', 'game_addcoinbyshare',
    'game_addcoinbysharevideo', 'game_obtainttcoin0319', 'game_additem',
    'game_addgametage', 'game_gmsetgold', 'game_gmincothercoin', 'game_gmsetgametage',
    # 排行榜/角色配置写
    'game_savegamerank', 'game_deletegamerankscore', 'game_uploadgamerankscore',
    'game_delgamerank', 'game_saveroleactorconf', 'game_delroleactorconf',
    'game_saveroleweaponconf', 'game_delroleweaponconf', 'game_saverolebulletconf',
    'game_delrolebulletconf',
    # 账号绑定
    'game_bindrole', 'game_gmbindrole', 'game_gmrevokebindrole',
])


def _banned_write_uid(cmd):
    """若本连接是封号号且命令为写操作，返回其 uid；否则返回 ''。
    用 store.current_user() 取本连接会话 uid（ContextVar，已由 handler 注入）。"""
    if cmd not in BANNED_WRITE_CMDS:
        return ''
    try:
        _cu = store.current_user()
        _uid = str(_cu.get('userId')) if isinstance(_cu, dict) else ''
        if _uid and _is_banned(_uid):
            return _uid
    except Exception:
        pass
    return ''


# 封号号操作受限时：追加踢线指令让客户端重连、重新弹封号窗。
# 客户端无「操作中被弹窗」通道，只能靠「断线→自动重连→登录弹 Notice」实现提示。
_BAN_KICK_THROTTLE = {}   # uid -> 上次触发踢线的 epoch 秒


def _queue_ban_kick(uid):
    """同步追加一条踢线指令（节流：同 uid 30 秒内只触发一次）。"""
    try:
        import time as _t
        _now = _t.time()
        _last = _BAN_KICK_THROTTLE.get(uid, 0)
        if _now - _last < 30:
            return False
        _BAN_KICK_THROTTLE[uid] = _now
        with open(KICK_FILE, 'a', encoding='utf8') as _f:
            _f.write(json.dumps({'uid': uid, 'reason': 'ban_operation'}, ensure_ascii=False) + '\n')
        log('  BAN_KICK_QUEUED uid=%s (操作受限触发重连弹窗)' % uid)
        return True
    except Exception as e:
        log('  BAN_KICK_ERR', repr(e))
        return False


async def kick_uid(uid, reason=''):
    """实时断开某 uid 的全部 WS 连接（须在事件循环里 await）。"""
    uid = str(uid or '')
    with WS_LOCK:
        conns = list(WS_BY_UID.get(uid, set()))
    if not conns:
        log('  KICK uid=%s 无在线连接' % uid)
        return 0
    n = 0
    for websocket in conns:
        try:
            await websocket.close(code=4001, reason=(reason or 'banned')[:100])
            n += 1
        except Exception as e:
            log('  KICK_CLOSE_ERR', repr(e))
    log('  KICK uid=%s 断开 %d 条连接' % (uid, n))
    return n


async def _kick_watch_loop():
    """轮询 data/kick.jsonl，处理后台下发的封号踢线指令（每行一条 JSON）。"""
    while True:
        await asyncio.sleep(1.0)
        try:
            if not os.path.exists(KICK_FILE):
                continue
            size = os.path.getsize(KICK_FILE)
            off = _kick_offset[0]
            if size < off:      # 文件被重建/截断
                off = _kick_offset[0] = 0
            if size <= off:
                continue
            with open(KICK_FILE, 'rb') as f:
                f.seek(off)
                chunk = f.read()
                _kick_offset[0] = f.tell()
            for line in chunk.decode('utf8', 'replace').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    uid = str(item.get('uid') or '')
                    reason = str(item.get('reason') or '')
                    if uid:
                        await kick_uid(uid, reason)
                except Exception as e:
                    log('  KICK_LINE_ERR', repr(e))
        except Exception as e:
            log('  KICK_WATCH_ERR', repr(e))


# ---------------- lx 解码 ----------------
def unlx_key(b):
    return (((b[2] >> 6 & 1) << 7) | ((b[2] >> 4 & 1) << 6) | ((b[2] >> 2 & 1) << 5) |
            ((b[2] & 1) << 4) | ((b[3] >> 6 & 1) << 3) | ((b[3] >> 4 & 1) << 2) |
            ((b[3] >> 2 & 1) << 1) | (b[3] & 1))


def inflate_raw(b):
    try:
        import lz4.frame
        d = bytearray(b[:100])
        k = unlx_key(b)
        for i in range(len(d) - 1, 1, -1):
            d[i] ^= k
        d[0], d[1], d[2], d[3] = 4, 34, 77, 24
        return lz4.frame.decompress(bytes(d) + b[100:])
    except Exception:
        return None


def readable(b):
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:300])


# ---------------- bon 解码 ----------------
def r7(b, p):
    v, sh = 0, 0
    while True:
        c = b[p]
        p += 1
        v |= (c & 0x7f) << sh
        if not (c & 0x80):
            return v, p
        sh += 7


def _bd(b, p, strs):
    t = b[p]; p += 1
    if t == 0: return None, p
    if t == 1: return struct.unpack_from('<i', b, p)[0], p + 4
    if t == 2: return struct.unpack_from('<q', b, p)[0], p + 8
    if t == 4: return struct.unpack_from('<d', b, p)[0], p + 8
    if t == 5:
        n, p = r7(b, p); s = b[p:p + n].decode('utf8', 'replace'); p += n
        strs.append(s); return s, p
    if t == 6: return bool(b[p]), p + 1
    if t == 7:
        n, p = r7(b, p); d = b[p:p + n]; p += n
        # 0x07 二进制块有两种来源：
        #   * 服务端回包的 body（内部就是嵌套 bon）-> 解成 dict/list
        #   * 客户端上传的 PNG content（原始字节）-> 必须原样保留，否则图片数据丢失
        # 用「是否消费完整块」区分，避免把 PNG 首字节 0x89 误当成 bon 类型。
        try:
            inner, q = _bd(d, 0, [])
            if q == len(d) and isinstance(inner, (dict, list)):
                return inner, p
        except Exception:
            pass
        return bytes(d), p
    if t == 8:
        n, p = r7(b, p); o = {}
        for _ in range(n):
            k, p = _bd(b, p, strs); v, p = _bd(b, p, strs); o[str(k)] = v
        return o, p
    if t == 9:
        n, p = r7(b, p); a = []
        for _ in range(n):
            v, p = _bd(b, p, strs); a.append(v)
        return a, p
    if t == 0x63:
        i, p = r7(b, p)
        return (strs[i] if i < len(strs) else '<ref%d>' % i), p
    return '<type 0x%02x>' % t, p


def bon_decode(b):
    return _bd(b, 0, [])[0]


# ---------------- 动态配置数据 ----------------
# 首页/发现页 Banner。客户端 BbsBanner 组件真正读取的字段是
#   cfg.imgPath(走 fileCDN 拼 png) / cfg.bannerType(字符串枚举) / cfg.commentId / cfg.questionUrl
# 旧的 imgUrl/jumpUrl/jumpType 从未被该组件读取，保留仅为兼容其它读取路径。
# imgPath 用「纯文件名」：downLoadPng 拼成 fileCDN(/GameCreator-byte/) + imgPath，
# nginx 把该前缀 alias 到 uploads/cover/，实测返回 200 image/png。
# bannerType 固定 'public'：onClick 的 public 分支是空操作(break)，
# 不跳外部 URL、不弹「下载二代」诱导框、不进入不存在的 TalkScene——最安全。
BANNERS = [
    {'id': 1, 'title': '像素冒险', 'imgPath': 'demo1.png',
     'imgUrl': '/uploads/cover/demo1.png', 'jumpUrl': '', 'jumpType': 0,
     'bannerType': 'public', 'commentId': '', 'questionUrl': ''},
    {'id': 2, 'title': '方块生存', 'imgPath': 'demo4.png',
     'imgUrl': '/uploads/cover/demo4.png', 'jumpUrl': '', 'jumpType': 0,
     'bannerType': 'public', 'commentId': '', 'questionUrl': ''},
    {'id': 3, 'title': '弹幕射击', 'imgPath': 'demo5.png',
     'imgUrl': '/uploads/cover/demo5.png', 'jumpUrl': '', 'jumpType': 0,
     'bannerType': 'public', 'commentId': '', 'questionUrl': ''},
]


# 首页横幅开关配置：dyn 与 config_for_id 共用同一份，保证两条读取路径一致。
BANNER_CONF = {
    'isOpen': True,             # 显示横幅（图片链路已实测 200）
    'bannerType': 'public',     # 点击空操作，安全
    'imgPath': 'demo1.png',
    'commentId': '', 'questionUrl': '', 'downLoadUrl': '',
    'hasChosen': False, 'lvLimit': 0, 'fansLimit': 0,
    'list': BANNERS, 'banners': BANNERS,
}

# 公告：列表有内容，但【刻意不设 msg / version】。
# checkPanel 只有 `t.msg && t.version == gameEnv.creatorVersion` 才在每次登录弹 NoticePanel；
# creatorVersion 由真机 getClientVersion() 覆盖、服务端不可控，填了就是每次登录骚扰弹窗。
NOTICE_CONF = {
    'list': [],
    'total': 0,
}


def _ban_notice():
    """封号(信誉叶子=0)玩家登录时注入的 Notice。
    客户端 checkPanel 弹窗硬条件：t.msg && t.version == creatorVersion(真机 getClientVersion)。
    version 默认 0.8.10，可用 feat.ban_notice_version 覆盖，换 APP 版本无需改代码。
    """
    _ver = '0.8.10'
    try:
        _cfg = str((store.load_db().get('feat') or {}).get('ban_notice_version') or '').strip()
        if _cfg:
            _ver = _cfg
    except Exception:
        pass
    _msg = (
        '═══════════════\n'
        '⚠ 账号封禁通知\n'
        '═══════════════\n\n'
        '你的信誉叶子已被扣至 0，账号已被封禁。\n'
        '以下功能已被限制：\n\n'
        '· 发布或编辑作品、动态、商品\n'
        '· 搜索、评论、点赞、收藏、催更\n'
        '· 修改昵称、头像、简介\n'
        '· 私信、举报其他玩家\n\n'
        '如需申诉，请联系管理员'
    )
    return {'msg': _msg, 'version': _ver, 'list': [], 'total': 0}


GAMES = []  # 内置测试作品已清空，仅保留玩家自己上传的作品
GAME_IDS = [g['id'] for g in GAMES]


def dynamic_games():
    """内置作品 + 玩家发布作品（过滤已下架）。内置清空后，这里就是玩家自己上传的作品。
    供登录回包/首页列表/动态配置使用，避免硬编码 GAMES 为空导致精选/热门/推荐空白。"""
    out = [dict(g) for g in GAMES]
    try:
        ft = features.load_feat()
        off = set(str(x) for x in ft.get('offGames', []))
        for g in ft.get('games', []):
            if str(g.get('id')) in off:
                continue
            try:
                out.append(features.game_cell(g))
            except Exception:
                out.append(dict(g))
    except Exception:
        pass
    return out


def dynamic_game_ids():
    """当前可见作品 id 列表（精选/热门/GameChosenIds 用）。"""
    return [g.get('id') for g in dynamic_games()]


# ---- ABTest 配置：所有 ABTestType 都要有对象，避免 undefined.isOpen 崩溃 ----
# isOpen=False 且 targetPlan!=0 -> getABTestValue 立刻 return，不碰 role.createAt / role.aBTest
# 目标值让首页子 tab 全部显示：涉及项走 A 方案（601/701/401），其余走 B 方案保持稳定。
_AB_TARGET = {
    'recommendAB':          202,   # recommendGame_B
    'chosenCntAB':          302,   # aBTest3_B
    'chosenPagePosAB':      401,   # aBTest4_A -> 发现在前，精选在后
    'gameTypeAB':           502,   # aBTest5_B
    'discoverForNewUserAB': 601,   # aBTest6_A -> 显示 最新/BUFF榜/关注/创意工坊 + 搜索框
    'noChosen':             701,   # aBTest7_A -> 追加 精选 tab
    'onlyChosen':           802,   # aBTest8_B
}
ABTEST_SWITCHS = {
    k: {'isOpen': False, 'targetPlan': v, 'newUserStartTime': 0}
    for k, v in _AB_TARGET.items()
}


# ======================= 蓝V / 官方账号（服务端下发）=======================
# 客户端 DynamicMng.isGmPlayer():
#   (this.map.get("GmPlayerIds") || []).indexOf(role.id) >= 0
# 名单不再硬编码：由后台(admin.py)把用户 authed 置 true，服务端动态生成。
def gm_ids():
    try:
        return store.gm_ids()
    except Exception:
        return []


GM_IDS = []   # 兼容旧引用；实际值一律走 gm_ids()

# ======================= 教程：全量完成标记 =======================
# roleLogin(): F.default.Ins.completeTaskIds = e.role.completeTaskIds; F.default.Ins.init()
# GuideMng.init(): 若 !isComplete(EditWorld) 就 push 1..EditWorld 并 save()；
# 最后按 isComplete(CreateGame/CreateWorld/EditWorld) 决定放哪段教程。
# 服务端给空数组 => 每次登录从头放，且编辑器初始化会再触发一次 => 「同一轮对话放两遍」。
# 全部 ID 标记完成 => init() 直接 return，教程不再放，game_saveguide 也不再发。
ALL_GUIDE_IDS = [1, 2, 3, 4, 1001, 1002, 1003, 1004, 1101, 1102]

# ======================= 动态（社区测试数据）=======================
_T0 = int(time.time() * 1000)

def make_talk(title, text, hours=0, up=0):
    """构造符合 TalkData(a(0)/a(1)/a(2)) schema 的一条动态。
    simpleContent 是 a(0) 标量直传：TalkCell.setData 读 o.text / o.specialSection。
    status 用 ManReviewStatus.success=1（0=noPublish 会被过滤）。"""
    ts = _T0 - hours * 3600000
    _cu = None
    try:
        _cu = store.current_user()
    except Exception:
        _cu = None
    _cu = _cu if isinstance(_cu, dict) else {}
    _uid = str(_cu.get('userId', '1000111'))
    try:
        _pid = int(_uid)
    except Exception:
        _pid = 1000111
    # uId 占位：add_talk 会强制覆盖成 talkId(hash)，这里给作者 uid 仅兼容旧调用
    return {
        'uId': _uid, 'playerId': _pid, 'userLevel': _cu.get('level', 99),
        'userImg': '', 'userName': str(_cu.get('userName') or '玩家'),
        'userIntro': str(_cu.get('userIntro') or ''),
        'talkType': 'trends',
        'title': title,
        'simpleContent': {'text': text},
        'content': {},
        'upCnt': up, 'reportCnt': 0, 'commentsCnt': 0, 'commentsCntSum': 0,
        'isTop': False, 'isUp': False, 'isDown': False,
        'topComment': {}, 'comments': [],
        'status': 1, 'offReason': {},
        'createStamp': ts, 'newCommentStamp': ts, 'upStamp': ts,
        'collectionCntSum': 0,
    }

# 演示动态已移除：全部动态由 store(data/talks.json) 持久化，后台可增删改
TALKS = []

# 动态统一由 store 持久化到 data/talks.json（后台 admin 可增删改，重启不丢）
def save_user_talks():
    pass  # 兼容旧调用；写入由 store.add_talk 完成


def all_talks(talk_type=None, uid=None):
    """社区动态列表。

    talk_type: 客户端 Game_LoadTalk 的 talkType 参数，取值 trends/chosen/official/top。
      客户端拿到 talkList 后只按 status 过滤、不按 talkType 二次筛选，
      所以服务端必须按请求的 talkType 返回对应分类，否则「官方/精选」页签会串显普通动态。
      - chosen  : 精选动态（talkType==chosen 或 isChosen 标记）
      - official: 官方动态（蓝V/authed 用户发布的，或 talkType==official）
      - trends  : 普通动态（默认，非官方非精选）
      - top     : 置顶动态（isTop）
    未传 talk_type 时返回全部（兼容旧调用）。
    置顶(isTop)优先、组内按时间倒序；名字/头像/等级按当前账号资料实时覆盖。
    """
    try:
        talks = store.load_talks() or []
        try:
            db = store.load_db()
            users = db.get('users', {}) if isinstance(db, dict) else {}
        except Exception:
            users = {}
        def _top(t):
            v = t.get('isTop') if isinstance(t, dict) else None
            if isinstance(v, bool): return v
            if isinstance(v, (int, float)): return v != 0
            return str(v).strip().lower() in ('true', '1', 'yes', 'on')
        def _stamp(t):
            try: return int((t or {}).get('createStamp') or 0)
            except Exception: return 0
        def _tt(t):
            return str((t or {}).get('talkType') or 'trends')
        def _is_chosen(t):
            if _tt(t) == 'chosen':
                return True
            v = t.get('isChosen') if isinstance(t, dict) else None
            if isinstance(v, bool): return v
            return str(v).strip().lower() in ('true', '1', 'yes', 'on')
        def _is_official(t):
            if _tt(t) == 'official':
                return True
            pid = str((t or {}).get('playerId', ''))
            u = users.get(pid) if isinstance(users, dict) else None
            return bool(isinstance(u, dict) and u.get('authed'))
        # 按指定用户 uid 过滤（个人主页 loadowntalk 带 roleId）
        if uid not in (None, '', 0, '0'):
            _uid = str(uid)
            talks = [t for t in talks if str((t or {}).get('playerId','')) == _uid]
        # 按 talkType 过滤
        if talk_type in ('chosen', '精华', '精选'):
            talks = [t for t in talks if _is_chosen(t) or _is_official(t)]  # 官方帖也在精华显示
        elif talk_type in ('official', '官方'):
            talks = [t for t in talks if _is_official(t)]
        elif talk_type in ('top', '置顶'):
            talks = [t for t in talks if _top(t)]
        elif talk_type in ('trends', '动态', None, ''):
            talks = [t for t in talks if not _is_chosen(t)]  # 官方帖也在动态显示（仅排除精选）
        # 名字/头像/等级按当前账号资料实时覆盖（不写回磁盘）
        def _fresh(t):
            t = dict(t) if isinstance(t, dict) else t
            if not isinstance(t, dict):
                return t
            pid = str(t.get('playerId', ''))
            u = users.get(pid) if isinstance(users, dict) else None
            if isinstance(u, dict):
                if u.get('userName') is not None: t['userName'] = u.get('userName')
                if u.get('userImg') is not None: t['userImg'] = u.get('userImg')
                if u.get('level') is not None: t['userLevel'] = u.get('level')
                if u.get('userIntro') is not None: t['userIntro'] = u.get('userIntro')
            return t
        top = [_fresh(t) for t in talks if _top(t)]
        normal = [_fresh(t) for t in talks if not _top(t)]
        top.sort(key=_stamp, reverse=True)
        normal.sort(key=_stamp, reverse=True)
        return top + normal
    except Exception:
        return []


def login_payload(now):
    """构造符合 Game_RLogin schema 的完整回包。

    客户端: SendCmdAsync({cmd: game_login}, Game_RLogin)
         -> DecodeMsg(decBody, Game_RLogin) -> new Game_RLogin().setValue(decBody)
    setValue 只认 schema 注册字段，且按类型解析：
      se(1, Class)  -> 单对象，递归 setValue   (role / roleGameConf / offLineChangeMsg)
      se(2, Class)  -> 对象数组，逐项 setValue  (newGameDatas / followGameDatas / saleSummarys...)
      se(2)         -> 数组                    (hotGameIdList / gameSlotUnlockLvls ...)
      se(5)         -> Map，逐 key m.set(k, v) (dynamicConfig)
      se(0)         -> 标量                    (newMsgCnt / canObtainTTCoin ...)
    GDRole 里 a(4) 是 Date（传毫秒时间戳）、a(3) 是 Map（传对象）、a(1) 是嵌套对象。
    """
    # [guest-no-formal-flag] 游客占位号不发放正式账号标识，客户端 isVisitor() 判为游客，
    # 发布作品/动态/改资料门禁保持关闭。真人号均为真实手机号，不受影响。
    try:
        _cu = store.current_user()
        _is_guest = isinstance(_cu, dict) and str(_cu.get('phone', '')) == '__guest_placeholder__'
    except Exception:
        _is_guest = False
    _platforms = [] if _is_guest else ['app-mobile']
    role = {
        'id': 1000111, 'uId': 1000111, 'sId': 1000111, 'uKey': '',
        'userInfo': {},                      # a(1) 嵌套对象
        'coin': 8888, 'diamond': 100, 'creditScore': 3,
        'reviewCreditScore': 100, 'examScore': 100,   # 发布商品需 examScore>=100
        'publishGameTimes': 0, 'publishGoodsTimes': 0,
        'creditTime': now,                  # a(4) Date
        'creditMsgList': [],
        'goodsIds': [], 'myGameMaxCnt': 10, 'myGoodsMaxCnt': 10,
        'authed': False, 'creatorVersion': '', 'userName': '玩家',
        'exp': 0, 'level': 99, 'userImg': '', 'userIntro': '',
        # ★ UnlockPublishLvl=5：level=1 会弹「等级5解锁」，卡死发动态/发布作品
        'gameIncId': 0, 'worldIncId': 0, 'variableIncId': 0, 'customColorIncId': 0,
        'games': [], 'collectionGames': [], 'worlds': [], 'variables': [],
        'fansCount': 0, 'bindRoleCode': '', 'beBindList': [], 'channel': 'hortor',
        'customActorGroups': [], 'customColors': [], 'guideVersion': '0.8.10',
        # ★ 教程全量完成：根治「同一轮对话放两遍」+ 每次登录重放
        'completeTaskIds': list(ALL_GUIDE_IDS), 'follows': [],
        'createAt': now - 86400000 * 30,    # a(4) Date：30天前，避免"新用户"分支
        'collectionGoods': [], 'collectionTalks': [],
        'newUserImg': '', 'userImgTime': now, 'newUserImgReviewStatus': 0,
        'offReason': {},                    # a(1) 嵌套对象
        'addCoinCounters': {},              # a(3) Map
        'aBTest': {},                       # a(3) Map
    }
    role_game_conf = {
        'tileConfIds': [], 'actorConfIds': [], 'deviceConfIds': [],
        'propConfIds': [], 'weaponConfIds': [], 'bulletConfIds': [],
    }
    # dynamicConfig (se(5) Map) 一次性喂给 DynamicMng.Ins.init()，
    # 这样 loadOne() 直接命中，不会再发 game_getonedynamicconfig，也不会拿到 Promise。
    dyn = {
        'abTestSwitchs': ABTEST_SWITCHS,
        'DisableFunction': _editor_gate_disable()[0],  # 编辑器维护开关(热加载)
        'InspectVersionData': {},       # isInspectVersion 读 e[channel]
        'GameSwitchs': [], 'GameChosenIds': dynamic_game_ids(), 'GameTypeSwitch': {},
        'GameTags': [], 'GiftRank': {}, 'GamePotential': {}, 'GmPlayerIds': gm_ids(),
        'ViolationsNames': {}, 'IpGameIds': [], 'IpGoodsIds': [],
        'ChosenGoodsIds': [],
        'bbsBanner': {'list': BANNERS, 'total': len(BANNERS), 'isOpen': False},
        'bannerConf': BANNER_CONF,
        'GameTagSwitch': {'isOpen': False},
        'GuideOnLineTime': {'guideOnlineTime': 0, 'onlineTime': 0, 'openGuide': False},
        'Notice': config_for_id('Notice'),   # 后台公告优先：登录回包也读 db 的 notice_list
    }
    # ===== 多用户：把「当前会话账号」的字段覆盖到回包（try 兜底，绝不白屏）=====
    # 后台改 G币(coin)/钻石/等级/昵称/简介/蓝V(authed) 后，客户端 game_login 立即读到。
    try:
        dyn['GmPlayerIds'] = gm_ids()
    except Exception:
        pass
    try:
        u = store.current_user()
        if isinstance(u, dict):
            try:
                rid = int(u.get('userId', 1000111))
            except Exception:
                rid = 1000111
            role['id'] = rid; role['uId'] = rid; role['sId'] = rid
            # ★ 我的游戏列表：动态返回该用户在 ft.editor[uid].gamedata 下的存档 id。
            # 否则客户端 gameMng.gameIds 恒为空 -> 重进 APP 后「我的作品」全部丢失。
            try:
                _ft = features.load_feat()
                _ed = _ft.get('editor', {}).get(str(rid), {})
                role['games'] = list(_ed.get('gamedata', {}).keys())
            except Exception:
                pass
            # ★ 修复：自己主页粉丝/关注数不能写死 0/空，按 feat 真实数据覆盖。
            # 客户端 MinePage 读 role.fansCount / role.follows 显示计数和列表。
            try:
                _ft = features.load_feat()
                _fans = _ft.get('fans', {}).get(str(rid), []) or []
                _follows = _ft.get('follows', {}).get(str(rid), []) or []
                role['fansCount'] = len(_fans)
                role['follows'] = [features.as_int(x, 0) for x in _follows]
                role['followsCount'] = len(_follows)
                role['followCount'] = len(_follows)
            except Exception:
                pass
            for _k in ('coin', 'diamond', 'level', 'exp', 'userName',
                       'userIntro', 'userImg', 'authed'):
                if _k in u and u[_k] is not None:
                    role[_k] = u[_k]
            # ★ 信誉分：后台扣分/加分后，重新登录即生效（否则 CreditMng.Ins.credit 恒为默认值，
            #    点赞/收藏/举报/发布等「credit<=2 不可操作」的限制永远不触发）。
            #    语义：0~3 等级点（3=满信誉全绿，2/1=缺信誉，0=封号），客户端按此渲染叶子。
            try:
                _cs = _ft.get('credit', {}).get(str(rid), {})
                _score = max(0, min(3, features.as_int(_cs.get('score'), 3)))
                role['creditScore'] = _score
                role['creditMsgList'] = _cs.get('list', [])[:20]
                # 封号弹窗：信誉分(叶子)=0 时注入专属 Notice，客户端 checkPanel 命中后
                # 弹出 NoticePanel 显示「账号被封 + 受限功能清单」。只影响被封玩家自己。
                if _score == 0:
                    dyn['Notice'] = _ban_notice()
            except Exception:
                pass
            # 头像审核结果下发：0=无 / 1=通过 / 2=审核中 / 3=拒绝
            # 后台点「通过」后，客户端重新登录即读到 success + 新 userImg。
            try:
                _rs = u.get('imgReviewStatus', 0)
                role['newUserImgReviewStatus'] = _rs if _rs in (0, 1, 2, 3) else 0
                role['newUserImg'] = str(u.get('newUserImg') or '')
            except Exception:
                pass
    except Exception:
        pass
    return {
        'role': role,                       # se(1, GDRole)
        'dynamicConfig': dyn,               # se(5) Map
        'roleGameConf': role_game_conf,     # se(1, GDRoleGameConf)
        # ★ 以下「事件型弹窗触发器」刻意留空：checkPanel 里只要非空/为真，
        #   每次登录都会弹「升级/领取/栏位解锁/销售结算」面板，属骚扰且无真实数据。
        'offLineChangeMsg': {},             # incExp>0 才弹升级面板
        'saleSummarys': [], 'gameSaleSummarys': [], 'adSummarys': [], 'rebornSummarys': [],
        'unlockGameRewards': [], 'unlockGoodsRewards': [],
        'gameSlotUnlockLvls': [], 'goodsSlotUnlockLvls': [],
        'hotGameIdList': dynamic_game_ids(),
        'newGameDatas': dynamic_games(),              # se(2, GameCellData) -> DiscoverMng.freshGames
        'followGameDatas': [],
        'newMsgCnt': 0, 'newAggregateMsgCnt': 0, 'newFansCnt': 0, 'newCommentCnt': 0,
        'canObtainTTCoin': False, 'customActorGroups': [],
        'addCoinByAdvertCnt': 0, 'addCoinByAdvertLimit': 0, 'addCoinByAdvertReset': 0,
        'collectionGoods': [], 'giftCfgVersion': '',
        # ★ 正式账号标记：roleLogin() 里
        #   socialBinded = e.userPlatforms && e.userPlatforms.length > 0
        #   isVisitor() = isApp() && !socialBinded
        # 非空数组 => 非游客 => 发布作品/动态/改资料等功能全部解禁，
        # 且不再弹「请先绑定账号」。se(2) 数组，元素为平台字符串。
        'userPlatforms': _platforms,
        # 会话冗余字段（schema 未注册会被 setValue 忽略，但保留兼容其它读取路径）
        'code': 0, 'msg': 'ok', 'channel': 'hortor', 'time': now,
        'roleId': 1000111, 'userId': '1000111', 'userName': 'privsrv',
        'isRestore': 0, 'serverTime': now, 'sessionId': str(now),
        'gameId': 'GameCreator-app', 'data': {}, 'list': [],
    }


def _editor_gate_disable():
    """编辑器维护开关：读 data/editor_gate.json。
    返回 (disable_map, reason)。enabled=True 时禁用 hortor 渠道的创作类功能，
    客户端 isDisable 命中后弹 MessageBox 显示 reason。热加载，无需重启。"""
    try:
        _g = json.load(open('/opt/privsrv/data/editor_gate.json', encoding='utf8'))
    except Exception:
        return {}, ''
    if not _g.get('enabled'):
        return {}, ''
    _reason = str(_g.get('reason') or '功能维护中')
    # 枚举名见客户端 FunctionEnum：PublishGame="PublishGame2", CreativeGame="CreativeGame"
    _item = {
        'PublishGame2': False,
        'CreativeGame': False,
        'reason': _reason,
    }
    return {'hortor': _item, 'tt': _item, 'wx': _item}, _reason


def config_for_id(cid):
    """game_getonedynamicconfig 按 id 返回对应配置内容。"""
    if cid == 'Notice':
        # 后台公告优先：从 db.json feat.notice_list 读取。
        # ★ 客户端 checkPanel 弹窗硬条件：t.msg && t.version == 客户端版本。
        #   所以必须补顶层 msg(公告文字) + version(后台可配 feat.notice_version)。
        try:
            _db = store.load_db()
            _ft = _db.get('feat') or {}
            _list = _ft.get('notice_list')
            if isinstance(_list, list) and _list:
                _ver = str(_ft.get('notice_version') or '1.1.2')
                _msgs = []
                for _n in _list:
                    if isinstance(_n, dict) and int(_n.get('status') or 0) == 1:
                        _t = str(_n.get('title') or '').strip()
                        _c = str(_n.get('content') or '').strip()
                        _msgs.append(((_t + '\n' + _c) if (_t and _c) else (_t or _c)).strip())
                _msg = '\n\n'.join(_msgs)
                _out = {'list': _list, 'total': len(_list), 'version': _ver}
                if _msg:
                    _out['msg'] = _msg
                return _out
        except Exception:
            pass
        return NOTICE_CONF
    if cid == 'bbsBanner':
        return {'list': BANNERS, 'total': len(BANNERS), 'isOpen': False}
    if cid == 'abTestSwitchs':
        # getABTestValue(e) 用字符串 key 取: (map.get("abTestSwitchs") || ...)[e]
        # 每个 ABTestType 都要有 {isOpen, targetPlan, newUserStartTime}，
        # 否则 t.isOpen 抛异常 -> DiscoverPage.onLoad 被 Cocos 吞掉 -> 内容区空白。
        # targetPlan 给非 0 让 getABTestValue 直接 return，绕开 role.createAt/aBTest。
        return ABTEST_SWITCHS
    if cid == 'GuideOnLineTime':
        return {'guideOnlineTime': 0, 'onlineTime': 0, 'openGuide': False}
    # ===== 首页内容配置：DiscoverSubPage.refresh() 逐个 loadOne 消费 =====
    if cid == 'bannerConf':
        # 图片链路已打通(fileCDN 域名被 DNS 劫持 + 自签 CA + nginx 443 SNI 分发)，
        # 实测 /GameCreator-byte/demo1.png = 200 image/png，故可安全打开横幅。
        return BANNER_CONF
    if cid == 'GameTagSwitch':
        return {'isOpen': True}
    if cid == 'GameChosenIds':
        return dynamic_game_ids()
    if cid == 'GameTypeSwitch':
        return {}
    if cid == 'GameTags':
        return []
    if cid == 'GiftRank':
        return {}
    if cid == 'DisableFunction':
        return _editor_gate_disable()[0]
    if cid == 'InspectVersionData':
        return {}
    if cid == 'GameSwitchs':
        return []
    if cid == 'GamePotential':
        return {}
    if cid in ('IpGameIds', 'IpGoodsIds', 'ChosenGoodsIds'):
        return []
    if cid == 'ViolationsNames':
        return {}
    if cid == 'GmPlayerIds':
        # 蓝V名单由后台用户 authed 字段动态生成，服务端下发
        return gm_ids()
    # 兜底：返回空对象，避免客户端解析崩溃
    return {'list': [], 'total': 0}


# ---------------- 头像上传 / 审核（任务：后台审核头像）----------------
def req_param(req, name, default=None):
    """从 WS 请求的多个层级取参数（兼容客户端把 params 放顶层或 body/data）。"""
    srcs = [req]
    for k in ('body', 'params', 'data'):
        v = req.get(k)
        if isinstance(v, dict):
            srcs.append(v)
    for s in srcs:
        if name in s and s[name] not in (None, ''):
            return s[name]
    return default


def to_png_bytes(v):
    """把 bon 解码后的 content 还原成 PNG 字节。"""
    import base64 as _b64
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, list):
        try:
            return bytes(int(x) & 255 for x in v)
        except Exception:
            return b''
    if isinstance(v, str):
        try:
            return _b64.b64decode(v)
        except Exception:
            pass
        try:
            return v.encode('latin1')
        except Exception:
            return b''
    return b''


def save_upload_png(content):
    """把上传的 PNG 落到 /opt/privsrv/uploads/cover/，返回客户端可加载的 URL。
    nginx: /GameCreator-byte/ 与 /uploads/ 均指向 /opt/privsrv/uploads/。"""
    import os as _os, uuid as _uuid
    raw = to_png_bytes(content)
    if not raw:
        return None
    # 客户端 HeadIconMng.isCdnPng() 只认含 'pixel/' 的名字，否则显示内置默认头像；
    # downLoadPng 拼 fileCDN(=/GameCreator-byte/) + 名字，nginx alias 到 uploads/cover/。
    d = '/opt/privsrv/uploads/cover/pixel'
    _os.makedirs(d, exist_ok=True)
    name = 'avatar_%s.png' % _uuid.uuid4().hex[:12]
    with open(_os.path.join(d, name), 'wb') as f:
        f.write(raw)
    return 'pixel/' + name


# ---------------- 敏感词检测（Aspose AI 文本审核接口，单一接口 + 故障放行）----------------
# 接口：POST https://api.aspose.ai/total/text-moderation/Home/ProcessText
# 参数：InputText=文本（不需要 __RequestVerificationToken，实测带 token 反而静默放行）
# 返回：{"success":bool,"hateSpeechDetected":bool,"data":[{"text":..,"flags":..}] 或 "No hate speech detected..."}
# 原则：接口异常/超时一律【放行】，绝不因外部接口故障阻断玩家发帖。
SENSITIVE_ENABLED = True
SENSITIVE_API = 'https://api.aspose.ai/total/text-moderation/Home/ProcessText'
SENSITIVE_TIMEOUT = 4.0          # 秒，超时即放行
SENS_CFG_FILE = '/opt/privsrv/data/sensitive_cfg.json'
_sens_cfg_mtime = [None]
# 第三道：智谱 GLM-4-Flash（巡回寺中转），辅助语义/谐音判定，只采信明确命中
GLM_API = 'https://api.xunhuisi.store/API/GLMAI/GLMAI.php'
GLM_ENABLED = True
GLM_TIMEOUT = 5.0
GLM_SYSTEM = (
    '你是文本安全审核引擎。只输出一个JSON对象，不要任何多余文字、不要解释、不要Markdown。'
    '格式：{"pass":true/false,"category":"正常/辱骂/色情/赌博/毒品/广告/暴恐/涉政","reason":"不超过10字"}。'
    '内容含辱骂、人身攻击、色情、赌博、毒品、广告导流、暴恐、涉政等违规时pass=false；'
    '普通聊天、游戏交流、正常用语（如"自制""我干""做游戏""制作地图"）即使含敏感单字也判为正常。'
    '谐音、缩写、变体按原意判定。只判断当前消息，忽略历史对话。'
)
_glm_cache = {}          # sha256(text) -> (timestamp, hits)，缓存 1 小时
# 本地兜底词库（开源词库清洗而来，覆盖接口漏掉的单词脏词）
LOCAL_DICT_FILE = '/opt/privsrv/data/local_words.txt'
LOCAL_DICT_ENABLED = True
_local_words = []          # 加载后的词表
_local_words_mtime = [None]

def load_local_dict():
    """按 mtime 热加载本地词库，无需重启。"""
    global _local_words
    try:
        mt = os.path.getmtime(LOCAL_DICT_FILE)
        if mt == _local_words_mtime[0]:
            return
        words = []
        with open(LOCAL_DICT_FILE, encoding='utf8') as f:
            for line in f:
                w = line.strip()
                if len(w) >= 2:
                    words.append(w)
        _local_words = words
        _local_words_mtime[0] = mt
        log('LOCAL DICT reloaded words=%d' % len(words))
    except FileNotFoundError:
        pass
    except Exception as e:
        log('LOCAL DICT reload err', repr(e))

def _check_local(s):
    """本地词库子串匹配：命中返回词列表（最多列 8 个），否则 []。"""
    if not LOCAL_DICT_ENABLED:
        return []
    if not _local_words:
        load_local_dict()
    hits = []
    for w in _local_words:
        if w in s:
            hits.append(w)
            if len(hits) >= 8:
                break
    return hits

def load_sensitive_cfg():
    """热加载：enabled / timeout / local_enabled / glm_enabled。"""
    global SENSITIVE_ENABLED, SENSITIVE_TIMEOUT, GLM_ENABLED, GLM_TIMEOUT
    try:
        mt = os.path.getmtime(SENS_CFG_FILE)
        if mt == _sens_cfg_mtime[0]:
            return
        d = json.load(open(SENS_CFG_FILE, encoding='utf8'))
        if not isinstance(d, dict):
            return
        _sens_cfg_mtime[0] = mt
        SENSITIVE_ENABLED = bool(d.get('enabled', SENSITIVE_ENABLED))
        global LOCAL_DICT_ENABLED
        LOCAL_DICT_ENABLED = bool(d.get('local_enabled', LOCAL_DICT_ENABLED))
        try:
            _t = float(d.get('timeout', SENSITIVE_TIMEOUT))
            SENSITIVE_TIMEOUT = max(4.0, _t)   # Aspose 响应较慢，设 4 秒下限，避免误放行
        except Exception: pass
        GLM_ENABLED = bool(d.get('glm_enabled', GLM_ENABLED))
        try:
            _gt = float(d.get('glm_timeout', GLM_TIMEOUT))
            GLM_TIMEOUT = max(3.0, min(10.0, _gt))
        except Exception: pass
        log('SENSITIVE CFG reloaded (aspose+glm) enabled=%s glm=%s' % (SENSITIVE_ENABLED, GLM_ENABLED))
    except FileNotFoundError:
        pass
    except Exception as e:
        log('SENSITIVE CFG reload err', repr(e))

def _check_aspose(s):
    """Aspose AI 审核：返回被标记的原文词列表；异常/超时返回 []（放行）。"""
    try:
        import requests
        r = requests.post(SENSITIVE_API,
                          data={'InputText': s[:1000]},
                          headers={'Referer': 'https://products.aspose.ai/',
                                   'User-Agent': 'Mozilla/5.0'},
                          timeout=SENSITIVE_TIMEOUT)
        obj = r.json()
        if not obj.get('success'):
            log('SENSITIVE aspose success!=true', repr(obj)[:200])
            return []
        if not obj.get('hateSpeechDetected'):
            return []
        data = obj.get('data')
        hits = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    w = str(item.get('text') or '').strip()
                    flag = str(item.get('flags') or '')
                else:
                    w, flag = str(item).strip(), ''
                if w and w.lower() != 'no hate speech detected in the provided text.':
                    hits.append(w if not flag else w)
        return hits
    except Exception as e:
        log('SENSITIVE aspose fail-open', repr(e))
        return []

def _check_glm(s):
    """GLM 辅助审核：只采信明确命中；超时/异常/解析失败一律放行。结果缓存 1 小时。"""
    if not GLM_ENABLED:
        return []
    try:
        import requests
        import hashlib
        key = hashlib.sha256(s.encode('utf8')).hexdigest()
        now = time.time()
        cached = _glm_cache.get(key)
        if cached and now - cached[0] < 3600:
            return list(cached[1])
        r = requests.get(GLM_API,
                         params={'user': 'ps_' + key[:24],
                                 'msg': s[:1000],
                                 'system': GLM_SYSTEM,
                                 'type': 'json'},
                         timeout=GLM_TIMEOUT)
        obj = r.json()
        reply = obj.get('reply')
        if obj.get('code') != 200 or not isinstance(reply, str):
            return []
        txt = reply.strip()
        if txt.startswith('```'):
            txt = txt.split('\n', 1)[-1]
            txt = txt.rsplit('```', 1)[0]
        i, j = txt.find('{'), txt.rfind('}')
        if i < 0 or j <= i:
            return []
        d = json.loads(txt[i:j + 1])
        cat = str(d.get('category') or '').strip()
        passed = d.get('pass')
        hit = (passed is False) or (bool(cat) and cat != '正常')
        hits = []
        if hit:
            reason = str(d.get('reason') or '').strip()
            hits = ['GLM:' + cat + (('(' + reason + ')') if reason else '')]
        if len(_glm_cache) > 2000:
            _glm_cache.clear()
        _glm_cache[key] = (now, hits)
        return hits
    except Exception as e:
        log('SENSITIVE glm fail-open', repr(e))
        return []

def sensitive_check(text):
    """三路并联：本地词库 + Aspose AI + GLM；任一命中即拦截，接口故障放行。"""
    load_sensitive_cfg()
    if not SENSITIVE_ENABLED:
        return []
    s = str(text or '').strip()
    if not s:
        return []
    # 第一道：本地词库（离线、稳定、不漏单词）
    local_hits = _check_local(s)
    # 第二/三道：两个网络接口并行，取较慢者，互不拖累
    import concurrent.futures
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    try:
        f_api = ex.submit(_check_aspose, s)
        f_glm = ex.submit(_check_glm, s)
        api_hits = f_api.result()
        glm_hits = f_glm.result()
    finally:
        ex.shutdown(wait=False)
    hits = local_hits + api_hits + glm_hits
    # 去重（保序）
    seen, uniq = set(), []
    for w in hits:
        if w in seen or len(w) < 1:
            continue
        seen.add(w)
        uniq.append(w)
    if uniq:
        src = '+'.join([n for n, h in (('local', local_hits), ('aspose', api_hits), ('glm', glm_hits)) if h])
        log('SENSITIVE HIT[%s]' % src, repr(uniq), 'text=', repr(s[:80]))
    return uniq

def make_reply(req):
    if not isinstance(req, dict):
        return None, None
    cmd = req.get('cmd') or 'game_login'
    seq = int(req.get('seq') or 0)
    now = int(time.time() * 1000)
    # ★ 封号号写操作拦截：信誉叶子=0 的玩家，写命令返回 schema 合规空包、服务端不落库。
    #   读命令/登录/心跳全部放行，玩家能看到封号弹窗和页面，但发不出任何内容。
    _ban_uid = _banned_write_uid(cmd)
    if _ban_uid:
        log('  BAN_BLOCK cmd=%s uid=%s' % (cmd, _ban_uid))
        # 触发踢线→客户端重连→登录时弹封号窗（客户端无操作中弹窗通道，只能这样提示）
        _queue_ban_kick(_ban_uid)
        try:
            payload = features.payload(cmd)   # schema 全字段默认值，客户端不白屏
            if isinstance(payload, dict):
                # code 保持 0：客户端 SendCmdAsync 仅当 code==0 才 resolve，
                # 非0 会让 await 永久挂起、界面卡死。封死靠「数据不落库」，提示靠登录弹窗。
                payload['msg'] = '账号已被封禁，无法操作'
                payload['success'] = False
        except Exception:
            payload = {'msg': '账号已被封禁，无法操作'}
    # 业务响应体：data 承载具体配置，list 作为冗余承载，兼容不同客户端取值方式
    elif cmd == 'game_getonedynamicconfig':
        cid = (req.get('body') or {}).get('id', '')
        cfg = config_for_id(cid)
        payload = {'dynamicConfig': cfg,
                   'data': cfg, 'list': cfg.get('list', cfg) if isinstance(cfg, dict) else cfg,
                   'total': cfg.get('total', 0) if isinstance(cfg, dict) else 0,
                   'id': cid, 'code': 0, 'msg': 'ok'}
    elif cmd == 'game_getgiftdyncfg':
        payload = {'data': {'giftList': [], 'list': []}, 'list': [], 'code': 0, 'msg': 'ok'}
    elif cmd == 'game_saveguide':
        # Game_RSaveGuide = class extends re {}（空 schema），回空对象即可。
        # 教程已由 role.completeTaskIds 全量完成，正常不会再走到这里。
        payload = {}
    elif cmd in ('game_createtalk', 'game_createofficialtalk'):
        # 客户端 publishTalk() -> SendCmdAsync(..., Game_RCreateTalk)
        # Game_RCreateTalk: code(a0) / sensitiveWords(a2) / talkData(a1 TalkData)
        # 成功后客户端把回包 talkData unshift 进本地列表 -> 必须带完整 TalkData。
        # ★ 游客禁止发帖：uid=0 虚拟游客不落库，避免"游客帖"污染社区
        _cu_guard = None
        try:
            _cu_guard = store.current_user()
        except Exception:
            pass
        _uid_guard = str((_cu_guard or {}).get('userId', '')) if isinstance(_cu_guard, dict) else ''
        if (not _uid_guard) or _uid_guard == str(store.GUEST_UID):
            log('TALK_BLOCK guest publish')
            payload = {'code': 1, 'msg': '请先登录后再发布', 'success': False,
                       'result': False, 'sensitiveWords': [], 'talkData': {},
                       'data': {}, 'list': [], 'id': ''}
        else:
            _b = req.get('body') or {}
            # 客户端 SendCmdAsync({cmd, params}) 可能把 params 直接摊在 body，
            # 也可能包一层 body.params，两种都兼容。
            params = _b.get('params') if isinstance(_b.get('params'), dict) else _b
            if not isinstance(params, dict): params = {}
            sc = params.get('simpleContent')
            text = sc.get('text', '') if isinstance(sc, dict) else ''
            # 敏感词检测：标题+正文一起查；命中则拦截发布（不落库），fail-open 放行
            _sensitive_hits = sensitive_check(str(params.get('title') or '') + ' ' + str(text or ''))
            if not _sensitive_hits:
                td = make_talk(str(params.get('title') or '')[:60] or '我的动态',
                               str(text or '')[:500] or '（无正文）', 0, 0)
                td['content'] = params.get('content') if isinstance(params.get('content'), dict) else {}
                # 官方动态命令：正确标记 talkType=official，才能在「官方」页签显示
                if cmd == 'game_createofficialtalk':
                    td['talkType'] = 'official'
                elif params.get('talkType'):
                    td['talkType'] = str(params.get('talkType'))
                # 动态归属当前账号 + 走共享层持久化（后台可删改）
                try:
                    cu = store.current_user()
                    if isinstance(cu, dict):
                        # 不要覆写 uId：它是动态唯一主键，由 store.add_talk 统一赋 talkId
                        try:
                            td['playerId'] = int(cu.get('userId', td['playerId']))
                        except Exception:
                            pass
                        td['userName'] = str(cu.get('userName') or td['userName'])
                        td['userIntro'] = str(cu.get('userIntro') or '')
                        td['userLevel'] = cu.get('level', td['userLevel'])
                except Exception:
                    pass
                td = store.add_talk(td)
                print('  [talk] CREATE title=%r total=%d' % (td['title'], len(store.load_talks())), flush=True)
                payload = {'code': 0, 'msg': 'ok', 'success': True, 'result': True,
                           'sensitiveWords': [], 'talkData': td,
                           'data': td, 'list': [], 'id': td.get('uId', '')}
            else:
                log('TALK_BLOCK sensitive', repr(_sensitive_hits))
                payload = {'code': 1, 'msg': '内容含敏感词，请修改后发布',
                           'success': False, 'result': False,
                           'sensitiveWords': _sensitive_hits,
                           'talkData': {}, 'data': {}, 'list': [], 'id': ''}

    elif cmd in ('game_loadtalk', 'game_loadowntalk', 'game_loadtalkbyidlist'):
        # Game_RLoadTalk = Wo: startMember(se0) / talkList(se2 TalkData)
        # 按客户端请求的 talkType 分类返回（官方/精选/动态页签互不串显）
        # ★ game_loadowntalk 进别人主页时带 roleId：必须只返回该用户的动态
        _tt = req_param(req, 'talkType', None)
        _owner = None
        if cmd == 'game_loadowntalk':
            for _k in ('roleId', 'userId', 'uid', 'playerId', 'id'):
                _v = req_param(req, _k, None)
                if _v not in (None, '', 0, '0'):
                    _owner = _v
                    break
            # 进主页看某人全部帖子：绕开 talkType 分类过滤（否则官方/精选帖被排除）
            if _owner is not None and _tt in (None, '', 'trends'):
                _tt = 'all'
        _list = all_talks(_tt, uid=_owner)
        payload = {'talkList': _list, 'startMember': '',
                   'total': len(_list), 'code': 0, 'msg': 'ok',
                   'data': {'talkList': _list}, 'list': _list}
    elif cmd == 'game_searchtalk':
        # 搜索帖子：按关键词匹配标题/正文/作者，返回 TalkList（客户端 Game_RSearchTalk）
        _kw = str(req_param(req, 'searchName', req_param(req, 'keyword', req_param(req, 'searchKey', ''))) or '').strip()
        _all = all_talks(None)
        if _kw:
            def _hit(t):
                blob = ' '.join(str(t.get(k, '')) for k in ('title', 'userName', 'userIntro'))
                sc = t.get('simpleContent')
                if isinstance(sc, dict): blob += ' ' + str(sc.get('text', ''))
                ct = t.get('content')
                if isinstance(ct, dict):
                    for sec in (ct.get('sections') or []):
                        if isinstance(sec, dict): blob += ' ' + str(sec.get('text', ''))
                return _kw.lower() in blob.lower()
            _list = [t for t in _all if _hit(t)]
        else:
            _list = _all
        try:
            _s = int(req_param(req, 'start', 0) or 0)
            _e = int(req_param(req, 'end', len(_list)) or len(_list))
        except Exception:
            _s, _e = 0, len(_list)
        _page = _list[_s:_e]
        payload = {'talkList': _page, 'startMember': '', 'total': len(_list),
                   'code': 0, 'msg': 'ok',
                   'data': {'talkList': _page}, 'list': _page}
    elif cmd == 'game_searchgame':
        # 搜索作品：按名称模糊匹配，返回 Game_RSearchGame.gameDatas
        _kw = str(req_param(req, 'searchName', req_param(req, 'keyword', '')) or '').strip().lower()
        _all = dynamic_games()
        _list = [g for g in _all if (not _kw or _kw in str(g.get('name', '')).lower())]
        try:
            _s = int(req_param(req, 'start', 0) or 0)
            _e = int(req_param(req, 'end', len(_list)) or len(_list))
        except Exception:
            _s, _e = 0, len(_list)
        _page = _list[_s:_e]
        payload = {'gameDatas': _page, 'data': {'gameDatas': _page},
                   'list': _page, 'total': len(_list), 'code': 0, 'msg': 'ok'}
    elif cmd == 'game_searchrole':
        # 搜索用户：按昵称模糊匹配，返回 Game_RSearchRole.roleDatas
        _kw = str(req_param(req, 'searchName', req_param(req, 'keyword', '')) or '').strip().lower()
        _all = []
        try:
            _db = store.load_db()
            for _pid, _u in (_db.get('users') or {}).items():
                if not isinstance(_u, dict):
                    continue
                if _kw and _kw not in str(_u.get('userName', '')).lower():
                    continue
                _all.append({
                    'id': int(_pid) if str(_pid).isdigit() else _pid,
                    'uId': str(_pid), 'playerId': _pid,
                    'userId': str(_pid),
                    'userName': str(_u.get('userName') or ('玩家' + str(_pid)[-4:])),
                    'userImg': str(_u.get('userImg') or ''),
                    'level': _u.get('level', 1),
                    'authed': bool(_u.get('authed', False)),
                    'userIntro': str(_u.get('userIntro') or ''),
                })
        except Exception:
            pass
        try:
            _s = int(req_param(req, 'start', 0) or 0)
            _e = int(req_param(req, 'end', len(_all)) or len(_all))
        except Exception:
            _s, _e = 0, len(_all)
        _page = _all[_s:_e]
        payload = {'roleDatas': _page, 'data': {'roleDatas': _page},
                   'list': _page, 'total': len(_all), 'code': 0, 'msg': 'ok'}
    elif cmd == 'game_uploadimage':
        # 客户端 Util.uploadPng：发 Game_UploadImage 带 PNG 二进制 content，
        # 期待 Game_RUploadImage = { url, reason }。reason 必须为空才算上传成功。
        content = req_param(req, 'content')
        url = save_upload_png(content) if content is not None else None
        if not url:
            payload = {'code': -1, 'reason': '图片数据为空', 'url': '',
                       'msg': 'upload failed', 'data': {}, 'list': []}
        else:
            payload = {'code': 0, 'reason': '', 'url': url, 'msg': 'ok',
                       'data': {'url': url, 'reason': ''}, 'list': []}
            log('  UPLOADIMG ->', url)
    elif cmd == 'game_updateuserimg':
        # 客户端把 role.newUserImgReviewStatus 硬编码为「审核中」，
        # 服务端在此登记待审核记录；后台通过后 game_login 会下发 success + 新头像。
        url = str(req_param(req, 'newUserImg', '') or '')
        _db = store.load_db()
        _cu = store.current_user()
        _uid = str(_cu.get('userId')) if isinstance(_cu, dict) else (
            _db.get('currentUid') or _db.get('lastUser') or '')
        _r = review.add_pending(_db, _uid, url) if (_uid and url) else None
        store.save_db(_db)
        log('  UPDATEUSERIMG uid=%s url=%s rid=%s auto=%s' %
            (_uid, url, (_r or {}).get('rid'), review.auto_enabled()))
        payload = {'code': 0, 'msg': 'ok', 'result': True, 'success': True,
                   'newUserImg': url, 'status': review.INREVIEW,
                   'data': {'newUserImg': url}, 'list': []}
    elif cmd == 'game_getneedreviewimagelist':
        # Game_RGetNeedReviewImageList = Ft: needImageList(se2)。空列表=无待审图
        payload = {'needImageList': [], 'code': 0, 'msg': 'ok',
                   'data': {'needImageList': []}, 'list': []}
    elif cmd == 'game_getuserdetailmsg':
        # Game_RGetUserDetailMsg = Io: userDetailMsg(se1 UserDetailMsg)
        # ★ 按请求 id 返回「目标用户」的资料。客户端点别人主页时 body 带 {id: 目标uid}，
        #   旧实现永远用 current_user()，导致进任何人的主页都显示自己的信息、只是 ID 不同。
        tid = ''
        try:
            if isinstance(req, dict):
                for _src in (req, req.get('body'), req.get('params'), req.get('data')):
                    if isinstance(_src, dict) and _src.get('id') not in (None, ''):
                        _v = str(_src['id'])
                        # 详情页拿不到作者时会带 id=0；归一化为空 -> 回退当前用户，
                        # 避免显示成「玩家0」并把粉丝/关注数串成自己的。
                        tid = '' if _v in ('0', 'None') else _v
                        break
        except Exception:
            pass
        users, cu = {}, {}
        try:
            users = store.load_db().get('users', {}) or {}
        except Exception:
            pass
        try:
            _cu = store.current_user()
            cu = _cu if isinstance(_cu, dict) else {}
        except Exception:
            pass
        u = users.get(tid) or {}
        if not u and not tid:
            u = cu
        try:
            pid = int(tid or u.get('userId') or cu.get('userId') or 1000001)
        except Exception:
            pid = 1000001
        try:
            _lv = int(u.get('level') or 1)
        except Exception:
            _lv = 1
        ft = {}
        try:
            ft = features.load_feat() if features else {}
        except Exception:
            ft = {}
        my = str(cu.get('userId') or '')
        my_follows = [str(x) for x in (ft.get('follows', {}).get(my, []) or [])]
        fans = ft.get('fans', {}).get(str(pid), []) or []
        follows = ft.get('follows', {}).get(str(pid), []) or []
        detail = features.data_obj('UserDetailMsg', **{
            'playerId': pid,
            'userName': str(u.get('userName') or ('玩家' + str(pid)[-4:])),
            'userImg': str(u.get('userImg') or ''),
            'userIntro': str(u.get('userIntro') or u.get('sign') or ''),
            'level': _lv,
            'isFollow': str(pid) in my_follows,
            'fansCount': len(fans),
            'followCount': len(follows),
            'goodsIds': [],
            'gameDatas': [],
        })
        # 兼容字段（UserDetailMsg 未注册，客户端 setValue 会跳过；调试/后台可读）
        detail['id'] = pid
        detail['uId'] = str(pid)
        payload = {'userDetailMsg': detail, 'code': 0, 'msg': 'ok',
                   'data': detail, 'list': []}
    elif cmd == 'game_getusersimplemsg':
        # Game_RGetUserSimpleMsg = bo: userSimpleMsgList(se2 UserSimpleMsg)
        sm = {'id': 1000111, 'userName': '玩家', 'userImg': '',
              'coin': 8888, 'diamond': 100, 'level': 99,
              'creditScore': 3, 'isFollow': False, 'authed': False,
              'fansCount': 0, 'followsCount': 0}
        try:
            cu = store.current_user()
            if isinstance(cu, dict):
                try:
                    sm['id'] = int(cu.get('userId', sm['id']))
                except Exception:
                    pass
                sm['userName'] = str(cu.get('userName') or sm['userName'])
                sm['coin'] = cu.get('coin', sm['coin'])
                sm['diamond'] = cu.get('diamond', sm['diamond'])
                sm['level'] = cu.get('level', sm['level'])
                sm['authed'] = bool(cu.get('authed', False))
                # 信誉分读真实值（后台加/扣后即时反映），0~3 等级点
                try:
                    _ft = features.load_feat() if features else {}
                    _cid = str(cu.get('userId') or sm['id'])
                    sm['creditScore'] = max(0, min(3, features.as_int(_ft.get('credit', {}).get(_cid, {}).get('score'), 3)))
                except Exception:
                    pass
        except Exception:
            pass
        payload = {'userSimpleMsgList': [sm], 'code': 0, 'msg': 'ok',
                   'data': {'userSimpleMsgList': [sm]}, 'list': [sm]}
    elif cmd == 'game_getusercreditmsg':
        # 信誉明细（CreditScene.loadData 读 userCreditMsgList / creditScoreRecoverProcess）。
        # 客户端 CreditMng.loadData 只在首次进入时拉一次，故此处返回当前用户的真实明细。
        _list = []
        _process = 0
        try:
            _cu = store.current_user()
            _uid = str(_cu.get('userId')) if isinstance(_cu, dict) else None
            if _uid:
                _ft = features.load_feat() if features else {}
                _cs = _ft.get('credit', {}).get(_uid, {})
                _list = _cs.get('list', [])[:50]
                _process = features.as_int(_cs.get('recoverProcess'), 0)
        except Exception:
            pass
        payload = {'userCreditMsgList': _list, 'creditMsgList': _list,
                   'creditScoreRecoverProcess': _process, 'code': 0, 'msg': 'ok',
                   'data': {'userCreditMsgList': _list}, 'list': _list}
    elif cmd in ('game_gethomepagegamedata', 'game_gethomepagenewgames',
                 'game_gethomepagerecommendsgames', 'game_gethomepagefollowusergames'):
        # GameMng.loadGames(ids) -> Game_RGetHomepageGameData.gameDatas (GameCellData[])
        # 客户端不按 ids 过滤，直接采用回包里的 gameDatas
        _gd = dynamic_games()
        payload = {'gameDatas': _gd, 'data': {'gameDatas': _gd},
                   'list': _gd, 'total': len(_gd), 'startMember': '',
                   'code': 0, 'msg': 'ok'}
    elif cmd == 'game_login':
        # ★ 关键：按 Game_RLogin schema 返回完整字段，原版首页才有数据可渲染
        payload = login_payload(now)
    else:
        # 其它 cmd：先交给统一功能层分发（社交/内容/编辑器/商城）。
        # 未命中返回 None -> 走原兜底，已跑通的 20 个分支完全不受影响。
        _ext = None
        if features is not None:
            try:
                _ext = features.dispatch(cmd, req)
            except Exception as _fe:
                log('  FEATURE_ERR', cmd, str(_fe))
        if _ext is not None:
            payload = _ext
        else:
            # 未知指令：保持会话字段
            payload = {
                'code': 0, 'msg': 'ok', 'channel': 'hortor', 'time': now,
                'roleId': 1000111, 'userId': '1000111', 'userName': 'privsrv',
                'isRestore': 0, 'serverTime': now, 'sessionId': str(now),
                'gameId': 'GameCreator-app', 'data': {}, 'list': [],
            }
    # ★★ 关键（来自客户端 WC_doReceive 源码）：
    #   n.decBody = n.body && bon.decode(n.body);   <- 直接对 body 做【裸 bon】解码
    #   这一行在 try 最开头，若 body 不是合法 bon 会抛异常 -> 整个 doReceive 进 catch，
    #   后面的 `if (n.resp === i.seq) i.resolve(n)` 不会执行 -> sendAsync Promise 永远 pending
    #   -> App 卡在 game_login，首页内容请求发不出去（首页空白）。
    #   因此 body 必须是【裸 bon(payload) 字节】，绝不能是 lz4 流（那是 HTTP 登录的套路）。
    # 补强已实现分支：给 game_login / game_loadtalk 等附加互动数据（内部 try 保护）
    if features is not None:
        try:
            payload = features.post_process_all(cmd, payload, req)
        except Exception as _fe:
            log('  POSTPROC_ERR', cmd, str(_fe))
    body_raw = bon_encode(payload)   # 裸 bon 字节，客户端 bon.decode 可直接解
    msg = {
        'ack': seq,        # 确认客户端发出去的包（_sndQueue.confirm）
        'resp': seq,       # ★关键：让 doReceive 里 sendAsync 的 Promise resolve（须严格 === 请求 seq）
        'cmd': cmd,        # 非 _sys/*，才会进 default -> doReceive
        'body': body_raw,  # 裸 bon 字节（客户端 bon.decode(n.body) 得到 payload）
        'time': now,
        'code': 0,         # doReceive: n.code = ~~n.code，负值会进 Error 状态
        # seq 故意不给（保持 0），客户端心跳就会走单字节 0x00
        # 冗余：业务字段同时放在外层，兼容「直接读 msg.data/list」的取值方式
        'data': payload.get('data', {}),
        'list': payload.get('list', []),
        'total': payload.get('total', 0),
        'id': payload.get('id', ''),
        'roleId': payload.get('roleId', 1000111),
        'userId': payload.get('userId', '1000111'),
        'userName': payload.get('userName', 'privsrv'),
        'sessionId': payload.get('sessionId', str(now)),
        'serverTime': payload.get('serverTime', now),
    }
    return lz4_xor_encode(bon_encode(msg)), msg


async def handler(ws, *args):
    try:
        req = getattr(ws, 'request', None)
        path = getattr(req, 'path', '?') if req else '?'
        hdr = dict(req.headers) if req is not None and hasattr(req, 'headers') else {}
    except Exception:
        path, hdr = '?', {}
    log('CONNECT', path, ws.remote_address, json.dumps(hdr, ensure_ascii=False)[:300])
    # 连接级身份：从 ?p={"roleToken":...} 解析本连接 uid，避免多人共享全局 currentUid 串号
    conn_uid = ''
    try:
        import urllib.parse
        _q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query).get('p', [''])[0]
        if _q:
            _pj = json.loads(_q)
            _tok = str((_pj or {}).get('roleToken', '') or '')
            if _tok:
                _uid_by_tok, _ = store.user_by_token(_tok)
                conn_uid = str(_uid_by_tok) if _uid_by_tok else ''
    except Exception as _ue:
        log('  UID_PARSE_ERR', repr(_ue))
    log('  BIND uid=%s' % (conn_uid or '(fallback-global)'))
    # 封号玩家允许登录：登录回包下发 creditScore=0，客户端据此显示「被封」提示并限制功能。
    # 只在「封号动作发生的那一刻」由 kick 指令踢掉在线连接（实时掉线）；重连不再拦截，
    # 否则客户端会陷入 BIND->REJECT 死循环、卡在「下线完成」界面（用户反馈的问题）。
    # 绑定 ws 对象，供后台封号时实时踢线
    ws_bind(conn_uid, ws)
    # 在线登记：从 p 参数取 connId，IP 用对端地址（经 nginx 转发时为 127.0.0.1）
    _cid = ''
    _peer_ip = ''
    try:
        import urllib.parse as _up
        _peer_ip = (ws.remote_address[0] if ws.remote_address else '')
        _q2 = _up.parse_qs(_up.urlparse(path).query).get('p', [''])[0]
        if _q2:
            _cid = str((json.loads(_q2) or {}).get('connId', '') or '')
    except Exception:
        pass
    if not _cid:
        _cid = '%s:%s' % (_peer_ip, id(ws))
    online_add(_cid, conn_uid, _peer_ip)
    try:
        async for msg in ws:
            online_touch(_cid)
            if isinstance(msg, (bytes, bytearray)):
                b = bytes(msg)
                log('RECV bin', len(b), b[:120].hex())
                # 单字节 0x00 = 客户端心跳；addResp 开头会 resetConnectionTimeout，
                # 只要回任意一个字节即可保活，且 <=1 会直接 return，不触发业务分发。
                if len(b) <= 1:
                    log('  PING -> PONG 0x00')
                    try:
                        await ws.send(b'\x00')
                    except Exception:
                        pass
                    continue
                raw = inflate_raw(b)
                reqobj = None
                if raw:
                    log('  INFLATE', len(raw), readable(raw))
                    try:
                        reqobj = bon_decode(raw)
                        log('  REQ', json.dumps(reqobj, ensure_ascii=False, default=str)[:500])
                    except Exception as e:
                        log('  BONERR', str(e))
                cmd = reqobj.get('cmd', '') if isinstance(reqobj, dict) else ''
                # 系统帧（_sys/ack 心跳确认等）：addResp 里直接 return，只需回一个字节保活
                if cmd.startswith('_sys/'):
                    log('  SYS', cmd, '-> PONG 0x00')
                    try:
                        await ws.send(b'\x00')
                    except Exception:
                        pass
                    continue
                _cv_tok = store.set_session_uid(conn_uid)
                try:
                    frame, reply = make_reply(reqobj)
                finally:
                    store.clear_session_uid(_cv_tok)
                if frame:
                    log('  SENT', json.dumps({k: (v if not isinstance(v, bytes) else '<bin %d B>' % len(v))
                                             for k, v in reply.items()}, ensure_ascii=False)[:400])
                    try:
                        await ws.send(frame)
                    except Exception as e:
                        log('  SENDERR', str(e))
            else:
                log('RECV txt', len(msg), str(msg)[:300])
                try:
                    await ws.send(b'\x00')
                except Exception:
                    pass
    except Exception:
        log('ERR', traceback.format_exc()[-400:].replace('\n', ' | '))
    online_remove(_cid)
    ws_unbind(conn_uid, ws)
    log('CLOSE', path)


async def _online_flush_loop():
    while True:
        await asyncio.sleep(5)
        online_maybe_flush()


async def main():
    async with websockets.serve(handler, '127.0.0.1', 8765, max_size=None,
                                ping_interval=None):
        log('LISTEN 127.0.0.1:8765')
        asyncio.ensure_future(_online_flush_loop())
        asyncio.ensure_future(_kick_watch_loop())
        await asyncio.Future()


if __name__ == '__main__':
    asyncio.run(main())
