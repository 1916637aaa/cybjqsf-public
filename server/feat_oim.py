#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OIM 私聊：会话列表 / 历史消息 / 发送消息 / 删除会话。

客户端协议（源码 index.e248a.js 77644 / 80020 / 82182）：
  命令 oim_getconversationlist / oim_gethistory / oim_sendmsg / oim_delconversation
  响应 OIM_GetConversationListResp(convs: OIMConversation[])
       OIM_GetHistoryResp(msgs: OIMMsg[])
  OIMMsg         : id, from(OIMUser), oppId, time(Date), convType, contType, content, extra
  OIMConversation: convType, oppId, oppInfo(OIMUser), time
  OIMUser        : id, name, avatar, extra
  convType: system=0 peer=1 group=2 chatRoom=3 world=4 server=5
  contType: text=0 image=1 voice=2 custom=99

注意：该版本客户端只有协议与数据类，没有聊天界面调用点；本模块把服务端能力
补完整（真实 WS 可验证），并让预置的测试账号对话能被读到。

数据全部落 db.feat.oimMsgs / oimBots / oimHidden，用 F.mutate 保证跨进程一致。
绝不在 mutate 事务内调用 store.load_db()（flock 会自死锁），用户资料一律在
顶层取好快照再传入事务。
"""
import features as F

PEER = 1      # OIMConversationType.peer
TEXT = 0      # OIMContentType.text

_REPLIES = [
    '哈哈，我看到啦～',
    '这个作品我也玩了，挺有意思的！',
    '好呀，回头一起做张地图吧',
    '收到！等你更新新作品哦',
    '你最近又出新作了？我去看看',
    '嗯嗯，我关注你啦，常联系～',
]


def cmd(req, default):
    return (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or default


def _opp(req):
    """对端 id，兼容客户端各种参数名；0 表示未指定。"""
    return F.as_int(F.first(req, 0, 'oppId', 'oppID', 'playerId', 'targetId',
                            'peerId', 'to', 'toId', 'id', 'rid', 'userId'), 0)


def _me():
    """当前用户 OIMUser 快照（顶层调用，不在事务内）。"""
    u = {}
    try:
        import store
        cu = store.current_user()
        if isinstance(cu, dict):
            u = cu
    except Exception:
        pass
    uid = F.as_int(F.uid(), 0)
    return F.data_obj('OIMUser', **{
        'id': uid,
        'name': str(u.get('userName') or F.uname() or '我'),
        'avatar': str(u.get('userImg') or ''),
        'extra': '',
    })


def _user_of(ft, pid, me):
    """对端 OIMUser：优先用历史消息里的 from 快照，其次 db.users 资料。"""
    p = F.as_int(pid, 0)
    if p == F.as_int(me.get('id'), 0):
        return dict(me)
    snap = None
    for m in reversed(ft.get('oimMsgs', [])):
        fr = m.get('from')
        if isinstance(fr, dict) and F.as_int(fr.get('id'), 0) == p:
            snap = fr
            break
    if snap is None:
        try:
            import json
            with open(F.DB_FILE, encoding='utf8') as f:
                db = json.load(f)
            u = (db.get('users') or {}).get(str(p))
            if isinstance(u, dict):
                snap = {'id': p, 'name': str(u.get('userName') or ('玩家' + str(p)[-4:])),
                        'avatar': str(u.get('userImg') or ''), 'extra': ''}
        except Exception:
            pass
    if snap is None:
        snap = {'id': p, 'name': '玩家' + str(p)[-4:], 'avatar': '', 'extra': ''}
    return F.data_obj('OIMUser', **snap)


def _msg(mid, sender, opp_id, content, stamp, conv=PEER, cont=TEXT, extra=''):
    """构造一条 schema 合规的 OIMMsg dict（from 是关键字，用 **dict 传入）。"""
    return F.data_obj('OIMMsg', **{
        'id': mid, 'from': sender, 'oppId': opp_id, 'time': stamp,
        'convType': conv, 'contType': cont, 'content': str(content), 'extra': extra,
    })


def _from_id(m):
    fr = m.get('from')
    return F.as_int(fr.get('id'), 0) if isinstance(fr, dict) else 0


def _pair(ft, me_id, opp):
    """两人之间的全部消息，按时间升序。"""
    out = []
    for m in ft.get('oimMsgs', []):
        if not isinstance(m, dict):
            continue
        fid = _from_id(m)
        oid = F.as_int(m.get('oppId'), 0)
        if (fid == me_id and oid == opp) or (fid == opp and oid == me_id):
            out.append(m)
    out.sort(key=lambda x: F.as_int(x.get('time'), 0))
    return out


def _pick_reply(content, stamp):
    return _REPLIES[(len(str(content)) + stamp) % len(_REPLIES)]


@F.register('oim_getconversationlist')
def h_convs(req):
    ft = F.load_feat()
    me = _me()
    me_id = F.as_int(me.get('id'), 0)
    hidden = set(str(x) for x in (ft.get('oimHidden', {}).get(str(me_id), []) or []))
    peers = {}   # pid -> (lastStamp, snap or None)
    for m in ft.get('oimMsgs', []):
        if not isinstance(m, dict):
            continue
        fid = _from_id(m)
        oid = F.as_int(m.get('oppId'), 0)
        if fid == me_id and oid and oid != me_id:
            peer, snap = oid, None
        elif oid == me_id and fid and fid != me_id:
            peer, snap = fid, m.get('from')
        else:
            continue
        if str(peer) in hidden:
            continue
        t = F.as_int(m.get('time'), 0)
        if peer not in peers or t > peers[peer][0]:
            peers[peer] = (t, snap)
    convs = []
    for p, (t, snap) in sorted(peers.items(), key=lambda kv: -kv[1][0]):
        info = snap if isinstance(snap, dict) and F.as_int(snap.get('id'), 0) == p else _user_of(ft, p, me)
        convs.append(F.data_obj('OIMConversation', **{
            'convType': PEER, 'oppId': p, 'oppInfo': info, 'time': t,
        }))
    return F.payload('oim_getconversationlist', convs=convs)


@F.register('oim_gethistory')
def h_history(req):
    c = cmd(req, 'oim_gethistory')
    opp = _opp(req)
    ft = F.load_feat()
    me_id = F.as_int(F.uid(), 0)
    msgs = _pair(ft, me_id, opp) if opp else []
    s = max(0, F.as_int(F.first(req, 0, 'startIndex', 'start', 'offset'), 0))
    cnt = F.as_int(F.first(req, 200, 'count', 'limit', 'pageSize', 'pageCount'), 200)
    cnt = max(1, min(cnt, 500))
    # 兼容把 endIndex 当「数量」传的调用
    e = F.as_int(F.first(req, 0, 'endIndex', 'end'), 0)
    if 0 < e <= 500 and e < cnt:
        cnt = e
    return F.payload(c, msgs=msgs[s:s + cnt])


@F.register('oim_sendmsg')
def h_send(req):
    c = cmd(req, 'oim_sendmsg')
    opp = _opp(req)
    content = str(F.first(req, '', 'content', 'msg', 'text', 'message', 'cont') or '')
    conv = F.as_int(F.first(req, PEER, 'convType'), PEER)
    cont = F.as_int(F.first(req, TEXT, 'contType'), TEXT)
    # 空消息/未指定对端：不落库（探针、回归的空请求会走到这里）
    if not opp or not content.strip():
        return F.payload(c, id=0, code=0)
    # 私信敏感词检测（与发帖/评论同一套三路）；命中不落库
    try:
        import agentsrv as _asrv
        _hits = _asrv.sensitive_check(content)
        if _hits:
            return F.payload(c, id=0, code=1, msg='内容含敏感词，无法发送',
                             result=False, success=False, sensitiveWords=_hits)
    except Exception:
        pass

    me = _me()
    me_id = F.as_int(me.get('id'), 0)
    stamp = F.now_ms()

    # 顶层先取好「对方」资料与是否需要自动回复，事务内不再读 db
    ft0 = F.load_feat()
    bots = [F.as_int(x, 0) for x in (ft0.get('oimBots', []) or [])]
    bot_user = _user_of(ft0, opp, me) if (opp and opp in bots) else None
    reply = _pick_reply(content, stamp) if bot_user else None

    def fn(ft, db):
        msgs = ft.setdefault('oimMsgs', [])
        mid = F.next_id(ft, 'oim')
        msgs.append(_msg(mid, me, opp, content, stamp, conv, cont))
        if bot_user and reply and opp:
            msgs.append(_msg(F.next_id(ft, 'oim'), bot_user, me_id,
                             reply, stamp + 1200, conv, cont))
        ft['oimMsgs'] = msgs[-1000:]
        return mid

    mid = F.mutate(fn)
    return F.payload(c, id=mid, code=0)


@F.register('oim_delconversation')
def h_delconv(req):
    c = cmd(req, 'oim_delconversation')
    opp = _opp(req)
    me_id = F.as_int(F.uid(), 0)

    def fn(ft, db):
        h = ft.setdefault('oimHidden', {}).setdefault(str(me_id), [])
        if opp and str(opp) not in h:
            h.append(str(opp))

    F.mutate(fn)
    return F.payload(c, code=0)


def post_process(cmd, payload, req):
    """占位：OIM 命令由本模块直接产出回包，无需补强 agentsrv 分支。"""
    return payload
