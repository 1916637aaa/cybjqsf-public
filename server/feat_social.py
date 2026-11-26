#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""社交互动：点赞/顶踩、关注/粉丝、评论/回复、收藏、消息通知。

字段名与类型全部来自客户端 _autogen/cmd 响应类（protocol.json），由 features.payload()
做 schema 合规填充，业务值覆盖时自动类型对齐。
"""
import features as F

# ============================ 点赞 / 顶踩 ============================
def _talk_id(req):
    return F.first(req, '', 'talkId', 'iD', 'id', 'talkID')

def _game_ids(req):
    return F.as_list(F.first(req, [], 'ids', 'id', 'gameId', 'gameIds'))

def _comment_id(req):
    return F.first(req, '', 'commentId', 'id', 'iD')

@F.register('game_uptalk', 'game_downtalk', 'game_canceluptalk', 'game_canceldowntalk',
            'game_uptalkcomment', 'game_downtalkcomment')
def h_updown(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_uptalk'
    field = 'down' if 'down' in cmd else 'up'
    on = not cmd.startswith('game_cancel')
    # 评论顶踩用 commentId 作 key
    if 'comment' in cmd:
        tid = _comment_id(req); u = F.uid(); kind = 'talkcomment'
    else:
        tid = _talk_id(req); u = F.uid(); kind = 'talk'
    def fn(ft, db):
        F.set_thumb(ft, kind, tid, u, field, on)
        return F.thumb_state(ft, kind, tid, u)[0]
    n = F.mutate(fn)
    return F.payload(cmd, upCnt=n, thumbCnt=n)

@F.register('game_thumbtalk', 'game_cancelthumbtalk')
def h_thumbtalk(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_thumbtalk'
    tid = _talk_id(req); u = F.uid(); on = not cmd.startswith('game_cancel')
    def fn(ft, db):
        F.set_thumb(ft, 'talkthumb', tid, u, 'like', on)
        return F.thumb_state(ft, 'talkthumb', tid, u)[3]
    n = F.mutate(fn)
    return F.payload(cmd, thumbCnt=n, upCnt=n)

@F.register('game_thumbgames', 'game_cancelthumbgames')
def h_thumbgames(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_thumbgames'
    ids = _game_ids(req); u = F.uid(); on = not cmd.startswith('game_cancel')
    def fn(ft, db):
        for gid in ids: F.set_thumb(ft, 'game', gid, u, 'like', on)
        return ids
    F.mutate(fn)
    return F.payload(cmd, ids=ids)

@F.register('game_thumbtalkcomment', 'game_cancelthumbtalkcomment',
            'game_thumbgamecomment', 'game_cancelthumbgamecomment')
def h_thumbcomment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_thumbtalkcomment'
    cid = _comment_id(req); u = F.uid(); on = not cmd.startswith('game_cancel')
    kind = 'gamecomment' if 'gamecomment' in cmd else 'talkcomment'
    def fn(ft, db):
        F.set_thumb(ft, kind, cid, u, 'like', on)
        for c in ft.get('comments', []):
            if str(c.get('id')) == str(cid):
                c['thumbCnt'] = n = len(ft['thumbs'].get(F.thumb_key(kind, cid), {}).get('like', []))
                c['likeCnt'] = n
                break
        return len(ft['thumbs'].get(F.thumb_key(kind, cid), {}).get('like', []))
    n = F.mutate(fn)
    return F.payload(cmd, thumbCnt=n)

@F.register('game_getthumbtalkcomment', 'game_getthumbgamecomment')
def h_getthumbcomment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_getthumbtalkcomment'
    ft = F.load_feat()
    kind = 'gamecomment' if 'gamecomment' in cmd else 'talkcomment'
    m = {}
    for k, v in ft.get('thumbs', {}).items():
        if k.startswith(kind + '|'): m[k.split('|', 1)[1]] = len(v.get('like', []))
    key = 'gameCommentMap' if kind == 'gamecomment' else 'thumbMap'
    return F.payload(cmd, **{key: m})

# ============================ 关注 / 粉丝 ============================
@F.register('game_followuser', 'game_cancelfollowuser')
def h_follow(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_followuser'
    fid = str(F.first(req, '', 'followId', 'id', 'playerId', 'rid'))
    u = F.uid(); on = cmd == 'game_followuser'
    def fn(ft, db):
        fol = ft.setdefault('follows', {}).setdefault(u, [])
        fans = ft.setdefault('fans', {}).setdefault(fid, [])
        nf = ft.setdefault('newFans', {}).setdefault(fid, [])
        if on:
            if fid not in fol: fol.append(fid)
            if u not in fans: fans.append(u)
            if fid == u: nf.remove(u) if u in nf else None
        else:
            if fid in fol: fol.remove(fid)
            if u in fans: fans.remove(u)
        # 同步用户表计数（后台可见）
        us = db.get('users', {})
        if isinstance(us, dict):
            if u in us: us[u]['followCount'] = len(fol)
            if fid in us: us[fid]['fansCount'] = len(fans)
        return len(fol)
    F.mutate(fn)
    return F.payload(cmd, followId=F.as_int(fid, 0), result=True, success=True)

@F.register('game_getfollow')
def h_getfollow(req):
    rid = str(F.first(req, F.uid(), 'rid', 'playerId', 'id'))
    ft = F.load_feat()
    return F.payload('game_getfollow', ids=[F.as_int(x, 0) for x in ft.get('follows', {}).get(rid, [])])

@F.register('game_getfans')
def h_getfans(req):
    rid = str(F.first(req, F.uid(), 'rid', 'playerId', 'id'))
    s = F.as_int(F.first(req, 0, 'startIndex', 'start'), 0)
    e = F.as_int(F.first(req, 20, 'endIndex', 'end'), 20)
    ft = F.load_feat()
    ids = [F.as_int(x, 0) for x in ft.get('fans', {}).get(rid, [])]
    nf = len(ft.get('newFans', {}).get(rid, []))
    return F.payload('game_getfans', ids=ids[s:e], newFansCnt=nf)

@F.register('game_clearnewfans')
def h_clearnewfans(req):
    u = F.uid()
    F.mutate(lambda ft, db: ft.setdefault('newFans', {}).__setitem__(u, []))
    # 客户端 Game_RClearNewFans 是「空响应类」(class extends re {})。
    # body 必须是干净的裸 BON 空对象；带多余字段会让 DecodeMsg 异常 ->
    # SendCmdAsync 完不成 -> refresh() 卡在清红点，后面的 appendLoadFansIds/loadInfos
    # 永远不会执行，粉丝页就一直空白。
    return F.EMPTY_RESP

# ============================ 评论 / 回复 ============================
def _new_comment(ft, req, kind, parent=0):
    tid = str(F.first(req, '', 'talkId', 'gameId', 'id') if kind == 'talk' else
              F.first(req, '', 'gameId', 'id', 'talkId'))
    cid = F.first(req, '', 'commentId', 'replayCommentId', 'parentId')
    content = F.first(req, '', 'content', 'msg', 'reviewStr', 'text')
    if isinstance(content, dict): content = content.get('text', '') or content.get('msg', '')
    content = str(content or '')[:500]
    my = F.uid()
    rec = {
        'id': F.next_id(ft, 'comment'),
        '_kind': kind, '_target': tid, '_parent': F.as_int(parent or cid, 0),
        'playerId': F.as_int(my, 0), 'userName': F.uname(), 'userImg': F.uimg(),
        'userIntro': '', 'userLevel': F.as_int(F.ulevel(), 10),
        'stamp': F.now_ms(), 'thumbCnt': 0, 'likeCnt': 0, 'reportCnt': 0,
        'openCnt': 0, 'status': 1, 'offReason': {},
        'replayCommentId': F.as_int(parent or cid, 0),
        'targetPlayerId': 0, 'targetPlayerName': '',
    }
    if kind == 'talk':
        rec.update({'talkId': F.as_int(tid, 0), 'content': content,
                    'subCommentsCnt': 0, 'comments': [], 'commentIds': []})
    else:
        rec.update({'gameId': F.as_int(tid, 0), 'gameIcon': '', 'msg': content,
                    'subCommentsCnt': 0, 'comments': [], 'commentIds': []})
    ft.setdefault('comments', []).append(rec)
    ft['comments'] = ft['comments'][-500:]
    return rec, tid, content

@F.register('game_commenttalk', 'game_replytalkcomment', 'game_commentgame')
def h_comment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_commenttalk'
    kind = 'game' if cmd == 'game_commentgame' else 'talk'
    parent = F.as_int(F.first(req, 0, 'commentId', 'replayCommentId', 'parentId'), 0)
    # 评论/回复同样过敏感词三路检测（发帖已接，评论此前遗漏）
    try:
        import agentsrv as _asrv
        _c = F.first(req, '', 'content', 'msg', 'reviewStr', 'text')
        if isinstance(_c, dict):
            _c = _c.get('text', '') or _c.get('msg', '')
        _hits = _asrv.sensitive_check(str(_c or ''))
        if _hits:
            return F.payload(cmd, comment={}, code=1, msg='内容含敏感词，请修改后发表',
                             success=False, result=False, sensitiveWords=_hits)
    except Exception as _e:
        pass   # 检测异常一律放行，不影响评论主流程
    def fn(ft, db):
        rec, tid, content = _new_comment(ft, req, kind, parent)
        cnt = len([c for c in ft['comments'] if c.get('_kind') == kind and
                   str(c.get('_target')) == str(tid) and not c.get('_parent')])
        return rec, tid, cnt
    rec, tid, cnt = F.mutate(fn)
    ft = F.load_feat()
    obj = F.comment_obj(ft, rec, kind)
    if kind == 'talk': F.patch_talk(tid, {'commentsCnt': cnt, 'commentsCntSum': cnt})
    # 给目标作者发一条新评论通知
    F.mutate(lambda f2, db: F.add_msg(f2, 2, F.uid(), text='评论：' + str(rec.get('content') or rec.get('msg') or ''),
                                      userName=F.uname(), userImg=F.uimg()))
    return F.payload(cmd, comment=obj, code=0, sensitiveWords=[])

def _load_comments(req, kind, sub=False, first_level=False):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_loadtalkcomment'
    ft = F.load_feat()
    if sub or first_level:
        cid = F.first(req, '', 'commentId', 'id')
        if first_level:
            obj = None
            for c in ft.get('comments', []):
                if str(c.get('id')) == str(cid):
                    obj = F.comment_obj(ft, c, kind); break
            return F.payload(cmd, comment=obj or {})
        # 子评论按 _parent 匹配
        lst = [F.comment_obj(ft, c, kind) for c in ft.get('comments', [])
               if str(c.get('_kind')) == str(kind) and str(c.get('_parent')) == str(cid)]
        return F.payload(cmd, comments=lst)
    tid = str(F.first(req, '', 'talkId', 'gameId', 'id'))
    lst = [F.comment_obj(ft, c, kind) for c in F.comment_list(ft, kind, tid, 0)]
    s = F.as_int(F.first(req, 0, 'start', 'startIndex'), 0)
    e = F.as_int(F.first(req, 20, 'end', 'endIndex'), 20)
    return F.payload(cmd, comments=lst[s:e], commentsCnt=len(lst), commentsCntSum=len(lst))

@F.register('game_loadtalkcomment', 'game_loadgamecomment', 'game_loadowntalkcomment')
def h_loadcomment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_loadtalkcomment'
    return _load_comments(req, 'game' if 'gamecomment' in cmd else 'talk')

@F.register('game_loadtalksubcomment', 'game_loadgamesubcomment')
def h_loadsub(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_loadtalksubcomment'
    return _load_comments(req, 'game' if 'gamesub' in cmd else 'talk', sub=True)

@F.register('game_loadfirstleveltalkcomment', 'game_loadfirstlevelgamecomment')
def h_loadfirst(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_loadfirstleveltalkcomment'
    return _load_comments(req, 'game' if 'gamecomment' in cmd else 'talk', first_level=True)

@F.register('game_deltalkcomment', 'game_delgamecomment')
def h_delcomment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_deltalkcomment'
    cid = str(F.first(req, '', 'commentId', 'id'))
    def fn(ft, db):
        n = len(ft.get('comments', []))
        ft['comments'] = [c for c in ft.get('comments', [])
                          if str(c.get('id')) != cid and str(c.get('_parent')) != cid]
        return n - len(ft['comments'])
    F.mutate(fn)
    return F.payload(cmd, commentId=F.as_int(cid, 0), code=0)

@F.register('game_modifytalkcomment')
def h_modifycomment(req):
    cid = str(F.first(req, '', 'commentId', 'id'))
    content = str(F.first(req, '', 'content', 'msg', 'reviewStr') or '')[:500]
    # 修改评论：敏感词检测（避免先发正常再改成违规）
    try:
        import agentsrv as _asrv
        _hits = _asrv.sensitive_check(content)
        if _hits:
            return F.payload('game_modifytalkcomment', comment={}, code=1,
                             msg='内容含敏感词，请修改后再提交',
                             result=False, success=False, sensitiveWords=_hits)
    except Exception:
        pass
    def fn(ft, db):
        for c in ft.get('comments', []):
            if str(c.get('id')) == cid:
                c['content'] = content; c['msg'] = content
                return F.comment_obj(ft, c, 'talk')
        return {}
    obj = F.mutate(fn)
    return F.payload('game_modifytalkcomment', comment=obj, code=0)

@F.register('game_reporttalkcomment', 'game_reportgamecomment')
def h_reportcomment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_reporttalkcomment'
    cid = str(F.first(req, '', 'commentId', 'id'))
    reason = str(F.first(req, '', 'reason', 'msg', 'content') or '')[:200]
    def fn(ft, db):
        n = 0
        target_type, target_id, owner_uid, content = 'talk', '', '', ''
        for c in ft.get('comments', []):
            if str(c.get('id')) == cid:
                c['reportCnt'] = F.as_int(c.get('reportCnt'), 0) + 1
                n = c['reportCnt']
                target_type = str(c.get('_kind') or 'talk')
                target_id = str(c.get('_target') or c.get('talkId') or c.get('gameId') or '')
                owner_uid = str(c.get('playerId') or '')
                content = str(c.get('content') or '')[:120]
                break
        # 评论举报也进 reports，后台统一处理；不重复叠加同一人同一评论的举报
        rid = F.next_id(ft, 'report')
        ft.setdefault('reports', []).append({
            'id': rid, 'kind': 'comment', 'targetId': cid,
            'targetType': target_type, 'targetOwner': owner_uid, 'content': content,
            'uid': F.uid(), 'userName': F.uname(), 'reason': reason,
            'stamp': F.now_ms(), 'status': 0,
        })
        ft['reports'] = ft['reports'][-300:]
        return n
    n = F.mutate(fn)
    return F.payload(cmd, reportCnt=n)

@F.register('game_settalkcommenttop', 'game_deltalkcommenttop')
def h_commenttop(req):
    """评论置顶/取消：真实写入 ft['commentTop']，comment_list 会自动置顶优先。"""
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_settalkcommenttop'
    cid = str(F.first(req, '', 'commentId', 'id'))
    on = cmd == 'game_settalkcommenttop'
    # 从评论记录反查 kind/target（客户端未必传目标 id）
    def fn(ft, db):
        kind, target = 'talk', str(F.first(req, '', 'talkId', 'gameId', 'id') or '')
        for c in ft.get('comments', []):
            if str(c.get('id')) == cid:
                kind = str(c.get('_kind') or kind)
                target = str(c.get('_target') or target)
                break
        key = '%s|%s' % (kind, target)
        tops = ft.setdefault('commentTop', {}).setdefault(key, [])
        if on:
            if cid not in tops: tops.append(cid)
        else:
            if cid in tops: tops.remove(cid)
        return tops, key
    tops, key = F.mutate(fn)
    return F.payload(cmd, code=0, commentId=F.as_int(cid, 0), topIds=list(tops))

# ============================ 收藏 ============================
@F.register('game_collectiontalk', 'game_cancelcollectiontalk')
def h_collectiontalk(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_collectiontalk'
    tid = str(F.first(req, '', 'iD', 'talkId', 'id'))
    u = F.uid(); on = cmd == 'game_collectiontalk'
    def fn(ft, db):
        lst = F.collection_of(ft, u, 'talk')
        if on:
            if tid not in lst: lst.append(tid)
        else:
            if tid in lst: lst.remove(tid)
        return len(lst)
    F.mutate(fn)
    # 客户端: 1 != o.code 才算收藏成功，故成功必须 code=0
    return F.payload(cmd, code=0, iD=F.as_int(tid, 0))

@F.register('game_collectiongames', 'game_cancelcollectiongames',
            'game_collectionggoods', 'game_cancelcollectiongoods')
def h_collectionids(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_collectiongames'
    ids = F.as_list(F.first(req, [], 'ids', 'id', 'iD'))
    kind = 'goods' if 'goods' in cmd else 'games'
    u = F.uid(); on = cmd.startswith('game_collection')
    def fn(ft, db):
        lst = F.collection_of(ft, u, kind)
        for i in ids:
            if on:
                if i not in lst: lst.append(i)
            else:
                if i in lst: lst.remove(i)
        return list(lst)
    F.mutate(fn)
    return F.payload(cmd, ids=[F.as_int(x, 0) for x in ids])

# ============================ 消息 / 通知 ============================
# 客户端 MsgType 枚举（源码 index.e248a.js）：
# 0=collectionGame 1=thumbGame 2=playGame 3=commentGame 4=hurryGame 5=followYou 6=buyGoods
MSGTYPE_FOLLOW = 5
MSGTYPE_COMMENT = 3
MSGTYPE_THUMB = 1

# MsgData / AggregateUserInfo / CommentMeData 的字段都来自客户端 schema，
# 这里只取注册过的字段，绝不把内部 _xxx 私有键塞进 BON 回包。
_MSGDATA_FIELDS = ('type', 'playerId', 'userLevel', 'userName', 'userImg',
                   'gameId', 'gameIcon', 'goodsId', 'goodsTextureName')


def _msgdata(m):
    d = {}
    for k in _MSGDATA_FIELDS:
        if k in ('type', 'playerId', 'userLevel', 'gameId', 'goodsId'):
            d[k] = F.as_int(m.get(k), 0)
        else:
            d[k] = str(m.get(k) or '')
    return F.data_obj('MsgData', **d)


def _agg_user(m):
    """userInfoList 元素是 AggregateUserInfo，不是 UserSimpleMsg。"""
    return F.data_obj('AggregateUserInfo', **{
        'playerId': F.as_int(m.get('playerId'), 0),
        'userLevel': F.as_int(m.get('userLevel'), 0),
        'userName': str(m.get('userName') or ''),
        'userImg': str(m.get('userImg') or ''),
        'stamp': F.as_int(m.get('_stamp'), 0),
    })


def _comment_me_obj(c):
    """game_getnewcommentlistv2.commentList 的元素是 CommentMeData（评论我的人）。"""
    # ★ CommentMeCell.onClick -> e.setData(this.data.id, this.data.commentId)
    #   第一个参数被当动态主键(TalkScene.setData 的 uId)。旧实现填评论记录 id，
    #   导致 game_loadtalkdetail {talkId: 10008}（评论 id）查不到动态、详情空白。
    #   id 必须是动态唯一主键(TalkData.uId = talkId hash = 评论 _target)。
    return F.data_obj('CommentMeData', **{
        'id': str(c.get('_target') or c.get('talkId') or ''),
        'commentId': F.as_int(c.get('id'), 0),
        'type': 1,                       # CommentType.talkType
        'playerId': F.as_int(c.get('playerId'), 0),
        'userLevel': F.as_int(c.get('userLevel'), 0),
        'userImg': str(c.get('userImg') or ''),
        'userName': str(c.get('userName') or ''),
        'gameIcon': '',
        'content': (str(c.get('content') or '') if not isinstance(c.get('content'), dict)
                    else str(c['content'].get('msg') or '')),
        'targetPlayerId': F.as_int(c.get('targetPlayerId'), 0),
        'targetPlayerName': str(c.get('targetPlayerName') or ''),
        'stamp': F.as_int(c.get('stamp'), 0),
        'thumbCnt': F.as_int(c.get('thumbCnt'), 0),
        'reportCnt': F.as_int(c.get('reportCnt'), 0),
    })


@F.register('game_getmsglist')
def h_getmsglist(req):
    ft = F.load_feat()
    msgs = list(reversed(ft.get('msgs', [])))
    unread = sum(1 for m in msgs if not m.get('_read'))
    return F.payload('game_getmsglist', msgList=[_msgdata(m) for m in msgs[:50]],
                     newMsgCnt=unread)


@F.register('game_getaggregatemsglist')
def h_getaggregate(req):
    """按 startIndex/endIndex 分页 + 按 MsgType 聚合。

    客户端 appendLoadMsgs() 用 msgs.length 当作下一页 startIndex 并把返回项
    全量 push；旧实现忽略分页每次都回全量 7 条，客户端会无限追加、列表卡死。
    """
    ft = F.load_feat()
    s = F.as_int(F.first(req, 0, 'startIndex', 'start'), 0)
    e = F.as_int(F.first(req, 10, 'endIndex', 'end'), 10)
    msgs = list(reversed(ft.get('msgs', [])))
    page = msgs[s:e] if e > s else []
    groups = {}
    for m in page:
        t = F.as_int(m.get('type'), 0)
        g = groups.setdefault(t, {'type': t, 'lastStamp': 0, 'users': []})
        g['lastStamp'] = max(g['lastStamp'], F.as_int(m.get('_stamp'), 0))
        g['users'].append(_agg_user(m))
    agg = [F.data_obj('AggregateMsgData', **{
        'type': g['type'], 'lastStamp': g['lastStamp'],
        'gameId': '', 'gameIcon': '', 'goodsId': '', 'goodsTextureName': '',
        'userInfoList': g['users'],
    }) for g in groups.values()]
    unread = sum(1 for m in msgs if not m.get('_read'))
    return F.payload('game_getaggregatemsglist', aggregateMsgList=agg,
                     newAggregateMsgCnt=unread, newMsgCnt=unread)

def _new_comments(ft):
    """别人发给我（或我的作品/动态）的、尚未读的新评论，按时间倒序。

    用「评论记录上的 _new_read 标记」判断已读，不依赖时间戳：
    客户端评论 stamp 可能带偏移/未来值，时间戳比较会误判。清红点时给所有
    现存评论打标，之后新建的评论没有该标记，自然重新算未读。
    """
    my = str(F.uid())
    out = [c for c in ft.get('comments', [])
           if str(c.get('playerId')) != my and not c.get('_new_read')]
    out.sort(key=lambda x: F.as_int(x.get('stamp'), 0), reverse=True)
    return out

@F.register('game_getnewcommentlist', 'game_getnewcommentlistv2')
def h_getnewcomment(req):
    cmd = (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or 'game_getnewcommentlist'
    ft = F.load_feat()
    s = F.as_int(F.first(req, 0, 'startIndex', 'start'), 0)
    cnt = F.as_int(F.first(req, 8, 'count', 'end', 'endIndex'), 8)
    news = _new_comments(ft)
    # commentList 的元素是 CommentMeData，不是 TalkComment（旧实现字段全不匹配，
    # 客户端 CommentMeCell 渲染不出来，评论页就是空白）。
    # 清过红点后未读为空时仍返回历史「评论我」记录，列表不会变空。
    pool = news
    if not pool:
        my = str(F.uid())
        pool = [c for c in ft.get('comments', []) if str(c.get('playerId')) != my]
    pool = sorted(pool, key=lambda x: F.as_int(x.get('stamp'), 0), reverse=True)
    page = pool[s:s + cnt]
    lst = [_comment_me_obj(c) for c in page]
    return F.payload(cmd, commentList=lst, newCommentCnt=len(news),
                     startIndex=s + len(page))


@F.register('game_clearnewcomment', 'game_clearnewmsg')
def h_cleardot(req):
    """清红点：只标记已读、不删数据。

    Game_RClearNewComment / Game_RClearNewMsg 都是空响应类，回包 body 必须是
    干净的裸 BON 空对象，否则客户端 setValue 异常 -> SendCmdAsync 完不成 ->
    评论页 refresh() 卡在清红点，appendLoadCommentMe() 永远不执行。
    """
    def fn(ft, db):
        for m in ft.get('msgs', []): m['_read'] = True
        for c in ft.get('comments', []): c['_new_read'] = True
    F.mutate(fn)
    return F.EMPTY_RESP

# ============================ post_process：补强已实现分支 ============================
def _read_users():
    """只读 db.json 的 users（直读文件、不加锁，绝不在 mutate 事务内调用）。"""
    try:
        import json
        with open(F.DB_FILE, encoding='utf8') as f:
            d = json.load(f)
        return d.get('users', {}) if isinstance(d.get('users'), dict) else {}
    except Exception:
        return {}


def _inject_simple_msgs(payload, req):
    """game_getusersimplemsg：按请求 ids 返回真实资料。

    客户端 loadInfos(ids) 用 playerInfoMap.set(t.playerId, t) 取资料；agentsrv
    原分支只回当前用户一个，粉丝/评论列表会全部显示不出来。这里补齐。
    """
    ids = F.as_list(F.first(req, [], 'ids', 'idList', 'playerIds', 'playerIdList'))
    if not ids:
        return
    users = _read_users()
    ft = F.load_feat()
    my = str(F.uid())
    follows = [str(x) for x in (ft.get('follows', {}).get(my, []) or [])]
    out = []
    for x in ids:
        i = F.as_int(x, 0)
        u = users.get(str(i)) or {}
        out.append(F.data_obj('UserSimpleMsg', **{
            'playerId': i,
            'userName': str(u.get('userName') or ('玩家' + str(i)[-4:])),
            'userImg': str(u.get('userImg') or ''),
            'userIntro': str(u.get('userIntro') or u.get('sign') or ''),
            'level': F.as_int(u.get('level'), 1),
            'isFollow': str(i) in follows,
        }))
    payload['userSimpleMsgList'] = out
    if isinstance(payload.get('data'), dict):
        payload['data']['userSimpleMsgList'] = out
    payload['list'] = out


def _inject_detail_counts(payload, req):
    """game_getuserdetailmsg：按请求的目标 id 补真实资料与计数（兜底，不覆盖已有值）。"""
    # 计数口径必须与独立分支写好的 userDetailMsg.playerId 完全对齐；
    # 否则 id=0/空 时会回退成当前用户，把目标账号的粉丝/关注数串成自己的。
    d0 = payload.get('userDetailMsg')
    if isinstance(d0, dict) and str(d0.get('playerId') or '0') not in ('0', '', 'None'):
        target = str(d0['playerId'])
    else:
        target = str(F.first(req, F.uid(), 'id', 'playerId', 'rid', 'userId') or '') or str(F.uid())
    my = str(F.uid())
    ft = F.load_feat()
    users = _read_users()
    u = users.get(target) or {}
    fans = len(ft.get('fans', {}).get(target, []) or [])
    follows = len(ft.get('follows', {}).get(target, []) or [])
    my_follows = [str(x) for x in (ft.get('follows', {}).get(my, []) or [])]
    d = payload.get('userDetailMsg')
    if isinstance(d, dict):
        d.setdefault('playerId', F.as_int(target, 0))
        d['fansCount'] = fans
        d['followCount'] = follows
        d['followsCount'] = follows
        d.setdefault('isFollow', target in my_follows)
        if u:
            d.setdefault('userName', str(u.get('userName') or ''))
            d.setdefault('userImg', str(u.get('userImg') or ''))
            d.setdefault('userIntro', str(u.get('userIntro') or u.get('sign') or ''))
            d.setdefault('level', F.as_int(u.get('level'), 1))
        payload['userDetailMsg'] = d
    if isinstance(payload.get('data'), dict):
        payload['data']['fansCount'] = fans
        payload['data']['followCount'] = follows
        payload['data']['followsCount'] = follows


def post_process(cmd, payload, req):
    """agentsrv.make_reply 末尾调用：给已实现分支补充互动数据，不改其原有逻辑。"""
    try:
        if not isinstance(payload, dict): return payload
        if cmd in ('game_loadtalk', 'game_loadowntalk', 'game_loadtalkbyidlist',
                   'game_searchtalk', 'game_loadowntalk'):
            ft = F.load_feat(); my = F.uid()
            tl = payload.get('talkList') or payload.get('list') or []
            if not isinstance(tl, list): return payload
            for t in tl:
                if not isinstance(t, dict): continue
                tid = str(t.get('talkId') or '')
                if not tid: continue
                up = F.thumb_state(ft, 'talk', tid, my)[0]
                t['upCnt'] = F.as_int(t.get('upCnt'), 0) + up
                t['isUp'] = my in ft.get('thumbs', {}).get(F.thumb_key('talk', tid), {}).get('up', [])
                t['isDown'] = my in ft.get('thumbs', {}).get(F.thumb_key('talk', tid), {}).get('down', [])
                cs = [c for c in ft.get('comments', [])
                      if c.get('_kind') == 'talk' and str(c.get('_target')) == tid]
                t['commentsCnt'] = len(cs)
                t['commentsCntSum'] = len(cs)
            if cmd == 'game_loadowntalk':
                # uId 已是动态主键(hash)，归属要按 playerId(作者 uid) 判断
                payload['talkList'] = [t for t in tl if str(t.get('playerId')) == str(my)]
                payload['list'] = payload['talkList']
                payload['total'] = len(payload['talkList'])
        elif cmd == 'game_login':
            ft = F.load_feat(); my = F.uid()
            role = payload.get('role')
            # 登录回包不下发未读红点：客户端进粉丝/评论页会先 yield clearXXXDot()，
            # 清红点流程一旦因回包不干净而卡住，后面的 appendLoadFansIds /
            # appendLoadCommentMe / loadInfos 全都不会执行，页面就一直空白。
            # 红点改由 game_getfans / game_getnewcommentlistv2 自带的 newXxxCnt 驱动。
            if isinstance(role, dict):
                role['newFansCnt'] = 0
                role['newCommentCnt'] = 0
                role['newMsgCnt'] = 0
                role['newAggregateMsgCnt'] = 0
                role['followIds'] = [F.as_int(x, 0) for x in ft.get('follows', {}).get(my, [])]
            payload['newFansCnt'] = 0
            payload['newCommentCnt'] = 0
            payload['newMsgCnt'] = 0
            payload['newAggregateMsgCnt'] = 0
        elif cmd == 'game_getusersimplemsg':
            _inject_simple_msgs(payload, req)
        elif cmd == 'game_getuserdetailmsg':
            _inject_detail_counts(payload, req)
    except Exception as e:
        F.log('POST_PROCESS_ERR', cmd, repr(e))
    return payload
