#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内容：动态管理、搜索、作品详情、排行榜、举报审核、埋点上报。"""
import features as F

def cmd(req, default):
    return (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or default

# 内置敏感词库（私服测试用；后台可通过 ft['sensitiveWords'] 覆盖）
SEED_SENSITIVE = ['外挂', '代充', '刷钻', '免费领', '加群', '私服外链']


def _bump_play(gid, key, n=1):
    """累加作品运营统计到 ft['gamePlay'][gid]。"""
    gid = str(gid)
    def fn(ft, db):
        rec = ft.setdefault('gamePlay', {}).setdefault(gid,
                     {'playCnt': 0, 'clickCnt': 0, 'showCnt': 0, 'hurryCnt': 0})
        rec[key] = F.as_int(rec.get(key), 0) + n
        return dict(rec)
    return F.mutate(fn)


def _play_rec(gid):
    ft = F.load_feat()
    return ft.get('gamePlay', {}).get(str(gid), {}) or {}


def _credit():
    ft = F.load_feat()
    return ft.setdefault('credit', {}).setdefault(str(F.uid()), {'score': 100, 'list': []})

def _games():
    """内置测试作品 + 用户发布作品，叠加运营统计(gamePlay)、过滤已下架作品(offGames)。

    统计以「增量」存在 ft['gamePlay'][gid]，展示时叠加到基础值，不改内置常量、
    不改用户作品原始记录，零副作用。playCnt/hurryCnt 是 GameCellData 注册字段，
    叠加后客户端可见；clickCnt/showCnt 供排行/后台使用。
    """
    try:
        import agentsrv
        base = [dict(g) for g in agentsrv.GAMES]
    except Exception:
        base = []
    try:
        ft = F.load_feat()
        for g in ft.get('games', []):
            base.append(F.game_cell(g))
    except Exception:
        pass
    try:
        ft = F.load_feat()
        off = set(str(x) for x in ft.get('offGames', []))
        play = ft.get('gamePlay', {}) if isinstance(ft.get('gamePlay'), dict) else {}
        out = []
        for g in base:
            gid = str(g.get('id'))
            if gid in off:                       # 下架作品不再出现在任何列表
                continue
            st = play.get(gid)
            if isinstance(st, dict):
                g = dict(g)
                for k in ('playCnt', 'hurryCnt'):
                    if k in st:
                        g[k] = F.as_int(g.get(k), 0) + F.as_int(st.get(k), 0)
            out.append(g)
        return out
    except Exception:
        return base

def _game_by_id(gid):
    for g in _games():
        if str(g.get('id')) == str(gid): return g
    return {}

# ============================ 动态管理 ============================
@F.register('game_deletetalk', 'game_officialdeletetalk')
def h_deletetalk(req):
    c = cmd(req, 'game_deletetalk')
    tid = str(F.first(req, '', 'talkId', 'id', 'iD'))
    def fn(ft, db):
        ft.setdefault('comments', [])
        ft['comments'] = [x for x in ft['comments']
                          if not (x.get('_kind') == 'talk' and str(x.get('_target')) == tid)]
    F.mutate(fn)
    try:
        import store
        store.del_talk(tid)
    except Exception:
        pass
    return F.payload(c, code=0)

@F.register('game_modifytalk', 'game_modifyofficialtalk')
def h_modifytalk(req):
    c = cmd(req, 'game_modifytalk')
    tid = str(F.first(req, '', 'talkId', 'id'))
    title = str(F.first(req, '', 'title') or '')[:60]
    simple = F.first(req, None, 'simpleContent')
    content = F.first(req, None, 'content')
    patch = {}
    if title: patch['title'] = title
    if isinstance(simple, dict): patch['simpleContent'] = simple
    elif simple is not None: patch['simpleContent'] = {'text': str(simple)[:500]}
    if isinstance(content, dict): patch['content'] = content
    # 修改动态：敏感词检测（避免先发正常再改成违规）
    try:
        import agentsrv as _asrv
        _txt = title + ' ' + str((patch.get('simpleContent') or {}).get('text', '')
                                 if isinstance(patch.get('simpleContent'), dict)
                                 else patch.get('simpleContent') or '')
        _hits = _asrv.sensitive_check(_txt)
        if _hits:
            return F.payload(c, code=1, msg='内容含敏感词，请修改后再提交',
                             result=False, success=False, sensitiveWords=_hits)
    except Exception:
        pass
    t = F.patch_talk(tid, patch) or F.find_talk(tid) or {}
    return F.payload(c, code=0, talkData=t, sensitiveWords=[])

@F.register('game_settalktop', 'game_deltalktop', 'game_settalkchosen', 'game_deltalkchosen')
def h_talkflag(req):
    c = cmd(req, 'game_settalktop')
    tid = str(F.first(req, '', 'talkId', 'id'))
    if 'chosen' in c:
        F.patch_talk(tid, {'isChosen': c.startswith('game_set')})
    else:
        F.patch_talk(tid, {'isTop': c.startswith('game_set')})
    return F.payload(c, code=0)

@F.register('game_loadtalkdetail')
def h_talkdetail(req):
    """动态详情：客户端把 TalkData.uId 当主键，点进来传 {talkId: uId}。

    旧实现 find_talk 命中不了（uId 曾是作者 uid），talkData 为空 ->
    详情页正文/评论/点赞/作者全部丢失。这里统一主键后回填完整 TalkData。
    """
    tid = str(F.first(req, '', 'talkId', 'id'))
    ft = F.load_feat()
    t = F.find_talk(tid) or {}
    # 兜底：从消息中心「评论」点进来时，客户端可能把 CommentMeData.id
    # （=评论记录 id）当 talkId 传。反查该评论所属动态，仍能打开正确详情。
    if not t:
        for c in ft.get('comments', []):
            if str(c.get('id')) == tid and c.get('_target'):
                tid = str(c['_target'])
                t = F.find_talk(tid) or {}
                break
    if isinstance(t, dict) and t:
        t = dict(t)
        first = F.comment_list(ft, 'talk', tid, 0)          # 一级评论（含置顶优先）
        allc = [c for c in ft.get('comments', [])
                if c.get('_kind') == 'talk' and str(c.get('_target')) == tid]
        t['commentsCnt'] = len(first)
        t['commentsCntSum'] = len(allc)
        t['comments'] = [F.comment_obj(ft, x, 'talk') for x in first[:20]]
        t['topComment'] = F.comment_obj(ft, first[0], 'talk') if first else {}
        # 点赞：保留动态基础值 + 真实顶/踩数
        t['upCnt'] = F.as_int(t.get('upCnt'), 0) + F.thumb_state(ft, 'talk', tid, F.uid())[0]
        # 正文：详情页用 content.sections 渲染；为空时用 simpleContent 兜底成文本段
        cont = t.get('content') if isinstance(t.get('content'), dict) else {}
        if not cont.get('sections'):
            sc = t.get('simpleContent')
            txt = sc.get('text', '') if isinstance(sc, dict) else ''
            if txt:
                cont = {'sections': [{'type': 0, 'text': txt}]}
        t['content'] = cont
        if not isinstance(t.get('simpleContent'), dict):
            t['simpleContent'] = {'text': ''}
    return F.payload('game_loadtalkdetail', talkData=t)

# ============================ 搜索 ============================
@F.register('game_searchgame', 'game_searchgamebytag', 'game_searchrole')
def h_search(req):
    c = cmd(req, 'game_searchgame')
    name = str(F.first(req, '', 'searchName', 'name', 'key', 'tag') or '').strip()
    s = F.as_int(F.first(req, 0, 'start', 'startIndex'), 0)
    e = F.as_int(F.first(req, 15, 'end', 'endIndex'), 15)
    games = _games()
    if name:
        games = [g for g in games if name in str(g.get('name') or '')]
    out = games[s:e]
    if c == 'game_searchrole':
        # 搜人：返回玩家列表（roleDatas 是 UserSimpleMsg 风格）
        try:
            import store
            db = store.load_db()
            roles = [F.user_simple(u) for k, u in db.get('users', {}).items()
                     if (not name or name in str(u.get('userName') or ''))][s:e]
            return F.payload(c, roleDatas=roles)
        except Exception:
            return F.payload(c, roleDatas=[])
    return F.payload(c, gameDatas=out)

# ============================ 作品列表 / 详情 ============================
@F.register('game_getnewgamelist', 'game_getnewgameidlist', 'game_gethomepagenewgames',
            'game_gethomepagegamedata', 'game_gethomepagerecommendsgames',
            'game_gethomepagefollowusergames', 'game_getplaygamestatistics',
            'game_getcostcoinrecommendgames', 'game_getsourcecreativegamerank',
            'game_getcreativerank', 'game_getbereportgamedata')
def h_gamelist(req):
    c = cmd(req, 'game_getnewgamelist')
    games = _games()
    s = F.as_int(F.first(req, 0, 'start', 'startIndex'), 0)
    e = F.as_int(F.first(req, 20, 'end', 'endIndex'), 20)
    ids = [F.as_int(g.get('id'), 0) for g in games]
    return F.payload(c, gameDatas=games[s:e], gameIdList=ids[s:e],
                     startMember=0, sourceReleaseGame={})

@F.register('game_getrecommendgameidlist', 'game_getgameidlistbygametag')
def h_idlist(req):
    c = cmd(req, 'game_getrecommendgameidlist')
    ft = F.load_feat()
    games = _games()
    if c == 'game_getgameidlistbygametag':
        tag = str(F.first(req, '', 'tag', 'gameTag', 'tage', 'name') or '').strip()
        if tag:
            tags = ft.get('gameTags', {}) or {}
            games = [g for g in games
                     if tag in [str(t) for t in tags.get(str(g.get('id')), [])]]
    ids = [F.as_int(g.get('id'), 0) for g in games]
    return F.payload(c, recommendList=ids, gameIdList=ids)

@F.register('game_getgamedetail')
def h_gamedetail(req):
    gid = str(F.first(req, '', 'id', 'gameId'))
    g = _game_by_id(gid)
    ft = F.load_feat()
    # 用 comment_list（含置顶优先），让「置顶评论」真正生效
    cs = [F.comment_obj(ft, x, 'game') for x in F.comment_list(ft, 'game', gid, 0)][:20]
    # ★ 修复：作者必须是作品的真实发布者(_uid)，不能用当前登录用户。
    # 否则看别人的作品时，作者显示成自己、点进去跳自己主页。
    try:
        import store
        db_all = store.load_db()
        users = db_all.get('users', {}) if isinstance(db_all, dict) else {}
        g_before = _game_by_id(gid) or {}
        author_uid = str(g_before.get('_uid') or g_before.get('authorId') or '')
        u = users.get(author_uid) if isinstance(users, dict) and author_uid else None
        if not isinstance(u, dict):
            u = {'userId': F.as_int(author_uid, 0), 'userName': ''}
        author = F.user_simple({'userId': u.get('userId', F.as_int(author_uid, 0)),
                                'userName': u.get('userName') or ('玩家' + author_uid[-4:]),
                                'userImg': u.get('userImg'), 'userIntro': u.get('userIntro') or u.get('sign'),
                                'level': u.get('level')})
        # ★ 客户端 GameCoverScene 用 authorMsg.id 当 roleId 跳作者主页；
        # user_simple 只回 playerId，缺失 id 会导致 roleId=0 -> 显示成当前登录用户。
        if isinstance(author, dict):
            author['id'] = F.as_int(author.get('playerId') or author_uid, 0)
    except Exception:
        author = {}
    # 补齐客户端 GameCoverScene 实际会读取的展示字段：
    #   isThumb/isCollection/isPlay/isHurry(按钮态) / tagList(标签) / dataVersion / gDGiftScoreInfo
    # 缺失时 setValue 会取类型默认值，界面虽然不崩但「点赞/收藏/标签」显示不完整。
    # gameDataCdnUrl：作品发布时由客户端上传的工程 .bin 文件名，存于作品记录；
    # 无上传作品（内置 seed）则为空，客户端 onPlayBtn 会安全返回不崩。
    g = dict(g) if isinstance(g, dict) else {}
    g.setdefault('tagList', [])
    g.setdefault('isThumb', False)
    g.setdefault('isCollection', False)
    g.setdefault('isPlay', False)
    g.setdefault('isHurry', False)
    g.setdefault('gDGiftScoreInfo', {})
    g.setdefault('dataVersion', 0)
    g.setdefault('openData', {})
    g.setdefault('gameDataCdnUrl', '')
    rank = list(ft.get('ranks', {}).get(str(gid), []))[:10]
    return F.payload('game_getgamedetail', authorMsg=author, releaseGameData=g,
                     creativeGameData={}, gameTopComment=cs[0] if cs else {},
                     rankList=rank, id=F.as_int(gid, 0))


def post_process(cmd, payload, req):
    """补强 agentsrv 已实现分支：game_getusercreditmsg 回填真实信用分与明细。"""
    try:
        if not isinstance(payload, dict): return payload
        if cmd == 'game_getusercreditmsg':
            uid = str(F.first(req, F.uid(), 'playerId', 'rid', 'userId') or F.uid())
            ft = F.load_feat()
            rec = ft.get('credit', {}).get(uid, {}) or {}
            score = F.as_int(rec.get('score'), 100)
            msgs = list(rec.get('list', []) or [])
            # 封号号(叶子=0)：在信誉明细顶部注入醒目封禁提示。
            # 客户端叶子只读登录瞬间且不刷新，这里让信誉页明确显示封禁状态。
            if score <= 0:
                try:
                    import time as _t
                    _tip = {'score': 0,
                            'reason': '⚠ 账号已被封禁：叶子扣至0，全部功能受限',
                            'stamp': int(_t.time() * 1000)}
                    msgs = [_tip] + msgs
                except Exception:
                    pass
            payload['creditScore'] = score
            payload['creditScoreRecoverProcess'] = 0
            payload['userCreditMsgList'] = msgs[:20]
            # 兼容 agentsrv 分支使用的旧字段名
            payload['creditMsgList'] = msgs[:20]
            if isinstance(payload.get('data'), dict):
                payload['data']['creditMsgList'] = msgs[:20]
                payload['data']['creditScore'] = score
    except Exception as e:
        F.log('POST_PROCESS_ERR', cmd, repr(e))
    return payload

@F.register('game_subgamelist', 'game_hurrygames', 'game_playgames',
            'game_playgamestatistics', 'game_clickrecommendsgames')
def h_play(req):
    """游玩/催更/点击：真实累加 ft['gamePlay']，回包带上真实累计次数。"""
    c = cmd(req, 'game_playgames')
    ids = F.as_list(F.first(req, [], 'ids', 'id', 'gameId'))
    if not ids:
        single = F.first(req, '', 'gid', 'gameID')
        if single: ids = [single]
    key = ('hurryCnt' if 'hurry' in c else
           'clickCnt' if 'click' in c else
           'showCnt' if 'subgame' in c else 'playCnt')
    play_cnts, click_cnts = [], 0
    for gid in ids:
        rec = _bump_play(gid, key, 1)
        play_cnts.append(F.as_int(rec.get('playCnt'), 0))
        click_cnts += F.as_int(rec.get('clickCnt'), 0)
    return F.payload(c, ids=[F.as_int(x, 0) for x in ids],
                     id=F.as_int(ids[0], 0) if ids else 0,
                     playCntList=play_cnts or [1] * len(ids),
                     playCnt=play_cnts[0] if play_cnts else 0,
                     clickCnt=click_cnts or len(ids))

# ============================ 排行榜 ============================
@F.register('game_getgamerank', 'game_getreleasegamerank', 'game_getreviewgamedata',
            'game_getgameshop', 'game_getgameshopids', 'game_getsimplegoods')
def h_rank(req):
    c = cmd(req, 'game_getgamerank')
    ft = F.load_feat()
    key = F.first(req, 'default', 'rankKey', 'id', 'sortType')
    data = ft.get('ranks', {}).get(str(key), [])
    ids = [F.as_int(x.get('id'), 0) for x in data]
    return F.payload(c, datas=data, ids=ids,
                     goodsInfoList=[F.goods_cell(x) for x in data])

@F.register('game_uploadgamerankscore', 'game_savegamerank')
def h_saverank(req):
    c = cmd(req, 'game_uploadgamerankscore')
    gid = F.as_int(F.first(req, 0, 'gameId', 'id'), 0)
    scores = F.first(req, [], 'scores', 'score')
    if not isinstance(scores, (list, tuple)): scores = [scores]
    def fn(ft, db):
        key = str(gid)
        cur = ft.setdefault('ranks', {}).setdefault(key, [])
        cur.append({'id': F.next_id(ft, 'conf'), 'gameId': gid,
                    'playerId': F.as_int(F.uid(), 0), 'score': F.as_int(scores[0], 0) if scores else 0,
                    'sortType': 0, 'cycleType': 0, 'conf': 0})
        ft['ranks'][key] = cur[-100:]
        return F.next_id(ft, 'conf')
    rid = F.mutate(fn)
    return F.payload(c, gameId=gid, id=rid, scores=list(scores))

@F.register('game_delgamerank', 'game_delreleasegamerank', 'game_deletegamerankscore',
            'game_delgameshop')
def h_delrank(req):
    """删除排行榜：真实从 ft['ranks'] 移除指定 id 的分数记录。"""
    c = cmd(req, 'game_delgamerank')
    ids = set(F.as_list(F.first(req, [], 'ids', 'id')))
    gid = str(F.first(req, '', 'gameId', 'rankKey') or '')
    def fn(ft, db):
        ranks = ft.setdefault('ranks', {})
        keys = [gid] if gid else list(ranks.keys())
        for k in keys:
            if not isinstance(ranks.get(k), list): continue
            if ids:
                ranks[k] = [x for x in ranks[k]
                            if str(x.get('id')) not in ids and str(x.get('gameId')) not in ids]
            elif c == 'game_deletegamerankscore':
                ranks[k] = []
    F.mutate(fn)
    return F.payload(c, ids=[F.as_int(x, 0) for x in ids])

@F.register('game_inccreditscore')
def h_creditscore(req):
    """信用分：真实累加 ft['credit'][uid]，并留一条变动明细。"""
    inc = F.as_int(F.first(req, 1, 'incScore', 'score'), 1)
    def fn(ft, db):
        rec = ft.setdefault('credit', {}).setdefault(str(F.uid()), {'score': 100, 'list': []})
        rec['score'] = F.as_int(rec.get('score'), 100) + inc
        rec.setdefault('list', []).append(F.data_obj('UserCreditMsg',
                       score=inc, reason='行为加分', stamp=F.now_ms()))
        rec['list'] = rec['list'][-50:]
        return rec['score']
    score = F.mutate(fn)
    return F.payload('game_inccreditscore', incScore=inc,
                     playerId=F.as_int(F.uid(), 0), creditScore=score)

# ============================ 举报 / 审核 ============================
def _report(req, kind, c):
    tid = str(F.first(req, '', 'id', 'gameId', 'talkId', 'playerId', 'goodsId', 'commentId'))
    reason = str(F.first(req, '', 'reason', 'msg', 'content') or '')[:200]
    def fn(ft, db):
        rid = F.next_id(ft, 'report')
        ft.setdefault('reports', []).append({
            'id': rid, 'kind': kind, 'targetId': tid, 'uid': F.uid(),
            'userName': F.uname(), 'reason': reason, 'stamp': F.now_ms(),
            'status': 0,
        })
        ft['reports'] = ft['reports'][-300:]
        return rid
    rid = F.mutate(fn)
    return F.payload(c, id=rid, code=0, reportCnt=1)

@F.register('game_reportgame', 'game_reportgoods', 'game_reportplayer', 'game_reporttalk')
def h_report(req):
    c = cmd(req, 'game_reportgame')
    # ★ 修复：所有举报命令都带 game_ 前缀，'game' in c 永远为真，导致全归成作品。
    # 必须按完整命令名精确匹配。
    _kinds = {
        'game_reportgame': 'game',
        'game_reportgoods': 'goods',
        'game_reportplayer': 'player',
        'game_reporttalk': 'talk',
    }
    kind = _kinds.get(c, 'game')
    return _report(req, kind, c)

@F.register('game_revokereportgame', 'game_revokereportgoods', 'game_revokereportplayer',
            'game_revokereportgamecomment', 'game_dealwithreportgamecomment',
            'game_dealwithreportgoods')
def h_revoke(req):
    c = cmd(req, 'game_revokereportgame')
    rid = str(F.first(req, '', 'id', 'reportId'))
    def fn(ft, db):
        for r in ft.get('reports', []):
            if str(r.get('id')) == rid: r['status'] = 2
    F.mutate(fn)
    return F.payload(c, id=F.as_int(rid, 0))


@F.register('game_dealwithreportplayer')
def h_dealwithreportplayer(req):
    """GM 处理玩家举报（APP 里用户主页「封号/处罚」按钮）：
    - score<0 扣目标信誉分(叶子)，扣到 0 即封号；
    - needReset* 重置 昵称/头像/简介；
    - 信誉分归 0 时写 kick.jsonl，agentsrv 立即踢掉该 uid 全部在线连接并拒绝重连。
    """
    c = cmd(req, 'game_dealwithreportplayer')
    target = str(F.first(req, '', 'id', 'targetId', 'playerId', 'userId'))
    reason = str(F.first(req, '', 'reason') or '')[:200]
    try:
        score = int(F.param(req, 'score', 0) or 0)
    except Exception:
        score = 0
    reset_name = bool(F.param(req, 'needResetUserName', False))
    reset_img = bool(F.param(req, 'needResetUserImg', False))
    reset_intro = bool(F.param(req, 'needResetIntro', False))
    new_score = [None]
    banned = [False]

    def fn(ft, db):
        if not target or target == '0':
            return
        # 信誉分：0~3 叶子等级点
        rec = ft.setdefault('credit', {}).setdefault(target, {'score': 3, 'list': []})
        old = F.as_int(rec.get('score'), 3)
        new = max(0, min(3, old + score)) if score else old
        rec['score'] = new
        new_score[0] = new
        if score:
            rec.setdefault('list', []).append({
                'score': score, 'reason': reason or ('GM处罚 ' + c),
                'stamp': F.now_ms(),
            })
            rec['list'] = rec['list'][-50:]
        u = db.get('users', {}).get(target)
        if isinstance(u, dict):
            # 同步 creditScore 字段
            if score:
                u['creditScore'] = new
            # 重置违规资料
            if reset_name:
                u['userName'] = '玩家' + target[-4:]
            if reset_img:
                u['userImg'] = '/uploads/cover/avatar.png'
                u['newUserImg'] = ''
                u['imgReviewStatus'] = 0
            if reset_intro:
                u['userIntro'] = '这个人很懒，什么都没写'
        if new <= 0 and (score < 0 or old <= 0):
            banned[0] = True
        # 把举报标记已处理
        for r in ft.get('reports', []):
            if str(r.get('targetId')) == target or str(r.get('uid')) == target:
                r['status'] = 2
        return new

    F.mutate(fn)
    # 封号：写踢线指令，agentsrv 轮询后立即断开该 uid 全部连接并拒绝重连
    if banned[0] and target and target != '0':
        try:
            import json, time
            kick = '/opt/privsrv/data/kick.jsonl'
            with open(kick, 'a', encoding='utf8') as f:
                f.write(json.dumps({'uid': target, 'reason': reason or 'GM封号'},
                                   ensure_ascii=False) + '\n')
        except Exception:
            pass
    return F.payload(c, id=F.as_int(target, 0), score=new_score[0] or 0)


@F.register('game_clearreportgame', 'game_clearreportgoods', 'game_clearreportplayer',
            'game_clearreporttalk', 'game_clearreporttalkcomment', 'game_clearreportgamecomment')
def h_clearreport(req):
    c = cmd(req, 'game_clearreportgame')
    kind = ('game' if 'game' in c else 'goods' if 'goods' in c else
            'player' if 'player' in c else 'talk')
    def fn(ft, db):
        ft['reports'] = [r for r in ft.get('reports', []) if r.get('kind') != kind]
    F.mutate(fn)
    return F.payload(c)

@F.register('game_getreportgameidlist', 'game_getreportgoodsidlist', 'game_getreportplayeridlist',
            'game_getreporttalklist', 'game_getreporttalkcommentlist',
            'game_getreportgamecommentlist', 'game_getreportsensitiveimg',
            'game_getmanualreportsensitiveimg', 'game_getreviewgamedata')
def h_reportlist(req):
    c = cmd(req, 'game_getreporttalklist')
    ft = F.load_feat()
    rs = list(reversed(ft.get('reports', [])))
    smap = {str(r.get('id')): 1 for r in rs}
    return F.payload(c, talkList=rs, comments=rs, reportGameCommentList=rs,
                     sensitiveImgMsgList=[], reportScoreMap=smap,
                     gameIdList=[F.as_int(r.get('targetId'), 0) for r in rs],
                     goodsIdList=[F.as_int(r.get('targetId'), 0) for r in rs],
                     playerIdList=[F.as_int(r.get('targetId'), 0) for r in rs],
                     datas=rs)

@F.register('game_reviewgame', 'game_adminsetgamestatus', 'game_admingetgamemsgbyreviewid')
def h_reviewgame(req):
    c = cmd(req, 'game_reviewgame')
    gid = str(F.first(req, '', 'id', 'gameId', 'reviewId'))
    return F.payload(c, gameData=_game_by_id(gid), datas=[_game_by_id(gid)])

@F.register('game_offgame', 'game_offgoods', 'game_ownoffgame')
def h_off(req):
    """下架作品/商品：真实写入 offGames/offGoods，_games()/商城列表会自动过滤。"""
    c = cmd(req, 'game_offgame')
    ids = F.as_list(F.first(req, [], 'ids', 'id', 'gameId', 'goodsId'))
    key = 'offGoods' if 'goods' in c else 'offGames'
    def fn(ft, db):
        cur = ft.setdefault(key, [])
        for i in ids:
            if i not in cur: cur.append(i)
        return list(cur)
    F.mutate(fn)
    return F.payload(c, id=F.as_int(ids[0], 0) if ids else 0,
                     ids=[F.as_int(x, 0) for x in ids], code=0)

@F.register('game_addgametage', 'game_gmsetgametage')
def h_tag(req):
    """给作品打标签：真实写入 gameTags，getgameidlistbygametag 会按标签过滤。"""
    c = cmd(req, 'game_addgametage')
    gid = str(F.first(req, '', 'gameID', 'gameId', 'id'))
    tags = F.as_list(F.first(req, [], 'tags', 'tag', 'tage', 'name'))
    # 过滤敏感词，命中则拒绝并回传词表
    words = _sensitive_words()
    hit = [w for t in tags for w in words if w and w in str(t)]
    def fn(ft, db):
        if hit: return list(ft.get('gameTags', {}).get(gid, []))
        cur = ft.setdefault('gameTags', {}).setdefault(gid, [])
        for t in tags:
            if t not in cur: cur.append(t)
        return list(cur)
    F.mutate(fn)
    return F.payload(c, code=1 if hit else 0, gameID=F.as_int(gid, 0), sensitiveWords=hit)

def _sensitive_words():
    ft = F.load_feat()
    w = ft.get('sensitiveWords')
    return list(w) if isinstance(w, list) and w else list(SEED_SENSITIVE)

@F.register('game_sensitivemsg')
def h_sensitive(req):
    """返回敏感词库；若请求带文本，则回传命中的词并给出校验结果。"""
    words = _sensitive_words()
    text = str(F.first(req, '', 'msg', 'text', 'content', 'str') or '')
    hit = [w for w in words if w and w in text] if text else []
    return F.payload('game_sensitivemsg', code=1 if hit else 0,
                     sensitiveWords=hit if text else words, errorCode=1 if hit else 0)

@F.register('game_reportgameclick', 'game_reportgameshow',
            'game_reportgoodsclick', 'game_reportgoodsshow')
def h_track(req):
    """曝光/点击埋点：真实累加 showCnt/clickCnt 到 gamePlay。"""
    c = cmd(req, 'game_reportgameclick')
    ids = F.as_list(F.first(req, [], 'ids', 'id', 'gameId', 'goodsId'))
    key = 'showCnt' if 'show' in c else 'clickCnt'
    for gid in ids: _bump_play(gid, key, 1)
    return F.payload(c, code=0, errorCode=0)

@F.register('game_resetbannergames', 'game_resetchosengames', 'game_resetchosengoods')
def h_reset(req):
    """重置运营位：清空对应 flags 记录。"""
    c = cmd(req, 'game_resetbannergames')
    key = ('bannerGames' if 'banner' in c else
           'chosenGames' if 'chosengames' in c else 'chosenGoods')
    F.mutate(lambda ft, db: ft.setdefault('flags', {}).__setitem__(key, []))
    return F.payload(c, code=0)

@F.register('game_reportbugmsg', 'game_debuggetrecommendgamemsg')
def h_ack(req):
    """纯上报类命令：客户端发完不等有效数据，回成功即可。"""
    c = cmd(req, 'game_reportbugmsg')
    return F.payload(c, code=0, sensitiveWords=[], errorCode=0)
