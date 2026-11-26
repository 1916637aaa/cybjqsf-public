#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""商城 / 道具 / 礼物 / 广告得币。"""
import features as F

# 游戏基础元数据（与 agentsrv.GAMES 同步）：礼物/排行榜按 gameId 展示名字与图标。
# 优先取 ft['games'] / editor 存档里的动态名字，取不到时回退到此静态表。
GAME_META = {
    '1001': ('像素冒险', 'demo1.png'), '1002': ('方块生存', 'demo4.png'),
    '1003': ('弹幕射击', 'demo5.png'), '1004': ('迷宫探秘', 'demo1.png'),
    '1005': ('塔防物语', 'demo4.png'), '1006': ('跑酷达人', 'demo5.png'),
    '1007': ('星空战机', 'demo1.png'), '1008': ('农场物语', 'demo4.png'),
    '1009': ('节奏大师', 'demo5.png'), '1010': ('解谜之门', 'demo1.png'),
    '1011': ('赛车狂飙', 'demo4.png'), '1012': ('海底探险', 'demo5.png'),
    '3003': ('我的作品', 'demo1.png'),
    '6011': ('我的作品1', 'icon1'), '6012': ('我的作品1', 'icon1'),
}

# 内置测试商品库：与 agentsrv.GAMES 的做法一致，种子放在代码里（存在私服），
# 清库/重建 db 后商城依然有内容；db.feat.goods 里的自定义商品会叠加在前面。
# 字段按客户端 GoodsCellData schema 命名，price 为 G币，购买时真实扣币。
SEED_GOODS = [
    {'id': 9001, 'name': '像素勇者皮肤',   'goodsType': 1, 'price': 120,
     'iconTextureName': 'demo1.png', 'playerId': 1000001, 'saleCnt': 328,
     'upStamp': 1730000000012, 'goodsContentCnt': 1, 'advert': ''},
    {'id': 9002, 'name': '星际战机组件',   'goodsType': 3, 'price': 260,
     'iconTextureName': 'demo4.png', 'playerId': 1000001, 'saleCnt': 205,
     'upStamp': 1730000000011, 'goodsContentCnt': 4, 'advert': ''},
    {'id': 9003, 'name': '经典像素表情包', 'goodsType': 2, 'price': 0,
     'iconTextureName': 'demo5.png', 'playerId': 1000001, 'saleCnt': 1203,
     'upStamp': 1730000000010, 'goodsContentCnt': 8, 'advert': '限时免费'},
    {'id': 9004, 'name': '爆炸特效包',     'goodsType': 4, 'price': 380,
     'iconTextureName': 'demo1.png', 'playerId': 1000001, 'saleCnt': 156,
     'upStamp': 1730000000009, 'goodsContentCnt': 6, 'advert': ''},
    {'id': 9005, 'name': '复古地砖素材',   'goodsType': 3, 'price': 180,
     'iconTextureName': 'demo4.png', 'playerId': 1000001, 'saleCnt': 274,
     'upStamp': 1730000000008, 'goodsContentCnt': 16, 'advert': ''},
    {'id': 9006, 'name': '魔法少女立绘',   'goodsType': 1, 'price': 520,
     'iconTextureName': 'demo5.png', 'playerId': 1000001, 'saleCnt': 98,
     'upStamp': 1730000000007, 'goodsContentCnt': 1, 'advert': '热门'},
    {'id': 9007, 'name': '8-bit 背景音乐',  'goodsType': 2, 'price': 200,
     'iconTextureName': 'demo1.png', 'playerId': 1000001, 'saleCnt': 412,
     'upStamp': 1730000000006, 'goodsContentCnt': 5, 'advert': ''},
    {'id': 9008, 'name': '机关与陷阱合集', 'goodsType': 3, 'price': 680,
     'iconTextureName': 'demo4.png', 'playerId': 1000001, 'saleCnt': 77,
     'upStamp': 1730000000005, 'goodsContentCnt': 12, 'advert': ''},
    {'id': 9009, 'name': '黄金宝箱道具',   'goodsType': 2, 'price': 888,
     'iconTextureName': 'demo5.png', 'playerId': 1000001, 'saleCnt': 63,
     'upStamp': 1730000000004, 'goodsContentCnt': 1, 'advert': '稀有'},
    {'id': 9010, 'name': '全套武器贴图',   'goodsType': 3, 'price': 1280,
     'iconTextureName': 'demo1.png', 'playerId': 1000001, 'saleCnt': 41,
     'upStamp': 1730000000003, 'goodsContentCnt': 24, 'advert': ''},
    {'id': 9011, 'name': '动态光效大师',   'goodsType': 4, 'price': 1888,
     'iconTextureName': 'demo4.png', 'playerId': 1000001, 'saleCnt': 29,
     'upStamp': 1730000000002, 'goodsContentCnt': 9, 'advert': '新品'},
    {'id': 9012, 'name': '创游周年纪念套装', 'goodsType': 1, 'price': 6480,
     'iconTextureName': 'demo5.png', 'playerId': 1000001, 'saleCnt': 12,
     'upStamp': 1730000000001, 'goodsContentCnt': 32, 'advert': '典藏'},
]


# 内置礼物配置（DynamicGameGiftCfg 字段：id/exp/coin/iconUrl/name/intr）。
# coin 为单次送礼花费的 G币，exp 为增加的经验；送礼时按 coin×数量 真实扣币。
SEED_GIFTS = [
    {'id': 1, 'name': '棒棒糖', 'coin': 10,   'exp': 5,   'iconUrl': 'gift1.png', 'intr': '甜甜的心意'},
    {'id': 2, 'name': '鲜花',   'coin': 50,   'exp': 20,  'iconUrl': 'gift2.png', 'intr': '送你一束花'},
    {'id': 3, 'name': '金奖杯', 'coin': 200,  'exp': 80,  'iconUrl': 'gift3.png', 'intr': '实至名归'},
    {'id': 4, 'name': '大火箭', 'coin': 1000, 'exp': 400, 'iconUrl': 'gift4.png', 'intr': '豪华礼物'},
]

# 分享/视频得币：每日上限与单次奖励（防刷，但私服里保持宽松）
SHARE_DAILY_LIMIT = 20
SHARE_REWARD = 20


def cmd(req, default):
    return (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or default


def _add_coin(db, delta):
    """在事务内给用户加/减 G币（coin/gCoin/g币 三个键同步），返回最新余额。"""
    u = str(F.uid())
    us = db.get('users', {})
    if isinstance(us, dict) and u in us:
        cur = max(0, F.as_int(us[u].get('coin'), 0) + delta)
        for k in ('coin', 'gCoin', 'g币'):
            us[u][k] = cur
        return cur
    return 0


def _gift_price(gift_id):
    for g in SEED_GIFTS:
        if str(g.get('id')) == str(gift_id):
            return F.as_int(g.get('coin'), 0)
    return 0


def merged_goods(ft=None):
    """db 自定义商品 + 内置种子（db 优先，按 id 去重），并过滤已下架商品。"""
    ft = ft if isinstance(ft, dict) else F.load_feat()
    off = set(str(x) for x in ft.get('offGoods', []))
    out = [g for g in (ft.get('goods', []) or []) if str(g.get('id')) not in off]
    have = set(str(g.get('id')) for g in out)
    for g in SEED_GOODS:
        if str(g.get('id')) not in have and str(g.get('id')) not in off:
            out.append(g)
    return out


def _all_goods():
    return [F.goods_cell(g) for g in merged_goods()]


def price_of(ft, gid):
    for g in merged_goods(ft):
        if str(g.get('id')) == str(gid):
            return F.as_int(g.get('price'), 0)
    return 0

@F.register('game_getgoodsids', 'game_getgoodsinfos', 'game_getnewgoods',
            'game_getowngoodsinfos', 'game_getsimplegoods', 'game_newsearchgoods',
            'game_searchgoods', 'game_getrecommendgoodsidlist', 'game_getchosengoodsids',
            'game_getgameshop', 'game_getgameshopids')
def h_goodslist(req):
    c = cmd(req, 'game_getgoodsinfos')
    name = str(F.first(req, '', 'searchName', 'name') or '').strip()
    goods = _all_goods()
    if name:
        goods = [g for g in goods if name in str(g.get('name') or '')]
    # 详情类命令按请求的 ids 精确返回（列表类命令如 getgoodsids 仍返回全库）
    if c in ('game_getgoodsinfos', 'game_getsimplegoods', 'game_getowngoodsinfos'):
        want = F.as_list(F.param(req, 'ids') or F.param(req, 'goodsIds') or [])
        if want:
            wset = set(str(x) for x in want)
            goods = [g for g in goods if str(g.get('id')) in wset]
    if c == 'game_getowngoodsinfos':
        u = F.uid()
        ft = F.load_feat()
        own = set(str(x) for x in ft.get('inventory', {}).get(str(u), []))
        goods = [g for g in goods if str(g.get('id')) in own]
    ids = [F.as_int(g.get('id'), 0) for g in goods]
    return F.payload(c, goodsInfoList=goods, goodsIds=ids, recommendGoodsIds=ids,
                     recommendList=ids, recommendGoods=goods, datas=goods, ids=ids,
                     startMember=0)

@F.register('game_buygoods')
def h_buygoods(req):
    gid = str(F.first(req, '', 'id', 'goodsId'))
    u = F.uid()
    def fn(ft, db):
        ft.setdefault('inventory', {}).setdefault(str(u), [])
        if gid not in ft['inventory'][str(u)]:
            ft['inventory'][str(u)].append(gid)
        # 价格从「db 商品 + 内置种子」里查，避免商品库为空时购买不扣币
        price = price_of(ft, gid)
        us = db.get('users', {})
        if isinstance(us, dict) and str(u) in us:
            cur = max(0, F.as_int(us[str(u)].get('coin'), 0) - price)
            for k in ('coin', 'gCoin', 'g币'):
                us[str(u)][k] = cur
            return cur
        return 0
    cur = F.mutate(fn)
    return F.payload('game_buygoods', id=F.as_int(gid, 0), coin=cur)

@F.register('game_sendgift')
def h_sendgift(req):
    gid = str(F.first(req, '', 'gameId', 'id'))
    cnt = max(1, F.as_int(F.first(req, 1, 'giftCount', 'count'), 1))
    gift_id = F.as_int(F.first(req, 0, 'giftID', 'giftId', 'id'), 0)
    price = _gift_price(gift_id) * cnt
    def fn(ft, db):
        u = str(F.uid())
        us = db.get('users', {})
        cur = F.as_int(us.get(u, {}).get('coin'), 0) if isinstance(us, dict) else 0
        if price > 0 and cur < price:
            return ('NO_COIN', cur)          # 余额不足：不扣、不记录
        ft.setdefault('gifts', []).append({
            'id': F.next_id(ft, 'msg'), 'gameId': F.as_int(gid, 0),
            'playerId': F.as_int(F.uid(), 0), 'userName': F.uname(),
            'giftID': gift_id, 'giftCount': cnt, 'coin': price, 'stamp': F.now_ms(),
        })
        ft['gifts'] = ft['gifts'][-200:]
        cur = _add_coin(db, -price) if price > 0 else cur
        return ('OK', cur)
    status, cur = F.mutate(fn)
    # 客户端: 1 != code 才算成功，故成功必须 code=0
    return F.payload('game_sendgift', code=0 if status == 'OK' else 1, coin=cur)

@F.register('game_getgiftrankdata', 'game_getrolegiftrankdata')
def h_giftrank(req):
    c = cmd(req, 'game_getgiftrankdata')
    ft = F.load_feat()
    gifts = list(reversed(ft.get('gifts', [])))
    # 游戏元数据(名字/图标)查找：优先发布游戏 ft['games']，其次编辑器存档
    meta = {}
    for gm in (ft.get('games', []) or []):
        if isinstance(gm, dict) and gm.get('id'):
            meta[str(gm['id'])] = (gm.get('name', ''), gm.get('iconTextureName', ''))
    for _uid, _sub in (ft.get('editor', {}) or {}).items():
        for _gid, _gv in (_sub.get('gamedata', {}) or {}).items():
            if isinstance(_gv, dict):
                meta.setdefault(str(_gid), (_gv.get('name', ''), _gv.get('iconTextureName', '')))
    # 按 gameId 聚合
    agg = {}
    for g in gifts:
        k = str(g.get('gameId', 0))
        agg[k] = agg.get(k, 0) + F.as_int(g.get('giftCount'), 0)
    rank = []
    for k, v in sorted(agg.items(), key=lambda x: -x[1])[:50]:
        nm, ic = meta.get(k) or GAME_META.get(k) or (k, '')
        rank.append({'id': k, 'rankKey': k, 'score': v, 'gameId': k, 'giftCount': v,
                     'gameName': nm, 'gameIcon': ic,
                     'playerId': F.as_int(F.uid(), 0), 'userName': F.uname()})
    return F.payload(c, rankList=rank, score=sum(agg.values()),
                     checkerInfo={}, code=0, rankType=0, beginIndex=0)

@F.register('game_getgiftdyncfg')
def h_giftcfg(req):
    # DynamicGameGift: version(标量) + datas(Map, 键为礼物id字符串)
    cfg, gift_list = _gift_cfg()
    return F.payload('game_getgiftdyncfg', cfg=cfg, giftList=gift_list)

@F.register('game_addcoinbyshare', 'game_addcoinbysharevideo',
            'game_addcoinbyadvert', 'game_addcoinbyadvertv2',
            'game_addothercoinbyadvert', 'game_addothercoinbyadvertv2')
def h_sharecoin(req):
    """分享/看视频/看广告得币：真实加币 + 每日次数上限（防刷）。"""
    c = cmd(req, 'game_addcoinbyshare')
    import time
    day = time.strftime('%Y-%m-%d')
    u = str(F.uid())
    def fn(ft, db):
        daily = ft.setdefault('coinDaily', {}).setdefault(u, {})
        used = F.as_int(daily.get(day), 0)
        if used >= SHARE_DAILY_LIMIT:
            return (F.as_int(db.get('users', {}).get(u, {}).get('coin'), 0), 0, used)
        daily[day] = used + 1
        cur = _add_coin(db, SHARE_REWARD)
        return (cur, SHARE_REWARD, used + 1)
    cur, got, used = F.mutate(fn)
    return F.payload(c, coin=cur, curCoin=cur, errorCode=0,
                     addCoinByShareCnt=used, addCoinByAdvertCnt=used,
                     addCoinByAdvertLimit=SHARE_DAILY_LIMIT, addCoinByAdvertReset=0)

@F.register('game_additem')
def h_additem(req):
    """加道具入背包：真实落库，支持 itemId/id/ids，返回背包。"""
    items = F.as_list(F.first(req, [], 'itemId', 'itemIds', 'id', 'ids', 'goodsId'))
    u = str(F.uid())
    def fn(ft, db):
        bag = ft.setdefault('items', {}).setdefault(u, [])
        for it in items:
            if it not in bag: bag.append(it)
        return list(bag)
    bag = F.mutate(fn)
    return F.payload('game_additem', items=bag, itemIds=bag, code=0)

@F.register('game_costcoinrecommendgame', 'game_costcoiningame')
def h_costcoin(req):
    """消费 G币（推荐作品/游戏内消费）：真实扣币，余额不足返回 errorCode。"""
    c = cmd(req, 'game_costcoinrecommendgame')
    cost = F.as_int(F.first(req, 100, 'coin', 'cost', 'costCoin', 'count'), 100)
    cost = max(0, cost)
    def fn(ft, db):
        u = str(F.uid())
        us = db.get('users', {})
        cur = F.as_int(us.get(u, {}).get('coin'), 0) if isinstance(us, dict) else 0
        if cur < cost:
            return (1, cur)
        return (0, _add_coin(db, -cost))
    err, cur = F.mutate(fn)
    return F.payload(c, coin=cur, errorCode=err)


# ---------------- post_process：补强 agentsrv 已实现分支 ----------------
def _gift_cfg():
    datas = {}
    for g in SEED_GIFTS:
        datas[str(g['id'])] = F.data_obj('DynamicGameGiftCfg', **g)
    return F.data_obj('DynamicGameGift', version=1, datas=datas), list(datas.values())


def post_process(cmd, payload, req):
    """game_getgiftdyncfg 在 agentsrv 有独立分支（回空 giftList），此处回填真实礼物配置。

    同时补顶层 cfg（Game_RGetGiftDynCfg 注册字段）与 data.giftList（客户端常见读法），
    兼容两种取值方式；不影响其它命令。
    """
    try:
        if not isinstance(payload, dict): return payload
        if cmd == 'game_getgiftdyncfg':
            cfg, gift_list = _gift_cfg()
            payload['cfg'] = cfg
            payload['version'] = 1
            if isinstance(payload.get('data'), dict):
                payload['data']['cfg'] = cfg
                payload['data']['giftList'] = gift_list
                payload['data']['datas'] = cfg.get('datas', {})
            payload.setdefault('giftList', gift_list)
    except Exception as e:
        F.log('POST_PROCESS_ERR', cmd, repr(e))
    return payload
