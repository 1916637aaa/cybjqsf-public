#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""头像审核共享逻辑（纯函数，操作 db dict）。

锁与原子写由调用方负责：
    db = store.load_db(); review.add_pending(db, uid, url); store.save_db(db)
因此与 server(HTTP) / agentsrv(WS) / admin(后台) 共用同一份 db.json，天然一致。

status 对齐客户端 ManReviewStatus: 0=无, 1=success(通过), 2=inReview(审核中), 3=fail(拒绝)
用户字段：newUserImg(待审图片URL) / imgReviewStatus(0/1/2/3) / userImg(正式头像URL)
"""
import os, json, time, uuid

BASE = '/opt/privsrv'
CFG = os.path.join(BASE, 'data', 'review_cfg.json')

SUCCESS = 1
INREVIEW = 2
FAIL = 3
STATUS_CN = {0: '已作废', 1: '已通过', 2: '待审核', 3: '已拒绝'}


def _cfg():
    try:
        with open(CFG, encoding='utf8') as f:
            return json.load(f)
    except Exception:
        return {'auto': False}


def auto_enabled():
    return bool(_cfg().get('auto'))


def set_auto(v):
    d = _cfg()
    d['auto'] = bool(v)
    tmp = CFG + '.tmp'
    with open(tmp, 'w', encoding='utf8') as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, CFG)
    return bool(v)


def _new_rid():
    return uuid.uuid4().hex[:12]


def _find(db, rid):
    for r in db.get('reviews', []):
        if str(r.get('rid')) == str(rid):
            return r
    return None


def add_pending(db, uid, url, note=''):
    """用户上传新头像：生成待审核记录，并把账号标记为审核中。
    开启「自动通过」时直接走 approve。返回 review dict（用户不存在则 None）。"""
    u = db['users'].get(str(uid))
    if not isinstance(u, dict):
        return None
    reviews = db.setdefault('reviews', [])
    # 同一用户旧的待审记录作废，避免堆积
    for r in reviews:
        if str(r.get('uid')) == str(uid) and r.get('status') == INREVIEW:
            r['status'] = 0
            r['doneStamp'] = int(time.time() * 1000)
            r['reason'] = '被新上传的头像替换'
    r = {
        'rid': _new_rid(), 'uid': str(uid), 'userName': str(u.get('userName') or ''),
        'url': str(url or ''), 'status': INREVIEW,
        'createStamp': int(time.time() * 1000), 'doneStamp': 0,
        'reason': note or '用户上传新头像',
    }
    reviews.append(r)
    u['newUserImg'] = r['url']
    u['imgReviewStatus'] = INREVIEW
    if auto_enabled():
        return approve(db, r['rid'], by='auto')
    return r


def approve(db, rid, by='admin'):
    """审核通过：新头像正式生效（userImg），状态置为 success。"""
    r = _find(db, rid)
    if not r:
        return None
    u = db['users'].get(str(r['uid']))
    if isinstance(u, dict):
        u['userImg'] = r['url']
        u['newUserImg'] = ''
        u['imgReviewStatus'] = SUCCESS
    r['status'] = SUCCESS
    r['doneStamp'] = int(time.time() * 1000)
    r['reason'] = '审核通过（%s）' % ('自动' if by == 'auto' else '后台')
    return r


def reject(db, rid, reason='', by='admin'):
    """审核拒绝：保留旧头像，状态置为 fail。"""
    r = _find(db, rid)
    if not r:
        return None
    u = db['users'].get(str(r['uid']))
    if isinstance(u, dict):
        u['newUserImg'] = ''
        u['imgReviewStatus'] = FAIL
    r['status'] = FAIL
    r['doneStamp'] = int(time.time() * 1000)
    r['reason'] = reason or '审核未通过'
    return r


def delete(db, rid):
    rs = db.get('reviews', [])
    n = len(rs)
    db['reviews'] = [r for r in rs if str(r.get('rid')) != str(rid)]
    return n - len(db['reviews'])


def clear_done(db):
    rs = db.get('reviews', [])
    n = len(rs)
    db['reviews'] = [r for r in rs if r.get('status') == INREVIEW]
    return n - len(db['reviews'])
