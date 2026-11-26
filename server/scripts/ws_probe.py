#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WS 回包探针：真实连本机 8765 发 game_login，确认能拿到 role。"""
import sys, os, asyncio
KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)
import agentsrv
from server import bon_encode, lz4_xor_encode

async def main():
    import websockets
    async with websockets.connect('ws://127.0.0.1:8765/agent') as ws:
        await ws.send(lz4_xor_encode(bon_encode({'cmd': 'game_login', 'seq': 1})))
        raw = await asyncio.wait_for(ws.recv(), timeout=8)
        msg = agentsrv.bon_decode(agentsrv.inflate_raw(raw))
        body = msg.get('body')
        payload = body if isinstance(body, dict) else agentsrv.bon_decode(body)
        role = payload.get('role', {}) if isinstance(payload, dict) else {}
        ok = isinstance(role, dict) and 'creditScore' in role
        print('WS_PROBE_OK' if ok else 'WS_PROBE_FAIL',
              'role.id=%s creditScore=%s' % (role.get('id'), role.get('creditScore')))
        return ok

if __name__ == '__main__':
    sys.exit(0 if asyncio.run(main()) else 1)
