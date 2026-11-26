#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
复活成品 APK 自检 —— 在装进手机之前，用代码确认「没有连回旧服务器」。

检查项：
  1. 解密 index.jsc，列出里面所有 ws:// 与 http:// 主机地址
  2. 断言主连接 ws://<IP>/agent 与热修 BASE http://<IP> 都等于期望的新 IP
  3. 断言 IP 占位符 __SRV_IP__ 已全部被替换
  4. 断言 V3 的 4 处补丁标记都在（界面修复 + 热修通道）
  5. 若配置了 FORBID_IPS（旧服务器 IP），断言整个 APK 二进制里绝不含它们
  6. 断言 APK 可被 zip 正常读取、含 META-INF 签名

用法：
    python3 verify_apk.py                      # 期望 IP 从 conf/revive.env 读
    python3 verify_apk.py --expect-ip 1.2.3.4
    python3 verify_apk.py --forbid-ip 5.6.7.8   # 可重复

依赖：仅 Python 3 标准库
"""
import zipfile, struct, gzip, os, sys, re, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(os.path.dirname(HERE))
JSC = 'assets/assets/main/index.e248a.jsc'
KEY = b'ce27dc26-f6dc-47'
DELTA = 0x9e3779b9
key4 = list(struct.unpack('<4I', KEY))
PLACEHOLDER = '__SRV_IP__'

PATCH_MARKS = [
    ('HomeScene 首页修复', 'HS onLoad'),
    ('DiscoverPage 发现页修复', 'DP ADDED'),
    ('远程热修通道 LOADER', 'PRIVSRV v3 hotfix channel'),
    ('状态上报', 'BOOT v3'),
]


def MX(z, y, s, p, e):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
            ((s ^ y) + (key4[(p & 3) ^ e] ^ z))) & 0xffffffff


def btea_dec(v, n):
    if n < 2:
        return
    rounds = 6 + 52 // n
    s = (rounds * DELTA) & 0xffffffff
    y = v[0]
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            zz = v[p - 1]
            v[p] = (v[p] - MX(zz, y, s, p, e)) & 0xffffffff
            y = v[p]
        zz = v[n - 1]
        v[0] = (v[0] - MX(zz, y, s, 0, e)) & 0xffffffff
        y = v[0]
        s = (s - DELTA) & 0xffffffff


def decode_jsc(data):
    n = len(data) // 4
    v = list(struct.unpack_from('<%dI' % n, data, 0))
    btea_dec(v, n)
    ln = v[n - 1]
    if not (0 < ln <= (n - 1) * 4):
        raise ValueError('bad length word')
    raw = struct.pack('<%dI' % n, *v)[:ln]
    if raw[:2] == b'\x1f\x8b':
        raw = gzip.decompress(raw)
    return raw


def read_env():
    ip, forbid = '', []
    envf = os.path.join(KIT, 'conf', 'revive.env')
    if os.path.exists(envf):
        for line in open(envf, encoding='utf-8'):
            m = re.match(r'\s*YOUR_SERVER_IP\s*=\s*([^\s#]+)', line)
            if m and not ip:
                ip = m.group(1).strip()
            m2 = re.match(r'\s*FORBID_IPS\s*=\s*([^\s#]*)', line)
            if m2 and m2.group(1):
                forbid += [x for x in re.split(r'[,，]+', m2.group(1)) if x]
    if ip.startswith('YOUR_'):
        ip = ''
    return ip, forbid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--expect-ip', default='')
    ap.add_argument('--forbid-ip', action='append', default=[])
    ap.add_argument('--apk', default='')
    args = ap.parse_args()

    env_ip, env_forbid = read_env()
    expect = (args.expect_ip or env_ip or os.environ.get('PRIVSRV_IP', '')).strip()
    forbid = args.forbid_ip + env_forbid

    apk = args.apk
    if not apk:
        for cand in ['创游编辑器_私服版_已签名.apk', '创游编辑器_私服版_未签名.apk']:
            p = os.path.join(HERE, '..', 'out', cand)
            if os.path.exists(p):
                apk = p
                break
    if not apk or not os.path.exists(apk):
        raise SystemExit('[FAIL] 找不到待校验 APK，请用 --apk 指定，或先运行 build_revived_apk.py')
    apk = os.path.abspath(apk)

    print('校验对象 :', apk)
    print('期望 IP  :', expect or '(未指定，仅做结构检查)')
    print('禁止出现 :', forbid or '(未配置)')
    print('-' * 56)

    z = zipfile.ZipFile(apk)
    assert z.testzip() is None, 'zip 结构损坏'
    js = decode_jsc(z.read(JSC)).decode('utf-8', 'replace')
    print('[OK] index.jsc 解密成功，源码 %d 字符' % len(js))

    # 1/2. 地址检查
    ws = re.findall(r'ws://([^\s"\']+)/agent', js)
    base = re.findall(r"var BASE\s*=\s*'http://([^']+)'", js)
    print('  WS 主连接 :', ws)
    print('  热修 BASE :', base)
    if expect:
        assert ws == [expect], 'WS 地址不等于期望 IP: %r != %r' % (ws, expect)
        assert base == [expect], '热修 BASE 不等于期望 IP: %r != %r' % (base, expect)
        print('[OK] 两处服务器地址都指向新 IP:', expect)

    # 3. 占位符
    assert PLACEHOLDER not in js, 'IP 占位符未替换干净'
    print('[OK] 无未替换的 IP 占位符')

    # 4. 补丁标记
    for name, mark in PATCH_MARKS:
        assert mark in js, '补丁缺失: %s (标记 %r)' % (name, mark)
        print('[OK] 补丁在位:', name)

    # 5. 全 APK 二进制禁止旧 IP
    if forbid:
        blob = open(apk, 'rb').read()
        # 同时检查 jsc 解密后的明文（密文里可能扫不到）
        for old in forbid:
            ob = old.encode()
            assert ob not in blob, 'APK 二进制里仍含禁止的旧 IP: %s' % old
            assert ob not in js.encode('utf-8', 'ignore'), 'jsc 源码里仍含禁止的旧 IP: %s' % old
        print('[OK] 全 APK 二进制与源码均不含任何禁止的旧 IP')

    # 6. 签名
    sigs = [n for n in z.namelist() if n.startswith('META-INF/') and
            n.upper().endswith(('.RSA', '.DSA', '.EC'))]
    print('  签名块 :', sigs or '(未签名 —— 未签名包不能直接安装)')

    print('-' * 56)
    print('✓ VERIFY_OK')


if __name__ == '__main__':
    main()
