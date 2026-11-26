#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
客户端「复活」重打包脚本 —— 原版 APK -> 指向【新服务器 IP】的可用安装包（未签名）

背景
----
历史上真机验证成功连上私服的最终版本是「V3 修复版」。它在原版 APK 基础上改了 4 处，
其中 2 处把服务器地址写死成了【旧服务器的公网 IP】。换服务器后，只要把这两处 IP
换成新服务器 IP，其余补丁逐字保留，就能得到一个与 V3 等价、但连向新服务器的版本。

本脚本就是 V3 的参数化复刻：**代码里不含任何真实 IP**，IP 全部由 PRIVSRV_IP 注入。
因此本文件可以安全地放进教程/交接包，转交给任何人在任意服务器上重建。

V3 的 4 处改动（本脚本全部保留）
  1. HomeScene.onLoad   主动触发 onToggleChange(0)   —— 修首页内容区空白
  2. DiscoverPage.onLoad 内联直接加载默认内容子页     —— 修发现页内容区空白
  3. WS 直连私服 IP： urlRoot+"/agent" -> "ws://<IP>/agent"  ← 服务器地址在这
  4. 追加远程热修通道 LOADER：BASE = "http://<IP>"          ← 服务器地址在这
     （另：保持原生自动重登分支，不强制手动登录）

用法
----
    # 方式 A：环境变量
    PRIVSRV_IP=新服务器公网IP python3 build_revived_apk.py

    # 方式 B：在 conf/revive.env 里填 YOUR_SERVER_IP=新服务器公网IP 后直接运行
    python3 build_revived_apk.py

产出
----
    client/out/创游编辑器_私服版_未签名.apk
    然后执行： bash sign_apk.sh    生成可安装的已签名 APK
    校验：     python3 verify_apk.py

依赖：仅 Python 3 标准库（无第三方依赖）
密钥：XXTEA key = ce27dc26-f6dc-47 （Cocos 编译期常量，见 client/src/README.md）
"""
import zipfile, struct, gzip, os, sys, hashlib, re

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(os.path.dirname(HERE))          # client/tools -> 包根
SRC = os.path.join(HERE, '..', 'base', '创游编辑器_v0.8.10_原版.apk')
OUTD = os.path.join(HERE, '..', 'out')
OUT = os.path.join(OUTD, '创游编辑器_私服版_未签名.apk')
JSC = 'assets/assets/main/index.e248a.jsc'
KEY = b'ce27dc26-f6dc-47'                              # 16B XXTEA 密钥
DELTA = 0x9e3779b9
key4 = list(struct.unpack('<4I', KEY))
PLACEHOLDER = '__SRV_IP__'


def resolve_ip():
    """新服务器 IP 只能来自环境变量或 conf/revive.env，绝不硬编码。"""
    ip = os.environ.get('PRIVSRV_IP', '').strip()
    if not ip:
        envf = os.path.join(KIT, 'conf', 'revive.env')
        if os.path.exists(envf):
            for line in open(envf, encoding='utf-8'):
                m = re.match(r'\s*YOUR_SERVER_IP\s*=\s*([^\s#]+)', line)
                if m:
                    ip = m.group(1).strip()
                    break
    if not ip or ip.startswith('YOUR_') or ip in ('0.0.0.0', ''):
        raise SystemExit(
            '[FAIL] 未指定新服务器 IP。\n'
            '       方式A: PRIVSRV_IP=<新服务器公网IP> python3 build_revived_apk.py\n'
            '       方式B: 在 conf/revive.env 填 YOUR_SERVER_IP=<新服务器公网IP>')
    if not re.match(r'^[A-Za-z0-9.\-]+$', ip):
        raise SystemExit('[FAIL] IP/域名含非法字符: %r' % ip)
    return ip


# ---------------- XXTEA (Cocos include-length 格式) ----------------
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


def btea_enc(v, n):
    if n < 2:
        return
    rounds = 6 + 52 // n
    s = 0
    zz = v[n - 1]
    for _ in range(rounds):
        s = (s + DELTA) & 0xffffffff
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + MX(zz, y, s, p, e)) & 0xffffffff
            zz = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + MX(zz, y, s, n - 1, e)) & 0xffffffff
        zz = v[n - 1]


def decode_jsc(data):
    n = len(data) // 4
    v = list(struct.unpack_from('<%dI' % n, data, 0))
    btea_dec(v, n)
    ln = v[n - 1]
    if not (0 < ln <= (n - 1) * 4):
        raise ValueError('bad length word %d (n=%d)' % (ln, n))
    return struct.pack('<%dI' % n, *v)[:ln]


def encode_jsc(js_bytes):
    gz = gzip.compress(js_bytes, compresslevel=9, mtime=0)
    L = len(gz)
    gzp = gz + b'\x00' * ((-L) % 4)
    n = len(gzp) // 4
    v = list(struct.unpack_from('<%dI' % n, gzp, 0))
    v.append(L)                     # 末尾 word = 原始明文长度
    N = n + 1
    btea_enc(v, N)
    return struct.pack('<%dI' % N, *v)


# ---------------- V3 补丁（逐字保留，仅把 IP 换成占位符） ----------------
# 2. DiscoverPage：绕开 idx guard 与 async 异常吞噬，直接加载默认子页
DP_PATCH = r'''setTimeout(() => {
  try {
    var R = window.__psrvR || function () {};
    var self = this;
    R('DP onLoad');
    try { if (self.toggleGroup) { self.toggleGroup.idx = 0; self.toggleGroup.lastIdx = 0; } } catch (e) {}
    var nm = (self.datas && self.datas[0] && self.datas[0].prefab) || 'DiscoverSubPage';
    R('DP target=' + nm);
    var go = function (tries) {
      try {
        var ex = self.pageMap && self.pageMap.get(nm);
        if (ex && ex.active) { R('DP already'); return; }
        var pr = d.Util.loadBundleRes('Scene/HomeScene/DiscoverPage/' + nm);
        if (!pr || typeof pr.then !== 'function') { R('DP no promise'); return; }
        pr.then(function (prefab) {
          try {
            R('DP prefab=' + (prefab ? 'ok' : 'null'));
            if (!prefab) { if (tries < 3) setTimeout(function () { go(tries + 1); }, 700); return; }
            var node = cc.instantiate(prefab);
            self.content.addChild(node);
            node.active = true;
            if (self.pageMap) self.pageMap.set(nm, node);
            R('DP ADDED');
          } catch (e) { R('DP inst ERR ' + e); if (tries < 3) setTimeout(function () { go(tries + 1); }, 700); }
        }, function (err) { R('DP load ERR ' + err); if (tries < 3) setTimeout(function () { go(tries + 1); }, 700); });
      } catch (e) { R('DP go ERR ' + e); }
    };
    go(0);
  } catch (e) {}
}, 300);
'''

# 4. 远程热修通道 + 状态上报（IP 用占位符，最后统一替换）
LOADER = r'''

/* ===== PRIVSRV v3 hotfix channel (async, non-blocking) ===== */
(function () {
  var BASE = 'http://__SRV_IP__';
  function R(m) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/hf?m=' + encodeURIComponent(String(m).slice(0, 180)) + '&t=' + new Date().getTime(), true);
      x.send();
    } catch (e) {}
  }
  try { window.__psrvR = R; } catch (e) {}
  try {
    var x = new XMLHttpRequest();
    x.open('GET', BASE + '/hotfix.js?t=' + new Date().getTime(), true);
    x.onload = function () {
      try {
        if (x.status === 200 && x.responseText) {
          R('HF loaded ' + x.responseText.length);
          try { (new Function(x.responseText))(); }
          catch (e) { try { eval(x.responseText); } catch (e2) { R('HF eval ERR ' + e); } }
        } else R('HF fail ' + x.status);
      } catch (e) { R('HF onload ERR ' + e); }
    };
    x.onerror = function () { R('HF neterr'); };
    x.send();
    R('HF request');
  } catch (e) { R('HF ERR ' + e); }
  R('BOOT v3');
})();
'''

PATCHES = [
    (
        '1. HomeScene.onLoad 主动加载默认主页面（修首页内容区空白）',
        'onLoad() {\n'
        'this.toggleGroup.node.on(r.default.TOGGLE_CHANGE, this.onToggleChange, this);\n'
        'this.createBtn.node.on(T.default.CLICK, this.onTapCreate, this);\n'
        '}',
        'onLoad() {\n'
        'this.toggleGroup.node.on(r.default.TOGGLE_CHANGE, this.onToggleChange, this);\n'
        'this.createBtn.node.on(T.default.CLICK, this.onTapCreate, this);\n'
        'setTimeout(() => { try { (window.__psrvR || function(){})("HS onLoad"); this.onToggleChange(0); } catch (e) { (window.__psrvR || function(){})("HS ERR " + e); } }, 0);\n'
        '}',
    ),
    (
        '2. DiscoverPage.onLoad 内联直接加载默认内容子页（修发现页空白）',
        'd.Util.makeBro(this.toggle.node, this.datas.length, (e, t) => {\n'
        'let o = e.getComponent(s.default), i = this.datas[t];\n'
        'o.label.string = i.name;\n'
        'd.Util.updateLabel(o.label);\n'
        'o.node.width = o.label.node.width + 40;\n'
        'd.Util.updateAllWidget(o.node);\n'
        '});\n'
        '}',
        'd.Util.makeBro(this.toggle.node, this.datas.length, (e, t) => {\n'
        'let o = e.getComponent(s.default), i = this.datas[t];\n'
        'o.label.string = i.name;\n'
        'd.Util.updateLabel(o.label);\n'
        'o.node.width = o.label.node.width + 40;\n'
        'd.Util.updateAllWidget(o.node);\n'
        '});\n'
        + DP_PATCH +
        '}',
    ),
    (
        '3. WS 直连新私服 IP（修卡登录：不依赖 DNS 解析官方域名）',
        'let o = d.gameEnv.urlRoot + "/agent";',
        'let o = "ws://__SRV_IP__/agent";',
    ),
]


def is_sig(nm):
    if not nm.startswith('META-INF/'):
        return False
    base = nm.rsplit('/', 1)[-1].upper()
    return base == 'MANIFEST.MF' or base.endswith(('.SF', '.RSA', '.DSA', '.EC'))


def main():
    srv_ip = resolve_ip()
    print('目标新服务器 IP :', srv_ip)
    print('基底 APK        :', os.path.abspath(SRC))
    if not os.path.exists(SRC):
        raise SystemExit('[FAIL] 找不到原版基底 APK: %s' % SRC)

    z = zipfile.ZipFile(SRC)
    orig_cipher = z.read(JSC)
    gz = decode_jsc(orig_cipher)
    js_bytes = gzip.decompress(gz)
    js = js_bytes.decode('utf-8')
    print('原 jsc: %dB -> gzip %dB -> js %dB' % (len(orig_cipher), len(gz), len(js_bytes)))

    # 加解密实现自检：原密文解密再加密必须逐字节还原
    n = len(orig_cipher) // 4
    vv = list(struct.unpack_from('<%dI' % n, orig_cipher, 0))
    btea_dec(vv, n)
    btea_enc(vv, n)
    assert struct.pack('<%dI' % n, *vv) == orig_cipher, 'XXTEA round-trip 自检失败'
    print('[OK] XXTEA 加解密 round-trip 字节级一致')

    for name, anchor, repl in PATCHES:
        c = js.count(anchor)
        if c != 1:
            raise SystemExit('[FAIL] 锚点不唯一: %s -> count=%d（原版 APK 版本可能不匹配）' % (name, c))
        js = js.replace(anchor, repl, 1)
        print('[OK] 补丁: %s' % name)

    js += LOADER
    print('[OK] 补丁: 4. 追加远程热修通道 (%d 字节)' % len(LOADER))

    # 统一注入 IP，并断言占位符全部被替换（防止漏改导致成品连回旧机）
    cnt = js.count(PLACEHOLDER)
    if cnt != 2:
        raise SystemExit('[FAIL] IP 占位符数量异常: 期望 2，实际 %d' % cnt)
    js = js.replace(PLACEHOLDER, srv_ip)
    print('[OK] 注入新服务器 IP 到 %d 处地址（ws:// 与 http://）' % cnt)

    assert 'let e = r.PlatType.Visitor, t = l.crossPlatform.getStorageSync(E.SaveDefines.KeyLoginType), o = !1;' in js
    print('[OK] 保持原生自动重登分支')

    new_js = js.encode('utf-8')
    new_cipher = encode_jsc(new_js)
    back = gzip.decompress(decode_jsc(new_cipher))
    assert back == new_js, 'jsc 回读自检失败'
    print('[OK] 新 jsc 回读一致: %dB -> js %dB' % (len(new_cipher), len(back)))

    os.makedirs(OUTD, exist_ok=True)
    zout = zipfile.ZipFile(OUT, 'w', allowZip64=True)
    kept = skipped = 0
    for info in z.infolist():
        if is_sig(info.filename):
            skipped += 1
            continue
        data = new_cipher if info.filename == JSC else z.read(info.filename)
        ni = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        ni.compress_type = info.compress_type
        ni.external_attr = info.external_attr
        ni.internal_attr = info.internal_attr
        ni.create_system = info.create_system
        ni.comment = info.comment
        ni.extra = info.extra
        zout.writestr(ni, data)
        kept += 1
    zout.comment = z.comment
    zout.close()
    print('[OK] 重建 APK: 保留 %d 条, 剔除旧签名 %d 条' % (kept, skipped))

    # 完整性自检：除 jsc 与签名外，其余条目必须字节一致
    zb = zipfile.ZipFile(OUT)
    assert zb.testzip() is None, 'zip 损坏'
    diff = [nm for nm in z.namelist()
            if not is_sig(nm) and z.read(nm) != zb.read(nm)]
    assert diff == [JSC], '意外改动条目: %s' % diff
    print('[OK] 完整性: 仅 %s 被替换' % JSC)

    print('\n输出: %s (%d bytes)' % (OUT, os.path.getsize(OUT)))
    print('SHA256:', hashlib.sha256(open(OUT, 'rb').read()).hexdigest())
    print('\n下一步: bash sign_apk.sh   （生成可安装的已签名 APK）')


if __name__ == '__main__':
    main()
