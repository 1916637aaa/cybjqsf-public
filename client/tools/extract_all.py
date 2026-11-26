#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""创游编辑器 私服版 APK 客户端源码一键提取
   .jsc = XXTEA(gzip(js)), key = 硬编码在 libcocos2djs.so 的 16 字节
"""
import zipfile, struct, gzip, os, sys, io

APK='app.apk'
KEY=b'ce27dc26-f6dc-47'          # 16B, from libcocos2djs.so .rodata assert len(KEY)==16
OUT='app_src'                       # 输出目录
DELTA=0x9e3779b9

def btea_dec(v,n,key4):
    """标准 XXTEA (Corrected Block TEA) 解密, in-place"""
    MX=lambda z,y,sum,p,e: ((((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((sum^y)+(key4[(p&3)^e]^z)))
    if n<2: return
    rounds=6+52//n; s=(rounds*DELTA)&0xffffffff; y=v[0]
    for _ in range(rounds):
        e=(s>>2)&3
        for p in range(n-1,0,-1):
            z=v[p-1]; v[p]=(v[p]-MX(z,y,s,p,e))&0xffffffff; y=v[p]
        z=v[n-1]; v[0]=(v[0]-MX(z,y,s,0,e))&0xffffffff; y=v[0]
        s=(s-DELTA)&0xffffffff

def xxtea_decrypt_bytes(data,key):
    """Cocos/xxtea include-length 格式: 解密后最后 word = 明文长度"""
    n=len(data)//4
    v=list(struct.unpack_from('<%dI'%n,data,0))
    key4=list(struct.unpack('<4I',key))
    btea_dec(v,n,key4)
    ln=v[n-1]
    if not (0<ln<=(n-1)*4): raise ValueError('bad length word %d (n=%d)'%(ln,n))
    out=struct.pack('<%dI'%n,*v)
    return out[:ln]

def decode_jsc(data,key):
    raw=xxtea_decrypt_bytes(data,key)
    # 可能是 gzip / 纯文本 / zlib
    if raw[:2]==b'\x1f\x8b': raw=gzip.decompress(raw)
    elif raw[:2] in (b'x\x01',b'x\x9c',b'x\xda'):
        import zlib; raw=zlib.decompress(raw)
    return raw

def main():
    z=zipfile.ZipFile(APK)
    os.makedirs(OUT,exist_ok=True)
    jscs=sorted(n for n in z.namelist() if n.endswith('.jsc'))
    js  =sorted(n for n in z.namelist() if n.endswith('.js'))
    print('密钥:',KEY,'  .jsc数:',len(jscs),'  明文.js数:',len(js))
    ok=fail=0; report=[]
    for n in jscs:
        data=z.read(n)
        try:
            raw=decode_jsc(data,KEY)
            txt=raw.decode('utf8','replace')
            # 输出路径: 去掉 assets/ 前缀, .jsc->.js
            rel=n[len('assets/'):] if n.startswith('assets/') else n
            rel=rel[:-4]+'.js'
            dst=os.path.join(OUT,rel)
            os.makedirs(os.path.dirname(dst),exist_ok=True)
            open(dst,'w',encoding='utf8').write(txt)
            ok+=1
            report.append((n,len(data),len(txt),'OK'))
            print('  OK   %-56s %7dB -> %8d chars'%(n[:56],len(data),len(txt)))
        except Exception as e:
            fail+=1; report.append((n,len(data),0,'FAIL '+str(e)[:60]))
            print('  FAIL %-56s %s'%(n[:56],e))
    # 明文 .js 一并复制
    for n in js:
        rel=n[len('assets/'):] if n.startswith('assets/') else n
        dst=os.path.join(OUT,rel)
        os.makedirs(os.path.dirname(dst),exist_ok=True)
        open(dst,'wb').write(z.read(n))
        report.append((n,z.getinfo(n).file_size,z.getinfo(n).file_size,'PLAIN'))
    print('\n结果: 解密成功 %d / 失败 %d, 另附明文 js %d'%(ok,fail,len(js)))
    total=sum(r[2] for r in report if r[3]=='OK')
    print('解密源码总字符数:',total)
    with open(os.path.join(OUT,'_manifest.txt'),'w',encoding='utf8') as f:
        f.write('key=%s\n'%KEY.decode())
        for n,a,b,s in report: f.write('%s\t%d\t%d\t%s\n'%(n,a,b,s))
    return fail

if __name__=='__main__':
    sys.exit(1 if main() else 0)
