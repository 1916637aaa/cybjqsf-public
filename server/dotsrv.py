#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
私服 DoT（DNS-over-TLS）服务 —— 供 Android「私人 DNS」使用
=========================================================
用途：绕过运营商/路由器对 53 端口的劫持。Android 原生「私人 DNS」
      走 853/TCP 加密通道，本地网络无法篡改，WiFi 与移动数据都生效。

用法：手机 设置 → 私人 DNS → 填写本服务的域名（不是 IP）
"""

import socket, ssl, struct, threading, sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dnssrv import parse_name, build_hijack_answer, forward, SRV_IP, HIJACK_SUFFIX

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('dot')

# DoT 私人 DNS 域名：Android「私人 DNS」要填一个域名而非 IP。
# 用 nip.io 这类通配 DNS 即可：把 <IP>.nip.io 解析回该 IP，无需自己注册域名。
# 例如服务器 IP 是 1.2.3.4，就填 1-2-3-4.nip.io。
DOMAIN = os.environ.get('PRIVSRV_DOMAIN', (SRV_IP.replace('.', '-') + '.nip.io') if SRV_IP else 'privsrv.nip.io')
_HOME = os.path.dirname(os.path.abspath(__file__))
CERT = os.environ.get('PRIVSRV_DOT_CERT', os.path.join(_HOME, 'certs', 'dot.crt'))
KEY = os.environ.get('PRIVSRV_DOT_KEY', os.path.join(_HOME, 'certs', 'dot.key'))


def resolve(query):
    """处理单条 DNS 报文，返回响应"""
    try:
        qname, _ = parse_name(query, 12)
        low = qname.lower()
        if any(low == s or low.endswith(b'.' + s) for s in HIJACK_SUFFIX):
            log.info('劫持 %s -> %s' % (qname.decode('utf8', 'replace'), SRV_IP))
            return build_hijack_answer(query, qname, SRV_IP)
        return forward(query)
    except Exception as e:
        log.warning('解析失败: %s' % e)
        return None


def serve(conn, addr):
    try:
        while True:
            hdr = conn.recv(2)
            if len(hdr) < 2:
                break
            n = struct.unpack('!H', hdr)[0]
            if n == 0 or n > 4096:
                break
            buf = b''
            while len(buf) < n:
                chunk = conn.recv(n - len(buf))
                if not chunk:
                    break
                buf += chunk
            if len(buf) < n:
                break
            resp = resolve(buf)
            if resp is None:
                break
            conn.sendall(struct.pack('!H', len(resp)) + resp)
    except Exception as e:
        log.debug('连接结束 %s: %s' % (addr[0], e))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 853
    if not os.path.exists(CERT):
        log.error('证书不存在: %s（请先签发）' % CERT)
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(128)
    log.info('DoT 服务启动 0.0.0.0:%d  域名 %s  劫持 -> %s' % (port, DOMAIN, SRV_IP))

    while True:
        try:
            raw, addr = srv.accept()
            try:
                conn = ctx.wrap_socket(raw, server_side=True)
            except Exception as e:
                log.warning('TLS 握手失败 %s: %s' % (addr[0], e))
                raw.close()
                continue
            threading.Thread(target=serve, args=(conn, addr), daemon=True).start()
        except Exception as e:
            log.warning('accept 失败: %s' % e)


if __name__ == '__main__':
    main()
