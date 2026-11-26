#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
私服 DNS 劫持服务（供免 root 手机使用）
======================================
用途：手机没 root 改不了 /system/etc/hosts，改为把手机 WiFi 的 DNS
      指向本服务器，由本服务把已停服的域名解析到私服 IP。

  * 命中劫持域名  -> 直接返回私服 IP（A 记录）
  * 其余域名      -> 转发给上游 DNS（8.8.8.8），不影响正常上网

监听 UDP 53。
"""

import socket, struct, sys, os, threading, logging

# PRIVSRV_IP：你自己的服务器公网 IP，由 conf/privsrv.env 注入（安装脚本自动探测/填写）。
# 未配置时不返回任何 A 记录（避免误把域名指到别人的机器）。
SRV_IP = os.environ.get('PRIVSRV_IP', '').strip()
UPSTREAM = os.environ.get('PRIVSRV_UPSTREAM', '223.5.5.5')
HIJACK_SUFFIX = (
    b'hortorgames.com',
    b'hortorinteractive.com',
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('dns')
if not SRV_IP:
    log.warning('PRIVSRV_IP 未配置！请在 conf/privsrv.env 里填写本机公网 IP，DNS 劫持才会生效')


def parse_name(data, off):
    """解析 DNS 域名（支持压缩指针）"""
    parts = []
    jumped = False
    end = off
    p = off
    for _ in range(64):
        if p >= len(data):
            break
        ln = data[p]
        if ln == 0:
            p += 1
            if not jumped:
                end = p
            break
        if ln & 0xC0 == 0xC0:
            if not jumped:
                end = p + 2
            p = struct.unpack('!H', data[p:p + 2])[0] & 0x3FFF
            jumped = True
            continue
        parts.append(data[p + 1:p + 1 + ln])
        p += 1 + ln
    return b'.'.join(parts), end


def build_hijack_answer(query, qname, ip):
    """构造 A 记录应答"""
    tid = query[0:2]
    # QR=1(响应) Opcode=0 AA=1 RD=1 RA=1 rcode=0
    flags = struct.pack('!H', 0x8180)
    header = tid + flags + struct.pack('!HHHH', 1, 1, 0, 0)

    qend = 12
    # 跳过 question（复制原始字节即可）
    _, qend = parse_name(query, 12)
    question = query[12:qend + 4]

    # answer: 名称指针指向 question 起始(0xC00C)
    answer = struct.pack('!HHHIH', 0xC00C, 1, 1, 60, 4)
    answer += socket.inet_aton(ip)
    return header + question + answer


def forward(query):
    """转发给上游 DNS"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(query, (UPSTREAM, 53))
        resp, _ = s.recvfrom(4096)
        return resp
    except Exception:
        return None
    finally:
        s.close()


def handle(query, addr, sock):
    try:
        if len(query) < 12:
            return
        qname, _ = parse_name(query, 12)
        low = qname.lower()
        hit = any(low == s or low.endswith(b'.' + s) for s in HIJACK_SUFFIX)
        if hit:
            resp = build_hijack_answer(query, qname, SRV_IP)
            log.info('劫持 %s -> %s (来自 %s)' % (qname.decode('utf8', 'replace'), SRV_IP, addr[0]))
        else:
            resp = forward(query)
            if resp is None:
                return
        sock.sendto(resp, addr)
    except Exception as e:
        log.warning('处理失败 %s: %s' % (addr[0], e))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    log.info('DNS 劫持服务启动 0.0.0.0:%d  劫持目标 -> %s  上游 %s' % (port, SRV_IP, UPSTREAM))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=handle, args=(data, addr, sock), daemon=True).start()
        except Exception as e:
            log.warning('接收失败: %s' % e)


if __name__ == '__main__':
    main()
