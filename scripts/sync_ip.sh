#!/usr/bin/env bash
# ============================================================
# 把 conf/revive.env 里填的「新服务器 IP」同步到服务端配置，
# 让一键安装脚本无需交互、且服务端与客户端共用同一个 IP。
#
# 用法： bash scripts/sync_ip.sh
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KIT="$(dirname "$HERE")"
ENVF="$KIT/conf/revive.env"
SENV="$KIT/server/conf/privsrv.env"

IP="$(grep -E '^YOUR_SERVER_IP=' "$ENVF" | head -1 | cut -d= -f2- | tr -d ' \r' | sed 's/#.*//')"

if [ -z "$IP" ] || [[ "$IP" == YOUR_* ]]; then
  echo "✗ 请先在 $ENVF 里填 YOUR_SERVER_IP=<新服务器公网IP>"
  exit 1
fi

if [ ! -f "$SENV" ]; then
  echo "✗ 找不到 $SENV"; exit 1
fi

if grep -q '^PRIVSRV_IP=' "$SENV"; then
  sed -i "s|^PRIVSRV_IP=.*|PRIVSRV_IP=$IP|" "$SENV"
else
  echo "PRIVSRV_IP=$IP" >> "$SENV"
fi

echo "✓ 已同步新服务器 IP = $IP"
echo "    conf/revive.env        YOUR_SERVER_IP"
echo "    server/conf/privsrv.env PRIVSRV_IP"
echo
echo "下一步："
echo "  1) 部署服务端： sudo cp -a server/. /opt/privsrv/ && cd /opt/privsrv && sudo bash scripts/install.sh"
echo "  2) 重建客户端： PRIVSRV_IP=$IP python3 client/tools/build_revived_apk.py && bash client/tools/sign_apk.sh"
