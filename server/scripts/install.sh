#!/usr/bin/env bash
# ============================================================
#  私服一键安装脚本 —— 在【你自己的】服务器上部署一套完整独立私服
#
#  用法：
#    1) 把服务端放到 /opt/privsrv（源码按此固定路径编写，脚本会强校验）
#       复活交接包：在【包根】执行
#         sudo mkdir -p /opt/privsrv && sudo cp -a server/. /opt/privsrv/ && cd /opt/privsrv
#       （IP 已由包根 scripts/sync_ip.sh 写入 conf/privsrv.env，本脚本无需交互）
#    2) sudo bash scripts/install.sh
#
#  脚本会：检查环境 -> 询问/确认服务器 IP -> 生成证书/密码 ->
#          安装依赖 -> 配置 nginx -> 安装并启动 6 个 systemd 服务 -> 自检
#  全程不连任何外部私服，装完客户端连的就是【本机】。
# ============================================================
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
ENVF="$KIT/conf/privsrv.env"

echo "============================================"
echo "  私服安装程序   目录: $KIT"
echo "============================================"

# ---------- 0. root 检查 ----------
if [ "$(id -u)" != "0" ]; then echo "✗ 请用 root 运行（sudo bash scripts/install.sh）"; exit 1; fi

# ---------- 1. 固定路径检查 ----------
if [ "$KIT" != "/opt/privsrv" ]; then
  echo "✗ 本包必须解压到 /opt/privsrv 使用（源码按此固定路径编写）。"
  echo "  当前目录: $KIT"
  echo "  请执行: sudo mkdir -p /opt && sudo mv '$KIT' /opt/privsrv && cd /opt/privsrv && sudo bash scripts/install.sh"
  exit 1
fi

# ---------- 2. 依赖检查/安装 ----------
echo "[1/7] 检查运行环境 ..."
command -v python3 >/dev/null || { echo "✗ 缺少 python3"; exit 1; }
command -v node   >/dev/null || { echo "✗ 缺少 node（用于 lz4 编码），请先安装 nodejs"; exit 1; }
command -v openssl >/dev/null || { echo "✗ 缺少 openssl"; exit 1; }
command -v nginx  >/dev/null || echo "  [!] 未检测到 nginx：请先安装 nginx 后再运行（见教程）"

PY=python3
$PY -c "import flask, bcrypt, websockets" 2>/dev/null || {
  echo "  安装 Python 依赖 ..."
  $PY -m pip install -q -r "$KIT/requirements.txt" 2>/dev/null || \
    { echo "  pip 安装失败，尝试系统包管理器 ..."; \
      (apt-get install -y python3-flask python3-bcrypt python3-websockets 2>/dev/null) || \
      { echo "✗ 依赖安装失败，请手动: pip3 install flask bcrypt websockets"; exit 1; }; }
}
echo "  ✓ python3 / node / openssl / flask.bcrypt.websockets"

# ---------- 3. 确定服务器 IP ----------
echo "[2/7] 配置服务器 IP ..."
CUR_IP="$(grep -E '^PRIVSRV_IP=' "$ENVF" | cut -d= -f2- | tr -d ' ')"
# 自动探测一个候选（取默认路由出口 IP）
CAND="$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || true)"
[ -z "$CAND" ] && CAND="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "$CUR_IP" ]; then
  if [ -t 0 ]; then
    read -rp "  请输入本服务器公网 IP [检测到: ${CAND:-无}]: " IN_IP
    CUR_IP="${IN_IP:-$CAND}"
  else
    CUR_IP="$CAND"
  fi
fi
if [ -z "$CUR_IP" ]; then
  echo "✗ 无法确定服务器 IP。请编辑 conf/privsrv.env，把 PRIVSRV_IP= 填上你的公网 IP 后重跑。"
  exit 1
fi
# 写回 env（幂等）
if grep -q '^PRIVSRV_IP=' "$ENVF"; then
  sed -i "s|^PRIVSRV_IP=.*|PRIVSRV_IP=$CUR_IP|" "$ENVF"
else
  echo "PRIVSRV_IP=$CUR_IP" >> "$ENVF"
fi
echo "  ✓ PRIVSRV_IP=$CUR_IP"
# 导出给后续脚本
export PRIVSRV_IP="$CUR_IP"

# ---------- 4. 生成证书 ----------
echo "[3/7] 生成自签证书（SAN 带你的 IP）..."
bash "$KIT/scripts/gen_certs.sh"

# ---------- 5. 初始化后台密码 ----------
echo "[4/7] 初始化后台管理密码 ..."
bash "$KIT/scripts/init_admin.sh"

# ---------- 6. 目录与权限 ----------
echo "[5/7] 准备目录与权限 ..."
mkdir -p "$KIT/logs" "$KIT/uploads/cover/pixel" "$KIT/data"
chmod 600 "$KIT"/certs/*.key 2>/dev/null || true
chmod +x "$KIT"/scripts/*.sh
# python 语法自检
$PY -m py_compile "$KIT"/*.py && echo "  ✓ Python 语法检查通过"

# ---------- 7. nginx 配置 ----------
echo "[6/7] 配置 nginx ..."
NGX_OK=0
if [ -d /etc/nginx/conf.d ]; then
  cp "$KIT/conf/nginx/privsrv.conf" /etc/nginx/conf.d/privsrv.conf && NGX_OK=1
  echo "  已放到 /etc/nginx/conf.d/privsrv.conf"
elif [ -d /www/server/panel/vhost/nginx ]; then
  cp "$KIT/conf/nginx/privsrv.conf" /www/server/panel/vhost/nginx/privsrv.conf && NGX_OK=1
  echo "  已放到宝塔 /www/server/panel/vhost/nginx/privsrv.conf（请确认主配置 include 了该目录）"
else
  echo "  [!] 未找到 nginx 配置目录，请手动复制 conf/nginx/privsrv.conf（见教程）"
fi
if [ "$NGX_OK" = "1" ] && command -v nginx >/dev/null; then
  nginx -t 2>/dev/null && (nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true) && echo "  ✓ nginx 已重载" \
    || echo "  [!] nginx 配置校验未通过，请手动检查（nginx -t）"
fi

# ---------- 8. systemd 服务 ----------
echo "[7/7] 安装并启动 systemd 服务 ..."
cp "$KIT"/conf/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
for u in privsrv agentsrv privsrv-admin privsrv-proxy privsrv-dns privsrv-dot; do
  systemctl enable "$u" >/dev/null 2>&1 || true
  systemctl restart "$u" >/dev/null 2>&1 || true
done
sleep 3
echo ""
echo "  服务状态："
for u in privsrv agentsrv privsrv-admin privsrv-proxy privsrv-dns privsrv-dot; do
  printf '    %-18s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
done

echo ""
echo "============================================"
echo "  ✓ 安装完成。现在这套私服跑在【本机 $CUR_IP】上"
echo "============================================"
echo ""
echo "  客户端接入（手机与服务器网络可达）："
echo "   方式A WiFi 代理： 代理主机 $CUR_IP  端口 8080，并安装信任根证书"
echo "   方式B 私人 DNS ： Android 私人 DNS 填  $CUR_IP  或  $(echo "$CUR_IP"|tr '.' '-').nip.io"
echo "   根证书（装到手机并信任）： $KIT/uploads/privsrv-ca.crt"
echo "   后台管理： https://$CUR_IP:38443   （密码见 $KIT/admin_password.txt）"
echo ""
echo "  防火墙/安全组需放行： 80 443 8080 8443(仅本机) 8765(仅本机) 38443 53 853"
echo "  详细步骤与排错见： docs/开服教程.md"
echo ""
