#!/usr/bin/env bash
# ============================================================
#  开服自检：逐项确认端口、服务、证书、回包是否正常
#  用法： bash scripts/check.sh
# ============================================================
set -u
KIT="$(cd "$(dirname "$0")/.." && pwd)"
source "$KIT/conf/privsrv.env"
IP="${PRIVSRV_IP:-127.0.0.1}"
OK=0; BAD=0
chk(){ if eval "$2" >/dev/null 2>&1; then echo "  [✓] $1"; OK=$((OK+1)); else echo "  [✗] $1"; BAD=$((BAD+1)); fi; }

echo "=== 服务状态 ==="
for u in privsrv agentsrv privsrv-admin privsrv-proxy privsrv-dns privsrv-dot; do
  chk "$u = active" "systemctl is-active $u | grep -q active"
done
echo "=== 端口监听 ==="
chk "8443 后端"      "ss -ltn | grep -q ':8443'"
chk "8765 WS"        "ss -ltn | grep -q ':8765'"
chk "38443 后台"     "ss -ltn | grep -q ':38443'"
chk "8080 代理"      "ss -ltn | grep -q ':8080'"
chk "443 nginx"      "ss -ltn | grep -q ':443'"
chk "80 nginx"       "ss -ltn | grep -q ':80 '"
chk "53 DNS"         "ss -lun | grep -q ':53 '"
echo "=== 证书 ==="
chk "游戏证书存在"   "test -f $KIT/certs/server.crt"
chk "后台证书 SAN 含本机IP" "openssl x509 -in $KIT/certs/admin.crt -noout -text | grep -q '$IP'"
chk "根CA存在"       "test -f $KIT/certs/privsrv-ca.crt"
echo "=== 回包 ==="
chk "后端 / 响应"    "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/ | grep -qE '200|302|404'"
chk "后台登录页"     "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:38443/login | grep -q 200"
chk "WS game_login 回包" "python3 $KIT/scripts/ws_probe.py | grep -q WS_PROBE_OK"
echo ""
echo "结果: $OK 项通过, $BAD 项失败"
[ "$BAD" -eq 0 ] && echo "✓ 全部正常" || echo "✗ 有异常，见 docs/开服教程.md 排错章节"
