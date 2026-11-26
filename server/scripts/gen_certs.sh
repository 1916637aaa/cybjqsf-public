#!/usr/bin/env bash
# ============================================================
#  生成私服全套自签证书（CA / 游戏域名证书 / 后台证书 / DoT 证书）
#  关键：所有证书的 SAN 都带【你自己的服务器 IP】，不会残留任何他人地址。
#  用法： bash scripts/gen_certs.sh           （读 conf/privsrv.env 的 PRIVSRV_IP）
# ============================================================
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
source "$KIT/conf/privsrv.env"

IP="${PRIVSRV_IP:-}"
if [ -z "$IP" ]; then
  echo "✗ conf/privsrv.env 里 PRIVSRV_IP 未填写，请先填本机公网 IP"; exit 1
fi
CERT="$KIT/certs"
mkdir -p "$CERT"
cd "$CERT"
echo "[*] 使用服务器 IP: $IP"

# ---------- 1. 根 CA（手机需要安装并信任这个 CA）----------
if [ ! -f privsrv-ca.key ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout privsrv-ca.key -out privsrv-ca.crt \
    -subj "/C=CN/O=CreatorPrivSrv/CN=Creator PrivSrv Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  echo "[+] 生成根 CA: privsrv-ca.crt / privsrv-ca.key"
else
  echo "[=] 根 CA 已存在，复用"
fi
chmod 600 privsrv-ca.key

# ---------- 2. 游戏域名证书（*.hortorgames.com 等，nginx 443 用）----------
cat > _server_ext.cnf <<EOF
[req]
distinguished_name=dn
[dn]
[v3]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt
[alt]
DNS.1=*.hortorgames.com
DNS.2=hortorgames.com
DNS.3=platform.hortorgames.com
DNS.4=ucenter-app-server.hortorgames.com
DNS.5=pay-app-server.hortorgames.com
DNS.6=anti.hortorgames.com
DNS.7=speech-recognize-server.hortorgames.com
DNS.8=ios-app.hortorgames.com
DNS.9=mp.hortorgames.com
DNS.10=*.hortorinteractive.com
DNS.11=hortorinteractive.com
DNS.12=localhost
IP.1=127.0.0.1
IP.2=$IP
EOF
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/C=CN/O=Hortor/CN=*.hortorgames.com" 2>/dev/null
openssl x509 -req -in server.csr -CA privsrv-ca.crt -CAkey privsrv-ca.key \
  -CAcreateserial -out server.crt -days 3650 -sha256 -extfile _server_ext.cnf -extensions v3 2>/dev/null
echo "[+] 生成游戏域名证书: server.crt / server.key"

# ---------- 3. 后台管理证书（SAN = 你的 IP，浏览器访问 https://IP:38443 用）----------
cat > _admin_ext.cnf <<EOF
[v3]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt
[alt]
IP.1=$IP
DNS.1=$IP
DNS.2=localhost
IP.2=127.0.0.1
EOF
openssl req -newkey rsa:2048 -nodes -keyout admin.key -out admin.csr \
  -subj "/CN=$IP" 2>/dev/null
openssl x509 -req -in admin.csr -CA privsrv-ca.crt -CAkey privsrv-ca.key \
  -CAcreateserial -out admin.crt -days 3650 -sha256 -extfile _admin_ext.cnf -extensions v3 2>/dev/null
echo "[+] 生成后台证书: admin.crt / admin.key"

# ---------- 4. DoT 证书（Android 私人 DNS）----------
DOMAIN="${PRIVSRV_DOMAIN:-$(echo "$IP" | tr '.' '-').nip.io}"
cat > _dot_ext.cnf <<EOF
[v3]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$DOMAIN
EOF
openssl req -newkey rsa:2048 -nodes -keyout dot.key -out dot.csr \
  -subj "/CN=$DOMAIN" 2>/dev/null
openssl x509 -req -in dot.csr -CA privsrv-ca.crt -CAkey privsrv-ca.key \
  -CAcreateserial -out dot.crt -days 3650 -sha256 -extfile _dot_ext.cnf -extensions v3 2>/dev/null
echo "[+] 生成 DoT 证书: dot.crt / dot.key  (私人 DNS 域名: $DOMAIN)"

# ---------- 5. 供手机安装的 CA（放到 uploads/ 方便下载）----------
mkdir -p "$KIT/uploads"
cp privsrv-ca.crt "$KIT/uploads/privsrv-ca.crt"
echo "[+] 已把根 CA 放到 uploads/privsrv-ca.crt"

chmod 600 *.key
rm -f *.csr _server_ext.cnf _admin_ext.cnf _dot_ext.cnf
echo ""
echo "✓ 证书全部生成完成。请把下面这个文件安装到手机并『信任』它："
echo "    $KIT/uploads/privsrv-ca.crt"
