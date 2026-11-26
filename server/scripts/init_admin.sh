#!/usr/bin/env bash
# ============================================================
#  初始化后台管理密码（随机生成，绝不复用任何现有密码）
#  生成：data/admin_auth.json (bcrypt 哈希 + 会话密钥)
#        admin_password.txt   (明文，仅 root 可读，装完请自行保存并删除)
# ============================================================
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$KIT"

if [ -f data/admin_auth.json ]; then
  echo "[=] data/admin_auth.json 已存在，跳过（如需重置先删除它）"
  exit 0
fi

python3 - <<'PY'
import bcrypt, secrets, json, os
pw = secrets.token_urlsafe(18)
pw_hash = bcrypt.hashpw(pw.encode('utf8'), bcrypt.gensalt(rounds=12)).decode('utf8')
secret = secrets.token_urlsafe(32)
json.dump({'pw_hash': pw_hash, 'secret': secret},
          open('data/admin_auth.json', 'w'), ensure_ascii=False, indent=1)
with open('admin_password.txt', 'w') as f:
    f.write(pw)
os.chmod('data/admin_auth.json', 0o600)
os.chmod('admin_password.txt', 0o600)
print('[+] 后台随机密码已生成 -> admin_password.txt')
PY
echo ""
echo "  后台管理密码（请立即保存，之后可删除 admin_password.txt）："
echo "  ----------------------------------------"
cat admin_password.txt; echo
echo "  ----------------------------------------"
