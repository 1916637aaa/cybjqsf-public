#!/usr/bin/env bash
# ============================================================
# 对 build_revived_apk.py 产出的「未签名 APK」做 zipalign + 重签名
#
# 为什么必须重签名：
#   改过 index.jsc 后旧签名失效，Android 会拒绝安装。
#   原版是官方签名（CN=Hortor），我们无法复用；历史 V3/免root版
#   也都是现场各生成一把新 keystore（apksigner 验证可见三套不同证书），
#   所以这里同样现场生成，不需要、也不应该去找旧密钥口令。
#
# 用法： bash sign_apk.sh
# 产出： client/out/创游编辑器_私服版_已签名.apk   ← 装进手机的就是这个
# 依赖： keytool / zipalign / apksigner（Android SDK build-tools）
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$HERE/../out"
UNSIGNED="$OUTDIR/创游编辑器_私服版_未签名.apk"
ALIGNED="$OUTDIR/创游编辑器_私服版_aligned.apk"
FINAL="$OUTDIR/创游编辑器_私服版_已签名.apk"
KS="$OUTDIR/revive.jks"

KS_PASS='privsrv-revive-2026'
KS_ALIAS='revive'

for t in keytool zipalign apksigner; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "[FAIL] 缺少 $t。请先安装 Android SDK build-tools 与 JDK，例如："
    echo "       apt-get update && apt-get install -y apksigner zipalign openjdk-17-jdk-headless"
    echo "       或把 \$ANDROID_HOME/build-tools/<版本>/ 与 JDK/bin 加入 PATH"
    exit 1
  fi
done

if [ ! -f "$UNSIGNED" ]; then
  echo "[FAIL] 找不到 $UNSIGNED，请先运行 build_revived_apk.py"
  exit 1
fi

echo "[1/4] 生成新签名密钥（首次运行时）"
if [ ! -f "$KS" ]; then
  keytool -genkeypair -v \
    -keystore "$KS" -alias "$KS_ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KS_PASS" -keypass "$KS_PASS" \
    -dname "CN=PrivSrv Revive, OU=Private, O=PrivSrv, L=CN, ST=CN, C=CN" 2>&1 | tail -3
else
  echo "      复用已有 $KS"
fi

echo "[2/4] zipalign 对齐"
cp -f "$UNSIGNED" "$ALIGNED"
zipalign -f -p 4 "$ALIGNED" "$ALIGNED.tmp" 2>/dev/null || zipalign -f -p 4 "$UNSIGNED" "$ALIGNED"
if [ -f "$ALIGNED.tmp" ]; then mv -f "$ALIGNED.tmp" "$ALIGNED"; fi

echo "[3/4] apksigner 签名（v1+v2+v3，兼容 Android 11+ 强制 v2）"
apksigner sign \
  --ks "$KS" --ks-key-alias "$KS_ALIAS" \
  --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --out "$FINAL" "$ALIGNED"

echo "[4/4] 验证签名"
apksigner verify --print-certs "$FINAL" 2>&1 | grep -E 'Signer #1 certificate (DN|SHA-256 digest)' || true

echo
echo "✓ 完成。安装到手机的文件："
echo "    $FINAL"
echo "  ($(du -h "$FINAL" | cut -f1))"
echo
echo "注意：签名与原版不同，手机上必须先卸载原版再安装（覆盖安装必定失败）。"
