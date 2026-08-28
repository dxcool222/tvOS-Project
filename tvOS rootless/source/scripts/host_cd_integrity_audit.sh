#!/bin/bash
# Host CodeDirectory integrity audit (102705 codeLimit closure gate).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHoma="$ROOT/../Dopamine_Rootful-main/BaseBin/ChOma"
WORK=/tmp/dt705_cd_audit
BIN="$WORK/host_cd_integrity_audit"
IPA="${1:-$ROOT/../dopamin-tvOS-kfd-102704-CHOMA-LAYOUT-FIX-DIAG.ipa}"
HOOK_SRC="$WORK/fixture/launchdhook516.dylib"
ENT="$WORK/fixture/entitlements_launchdhook681.plist"
ORIG_HOOK="$WORK/fixture/original_launchdhook516.dylib"

rm -rf "$WORK"
mkdir -p "$WORK/fixture"

if [[ ! -f "$IPA" ]]; then
  echo "ERROR: missing IPA: $IPA"
  exit 1
fi

unzip -q -o "$IPA" \
  "Payload/dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib" \
  "Payload/dopamin-tvOS-kfd.app/Handoff516/entitlements_launchdhook681.plist" -d "$WORK"
cp "$WORK/Payload/dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib" "$ORIG_HOOK"
cp "$WORK/Payload/dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib" "$HOOK_SRC"
mv "$WORK/Payload/dopamin-tvOS-kfd.app/Handoff516/entitlements_launchdhook681.plist" "$ENT"
rm -rf "$WORK/Payload"

clang -O2 -fobjc-arc \
  -I"$CHoma/include" -I"$CHoma/src" -I"$CHoma/include/choma" -I"$ROOT" \
  "$ROOT/scripts/host_cd_integrity_audit.c" "$ROOT/dt_choma_platform_sign.c" "$CHoma"/src/*.c \
  -lcompression -o "$BIN"

echo "=== 1. Original vs transformed CodeDirectory compare ==="
"$BIN" compare "$ORIG_HOOK" "$HOOK_SRC" "$ENT"

echo ""
echo "=== 2. Final structural audit (sign + verify) ==="
"$BIN" sign "$HOOK_SRC" "$ENT"
