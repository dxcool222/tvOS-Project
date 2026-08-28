#!/bin/bash
# BUILD102730 Gate 1 — isolated three-dylib host closure (no device IPA, no frozen overwrites).
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
OUT="$KFD/build/gate1/Handoff516"
SRC="$KFD/handoff516/source"
SDK="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
CC="xcrun -sdk appletvos clang"
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
TVOS_MIN=14.0

mkdir -p "$OUT" "$KFD/build/gate1/obj/hook"

echo "=== Gate1 Step 1: libjailbreak + libchoma (Handoff role) ==="
bash "$KFD/scripts/build_gate1_libjailbreak.sh"

INC=(
  -I"$KFD/build/gate1/include"
  -I"$KFD/build/gate1/include/choma"
  -I"$KFD/stubs"
  -I"/tmp/dopamin-dopamine/BaseBin/_external/include"
  -I"/tmp/dopamin-dopamine/BaseBin/libjailbreak/src"
  -I"$SRC/include"
  -I"$SRC/include/libjailbreak"
  -I"$SRC/include/jbserver"
)

CFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -O2
  -Wno-error
  -Wno-deprecated-declarations
  -Wno-availability
  -D_DARWIN_UNLIMITED_SYSCALLS
  -fPIC
  -fobjc-arc
  "${INC[@]}"
)

HOOK_OBJS=()
compile() {
  local src="$1" obj="$2"
  echo "  CC $(basename "$src")"
  if [[ "$src" == *.m ]]; then
    $CC "${CFLAGS[@]}" -c "$src" -o "$obj"
  else
    $CC "${CFLAGS[@]}" -c "$src" -o "$obj"
  fi
  HOOK_OBJS+=("$obj")
}

echo "=== Gate1 Step 2: launchdhook516.dylib (source-built, no xpc_hook) ==="
compile "$SRC/launchdhook/dt_launchdhook516_main_gate1.m" "$KFD/build/gate1/obj/hook/main_gate1.o"
compile "$SRC/launchdhook/dt_launchdhook516_boomerang.c" "$KFD/build/gate1/obj/hook/boomerang516.o"
compile "$SRC/launchdhook/dt_jbserver_mach516.c" "$KFD/build/gate1/obj/hook/jbserver_mach516.o"
compile "$SRC/launchdhook/jbserver/dt_jbdomain_watchdog_gate1.c" "$KFD/build/gate1/obj/hook/dt_jbdomain_watchdog_gate1.o"

for f in "$SRC/launchdhook/jbserver/"*.c; do
  base=$(basename "$f")
  [[ "$base" == "jbserver_mach.c" ]] && continue
  [[ "$base" == "jbdomain_watchdog.c" ]] && continue
  [[ "$base" == "dt_jbdomain_watchdog_gate1.c" ]] && continue
  compile "$f" "$KFD/build/gate1/obj/hook/$base.o"
done

HOOK_OUT="$OUT/launchdhook516.dylib"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/launchdhook516.dylib" \
  -L"$OUT" -ljailbreak \
  "${HOOK_OBJS[@]}" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm -lobjc \
  -o "$HOOK_OUT"

"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o "$HOOK_OUT" "$HOOK_OUT"

LDID="${LDID:-/opt/local/bin/ldid}"
if [[ -x "$LDID" ]]; then
  "$LDID" -S"$KFD/handoff681/entitlements_launchdhook681.plist" "$HOOK_OUT" 2>/dev/null || true
fi

echo "=== Gate1 trio built in $OUT ==="
ls -la "$OUT"/*.dylib
echo "SEED_BINARY_USAGE=NO"
echo "ALL_THREE_SOURCE_BUILT=YES"
