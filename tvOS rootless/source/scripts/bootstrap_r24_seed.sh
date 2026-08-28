#!/bin/bash
# Build frozen 102738P SEED trio (opainject/jbctl/libchoma) from source — no IPA/old artifacts.
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=scripts/clean_project_env.sh
source "$SCRIPT/clean_project_env.sh"

KFD="$DT_KFD_ROOT"
SEED="$DT_BUILD_ROOT/build/102738P/Handoff516"
DOPAMINE="$DT_DOPAMINE_ROOT"
OPAINJECT_SRC="$DOPAMINE/BaseBin/opainject"
SDK="${TVOS_SYSROOT:-$HOME/theos/sdks/AppleTVOS16.4.sdk}"
TVOS_MIN=14.0
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
LDID="${LDID:-$(command -v ldid || true)}"
INSTALL_NAME_TOOL="${INSTALL_NAME_TOOL:-/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool}"

[[ -d "$SDK" ]] || { echo "ERROR: missing SDK $SDK"; exit 1; }
[[ -f "$KFD/basebin/out/libchoma.dylib" ]] || { echo "ERROR: run basebin dylibs first"; exit 1; }

mkdir -p "$SEED"
OBJ="$DT_BUILD_ROOT/build/seed_obj"
mkdir -p "$OBJ/opainject"
cp -p "$KFD/handoff681/entitlements_launchdhook681.plist" "$SEED/"

CFLAGS=( -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" -O2
  -Wno-deprecated-declarations -Wno-error -D_DARWIN_UNLIMITED_SYSCALLS )

echo "=== seed dt_jbctl516 ==="
xcrun -sdk appletvos clang "${CFLAGS[@]}" -o "$SEED/dt_jbctl516" "$KFD/handoff681/dt_jbctl681.c"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o "$SEED/dt_jbctl516" "$SEED/dt_jbctl516"
[[ -x "$LDID" ]] && "$LDID" -S"$KFD/handoff681/entitlements_jbctl681.plist" "$SEED/dt_jbctl516"
chmod +x "$SEED/dt_jbctl516"

echo "=== seed dt_opainject516 ==="
cp "$OPAINJECT_SRC"/dyld.m "$OPAINJECT_SRC"/shellcode_inject.m "$OPAINJECT_SRC"/thread_utils.m \
   "$OPAINJECT_SRC"/task_utils.m "$OPAINJECT_SRC"/arm64.m "$OPAINJECT_SRC"/*.h "$OBJ/opainject/" 2>/dev/null || true
cp "$KFD/handoff681/dt_opainject681_rop_inject.h" "$OBJ/opainject/rop_inject.h"
cp "$KFD/handoff681/dt_opainject681_main.m" "$OBJ/opainject/main.m"
cp "$KFD/handoff681/dt_opainject681_rop_inject.m" "$OBJ/opainject/rop_inject.m"
cp "$KFD/handoff681/dt_opainject_tvos_prefix.h" "$OBJ/opainject/"
OPAINJECT_CFLAGS=( "${CFLAGS[@]}" -include "$OBJ/opainject/dt_opainject_tvos_prefix.h"
  -I"$OBJ/opainject" -I"$DOPAMINE/BaseBin/_external/include"
  -framework CoreFoundation -framework Foundation -ldl -Wl,-undefined,dynamic_lookup )
xcrun -sdk appletvos clang "${OPAINJECT_CFLAGS[@]}" -o "$SEED/dt_opainject516" \
  "$OBJ/opainject/main.m" "$OBJ/opainject/dyld.m" "$OBJ/opainject/shellcode_inject.m" \
  "$OBJ/opainject/rop_inject.m" "$OBJ/opainject/thread_utils.m" "$OBJ/opainject/task_utils.m" \
  "$OBJ/opainject/arm64.m"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o "$SEED/dt_opainject516" "$SEED/dt_opainject516"
[[ -x "$LDID" ]] && "$LDID" -S"$KFD/handoff681/entitlements_opainject681.plist" "$SEED/dt_opainject516"
chmod +x "$SEED/dt_opainject516"
strings "$SEED/dt_opainject516" | grep -q post-consume

echo "=== seed libchoma.dylib ==="
cp -p "$KFD/basebin/out/libchoma.dylib" "$SEED/libchoma.dylib"
"$INSTALL_NAME_TOOL" -id "@loader_path/libchoma.dylib" "$SEED/libchoma.dylib" || true
[[ -x "$LDID" ]] && "$LDID" -S "$SEED/libchoma.dylib" || true

echo "R24_SEED_BOOTSTRAP=PASS dir=$SEED"
