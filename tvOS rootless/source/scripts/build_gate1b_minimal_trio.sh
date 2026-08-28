#!/bin/bash
# Gate 1B — minimal hook + libjailbreak + libchoma (host-only, isolated output).
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
MIN="$KFD/handoff516/source/launchdhook/minimal"
CLIENT_INC="$KFD/handoff516/source/libjailbreak/client"
BUILD_ROOT="${GATE1B_BUILD_ROOT:-$KFD/build/gate1b}"
export GATE1B_BUILD_ROOT="$BUILD_ROOT"
OUT="$BUILD_ROOT/Handoff516"
OBJ="$BUILD_ROOT/obj/hook"

SDK="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
CC="xcrun -sdk appletvos clang"
TVOS_MIN=14.0

mkdir -p "$OBJ" "$OUT"

echo "=== Gate1B Step 1: libchoma (source-built) ==="
bash "$KFD/scripts/build_gate1b_libchoma.sh"

echo "=== Gate1B Step 2: libjailbreak (minimal client) ==="
bash "$KFD/scripts/build_gate1b_libjailbreak.sh"

INC=(
  -I"$CLIENT_INC"
  -I"$KFD/handoff516/source/include/libjailbreak"
  -I"$KFD/handoff516/source/include/external"
)

CFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -O2
  -Wno-error
  -fPIC
  -fobjc-arc
  "${INC[@]}"
)
if [[ -n "${GATE1B_EXTRA_CFLAGS:-}" ]]; then
  read -r -a EXTRA_CFLAGS <<< "$GATE1B_EXTRA_CFLAGS"
  CFLAGS+=("${EXTRA_CFLAGS[@]}")
fi

echo "=== Gate1B Step 3: launchdhook516 minimal ==="
$CC "${CFLAGS[@]}" -c "$MIN/dt_launchdhook516_main_gate1b.m" -o "$OBJ/main_gate1b.o"
$CC "${CFLAGS[@]}" -c "$MIN/dt_launchdhook516_boomerang.c" -o "$OBJ/boomerang.o"

HOOK="$OUT/launchdhook516.dylib"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/launchdhook516.dylib" \
  -L"$OUT" -ljailbreak \
  "$OBJ/main_gate1b.o" "$OBJ/boomerang.o" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm -lobjc \
  -o "$HOOK"

echo "=== Gate1B trio built in $OUT ==="
ls -la "$OUT"/*.dylib
echo "SEED_BINARY_USAGE=NO"
echo "ALL_THREE_COMPILED_DURING_GATE1B=YES"
