#!/bin/bash
# Gate 1B — source-build libchoma from current-tree pinned sources only.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
SRC="$KFD/handoff516/source/libchoma"
OUT="${GATE1B_BUILD_ROOT:-$KFD/build/gate1b}"
OBJ="$OUT/obj/choma"
LIB="$OUT/Handoff516/libchoma.dylib"

SDK="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
CC="xcrun -sdk appletvos clang"
TVOS_MIN=14.0

CFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -O2
  -Wno-error
  -Wno-deprecated-declarations
  -DDISABLE_SIGNING=1
  -fPIC
  -I"$SRC"
)
if [[ -n "${GATE1B_EXTRA_CFLAGS:-}" ]]; then
  read -r -a EXTRA_CFLAGS <<< "$GATE1B_EXTRA_CFLAGS"
  CFLAGS+=("${EXTRA_CFLAGS[@]}")
fi

mkdir -p "$OBJ" "$OUT/Handoff516"

OBJS=()
for c in "$SRC"/*.c; do
  base=$(basename "$c" .c)
  obj="$OBJ/$base.o"
  echo "  CC choma/$base.c"
  $CC "${CFLAGS[@]}" -c "$c" -o "$obj"
  OBJS+=("$obj")
done

echo "  LD libchoma.dylib (Gate1B source-built)"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/libchoma.dylib" \
  "${OBJS[@]}" \
  -framework CoreFoundation \
  -o "$LIB"

echo "GATE1B_LIBCHOMA_BUILT=$LIB"
