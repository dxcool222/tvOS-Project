#!/bin/bash
# Gate 1B — minimal libjailbreak client dylib (current-tree sources only).
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
CORE="$KFD/handoff516/source/libjailbreak/core"
CLIENT="$KFD/handoff516/source/libjailbreak/client"
STUBS="$CORE/stubs"
INC="$KFD/handoff516/source/include/libjailbreak"
EXT="$KFD/handoff516/source/include/external"
OUT="${GATE1B_BUILD_ROOT:-$KFD/build/gate1b}"
OBJ="$OUT/obj/libjb"
LIB="$OUT/Handoff516/libjailbreak.dylib"

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
  -Wno-availability
  -Wno-nonportable-include-path
  -D_DARWIN_UNLIMITED_SYSCALLS
  -fPIC
  -fobjc-arc
  -I"$INC"
  -I"$EXT"
  -I"$EXT/bsm"
  -I"$EXT/os"
  -I"$CORE"
  -I"$CLIENT"
  -I"$STUBS"
  -I"$KFD/handoff516/source/include"
  -I"$KFD/handoff516/source/libchoma"
)
if [[ -n "${GATE1B_EXTRA_CFLAGS:-}" ]]; then
  read -r -a EXTRA_CFLAGS <<< "$GATE1B_EXTRA_CFLAGS"
  CFLAGS+=("${EXTRA_CFLAGS[@]}")
fi

LDFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -dynamiclib
  -install_name "@loader_path/libjailbreak.dylib"
  -lcompression
  -lbsm
  -L"$OUT/Handoff516"
  -lchoma
  -framework Foundation
  -framework CoreServices
  -framework Security
  -Wl,-u,_libjailbreak_physrw_pte_init
  -Wl,-u,_device_supports_physrw_pte
)

mkdir -p "$OBJ" "$OUT/Handoff516"

compile() {
  local src="$1" obj="$2"
  echo "  CC $(basename "$src")"
  if [[ "$src" == *.m ]]; then
    $CC "${CFLAGS[@]}" -c "$src" -o "$obj"
  elif [[ "$src" == *.S ]]; then
    $CC "${CFLAGS[@]}" -c "$src" -o "$obj"
  else
    $CC "${CFLAGS[@]}" -c "$src" -o "$obj"
  fi
}

OBJS=()
for f in info.c primitives.c translation.c kernel.c physrw_pte.c; do
  o="$OBJ/$f.o"; compile "$CORE/$f" "$o"; OBJS+=("$o")
done
compile "$CORE/kalloc_pt.m" "$OBJ/kalloc_pt.o"; OBJS+=("$OBJ/kalloc_pt.o")
for f in dt_mach_thread_shim.c dt_kcall_arm64_tvos.c dt_kcall_fugu14_minimal.c \
  dt_pmap_util.c dt_pte_kwrite_stub.c; do
  o="$OBJ/$f.o"; compile "$STUBS/$f" "$o"; OBJS+=("$o")
done
compile "$STUBS/kcall_Fugu14.S" "$OBJ/kcall_Fugu14.o"; OBJS+=("$OBJ/kcall_Fugu14.o")
for f in dt_jbclient_xpc_gate1b.c dt_jbclient_primitives_gate1b.c; do
  o="$OBJ/$f.o"; compile "$CLIENT/$f" "$o"; OBJS+=("$o")
done

echo "  LD libjailbreak.dylib (Gate1B minimal client)"
$CC "${LDFLAGS[@]}" "${OBJS[@]}" -o "$LIB"
echo "GATE1B_LIBJAILBREAK_BUILT=$LIB"
