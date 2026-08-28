#!/bin/bash
# Gate 1 isolated libjailbreak (Handoff/preboot role) — does NOT write basebin/out/.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
bash "$KFD/scripts/setup_build_symlinks.sh" 2>/dev/null || true

ROOT="/tmp/dopamin-root"
KFD_ROOT="/tmp/dopamin-kfd"
DOPAMINE="/tmp/dopamin-dopamine"
CHoma="$DOPAMINE/BaseBin/ChOma"
LIBJB="$DOPAMINE/BaseBin/libjailbreak"
GATE1_SRC="$KFD/handoff516/source/libjailbreak"
OUT="$KFD/build/gate1"
OBJ="$OUT/obj/libjb"
CHOMA_OUT="$OUT/Handoff516/libchoma.dylib"
LIBJB_OUT="$OUT/Handoff516/libjailbreak.dylib"

SDK="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
CC="xcrun -sdk appletvos clang"
TVOS_MIN=14.0

INC=(
  -I"$OUT/include"
  -I"$OUT/include/choma"
  -I"$KFD/stubs"
  -I"$DOPAMINE/BaseBin/_external/include"
  -I"$CHoma/src"
  -I"$LIBJB/src"
  -I"$KFD/handoff516/source/include/libjailbreak"
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
  "${INC[@]}"
)

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

mkdir -p "$OBJ" "$OUT/Handoff516" "$OUT/include/choma"
if [[ ! -d "$OUT/include/choma" ]] || [[ -z "$(ls -A "$OUT/include/choma" 2>/dev/null)" ]]; then
  cp "$CHoma/src/"*.h "$OUT/include/choma/" 2>/dev/null || true
fi

compile() {
  local src="$1" obj="$2"
  echo "  CC $(basename "$src")"
  $CC "${CFLAGS[@]}" -c "$src" -o "$obj"
}

# libchoma: copy from frozen basebin/out and retarget install name on COPY only
if [[ ! -f "$KFD/basebin/out/libchoma.dylib" ]]; then
  echo "ERROR: basebin/out/libchoma.dylib missing (read-only copy source)"
  exit 1
fi
cp "$KFD/basebin/out/libchoma.dylib" "$CHOMA_OUT"
INSTALL_NAME_TOOL="${INSTALL_NAME_TOOL:-/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool}"
"$INSTALL_NAME_TOOL" -id "@loader_path/libchoma.dylib" "$CHOMA_OUT"

BASE_OBJS=()
for pair in \
  "info.c" \
  "primitives.c" \
  "translation.c" \
  "kernel.c" \
  "jbserver.c" \
  "jbserver_boomerang.c" \
  "physrw_pte.c" \
  "trustcache.c" \
  "kalloc_pt.m" \
  "dt_mach_thread_shim.c" \
  "dt_kcall_arm64_tvos.c" \
  "dt_kcall_fugu14_minimal.c" \
  "kcall_Fugu14.S" \
  "dt_pmap_util.c" \
  "dt_pte_kwrite_stub.c"; do
  base="$pair"
  objname=$(basename "$pair" | sed 's/\.[cmS]$/.o/')
  src=""
  case "$pair" in
    dt_*) src="$KFD/stubs/$pair" ;;
    kcall_Fugu14.S) src="$LIBJB/src/kcall_Fugu14.S" ;;
    kalloc_pt.m) src="$LIBJB/src/kalloc_pt.m" ;;
    *) src="$LIBJB/src/$pair" ;;
  esac
  compile "$src" "$OBJ/$objname"
  BASE_OBJS+=("$OBJ/$objname")
done

GATE1_OBJS=()
for pair in \
  "$GATE1_SRC/jbclient_xpc.c" \
  "$GATE1_SRC/dt_jbclient_mach_tvos_stub.c" \
  "$GATE1_SRC/jbroot.c" \
  "$GATE1_SRC/signatures.c" \
  "$GATE1_SRC/dt_jbclient_primitives_tvos.c" \
  "$GATE1_SRC/dt_gate1_util_exports.c" \
  "$GATE1_SRC/dt_gate1_string_util.c" \
  "$GATE1_SRC/dt_physrw_init_tvos_stub.c"; do
  obj="$OBJ/$(basename "$pair" .c).o"
  compile "$pair" "$obj"
  GATE1_OBJS+=("$obj")
done

echo "  LD libjailbreak.dylib (Gate1 Handoff)"
$CC "${LDFLAGS[@]}" "${BASE_OBJS[@]}" "${GATE1_OBJS[@]}" -o "$LIBJB_OUT"

echo "GATE1_LIBJAILBREAK_BUILT=$LIBJB_OUT"
