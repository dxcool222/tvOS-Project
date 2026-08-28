#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
ROOT="$(cd "$PROJECT/.." && pwd -P)"
DOPAMINE="${DOPAMINE:-/tmp/dopamin-dopamine}"
LIBJB_SRC="$DOPAMINE/BaseBin/libjailbreak/src"
SERVER102737_SRC="$PROJECT/handoff516/source/libjailbreak/server102737"
INPUT="$PROJECT/build/102736C/Handoff516"
BUILD_ROOT="$PROJECT/build/102737D"
OUT="$BUILD_ROOT/Handoff516"
HOOK_OBJ="$BUILD_ROOT/obj/hook"
FW_OUT="$BUILD_ROOT/Frameworks"
FW_OBJ="$BUILD_ROOT/obj/app_libjailbreak"
MIN="$PROJECT/handoff516/source/launchdhook/minimal"
CLIENT_INC="$PROJECT/handoff516/source/libjailbreak/client"
SDK="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
CC="xcrun -sdk appletvos clang"
TVOS_MIN=14.0

expect_sha() {
    local path="$1" expected="$2"
    local got
    got="$(shasum -a 256 "$path" | awk '{print $1}')"
    if [[ "$got" != "$expected" ]]; then
        echo "SHA256 mismatch: $path" >&2
        echo "  expected $expected" >&2
        echo "  got      $got" >&2
        exit 1
    fi
}

compile_fw() {
    local src="$1" obj="$2"
    echo "  CC app-fw $(basename "$src")"
    $CC "${FW_CFLAGS[@]}" -c "$src" -o "$obj"
}

if [[ ! -d "$INPUT" ]]; then
    echo "ERROR: missing BUILD102736C Handoff516 input: $INPUT" >&2
    exit 1
fi
if [[ ! -d "$LIBJB_SRC" ]]; then
    echo "ERROR: missing Dopamine libjailbreak source: $LIBJB_SRC" >&2
    exit 1
fi
if [[ ! -d "$SERVER102737_SRC" ]]; then
    echo "ERROR: missing BUILD102737D server telemetry source: $SERVER102737_SRC" >&2
    exit 1
fi
if [[ ! -d "$SDK" ]]; then
    echo "ERROR: missing AppleTVOS SDK: $SDK" >&2
    exit 1
fi

expect_sha "$INPUT/launchdhook516.dylib" \
  "e975a8b9491543df47194139af290d3a641e2316748e61330008df45d2a3cf1f"
expect_sha "$INPUT/libjailbreak.dylib" \
  "9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79"
expect_sha "$INPUT/libchoma.dylib" \
  "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$INPUT/dt_opainject516" \
  "0b7dcd9c7258d33e347c94258b57817d0a04fc163af855d3b21499598f6b48fb"

rm -rf "$OUT" "$HOOK_OBJ" "$FW_OUT" "$FW_OBJ"
mkdir -p "$OUT" "$HOOK_OBJ" "$FW_OUT" "$FW_OBJ"
cp -R "$INPUT/." "$OUT/"
rm -f "$OUT/launchdhook516.dylib" "$OUT/libjailbreak.dylib" \
  "$OUT/BUILD102736C_RESOURCE_MANIFEST.txt"

echo "=== BUILD102737D Handoff libjailbreak client telemetry rebuild ==="
GATE1B_BUILD_ROOT="$BUILD_ROOT" \
GATE1B_EXTRA_CFLAGS="-DDT_BUILD102732C_TELEMETRY=1 -DDT_BUILD102735D_TRACE=1 -DDT_BUILD102737D_TELEMETRY=1" \
  bash "$PROJECT/scripts/build_gate1b_libjailbreak.sh"

INC=(
  -I"$CLIENT_INC"
  -I"$PROJECT/handoff516/source/include/libjailbreak"
  -I"$PROJECT/handoff516/source/include/external"
)

HOOK_CFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -O2
  -Wno-error
  -fPIC
  -fobjc-arc
  -DDT_BUILD102732C_TELEMETRY=1
  -DDT_BUILD102735D_TRACE=1
  -DDT_BUILD102737D_TELEMETRY=1
  "${INC[@]}"
)

echo "=== BUILD102737D trace-enabled launchdhook516 rebuild ==="
$CC "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_main_gate1b.m" -o "$HOOK_OBJ/main_gate1b.o"
$CC "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_boomerang.c" -o "$HOOK_OBJ/boomerang.o"

HOOK="$OUT/launchdhook516.dylib"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/launchdhook516.dylib" \
  -L"$OUT" -ljailbreak \
  "$HOOK_OBJ/main_gate1b.o" "$HOOK_OBJ/boomerang.o" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm -lobjc \
  -o "$HOOK"

echo "=== BUILD102737D app-framework libjailbreak server telemetry rebuild ==="
FW_CFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -O2
  -Wno-error
  -Wno-ambiguous-macro
  -Wno-unused-variable
  -Wno-unused-but-set-variable
  -Wno-availability
  -Wno-deprecated-declarations
  -D_DARWIN_UNLIMITED_SYSCALLS
  -DDT_BUILD102737D_TELEMETRY=1
  -fPIC
  -fobjc-arc
  -I"$LIBJB_SRC"
  -I"$LIBJB_SRC/atomic_headers"
  -I"$PROJECT/basebin/out/include"
  -I"$PROJECT/basebin/out/include/choma"
  -I"$PROJECT/stubs"
  -I"$DOPAMINE/BaseBin/_external/include"
  -I"$DOPAMINE/BaseBin/ChOma/src"
)

FW_OBJS=()
for f in info.c primitives.c translation.c kernel.c jbserver.c jbserver_boomerang.c physrw_pte.c trustcache.c; do
    o="$FW_OBJ/$f.o"
    case "$f" in
      jbserver.c|jbserver_boomerang.c|physrw_pte.c)
        compile_fw "$SERVER102737_SRC/$f" "$o"
        ;;
      *)
        compile_fw "$LIBJB_SRC/$f" "$o"
        ;;
    esac
    FW_OBJS+=("$o")
done
compile_fw "$SERVER102737_SRC/kalloc_pt.m" "$FW_OBJ/kalloc_pt.o"
FW_OBJS+=("$FW_OBJ/kalloc_pt.o")
for f in dt_mach_thread_shim.c dt_kcall_arm64_tvos.c dt_kcall_fugu14_minimal.c \
  dt_pmap_util.c dt_pte_kwrite_stub.c; do
    o="$FW_OBJ/$f.o"
    compile_fw "$PROJECT/stubs/$f" "$o"
    FW_OBJS+=("$o")
done
compile_fw "$LIBJB_SRC/kcall_Fugu14.S" "$FW_OBJ/kcall_Fugu14.o"
FW_OBJS+=("$FW_OBJ/kcall_Fugu14.o")

$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@executable_path/Frameworks/libjailbreak.dylib" \
  "${FW_OBJS[@]}" \
  -o "$FW_OUT/libjailbreak.dylib" \
  -lcompression -lbsm -L"$PROJECT/basebin/out" -lchoma \
  -Wl,-u,_libjailbreak_physrw_pte_init \
  -Wl,-u,_device_supports_physrw_pte \
  -Wl,-export_dynamic \
  -framework Foundation -framework CoreServices -framework Security

chmod +x "$OUT/"* "$FW_OUT/libjailbreak.dylib"

bash "$PROJECT/scripts/write_hook_build_manifest.sh" \
  "$OUT/launchdhook516.dylib" \
  "$OUT/hook_build_manifest.txt"

{
    echo "CFBundleVersion=102737"
    echo "launchdhook516.dylib=$(shasum -a 256 "$OUT/launchdhook516.dylib" | awk '{print $1}')"
    echo "libjailbreak.dylib=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
    echo "libchoma.dylib=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
    echo "dt_jbctl516=$(shasum -a 256 "$OUT/dt_jbctl516" | awk '{print $1}')"
    echo "dt_opainject516=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
    echo "app_framework_libjailbreak.dylib=$(shasum -a 256 "$FW_OUT/libjailbreak.dylib" | awk '{print $1}')"
} > "$OUT/BUILD102737D_RESOURCE_MANIFEST.txt"

strings "$OUT/launchdhook516.dylib" | grep -q ".dt102737_constructor_trace"
strings "$OUT/libjailbreak.dylib" | grep -q "PTE_HANDOFF_REQUEST_BEGIN"
strings "$FW_OUT/libjailbreak.dylib" | grep -q "BUILD102737D_SERVER_GET_PHYSRW_REQUEST_RECEIVED"
strings "$FW_OUT/libjailbreak.dylib" | grep -q "BUILD102737D_PTE_STAGE_%s_BEGIN=YES"

echo "BUILD102737D_HANDOFF_REBUILD=PASS"
echo "BUILD102737D_APP_FRAMEWORK_LIBJAILBREAK_REBUILD=PASS"
echo "BUILD102737D_HOOK_SHA256=$(shasum -a 256 "$OUT/launchdhook516.dylib" | awk '{print $1}')"
echo "BUILD102737D_HANDOFF_LIBJAILBREAK_SHA256=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
echo "BUILD102737D_APP_FRAMEWORK_LIBJAILBREAK_SHA256=$(shasum -a 256 "$FW_OUT/libjailbreak.dylib" | awk '{print $1}')"
echo "BUILD102737D_OPAINJECT_HELPER_REUSED_SHA256=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
