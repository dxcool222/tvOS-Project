#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
INPUT="$PROJECT/build/102734C/Payload/dopamin-tvOS-kfd.app/Handoff516"
BUILD_ROOT="$PROJECT/build/102735D"
OUT="$BUILD_ROOT/Handoff516"
OBJ="$BUILD_ROOT/obj/hook"
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

if [[ ! -d "$INPUT" ]]; then
    echo "ERROR: missing frozen 102734C Handoff516 input: $INPUT" >&2
    exit 1
fi

expect_sha "$INPUT/libjailbreak.dylib" \
  "9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79"
expect_sha "$INPUT/libchoma.dylib" \
  "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$INPUT/dt_opainject516" \
  "195b3368adf770fa618a459dffe6ba8a64a4b1523c842a9832d43bc77af0d57d"

rm -rf "$OUT" "$OBJ"
mkdir -p "$OUT" "$OBJ"
cp -R "$INPUT/." "$OUT/"
rm -f "$OUT/launchdhook516.dylib" "$OUT/BUILD102734C_RESOURCE_MANIFEST.txt"

INC=(
  -I"$CLIENT_INC"
  -I"$PROJECT/handoff516/source/include/libjailbreak"
  -I"$PROJECT/handoff516/source/include/external"
)

CFLAGS=(
  -arch arm64
  -isysroot "$SDK"
  -mtvos-version-min="$TVOS_MIN"
  -O2
  -Wno-error
  -fPIC
  -fobjc-arc
  -DDT_BUILD102732C_TELEMETRY=1
  -DDT_BUILD102735D_TRACE=1
  "${INC[@]}"
)

echo "=== BUILD102735D trace-enabled launchdhook516 only ==="
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

chmod +x "$OUT/"*

bash "$PROJECT/scripts/write_hook_build_manifest.sh" \
  "$OUT/launchdhook516.dylib" \
  "$OUT/hook_build_manifest.txt"

{
    echo "CFBundleVersion=102735"
    echo "launchdhook516.dylib=$(shasum -a 256 "$OUT/launchdhook516.dylib" | awk '{print $1}')"
    echo "libjailbreak.dylib=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
    echo "libchoma.dylib=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
    echo "dt_opainject516=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
} > "$OUT/BUILD102735D_RESOURCE_MANIFEST.txt"

echo "BUILD102735D_HOOK_ONLY_REBUILD=PASS"
echo "BUILD102735D_LAUNCHDHOOK_PRE_SIGN_SHA256=$(shasum -a 256 "$OUT/launchdhook516.dylib" | awk '{print $1}')"
echo "BUILD102735D_LIBJAILBREAK_REUSED_SHA256=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
echo "BUILD102735D_LIBCHOMA_REUSED_SHA256=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
echo "BUILD102735D_OPAINJECT_REUSED_SHA256=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
