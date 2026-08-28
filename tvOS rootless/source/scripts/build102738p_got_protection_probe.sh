#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
INPUT="$PROJECT/build/102737D/Handoff516"
INPUT_FW="$PROJECT/build/102737D/Frameworks/libjailbreak.dylib"
BUILD_ROOT="$PROJECT/build/102738P"
OUT="$BUILD_ROOT/Handoff516"
FW_OUT="$BUILD_ROOT/Frameworks"
OBJ="$BUILD_ROOT/obj/hook"
MIN="$PROJECT/handoff516/source/launchdhook/minimal"
SDK="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
CC=(xcrun -sdk appletvos clang)
TVOS_MIN=14.0

expect_sha() {
    local path="$1" expected="$2" got
    got="$(shasum -a 256 "$path" | awk '{print $1}')"
    if [[ "$got" != "$expected" ]]; then
        echo "SHA256 mismatch: $path" >&2
        echo "  expected $expected" >&2
        echo "  got      $got" >&2
        exit 1
    fi
}

[[ -d "$INPUT" ]] || { echo "ERROR: missing frozen BUILD102737D handoff: $INPUT" >&2; exit 1; }
[[ -f "$INPUT_FW" ]] || { echo "ERROR: missing frozen BUILD102737D framework libjailbreak: $INPUT_FW" >&2; exit 1; }
[[ -d "$SDK" ]] || { echo "ERROR: missing AppleTVOS SDK: $SDK" >&2; exit 1; }

# Freeze every proven resource before doing any work. Only launchdhook516 is rebuilt.
expect_sha "$INPUT/dt_jbctl516" "6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067"
expect_sha "$INPUT/dt_opainject516" "0b7dcd9c7258d33e347c94258b57817d0a04fc163af855d3b21499598f6b48fb"
expect_sha "$INPUT/entitlements_launchdhook681.plist" "4d63822e924c55eae1c862dbebfe8a8c2270a915f72efd6b9276a434892e014b"
expect_sha "$INPUT/libchoma.dylib" "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$INPUT/libjailbreak.dylib" "0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754"
expect_sha "$INPUT_FW" "b4f4ba62330f1637c26421c9b55c395392b156018148d321b0c3fc995e2672f0"

rm -rf "$OUT" "$FW_OUT" "$OBJ"
mkdir -p "$OUT" "$FW_OUT" "$OBJ"
cp -R "$INPUT/." "$OUT/"
cp "$INPUT_FW" "$FW_OUT/libjailbreak.dylib"
rm -f "$OUT/launchdhook516.dylib" "$OUT/hook_build_manifest.txt" \
  "$OUT/BUILD102737D_RESOURCE_MANIFEST.txt"

INC=(
  -I"$PROJECT/handoff516/source/libjailbreak/client"
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
  -DDT_BUILD102738P_TELEMETRY=1
  "${INC[@]}"
)

echo "=== BUILD102738P launchd GOT protection-only hook rebuild ==="
"${CC[@]}" "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_main_gate1b.m" -o "$OBJ/main_gate1b.o"
"${CC[@]}" "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_boomerang.c" -o "$OBJ/boomerang.o"
"${CC[@]}" "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_got_probe_102738p.c" -o "$OBJ/got_probe.o"

HOOK="$OUT/launchdhook516.dylib"
"${CC[@]}" -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/launchdhook516.dylib" \
  -L"$OUT" -ljailbreak \
  "$OBJ/main_gate1b.o" "$OBJ/boomerang.o" "$OBJ/got_probe.o" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm -lobjc \
  -o "$HOOK"

chmod +x "$OUT/"* "$FW_OUT/libjailbreak.dylib"

bash "$PROJECT/scripts/write_hook_build_manifest.sh" \
  "$HOOK" "$OUT/hook_build_manifest.txt"

{
    echo "CFBundleVersion=102738"
    echo "SCOPE=LAUNCHD_GOT_PROTECTION_ONLY"
    echo "REPAIR_VARIANT=102738R_RECURSIVE_POINTER_VALIDATOR"
    echo "TRACE_TRANSPORT_FILENAME=.dt102737_constructor_trace"
    echo "launchdhook516.dylib=$(shasum -a 256 "$HOOK" | awk '{print $1}')"
    echo "libjailbreak.dylib=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
    echo "libchoma.dylib=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
    echo "dt_jbctl516=$(shasum -a 256 "$OUT/dt_jbctl516" | awk '{print $1}')"
    echo "dt_opainject516=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
    echo "app_framework_libjailbreak.dylib=$(shasum -a 256 "$FW_OUT/libjailbreak.dylib" | awk '{print $1}')"
} > "$OUT/BUILD102738P_RESOURCE_MANIFEST.txt"

# Re-check frozen outputs after copying and prove the new hook contains only the probe contract.
expect_sha "$OUT/dt_jbctl516" "6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067"
expect_sha "$OUT/dt_opainject516" "0b7dcd9c7258d33e347c94258b57817d0a04fc163af855d3b21499598f6b48fb"
expect_sha "$OUT/entitlements_launchdhook681.plist" "4d63822e924c55eae1c862dbebfe8a8c2270a915f72efd6b9276a434892e014b"
expect_sha "$OUT/libchoma.dylib" "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$OUT/libjailbreak.dylib" "0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754"
expect_sha "$FW_OUT/libjailbreak.dylib" "b4f4ba62330f1637c26421c9b55c395392b156018148d321b0c3fc995e2672f0"

HOOK_STRINGS="$OBJ/hook_strings.txt"
strings "$HOOK" > "$HOOK_STRINGS"
rg -q '\.dt102737_constructor_trace' "$HOOK_STRINGS"
rg -q 'BUILD102738P_PROBE_ENTER' "$HOOK_STRINGS"
rg -q 'BUILD102738R_POINTER_VALIDATOR_REPAIR' "$HOOK_STRINGS"
rg -q 'GOT_POINTER_BASIC_QUERY_DIAGNOSTIC_ONLY' "$HOOK_STRINGS"
rg -q 'GOT_POINTER_RECURSE_QUERY_RC' "$HOOK_STRINGS"
rg -q 'GOT_POINTER_RECURSE_CONTAINS_POINTER' "$HOOK_STRINGS"
rg -q 'GOT_POINTER_RECURSE_MAPPING_PASS' "$HOOK_STRINGS"
rg -q 'GOT_PROTECTION_TEST_PASS' "$HOOK_STRINGS"
rg -q 'GOT_PROTECTION_RESTORE_FATAL' "$HOOK_STRINGS"
rg -q 'GOT_POINTER_UNCHANGED_PASS' "$HOOK_STRINGS"
if rg -q 'MSHookFunction|initXPCHooks|GOT_POINTER_REPLACED' "$HOOK_STRINGS"; then
    echo "ERROR: hook backend or pointer-replacement marker leaked into protection-only build" >&2
    exit 1
fi
nm -u "$HOOK" 2>/dev/null | rg -q '_vm_region_recurse_64'

echo "BUILD102738P_HOOK_ONLY_REBUILD=PASS"
echo "BUILD102738R_POINTER_VALIDATOR_REPAIR=PASS"
echo "BUILD102738P_FROZEN_RESOURCES=PASS"
echo "BUILD102738P_HOOK_SHA256=$(shasum -a 256 "$HOOK" | awk '{print $1}')"
echo "BUILD102738P_HANDOFF_LIBJAILBREAK_SHA256=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
echo "BUILD102738P_APP_FRAMEWORK_LIBJAILBREAK_SHA256=$(shasum -a 256 "$FW_OUT/libjailbreak.dylib" | awk '{print $1}')"
