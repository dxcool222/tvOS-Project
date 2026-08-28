#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
ROOT="$(cd "$PROJECT/.." && pwd -P)"
DOPAMINE="${DOPAMINE:-$ROOT/Dopamine_Rootful-main}"
OPAINJECT_SRC="$DOPAMINE/BaseBin/opainject"
INPUT="$PROJECT/build/102735D/Handoff516"
BUILD="${DT681_BUILD:-$PROJECT/.theos/obj/handoff681}"
BUILD_ROOT="$PROJECT/build/102736C"
OUT="$BUILD_ROOT/Handoff516"
SDK=appletvos
TVOS_MIN=14.0
SYSROOT="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
LDID="${LDID:-/opt/local/bin/ldid}"
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"

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

verify_tvos_platform() {
    local bin="$1"
    if ! "$VTOOL" -show-build "$bin" 2>/dev/null | grep -q "platform TVOS"; then
        echo "ERROR: $(basename "$bin") is not platform TVOS"
        "$VTOOL" -show-build "$bin" 2>/dev/null || true
        exit 1
    fi
}

if [[ ! -d "$SYSROOT" ]]; then
    echo "ERROR: missing AppleTVOS16.4 SDK at $SYSROOT"
    exit 1
fi
if [[ ! -d "$OPAINJECT_SRC" ]]; then
    echo "ERROR: missing Dopamine opainject sources at $OPAINJECT_SRC"
    exit 1
fi
if [[ ! -d "$INPUT" ]]; then
    echo "ERROR: missing BUILD102735D Handoff516 input: $INPUT"
    exit 1
fi
if [[ ! -x "$LDID" ]]; then
    echo "ERROR: ldid missing at $LDID"
    exit 1
fi

expect_sha "$INPUT/launchdhook516.dylib" \
  "e975a8b9491543df47194139af290d3a641e2316748e61330008df45d2a3cf1f"
expect_sha "$INPUT/libjailbreak.dylib" \
  "9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79"
expect_sha "$INPUT/libchoma.dylib" \
  "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$INPUT/dt_jbctl516" \
  "6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067"
expect_sha "$INPUT/dt_opainject516" \
  "195b3368adf770fa618a459dffe6ba8a64a4b1523c842a9832d43bc77af0d57d"

rm -rf "$OUT"
mkdir -p "$OUT" "$BUILD/opainject"
cp -R "$INPUT/." "$OUT/"
rm -f "$OUT/dt_opainject516" "$OUT/BUILD102735D_RESOURCE_MANIFEST.txt"

CFLAGS=(
    -arch arm64
    -isysroot "$SYSROOT"
    -mtvos-version-min="$TVOS_MIN"
    -O2
    -Wno-deprecated-declarations
    -Wno-error
    -D_DARWIN_UNLIMITED_SYSCALLS
    -DDT_BUILD102736C_TASKPORT_REPAIR=1
)

cp "$OPAINJECT_SRC"/dyld.m "$OPAINJECT_SRC"/shellcode_inject.m "$OPAINJECT_SRC"/thread_utils.m \
    "$OPAINJECT_SRC"/task_utils.m "$OPAINJECT_SRC"/arm64.m "$OPAINJECT_SRC"/*.h "$BUILD/opainject/" 2>/dev/null || true
cp "$PROJECT/handoff681/dt_opainject681_rop_inject.h" "$BUILD/opainject/rop_inject.h"
cp "$PROJECT/handoff681/dt_opainject681_main.m" "$BUILD/opainject/main.m"
cp "$PROJECT/handoff681/dt_opainject681_rop_inject.m" "$BUILD/opainject/rop_inject.m"
cp "$PROJECT/handoff681/dt_opainject_tvos_prefix.h" "$BUILD/opainject/"

OPAINJECT_CFLAGS=(
    "${CFLAGS[@]}"
    -include "$BUILD/opainject/dt_opainject_tvos_prefix.h"
    -I"$BUILD/opainject"
    -I"$DOPAMINE/BaseBin/_external/include"
    -framework CoreFoundation
    -framework Foundation
    -ldl
    -Wl,-undefined,dynamic_lookup
)

OPAINJECT_SRCS=(
    "$BUILD/opainject/main.m"
    "$BUILD/opainject/dyld.m"
    "$BUILD/opainject/shellcode_inject.m"
    "$BUILD/opainject/rop_inject.m"
    "$BUILD/opainject/thread_utils.m"
    "$BUILD/opainject/task_utils.m"
    "$BUILD/opainject/arm64.m"
)

echo "=== BUILD102736C dt_opainject516 helper-only rebuild ==="
xcrun -sdk "$SDK" clang "${OPAINJECT_CFLAGS[@]}" -o "$OUT/dt_opainject516" \
    "${OPAINJECT_SRCS[@]}"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o \
    "$OUT/dt_opainject516" "$OUT/dt_opainject516"

"$LDID" -S"$PROJECT/handoff681/entitlements_opainject681.plist" "$OUT/dt_opainject516"
chmod +x "$OUT/dt_opainject516"
chmod +x "$OUT/"*
verify_tvos_platform "$OUT/dt_opainject516"

expect_sha "$OUT/launchdhook516.dylib" \
  "e975a8b9491543df47194139af290d3a641e2316748e61330008df45d2a3cf1f"
expect_sha "$OUT/libjailbreak.dylib" \
  "9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79"
expect_sha "$OUT/libchoma.dylib" \
  "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"

strings "$OUT/dt_opainject516" > "$BUILD/opainject/dt_opainject516.102736C.strings"
grep -q "BUILD102736C_TASK_FOR_PID_SYMBOL_ADDRESS" "$BUILD/opainject/dt_opainject516.102736C.strings"
grep -q "BUILD102736C_TASK_FOR_PID_OUTPUT_BEFORE" "$BUILD/opainject/dt_opainject516.102736C.strings"
grep -q "BUILD102736C_MACH_PORT_TYPE_RC" "$BUILD/opainject/dt_opainject516.102736C.strings"
grep -q "BUILD102736C_TASK_INFO_RC" "$BUILD/opainject/dt_opainject516.102736C.strings"
grep -q "BUILD102736C_TARGET_PID_PATH" "$BUILD/opainject/dt_opainject516.102736C.strings"
grep -q "BUILD102736C_REMOTE_DLOPEN_RC" "$BUILD/opainject/dt_opainject516.102736C.strings"
"$LDID" -e "$OUT/dt_opainject516" > "$BUILD/opainject/dt_opainject516.102736C.entitlements"
grep -q "task_for_pid-allow" "$BUILD/opainject/dt_opainject516.102736C.entitlements"
grep -q "platform-application" "$BUILD/opainject/dt_opainject516.102736C.entitlements"
grep -q "com.apple.system-task-ports" "$BUILD/opainject/dt_opainject516.102736C.entitlements"

{
    echo "CFBundleVersion=102736"
    echo "launchdhook516.dylib=$(shasum -a 256 "$OUT/launchdhook516.dylib" | awk '{print $1}')"
    echo "libjailbreak.dylib=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
    echo "libchoma.dylib=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
    echo "dt_jbctl516=$(shasum -a 256 "$OUT/dt_jbctl516" | awk '{print $1}')"
    echo "dt_opainject516=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
} > "$OUT/BUILD102736C_RESOURCE_MANIFEST.txt"

echo "BUILD102736C_OPAINJECT_HELPER_SHA256=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
echo "BUILD102736C_HOOK_REUSED_SHA256=$(shasum -a 256 "$OUT/launchdhook516.dylib" | awk '{print $1}')"
echo "BUILD102736C_LIBJAILBREAK_REUSED_SHA256=$(shasum -a 256 "$OUT/libjailbreak.dylib" | awk '{print $1}')"
echo "BUILD102736C_LIBCHOMA_REUSED_SHA256=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
echo "BUILD102736C_OPAINJECT_HELPER_ONLY_REBUILD=PASS"
