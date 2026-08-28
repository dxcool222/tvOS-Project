#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
ROOT="$(cd "$PROJECT/.." && pwd -P)"
DOPAMINE="${DOPAMINE:-$ROOT/Dopamine_Rootful-main}"
OPAINJECT_SRC="$DOPAMINE/BaseBin/opainject"
BUILD="${DT681_BUILD:-$PROJECT/.theos/obj/handoff681}"
OUT="$BUILD/Handoff516"
SDK=appletvos
TVOS_MIN=14.0
SYSROOT="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
LDID="${LDID:-/opt/local/bin/ldid}"
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"

if [[ ! -d "$SYSROOT" ]]; then
    echo "ERROR: missing AppleTVOS16.4 SDK at $SYSROOT"
    exit 1
fi
if [[ ! -d "$OPAINJECT_SRC" ]]; then
    echo "ERROR: missing Dopamine opainject sources at $OPAINJECT_SRC"
    exit 1
fi

verify_tvos_platform() {
    local bin="$1"
    if ! "$VTOOL" -show-build "$bin" 2>/dev/null | grep -q "platform TVOS"; then
        echo "ERROR: $(basename "$bin") is not platform TVOS"
        "$VTOOL" -show-build "$bin" 2>/dev/null || true
        exit 1
    fi
}

mkdir -p "$OUT" "$BUILD/opainject"
rm -f "$OUT/dt_opainject516"

CFLAGS=(
    -arch arm64
    -isysroot "$SYSROOT"
    -mtvos-version-min="$TVOS_MIN"
    -O2
    -Wno-deprecated-declarations
    -Wno-error
    -D_DARWIN_UNLIMITED_SYSCALLS
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

echo "=== BUILD102734C dt_opainject516 helper-only rebuild ==="
xcrun -sdk "$SDK" clang "${OPAINJECT_CFLAGS[@]}" -o "$OUT/dt_opainject516" \
    "${OPAINJECT_SRCS[@]}"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o \
    "$OUT/dt_opainject516" "$OUT/dt_opainject516"

if [[ ! -x "$LDID" ]]; then
    echo "ERROR: ldid missing at $LDID"
    exit 1
fi
"$LDID" -S"$PROJECT/handoff681/entitlements_opainject681.plist" "$OUT/dt_opainject516"
chmod +x "$OUT/dt_opainject516"
verify_tvos_platform "$OUT/dt_opainject516"

strings "$OUT/dt_opainject516" > "$BUILD/opainject/dt_opainject516.strings"
grep -q "BUILD102734C_OPAINJECT_FAILURE_BRANCH" "$BUILD/opainject/dt_opainject516.strings"
grep -q "BUILD102734C_TASK_PORT_VALID" "$BUILD/opainject/dt_opainject516.strings"
"$LDID" -e "$OUT/dt_opainject516" > "$BUILD/opainject/dt_opainject516.entitlements"
grep -q "task_for_pid-allow" "$BUILD/opainject/dt_opainject516.entitlements"
grep -q "platform-application" "$BUILD/opainject/dt_opainject516.entitlements"

echo "BUILD102734C_OPAINJECT_HELPER_SHA256=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
echo "BUILD102734C_OPAINJECT_HELPER_ONLY_REBUILD=PASS"
