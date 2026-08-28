#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
BUILD="${DT672_BUILD:-$PROJECT/.theos/obj/handoff672}"
SDK=appletvos
TVOS_MIN=14.0
SYSROOT="${TVOS_SYSROOT:-/Users/dxcool223/theos/sdks/AppleTVOS16.4.sdk}"
LDID="${LDID:-/opt/local/bin/ldid}"
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"

if [[ ! -d "$SYSROOT" ]]; then
    echo "ERROR: missing AppleTVOS16.4 SDK at $SYSROOT"
    exit 1
fi

verify_tvos_platform() {
    local bin="$1"
    local name
    name="$(basename "$bin")"
    if ! "$VTOOL" -show-build "$bin" 2>/dev/null | grep -q "platform TVOS"; then
        echo "ERROR: $name is not platform TVOS:"
        "$VTOOL" -show-build "$bin" 2>/dev/null || true
        exit 1
    fi
    echo "OK platform TVOS: $name"
}

mkdir -p "$BUILD/Handoff672"

CFLAGS=(
    -arch arm64
    -isysroot "$SYSROOT"
    -mtvos-version-min="$TVOS_MIN"
    -O2
    -Wno-deprecated-declarations
    -Wno-error
    -D_DARWIN_UNLIMITED_SYSCALLS
)

echo "=== build672 dt_tool672_probe (tvOS SDK) ==="
xcrun -sdk "$SDK" clang "${CFLAGS[@]}" -o "$BUILD/Handoff672/dt_tool672_probe" \
    "$PROJECT/handoff672/dt_tool672_probe.c"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o \
    "$BUILD/Handoff672/dt_tool672_probe" "$BUILD/Handoff672/dt_tool672_probe"
if [[ -x "$LDID" ]]; then
    "$LDID" -S"$PROJECT/entitlements_direct672_tool.plist" \
        "$BUILD/Handoff672/dt_tool672_probe"
else
    echo "WARN: ldid not found — tool may be unsigned"
fi
chmod +x "$BUILD/Handoff672/dt_tool672_probe"
verify_tvos_platform "$BUILD/Handoff672/dt_tool672_probe"

echo "=== build672 handoff complete ==="
ls -la "$BUILD/Handoff672/"
