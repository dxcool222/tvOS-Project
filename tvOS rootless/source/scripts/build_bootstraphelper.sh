#!/bin/bash
# Build bootstraphelper for tvOS KFD IPA (persona-root helper, build102+)
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${DT_HELPER_BUILD:-$PROJECT/.theos/obj/bootstraphelper}"
SDK="appletvos"
ARCH=arm64
MIN_OS=14.0

VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
CLANG="xcrun -sdk $SDK clang"
LDID="${LDID:-/opt/local/bin/ldid}"

mkdir -p "$BUILD"

CFLAGS="-arch $ARCH -isysroot $(xcrun --sdk $SDK --show-sdk-path) -mtvos-version-min=$MIN_OS -fobjc-arc -O2"
LDFLAGS="-arch $ARCH -isysroot $(xcrun --sdk $SDK --show-sdk-path) -mtvos-version-min=$MIN_OS"

OUT="$BUILD/bootstraphelper"
$CLANG $CFLAGS $LDFLAGS -o "$OUT" "$PROJECT/bootstraphelper.m" "$PROJECT/dt_helper_sandbox_ext.m" -framework Foundation
"$VTOOL" -set-build-version tvos "$MIN_OS" "$MIN_OS" -replace -o "$OUT" "$OUT"
if [[ -x "$LDID" ]]; then
    "$LDID" -S"$PROJECT/entitlements_helper.plist" "$OUT"
else
    echo "WARN: ldid not found — bootstraphelper may be unsigned"
fi
chmod +x "$OUT"
echo "bootstraphelper: $OUT"
