#!/bin/bash
# BUILD102631 — build tvOS arm64 probe_true for bootstrap_g2 embed.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${PROJECT}/bootstrap_g2/usr/bin"
OUT="${OUT_DIR}/probe_true"
SDK="appletvos"
ARCH=arm64
MIN_OS=14.0
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
CLANG="xcrun -sdk $SDK clang"

mkdir -p "$OUT_DIR"

CFLAGS="-arch $ARCH -isysroot $(xcrun --sdk $SDK --show-sdk-path) -mtvos-version-min=$MIN_OS"
LDFLAGS="-arch $ARCH -isysroot $(xcrun --sdk $SDK --show-sdk-path) -mtvos-version-min=$MIN_OS -nostdlib -static -Wl,-e,_main"

$CLANG $CFLAGS $LDFLAGS -o "$OUT" "$PROJECT/scripts/probe_true.S"
"$VTOOL" -set-build-version tvos "$MIN_OS" "$MIN_OS" -replace -o "$OUT" "$OUT"
chmod 755 "$OUT"

echo "probe_true: $OUT"
file "$OUT"
otool -L "$OUT" || true
"$VTOOL" -show-build "$OUT"
