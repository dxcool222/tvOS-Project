#!/bin/bash
# Build-time: fetch ldid (iphoneos arm64), retag for tvOS, sign for IPA embed (G4).
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$PROJECT/Tools"
CACHE="${TOOLS_CACHE:-$PROJECT/.tools-cache}"
LDID_SRC="$CACHE/ldid_iphoneos_arm64"
LDID_BIN="$OUT/ldid"
ENT="$OUT/entitlements_tools.plist"

VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
LDID="${LDID:-/opt/local/bin/ldid}"
MIN_OS="${TVOS_MIN_OS:-14.0}"
SDK_VERSION="${TVOS_SDK_VERSION:-16.4}"

mkdir -p "$OUT" "$CACHE"

if [[ ! -f "$ENT" ]]; then
    echo "ERROR: missing $ENT"
    exit 1
fi

if [[ ! -f "$LDID_SRC" ]]; then
    echo "=== Fetch ldid (iphoneos arm64) ==="
    curl -fsSL "https://github.com/ProcursusTeam/ldid/releases/download/v2.1.5-procursus7/ldid_iphoneos_arm64" -o "$LDID_SRC"
fi

cp "$LDID_SRC" "$LDID_BIN"
chmod +x "$LDID_BIN"
"$VTOOL" -set-build-version tvos "$MIN_OS" "$SDK_VERSION" -replace -o "$LDID_BIN" "$LDID_BIN"
"$LDID" -S"$ENT" "$LDID_BIN"

echo "=== Tools/ldid ready ==="
ls -la "$LDID_BIN"
file "$LDID_BIN"
