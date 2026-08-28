#!/bin/bash
# Build-time: carve G2 Tier-1 subset from tvbootstrap into bootstrap_g2/ for IPA embed.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
ZST="${DT_G2_BOOTSTRAP_TAR:-${DT_WORKSPACE_ROOT:-$(cd "$PROJECT/.." && pwd)}/bootstrap/tars/tvbootstrap-ssh-1900.tar.zst}"
OUT="$PROJECT/bootstrap_g2"
if [[ -f "$OUT/usr/bin/bash" ]]; then
    echo "=== pack bootstrap_g2: reuse existing tree ==="
    exit 0
fi
INSTALL_NAME_TOOL="${INSTALL_NAME_TOOL:-/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool}"
INSTALL_NAME_ID() {
    local bin="$1"
    local id="$2"
    [[ -f "$bin" ]] || return 0
    "$INSTALL_NAME_TOOL" -id "$id" "$bin" 2>/dev/null || true
}

if [[ ! -f "$ZST" ]]; then
    echo "ERROR: missing $ZST"
    exit 1
fi

MEMBERS=(
    ./usr/bin/bash
    ./usr/bin/dash
    ./usr/lib/libreadline.8.dylib
    ./usr/lib/libreadline.8.2.dylib
    ./usr/lib/libhistory.8.dylib
    ./usr/lib/libhistory.8.2.dylib
    ./usr/lib/libncursesw.6.dylib
    ./usr/lib/libiosexec.1.dylib
)

rm -rf "$OUT"
mkdir -p "$OUT"

echo "=== pack bootstrap_g2 from tvbootstrap ==="
zstd -dc "$ZST" | tar -xf - -C "$OUT" "${MEMBERS[@]}"

fix_id() {
    local bin="$1"
    shift
    [[ -f "$bin" ]] || return 0
    for dep in "$@"; do
        local old="${dep%%|*}"
        local new="${dep##*|}"
        "$INSTALL_NAME_TOOL" -change "$old" "$new" "$bin" 2>/dev/null || true
    done
}

LIB='@loader_path/../lib'
fix_id "$OUT/usr/bin/bash" \
    "@rpath/libiosexec.1.dylib|${LIB}/libiosexec.1.dylib" \
    "/usr/lib/libreadline.8.dylib|${LIB}/libreadline.8.dylib" \
    "/usr/lib/libhistory.8.dylib|${LIB}/libhistory.8.dylib" \
    "/usr/lib/libncursesw.6.dylib|${LIB}/libncursesw.6.dylib"

fix_id "$OUT/usr/bin/dash" \
    "@rpath/libiosexec.1.dylib|${LIB}/libiosexec.1.dylib"

fix_id "$OUT/usr/lib/libreadline.8.2.dylib" \
    "@rpath/libiosexec.1.dylib|@loader_path/libiosexec.1.dylib" \
    "/usr/lib/libncursesw.6.dylib|@loader_path/libncursesw.6.dylib" \
    "/usr/lib/libreadline.8.dylib|@loader_path/libreadline.8.dylib"

fix_id "$OUT/usr/lib/libhistory.8.2.dylib" \
    "@rpath/libiosexec.1.dylib|@loader_path/libiosexec.1.dylib"

fix_id "$OUT/usr/lib/libncursesw.6.dylib" \
    "@rpath/libiosexec.1.dylib|@loader_path/libiosexec.1.dylib" \
    "/usr/lib/libncursesw.6.dylib|@loader_path/libncursesw.6.dylib"

fix_id "$OUT/usr/lib/libhistory.8.dylib" \
    "@rpath/libiosexec.1.dylib|@loader_path/libiosexec.1.dylib" \
    "/usr/lib/libhistory.8.dylib|@loader_path/libhistory.8.dylib" \
    "/usr/lib/libncursesw.6.dylib|@loader_path/libncursesw.6.dylib"

fix_id "$OUT/usr/lib/libreadline.8.dylib" \
    "@rpath/libiosexec.1.dylib|@loader_path/libiosexec.1.dylib" \
    "/usr/lib/libreadline.8.dylib|@loader_path/libreadline.8.dylib" \
    "/usr/lib/libncursesw.6.dylib|@loader_path/libncursesw.6.dylib"

IOSEX='@loader_path/libiosexec.1.dylib'
echo "=== build75 rootful paths: real Procursus libiosexec + @loader_path LC_ID_DYLIB ==="
fix_id "$OUT/usr/lib/libiosexec.1.dylib" \
    "/usr/lib/libiosexec.1.dylib|${IOSEX}" \
    "@rpath/libiosexec.1.dylib|${IOSEX}"
INSTALL_NAME_ID "$OUT/usr/lib/libiosexec.1.dylib" "$IOSEX"

for base in libreadline.8.2.dylib libhistory.8.2.dylib libncursesw.6.dylib; do
    INSTALL_NAME_ID "$OUT/usr/lib/$base" "@loader_path/$base"
done
INSTALL_NAME_ID "$OUT/usr/lib/libiosexec.1.dylib" "$IOSEX"

ln -sf libreadline.8.2.dylib "$OUT/usr/lib/libreadline.8.dylib"
ln -sf libhistory.8.2.dylib "$OUT/usr/lib/libhistory.8.dylib"
echo "=== libiosexec: Procursus tarball (not tvOS stub) id=${IOSEX} ==="

echo "=== BUILD102631: embed tvOS arm64 probe_true ==="
bash "$PROJECT/scripts/build_probe_true.sh"

COUNT=$(find "$OUT" \( -type f -o -type l \) | wc -l | tr -d ' ')
SIZE=$(du -sh "$OUT" | awk '{print $1}')
echo "=== bootstrap_g2 ready: $COUNT files, $SIZE ==="
find "$OUT" \( -type f -o -type l \) | sed "s|^$OUT/||" | sort
