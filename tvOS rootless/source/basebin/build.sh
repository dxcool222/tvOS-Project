#!/bin/bash
# BaseBin dylibs — xcrun clang + AppleTVOS16.4.sdk (tvOS 16.5 device)
set -euo pipefail

BASEBIN_DIR="$(cd "$(dirname "$0")" && pwd)"
KFD_ROOT="$(cd "$BASEBIN_DIR/.." && pwd)"
ROOT="$(cd "$KFD_ROOT/../.." && pwd)"
DOPAMINE="$ROOT/Dependencies/Dopamine-2.x"
CHoma="$DOPAMINE/BaseBin/ChOma"
XPF_DIR="$DOPAMINE/BaseBin/XPF"
LIBJB="$DOPAMINE/BaseBin/libjailbreak"
OUT="$BASEBIN_DIR/out"

export THEOS="${THEOS:-$HOME/theos}"
SDK=appletvos
ARCH=arm64
MIN_OS="${TVOS_MIN_OS:-14.0}"
SDK_VERSION="${TVOS_SDK_VERSION:-16.4}"
SYSROOT="${TVOS_SYSROOT:-$THEOS/sdks/AppleTVOS${SDK_VERSION}.sdk}"
CLANG=(xcrun -sdk "$SDK" clang)
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
LDID="${LDID:-/opt/local/bin/ldid}"

INC=(
    -I"$OUT/include"
    -I"$DOPAMINE/BaseBin/_external/include"
    -I"$CHoma/src"
    -I"$XPF_DIR/src"
    -I"$LIBJB/src"
    -I"$LIBJB/src/atomic_headers"
    -I"$DOPAMINE/BaseBin/_external/modules/litehook/src"
)

CFLAGS=(
    -arch "$ARCH"
    -isysroot "$SYSROOT"
    -mtvos-version-min="$MIN_OS"
    -Wno-error -Wno-ambiguous-macro -Wno-unused-variable -Wno-unused-but-set-variable -Wno-availability
    -D_DARWIN_UNLIMITED_SYSCALLS
    -fobjc-arc -O2 -Wno-deprecated-declarations
    "${INC[@]}"
)

LDFLAGS=(
    -arch "$ARCH"
    -isysroot "$SYSROOT"
    -mtvos-version-min="$MIN_OS"
    -lcompression -lbsm
)

CHOMa_SRCS=("$CHoma"/src/*.c)
XPF_SRCS=(
    "$XPF_DIR/src/common.c"
    "$XPF_DIR/src/decompress.c"
    "$XPF_DIR/src/xpf.c"
    "$XPF_DIR/src/non_ppl.c"
    "$XPF_DIR/src/ppl.c"
    "$XPF_DIR/src/bad_recovery.c"
)
LIBJB_SRCS=(
    "$LIBJB/src/info.c"
    "$LIBJB/src/primitives.c"
    "$LIBJB/src/translation.c"
    "$KFD_ROOT/stubs/libjailbreak_stub.c"
)

sign_macho() {
    local bin="$1"
    "$VTOOL" -set-build-version tvos "$MIN_OS" "$SDK_VERSION" -replace -o "$bin" "$bin"
    "$LDID" -S "$bin"
}

echo "=== basebin (tvOS $MIN_OS+, SDK $SDK_VERSION) ==="
echo "SDK: $SYSROOT"

if [[ ! -d "$SYSROOT" ]]; then
    echo "ERROR: missing $SYSROOT"
    exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT/obj/choma" "$OUT/obj/xpf" "$OUT/obj/libjb" "$OUT/include/choma" "$OUT/include/xpf"
cp "$CHoma"/src/*.h "$OUT/include/choma/"
cp "$XPF_DIR/src/xpf.h" "$OUT/include/xpf/"

for src in "${CHOMa_SRCS[@]}"; do
    base="$(basename "$src" .c)"
    "${CLANG[@]}" "${CFLAGS[@]}" -DDISABLE_SIGNING=1 -fPIC -c "$src" -o "$OUT/obj/choma/$base.o"
done

for src in "${XPF_SRCS[@]}"; do
    base="$(basename "$src" .c)"
    "${CLANG[@]}" "${CFLAGS[@]}" -fPIC -c "$src" -o "$OUT/obj/xpf/$base.o"
done

for src in "${LIBJB_SRCS[@]}"; do
    base="$(basename "$src" .c)"
    "${CLANG[@]}" "${CFLAGS[@]}" -fPIC -c "$src" -o "$OUT/obj/libjb/$base.o"
done

CHOMa_OBJS=("$OUT/obj/choma"/*.o)
XPF_OBJS=("$OUT/obj/xpf"/*.o)
LIBJB_OBJS=("$OUT/obj/libjb"/*.o)

"${CLANG[@]}" "${CFLAGS[@]}" -dynamiclib \
    -install_name @executable_path/Frameworks/libchoma.dylib \
    "${CHOMa_OBJS[@]}" -o "$OUT/libchoma.dylib" \
    "$CHoma/external/ios/libcrypto.a" -framework CoreFoundation
sign_macho "$OUT/libchoma.dylib"

"${CLANG[@]}" "${CFLAGS[@]}" -dynamiclib \
    -install_name @executable_path/Frameworks/libxpf.dylib \
    "${XPF_OBJS[@]}" -o "$OUT/libxpf.dylib" \
    "${LDFLAGS[@]}" -L"$OUT" -lchoma -framework Foundation
sign_macho "$OUT/libxpf.dylib"

"${CLANG[@]}" "${CFLAGS[@]}" -dynamiclib \
    -install_name @executable_path/Frameworks/libjailbreak.dylib \
    "${LIBJB_OBJS[@]}" -o "$OUT/libjailbreak.dylib" \
    "${LDFLAGS[@]}" -L"$OUT" -lchoma \
    -framework Foundation -framework CoreServices -framework Security
sign_macho "$OUT/libjailbreak.dylib"

echo "=== basebin done ==="
ls -lh "$OUT"/*.dylib
otool -l "$OUT/libxpf.dylib" | grep -A4 LC_BUILD_VERSION | head -5
