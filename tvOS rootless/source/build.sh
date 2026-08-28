#!/bin/bash
# dopamin-tvOS-kfd — TrollStore IPA (matches dopamin-tvOS packaging)
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$PROJECT/../.." && pwd)"
DOPAMINE="$ROOT/Dependencies/Dopamine-2.x"
KFD="$DOPAMINE/Application/Dopamine/Exploits/kfd"
BASEBIN="$PROJECT/basebin/out"

BUILD="${DOPAMIN_KFD_BUILD:-$PROJECT/build}"
export THEOS="${THEOS:-$HOME/theos}"

SDK=appletvos
ARCH=arm64
MIN_OS="${TVOS_MIN_OS:-14.0}"
SDK_VERSION="${TVOS_SDK_VERSION:-16.4}"
SYSROOT="${TVOS_SYSROOT:-$THEOS/sdks/AppleTVOS${SDK_VERSION}.sdk}"
CLANG=(xcrun -sdk "$SDK" clang)

APP_NAME="dopamin-tvOS-kfd"
BUNDLE_APP="${APP_NAME}.app"
IPA_NAME="${APP_NAME}.ipa"

VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
INSTALL_NAME_TOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool"
LDID="${LDID:-/opt/local/bin/ldid}"

sign_macho() {
    local bin="$1"
    local ent="${2:-}"
    "$VTOOL" -set-build-version tvos "$MIN_OS" "$SDK_VERSION" -replace -o "$bin" "$bin"
    if [[ -n "$ent" ]]; then
        "$LDID" -S"$ent" "$bin"
    else
        "$LDID" -S "$bin"
    fi
}

echo "=== dopamin-tvOS-kfd build ==="
echo "Project: $PROJECT"
echo "Target:  tvOS 16.5 (SDK $SDK_VERSION, min $MIN_OS)"
echo "SDK:     $SYSROOT"

for p in "$SYSROOT" "$DOPAMINE" "$LDID"; do
    if [[ ! -e "$p" ]]; then
        echo "ERROR: missing $p"
        exit 1
    fi
done

export TVOS_MIN_OS="$MIN_OS"
export TVOS_SDK_VERSION="$SDK_VERSION"
export TVOS_SYSROOT="$SYSROOT"
bash "$PROJECT/basebin/build.sh"

CFLAGS=(
    -arch "$ARCH"
    -isysroot "$SYSROOT"
    -mtvos-version-min="$MIN_OS"
    -fobjc-arc -O2
    -Wno-deprecated-declarations -Wno-error
    -D_DARWIN_UNLIMITED_SYSCALLS
    -DDT_POST_KOPEN_PTE=0
    -DDT_PHYSRW_HANDOFF=1
    -DDT_BUILD_NUM=50
    -I"$PROJECT/stubs"
    -I"$PROJECT/libkfd"
    -I"$DOPAMINE/BaseBin/_external/include"
    -I"$BASEBIN/include"
    -I"$BASEBIN/include/choma"
    -I"$BASEBIN/include/xpf"
    -I"$KFD/Exploit"
    -I"$KFD"
    -I"$DOPAMINE/BaseBin/libjailbreak/src"
)

LDFLAGS=(
    -arch "$ARCH"
    -isysroot "$SYSROOT"
    -mtvos-version-min="$MIN_OS"
    -L"$BASEBIN"
    -lxpf -ljailbreak -lcompression
    -Wl,-rpath,@executable_path/Frameworks
    -framework UIKit -framework Foundation -framework IOSurface
)

PAYLOAD="$BUILD/Payload/$BUNDLE_APP"
rm -rf "$BUILD/Payload"
mkdir -p "$PAYLOAD/Frameworks"

echo "=== Pack bootstrap_g2 ==="
bash "$PROJECT/scripts/pack_bootstrap_g2.sh"

echo "=== Build app binary ==="
"${CLANG[@]}" "${CFLAGS[@]}" "${LDFLAGS[@]}" \
    -o "$BUILD/$APP_NAME" \
    "$PROJECT/main.m" \
    "$PROJECT/DTKFDConfig.m" \
    "$PROJECT/DTSettingsViewController.m" \
    "$PROJECT/DTLogCapture.m" \
    "$PROJECT/DTRunLogger.m" \
    "$PROJECT/DTDeviceInfo.m" \
    "$PROJECT/DTKernelPath.m" \
    "$PROJECT/DTKFDRunner.m" \
    "$PROJECT/DTBootstrap.m" \
    "$PROJECT/dt_baked_offsets.m" \
    "$PROJECT/dt_kfund_import.m" \
    "$PROJECT/dt_xpf_patchfind.m" \
    "$PROJECT/dt_misaka_offsets.m" \
    "$PROJECT/dt_do_fun.m" \
    "$PROJECT/dt_pte_kwrite.c" \
    "$PROJECT/kfd_tvos.m" \
    "$PROJECT/stubs/syscall_shim.c" \
    "$PROJECT/stubs/iokit_shim.c" \
    "$PROJECT/stubs/dt_pte_kwrite_stub.c"

"$INSTALL_NAME_TOOL" -change "@loader_path/libjailbreak.dylib" \
    "@executable_path/Frameworks/libjailbreak.dylib" "$BUILD/$APP_NAME" 2>/dev/null || true
"$INSTALL_NAME_TOOL" -change "@loader_path/libxpf.dylib" \
    "@executable_path/Frameworks/libxpf.dylib" "$BUILD/$APP_NAME" 2>/dev/null || true

echo "=== Package .app ==="
cp "$BUILD/$APP_NAME" "$PAYLOAD/$APP_NAME"
cp "$PROJECT/Info.plist" "$PAYLOAD/Info.plist"
rm -rf "$PAYLOAD/bootstrap_g2"
cp -R "$PROJECT/bootstrap_g2" "$PAYLOAD/bootstrap_g2"
for dylib in libchoma libxpf libjailbreak; do
    cp "$BASEBIN/${dylib}.dylib" "$PAYLOAD/Frameworks/"
done
chmod +x "$PAYLOAD/$APP_NAME"

echo "=== Sign all Mach-O (last step before zip) ==="
sign_macho "$PAYLOAD/$APP_NAME" "$PROJECT/entitlements.plist"
for dylib in libchoma libxpf libjailbreak; do
    sign_macho "$PAYLOAD/Frameworks/${dylib}.dylib"
done

echo "=== Verify ==="
plutil -lint "$PAYLOAD/Info.plist"
/usr/libexec/PlistBuddy -c "Print :CFBundleSupportedPlatforms:0" "$PAYLOAD/Info.plist" | grep -q AppleTVOS
/usr/libexec/PlistBuddy -c "Print :LSRequiresIPhoneOS" "$PAYLOAD/Info.plist" | grep -q true
/usr/libexec/PlistBuddy -c "Print :MinimumOSVersion" "$PAYLOAD/Info.plist" | grep -q 14.0
/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$PAYLOAD/Info.plist" | grep -q "$APP_NAME"
test -x "$PAYLOAD/$APP_NAME"
otool -l "$PAYLOAD/$APP_NAME" | grep -q "platform 3"
"$LDID" -e "$PAYLOAD/$APP_NAME" | grep -q platform-application
for dylib in libchoma libxpf libjailbreak; do
    otool -l "$PAYLOAD/Frameworks/${dylib}.dylib" | grep -q LC_CODE_SIGNATURE
done

cd "$BUILD"
rm -f "$IPA_NAME" "$PROJECT/$IPA_NAME" "$ROOT/$IPA_NAME"
zip -r "$IPA_NAME" Payload -x "*.DS_Store" -x "**/.DS_Store" > /dev/null
cp "$IPA_NAME" "$PROJECT/$IPA_NAME"
cp "$IPA_NAME" "$ROOT/$IPA_NAME"
cp "$IPA_NAME" "$ROOT/build50.ipa"

rm -rf "$ROOT/Payload/${BUNDLE_APP}"
mkdir -p "$ROOT/Payload"
rsync -a "$BUILD/Payload/" "$ROOT/Payload/"

echo "=== IPA contents ==="
unzip -l "$ROOT/$IPA_NAME"
echo "=== Done ==="
ls -lh "$ROOT/$IPA_NAME"
