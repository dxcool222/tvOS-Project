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
SEED_IPA="${DT681_SEED_IPA:-$ROOT/build102.5.21.ipa}"

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

mkdir -p "$OUT" "$BUILD/opainject"

CFLAGS=(
    -arch arm64
    -isysroot "$SYSROOT"
    -mtvos-version-min="$TVOS_MIN"
    -O2
    -Wno-deprecated-declarations
    -Wno-error
    -D_DARWIN_UNLIMITED_SYSCALLS
)

echo "=== build681 dt_jbctl516 ==="
xcrun -sdk "$SDK" clang "${CFLAGS[@]}" -o "$OUT/dt_jbctl516" \
    "$PROJECT/handoff681/dt_jbctl681.c"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o \
    "$OUT/dt_jbctl516" "$OUT/dt_jbctl516"
if [[ -x "$LDID" ]]; then
    "$LDID" -S"$PROJECT/handoff681/entitlements_jbctl681.plist" "$OUT/dt_jbctl516"
    echo "OK ldid jbctl681 entitlements"
else
    echo "WARN: ldid missing — jbctl681 unsigned"
fi
chmod +x "$OUT/dt_jbctl516"
verify_tvos_platform "$OUT/dt_jbctl516"

echo "=== build681 seed launchdhook from $SEED_IPA ==="
UNSIGNED_HOOK="$OUT/launchdhook516.unsigned.dylib"
if [[ -f "$SEED_IPA" ]]; then
    TMP="$(mktemp -d)"
    unzip -q "$SEED_IPA" -d "$TMP"
    SEED_DIR="$TMP/Payload/dopamin-tvOS-kfd.app/Handoff516"
    if [[ -f "$SEED_DIR/launchdhook516.dylib" ]]; then
        cp "$SEED_DIR/launchdhook516.dylib" "$UNSIGNED_HOOK"
        chmod +x "$UNSIGNED_HOOK" 2>/dev/null || true
    else
        echo "ERROR: seed IPA missing launchdhook516.dylib"
        exit 1
    fi
    rm -rf "$TMP"
else
    echo "WARN: seed IPA missing — reuse existing .theos artifacts if present"
    OLD="$PROJECT/.theos/obj/handoff516/Handoff516"
    if [[ -f "$OLD/launchdhook516.dylib" ]]; then
        cp "$OLD/launchdhook516.dylib" "$UNSIGNED_HOOK"
    else
        echo "ERROR: missing launchdhook516.dylib and no seed IPA"
        exit 1
    fi
fi

echo "=== build681 ldid-sign launchdhook516 (IPA/TrollStore-safe; platform -P at runtime) ==="
cp "$UNSIGNED_HOOK" "$OUT/launchdhook516.dylib"
if [[ -x "$LDID" ]]; then
    "$LDID" -S"$PROJECT/handoff681/entitlements_launchdhook681.plist" "$OUT/launchdhook516.dylib"
    echo "OK ldid launchdhook681 entitlements (CodeDirectory.platform=0 for TrollStore install)"
else
    echo "WARN: ldid missing — launchdhook516 unsigned"
fi
chmod +x "$OUT/launchdhook516.dylib"
verify_tvos_platform "$OUT/launchdhook516.dylib"
rm -f "$UNSIGNED_HOOK"
echo "HOOK_BUILD_FUNCTION=build681_handoff.sh ldid-seed-copy"
echo "HOOK_SIGNING_TOOL=ldid (build-time adhoc; NOT ChOma platform byte)"
echo "HOOK_RUNTIME_PLATFORM_SIGN=Tools/ldid -S entitlements -P13 on device (build699+)"
echo "HOOK_ENTITLEMENTS_FILE=$PROJECT/handoff681/entitlements_launchdhook681.plist"

echo "=== build681 dt_opainject516 (Dopamine + post-consume skip) ==="
mkdir -p "$BUILD/opainject"
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

xcrun -sdk "$SDK" clang "${OPAINJECT_CFLAGS[@]}" -o "$OUT/dt_opainject516" \
    "${OPAINJECT_SRCS[@]}"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o \
    "$OUT/dt_opainject516" "$OUT/dt_opainject516"
if [[ -x "$LDID" ]]; then
    "$LDID" -S"$PROJECT/handoff681/entitlements_opainject681.plist" "$OUT/dt_opainject516"
    echo "OK ldid opainject681 entitlements"
else
    echo "WARN: ldid missing — opainject681 unsigned"
fi
chmod +x "$OUT/dt_opainject516"
verify_tvos_platform "$OUT/dt_opainject516"

if strings "$OUT/dt_opainject516" | grep -q "post-consume"; then
    echo "OK opainject681 post-consume path present"
else
    echo "ERROR: opainject681 missing post-consume strings"
    exit 1
fi

echo "=== build681 handoff complete ==="
ls -la "$OUT/"

if [[ ! -f "$PROJECT/basebin/out/libjailbreak.dylib" ]]; then
    echo "ERROR: basebin/out/libjailbreak.dylib missing — run make -C basebin dylibs first"
    exit 1
fi
cp "$PROJECT/basebin/out/libjailbreak.dylib" "$OUT/libjailbreak.dylib"
cp "$PROJECT/basebin/out/libchoma.dylib" "$OUT/libchoma.dylib" 2>/dev/null || true
# Handoff/preboot role: colocated libchoma beside staged libjailbreak (@loader_path).
# App Frameworks copy keeps @executable_path/Frameworks/libchoma.dylib from basebin/out.
INSTALL_NAME_TOOL="${INSTALL_NAME_TOOL:-/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool}"
"$INSTALL_NAME_TOOL" -change "@executable_path/Frameworks/libchoma.dylib" \
    "@loader_path/libchoma.dylib" "$OUT/libjailbreak.dylib"
if ! otool -L "$OUT/libjailbreak.dylib" | grep -q '@loader_path/libchoma.dylib'; then
    echo "ERROR: Handoff516 libjailbreak missing @loader_path/libchoma.dylib after retarget"
    exit 1
fi
if [[ -x "$LDID" ]]; then
    "$LDID" -S "$OUT/libjailbreak.dylib"
    "$LDID" -S "$OUT/libchoma.dylib" 2>/dev/null || true
fi
echo "OK staged basebin libjailbreak into Handoff516 with @loader_path/libchoma retarget"
