#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
BUILD_ROOT="$PROJECT/build/102732C"
INPUT_ROOT="$PROJECT/build/gate1b1/Handoff516"
INPUT_COPY_ROOT="$BUILD_ROOT/gate1b1_inputs/Handoff516"
OUT_ROOT="$BUILD_ROOT/Handoff516"
IPA_NAME="dopamin-tvOS-kfd-102732C-CONSTRUCTOR-BOOMERANG-ONLY.ipa"
IPA_PATH="$BUILD_ROOT/$IPA_NAME"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102732c_src"
DEBUG_APP="$MAKE_PROJECT/.theos/obj/appletv/debug/dopamin-tvOS-kfd.app"

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

mkdir -p "$INPUT_COPY_ROOT"

expect_sha "$INPUT_ROOT/launchdhook516.dylib" \
  "c48b4fee09fea6e9c7852c274e3b8cbe651849a97cc3a2efa7d3a698d696c92a"
expect_sha "$INPUT_ROOT/libjailbreak.dylib" \
  "e0d5e20093e94605b7a679f18dc27acc97cf1b82d5878b888763afb12c7800f7"
expect_sha "$INPUT_ROOT/libchoma.dylib" \
  "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"

cp "$INPUT_ROOT/launchdhook516.dylib" "$INPUT_COPY_ROOT/"
cp "$INPUT_ROOT/libjailbreak.dylib" "$INPUT_COPY_ROOT/"
cp "$INPUT_ROOT/libchoma.dylib" "$INPUT_COPY_ROOT/"

rm -rf "$BUILD_ROOT/obj" "$OUT_ROOT"
GATE1B_BUILD_ROOT="$BUILD_ROOT" \
GATE1B_EXTRA_CFLAGS="-DDT_BUILD102732C_TELEMETRY=1" \
  bash "$PROJECT/scripts/build_gate1b_minimal_trio.sh"

# libchoma does not need telemetry; keep the exact Gate 1B.1 binary in the packaged trio.
cp "$INPUT_ROOT/libchoma.dylib" "$OUT_ROOT/libchoma.dylib"

rm -rf "$MAKE_PROJECT"
mkdir -p "$MAKE_PROJECT"
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
mkdir -p "$MAKE_PROJECT/build/102732C/Handoff516"
cp "$OUT_ROOT/launchdhook516.dylib" "$MAKE_PROJECT/build/102732C/Handoff516/launchdhook516.dylib"
cp "$OUT_ROOT/libjailbreak.dylib" "$MAKE_PROJECT/build/102732C/Handoff516/libjailbreak.dylib"
cp "$OUT_ROOT/libchoma.dylib" "$MAKE_PROJECT/build/102732C/Handoff516/libchoma.dylib"
DT_SKIP_BASEBIN_REBUILD=1 make -C "$MAKE_PROJECT" all fixup-dylibs

mkdir -p "$DEBUG_APP/Handoff516"
cp "$MAKE_PROJECT/build/102732C/Handoff516/launchdhook516.dylib" "$DEBUG_APP/Handoff516/launchdhook516.dylib"
cp "$MAKE_PROJECT/build/102732C/Handoff516/libjailbreak.dylib" "$DEBUG_APP/Handoff516/libjailbreak.dylib"
cp "$MAKE_PROJECT/build/102732C/Handoff516/libchoma.dylib" "$DEBUG_APP/Handoff516/libchoma.dylib"
chmod +x "$DEBUG_APP/Handoff516/"*.dylib
bash "$MAKE_PROJECT/scripts/write_hook_build_manifest.sh" \
  "$DEBUG_APP/Handoff516/launchdhook516.dylib" \
  "$DEBUG_APP/Handoff516/hook_build_manifest.txt"

rm -rf "$BUILD_ROOT/Payload"
mkdir -p "$BUILD_ROOT/Payload"
cp -R "$DEBUG_APP" "$BUILD_ROOT/Payload/"
find "$BUILD_ROOT/Payload" -name '*.i64' -delete
rm -f "$IPA_PATH" "$PROJECT/$IPA_NAME"
(cd "$BUILD_ROOT" && zip -qr "$IPA_PATH" Payload)
cp "$IPA_PATH" "$PROJECT/$IPA_NAME"

bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$IPA_PATH" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102732.txt"

cat <<EOF
BUILD102732C_PACKAGE_COMPLETE
BUILD_SPECIFIC_HOOK_TELEMETRY_BINARY_PATH=$OUT_ROOT/launchdhook516.dylib
BUILD_SPECIFIC_HOOK_PRE_SIGN_SHA256=$(shasum -a 256 "$OUT_ROOT/launchdhook516.dylib" | awk '{print $1}')
BUILD_SPECIFIC_LIBJAILBREAK_PRE_SIGN_SHA256=$(shasum -a 256 "$OUT_ROOT/libjailbreak.dylib" | awk '{print $1}')
BUILD_SPECIFIC_LIBCHOMA_PRE_SIGN_SHA256=$(shasum -a 256 "$OUT_ROOT/libchoma.dylib" | awk '{print $1}')
IPA_PATH=$IPA_PATH
IPA_SHA256=$(shasum -a 256 "$IPA_PATH" | awk '{print $1}')
EOF
