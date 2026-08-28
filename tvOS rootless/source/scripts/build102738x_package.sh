#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102738x_src"
TEMP_IPA_NAME="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102738X-GOT-WRAPPER-ROUNDTRIP.ipa"

MODULE_CACHE_CREATED=0
if [[ -z "${CLANG_MODULE_CACHE_PATH:-}" ]]; then
    CLANG_MODULE_CACHE_PATH="$(mktemp -d /tmp/dt102738x_module_cache.XXXXXX)"
    MODULE_CACHE_CREATED=1
fi
export CLANG_MODULE_CACHE_PATH
cleanup() {
    if [[ "$MODULE_CACHE_CREATED" == "1" ]]; then
        rm -rf "$CLANG_MODULE_CACHE_PATH"
    fi
}
trap cleanup EXIT

echo "=== BUILD102738X prepare space-free Theos source copy ==="
rm -rf "$MAKE_PROJECT"
mkdir -p "$MAKE_PROJECT"
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102738X build isolated hook from frozen BUILD102738R ==="
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
  bash "$MAKE_PROJECT/scripts/build102738x_got_wrapper_roundtrip.sh"

echo "=== BUILD102738X compile and package ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102738X_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA_NAME" ]] || {
    echo "ERROR: missing completed temporary IPA: $MAKE_PROJECT/$TEMP_IPA_NAME" >&2
    exit 1
}
[[ -d "$MAKE_PROJECT/build/102738P/Payload" ]] || {
    echo "ERROR: missing completed temporary BUILD102738P payload" >&2
    exit 1
}

rm -rf "$PROJECT/build/102738X"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102738X"
rm -f "$PROJECT/build/102738X/$TEMP_IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/build/102738X/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/$IPA_NAME"

set -o pipefail
DT_EXPECT_102738_VARIANT=X \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102738X.txt"

echo "BUILD102738X_PACKAGE_COMPLETE=YES"
echo "BUILD102738X_FROZEN_102738W_OVERWRITTEN=NO"
echo "BUILD102738X_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102738X_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
