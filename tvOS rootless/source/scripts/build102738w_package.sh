#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102738w_src"
TEMP_IPA_NAME="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102738W-GOT-SAME-VALUE-STORE.ipa"

MODULE_CACHE_CREATED=0
if [[ -z "${CLANG_MODULE_CACHE_PATH:-}" ]]; then
    CLANG_MODULE_CACHE_PATH="$(mktemp -d /tmp/dt102738w_module_cache.XXXXXX)"
    MODULE_CACHE_CREATED=1
fi
export CLANG_MODULE_CACHE_PATH
cleanup() {
    if [[ "$MODULE_CACHE_CREATED" == "1" ]]; then
        rm -rf "$CLANG_MODULE_CACHE_PATH"
    fi
}
trap cleanup EXIT

echo "=== BUILD102738W prepare space-free Theos source copy ==="
rm -rf "$MAKE_PROJECT"
mkdir -p "$MAKE_PROJECT"
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"

# Keep the proven numeric 102738 application gates. The Makefile's 102738P
# output name is transient inside /tmp; the staged result is copied back as W.
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102738W build isolated hook from frozen BUILD102738R ==="
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
  bash "$MAKE_PROJECT/scripts/build102738w_got_same_value_store.sh"

echo "=== BUILD102738W compile and package ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102738W_VARIANT=1 DT_102738W_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA_NAME" ]] || {
    echo "ERROR: missing completed temporary IPA: $MAKE_PROJECT/$TEMP_IPA_NAME" >&2
    exit 1
}
[[ -d "$MAKE_PROJECT/build/102738P/Payload" ]] || {
    echo "ERROR: missing completed temporary BUILD102738P payload" >&2
    exit 1
}

rm -rf "$PROJECT/build/102738W"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102738W"
rm -f "$PROJECT/build/102738W/$TEMP_IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/build/102738W/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/$IPA_NAME"

set -o pipefail
bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102738W.txt"

echo "BUILD102738W_PACKAGE_COMPLETE=YES"
echo "BUILD102738W_FROZEN_102738R_OVERWRITTEN=NO"
echo "BUILD102738W_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102738W_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
