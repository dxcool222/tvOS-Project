#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102738y_src"
TEMP_IPA_NAME="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102738Y-NONBLOCKING-REPAIR.ipa"

MODULE_CACHE_CREATED=0
if [[ -z "${CLANG_MODULE_CACHE_PATH:-}" ]]; then
  CLANG_MODULE_CACHE_PATH="$(mktemp -d /tmp/dt102738y_module_cache.XXXXXX)"
  MODULE_CACHE_CREATED=1
fi
export CLANG_MODULE_CACHE_PATH
cleanup() {
  if [[ "$MODULE_CACHE_CREATED" == "1" ]]; then
    rm -rf "$CLANG_MODULE_CACHE_PATH"
  fi
}
trap cleanup EXIT

echo "=== BUILD102738Y prepare space-free Theos source copy ==="
rm -rf "$MAKE_PROJECT"
mkdir -p "$MAKE_PROJECT"
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102738Y build isolated hook from frozen BUILD102738R ==="
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
  bash "$MAKE_PROJECT/scripts/build102738y_got_wrapper_invocation.sh"

echo "=== BUILD102738Y compile and package ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102738Y_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA_NAME" ]] || { echo "ERROR: missing temporary IPA" >&2; exit 1; }
[[ -d "$MAKE_PROJECT/build/102738P/Payload" ]] || { echo "ERROR: missing temporary payload" >&2; exit 1; }

rm -rf "$PROJECT/build/102738Y"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102738Y"
rm -f "$PROJECT/build/102738Y/$TEMP_IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/build/102738Y/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=Y \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102738Y.txt"

echo "BUILD102738Y_PACKAGE_COMPLETE=YES"
echo "BUILD102738Y_FROZEN_102738X_OVERWRITTEN=NO"
echo "BUILD102738Y_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102738Y_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
