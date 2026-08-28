#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739a_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739A-POST-WALL2-WRAPPER-INVOCATION-OBSERVER.ipa"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739a_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739A prepare isolated space-free source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739A build hook and read-only observer helper ==="
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
  DOPAMINE="$WORKSPACE_ROOT/Dopamine_Rootful-main" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739A compile and package on frozen 102738 functional gate ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102739A_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]] || { echo "ERROR: temporary IPA missing" >&2; exit 1; }
rm -rf "$PROJECT/build/102739A"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739A"
rm -f "$PROJECT/build/102739A/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739A/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=A \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739A.txt"

echo "BUILD102739A_PACKAGE_COMPLETE=YES"
echo "BUILD102739A_COMPILED_FUNCTIONAL_GATE=102738"
echo "BUILD102739A_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102739A_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
