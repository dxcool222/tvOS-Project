#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102738r_src"
TEMP_IPA_NAME="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102738R-RECURSIVE-POINTER-VALIDATOR.ipa"

echo "=== BUILD102738R prepare space-free Theos source copy ==="
rm -rf "$MAKE_PROJECT"
mkdir -p "$MAKE_PROJECT"
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"

# Keep the proven numeric 102738 application gates. The Makefile's 102738P
# output is transient inside /tmp; the repaired result is copied back as R.
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102738R compile and package ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA_NAME" ]] || {
    echo "ERROR: missing completed temporary IPA: $MAKE_PROJECT/$TEMP_IPA_NAME" >&2
    exit 1
}
[[ -d "$MAKE_PROJECT/build/102738P/Payload" ]] || {
    echo "ERROR: missing completed temporary BUILD102738P payload" >&2
    exit 1
}

rm -rf "$PROJECT/build/102738R"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102738R"
rm -f "$PROJECT/build/102738R/$TEMP_IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/build/102738R/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA_NAME" "$PROJECT/$IPA_NAME"

set -o pipefail
bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102738R.txt"

echo "BUILD102738R_PACKAGE_COMPLETE=YES"
echo "BUILD102738R_OLD_102738P_OVERWRITTEN=NO"
echo "BUILD102738R_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102738R_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
