#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102738p_src"
IPA_NAME="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"

echo "=== BUILD102738P prepare space-free Theos source copy ==="
rm -rf "$MAKE_PROJECT"
mkdir -p "$MAKE_PROJECT"
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"

# Force the app to compile with DT_BUILD_NUM=102738, but retain the already-proven
# auxiliary helper objects that fixup-dylibs packages unchanged.
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102738P compile and package ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$IPA_NAME" ]] || {
    echo "ERROR: missing completed IPA: $MAKE_PROJECT/$IPA_NAME" >&2
    exit 1
}
[[ -d "$MAKE_PROJECT/build/102738P/Payload" ]] || {
    echo "ERROR: missing completed BUILD102738P payload" >&2
    exit 1
}

rm -rf "$PROJECT/build/102738P"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102738P"
cp "$MAKE_PROJECT/$IPA_NAME" "$PROJECT/$IPA_NAME"

set -o pipefail
bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102738.txt"

echo "BUILD102738P_PACKAGE_COMPLETE=YES"
echo "BUILD102738P_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102738P_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
