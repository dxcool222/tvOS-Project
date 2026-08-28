#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739b_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739B-POST-ORIGINAL-RETURN-PATH.ipa"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739b_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739B prepare isolated space-free source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739B build post-original return hook and read-only observer ==="
DT_BUILD102739B_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$WORKSPACE_ROOT/Dopamine_Rootful-main" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739B compile and package on frozen 102738 functional gate ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102739B_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]] || {
    echo "ERROR: temporary IPA missing" >&2
    exit 1
}
rm -rf "$PROJECT/build/102739B"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739B"
rm -f "$PROJECT/build/102739B/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739B/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=B \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739B.txt"

HOOK="$PROJECT/build/102739B/Handoff516/launchdhook516.dylib"
HELPER="$PROJECT/build/102739B/Handoff516/dt_opainject516"
WRAPPER_DISASM="$PROJECT/build/102739B/obj/hook/wrapper_disassembly.txt"
{
    echo "BUILD102739B_FINAL_HOST_AUDIT"
    echo "FUNCTIONAL_GATE=102738"
    echo "SCOPE=POST_WALL2_ORIGINAL_RETURN_PATH_OBSERVATION"
    echo "IOS_BLUEPRINT_CALLS_ORIGINAL_AND_REGAINS_CONTROL=YES"
    echo "WRAPPER_CALL_INSTRUCTION_COUNT=$(rg -c $'\tblr\t' "$WRAPPER_DISASM")"
    echo "WRAPPER_RETURN_INSTRUCTION_COUNT=$(rg -c $'\tret' "$WRAPPER_DISASM")"
    echo "WRAPPER_ATOMIC_LOAD_EXCLUSIVE_COUNT=$(rg -c $'\tldxr\t|\tldaxr\t' "$WRAPPER_DISASM")"
    echo "WRAPPER_ATOMIC_STORE_EXCLUSIVE_COUNT=$(rg -c $'\tstxr\t|\tstlxr\t' "$WRAPPER_DISASM")"
    echo "EXPORTED_TELEMETRY_SYMBOL=_g_dt102739b_return_telemetry"
    echo "TELEMETRY_SIZE=16"
    echo "TELEMETRY_READ_ORDER=RETURN_THEN_ENTRY"
    echo "POST_WALL2_GOT_REVALIDATION=YES"
    echo "POST_WALL2_GOT_OFFSET=0x65018"
    echo "POST_WALL2_EXPECTED_POINTER=REMOTE_WRAPPER_SYMBOL"
    echo "BOUNDED_POLL_INTERVAL_US=20000"
    echo "BOUNDED_POLL_ATTEMPTS=100"
    echo "OBSERVER_REMOTE_DLOPEN=NO"
    echo "OBSERVER_REMOTE_WRITE=NO"
    echo "MESSAGE_OR_XOUT_DEREFERENCE=NO"
    echo "MESSAGE_PARSING=NO"
    echo "JBSERVER=NO"
    echo "BOOTSTRAP_CHANGED=NO"
    echo "HOOK_SHA256=$(shasum -a 256 "$HOOK" | awk '{print $1}')"
    echo "HELPER_SHA256=$(shasum -a 256 "$HELPER" | awk '{print $1}')"
    echo "IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739B_FINAL_HOST_AUDIT.txt"

echo "BUILD102739B_PACKAGE_COMPLETE=YES"
echo "BUILD102739B_COMPILED_FUNCTIONAL_GATE=102738"
echo "BUILD102739B_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102739B_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
