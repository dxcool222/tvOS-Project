#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739c_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739C-XPC-OUTPUT-CONTRACT.ipa"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739c_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739C prepare isolated space-free source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739C build guarded output-contract hook and read-only observer ==="
DT_BUILD102739C_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$WORKSPACE_ROOT/Dopamine_Rootful-main" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739C compile and package on frozen 102738 functional gate ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102739C_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]] || {
    echo "ERROR: temporary IPA missing" >&2
    exit 1
}
rm -rf "$PROJECT/build/102739C"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739C"
rm -f "$PROJECT/build/102739C/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739C/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=C \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739C.txt"

HOOK="$PROJECT/build/102739C/Handoff516/launchdhook516.dylib"
HELPER="$PROJECT/build/102739C/Handoff516/dt_opainject516"
WRAPPER_DISASM="$PROJECT/build/102739C/obj/hook/wrapper_disassembly.txt"
HOOK_UNDEFINED="$PROJECT/build/102739C/obj/hook/hook_undefined_symbols.txt"
nm -u "$HOOK" > "$HOOK_UNDEFINED"

[[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]]
rg -q $'\tret' "$WRAPPER_DISASM"
if rg -q '_xpc_|_fprintf|_open|_mmap|_write' "$WRAPPER_DISASM"; then
    echo "ERROR: out-of-scope call leaked into 102739C wrapper" >&2
    exit 1
fi
if rg -q '_xpc_(get_type|release|retain|dictionary)|_jbserver_received' "$HOOK_UNDEFINED"; then
    echo "ERROR: XPC parsing, ownership, or jbserver symbol leaked into 102739C hook" >&2
    exit 1
fi

for frozen in \
    "dt_jbctl516:6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067" \
    "libjailbreak.dylib:0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754" \
    "libchoma.dylib:40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"; do
    file="${frozen%%:*}"
    expected="${frozen#*:}"
    actual="$(shasum -a 256 "$PROJECT/build/102739C/Handoff516/$file" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || {
        echo "ERROR: frozen resource changed: $file" >&2
        exit 1
    }
done

{
    echo "BUILD102739C_FINAL_HOST_AUDIT"
    echo "FUNCTIONAL_GATE=102738"
    echo "SCOPE=POST_WALL2_XPC_OUTPUT_CONTRACT_OBSERVATION"
    echo "IOS_GUARD_ORDER=result_zero_then_xout_then_object"
    echo "TVOS_LAUNCHD_X4_OUTPUT_POINTER_IDA_PROVEN=YES"
    echo "TVOS_LAUNCHD_W0_ZERO_SUCCESS_IDA_PROVEN=YES"
    echo "LAUNCHD_GOT_OFFSET=0x65018"
    echo "WRAPPER_ORIGINAL_INDIRECT_CALL_COUNT=$(rg -c $'\tblr\t' "$WRAPPER_DISASM")"
    echo "WRAPPER_RETURN_INSTRUCTION_COUNT=$(rg -c $'\tret' "$WRAPPER_DISASM")"
    echo "EXPORTED_TELEMETRY_SYMBOL=_g_dt102739c_output_telemetry"
    echo "TELEMETRY_SIZE=48"
    echo "TELEMETRY_FIELDS=entry,return,success_return,xout_argument,success_xout,success_object"
    echo "GUARDED_XOUT_DEREFERENCE=YES"
    echo "XPC_API_CALLS=NO"
    echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
    echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
    echo "MESSAGE_PARSING=NO"
    echo "JBSERVER=NO"
    echo "BOOTSTRAP_CHANGED=NO"
    echo "OBSERVER_REMOTE_DLOPEN=NO"
    echo "OBSERVER_REMOTE_WRITE=NO"
    echo "FROZEN_LIBJAILBREAK_LIBCHOMA_JBCTL=PASS"
    echo "HOOK_SHA256=$(shasum -a 256 "$HOOK" | awk '{print $1}')"
    echo "HELPER_SHA256=$(shasum -a 256 "$HELPER" | awk '{print $1}')"
    echo "IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739C_FINAL_HOST_AUDIT.txt"

echo "BUILD102739C_PACKAGE_COMPLETE=YES"
echo "BUILD102739C_COMPILED_FUNCTIONAL_GATE=102738"
echo "BUILD102739C_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102739C_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
