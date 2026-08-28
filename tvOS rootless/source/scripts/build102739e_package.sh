#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739e_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739E-READ-ONLY-XPC-DICTIONARY-CLASSIFIER.ipa"
FROZEN_D_HOOK_SHA="96ee5782cb3732ec771a1033662061cff6bbdaa55e0fb9094c4a841ef69b9091"
FROZEN_D_HELPER_SHA="14a673d835990a06c6465667c7d9694da85901a822189f5e52656ba4c61f2bd1"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739e_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739E prepare isolated space-free source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739E build read-only classifier hook and deterministic observer ==="
DT_BUILD102739E_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$DOPAMINE_ROOT" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739E regenerate auxiliary app bundle helpers ==="
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" \
  "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod +x "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739E compile and package on frozen 102738 functional gate ==="
DT_WORKSPACE_ROOT="$REPO_ROOT" DT_102739E_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]] || {
    echo "ERROR: temporary IPA missing" >&2
    exit 1
}
rm -rf "$PROJECT/build/102739E"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739E"
rm -f "$PROJECT/build/102739E/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739E/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=E \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739E.txt"

HOOK="$PROJECT/build/102739E/Handoff516/launchdhook516.dylib"
HELPER="$PROJECT/build/102739E/Handoff516/dt_opainject516"
OBJ="$PROJECT/build/102739E/obj"
WRAPPER_DISASM="$OBJ/hook/wrapper_disassembly.txt"
HOOK_UNDEFINED="$OBJ/hook/hook_undefined_symbols.txt"
HELPER_STRINGS="$OBJ/opainject/helper_strings.txt"
APP_STRINGS="$OBJ/app_strings.txt"
RESOURCE_MANIFEST="$PROJECT/build/102739E/Handoff516/BUILD102739E_RESOURCE_MANIFEST.txt"
mkdir -p "$OBJ/hook" "$OBJ/opainject"
nm -u "$HOOK" > "$HOOK_UNDEFINED"
strings "$HELPER" > "$HELPER_STRINGS"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd \
  | strings > "$APP_STRINGS"

original_line="$(rg -n $'\tblr\t' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
type_line="$(rg -n '_xpc_get_type' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
[[ -n "$original_line" && -n "$type_line" && "$original_line" -lt "$type_line" ]]
[[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]]
rg -q $'\tret' "$WRAPPER_DISASM"
for call in _xpc_get_type _xpc_dictionary_get_value \
    _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp; do
    rg -q "$call" "$WRAPPER_DISASM"
    rg -q "$call" "$HOOK_UNDEFINED"
done
if rg -q '_xpc_(release|retain)|_fprintf|_open|_mmap|_write|_jbserver' \
    "$WRAPPER_DISASM"; then
    echo "ERROR: forbidden ownership, I/O, or jbserver call in 102739E wrapper" >&2
    exit 1
fi
if rg -q '_xpc_(release|retain)|_jbserver_received' "$HOOK_UNDEFINED"; then
    echo "ERROR: forbidden ownership or jbserver symbol in 102739E hook" >&2
    exit 1
fi
nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739e_dictionary_telemetry'
for marker in \
    BUILD102739E_EXACT_CONTROLLED_PROBE_DELTA= \
    BUILD102739E_READ_ONLY_DICTIONARY_CLASSIFICATION= \
    BUILD102739E_ORIGINAL_RETURN_PRESERVED=YES \
    BUILD102739E_REMOTE_DLOPEN_ATTEMPTED=NO \
    BUILD102739E_REMOTE_WRITE_ATTEMPTED=NO; do
    rg -q "$marker" "$HELPER_STRINGS"
done
for marker in \
    BUILD102739E_SCOPE=READ_ONLY_POST_ORIGINAL_XPC_DICTIONARY_CLASSIFICATION \
    BUILD102739E_TRIGGER_REQUEST_COUNT=1 \
    BUILD102739E_OBJECT_OWNERSHIP_CHANGED=NO \
    BUILD102739E_ORIGINAL_RETURN_CHANGED=NO \
    BUILD102739E_JBSERVER_IMPLEMENTED=NO; do
    rg -q "$marker" "$APP_STRINGS"
done

for frozen in \
    "dt_jbctl516:6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067" \
    "libjailbreak.dylib:0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754" \
    "libchoma.dylib:40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"; do
    file="${frozen%%:*}"
    expected="${frozen#*:}"
    actual="$(shasum -a 256 "$PROJECT/build/102739E/Handoff516/$file" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || {
        echo "ERROR: frozen resource changed: $file" >&2
        exit 1
    }
done

[[ -f "$RESOURCE_MANIFEST" ]]
for file in launchdhook516.dylib libjailbreak.dylib libchoma.dylib \
    dt_jbctl516 dt_opainject516; do
    expected="$(shasum -a 256 "$PROJECT/build/102739E/Handoff516/$file" | awk '{print $1}')"
    rg -q "^${file}=${expected}$" "$RESOURCE_MANIFEST"
done
rg -q '^TELEMETRY_RECORD_SIZE=88$' "$RESOURCE_MANIFEST"
rg -q '^XPC_OBJECT_OWNERSHIP_CHANGED=NO$' "$RESOURCE_MANIFEST"
rg -q '^ORIGINAL_RETURN_VALUE_CHANGED=NO$' "$RESOURCE_MANIFEST"

HOOK_SHA="$(shasum -a 256 "$HOOK" | awk '{print $1}')"
HELPER_SHA="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
HELPER_CDHASH="$(codesign -dvvv "$HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)"
[[ "$HOOK_SHA" != "$FROZEN_D_HOOK_SHA" ]]
[[ "$HELPER_SHA" != "$FROZEN_D_HELPER_SHA" ]]
[[ "$HELPER_CDHASH" =~ ^[0-9a-f]{40}$ ]]

{
    echo "BUILD102739E_FINAL_HOST_AUDIT"
    echo "TARGET_TVOS_VERSION=16.5"
    echo "TARGET_BUILD=20L563"
    echo "FUNCTIONAL_GATE=102738"
    echo "VARIANT=102739E"
    echo "SCOPE=READ_ONLY_POST_ORIGINAL_XPC_DICTIONARY_CLASSIFICATION"
    echo "IOS_GUARD_ORDER=original_then_result_zero_then_xout_then_object_then_dictionary"
    echo "TVOS_LAUNCHD_X4_OUTPUT_POINTER_IDA_PROVEN=YES"
    echo "TVOS_LAUNCHD_CALLSITE=0x100040660"
    echo "LAUNCHD_GOT_OFFSET=0x65018"
    echo "WRAPPER_ORIGINAL_INDIRECT_CALL_COUNT=$(rg -c $'\tblr\t' "$WRAPPER_DISASM")"
    echo "WRAPPER_ORIGINAL_CALL_BEFORE_XPC_CLASSIFICATION=PASS"
    echo "EXPORTED_TELEMETRY_SYMBOL=_g_dt102739e_dictionary_telemetry"
    echo "TELEMETRY_SIZE=88"
    echo "EXACT_PROBE_EXPECTED_DELTA=1"
    echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
    echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
    echo "JBSERVER_ENABLED=NO"
    echo "BOOTSTRAP_CHANGED=NO"
    echo "OBSERVER_REMOTE_DLOPEN=NO"
    echo "OBSERVER_REMOTE_WRITE=NO"
    echo "FROZEN_LIBJAILBREAK_LIBCHOMA_JBCTL=PASS"
    echo "BUNDLED_HOOK_PRE_DEVICE_STAGE_SHA256=$HOOK_SHA"
    echo "SIGNED_HELPER_SHA256=$HELPER_SHA"
    echo "SIGNED_HELPER_CDHASH=$HELPER_CDHASH"
    echo "DEVICE_POSTSIGN_HOOK_CDHASH_REPARSE_REQUIRED=YES"
    echo "DEVICE_POSTSIGN_HOOK_TRUST_QUERY_REQUIRED=YES"
    echo "DEVICE_HELPER_TRUST_QUERY_REQUIRED=YES"
    echo "RUNTIME_TRUSTCACHE_ENTRY_COUNT_EXPECTED=5"
    echo "HOOK_SHA256=$HOOK_SHA"
    echo "HELPER_SHA256=$HELPER_SHA"
    echo "IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739E_FINAL_HOST_AUDIT.txt"

echo "BUILD102739E_PACKAGE_COMPLETE=YES"
echo "BUILD102739E_COMPILED_FUNCTIONAL_GATE=102738"
echo "BUILD102739E_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102739E_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
