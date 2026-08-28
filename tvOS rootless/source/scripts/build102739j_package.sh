#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739j_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739J-CONTROLLED-REPLY-ROUNDTRIP.ipa"
OUTPUT_DIR="$REPO_ROOT/Output"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739j_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739J prepare isolated source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739J build controlled reply roundtrip hook and observer ==="
DT_BUILD102739J_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$DOPAMINE_ROOT" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739J regenerate auxiliary helpers ==="
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" \
  "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod +x "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739J compile and package on functional gate 102738 ==="
DT_WORKSPACE_ROOT="$REPO_ROOT" DT_102739J_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]]
rm -rf "$PROJECT/build/102739J"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739J"
rm -f "$PROJECT/build/102739J/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739J/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=J \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739J.txt"

HOOK="$PROJECT/build/102739J/Handoff516/launchdhook516.dylib"
HELPER="$PROJECT/build/102739J/Handoff516/dt_opainject516"
OBJ="$PROJECT/build/102739J/obj"
WRAPPER_DISASM="$OBJ/hook/wrapper_disassembly.txt"
HOOK_UNDEFINED="$OBJ/hook/hook_undefined_symbols.txt"
HELPER_STRINGS="$OBJ/opainject/helper_strings.txt"
APP_STRINGS="$OBJ/app_strings.txt"
APP_BINARY="$OBJ/app_binary"
APP_CAPTURE_DISASM="$OBJ/app_capture_disassembly.txt"
RESOURCE_MANIFEST="$PROJECT/build/102739J/Handoff516/BUILD102739J_RESOURCE_MANIFEST.txt"
mkdir -p "$OBJ/hook" "$OBJ/opainject"
nm -u "$HOOK" > "$HOOK_UNDEFINED"
strings "$HELPER" > "$HELPER_STRINGS"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd \
  | strings > "$APP_STRINGS"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd \
  > "$APP_BINARY"
otool -tvV "$APP_BINARY" \
  | awk '/^_dt_spawn_capture_internal:/{inside=1} /^_dt_spawn_root_capture:/{inside=0} inside' \
  > "$APP_CAPTURE_DISASM"
rg -q '^_dt_spawn_capture_internal:$' "$APP_CAPTURE_DISASM"
if rg -q 'setLength:|#0x2000|0x2000' "$APP_CAPTURE_DISASM"; then
    echo "ERROR: compiled J spawn capture still contains the 8192-byte truncation path" >&2
    exit 1
fi

rg -q '^#ifndef DT_BUILD102739J_VARIANT$' "$PROJECT/spawn_root.m"
rg -q 'data.length = 8192;' "$PROJECT/spawn_root.m"
rg -q 'BUILD102739J_OBSERVER_CAPTURE_TRUNCATED=NO' "$PROJECT/dt_build681_client.m"
rg -q 'direct_j_verdict_parsed_102739j' "$PROJECT/dt_kcall_planb.m"

[[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 3 ]]
original_line="$(rg -n $'\tblr\t' "$WRAPPER_DISASM" | sed -n '1p' | cut -d: -f1)"
permission_line="$(rg -n $'\tblr\t' "$WRAPPER_DISASM" | sed -n '2p' | cut -d: -f1)"
handler_line="$(rg -n $'\tblr\t' "$WRAPPER_DISASM" | sed -n '3p' | cut -d: -f1)"
audit_line="$(rg -n '_xpc_dictionary_get_audit_token' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
[[ -n "$original_line" && -n "$permission_line" && -n "$handler_line" && -n "$audit_line" ]]
[[ "$original_line" -lt "$audit_line" && "$audit_line" -lt "$permission_line" ]]
[[ "$permission_line" -lt "$handler_line" ]]
create_line="$(rg -n '_xpc_dictionary_create_reply' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
set_string_line="$(rg -n '_xpc_dictionary_set_string' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
set_int64_line="$(rg -n '_xpc_dictionary_set_int64' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
get_int64_line="$(rg -n '_xpc_dictionary_get_int64' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
send_line="$(rg -n '_xpc_pipe_routine_reply' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
precommit_release_line="$(rg -n '_xpc_release' "$WRAPPER_DISASM" | sed -n '1p' | cut -d: -f1)"
reply_release_line="$(rg -n '_xpc_release' "$WRAPPER_DISASM" | sed -n '2p' | cut -d: -f1)"
input_release_line="$(rg -n '_xpc_release' "$WRAPPER_DISASM" | sed -n '3p' | cut -d: -f1)"
return22_line="$(rg -n 'mov[[:space:]]+w19, #0x16' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
[[ "$(rg -c '_xpc_release' "$WRAPPER_DISASM")" -eq 3 ]]
[[ "$handler_line" -lt "$create_line" && "$create_line" -lt "$set_string_line" ]]
[[ "$set_string_line" -lt "$set_int64_line" && "$set_int64_line" -lt "$get_int64_line" ]]
[[ "$get_int64_line" -lt "$precommit_release_line" && "$precommit_release_line" -lt "$send_line" ]]
[[ "$send_line" -lt "$reply_release_line" && "$reply_release_line" -lt "$input_release_line" ]]
[[ "$input_release_line" -lt "$return22_line" ]]
sed -n "$((reply_release_line - 1))p" "$WRAPPER_DISASM" | rg -q 'mov[[:space:]]+x0, x22'
sed -n "$((input_release_line - 1))p" "$WRAPPER_DISASM" | rg -q 'mov[[:space:]]+x0, x21'
rg -q 'literal pool symbol address: __xpc_type_string' "$WRAPPER_DISASM"
rg -q 'literal pool symbol address: __xpc_type_int64' "$WRAPPER_DISASM"
rg -q 'and[[:space:]]+w8, w19, #0xffffffdf' "$WRAPPER_DISASM"
for call in _xpc_get_type _xpc_dictionary_get_value \
    _xpc_dictionary_get_uint64 _xpc_dictionary_get_string \
    _xpc_dictionary_get_int64 _xpc_dictionary_set_string \
    _xpc_dictionary_set_int64 _xpc_dictionary_create_reply \
    _xpc_pipe_routine_reply _xpc_release _strcmp \
    _xpc_dictionary_get_audit_token _audit_token_to_pid \
    _audit_token_to_euid; do
    rg -q "$call" "$WRAPPER_DISASM"
    rg -q "$call" "$HOOK_UNDEFINED"
done
if rg -q '_xpc_retain|_fprintf|_open|_mmap|_write|_jbserver|_jbinfo|_strdup|_malloc|_free' \
    "$WRAPPER_DISASM"; then
    echo "ERROR: forbidden retain, allocation, I/O, jbinfo, or jbserver call in 102739J wrapper" >&2
    exit 1
fi
nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739j_reply_telemetry'

for marker in \
    BUILD102739J_HANDLER_CALL_ATTEMPT_DELTA= \
    BUILD102739J_HANDLER_RETURN_DELTA= \
    BUILD102739J_HANDLER_ARG0_OUTPUT_SLOT_MATCH_DELTA= \
    BUILD102739J_HANDLER_ARGS1_THROUGH_7_NULL_DELTA= \
    BUILD102739J_HANDLER_OUTPUT_WRITE_DELTA= \
    BUILD102739J_ARGSOUT0_SENTINEL_MATCH_DELTA= \
    BUILD102739J_ARGSOUT_TAIL_NULL_DELTA= \
    BUILD102739J_HANDLER_RESULT_MATCH_DELTA= \
    BUILD102739J_CONTROLLED_HANDLER_COMPLETE_DELTA= \
    BUILD102739J_ORIGINAL_RECEIVE_CALL_DELTA= \
    BUILD102739J_ORIGINAL_RECEIVE_RETURN_DELTA= \
    BUILD102739J_REPLY_CREATE_ATTEMPT_DELTA= \
    BUILD102739J_REPLY_READBACK_MATCH_DELTA= \
    BUILD102739J_REPLY_SEND_ATTEMPT_DELTA= \
    BUILD102739J_SERVER_REPLY_RELEASE_DELTA= \
    BUILD102739J_INPUT_CONSUME_RELEASE_DELTA= \
    BUILD102739J_SERVER_COMMITTED_LIFECYCLE_PASS_DELTA= \
    BUILD102739J_WRAPPER_RETURN_22_DELTA= \
    BUILD102739J_TRIGGER_REPLY_IS_DICTIONARY= \
    BUILD102739J_TRIGGER_REPLY_ROOT_PATH_TYPE_STRING= \
    BUILD102739J_TRIGGER_REPLY_RESULT_TYPE_INT64= \
    BUILD102739J_CLIENT_REPLY_RELEASE_DELTA=1 \
    BUILD102739J_BOOTSTRAP_TOUCHED=NO \
    BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP=PASS; do
    rg -q "$marker" "$HELPER_STRINGS"
done
for marker in \
    BUILD102739J_SCOPE=CONTROLLED_REPLY_ROUNDTRIP \
    BUILD102739J_BLUEPRINT=IOS_JBSERVER_LINES_113_THROUGH_187_AND_XPC_HOOK_LINES_51_THROUGH_60 \
    BUILD102739J_TRIGGER_REQUEST_COUNT=1 \
    BUILD102739J_TRIGGER_DOMAIN=1 \
    BUILD102739J_TRIGGER_ACTION=1 \
    BUILD102739J_REPLY_ROOT_PATH=STATIC_SENTINEL \
    BUILD102739J_REPLY_RESULT=0 \
    BUILD102739J_COMMITTED_INPUT_CONSUME=YES \
    BUILD102739J_COMMITTED_RETURN_VALUE=22 \
    BUILD102739J_OBSERVER_CAPTURE_BYTES= \
    BUILD102739J_OBSERVER_CAPTURE_TRUNCATED=NO \
    BUILD102739J_DIRECT_HELPER_VERDICT_PARSED= \
    BUILD102739J_REAL_JBROOT_HANDLER_INVOKED=NO \
    BUILD102739J_BOOTSTRAP_CHANGED=NO; do
    rg -q "$marker" "$APP_STRINGS"
done

for frozen in \
    "dt_jbctl516:6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067" \
    "libjailbreak.dylib:0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754" \
    "libchoma.dylib:40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"; do
    file="${frozen%%:*}"
    expected="${frozen#*:}"
    actual="$(shasum -a 256 "$PROJECT/build/102739J/Handoff516/$file" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]]
done

[[ -f "$RESOURCE_MANIFEST" ]]
rg -q '^TELEMETRY_RECORD_SIZE=584$' "$RESOURCE_MANIFEST"
rg -q '^CONTROLLED_HANDLER_ARGUMENT_COUNT=8$' "$RESOURCE_MANIFEST"
rg -q '^CONTROLLED_HANDLER_ENABLED=YES$' "$RESOURCE_MANIFEST"
rg -q '^REAL_JBROOT_HANDLER_ENABLED=NO$' "$RESOURCE_MANIFEST"
rg -q '^STATIC_SENTINEL_OUTPUT=YES$' "$RESOURCE_MANIFEST"
rg -q '^REPLY_CREATION_ENABLED=YES$' "$RESOURCE_MANIFEST"
rg -q '^REPLY_SEND_ENABLED=YES$' "$RESOURCE_MANIFEST"
rg -q '^COMMITTED_INPUT_CONSUME_ENABLED=YES$' "$RESOURCE_MANIFEST"
rg -q '^COMMITTED_RETURN_VALUE=22$' "$RESOURCE_MANIFEST"
rg -q '^BOOTSTRAP_CHANGED=NO$' "$RESOURCE_MANIFEST"

HOOK_SHA="$(shasum -a 256 "$HOOK" | awk '{print $1}')"
HELPER_SHA="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
HELPER_CDHASH="$(codesign -dvvv "$HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)"
[[ "$HELPER_CDHASH" =~ ^[0-9a-f]{40}$ ]]

{
    echo "BUILD102739J_FINAL_HOST_AUDIT"
    echo "TARGET_TVOS_VERSION=16.5"
    echo "TARGET_BUILD=20L563"
    echo "FUNCTIONAL_GATE=102738"
    echo "VARIANT=102739J"
    echo "SCOPE=CONTROLLED_REPLY_ROUNDTRIP"
    echo "LAUNCHD_GOT_OFFSET=0x65018"
    echo "ORIGINAL_CALL_COUNT=1"
    echo "PERMISSION_HANDLER_CALL_COUNT=1"
    echo "CONTROLLED_ACTION_HANDLER_CALL_COUNT=1"
    echo "ORIGINAL_CALL_BEFORE_CLASSIFICATION=PASS"
    echo "AUDIT_TOKEN_BEFORE_PERMISSION=PASS"
    echo "PERMISSION_BEFORE_CONTROLLED_HANDLER=PASS"
    echo "CONTROLLED_HANDLER_ARGUMENT_COUNT=8"
    echo "REAL_JBROOT_HANDLER_ENABLED=NO"
    echo "STATIC_SENTINEL_OUTPUT=YES"
    echo "REPLY_CREATION_ENABLED=YES"
    echo "REPLY_SEND_ENABLED=YES"
    echo "REPLY_READBACK_TYPE_VALIDATION=PASS"
    echo "REPLY_CREATE_BEFORE_SEND=PASS"
    echo "REPLY_READBACK_BEFORE_SEND=PASS"
    echo "PRECOMMIT_RELEASE_BEFORE_SEND=PASS"
    echo "COMMITTED_REPLY_RELEASE_POINTER=CREATED_REPLY"
    echo "COMMITTED_INPUT_RELEASE_POINTER=RECEIVED_OBJECT"
    echo "COMMITTED_RELEASE_ORDER=PASS"
    echo "RETURN_22_AFTER_INPUT_RELEASE=PASS"
    echo "SERVER_REPLY_RC_0_OR_32_GATE=PASS"
    echo "OBSERVER_CAPTURE_8192_TRUNCATION_FOR_J=DISABLED"
    echo "COMPILED_J_CAPTURE_SETLENGTH_CALL=ABSENT"
    echo "OBSERVER_CAPTURE_LENGTH_TELEMETRY=ENABLED"
    echo "DIRECT_HELPER_J_PASS_REQUIRED=YES"
    echo "LAUNCHD_TRANSACTION_SEMANTICS_CHANGED=NO"
    echo "COMMITTED_INPUT_CONSUME_ENABLED=YES"
    echo "COMMITTED_RETURN_VALUE=22"
    echo "NONPROBE_XPC_OBJECT_OWNERSHIP_CHANGED=NO"
    echo "NONPROBE_ORIGINAL_RETURN_VALUE_CHANGED=NO"
    echo "BOOTSTRAP_CHANGED=NO"
    echo "TELEMETRY_SIZE=584"
    echo "HOOK_SHA256=$HOOK_SHA"
    echo "HELPER_SHA256=$HELPER_SHA"
    echo "SIGNED_HELPER_CDHASH=$HELPER_CDHASH"
    echo "HOOK_PACKAGE_SIGNING_STATE=UNSIGNED_PRESTAGE"
    echo "HOOK_RUNTIME_PLATFORM_SIGN_BEFORE_TRUSTCACHE=ENFORCED"
    echo "RUNTIME_TRUSTCACHE_ENTRY_COUNT_EXPECTED=5"
    echo "IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739J_FINAL_HOST_AUDIT.txt"

mkdir -p "$OUTPUT_DIR"
cp "$PROJECT/$IPA_NAME" "$OUTPUT_DIR/$IPA_NAME"
echo "BUILD102739J_PACKAGE_COMPLETE=YES"
echo "BUILD102739J_IPA_PATH=$OUTPUT_DIR/$IPA_NAME"
echo "BUILD102739J_IPA_SHA256=$(shasum -a 256 "$OUTPUT_DIR/$IPA_NAME" | awk '{print $1}')"
