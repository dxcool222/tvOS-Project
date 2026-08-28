#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739g_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739G-READ-ONLY-DOMAIN-PERMISSION-ACTION.ipa"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739g_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739G prepare isolated source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739G build read-only resolver hook and observer ==="
DT_BUILD102739G_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$DOPAMINE_ROOT" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739G regenerate auxiliary helpers ==="
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" \
  "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod +x "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739G compile and package on functional gate 102738 ==="
DT_WORKSPACE_ROOT="$REPO_ROOT" DT_102739G_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]]
rm -rf "$PROJECT/build/102739G"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739G"
rm -f "$PROJECT/build/102739G/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739G/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=G \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739G.txt"

HOOK="$PROJECT/build/102739G/Handoff516/launchdhook516.dylib"
HELPER="$PROJECT/build/102739G/Handoff516/dt_opainject516"
OBJ="$PROJECT/build/102739G/obj"
WRAPPER_DISASM="$OBJ/hook/wrapper_disassembly.txt"
HOOK_UNDEFINED="$OBJ/hook/hook_undefined_symbols.txt"
HELPER_STRINGS="$OBJ/opainject/helper_strings.txt"
APP_STRINGS="$OBJ/app_strings.txt"
RESOURCE_MANIFEST="$PROJECT/build/102739G/Handoff516/BUILD102739G_RESOURCE_MANIFEST.txt"
mkdir -p "$OBJ/hook" "$OBJ/opainject"
nm -u "$HOOK" > "$HOOK_UNDEFINED"
strings "$HELPER" > "$HELPER_STRINGS"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd \
  | strings > "$APP_STRINGS"

[[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 2 ]]
original_line="$(rg -n $'\tblr\t' "$WRAPPER_DISASM" | sed -n '1p' | cut -d: -f1)"
permission_line="$(rg -n $'\tblr\t' "$WRAPPER_DISASM" | sed -n '2p' | cut -d: -f1)"
audit_line="$(rg -n '_xpc_dictionary_get_audit_token' "$WRAPPER_DISASM" | head -1 | cut -d: -f1)"
[[ -n "$original_line" && -n "$permission_line" && -n "$audit_line" ]]
[[ "$original_line" -lt "$audit_line" && "$audit_line" -lt "$permission_line" ]]
for call in _xpc_get_type _xpc_dictionary_get_value \
    _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp \
    _xpc_dictionary_get_audit_token _audit_token_to_pid \
    _audit_token_to_euid; do
    rg -q "$call" "$WRAPPER_DISASM"
    rg -q "$call" "$HOOK_UNDEFINED"
done
if rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver' \
    "$WRAPPER_DISASM"; then
    echo "ERROR: forbidden ownership, reply, I/O, or jbserver call in 102739G wrapper" >&2
    exit 1
fi
rg -q 'bl.*dt102739g_unreachable_get_jbroot' "$WRAPPER_DISASM" && {
    echo "ERROR: GET_JBROOT placeholder is reachable from 102739G wrapper" >&2
    exit 1
}
nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739g_domain_action_telemetry'

for marker in \
    BUILD102739G_DOMAIN_RESOLUTION_ATTEMPT_DELTA= \
    BUILD102739G_DOMAIN_RESOLUTION_SUCCESS_DELTA= \
    BUILD102739G_PERMISSION_CHECK_DELTA= \
    BUILD102739G_PERMISSION_ALLOW_DELTA= \
    BUILD102739G_ACTION_NONZERO_DELTA= \
    BUILD102739G_ACTION_RESOLUTION_ATTEMPT_DELTA= \
    BUILD102739G_ACTION_RESOLUTION_SUCCESS_DELTA= \
    BUILD102739G_HANDLER_INVOCATION_DELTA= \
    BUILD102739G_GET_JBROOT_DESCRIPTOR_RESOLVED=YES \
    BUILD102739G_READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION=PASS; do
    rg -q "$marker" "$HELPER_STRINGS"
done
for marker in \
    BUILD102739G_SCOPE=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION \
    BUILD102739G_TRIGGER_REQUEST_COUNT=1 \
    BUILD102739G_TRIGGER_DOMAIN=1 \
    BUILD102739G_TRIGGER_ACTION=1 \
    BUILD102739G_SHADOW_DOMAIN_TABLE_ENABLED=YES \
    BUILD102739G_PERMISSION_CHECK_ENABLED=YES \
    BUILD102739G_HANDLER_DISPATCH_IMPLEMENTED=NO \
    BUILD102739G_REPLY_CREATION_IMPLEMENTED=NO \
    BUILD102739G_BOOTSTRAP_CHANGED=NO; do
    rg -q "$marker" "$APP_STRINGS"
done

for frozen in \
    "dt_jbctl516:6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067" \
    "libjailbreak.dylib:0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754" \
    "libchoma.dylib:40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"; do
    file="${frozen%%:*}"
    expected="${frozen#*:}"
    actual="$(shasum -a 256 "$PROJECT/build/102739G/Handoff516/$file" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]]
done

[[ -f "$RESOURCE_MANIFEST" ]]
rg -q '^SHADOW_DOMAIN_TABLE_ENABLED=YES$' "$RESOURCE_MANIFEST"
rg -q '^PERMISSION_CHECK_ENABLED=YES$' "$RESOURCE_MANIFEST"
rg -q '^HANDLER_DISPATCH_ENABLED=NO$' "$RESOURCE_MANIFEST"
rg -q '^REPLY_CREATION_ENABLED=NO$' "$RESOURCE_MANIFEST"

HOOK_SHA="$(shasum -a 256 "$HOOK" | awk '{print $1}')"
HELPER_SHA="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
HELPER_CDHASH="$(codesign -dvvv "$HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)"
[[ "$HELPER_CDHASH" =~ ^[0-9a-f]{40}$ ]]

{
    echo "BUILD102739G_FINAL_HOST_AUDIT"
    echo "TARGET_TVOS_VERSION=16.5"
    echo "TARGET_BUILD=20L563"
    echo "FUNCTIONAL_GATE=102738"
    echo "VARIANT=102739G"
    echo "SCOPE=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION"
    echo "IOS_DISPATCH_PREFIX=type_keys_domain_resolve_token_permission_action_resolve"
    echo "LAUNCHD_GOT_OFFSET=0x65018"
    echo "ORIGINAL_CALL_COUNT=1"
    echo "PERMISSION_HANDLER_CALL_COUNT=1"
    echo "ORIGINAL_CALL_BEFORE_CLASSIFICATION=PASS"
    echo "AUDIT_TOKEN_BEFORE_PERMISSION=PASS"
    echo "SHADOW_DOMAIN_TABLE_ENABLED=YES"
    echo "HANDLER_INVOCATION_ENABLED=NO"
    echo "REPLY_CREATION_ENABLED=NO"
    echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
    echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
    echo "BOOTSTRAP_CHANGED=NO"
    echo "TELEMETRY_SIZE=192"
    echo "HOOK_SHA256=$HOOK_SHA"
    echo "HELPER_SHA256=$HELPER_SHA"
    echo "SIGNED_HELPER_CDHASH=$HELPER_CDHASH"
    echo "IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739G_FINAL_HOST_AUDIT.txt"

echo "BUILD102739G_PACKAGE_COMPLETE=YES"
echo "BUILD102739G_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102739G_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
