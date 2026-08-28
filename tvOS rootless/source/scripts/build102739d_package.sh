#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_ROOT="$(cd "$PROJECT/.." && pwd -P)"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739d_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739D-DETERMINISTIC-LAUNCHD-XPC-TRIGGER.ipa"
FROZEN_HOOK_SHA="96ee5782cb3732ec771a1033662061cff6bbdaa55e0fb9094c4a841ef69b9091"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739d_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739D prepare isolated space-free source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739D reuse exact 102739C hook and build deterministic observer ==="
DT_BUILD102739D_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$WORKSPACE_ROOT/Dopamine_Rootful-main" \
  bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

[[ "$(shasum -a 256 "$MAKE_PROJECT/build/102738P/Handoff516/launchdhook516.dylib" | awk '{print $1}')" == "$FROZEN_HOOK_SHA" ]]

echo "=== BUILD102739D compile and package on frozen 102738 functional gate ==="
DT_WORKSPACE_ROOT="$WORKSPACE_ROOT" DT_102739D_VARIANT=1 DT_102738_PREBUILT=1 \
  make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]] || {
    echo "ERROR: temporary IPA missing" >&2
    exit 1
}
rm -rf "$PROJECT/build/102739D"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739D"
rm -f "$PROJECT/build/102739D/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739D/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=C \
  bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
  | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739D.txt"

HOOK="$PROJECT/build/102739D/Handoff516/launchdhook516.dylib"
HELPER="$PROJECT/build/102739D/Handoff516/dt_opainject516"
HELPER_STRINGS="$PROJECT/build/102739D/obj/opainject/helper_strings.txt"
OBSERVER_DISASM="$PROJECT/build/102739D/obj/opainject/observer_disassembly.txt"
TRIGGER_DISASM="$PROJECT/build/102739D/obj/opainject/trigger_disassembly.txt"
HELPER_UNDEFINED="$PROJECT/build/102739D/obj/opainject/helper_undefined_symbols.txt"
APP_STRINGS="$PROJECT/build/102739D/obj/app_strings.txt"
strings "$MAKE_PROJECT/.theos/obj/appletv/debug/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd" > "$APP_STRINGS"
otool -tvV "$HELPER" | sed -n '/_dt102739d_send_one_launchd_request:/,/^_/p' > "$TRIGGER_DISASM"
nm -u "$HELPER" > "$HELPER_UNDEFINED"

[[ "$(shasum -a 256 "$HOOK" | awk '{print $1}')" == "$FROZEN_HOOK_SHA" ]]
for marker in \
    BUILD102739D_BOOTSTRAP_PORT_RC= \
    BUILD102739D_BOOTSTRAP_PORT_VALID= \
    BUILD102739D_BOOTSTRAP_PIPE_CREATED= \
    BUILD102739D_TRIGGER_TIMEOUT_GUARD_SECONDS=3 \
    BUILD102739D_TRIGGER_SEND_ATTEMPTED=YES \
    BUILD102739D_TRIGGER_SEND_RC= \
    BUILD102739D_BASELINE_ENTRY_COUNT= \
    BUILD102739D_BASELINE_RETURN_COUNT= \
    BUILD102739D_ENTRY_DELTA= \
    BUILD102739D_RETURN_DELTA= \
    BUILD102739D_SUCCESS_OBJECT_DELTA= \
    BUILD102739D_COUNTERS_MONOTONIC= \
    BUILD102739D_DETERMINISTIC_INVOCATION= \
    BUILD102739D_DETERMINISTIC_RETURN_PATH=; do
    rg -q "$marker" "$HELPER_STRINGS"
done
for symbol in _task_get_special_port _xpc_pipe_create_from_port \
    _xpc_pipe_routine_with_flags _xpc_dictionary_create_empty \
    _xpc_dictionary_set_uint64 _xpc_release _alarm; do
    rg -q "$symbol" "$HELPER_UNDEFINED"
done
rg -q '_task_get_special_port' "$TRIGGER_DISASM"
rg -q '_xpc_pipe_create_from_port' "$TRIGGER_DISASM"
rg -q '_xpc_pipe_routine_with_flags' "$TRIGGER_DISASM"
[[ "$(rg -c '_xpc_pipe_routine_with_flags' "$TRIGGER_DISASM")" -eq 1 ]]
[[ "$(rg -c '_alarm' "$TRIGGER_DISASM")" -eq 2 ]]
if rg -q '_task_write|_mach_vm_write|_injectDylibViaRop|_thread_create' \
    "$OBSERVER_DISASM" "$TRIGGER_DISASM"; then
    echo "ERROR: remote mutation leaked into BUILD102739D observer" >&2
    exit 1
fi
for marker in \
    BUILD102739D_RUNNER_ENTRY \
    BUILD102739D_INSERTION_AFTER_PHYSRW_HANDOFF \
    BUILD102739D_FROZEN_102739C_HOOK_REUSED=YES \
    BUILD102739D_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE \
    BUILD102739D_TRIGGER_REQUEST_COUNT=1 \
    BUILD102739D_PID1_IDENTITY_UNCHANGED; do
    rg -q "$marker" "$APP_STRINGS"
done

for frozen in \
    "dt_jbctl516:6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067" \
    "libjailbreak.dylib:0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754" \
    "libchoma.dylib:40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"; do
    file="${frozen%%:*}"
    expected="${frozen#*:}"
    actual="$(shasum -a 256 "$PROJECT/build/102739D/Handoff516/$file" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]]
done

{
    echo "BUILD102739D_FINAL_HOST_AUDIT"
    echo "FUNCTIONAL_GATE=102738"
    echo "SCOPE=DETERMINISTIC_POST_WALL2_LAUNCHD_XPC_TRIGGER"
    echo "FROZEN_HOOK_SOURCE=BUILD102739C"
    echo "FROZEN_HOOK_SHA256=$FROZEN_HOOK_SHA"
    echo "FROZEN_HOOK_IDENTITY=PASS"
    echo "TRIGGER_PROCESS=EXTERNAL_OPAINJECT_OBSERVER"
    echo "TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE"
    echo "TRIGGER_REQUEST_COUNT=1"
    echo "TRIGGER_TIMEOUT_GUARD_SECONDS=3"
    echo "TRIGGER_ENVELOPE=IOS_JB_DOMAIN_ACTION"
    echo "LAUNCHD_GOT_OFFSET=0x65018"
    echo "REMOTE_DLOPEN_FOR_OBSERVER=NO"
    echo "REMOTE_WRITE_FOR_OBSERVER=NO"
    echo "LAUNCHD_HOOK_CODE_CHANGED=NO"
    echo "JBSERVER_ENABLED=NO"
    echo "MESSAGE_PARSING_ENABLED=NO"
    echo "FROZEN_LIBJAILBREAK_LIBCHOMA_JBCTL=PASS"
    echo "HELPER_SHA256=$(shasum -a 256 "$HELPER" | awk '{print $1}')"
    echo "IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739D_FINAL_HOST_AUDIT.txt"

echo "BUILD102739D_PACKAGE_COMPLETE=YES"
echo "BUILD102739D_COMPILED_FUNCTIONAL_GATE=102738"
echo "BUILD102739D_IPA_PATH=$PROJECT/$IPA_NAME"
echo "BUILD102739D_IPA_SHA256=$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
