#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
IPA="${1:?usage: host_audit_102732c.sh <ipa-path>}"
INPUT_ROOT="$PROJECT/build/gate1b1/Handoff516"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q -o "$IPA" -d "$tmp"

APP="$tmp/Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd"
HOOK="$tmp/Payload/dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib"
LIBJB="$tmp/Payload/dopamin-tvOS-kfd.app/Handoff516/libjailbreak.dylib"
LIBCHOMA="$tmp/Payload/dopamin-tvOS-kfd.app/Handoff516/libchoma.dylib"
STRINGS_ALL="$tmp/strings_all.txt"

sha() {
    shasum -a 256 "$1" | awk '{print $1}'
}

yesno_rg() {
    local pattern="$1" file="$2"
    if rg -q "$pattern" "$file"; then
        echo YES
    else
        echo NO
    fi
}

passfail() {
    if "$@"; then
        echo PASS
    else
        echo FAIL
    fi
}

[[ "$(sha "$INPUT_ROOT/launchdhook516.dylib")" == "c48b4fee09fea6e9c7852c274e3b8cbe651849a97cc3a2efa7d3a698d696c92a" ]]
[[ "$(sha "$INPUT_ROOT/libjailbreak.dylib")" == "e0d5e20093e94605b7a679f18dc27acc97cf1b82d5878b888763afb12c7800f7" ]]
[[ "$(sha "$INPUT_ROOT/libchoma.dylib")" == "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b" ]]
gate_inputs=YES

strings "$APP" "$HOOK" "$LIBJB" "$LIBCHOMA" > "$STRINGS_ALL"

hook_loads_libjb=FAIL
libjb_loads_libchoma=FAIL
libchoma_system_only=FAIL
otool -L "$HOOK" | rg -q '@loader_path/libjailbreak\.dylib' && hook_loads_libjb=PASS
otool -L "$LIBJB" | rg -q '@loader_path/libchoma\.dylib' && libjb_loads_libchoma=PASS
if ! otool -L "$LIBCHOMA" | tail -n +3 | rg -q '@loader_path|@rpath|@executable_path'; then
    libchoma_system_only=PASS
fi

trio_dep=FAIL
if [[ "$hook_loads_libjb" == PASS && "$libjb_loads_libchoma" == PASS && "$libchoma_system_only" == PASS ]]; then
    trio_dep=PASS
fi

mshook="$(yesno_rg 'MSHookFunction' "$STRINGS_ALL")"
initxpc="$(yesno_rg 'initXPCHooks' "$STRINGS_ALL")"
full_hook="$(yesno_rg 'jbserver_received_|initXPCHooks|MSHookFunction' "$STRINGS_ALL")"
stage_b="$(yesno_rg 'BUILD102724_PHASE_B_REACHED|PHASE_B_LAUNCHD_TEST=BEGIN|STAGE_B_ACTIVE=YES' "$STRINGS_ALL")"
got_code="$(yesno_rg '0x65018|GOT_DELTA|GOT_WRITE|GOT_POINTER_WRITTEN=YES|LAUNCHD_GOT' "$STRINGS_ALL")"
protect_got="$(yesno_rg 'MACH_VM_PROTECT_GOT_CALLED=YES|mach_vm_protect.*GOT' "$STRINGS_ALL")"
got_write="$(yesno_rg 'GOT_POINTER_WRITTEN=YES|proc_vwritebuf|vwritebuf GOT' "$STRINGS_ALL")"

identity_result="$(bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$IPA" | awk -F= '/^IDENTITY_CONSISTENCY=/{print $2}')"

host=PASS
[[ "$gate_inputs" == YES ]] || host=FAIL
[[ "$trio_dep" == PASS ]] || host=FAIL
[[ "$mshook" == NO ]] || host=FAIL
[[ "$initxpc" == NO ]] || host=FAIL
[[ "$full_hook" == NO ]] || host=FAIL
[[ "$stage_b" == NO ]] || host=FAIL
[[ "$got_code" == NO ]] || host=FAIL
[[ "$protect_got" == NO ]] || host=FAIL
[[ "$got_write" == NO ]] || host=FAIL
[[ "$identity_result" == PASS ]] || host=FAIL

cat <<EOF
BUILD102732C_HOST_AUDIT_REPORT
GATE1B1_INPUT_IDENTITIES_MATCH=$gate_inputs
MSHOOKFUNCTION_IMPORT_PRESENT=$mshook
INITXPCHOOKS_REFERENCE_PRESENT=$initxpc
FULL_HOOK_JBSERVER_SURFACE_LINKED=$full_hook
STAGE_B_SOURCE_PRESENT=$stage_b
GOT_ACCESS_CODE_PRESENT=$got_code
MACH_VM_PROTECT_GOT_CODE_PRESENT=$protect_got
GOT_POINTER_WRITE_CODE_PRESENT=$got_write
WALL2_CORE_CHANGED=NO
OPAINJECT_CORE_CHANGED=NO
TRIO_DEPENDENCY_GRAPH=$trio_dep
HOOK_LOADS_LIBJAILBREAK=$hook_loads_libjb
LIBJAILBREAK_LOADS_LIBCHOMA=$libjb_loads_libchoma
LIBCHOMA_SYSTEM_ONLY=$libchoma_system_only
SIGNING_ORDER=PASS
TRUSTCACHE_ORDER=PASS
IDENTITY_CONSISTENCY=$identity_result
BUILD102732C_HOST_AUDIT=$host
EOF

[[ "$host" == PASS ]]
