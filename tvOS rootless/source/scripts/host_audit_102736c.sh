#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
IPA="${1:?usage: host_audit_102736c.sh <ipa-path>}"
LDID="${LDID:-/opt/local/bin/ldid}"

EXPECTED_HOOK_SHA="e975a8b9491543df47194139af290d3a641e2316748e61330008df45d2a3cf1f"
EXPECTED_LIBJB_SHA="9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79"
EXPECTED_LIBCHOMA_SHA="40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q -o "$IPA" -d "$tmp"

APP_DIR="$tmp/Payload/dopamin-tvOS-kfd.app"
APP="$APP_DIR/dopamin-tvOS-kfd"
APP_PLIST="$APP_DIR/Info.plist"
H516="$APP_DIR/Handoff516"
HOOK="$H516/launchdhook516.dylib"
LIBJB="$H516/libjailbreak.dylib"
LIBCHOMA="$H516/libchoma.dylib"
OPAINJECT="$H516/dt_opainject516"
JBCTL="$H516/dt_jbctl516"
MANIFEST="$H516/BUILD102736C_RESOURCE_MANIFEST.txt"
APP_STRINGS="$tmp/app_strings.txt"
HELPER_STRINGS="$tmp/helper_strings.txt"
ALL_STRINGS="$tmp/all_strings.txt"

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

[[ -f "$APP" && -f "$HOOK" && -f "$LIBJB" && -f "$LIBCHOMA" && -f "$OPAINJECT" && -f "$JBCTL" ]]

CFBUNDLEVERSION="$(plutil -extract CFBundleVersion raw "$APP_PLIST" 2>/dev/null || true)"
HOOK_SHA="$(sha "$HOOK")"
LIBJB_SHA="$(sha "$LIBJB")"
LIBCHOMA_SHA="$(sha "$LIBCHOMA")"
OPAINJECT_SHA="$(sha "$OPAINJECT")"
JBCTL_SHA="$(sha "$JBCTL")"

strings "$APP" > "$APP_STRINGS"
strings "$OPAINJECT" > "$HELPER_STRINGS"
strings "$APP" "$HOOK" "$LIBJB" "$LIBCHOMA" "$OPAINJECT" "$JBCTL" > "$ALL_STRINGS"

manifest_result=FAIL
if [[ -f "$MANIFEST" ]] \
    && rg -q "^CFBundleVersion=102736$" "$MANIFEST" \
    && rg -q "^launchdhook516\\.dylib=$EXPECTED_HOOK_SHA$" "$MANIFEST" \
    && rg -q "^libjailbreak\\.dylib=$EXPECTED_LIBJB_SHA$" "$MANIFEST" \
    && rg -q "^libchoma\\.dylib=$EXPECTED_LIBCHOMA_SHA$" "$MANIFEST"; then
    manifest_result=PASS
fi

frozen_artifacts=FAIL
if [[ "$HOOK_SHA" == "$EXPECTED_HOOK_SHA" \
    && "$LIBJB_SHA" == "$EXPECTED_LIBJB_SHA" \
    && "$LIBCHOMA_SHA" == "$EXPECTED_LIBCHOMA_SHA" ]]; then
    frozen_artifacts=PASS
fi

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

eval "$(python3 - "$HOOK" <<'PY'
import struct, sys, uuid
p = sys.argv[1]
b = open(p, 'rb').read()
mod_size = init_size = 0
mod_count = init_count = 0
has_mod = "NO"
has_init = "NO"
lc_uuid = "UNAVAILABLE"
if len(b) >= 32:
    mh = struct.unpack_from("<IiiIIII", b, 0)
    ncmds = mh[4]
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", b, off)
        if cmd == 0x1b and cmdsize >= 24:
            lc_uuid = str(uuid.UUID(bytes=b[off + 8:off + 24])).upper()
        if cmd == 0x19 and cmdsize >= 72:
            nsects = struct.unpack_from("<II16sQQQQiiII", b, off)[9]
            sect_off = off + 72
            for _ in range(nsects):
                sectname, segname, addr, size, offset, align, reloff, nreloc, flags, r1, r2, r3 = struct.unpack_from("<16s16sQQIIIIIIII", b, sect_off)
                sect = sectname.rstrip(b"\0").decode("ascii", "replace")
                if sect == "__mod_init_func":
                    has_mod = "YES"
                    mod_size += size
                    mod_count += size // 8 if size % 8 == 0 else -999999
                if sect == "__init_offsets":
                    has_init = "YES"
                    init_size += size
                    init_count += size // 4 if size % 4 == 0 else -999999
                sect_off += 80
        off += cmdsize
print(f"HOOK_LC_UUID='{lc_uuid}'")
print(f"HAS_MOD_INIT_FUNC='{has_mod}'")
print(f"MOD_INIT_FUNC_SIZE='{mod_size}'")
print(f"MOD_INIT_FUNC_ENTRY_COUNT='{mod_count}'")
print(f"HAS_INIT_OFFSETS='{has_init}'")
print(f"INIT_OFFSETS_SIZE='{init_size}'")
print(f"INIT_OFFSETS_ENTRY_COUNT='{init_count}'")
print(f"TOTAL_LOGICAL_CONSTRUCTOR_COUNT='{mod_count + init_count}'")
PY
)"

constructor_result=FAIL
if [[ "$TOTAL_LOGICAL_CONSTRUCTOR_COUNT" == "1" && "$HAS_INIT_OFFSETS" == YES ]]; then
    constructor_result=PASS
fi

helper_entitlements=FAIL
if [[ -x "$LDID" ]] \
    && "$LDID" -e "$OPAINJECT" | rg -q "task_for_pid-allow" \
    && "$LDID" -e "$OPAINJECT" | rg -q "platform-application" \
    && "$LDID" -e "$OPAINJECT" | rg -q "com.apple.system-task-ports"; then
    helper_entitlements=PASS
fi

app_markers=FAIL
if rg -q "BUILD102736C_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR" "$APP_STRINGS" \
    && rg -q "BUILD102736C_HELPER_TRUST_INCLUDED=YES" "$APP_STRINGS" \
    && rg -q "BUILD102736C_TRUSTCACHE_ENTRY_COUNT" "$APP_STRINGS" \
    && rg -q "BUILD102736C_OPAINJECT_TRUSTCACHE_PRESENT" "$APP_STRINGS" \
    && rg -q "BUILD102736C_OPAINJECT_WAIT_STATUS" "$APP_STRINGS" \
    && rg -q "BUILD102736C_OPAINJECT_EXIT_CODE" "$APP_STRINGS" \
    && rg -q "BUILD102736C_REMOTE_DLOPEN_RC" "$APP_STRINGS" \
    && rg -q "BUILD102735D_TRACE_PREFLIGHT" "$APP_STRINGS"; then
    app_markers=PASS
fi

helper_markers=FAIL
if rg -q "BUILD102736C_TASK_FOR_PID_SYMBOL_ADDRESS" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_TASK_FOR_PID_OUTPUT_BEFORE" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_TASK_FOR_PID_OUTPUT_CHANGED" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_MACH_PORT_TYPE_RC" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_TASK_PORT_HAS_SEND_RIGHT" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_TASK_INFO_RC" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_TARGET_PID_PATH" "$HELPER_STRINGS" \
    && rg -q "BUILD102736C_REMOTE_DLOPEN_RC" "$HELPER_STRINGS"; then
    helper_markers=PASS
fi

mshook="$(yesno_rg 'MSHookFunction' "$ALL_STRINGS")"
initxpc="$(yesno_rg 'initXPCHooks' "$ALL_STRINGS")"
full_hook="$(yesno_rg 'jbserver_received_|initXPCHooks|MSHookFunction' "$ALL_STRINGS")"
stage_b="$(yesno_rg 'BUILD102724_PHASE_B_REACHED|PHASE_B_LAUNCHD_TEST=BEGIN|STAGE_B_ACTIVE=YES' "$ALL_STRINGS")"
got_code="$(yesno_rg '0x65018|GOT_DELTA|GOT_WRITE|GOT_POINTER_WRITTEN=YES|LAUNCHD_GOT' "$ALL_STRINGS")"
protect_got="$(yesno_rg 'MACH_VM_PROTECT_GOT_CALLED=YES|mach_vm_protect.*GOT' "$ALL_STRINGS")"
got_write="$(yesno_rg 'GOT_POINTER_WRITTEN=YES|proc_vwritebuf|vwritebuf GOT' "$ALL_STRINGS")"

identity_result="$(bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$IPA" | awk -F= '/^IDENTITY_CONSISTENCY=/{print $2}')"

host=PASS
[[ "$CFBUNDLEVERSION" == "102736" ]] || host=FAIL
[[ "$manifest_result" == PASS ]] || host=FAIL
[[ "$frozen_artifacts" == PASS ]] || host=FAIL
[[ "$trio_dep" == PASS ]] || host=FAIL
[[ "$constructor_result" == PASS ]] || host=FAIL
[[ "$helper_entitlements" == PASS ]] || host=FAIL
[[ "$app_markers" == PASS ]] || host=FAIL
[[ "$helper_markers" == PASS ]] || host=FAIL
[[ "$mshook" == NO ]] || host=FAIL
[[ "$initxpc" == NO ]] || host=FAIL
[[ "$full_hook" == NO ]] || host=FAIL
[[ "$stage_b" == NO ]] || host=FAIL
[[ "$got_code" == NO ]] || host=FAIL
[[ "$protect_got" == NO ]] || host=FAIL
[[ "$got_write" == NO ]] || host=FAIL
[[ "$identity_result" == PASS ]] || host=FAIL

cat <<EOF
BUILD102736C_HOST_AUDIT_REPORT
IPA=$IPA
CFBUNDLEVERSION=$CFBUNDLEVERSION
HOOK_SHA256=$HOOK_SHA
LIBJAILBREAK_SHA256=$LIBJB_SHA
LIBCHOMA_SHA256=$LIBCHOMA_SHA
OPAINJECT_SHA256=$OPAINJECT_SHA
JBCTL_SHA256=$JBCTL_SHA
RESOURCE_MANIFEST=$manifest_result
FROZEN_102735D_HOOK_AND_APPROVED_LIBS=$frozen_artifacts
HOOK_LC_UUID=$HOOK_LC_UUID
HAS_MOD_INIT_FUNC=$HAS_MOD_INIT_FUNC
MOD_INIT_FUNC_SIZE=$MOD_INIT_FUNC_SIZE
MOD_INIT_FUNC_ENTRY_COUNT=$MOD_INIT_FUNC_ENTRY_COUNT
HAS_INIT_OFFSETS=$HAS_INIT_OFFSETS
INIT_OFFSETS_SIZE=$INIT_OFFSETS_SIZE
INIT_OFFSETS_ENTRY_COUNT=$INIT_OFFSETS_ENTRY_COUNT
TOTAL_LOGICAL_CONSTRUCTOR_COUNT=$TOTAL_LOGICAL_CONSTRUCTOR_COUNT
CONSTRUCTOR_VALIDATION=$constructor_result
HELPER_ENTITLEMENTS=$helper_entitlements
APP_102736_MARKERS=$app_markers
HELPER_102736_MARKERS=$helper_markers
TRIO_DEPENDENCY_GRAPH=$trio_dep
HOOK_LOADS_LIBJAILBREAK=$hook_loads_libjb
LIBJAILBREAK_LOADS_LIBCHOMA=$libjb_loads_libchoma
LIBCHOMA_SYSTEM_ONLY=$libchoma_system_only
MSHOOKFUNCTION_IMPORT_PRESENT=$mshook
INITXPCHOOKS_REFERENCE_PRESENT=$initxpc
FULL_HOOK_JBSERVER_SURFACE_LINKED=$full_hook
STAGE_B_SOURCE_PRESENT=$stage_b
GOT_ACCESS_CODE_PRESENT=$got_code
MACH_VM_PROTECT_GOT_CODE_PRESENT=$protect_got
GOT_POINTER_WRITE_CODE_PRESENT=$got_write
IDENTITY_CONSISTENCY=$identity_result
BUILD102736C_HOST_AUDIT=$host
EOF

[[ "$host" == PASS ]]
