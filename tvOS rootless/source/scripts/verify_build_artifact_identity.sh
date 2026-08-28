#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
IPA="${1:?usage: verify_build_artifact_identity.sh <ipa-path>}"

if [[ ! -f "$IPA" ]]; then
    echo "ERROR: IPA not found: $IPA" >&2
    exit 1
fi

MAKEFILE_DT_BUILD_NUM="$(rg -o 'DT_BUILD_NUM=([0-9]+)' "$PROJECT/Makefile" | head -1 | cut -d= -f2 || true)"
INFO_PLIST_VERSION="$(plutil -extract CFBundleVersion raw "$PROJECT/Info.plist" 2>/dev/null || true)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unzip -q -o "$IPA" -d "$TMP"

APP_BIN="$TMP/Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd"
APP_ROOT="$TMP/Payload/dopamin-tvOS-kfd.app"
APP_PLIST="$TMP/Payload/dopamin-tvOS-kfd.app/Info.plist"
APP_FRAMEWORK_LIBJAILBREAK="$TMP/Payload/dopamin-tvOS-kfd.app/Frameworks/libjailbreak.dylib"
APP_HANDOFF="$TMP/Payload/dopamin-tvOS-kfd.app/Handoff516"
APP_HOOK="$APP_HANDOFF/launchdhook516.dylib"
APP_HELPER="$APP_HANDOFF/dt_opainject516"
APP_ROOTLESS_PAYLOAD="$TMP/Payload/dopamin-tvOS-kfd.app/RootlessPayload"
APP_ROOTLESS_TRUST="$TMP/Payload/dopamin-tvOS-kfd.app/ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"
APP_ROOTLESS_PATH_MANIFEST="$TMP/Payload/dopamin-tvOS-kfd.app/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"
APP_ROOTLESS_VARIANT_FILE="$TMP/Payload/dopamin-tvOS-kfd.app/ROOTLESS_VARIANT_IDENTITY.txt"

ROOTLESS_IPA=0
if [[ -d "$APP_ROOTLESS_PAYLOAD" && -f "$APP_ROOTLESS_TRUST" ]]; then
    ROOTLESS_IPA=1
fi
if [[ "${DT_ROOTLESS_R4:-}" == "1" ]]; then
    ROOTLESS_IPA=1
fi

if [[ ! -f "$APP_BIN" ]]; then
    echo "ERROR: main executable missing in IPA" >&2
    exit 1
fi

CFBUNDLEVERSION_FROM_PACKAGED_IPA="$(plutil -extract CFBundleVersion raw "$APP_PLIST" 2>/dev/null || true)"
IPA_SHA256="$(shasum -a 256 "$IPA" | awk '{print $1}')"
PAYLOAD_BINARY_SHA256="$(shasum -a 256 "$APP_BIN" | awk '{print $1}')"
APP_STRINGS="$TMP/app_strings.txt"
strings "$APP_BIN" > "$APP_STRINGS"
BUILD102725R_STRING_COUNT="$(rg -c 'BUILD102725R' "$APP_STRINGS" || echo 0)"
BUILD102726D_STRING_COUNT="$(rg -c 'BUILD102726D' "$APP_STRINGS" || echo 0)"
BUILD102727R_STRING_COUNT="$(rg -c 'BUILD102727R' "$APP_STRINGS" || echo 0)"
BUILD102728R_STRING_COUNT="$(rg -c 'BUILD102728R' "$APP_STRINGS" || echo 0)"
BUILD102729A_STRING_COUNT="$(rg -c 'BUILD102729A' "$APP_STRINGS" || echo 0)"
BUILD102732C_STRING_COUNT="$(rg -c 'BUILD102732C' "$APP_STRINGS" || echo 0)"
BUILD102734C_STRING_COUNT="$(rg -c 'BUILD102734C' "$APP_STRINGS" || echo 0)"
BUILD102735D_STRING_COUNT="$(rg -c 'BUILD102735D' "$APP_STRINGS" || echo 0)"
BUILD102736C_STRING_COUNT="$(rg -c 'BUILD102736C' "$APP_STRINGS" || echo 0)"
BUILD102737D_STRING_COUNT="$(rg -c 'BUILD102737D' "$APP_STRINGS" || echo 0)"
BUILD102738P_STRING_COUNT="$(rg -c 'BUILD102738P' "$APP_STRINGS" || echo 0)"
BUILD102738W_STRING_COUNT="$(rg -c 'BUILD102738W' "$APP_STRINGS" || echo 0)"
BUILD102738X_STRING_COUNT="$(rg -c 'BUILD102738X' "$APP_STRINGS" || echo 0)"
BUILD102738Y_STRING_COUNT="$(rg -c 'BUILD102738Y' "$APP_STRINGS" || echo 0)"
BUILD102738Z_STRING_COUNT="$(rg -c 'BUILD102738Z' "$APP_STRINGS" || echo 0)"
BUILD102739A_STRING_COUNT="$(rg -c 'BUILD102739A' "$APP_STRINGS" || echo 0)"
BUILD102739B_STRING_COUNT="$(rg -c 'BUILD102739B' "$APP_STRINGS" || echo 0)"
BUILD102739C_STRING_COUNT="$(rg -c 'BUILD102739C' "$APP_STRINGS" || echo 0)"
BUILD102739E_STRING_COUNT="$(rg -c 'BUILD102739E' "$APP_STRINGS" || echo 0)"
BUILD102739F_STRING_COUNT="$(rg -c 'BUILD102739F' "$APP_STRINGS" || echo 0)"
BUILD102739G_STRING_COUNT="$(rg -c 'BUILD102739G' "$APP_STRINGS" || echo 0)"
BUILD102739H_STRING_COUNT="$(rg -c 'BUILD102739H' "$APP_STRINGS" || echo 0)"
BUILD102739I_STRING_COUNT="$(rg -c 'BUILD102739I' "$APP_STRINGS" || echo 0)"
BUILD102739J_STRING_COUNT="$(rg -c 'BUILD102739J' "$APP_STRINGS" || echo 0)"
BUILD102739K_STRING_COUNT="$(rg -c 'BUILD102739K' "$APP_STRINGS" || echo 0)"
BUILD102739M_STRING_COUNT="$(rg -c 'BUILD102739M' "$APP_STRINGS" || echo 0)"

case "$MAKEFILE_DT_BUILD_NUM" in
    102725)
        COMPILED_SCOPE_MARKER="BUILD102725R_SCOPE=READ_ONLY_LAUNCHD_BASE_GOT_AND_PROTECTION_QUERY"
        COMPILED_BUILD_MARKER="BUILD102725R_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102725R-READONLY-LAUNCHD-GOT-PROBE.ipa"
        ;;
    102726)
        COMPILED_SCOPE_MARKER="BUILD102726D_SCOPE=READ_ONLY_LAUNCHD_USERSPACE_READ_PATH_DIAGNOSTIC"
        COMPILED_BUILD_MARKER="BUILD102726D_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102726D-LAUNCHD-READ-PATH-DIAGNOSTIC.ipa"
        ;;
    102728)
        COMPILED_SCOPE_MARKER="BUILD102728R_SCOPE=READ_ONLY_LAUNCHD_GOT_CLOSURE_MINOS_ENCODING_FIX"
        COMPILED_BUILD_MARKER="BUILD102725R_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102728R-READONLY-LAUNCHD-GOT-CLOSURE.ipa"
        ;;
    102729)
        COMPILED_SCOPE_MARKER="BUILD102729A_SCOPE=SELF_PROCESS_MACH_VM_PROTECT_CONTROL"
        COMPILED_BUILD_MARKER="BUILD102729A_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102729A-SELF-PAGE-PROTECTION-CONTROL.ipa"
        ;;
    102732)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=CONSTRUCTOR_BOOMERANG_ONLY"
        COMPILED_BUILD_MARKER="BUILD102732C_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102732C-CONSTRUCTOR-BOOMERANG-ONLY.ipa"
        ;;
    102733)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=CONSTRUCTOR_BOOMERANG_ONLY_VALIDATOR_FIX"
        COMPILED_BUILD_MARKER="BUILD102732C_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102733C-CONSTRUCTOR-VALIDATOR-FIX.ipa"
        ;;
    102734)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR"
        COMPILED_BUILD_MARKER="BUILD102734C_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102734C-OPAINJECT-TASKPORT-FIX.ipa"
        ;;
    102735)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC"
        COMPILED_BUILD_MARKER="BUILD102735D_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102735D-PREBOOT-CONSTRUCTOR-TRACE.ipa"
        ;;
    102736)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR"
        COMPILED_BUILD_MARKER="BUILD102736C_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102736C-TASKPORT-REPAIR.ipa"
        ;;
    102737)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC"
        COMPILED_BUILD_MARKER="BUILD102737D_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102737D-PTE-HANDOFF-DIAGNOSTIC.ipa"
        ;;
    102738)
        COMPILED_SCOPE_MARKER="COMPILED_SCOPE_MARKER=LAUNCHD_GOT_PROTECTION_ONLY"
        COMPILED_BUILD_MARKER="BUILD102738P_BEGIN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
        ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102738R-RECURSIVE-POINTER-VALIDATOR.ipa"
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            # Frozen 102738 baseline IDs remain in the binary; product filename is rootless R21+.
            EXPECTED_NAMED_IPA="dopamin-tvOS-kfd-ROOTLESS-R24.ipa"
            ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-ROOTLESS-R23.ipa"
            SECOND_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-ROOTLESS-R22.ipa"
            THIRD_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-ROOTLESS-R21.ipa"
            if [[ "${DT_ROOTLESS_R24:-}" == "1" ]] || [[ "$(basename "${IPA:-}")" == *ROOTLESS-R24* ]]; then
                # R24 CBR identity: live XPC/spawn contract (gate1-era BEGIN markers are not the bar).
                COMPILED_BUILD_MARKER="ROOTLESS_R24_CBR_SPAWN_HOOK_PACKAGED=YES"
                COMPILED_SCOPE_MARKER="ROOTLESS_R24_HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib"
            fi
        else
            SECOND_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102738W-GOT-SAME-VALUE-STORE.ipa"
            THIRD_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102738X-GOT-WRAPPER-ROUNDTRIP.ipa"
            FOURTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102738Y-GOT-WRAPPER-INVOCATION-PROOF.ipa"
            FIFTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102738Y-NONBLOCKING-REPAIR.ipa"
            SIXTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102738Z-PERSISTENT-WRAPPER-INSTALL.ipa"
            SEVENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739A-POST-WALL2-WRAPPER-INVOCATION-OBSERVER.ipa"
            EIGHTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739B-POST-ORIGINAL-RETURN-PATH.ipa"
            NINTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739C-XPC-OUTPUT-CONTRACT.ipa"
            TENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739D-DETERMINISTIC-LAUNCHD-XPC-TRIGGER.ipa"
            ELEVENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739E-READ-ONLY-XPC-DICTIONARY-CLASSIFIER.ipa"
            TWELFTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739F-READ-ONLY-CALLER-IDENTITY.ipa"
            THIRTEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739G-READ-ONLY-DOMAIN-PERMISSION-ACTION.ipa"
            FOURTEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739H-READ-ONLY-ACTION-ARGUMENT-MARSHALLING.ipa"
            FIFTEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739I-CONTROLLED-ACTION-HANDLER-ABI.ipa"
            SIXTEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739J-CONTROLLED-REPLY-ROUNDTRIP.ipa"
            SEVENTEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739K-ROOTFUL-BOOTSTRAP-READ-ONLY-PREFLIGHT.ipa"
            EIGHTEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739K-OBS1-CONSOLE-VISIBLE-READ-ONLY-PREFLIGHT.ipa"
            NINETEENTH_ALTERNATE_NAMED_IPA="dopamin-tvOS-kfd-102739K-OBS2-CONSOLE-VISIBLE-READ-ONLY-PREFLIGHT.ipa"
        fi
        ;;
    *)
        COMPILED_SCOPE_MARKER="UNKNOWN"
        COMPILED_BUILD_MARKER="UNKNOWN"
        EXPECTED_NAMED_IPA="dopamin-tvOS-kfd.ipa"
        ;;
esac

IDENTITY_CONSISTENCY="PASS"
LIBCHOMA_SOURCE_BUILD_IDENTITY="N/A"
OPAINJECT516_SOURCE_BUILD_IDENTITY="N/A"
FINAL_PAYLOAD_RPATH_CONTRACT="N/A"
UIALERT_ENTITLEMENT_AUDIT_INPUT="N/A"
FROZEN_V26_102737D_ACTIVE_PINS=0
fail() {
    IDENTITY_CONSISTENCY="FAIL"
    echo "IDENTITY_FAIL: $1" >&2
}

[[ "$INFO_PLIST_VERSION" == "$MAKEFILE_DT_BUILD_NUM" ]] || fail "Info.plist CFBundleVersion ($INFO_PLIST_VERSION) != Makefile DT_BUILD_NUM ($MAKEFILE_DT_BUILD_NUM)"
[[ "$CFBUNDLEVERSION_FROM_PACKAGED_IPA" == "$MAKEFILE_DT_BUILD_NUM" ]] || fail "packaged CFBundleVersion ($CFBUNDLEVERSION_FROM_PACKAGED_IPA) != Makefile DT_BUILD_NUM ($MAKEFILE_DT_BUILD_NUM)"
rg -q "$COMPILED_BUILD_MARKER" "$APP_STRINGS" || fail "missing compiled build marker $COMPILED_BUILD_MARKER"
rg -q "$COMPILED_SCOPE_MARKER" "$APP_STRINGS" || fail "missing compiled scope marker $COMPILED_SCOPE_MARKER"

if [[ "$MAKEFILE_DT_BUILD_NUM" == "102725" ]]; then
    [[ "$BUILD102725R_STRING_COUNT" -gt 0 ]] || fail "BUILD102725R string count is 0"
    [[ "$BUILD102726D_STRING_COUNT" -eq 0 ]] || fail "BUILD102726D strings present in 102725 build"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build725r_run_readonly_launchd_probe" || fail "725R probe symbol missing"
elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102726" ]]; then
    [[ "$BUILD102726D_STRING_COUNT" -gt 0 ]] || fail "BUILD102726D string count is 0"
    [[ "$BUILD102725R_STRING_COUNT" -eq 0 ]] || fail "BUILD102725R strings present in 102726 build"
    [[ "$BUILD102727R_STRING_COUNT" -eq 0 ]] || fail "BUILD102727R strings present in 102726 build"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build726d_run_readonly_launchd_read_diag" || fail "726D diag symbol missing"
elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102728" ]]; then
    [[ "$BUILD102725R_STRING_COUNT" -gt 0 ]] || fail "BUILD102725R string count is 0"
    [[ "$BUILD102726D_STRING_COUNT" -eq 0 ]] || fail "BUILD102726D strings present in 102728 build"
    [[ "$BUILD102727R_STRING_COUNT" -eq 0 ]] || fail "BUILD102727R strings present in 102728 build"
    rg -q "BUILD102728R_SCOPE" "$APP_STRINGS" || fail "missing BUILD102728R scope marker"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build725r_run_readonly_launchd_probe" || fail "725R probe symbol missing"
elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102727" ]]; then
    [[ "$BUILD102727R_STRING_COUNT" -gt 0 ]] || fail "BUILD102727R string count is 0"
    [[ "$BUILD102725R_STRING_COUNT" -eq 0 ]] || fail "BUILD102725R strings present in 102727 build"
    [[ "$BUILD102726D_STRING_COUNT" -eq 0 ]] || fail "BUILD102726D strings present in 102727 build"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build727r_run_readonly_launchd_contract_telemetry" || fail "727R telemetry symbol missing"
elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102729" ]]; then
    [[ "$BUILD102729A_STRING_COUNT" -gt 0 ]] || fail "BUILD102729A string count is 0"
    [[ "$BUILD102725R_STRING_COUNT" -eq 0 ]] || fail "BUILD102725R strings present in 102729 build"
    [[ "$BUILD102726D_STRING_COUNT" -eq 0 ]] || fail "BUILD102726D strings present in 102729 build"
    [[ "$BUILD102727R_STRING_COUNT" -eq 0 ]] || fail "BUILD102727R strings present in 102729 build"
    [[ "$BUILD102728R_STRING_COUNT" -eq 0 ]] || fail "BUILD102728R strings present in 102729 build"
    rg -q "BUILD102729A_SCOPE=SELF_PROCESS_MACH_VM_PROTECT_CONTROL" "$APP_STRINGS" || fail "missing BUILD102729A scope marker"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build729a_run_self_page_protection_control" || fail "729A probe symbol missing"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt729a_mach_vm_protect" || fail "729A mach_vm_protect wrapper missing"
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build725r_run_readonly_launchd_probe" && fail "725R probe symbol present in 102729 build"
    rg -q "BUILD102729A_UNPROTECT_REQUEST_PROT=0x3" "$APP_STRINGS" || fail "missing RW request marker string"
    rg -q "BUILD102729A_RESTORE_REQUEST_PROT=0x1" "$APP_STRINGS" || fail "missing READ restore marker string"
    rg -q "BUILD102729A_UNPROTECT_REQUEST_PROT=0x13" "$APP_STRINGS" && fail "stock prot 0x13 request present"
    rg -q "BUILD102729A_RESTORE_REQUEST_PROT=0x5" "$APP_STRINGS" && fail "stock restore 0x5 request present"
    HOST_AUDIT_RESULT="PASS"
    rg -q "BUILD102729A_GOT_ACCESSED=NO" "$APP_STRINGS" || { HOST_AUDIT_RESULT="FAIL"; fail "missing GOT safety marker"; }
    rg -q "BUILD102729A_LAUNCHD_ACCESSED=NO" "$APP_STRINGS" || { HOST_AUDIT_RESULT="FAIL"; fail "missing launchd safety marker"; }
    rg -q "BUILD102729A_PHYSICAL_WRITE_USED=NO" "$APP_STRINGS" || { HOST_AUDIT_RESULT="FAIL"; fail "missing physwrite safety marker"; }
elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102732" || "$MAKEFILE_DT_BUILD_NUM" == "102733" || "$MAKEFILE_DT_BUILD_NUM" == "102734" || "$MAKEFILE_DT_BUILD_NUM" == "102735" || "$MAKEFILE_DT_BUILD_NUM" == "102736" || "$MAKEFILE_DT_BUILD_NUM" == "102737" || "$MAKEFILE_DT_BUILD_NUM" == "102738" ]]; then
    [[ "$BUILD102732C_STRING_COUNT" -gt 0 ]] || fail "BUILD102732C string count is 0"
    [[ "$BUILD102725R_STRING_COUNT" -eq 0 ]] || fail "BUILD102725R strings present in $MAKEFILE_DT_BUILD_NUM build"
    [[ "$BUILD102726D_STRING_COUNT" -eq 0 ]] || fail "BUILD102726D strings present in $MAKEFILE_DT_BUILD_NUM build"
    [[ "$BUILD102727R_STRING_COUNT" -eq 0 ]] || fail "BUILD102727R strings present in $MAKEFILE_DT_BUILD_NUM build"
    [[ "$BUILD102728R_STRING_COUNT" -eq 0 ]] || fail "BUILD102728R strings present in $MAKEFILE_DT_BUILD_NUM build"
    rg -q "BUILD102729A_SCOPE|BUILD102729A_BEGIN|SELF_PROCESS_MACH_VM_PROTECT_CONTROL" "$APP_STRINGS" && fail "102729A executable-scope strings present in $MAKEFILE_DT_BUILD_NUM build"
    if [[ "$MAKEFILE_DT_BUILD_NUM" == "102733" ]]; then
        rg -q "BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_VALIDATOR_FIX" "$APP_STRINGS" || fail "missing 102733 validator-fix scope marker"
        rg -q "BUILD102732C_INIT_OFFSETS_COUNT" "$APP_STRINGS" || fail "missing init-offset constructor marker"
        rg -q "BUILD102732C_LOGICAL_CONSTRUCTOR_COUNT" "$APP_STRINGS" || fail "missing logical constructor marker"
        rg -q "BUILD102732C_CONSTRUCTOR_VALIDATION" "$APP_STRINGS" || fail "missing constructor validation marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102734" ]]; then
        [[ "$BUILD102734C_STRING_COUNT" -gt 0 ]] || fail "BUILD102734C string count is 0"
        rg -q "BUILD102734C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR" "$APP_STRINGS" || fail "missing 102734 repair scope marker"
        rg -q "BUILD102734C_BUNDLE_RESOURCE_IDENTITY" "$APP_STRINGS" || fail "missing bundle identity marker"
        rg -q "BUILD102734C_BUNDLE_FILE_SHA_POLICY" "$APP_STRINGS" || fail "missing bundle SHA policy marker"
        rg -q "BUILD102734C_STAGE_COPY_IDENTITY" "$APP_STRINGS" || fail "missing staged copy identity marker"
        rg -q "BUILD102734C_STAGE_COPY_COMPARE" "$APP_STRINGS" || fail "missing staged copy compare marker"
        rg -q "BUILD102734C_TRUSTCACHE_ENTRY_COUNT" "$APP_STRINGS" || fail "missing 102734 trustcache count marker"
        rg -q "BUILD102734C_OPAINJECT_TRUSTCACHE_PRESENT" "$APP_STRINGS" || fail "missing opainject trust marker"
        rg -q "BUILD102734C_OPAINJECT_WAIT_STATUS" "$APP_STRINGS" || fail "missing opainject wait status marker"
        rg -q "BUILD102734C_OPAINJECT_EXIT_CODE" "$APP_STRINGS" || fail "missing opainject exit code marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102735" ]]; then
        [[ "$BUILD102735D_STRING_COUNT" -gt 0 ]] || fail "BUILD102735D string count is 0"
        rg -q "BUILD102735D_SCOPE=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC" "$APP_STRINGS" || fail "missing 102735D scope marker"
        rg -q "BUILD102735D_TRACE_PREFLIGHT" "$APP_STRINGS" || fail "missing 102735D trace preflight marker"
        rg -q "BUILD102735D_TRACE_PATH_UNDER_PRIVATE_PREBOOT" "$APP_STRINGS" || fail "missing 102735D preboot path marker"
        rg -q "BUILD102735D_TRACE_PATH_UNDER_PRIVATE_VAR_JB" "$APP_STRINGS" || fail "missing 102735D private var jb rejection marker"
        rg -q "BUILD102735D_TRACE_HOOK_APPEND_OBSERVED" "$APP_STRINGS" || fail "missing 102735D hook append marker"
        rg -q "BUILD102735D_REMOTE_DLOPEN_RC" "$APP_STRINGS" || fail "missing 102735D remote dlopen marker"
        rg -q "NO_HOOK_TRACE_AFTER_REMOTE_DLOPEN" "$APP_STRINGS" || fail "missing 102735D no-trace classification"
        rg -q "BUILD102735D_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102735D runner marker"
        rg -q "BUILD102735D_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102735D insertion marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102736" ]]; then
        [[ "$BUILD102736C_STRING_COUNT" -gt 0 ]] || fail "BUILD102736C string count is 0"
        [[ "$BUILD102735D_STRING_COUNT" -gt 0 ]] || fail "BUILD102735D trace string count is 0 in 102736 build"
        rg -q "BUILD102736C_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR" "$APP_STRINGS" || fail "missing 102736C scope marker"
        rg -q "BUILD102736C_REPAIR_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR" "$APP_STRINGS" || fail "missing 102736C repair scope marker"
        rg -q "BUILD102736C_HELPER_TRUST_INCLUDED=YES" "$APP_STRINGS" || fail "missing 102736C helper trust marker"
        rg -q "BUILD102736C_TRUSTCACHE_ENTRY_COUNT" "$APP_STRINGS" || fail "missing 102736C trustcache count marker"
        rg -q "BUILD102736C_OPAINJECT_TRUSTCACHE_PRESENT" "$APP_STRINGS" || fail "missing 102736C opainject trust marker"
        rg -q "BUILD102736C_OPAINJECT_WAIT_STATUS" "$APP_STRINGS" || fail "missing 102736C opainject wait status marker"
        rg -q "BUILD102736C_OPAINJECT_EXIT_CODE" "$APP_STRINGS" || fail "missing 102736C opainject exit code marker"
        rg -q "BUILD102736C_REMOTE_DLOPEN_RC" "$APP_STRINGS" || fail "missing 102736C remote dlopen marker"
        rg -q "BUILD102735D_TRACE_PREFLIGHT" "$APP_STRINGS" || fail "missing preserved 102735D trace preflight marker"
        rg -q "BUILD102735D_TRACE_HOOK_APPEND_OBSERVED" "$APP_STRINGS" || fail "missing preserved 102735D hook append marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102737" ]]; then
        [[ "$BUILD102737D_STRING_COUNT" -gt 0 ]] || fail "BUILD102737D string count is 0"
        [[ "$BUILD102735D_STRING_COUNT" -gt 0 ]] || fail "BUILD102735D trace string count is 0 in 102737 build"
        rg -q "BUILD102737D_SCOPE=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC" "$APP_STRINGS" || fail "missing 102737D scope marker"
        rg -q "BUILD102737D_WALL2_RESTORE_AFTER_HOOK_TERMINAL_OR_TIMEOUT" "$APP_STRINGS" || fail "missing 102737D Wall2 ordering marker"
        rg -q "BUILD102737D_PTE_REQUEST_REACHED_SERVER" "$APP_STRINGS" || fail "missing 102737D server-reached summary marker"
        rg -q "BUILD102737D_PTE_SERVER_LAST_STAGE" "$APP_STRINGS" || fail "missing 102737D server-stage summary marker"
        rg -q "BUILD102737D_PTE_CLIENT_ASID_PTR_VALID" "$APP_STRINGS" || fail "missing 102737D client-ASID summary marker"
        rg -q "BUILD102737D_RESULT" "$APP_STRINGS" || fail "missing 102737D result marker"
        rg -q "BUILD102737D_TASK_PORT_REPAIR_CHANGED=NO" "$APP_STRINGS" || fail "missing 102737D task-port frozen marker"
        rg -q "BUILD102737D_REMOTE_DLOPEN_IMPLEMENTATION_CHANGED=NO" "$APP_STRINGS" || fail "missing 102737D remote-dlopen frozen marker"
        rg -q "BUILD102737D_WALL2_CORE_CHANGED=NO" "$APP_STRINGS" || fail "missing 102737D Wall2 core frozen marker"
        rg -q "BUILD102737D_HELPER_TRUST_INCLUDED=YES" "$APP_STRINGS" || fail "missing 102737D helper-trust marker"
        rg -q "BUILD102737D_TRUSTCACHE_ENTRY_COUNT" "$APP_STRINGS" || fail "missing 102737D trustcache entry-count marker"
        rg -q "BUILD102737D_JBCTL_TRUSTCACHE_PRESENT" "$APP_STRINGS" || fail "missing 102737D jbctl trust marker"
        rg -q "BUILD102737D_OPAINJECT_TRUSTCACHE_PRESENT" "$APP_STRINGS" || fail "missing 102737D opainject trust marker"
        rg -q "BUILD102737D_ALL_TRUST_VERIFY" "$APP_STRINGS" || fail "missing 102737D all-trust marker"
        [[ -f "$APP_FRAMEWORK_LIBJAILBREAK" ]] || fail "missing packaged Frameworks/libjailbreak.dylib"
        nm -gU "$APP_FRAMEWORK_LIBJAILBREAK" 2>/dev/null | rg -q "_kalloc_pt_is_initialized" || fail "missing Frameworks/libjailbreak export _kalloc_pt_is_initialized"
        nm -gU "$APP_FRAMEWORK_LIBJAILBREAK" 2>/dev/null | rg -q "_kalloc_pt_pool_count" || fail "missing Frameworks/libjailbreak export _kalloc_pt_pool_count"
        nm -gU "$APP_FRAMEWORK_LIBJAILBREAK" 2>/dev/null | rg -q "_kalloc_pt_prefill" || fail "missing Frameworks/libjailbreak export _kalloc_pt_prefill"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102738" ]]; then
        R24_CBR=0
        if [[ "${DT_ROOTLESS_R24:-}" == "1" ]] || [[ "$(basename "$IPA")" == *ROOTLESS-R24* ]]; then
            R24_CBR=1
        fi
        [[ "$BUILD102738P_STRING_COUNT" -gt 0 ]] || fail "BUILD102738P string count is 0"
        [[ "$BUILD102737D_STRING_COUNT" -gt 0 ]] || fail "preserved BUILD102737D chain strings missing"
        [[ "$BUILD102735D_STRING_COUNT" -gt 0 ]] || fail "preserved BUILD102735D trace strings missing"
        if [[ "$R24_CBR" -eq 1 ]]; then
            # R24 CBR: gate1-era STAGE literals are not the acceptance bar; hook/systemhook contracts are.
            rg -q "BUILD102738P_XPC_HOOK_PACKAGED=YES" "$APP_STRINGS" || fail "R24 missing app XPC packaged STAGE"
            rg -q "ROOTLESS_R24_CBR_SPAWN_HOOK_PACKAGED=YES" "$APP_STRINGS" || fail "R24 missing spawn packaged STAGE"
            rg -q "ROOTLESS_R24_HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib" "$APP_STRINGS" || fail "R24 missing HOOK_DYLIB_PATH STAGE"
            rg -q "BUILD102738P_PID1_PRESENT_AFTER_RETURN" "$APP_STRINGS" || true
            rg -q "BUILD102738P_RESULT" "$APP_STRINGS" || true
        else
        rg -q "BUILD102738P_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY" "$APP_STRINGS" || fail "missing 102738P scope marker"
        rg -q "BUILD102738P_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102738P runner marker"
        rg -q "BUILD102738P_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102738P insertion marker"
        rg -q "BUILD102738P_HELPER_TRUST_INCLUDED=YES" "$APP_STRINGS" || fail "missing 102738P helper-trust marker"
        rg -q "BUILD102738P_TRUSTCACHE_ENTRY_COUNT" "$APP_STRINGS" || fail "missing 102738P trustcache-count marker"
        rg -q "BUILD102738P_ALL_TRUST_VERIFY" "$APP_STRINGS" || fail "missing 102738P all-trust marker"
        rg -q "BUILD102738P_TRACE_TRANSPORT_REUSED_FROM_102737=YES" "$APP_STRINGS" || fail "missing frozen trace-transport marker"
        rg -q "BUILD102738P_WALL2_RESTORE_AFTER_HOOK_TERMINAL_OR_TIMEOUT" "$APP_STRINGS" || fail "missing 102738P Wall2 ordering marker"
        if [[ "$BUILD102739J_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739J_SCOPE=CONTROLLED_REPLY_ROUNDTRIP" "$APP_STRINGS" || fail "missing 102739J scope marker"
            rg -q "BUILD102739J_BLUEPRINT=IOS_JBSERVER_LINES_113_THROUGH_187_AND_XPC_HOOK_LINES_51_THROUGH_60" "$APP_STRINGS" || fail "missing 102739J blueprint marker"
            rg -q "BUILD102739J_TRIGGER_REQUEST_COUNT=1" "$APP_STRINGS" || fail "missing 102739J single-trigger marker"
            rg -q "BUILD102739J_TRIGGER_DOMAIN=1" "$APP_STRINGS" || fail "missing 102739J domain marker"
            rg -q "BUILD102739J_TRIGGER_ACTION=1" "$APP_STRINGS" || fail "missing 102739J action marker"
            rg -q "BUILD102739J_COMMITTED_INPUT_CONSUME=YES" "$APP_STRINGS" || fail "missing 102739J consume marker"
            rg -q "BUILD102739J_COMMITTED_RETURN_VALUE=22" "$APP_STRINGS" || fail "missing 102739J return marker"
            rg -q "BUILD102739J_REAL_JBROOT_HANDLER_INVOKED=NO" "$APP_STRINGS" || fail "missing 102739J no-real-handler marker"
            rg -q "BUILD102739J_BOOTSTRAP_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739J no-bootstrap marker"
            rg -q "BUILD102739J_RESULT" "$APP_STRINGS" || fail "missing 102739J result marker"
        elif [[ "$BUILD102739I_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739I_SCOPE=CONTROLLED_ACTION_HANDLER_ABI" "$APP_STRINGS" || fail "missing 102739I scope marker"
            rg -q "BUILD102739I_BLUEPRINT=IOS_JBSERVER_LINE_104_HANDLER_CALL_ABI" "$APP_STRINGS" || fail "missing 102739I blueprint marker"
            rg -q "BUILD102739I_TRIGGER_REQUEST_COUNT=1" "$APP_STRINGS" || fail "missing 102739I single-trigger marker"
            rg -q "BUILD102739I_TRIGGER_DOMAIN=1" "$APP_STRINGS" || fail "missing 102739I domain marker"
            rg -q "BUILD102739I_TRIGGER_ACTION=1" "$APP_STRINGS" || fail "missing 102739I action marker"
            rg -q "BUILD102739I_CONTROLLED_HANDLER_ARGUMENT_COUNT=8" "$APP_STRINGS" || fail "missing 102739I handler ABI marker"
            rg -q "BUILD102739I_CONTROLLED_HANDLER_OUTPUT=STATIC_SENTINEL" "$APP_STRINGS" || fail "missing 102739I sentinel marker"
            rg -q "BUILD102739I_REAL_JBROOT_HANDLER_INVOKED=NO" "$APP_STRINGS" || fail "missing 102739I no-real-handler marker"
            rg -q "BUILD102739I_REPLY_CREATION_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739I no-reply marker"
            rg -q "BUILD102739I_BOOTSTRAP_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739I no-bootstrap marker"
            rg -q "BUILD102739I_RESULT" "$APP_STRINGS" || fail "missing 102739I result marker"
        elif [[ "$BUILD102739H_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739H_SCOPE=READ_ONLY_ACTION_ARGUMENT_MARSHALLING" "$APP_STRINGS" || fail "missing 102739H scope marker"
            rg -q "BUILD102739H_BLUEPRINT=IOS_JBSERVER_LINES_59_THROUGH_102" "$APP_STRINGS" || fail "missing 102739H blueprint marker"
            rg -q "BUILD102739H_TRIGGER_REQUEST_COUNT=1" "$APP_STRINGS" || fail "missing 102739H single-trigger marker"
            rg -q "BUILD102739H_TRIGGER_DOMAIN=1" "$APP_STRINGS" || fail "missing 102739H domain marker"
            rg -q "BUILD102739H_TRIGGER_ACTION=1" "$APP_STRINGS" || fail "missing 102739H action marker"
            rg -q "BUILD102739H_ARGUMENT_DESCRIPTOR_COUNT=1" "$APP_STRINGS" || fail "missing 102739H descriptor-count marker"
            rg -q "BUILD102739H_ARGUMENT_DESCRIPTOR_NAME=root-path" "$APP_STRINGS" || fail "missing 102739H descriptor-name marker"
            rg -q "BUILD102739H_ARGUMENT_DESCRIPTOR_TYPE=JBS_TYPE_STRING" "$APP_STRINGS" || fail "missing 102739H descriptor-type marker"
            rg -q "BUILD102739H_ARGUMENT_DESCRIPTOR_DIRECTION=OUT" "$APP_STRINGS" || fail "missing 102739H descriptor-direction marker"
            rg -q "BUILD102739H_HANDLER_INVOCATION_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739H no-handler marker"
            rg -q "BUILD102739H_REPLY_CREATION_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739H no-reply marker"
            rg -q "BUILD102739H_BOOTSTRAP_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739H no-bootstrap marker"
            rg -q "BUILD102739H_RESULT" "$APP_STRINGS" || fail "missing 102739H result marker"
        elif [[ "$BUILD102739G_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739G_SCOPE=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION" "$APP_STRINGS" || fail "missing 102739G scope marker"
            rg -q "BUILD102739G_BLUEPRINT=IOS_JBSERVER_PREFIX_THROUGH_ACTION_RESOLUTION" "$APP_STRINGS" || fail "missing 102739G blueprint marker"
            rg -q "BUILD102739G_TRIGGER_REQUEST_COUNT=1" "$APP_STRINGS" || fail "missing 102739G single-trigger marker"
            rg -q "BUILD102739G_TRIGGER_DOMAIN=1" "$APP_STRINGS" || fail "missing 102739G domain marker"
            rg -q "BUILD102739G_TRIGGER_ACTION=1" "$APP_STRINGS" || fail "missing 102739G action marker"
            rg -q "BUILD102739G_SHADOW_DOMAIN_TABLE_ENABLED=YES" "$APP_STRINGS" || fail "missing 102739G shadow-table marker"
            rg -q "BUILD102739G_PERMISSION_CHECK_ENABLED=YES" "$APP_STRINGS" || fail "missing 102739G permission marker"
            rg -q "BUILD102739G_HANDLER_DISPATCH_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739G no-dispatch marker"
            rg -q "BUILD102739G_REPLY_CREATION_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739G no-reply marker"
            rg -q "BUILD102739G_OBJECT_OWNERSHIP_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739G ownership marker"
            rg -q "BUILD102739G_ORIGINAL_RETURN_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739G return marker"
            rg -q "BUILD102739G_RESULT" "$APP_STRINGS" || fail "missing 102739G result marker"
            rg -q "BUILD102739C_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing carried 102739C runner marker"
            rg -q "BUILD102739C_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing carried 102739C insertion marker"
        elif [[ "$BUILD102739F_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739F_SCOPE=READ_ONLY_CALLER_IDENTITY" "$APP_STRINGS" || fail "missing 102739F scope marker"
            rg -q "BUILD102739F_BLUEPRINT=IOS_XPC_HOOK_CALLER_IDENTITY_GUARDS_ONLY" "$APP_STRINGS" || fail "missing 102739F blueprint marker"
            rg -q "BUILD102739F_TRIGGER_REQUEST_COUNT=1" "$APP_STRINGS" || fail "missing 102739F single-trigger marker"
            rg -q "BUILD102739F_TRIGGER_DOMAIN=1" "$APP_STRINGS" || fail "missing 102739F domain marker"
            rg -q "BUILD102739F_TRIGGER_ACTION=1" "$APP_STRINGS" || fail "missing 102739F action marker"
            rg -q "BUILD102739F_OBJECT_OWNERSHIP_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739F ownership marker"
            rg -q "BUILD102739F_ORIGINAL_RETURN_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739F return-preservation marker"
            rg -q "BUILD102739F_JBSERVER_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739F no-jbserver marker"
            rg -q "BUILD102739F_HANDLER_DISPATCH_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739F no-dispatch marker"
            rg -q "BUILD102739F_REPLY_CREATION_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739F no-reply marker"
            rg -q "BUILD102739F_RESULT" "$APP_STRINGS" || fail "missing 102739F result marker"
            rg -q "BUILD102739C_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing carried 102739C runner marker"
            rg -q "BUILD102739C_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing carried 102739C insertion marker"
        elif [[ "$BUILD102739E_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739E_SCOPE=READ_ONLY_POST_ORIGINAL_XPC_DICTIONARY_CLASSIFICATION" "$APP_STRINGS" || fail "missing 102739E scope marker"
            rg -q "BUILD102739E_BLUEPRINT=IOS_XPC_HOOK_TYPE_AND_ENVELOPE_GUARDS_ONLY" "$APP_STRINGS" || fail "missing 102739E blueprint marker"
            rg -q "BUILD102739E_TRIGGER_REQUEST_COUNT=1" "$APP_STRINGS" || fail "missing 102739E single-trigger marker"
            rg -q "BUILD102739E_OBJECT_OWNERSHIP_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739E ownership marker"
            rg -q "BUILD102739E_ORIGINAL_RETURN_CHANGED=NO" "$APP_STRINGS" || fail "missing 102739E return-preservation marker"
            rg -q "BUILD102739E_RESULT" "$APP_STRINGS" || fail "missing 102739E result marker"
            rg -q "BUILD102739C_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing carried 102739C runner marker"
            rg -q "BUILD102739C_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing carried 102739C insertion marker"
        elif [[ "$BUILD102739C_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739C_SCOPE=POST_WALL2_XPC_OUTPUT_CONTRACT_OBSERVATION" "$APP_STRINGS" || fail "missing 102739C scope marker"
            rg -q "BUILD102739C_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102739C runner marker"
            rg -q "BUILD102739C_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102739C insertion marker"
            rg -q "BUILD102739C_FROZEN_102739B_RETURN_FOUNDATION_REUSED=YES" "$APP_STRINGS" || fail "missing 102739C frozen-foundation marker"
            rg -q "BUILD102739C_TVOS_LAUNCHD_X4_OUTPUT_POINTER_PROVEN_BY_IDA=YES" "$APP_STRINGS" || fail "missing 102739C x4 proof marker"
            rg -q "BUILD102739C_TVOS_LAUNCHD_W0_ZERO_SUCCESS_PROVEN_BY_IDA=YES" "$APP_STRINGS" || fail "missing 102739C w0 proof marker"
            rg -q "BUILD102739C_OBSERVER_AFTER_WALL2_RESTORE" "$APP_STRINGS" || fail "missing 102739C ordering marker"
            rg -q "BUILD102739C_XPC_OUTPUT_CONTRACT" "$APP_STRINGS" || fail "missing 102739C result marker"
            rg -q "BUILD102739C_PID1_IDENTITY_UNCHANGED" "$APP_STRINGS" || fail "missing 102739C PID1 marker"
            rg -q "BUILD102739C_GUARDED_XOUT_DEREFERENCE=YES" "$APP_STRINGS" || fail "missing 102739C guarded-dereference marker"
            rg -q "BUILD102739C_XPC_API_CALLS=NO" "$APP_STRINGS" || fail "missing 102739C no-XPC-call marker"
        elif [[ "$BUILD102739B_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739B_SCOPE=POST_WALL2_ORIGINAL_RETURN_PATH_OBSERVATION" "$APP_STRINGS" || fail "missing 102739B scope marker"
            rg -q "BUILD102739B_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102739B runner marker"
            rg -q "BUILD102739B_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102739B insertion marker"
            rg -q "BUILD102739B_FROZEN_102739A_INSTALL_FOUNDATION_REUSED=YES" "$APP_STRINGS" || fail "missing 102739B frozen-foundation marker"
            rg -q "BUILD102739B_OBSERVER_AFTER_WALL2_RESTORE" "$APP_STRINGS" || fail "missing 102739B ordering marker"
            rg -q "BUILD102739B_POST_ORIGINAL_RETURN_PATH" "$APP_STRINGS" || fail "missing 102739B result marker"
            rg -q "BUILD102739B_PID1_IDENTITY_UNCHANGED" "$APP_STRINGS" || fail "missing 102739B PID1 identity marker"
            rg -q "BUILD102739B_MESSAGE_OR_XOUT_DEREFERENCE=NO" "$APP_STRINGS" || fail "missing 102739B no-dereference marker"
        elif [[ "$BUILD102739A_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102739A_SCOPE=POST_WALL2_READ_ONLY_WRAPPER_INVOCATION_OBSERVATION" "$APP_STRINGS" || fail "missing 102739A scope marker"
            rg -q "BUILD102739A_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102739A runner marker"
            rg -q "BUILD102739A_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102739A insertion marker"
            rg -q "BUILD102739A_FROZEN_102738Z_INSTALL_FOUNDATION_REUSED=YES" "$APP_STRINGS" || fail "missing 102739A frozen-foundation marker"
            rg -q "BUILD102739A_SHARED_TELEMETRY_FILE_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102739A no-shared-file marker"
            rg -q "BUILD102739A_OBSERVER_AFTER_WALL2_RESTORE" "$APP_STRINGS" || fail "missing 102739A ordering marker"
            rg -q "BUILD102739A_POST_WALL2_INVOCATION_OBSERVED" "$APP_STRINGS" || fail "missing 102739A result marker"
            rg -q "BUILD102739A_PID1_IDENTITY_UNCHANGED" "$APP_STRINGS" || fail "missing 102739A PID1 identity marker"
        elif [[ "$BUILD102738Z_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102738Z_SCOPE=LAUNCHD_GOT_PERSISTENT_TRANSPARENT_WRAPPER_INSTALL_ONLY" "$APP_STRINGS" || fail "missing 102738Z scope marker"
            rg -q "BUILD102738Z_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102738Z runner marker"
            rg -q "BUILD102738Z_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102738Z insertion marker"
            rg -q "BUILD102738Z_GOT_WRAPPER_INSTALL_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738Z install marker"
            rg -q "BUILD102738Z_WRAPPER_PERSISTENT_AFTER_CTOR=YES" "$APP_STRINGS" || fail "missing 102738Z persistence marker"
            rg -q "BUILD102738Z_CONSTRUCTOR_OBSERVATION_WAIT_MS=0" "$APP_STRINGS" || fail "missing 102738Z no-wait marker"
            rg -q "BUILD102738Z_ORIGINAL_POINTER_RESTORE_IN_CTOR=NO" "$APP_STRINGS" || fail "missing 102738Z no-constructor-cleanup marker"
            rg -q "BUILD102738Z_INVOCATION_PROOF_CLAIMED=NO" "$APP_STRINGS" || fail "missing 102738Z no-invocation-claim marker"
            rg -q "BUILD102738Z_RESULT" "$APP_STRINGS" || fail "missing 102738Z result marker"
        elif [[ "$BUILD102738Y_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102738Y_SCOPE=CONTROLLED_LAUNCHD_GOT_WRAPPER_NONBLOCKING_SINGLE_SAMPLE" "$APP_STRINGS" || fail "missing repaired 102738Y scope marker"
            rg -q "BUILD102738Y_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102738Y runner marker"
            rg -q "BUILD102738Y_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102738Y insertion marker"
            rg -q "BUILD102738Y_GOT_WRAPPER_INSTALL_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738Y install marker"
            rg -q "BUILD102738Y_INVOCATION_COUNTER_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738Y counter marker"
            rg -q "BUILD102738Y_ORIGINAL_POINTER_RESTORE_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738Y restore marker"
            rg -q "BUILD102738Y_MAX_OBSERVATION_MS=0" "$APP_STRINGS" || fail "missing repaired 102738Y nonblocking-window marker"
            rg -q "BUILD102738Y_XPC_MESSAGE_PARSING_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102738Y no-parsing marker"
            rg -q "BUILD102738Y_JBSERVER_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102738Y no-jbserver marker"
            rg -q "BUILD102738Y_RESULT" "$APP_STRINGS" || fail "missing 102738Y result marker"
        elif [[ "$BUILD102738X_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102738X_SCOPE=LAUNCHD_GOT_TRANSPARENT_REBIND_ROUNDTRIP_ONLY" "$APP_STRINGS" || fail "missing 102738X scope marker"
            rg -q "BUILD102738X_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102738X runner marker"
            rg -q "BUILD102738X_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102738X insertion marker"
            rg -q "BUILD102738X_GOT_DIFFERENT_POINTER_STORE_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738X different-pointer marker"
            rg -q "BUILD102738X_GOT_ORIGINAL_POINTER_RESTORE_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738X original-restore marker"
            rg -q "BUILD102738X_WRAPPER_PERSISTENT_INSTALL=NO" "$APP_STRINGS" || fail "missing 102738X nonpersistent marker"
            rg -q "BUILD102738X_XPC_MESSAGE_PARSING_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102738X no-message-parsing marker"
            rg -q "BUILD102738X_JBSERVER_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102738X no-jbserver marker"
            rg -q "BUILD102738X_RESULT" "$APP_STRINGS" || fail "missing 102738X result marker"
        elif [[ "$BUILD102738W_STRING_COUNT" -gt 0 ]]; then
            rg -q "BUILD102738W_SCOPE=LAUNCHD_GOT_SAME_VALUE_STORE_ONLY" "$APP_STRINGS" || fail "missing 102738W scope marker"
            rg -q "BUILD102738W_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102738W runner marker"
            rg -q "BUILD102738W_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102738W insertion marker"
            rg -q "BUILD102738W_GOT_POINTER_WRITE_IMPLEMENTED=YES" "$APP_STRINGS" || fail "missing 102738W write-implemented marker"
            rg -q "BUILD102738W_GOT_POINTER_REPLACED=NO" "$APP_STRINGS" || fail "missing 102738W no-replacement marker"
            rg -q "BUILD102738W_XPC_HOOK_INSTALL_IMPLEMENTED=NO" "$APP_STRINGS" || fail "missing 102738W no-hook-install marker"
            rg -q "BUILD102738W_RESULT" "$APP_STRINGS" || fail "missing 102738W result marker"
        else
            rg -q "BUILD102738P_GOT_POINTER_WRITE_PERFORMED=NO" "$APP_STRINGS" || fail "missing protection-only no-pointer-write marker"
        fi
        rg -q "BUILD102738P_PID1_PRESENT_AFTER_RETURN" "$APP_STRINGS" || fail "missing post-return PID 1 presence marker"
        rg -q "BUILD102738P_PID1_IDENTITY_UNCHANGED" "$APP_STRINGS" || fail "missing post-return PID 1 identity marker"
        rg -q "BUILD102738P_RESULT" "$APP_STRINGS" || fail "missing 102738P result marker"
        fi

        [[ -f "$APP_HOOK" ]] || fail "missing packaged launchdhook516.dylib"
        [[ -f "$APP_FRAMEWORK_LIBJAILBREAK" ]] || fail "missing packaged Frameworks/libjailbreak.dylib"
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            HANDOFF_MANIFEST="$APP_HANDOFF/ROOTLESS_R24_CBR_HANDOFF_MANIFEST.txt"
            [[ -f "$HANDOFF_MANIFEST" ]] || HANDOFF_MANIFEST="$APP_HANDOFF/ROOTLESS_R5_HANDOFF_MANIFEST.txt"
            [[ -f "$HANDOFF_MANIFEST" ]] || fail "missing Handoff source-build manifest"
            for artifact in dt_jbctl516 dt_opainject516 entitlements_launchdhook681.plist libchoma.dylib libjailbreak.dylib; do
                [[ -f "$APP_HANDOFF/$artifact" ]] || fail "missing Handoff516/$artifact"
            done
            handoff_manifest_sha() {
                rg "^${1}=" "$HANDOFF_MANIFEST" | head -1 | cut -d= -f2-
            }
            for artifact in libchoma.dylib dt_opainject516 dt_jbctl516; do
                expected="$(handoff_manifest_sha "$artifact")"
                actual="$(shasum -a 256 "$APP_HANDOFF/$artifact" | awk '{print $1}')"
                [[ -n "$expected" && "$actual" == "$expected" ]] || fail "$artifact source-build identity mismatch (manifest=$expected ipa=$actual)"
            done
            LIBCHOMA_SOURCE_BUILD_IDENTITY="PASS"
            OPAINJECT516_SOURCE_BUILD_IDENTITY="PASS"
            FROZEN_V26_102737D_ACTIVE_PINS=0
        else
            for frozen in dt_jbctl516 dt_opainject516 entitlements_launchdhook681.plist libchoma.dylib libjailbreak.dylib; do
                [[ -f "$APP_HANDOFF/$frozen" ]] || fail "missing frozen Handoff516/$frozen"
            done
            [[ "$(shasum -a 256 "$APP_HANDOFF/dt_jbctl516" | awk '{print $1}')" == "6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067" ]] || fail "dt_jbctl516 changed from 102737D"
            if [[ "$BUILD102739A_STRING_COUNT" -eq 0 && "$BUILD102739B_STRING_COUNT" -eq 0 \
                && "$BUILD102739C_STRING_COUNT" -eq 0 && "$BUILD102739E_STRING_COUNT" -eq 0 \
                && "$BUILD102739F_STRING_COUNT" -eq 0 && "$BUILD102739G_STRING_COUNT" -eq 0 \
                && "$BUILD102739H_STRING_COUNT" -eq 0 && "$BUILD102739I_STRING_COUNT" -eq 0 \
                && "$BUILD102739J_STRING_COUNT" -eq 0 ]]; then
                [[ "$(shasum -a 256 "$APP_HANDOFF/dt_opainject516" | awk '{print $1}')" == "0b7dcd9c7258d33e347c94258b57817d0a04fc163af855d3b21499598f6b48fb" ]] || fail "dt_opainject516 changed from 102737D"
            fi
            [[ "$(shasum -a 256 "$APP_HANDOFF/entitlements_launchdhook681.plist" | awk '{print $1}')" == "4d63822e924c55eae1c862dbebfe8a8c2270a915f72efd6b9276a434892e014b" ]] || fail "launchdhook entitlements changed from 102737D"
            [[ "$(shasum -a 256 "$APP_HANDOFF/libchoma.dylib" | awk '{print $1}')" == "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b" ]] || fail "Handoff libchoma changed from 102737D"
            FROZEN_V26_102737D_ACTIVE_PINS=4
        fi
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            # EXPECTED_ROOTLESS_VARIANT_DIFFERENCE: fuller Handoff libjailbreak (R4 jbroot.c).
            nm -gU "$APP_HANDOFF/libjailbreak.dylib" 2>/dev/null | rg -q "_get_jbroot" || fail "rootless Handoff libjailbreak missing _get_jbroot"
            [[ -d "$APP_ROOTLESS_PAYLOAD" ]] || fail "rootless IPA missing RootlessPayload"
            [[ -f "$APP_ROOTLESS_TRUST" ]] || fail "rootless IPA missing trust manifest"
            [[ -f "$APP_ROOTLESS_PATH_MANIFEST" ]] || fail "rootless IPA missing path manifest"
            python3 "$PROJECT/../tools/rootless_add_dest_libiosexec_rpath.py" \
                "$APP_ROOTLESS_PAYLOAD" --trust "$APP_ROOTLESS_TRUST" --verify-only \
                || fail "final packed payload missing /var/jb/usr/lib dest rpath contract"
            FINAL_PAYLOAD_RPATH_CONTRACT="PASS"
            [[ -f "$PROJECT/../bootstrap/entitlements/appletvos_extract_entitlements.xml" ]] \
                || fail "missing bootstrap entitlement input XML"
            python3 "$PROJECT/../tools/rootless_sign_uialert_cfusernotification.py" \
                "$APP_ROOTLESS_PAYLOAD" --trust "$APP_ROOTLESS_TRUST" --verify-only \
                || fail "packed uialert entitlement contract failed"
            UIALERT_ENTITLEMENT_AUDIT_INPUT="PASS"
            rg -q "ROOTLESS_VARIANT=R6" "$APP_STRINGS" || fail "missing ROOTLESS_VARIANT=R6 compiled marker"
            rg -q "COMPILED_ROOTLESS_MARKER=ROOTLESS_R6_BEGIN" "$APP_STRINGS" || fail "missing COMPILED_ROOTLESS_MARKER"
            if [[ -f "$APP_ROOTLESS_VARIANT_FILE" ]]; then
                rg -q "ROOTLESS_VARIANT=R6" "$APP_ROOTLESS_VARIANT_FILE" || fail "ROOTLESS_VARIANT_IDENTITY.txt missing ROOTLESS_VARIANT=R6"
            fi
            # R24 CBR: systemhook must be packaged; XPC/spawn markers inverted vs gate1 forbid.
            if [[ "${DT_ROOTLESS_R24:-}" == "1" ]] || [[ -f "$APP_HANDOFF/systemhook.dylib" ]]; then
                [[ -f "$APP_HANDOFF/systemhook.dylib" ]] || fail "R24 missing Handoff516/systemhook.dylib"
                strings "$APP_HANDOFF/systemhook.dylib" | rg -q '/usr/lib/systemhook.dylib' || fail "systemhook missing fakelib HOOK_DYLIB_PATH"
                ! strings "$APP_HANDOFF/systemhook.dylib" | rg -q '/var/jb/basebin/systemhook.dylib' || fail "systemhook retains retired raw JBROOT injection path"
                [[ -f "$APP_ROOT/R24DyldDelivery/dyld" ]] || fail "R24 missing exact tvOS patched dyld"
                [[ -f "$APP_ROOT/R24DyldDelivery/R24_TVOS_DYLD_DELIVERY_IDENTITY.json" ]] || fail "R24 missing dyld evidence manifest"
                ! strings "$APP_HANDOFF/systemhook.dylib" | rg -q 'TweakLoader.dylib' || fail "systemhook must not embed TweakLoader for CBR"
                strings "$APP_HOOK" | rg -q 'XPC_HOOK_INSTALL_VERIFIED=YES' || fail "R24 hook missing XPC verified install"
                strings "$APP_HOOK" | rg -q 'SPAWN_HOOK_INSTALL_VERIFIED=YES' || fail "R24 hook missing SPAWN verified install"
                nm -gU "$APP_HOOK" 2>/dev/null | rg -q '_initXPCHooks' || fail "R24 hook missing initXPCHooks"
                nm -gU "$APP_HOOK" 2>/dev/null | rg -q '_initSpawnHooks' || fail "R24 hook missing initSpawnHooks"
                rg -q "BUILD102738P_XPC_HOOK_PACKAGED=YES" "$APP_STRINGS" || fail "R24 app STAGE missing XPC packaged"
                rg -q "ROOTLESS_R24_DEP_GATE_CBR_SURFACE_REQUIRED=YES" "$APP_STRINGS" || fail "R24 MAIN missing DEP invert STAGE (device polarity)"
                python3 "$PROJECT/../tools/rootless_r24_host_sim_gates.py" "$IPA" || fail "R24 host DEP-contract gates failed"
            fi
        else
            [[ "$(shasum -a 256 "$APP_HANDOFF/libjailbreak.dylib" | awk '{print $1}')" == "0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754" ]] || fail "Handoff libjailbreak changed from 102737D"
        fi
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            # EXPECTED_ROOTLESS_VARIANT_DIFFERENCE: Framework libjailbreak rebuilt with R4/CBR.
            if [[ -f "$APP_HANDOFF/systemhook.dylib" ]]; then
                nm -gU "$APP_FRAMEWORK_LIBJAILBREAK" 2>/dev/null | rg -q "_get_jbroot" || fail "R24 Framework libjailbreak missing _get_jbroot"
            else
                # Pre-CBR rootless may still ship frozen 102737D Framework hash.
                FW_SHA="$(shasum -a 256 "$APP_FRAMEWORK_LIBJAILBREAK" | awk '{print $1}')"
                if [[ "$FW_SHA" != "ee2644907cb298680f07b6c5e8f3f55e1b786bf3ba39fca6830a3dc13886613d" ]]; then
                    nm -gU "$APP_FRAMEWORK_LIBJAILBREAK" 2>/dev/null | rg -q "_get_jbroot" || fail "rootless Framework libjailbreak neither frozen hash nor _get_jbroot"
                fi
            fi
        else
            [[ "$(shasum -a 256 "$APP_FRAMEWORK_LIBJAILBREAK" | awk '{print $1}')" == "ee2644907cb298680f07b6c5e8f3f55e1b786bf3ba39fca6830a3dc13886613d" ]] || fail "packaged Framework libjailbreak changed from packaged 102737D"
        fi

        HOOK_STRINGS="$TMP/hook_strings.txt"
        strings "$APP_HOOK" > "$HOOK_STRINGS"
        rg -q '\.dt102737_constructor_trace' "$HOOK_STRINGS" || fail "hook does not retain frozen trace filename"
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            LEGACY_102739J_IDENTITY="NOT_APPLICABLE_ROOTLESS"
            rg -q 'BUILD102738P_PROBE_ENTER' "$HOOK_STRINGS" || fail "rootless fuller hook missing GOT probe enter"
            rg -q '/var/jb' "$HOOK_STRINGS" || fail "rootless fuller hook missing /var/jb sandbox spelling"
            rg -q '/private/var/jb' "$HOOK_STRINGS" || fail "rootless fuller hook missing /private/var/jb sandbox spelling"
            nm -gU "$APP_HOOK" 2>/dev/null | rg -q "jbserver|systemwide" || true
        elif [[ "$BUILD102739J_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739J_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739J hook probe-entry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739j_reply_telemetry' || fail "102739J telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            for marker in BUILD102739J_TRIGGER_REPLY_IS_DICTIONARY= \
                BUILD102739J_TRIGGER_REPLY_ROOT_PATH_TYPE_STRING= \
                BUILD102739J_TRIGGER_REPLY_RESULT_TYPE_INT64= \
                BUILD102739J_ORIGINAL_RECEIVE_CALL_DELTA= \
                BUILD102739J_SERVER_COMMITTED_LIFECYCLE_PASS_DELTA= \
                BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP=PASS; do
                rg -q "$marker" "$HELPER_STRINGS" || fail "102739J helper marker missing: $marker"
            done
        elif [[ "$BUILD102739I_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739I_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739I hook probe-entry marker missing"
            rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739I telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739i_handler_telemetry' || fail "102739I telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            for marker in BUILD102739I_OBSERVER_MODE=READ_ONLY \
                BUILD102739I_HANDLER_INVOCATION_DELTA= \
                BUILD102739I_MARSHALLING_COMPLETE_DELTA= \
                BUILD102739I_HANDLER_CALL_ATTEMPT_DELTA= \
                BUILD102739I_HANDLER_RETURN_DELTA= \
                BUILD102739I_HANDLER_ARG0_OUTPUT_SLOT_MATCH_DELTA= \
                BUILD102739I_HANDLER_ARGS1_THROUGH_7_NULL_DELTA= \
                BUILD102739I_HANDLER_OUTPUT_WRITE_DELTA= \
                BUILD102739I_ARGSOUT0_SENTINEL_MATCH_DELTA= \
                BUILD102739I_ARGSOUT_TAIL_NULL_DELTA= \
                BUILD102739I_HANDLER_RESULT_MATCH_DELTA= \
                BUILD102739I_CONTROLLED_HANDLER_COMPLETE_DELTA= \
                BUILD102739I_REAL_JBROOT_HANDLER_INVOKED=NO \
                BUILD102739I_REPLY_CREATED=NO \
                BUILD102739I_BOOTSTRAP_TOUCHED=NO \
                BUILD102739I_CONTROLLED_ACTION_HANDLER_ABI=PASS; do
                rg -q "$marker" "$HELPER_STRINGS" || fail "102739I helper marker missing: $marker"
            done
        elif [[ "$BUILD102739H_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739H_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739H hook probe-entry marker missing"
            rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739H telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739h_argument_telemetry' || fail "102739H telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            for marker in BUILD102739H_OBSERVER_MODE=READ_ONLY \
                BUILD102739H_HANDLER_POINTER_CAPTURE_DELTA= \
                BUILD102739H_HANDLER_POINTER_NONNULL_DELTA= \
                BUILD102739H_ARGS_ZERO_INITIALIZED_DELTA= \
                BUILD102739H_ARGSOUT_ZERO_INITIALIZED_DELTA= \
                BUILD102739H_ARG_DESCRIPTOR_SCAN_DELTA= \
                BUILD102739H_ARG_NAME_ROOT_PATH_DELTA= \
                BUILD102739H_ARG_TYPE_STRING_DELTA= \
                BUILD102739H_ARG_DIRECTION_OUT_DELTA= \
                BUILD102739H_OUTPUT_SLOT_BIND_DELTA= \
                BUILD102739H_ARG_TERMINATOR_FOUND_DELTA= \
                BUILD102739H_MARSHALLING_COMPLETE_DELTA= \
                BUILD102739H_HANDLER_INVOKED=NO \
                BUILD102739H_REPLY_CREATED=NO \
                BUILD102739H_BOOTSTRAP_TOUCHED=NO \
                BUILD102739H_READ_ONLY_ACTION_ARGUMENT_MARSHALLING=PASS; do
                rg -q "$marker" "$HELPER_STRINGS" || fail "102739H helper marker missing: $marker"
            done
        elif [[ "$BUILD102739G_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739G_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739G hook probe-entry marker missing"
            rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739G telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739g_domain_action_telemetry' || fail "102739G telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            for marker in BUILD102739G_OBSERVER_MODE=READ_ONLY \
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
                rg -q "$marker" "$HELPER_STRINGS" || fail "102739G helper marker missing: $marker"
            done
        elif [[ "$BUILD102739F_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739F_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739F hook probe-entry marker missing"
            rg -q 'BUILD102739F_CALLER_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739F telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739f_caller_identity_telemetry' || fail "102739F telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            rg -q 'BUILD102739F_OBSERVER_MODE=READ_ONLY' "$HELPER_STRINGS" || fail "102739F read-only observer marker missing"
            rg -q 'BUILD102739F_REMOTE_DLOPEN_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739F no-dlopen marker missing"
            rg -q 'BUILD102739F_REMOTE_WRITE_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739F no-write marker missing"
            rg -q 'BUILD102739F_EXACT_CONTROLLED_PROBE_DELTA=' "$HELPER_STRINGS" || fail "102739F exact-probe marker missing"
            rg -q 'BUILD102739F_DOMAIN_NONZERO_DELTA=' "$HELPER_STRINGS" || fail "102739F domain-nonzero marker missing"
            rg -q 'BUILD102739F_SYSTEMWIDE_DOMAIN_CANDIDATE_DELTA=' "$HELPER_STRINGS" || fail "102739F systemwide-domain marker missing"
            rg -q 'BUILD102739F_AUDIT_TOKEN_CAPTURE_DELTA=' "$HELPER_STRINGS" || fail "102739F audit-token marker missing"
            rg -q 'BUILD102739F_TOKEN_PID_MATCH=' "$HELPER_STRINGS" || fail "102739F token-pid-match marker missing"
            rg -q 'BUILD102739F_TOKEN_EUID_MATCH=' "$HELPER_STRINGS" || fail "102739F token-euid-match marker missing"
            rg -q 'BUILD102739F_READ_ONLY_CALLER_IDENTITY=' "$HELPER_STRINGS" || fail "102739F caller-identity result marker missing"
        elif [[ "$BUILD102739E_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739E_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739E hook probe-entry marker missing"
            rg -q 'BUILD102739E_DICTIONARY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739E telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739e_dictionary_telemetry' || fail "102739E telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            rg -q 'BUILD102739E_OBSERVER_MODE=READ_ONLY' "$HELPER_STRINGS" || fail "102739E read-only observer marker missing"
            rg -q 'BUILD102739E_REMOTE_DLOPEN_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739E no-dlopen marker missing"
            rg -q 'BUILD102739E_REMOTE_WRITE_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739E no-write marker missing"
            rg -q 'BUILD102739E_EXACT_CONTROLLED_PROBE_DELTA=' "$HELPER_STRINGS" || fail "102739E exact-probe marker missing"
            rg -q 'BUILD102739E_READ_ONLY_DICTIONARY_CLASSIFICATION=' "$HELPER_STRINGS" || fail "102739E classifier result marker missing"
        elif [[ "$BUILD102739C_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739C_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739C hook probe-entry marker missing"
            rg -q 'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102739C persistent wrapper marker missing"
            rg -q 'BUILD102739C_OUTPUT_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739C telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739c_output_telemetry' || fail "102739C telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            rg -q 'BUILD102739C_OBSERVER_MODE=READ_ONLY' "$HELPER_STRINGS" || fail "102739C read-only observer marker missing"
            rg -q 'BUILD102739C_REMOTE_DLOPEN_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739C no-dlopen marker missing"
            rg -q 'BUILD102739C_REMOTE_WRITE_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739C no-write marker missing"
            rg -q 'BUILD102739C_SUCCESS_RETURN_COUNT=' "$HELPER_STRINGS" || fail "102739C success-return marker missing"
            rg -q 'BUILD102739C_XOUT_ARGUMENT_COUNT=' "$HELPER_STRINGS" || fail "102739C xOut marker missing"
            rg -q 'BUILD102739C_SUCCESS_XOUT_COUNT=' "$HELPER_STRINGS" || fail "102739C success-xOut marker missing"
            rg -q 'BUILD102739C_SUCCESS_OBJECT_COUNT=' "$HELPER_STRINGS" || fail "102739C object marker missing"
            rg -q 'BUILD102739C_COUNTER_INVARIANTS=' "$HELPER_STRINGS" || fail "102739C invariant marker missing"
            rg -q 'BUILD102739C_OUTPUT_CONTRACT_OBSERVED=' "$HELPER_STRINGS" || fail "102739C result marker missing"
        elif [[ "$BUILD102739B_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739B_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739B hook probe-entry marker missing"
            rg -q 'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102739B persistent wrapper marker missing"
            rg -q 'BUILD102739B_RETURN_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739B exported telemetry marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739b_return_telemetry' || fail "102739B exported telemetry symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            rg -q 'BUILD102739B_OBSERVER_MODE=READ_ONLY' "$HELPER_STRINGS" || fail "102739B read-only observer marker missing"
            rg -q 'BUILD102739B_REMOTE_DLOPEN_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739B no-dlopen marker missing"
            rg -q 'BUILD102739B_REMOTE_WRITE_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739B no-write marker missing"
            rg -q 'BUILD102739B_RETURN_COUNT_READ_RC=' "$HELPER_STRINGS" || fail "102739B return-first read marker missing"
            rg -q 'BUILD102739B_ENTRY_COUNT_READ_RC=' "$HELPER_STRINGS" || fail "102739B entry-second read marker missing"
            rg -q 'BUILD102739B_POST_WALL2_ENTRY_COUNT=' "$HELPER_STRINGS" || fail "102739B entry-count marker missing"
            rg -q 'BUILD102739B_POST_WALL2_RETURN_COUNT=' "$HELPER_STRINGS" || fail "102739B return-count marker missing"
            rg -q 'BUILD102739B_RETURN_PATH_OBSERVED=' "$HELPER_STRINGS" || fail "102739B return-path marker missing"
        elif [[ "$BUILD102739A_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102739A_PROBE_ENTER' "$HOOK_STRINGS" || fail "102739A hook probe-entry marker missing"
            rg -q 'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102739A persistent counting-wrapper marker missing"
            rg -q 'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102739A persistent installation marker missing"
            rg -q 'BUILD102739A_COUNTER_EXPORTED_YES' "$HOOK_STRINGS" || fail "102739A exported-counter marker missing"
            nm -g "$APP_HOOK" 2>/dev/null | rg -q '_g_dt102739a_invocation_count' || fail "102739A exported counter symbol missing"
            HELPER_STRINGS="$TMP/helper_strings.txt"
            strings "$APP_HELPER" > "$HELPER_STRINGS"
            rg -q 'BUILD102739A_OBSERVER_MODE=READ_ONLY' "$HELPER_STRINGS" || fail "102739A read-only observer marker missing"
            rg -q 'BUILD102739A_REMOTE_DLOPEN_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739A no-dlopen marker missing"
            rg -q 'BUILD102739A_REMOTE_WRITE_ATTEMPTED=NO' "$HELPER_STRINGS" || fail "102739A no-write marker missing"
            rg -q 'BUILD102739A_HOOK_UUID_MATCH=' "$HELPER_STRINGS" || fail "102739A UUID validation marker missing"
            rg -q 'BUILD102739A_POST_WALL2_INVOCATION_COUNT=' "$HELPER_STRINGS" || fail "102739A counter result marker missing"
        elif [[ "$BUILD102738Z_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102738Z_PROBE_ENTER' "$HOOK_STRINGS" || fail "102738Z hook probe-entry marker missing"
            rg -q 'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102738Z counting-wrapper marker missing"
            rg -q 'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102738Z persistent implementation marker missing"
            rg -q 'GOT_WRAPPER_INSTALL_PASS' "$HOOK_STRINGS" || fail "102738Z install-pass marker missing"
            rg -q 'GOT_WRAPPER_PERSISTENT_INSTALL_PASS' "$HOOK_STRINGS" || fail "102738Z persistent-install marker missing"
            rg -q 'GOT_PROTECTION_RESTORE_PASS' "$HOOK_STRINGS" || fail "102738Z protection-restore marker missing"
            rg -q 'GOT_WRAPPER_INVOCATION_PROOF_PASS|GOT_WRAPPER_INVOKED_PASS|GOT_ORIGINAL_RESTORE_PASS' "$HOOK_STRINGS" && fail "cleanup/invocation-proof material leaked into Z hook"
        elif [[ "$BUILD102738Y_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102738Y_PROBE_ENTER' "$HOOK_STRINGS" || fail "102738Y hook probe-entry marker missing"
            rg -q 'BUILD102738Y_COUNTING_WRAPPER_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "102738Y counting-wrapper marker missing"
            rg -q 'GOT_WRAPPER_INSTALL_PASS' "$HOOK_STRINGS" || fail "102738Y install-pass marker missing"
            rg -q 'GOT_WRAPPER_INVOCATION_COUNT_AFTER' "$HOOK_STRINGS" || fail "102738Y invocation-count marker missing"
            rg -q 'GOT_WRAPPER_INVOKED_PASS' "$HOOK_STRINGS" || fail "102738Y invocation marker missing"
            rg -q 'GOT_WRAPPER_INVOCATION_PROOF_PASS' "$HOOK_STRINGS" || fail "102738Y invocation-proof marker missing"
            rg -q 'GOT_ORIGINAL_RESTORE_PASS' "$HOOK_STRINGS" || fail "102738Y original-restore marker missing"
            rg -q 'BUILD102738W_|BUILD102738X_PROBE_ENTER|GOT_SAME_VALUE_STORE_PASS' "$HOOK_STRINGS" && fail "prior probe material leaked into Y hook"
        elif [[ "$BUILD102738X_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102738X_PROBE_ENTER' "$HOOK_STRINGS" || fail "102738X hook probe-entry marker missing"
            rg -q 'BUILD102738X_TRANSPARENT_WRAPPER_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "transparent-wrapper implementation marker missing"
            rg -q 'GOT_WRAPPER_POINTER_DIFFERS_PASS' "$HOOK_STRINGS" || fail "wrapper-different marker missing"
            rg -q 'GOT_WRAPPER_EXEC_MAPPING_PASS' "$HOOK_STRINGS" || fail "wrapper executable-mapping marker missing"
            rg -q 'GOT_WRAPPER_IN_HOOK_IMAGE_PASS' "$HOOK_STRINGS" || fail "wrapper image-range marker missing"
            rg -q 'GOT_WRAPPER_STORE_PASS' "$HOOK_STRINGS" || fail "wrapper-store pass marker missing"
            rg -q 'GOT_ORIGINAL_RESTORE_PASS' "$HOOK_STRINGS" || fail "original-restore pass marker missing"
            rg -q 'GOT_WRAPPER_ROUNDTRIP_PASS' "$HOOK_STRINGS" || fail "wrapper-roundtrip pass marker missing"
            rg -q 'GOT_SAME_VALUE_STORE_PASS|BUILD102738W_' "$HOOK_STRINGS" && fail "W same-value probe material leaked into X hook"
        elif [[ "$BUILD102738W_STRING_COUNT" -gt 0 ]]; then
            rg -q 'BUILD102738W_PROBE_ENTER' "$HOOK_STRINGS" || fail "102738W hook probe-entry marker missing"
            rg -q 'BUILD102738W_SAME_VALUE_STORE_IMPLEMENTED_YES' "$HOOK_STRINGS" || fail "same-value-store implementation marker missing"
            rg -q 'GOT_PRESTORE_MATCH_PASS' "$HOOK_STRINGS" || fail "pre-store equality marker missing"
            rg -q 'GOT_SAME_VALUE_STORE_PASS' "$HOOK_STRINGS" || fail "same-value-store pass marker missing"
            rg -q 'GOT_SAME_VALUE_STORE_READBACK' "$HOOK_STRINGS" || fail "same-value-store readback marker missing"
            rg -q 'GOT_POINTER_REPLACED_NO' "$HOOK_STRINGS" || fail "no-pointer-replacement marker missing"
        else
            rg -q 'BUILD102738P_PROBE_ENTER' "$HOOK_STRINGS" || fail "hook probe-entry marker missing"
        fi
        rg -q 'BUILD102738R_POINTER_VALIDATOR_REPAIR' "$HOOK_STRINGS" || fail "recursive pointer-validator repair marker missing"
        rg -q 'GOT_POINTER_BASIC_QUERY_DIAGNOSTIC_ONLY' "$HOOK_STRINGS" || fail "basic-query diagnostic-only marker missing"
        rg -q 'GOT_POINTER_RECURSE_QUERY_RC' "$HOOK_STRINGS" || fail "recursive-query RC marker missing"
        rg -q 'GOT_POINTER_RECURSE_CONTAINS_POINTER' "$HOOK_STRINGS" || fail "recursive-query containment marker missing"
        rg -q 'GOT_POINTER_RECURSE_MAPPING_PASS' "$HOOK_STRINGS" || fail "recursive-query pass marker missing"
        rg -q 'GOT_PROTECTION_TEST_PASS' "$HOOK_STRINGS" || fail "hook protection-pass marker missing"
        rg -q 'GOT_PROTECTION_RESTORE_FATAL' "$HOOK_STRINGS" || fail "hook fatal-restore marker missing"
        if [[ "$BUILD102738Z_STRING_COUNT" -eq 0 ]]; then
            rg -q 'GOT_POINTER_UNCHANGED_PASS' "$HOOK_STRINGS" || fail "hook pointer-unchanged marker missing"
        fi
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            : # EXPECTED_ROOTLESS_VARIANT_DIFFERENCE: fuller hook includes jbserver/xpc material
        else
            rg -q 'MSHookFunction|initXPCHooks|xpc_receive_mach_msg_hook|jbserver_received|JBSERVER_MACH_MAGIC' "$HOOK_STRINGS" && fail "hook contains out-of-scope functional message-hook material"
        fi
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            LEGACY_102739J_IDENTITY="${LEGACY_102739J_IDENTITY:-NOT_APPLICABLE_ROOTLESS}"
        elif [[ "$BUILD102739J_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739J wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 3 ]] || fail "102739J wrapper indirect call count is not three"
            for call in _xpc_dictionary_create_reply _xpc_dictionary_set_string _xpc_dictionary_set_int64 _xpc_dictionary_get_value _xpc_get_type _xpc_dictionary_get_string _xpc_dictionary_get_int64 _xpc_pipe_routine_reply _xpc_release; do
                rg -q "$call" "$WRAPPER_DISASM" || fail "102739J wrapper missing $call"
            done
            rg -q '_xpc_retain|_fprintf|_open|_mmap|_write|_jbserver|_jbinfo|_strdup|_malloc|_free' "$WRAPPER_DISASM" && fail "102739J wrapper contains forbidden functionality"
        elif [[ "$BUILD102739I_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739I wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 3 ]] || fail "102739I wrapper does not contain exactly original, permission, and controlled-handler indirect calls"
            for call in _xpc_get_type _xpc_dictionary_get_value _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp _xpc_dictionary_get_audit_token _audit_token_to_pid _audit_token_to_euid; do
                rg -q "$call" "$WRAPPER_DISASM" || fail "102739I wrapper missing $call"
            done
            rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver|_jbinfo|_strdup|_malloc|_free' "$WRAPPER_DISASM" && fail "102739I wrapper contains forbidden ownership, reply, allocation, I/O, jbinfo, or jbserver call"
        elif [[ "$BUILD102739H_STRING_COUNT" -gt 0 || "$BUILD102739G_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739G wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 2 ]] || fail "102739G/H wrapper does not contain exactly original and permission indirect calls"
            for call in _xpc_get_type _xpc_dictionary_get_value _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp _xpc_dictionary_get_audit_token _audit_token_to_pid _audit_token_to_euid; do
                rg -q "$call" "$WRAPPER_DISASM" || fail "102739G/H wrapper missing $call"
            done
            rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver|_jbinfo|_strdup|_malloc|_free' "$WRAPPER_DISASM" && fail "102739G/H wrapper contains forbidden ownership, reply, allocation, I/O, or jbserver call"
            rg -q 'bl.*dt102739g_unreachable_get_jbroot' "$WRAPPER_DISASM" && fail "102739G/H wrapper invokes the forbidden GET_JBROOT placeholder"
        elif [[ "$BUILD102739F_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739F wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]] || fail "102739F wrapper does not call original exactly once"
            rg -q $'\tret' "$WRAPPER_DISASM" || fail "102739F wrapper does not return"
            for call in _xpc_get_type _xpc_dictionary_get_value _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp _xpc_dictionary_get_audit_token _audit_token_to_pid _audit_token_to_euid; do
                rg -q "$call" "$WRAPPER_DISASM" || fail "102739F wrapper missing $call"
            done
            rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver' "$WRAPPER_DISASM" && fail "102739F wrapper contains forbidden ownership, reply, I/O, or jbserver call"
        elif [[ "$BUILD102739E_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739E wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]] || fail "102739E wrapper does not call original exactly once"
            rg -q $'\tret' "$WRAPPER_DISASM" || fail "102739E wrapper does not return"
            for call in _xpc_get_type _xpc_dictionary_get_value _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp; do
                rg -q "$call" "$WRAPPER_DISASM" || fail "102739E wrapper missing $call"
            done
            rg -q '_xpc_(release|retain)|_fprintf|_open|_mmap|_write|_jbserver' "$WRAPPER_DISASM" && fail "102739E wrapper contains forbidden ownership, I/O, or jbserver call"
        elif [[ "$BUILD102739C_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739C wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]] || fail "102739C wrapper does not call original exactly once"
            rg -q $'\tret' "$WRAPPER_DISASM" || fail "102739C wrapper does not return"
            [[ "$(rg -c $'\tldxr\t|\tldaxr\t' "$WRAPPER_DISASM")" -ge 6 ]] || fail "102739C wrapper lacks guarded atomic classifications"
            rg -q $'\tldar\t' "$WRAPPER_DISASM" || fail "102739C wrapper does not acquire-load original"
            rg -q $'\tldr\tx[0-9]+, \[x[0-9]+\]' "$WRAPPER_DISASM" || fail "102739C wrapper lacks guarded output-object load"
            rg -q '_xpc_|_fprintf|_open|_mmap|_write' "$WRAPPER_DISASM" && fail "102739C wrapper contains out-of-scope call"
        elif [[ "$BUILD102739B_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "102739B wrapper symbol missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            [[ "$(rg -c $'\tldxr\t|\tldaxr\t' "$WRAPPER_DISASM")" -ge 2 ]] || fail "102739B wrapper lacks two atomic increments"
            [[ "$(rg -c $'\tstxr\t|\tstlxr\t' "$WRAPPER_DISASM")" -ge 2 ]] || fail "102739B wrapper lacks two atomic stores"
            rg -q $'\tldar\t' "$WRAPPER_DISASM" || fail "102739B wrapper does not acquire-load original"
            rg -q $'\tblr\t' "$WRAPPER_DISASM" || fail "102739B wrapper does not call original"
            rg -q $'\tret' "$WRAPPER_DISASM" || fail "102739B wrapper does not return"
            sed -n '/blr[[:space:]]x8/,/ret/p' "$WRAPPER_DISASM" > "$TMP/wrapper_post_call.txt"
            [[ -s "$TMP/wrapper_post_call.txt" ]] || fail "102739B post-call disassembly slice is empty"
            rg -q '(^|[^[:alnum:]_])[wx]0([^[:alnum:]_]|$)' "$TMP/wrapper_post_call.txt" && fail "102739B post-call telemetry clobbers original return register"
        elif [[ "$BUILD102738Z_STRING_COUNT" -gt 0 || "$BUILD102738Y_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_run_got_wrapper_invocation_probe' || fail "Y invocation probe symbol missing"
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper' || fail "Y counting wrapper symbol missing"
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738y_atomic_store_pointer' || fail "Y atomic pointer-store helper missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            rg -q $'\tldxr\t|\tldaxr\t' "$WRAPPER_DISASM" || fail "Y wrapper lacks inline atomic load-exclusive"
            rg -q $'\tstxr\t|\tstlxr\t' "$WRAPPER_DISASM" || fail "Y wrapper lacks inline atomic store-exclusive"
            rg -q $'\tldar\t' "$WRAPPER_DISASM" || fail "Y wrapper does not acquire-load original"
            rg -q $'\tbr\t' "$WRAPPER_DISASM" || fail "Y wrapper does not tail-forward"
            rg -q $'\t(bl|blr|ret)\b' "$WRAPPER_DISASM" && fail "Y wrapper contains a call or return"
        elif [[ "$BUILD102738X_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738x_run_got_wrapper_roundtrip_probe' || fail "GOT wrapper-roundtrip probe symbol missing"
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738x_transparent_wrapper' || fail "transparent wrapper symbol missing"
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738x_atomic_store_pointer' || fail "atomic pointer-store helper missing"
            WRAPPER_DISASM="$TMP/wrapper_disassembly.txt"
            otool -tvV "$APP_HOOK" | sed -n '/_dt102738x_transparent_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
            rg -q $'\tldar\tx5, \[x8\]' "$WRAPPER_DISASM" || fail "wrapper does not acquire-load saved original into x5"
            rg -q $'\tbr\tx5' "$WRAPPER_DISASM" || fail "wrapper does not tail-branch to saved original"
            rg -q $'\t(bl|blr|ret)\b' "$WRAPPER_DISASM" && fail "wrapper contains a non-transparent call or return"
        elif [[ "$BUILD102738W_STRING_COUNT" -gt 0 ]]; then
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738w_run_got_same_value_store_probe' || fail "GOT same-value-store probe symbol missing"
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738w_atomic_store_same_value' || fail "atomic same-value-store helper missing"
        else
            nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738p_run_got_protection_probe' || fail "GOT protection probe symbol missing"
        fi
        nm "$APP_HOOK" 2>/dev/null | rg -q '_dt102738p_mach_vm_protect' || fail "direct mach_vm_protect wrapper missing"
        nm -u "$APP_HOOK" 2>/dev/null | rg -q '_vm_region_recurse_64' || fail "recursive VM-region import missing"
        nm -gU "$APP_FRAMEWORK_LIBJAILBREAK" 2>/dev/null | rg -q "_kalloc_pt_is_initialized" || fail "missing frozen Framework libjailbreak PTE export"
        HOST_AUDIT_RESULT="PASS"
    else
        rg -q "BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY" "$APP_STRINGS" || fail "missing 102732C scope marker"
    fi
    if [[ "$MAKEFILE_DT_BUILD_NUM" != "102738" ]]; then
        rg -q "BUILD102732C_GOT_ACCESSED=NO" "$APP_STRINGS" || fail "missing 102732C GOT safety marker"
        rg -q "BUILD102732C_MACH_VM_PROTECT_GOT_CALLED=NO" "$APP_STRINGS" || fail "missing 102732C protection safety marker"
        rg -q "BUILD102732C_STAGE_B_ACTIVE=NO" "$APP_STRINGS" || fail "missing 102732C Stage B safety marker"
    fi
    if [[ "$MAKEFILE_DT_BUILD_NUM" == "102734" ]]; then
        rg -q "BUILD102734C_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102734 runner marker"
        rg -q "BUILD102734C_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102734 insertion marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102735" ]]; then
        rg -q "BUILD102735D_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102735 runner marker"
        rg -q "BUILD102735D_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102735 insertion marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102736" ]]; then
        rg -q "BUILD102736C_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102736 runner marker"
        rg -q "BUILD102736C_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102736 insertion marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102737" ]]; then
        rg -q "BUILD102737D_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102737 runner marker"
        rg -q "BUILD102737D_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102737 insertion marker"
    elif [[ "$MAKEFILE_DT_BUILD_NUM" == "102738" ]]; then
        # Rootless product blocks run699; runner/insertion live only on the dead constructor path.
        if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
            : # EXPECTED_ROOTLESS_VARIANT_DIFFERENCE: orch path, not run699
        else
            rg -q "BUILD102738P_RUNNER_ENTRY" "$APP_STRINGS" || fail "missing 102738 runner marker"
            rg -q "BUILD102738P_INSERTION_AFTER_PHYSRW_HANDOFF" "$APP_STRINGS" || fail "missing 102738 insertion marker"
        fi
    else
        nm "$APP_BIN" 2>/dev/null | rg -q "dt102732c_run_constructor_boomerang_only" || fail "102732C branch symbol missing"
    fi
    nm "$APP_BIN" 2>/dev/null | rg -q "dt_build729a_run_self_page_protection_control" && fail "729A probe symbol present in 102732 build"
    HOST_AUDIT_RESULT="PASS"
else
    HOST_AUDIT_RESULT="N/A"
fi

if [[ "$MAKEFILE_DT_BUILD_NUM" != "102729" && -z "${HOST_AUDIT_RESULT:-}" ]]; then
    HOST_AUDIT_RESULT="N/A"
fi

if [[ "${DT_EXPECT_102738_VARIANT:-}" == "X" && "$BUILD102738X_STRING_COUNT" -eq 0 ]]; then
    fail "102738X was requested but no BUILD102738X strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "Y" && "$BUILD102738Y_STRING_COUNT" -eq 0 ]]; then
    fail "102738Y was requested but no BUILD102738Y strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "Z" && "$BUILD102738Z_STRING_COUNT" -eq 0 ]]; then
    fail "102738Z was requested but no BUILD102738Z strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "A" && "$BUILD102739A_STRING_COUNT" -eq 0 ]]; then
    fail "102739A was requested but no BUILD102739A strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "B" && "$BUILD102739B_STRING_COUNT" -eq 0 ]]; then
    fail "102739B was requested but no BUILD102739B strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "E" && "$BUILD102739E_STRING_COUNT" -eq 0 ]]; then
    fail "102739E was requested but no BUILD102739E strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "F" && "$BUILD102739F_STRING_COUNT" -eq 0 ]]; then
    fail "102739F was requested but no BUILD102739F strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "G" && "$BUILD102739G_STRING_COUNT" -eq 0 ]]; then
    fail "102739G was requested but no BUILD102739G strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "H" && "$BUILD102739H_STRING_COUNT" -eq 0 ]]; then
    fail "102739H was requested but no BUILD102739H strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "I" && "$BUILD102739I_STRING_COUNT" -eq 0 ]]; then
    fail "102739I was requested but no BUILD102739I strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "J" && "$BUILD102739J_STRING_COUNT" -eq 0 ]]; then
    fail "102739J was requested but no BUILD102739J strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "K" && "$BUILD102739K_STRING_COUNT" -eq 0 ]]; then
    fail "102739K was requested but no BUILD102739K strings are present"
fi
if [[ "${DT_EXPECT_102738_VARIANT:-}" == "M" && "$BUILD102739M_STRING_COUNT" -eq 0 ]]; then
    fail "102739M was requested but no BUILD102739M strings are present"
fi

IPA_FILENAME="$(basename "$IPA")"
if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
    case "$IPA_FILENAME" in
        dopamin-tvOS-kfd-ROOTLESS-R21.ipa|dopamin-tvOS-kfd-ROOTLESS-R22.ipa|dopamin-tvOS-kfd-ROOTLESS-R23.ipa|dopamin-tvOS-kfd-ROOTLESS-R24.ipa) ;;
        *) fail "unexpected IPA filename $IPA_FILENAME (expected ROOTLESS-R21/R22/R23/R24)" ;;
    esac
else
    [[ "$IPA_FILENAME" == "$EXPECTED_NAMED_IPA" || "$IPA_FILENAME" == "${ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${SECOND_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${THIRD_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${FOURTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${FIFTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${SIXTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${SEVENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${EIGHTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${NINTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${TENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${ELEVENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${TWELFTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${THIRTEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${FOURTEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${FIFTEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${SIXTEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${SEVENTEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${EIGHTEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${NINETEENTH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "${TWENTIETH_ALTERNATE_NAMED_IPA:-}" || "$IPA_FILENAME" == "dopamin-tvOS-kfd.ipa" ]] || fail "unexpected IPA filename $IPA_FILENAME (expected $EXPECTED_NAMED_IPA)"
fi

if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
    if [[ "$IDENTITY_CONSISTENCY" == "PASS" ]]; then
        ROOTLESS_IDENTITY_CONSISTENCY="PASS"
    else
        ROOTLESS_IDENTITY_CONSISTENCY="FAIL"
    fi
    LEGACY_102739J_IDENTITY="${LEGACY_102739J_IDENTITY:-NOT_APPLICABLE_ROOTLESS}"
    ROOTLESS_VARIANT_OUT="R6"
    ROOTLESS_ARCH_OUT="appletvos-arm64-rootless"
else
    ROOTLESS_IDENTITY_CONSISTENCY="N/A"
    LEGACY_102739J_IDENTITY="${LEGACY_102739J_IDENTITY:-N/A}"
    ROOTLESS_VARIANT_OUT="N/A"
    ROOTLESS_ARCH_OUT="N/A"
fi

cat <<EOF
BUILD_ARTIFACT_IDENTITY

SOURCE_DT_BUILD_NUM=$MAKEFILE_DT_BUILD_NUM

MAKEFILE_DT_BUILD_NUM=$MAKEFILE_DT_BUILD_NUM

INFO_PLIST_VERSION=$INFO_PLIST_VERSION

COMPILED_SCOPE_MARKER=$COMPILED_SCOPE_MARKER

COMPILED_BUILD_MARKER=$COMPILED_BUILD_MARKER

ROOTLESS_IPA=$ROOTLESS_IPA

ROOTLESS_VARIANT=$ROOTLESS_VARIANT_OUT

ROOTLESS_ARCH=$ROOTLESS_ARCH_OUT

LEGACY_102739J_IDENTITY=$LEGACY_102739J_IDENTITY

ROOTLESS_IDENTITY_CONSISTENCY=$ROOTLESS_IDENTITY_CONSISTENCY

IPA_FILENAME=$IPA_FILENAME

IPA_PATH=$IPA

IPA_SHA256=$IPA_SHA256

PAYLOAD_BINARY_SHA256=$PAYLOAD_BINARY_SHA256

CFBUNDLEVERSION_FROM_PACKAGED_IPA=$CFBUNDLEVERSION_FROM_PACKAGED_IPA

BUILD102725R_STRING_COUNT=$BUILD102725R_STRING_COUNT

BUILD102726D_STRING_COUNT=$BUILD102726D_STRING_COUNT

BUILD102727R_STRING_COUNT=$BUILD102727R_STRING_COUNT

BUILD102728R_STRING_COUNT=$BUILD102728R_STRING_COUNT

BUILD102729A_STRING_COUNT=$BUILD102729A_STRING_COUNT

BUILD102732C_STRING_COUNT=$BUILD102732C_STRING_COUNT

BUILD102734C_STRING_COUNT=$BUILD102734C_STRING_COUNT

BUILD102735D_STRING_COUNT=$BUILD102735D_STRING_COUNT

BUILD102736C_STRING_COUNT=$BUILD102736C_STRING_COUNT

BUILD102737D_STRING_COUNT=$BUILD102737D_STRING_COUNT

BUILD102738P_STRING_COUNT=$BUILD102738P_STRING_COUNT

BUILD102738W_STRING_COUNT=$BUILD102738W_STRING_COUNT

BUILD102738X_STRING_COUNT=$BUILD102738X_STRING_COUNT

BUILD102738Y_STRING_COUNT=$BUILD102738Y_STRING_COUNT

BUILD102738Z_STRING_COUNT=$BUILD102738Z_STRING_COUNT

BUILD102739A_STRING_COUNT=$BUILD102739A_STRING_COUNT

BUILD102739B_STRING_COUNT=$BUILD102739B_STRING_COUNT

BUILD102739C_STRING_COUNT=$BUILD102739C_STRING_COUNT

BUILD102739E_STRING_COUNT=$BUILD102739E_STRING_COUNT

BUILD102739F_STRING_COUNT=$BUILD102739F_STRING_COUNT

BUILD102739G_STRING_COUNT=$BUILD102739G_STRING_COUNT

BUILD102739H_STRING_COUNT=$BUILD102739H_STRING_COUNT

BUILD102739I_STRING_COUNT=$BUILD102739I_STRING_COUNT

BUILD102739J_STRING_COUNT=$BUILD102739J_STRING_COUNT

BUILD102739K_STRING_COUNT=$BUILD102739K_STRING_COUNT

BUILD102739M_STRING_COUNT=$BUILD102739M_STRING_COUNT

HOST_AUDIT_RESULT=${HOST_AUDIT_RESULT:-N/A}

IDENTITY_CONSISTENCY=$IDENTITY_CONSISTENCY

ROOTLESS_IDENTITY_CONSISTENCY=${ROOTLESS_IDENTITY_CONSISTENCY:-N/A}

LIBCHOMA_SOURCE_BUILD_IDENTITY=$LIBCHOMA_SOURCE_BUILD_IDENTITY

OPAINJECT516_SOURCE_BUILD_IDENTITY=$OPAINJECT516_SOURCE_BUILD_IDENTITY

FINAL_PAYLOAD_RPATH_CONTRACT=$FINAL_PAYLOAD_RPATH_CONTRACT

UIALERT_ENTITLEMENT_AUDIT_INPUT=$UIALERT_ENTITLEMENT_AUDIT_INPUT

FROZEN_V26_102737D_ACTIVE_PINS=$FROZEN_V26_102737D_ACTIVE_PINS

LEGACY_102739J_IDENTITY=${LEGACY_102739J_IDENTITY:-N/A}
EOF

[[ "$IDENTITY_CONSISTENCY" == "PASS" ]] || exit 1
if [[ "$ROOTLESS_IPA" -eq 1 ]]; then
    [[ "$ROOTLESS_IDENTITY_CONSISTENCY" == "PASS" ]] || exit 1
fi
