#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT=/tmp/dopamin_tvos_kfd_102739m_src
MODULE_CACHE=/tmp/dt102739m_module_cache
TEMP_IPA=dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa
IPA_NAME=dopamin-tvOS-kfd-102739M-REPAIRED-V6-ENVIRONMENT-CONTRACT-FIX.ipa
OUTPUT_DIR="$REPO_ROOT/Output"
FROZEN_L="$OUTPUT_DIR/dopamin-tvOS-kfd-102739L-PERMANENT-FREEZE.zip"
FROZEN_J="$PROJECT/build/102739J/Handoff516"
HELPER_NAME=dt_probe102739m
HELPER_ENTITLEMENTS="$MAKE_PROJECT/entitlements_build102739m_helper.plist"
TRUST_UUID=1027394d-0000-4000-8000-000000000001

rm -rf "$MAKE_PROJECT" "$MODULE_CACHE"
mkdir -p "$MAKE_PROJECT" "$MODULE_CACHE"

echo "=== BUILD102739M verify frozen lineage ==="
[[ "$(shasum -a 256 "$FROZEN_L" | awk '{print $1}')" == \
    b797ebc898e5e189a836abe6779ad69167db7d3af51dfc408c544a25a7f47748 ]]

echo "=== BUILD102739M prepare isolated source ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739M regenerate inherited pinned resources ==="
DT_REPO_ROOT="$REPO_ROOT" bash "$MAKE_PROJECT/scripts/generate102739k_bootstrap_manifest.sh"
bash "$MAKE_PROJECT/scripts/generate102739l_bootstrap_policy.sh"
DT_BUILD102739J_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$DOPAMINE_ROOT" \
    bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" \
    "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod 0755 "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739M build and sign isolated helper ==="
HELPER_DIR="$MAKE_PROJECT/.theos/obj/build102739m"
HELPER="$HELPER_DIR/$HELPER_NAME"
mkdir -p "$HELPER_DIR"
xcrun --sdk appletvos clang -target arm64-apple-tvos14.0 -Os -Wall -Wextra -Werror \
    "$MAKE_PROJECT/build102739m_helper.c" -o "$HELPER"
/opt/local/bin/ldid -S"$HELPER_ENTITLEMENTS" "$HELPER"
chmod 0755 "$HELPER"
HELPER_ENTITLEMENTS_ACTUAL="$HELPER_DIR/helper_entitlements.plist"
/opt/local/bin/ldid -e "$HELPER" > "$HELPER_ENTITLEMENTS_ACTUAL"
plutil -lint "$HELPER_ENTITLEMENTS_ACTUAL"
[[ "$(plutil -extract 'com.apple.private.sandbox.profile:embedded' raw \
    "$HELPER_ENTITLEMENTS_ACTUAL")" == container ]]
[[ "$(rg -c '=>' < <(plutil -p "$HELPER_ENTITLEMENTS_ACTUAL"))" -eq 1 ]]
for forbidden in platform-application com.apple.private.security.no-sandbox \
    com.apple.private.security.container-required get-task-allow task_for_pid-allow; do
    ! plutil -p "$HELPER_ENTITLEMENTS_ACTUAL" | rg -Fq "\"$forbidden\""
done
HELPER_SHA="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
HELPER_CDHASH="$(codesign -dvvv "$HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)"
[[ "$HELPER_SHA" =~ ^[0-9a-f]{64}$ ]]
[[ "$HELPER_CDHASH" =~ ^[0-9a-f]{40}$ ]]
perl -0pi -e 's/DT102739M_HELPER_SHA256 "[0-9a-fA-F]+"/DT102739M_HELPER_SHA256 "'"$HELPER_SHA"'"/' \
    "$MAKE_PROJECT/build102739m_identity.h"
perl -0pi -e 's/DT102739M_HELPER_CDHASH "[0-9a-fA-F]+"/DT102739M_HELPER_CDHASH "'"$HELPER_CDHASH"'"/' \
    "$MAKE_PROJECT/build102739m_identity.h"
rg -q "DT102739M_HELPER_SHA256 \"$HELPER_SHA\"" "$MAKE_PROJECT/build102739m_identity.h"
rg -q "DT102739M_HELPER_CDHASH \"$HELPER_CDHASH\"" "$MAKE_PROJECT/build102739m_identity.h"

echo "=== BUILD102739M compile and package ==="
CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" DT_WORKSPACE_ROOT="$REPO_ROOT" \
DT_102739M_VARIANT=1 DT_102738_PREBUILT=1 make -C "$MAKE_PROJECT" ipa
[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]]

rm -rf "$PROJECT/build/102739M_REPAIRED_V6"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/102739M_REPAIRED_V6"
rm -f "$PROJECT/build/102739M_REPAIRED_V6/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/102739M_REPAIRED_V6/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=M \
    bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$MAKE_PROJECT/$TEMP_IPA" \
    | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739M_REPAIRED_V6.txt"

echo "=== BUILD102739M inspect packaged binaries ==="
OBJ="$PROJECT/build/102739M_REPAIRED_V6/obj"
mkdir -p "$OBJ"
APP="$OBJ/app_binary"
PACKAGED_HELPER="$OBJ/$HELPER_NAME"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd > "$APP"
unzip -p "$PROJECT/$IPA_NAME" "Payload/dopamin-tvOS-kfd.app/$HELPER_NAME" > "$PACKAGED_HELPER"
cmp -s "$HELPER" "$PACKAGED_HELPER"
[[ "$(shasum -a 256 "$PACKAGED_HELPER" | awk '{print $1}')" == "$HELPER_SHA" ]]
[[ "$(codesign -dvvv "$PACKAGED_HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)" == "$HELPER_CDHASH" ]]
PACKAGED_ENTITLEMENTS="$OBJ/packaged_helper_entitlements.plist"
/opt/local/bin/ldid -e "$PACKAGED_HELPER" > "$PACKAGED_ENTITLEMENTS"
plutil -lint "$PACKAGED_ENTITLEMENTS"

APP_LOAD_COMMANDS="$OBJ/app_load_commands.txt"
EMBEDDED_HELPER="$OBJ/embedded_$HELPER_NAME"
otool -l "$APP" > "$APP_LOAD_COMMANDS"
SECTION_META="$(awk '
    $1 == "sectname" { wanted = ($2 == "__dtmhelper") }
    wanted && $1 == "segname" { segment = $2 }
    wanted && $1 == "size" { size = $2 }
    wanted && $1 == "offset" { print segment, size, $2; exit }
' "$APP_LOAD_COMMANDS")"
[[ -n "$SECTION_META" ]]
read -r SECTION_SEGMENT SECTION_SIZE_HEX SECTION_OFFSET <<< "$SECTION_META"
[[ "$SECTION_SEGMENT" == "__DATA" ]]
[[ "$SECTION_SIZE_HEX" =~ ^0x[0-9a-fA-F]+$ ]]
[[ "$SECTION_OFFSET" =~ ^[0-9]+$ ]]
SECTION_SIZE=$((SECTION_SIZE_HEX))
[[ "$SECTION_SIZE" -eq "$(stat -f %z "$HELPER")" ]]
dd if="$APP" of="$EMBEDDED_HELPER" bs=1 skip="$SECTION_OFFSET" count="$SECTION_SIZE" status=none
cmp -s "$HELPER" "$EMBEDDED_HELPER"
[[ "$(shasum -a 256 "$EMBEDDED_HELPER" | awk '{print $1}')" == "$HELPER_SHA" ]]
[[ "$(codesign -dvvv "$EMBEDDED_HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)" == "$HELPER_CDHASH" ]]
EMBEDDED_ENTITLEMENTS="$OBJ/embedded_helper_entitlements.plist"
/opt/local/bin/ldid -e "$EMBEDDED_HELPER" > "$EMBEDDED_ENTITLEMENTS"
plutil -lint "$EMBEDDED_ENTITLEMENTS"
cp "$HELPER_ENTITLEMENTS_ACTUAL" "$OBJ/source_helper_entitlements.canonical.plist"
cp "$PACKAGED_ENTITLEMENTS" "$OBJ/packaged_helper_entitlements.canonical.plist"
cp "$EMBEDDED_ENTITLEMENTS" "$OBJ/embedded_helper_entitlements.canonical.plist"
plutil -convert binary1 "$OBJ/source_helper_entitlements.canonical.plist"
plutil -convert binary1 "$OBJ/packaged_helper_entitlements.canonical.plist"
plutil -convert binary1 "$OBJ/embedded_helper_entitlements.canonical.plist"
cmp -s "$OBJ/source_helper_entitlements.canonical.plist" \
    "$OBJ/packaged_helper_entitlements.canonical.plist"
cmp -s "$OBJ/source_helper_entitlements.canonical.plist" \
    "$OBJ/embedded_helper_entitlements.canonical.plist"

file "$PACKAGED_HELPER" | tee "$OBJ/helper_file.txt"
otool -L "$PACKAGED_HELPER" | tee "$OBJ/helper_dependencies.txt"
nm -u "$PACKAGED_HELPER" > "$OBJ/helper_undefined.txt"
otool -l "$PACKAGED_HELPER" > "$OBJ/helper_load_commands.txt"
rg -q 'Mach-O 64-bit executable arm64' "$OBJ/helper_file.txt"
[[ "$(rg -c '^\s+/usr/lib/libSystem\.B\.dylib ' "$OBJ/helper_dependencies.txt")" -eq 1 ]]
[[ "$(rg -c '^\s+/' "$OBJ/helper_dependencies.txt")" -eq 1 ]]
for symbol in _proc_pidpath _dprintf _getpid _getuid _geteuid _csops; do
    rg -q "$symbol" "$OBJ/helper_undefined.txt"
done
if rg -q '_(Foundation|objc_|xpc_|posix_spawn|fork|exec|system|open|write|socket|connect|launchctl|dpkg)' \
    "$OBJ/helper_undefined.txt"; then
    echo "ERROR: forbidden M helper import" >&2
    exit 1
fi
rg -q 'platform 3' "$OBJ/helper_load_commands.txt"
! strings "$PACKAGED_HELPER" | rg -Fq "$HELPER_CDHASH"
rg -q 'BUILD102739M_REPAIRED_V6' "$PACKAGED_HELPER"
! strings "$PACKAGED_HELPER" | rg -q 'BUILD102739M_REPAIRED_V[245]'

APP_STRINGS="$OBJ/app_strings.txt"
APP_UNDEFINED="$OBJ/app_undefined.txt"
M_DISASM="$OBJ/m_execution_disassembly.txt"
M_ENTRY_DISASM="$OBJ/m_entry_disassembly.txt"
M_SPAWN_DISASM="$OBJ/m_spawn_disassembly.txt"
M_LOOSE_DISASM="$OBJ/m_loose_diagnostic_disassembly.txt"
FLOW_DISASM="$OBJ/m_order_disassembly.txt"
strings "$APP" > "$APP_STRINGS"
nm -u "$APP" > "$APP_UNDEFINED"
otool -tvV "$APP" > "$M_DISASM"
awk '
    /^_dt_build102739m_run_external_helper_execution_proof:$/ {inside=1}
    inside && /^_[A-Za-z0-9_]+:$/ && $0 != "_dt_build102739m_run_external_helper_execution_proof:" {inside=0}
    inside {print}
' "$M_DISASM" > "$M_ENTRY_DISASM"
awk '
    /^_dt102739m_spawn:$/ {inside=1}
    inside && /^_[A-Za-z0-9_]+:$/ && $0 != "_dt102739m_spawn:" {inside=0}
    inside {print}
' "$M_DISASM" > "$M_SPAWN_DISASM"
awk '
    /^_dt102739m_log_loose_diagnostic:$/ {inside=1}
    inside && /^_[A-Za-z0-9_]+:$/ && $0 != "_dt102739m_log_loose_diagnostic:" {inside=0}
    inside {print}
' "$M_DISASM" > "$M_LOOSE_DISASM"
otool -tvV "$APP" | awk '
    /^_dt102732c_run_constructor_boomerang_only:$/ {inside=1}
    inside && /^_[A-Za-z0-9_]+:$/ && $0 != "_dt102732c_run_constructor_boomerang_only:" {inside=0}
    inside {print}
' > "$FLOW_DISASM"
for call in _dt_cdhash_trustcached _mkdirat _openat \
    _dt_trustcache_upload_batch_cdhashes _dt102739m_spawn; do
    rg -q "$call" "$M_ENTRY_DISASM"
done
for call in _unlinkat _proc_pidpath _fdopendir _readdir; do
    rg -q "$call" "$M_DISASM"
done
for call in _posix_spawn _waitpid _kill; do
    rg -q "$call" "$M_SPAWN_DISASM"
done
[[ "$(rg -c 'symbol stub for: _posix_spawn$' "$M_SPAWN_DISASM")" -eq 1 ]]
[[ "$(rg -c 'bl[[:space:]]+_dt_trustcache_upload_batch_cdhashes$' "$M_ENTRY_DISASM")" -eq 1 ]]
[[ "$(rg -c 'bl[[:space:]]+_dt102739m_spawn$' "$M_ENTRY_DISASM")" -eq 1 ]]
if rg -q '_dt_trustcache_upload_batch_cdhashes|_dt102739m_spawn|_posix_spawn' "$M_LOOSE_DISASM"; then
    echo "ERROR: loose diagnostic reaches trust or spawn" >&2
    exit 1
fi
for call in _posix_spawn _posix_spawn_file_actions_init \
    _posix_spawn_file_actions_adddup2 _posix_spawn_file_actions_addclose \
    _posix_spawn_file_actions_destroy; do
    rg -q "$call" "$APP_UNDEFINED"
done
if rg -q 'posix_spawnattr_set_registered_ports_np|posix_spawnattr_set_persona_np|\bfork\b|\bexecve\b' \
    "$PROJECT/dt_build102739m.m"; then
    echo "ERROR: forbidden M spawn path" >&2
    exit 1
fi
PRETRUST_LINE="$(rg -n 'bl[[:space:]]+_dt_cdhash_trustcached$' "$M_ENTRY_DISASM" | head -1 | cut -d: -f1)"
MKDIR_LINE="$(rg -n 'symbol stub for: _mkdirat$' "$M_ENTRY_DISASM" | head -1 | cut -d: -f1)"
UPLOAD_LINE="$(rg -n 'bl[[:space:]]+_dt_trustcache_upload_batch_cdhashes$' "$M_ENTRY_DISASM" | head -1 | cut -d: -f1)"
SPAWN_LINE="$(rg -n 'bl[[:space:]]+_dt102739m_spawn$' "$M_ENTRY_DISASM" | head -1 | cut -d: -f1)"
[[ "$PRETRUST_LINE" -lt "$MKDIR_LINE" && "$MKDIR_LINE" -lt "$UPLOAD_LINE" \
    && "$UPLOAD_LINE" -lt "$SPAWN_LINE" ]]
rg -q 'char \*const envp\[\] = \{NULL\}' "$PROJECT/dt_build102739m.m"
rg -q 'finalWait == child' "$PROJECT/dt_build102739m.m"
rg -q 'fdopendir\(scanFD\)' "$PROJECT/dt_build102739m.m"
rg -q 'getsectiondata\(&_mh_execute_header' "$PROJECT/dt_build102739m.m"
rg -q 'fields.count != 21' "$PROJECT/dt_build102739m.m"
rg -q 'self_cdhash_rc.*self_cdhash_errno.*self_cdhash=%s' "$PROJECT/build102739m_helper.c"
rg -q 'effective_env_count=%zu env_name_count=%zu' "$PROJECT/build102739m_helper.c"
rg -q 'env_names_hex=%s env_name_overflow=%s env_name_duplicates=%s' \
    "$PROJECT/build102739m_helper.c"
rg -q 'qsort\(env_names, env_name_count' "$PROJECT/build102739m_helper.c"
rg -q 'DT_MAX_ENV_NAMES = 32' "$PROJECT/build102739m_helper.c"
rg -q 'DT_MAX_ENV_NAME_BYTES = 128' "$PROJECT/build102739m_helper.c"
rg -q 'kDT102739MOutputLimit = 32768' "$PROJECT/dt_build102739m.m"
rg -q 'dt102739m_decode_lower_hex\(record\[@"self_cdhash"\]' "$PROJECT/dt_build102739m.m"
rg -q 'dt102739m_decode_environment_names\(record\[@"env_names_hex"\]' \
    "$PROJECT/dt_build102739m.m"
rg -q 'M_PARENT_REQUESTED_ENVIRONMENT_COUNT=0' "$PROJECT/dt_build102739m.m"
rg -q 'M_HELPER_ENVIRONMENT_CAPTURE=%@' "$PROJECT/dt_build102739m.m"
rg -q 'M_HELPER_ENVIRONMENT_POLICY=%@' "$PROJECT/dt_build102739m.m"
rg -q 'M_FAILURE_STAGE=CHILD_ENVIRONMENT_CAPTURE' "$PROJECT/dt_build102739m.m"
rg -q 'M_FAILURE_STAGE=CHILD_ENVIRONMENT_POLICY' "$PROJECT/dt_build102739m.m"
! rg -q 'record\[@"env_count"\]|effective_env_count"\] isEqualToString:@"0"' \
    "$PROJECT/dt_build102739m.m"
rg -q 'memcmp\(childSelfHash, helperHash' "$PROJECT/dt_build102739m.m"
rg -q 'M_STAGED_DESCRIPTOR_HELD_THROUGH_PRESPAWN' "$PROJECT/dt_build102739m.m"
rg -q 'M_LOOSE_DIAGNOSTIC_GATES_EXECUTION=NO' "$PROJECT/dt_build102739m.m"
rg -q 'hasPrefix:@"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_PASS"' "$PROJECT/dt_build102739m.m"
rg -q 'verdict = @"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_PASS_WITH_RESIDUAL_IN_MEMORY_HELPER_TRUST"' \
    "$PROJECT/dt_build102739m.m"
rg -q 'M_HELPER_EMBEDDED_SANDBOX_PROFILE=container' "$PROJECT/dt_build102739m.m"
rg -q 'M_PARENT_SANDBOX_EXTENSION_ISSUE_ENABLED=NO' "$PROJECT/dt_build102739m.m"
rg -q 'M_PARENT_SANDBOX_EXTENSION_CONSUME_ENABLED=NO' "$PROJECT/dt_build102739m.m"
! rg -q 'sandbox_extension_(issue|consume|release)|dt102739m_.*extensions' \
    "$PROJECT/dt_build102739m.m"
! rg -q 'sandbox_extension_(issue|consume|release)|dt102739m_.*extensions' "$M_ENTRY_DISASM"
rg -q 'termSignal != 0 && !recordOK' "$PROJECT/dt_build102739m.m"
WAIT_CLASSIFIER_LINE="$(rg -n 'else if \(!reaped \|\| timeout\)' \
    "$PROJECT/dt_build102739m.m" | cut -d: -f1)"
TERM_CLASSIFIER_LINE="$(rg -n 'else if \(termSignal != 0 && !recordOK\)' \
    "$PROJECT/dt_build102739m.m" | cut -d: -f1)"
PROTOCOL_CLASSIFIER_LINE="$(rg -n 'else if \(!recordOK \|\| !protocolMatch' \
    "$PROJECT/dt_build102739m.m" | cut -d: -f1)"
ENV_CAPTURE_CLASSIFIER_LINE="$(rg -n 'else if \(!environmentCaptureOK\)' \
    "$PROJECT/dt_build102739m.m" | cut -d: -f1)"
ENV_POLICY_CLASSIFIER_LINE="$(rg -n 'else if \(!environmentPolicyOK\)' \
    "$PROJECT/dt_build102739m.m" | cut -d: -f1)"
[[ "$WAIT_CLASSIFIER_LINE" -lt "$TERM_CLASSIFIER_LINE" \
    && "$TERM_CLASSIFIER_LINE" -lt "$PROTOCOL_CLASSIFIER_LINE" \
    && "$PROTOCOL_CLASSIFIER_LINE" -lt "$ENV_CAPTURE_CLASSIFIER_LINE" \
    && "$ENV_CAPTURE_CLASSIFIER_LINE" -lt "$ENV_POLICY_CLASSIFIER_LINE" ]]
rg -q 'NSString \*jHookPath = dt710_resolve_hook_path\(\);' "$PROJECT/dt_build102739m.m"
! rg -q 'jHookPath = \[handoff stringByAppendingPathComponent:@"launchdhook516\.dylib"\]' \
    "$PROJECT/dt_build102739m.m"
for marker in M_PRESERVATION_PID1_PATH_AVAILABLE M_PRESERVATION_PID1_PROC_AVAILABLE \
    M_PRESERVATION_LTOP_SHA_AVAILABLE M_PRESERVATION_J_HOOK_PATH_ROLE=POST_SIGN_PREBOOT_ARTIFACT \
    M_PRESERVATION_J_HOOK_CDHASH_AVAILABLE M_PRESERVATION_J_HOOK_TRUSTED \
    M_PRESERVATION_J_HELPER_PATH_ROLE=INSTALLED_BUNDLE_ARTIFACT \
    M_PRESERVATION_J_HELPER_CDHASH_AVAILABLE M_PRESERVATION_J_HELPER_TRUSTED \
    M_PRESERVATION_PREREQUISITES; do
    rg -q "$marker" "$PROJECT/dt_build102739m.m"
done
! rg -q '\b(usleep|sleep)\s*\(' "$PROJECT/dt_build102739m.m"
rg -Fq "$HELPER_SHA" "$APP_STRINGS"
rg -Fq "$HELPER_CDHASH" "$APP_STRINGS"

RESTORE_LINE="$(rg -n 'bl[[:space:]]+_dt102732c_restore_wall2$' "$FLOW_DISASM" | tail -1 | cut -d: -f1)"
K_LINE="$(rg -n 'bl[[:space:]]+_dt_build102739k_run_rootful_bootstrap_preflight$' "$FLOW_DISASM" | head -1 | cut -d: -f1)"
L_LINE="$(rg -n 'bl[[:space:]]+_dt_build102739l_run_rootful_bootstrap_policy_preflight$' "$FLOW_DISASM" | head -1 | cut -d: -f1)"
M_LINE="$(rg -n 'bl[[:space:]]+_dt_build102739m_run_external_helper_execution_proof$' "$FLOW_DISASM" | head -1 | cut -d: -f1)"
[[ "$RESTORE_LINE" -lt "$K_LINE" && "$K_LINE" -lt "$L_LINE" && "$L_LINE" -lt "$M_LINE" ]]

for marker in BUILD102739M_SCOPE=EXTERNAL_HELPER_EXECUTION_PROOF \
    BUILD102739M_BASELINE=BUILD102739L_FROZEN_DEVICE_PASS \
    BUILD102739L_BASELINE_RESULT=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PASS \
    M_HELPER_SPAWN_API=posix_spawn M_PARENT_ENVIRONMENT_REQUEST=EXPLICIT_EMPTY \
    M_HELPER_WAIT_TIMEOUT_MS=8000 M_HELPER_OBSERVATION_INTERVAL_MS=100 \
    M_HELPER_REGISTERED_MACH_PORTS=NO M_HELPER_ROOT_PERSONA=NO \
    M_HELPER_CHILD_PLATFORMIZE_CALL=NO M_KERNEL_TRUSTCACHE_NODE_CONTENT_INSPECTED=NO \
    M_BOOTSTRAP_ARCHIVE_TOUCHED=NO \
    BUILD102739M_VARIANT=BUILD102739M_REPAIRED_V6 \
    BUILD102739M_PROTOCOL= M_TRANSPORT=EMBEDDED_FINAL_SIGNED_BYTES \
    M_PARENT_REQUESTED_ENVIRONMENT_COUNT=0 M_HELPER_EFFECTIVE_ENVIRONMENT_NAMES_HEX= \
    M_HELPER_ENVIRONMENT_CAPTURE= M_HELPER_ENVIRONMENT_POLICY= \
    M_LOOSE_DIAGNOSTIC_GATES_EXECUTION=NO M_HELPER_SELF_CDHASH_MATCH= \
    BUILD102739M_FINAL_RESULT=; do
    rg -q "$marker" "$APP_STRINGS"
done
for ui in 'Run Bring-Up' 'Diagnostics' 'Remove Legacy /var/jb'; do
    rg -q "$ui" "$APP_STRINGS"
done
rg -q '#ifndef DT_BUILD102739M_VARIANT' "$PROJECT/main.m"
rg -q 'run699PlatformHookClosureWithConfig' "$PROJECT/main.m"

for frozen in launchdhook516.dylib dt_opainject516 dt_jbctl516 \
    libjailbreak.dylib libchoma.dylib; do
    cmp -s "$FROZEN_J/$frozen" "$PROJECT/build/102739M_REPAIRED_V6/Handoff516/$frozen"
done
if unzip -l "$PROJECT/$IPA_NAME" | rg -q '\.tar\.zst|\.deb$|PurePKG\.app'; then
    echo "ERROR: M introduced bootstrap/package payload" >&2
    exit 1
fi

IPA_SHA="$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"
IPA_SIZE="$(stat -f %z "$PROJECT/$IPA_NAME")"
IPA_TIMESTAMP="$(stat -f '%Sm' -t '%Y-%m-%dT%H:%M:%S%z' "$PROJECT/$IPA_NAME")"
HOOK_SHA="$(shasum -a 256 "$PROJECT/build/102739M_REPAIRED_V6/Handoff516/launchdhook516.dylib" | awk '{print $1}')"
J_HELPER_SHA="$(shasum -a 256 "$PROJECT/build/102739M_REPAIRED_V6/Handoff516/dt_opainject516" | awk '{print $1}')"

{
    echo BUILD102739M_REPAIRED_V6_FINAL_HOST_AUDIT
    echo VARIANT=BUILD102739M_REPAIRED_V6
    echo BASELINE_VARIANT=BUILD102739L
    echo TARGET_MODEL=AppleTV6,2
    echo TARGET_BUILD=20L563
    echo FROZEN_L_ARCHIVE_SHA256_MATCH=YES
    echo CHANGESET_SCOPE=BUILD102739M_ENVIRONMENT_CONTRACT_REPAIR
    echo UI_LAYOUT_INHERITED=YES
    echo RUN_BRINGUP_TARGET_MATCHES_FROZEN_L_PATH=YES
    echo G1_G4_VISIBLE=NO
    echo G1_G4_CALLABLE_FROM_UI=NO
    echo M_HELPER_COUNT=1
    echo M_HELPER_FINAL_SIGNED=YES
    echo M_HELPER_ARM64=YES
    echo M_HELPER_PLATFORM_TVOS=YES
    echo M_HELPER_DEPENDENCY_GATE=PASS
    echo M_V6_HELPER_ENTITLEMENT_PROFILE=container
    echo M_V6_HELPER_ENTITLEMENT_COUNT=1
    echo M_V6_HELPER_FORBIDDEN_ENTITLEMENT_COUNT=0
    echo M_V6_HELPER_ENTITLEMENTS_PACKAGED_MATCH=YES
    echo M_V6_HELPER_ENTITLEMENTS_EMBEDDED_MATCH=YES
    echo M_HELPER_SHA256="$HELPER_SHA"
    echo M_HELPER_CDHASH="$HELPER_CDHASH"
    echo M_HELPER_EXPECTED_CDHASH_EMBEDDED_IN_HELPER=NO
    echo M_FINAL_IPA_EMBEDDED_SECTION=__DATA,__dtmhelper
    echo M_FINAL_IPA_EMBEDDED_PAYLOAD_SIZE_MATCH=YES
    echo M_FINAL_IPA_EMBEDDED_PAYLOAD_SHA256_MATCH=YES
    echo M_FINAL_IPA_LOOSE_HELPER_SHA256_MATCH=YES
    echo M_FINAL_IPA_LOOSE_HELPER_CDHASH_MATCH=YES
    echo M_LOOSE_HELPER_EXECUTION_SOURCE=NO
    echo M_LOOSE_HELPER_TRUST_SOURCE=NO
    echo M_EMBEDDED_STAGED_HELPER_ONLY_EXECUTION_SOURCE=YES
    echo M_EMBEDDED_STAGED_HELPER_ONLY_TRUST_SOURCE=YES
    echo M_PROTOCOL_PRODUCER_PARSER_SCHEMA_MATCH=YES
    echo M_PRESERVATION_J_HOOK_PATH_ROLE=POST_SIGN_PREBOOT_ARTIFACT
    echo M_PRESERVATION_J_HELPER_PATH_ROLE=INSTALLED_BUNDLE_ARTIFACT
    echo M_PRESERVATION_PREDICATES_INDIVIDUALLY_TELEMETRIED=YES
    echo M_BUNDLE_LAUNCHDHOOK_TRUST_PREDICATE_REMOVED=YES
    echo M_STAGED_DESCRIPTOR_HELD_THROUGH_PRESPAWN=YES
    echo M_STAGED_IDENTITY_DOMINATES_TRUST_UPLOAD=YES
    echo M_PRESPAWN_REVALIDATION_DOMINATES_SPAWN=YES
    echo M_PARENT_SANDBOX_EXTENSION_ISSUE_ENABLED=NO
    echo M_PARENT_SANDBOX_EXTENSION_CONSUME_ENABLED=NO
    echo M_PARENT_SANDBOX_SLOT0_REPLACED=NO
    echo M_GLOBAL_UNSANDBOX_ENABLED=NO
    echo M_TRUSTCACHE_UUID="$TRUST_UUID"
    echo M_DIRECT_POSIX_SPAWN=YES
    echo M_EXPLICIT_EMPTY_ENVIRONMENT=YES
    echo M_PARENT_REQUESTED_ENVIRONMENT_COUNT=0
    echo M_EFFECTIVE_ENVIRONMENT_COUNT_HARDCODED=NO
    echo M_EFFECTIVE_ENVIRONMENT_NAME_LIMIT=32
    echo M_EFFECTIVE_ENVIRONMENT_NAME_BYTE_LIMIT=128
    echo M_EFFECTIVE_ENVIRONMENT_RECORD_CAPTURE_LIMIT=32768
    echo M_EFFECTIVE_ENVIRONMENT_NAMES_ENCODING=LOWERCASE_HEX_SORTED
    echo M_EFFECTIVE_ENVIRONMENT_VALUES_CAPTURED=NO
    echo M_EFFECTIVE_ENVIRONMENT_CAPTURE_REQUIRED=YES
    echo M_EFFECTIVE_ENVIRONMENT_DYLD_COUNT_REQUIRED=0
    echo M_EFFECTIVE_ENVIRONMENT_DYLD_INSERT_REQUIRED=ABSENT
    echo M_ENVIRONMENT_FAILURE_CLASSIFIERS_SPLIT=YES
    echo M_FIXED_DELAY_AFTER_TRUST_UPLOAD_US=0
    echo M_INHERITED_TRIGGER_TIMEOUT_SECONDS=3
    echo M_HELPER_WAIT_TIMEOUT_MS=8000
    echo M_HELPER_OBSERVATION_INTERVAL_MS=100
    echo M_FRESH_PROOF_PRETRUST_CHECK_BEFORE_STAGING=YES
    echo M_PRETRUST_DOMINATES_STAGING=YES
    echo M_TRUST_UPLOAD_DOMINATES_SPAWN=YES
    echo M_SPAWN_CALL_COUNT=1
    echo M_TIMEOUT_REAP_RESULT_CHECKED=YES
    echo M_RUN_DIRECTORY_ENUMERATED_BEFORE_REMOVAL=YES
    echo M_KERNEL_NODE_CONTENT_INSPECTION_CLAIMED=NO
    echo BOOTSTRAP_ARCHIVE_INCLUDED_BY_M=NO
    echo EXTRACTION_ENGINE_INCLUDED_BY_M=NO
    echo DPKG_INVOCATION_ENABLED=NO
    echo PUREPKG_ENABLED=NO
    echo ELLEKIT_ENABLED=NO
    echo SERVICE_LOAD_ENABLED=NO
    echo ACCOUNT_MUTATION_ENABLED=NO
    echo PERSISTENCE_ENABLED=NO
    echo USERSPACE_REBOOT_ENABLED=NO
    echo WALL2_RESTORE_BEFORE_K_BEFORE_L_BEFORE_M=PASS
    echo FROZEN_J_HOOK_SHA256="$HOOK_SHA"
    echo FROZEN_J_HELPER_SHA256="$J_HELPER_SHA"
    echo IPA_FILENAME="$IPA_NAME"
    echo IPA_SHA256="$IPA_SHA"
    echo IPA_SIZE="$IPA_SIZE"
    echo IPA_TIMESTAMP="$IPA_TIMESTAMP"
    echo HOST_AUDIT_RESULT=PASS
} | tee "$PROJECT/docs/reports/BUILD102739M_REPAIRED_V6_FINAL_HOST_AUDIT.txt"

mkdir -p "$OUTPUT_DIR"
cp "$PROJECT/$IPA_NAME" "$OUTPUT_DIR/$IPA_NAME"
cp "$PROJECT/docs/reports/BUILD102739M_REPAIRED_V6_FINAL_HOST_AUDIT.txt" "$OUTPUT_DIR/"
cp "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739M_REPAIRED_V6.txt" "$OUTPUT_DIR/"
echo BUILD102739M_REPAIRED_V6_PACKAGE_COMPLETE=YES
echo "BUILD102739M_IPA_PATH=$OUTPUT_DIR/$IPA_NAME"
echo "BUILD102739M_IPA_SHA256=$IPA_SHA"
