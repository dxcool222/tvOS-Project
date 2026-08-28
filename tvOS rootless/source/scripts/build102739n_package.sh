#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT=/tmp/dopamin_tvos_kfd_102739n_src
MODULE_CACHE=/tmp/dt102739n_module_cache
TEMP_IPA=dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa
IPA_NAME=dopamin-tvOS-kfd-102739N-PERSISTED-STATE-DIAGNOSTIC-REPAIRED-V3.ipa
OUTPUT_DIR="$REPO_ROOT/Output"
BUILD_DIR="$PROJECT/build/102739N"
FREEZE="$OUTPUT_DIR/dopamin-tvOS-kfd-102739M-REPAIRED-V6-PERMANENT-FREEZE.zip"
FREEZE_DIR="$OUTPUT_DIR/dopamin-tvOS-kfd-102739M-REPAIRED-V6-PERMANENT-FREEZE"
KNOWN_GOOD="$FREEZE_DIR/KNOWN_GOOD_102739M_REPAIRED_V6"
M_HELPER="$KNOWN_GOOD/dt_probe102739m"
N_HELPER_NAME=dt_probe102739n
N_ENTITLEMENTS="$MAKE_PROJECT/entitlements_build102739n_helper.plist"
BLUEPRINT="$REPO_ROOT/blueprint(BUILD102739N).md"

rm -rf "$MAKE_PROJECT" "$MODULE_CACHE"
mkdir -p "$MAKE_PROJECT" "$MODULE_CACHE" "$OUTPUT_DIR"

echo "=== BUILD102739N verify immutable authorities ==="
[[ "$(shasum -a 256 "$FREEZE" | awk '{print $1}')" == ee55d959339930c3f9ba3371cbd0afe8495dfd27f7e8408e96d90ec7289881f0 ]]
(cd "$FREEZE_DIR" && shasum -a 256 -c SHA256SUMS.txt >/dev/null)
[[ "$(shasum -a 256 "$KNOWN_GOOD/dopamin-tvOS-kfd-102739M-REPAIRED-V6-ENVIRONMENT-CONTRACT-FIX.ipa" | awk '{print $1}')" == 50e8830f9dad77e8bb098f182eec3d8bb98d88c65f658d1636310b88cdbb4e60 ]]
[[ "$(shasum -a 256 "$M_HELPER" | awk '{print $1}')" == d56cc4c6ea2c1eaaaacaef3a25a2b7037955c90ed7f612b96a5e08675cf246e2 ]]
[[ "$(codesign -dvvv "$M_HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)" == 3c064750d583755757a050ec2e3f637c75de6d88 ]]
[[ "$(shasum -a 256 "$BLUEPRINT" | awk '{print $1}')" == f502f295c17914ac9cc6bb034a9328349fb84e46ffba525c7c7818cba6c7cd51 ]]

echo "=== BUILD102739N host classifier vectors ==="
clang -std=c11 -Wall -Wextra -Werror "$PROJECT/build102739n_classifier_test.c" -o /tmp/build102739n_classifier_test
/tmp/build102739n_classifier_test

echo "=== BUILD102739N prepare isolated source ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739N regenerate inherited pinned resources ==="
DT_REPO_ROOT="$REPO_ROOT" bash "$MAKE_PROJECT/scripts/generate102739k_bootstrap_manifest.sh"
bash "$MAKE_PROJECT/scripts/generate102739l_bootstrap_policy.sh"
DT_BUILD102739J_MODE=1 DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" DOPAMINE="$DOPAMINE_ROOT" bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod 0755 "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739N install exact frozen M helper input ==="
mkdir -p "$MAKE_PROJECT/.theos/obj/build102739m"
cp "$M_HELPER" "$MAKE_PROJECT/.theos/obj/build102739m/dt_probe102739m"
chmod 0755 "$MAKE_PROJECT/.theos/obj/build102739m/dt_probe102739m"
perl -0pi -e 's/DT102739M_HELPER_SHA256 "[0-9a-fA-F]+"/DT102739M_HELPER_SHA256 "d56cc4c6ea2c1eaaaacaef3a25a2b7037955c90ed7f612b96a5e08675cf246e2"/' "$MAKE_PROJECT/build102739m_identity.h"
perl -0pi -e 's/DT102739M_HELPER_CDHASH "[0-9a-fA-F]+"/DT102739M_HELPER_CDHASH "3c064750d583755757a050ec2e3f637c75de6d88"/' "$MAKE_PROJECT/build102739m_identity.h"

echo "=== BUILD102739N build and sign final tvOS helper ==="
N_HELPER_DIR="$MAKE_PROJECT/.theos/obj/build102739n"
N_HELPER="$N_HELPER_DIR/$N_HELPER_NAME"
mkdir -p "$N_HELPER_DIR"
xcrun --sdk appletvos clang -target arm64-apple-tvos14.0 -Os -Wall -Wextra -Werror "$MAKE_PROJECT/build102739n_helper.c" -o "$N_HELPER"
/opt/local/bin/ldid -S"$N_ENTITLEMENTS" "$N_HELPER"
chmod 0755 "$N_HELPER"
N_ENTITLEMENTS_ACTUAL="$N_HELPER_DIR/helper_entitlements.plist"
/opt/local/bin/ldid -e "$N_HELPER" > "$N_ENTITLEMENTS_ACTUAL"
plutil -lint "$N_ENTITLEMENTS_ACTUAL"
[[ "$(plutil -extract 'com.apple.private.sandbox.profile:embedded' raw "$N_ENTITLEMENTS_ACTUAL")" == container ]]
[[ "$(rg -c '=>' < <(plutil -p "$N_ENTITLEMENTS_ACTUAL"))" -eq 1 ]]
for forbidden in platform-application com.apple.private.security.no-sandbox com.apple.private.security.container-required get-task-allow task_for_pid-allow; do
    ! plutil -p "$N_ENTITLEMENTS_ACTUAL" | rg -Fq "\"$forbidden\""
done
N_SHA="$(shasum -a 256 "$N_HELPER" | awk '{print $1}')"
N_CDHASH="$(codesign -dvvv "$N_HELPER" 2>&1 | sed -n 's/^CDHash=//p' | head -1)"
[[ "$N_SHA" =~ ^[0-9a-f]{64}$ ]]
[[ "$N_CDHASH" =~ ^[0-9a-f]{40}$ ]]
[[ "$N_CDHASH" != 3c064750d583755757a050ec2e3f637c75de6d88 ]]
perl -0pi -e 's/DT102739N_HELPER_SHA256 "[0-9a-fA-F]+"/DT102739N_HELPER_SHA256 "'"$N_SHA"'"/' "$MAKE_PROJECT/build102739n_identity.h"
perl -0pi -e 's/DT102739N_HELPER_CDHASH "[0-9a-fA-F]+"/DT102739N_HELPER_CDHASH "'"$N_CDHASH"'"/' "$MAKE_PROJECT/build102739n_identity.h"

echo "=== BUILD102739N compile and package ==="
CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" DT_WORKSPACE_ROOT="$REPO_ROOT" DT_102739N_VARIANT=1 DT_102738_PREBUILT=1 make -C "$MAKE_PROJECT" ipa
[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]]

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/obj"
cp "$MAKE_PROJECT/$TEMP_IPA" "$BUILD_DIR/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$OUTPUT_DIR/$IPA_NAME"
cp "$N_HELPER" "$BUILD_DIR/$N_HELPER_NAME"
cp "$M_HELPER" "$BUILD_DIR/dt_probe102739m"

echo "=== BUILD102739N inspect packaged binaries ==="
OBJ="$BUILD_DIR/obj"
APP="$OBJ/app_binary"
PACKAGED_N="$OBJ/$N_HELPER_NAME"
PACKAGED_M="$OBJ/dt_probe102739m"
unzip -p "$OUTPUT_DIR/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd > "$APP"
unzip -p "$OUTPUT_DIR/$IPA_NAME" "Payload/dopamin-tvOS-kfd.app/$N_HELPER_NAME" > "$PACKAGED_N"
unzip -p "$OUTPUT_DIR/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dt_probe102739m > "$PACKAGED_M"
cmp -s "$N_HELPER" "$PACKAGED_N"
cmp -s "$M_HELPER" "$PACKAGED_M"
[[ "$(shasum -a 256 "$PACKAGED_N" | awk '{print $1}')" == "$N_SHA" ]]
[[ "$(codesign -dvvv "$PACKAGED_N" 2>&1 | sed -n 's/^CDHash=//p' | head -1)" == "$N_CDHASH" ]]

APP_LOAD="$OBJ/app_load_commands.txt"
APP_DISASM="$OBJ/app_disassembly.txt"
APP_UNDEFINED="$OBJ/app_undefined.txt"
APP_STRINGS="$OBJ/app_strings.txt"
otool -l "$APP" > "$APP_LOAD"
otool -tvV "$APP" > "$APP_DISASM"
nm -u "$APP" > "$APP_UNDEFINED"
strings "$APP" > "$APP_STRINGS"

extract_section() {
    local section="$1" output="$2" expected="$3"
    local meta segment size_hex offset size
    meta="$(awk -v target="$section" '
        $1 == "sectname" { wanted = ($2 == target) }
        wanted && $1 == "segname" { segment = $2 }
        wanted && $1 == "size" { size = $2 }
        wanted && $1 == "offset" { print segment, size, $2; exit }
    ' "$APP_LOAD")"
    [[ -n "$meta" ]]
    read -r segment size_hex offset <<< "$meta"
    [[ "$segment" == "__DATA" ]]
    size=$((size_hex))
    [[ "$size" -eq "$(stat -f %z "$expected")" ]]
    dd if="$APP" of="$output" bs=1 skip="$offset" count="$size" status=none
    cmp -s "$expected" "$output"
}
extract_section __dtmhelper "$OBJ/embedded_dt_probe102739m" "$M_HELPER"
extract_section __dtnhelper "$OBJ/embedded_dt_probe102739n" "$N_HELPER"

file "$PACKAGED_N" > "$OBJ/n_helper_file.txt"
otool -L "$PACKAGED_N" > "$OBJ/n_helper_dependencies.txt"
nm -u "$PACKAGED_N" > "$OBJ/n_helper_undefined.txt"
otool -l "$PACKAGED_N" > "$OBJ/n_helper_load_commands.txt"
otool -tvV "$PACKAGED_N" > "$OBJ/n_helper_disassembly.txt"
rg -q 'Mach-O 64-bit executable arm64' "$OBJ/n_helper_file.txt"
[[ "$(rg -c '^\s+/usr/lib/libSystem\.B\.dylib ' "$OBJ/n_helper_dependencies.txt")" -eq 1 ]]
[[ "$(rg -c '^\s+/' "$OBJ/n_helper_dependencies.txt")" -eq 1 ]]
rg -q 'platform 3' "$OBJ/n_helper_load_commands.txt"
rg -q '_dprintf' "$OBJ/n_helper_undefined.txt"
[[ "$(rg -c 'symbol stub for: _dprintf$' "$OBJ/n_helper_disassembly.txt")" -eq 1 ]]
! rg -q '_(open|write|fwrite|fprintf|puts|xpc_|socket|connect|posix_spawn|fork|exec|system|launchctl|dpkg)' "$OBJ/n_helper_undefined.txt"

for symbol in _sysctlbyname _uuid_parse _uuid_unparse_lower _renameatx_np _openat _mkdirat _fsync _posix_spawn _waitpid _kill; do
    rg -q "$symbol" "$APP_UNDEFINED"
done
for marker in BUILD102739N_V2 RUN_A_FRESH RUN_B_REACTIVATE SAME_BOOT_AWAITING_REBOOT BOOT_IDENTITY_AMBIGUOUS PERSISTENT_CONTROL_FIXTURE_STAGE_PASS_AWAITING_REBOOT PERSISTENT_CONTROL_FIXTURE_REACTIVATION_AND_CLEANUP_PASS_WITH_RESIDUAL_IN_MEMORY_TRUST BUILD102739N_M_FULL_EXTERNAL_HELPER_PROOF=NOT_INVOKED_ON_RUN_B; do
    rg -q "$marker" "$APP_STRINGS"
done
for marker in BUILD102739N_M_IDENTITY_SOURCE=EMBEDDED_FINAL_SIGNED_BYTES BUILD102739N_M_EMBEDDED_SECTION=__DATA,__dtmhelper BUILD102739N_M_EMBEDDED_PAYLOAD_SHA256_MATCH BUILD102739N_M_EXPECTED_CDHASH_DECODED BUILD102739N_M_LOOSE_BUNDLE_IDENTITY_GATES_RUN_B=NO; do
    rg -q "$marker" "$APP_STRINGS"
done
for marker in BUILD102739N_PERSISTED_DIAGNOSTIC_REVISION=REPAIRED_V3 BUILD102739N_PERSISTED_DIAGNOSTIC_READ_ONLY=YES BUILD102739N_HELPER_DEV_MATCH BUILD102739N_HELPER_INO_MATCH BUILD102739N_CONTROL_IDENTITY_MATCH BUILD102739N_TESTS_IDENTITY_MATCH BUILD102739N_FIXTURE_IDENTITY_MATCH BUILD102739N_PERSISTED_DIAGNOSTIC_RESULT BUILD102739N_DIAGNOSTIC_RECOVERY_MUTATION_ENABLED=NO; do
    rg -q "$marker" "$APP_STRINGS"
done
! rg -q 'dt102739n_resume_cleanup|dt102739n_recover_staging' < <(sed -n '/_dt_build102739n_classify_before_chain:/,/^_dt102739n_snapshot_protected:/p' "$APP_DISASM")
M_SNAPSHOT_DISASM="$OBJ/m_snapshot_disassembly.txt"
sed -n '/_dt102739n_m_snapshot:/,/^_dt102739n_cleanup_text:/p' "$APP_DISASM" > "$M_SNAPSHOT_DISASM"
for symbol in _getsectiondata _dt102739n_sha256_bytes _dt102739n_decode_lower_hex _dt_cdhash_trustcached; do
    rg -q "$symbol" "$M_SNAPSHOT_DISASM"
done
! rg -q '_dt102739n_cdhash|_dt_macho_best_cdhash_from_path|_NSBundle' "$M_SNAPSHOT_DISASM"
rg -q 'dt_build102739n_classify_before_chain' "$APP_DISASM"
rg -q 'dt_build102739n_run_persistent_control_fixture_proof' "$APP_DISASM"
rg -q 'dt_build102739m_run_external_helper_execution_proof' "$APP_DISASM"

for forbidden in 'tvbootstrap-ssh' '.tar.zst' 'PurePKG.app'; do
    ! unzip -l "$OUTPUT_DIR/$IPA_NAME" | rg -Fq "$forbidden"
done
! unzip -l "$OUTPUT_DIR/$IPA_NAME" | rg -q '\.deb$'
! rg -q '/var/jb|archive_read|libarchive|dpkg|launchctl|userspace reboot' "$MAKE_PROJECT/dt_build102739n.m" "$MAKE_PROJECT/build102739n_helper.c"

IPA_SHA="$(shasum -a 256 "$OUTPUT_DIR/$IPA_NAME" | awk '{print $1}')"
IPA_SIZE="$(stat -f %z "$OUTPUT_DIR/$IPA_NAME")"
{
    echo BUILD102739N_FINAL_HOST_AUDIT
    echo VARIANT=BUILD102739N_V2
    echo BASELINE_VARIANT=BUILD102739M_REPAIRED_V6
    echo TARGET_MODEL=AppleTV6,2
    echo TARGET_BUILD=20L563
    echo TARGET_SDK_FAMILY=AppleTVOS
    echo DEPLOYMENT_TARGET=14.0
    echo FROZEN_M_ARCHIVE_SHA256_MATCH=YES
    echo FROZEN_M_IPA_SHA256_MATCH=YES
    echo FROZEN_M_SOURCE_AND_ARTIFACTS_UNMODIFIED=YES
    echo N_HELPER_COUNT=1
    echo N_HELPER_FINAL_SIGNED_BEFORE_HASHING=YES
    echo N_HELPER_SHA256="$N_SHA"
    echo N_HELPER_CDHASH="$N_CDHASH"
    echo N_HELPER_EMBEDDED_SANDBOX_PROFILE=container
    echo N_HELPER_DEPENDENCY_GATE=PASS
    echo N_HELPER_DPRINTF_IMPORT=YES
    echo N_HELPER_DIRECT_WRITE_IMPORT=NO
    echo N_LOOSE_PACKAGED_EMBEDDED_HELPER_BYTE_IDENTITY=PASS
    echo N_BOOT_IDENTITY_CLASSIFIER_HOST_VECTORS=PASS
    echo N_TRUSTCACHE_UUID=1027394e-0000-4000-8000-000000000001
    echo N_TRUSTCACHE_PAYLOAD_ENTRY_COUNT=1
    echo N_DESCRIPTOR_RELATIVE_OPERATIONS=YES
    echo N_O_NOFOLLOW_GATE=PASS
    echo N_O_EXCL_GATE=PASS
    echo N_MANIFEST_COMMIT_CLEANUP_ATOMIC_PUBLISH=YES
    echo N_RUN_A_REQUIRES_FRESH_M_PASS=YES
    echo N_RUN_B_CALLS_M_FRESH_PROOF=NO
    echo N_RUN_B_M_IDENTITY_SOURCE=EMBEDDED_FINAL_SIGNED_BYTES
    echo N_RUN_B_M_EMBEDDED_SECTION=__DATA,__dtmhelper
    echo N_RUN_B_M_EMBEDDED_BYTE_IDENTITY=PASS
    echo N_RUN_B_M_LOOSE_BUNDLE_IDENTITY_GATES_EXECUTION=NO
    echo N_PERSISTED_STATE_DIAGNOSTIC_REVISION=REPAIRED_V3
    echo N_PERSISTED_STATE_DIAGNOSTIC_READ_ONLY=YES
    echo N_PERSISTED_STATE_VALIDATION_RELAXED=NO
    echo N_CLASSIFIER_RECOVERY_MUTATION_ENABLED=NO
    echo N_SAME_BOOT_UPLOAD_COUNT=0
    echo N_SAME_BOOT_SPAWN_COUNT=0
    echo NEW_KERNEL_OFFSET_COUNT=0
    echo NEW_LAUNCHD_OFFSET_COUNT=0
    echo NEW_UI_BUTTON_COUNT=0
    echo BOOTSTRAP_INSTALL_ENABLED=NO
    echo IPA_NAME="$IPA_NAME"
    echo IPA_SHA256="$IPA_SHA"
    echo IPA_SIZE="$IPA_SIZE"
    echo HOST_RESULT=PASS
} | tee "$BUILD_DIR/BUILD102739N_FINAL_HOST_AUDIT.txt"
cp "$BUILD_DIR/BUILD102739N_FINAL_HOST_AUDIT.txt" "$PROJECT/docs/reports/BUILD102739N_FINAL_HOST_AUDIT.txt"
shasum -a 256 "$OUTPUT_DIR/$IPA_NAME" > "$OUTPUT_DIR/$IPA_NAME.sha256"
echo "OUTPUT_IPA=$OUTPUT_DIR/$IPA_NAME"
echo "OUTPUT_IPA_SHA256=$IPA_SHA"
