#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739k_obs2_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739K-OBS2-CONSOLE-VISIBLE-READ-ONLY-PREFLIGHT.ipa"
BUILD_SLOT="102739K_OBS2"
OUTPUT_DIR="$REPO_ROOT/Output"
ARCHIVE="$REPO_ROOT/tvOS/tvbootstrap-ssh-1900.tar.zst"
FROZEN_J="$PROJECT/build/102739J/Handoff516"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739k_obs2_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739K-OBS2 verify frozen J and pinned bootstrap inputs ==="
[[ "$(shasum -a 256 "$PROJECT/build/102739J/dopamin-tvOS-kfd-102739J-CONTROLLED-REPLY-ROUNDTRIP.ipa" | awk '{print $1}')" == \
    "5e5937d14f93d95f43cb6a5c1d5c3578e045a5b4dfbe3e2c36029f7e2a5bd000" ]]
[[ "$(shasum -a 256 "$FROZEN_J/launchdhook516.dylib" | awk '{print $1}')" == \
    "1aac987a875427fd4e1ffe67d2373f56cb0599ce856af31a094600d2d688141e" ]]
[[ "$(shasum -a 256 "$FROZEN_J/dt_opainject516" | awk '{print $1}')" == \
    "b21ebb77d83e1fb78fa03e9a3c1ff9c40c888a032b0eefa03299bbae942ee67f" ]]
[[ -f "$ARCHIVE" ]]

echo "=== BUILD102739K-OBS2 prepare isolated source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739K-OBS2 generate pinned read-only destination manifest ==="
DT_REPO_ROOT="$REPO_ROOT" \
    bash "$MAKE_PROJECT/scripts/generate102739k_bootstrap_manifest.sh"

echo "=== BUILD102739K-OBS2 rebuild frozen J hook and observer ==="
DT_BUILD102739J_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$DOPAMINE_ROOT" \
    bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739K-OBS2 regenerate unchanged auxiliary helpers ==="
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" \
    "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod +x "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739K-OBS2 compile and package on repaired K flags ==="
DT_WORKSPACE_ROOT="$REPO_ROOT" DT_102739K_VARIANT=1 DT_102738_PREBUILT=1 \
    make -C "$MAKE_PROJECT" ipa

[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]]
rm -rf "$PROJECT/build/$BUILD_SLOT"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/$BUILD_SLOT"
rm -f "$PROJECT/build/$BUILD_SLOT/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/$BUILD_SLOT/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=K \
    bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$PROJECT/$IPA_NAME" \
    | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739K_OBS2.txt"

APP_BINARY="$PROJECT/build/$BUILD_SLOT/obj/app_binary"
APP_STRINGS="$PROJECT/build/$BUILD_SLOT/obj/app_strings.txt"
PREFLIGHT_DISASM="$PROJECT/build/$BUILD_SLOT/obj/preflight_disassembly.txt"
APP_FLOW_DISASM="$PROJECT/build/$BUILD_SLOT/obj/wall2_restore_order_disassembly.txt"
ACTIVE_WINDOW_DISASM="$PROJECT/build/$BUILD_SLOT/obj/wall2_post_inject_active_window_disassembly.txt"
PACKAGED_MANIFEST="$PROJECT/build/$BUILD_SLOT/obj/BUILD102739K_CF1900_PATHS.tsv"
SOURCE_MANIFEST="$MAKE_PROJECT/bootstrap_preflight/BUILD102739K_CF1900_PATHS.tsv"
mkdir -p "$PROJECT/build/$BUILD_SLOT/obj"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd > "$APP_BINARY"
strings "$APP_BINARY" > "$APP_STRINGS"
unzip -p "$PROJECT/$IPA_NAME" \
    Payload/dopamin-tvOS-kfd.app/BUILD102739K_CF1900_PATHS.tsv > "$PACKAGED_MANIFEST"
cmp -s "$SOURCE_MANIFEST" "$PACKAGED_MANIFEST"

otool -tvV "$APP_BINARY" \
    | awk '/^_dt_build102739k_run_rootful_bootstrap_preflight:/{inside=1} /^_dt_choma_macho_best_cdhash_from_path:/{inside=0} inside' \
    > "$PREFLIGHT_DISASM"
rg -q '^_dt_build102739k_run_rootful_bootstrap_preflight:$' "$PREFLIGHT_DISASM"
for call in _lstat _stat _statfs _access _sysctlbyname _geteuid \
    _dt_build_rootful_remount_ok _dt_spawn_plain_capture; do
    rg -q "$call" "$PREFLIGHT_DISASM"
done

otool -tvV "$APP_BINARY" \
    | awk '/^_dt102732c_run_constructor_boomerang_only:/{inside=1} /^_dt102732c_restore_wall2:/{inside=0} inside' \
    > "$APP_FLOW_DISASM"
for call in _dt681_spawn_opainject_launchd _dt102732c_restore_wall2 \
    _dt102732c_reemit_hook_capture _dt102735d_poll_trace_and_boomerang; do
    rg -q "$call" "$APP_FLOW_DISASM"
done
INJECT_LINE="$(rg -n 'bl[[:space:]]+_dt681_spawn_opainject_launchd$' "$APP_FLOW_DISASM" | tail -1 | cut -d: -f1)"
RESTORE_LINE="$(rg -n 'bl[[:space:]]+_dt102732c_restore_wall2$' "$APP_FLOW_DISASM" | tail -1 | cut -d: -f1)"
REPLAY_LINE="$(rg -n 'bl[[:space:]]+_dt102732c_reemit_hook_capture$' "$APP_FLOW_DISASM" | tail -1 | cut -d: -f1)"
POLL_LINE="$(rg -n 'bl[[:space:]]+_dt102735d_poll_trace_and_boomerang$' "$APP_FLOW_DISASM" | head -1 | cut -d: -f1)"
[[ "$INJECT_LINE" -lt "$RESTORE_LINE" ]]
[[ "$RESTORE_LINE" -lt "$REPLAY_LINE" ]]
[[ "$REPLAY_LINE" -lt "$POLL_LINE" ]]
PREFLIGHT_CALL_LINE="$(rg -n 'bl[[:space:]]+_dt_build102739k_run_rootful_bootstrap_preflight$' "$APP_FLOW_DISASM" | head -1 | cut -d: -f1)"
[[ "$RESTORE_LINE" -lt "$PREFLIGHT_CALL_LINE" ]]
[[ "$POLL_LINE" -lt "$PREFLIGHT_CALL_LINE" ]]
sed -n "${INJECT_LINE},${RESTORE_LINE}p" "$APP_FLOW_DISASM" > "$ACTIVE_WINDOW_DISASM"
if rg -q '_dt699_stage|_dt102732c_reemit_hook_capture|_dt102735d_poll_trace_and_boomerang|symbol stub for: _(fsync|sleep|usleep|nanosleep)$' \
    "$ACTIVE_WINDOW_DISASM"; then
    echo "ERROR: blocking telemetry or observation entered the post-inject Wall2 window" >&2
    exit 1
fi
sed -n "${RESTORE_LINE},${REPLAY_LINE}p" "$APP_FLOW_DISASM" \
    | rg -q 'symbol stub for: _proc_rele$'
if rg -q 'symbol stub for: _(open|write|pwrite|unlink|remove|rename|mkdir|rmdir|chmod|chown|mount|unmount|symlink|link|truncate|fopen)$' \
    "$PREFLIGHT_DISASM"; then
    echo "ERROR: mutating filesystem API present in BUILD102739K preflight" >&2
    exit 1
fi
if rg -n 'writeToFile|createFile|removeItem|moveItem|copyItem|createDirectory|createSymbolicLink' \
    "$PROJECT/dt_bootstrap_preflight.m"; then
    echo "ERROR: mutating Foundation selector present in BUILD102739K preflight source" >&2
    exit 1
fi
rg -q 'hasPrefix:@"BUILD102739K_"' "$PROJECT/DTRunLogger.m"

for marker in \
    BUILD102739K_SCOPE=ROOTFUL_BOOTSTRAP_READ_ONLY_PREFLIGHT \
    BUILD102739K_BASELINE=BUILD102739J_FROZEN \
    BUILD102739K_BOOTSTRAP_EXTRACTION_ENABLED=NO \
    BUILD102739K_PACKAGE_INSTALL_ENABLED=NO \
    BUILD102739K_SERVICE_MUTATION_ENABLED=NO \
    BUILD102739K_BOOTSTRAP_TARGET_MUTATION_CALLS=0 \
    'BUILD102739K_ACTUAL_REMOUNT_SUCCESS=' \
    'BUILD102739K_ARCHIVE_HASH_PIN_MATCH=' \
	'BUILD102739K_INVENTORY_PATH_COUNT=' \
	'BUILD102739K_MALFORMED_DETAIL_COUNT=' \
	'BUILD102739K_MALFORMED_%02lu_SOURCE_LINE=' \
	'BUILD102739K_MALFORMED_%02lu_REASON=' \
	'BUILD102739K_MALFORMED_%02lu_RAW=' \
	'BUILD102739K_MALFORMED_%02lu_PATH=' \
	'BUILD102739K_MALFORMED_%02lu_STANDARDIZED_PATH=' \
	'BUILD102739K_UNRESOLVED_COLLISION_COUNT=' \
	'BUILD102739K_LTOP_LSTAT_RC=' \
	'BUILD102739K_LTOP_SIZE=' \
	'BUILD102739K_LTOP_SHA256=' \
	BUILD102739K_LTOP_EXPECTED_SIZE= \
	BUILD102739K_LTOP_EXPECTED_SHA256= \
	'BUILD102739K_LTOP_EXPECTED_PAYLOAD_MATCH=' \
	'BUILD102739K_LAUNCHCTL_BIN_NODE_LSTAT_RC=' \
	'BUILD102739K_LAUNCHCTL_BIN_NODE_LSTAT_ERRNO=' \
	'BUILD102739K_LAUNCHCTL_BIN_NODE_TYPE=' \
	'BUILD102739K_LAUNCHCTL_BIN_TARGET_STAT_RC=' \
	'BUILD102739K_LAUNCHCTL_BIN_TARGET_STAT_ERRNO=' \
	'BUILD102739K_LAUNCHCTL_BIN_TARGET_USABLE=' \
	BUILD102739K_LAUNCHCTL_DOPAMINE_PATH=/usr/bin/launchctl \
	'BUILD102739K_LAUNCHCTL_DOPAMINE_LSTAT_RC=' \
	'BUILD102739K_LAUNCHCTL_DOPAMINE_LSTAT_ERRNO=' \
	'BUILD102739K_LAUNCHCTL_DOPAMINE_PRESENT=' \
	'BUILD102739K_SERVICE_QUERY_APPLICABILITY=' \
	'BUILD102739K_SERVICE_QUERY_COMPLETE=' \
    'BUILD102739K_TRACKED_PATH_IDENTITIES_UNCHANGED=' \
    BUILD102739K_BOOTSTRAP_TARGET_FILES_CREATED=0 \
    BUILD102739K_BOOTSTRAP_TARGET_FILES_MODIFIED=0 \
    BUILD102739K_BOOTSTRAP_TARGET_FILES_REMOVED=0 \
    BUILD102739K_APP_RUN_LOG_EXCLUDED_FROM_TARGET_COUNTS=YES \
    BUILD102739K_BOOTSTRAP_MARKER_CHANGED=NO \
    BUILD102739K_SERVICES_CHANGED=NO \
    BUILD102739K_WALL2_RESTORE_ORDER_REPAIR=YES \
    BUILD102739K_RESTORE_BEFORE_CAPTURE_REPLAY=YES \
    BUILD102739K_RESTORE_BEFORE_TRACE_POLL=YES \
    BUILD102739K_REPORT_SCHEMA=1 \
    'BUILD102739K_RUN_ID=' \
    BUILD102739K_REPORT_BEGIN=YES \
    'BUILD102739K_MODEL_GATE=' \
    'BUILD102739K_BUILD_GATE=' \
    'BUILD102739K_CF1900_GATE=' \
    'BUILD102739K_EUID0_GATE=' \
    'BUILD102739K_REMOUNT_GATE=' \
    'BUILD102739K_MANIFEST_GATE=' \
    'BUILD102739K_INVENTORY_READ_GATE=' \
    'BUILD102739K_MOUNT_SURVEY_GATE=' \
    'BUILD102739K_CANDIDATE_SURVEY_GATE=' \
    'BUILD102739K_SERVICE_QUERY_GATE=' \
    'BUILD102739K_SERVICE_STATE_GATE=' \
    'BUILD102739K_TRACKED_IDENTITY_GATE=' \
    'BUILD102739K_FAILURE_MASK=' \
    'BUILD102739K_RESULT_CONSISTENCY=' \
    'BUILD102739K_READ_ONLY_PREFLIGHT_RESULT=' \
    'BUILD102739K_SUMMARY=' \
    'BUILD102739K_REPORT_COMPLETE=' \
    BUILD102739K_REPORT_END=YES \
    BUILD102739K_FINAL_RESULT=; do
    rg -q "$marker" "$APP_STRINGS"
done

[[ "$(wc -l < "$PACKAGED_MANIFEST" | tr -d ' ')" -eq 4049 ]]
rg -q '^#ARCHIVE_MEMBER_COUNT=4041$' "$PACKAGED_MANIFEST"
rg -q '^#INVENTORY_PATH_COUNT=4040$' "$PACKAGED_MANIFEST"
[[ "$(rg -c $'^[dl-]\t/' "$PACKAGED_MANIFEST")" -eq 4040 ]]
rg -q 'JBROOT_PATH\("/usr/bin/launchctl"\)' \
    "$REPO_ROOT/Dopamine_Rootful/Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
ARCHIVE_LTOP_SHA="$(tar --zstd -xOf "$ARCHIVE" ./usr/bin/ltop | shasum -a 256 | awk '{print $1}')"
[[ "$ARCHIVE_LTOP_SHA" == "a351548370a646d819e40a0c5f25fbff51d9454d4ff094e0c654322ef0ab20cb" ]]
tar --zstd -tvf "$ARCHIVE" | rg -q '^lrwxrwxrwx .* \./bin/launchctl -> /usr/bin/launchctl$'
tar --zstd -tvf "$ARCHIVE" | rg -q '^-rwxr-xr-x .* \./usr/bin/launchctl$'
if unzip -l "$PROJECT/$IPA_NAME" | rg -q 'tvbootstrap|\.tar\.zst|\.deb$|PurePKG'; then
    echo "ERROR: bootstrap archive/package payload was bundled in read-only BUILD102739K" >&2
    exit 1
fi

for frozen_file in launchdhook516.dylib dt_opainject516 dt_jbctl516 \
    libjailbreak.dylib libchoma.dylib; do
    cmp -s "$FROZEN_J/$frozen_file" "$PROJECT/build/$BUILD_SLOT/Handoff516/$frozen_file"
done

HOOK_SHA="$(shasum -a 256 "$PROJECT/build/$BUILD_SLOT/Handoff516/launchdhook516.dylib" | awk '{print $1}')"
HELPER_SHA="$(shasum -a 256 "$PROJECT/build/$BUILD_SLOT/Handoff516/dt_opainject516" | awk '{print $1}')"
MANIFEST_SHA="$(shasum -a 256 "$PACKAGED_MANIFEST" | awk '{print $1}')"
IPA_SHA="$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"

{
    echo "BUILD102739K_OBS2_FINAL_HOST_AUDIT"
    echo "TARGET_MODEL=AppleTV6,2"
    echo "TARGET_TVOS_VERSION=16.5"
    echo "TARGET_BUILD=20L563"
    echo "BASELINE=BUILD102739J_FROZEN"
    echo "SCOPE=CONSOLE_VISIBLE_ROOTFUL_BOOTSTRAP_READ_ONLY_PREFLIGHT"
    echo "J_HOOK_BINARY_IDENTICAL=YES"
    echo "J_HELPER_BINARY_IDENTICAL=YES"
    echo "PINNED_BOOTSTRAP_FAMILY=appletvos-arm64"
    echo "PINNED_BOOTSTRAP_CF_VERSION=1900"
    echo "PINNED_ARCHIVE_SHA256=54299aaf56176695b4fe6883f13bd67617d8c008e5bc5778591ec3940e5e7666"
    echo "ARCHIVE_MEMBER_COUNT=4041"
    echo "INVENTORY_PATH_COUNT=4040"
    echo "PACKAGED_MANIFEST_SHA256=$MANIFEST_SHA"
    echo "ARCHIVE_BUNDLED=NO"
    echo "DEB_PACKAGES_BUNDLED=NO"
    echo "BOOTSTRAP_EXTRACTION_ENABLED=NO"
    echo "PACKAGE_INSTALL_ENABLED=NO"
    echo "SERVICE_MUTATION_ENABLED=NO"
    echo "PREFLIGHT_BOOTSTRAP_MUTATING_C_API_CALLS=0"
    echo "PREFLIGHT_BOOTSTRAP_MUTATING_FOUNDATION_SELECTORS=0"
    echo "APP_RUN_LOG_EXCLUDED_FROM_BOOTSTRAP_TARGET_COUNTS=YES"
    echo "ACTUAL_REMOUNT_SUCCESS_REQUIRED=YES"
    echo "LSTAT_INVENTORY_ENABLED=YES"
    echo "MOUNT_SURVEY_ENABLED=YES"
    echo "STORAGE_CANDIDATE_SURVEY_ENABLED=YES"
    echo "SERVICE_READ_ONLY_QUERY_ENABLED=YES"
    echo "TRACKED_IDENTITY_BEFORE_AFTER_CHECK=YES"
    echo "SYNCHRONOUS_OPAINJECT_BEFORE_RESTORE=PASS"
    echo "WALL2_RESTORE_BEFORE_CAPTURE_REPLAY=PASS"
    echo "WALL2_RESTORE_BEFORE_TRACE_POLL=PASS"
    echo "POST_INJECT_PRE_RESTORE_BLOCKING_CALLS=0"
    echo "LAUNCHD_PROC_RELEASE_BEFORE_CAPTURE_REPLAY=PASS"
    echo "LONG_OBSERVATION_RUNS_POST_RESTORE=PASS"
    echo "K_PREFLIGHT_RUNS_AFTER_WALL2_RESTORE=PASS"
    echo "K_PREFLIGHT_RUNS_AFTER_J_OBSERVATION=PASS"
    echo "K_CONSOLE_PREFIX_FILTER=BUILD102739K_"
	echo "FAILURE_MASK_ENABLED=YES"
	echo "BOUNDED_FAILURE_DETAIL_LIMIT=16"
	echo "BOUNDED_COLLISION_DETAIL_LIMIT=16"
	echo "BOUNDED_MALFORMED_DETAIL_LIMIT=16"
	echo "MALFORMED_SOURCE_LINE_EVIDENCE=YES"
	echo "MALFORMED_DEVICE_STANDARDIZATION_EVIDENCE=YES"
	echo "LTOP_READ_ONLY_SHA256_ENABLED=YES"
	echo "LTOP_EXPECTED_SIZE=93088"
	echo "LTOP_EXPECTED_SHA256=$ARCHIVE_LTOP_SHA"
	echo "LAUNCHCTL_ARCHIVE_BIN_NODE_TYPE=SYMLINK"
	echo "LAUNCHCTL_ARCHIVE_BIN_TARGET=/usr/bin/launchctl"
	echo "LAUNCHCTL_ARCHIVE_TARGET_TYPE=REGULAR_EXECUTABLE"
	echo "DOPAMINE_ROOTFUL_LAUNCHCTL_PATH=JBROOT/usr/bin/launchctl"
	echo "SERVICE_QUERY_APPLICABILITY_TELEMETRY=YES"
	echo "SERVICE_QUERY_PASS_CRITERIA_CHANGED=NO"
	echo "K_PREFLIGHT_PASS_CRITERIA_CHANGED=NO"
	echo "OBS2_DIAGNOSTIC_ONLY=YES"
    echo "J_K_VERDICTS_SEPARATED=YES"
    echo "UI_CHANGED=NO"
    echo "HOOK_SHA256=$HOOK_SHA"
    echo "HELPER_SHA256=$HELPER_SHA"
    echo "IPA_SHA256=$IPA_SHA"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739K_OBS2_FINAL_HOST_AUDIT.txt"

mkdir -p "$OUTPUT_DIR"
cp "$PROJECT/$IPA_NAME" "$OUTPUT_DIR/$IPA_NAME"
echo "BUILD102739K_OBS2_PACKAGE_COMPLETE=YES"
echo "BUILD102739K_OBS2_IPA_PATH=$OUTPUT_DIR/$IPA_NAME"
echo "BUILD102739K_OBS2_IPA_SHA256=$IPA_SHA"
