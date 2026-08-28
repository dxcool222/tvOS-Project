#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
DOPAMINE_ROOT="$REPO_ROOT/Dependencies/Dopamine-2.x"
MAKE_PROJECT="/tmp/dopamin_tvos_kfd_102739l_src"
TEMP_IPA="dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"
IPA_NAME="dopamin-tvOS-kfd-102739L-ROOTFUL-BOOTSTRAP-POLICY-READ-ONLY-PREFLIGHT.ipa"
BUILD_SLOT="102739L"
OUTPUT_DIR="$REPO_ROOT/Output"
ARCHIVE="$REPO_ROOT/tvOS/tvbootstrap-ssh-1900.tar.zst"
OTA_LTOP="$REPO_ROOT/../ltop-tvOS-16.5-20L563"
FROZEN_J="$PROJECT/build/102739J/Handoff516"
ADDONS="/private/tmp/tvos-addon-deb-audit"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/dt102739l_module_cache}"
rm -rf "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$MAKE_PROJECT"

echo "=== BUILD102739L verify frozen lineage and pinned inputs ==="
[[ "$(shasum -a 256 "$PROJECT/build/102739J/dopamin-tvOS-kfd-102739J-CONTROLLED-REPLY-ROUNDTRIP.ipa" | awk '{print $1}')" == \
    "5e5937d14f93d95f43cb6a5c1d5c3578e045a5b4dfbe3e2c36029f7e2a5bd000" ]]
[[ "$(shasum -a 256 "$FROZEN_J/launchdhook516.dylib" | awk '{print $1}')" == \
    "1aac987a875427fd4e1ffe67d2373f56cb0599ce856af31a094600d2d688141e" ]]
[[ "$(shasum -a 256 "$FROZEN_J/dt_opainject516" | awk '{print $1}')" == \
    "b21ebb77d83e1fb78fa03e9a3c1ff9c40c888a032b0eefa03299bbae942ee67f" ]]
[[ "$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')" == \
    "54299aaf56176695b4fe6883f13bd67617d8c008e5bc5778591ec3940e5e7666" ]]
[[ "$(shasum -a 256 "$OTA_LTOP" | awk '{print $1}')" == \
    "38e463ade2f9336dad8cd746a00da6aa4be0781de3d128f8cac15a6554c2d698" ]]
[[ "$(stat -f %z "$OTA_LTOP")" -eq 69216 ]]

declare -a addon_specs=(
    "autosign_2.0.3_appletvos-arm64.deb:b4d28fba5854327d8e0c062fa02b60628d5457086ae22ebb768090a901dacd0c"
    "dhinakg-keyring_2023.04.02_all.deb:85f72fa60f8fc23b446120952fee75acdfa2a651491c476e600f1dba77ef1400"
    "ellekit_1.1.3-palera1n2_appletvos-arm64.deb:9ad2752bb5ed09a378270f491785d19d55834c52438ff167d78854bf7882cc84"
    "ldid_2.1.5-procursus7_appletvos-arm64.deb:0ab363ec064b9abf15079e0af46930dea5751c9a3785a0552fc2b53d66cc5864"
    "libkrw0-tfp0_1.1.1_appletvos-arm64.deb:ae07cb331b78bc2d9ffe87a92a53f0496006bf850b9d34780c0df435faeac5e3"
    "libplist3_2.2.0+git20230130.4b50a5a_appletvos-arm64.deb:b3921e7ac526fbe32082b9fb6a9ab533f4846a5ccabbcb063cf819d275162f54"
    "palera1n-keyring_2024.03.23_all.deb:84a4aca320b3662ec98b6ca91839cb2bc24fef3b60bea859504272742fb4aabe"
    "lrdsnow-keyring_2024.03.28_all.deb:e6cfed2bc07d295003379e6c772e4ff77e0385bbcd5659857a04e98cadbe5ff0"
    "uwu.lrdsnow.purepkg_appletvos-arm64.deb:895b3ed76b0408f88f5106bf2d857ef993f8bb2d30347e6c6d597a74b3b87672"
)
addon_files_available=YES
for spec in "${addon_specs[@]}"; do
    name="${spec%%:*}"
    expected="${spec##*:}"
    if [[ ! -f "$ADDONS/$name" ]]; then
        addon_files_available=NO
        continue
    fi
    actual="$(shasum -a 256 "$ADDONS/$name" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        echo "ERROR: add-on package identity mismatch: $name" >&2
        exit 1
    fi
done

echo "=== BUILD102739L prepare isolated source copy ==="
rsync -a --delete "$PROJECT/" "$MAKE_PROJECT/"
rm -rf "$MAKE_PROJECT/.theos/obj/appletv" "$MAKE_PROJECT/.theos/build_session"

echo "=== BUILD102739L generate K inventory and adapted policy resources ==="
DT_REPO_ROOT="$REPO_ROOT" bash "$MAKE_PROJECT/scripts/generate102739k_bootstrap_manifest.sh"
bash "$MAKE_PROJECT/scripts/generate102739l_bootstrap_policy.sh"

echo "=== BUILD102739L rebuild frozen J hook and repaired observer ==="
DT_BUILD102739J_MODE=1 \
DT_BUILD_OUTPUT_ROOT="$MAKE_PROJECT/build/102738P" \
DOPAMINE="$DOPAMINE_ROOT" \
    bash "$MAKE_PROJECT/scripts/build102739a_post_wall2_observer.sh"

echo "=== BUILD102739L regenerate unchanged auxiliary helpers ==="
bash "$MAKE_PROJECT/scripts/build_bootstraphelper.sh"
bash "$MAKE_PROJECT/scripts/build583_handoff.sh"
bash "$MAKE_PROJECT/scripts/build653_handoff.sh"
bash "$MAKE_PROJECT/scripts/build672_handoff.sh"
mkdir -p "$MAKE_PROJECT/.theos/obj/handoff674/Control661"
cp "$MAKE_PROJECT/frozen_inputs/Control661/dt_direct653_helper_control661" \
    "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"
chmod +x "$MAKE_PROJECT/.theos/obj/handoff674/Control661/dt_direct653_helper_control661"

echo "=== BUILD102739L compile and package read-only policy preflight ==="
DT_WORKSPACE_ROOT="$REPO_ROOT" DT_102739L_VARIANT=1 DT_102738_PREBUILT=1 \
    make -C "$MAKE_PROJECT" ipa
[[ -f "$MAKE_PROJECT/$TEMP_IPA" ]]

rm -rf "$PROJECT/build/$BUILD_SLOT"
cp -R "$MAKE_PROJECT/build/102738P" "$PROJECT/build/$BUILD_SLOT"
rm -f "$PROJECT/build/$BUILD_SLOT/$TEMP_IPA"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/build/$BUILD_SLOT/$IPA_NAME"
cp "$MAKE_PROJECT/$TEMP_IPA" "$PROJECT/$IPA_NAME"

DT_EXPECT_102738_VARIANT=K \
    bash "$PROJECT/scripts/verify_build_artifact_identity.sh" "$MAKE_PROJECT/$TEMP_IPA" \
    | tee "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739L.txt"

OBJ="$PROJECT/build/$BUILD_SLOT/obj"
APP_BINARY="$OBJ/app_binary"
APP_STRINGS="$OBJ/app_strings.txt"
L_DISASM="$OBJ/policy_preflight_disassembly.txt"
READLINK_DISASM="$OBJ/policy_readlink_disassembly.txt"
APP_FLOW_DISASM="$OBJ/wall2_restore_order_disassembly.txt"
mkdir -p "$OBJ"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd > "$APP_BINARY"
strings "$APP_BINARY" > "$APP_STRINGS"
otool -tvV "$APP_BINARY" | awk '
    /^_dt_build102739l_run_rootful_bootstrap_policy_preflight:$/ { inside=1 }
    inside && /^_[A-Za-z0-9_]+:$/ && $0 != "_dt_build102739l_run_rootful_bootstrap_policy_preflight:" { inside=0 }
    inside { print }
' > "$L_DISASM"
rg -q '^_dt_build102739l_run_rootful_bootstrap_policy_preflight:$' "$L_DISASM"
for call in _lstat _statfs _proc_pidpath _kill _dt102739l_readlink; do
    rg -q "$call" "$L_DISASM"
done
otool -tvV "$APP_BINARY" | awk '
    /^_dt102739l_readlink:$/ { inside=1 }
    inside && /^_[A-Za-z0-9_]+:$/ && $0 != "_dt102739l_readlink:" { inside=0 }
    inside { print }
' > "$READLINK_DISASM"
rg -q 'symbol stub for: _readlink$' "$READLINK_DISASM"
if rg -q 'symbol stub for: _(open|write|pwrite|unlink|remove|rename|mkdir|rmdir|chmod|chown|mount|unmount|symlink|link|truncate|fopen|system|posix_spawn|execve)$' \
    "$L_DISASM" "$READLINK_DISASM"; then
    echo "ERROR: mutating or execution API present in BUILD102739L policy preflight" >&2
    exit 1
fi
if rg -n 'writeToFile|createFile|removeItem|moveItem|copyItem|createDirectory|createSymbolicLink|setAttributes' \
    "$PROJECT/dt_bootstrap_preflight.m"; then
    echo "ERROR: mutating Foundation selector present in bootstrap preflight source" >&2
    exit 1
fi
K_VALIDATOR_SOURCE="$OBJ/k_path_validator_source.txt"
sed -n '/^static BOOL dt102739k_path_is_normalized/,/^static void dt102739k_check_parent_symlinks/p' \
    "$PROJECT/dt_bootstrap_preflight.m" > "$K_VALIDATOR_SOURCE"
rg -q 'componentsSeparatedByString:@"/"' "$K_VALIDATOR_SOURCE"
if rg -q '\b(stringByStandardizingPath|stringByResolvingSymlinksInPath|realpath|lstat|stat)\b' \
    "$K_VALIDATOR_SOURCE"; then
    echo "ERROR: filesystem-sensitive operation present in K lexical path validator" >&2
    exit 1
fi
rg -q 'serviceQueryDeferred = launchctlAbsentBeforeBootstrap' \
    "$PROJECT/dt_bootstrap_preflight.m"
rg -q 'serviceQueryComplete = serviceQueryApplicable || serviceQueryDeferred' \
    "$PROJECT/dt_bootstrap_preflight.m"

otool -tvV "$APP_BINARY" \
    | awk '/^_dt102732c_run_constructor_boomerang_only:/{inside=1} /^_dt102732c_restore_wall2:/{inside=0} inside' \
    > "$APP_FLOW_DISASM"
RESTORE_LINE="$(rg -n 'bl[[:space:]]+_dt102732c_restore_wall2$' "$APP_FLOW_DISASM" | tail -1 | cut -d: -f1)"
POLL_LINE="$(rg -n 'bl[[:space:]]+_dt102735d_poll_trace_and_boomerang$' "$APP_FLOW_DISASM" | head -1 | cut -d: -f1)"
K_LINE="$(rg -n 'bl[[:space:]]+_dt_build102739k_run_rootful_bootstrap_preflight$' "$APP_FLOW_DISASM" | head -1 | cut -d: -f1)"
L_LINE="$(rg -n 'bl[[:space:]]+_dt_build102739l_run_rootful_bootstrap_policy_preflight$' "$APP_FLOW_DISASM" | head -1 | cut -d: -f1)"
[[ "$RESTORE_LINE" -lt "$POLL_LINE" ]]
[[ "$POLL_LINE" -lt "$K_LINE" ]]
[[ "$K_LINE" -lt "$L_LINE" ]]

for marker in \
    'BUILD102739K_SERVICE_QUERY_PATH=' \
    'BUILD102739K_SERVICE_QUERY_DEFERRED_EXPECTED_ABSENCE=' \
    BUILD102739L_SCOPE=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PREFLIGHT \
    BUILD102739L_BASELINE=BUILD102739K_OBS2_REPAIRED \
    BUILD102739L_BOOTSTRAP_EXTRACTION_ENABLED=NO \
    BUILD102739L_PACKAGE_INSTALL_ENABLED=NO \
    BUILD102739L_PUREPKG_INSTALL_ENABLED=NO \
    BUILD102739L_ELLEKIT_INSTALL_ENABLED=NO \
    BUILD102739L_ELLEKIT_PID1_INJECTION_ENABLED=NO \
    BUILD102739L_SCRIPT_EXECUTION_ENABLED=NO \
    BUILD102739L_SERVICE_MUTATION_ENABLED=NO \
    BUILD102739L_BOOTSTRAP_TARGET_MUTATION_CALLS=0 \
    BUILD102739L_APPLE_LTOP_POLICY=PRESERVE_EXACT \
    BUILD102739L_PROCURSUS_LTOP_DESTINATION_ACTION=EXCLUDE \
    BUILD102739L_SYSTEM_CMDS_LTOP_OWNERSHIP_ACTION=REMOVE \
    BUILD102739L_EXISTING_DIRECTORY_METADATA_ACTION=PRESERVE \
    BUILD102739L_KNOWN_STOCK_FILE_COLLISION_COUNT=1 \
    BUILD102739L_KNOWN_DIRECTORY_METADATA_DIFFERENCE_COUNT=2 \
    BUILD102739L_BOOTSTRAP_TARGET_FILES_CREATED=0 \
    BUILD102739L_BOOTSTRAP_TARGET_FILES_MODIFIED=0 \
    BUILD102739L_BOOTSTRAP_TARGET_FILES_REMOVED=0 \
    BUILD102739L_APP_RUN_LOG_EXCLUDED_FROM_TARGET_COUNTS=YES \
    BUILD102739L_BOOTSTRAP_MARKER_CHANGED=NO \
    BUILD102739L_SERVICES_CHANGED=NO \
    'BUILD102739L_APPLE_LTOP_IDENTITY_MATCH=' \
    'BUILD102739L_ETC_ALIAS_MATCH=' \
    'BUILD102739L_VAR_ALIAS_MATCH=' \
    'BUILD102739L_GENERATED_DESTINATIONS_UNCHANGED=' \
    'BUILD102739L_PID1_PRESENT_AFTER_PREFLIGHT=' \
    'BUILD102739L_PID1_IDENTITY_UNCHANGED=' \
    'BUILD102739L_UNRESOLVED_POLICY_COUNT=' \
    BUILD102739L_FINAL_RESULT=; do
    rg -q "$marker" "$APP_STRINGS"
done
rg -q 'hasPrefix:@"BUILD102739L_"' "$PROJECT/DTRunLogger.m"

PLAN="$OBJ/BUILD102739L_ADAPTED_PLAN.tsv"
POLICY="$OBJ/BUILD102739L_POLICY.tsv"
K_MANIFEST="$OBJ/BUILD102739K_CF1900_PATHS.tsv"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/BUILD102739K_CF1900_PATHS.tsv > "$K_MANIFEST"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/BUILD102739L_ADAPTED_PLAN.tsv > "$PLAN"
unzip -p "$PROJECT/$IPA_NAME" Payload/dopamin-tvOS-kfd.app/BUILD102739L_POLICY.tsv > "$POLICY"
cmp -s "$MAKE_PROJECT/bootstrap_preflight/BUILD102739K_CF1900_PATHS.tsv" "$K_MANIFEST"
cmp -s "$MAKE_PROJECT/bootstrap_preflight/BUILD102739L_ADAPTED_PLAN.tsv" "$PLAN"
cmp -s "$MAKE_PROJECT/bootstrap_preflight/BUILD102739L_POLICY.tsv" "$POLICY"
[[ "$(rg -c $'^[dl-]\t/' "$K_MANIFEST")" -eq 4040 ]]
rg -q '^#ARCHIVE_MEMBER_COUNT=4041$' "$K_MANIFEST"
rg -q '^#INVENTORY_PATH_COUNT=4040$' "$K_MANIFEST"
for private_alias_path in /private/etc /private/var /private/var/empty \
    /private/var/db /private/var/log /private/var/run; do
    rg -Fqx $'d\t'"$private_alias_path" "$K_MANIFEST"
done
[[ "$(rg -c $'^[dl-]\t/' "$PLAN")" -eq 4039 ]]
! rg -q $'^[dl-]\t/usr/bin/ltop$' "$PLAN"
rg -q '^#PROCURSUS_LTOP_DESTINATION_ACTION=EXCLUDE$' "$PLAN"
rg -q '^#SYSTEM_CMDS_LTOP_OWNERSHIP_ACTION=REMOVE$' "$PLAN"
[[ "$(rg -c '^INTERSECTION\t' "$POLICY")" -eq 19 ]]
[[ "$(rg -c '^ADDON\t' "$POLICY")" -eq 9 ]]
[[ "$(rg -c '^GENERATED\t' "$POLICY")" -eq 32 ]]
[[ "$(rg -c '^SCRIPT_EFFECT_SET\t' "$POLICY")" -eq 3 ]]

if unzip -l "$PROJECT/$IPA_NAME" | rg -q 'tvbootstrap|\.tar\.zst|\.deb$|PurePKG\.app'; then
    echo "ERROR: bootstrap archive/package payload bundled in read-only BUILD102739L" >&2
    exit 1
fi
for frozen_file in launchdhook516.dylib dt_opainject516 dt_jbctl516 \
    libjailbreak.dylib libchoma.dylib; do
    cmp -s "$FROZEN_J/$frozen_file" "$PROJECT/build/$BUILD_SLOT/Handoff516/$frozen_file"
done

HOOK_SHA="$(shasum -a 256 "$PROJECT/build/$BUILD_SLOT/Handoff516/launchdhook516.dylib" | awk '{print $1}')"
HELPER_SHA="$(shasum -a 256 "$PROJECT/build/$BUILD_SLOT/Handoff516/dt_opainject516" | awk '{print $1}')"
K_MANIFEST_SHA="$(shasum -a 256 "$K_MANIFEST" | awk '{print $1}')"
PLAN_SHA="$(shasum -a 256 "$PLAN" | awk '{print $1}')"
POLICY_SHA="$(shasum -a 256 "$POLICY" | awk '{print $1}')"
IPA_SHA="$(shasum -a 256 "$PROJECT/$IPA_NAME" | awk '{print $1}')"

{
    echo "BUILD102739L_FINAL_HOST_AUDIT"
    echo "TARGET_MODEL=AppleTV6,2"
    echo "TARGET_TVOS_VERSION=16.5"
    echo "TARGET_BUILD=20L563"
    echo "BASELINE=BUILD102739K_OBS2_REPAIRED"
    echo "SCOPE=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PREFLIGHT"
    echo "J_HOOK_BINARY_IDENTICAL=YES"
    echo "J_HELPER_BINARY_IDENTICAL=YES"
    echo "PINNED_ARCHIVE_SHA256=54299aaf56176695b4fe6883f13bd67617d8c008e5bc5778591ec3940e5e7666"
    echo "APPLE_LTOP_SHA256=38e463ade2f9336dad8cd746a00da6aa4be0781de3d128f8cac15a6554c2d698"
    echo "APPLE_LTOP_POLICY=PRESERVE_EXACT"
    echo "PROCURSUS_LTOP_DESTINATION_ACTION=EXCLUDE"
    echo "SYSTEM_CMDS_LTOP_OWNERSHIP_ACTION=REMOVE"
    echo "EXISTING_DIRECTORY_METADATA_ACTION=PRESERVE"
    echo "KNOWN_STOCK_FILE_COLLISION_COUNT=1"
    echo "KNOWN_DIRECTORY_METADATA_DIFFERENCE_COUNT=2"
    echo "K_MANIFEST_PACKAGED=YES"
    echo "K_MANIFEST_PATH_COUNT=4040"
    echo "K_PATH_VALIDATION=LEXICAL_ONLY"
    echo "K_PRIVATE_ALIAS_PATHS_ACCEPTED=YES"
    echo "K_SERVICE_EXPECTED_ABSENCE_IS_DEFERRED_PASS=YES"
    echo "ADAPTED_INSTALL_PATH_COUNT=4039"
    echo "ADDON_PACKAGE_IDENTITIES_DECLARED=9"
    echo "ADDON_PACKAGE_FILES_AVAILABLE=$addon_files_available"
    if [[ "$addon_files_available" == YES ]]; then
        echo "ADDON_PACKAGE_HASHES_VERIFIED=YES"
    else
        echo "ADDON_PACKAGE_HASHES_VERIFIED=NOT_APPLICABLE_MISSING_READ_ONLY_INPUTS"
    fi
    echo "GENERATED_DESTINATIONS_INVENTORIED=32"
    echo "SCRIPT_EFFECT_SETS_PARSE_ONLY=3"
    echo "PUREPKG_INSTALL_ENABLED=NO"
    echo "ELLEKIT_INSTALL_ENABLED=NO"
    echo "ELLEKIT_PID1_INJECTION_ENABLED=NO"
    echo "BOOTSTRAP_ARCHIVE_BUNDLED=NO"
    echo "DEB_PACKAGES_BUNDLED=NO"
    echo "BOOTSTRAP_MUTATING_CALLS_IN_L_PREFLIGHT=0"
    echo "WALL2_RESTORE_BEFORE_K_PREFLIGHT=PASS"
    echo "K_PREFLIGHT_BEFORE_L_POLICY_PREFLIGHT=PASS"
    echo "K_MANIFEST_SHA256=$K_MANIFEST_SHA"
    echo "ADAPTED_PLAN_SHA256=$PLAN_SHA"
    echo "POLICY_SHA256=$POLICY_SHA"
    echo "HOOK_SHA256=$HOOK_SHA"
    echo "HELPER_SHA256=$HELPER_SHA"
    echo "IPA_SHA256=$IPA_SHA"
    echo "HOST_AUDIT_RESULT=PASS"
} | tee "$PROJECT/docs/reports/BUILD102739L_FINAL_HOST_AUDIT.txt"

mkdir -p "$OUTPUT_DIR"
cp "$PROJECT/$IPA_NAME" "$OUTPUT_DIR/$IPA_NAME"
cp "$PROJECT/docs/reports/BUILD102739L_FINAL_HOST_AUDIT.txt" "$OUTPUT_DIR/"
cp "$PROJECT/docs/reports/BUILD_ARTIFACT_IDENTITY_102739L.txt" "$OUTPUT_DIR/"
echo "BUILD102739L_PACKAGE_COMPLETE=YES"
echo "BUILD102739L_IPA_PATH=$OUTPUT_DIR/$IPA_NAME"
echo "BUILD102739L_IPA_SHA256=$IPA_SHA"
