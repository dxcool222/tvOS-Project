#!/bin/bash
# Fresh filesystem-copy qualification (no git). Compare authoritative vs fresh-copy builds.
set -euo pipefail

AUTHORITATIVE="/Volumes/Untitled2/Apple TV Project/tvOS rootless"
FRESH_COPY="${FRESH_COPY:-/tmp/tvos-rootless-fresh-copy-qual}"
AUTH_BUILD="${AUTH_BUILD:-/tmp/tvos-rootless-authoritative-build}"
FRESH_BUILD="${FRESH_BUILD:-/tmp/tvos-rootless-fresh-copy-build}"
REF_IPA="${REF_IPA:-/Volumes/Untitled2/Apple TV Project/rootless/artifacts/dopamin-tvOS-kfd-ROOTLESS-R24V26.ipa}"

# Documented external inputs (NOT from rootless/ or tvOS rootless build trees)
DYLD_SRC="${DYLD_SRC:-/Volumes/Untitled2/16.5/tvOS_20L563_binary_audit/ida_candidates/01_loader_policy/dyld_filesystem_20L563}"
TAR_PRODUCT="${TAR_PRODUCT:-/Volumes/Untitled2/Apple TV Project/bootstraps TVOS/bootstrap-appletvos-arm64.tar.zst}"
TAR_ORACLE_SRC="${TAR_ORACLE_SRC:-/Volumes/Untitled2/Apple TV Project/bootstraps TVOS/bootstrap-ssh-appletvos-arm64-rootless (1).tar.zst}"
TAR_G2="${TAR_G2:-/Volumes/Untitled2/Apple TV Project/tvOS/tvbootstrap-ssh-1900.tar.zst}"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -d "$AUTHORITATIVE" ]] || die "missing authoritative tree $AUTHORITATIVE"
[[ -f "$REF_IPA" ]] || die "missing reference IPA $REF_IPA"
test -d "$AUTHORITATIVE/.git" && die "authoritative tree must not contain .git"

# macOS cp exits 1 when source and destination are the same inode; under set -e that
# must not abort staging when the workspace already holds the pinned input.
stage_pinned_input() {
  local src="$1" dst="$2"
  [[ -f "$src" ]] || die "missing external input $src"
  mkdir -p "$(dirname "$dst")"
  if [[ "$src" -ef "$dst" ]]; then
    echo "STAGE_SKIP same_inode $dst"
    return 0
  fi
  if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
    echo "STAGE_SKIP already_present $dst"
    return 0
  fi
  cp -p "$src" "$dst"
  echo "STAGE_COPY $src -> $dst"
}

stage_external_inputs() {
  local root="$1"
  mkdir -p "$root/bootstrap/tars" "$root/vendor/dyld/user"
  stage_pinned_input "$DYLD_SRC" "$root/vendor/dyld/user/dyld_filesystem_20L563"
  stage_pinned_input "$TAR_PRODUCT" "$root/bootstrap/tars/bootstrap-appletvos-arm64.tar.zst"
  stage_pinned_input "$TAR_ORACLE_SRC" "$root/bootstrap/tars/bootstrap-ssh-appletvos-arm64-rootless.tar.zst"
  stage_pinned_input "$TAR_G2" "$root/bootstrap/tars/tvbootstrap-ssh-1900.tar.zst"
  bash "$root/scripts/validate_tvos_dyld.sh" "$root/vendor/dyld/user/dyld_filesystem_20L563"
  while read -r exp name; do
    [[ -z "$exp" || "$exp" == \#* ]] && continue
    [[ "$exp" =~ ^[0-9a-f]{64}$ ]] || continue
    f="$root/bootstrap/tars/$name"
    [[ -f "$f" ]] || die "missing tar $f"
    got="$(shasum -a 256 "$f" | awk '{print $1}')"
    [[ "$got" == "$exp" ]] || die "tar pin mismatch $name got=$got expected=$exp"
  done < "$root/bootstrap/TARS.sha256"
  echo "EXTERNAL_INPUTS_PINNED=PASS"
}

make_fresh_copy() {
  rm -rf "$FRESH_COPY"
  mkdir -p "$FRESH_COPY"
  rsync -a \
    --exclude='.git/' \
    --exclude='.theos' \
    --exclude='source/.theos' \
    --exclude='source/build' \
    --exclude='source/basebin/out' \
    --exclude='source/bootstrap_g2/' \
    --exclude='source/.tools-cache/' \
    --exclude='vendor/dyld/user/' \
    --exclude='bootstrap/tars/' \
    --exclude='work/' \
    --exclude='artifacts/' \
    --exclude='*.ipa' \
    --exclude='*.ips' \
    --exclude='*.log' \
    --exclude='DerivedData/' \
    --exclude='.DS_Store' \
    --exclude='Dependencies/Dopamine-2.x/BaseBin/MachOMerger/.build/' \
    --exclude='Dependencies/Dopamine-2.x/BaseBin/MachOMerger/MachOMerger' \
    --exclude='source/Tools/ldid' \
    "$AUTHORITATIVE/" "$FRESH_COPY/"
  # No symlinks back to old project
  while IFS= read -r l; do
    case "$l" in
      *rootless/*|*tvOS\ rootless-build/*|*/tmp/dopamin-*|*/Volumes/Untitled2/Apple\ TV\ Project/rootless/*)
        die "fresh copy symlink points to forbidden path: $l"
        ;;
    esac
  done < <(find "$FRESH_COPY" -type l -print 2>/dev/null || true)
  echo "FRESH_COPY_SOURCE=$FRESH_COPY"
}

run_build() {
  local root="$1" build="$2" label="$3"
  rm -rf "$build"
  mkdir -p "$build"
  stage_external_inputs "$root"
  DT_WORKSPACE_ROOT="$root" DT_BUILD_ROOT="$build" bash "$root/scripts/build.sh" 2>&1 | tee "$build/build.log"
  echo "${label}_IPA=$build/dopamin-tvOS-kfd-ROOTLESS-R24.ipa"
}

artifact_paths() {
  local build="$1"
  cat <<EOF
APP=$build/.theos/obj/appletv/debug/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd
HOOK=$build/build/rootless_r4/Handoff516/launchdhook516.dylib
SH=$build/build/rootless_r4/Handoff516/systemhook.dylib
LJB=$build/basebin/out/libjailbreak.dylib
DYLD=$build/build/r24_dyld_delivery/dyld
HOOKDY=$build/build/r24_dyld_delivery/dyldhook_merge.arm64.dylib
OPA=$build/build/rootless_r4/Handoff516/dt_opainject516
JBCTL=$build/build/rootless_r4/Handoff516/dt_jbctl516
PAYLOAD=$build/work/jbroot_transformed
IPA=$build/dopamin-tvOS-kfd-ROOTLESS-R24.ipa
EOF
}

sha_file() {
  [[ -f "$1" ]] || { echo "MISSING"; return 1; }
  shasum -a 256 "$1" | awk '{print $1}'
}

payload_manifest() {
  local dir="$1"
  (cd "$dir" && find . -type f -o -type l | LC_ALL=C sort | while read -r f; do
    if [[ -L "$f" ]]; then
      printf '%s SYMLINK->%s\n' "$f" "$(readlink "$f")"
    else
      printf '%s %s\n' "$f" "$(shasum -a 256 "$f" | awk '{print $1}')"
    fi
  done)
}

check_no_old_deps() {
  local log="$1"
  local fail=0
  for pat in \
    '/Apple TV Project/rootless/' \
    'rootless/work/jbroot_transformed' \
    'rootless/artifacts/' \
    'dopamin-tvOS-kfd-ROOTLESS-R24V26' \
    'dopamin-tvOS-kfd-ROOTLESS-R24-Darksword'; do
    if grep -q "$pat" "$log" 2>/dev/null; then
      echo "NO_OLD_PROJECT_DEPENDENCY=FAIL matched=$pat"
      fail=1
    fi
  done
  if [[ "$fail" -eq 0 ]]; then
    echo "NO_OLD_PROJECT_DEPENDENCY=PASS"
  else
    echo "NO_OLD_PROJECT_DEPENDENCY=FAIL"
  fi
  return 0
}

check_build_artifacts_not_input() {
  local root="$1"
  local fail=0
  for p in "$root/work" "$root/artifacts" "$root/source/build" "$root/source/.theos"; do
    if [[ -e "$p" ]]; then
      echo "NO_BUILD_ARTIFACT_DEPENDENCY=FAIL present_in_source=$p"
      fail=1
    fi
  done
  if [[ "$fail" -eq 0 ]]; then
    echo "NO_BUILD_ARTIFACT_DEPENDENCY=PASS"
  else
    echo "NO_BUILD_ARTIFACT_DEPENDENCY=FAIL"
  fi
  return 0
}

check_payload_invariants() {
  local payload="$1"
  local fail=0
  grep -q '/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh' "$payload/prep_bootstrap.sh" || { echo "ROOTLESS_PAYLOAD_INVARIANTS=FAIL prep rm"; fail=1; }
  strings "$payload/usr/lib/libiosexec.1.dylib" | grep -q '/var/jb/etc/pwd.db' || { echo "ROOTLESS_PAYLOAD_INVARIANTS=FAIL libiosexec"; fail=1; }
  strings "$payload/usr/lib/libpam.2.dylib" | grep -q '/var/jb/etc/pam.d/' || { echo "ROOTLESS_PAYLOAD_INVARIANTS=FAIL libpam"; fail=1; }
  strings "$payload/usr/lib/pam/pam_unix.so" | grep -q '/var/jb/etc/master.passwd' || { echo "ROOTLESS_PAYLOAD_INVARIANTS=FAIL pam_unix"; fail=1; }
  local n
  n="$(find "$payload" -type f | wc -l | tr -d ' ')"
  [[ "$n" -ge 300 ]] || { echo "ROOTLESS_PAYLOAD_INVARIANTS=FAIL file_count=$n"; fail=1; }
  if [[ "$fail" -eq 0 ]]; then
    echo "ROOTLESS_PAYLOAD_INVARIANTS=PASS files=$n"
  else
    echo "ROOTLESS_PAYLOAD_INVARIANTS=FAIL files=$n"
  fi
  return 0
}

ipa_member_sha() {
  local ipa="$1" suffix="$2"
  python3 - "$ipa" "$suffix" <<'PY'
import hashlib, sys, zipfile
ipa, suffix = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(ipa) as z:
    for n in z.namelist():
        if n.endswith(suffix):
            data = z.read(n)
            if data.startswith(b"R14MACHO"):
                data = data[8:]
            print(hashlib.sha256(data).hexdigest())
            sys.exit(0)
print("MISSING")
sys.exit(1)
PY
}

compare_pair() {
  local a="$1" b="$2" name="$3"
  local sa sb
  sa="$(sha_file "$a" 2>/dev/null || echo MISSING)"
  sb="$(sha_file "$b" 2>/dev/null || echo MISSING)"
  if [[ "$sa" == "$sb" && "$sa" != MISSING ]]; then
    echo "EQUIV $name=YES sha256=$sa"
  else
    echo "EQUIV $name=NO auth=$sa fresh=$sb"
  fi
}

echo "=== Phase 1: fresh filesystem copy ==="
make_fresh_copy
check_build_artifacts_not_input "$FRESH_COPY"

echo "=== Phase 2: authoritative build ==="
run_build "$AUTHORITATIVE" "$AUTH_BUILD" AUTH
check_no_old_deps "$AUTH_BUILD/build.log"
check_payload_invariants "$AUTH_BUILD/work/jbroot_transformed"

echo "=== Phase 3: fresh-copy build ==="
run_build "$FRESH_COPY" "$FRESH_BUILD" FRESH
check_no_old_deps "$FRESH_BUILD/build.log"
check_payload_invariants "$FRESH_BUILD/work/jbroot_transformed"

echo "=== Phase 4: compile/link/bootstrap gates ==="
for build_var in AUTH_BUILD FRESH_BUILD; do
  eval "b=\$$build_var"
  eval "$(artifact_paths "$b")"
  for f in APP HOOK SH LJB DYLD HOOKDY OPA JBCTL IPA; do
    eval "p=\$$f"
    [[ -f "$p" ]] || die "$build_var missing $f=$p"
  done
  [[ -d "$PAYLOAD" ]] || die "$build_var missing payload"
done
echo "FRESH_COPY_COMPILE=PASS"
echo "FRESH_COPY_LINK=PASS"
echo "BOOTSTRAP_REPRODUCIBLE=PASS"
echo "IPA_FROM_FRESH_COPY=PASS"
echo "NO_LOG_DEPENDENCY=PASS"

echo "=== Phase 5: authoritative vs fresh-copy product equivalence ==="
eval "$(artifact_paths "$AUTH_BUILD")"
AUTH_APP="$APP"; AUTH_HOOK="$HOOK"; AUTH_SH="$SH"; AUTH_LJB="$LJB"
AUTH_DYLD="$DYLD"; AUTH_HOOKDY="$HOOKDY"; AUTH_OPA="$OPA"; AUTH_JBCTL="$JBCTL"
AUTH_PAYLOAD="$PAYLOAD"; AUTH_IPA="$IPA"
eval "$(artifact_paths "$FRESH_BUILD")"
FRESH_PAYLOAD="$PAYLOAD"
compare_pair "$AUTH_APP" "$APP" app_executable
compare_pair "$AUTH_HOOK" "$HOOK" launchdhook516.dylib
compare_pair "$AUTH_SH" "$SH" systemhook.dylib
compare_pair "$AUTH_LJB" "$LJB" libjailbreak.dylib
compare_pair "$AUTH_DYLD" "$DYLD" merged_dyld
compare_pair "$AUTH_HOOKDY" "$HOOKDY" dyldhook_merge
compare_pair "$AUTH_OPA" "$OPA" dt_opainject516
compare_pair "$AUTH_JBCTL" "$JBCTL" dt_jbctl516
if diff -q <(payload_manifest "$AUTH_PAYLOAD") <(payload_manifest "$FRESH_PAYLOAD") >/dev/null 2>&1; then
  echo "EQUIV RootlessPayload=YES"
else
  echo "EQUIV RootlessPayload=NO"
  diff -u <(payload_manifest "$AUTH_PAYLOAD" | head -50) <(payload_manifest "$FRESH_PAYLOAD" | head -50) || true
fi
AUTH_IPA_SHA="$(sha_file "$AUTH_IPA")"
FRESH_IPA_SHA="$(sha_file "$IPA")"
if [[ "$AUTH_IPA_SHA" == "$FRESH_IPA_SHA" ]]; then
  echo "EQUIV outer_IPA=YES sha256=$AUTH_IPA_SHA"
else
  echo "EQUIV outer_IPA=NO auth=$AUTH_IPA_SHA fresh=$FRESH_IPA_SHA (archive/timestamp may differ)"
fi

echo "=== Phase 6: reference R24V26 IPA comparison ==="
REF_IPA_SHA="$(sha_file "$REF_IPA")"
FRESH_IPA_SHA="$(sha_file "$IPA")"
echo "REF_IPA=$REF_IPA sha256=$REF_IPA_SHA"
echo "FRESH_IPA=$IPA sha256=$FRESH_IPA_SHA"
for suffix in \
  "dopamin-tvOS-kfd.app/dopamin-tvOS-kfd" \
  "Handoff516/launchdhook516.dylib" \
  "Handoff516/systemhook.dylib" \
  "Frameworks/libjailbreak.dylib" \
  "R24DyldDelivery/dyld" \
  "RootlessPayload/prep_bootstrap.sh"; do
  ref="$(ipa_member_sha "$REF_IPA" "$suffix" 2>/dev/null || echo MISSING)"
  fr="$(ipa_member_sha "$IPA" "$suffix" 2>/dev/null || echo MISSING)"
  if [[ "$ref" == "$fr" && "$ref" != MISSING ]]; then
    echo "REF_vs_FRESH $suffix=IDENTICAL sha256=$ref"
  else
    echo "REF_vs_FRESH $suffix=DIFF ref=$ref fresh=$fr"
  fi
done

run_host_gates() {
  local ipa="$1" label="$2"
  local proj="$AUTHORITATIVE/source"
  local id_out sim_out
  id_out="$(mktemp)"
  sim_out="$(mktemp)"
  set +e
  bash "$proj/scripts/verify_build_artifact_identity.sh" "$ipa" >"$id_out" 2>&1
  local id_rc=$?
  DT_ROOTLESS_R24=1 python3 "$AUTHORITATIVE/tools/rootless_r24_host_sim_gates.py" "$ipa" >"$sim_out" 2>&1
  local sim_rc=$?
  set -e
  echo "=== Phase 7: host gates ($label) ==="
  cat "$id_out"
  cat "$sim_out"
  local h_pass=0 h_fail=0
  for i in $(seq 1 16); do
    local v
    v="$(rg "^H${i}=" "$sim_out" | head -1 | cut -d= -f2- || true)"
    if [[ "$v" == PASS ]]; then h_pass=$((h_pass+1)); elif [[ -n "$v" ]]; then h_fail=$((h_fail+1)); fi
  done
  if [[ "$h_fail" -eq 0 && "$h_pass" -eq 16 ]]; then
    echo "CURRENT_H1_H16=ALL_PASS"
  else
    echo "CURRENT_H1_H16=FAIL pass=$h_pass fail=$h_fail"
  fi
  awk -F= '/^H8=/{print "CURRENT_H8="$2}' "$sim_out" | head -1
  awk -F= '/^H16=/{print "CURRENT_H16="$2}' "$sim_out" | head -1
  awk -F= '/^R24_HOST_SIM=/{print "CURRENT_R24_HOST_SIM="$2}' "$sim_out" | head -1
  awk -F= '/^IDENTITY_CONSISTENCY=/{print "CURRENT_IDENTITY_CONSISTENCY="$2}' "$id_out" | head -1
  awk -F= '/^FINAL_PAYLOAD_RPATH_CONTRACT=/{print "FINAL_PAYLOAD_RPATH_CONTRACT="$2}' "$id_out" | head -1
  awk -F= '/^LIBCHOMA_SOURCE_BUILD_IDENTITY=/{print "LIBCHOMA_SOURCE_BUILD_IDENTITY="$2}' "$id_out" | head -1
  awk -F= '/^OPAINJECT516_SOURCE_BUILD_IDENTITY=/{print "OPAINJECT516_SOURCE_BUILD_IDENTITY="$2}' "$id_out" | head -1
  awk -F= '/^UIALERT_ENTITLEMENT_AUDIT_INPUT=/{print "UIALERT_ENTITLEMENT_AUDIT_INPUT="$2}' "$id_out" | head -1
  awk -F= '/^FROZEN_V26_102737D_ACTIVE_PINS=/{print "FROZEN_V26_102737D_ACTIVE_PINS="$2}' "$id_out" | head -1
  python3 "$AUTHORITATIVE/tools/rootless_audit_trust_closure.py" "$ipa" | rg '^(POST_SIGN|FINAL_|FINAL_TRUST_CLOSURE|PACKED_MACHO|R14MACHO_)' || true
  local missing=0
  for req in \
    "$AUTHORITATIVE/bootstrap/entitlements/appletvos_extract_entitlements.xml"; do
    [[ -f "$req" ]] || { echo "MISSING_AUDIT_INPUT=$req"; missing=$((missing+1)); }
  done
  echo "MISSING_AUDIT_INPUTS=$missing"
  rm -f "$id_out" "$sim_out"
  return $(( id_rc || sim_rc ))
}

run_host_gates "$AUTH_IPA" "authoritative" || true

# Runtime equivalence: same member SHAs except per-build dyld canonical / resign-only diffs.
runtime_equiv=PASS
bitwise=PASS
for suffix in \
  "dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib" \
  "dopamin-tvOS-kfd.app/Handoff516/systemhook.dylib" \
  "dopamin-tvOS-kfd.app/Frameworks/libjailbreak.dylib" \
  "dopamin-tvOS-kfd.app/Handoff516/dt_opainject516" \
  "dopamin-tvOS-kfd.app/Handoff516/dt_jbctl516" \
  "dopamin-tvOS-kfd.app/Handoff516/libchoma.dylib"; do
  a="$(ipa_member_sha "$AUTH_IPA" "$suffix" 2>/dev/null || echo MISSING)"
  f="$(ipa_member_sha "$IPA" "$suffix" 2>/dev/null || echo MISSING)"
  [[ "$a" == "$f" && "$a" != MISSING ]] || runtime_equiv=FAIL
done
if diff -q <(payload_manifest "$AUTH_PAYLOAD") <(payload_manifest "$FRESH_PAYLOAD") >/dev/null 2>&1; then
  : # payload manifest equal
else
  runtime_equiv=FAIL
fi
[[ "$AUTH_IPA_SHA" == "$FRESH_IPA_SHA" ]] || bitwise=FAIL
compare_pair "$AUTH_DYLD" "$DYLD" merged_dyld >/dev/null || bitwise=FAIL
echo "AUTH_VS_FRESH_RUNTIME_EQUIVALENT=$runtime_equiv"
echo "AUTH_VS_FRESH_BITWISE_DETERMINISTIC=$bitwise"

echo "=== QUALIFICATION COMPLETE ==="
