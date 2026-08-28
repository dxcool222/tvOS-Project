#!/bin/bash
# Extract appletvos_extract + oracle_jb bootstrap inputs from pinned Procursus tars.
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=../source/scripts/clean_project_env.sh
source "$SCRIPT/../source/scripts/clean_project_env.sh"

TARS_DIR="${DT_BOOTSTRAP_TARS_DIR:-$DT_WORKSPACE_ROOT/bootstrap/tars}"
PRODUCT="$TARS_DIR/bootstrap-appletvos-arm64.tar.zst"
ORACLE="$TARS_DIR/bootstrap-ssh-appletvos-arm64-rootless.tar.zst"
PIN_FILE="$DT_WORKSPACE_ROOT/bootstrap/TARS.sha256"
APP_OUT="$DT_BUILD_ROOT/work/appletvos_extract"
ORA_OUT="$DT_BUILD_ROOT/work/oracle_jb"

verify_tar() {
  local file="$1" expected="$2"
  [[ -f "$file" ]] || { echo "ERROR: missing bootstrap tar $file"; exit 1; }
  local got
  got="$(shasum -a 256 "$file" | awk '{print $1}')"
  [[ "$got" == "$expected" ]] || { echo "ERROR: tar SHA mismatch $file got=$got expected=$expected"; exit 1; }
}

PRODUCT_SHA="$(awk '/bootstrap-appletvos/{print $1}' "$PIN_FILE")"
ORACLE_SHA="$(awk '/bootstrap-ssh-appletvos-arm64-rootless/{print $1}' "$PIN_FILE")"
verify_tar "$PRODUCT" "$PRODUCT_SHA"
verify_tar "$ORACLE" "$ORACLE_SHA"

if [[ -f "$APP_OUT/usr/bin/bash" && -f "$ORA_OUT/usr/lib/libiosexec.1.dylib" ]]; then
  echo "BOOTSTRAP_INPUTS=REUSE appletvos_extract oracle_jb"
  exit 0
fi

echo "=== extract appletvos_extract ==="
rm -rf "$APP_OUT"
mkdir -p "$APP_OUT"
zstd -dc "$PRODUCT" | tar -xf - -C "$APP_OUT"

echo "=== extract oracle_jb ==="
rm -rf "$ORA_OUT"
TMP_ORA="$(mktemp -d)"
mkdir -p "$ORA_OUT"
zstd -dc "$ORACLE" | tar -xf - -C "$TMP_ORA"
rsync -a "$TMP_ORA/var/jb/" "$ORA_OUT/"
rm -rf "$TMP_ORA"

echo "BOOTSTRAP_INPUTS=PASS appletvos_extract=$APP_OUT oracle_jb=$ORA_OUT"
