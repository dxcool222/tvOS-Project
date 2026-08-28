#!/bin/bash
# Ensure prep_bootstrap.sh ends with dest-abs self-removal (R18/R20 contract).
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
source "$SCRIPT/../source/scripts/clean_project_env.sh"
PREP="$DT_BUILD_ROOT/work/jbroot_transformed/prep_bootstrap.sh"
NEEDLE="/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh"
[[ -f "$PREP" ]] || { echo "ERROR: missing $PREP"; exit 1; }
if ! grep -Fq "$NEEDLE" "$PREP"; then
  printf '\n%s\n' "$NEEDLE" >> "$PREP"
fi
chmod 755 "$PREP"
echo "PREP_BOOTSTRAP_BASE_PATCH=PASS"
