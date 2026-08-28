#!/bin/bash
# Force recompile of objects that embed generated/dt_rootless_r24_dyld_identity.h
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
source "$SCRIPT/clean_project_env.sh"

OBJ_ROOT="$DT_BUILD_ROOT/.theos/obj"
[[ -d "$OBJ_ROOT" ]] || exit 0

patterns=(
  '*dt_rootless_dyld_delivery*'
  '*main_cbr*'
)

removed=0
for pat in "${patterns[@]}"; do
  while IFS= read -r -d '' f; do
    rm -f "$f"
    removed=$((removed + 1))
  done < <(find "$OBJ_ROOT" -name "$pat" -print0 2>/dev/null || true)
done

echo "R24_DYLD_IDENTITY_CONSUMERS_INVALIDATED=$removed"
