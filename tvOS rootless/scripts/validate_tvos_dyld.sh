#!/bin/bash
# Validate user-supplied stock tvOS 16.5 (20L563) dyld input against pinned contract.
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=source/scripts/clean_project_env.sh
source "$SCRIPT/../source/scripts/clean_project_env.sh"

CONTRACT="$DT_WORKSPACE_ROOT/vendor/dyld/TVOS_20L563_DYLD_CONTRACT.json"
EXPECTED_SHA="$(python3 - "$CONTRACT" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["expected_sha256"])
PY
)"
EXPECTED_UUID="$(python3 - "$CONTRACT" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["expected_uuid"])
PY
)"
EXPECTED_SIZE="$(python3 - "$CONTRACT" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["expected_size_bytes"])
PY
)"

CANDIDATE="${1:-}"
if [[ -z "$CANDIDATE" ]]; then
  for p in "$DT_WORKSPACE_ROOT/vendor/dyld/user/dyld_filesystem_20L563" \
           "$DT_WORKSPACE_ROOT/vendor/dyld/user/dyld" \
           "${TVOS_DYLD_INPUT:-}"; do
    [[ -n "$p" && -f "$p" ]] && CANDIDATE="$p" && break
  done
fi
[[ -n "$CANDIDATE" && -f "$CANDIDATE" ]] || {
  echo "ERROR: tvOS dyld input missing. Place stock dyld at vendor/dyld/user/dyld_filesystem_20L563" >&2
  echo "       or pass path as first argument / set TVOS_DYLD_INPUT." >&2
  exit 1
}

ACTUAL_SHA="$(shasum -a 256 "$CANDIDATE" | awk '{print $1}')"
ACTUAL_SIZE="$(stat -f%z "$CANDIDATE" 2>/dev/null || stat -c%s "$CANDIDATE")"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || { echo "ERROR: dyld SHA256 mismatch got=$ACTUAL_SHA"; exit 2; }
[[ "$ACTUAL_SIZE" == "$EXPECTED_SIZE" ]] || { echo "ERROR: dyld size mismatch got=$ACTUAL_SIZE expected=$EXPECTED_SIZE"; exit 2; }

ACTUAL_UUID="$(python3 "$DT_TOOLS_ROOT/rootless_macho_canonical_id.py" "$CANDIDATE" | awk -F= '/^UUID=/{print $2; exit}')"
[[ "$ACTUAL_UUID" == "$EXPECTED_UUID" ]] || { echo "ERROR: dyld UUID mismatch got=$ACTUAL_UUID expected=$EXPECTED_UUID"; exit 2; }

export DT_STOCK_DYLD="$CANDIDATE"
echo "DYLD_INPUT_IDENTITY=PASS path=$CANDIDATE sha256=$ACTUAL_SHA uuid=$ACTUAL_UUID"
