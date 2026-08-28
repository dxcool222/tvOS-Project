#!/bin/bash
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=scripts/clean_project_env.sh
source "$SCRIPT/clean_project_env.sh"

MM_SRC="$DT_DOPAMINE_ROOT/BaseBin/MachOMerger"
OUT="$DT_BUILD_ROOT/tools/MachOMerger"

[[ -d "$MM_SRC/Sources" ]] || { echo "ERROR: MachOMerger source missing"; exit 1; }

pushd "$MM_SRC" >/dev/null
MACOS=1 make clean >/dev/null 2>&1 || true
MACOS=1 make
popd >/dev/null

cp -f "$MM_SRC/MachOMerger" "$OUT"
chmod +x "$OUT"
echo "MachOMerger host tool: $OUT"
