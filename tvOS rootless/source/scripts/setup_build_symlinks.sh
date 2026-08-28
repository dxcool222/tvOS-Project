#!/bin/bash
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
if [[ -n "${DT_WORKSPACE_ROOT:-}" ]]; then
  ROOT="$(cd "$DT_WORKSPACE_ROOT" && pwd -P)"
else
  ROOT="$(cd "$KFD/.." && pwd -P)"
  if [[ ! -d "$ROOT/Dependencies/Dopamine-2.x" && -d "$ROOT/../Dependencies/Dopamine-2.x" ]]; then
    ROOT="$(cd "$ROOT/.." && pwd -P)"
  fi
fi
if [[ -d "$ROOT/Dependencies/Dopamine-2.x" ]]; then
  DOPAMINE="$ROOT/Dependencies/Dopamine-2.x"
elif [[ -d "$ROOT/Dopamine-2.x" ]]; then
  DOPAMINE="$ROOT/Dopamine-2.x"
elif [[ -d "$ROOT/Dopamine_Rootful-main" ]]; then
  DOPAMINE="$ROOT/Dopamine_Rootful-main"
else
  echo "ERROR: bundled Dopamine dependency missing under $ROOT/Dependencies/Dopamine-2.x" >&2
  exit 1
fi
ln -sfn "$ROOT" /tmp/dopamin-root
ln -sfn "$KFD" /tmp/dopamin-kfd
ln -sfn "$DOPAMINE" /tmp/dopamin-dopamine
