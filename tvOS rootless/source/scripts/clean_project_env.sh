#!/bin/bash
# Out-of-tree build environment for tvOS rootless (standalone; no old rootless paths).
set -euo pipefail
ENV_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
KFD="$(cd "$ENV_SCRIPT/.." && pwd -P)"
WS="$(cd "$KFD/.." && pwd -P)"
if [[ -n "${DT_BUILD_ROOT:-}" ]]; then
  mkdir -p "$DT_BUILD_ROOT"
  BUILD="$(cd "$DT_BUILD_ROOT" && pwd -P)"
else
  BUILD="$(cd "$WS/../tvOS rootless-build" && pwd -P)"
fi

export DT_WORKSPACE_ROOT="$WS"
export DT_BUILD_ROOT="$BUILD"
export DT_KFD_ROOT="$KFD"
export DT_DOPAMINE_ROOT="$WS/Dependencies/Dopamine-2.x"
export DT_STOCK_DYLD="${DT_STOCK_DYLD:-$WS/vendor/dyld/user/dyld_filesystem_20L563}"
export DT_TOOLS_ROOT="$WS/tools"

mkdir -p "$BUILD/build" "$BUILD/basebin/out" "$BUILD/.theos/obj" "$BUILD/tools" "$BUILD/theos-root"

# Theos object dir outside source tree (always refresh — stale targets break repro builds)
rm -rf "$KFD/.theos" 2>/dev/null || true
ln -sfn "$BUILD/.theos" "$KFD/.theos"
# build/ symlink for scripts expecting $KFD/build
rm -rf "$KFD/build" 2>/dev/null || true
ln -sfn "$BUILD/build" "$KFD/build"
# basebin/out symlink
rm -rf "$KFD/basebin/out" 2>/dev/null || true
ln -sfn "$BUILD/basebin/out" "$KFD/basebin/out"

ln -sfn "$WS" /tmp/dopamin-root
ln -sfn "$KFD" /tmp/dopamin-kfd
ln -sfn "$DT_DOPAMINE_ROOT" /tmp/dopamin-dopamine
ln -sfn "$BUILD" /tmp/dopamin-build
