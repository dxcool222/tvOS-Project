#!/bin/bash
# Compile/link verification for tvOS rootless (no IPA, no device).
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
# shellcheck source=scripts/clean_project_env.sh
source "$SCRIPT/clean_project_env.sh"

THEOS="${THEOS:-$HOME/theos}"
export THEOS
source "$SCRIPT/clean_project_env.sh"
export THEOS_PROJECT_DIR="/tmp/dopamin-kfd"
export CLANG_MODULE_CACHE_PATH="$DT_BUILD_ROOT/.theos/module-cache"
mkdir -p "$CLANG_MODULE_CACHE_PATH"

echo "=== tvOS rootless compile verification ==="
echo "WORKSPACE=$DT_WORKSPACE_ROOT"
echo "BUILD=$DT_BUILD_ROOT"

bash "$SCRIPT/build_machomerger_host.sh"
make -C /tmp/dopamin-kfd/basebin dylibs
bash "$SCRIPT/bootstrap_r24_seed.sh"

cd /tmp/dopamin-kfd
make clean 2>/dev/null || true
make all DT_ROOTLESS_R4=1 DT_ROOTLESS_R24=1 DT_WORKSPACE_ROOT="$DT_WORKSPACE_ROOT"

APP="$DT_BUILD_ROOT/.theos/obj/appletv/debug/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd"
HOOK="$DT_BUILD_ROOT/build/rootless_r4/Handoff516/launchdhook516.dylib"
SH="$DT_BUILD_ROOT/build/rootless_r4/Handoff516/systemhook.dylib"
DYLD="$DT_BUILD_ROOT/build/r24_dyld_delivery/dyld"
HOOKDY="$DT_BUILD_ROOT/build/r24_dyld_delivery/dyldhook_merge.arm64.dylib"
OPA="$DT_BUILD_ROOT/build/rootless_r4/Handoff516/dt_opainject516"
JBCTL="$DT_BUILD_ROOT/build/rootless_r4/Handoff516/dt_jbctl516"
LJB="$DT_BUILD_ROOT/basebin/out/libjailbreak.dylib"

for f in "$APP" "$HOOK" "$SH" "$DYLD" "$HOOKDY" "$OPA" "$JBCTL" "$LJB"; do
  [[ -f "$f" ]] || { echo "MISSING: $f"; exit 1; }
  file "$f"
done

echo "COMPILE_VERIFY=PASS"
