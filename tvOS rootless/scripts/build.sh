#!/bin/bash
# One-command ROOTLESS R24 IPA build from clean tvOS rootless source tree.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
export DT_WORKSPACE_ROOT="$ROOT"
export DT_BUILD_ROOT="${DT_BUILD_ROOT:-$ROOT/../tvos-rootless-repro-build}"
export DT_TOOLS_ROOT="$ROOT/tools"
export THEOS="${THEOS:-$HOME/theos}"

echo "=== tvOS rootless build ==="
echo "WORKSPACE=$DT_WORKSPACE_ROOT"
echo "BUILD=$DT_BUILD_ROOT"

# Host prerequisites
command -v xcrun >/dev/null || { echo "ERROR: Xcode/xcrun required"; exit 1; }
command -v make >/dev/null || { echo "ERROR: GNU make required"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 required"; exit 1; }
command -v zstd >/dev/null || { echo "ERROR: zstd required"; exit 1; }
[[ -d "$THEOS" ]] || { echo "ERROR: THEOS missing at $THEOS"; exit 1; }
[[ -d "${TVOS_SYSROOT:-$HOME/theos/sdks/AppleTVOS16.4.sdk}" ]] || {
  echo "ERROR: AppleTVOS16.4.sdk missing (set TVOS_SYSROOT)"; exit 1; }

source "$ROOT/source/scripts/clean_project_env.sh"
bash "$ROOT/scripts/validate_tvos_dyld.sh"
bash "$ROOT/source/scripts/build_machomerger_host.sh"
if [[ "${DT_SKIP_BOOTSTRAP_GENERATION:-}" != "1" ]]; then
  bash "$ROOT/scripts/build_bootstrap_payload.sh"
else
  echo "BOOTSTRAP_GENERATION=SKIP"
fi

# Phase 1b–3 via /tmp symlink (Theos rejects spaces in project path)
export THEOS_PROJECT_DIR="/tmp/dopamin-kfd"
export CLANG_MODULE_CACHE_PATH="$DT_BUILD_ROOT/.theos/module-cache"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$DT_BUILD_ROOT/theos-root"

cd /tmp/dopamin-kfd
make -C basebin dylibs
if [[ "${DT_ROOTLESS_R24:-1}" = "1" ]]; then
  bash scripts/bootstrap_r24_seed.sh
  echo "=== Phase 2+3: R24 dyld delivery + generated identity (upstream of app) ==="
  bash scripts/build_r24_dyld_delivery.sh
  export DT_R24_DYLD_PREBUILT=1
fi

make clean 2>/dev/null || true
make ipa DT_ROOTLESS_R4=1 DT_ROOTLESS_R24=1 DT_REPRO_BUILD=1 \
  DT_R24_DYLD_PREBUILT="${DT_R24_DYLD_PREBUILT:-1}" \
  DT_WORKSPACE_ROOT="$DT_WORKSPACE_ROOT" DT_BUILD_ROOT="$DT_BUILD_ROOT" DT_TOOLS_ROOT="$DT_TOOLS_ROOT"

IPA="$DT_BUILD_ROOT/dopamin-tvOS-kfd-ROOTLESS-R24.ipa"
[[ -f "$IPA" ]] || IPA="/tmp/dopamin-build/theos-root/dopamin-tvOS-kfd-ROOTLESS-R24.ipa"
[[ -f "$IPA" ]] || { echo "ERROR: IPA not produced"; exit 1; }

echo "IPA_PACKAGE=PASS path=$IPA"
shasum -a 256 "$IPA"
