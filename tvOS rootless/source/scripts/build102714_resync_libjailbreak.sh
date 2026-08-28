#!/bin/bash
# BUILD102714: resync runtime libjailbreak gSystemInfo pmap layout with app (Dopamine-2.x info.h)
# without full basebin rebuild. Preserves Rootful tvOS kalloc_pt probe exports.
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
ROOTFUL="/tmp/dopamin-rootful"
DOP2="/tmp/dopamin-dopamine"
ln -sfn "$KFD/../Dopamine_Rootful-main" "$ROOTFUL" 2>/dev/null || true
bash "$KFD/scripts/setup_build_symlinks.sh"
# 1) Full libjailbreak with Dopamine-2.x info.h → pmap_expand uses gSystemInfo+0x2f8/+0x2fc
rm -rf "$KFD/basebin/out/obj/libjb" "$KFD/basebin/out/libjailbreak.dylib"
make -C "$KFD/basebin" out/libjailbreak.dylib
# 2) Replace kalloc_pt.o with Rootful tvOS probe exports (not in Dopamine-2.x kalloc_pt.m)
rm -f "$KFD/basebin/out/obj/libjb/kalloc_pt.o"
make -C "$KFD/basebin" out/obj/libjb/kalloc_pt.o DOPAMINE="$ROOTFUL"
make -C "$KFD/basebin" out/libjailbreak.dylib
echo "OK BUILD102714 libjailbreak resync: $(shasum -a 256 "$KFD/basebin/out/libjailbreak.dylib" | awk '{print $1}')"
