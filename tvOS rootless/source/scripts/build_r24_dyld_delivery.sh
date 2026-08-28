#!/bin/bash
# Phase 2+3: build/sign/merge R24 dyld, freeze it, generate identity header for app compile.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=scripts/clean_project_env.sh
source "$SCRIPT/clean_project_env.sh"
SRCROOT="$DT_KFD_ROOT"
DOPAMINE="$DT_DOPAMINE_ROOT"
DYLD_SRC="$DT_STOCK_DYLD"
SDK="${TVOS_SYSROOT:-$HOME/theos/sdks/AppleTVOS16.4.sdk}"
OUT="$DT_BUILD_ROOT/build/r24_dyld_delivery"
OBJ="$DT_BUILD_ROOT/.theos/obj/r24_dyld_delivery/hook"
MERGER="$DT_BUILD_ROOT/tools/MachOMerger"
LDID="${LDID:-$(command -v ldid || true)}"
CC=(xcrun -sdk appletvos clang)
FROZEN="$OUT/dyld.frozen"
STAMP="$OUT/R24_DYLD_IDENTITY_STAMP.txt"
HEADER="$SRCROOT/generated/dt_rootless_r24_dyld_identity.h"
FROZEN_V26_CANON="772a5bb86acf87f5dfd68cff0043640ab4645c9fecb1f76e278aaed28cacfcf7"

[[ -f "$DYLD_SRC" ]] || { echo "ERROR exact tvOS dyld missing: $DYLD_SRC" >&2; exit 1; }
[[ -d "$DOPAMINE/BaseBin/dyldhook/src" ]] || { echo "ERROR local Dopamine reference missing" >&2; exit 1; }
[[ -x "$MERGER" ]] || { echo "ERROR pinned MachOMerger host tool missing: $MERGER" >&2; exit 1; }
[[ -n "$LDID" && -x "$LDID" ]] || { echo "ERROR host ldid missing" >&2; exit 1; }

mkdir -p "$OUT" "$OBJ"
rm -f "$OBJ"/*.o "$OUT"/dyld.patched.premerge "$OUT"/dyld "$OUT"/dyld.frozen "$OUT"/dyldhook_merge.arm64.dylib

UP="$DOPAMINE/BaseBin/dyldhook/src"
TV="$SRCROOT/handoff516/source/dyldhook_tvos"
INC=(
  -I"$UP" -I"$DOPAMINE/BaseBin/libjailbreak/src"
  -I"$SRCROOT/handoff516/source/include"
  -I"$DT_BUILD_ROOT/build/rootless_r4/include"
  -I"$DOPAMINE/BaseBin/_external/include"
)
CFLAGS=(
  -arch arm64 -isysroot "$SDK" -mtvos-version-min=14.0 -O2 -fPIC
  -fno-stack-check -D_FORTIFY_SOURCE=0 -DIOS=16
  -D_DARWIN_UNLIMITED_SYSCALLS -Wno-deprecated-declarations -Wno-availability
  "${INC[@]}"
)

sources=(
  "$TV/dt_dyldhook_main_tvos.c"
  "$TV/dt_jbclient_mach_tvos.c"
  "$TV/dt_dyldhook_raw_write.S"
  "$UP/main.S" "$UP/reimpl.c" "$UP/fakelib_redirect.c" "$UP/lv_bypass.c"
  "$UP/spinlock_fix.c" "$UP/generated/ios16/task.c"
)
objs=()
for src in "${sources[@]}"; do
  base="$(basename "$src")"
  obj="$OBJ/${base%.*}.o"
  [[ "$base" == "main.S" ]] && obj="$OBJ/upstream_main_asm.o"
  "${CC[@]}" "${CFLAGS[@]}" -c "$src" -o "$obj"
  objs+=("$obj")
done

HOOK="$OUT/dyldhook_merge.arm64.dylib"
"${CC[@]}" -arch arm64 -isysroot "$SDK" -mtvos-version-min=14.0 \
  -dynamiclib -Wl,-add_split_seg_info "${objs[@]}" -o "$HOOK"
"$LDID" -S "$HOOK"

PRE="$OUT/dyld.patched.premerge"
MANIFEST="$OUT/R24_TVOS_DYLD_DELIVERY_IDENTITY.json"
python3 "$SCRIPT/r24_patch_exact_tvos_dyld.py" "$DYLD_SRC" "$PRE" "$MANIFEST"
"$MERGER" "$PRE" "$HOOK" "$OUT/dyld"
chmod 0755 "$OUT/dyld"
"$LDID" -S "$OUT/dyld"

# Freeze Phase-2 artifact before identity generation (immutable for rest of build).
cp -p "$OUT/dyld" "$FROZEN"
chmod 0555 "$FROZEN"

DYLD_SHA="$(shasum -a 256 "$FROZEN" | awk '{print $1}')"
HOOK_SHA="$(shasum -a 256 "$HOOK" | awk '{print $1}')"
_identity_lines=()
while IFS= read -r _identity_line; do
  _identity_lines+=("$_identity_line")
done < <(python3 - "$FROZEN" "$DT_TOOLS_ROOT" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[2])
from r24_dyld_contract import locate_generated_patch_offset
from rootless_macho_canonical_id import canonical_sha256, macho_uuid

dyld = sys.argv[1]
print(f"0x{locate_generated_patch_offset(dyld):x}")
print(canonical_sha256(dyld))
print(macho_uuid(dyld))
PY
)
GEN_PATCH_OFF="${_identity_lines[0]:-}"
GEN_CANON="${_identity_lines[1]:-}"
GEN_UUID="${_identity_lines[2]:-}"
[[ -n "$GEN_CANON" ]] || { echo "ERROR: empty canonical SHA from $FROZEN" >&2; exit 1; }

python3 - "$MANIFEST" "$DYLD_SHA" "$HOOK_SHA" "$GEN_PATCH_OFF" "$GEN_CANON" "$GEN_UUID" <<'PY'
import json
import sys

path, dyld_sha, hook_sha, patch_off, canon, uid = sys.argv[1:7]
data = json.loads(open(path, encoding="utf-8").read())
data["generated_patch_offset"] = patch_off
data["generated_canonical_sha256"] = canon
data["generated_uuid"] = uid
data["patched_merged_signed_sha256"] = dyld_sha
data["dyldhook_merge_sha256"] = hook_sha
open(path, "w", encoding="utf-8").write(json.dumps(data, indent=2) + "\n")
PY

python3 "$SCRIPT/generate_r24_dyld_identity_header.py" "$FROZEN" "$MANIFEST" "$HEADER"
printf 'R24_DYLD_CANONICAL_SHA256=%s\n' "$GEN_CANON" >"$STAMP"
printf 'R24_DYLD_RAW_SHA256=%s\n' "$DYLD_SHA" >>"$STAMP"
printf 'R24_DYLD_FROZEN_PATH=%s\n' "$FROZEN" >>"$STAMP"

if [[ "$GEN_CANON" == "$FROZEN_V26_CANON" ]]; then
  echo "ERROR: reproducible build still emits frozen V26 canonical identity" >&2
  exit 1
fi

bash "$SCRIPT/invalidate_r24_dyld_identity_consumers.sh"
touch "$HEADER" "$SRCROOT/dt_rootless_dyld_delivery.m"

rg -a -q 'R24_DYLDHOOK_CHECKIN_BEGIN' "$FROZEN"
rg -a -q 'R24_DYLDHOOK_CHECKIN_PASS' "$FROZEN"
nm "$FROZEN" > "$OUT/dyld.nm.txt"
rg -q 'MACHOMERGER_START_HOOK' "$OUT/dyld.nm.txt"
python3 - "$FROZEN" <<'PY'
import struct
import sys

data = open(sys.argv[1], "rb").read()
off = 32
ncmds = struct.unpack_from("<I", data, 16)[0]
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, off)
    if cmd == 0x1B:
        tag = data[off + 8 : off + 18]
        if tag != b"DOPATV165\x00":
            raise SystemExit(f"bad UUID tag: {tag!r}")
        break
    off += size
else:
    raise SystemExit("LC_UUID missing")
PY

echo "R24_DYLD_DELIVERY_BUILD=PASS dyld_sha256=$DYLD_SHA canonical_sha256=$GEN_CANON"
echo "R24_DYLD_FROZEN=$FROZEN"
