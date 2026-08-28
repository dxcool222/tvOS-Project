#!/bin/bash
# Read-only audit: R24 dyld identity build-order contract for a completed build tree.
set -euo pipefail

BUILD="${1:-${DT_BUILD_ROOT:-/tmp/tvos-rootless-authoritative-build}}"
KFD="${2:-/tmp/dopamin-kfd}"
TOOLS="${DT_TOOLS_ROOT:-$(cd "$(dirname "$0")/../../tools" && pwd -P)}"

FROZEN="$BUILD/build/r24_dyld_delivery/dyld.frozen"
HEADER="$KFD/generated/dt_rootless_r24_dyld_identity.h"
STAMP="$BUILD/build/r24_dyld_delivery/R24_DYLD_IDENTITY_STAMP.txt"
APP="$BUILD/.theos/obj/appletv/debug/dopamin-tvOS-kfd.app/dopamin-tvOS-kfd"
DYLD_OBJ="$(find "$BUILD/.theos/obj" -name 'dt_rootless_dyld_delivery.m.*.o' 2>/dev/null | head -1 || true)"

for f in "$FROZEN" "$HEADER" "$STAMP" "$APP"; do
  [[ -e "$f" ]] || { echo "R24_IDENTITY_AUDIT=FAIL missing=$f"; exit 1; }
done

python3 - "$FROZEN" "$HEADER" "$STAMP" "$APP" "$DYLD_OBJ" "$TOOLS" <<'PY'
import re
import sys
from pathlib import Path

frozen = Path(sys.argv[1])
header = Path(sys.argv[2])
stamp = Path(sys.argv[3])
app = Path(sys.argv[4])
dyld_obj = Path(sys.argv[5]) if sys.argv[5] else None
sys.path.insert(0, sys.argv[6])
from rootless_macho_canonical_id import canonical_sha256

actual = canonical_sha256(frozen)
header_text = header.read_text()
m = re.search(r'ROOTLESS_R24_GENERATED_DYLD_CANONICAL_SHA256_HEX "([0-9a-f]{64})"', header_text)
header_canon = m.group(1) if m else None
stamp_canon = None
for line in stamp.read_text().splitlines():
    if line.startswith("R24_DYLD_CANONICAL_SHA256="):
        stamp_canon = line.split("=", 1)[1].strip()

app_bytes = app.read_bytes()
app_has = actual.encode() in app_bytes

def ts(p: Path) -> float:
    return p.stat().st_mtime

frozen_t, header_t, obj_t = ts(frozen), ts(header), ts(dyld_obj) if dyld_obj and dyld_obj.exists() else 0.0
app_t = ts(app)

print(f"ACTUAL_DYLD_CANONICAL_SHA={actual}")
print(f"HEADER_CANONICAL_SHA={header_canon}")
print(f"STAMP_CANONICAL_SHA={stamp_canon}")
print(f"APP_EMBEDS_ACTUAL_CANONICAL={'YES' if app_has else 'NO'}")
print(f"DYLD_BUILT_BEFORE_APP={'PASS' if frozen_t <= obj_t else 'FAIL'} frozen_ts={frozen_t} obj_ts={obj_t}")
print(f"IDENTITY_HEADER_GENERATED_BEFORE_APP={'PASS' if header_t <= obj_t else 'FAIL'} header_ts={header_t}")
print(f"APP_COMPILED_WITH_GENERATED_IDENTITY={'PASS' if header_canon == actual and app_has else 'FAIL'}")
print(f"AUTH_RUNTIME_DYLD_IDENTITY_MATCH={'PASS' if header_canon == actual == stamp_canon and app_has else 'FAIL'}")
PY

APP_DIR="$BUILD/.theos/obj/appletv/debug/dopamin-tvOS-kfd.app"
bash "$KFD/scripts/verify_r24_dyld_packaging_identity.sh" "$APP_DIR" "$STAMP"
