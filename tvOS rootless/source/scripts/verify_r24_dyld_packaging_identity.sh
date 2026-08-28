#!/bin/bash
# Package-time gate: staged R24DyldDelivery/dyld canonical must match app-embedded expectation.
set -euo pipefail

APP_DIR="${1:?usage: verify_r24_dyld_packaging_identity.sh <dopamin.app dir>}"
STAMP="${2:-}"

DYLD="$APP_DIR/R24DyldDelivery/dyld"
APP_BIN="$APP_DIR/dopamin-tvOS-kfd"
TOOLS="${DT_TOOLS_ROOT:-$(cd "$(dirname "$0")/../../tools" && pwd -P)}"

[[ -f "$DYLD" ]] || { echo "R24_DYLD_IDENTITY_BUILD_CONTRACT=FAIL missing=$DYLD"; exit 1; }
[[ -f "$APP_BIN" ]] || { echo "R24_DYLD_IDENTITY_BUILD_CONTRACT=FAIL missing=$APP_BIN"; exit 1; }

_r24_identity_lines=()
while IFS= read -r _r24_line; do
  _r24_identity_lines+=("$_r24_line")
done < <(python3 - "$DYLD" "$APP_BIN" "$STAMP" "$TOOLS" <<'PY'
import re
import sys
from pathlib import Path

dyld_path, app_path, stamp_path, tools = sys.argv[1:5]
sys.path.insert(0, tools)
from rootless_macho_canonical_id import canonical_sha256

dyld = Path(dyld_path)
app = Path(app_path)
packaged = canonical_sha256(dyld)
app_bytes = app.read_bytes()
hex_strings = sorted(set(m.group(0).decode() for m in re.finditer(rb"[0-9a-f]{64}", app_bytes)))

app_expected = None
if packaged in hex_strings:
    app_expected = packaged
elif stamp_path and Path(stamp_path).is_file():
    stamp = Path(stamp_path).read_text().strip().split("=", 1)[-1].strip()
    if stamp in hex_strings:
        app_expected = stamp

print(packaged)
print(app_expected or "")
stamp_out = ""
if stamp_path and Path(stamp_path).is_file():
    stamp_out = Path(stamp_path).read_text().strip().split("=", 1)[-1].strip()
print(stamp_out)
PY
)
packaged_canonical="${_r24_identity_lines[0]:-}"
app_expected_canonical="${_r24_identity_lines[1]:-}"
stamp_canonical="${_r24_identity_lines[2]:-}"

echo "R24_DYLD_PACKAGED_CANONICAL=$packaged_canonical"
if [[ -n "$app_expected_canonical" ]]; then
  echo "R24_APP_EXPECTED_DYLD_CANONICAL=$app_expected_canonical"
else
  echo "R24_APP_EXPECTED_DYLD_CANONICAL=MISSING"
fi

if [[ -z "$app_expected_canonical" ]]; then
  echo "R24_DYLD_IDENTITY_BUILD_CONTRACT=FAIL reason=app_missing_expected_canonical"
  exit 1
fi

if [[ "$packaged_canonical" != "$app_expected_canonical" ]]; then
  echo "R24_DYLD_IDENTITY_BUILD_CONTRACT=FAIL reason=packaged_vs_app_mismatch"
  exit 1
fi

if [[ -n "$stamp_canonical" && "$stamp_canonical" != "$packaged_canonical" ]]; then
  echo "R24_DYLD_IDENTITY_BUILD_CONTRACT=FAIL reason=stamp_vs_packaged_mismatch stamp=$stamp_canonical packaged=$packaged_canonical"
  exit 1
fi

echo "R24_DYLD_IDENTITY_BUILD_CONTRACT=PASS"
