#!/bin/bash
# Build Handoff674 control661 from freshly built Handoff653 (no historical IPA).
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
BUILD="${DT674_BUILD:-$PROJECT/.theos/obj/handoff674}"
OUT="$BUILD/Control661/dt_direct653_helper_control661"
STAMP="$BUILD/Control661/FROZEN_661_SHA256.txt"
EMBED_C="$PROJECT/handoff674/frozen661_embed.c"
SRC653="$PROJECT/.theos/obj/handoff653/Handoff653/dt_direct653_helper"

if [[ ! -f "$SRC653" ]]; then
  echo "ERROR: build653 output missing at $SRC653 — run build653_handoff.sh first"
  exit 1
fi

mkdir -p "$BUILD/Control661"
cp "$SRC653" "$OUT"
chmod +x "$OUT"

SHA="$(shasum -a 256 "$OUT" | awk '{print $1}')"
echo "$SHA" > "$STAMP"
python3 - "$OUT" "$EMBED_C" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
out = Path(sys.argv[2])
data = src.read_bytes()
lines = [
    '#include "frozen661_embed.h"',
    '',
    f'const unsigned char kDT674Frozen661Embed[] = {{',
]
row = []
for i, b in enumerate(data):
    row.append(f'0x{b:02x}')
    if len(row) == 12:
        lines.append('    ' + ', '.join(row) + ',')
        row = []
if row:
    lines.append('    ' + ', '.join(row))
lines.append('};')
lines.append('')
lines.append(f'const size_t kDT674Frozen661EmbedLen = {len(data)};')
lines.append('')
out.write_text('\n'.join(lines))
PY
echo "CONTROL661_FROM_BUILD653=PASS sha=$SHA"
ls -la "$OUT" "$EMBED_C"
