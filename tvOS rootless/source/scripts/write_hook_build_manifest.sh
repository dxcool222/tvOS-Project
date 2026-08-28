#!/bin/bash
set -euo pipefail
HOOK="${1:?hook dylib path}"
MAN="${2:?manifest output path}"
echo "PLATFORM_HOOK_SHA256=$(shasum -a 256 "$HOOK" | awk '{print $1}')" > "$MAN"
if ! /opt/local/bin/ldid -h "$HOOK" 2>/dev/null \
    | awk -F= '/^CDHash=/{found=1; print "PLATFORM_HOOK_CDHASH="$2} END{exit found ? 0 : 1}' >> "$MAN"; then
    echo "PLATFORM_HOOK_CDHASH=UNAVAILABLE" >> "$MAN"
fi
python3 - "$HOOK" >> "$MAN" <<'PY'
import struct, sys
path = sys.argv[1]
data = open(path, 'rb').read()
idx = data.find(struct.pack('>I', 0xfade0c02))
if idx >= 0:
    print(f"CODEDIRECTORY_PLATFORM_BYTE={data[idx+28]}")
    ver = struct.unpack('>I', data[idx+8:idx+12])[0]
    fl = struct.unpack('>I', data[idx+12:idx+16])[0]
    print(f"CODEDIRECTORY_VERSION=0x{ver:x}")
    print(f"CODEDIRECTORY_FLAGS=0x{fl:x}")
PY
