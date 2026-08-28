#!/usr/bin/env python3
"""Prefix packed payload Mach-Os so the .app does not contain nested MH_MAGIC.

Device 21:51 all_logs: first TSV MACHO row (bin/sync, n_src=215) failed
packed macho SHA. IPA zip bytes of that path still match the TSV. installd /
TrollStore re-signs 0755 Mach-Os inside the installed .app.

Wrap is 8 bytes "R14MACHO" + original file. KIND stays MACHO. TSV SHA is of the
inner Mach-O. Dest copy unwraps. Packed files are 0644 data, not executables.
Does not rewrite the TSV.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import os
import stat
import sys
from pathlib import Path

HDR = b"R14MACHO"
MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: rootless_encode_packed_machos.py PAYLOAD_ROOT MANIFEST.tsv", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    if not root.is_dir() or not manifest.is_file():
        print("payload/manifest missing", file=sys.stderr)
        return 1
    lines = manifest.read_text().splitlines()
    hdr = lines[0].split("\t")
    i_rel = hdr.index("RELATIVE_PATH")
    i_kind = hdr.index("KIND")
    n = 0
    for line in lines[1:]:
        if not line:
            continue
        cols = line.split("\t")
        if cols[i_kind] != "MACHO":
            continue
        rel = cols[i_rel]
        path = root / rel
        if not os.path.lexists(path):
            print(f"missing {rel}", file=sys.stderr)
            return 1
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            print(f"bad inode {rel} mode={oct(st.st_mode)}", file=sys.stderr)
            return 1
        data = path.read_bytes()
        if data.startswith(HDR):
            inner = data[len(HDR):]
            if inner[:4] not in MACHO_MAGICS:
                print(f"wrap inner not macho {rel}", file=sys.stderr)
                return 1
            os.chmod(path, 0o644)
            n += 1
            continue
        if data[:4] not in MACHO_MAGICS:
            print(f"not macho {rel} magic={data[:4]!r}", file=sys.stderr)
            return 1
        path.write_bytes(HDR + data)
        os.chmod(path, 0o644)
        n += 1
    print(f"ENCODED_PACKED_MACHOS={n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
