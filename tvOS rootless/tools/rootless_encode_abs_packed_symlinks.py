#!/usr/bin/env python3
"""Replace absolute payload symlinks with regular marker files before IPA zip.

tvOS installd materializes .app trees while leftover /var/jb exists. Absolute
payload links (bin/bash -> /var/jb/usr/bin/bash) become regular files of the
target inode. Device packed_source_verify then fails:

  packed type mismatch symlink bin/bash
  n_src=188  (first TSV SYMLINK row)

Relative in-tree links are left as real symlinks.
Does not rewrite the TSV: KIND stays SYMLINK; dest install still symlink(TSV).
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import os
import stat
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: rootless_encode_abs_packed_symlinks.py PAYLOAD_ROOT MANIFEST.tsv", file=sys.stderr)
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
    i_tgt = hdr.index("SYMLINK_TARGET")
    n = 0
    for line in lines[1:]:
        if not line:
            continue
        cols = line.split("\t")
        if cols[i_kind] != "SYMLINK":
            continue
        tgt = cols[i_tgt] if i_tgt < len(cols) else ""
        if not tgt.startswith("/"):
            continue
        rel = cols[i_rel]
        path = root / rel
        if not os.path.lexists(path):
            print(f"missing {rel}", file=sys.stderr)
            return 1
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            got = os.readlink(path)
            if got != tgt:
                print(f"target mismatch {rel}: {got!r} != {tgt!r}", file=sys.stderr)
                return 1
            path.unlink()
        elif stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
            got = path.read_bytes()
            if got != tgt.encode():
                print(f"marker mismatch {rel} size={len(got)}", file=sys.stderr)
                return 1
            n += 1
            continue
        else:
            print(f"bad inode {rel} mode={oct(st.st_mode)}", file=sys.stderr)
            return 1
        path.write_bytes(tgt.encode())
        os.chmod(path, 0o644)
        n += 1
    print(f"ENCODED_ABS_PACKED_SYMLINKS={n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
