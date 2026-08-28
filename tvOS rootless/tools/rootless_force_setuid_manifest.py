#!/usr/bin/env python3
"""Force strap setuid MODE_OCT rows in path manifest (tar roster).

Host extract/rsync/encode often drop S_ISUID; install authority is the TSV.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import csv
import sys
from pathlib import Path

SETUID_RELS = {
    "usr/bin/chpass",
    "usr/bin/newgrp",
    "usr/bin/su",
    "usr/bin/quota",
    "usr/bin/sudo",
    "usr/bin/login",
    "usr/bin/passwd",
    "usr/sbin/shshd",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    args = ap.parse_args()
    path = Path(args.manifest)
    rows = list(csv.DictReader(path.open(), delimiter="\t"))
    if not rows:
        print("empty manifest", file=sys.stderr)
        return 1
    fieldnames = list(rows[0].keys())
    n = 0
    seen = set()
    for row in rows:
        rel = row.get("RELATIVE_PATH", "")
        if rel in SETUID_RELS:
            row["MODE_OCT"] = "0o4755"
            seen.add(rel)
            n += 1
    missing = SETUID_RELS - seen
    if missing:
        print(f"missing setuid rows: {sorted(missing)}", file=sys.stderr)
        return 1
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"FORCED_SETUID_MODE_ROWS={n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
