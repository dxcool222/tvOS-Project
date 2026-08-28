#!/usr/bin/env python3
"""Generate ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv from a RootlessPayload tree."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse, csv, hashlib, os, stat
from pathlib import Path


def is_macho(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(4) in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    except OSError:
        return False


def classify(rel: str, st: os.stat_result, is_link: bool, path: Path) -> tuple[str, str]:
    # disposition, kind
    if is_link:
        return "CREATE_SYMLINK", "SYMLINK"
    if stat.S_ISDIR(st.st_mode):
        return "CREATE_DIRECTORY", "DIRECTORY"
    if is_macho(path):
        return "INSTALL_FILE", "MACHO"
    if path.suffix in (".plist",):
        return "INSTALL_FILE", "PLIST"
    if path.suffix in (".list", ".md5sums", ".conffiles") or "dpkg" in rel:
        return "INSTALL_FILE", "PACKAGE_METADATA"
    if path.suffix in (".sh", ".bash") or (st.st_mode & 0o111):
        # scripts / executables without macho
        if path.suffix in (".sh", ".bash"):
            return "INSTALL_FILE", "SCRIPT"
    if path.suffix in (".sh",):
        return "INSTALL_FILE", "SCRIPT"
    return "INSTALL_FILE", "OTHER"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("payload_root")
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()
    root = Path(args.payload_root)
    rows = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        rel_dir = "." if dp == root else str(dp.relative_to(root))
        if rel_dir != ".":
            st = dp.lstat()
            rows.append(
                {
                    "RELATIVE_PATH": rel_dir,
                    "DISPOSITION": "CREATE_DIRECTORY",
                    "KIND": "DIRECTORY",
                    "SYMLINK_TARGET": "",
                    "MODE_OCT": oct(st.st_mode & 0o7777),
                    "SHA256": "",
                }
            )
        # also enumerate symlink-only children that os.walk may treat oddly
        for name in dirnames + filenames:
            p = dp / name
            try:
                st = p.lstat()
            except OSError:
                continue
            is_link = stat.S_ISLNK(st.st_mode)
            if not is_link and stat.S_ISDIR(st.st_mode):
                continue  # dirs handled when walked
            rel = str(p.relative_to(root))
            disp, kind = classify(rel, st, is_link, p)
            tgt = os.readlink(p) if is_link else ""
            sha = ""
            if not is_link and stat.S_ISREG(st.st_mode) and kind == "MACHO":
                sha = hashlib.sha256(p.read_bytes()).hexdigest()
            rows.append(
                {
                    "RELATIVE_PATH": rel,
                    "DISPOSITION": disp,
                    "KIND": kind,
                    "SYMLINK_TARGET": tgt,
                    "MODE_OCT": oct(st.st_mode & 0o7777),
                    "SHA256": sha,
                }
            )
    # dedupe by path (walk may double)
    seen = {}
    for r in rows:
        seen[r["RELATIVE_PATH"]] = r
    ordered = [seen[k] for k in sorted(seen)]
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["RELATIVE_PATH", "DISPOSITION", "KIND", "SYMLINK_TARGET", "MODE_OCT", "SHA256"],
            delimiter="\t",
        )
        w.writeheader()
        w.writerows(ordered)
    counts = {}
    for r in ordered:
        counts[r["KIND"]] = counts.get(r["KIND"], 0) + 1
        counts["DISP_" + r["DISPOSITION"]] = counts.get("DISP_" + r["DISPOSITION"], 0) + 1
    print(f"PACKAGED_PAYLOAD_ENTRY_COUNT={len(ordered)}")
    for k, v in sorted(counts.items()):
        print(f"{k}={v}")
    print(f"WROTE={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
