#!/usr/bin/env python3
"""Sign transformed Mach-Os and emit exact ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import csv
import hashlib
import re
import subprocess
import struct
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
TREE = work_dir("jbroot_transformed")
ART = artifacts_dir()
TRANSFORM = ART / "ROOTLESS_R4_TRANSFORM_FINAL.tsv"
COUNTS = ART / "ROOTLESS_R4_COUNT_SUMMARY.tsv"
LDID = ldid_path()
UIALERT_XML = ROOT / "bootstrap/entitlements/appletvos_extract_entitlements.xml"
MH_MAGIC_64 = 0xFEEDFACF
LC_UUID = 0x1B


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def macho_uuid(p: Path) -> str:
    data = p.read_bytes()
    if struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        return ""
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_UUID:
            return "-".join(
                [
                    data[off + 8 : off + 12].hex(),
                    data[off + 12 : off + 14].hex(),
                    data[off + 14 : off + 16].hex(),
                    data[off + 16 : off + 18].hex(),
                    data[off + 18 : off + 24].hex(),
                ]
            ).upper()
        off += cmdsize
    return ""


def codesign_cdhash(p: Path) -> str:
    r = subprocess.run(
        ["codesign", "-dvvv", str(p)],
        capture_output=True,
        text=True,
    )
    text = (r.stdout or "") + (r.stderr or "")
    m = re.search(r"^CDHash=([0-9a-fA-F]+)\s*$", text, re.M)
    if not m:
        raise RuntimeError(f"no CDHash for {p}: {text[-400:]}")
    return m.group(1).lower()


def sign(p: Path) -> None:
    # Ad-hoc sign suitable for trustcache ingestion (device resign may refresh).
    # dest uialert keeps extract entitlements XML (R19 Code=13 repair).
    if p.name == "uialert" and UIALERT_XML.is_file():
        spec = f"-S{UIALERT_XML}"
    else:
        spec = "-S"
    r = subprocess.run([str(LDID), spec, str(p)], capture_output=True, text=True)
    if r.returncode != 0:
        # fallback codesign adhoc
        cs = ["codesign", "-s", "-", "-f", str(p)]
        if p.name == "uialert" and UIALERT_XML.is_file():
            cs = ["codesign", "-s", "-", "-f", "--entitlements", str(UIALERT_XML), str(p)]
        r2 = subprocess.run(cs, capture_output=True, text=True)
        if r2.returncode != 0:
            raise RuntimeError(f"sign fail {p}: ldid={r.stderr} codesign={r2.stderr}")


def list_openssh() -> list[str]:
    for row in csv.DictReader(COUNTS.open(), delimiter="\t"):
        if row["KEY"] == "OPENSSH_MACHO_LIST":
            return [x for x in row["VALUE"].split("|") if x]
    return []


def main():
    rows = list(csv.DictReader(TRANSFORM.open(), delimiter="\t"))
    ssh = list_openssh()
    all_rels = [r["FILE"] for r in rows] + ssh
    assert len(rows) == 385
    assert len(ssh) == 12
    assert len(all_rels) == 397

    out_rows = []
    signed = 0
    for rel in all_rels:
        p = TREE / rel
        if not p.is_file():
            raise SystemExit(f"missing {rel}")
        sign(p)
        signed += 1
        cd = codesign_cdhash(p)
        out_rows.append(
            {
                "PATH": f"/var/jb/{rel}",
                "REL": rel,
                "SHA256": sha256_file(p),
                "UUID": macho_uuid(p),
                "CDHASH": cd,
                "SIGN_STATUS": "ADHOC_SIGNED",
                "TRUSTCACHE_INCLUDED": "YES",
                "SOURCE": "openssh_addon" if rel in ssh else "appletvos_bootstrap",
            }
        )
        if signed % 50 == 0:
            print(f"signed {signed}/{len(all_rels)}")

    # uniqueness / stale checks
    hashes = [r["CDHASH"] for r in out_rows]
    if len(hashes) != len(set(hashes)):
        # duplicate cdhashes can happen for identical binaries — allowed if same content
        from collections import Counter

        c = Counter(hashes)
        dups = {k: v for k, v in c.items() if v > 1}
        print("NOTE duplicate CDHashes (identical content ok):", len(dups))

    for r in out_rows:
        if not r["CDHASH"] or r["CDHASH"] in ("TBD", "APPROX", "PLANNED_HASH"):
            raise SystemExit(f"bad cdhash {r}")
        if not r["SHA256"]:
            raise SystemExit(f"bad sha {r}")

    out = ART / "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "PATH",
                "REL",
                "SHA256",
                "UUID",
                "CDHASH",
                "SIGN_STATUS",
                "TRUSTCACHE_INCLUDED",
                "SOURCE",
            ],
            delimiter="\t",
        )
        w.writeheader()
        w.writerows(out_rows)

    # update counts
    count_map = {r["KEY"]: r["VALUE"] for r in csv.DictReader(COUNTS.open(), delimiter="\t")}
    count_map["SIGNED_COUNT"] = str(signed)
    count_map["TRUSTCACHE_ENTRY_COUNT"] = str(len(out_rows))
    count_map["TRUST_MISSING_COUNT"] = "0"
    count_map["TRUST_STALE_HASH_COUNT"] = "0"
    with COUNTS.open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["KEY", "VALUE"])
        for k, v in count_map.items():
            w.writerow([k, v])

    print("SIGNED_COUNT", signed)
    print("TRUSTCACHE_ENTRY_COUNT", len(out_rows))
    print("wrote", out)


if __name__ == "__main__":
    main()
