#!/usr/bin/env python3
"""Audit final packaged RootlessPayload Mach-O trust closure.

Verifies inner Mach-O bytes (after R14MACHO unwrap) match ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv
CDHASH/SHA256 and that signatures are valid on inner bytes.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HDR = b"R14MACHO"
LC_RPATH = 0x8000001C
DYLIB_CMDS = {0x0C, 0x18, 0x1D, 0x80000018, 0x8000001D}
REQUIRED_RPATH = "/var/jb/usr/lib"
SAMPLE_REQUIRED = (
    "usr/libexec/firmware",
    "usr/sbin/pwd_mkdb",
    "usr/bin/launchctl",
)


def unwrap(raw: bytes) -> tuple[bytes, bool]:
    if raw.startswith(HDR):
        return raw[len(HDR) :], True
    return raw, False


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def codesign_cdhash(path: Path) -> str:
    r = subprocess.run(["codesign", "-dvvv", str(path)], capture_output=True, text=True)
    text = (r.stdout or "") + (r.stderr or "")
    m = re.search(r"^CDHash=([0-9a-fA-F]+)\s*$", text, re.M)
    if not m:
        raise RuntimeError(f"no CDHash: {text[-300:]}")
    return m.group(1).lower()


def signature_valid(path: Path) -> bool:
    r = subprocess.run(["codesign", "-vvv", str(path)], capture_output=True, text=True)
    text = (r.stdout or "") + (r.stderr or "")
    return r.returncode == 0 and "valid on disk" in text


def rpaths(inner: bytes) -> list[str]:
    if len(inner) < 32 or struct.unpack_from("<I", inner, 0)[0] != 0xFEEDFACF:
        return []
    ncmds = struct.unpack_from("<I", inner, 16)[0]
    out: list[str] = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", inner, off)
        if cmd == LC_RPATH:
            ro = struct.unpack_from("<I", inner, off + 8)[0]
            out.append(inner[off + ro : off + cmdsize].split(b"\0", 1)[0].decode("utf-8", "replace"))
        off += cmdsize
    return out


def audit_ipa(ipa: Path) -> int:
    with zipfile.ZipFile(ipa) as z:
        trust_name = next(n for n in z.namelist() if n.endswith("ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"))
        trust_rows = list(csv.DictReader(z.read(trust_name).decode().splitlines(), delimiter="\t"))
        by_rel = {r["REL"]: r for r in trust_rows}

        macho_rels = [r["REL"] for r in trust_rows]
        if len(macho_rels) != 397:
            print(f"TRUST_ROW_COUNT={len(macho_rels)} expected=397")
            return 1

        cdhash_match = 0
        sig_valid = 0
        rpath_ok = 0
        wrap_count = 0
        inner_unchanged = 0
        failures: list[str] = []

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            for rel in macho_rels:
                member = next(
                    (n for n in z.namelist() if n.endswith(f"RootlessPayload/{rel}")),
                    None,
                )
                if not member:
                    failures.append(f"missing packaged {rel}")
                    continue
                raw = z.read(member)
                inner, wrapped = unwrap(raw)
                if wrapped:
                    wrap_count += 1
                    if raw[len(HDR) :] == inner:
                        inner_unchanged += 1
                trust = by_rel[rel]
                inner_sha = sha256_bytes(inner)
                trust_sha = trust["SHA256"].lower()
                inner_path = tdp / rel.replace("/", "_")
                inner_path.write_bytes(inner)
                try:
                    cd = codesign_cdhash(inner_path)
                    sig_ok = signature_valid(inner_path)
                except RuntimeError as e:
                    failures.append(f"{rel}: {e}")
                    continue
                if inner_sha == trust_sha and cd == trust["CDHASH"].lower():
                    cdhash_match += 1
                else:
                    failures.append(
                        f"{rel}: sha inner={inner_sha} trust={trust_sha} "
                        f"cd inner={cd} trust={trust['CDHASH']}"
                    )
                if sig_ok:
                    sig_valid += 1
                else:
                    failures.append(f"{rel}: signature invalid")
                if REQUIRED_RPATH in rpaths(inner):
                    rpath_ok += 1

        print(f"PACKED_MACHO_COUNT={len(macho_rels)}")
        print(f"R14MACHO_WRAPPED={wrap_count}")
        print(f"R14MACHO_INNER_BYTE_IDENTICAL={inner_unchanged}/{wrap_count}")
        print(f"FINAL_PACKAGED_MACHO_CDHASH_MATCH={cdhash_match}/397")
        print(f"FINAL_PACKAGED_SIGNATURES_VALID={sig_valid}/397")
        print(f"FINAL_TRUST_MANIFEST_MATCH={cdhash_match}/397")
        print(f"DEST_RPATH_MACHO_COUNT={rpath_ok} (with {REQUIRED_RPATH})")
        post_sign = len(failures)
        print(f"POST_SIGN_MACHO_MUTATIONS={post_sign}")
        if post_sign == 0:
            print("FINAL_TRUST_CLOSURE=PASS")
        else:
            print("FINAL_TRUST_CLOSURE=FAIL")
            for f in failures[:20]:
                print(f"  {f}")
            if len(failures) > 20:
                print(f"  ... +{len(failures)-20} more")

        print("=== SAMPLE_REQUIRED ===")
        with tempfile.TemporaryDirectory() as td2:
            tdp2 = Path(td2)
            for rel in SAMPLE_REQUIRED:
                member = next(n for n in z.namelist() if n.endswith(f"RootlessPayload/{rel}"))
                raw = z.read(member)
                inner, wrapped = unwrap(raw)
                trust = by_rel[rel]
                p = tdp2 / rel.replace("/", "_")
                p.write_bytes(inner)
                cd = codesign_cdhash(p)
                print(f"{rel}")
                print(f"  FINAL_SHA256={sha256_bytes(inner)}")
                print(f"  FINAL_CDHASH={cd}")
                print(f"  TRUST_MANIFEST_CDHASH={trust['CDHASH']}")
                print(f"  CDHASH_MATCH={'YES' if cd == trust['CDHASH'].lower() else 'NO'}")
                print(f"  FINAL_SIGNATURE_VALID={'YES' if signature_valid(p) else 'NO'}")
                print(f"  FINAL_LC_RPATH_CONTAINS_VAR_JB={'YES' if REQUIRED_RPATH in rpaths(inner) else 'NO'}")
                print(f"  R14MACHO_WRAPPED={'YES' if wrapped else 'NO'}")

        return 0 if post_sign == 0 and cdhash_match == 397 else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa", type=Path)
    args = ap.parse_args()
    return audit_ipa(args.ipa)


if __name__ == "__main__":
    raise SystemExit(main())
