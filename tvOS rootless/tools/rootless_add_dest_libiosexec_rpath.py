#!/usr/bin/env python3
"""Add dest LC_RPATH /var/jb/usr/lib where 11:05 dyld never searched.

R16 packed Mach-Os that load @rpath/libiosexec.1.dylib with LC_RPATH only
/usr/lib abort at dest (ASI UUID-matched firmware, pwd_mkdb, launchctl).
Dash on that same burn had /usr/lib plus /var/jb/usr/lib and ran as
/var/jb/bin/sh. This uses the existing append_rpath helper from
rootless_macho_transform.py. Re-sign only rewritten files (ldid), then
patch those rows in ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv so live CDHash
matches. Does not rewrite load commands. Does not touch files that already
have dest rpath.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import csv
import hashlib
import re
import subprocess
import sys
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
sys.path.insert(0, str(ROOT / "tools"))
from rootless_macho_transform import (  # noqa: E402
    DYLIB_CMDS,
    LC_RPATH,
    append_rpath,
    dylib_path,
    iter_lcs,
    parse_macho,
    rpath_path,
)

DEST_RPATH = "/var/jb/usr/lib"
HDR = b"R14MACHO"
LDID = ldid_path()
UIALERT_XML = ROOT / "bootstrap/entitlements/appletvos_extract_entitlements.xml"
REQUIRED = (
    "usr/libexec/firmware",
    "usr/sbin/pwd_mkdb",
    "usr/bin/launchctl",
)
WRAP_UNWRAP_FAIL = "wrapped macho at this stage is not supported"


def unwrap_macho(raw: bytes) -> bytes:
    if raw.startswith(HDR):
        return raw[8:]
    return raw


def inner_bytes(raw: bytes) -> bytes:
    if raw.startswith(HDR):
        raise SystemExit(WRAP_UNWRAP_FAIL)
    return raw


def loads_and_rpaths(data: bytearray) -> tuple[list[str], list[str]]:
    swap, ncmds, _sizeofcmds = parse_macho(data)
    loads: list[str] = []
    rps: list[str] = []
    for _, off, cmd, cmdsize in iter_lcs(data, swap, ncmds):
        if cmd in DYLIB_CMDS:
            name, _ = dylib_path(data, off, cmdsize, swap)
            loads.append(name)
        elif cmd == LC_RPATH:
            rp, _ = rpath_path(data, off, cmdsize, swap)
            rps.append(rp)
    return loads, rps


def has_iosexec_rpath_load(loads: list[str]) -> bool:
    return any(name.endswith("libiosexec.1.dylib") or "libiosexec" in name for name in loads)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def sign(p: Path) -> None:
    # dest uialert must keep extract slot-5 XML (R19). Bare -S drops Code=13 key.
    if p.name == "uialert" and UIALERT_XML.is_file():
        spec = f"-S{UIALERT_XML}"
    else:
        spec = "-S"
    r = subprocess.run([str(LDID), spec, str(p)], capture_output=True, text=True)
    if r.returncode == 0:
        return
    cs = ["codesign", "-s", "-", "-f", str(p)]
    if p.name == "uialert" and UIALERT_XML.is_file():
        cs = ["codesign", "-s", "-", "-f", "--entitlements", str(UIALERT_XML), str(p)]
    r2 = subprocess.run(cs, capture_output=True, text=True)
    if r2.returncode != 0:
        raise SystemExit(f"sign fail {p}: ldid={r.stderr} codesign={r2.stderr}")


def codesign_cdhash(p: Path) -> str:
    r = subprocess.run(
        ["codesign", "-dvvv", str(p)],
        capture_output=True,
        text=True,
    )
    text = (r.stdout or "") + (r.stderr or "")
    m = re.search(r"^CDHash=([0-9a-fA-F]+)\s*$", text, re.M)
    if not m:
        raise SystemExit(f"no CDHash for {p}: {text[-400:]}")
    return m.group(1).lower()


def verify_required(tree: Path) -> None:
    missing = []
    for rel in REQUIRED:
        p = tree / rel
        if not p.is_file():
            missing.append(f"{rel} missing")
            continue
        data = bytearray(unwrap_macho(p.read_bytes()))
        loads, rps = loads_and_rpaths(data)
        if not has_iosexec_rpath_load(loads):
            missing.append(f"{rel} has no libiosexec load {loads}")
        if DEST_RPATH not in rps:
            missing.append(f"{rel} rpaths={rps}")
    if missing:
        raise SystemExit("REQUIRED_DEST_RPATH_FAIL " + " | ".join(missing))


def patch_trust(tsv: Path, updates: dict[str, tuple[str, str]]) -> None:
    rows = list(csv.DictReader(tsv.open(), delimiter="\t"))
    fieldnames = list(csv.DictReader(tsv.open(), delimiter="\t").fieldnames or [])
    if "REL" not in fieldnames or "CDHASH" not in fieldnames or "SHA256" not in fieldnames:
        raise SystemExit(f"bad trust tsv columns {fieldnames}")
    seen = {r["REL"] for r in rows}
    for rel in updates:
        if rel not in seen:
            raise SystemExit(f"trust TSV missing REL {rel}")
    out = []
    for r in rows:
        if r["REL"] in updates:
            sha, cd = updates[r["REL"]]
            r = dict(r)
            r["SHA256"] = sha
            r["CDHASH"] = cd
            r["SIGN_STATUS"] = "ADHOC_SIGNED"
        out.append(r)
    if len(out) != 397:
        raise SystemExit(f"trust row count {len(out)} != 397")
    with tsv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
        w.writeheader()
        w.writerows(out)


def apply_dest_rpath_patches(tree: Path, *, sign_after: bool) -> list[str]:
    patched: list[str] = []
    for p in sorted(tree.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        raw = p.read_bytes()
        if raw[:4] != b"\xcf\xfa\xed\xfe":
            continue
        data = bytearray(inner_bytes(raw))
        loads, rps = loads_and_rpaths(data)
        if not has_iosexec_rpath_load(loads):
            continue
        if DEST_RPATH in rps:
            continue
        swap, ncmds, sizeofcmds = parse_macho(data)
        try:
            ncmds, sizeofcmds = append_rpath(data, swap, ncmds, sizeofcmds, DEST_RPATH)
        except RuntimeError as e:
            raise SystemExit(f"append_rpath fail {p.relative_to(tree)}: {e}") from e
        p.write_bytes(data)
        if sign_after:
            sign(p)
        patched.append(str(p.relative_to(tree)))
    return patched


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--trust")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument(
        "--patch-only",
        action="store_true",
        help="append dest LC_RPATH only; signing/trust happen later in bootstrap pipeline",
    )
    args = ap.parse_args()
    tree = Path(args.tree)
    if not tree.is_dir():
        print("tree missing", file=sys.stderr)
        return 1
    if args.verify_only:
        verify_required(tree)
        print("DEST_RPATH_REQUIRED_OK firmware pwd_mkdb launchctl")
        return 0
    if args.patch_only:
        patched = apply_dest_rpath_patches(tree, sign_after=False)
        verify_required(tree)
        print(f"DEST_RPATH_PATCHED={len(patched)}")
        for rel in patched:
            print(f"  {rel}")
        if not patched:
            print("DEST_RPATH_ALREADY_PRESENT")
        return 0

    trust = Path(args.trust) if args.trust else None
    if trust is None or not trust.is_file():
        print("tree/trust missing (required unless --patch-only or --verify-only)", file=sys.stderr)
        return 1

    patched = apply_dest_rpath_patches(tree, sign_after=True)

    updates = {}
    for rel in patched:
        p = tree / rel
        updates[rel] = (sha256_file(p), codesign_cdhash(p))
    if updates:
        patch_trust(trust, updates)
    verify_required(tree)
    print(f"DEST_RPATH_ADDED={len(patched)}")
    for rel in patched:
        print(f"  {rel}")
    if not patched:
        print("DEST_RPATH_ALREADY_PRESENT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
