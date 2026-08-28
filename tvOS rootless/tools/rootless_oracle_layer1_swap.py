#!/usr/bin/env python3
"""R22-A: swap five oracle rootless Mach-Os into jbroot_transformed.

Copies from work/oracle_jb/, partial ldid sign, patches exactly five trust rows.
Does not run rootless_macho_transform.py. Does not touch other Mach-Os.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
sys.path.insert(0, str(ROOT / "tools"))
from rootless_add_dest_libiosexec_rpath import (  # noqa: E402
    codesign_cdhash,
    patch_trust,
    sign,
)

ORACLE = work_dir("oracle_jb")
DEFAULT_TREE = work_dir("jbroot_transformed")
DEFAULT_TRUST = artifacts_dir() / "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"

RELS = (
    "usr/lib/libiosexec.1.dylib",
    "usr/lib/libpam.2.dylib",
    "usr/lib/pam/pam_unix.so",
    "usr/lib/pam/pam_nologin.so",
    "usr/lib/pam/pam_permit.so",
)

ORACLE_SHA256 = {
    "usr/lib/libiosexec.1.dylib": "aa2354332ee53c96990887a190b20f8cd56c02f464bf878b8a79ccef72f88718",
    "usr/lib/libpam.2.dylib": "34fa66906759c8d30559dec70e28c52bef98f5b485600c556a750090bcaccbb0",
    "usr/lib/pam/pam_unix.so": "53e3f8fb3728559f0ee98d4461b2be629e6e0ec8df8807c8baaf6e2262009b24",
    "usr/lib/pam/pam_nologin.so": "388f8a358343d8fca3885b519b1801e0bef63ad99b55b95d8f0435e861172265",
    "usr/lib/pam/pam_permit.so": "6d807058d0b03b718956937d73c24703bbfe33033b69e616cd81c0571f9467e6",
}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def first_insn_ie_getpwnam(p: Path) -> str:
    out = subprocess.check_output(["otool", "-tV", str(p)], text=True)
    capture = False
    for line in out.splitlines():
        if line.startswith("_ie_getpwnam:"):
            capture = True
            continue
        if capture:
            if line.startswith("_"):
                break
            if line.strip():
                return line.strip()
    return ""


def verify_oracle_donor(rel: str, src: Path) -> None:
    if sha256_file(src) != ORACLE_SHA256[rel]:
        raise SystemExit(f"oracle donor sha mismatch {rel}: {src}")
    if rel == "usr/lib/libiosexec.1.dylib":
        insn = first_insn_ie_getpwnam(src)
        if "_getpwnam" in insn and "sub" not in insn.split()[1 if insn.split() else 0]:
            raise SystemExit(f"oracle libiosexec still stub: {insn}")
        strings = subprocess.check_output(["strings", str(src)], text=True, errors="replace")
        if "/var/jb/etc/pwd.db" not in strings:
            raise SystemExit("oracle libiosexec missing /var/jb/etc/pwd.db")
    if rel == "usr/lib/libpam.2.dylib":
        strings = subprocess.check_output(["strings", str(src)], text=True, errors="replace")
        if "/var/jb/etc/pam.d/" not in strings:
            raise SystemExit("oracle libpam missing /var/jb/etc/pam.d/")
    if rel == "usr/lib/pam/pam_unix.so":
        strings = subprocess.check_output(["strings", str(src)], text=True, errors="replace")
        if "/var/jb/etc/master.passwd" not in strings:
            raise SystemExit("oracle pam_unix missing /var/jb/etc/master.passwd")


def verify_no_transform_needed(p: Path) -> None:
    out = subprocess.check_output(["otool", "-L", str(p)], text=True)
    for line in out.splitlines()[1:]:
        name = line.strip().split()[0] if line.strip() else ""
        if name.startswith("/usr/lib/") and "libSystem" not in name:
            raise SystemExit(f"absolute /usr/lib load in oracle donor {p}: {name}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tree", nargs="?", default=str(DEFAULT_TREE))
    ap.add_argument("--trust", default=str(DEFAULT_TRUST))
    ap.add_argument("--oracle", default=str(ORACLE))
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()

    tree = Path(args.tree)
    trust = Path(args.trust)
    oracle = Path(args.oracle)
    if not tree.is_dir() or not oracle.is_dir():
        print("tree/oracle missing", file=sys.stderr)
        return 1
    if not args.verify_only and not trust.is_file():
        print("trust missing", file=sys.stderr)
        return 1

    swapped: list[str] = []
    for rel in RELS:
        src = oracle / rel
        dst = tree / rel
        if not src.is_file():
            raise SystemExit(f"missing oracle {rel}")
        verify_oracle_donor(rel, src)
        verify_no_transform_needed(src)
        if args.verify_only:
            if not dst.is_file():
                raise SystemExit(f"missing packed {rel}")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        if sha256_file(dst) != ORACLE_SHA256[rel]:
            raise SystemExit(f"copy verify fail {rel}")
        sign(dst)
        swapped.append(rel)

    if args.verify_only:
        print("R22_ORACLE_LAYER1_SWAP_VERIFY_OK files=5")
        return 0

    updates = {rel: (sha256_file(tree / rel), codesign_cdhash(tree / rel)) for rel in swapped}
    patch_trust(trust, updates)
    print(f"R22_ORACLE_LAYER1_SWAP_OK files={len(swapped)} trust_rows={len(updates)}")
    for rel in swapped:
        print(f"  {rel} sha={updates[rel][0][:16]}… cdhash={updates[rel][1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
