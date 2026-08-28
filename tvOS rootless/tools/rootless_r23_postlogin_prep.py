#!/usr/bin/env python3
"""R23: prepare jbroot_transformed for post-login SSH (homes / zsh / setuid).

USB-only. Mutates work/jbroot_transformed + patches trust for zsh only.
Does not touch frozen R21/R22 IPAs. Does not re-run macho_transform.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
sys.path.insert(0, str(ROOT / "tools"))
from rootless_add_dest_libiosexec_rpath import codesign_cdhash, patch_trust, sign  # noqa: E402

ORACLE = work_dir("oracle_jb")
DEFAULT_TREE = work_dir("jbroot_transformed")
DEFAULT_TRUST = artifacts_dir() / "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"

ZSH_REL = "usr/bin/zsh"
ORACLE_ZSH_SHA256 = "4655a40512da9fb2e2787d441d5d4c942a413555c2f032b1c5ca1139bc225c46"

SETUID_RELS = (
    "usr/bin/chpass",
    "usr/bin/newgrp",
    "usr/bin/su",
    "usr/bin/quota",
    "usr/bin/sudo",
    "usr/bin/login",
    "usr/bin/passwd",
    "usr/sbin/shshd",
)

HOME_DIRS = (
    "var/mobile",
    "var/root",
    "var/mobile/Library",
    "var/mobile/Library/Preferences",
)

def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ensure_homes(tree: Path) -> None:
    for rel in HOME_DIRS:
        d = tree / rel
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)


def apply_setuid(tree: Path) -> None:
    for rel in SETUID_RELS:
        p = tree / rel
        if not p.is_file() or p.is_symlink():
            raise SystemExit(f"setuid target missing or symlink: {rel}")
        os.chmod(p, 0o4755)
        st = p.lstat()
        if not (st.st_mode & stat.S_ISUID):
            raise SystemExit(f"chmod 4755 failed to set S_ISUID on {rel}: {oct(st.st_mode)}")


def swap_zsh(tree: Path, oracle: Path, trust: Path) -> None:
    src = oracle / ZSH_REL
    dst = tree / ZSH_REL
    if not src.is_file():
        raise SystemExit(f"missing oracle {ZSH_REL}")
    if sha256_file(src) != ORACLE_ZSH_SHA256:
        raise SystemExit(f"oracle zsh sha mismatch: {sha256_file(src)}")
    strings = subprocess.check_output(["strings", str(src)], text=True, errors="replace")
    if "/var/jb/usr/lib/zsh/5.9" not in strings:
        raise SystemExit("oracle zsh missing /var/jb/usr/lib/zsh/5.9")
    if "/var/jb/usr/share/zsh/functions" not in strings:
        raise SystemExit("oracle zsh missing /var/jb/usr/share/zsh/functions")
    loads = subprocess.check_output(["otool", "-L", str(src)], text=True)
    for line in loads.splitlines()[1:]:
        name = line.strip().split()[0] if line.strip() else ""
        if name.startswith("/usr/lib/") and "libSystem" not in name and "libiconv" not in name:
            raise SystemExit(f"unexpected absolute /usr/lib load on oracle zsh: {name}")
    dst.write_bytes(src.read_bytes())
    if sha256_file(dst) != ORACLE_ZSH_SHA256:
        raise SystemExit("zsh copy verify fail")
    sign(dst)
    patch_trust(trust, {ZSH_REL: (sha256_file(dst), codesign_cdhash(dst))})


def verify_prep(tree: Path) -> None:
    prep = tree / "prep_bootstrap.sh"
    text = prep.read_text()
    if "R23: ensure SSH homes exist" not in text:
        raise SystemExit("prep_bootstrap.sh missing R23 home block (generator contract)")
    needle = "/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if lines[-1] != needle:
        raise SystemExit("prep last executed line must be dest-abs rm")


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

    if args.verify_only:
        for rel in HOME_DIRS:
            if not (tree / rel).is_dir():
                raise SystemExit(f"missing home dir {rel}")
        zsh = tree / ZSH_REL
        if "/var/jb/usr/lib/zsh/5.9" not in subprocess.check_output(
            ["strings", str(zsh)], text=True, errors="replace"
        ):
            raise SystemExit("packed zsh missing rootless module_path")
        for rel in SETUID_RELS:
            st = (tree / rel).lstat()
            if not (st.st_mode & stat.S_ISUID):
                raise SystemExit(f"missing setuid on {rel}")
        prep = (tree / "prep_bootstrap.sh").read_text()
        if "R23: ensure SSH homes exist" not in prep:
            raise SystemExit("prep missing R23 home ensure block")
        print("R23_POSTLOGIN_PREP_VERIFY_OK")
        return 0

    if not trust.is_file():
        print("trust missing", file=sys.stderr)
        return 1

    ensure_homes(tree)
    swap_zsh(tree, oracle, trust)
    apply_setuid(tree)
    verify_prep(tree)
    print("R23_POSTLOGIN_PREP_OK")
    print(f"  homes={len(HOME_DIRS)} zsh={ZSH_REL} setuid={len(SETUID_RELS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
