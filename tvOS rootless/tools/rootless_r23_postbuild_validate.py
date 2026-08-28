#!/usr/bin/env python3
"""Post-build static validation for ROOTLESS-R23 post-login IPA."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import csv
import hashlib
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
R21_IPA = ROOT / "artifacts/dopamin-tvOS-kfd-ROOTLESS-R21.ipa"
R22_IPA = ROOT / "artifacts/dopamin-tvOS-kfd-ROOTLESS-R22.ipa"
R21_IPA_SHA = "5099371a1f2afe0fdb51eccd2edca08bbd931614352697e6bcc53d8c155f17f0"
R22_IPA_SHA = "838f3d095a3c5b3df07e69220225282e4e71823dfaea8513d8e10dcd096eb6cf"
R21_HOOK_SHA = "5223b886123a4adf4b3a8b594d47f047cb9204c4d4e7c34e4b2c9be14b21f040"

HOME_RELS = (
    "var/mobile",
    "var/root",
    "var/mobile/Library",
    "var/mobile/Library/Preferences",
)
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
ORACLE_RELS = (
    "usr/lib/libiosexec.1.dylib",
    "usr/lib/libpam.2.dylib",
    "usr/lib/pam/pam_unix.so",
    "usr/lib/pam/pam_nologin.so",
    "usr/lib/pam/pam_permit.so",
)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def unwrap(b: bytes) -> bytes:
    return b[8:] if b.startswith(b"R14MACHO") else b


def find_member(z: zipfile.ZipFile, suffix: str) -> str | None:
    for n in z.namelist():
        if n.endswith(suffix):
            return n
    return None


def strings_has(raw: bytes, needle: str) -> bool:
    return needle.encode() in raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("r23_ipa", type=Path)
    args = ap.parse_args()
    ipa = args.r23_ipa
    if not ipa.is_file():
        print("IPA missing", file=sys.stderr)
        return 1

    fails: list[str] = []
    r23_sha = sha256_file(ipa)
    if R21_IPA.is_file() and sha256_file(R21_IPA) != R21_IPA_SHA:
        fails.append("R21_IPA_SHA_DRIFT")
    if R22_IPA.is_file() and sha256_file(R22_IPA) != R22_IPA_SHA:
        fails.append("R22_IPA_SHA_DRIFT")
    if r23_sha in (R21_IPA_SHA, R22_IPA_SHA):
        fails.append("R23_IPA_COLLIDES_FROZEN")

    with zipfile.ZipFile(ipa) as z:
        path_m = find_member(z, "ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv")
        trust_m = find_member(z, "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv")
        prep_m = find_member(z, "RootlessPayload/prep_bootstrap.sh")
        hook_m = find_member(z, "Handoff516/launchdhook516.dylib")
        zsh_m = find_member(z, "RootlessPayload/usr/bin/zsh")
        if not all([path_m, trust_m, prep_m, hook_m, zsh_m]):
            fails.append("MISSING_CORE_MEMBERS")
            print(f"R23_BUILD_RESULT=FAIL")
            print("FAILS=" + ",".join(fails))
            return 1

        path_rows = list(csv.DictReader(z.read(path_m).decode().splitlines(), delimiter="\t"))
        if len(path_rows) != 4053:
            fails.append(f"PAYLOAD_ENTRY_COUNT={len(path_rows)}")
        modes = {r["RELATIVE_PATH"]: r["MODE_OCT"] for r in path_rows}
        for rel in HOME_RELS:
            if modes.get(rel) is None:
                # directories are CREATE_DIRECTORY rows
                row = next((r for r in path_rows if r["RELATIVE_PATH"] == rel), None)
                if not row or row["DISPOSITION"] != "CREATE_DIRECTORY":
                    fails.append(f"HOME_MISSING_{rel}")
        for rel in SETUID_RELS:
            if modes.get(rel) != "0o4755":
                fails.append(f"SETUID_MODE_{rel}={modes.get(rel)}")

        prep = z.read(prep_m).decode(errors="replace")
        if "R23: ensure SSH homes exist" not in prep:
            fails.append("PREP_HOMES_BLOCK")
        if not prep.strip().endswith("/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh") and \
           "/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh" not in [
               ln.strip() for ln in prep.splitlines() if ln.strip() and not ln.strip().startswith("#")
           ][-1:]:
            lines = [ln.strip() for ln in prep.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            if not lines or lines[-1] != "/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh":
                fails.append("PREP_ABS_RM_LAST")

        zsh = unwrap(z.read(zsh_m))
        if not strings_has(zsh, "/var/jb/usr/lib/zsh/5.9"):
            fails.append("ZSH_MODULE_PATH")
        if not strings_has(zsh, "/var/jb/usr/share/zsh/functions"):
            fails.append("ZSH_FPATH")

        trust_rows = {r["REL"]: r for r in csv.DictReader(z.read(trust_m).decode().splitlines(), delimiter="\t")}
        if len(trust_rows) != 397:
            fails.append(f"TRUST_COUNT={len(trust_rows)}")
        zsh_trust = trust_rows.get("usr/bin/zsh")
        if not zsh_trust or zsh_trust["SHA256"] != sha256_bytes(zsh):
            fails.append("ZSH_TRUST_STALE")

        for rel in ORACLE_RELS:
            m = find_member(z, f"RootlessPayload/{rel}")
            raw = unwrap(z.read(m))
            if rel == "usr/lib/libiosexec.1.dylib" and not strings_has(raw, "/var/jb/etc/pwd.db"):
                fails.append("ORACLE_LIBIOSEXEC")
            if rel == "usr/lib/libpam.2.dylib" and not strings_has(raw, "/var/jb/etc/pam.d/"):
                fails.append("ORACLE_LIBPAM")
            if rel == "usr/lib/pam/pam_unix.so" and not strings_has(raw, "/var/jb/etc/master.passwd"):
                fails.append("ORACLE_PAM_UNIX")
            if trust_rows[rel]["SHA256"] != sha256_bytes(raw):
                fails.append(f"ORACLE_TRUST_STALE_{rel}")

        hook_eq = sha256_bytes(z.read(hook_m)) == R21_HOOK_SHA

    tree_ops = (ROOT / "source/dt_rootless_tree_ops.c").read_text()
    if "(v & 07777)" not in tree_ops or tree_ops.count("mode & 07777") < 2:
        fails.append("TREE_OPS_MASK")

    pass_ok = not fails
    print(f"R23_BUILD_RESULT={'PASS' if pass_ok else 'FAIL'}")
    print(f"R23_IPA_PATH={ipa}")
    print(f"R23_IPA_SHA256={r23_sha}")
    print(f"PAYLOAD_ENTRY_COUNT={len(path_rows)}")
    print(f"HOOK_BYTE_EQUAL_R21={'YES' if hook_eq else 'NO'}")
    print(f"R23_HOME_DIRS={'PASS' if not any(f.startswith('HOME_') for f in fails) else 'FAIL'}")
    print(f"R23_ZSH_ROOTLESS_PREFIX={'PASS' if 'ZSH_MODULE_PATH' not in fails and 'ZSH_FPATH' not in fails else 'FAIL'}")
    print(f"R23_SUDO_SETUID={'PASS' if not any(f.startswith('SETUID_') for f in fails) else 'FAIL'}")
    if fails:
        print("R23_FAILS=" + ",".join(fails))
    return 0 if pass_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
