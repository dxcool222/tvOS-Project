#!/usr/bin/env python3
"""Install V26-contract bootstrap members from pinned tar extractions only."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace import work_dir  # noqa: E402

SRC = work_dir("appletvos_extract")
ORACLE = work_dir("oracle_jb")
OUT_TREE = work_dir("jbroot_transformed")

ACCOUNT_DB_FILES = (
    "etc/passwd",
    "etc/group",
    "etc/master.passwd",
)

EXTRAINST_REL = "Library/dpkg/info/openssh-server.extrainst_"
PROCURUS_SSL_ROOT = "private/etc/ssl"
JBROOT_SSL_ROOT = "etc/ssl"


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def copy_verified(src: Path, dst: Path, *, expected_sha: str | None = None) -> str:
    if not src.is_file():
        raise SystemExit(f"missing source file {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    got = sha256_file(dst)
    if sha256_file(src) != got:
        raise SystemExit(f"copy verify failed {src} -> {dst}")
    if expected_sha and got != expected_sha:
        raise SystemExit(f"sha256 mismatch {dst}: got={got} expected={expected_sha}")
    return got


def install_account_database() -> dict[str, str]:
    """Copy passwd/group/master.passwd from oracle rootless SSH extraction."""
    shas: dict[str, str] = {}
    for rel in ACCOUNT_DB_FILES:
        src = ORACLE / rel
        dst = OUT_TREE / rel
        shas[rel] = copy_verified(src, dst)
    return shas


def install_ssl_tree() -> dict[str, str]:
    """Copy SSL CA tree from Procursus base extraction (private/etc/ssl -> etc/ssl)."""
    src_root = SRC / PROCURUS_SSL_ROOT
    dst_root = OUT_TREE / JBROOT_SSL_ROOT
    if not src_root.is_dir():
        raise SystemExit(f"missing Procursus SSL tree {src_root}")

    cert_src = src_root / "cert.pem"
    cacert_src = src_root / "certs" / "cacert.pem"
    if not cert_src.is_symlink():
        raise SystemExit(f"expected symlink {cert_src}")
    if os.readlink(cert_src) != "certs/cacert.pem":
        raise SystemExit(f"unexpected cert.pem target: {os.readlink(cert_src)}")
    if not cacert_src.is_file():
        raise SystemExit(f"missing {cacert_src}")

    dst_root.mkdir(parents=True, exist_ok=True)
    (dst_root / "certs").mkdir(parents=True, exist_ok=True)

    cert_dst = dst_root / "cert.pem"
    cacert_dst = dst_root / "certs" / "cacert.pem"
    if cert_dst.exists() or cert_dst.is_symlink():
        cert_dst.unlink()
    cert_dst.symlink_to("certs/cacert.pem")

    cacert_sha = copy_verified(cacert_src, cacert_dst)

    resolved = (cert_dst.parent / os.readlink(cert_dst)).resolve()
    if resolved != cacert_dst.resolve():
        raise SystemExit(f"cert.pem does not resolve to cacert.pem: {resolved}")

    return {
        "etc/ssl/cert.pem": "symlink:certs/cacert.pem",
        "etc/ssl/certs/cacert.pem": cacert_sha,
    }


def install_openssh_extrainst() -> str:
    """Copy extrainst_ from oracle; rewrite interpreter to /var/jb/bin/sh."""
    src = ORACLE / EXTRAINST_REL
    dst = OUT_TREE / EXTRAINST_REL
    if not src.is_file():
        raise SystemExit(f"missing oracle {EXTRAINST_REL}")

    text = src.read_text()
    lines = text.splitlines(keepends=True)
    if not lines:
        raise SystemExit("empty extrainst_")
    first = lines[0].rstrip("\n")
    if first == "#!/bin/sh":
        lines[0] = "#!/var/jb/bin/sh\n"
    elif first != "#!/var/jb/bin/sh":
        raise SystemExit(f"unexpected extrainst shebang: {first!r}")

    body = "".join(lines)
    if "launchctl load -w /var/jb/Library/LaunchDaemons/com.openssh.sshd.plist" not in body:
        raise SystemExit("extrainst missing sshd launchctl load")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(body if body.endswith("\n") else body + "\n")
    os.chmod(dst, 0o755)
    if not os.access(dst, os.X_OK):
        raise SystemExit(f"extrainst not executable: {dst}")
    return sha256_file(dst)


def verify_dangling_ssl_symlinks() -> None:
    for rel in ("usr/lib/ssl/cacert.pem", "usr/lib/ssl/certs"):
        p = OUT_TREE / rel
        if not p.is_symlink():
            continue
        target = os.readlink(p)
        if not target.startswith("/var/jb/"):
            continue
        jb_rel = target[len("/var/jb/") :]
        if not (OUT_TREE / jb_rel).exists():
            raise SystemExit(f"dangling jbroot symlink {rel} -> {target}")


def main() -> int:
    if not OUT_TREE.is_dir():
        raise SystemExit(f"missing output tree {OUT_TREE}")
    if not SRC.is_dir() or not ORACLE.is_dir():
        raise SystemExit("missing appletvos_extract or oracle_jb")

    account = install_account_database()
    ssl = install_ssl_tree()
    extrainst_sha = install_openssh_extrainst()
    verify_dangling_ssl_symlinks()

    print("BOOTSTRAP_ENRICHMENT=PASS")
    for rel, sha in account.items():
        oracle_sha = sha256_file(ORACLE / rel)
        if sha != oracle_sha:
            raise SystemExit(f"account file oracle/payload mismatch {rel}")
        print(f"  ACCOUNT {rel} sha256={sha}")
    print(f"  SSL etc/ssl/certs/cacert.pem sha256={ssl['etc/ssl/certs/cacert.pem']}")
    print(f"  SSL etc/ssl/cert.pem={ssl['etc/ssl/cert.pem']}")
    print(f"  EXTRAINST {EXTRAINST_REL} sha256={extrainst_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
