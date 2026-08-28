#!/usr/bin/env python3
"""Generate device-proven rootless prep_bootstrap.sh from pinned source contract.

Lineage: oracle rootless prep responsibilities + R18 (pw -V, no chsh, pwd_mkdb -d)
+ R20 (fail-closed extrainst) + R23 (SSH home dirs). Does not read frozen V26 trees.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace import work_dir  # noqa: E402

OUT_TREE = work_dir("jbroot_transformed")

# Deterministic generator output (R18/R20/R23 contract).
PREP_BOOTSTRAP = """\
#!/var/jb/bin/sh

/var/jb/usr/libexec/firmware
/var/jb/usr/sbin/pwd_mkdb -d /var/jb/etc -p /var/jb/etc/master.passwd >/dev/null 2>&1
/var/jb/Library/dpkg/info/debianutils.postinst configure 99999
/var/jb/Library/dpkg/info/apt.postinst configure 999999
/var/jb/Library/dpkg/info/dash.postinst configure 999999
/var/jb/Library/dpkg/info/zsh.postinst configure 999999
/var/jb/Library/dpkg/info/bash.postinst configure 999999
/var/jb/Library/dpkg/info/vi.postinst configure 999999

# OpenSSH service registration is load-bearing for Bring-Up (P16 replacement).
# Fail closed if extrainst is missing or launchctl load fails.
if [ ! -x /var/jb/Library/dpkg/info/openssh-server.extrainst_ ]; then
    echo "prep_bootstrap: openssh-server.extrainst_ missing or not executable" >&2
    exit 1
fi
/var/jb/Library/dpkg/info/openssh-server.extrainst_ install || {
    echo "prep_bootstrap: openssh-server.extrainst_ install failed" >&2
    exit 1
}

/var/jb/usr/sbin/pwd_mkdb -d /var/jb/etc -p /var/jb/etc/master.passwd

/var/jb/usr/sbin/pw -V /var/jb/etc usermod mobile -s /var/jb/usr/bin/zsh
/var/jb/usr/sbin/pw -V /var/jb/etc usermod root -s /var/jb/usr/bin/zsh

if [ -z "$NO_PASSWORD_PROMPT" ]; then
    PASSWORDS=""
    PASSWORD1=""
    PASSWORD2=""
    while [ -z "$PASSWORD1" ] || [ ! "$PASSWORD1" = "$PASSWORD2" ]; do
            PASSWORDS="$(/var/jb/usr/bin/uialert -b "In order to use command line tools like \\"sudo\\" after jailbreaking, you will need to set a terminal passcode. (This cannot be empty)" --secure "Password" --secure "Repeat Password" -p "Set" "Set Password")"
            PASSWORD1="$(printf "%s\\n" "$PASSWORDS" | /var/jb/usr/bin/sed -n '1 p')"
            PASSWORD2="$(printf "%s\\n" "$PASSWORDS" | /var/jb/usr/bin/sed -n '2 p')"
    done
    printf "%s\\n" "$PASSWORD1" | /var/jb/usr/sbin/pw -V /var/jb/etc usermod 501 -h 0
fi

# R23: ensure SSH homes exist (strap tar has empty dirs; appletvos extract lacked them).
/var/jb/usr/bin/mkdir -p /var/jb/var/mobile /var/jb/var/root
/var/jb/usr/bin/mkdir -p /var/jb/var/mobile/Library/Preferences
/var/jb/usr/bin/chown -R 501:501 /var/jb/var/mobile
/var/jb/usr/bin/chown 0:0 /var/jb/var/root
/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh
"""

ROOTFUL_PATH_RE = re.compile(
    r"(?<![\w/])(/(?:usr|etc|Library|bin|sbin|opt|var|private)[^\s\"']*|/prep_bootstrap\.sh)"
)


def rootful_paths(text: str) -> list[str]:
    hits = []
    for m in ROOTFUL_PATH_RE.finditer(text):
        tok = m.group(1)
        if tok.startswith("/var/jb/"):
            continue
        hits.append(tok)
    return sorted(set(hits))


def verify_contract(text: str) -> None:
    checks = [
        ("#!/var/jb/bin/sh", "shebang"),
        ("-d /var/jb/etc -p /var/jb/etc/master.passwd", "pwd_mkdb -d"),
        ("openssh-server.extrainst_ missing", "extrainst fail-closed"),
        ("openssh-server.extrainst_ install", "extrainst install"),
        ("pw -V /var/jb/etc usermod mobile", "pw mobile shell"),
        ("pw -V /var/jb/etc usermod root", "pw root shell"),
        ("pw -V /var/jb/etc usermod 501", "pw password hash"),
        ("R23: ensure SSH homes exist", "R23 homes"),
        ("/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh", "dest-abs self-rm"),
    ]
    for needle, label in checks:
        if needle not in text:
            raise SystemExit(f"prep contract missing {label}: {needle!r}")
    if "/usr/bin/chsh" in text or "chsh -s" in text:
        raise SystemExit("prep must not invoke chsh (R18)")
    if "/prep_bootstrap.sh" in text.replace("/var/jb/prep_bootstrap.sh", ""):
        raise SystemExit("prep must not reference rootful /prep_bootstrap.sh")
    bad = rootful_paths(text)
    if bad:
        raise SystemExit(f"prep contains unexplained rootful paths: {bad}")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if lines[-1] != "/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh":
        raise SystemExit("prep last executed line must be dest-abs rm")


def write_prep(tree: Path) -> Path:
    prep = tree / "prep_bootstrap.sh"
    text = PREP_BOOTSTRAP
    verify_contract(text)
    prep.write_text(text)
    os.chmod(prep, 0o755)
    return prep


def main() -> int:
    if not OUT_TREE.is_dir():
        raise SystemExit(f"missing {OUT_TREE}")
    extrainst = OUT_TREE / "Library/dpkg/info/openssh-server.extrainst_"
    if not extrainst.is_file() or not os.access(extrainst, os.X_OK):
        raise SystemExit("openssh-server.extrainst_ must exist before prep generation")
    for rel in ("etc/passwd", "etc/group", "etc/master.passwd"):
        if not (OUT_TREE / rel).is_file():
            raise SystemExit(f"missing account db {rel} before prep generation")
    prep = write_prep(OUT_TREE)
    print("PREP_BOOTSTRAP_GENERATE=PASS")
    print(f"  path={prep}")
    print(f"  bytes={prep.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
