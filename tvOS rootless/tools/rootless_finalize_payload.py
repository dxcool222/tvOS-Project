#!/usr/bin/env python3
"""Finalize rootless payload: rewrite abs symlinks to /var/jb and dpkg DB paths."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace import work_dir

TREE = work_dir("jbroot_transformed")


def map_abs(target: str) -> str | None:
    if target.startswith("/var/jb/"):
        return target
    prefixes = (
        "/usr/",
        "/Library/",
        "/bin/",
        "/sbin/",
        "/etc/",
        "/private/etc/",
    )
    for p in prefixes:
        if target.startswith(p):
            if target.startswith("/private/etc/"):
                return "/var/jb/etc/" + target[len("/private/etc/") :]
            return "/var/jb" + target
    return None


def rewrite_symlinks(root: Path) -> tuple[int, int, list[str]]:
    changed = 0
    unresolved = 0
    problems = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            tgt = os.readlink(p)
            if not tgt.startswith("/"):
                continue
            if tgt.startswith("/var/jb/"):
                continue
            mapped = map_abs(tgt)
            if not mapped:
                unresolved += 1
                problems.append(f"UNMAPPED {p.relative_to(root)} -> {tgt}")
                continue
            # Prefer mapped path if present in tree; else keep map anyway (oracle style)
            rel = mapped[len("/var/jb/") :]
            if not (root / rel).exists() and not (root / rel).is_symlink():
                # try without forcing
                unresolved += 1
                problems.append(f"TARGET_MISSING {p.relative_to(root)} -> {mapped}")
                # still rewrite to /var/jb form (oracle)
            p.unlink()
            p.symlink_to(mapped)
            changed += 1
    return changed, unresolved, problems


def rewrite_dpkg(root: Path) -> int:
    info = root / "Library/dpkg/info"
    status = root / "Library/dpkg/status"
    n = 0

    def rewrite_text(text: str) -> str:
        out = text
        # path lines / directory entries
        for a, b in [
            ("\n/usr/", "\n/var/jb/usr/"),
            ("\n/Library/", "\n/var/jb/Library/"),
            ("\n/bin/", "\n/var/jb/bin/"),
            ("\n/sbin/", "\n/var/jb/sbin/"),
            ("\n/etc/", "\n/var/jb/etc/"),
            ("\n/private/etc/", "\n/var/jb/etc/"),
        ]:
            out = out.replace(a, b)
        if out.startswith("/usr/"):
            out = "/var/jb" + out
        elif out.startswith("/Library/"):
            out = "/var/jb" + out
        elif out.startswith("/bin/") or out.startswith("/sbin/") or out.startswith("/etc/"):
            out = "/var/jb" + out
        out = out.replace(
            "Architecture: appletvos-arm64\n",
            "Architecture: appletvos-arm64-rootless\n",
        )
        out = out.replace(
            "Architecture: appletvos-arm64\r\n",
            "Architecture: appletvos-arm64-rootless\r\n",
        )
        return out

    if info.is_dir():
        for p in info.iterdir():
            if p.suffix not in (
                ".list",
                ".md5sums",
                ".conffiles",
                ".postinst",
                ".preinst",
                ".prerm",
                ".postrm",
            ):
                continue
            try:
                text = p.read_text("utf-8")
            except Exception:
                continue
            nxt = rewrite_text(text)
            # also fix first-line absolute without leading newline
            lines = []
            for line in nxt.splitlines(True):
                if line.startswith(("/usr/", "/Library/", "/bin/", "/sbin/", "/etc/")):
                    line = "/var/jb" + line
                lines.append(line)
            nxt2 = "".join(lines)
            if nxt2 != text:
                p.write_text(nxt2, "utf-8")
                n += 1
    if status.is_file():
        text = status.read_text("utf-8")
        nxt = rewrite_text(text)
        if nxt != text:
            status.write_text(nxt, "utf-8")
            n += 1
    return n


def main():
    c, u, probs = rewrite_symlinks(TREE)
    d = rewrite_dpkg(TREE)
    print(f"SYMLINKS_REWRITTEN={c} UNRESOLVED_OR_MISSING_TARGET={u} DPKG_FILES_REWRITTEN={d}")
    for p in probs[:30]:
        print(p)
    if len(probs) > 30:
        print(f"... {len(probs)-30} more")


if __name__ == "__main__":
    main()
