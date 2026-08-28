#!/usr/bin/env python3
"""ROOTLESS-R4 host Mach-O transform — exact R3 accounting, USB-only outputs."""
from __future__ import annotations

import csv
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace import workspace_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
PLAN = ROOT / "bootstrap/manifests/ROOTLESS_R2_MACHO_TRANSFORM_PLAN.tsv"
OWN = ROOT / "bootstrap/manifests/ROOTLESS_R2_LIBRARY_OWNERSHIP_MATRIX.tsv"
SRC = work_dir("appletvos_extract")
ORACLE = work_dir("oracle_jb")
OUT_TREE = work_dir("jbroot_transformed")
ART = artifacts_dir()
LDID = ldid_path()

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLD = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x18
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19

DYLIB_CMDS = {LC_LOAD_DYLD, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB}


def u32(b: bytes, off: int, swap: bool) -> int:
    v = struct.unpack_from("<I" if not swap else ">I", b, off)[0]
    return v


def p32(v: int, swap: bool) -> bytes:
    return struct.pack("<I" if not swap else ">I", v)


def align8(n: int) -> int:
    return (n + 7) & ~7


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_cstring(buf: bytes, off: int, limit: int) -> str:
    end = buf.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return buf[off:end].decode("utf-8", "replace")


def parse_macho(data: bytearray):
    if len(data) < 32:
        raise ValueError("too small")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == MH_MAGIC_64:
        swap = False
    elif magic == MH_CIGAM_64:
        swap = True
    else:
        raise ValueError("not macho64")
    ncmds = u32(data, 16, swap)
    sizeofcmds = u32(data, 20, swap)
    return swap, ncmds, sizeofcmds


def iter_lcs(data: bytearray, swap: bool, ncmds: int):
    off = 32
    for i in range(ncmds):
        cmd = u32(data, off, swap)
        cmdsize = u32(data, off + 4, swap)
        if cmdsize < 8:
            raise ValueError("bad cmdsize")
        yield i, off, cmd, cmdsize
        off += cmdsize


def first_content_fileoff(data: bytearray, swap: bool, ncmds: int) -> int:
    """Earliest non-zero section file offset (header slack lives before it)."""
    min_off = len(data)
    for _, off, cmd, cmdsize in iter_lcs(data, swap, ncmds):
        if cmd != LC_SEGMENT_64:
            continue
        # segment_command_64: nsects at +64, sections follow at +72
        nsects = u32(data, off + 64, swap)
        so = off + 72
        for _ in range(nsects):
            # section_64: offset uint32 at +48
            sect_off = u32(data, so + 48, swap)
            if sect_off > 0:
                min_off = min(min_off, sect_off)
            so += 80
    return min_off


def get_uuid(data: bytearray, swap: bool, ncmds: int) -> str:
    for _, off, cmd, cmdsize in iter_lcs(data, swap, ncmds):
        if cmd == LC_UUID and cmdsize >= 24:
            return data[off + 8 : off + 24].hex().upper()
            # format with dashes
    return ""


def format_uuid(raw_hex: str) -> str:
    if len(raw_hex) != 32:
        return raw_hex
    h = raw_hex.lower()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".upper()


def dylib_path(data: bytearray, off: int, cmdsize: int, swap: bool) -> tuple[str, int]:
    # dylib_command: cmd,cmdsize,name.offset,timestamp,current,compat
    name_off = u32(data, off + 8, swap)
    return read_cstring(data, off + name_off, cmdsize - name_off), name_off


def rpath_path(data: bytearray, off: int, cmdsize: int, swap: bool) -> tuple[str, int]:
    path_off = u32(data, off + 8, swap)
    return read_cstring(data, off + path_off, cmdsize - path_off), path_off


def rewrite_path_in_cmd(data: bytearray, off: int, cmdsize: int, name_rel: int, new_path: str, swap: bool) -> bool:
    raw = new_path.encode("utf-8") + b"\x00"
    avail = cmdsize - name_rel
    if len(raw) > avail:
        return False
    # clear then write
    data[off + name_rel : off + cmdsize] = b"\x00" * avail
    data[off + name_rel : off + name_rel + len(raw)] = raw
    return True


def append_rpath(data: bytearray, swap: bool, ncmds: int, sizeofcmds: int, path: str) -> tuple[int, int]:
    """Append LC_RPATH if not present. Returns (new_ncmds, new_sizeofcmds)."""
    existing = []
    for _, off, cmd, cmdsize in iter_lcs(data, swap, ncmds):
        if cmd == LC_RPATH:
            p, _ = rpath_path(data, off, cmdsize, swap)
            existing.append(p)
    if path in existing:
        return ncmds, sizeofcmds

    path_b = path.encode("utf-8") + b"\x00"
    # rpath_command: 8 header + 4 path offset + path, align 8
    # path offset typically 12
    body = path_b
    cmdsize = align8(12 + len(body))
    pad = cmdsize - 12 - len(body)
    blob = p32(LC_RPATH, swap) + p32(cmdsize, swap) + p32(12, swap) + body + (b"\x00" * pad)

    content0 = first_content_fileoff(data, swap, ncmds)
    end = 32 + sizeofcmds
    slack = content0 - end
    if len(blob) > slack:
        raise RuntimeError(f"no slack for LC_RPATH {path}: need {len(blob)} have {slack}")
    data[end : end + len(blob)] = blob
    ncmds += 1
    sizeofcmds += len(blob)
    data[16:20] = p32(ncmds, swap)
    data[20:24] = p32(sizeofcmds, swap)
    return ncmds, sizeofcmds


def load_apple_set() -> set[str]:
    s = set()
    if OWN.exists():
        for r in csv.DictReader(OWN.open(), delimiter="\t"):
            if r.get("APPLE_OR_BOOTSTRAP") == "APPLE" or r.get("TARGET_ACTION") == "KEEP_STOCK_APPLE":
                s.add(r["INSTALL_NAME"])
            if r.get("DYLD_CACHE_PRESENT") == "YES":
                s.add(r["INSTALL_NAME"])
    # always-keep prefixes
    return s


def sudo_basename(p: str) -> str | None:
    pref = "/usr/libexec/sudo/"
    if p.startswith(pref):
        return p[len(pref) :]
    return None


def apply_plan_row(path: Path, row: dict, apple: set[str]) -> dict:
    data = bytearray(path.read_bytes())
    swap, ncmds, sizeofcmds = parse_macho(data)
    uuid = format_uuid(get_uuid(data, swap, ncmds).replace("-", "")) if False else ""
    # get uuid properly
    raw_uuid = ""
    for _, off, cmd, cmdsize in iter_lcs(data, swap, ncmds):
        if cmd == LC_UUID:
            raw_uuid = format_uuid(data[off + 8 : off + 24].hex())
            break

    transformed = False
    notes = []

    # Desired loads from plan
    new_loads = [x for x in row.get("NEW_LOADS", "").split("|") if x]
    new_id = row.get("NEW_LC_ID_DYLIB") or ""
    new_rpaths = [x for x in row.get("NEW_LC_RPATHS", "").split("|") if x]

    # Build map original->new from ORIGINAL_LOADS vs NEW_LOADS by index when same length
    orig_loads = [x for x in row.get("ORIGINAL_LOADS", "").split("|") if x]
    replace_map = {}
    if len(orig_loads) == len(new_loads):
        for o, n in zip(orig_loads, new_loads):
            if o != n:
                replace_map[o] = n

    # Sudo addendum always
    for o in list(replace_map.keys()) + orig_loads:
        bn = sudo_basename(o)
        if bn:
            replace_map[o] = f"@rpath/{bn}"
            if "/var/jb/usr/libexec/sudo" not in new_rpaths:
                new_rpaths.append("/var/jb/usr/libexec/sudo")
            notes.append("sudo_addendum")

    # Also rewrite any remaining abs /usr/lib Procursus not in apple set to @rpath
    for _, off, cmd, cmdsize in list(iter_lcs(data, swap, ncmds)):
        if cmd in DYLIB_CMDS:
            p, name_rel = dylib_path(data, off, cmdsize, swap)
            target = None
            if cmd == LC_ID_DYLIB and new_id and p != new_id:
                target = new_id
            elif p in replace_map:
                target = replace_map[p]
            elif p.startswith("/usr/lib/") and p not in apple and not p.startswith("/usr/lib/system/") and "libSystem" not in p:
                # only if plan said ROOTLESS_REQUIRED
                if row.get("ROOTLESS_REQUIRED") == "YES" and not any(
                    p.startswith(x)
                    for x in (
                        "/usr/lib/libobjc",
                        "/usr/lib/libc++",
                        "/usr/lib/libiconv",
                        "/usr/lib/libcharset",
                        "/usr/lib/libcompression",
                        "/usr/lib/libz.",
                        "/usr/lib/libresolv",
                        "/usr/lib/libbz2",
                        "/usr/lib/libutil",
                        "/usr/lib/libbsm",
                        "/usr/lib/libMobileGestalt",
                        "/usr/lib/libsandbox",
                        "/usr/lib/swift",
                    )
                ):
                    target = "@rpath/" + p.split("/")[-1]
            bn = sudo_basename(p)
            if bn:
                target = f"@rpath/{bn}"
                if "/var/jb/usr/libexec/sudo" not in new_rpaths:
                    new_rpaths.append("/var/jb/usr/libexec/sudo")
            if target and target != p:
                if not rewrite_path_in_cmd(data, off, cmdsize, name_rel, target, swap):
                    raise RuntimeError(f"{path}: cannot fit rewrite {p} -> {target}")
                transformed = True
                notes.append(f"rewrote:{p}->{target}")

    # Ensure rpaths
    for rp in new_rpaths:
        if rp == "/usr/lib" and "/var/jb/usr/lib" in new_rpaths:
            # keep both if plan asked; still add
            pass
        before = ncmds, sizeofcmds
        ncmds, sizeofcmds = append_rpath(data, swap, ncmds, sizeofcmds, rp)
        if (ncmds, sizeofcmds) != before:
            transformed = True
            notes.append(f"rpath_add:{rp}")

    # Always ensure /var/jb/usr/lib for ROOTLESS_REQUIRED
    if row.get("ROOTLESS_REQUIRED") == "YES" or row.get("REWRITE_CLASS") != "NO_REWRITE":
        before = ncmds, sizeofcmds
        ncmds, sizeofcmds = append_rpath(data, swap, ncmds, sizeofcmds, "/var/jb/usr/lib")
        if (ncmds, sizeofcmds) != before:
            transformed = True
            notes.append("rpath_add:/var/jb/usr/lib")

    if transformed or row.get("ROOTLESS_REQUIRED") == "YES":
        path.write_bytes(data)

    return {
        "FILE": row["FILE"],
        "TRANSFORMED": "YES" if transformed or row.get("ROOTLESS_REQUIRED") == "YES" and row.get("REWRITE_CLASS") != "NO_REWRITE" else ("YES" if transformed else "NO"),
        "UUID": raw_uuid,
        "NOTES": ";".join(notes),
        "CLASS": row.get("REWRITE_CLASS", ""),
        "ROOTLESS_REQUIRED": row.get("ROOTLESS_REQUIRED", ""),
    }


def copy_tree():
    if OUT_TREE.exists():
        shutil.rmtree(OUT_TREE)
    print("copying extract ->", OUT_TREE)
    shutil.copytree(SRC, OUT_TREE, symlinks=True)


def install_openssh_addon() -> list[str]:
    """Copy OpenSSH package files from oracle into transformed tree. Returns relative macho paths."""
    machos = []
    packages = ["openssh-client", "openssh-server", "openssh-sftp-server"]
    for pkg in packages:
        lst = ORACLE / "Library/dpkg/info" / f"{pkg}.list"
        if not lst.exists():
            raise SystemExit(f"missing oracle list {lst}")
        for line in lst.read_text().splitlines():
            if not line.startswith("/var/jb/"):
                continue
            rel = line[len("/var/jb/") :]
            src = ORACLE / rel
            dst = OUT_TREE / rel
            if src.is_symlink():
                dst.parent.mkdir(parents=True, exist_ok=True)
                if dst.exists() or dst.is_symlink():
                    dst.unlink()
                dst.symlink_to(os.readlink(src))
                continue
            if not src.is_file():
                if src.is_dir():
                    dst.mkdir(parents=True, exist_ok=True)
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            with open(src, "rb") as f:
                mag = f.read(4)
            if mag in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                machos.append(rel)
        # also copy control/list/md5sums into Library/dpkg/info
        for suf in (".list", ".md5sums", ".conffiles", ".prerm", ".postinst", ".postrm", ".preinst"):
            s = ORACLE / "Library/dpkg/info" / f"{pkg}{suf}"
            if s.exists():
                d = OUT_TREE / "Library/dpkg/info" / f"{pkg}{suf}"
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, d)
    return sorted(set(machos))


def exclusive_class(row: dict) -> str:
    if row.get("ROOTLESS_REQUIRED") == "YES" and row.get("REWRITE_CLASS") == "NO_REWRITE":
        return "ID_DYLIB_REWRITE_ONLY"
    if row.get("ROOTLESS_REQUIRED") == "YES":
        return "LOAD_AND_RPATH_REWRITE"
    return "UNCHANGED"


def main():
    ART.mkdir(parents=True, exist_ok=True)
    apple = load_apple_set()
    rows = list(csv.DictReader(PLAN.open(), delimiter="\t"))
    assert len(rows) == 385, len(rows)

    classes = {"LOAD_AND_RPATH_REWRITE": 0, "ID_DYLIB_REWRITE_ONLY": 0, "UNCHANGED": 0}
    for r in rows:
        classes[exclusive_class(r)] += 1
    assert classes["LOAD_AND_RPATH_REWRITE"] == 283
    assert classes["ID_DYLIB_REWRITE_ONLY"] == 1
    assert classes["UNCHANGED"] == 101
    assert sum(classes.values()) == 385

    copy_tree()

    results = []
    for r in rows:
        rel = r["FILE"]
        p = OUT_TREE / rel
        if not p.is_file():
            raise SystemExit(f"missing {rel}")
        # skip non-macho
        with p.open("rb") as f:
            mag = f.read(4)
        if mag not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            raise SystemExit(f"not macho {rel}")
        if mag == b"\xca\xfe\xba\xbe":
            # fat — unexpected for appletvos arm64 set; fail loudly
            raise SystemExit(f"fat macho unexpected: {rel}")
        meta = apply_plan_row(p, r, apple)
        meta["EXCLUSIVE_CLASS"] = exclusive_class(r)
        meta["SHA256_POST"] = sha256_file(p)
        results.append(meta)

    ssh_machos = install_openssh_addon()

    # Write transform final (bootstrap only)
    out_tsv = ART / "ROOTLESS_R4_TRANSFORM_FINAL.tsv"
    with out_tsv.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "FILE",
                "EXCLUSIVE_CLASS",
                "ROOTLESS_REQUIRED",
                "TRANSFORMED",
                "UUID",
                "SHA256_POST",
                "NOTES",
            ],
            delimiter="\t",
        )
        w.writeheader()
        for m in results:
            w.writerow({k: m[k] for k in w.fieldnames})

    # counts
    transformed = sum(1 for m in results if m["EXCLUSIVE_CLASS"] != "UNCHANGED")
    unchanged = sum(1 for m in results if m["EXCLUSIVE_CLASS"] == "UNCHANGED")
    summary = {
        "BOOTSTRAP_MACHO_COUNT": 385,
        "OPENSSH_ADDON_MACHO_COUNT": len(ssh_machos),
        "FINAL_MACHO_COUNT": 385 + len(ssh_machos),
        "TRANSFORMED_COUNT": transformed,
        "UNCHANGED_COUNT": unchanged,
        "LOAD_AND_RPATH_REWRITE": classes["LOAD_AND_RPATH_REWRITE"],
        "ID_DYLIB_REWRITE_ONLY": classes["ID_DYLIB_REWRITE_ONLY"],
    }
    assert summary["TRANSFORMED_COUNT"] == 284
    assert summary["UNCHANGED_COUNT"] == 101
    assert summary["TRANSFORMED_COUNT"] + summary["UNCHANGED_COUNT"] == summary["BOOTSTRAP_MACHO_COUNT"]

    with (ART / "ROOTLESS_R4_COUNT_SUMMARY.tsv").open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["KEY", "VALUE"])
        for k, v in summary.items():
            w.writerow([k, v])
        w.writerow(["OPENSSH_MACHO_LIST", "|".join(ssh_machos)])

    print("SUMMARY", summary)
    print("wrote", out_tsv)


if __name__ == "__main__":
    main()
