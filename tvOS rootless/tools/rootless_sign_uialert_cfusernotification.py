#!/usr/bin/env python3
"""R19: restore dest uialert CS slot 5 after dest-rpath rewrite.

Does not rewrite load commands. Does not bare-ldid -S this file.
XML is the extract/rootful slot-5 body (sha pinned).
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import csv
import hashlib
import re
import struct
import subprocess
import sys
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
sys.path.insert(0, str(ROOT / "tools"))
from rootless_add_dest_libiosexec_rpath import (  # noqa: E402
    DEST_RPATH,
    loads_and_rpaths,
    patch_trust,
    codesign_cdhash,
)

LDID = ldid_path()
XML = ROOT / "bootstrap/entitlements/appletvos_extract_entitlements.xml"
PINNED_XML_SHA = "9d45ce6cbf04501cbd27a02c98f95e5eaf6cf4c2324b3170f426d918bfb667dd"
R18_INNER_SHA = "a84550e46e71251d090be02189761fd44fe6661b3807cb35365c2beeab2adb05"
R18_CDHASH = "d71fb75df371b7003854312f71f1c7ef86eb56b4"
REL = "usr/bin/uialert"
HDR = b"R14MACHO"
KEY = b"com.apple.springboard.CFUserNotification"
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
LC_CODE_SIGNATURE = 0x1D


def inner_bytes(raw: bytes) -> bytes:
    if raw.startswith(HDR):
        return raw[8:]
    return raw


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def cs_ent_info(raw: bytes) -> dict:
    data = inner_bytes(raw)
    out = {
        "sha256": sha256_bytes(data),
        "size": len(data),
        "has_slot5": False,
        "key_in_file": KEY in data,
        "key_in_declared": False,
        "key_after_declared": False,
        "super_len": 0,
        "orphan_only": False,
        "rpaths": [],
    }
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        return out
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    cs_off = cs_sz = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_CODE_SIGNATURE:
            cs_off, cs_sz = struct.unpack_from("<II", data, off + 8)
            break
        off += cmdsize
    loads, rps = loads_and_rpaths(bytearray(data))
    out["rpaths"] = rps
    out["loads"] = loads
    if cs_off is None:
        return out
    blob = data[cs_off : cs_off + cs_sz]
    if len(blob) < 12:
        return out
    _magic, slen = struct.unpack(">II", blob[:8])
    count = struct.unpack(">I", blob[8:12])[0]
    out["super_len"] = slen
    declared = blob[:slen]
    after = blob[slen:] if slen < len(blob) else b""
    out["key_in_declared"] = KEY in declared
    out["key_after_declared"] = KEY in after
    for i in range(count):
        typ, offb = struct.unpack(">II", blob[12 + 8 * i : 20 + 8 * i])
        mag, ln = struct.unpack(">II", blob[offb : offb + 8])
        if mag == CSMAGIC_EMBEDDED_ENTITLEMENTS or typ == 5:
            out["has_slot5"] = True
            body = blob[offb + 8 : offb + ln]
            out["ent_xml_sha"] = sha256_bytes(body)
    out["orphan_only"] = (
        out["key_in_file"] and (not out["has_slot5"]) and (not out["key_in_declared"])
    )
    return out


def uialert_gate_ok(info: dict) -> bool:
    rps = info.get("rpaths") or []
    return (
        info.get("has_slot5") is True
        and info.get("key_in_declared") is True
        and info.get("ent_xml_sha") == PINNED_XML_SHA
        and "/usr/lib" in rps
        and DEST_RPATH in rps
        and info.get("sha256") != R18_INNER_SHA
        and not info.get("orphan_only")
    )


def sign_uialert(p: Path) -> None:
    xml_sha = sha256_bytes(XML.read_bytes())
    if xml_sha != PINNED_XML_SHA:
        raise SystemExit(f"XML sha {xml_sha} != pinned {PINNED_XML_SHA}")
    r = subprocess.run(
        [str(LDID), f"-S{XML}", str(p)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        r2 = subprocess.run(
            ["codesign", "-s", "-", "-f", "--entitlements", str(XML), str(p)],
            capture_output=True,
            text=True,
        )
        if r2.returncode != 0:
            raise SystemExit(f"uialert sign fail ldid={r.stderr} codesign={r2.stderr}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--trust", required=True)
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()
    tree = Path(args.tree)
    trust = Path(args.trust)
    p = tree / REL
    if not p.is_file() or p.is_symlink():
        print(f"missing {REL}", file=sys.stderr)
        return 1
    raw = p.read_bytes()
    if raw.startswith(HDR) and not args.verify_only:
        print("wrapped uialert not supported at this stage", file=sys.stderr)
        return 1
    if not args.verify_only:
        if not XML.is_file():
            print(f"missing xml {XML}", file=sys.stderr)
            return 1
        sign_uialert(p)
        sha = sha256_bytes(p.read_bytes())
        cd = codesign_cdhash(p)
        if sha == R18_INNER_SHA or cd == R18_CDHASH:
            print("sign did not change R18 identity", file=sys.stderr)
            return 1
        patch_trust(trust, {REL: (sha, cd)})
    info = cs_ent_info(raw)
    if raw.startswith(HDR):
        info["cdhash"] = "PACKED_WRAPPED"
    else:
        info["cdhash"] = codesign_cdhash(p)
    print(
        "UIALERT_SLOT5={has} KEY_IN_DECLARED={kd} ORPHAN_ONLY={oo} "
        "RPATHS={rp} SHA={sha} CDHASH={cd} SUPER_LEN={sl}".format(
            has=info["has_slot5"],
            kd=info["key_in_declared"],
            oo=info["orphan_only"],
            rp=",".join(info["rpaths"]),
            sha=info["sha256"],
            cd=info["cdhash"],
            sl=info["super_len"],
        )
    )
    if not uialert_gate_ok(info):
        print("UIALERT_ENTITLEMENT_GATE_FAIL", info, file=sys.stderr)
        return 1
    if not raw.startswith(HDR) and info["cdhash"] == R18_CDHASH:
        print("CDHASH still R18", file=sys.stderr)
        return 1
    print("UIALERT_ENTITLEMENT_GATE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
