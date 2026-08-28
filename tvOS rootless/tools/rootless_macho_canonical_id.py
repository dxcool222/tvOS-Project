#!/usr/bin/env python3
"""Canonical Mach-O identity for R24 D0 (TrollStore signature-invariant).

Hashes bytes [0, LC_CODE_SIGNATURE.dataoff) after normalizing ONLY fields proven
to change under TrollStore CoreTrust rewrite:

  - LC_SEGMENT_64 __LINKEDIT vmsize / filesize
  - LC_CODE_SIGNATURE datasize

The code-signature blob itself and any bytes after its bounded region are excluded
(not hashed). Fail closed on malformed Mach-O / missing CS / missing LINKEDIT /
bad offsets. Consumers that require the code signature to end exactly at EOF must
apply that separate structural policy (r24_dyld_contract.macho_cs_end_valid).

Must stay byte-compatible with source/dt_macho_canonical_id.c.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import hashlib
import struct
import sys
import uuid
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_UUID = 0x1B


class CanonicalIdError(ValueError):
    pass


def _u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def macho_uuid(path: Path | str) -> str:
    data = Path(path).read_bytes()
    if _u32(data, 0) != MH_MAGIC_64:
        raise CanonicalIdError("not thin MH_MAGIC_64")
    ncmds = _u32(data, 16)
    off = 32
    for _ in range(ncmds):
        cmd = _u32(data, off)
        cmdsize = _u32(data, off + 4)
        if cmdsize < 8:
            raise CanonicalIdError("bad cmdsize")
        if cmd == LC_UUID:
            return str(uuid.UUID(bytes=bytes(data[off + 8 : off + 24]))).upper()
        off += cmdsize
    raise CanonicalIdError("missing LC_UUID")


def canonical_sha256(path: Path | str) -> str:
    raw = Path(path).read_bytes()
    data = bytearray(raw)
    if _u32(data, 0) != MH_MAGIC_64:
        raise CanonicalIdError("not thin MH_MAGIC_64")
    ncmds = _u32(data, 16)
    sizeofcmds = _u32(data, 20)
    if 32 + sizeofcmds > len(data):
        raise CanonicalIdError("sizeofcmds out of range")

    off = 32
    le_cmd = None
    cs_cmd = None
    cs_off = None
    cs_sz = None
    end = 32 + sizeofcmds
    for _ in range(ncmds):
        if off + 8 > end:
            raise CanonicalIdError("cmd overrun")
        cmd = _u32(data, off)
        cmdsize = _u32(data, off + 4)
        if cmdsize < 8 or off + cmdsize > end:
            raise CanonicalIdError("bad cmdsize")
        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise CanonicalIdError("short SEGMENT_64")
            name = bytes(data[off + 8 : off + 24]).split(b"\0", 1)[0]
            if name == b"__LINKEDIT":
                le_cmd = off
        elif cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise CanonicalIdError("short CODE_SIGNATURE")
            cs_off = _u32(data, off + 8)
            cs_sz = _u32(data, off + 12)
            cs_cmd = off
        off += cmdsize

    if le_cmd is None:
        raise CanonicalIdError("missing __LINKEDIT")
    if cs_cmd is None or cs_off is None or cs_sz is None:
        raise CanonicalIdError("missing LC_CODE_SIGNATURE")
    if cs_off < 32 + sizeofcmds or cs_off > len(data):
        raise CanonicalIdError("CS dataoff out of range")
    if cs_sz > len(data) - cs_off:
        raise CanonicalIdError("CS datasize out of range")
    le_fileoff = _u64(data, le_cmd + 40)
    if le_fileoff > cs_off:
        raise CanonicalIdError("LINKEDIT fileoff past CS")
    filesize_norm = cs_off - le_fileoff

    prefix = bytearray(data[:cs_off])
    struct.pack_into("<Q", prefix, le_cmd + 32, filesize_norm)  # vmsize
    struct.pack_into("<Q", prefix, le_cmd + 48, filesize_norm)  # filesize
    struct.pack_into("<I", prefix, cs_cmd + 12, 0)  # datasize
    return hashlib.sha256(prefix).hexdigest()


def describe(path: Path | str) -> dict[str, str]:
    p = Path(path)
    raw = hashlib.sha256(p.read_bytes()).hexdigest()
    return {
        "PATH": str(p),
        "RAW_SHA256": raw,
        "CANONICAL_SHA256": canonical_sha256(p),
        "UUID": macho_uuid(p),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--require-equal", action="store_true")
    args = ap.parse_args()
    rows = []
    for p in args.paths:
        try:
            rows.append(describe(p))
        except CanonicalIdError as e:
            print(f"ERROR path={p} err={e}", file=sys.stderr)
            return 2
        for k, v in rows[-1].items():
            print(f"{k}={v}")
        print("---")
    if args.require_equal and len(rows) >= 2:
        c0 = rows[0]["CANONICAL_SHA256"]
        u0 = rows[0]["UUID"]
        for r in rows[1:]:
            if r["CANONICAL_SHA256"] != c0 or r["UUID"] != u0:
                print("EQUAL=NO", file=sys.stderr)
                return 1
        print("EQUAL=YES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
