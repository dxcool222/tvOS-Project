#!/usr/bin/env python3
"""R24 generated tvOS dyld contract validation (host + gate shared)."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import struct
from pathlib import Path

from rootless_macho_canonical_id import CanonicalIdError, canonical_sha256, macho_uuid

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_UUID = 0x1B
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_TWOLEVEL_HINTS = 0x16
LC_SEGMENT_SPLIT_INFO = 0x1E
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_NOTE = 0x31
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034

S_ZEROFILL = 0x1
S_GB_ZEROFILL = 0xC
S_THREAD_LOCAL_ZEROFILL = 0x12

EXPECTED_STOCK_SHA = "96806a0e57eef714ec806063714101f09afbbdd968346d0d6ba8c4d635b11fdf"
EXPECTED_GENERATED_RAW_SHA = "9c38f5f1e801057c08d0749226873122f40275c6fe04dfa3ca67ad64a72ec160"
EXPECTED_GENERATED_CANONICAL_SHA = (
    "772a5bb86acf87f5dfd68cff0043640ab4645c9fecb1f76e278aaed28cacfcf7"
)
EXPECTED_GENERATED_UUID = "444F5041-5456-3136-3500-0AF299CDDA68"
STOCK_PATCH_OFFSET = 0x3FDC
GENERATED_PATCH_OFFSET = 0x7FDC
STOCK_PATCH_PROLOGUE = "ff0301d1f65701a9f44f02a9fd7b03a9"
GENERATED_PATCH_BYTES = "e01f80d2c0035fd6"
JBINFO_SECTION_SIZE = 0x4000
EXPECTED_NCMDS = 14
EXPECTED_CS_OFF = 874032
EXPECTED_MAX_NON_SIGNATURE_END = 874020


def _u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def macho_cs_end_valid(path: Path | str) -> None:
    data = Path(path).read_bytes()
    if _u32(data, 0) != MH_MAGIC_64:
        raise CanonicalIdError("not thin MH_MAGIC_64")
    ncmds = _u32(data, 16)
    off = 32
    cs_off = cs_sz = None
    for _ in range(ncmds):
        cmd = _u32(data, off)
        cmdsize = _u32(data, off + 4)
        if cmd == LC_CODE_SIGNATURE:
            cs_off = _u32(data, off + 8)
            cs_sz = _u32(data, off + 12)
            break
        off += cmdsize
    if cs_off is None or cs_sz is None:
        raise CanonicalIdError("missing LC_CODE_SIGNATURE")
    if cs_off + cs_sz != len(data):
        raise CanonicalIdError("CS end != file size")


def _checked_end(off: int, count: int, width: int, limit: int, label: str) -> int:
    if off < 0 or count < 0 or width < 0:
        raise CanonicalIdError(f"{label} negative range")
    end = off + count * width
    if end < off or end > limit:
        raise CanonicalIdError(f"{label} range")
    return end


def runtime_dyld_layout(
    path: Path | str,
    *,
    expected_ncmds: int = EXPECTED_NCMDS,
    expected_cs_off: int = EXPECTED_CS_OFF,
    expected_max_non_signature_end: int = EXPECTED_MAX_NON_SIGNATURE_END,
    expected_jbinfo_size: int = JBINFO_SECTION_SIZE,
) -> dict[str, int]:
    """Fail-closed layout policy for installed generated-dyld phases.

    Unlike macho_cs_end_valid(), this permits an unreferenced post-signature
    trailer. It does not weaken canonical/UUID/patch identity; callers apply
    those independent gates through validate_installed_runtime_dyld_contract().
    """
    data = Path(path).read_bytes()
    if len(data) < 32 or _u32(data, 0) != MH_MAGIC_64:
        raise CanonicalIdError("not thin MH_MAGIC_64")
    ncmds = _u32(data, 16)
    sizeofcmds = _u32(data, 20)
    command_end = 32 + sizeofcmds
    if ncmds != expected_ncmds or command_end > len(data):
        raise CanonicalIdError("command table identity/bounds")

    off = 32
    cs_rows: list[tuple[int, int, int]] = []
    uuid_count = linkedit_count = jbinfo_count = 0
    symtab_count = dysymtab_count = 0
    linkedit_fileoff = linkedit_end = 0
    jbinfo_fileoff = jbinfo_size = 0
    max_non_signature_end = 0
    symtab_nsyms = 0
    dysym_indexes: tuple[int, int, int, int, int, int] | None = None

    def track(fileoff: int, count: int, width: int, label: str) -> int:
        nonlocal max_non_signature_end
        if count == 0:
            return fileoff
        end = _checked_end(fileoff, count, width, len(data), label)
        max_non_signature_end = max(max_non_signature_end, end)
        return end

    for _ in range(ncmds):
        if off + 8 > command_end:
            raise CanonicalIdError("cmd overrun")
        cmd = _u32(data, off)
        cmdsize = _u32(data, off + 4)
        if cmdsize < 8 or off + cmdsize > command_end:
            raise CanonicalIdError("bad cmdsize")

        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise CanonicalIdError("short SEGMENT_64")
            nsects = _u32(data, off + 64)
            if 72 + nsects * 80 != cmdsize:
                raise CanonicalIdError("segment section table size")
            segname = bytes(data[off + 8 : off + 24]).split(b"\0", 1)[0]
            seg_fileoff = _u64(data, off + 40)
            seg_filesize = _u64(data, off + 48)
            seg_end = _checked_end(seg_fileoff, 1, seg_filesize, len(data), "segment")
            if segname == b"__LINKEDIT":
                linkedit_count += 1
                linkedit_fileoff = seg_fileoff
                linkedit_end = seg_end
            elif seg_filesize:
                max_non_signature_end = max(max_non_signature_end, seg_end)

            so = off + 72
            for _section in range(nsects):
                sectname = bytes(data[so : so + 16]).split(b"\0", 1)[0]
                section_segname = bytes(data[so + 16 : so + 32]).split(b"\0", 1)[0]
                section_size = _u64(data, so + 40)
                section_fileoff = _u32(data, so + 48)
                reloff = _u32(data, so + 56)
                nreloc = _u32(data, so + 60)
                section_type = _u32(data, so + 64) & 0xFF
                if section_type not in (S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL) and section_size:
                    section_end = track(section_fileoff, 1, section_size, "section")
                    if section_fileoff < seg_fileoff or section_end > seg_end:
                        raise CanonicalIdError("section outside segment")
                track(reloff, nreloc, 8, "section relocations")
                if section_segname == b"__DATA" and sectname == b"__jbinfo":
                    jbinfo_count += 1
                    jbinfo_fileoff = section_fileoff
                    jbinfo_size = section_size
                so += 80
        elif cmd == LC_CODE_SIGNATURE:
            if cmdsize != 16:
                raise CanonicalIdError("bad CODE_SIGNATURE cmdsize")
            cs_off = _u32(data, off + 8)
            cs_size = _u32(data, off + 12)
            cs_rows.append((cs_off, cs_size, cs_off + cs_size))
        elif cmd == LC_UUID:
            if cmdsize != 24:
                raise CanonicalIdError("bad UUID cmdsize")
            uuid_count += 1
        elif cmd == LC_SYMTAB:
            if cmdsize != 24:
                raise CanonicalIdError("bad SYMTAB cmdsize")
            symtab_count += 1
            symoff, symtab_nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
            track(symoff, symtab_nsyms, 16, "symtab")
            track(stroff, strsize, 1, "strtab")
        elif cmd == LC_DYSYMTAB:
            if cmdsize != 80:
                raise CanonicalIdError("bad DYSYMTAB cmdsize")
            dysymtab_count += 1
            vals = struct.unpack_from("<" + "I" * 18, data, off + 8)
            dysym_indexes = vals[:6]
            for i, width in zip(range(6, 18, 2), (8, 56, 4, 4, 8, 8)):
                track(vals[i], vals[i + 1], width, "dysymtab")
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            if cmdsize != 48:
                raise CanonicalIdError("bad DYLD_INFO cmdsize")
            vals = struct.unpack_from("<" + "I" * 10, data, off + 8)
            for i in range(0, 10, 2):
                track(vals[i], vals[i + 1], 1, "dyld info")
        elif cmd in (
            LC_SEGMENT_SPLIT_INFO,
            LC_FUNCTION_STARTS,
            LC_DATA_IN_CODE,
            LC_DYLIB_CODE_SIGN_DRS,
            LC_LINKER_OPTIMIZATION_HINT,
            LC_DYLD_EXPORTS_TRIE,
            LC_DYLD_CHAINED_FIXUPS,
        ):
            if cmdsize != 16:
                raise CanonicalIdError("bad linkedit data cmdsize")
            dataoff, datasize = struct.unpack_from("<II", data, off + 8)
            track(dataoff, datasize, 1, "linkedit data")
        elif cmd == LC_TWOLEVEL_HINTS:
            if cmdsize != 16:
                raise CanonicalIdError("bad TWOLEVEL_HINTS cmdsize")
            dataoff, count = struct.unpack_from("<II", data, off + 8)
            track(dataoff, count, 4, "twolevel hints")
        elif cmd == LC_ENCRYPTION_INFO_64:
            if cmdsize != 24:
                raise CanonicalIdError("bad ENCRYPTION_INFO_64 cmdsize")
            dataoff, datasize = struct.unpack_from("<II", data, off + 8)
            track(dataoff, datasize, 1, "encryption info")
        elif cmd == LC_NOTE:
            if cmdsize != 40:
                raise CanonicalIdError("bad NOTE cmdsize")
            dataoff, datasize = struct.unpack_from("<QQ", data, off + 24)
            track(dataoff, datasize, 1, "note")
        off += cmdsize

    if off != command_end:
        raise CanonicalIdError("command table not exactly consumed")
    if len(cs_rows) != 1 or uuid_count != 1 or linkedit_count != 1 or jbinfo_count != 1:
        raise CanonicalIdError("command/section cardinality")
    if symtab_count != 1 or dysymtab_count != 1 or dysym_indexes is None:
        raise CanonicalIdError("symbol command cardinality")
    cs_off, cs_size, cs_end = cs_rows[0]
    if cs_off != expected_cs_off or cs_off < command_end or cs_end > len(data):
        raise CanonicalIdError("code signature bounds/identity")
    if linkedit_fileoff > cs_off or linkedit_end < cs_end:
        raise CanonicalIdError("LINKEDIT bounds")
    if max_non_signature_end != expected_max_non_signature_end or max_non_signature_end > cs_off:
        raise CanonicalIdError("non-signature reference boundary")
    if jbinfo_size != expected_jbinfo_size or jbinfo_fileoff + jbinfo_size > cs_off:
        raise CanonicalIdError("__jbinfo identity/bounds")
    ilocal, nlocal, iext, nextdef, iundef, nundef = dysym_indexes
    if ilocal + nlocal > symtab_nsyms or iext + nextdef > symtab_nsyms or iundef + nundef > symtab_nsyms:
        raise CanonicalIdError("dysymtab symbol indexes")

    return {
        "FILE_SIZE": len(data),
        "NCMDS": ncmds,
        "SIZEOFCMDS": sizeofcmds,
        "CS_OFF": cs_off,
        "CS_SIZE": cs_size,
        "CS_END": cs_end,
        "TRAILER_SIZE": len(data) - cs_end,
        "MAX_NON_SIGNATURE_END": max_non_signature_end,
        "JBINFO_FILEOFF": jbinfo_fileoff,
        "JBINFO_SIZE": jbinfo_size,
    }


def bytes_at_offset(path: Path | str, offset: int, length: int) -> bytes:
    data = Path(path).read_bytes()
    if offset < 0 or offset + length > len(data):
        raise CanonicalIdError("offset out of range")
    return data[offset : offset + length]


def jbinfo_section_size(path: Path | str) -> int:
    data = Path(path).read_bytes()
    if _u32(data, 0) != MH_MAGIC_64:
        raise CanonicalIdError("not thin MH_MAGIC_64")
    ncmds = _u32(data, 16)
    sizeofcmds = _u32(data, 20)
    off = 32
    end = 32 + sizeofcmds
    for _ in range(ncmds):
        if off + 8 > end:
            raise CanonicalIdError("cmd overrun")
        cmd = _u32(data, off)
        cmdsize = _u32(data, off + 4)
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            seg = bytes(data[off + 8 : off + 24]).split(b"\0", 1)[0]
            if seg == b"__DATA":
                nsects = _u32(data, off + 64)
                so = off + 72
                for _s in range(nsects):
                    if so + 80 > end:
                        raise CanonicalIdError("section overrun")
                    sect = bytes(data[so : so + 16]).split(b"\0", 1)[0]
                    if sect == b"__jbinfo":
                        size = _u64(data, so + 40)
                        fileoff = _u32(data, so + 48)
                        if fileoff + size > len(data):
                            raise CanonicalIdError("__jbinfo bounds")
                        return int(size)
                    so += 80
        off += cmdsize
    raise CanonicalIdError("missing __DATA,__jbinfo")


def locate_generated_patch_offset(path: Path | str) -> int:
    data = Path(path).read_bytes()
    needle = bytes.fromhex(GENERATED_PATCH_BYTES)
    idx = data.find(needle)
    if idx < 0:
        raise CanonicalIdError("generated patch bytes missing")
    return idx


def validate_installed_runtime_dyld_contract(path: Path | str, manifest: dict | None = None) -> dict[str, str]:
    p = Path(path)
    out: dict[str, str] = {"PATH": str(p)}
    layout = runtime_dyld_layout(p)
    out.update({f"LAYOUT_{k}": str(v) for k, v in layout.items()})
    out["RUNTIME_LAYOUT"] = "PASS"
    out["RAW_SHA256"] = __import__("hashlib").sha256(p.read_bytes()).hexdigest()
    out["CANONICAL_SHA256"] = canonical_sha256(p)
    out["UUID"] = macho_uuid(p)
    patch_off = GENERATED_PATCH_OFFSET
    patch = bytes_at_offset(p, patch_off, len(GENERATED_PATCH_BYTES) // 2)
    if patch.hex() != GENERATED_PATCH_BYTES:
        raise CanonicalIdError("patch bytes mismatch")
    out["GENERATED_PATCH_OFFSET"] = f"0x{patch_off:x}"
    jbinfo = jbinfo_section_size(p)
    if jbinfo != JBINFO_SECTION_SIZE:
        raise CanonicalIdError("__jbinfo size mismatch")
    out["JBINFO_SIZE"] = f"0x{jbinfo:x}"

    exp_canon = manifest.get("generated_canonical_sha256") if manifest else EXPECTED_GENERATED_CANONICAL_SHA
    exp_uuid = manifest.get("generated_uuid") if manifest else EXPECTED_GENERATED_UUID
    exp_patch_off = manifest.get("generated_patch_offset") if manifest else f"0x{GENERATED_PATCH_OFFSET:x}"
    if out["CANONICAL_SHA256"] != exp_canon:
        raise CanonicalIdError("canonical mismatch")
    if out["UUID"].upper() != str(exp_uuid).upper():
        raise CanonicalIdError("uuid mismatch")
    if out["GENERATED_PATCH_OFFSET"].lower() != str(exp_patch_off).lower():
        raise CanonicalIdError("generated patch offset mismatch")
    return out


def validate_generated_dyld_contract(path: Path | str, manifest: dict | None = None) -> dict[str, str]:
    """PRISTINE_BUILD_STRICT: runtime identity/layout plus CS-at-EOF."""
    out = validate_installed_runtime_dyld_contract(path, manifest)
    macho_cs_end_valid(path)
    out["CS_END_VALID"] = "PASS"
    out["PRISTINE_BUILD_STRICT"] = "PASS"
    return out
