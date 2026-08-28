#!/usr/bin/env python3
"""
BUILD65 — Kernelcache forensic probe (20L563 / AppleTV6,2)

Reads kernelcache.j105a.20L563.macho from disk. Every claim is either:
  • ON_DISK   — bytes/instructions/strings read from the Mach-O file
  • KNOWN     — cross-checked against dt_baked_offsets.h / BUILD65_IDA_TRACE.md registry
  • NEW       — discovered on disk, pending IDA MCP confirmation (listed separately)

No runtime guessing. Does not require IDA; produces BUILD65_KERNELCACHE_PROBE.txt
for human + IDA MCP verification.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import re
import struct
import sys
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
except ImportError:
    print("ERROR: capstone required (pip install capstone)", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths (defaults relative to repo root)
# ---------------------------------------------------------------------------
# tvrootshell/tvrootshell-1/dopamin-tvOS-kfd/tools/this.py → repo root is parents[3]
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_KERNEL = REPO_ROOT / "kernelcache.j105a.20L563.macho"
DEFAULT_OUT = Path(__file__).resolve().parents[1] / "BUILD65_KERNELCACHE_PROBE.txt"

IMAGE_BASE = 0xFFFFFFF_0070_0400  # __TEXT vmaddr — IDA reference base label

APFS_VA_LO = 0xFFFFFFF006970000
APFS_VA_HI = 0xFFFFFFF006A90000

# ---------------------------------------------------------------------------
# Registry: facts we already claim to know (from dt_baked_offsets.h + audits)
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class KnownOffset:
    name: str
    apfs_byte_off: int
    hex_off: str
    ida_ref: str
    in_exploit: bool


KNOWN_APFS_OFFSETS: list[KnownOffset] = [
    KnownOffset("APFS_VOL_SB", 192, "0xC0", "apfs_mount_update a1+192", True),
    KnownOffset("APFS_CONTAINER", 208, "0xD0", "apfs_mount_update a1+208", True),
    KnownOffset("APFS_VOL_NAME_STR_D8", 216, "0xD8", "handle_snapshot_mount strdup volname @ 0x9e0180 (NOT vol_sb)", False),
    KnownOffset("APFS_BACKUP_VOL_SB", 200, "0xC8", "revert_to_snapshot +200", False),
    KnownOffset("APFS_REVERT_XID", 248, "0xF8", "revert_to_snapshot +248", True),
    KnownOffset("APFS_MAIN_APFS", 312, "0x138", "child→outer back-pointer", True),
    KnownOffset("APFS_READONLY", 692, "0x2B4", "case5 write-upgrade gate", True),
    KnownOffset("APFS_MOUNT_MP", 720, "0x2D0", "handle_mount +720", False),
    KnownOffset("APFS_VOL_ID", 728, "0x2D8", "revert list walk match", False),
    KnownOffset("APFS_VOL_LIST_NEXT", 816, "0x330", "container vol list", False),
    KnownOffset("APFS_EPHEMERAL_GRAFT", 8584, "0x2188", "apfs_mount_update +8584", False),
]

KNOWN_CONTAINER_OFFSETS = [
    ("CONTAINER_MU_GATE", 316, "0x13C", True),
    ("CONTAINER_VOL_LIST", 496, "0x1F0", False),
    ("CONTAINER_NX_SB", 192, "0xC0", False),
    ("CONTAINER_REMAP", 324, "0x144", False),
]

KNOWN_SITES: list[dict] = [
    {
        "id": "apfs_mount_update_entry",
        "va": 0xFFFFFFF_006A_27314,
        "expect_fn": "sub_",
        "checks": [
            (0xFFFFFFF_006A_27338, r"ldr\s+\w+,\s*\[\w+,\s*#0xd0\]"),
            (0xFFFFFFF_006A_2733C, r"ldr\s+\w+,\s*\[\w+,\s*#0x13c\]"),
            (0xFFFFFFF_006A_2739C, r"ldr\s+\w+,\s*\[\w+,\s*#0xc0\]"),
            (0xFFFFFFF_006A_273A8, r"(cmp|b\.eq|tst)"),
        ],
    },
    {
        "id": "apfs_vfsop_mount_case5_writeupgrade",
        "va": 0xFFFFFFF_0069_D9F50,
        "checks": [
            (0xFFFFFFF_0069_DA2E4, r"ldrh\s+\w+"),
            (0xFFFFFFF_0069_DA2E8, r"cmp\s+\w+,\s*#8"),
            (0xFFFFFFF_0069_DA624, r"ldr\s+\w+,\s*\[\w+,\s*#0x2b4\]"),
            (0xFFFFFFF_0069_DA630, r"bl\s+"),
            (0xFFFFFFF_0069_DA638, r"ldr\s+\w+,\s*\[\w+,\s*#0x138\]"),
            (0xFFFFFFF_0069_DA970, r"bl\s+"),
        ],
    },
    {
        "id": "handle_snapshot_mount_child_link",
        "va": 0xFFFFFFF_0069_DFC30,
        "checks": [
            (0xFFFFFFF_0069_E0154, r"str\s+\w+,\s*\[\w+,\s*#0x138\]"),
            (0xFFFFFFF_0069_E0180, r"str\s+\w+,\s*\[\w+,\s*#0xd8\]"),
            (0xFFFFFFF_0069_E0634, r"bl\s+"),
            (0xFFFFFFF_0069_E08C4, r"bl\s+"),  # vfs_setfsprivate in handle_mount callee
        ],
    },
    {
        "id": "handle_mount_container_list",
        "va": 0xFFFFFFF_0069_E07B0,
        "checks": [
            (0xFFFFFFF_0069_E07F8, r"ldr\s+\w+,\s*\[\w+,\s*#0xd0\]"),
            (0xFFFFFFF_0069_E08C4, r"bl\s+"),
            (0xFFFFFFF_0069_E0B9C, r"ldr\s+\w+,\s*\[\w+,\s*#0x1f[08]\]"),
        ],
    },
    {
        "id": "revert_to_snapshot_vol_list",
        "va": 0xFFFFFFF_0069_74150,
        "checks": [
            (0xFFFFFFF_0069_743DC, r"ldr\s+\w+,\s*\[\w+,\s*#0x1f0\]"),
            (0xFFFFFFF_0069_743F0, r"(ldr|ccmp)\s+"),
            (0xFFFFFFF_0069_74404, r"ldr\s+\w+,\s*\[\w+,\s*#0x330\]"),
        ],
    },
    {
        "id": "mount_setup_csel_not_case5",
        "va": 0xFFFFFFF_0069_DBE84,
        "checks": [
            (0xFFFFFFF_0069_DBE84, r"ldr\s+\w+,\s*\[\w+,\s*#0x138\]"),
            (0xFFFFFFF_0069_DBE8C, r"csel\s+"),
            (0xFFFFFFF_0069_DBE90, r"ldr\s+\w+,\s*\[\w+,\s*#0xc0\]"),
        ],
    },
    {
        "id": "normal_mount_container_vol_sb_pair",
        "va": 0xFFFFFFF_0069_DAF34,
        "checks": [
            (0xFFFFFFF_0069_DAF34, r"str\s+\w+,\s*\[\w+,\s*#0xd0\]"),
            (0xFFFFFFF_0069_8727C, r"str\s+\w+,\s*\[\w+,\s*#0xc0\]"),
        ],
    },
    {
        "id": "nx_ro_to_rw_mu_gate",
        "va": 0xFFFFFFF_0069_878E8,
        "checks": [
            (0xFFFFFFF_0069_87974, r"(cmp|cbz|cbnz)\s+"),
            (0xFFFFFFF_0069_87D74, r"str\s+\w+,\s*\[\w+,\s*#0x13c\]"),
        ],
    },
    {
        "id": "vfs_iswriteupgrade",
        "va": 0xFFFFFFF_0073_73D58,
        "checks": [
            (0xFFFFFFF_0073_73D58, r"ldrb\s+\w+,\s*\[\w+,\s*#0x70\]"),
            (0xFFFFFFF_0073_73D6C, r"ubfx\s+\w+,\s*\w+,\s*#0x1a,\s*#1"),
        ],
    },
    {
        "id": "rootvnode_loader",
        "va": 0xFFFFFFF_0073_7577C,
        "checks": [
            (0xFFFFFFF_0073_7577C, r"adrp\s+"),
            (0xFFFFFFF_0073_75780, r"ldr\s+\w+,\s*\[\w+,\s*#"),
        ],
    },
]

KEY_STRINGS = [
    "handle_snapshot_mount",
    "handle_mount",
    "apfs_mount_update",
    "apfs_vfsop_mount",
    "revert_to_snapshot",
    "nx_ro_to_rw",
    "apfs_graft_mount_update_ro_to_rw",
    "com.apple.os.update-",
    "can't write-upgrade a snapshot mount",
    "fs_update_snap_vol_carefully",
    "mounting snapshot w/snap_xid",
    "unable to update mount as vol",
    "NXSB",
    "spaceman_reserve",
    "non writable nx dev",
    "nx_volume_group_update",
]

STRING_DISCOVERY_PATTERNS = [
    re.compile(r"apfs", re.I),
    re.compile(r"snapshot", re.I),
    re.compile(r"mount_update", re.I),
    re.compile(r"os\.update", re.I),
    re.compile(r"revert", re.I),
    re.compile(r"graft", re.I),
    re.compile(r"write-upgrade", re.I),
    re.compile(r"nx_ro", re.I),
    re.compile(r"nx_rw", re.I),
    re.compile(r"spaceman", re.I),
    re.compile(r"com\.apple\.os", re.I),
]

# ---------------------------------------------------------------------------
# Mach-O parsing
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int

    def contains_va(self, va: int) -> bool:
        return self.vmaddr <= va < self.vmaddr + self.vmsize

    def va_to_offset(self, va: int) -> Optional[int]:
        if not self.contains_va(va):
            return None
        return va - self.vmaddr + self.fileoff

    def offset_to_va(self, off: int) -> Optional[int]:
        if off < self.fileoff or off >= self.fileoff + self.filesize:
            return None
        return off - self.fileoff + self.vmaddr


@dataclasses.dataclass
class Section:
    name: str
    segname: str
    addr: int
    size: int
    offset: int


class MachOImage:
    LC_SEGMENT_64 = 0x19
    LC_SYMTAB = 0x2
    LC_DYSYMTAB = 0xB

    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        self.slice_off, self.slice_size = self._parse_fat()
        self.segments: list[Segment] = []
        self.sections: list[Section] = []
        self._parse_mach()
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

    def _parse_fat(self) -> tuple[int, int]:
        magic = struct.unpack(">I", self.raw[:4])[0]
        if magic != 0xCAFEBABE:
            return 0, len(self.raw)
        nfat = struct.unpack(">I", self.raw[4:8])[0]
        best = None
        for i in range(nfat):
            base = 8 + i * 20
            cputype, _, offset, size, _ = struct.unpack(">IIIII", self.raw[base : base + 20])
            if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                best = (offset, size)
                break
        if best is None:
            raise RuntimeError("no arm64 slice in fat binary")
        return best

    def _parse_mach(self) -> None:
        base = self.slice_off
        magic = struct.unpack("<I", self.raw[base : base + 4])[0]
        if magic != 0xFEEDFACF:
            raise RuntimeError(f"unexpected mach magic {magic:#x}")
        ncmds = struct.unpack("<I", self.raw[base + 16 : base + 20])[0]
        sizeofcmds = struct.unpack("<I", self.raw[base + 20 : base + 24])[0]
        _ = sizeofcmds  # reserved for future sanity checks
        pos = base + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", self.raw[pos : pos + 8])
            if cmd == self.LC_SEGMENT_64:
                if cmdsize < 72:
                    pos += cmdsize
                    continue
                segname = self.raw[pos + 8 : pos + 24].split(b"\0")[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack(
                    "<QQQQ", self.raw[pos + 24 : pos + 56]
                )
                self.segments.append(
                    Segment(segname, vmaddr, vmsize, fileoff, filesize)
                )
                if cmdsize < 68:
                    pos += cmdsize
                    continue
                nsects = struct.unpack("<I", self.raw[pos + 64 : pos + 68])[0]
                sect_pos = pos + 72
                for _s in range(nsects):
                    if sect_pos + 52 > len(self.raw):
                        break
                    sname = self.raw[sect_pos : sect_pos + 16].split(b"\0")[0].decode()
                    seg = self.raw[sect_pos + 16 : sect_pos + 32].split(b"\0")[0].decode()
                    addr, size, offset = struct.unpack(
                        "<QQI", self.raw[sect_pos + 32 : sect_pos + 52]
                    )
                    self.sections.append(Section(sname, seg, addr, size, offset))
                    sect_pos += 80
            pos += cmdsize

    def va_to_offset(self, va: int) -> Optional[int]:
        for seg in self.segments:
            o = seg.va_to_offset(va)
            if o is not None:
                return self.slice_off + o
        return None

    def read_va(self, va: int, size: int) -> Optional[bytes]:
        off = self.va_to_offset(va)
        if off is None:
            return None
        return self.raw[off : off + size]

    def disasm_at(self, va: int, count: int = 8) -> list[tuple[int, str, str]]:
        data = self.read_va(va, count * 4)
        if not data:
            return []
        out = []
        for ins in self.cs.disasm(data, va):
            out.append((ins.address, ins.mnemonic, ins.op_str))
        return out

    def insn_text(self, va: int) -> Optional[str]:
        d = self.disasm_at(va, 1)
        if not d:
            return None
        _, m, o = d[0]
        return f"{m} {o}".strip()

    def match_insn(self, va: int, pattern: str) -> bool:
        txt = self.insn_text(va)
        if txt is None:
            return False
        return re.search(pattern, txt, re.I) is not None

    def find_segment_for_va(self, va: int) -> Optional[str]:
        for s in self.segments:
            if s.contains_va(va):
                return s.name
        return None


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------
def iter_cstrings(data: bytes, min_len: int = 4) -> Iterator[tuple[int, str]]:
    i = 0
    n = len(data)
    while i < n:
        j = data.find(b"\0", i)
        if j == -1:
            break
        chunk = data[i:j]
        if len(chunk) >= min_len and all(32 <= c < 127 or c in (9, 10, 13) for c in chunk):
            try:
                yield i, chunk.decode("ascii")
            except UnicodeDecodeError:
                pass
        i = j + 1


def file_offset_to_va(img: MachOImage, file_off: int) -> Optional[int]:
    rel = file_off - img.slice_off
    for seg in img.segments:
        va = seg.offset_to_va(rel)
        if va is not None:
            return va
    for sec in img.sections:
        if sec.offset <= rel < sec.offset + sec.size:
            return sec.addr + (rel - sec.offset)
    return None


def scan_strings(img: MachOImage) -> dict[str, list[int]]:
    """Return string -> list of VAs (may be multiple copies)."""
    hits: dict[str, list[int]] = {}
    slice_data = img.raw[img.slice_off : img.slice_off + img.slice_size]
    for off, s in iter_cstrings(slice_data):
        abs_off = img.slice_off + off
        va = file_offset_to_va(img, abs_off)
        if va is None:
            continue
        hits.setdefault(s, []).append(va)
    return hits


def arm64_ldr_str_imm_offset(mnemonic: str, op: str) -> Optional[int]:
    m = re.search(r"#(0x[0-9a-f]+|\d+)", op, re.I)
    if not m:
        return None
    val = m.group(1)
    return int(val, 0) if val.lower().startswith("0x") else int(val)


def imm_matches(op: str, byte_offset: int) -> bool:
    """True if disasm operand immediate equals byte_offset (hex or decimal)."""
    imm = arm64_ldr_str_imm_offset("", op)
    if imm is None:
        return False
    return imm == byte_offset


def scan_apfs_offset_usage(img: MachOImage, va_lo: int, va_hi: int) -> dict[int, dict]:
    """Scan APFS VA range for LDR/STR with struct offsets we care about."""
    targets = {o.apfs_byte_off for o in KNOWN_APFS_OFFSETS}
    targets.update(o[1] for o in KNOWN_CONTAINER_OFFSETS)
    results: dict[int, dict] = {t: {"ldr": [], "str": []} for t in sorted(targets)}

    off = img.va_to_offset(va_lo)
    off_end = img.va_to_offset(va_hi - 4)
    if off is None or off_end is None:
        return results

    data = img.raw[off:off_end + 4]
    for ins in img.cs.disasm(data, va_lo):
        if ins.mnemonic not in ("ldr", "str", "ldrh", "ldrb", "strh", "strb"):
            continue
        matched = None
        for t in results:
            if imm_matches(ins.op_str, t):
                matched = t
                break
        if matched is None:
            continue
        entry = (ins.address, f"{ins.mnemonic} {ins.op_str}")
        kind = "str" if ins.mnemonic.startswith("str") else "ldr"
        results[matched][kind].append(entry)
    return results


def decode_adrp_add_target(img: MachOImage, va: int) -> Optional[int]:
    """If va is ADRP or ADRP+ADD pair start, return target VA."""
    insns = img.disasm_at(va, 2)
    if not insns:
        return None
    a0, m0, o0 = insns[0]
    if m0 != "adrp":
        return None
    m = re.match(r"(\w+),\s*#(0x[0-9a-f]+)", o0, re.I)
    if not m:
        return None
    rd = m.group(1)
    page = int(m.group(2), 16)
    if len(insns) < 2:
        return page
    _, m1, o1 = insns[1]
    if m1 != "add":
        return page
    m2 = re.match(rf"{rd},\s*{rd},\s*#(0x[0-9a-f]+|\d+)", o1, re.I)
    if not m2:
        return page
    lo = m2.group(1)
    add = int(lo, 0) if lo.lower().startswith("0x") else int(lo)
    return page + add


def find_string_xrefs(img: MachOImage, string_va: int, search_lo: int, search_hi: int) -> list[int]:
    """Find ADRP+ADD xrefs in [search_lo, search_hi) pointing at string_va."""
    xrefs = []
    off = img.va_to_offset(search_lo)
    off_end = img.va_to_offset(search_hi - 4)
    if off is None or off_end is None:
        return xrefs
    data = img.raw[off:off_end + 4]
    va = search_lo
    while va < search_hi - 4:
        insns = img.disasm_at(va, 2)
        if len(insns) >= 2 and insns[0][1] == "adrp":
            tgt = decode_adrp_add_target(img, va)
            if tgt is not None and abs(tgt - string_va) <= 4:
                xrefs.append(va)
        va += 4
    return xrefs


def find_bl_target(img: MachOImage, va: int) -> Optional[int]:
    insns = img.disasm_at(va, 1)
    if not insns or insns[0][1] != "bl":
        return None
    # capstone may show bl #0x...
    m = re.search(r"#(0x[0-9a-f]+)", insns[0][2], re.I)
    if m:
        return int(m.group(1), 16)
    # compute from opcode
    off = img.va_to_offset(va)
    if off is None:
        return None
    word = struct.unpack("<I", img.raw[off : off + 4])[0]
    imm26 = word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 |= ~0x03FFFFFF
    return va + (imm26 << 2)


def scan_str_x_to_offset(img: MachOImage, imm: int, va_lo: int, va_hi: int) -> list[tuple[int, str]]:
    """Find STR to struct offset `imm` — uses raw opcode filter + single-insn disasm (bulk cs.disasm desyncs in PLK)."""
    hits = []
    off = img.va_to_offset(va_lo)
    off_end = img.va_to_offset(va_hi - 4)
    if off is None or off_end is None:
        return hits
    raw = img.raw
    va = va_lo
    while va < va_hi:
        o = img.va_to_offset(va)
        if o is None:
            va += 4
            continue
        word = struct.unpack("<I", raw[o : o + 4])[0]
        # STR (64-bit, unsigned offset): base encoding 0xF9000000, imm12 = offset/8
        if (word & 0xFFC00000) == 0xF9000000:
            imm12 = ((word >> 10) & 0xFFF) * 8
            if imm12 == imm:
                txt = img.insn_text(va)
                if txt and txt.startswith("str") and ", [sp" not in txt.lower():
                    hits.append((va, txt))
        va += 4
    return hits


def rank_discovery_candidates(offset_usage: dict, str_xrefs: dict) -> list[str]:
    lines = []
    # vol list walk — high value if exploit doesn't implement
    vol_list = offset_usage.get(496, {})  # container+0x1F0 as ldr from container base? 
    # Actually 496 is decimal for container field; in APFS scan we used apfs offsets
    # container+0x1F0 = 496 — check 496 in results from scan which uses KNOWN set

    c330 = offset_usage.get(816, {})
    c138 = offset_usage.get(312, {})
    c_d8 = offset_usage.get(216, {})

    if c330.get("ldr"):
        lines.append(
            f"HIGH: APFS+0x330 (vol list next) has {len(c330['ldr'])} LDR sites — "
            f"enables container vol-list child discovery (IDA revert_to_snapshot @ 0x974404)"
        )
    if c138.get("str"):
        lines.append(
            f"HIGH: APFS+0x138 has {len(c138['str'])} STR sites on disk — "
            f"only child→outer expected; enumerate to find if outer→child ever set"
        )
    if c_d8.get("str"):
        lines.append(
            f"MED: APFS+0xD8 vol **name string** on snapshot child — {len(c_d8['str'])} STR "
            f"(strdup @ 0x9e017c); case5 reads vol_sb at fsprivate+0xC0 not +0xD8"
        )
    if str_xrefs.get("fs_update_snap_vol_carefully"):
        lines.append(
            "MED: fs_update_snap_vol_carefully string xrefs — snap link maintenance path"
        )
    if str_xrefs.get("nx_volume_group_update"):
        lines.append(
            "MED: nx_volume_group_update — handle_mount failure path @ 0x9e0c84"
        )
    return lines


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
class Report:
    def __init__(self):
        self.lines: list[str] = []

    def h1(self, t: str) -> None:
        self.lines.extend(["", "=" * 78, t, "=" * 78])

    def h2(self, t: str) -> None:
        self.lines.extend(["", "-" * 60, t, "-" * 60])

    def p(self, t: str = "") -> None:
        self.lines.append(t)

    def write(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def run_probe(kernel_path: Path, out_path: Path) -> int:
    img = MachOImage(kernel_path)
    r = Report()
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    r.h1("BUILD65 KERNELCACHE FORENSIC PROBE")
    r.p(f"Generated: {now}")
    r.p(f"Binary:    {kernel_path}")
    r.p(f"Size:      {len(img.raw):,} bytes (slice {img.slice_size:,} @ +{img.slice_off:#x})")
    r.p(f"Image ref: __TEXT vmaddr = {IMAGE_BASE:#x}")
    r.p("Method:    Mach-O parse + Capstone ARM64 disasm on raw file bytes")
    r.p("Rule:      ON_DISK facts only; NEW items require IDA MCP follow-up")

    r.h2("SEGMENTS (VA ↔ file mapping)")
    for seg in img.segments:
        r.p(
            f"  {seg.name:18} vmaddr={seg.vmaddr:#x} size={seg.vmsize:#x} "
            f"fileoff={seg.fileoff:#x} filesz={seg.filesize:#x}"
        )

    apfs_seg = img.find_segment_for_va(0xFFFFFFF_006A_27314)
    r.p(f"\n  apfs_mount_update @ {0xFFFFFFF_006A_27314:#x} → segment **{apfs_seg}**")

    # --- Known site verification ---
    r.h2("KNOWN SITE VERIFICATION (registry vs on-disk disasm)")
    confirmed = 0
    failed = 0
    for site in KNOWN_SITES:
        r.p(f"\n[{site['id']}] anchor {site['va']:#x} ({img.find_segment_for_va(site['va'])})")
        for check_va, pat in site["checks"]:
            txt = img.insn_text(check_va)
            ok = img.match_insn(check_va, pat)
            status = "CONFIRMED" if ok else "MISMATCH"
            if ok:
                confirmed += 1
            else:
                failed += 1
            r.p(f"  {status} {check_va:#x}: {txt or '<no bytes>'}")
            if not ok:
                r.p(f"           expected pattern: /{pat}/")
    r.p(f"\nSite checks: {confirmed} CONFIRMED, {failed} MISMATCH")

    # --- BL target verification (case5 → apfs_mount_update) ---
    r.h2("CALL GRAPH EDGES (BL targets, on-disk)")
    bl_cases = [
        ("case5_apfs_mount_update", 0xFFFFFFF_0069_DA970),
        ("handle_snapshot_handle_mount", 0xFFFFFFF_0069_E0634),
    ]
    for name, va in bl_cases:
        tgt = find_bl_target(img, va)
        txt = img.insn_text(va)
        r.p(f"  {name}: {va:#x}  {txt}")
        r.p(f"    → BL target {tgt:#x}" if tgt else "    → BL target UNKNOWN")

    # --- Strings ---
    r.h2("KEY STRINGS (on-disk VA)")
    all_strings = scan_strings(img)
    str_xrefs_map: dict[str, list[int]] = {}
    for ks in KEY_STRINGS:
        vas = []
        for s, addrs in all_strings.items():
            if ks in s:
                vas.extend(addrs)
        vas = sorted(set(vas))
        r.p(f"  '{ks}': {len(vas)} hit(s)")
        for va in vas[:5]:
            seg = img.find_segment_for_va(va)
            r.p(f"    {va:#x}  ({seg})")
            xrefs = find_string_xrefs(img, va, APFS_VA_LO, APFS_VA_HI)
            if xrefs:
                str_xrefs_map[ks] = xrefs
                for x in xrefs[:8]:
                    r.p(f"      xref adrp@ {x:#x}  {img.insn_text(x)}")

    # --- String discovery (broader) ---
    r.h2("STRING DISCOVERY (APFS/remount related, not in KEY_STRINGS)")
    discovered_strings: list[tuple[str, int]] = []
    key_set = set(KEY_STRINGS)
    for s, addrs in all_strings.items():
        if any(p.search(s) for p in STRING_DISCOVERY_PATTERNS):
            if not any(k in s for k in key_set):
                for va in addrs:
                    discovered_strings.append((s[:120], va))
    discovered_strings.sort(key=lambda x: x[1])
    r.p(f"  Found {len(discovered_strings)} additional string instance(s)")
    seen = set()
    for s, va in discovered_strings[:80]:
        if s in seen:
            continue
        seen.add(s)
        r.p(f"    {va:#x}  {repr(s)}")

    # --- Offset usage in APFS range ---
    r.h2("APFS MODULE OFFSET USAGE (__PLK_TEXT_EXEC APFS VA band)")
    r.p(f"  Scan range: {APFS_VA_LO:#x} – {APFS_VA_HI:#x}")
    usage = scan_apfs_offset_usage(img, APFS_VA_LO, APFS_VA_HI)

    r.p("\n  Known APFS struct offsets (exploit registry):")
    for ko in KNOWN_APFS_OFFSETS:
        u = usage.get(ko.apfs_byte_off, {"ldr": [], "str": []})
        expl = "IN_EXPLOIT" if ko.in_exploit else "NOT_IN_EXPLOIT"
        r.p(
            f"    {ko.name:28} +{ko.hex_off} ({ko.apfs_byte_off:4})  "
            f"LDR={len(u['ldr']):4} STR={len(u['str']):4}  [{expl}]  IDA: {ko.ida_ref}"
        )

    r.p("\n  Top LDR sites for exploit-critical offsets:")
    for off in (208, 192, 312, 692, 248, 816, 728, 216):
        u = usage.get(off, {"ldr": [], "str": []})
        r.p(f"\n    offset +{off:#x} ({off}) — {len(u['ldr'])} LDR, {len(u['str'])} STR")
        for va, txt in u["ldr"][:6]:
            r.p(f"      LDR {va:#x}  {txt}")
        for va, txt in u["str"][:6]:
            r.p(f"      STR {va:#x}  {txt}")

    # --- STR to +0x138 full APFS scan (outer←child question) ---
    r.h2("DISCOVERY: ALL STR APFS+0x138 IN APFS BAND")
    str138 = scan_str_x_to_offset(img, 0x138, APFS_VA_LO, APFS_VA_HI)
    r.p(f"  Total STR [*, #0x138] sites: {len(str138)}")
    for va, txt in str138:
        r.p(f"    {va:#x}  {txt}")

    # --- STR to +0xD0 (container assign) ---
    r.h2("DISCOVERY: ALL STR APFS+0xD0 IN APFS BAND (container link)")
    str_d0 = scan_str_x_to_offset(img, 0xD0, APFS_VA_LO, APFS_VA_HI)
    r.p(f"  Total STR [*, #0xD0] sites: {len(str_d0)}")
    for va, txt in str_d0:
        r.p(f"    {va:#x}  {txt}")

    # --- Gap analysis ---
    r.h2("GAP ANALYSIS — KNOWN vs UNKNOWN vs ON-DISK PROOF")
    gaps_known_proven = []
    gaps_known_unproven = []
    gaps_not_in_exploit = []

    for ko in KNOWN_APFS_OFFSETS:
        u = usage.get(ko.apfs_byte_off, {"ldr": [], "str": []})
        has_code = bool(u["ldr"] or u["str"])
        if has_code:
            gaps_known_proven.append(ko.name)
        else:
            gaps_known_unproven.append(ko.name)
        if not ko.in_exploit and has_code:
            gaps_not_in_exploit.append(ko.name)

    r.p("  KNOWN + ON-DISK code references:")
    r.p(f"    {', '.join(gaps_known_proven) or '(none)'}")
    r.p("  KNOWN but NO LDR/STR in APFS band (may be elsewhere or struct-only):")
    r.p(f"    {', '.join(gaps_known_unproven) or '(none)'}")
    r.p("  ON-DISK proven but NOT_IN_EXPLOIT (build boost candidates):")
    for name in gaps_not_in_exploit:
        ko = next(k for k in KNOWN_APFS_OFFSETS if k.name == name)
        u = usage[ko.apfs_byte_off]
        r.p(
            f"    ★ {name} (+{ko.hex_off}): LDR={len(u['ldr'])} STR={len(u['str'])} — {ko.ida_ref}"
        )

    # --- Ranked discoveries ---
    r.h2("RANKED BUILD BOOST CANDIDATES (on-disk evidence)")
    candidates = rank_discovery_candidates(usage, str_xrefs_map)
    if not candidates:
        r.p("  (none ranked — see STR/LDR dumps above)")
    for c in candidates:
        r.p(f"  ★ {c}")

    r.p("\n  Actionable paths NOT yet in build64 exploit code:")
    r.p("    1. Walk container+0x1F0 vol list via apfs+0x330 (revert_to_snapshot @ 0x9743dc)")
    r.p("    2. Reverse-find child: scan list for apfs+0x138 == outer")
    r.p("    3. Link-fix: copy child+0xC0 vol_sb to outer+0xC0 (NOT +0xD8 — that slot is volname string)")
    r.p("    4. Container+0x13C mu_gate clear path (nx_ro_to_rw @ 0x987d74)")
    r.p("    5. fs_update_snap_vol_carefully @ 0xa1e91c — snap link repair")

    # --- Bytes hash spot check ---
    r.h2("BYTE IDENTITY SPOT CHECKS")
    spots = [
        ("apfs_mount_update prologue", 0xFFFFFFF_006A_27314, 16),
        ("case5 snap block", 0xFFFFFFF_0069_DA638, 8),
        ("handle_snapshot STR +0x138", 0xFFFFFFF_0069_E0154, 4),
    ]
    for label, va, n in spots:
        b = img.read_va(va, n)
        if b:
            r.p(f"  {label} @ {va:#x}: {b.hex()}")
        else:
            r.p(f"  {label} @ {va:#x}: UNMAPPED")

    # --- Summary footer ---
    r.h2("VERIFICATION STATUS SUMMARY")
    r.p(f"  Known IDA sites checked:     {len(KNOWN_SITES)} groups")
    r.p(f"  Instruction checks passed:   {confirmed}")
    r.p(f"  Instruction checks failed:   {failed}")
    r.p(f"  Key strings indexed:         {len(KEY_STRINGS)}")
    r.p(f"  STR +0x138 sites (APFS):     {len(str138)}")
    r.p(f"  STR +0xD0 sites (APFS):      {len(str_d0)}")
    r.p("")
    r.p("  NEXT STEP: Agent verifies NEW/MISMATCH entries via IDA Pro MCP,")
    r.p("  then updates BUILD65_IDA_TRACE.md with ON_DISK_CONFIRMED tags.")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    r.write(out_path)
    print(f"Wrote {out_path} ({len(r.lines)} lines)")
    return 1 if failed else 0


def main() -> None:
    ap = argparse.ArgumentParser(description="BUILD65 kernelcache forensic probe")
    ap.add_argument(
        "-k",
        "--kernel",
        type=Path,
        default=DEFAULT_KERNEL,
        help=f"Path to kernelcache Mach-O (default: {DEFAULT_KERNEL})",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output report path (default: {DEFAULT_OUT})",
    )
    args = ap.parse_args()
    if not args.kernel.is_file():
        print(f"ERROR: kernel not found: {args.kernel}", file=sys.stderr)
        sys.exit(2)
    rc = run_probe(args.kernel, args.output)
    sys.exit(rc)


if __name__ == "__main__":
    main()
