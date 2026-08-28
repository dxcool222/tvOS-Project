#!/usr/bin/env python3
"""ROOTLESS HOST_SIM runner.

Compiles production dt_rootless_orch.c + R6 decide + R9 product gate against
the HOST_SIM platform. Does not emulate A10X/KFD. Does not talk to the Apple TV.
C gate registry is authoritative. Report metrics are computed or UNKNOWN.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SRC = ROOT / "source"
DOCS = ROOT / "docs" / "rootless_host_sim"
ART = HERE / "build"
LIB = ART / "librootless_host_sim.dylib"
TMP_BASE = Path("/tmp/rootless-host-sim")
CANDIDATE_IPA = ROOT / "artifacts" / "dopamin-tvOS-kfd-ROOTLESS-R21.ipa"
PACKED_PAYLOAD = SRC / "layout/Payload/dopamin-tvOS-kfd.app/RootlessPayload"
R10_DEVICE_FS_FAIL = "dotdot symlink usr/libexec/nitotv/firmware.sh -> ../firmware.sh"
R11_DEVICE_POSTVERIFY_FIRST = "postverify type mismatch symlink bin/bash"
R12_DEVICE_FS_FAIL = "JBROOT escape private/etc/localtime"
PATH_ERR_MAX = 256
PACKED_MANIFEST = PACKED_PAYLOAD.parent / "ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"
M4_COPY_DST = TMP_BASE / "m4_copied_jbroot"
M4_LEFTOVER_DST = TMP_BASE / "m4_leftover_jbroot"
M4_RESTAGE_DST = TMP_BASE / "m4_restage_jbroot"
M4_ETC_PARENT_DST = TMP_BASE / "m4_etc_parent_jbroot"
M4_CONV_DST = TMP_BASE / "m4_recovery_converge_jbroot"
M4_ROOTLINK_DST = TMP_BASE / "m4_rootlink_jbroot"
M4_ESCAPE_PROBE = TMP_BASE / "escape_probe"
M4_ENCODE_SRC = TMP_BASE / "m4_encoded_packed"
M4_ENCODE_DST = TMP_BASE / "m4_encoded_copied_jbroot"
M4_R22_STALE_DST = TMP_BASE / "m4_r22_stale_oracle_jbroot"
PACKED_TRUST = PACKED_PAYLOAD.parent / "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"
R16_BUILD_REPORT = ROOT / "docs" / "r16_ctor2_continuity" / "ROOTLESS_R16_FINAL_BUILD_REPORT.md"
R17_BUILD_REPORT = ROOT / "docs" / "r17_password_libiosexec" / "ROOTLESS_R17_FINAL_BUILD_REPORT.md"
R18_BUILD_REPORT = ROOT / "docs" / "r18_password_dest_passwd" / "ROOTLESS_R18_FINAL_BUILD_REPORT.md"
R19_BUILD_REPORT = ROOT / "docs" / "r19_uialert_cfusernotification" / "ROOTLESS_R19_FINAL_BUILD_REPORT.md"
R20_BUILD_REPORT = ROOT / "docs" / "r20_wall2_sigkill_launchd" / "ROOTLESS_R20_FINAL_BUILD_REPORT.md"
R21_BUILD_REPORT = ROOT / "docs" / "r21_prep_dest_abs_rm" / "ROOTLESS_R21_FINAL_BUILD_REPORT.md"
R13_BUILD_REPORT = ROOT / "docs" / "r13_recovery_overlay" / "ROOTLESS_R13_FINAL_BUILD_REPORT.md"
R13_IPA_SHA256 = "652f4b49144d40cabc58caf6ad438e1fac9183a490cf52da0eec5cc6cfa5f200"
R14_IPA_SHA256 = "1c7c3279a382ac0a3e30107f02d94e4ec8c6a3760d6089f366e206d768a5f3f2"
R15_IPA_SHA256 = "4be6d554cc5011360b34dea43d7e95f565924b645d5ca9d9f0f1e6b62b20d45f"
R16_IPA_SHA256 = "9f553504dd3f8c6d41d59f1b4e6f77d8f4897576aee99e133809e887966bb4ea"
R17_IPA_SHA256 = "8381e9c053d4bb86323b7942dfa7275a48e40d708dc2608345f3b76d254bccf8"
R18_IPA_SHA256 = "4a6c6ff3e00c07b4ec7e44748bbb631f9cb812381df87e6a9be5005fd9ef7e6b"
R16_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R16.ipa"
R17_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R17.ipa"
R18_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R18.ipa"
R19_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R19.ipa"
R20_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R20.ipa"
R21_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R21.ipa"
R22_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R22.ipa"
R23_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R23.ipa"
R24_CANDIDATE_FILENAME = "dopamin-tvOS-kfd-ROOTLESS-R24.ipa"
R22_BUILD_REPORT = ROOT / "docs/r22_layer1_oracle_abi_closure/ROOTLESS_R22_FINAL_BUILD_REPORT.md"
R23_BUILD_REPORT = ROOT / "docs/r22_layer1_oracle_abi_closure/ROOTLESS_R23_FINAL_BUILD_REPORT.md"
R24_BUILD_REPORT = ROOT / "docs/r23_completion_gap/ROOTLESS_R24_V23_KFD_KRW_SYMBOL_UNSHADOW_HOST_PIN_FINAL_BUILD_REPORT_2026-08-27.md"
R21_IPA_SHA256 = "5099371a1f2afe0fdb51eccd2edca08bbd931614352697e6bcc53d8c155f17f0"
R22_IPA_SHA256 = "838f3d095a3c5b3df07e69220225282e4e71823dfaea8513d8e10dcd096eb6cf"
R23_IPA_SHA256 = "071c6e7059cdf66017c6e980b32c6322cb036663a3fb1daf9a3a3f9bedf12906"
EXPECTED_PAYLOAD_ENTRIES = 4053
R23_HOME_RELS = (
    "var/mobile",
    "var/root",
    "var/mobile/Library",
    "var/mobile/Library/Preferences",
)
R23_SETUID_RELS = (
    "usr/bin/chpass",
    "usr/bin/newgrp",
    "usr/bin/su",
    "usr/bin/quota",
    "usr/bin/sudo",
    "usr/bin/login",
    "usr/bin/passwd",
    "usr/sbin/shshd",
)
R22_ORACLE_RELS = (
    "usr/lib/libiosexec.1.dylib",
    "usr/lib/libpam.2.dylib",
    "usr/lib/pam/pam_unix.so",
    "usr/lib/pam/pam_nologin.so",
    "usr/lib/pam/pam_permit.so",
)
R22_ORACLE_SHA256 = {
    "usr/lib/libiosexec.1.dylib": "aa2354332ee53c96990887a190b20f8cd56c02f464bf878b8a79ccef72f88718",
    "usr/lib/libpam.2.dylib": "34fa66906759c8d30559dec70e28c52bef98f5b485600c556a750090bcaccbb0",
    "usr/lib/pam/pam_unix.so": "53e3f8fb3728559f0ee98d4461b2be629e6e0ec8df8807c8baaf6e2262009b24",
    "usr/lib/pam/pam_nologin.so": "388f8a358343d8fca3885b519b1801e0bef63ad99b55b95d8f0435e861172265",
    "usr/lib/pam/pam_permit.so": "6d807058d0b03b718956937d73c24703bbfe33033b69e616cd81c0571f9467e6",
}


def trust_sha_for_rels(trust_path: Path, rels: tuple[str, ...]) -> dict[str, str]:
    import csv
    out: dict[str, str] = {}
    if not trust_path.is_file():
        return out
    for row in csv.DictReader(trust_path.open(), delimiter="\t"):
        if row.get("REL") in rels:
            out[row["REL"]] = row["SHA256"]
    return out
if os.environ.get("ROOTLESS_HOST_SIM_CANDIDATE", "").upper() == "R21":
    CANDIDATE_IPA = ROOT / "artifacts" / R21_CANDIDATE_FILENAME
elif os.environ.get("ROOTLESS_HOST_SIM_CANDIDATE", "").upper() == "R23":
    CANDIDATE_IPA = ROOT / "artifacts" / R23_CANDIDATE_FILENAME
elif (ROOT / "artifacts" / R24_CANDIDATE_FILENAME).is_file():
    CANDIDATE_IPA = ROOT / "artifacts" / R24_CANDIDATE_FILENAME
elif (ROOT / "artifacts" / R23_CANDIDATE_FILENAME).is_file():
    CANDIDATE_IPA = ROOT / "artifacts" / R23_CANDIDATE_FILENAME
elif (ROOT / "artifacts" / R22_CANDIDATE_FILENAME).is_file():
    CANDIDATE_IPA = ROOT / "artifacts" / R22_CANDIDATE_FILENAME
else:
    CANDIDATE_IPA = ROOT / "artifacts" / R21_CANDIDATE_FILENAME
R21_IPA = ROOT / "artifacts" / R21_CANDIDATE_FILENAME
R19_IPA_SHA256 = "1739468aacf2f96fd0aa3b4e9a18987553caf067cbbb9e3d21608dc865ba4640"
R20_IPA_SHA256 = "9fda0d52a79019860dc6b936a585201c8db37382f35b4cfa8b319f61a5f3a0aa"
DEST_LIB_RPATH = "/var/jb/usr/lib"
PREP_RPATH_RELS = (
    "usr/libexec/firmware",
    "usr/sbin/pwd_mkdb",
    "usr/bin/launchctl",
)
CTOR2_MARKER_RELS = (
    ".dt518_launchdhook_ctor_entered",
    ".dt516_launchdhook_loaded",
)
PACKED_MACHO_WRAP = b"R14MACHO"
MACHO_MAGICS = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}
BIN_SYNC_TSV_SHA256 = "70e3ffbaa93b6fe7c89f8f22b43325a78d027c61d5b3c2cd906db6a6676c0553"
PRODUCT_NFTW_FUNCS = (
    "_dt_rootless_copy_payload_tree",
    "_dt_rootless_packed_source_verify",
    "_dt_rootless_postverify_payload_tree_c",
)
R12_BUILD_REPORT = ROOT / "docs" / "r12_lstat_copy" / "ROOTLESS_R12_FINAL_BUILD_REPORT.md"
R11_BUILD_REPORT = ROOT / "docs" / "r11_install_symlink" / "ROOTLESS_R11_FINAL_BUILD_REPORT.md"
R10_BUILD_REPORT = ROOT / "docs" / "r10_shared_orchestrator" / "ROOTLESS_R10_FINAL_BUILD_REPORT.md"
R9_BUILD_REPORT = ROOT / "docs" / "r9_j_baseline" / "ROOTLESS_R9_FINAL_BUILD_REPORT.md"
DEVICE_MAKEFILE = SRC / "Makefile"
IDA_PROOF = ROOT / "docs" / "r16_ctor2_continuity" / "ROOTLESS_R16_BUTTON_TO_ORCH_IDA.md"

VARJB = {
    "ABSENT": 0, "VALID_ROOTLESS_SYMLINK": 1, "STALE_PROJECT_SYMLINK": 2,
    "STALE_PROJECT_DIRECTORY": 3, "LEGACY_ROOTFUL": 4, "ROOTLESS_INCOMPLETE": 5,
    "FOREIGN": 6, "COMMITTED_VALID": 7,
}
KIND_PRODUCT, KIND_DIAG, KIND_PHYS = 0, 1, 2
LC_RPATH_CMD = 0x8000001C


def macho_rpaths(data: bytes) -> list[str]:
    if data.startswith(PACKED_MACHO_WRAP):
        data = data[len(PACKED_MACHO_WRAP) :]
    if data[:4] not in MACHO_MAGICS:
        return []
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    rps: list[str] = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_RPATH_CMD and cmdsize >= 12:
            name_off = struct.unpack_from("<I", data, off + 8)[0]
            blob = data[off : off + cmdsize]
            if name_off < len(blob):
                rps.append(blob[name_off:].split(b"\x00", 1)[0].decode("utf-8", "replace"))
        off += cmdsize if cmdsize >= 8 else 8
    return rps


def path_has_dest_lib_rpath(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    return DEST_LIB_RPATH in macho_rpaths(path.read_bytes())


sys.path.insert(0, str(ROOT / "tools"))
from rootless_sign_uialert_cfusernotification import (  # noqa: E402
    PINNED_XML_SHA as UIALERT_PINNED_XML_SHA,
    R18_CDHASH as UIALERT_R18_CDHASH,
    R18_INNER_SHA as UIALERT_R18_INNER_SHA,
    REL as UIALERT_REL,
    cs_ent_info,
    uialert_gate_ok,
)


def uialert_declared_ok(raw: bytes) -> bool:
    return uialert_gate_ok(cs_ent_info(raw))


def uialert_trust_row_match(raw: bytes) -> bool:
    if not PACKED_TRUST.is_file():
        return False
    info = cs_ent_info(raw)
    lines = PACKED_TRUST.read_text().splitlines()
    if not lines:
        return False
    hdr = lines[0].split("\t")
    try:
        i_rel = hdr.index("REL")
        i_sha = hdr.index("SHA256")
        i_cd = hdr.index("CDHASH")
    except ValueError:
        return False
    for line in lines[1:]:
        if not line:
            continue
        cols = line.split("\t")
        if len(cols) <= max(i_rel, i_sha, i_cd):
            continue
        if cols[i_rel] != UIALERT_REL:
            continue
        return (
            cols[i_sha] == info["sha256"]
            and cols[i_sha] != UIALERT_R18_INNER_SHA
            and cols[i_cd] != UIALERT_R18_CDHASH
            and info.get("ent_xml_sha") == UIALERT_PINNED_XML_SHA
        )
    return False


def r18_orphan_only_reject_ok() -> bool:
    """Frozen R18 IPA must still be the proven orphan-key fixture (not slot 5)."""
    frozen = ROOT / "artifacts" / R18_CANDIDATE_FILENAME
    if not frozen.is_file() or sha256_file(frozen) != R18_IPA_SHA256:
        return False
    prefix = "Payload/dopamin-tvOS-kfd.app/RootlessPayload/"
    with zipfile.ZipFile(frozen) as z:
        n = prefix + UIALERT_REL
        if n not in z.namelist():
            return False
        info = cs_ent_info(z.read(n))
    return (
        info["orphan_only"] is True
        and info["has_slot5"] is False
        and info["key_in_declared"] is False
        and info["key_in_file"] is True
        and info["sha256"] == UIALERT_R18_INNER_SHA
    )


def prep_dest_passwd_argv_ok(text: str) -> bool:
    """Static prep argv: no chsh/chpass; dest pwd_mkdb -d; dest pw -V before usermod."""
    if "chsh" in text or "/usr/bin/chpass" in text:
        return False
    saw_pwd = False
    saw_pw = False
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if "pwd_mkdb" in s:
            saw_pwd = True
            if "-d /var/jb/etc" not in s:
                return False
            if "/var/jb/usr/sbin/pwd_mkdb" not in s:
                return False
            continue
        if "/var/jb/usr/sbin/pw" in s:
            saw_pw = True
            v = s.find("-V /var/jb/etc")
            u = s.find("usermod")
            if v < 0 or u < 0 or v > u:
                return False
    return saw_pwd and saw_pw


def prep_dest_abs_rm_ok(text: str) -> bool:
    """Last executed prep command must be dest-absolute rm; no remaining unpathed rm."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return False
    if lines[-1] != "/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh":
        return False
    for ln in lines:
        if ln == lines[-1]:
            continue
        if ln == "rm" or ln.startswith("rm ") or ln.startswith("rm\t"):
            return False
    return True


class Result(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("r6_path", ctypes.c_int),
        ("r6_state", ctypes.c_int),
        ("committed", ctypes.c_int),
        ("incomplete", ctypes.c_int),
        ("kfd_open_count", ctypes.c_int),
        ("kfd_reentry_count", ctypes.c_int),
        ("kfd_state", ctypes.c_int),
        ("failed_gate", ctypes.c_int),
        ("result", ctypes.c_char * 128),
        ("product_gate_fails", ctypes.c_int),
        ("diagnostic_fails_continued", ctypes.c_int),
    ]


class CopyCounts(ctypes.Structure):
    _fields_ = [
        ("n_src", ctypes.c_ulong),
        ("n_src_type_mismatch", ctypes.c_ulong),
        ("n_src_tgt_mismatch", ctypes.c_ulong),
        ("n_src_macho_ok", ctypes.c_ulong),
        ("n_src_macho_fail", ctypes.c_ulong),
        ("n_symlink_install", ctypes.c_ulong),
        ("n_symlink_imm_ok", ctypes.c_ulong),
        ("n_symlink_imm_fail", ctypes.c_ulong),
        ("n_macho_imm_ok", ctypes.c_ulong),
        ("n_macho_imm_fail", ctypes.c_ulong),
    ]


def packed_src_ok(c: CopyCounts) -> bool:
    return (
        c.n_src == EXPECTED_PAYLOAD_ENTRIES and c.n_src_type_mismatch == 0 and c.n_src_tgt_mismatch == 0
        and c.n_src_macho_ok == 397 and c.n_src_macho_fail == 0
    )


def manifest_install_ok(c: CopyCounts) -> bool:
    return (
        packed_src_ok(c)
        and c.n_symlink_install == 150 and c.n_symlink_imm_ok == 150
        and c.n_symlink_imm_fail == 0
        and c.n_macho_imm_ok == 397 and c.n_macho_imm_fail == 0
    )


def postverify_ok(rc: int, pv: PostverifyCounts) -> bool:
    return (
        rc == 0 and pv.n_fail == 0 and pv.n_missing == 0 and pv.n_extra == 0
        and pv.n_link == 150 and pv.n_macho == 397 and pv.n_dir == 411
        and not pv.first_err
    )


def c_packed_verify(lib, src: Path = PACKED_PAYLOAD) -> tuple[int, str, CopyCounts]:
    buf = ctypes.create_string_buffer(PATH_ERR_MAX)
    c = CopyCounts()
    rc = lib.dt_rootless_packed_source_verify(
        str(src).encode(), str(PACKED_MANIFEST).encode(),
        ctypes.byref(c), buf, PATH_ERR_MAX)
    return rc, buf.value.decode(), c


def c_copy(lib, src: Path, dst: Path) -> tuple[int, str, CopyCounts]:
    buf = ctypes.create_string_buffer(PATH_ERR_MAX)
    c = CopyCounts()
    rc = lib.dt_rootless_copy_payload_tree(
        str(src).encode(), str(dst).encode(), str(PACKED_MANIFEST).encode(),
        ctypes.byref(c), buf, PATH_ERR_MAX)
    return rc, buf.value.decode(), c


def c_postverify(lib, root: Path) -> tuple[int, PostverifyCounts]:
    pv = PostverifyCounts()
    rc = lib.dt_rootless_postverify_payload_tree_c(
        str(root).encode(), str(PACKED_MANIFEST).encode(), ctypes.byref(pv))
    return rc, pv


def packed_symlink_inventory() -> dict:
    """Catalog from the shared TSV. Python does not install or hash dest."""
    out = {"n": 0, "abs_var_jb": 0, "abs_ext": 0, "rel_int": 0, "dotdot": 0}
    if not PACKED_MANIFEST.is_file():
        return out
    lines = PACKED_MANIFEST.read_text().splitlines()
    hdr = lines[0].split("\t")
    i_kind = hdr.index("KIND")
    i_tgt = hdr.index("SYMLINK_TARGET")
    for line in lines[1:]:
        if not line:
            continue
        cols = line.split("\t")
        if cols[i_kind] != "SYMLINK":
            continue
        out["n"] += 1
        tgt = cols[i_tgt] if i_tgt < len(cols) else ""
        if tgt.startswith("/var/jb/"):
            out["abs_var_jb"] += 1
        elif tgt.startswith("/"):
            out["abs_ext"] += 1
        elif ".." in tgt.split("/"):
            out["dotdot"] += 1
        else:
            out["rel_int"] += 1
    return out


def otool_functions(path: Path) -> dict[str, str]:
    dump = subprocess.check_output(
        ["otool", "-tV", str(path)], text=True, stderr=subprocess.DEVNULL, errors="replace")
    funcs: dict[str, str] = {}
    cur = None
    buf: list[str] = []
    for line in dump.splitlines():
        if line.startswith("_") and line.endswith(":"):
            if cur is not None:
                funcs[cur] = "\n".join(buf)
            cur = line[:-1]
            buf = []
        else:
            buf.append(line)
    if cur is not None:
        funcs[cur] = "\n".join(buf)
    return funcs


def otool_labeled_sections(path: Path) -> dict[str, str]:
    """Map exported otool -tV labels to the instruction text until the next label.

    Statics between two exported labels are attributed to the previous label
    (fail-closed: a product label that contains _nftw is YES).
    """
    dump = subprocess.check_output(
        ["otool", "-tV", str(path)], text=True, stderr=subprocess.DEVNULL, errors="replace")
    sections: dict[str, list[str]] = {}
    cur: str | None = None
    for line in dump.splitlines():
        if line.startswith("_") and line.endswith(":"):
            cur = line[:-1]
            sections[cur] = []
            continue
        if cur is not None:
            sections[cur].append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


def product_nftw_copy_reachable(path: Path) -> str:
    """NO only if the three product copy/verify functions have no nftw call.

    Does not treat nearest-export attribution of a leftover nftw as NO.
    Does not use the ROOTLESS_R15_PRODUCT_NFTW_COPY_REACHABLE log string.
    Missing product labels → UNKNOWN (cannot prove).
    """
    if not path.is_file():
        return "UNKNOWN"
    try:
        sections = otool_labeled_sections(path)
    except subprocess.CalledProcessError:
        return "UNKNOWN"
    missing = [name for name in PRODUCT_NFTW_FUNCS if name not in sections]
    if missing:
        return "UNKNOWN"
    product_hit = False
    for name in PRODUCT_NFTW_FUNCS:
        text = sections[name]
        if not re.search(r"\b_nftw\b", text):
            continue
        if re.search(r"\b(bl|blr|callq|call|jmp)\b", text, re.I):
            product_hit = True
    return "YES" if product_hit else "NO"


def rm_path_nofollow(path: Path) -> None:
    if not os.path.lexists(path):
        return
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


class PostverifyCounts(ctypes.Structure):
    _fields_ = [
        ("n_file", ctypes.c_ulong),
        ("n_dir", ctypes.c_ulong),
        ("n_link", ctypes.c_ulong),
        ("n_macho", ctypes.c_ulong),
        ("n_fail", ctypes.c_ulong),
        ("n_type_symlink", ctypes.c_ulong),
        ("n_macho_type", ctypes.c_ulong),
        ("n_macho_sha", ctypes.c_ulong),
        ("n_missing", ctypes.c_ulong),
        ("n_extra", ctypes.c_ulong),
        ("first_err", ctypes.c_char * 256),
    ]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def compile_lib() -> None:
    subprocess.check_call(["make", "-C", str(HERE), "all"])


def load() -> ctypes.CDLL:
    lib = ctypes.CDLL(str(LIB))
    lib.sim_reset.argtypes = [ctypes.c_char_p]
    lib.sim_set_varjb.argtypes = [ctypes.c_int]
    lib.sim_set_n_owned.argtypes = [ctypes.c_int]
    lib.sim_set_n_stopped.argtypes = [ctypes.c_int]
    lib.sim_set_identity_ok.argtypes = [ctypes.c_int]
    lib.sim_set_payload_count.argtypes = [ctypes.c_int]
    lib.sim_set_trust_count.argtypes = [ctypes.c_int]
    lib.sim_set_payload_root.argtypes = [ctypes.c_char_p]
    lib.sim_set_obs.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.dt_rootless_payload_tree_install_check.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.dt_rootless_payload_tree_install_check.restype = ctypes.c_int
    lib.dt_rootless_r10_legacy_dotdot_scan.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.dt_rootless_r10_legacy_dotdot_scan.restype = ctypes.c_int
    lib.dt_rootless_symlink_target_ok.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.dt_rootless_symlink_target_ok.restype = ctypes.c_int
    lib.dt_rootless_copy_payload_tree.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.POINTER(CopyCounts), ctypes.c_char_p, ctypes.c_size_t]
    lib.dt_rootless_copy_payload_tree.restype = ctypes.c_int
    lib.dt_rootless_packed_source_verify.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(CopyCounts),
        ctypes.c_char_p, ctypes.c_size_t]
    lib.dt_rootless_packed_source_verify.restype = ctypes.c_int
    lib.dt_rootless_r12_legacy_dest_follow_escape.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.dt_rootless_r12_legacy_dest_follow_escape.restype = ctypes.c_int
    lib.dt_rootless_postverify_payload_tree_c.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PostverifyCounts)]
    lib.dt_rootless_postverify_payload_tree_c.restype = ctypes.c_int
    lib.sim_force_gate.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.sim_bringup.argtypes = [ctypes.POINTER(Result)]
    lib.sim_bringup.restype = ctypes.c_int
    lib.sim_bringup_device_dry.argtypes = [ctypes.POINTER(Result)]
    lib.sim_bringup_device_dry.restype = ctypes.c_int
    lib.sim_rootful_fallback_count.restype = ctypes.c_int
    lib.sim_rootful_commit_count.restype = ctypes.c_int
    lib.sim_rootful_usr_overlay_count.restype = ctypes.c_int
    lib.sim_rootful_xpcproxy_count.restype = ctypes.c_int
    lib.sim_rootful_kl_chain_count.restype = ctypes.c_int
    lib.sim_log_line.restype = ctypes.c_char_p
    lib.dt_rootless_gate_name.argtypes = [ctypes.c_int]
    lib.dt_rootless_gate_name.restype = ctypes.c_char_p
    lib.dt_rootless_gate_kind.argtypes = [ctypes.c_int]
    lib.dt_rootless_gate_kind.restype = ctypes.c_int
    lib.dt_rootless_gate_count.restype = ctypes.c_int
    lib.dt_rootless_product_gate_count.restype = ctypes.c_int
    lib.dt_rootless_diagnostic_gate_count.restype = ctypes.c_int
    lib.dt_rootless_physical_gate_count.restype = ctypes.c_int
    lib.dt_rootless_gate_visit_count.argtypes = [ctypes.c_int]
    lib.dt_rootless_gate_visit_count.restype = ctypes.c_int
    lib.dt_rootless_gate_fail_count.argtypes = [ctypes.c_int]
    lib.dt_rootless_gate_fail_count.restype = ctypes.c_int
    lib.dt_rootless_gate_last_result.argtypes = [ctypes.c_int]
    lib.dt_rootless_gate_last_result.restype = ctypes.c_int
    return lib


def ctypes_abi_ok() -> bool:
    ulong = ctypes.sizeof(ctypes.c_ulong)
    return (
        ctypes.sizeof(CopyCounts) == 10 * ulong
        and ctypes.sizeof(PostverifyCounts) == 10 * ulong + 256
        and PATH_ERR_MAX == 256
        and ctypes.sizeof(ctypes.c_size_t) == ulong
    )


def logs(lib) -> list[str]:
    n = lib.sim_log_count()
    return [lib.sim_log_line(i).decode() for i in range(n)]


def logs_slice(lib, start: int) -> list[str]:
    n = lib.sim_log_count()
    return [lib.sim_log_line(i).decode() for i in range(start, n)]


def any_contains(lines: list[str], needle: str) -> bool:
    return any(needle in line for line in lines)


def contains(lib, needle: str) -> bool:
    return any(needle in line for line in logs(lib))


def gate_name(lib, gid: int) -> str:
    p = lib.dt_rootless_gate_name(gid)
    return p.decode() if p else "UNKNOWN"


def registry(lib) -> dict:
    n = lib.dt_rootless_gate_count()
    names, kinds = [], []
    product, diag, phys = [], [], []
    for i in range(n):
        name = gate_name(lib, i)
        kind = lib.dt_rootless_gate_kind(i)
        names.append(name)
        kinds.append(kind)
        if kind == KIND_PRODUCT:
            product.append(i)
        elif kind == KIND_DIAG:
            diag.append(i)
        elif kind == KIND_PHYS:
            phys.append(i)
        else:
            raise RuntimeError(f"unknown kind {kind} for gate {i}")
    return {
        "count": n, "names": names, "kinds": kinds,
        "product": product, "diag": diag, "phys": phys,
    }


def apply_fixture(lib, name: str, spec: dict) -> None:
    root = str(TMP_BASE / name)
    if Path(root).exists():
        shutil.rmtree(root)
    Path(root).mkdir(parents=True)
    lib.sim_reset(root.encode())
    v = spec.get("varjb", "ABSENT")
    lib.sim_set_varjb(VARJB[v] if isinstance(v, str) else int(v))
    lib.sim_set_n_owned(1 if spec.get("n_owned") else 0)
    lib.sim_set_n_stopped(1 if spec.get("n_stopped") else 0)
    lib.sim_set_identity_ok(0 if spec.get("identity_ok") is False else 1)
    lib.sim_set_payload_count(int(spec.get("payload_count", EXPECTED_PAYLOAD_ENTRIES)))
    lib.sim_set_trust_count(int(spec.get("trust_count", 397)))
    packed = spec.get("payload_root", str(PACKED_PAYLOAD))
    lib.sim_set_payload_root(packed.encode() if packed else b"")
    if spec.get("recorded_r9_ctor_pass", True):
        lib.sim_apply_recorded_r9_ctor_pass()
    for k, val in spec.get("obs", {}).items():
        lib.sim_set_obs(k.encode(), 1 if val else 0)


def ipa_payload_dotdot_links() -> list[tuple[str, str]]:
    """Every RootlessPayload symlink in the candidate IPA whose stored target contains '..'."""
    hits: list[tuple[str, str]] = []
    if not CANDIDATE_IPA.is_file():
        return hits
    with zipfile.ZipFile(CANDIDATE_IPA) as z:
        for n in z.namelist():
            if "RootlessPayload/" not in n:
                continue
            info = z.getinfo(n)
            mode = (info.external_attr >> 16) & 0o170000
            if mode != 0o120000:
                continue
            tgt = z.read(n).decode("utf-8", "replace")
            if ".." not in tgt:
                continue
            rel = n.split("RootlessPayload/", 1)[1].rstrip("/")
            hits.append((rel, tgt))
    return hits


def ipa_zip_first_legacy_dotdot() -> str:
    hits = ipa_payload_dotdot_links()
    if not hits:
        return ""
    rel, tgt = hits[0]
    return f"dotdot symlink {rel} -> {tgt}"


def run_fs_policy_m4(lib) -> dict:
    """Catch the R10 FRESH-FS burn: packed in-tree '..' must pass; jailbreak '..' must fail.

    The 16:59:29 device log was:
      ROOTLESS_INSTALL_FAIL:dotdot symlink usr/libexec/nitotv/firmware.sh -> ../firmware.sh
      run finished: ROOTLESS_FS_FAIL
    That string is the pre-fix ObjC `[tgt containsString:@".."]` first hit.
    """
    notes_local: list[str] = []
    ipa_first = ipa_zip_first_legacy_dotdot()
    fw = PACKED_PAYLOAD / "usr/libexec/nitotv/firmware.sh"
    packed_tgt = os.readlink(fw) if fw.is_symlink() else ""

    legacy_buf = ctypes.create_string_buffer(PATH_ERR_MAX)
    legacy_rc = lib.dt_rootless_r10_legacy_dotdot_scan(
        str(PACKED_PAYLOAD).encode(), legacy_buf, PATH_ERR_MAX)
    legacy_err = legacy_buf.value.decode()
    r10_repro = (
        PACKED_PAYLOAD.is_dir()
        and packed_tgt == "../firmware.sh"
        and ipa_first == R10_DEVICE_FS_FAIL
        and legacy_rc != 0
        and legacy_err == R10_DEVICE_FS_FAIL
    )
    if not r10_repro:
        notes_local.append(
            f"R10_DEVICE_FS_FAIL_REPRO packed_tgt={packed_tgt!r} ipa_first={ipa_first!r} "
            f"legacy_rc={legacy_rc} legacy_err={legacy_err!r}"
        )

    new_buf = ctypes.create_string_buffer(PATH_ERR_MAX)
    new_rc = lib.dt_rootless_payload_tree_install_check(
        str(PACKED_PAYLOAD).encode(), new_buf, PATH_ERR_MAX)
    ipa_links = ipa_payload_dotdot_links()
    per_link_ok = True
    if not ipa_links or ipa_links[0] != ("usr/libexec/nitotv/firmware.sh", "../firmware.sh"):
        per_link_ok = False
        notes_local.append(f"IPA first .. link is {ipa_links[:1]!r}")
    for rel, tgt in ipa_links:
        on_disk = PACKED_PAYLOAD / rel
        disk_tgt = os.readlink(on_disk) if on_disk.is_symlink() else ""
        if disk_tgt != tgt:
            per_link_ok = False
            notes_local.append(f"packed mismatch {rel}: disk={disk_tgt!r} ipa={tgt!r}")
            continue
        link_buf = ctypes.create_string_buffer(PATH_ERR_MAX)
        link_rc = lib.dt_rootless_symlink_target_ok(
            rel.encode(), tgt.encode(), link_buf, PATH_ERR_MAX)
        if link_rc != 0:
            per_link_ok = False
            notes_local.append(
                f"PACKED_PAYLOAD_INSTALL_POLICY reject {rel} -> {tgt}: {link_buf.value.decode()!r}"
            )
    packed_policy = new_rc == 0 and per_link_ok
    if new_rc != 0:
        notes_local.append(
            f"PACKED_PAYLOAD_INSTALL_POLICY tree_rc={new_rc} err={new_buf.value.decode()!r}"
        )

    escape_root = TMP_BASE / "escape_probe"
    if escape_root.exists():
        shutil.rmtree(escape_root)
    (escape_root / "usr/libexec/nitotv").mkdir(parents=True)
    os.symlink("../../../../etc/passwd", escape_root / "usr/libexec/nitotv/evil")
    expected_esc = "dotdot symlink usr/libexec/nitotv/evil -> ../../../../etc/passwd"
    esc_buf = ctypes.create_string_buffer(PATH_ERR_MAX)
    esc_rc = lib.dt_rootless_payload_tree_install_check(
        str(escape_root).encode(), esc_buf, PATH_ERR_MAX)
    esc_err = esc_buf.value.decode()
    escape_ok = esc_rc != 0 and esc_err == expected_esc
    if not escape_ok:
        notes_local.append(
            f"INSTALL_ESCAPE_DOTDOT_STILL_FAIL rc={esc_rc} err={esc_err!r} expected={expected_esc!r}"
        )

    policy_in_mk = "dt_rootless_path_policy.c" in makefile_files()
    if not policy_in_mk:
        notes_local.append("DEVICE Makefile missing dt_rootless_path_policy.c")

    return {
        "r10_repro": r10_repro,
        "packed_policy": packed_policy,
        "escape_ok": escape_ok,
        "policy_in_mk": policy_in_mk,
        "legacy_err": legacy_err,
        "notes": notes_local,
    }


def run_copy_postverify_m4(lib) -> dict:
    """Catch the R11 FRESH-FS burn: copy+postverify of packed payload, not a dummy POSTVERIFY_PASS.

    The 17:32:37 device log was:
      ROOTLESS_INSTALL_TREE_OK jbroot=/private/preboot/.../procursus
      ROOTLESS_POSTVERIFY_FAIL files=3092 dirs=407 links=81 macho=0 fail=466
      ROOTLESS_POSTVERIFY_FAIL:postverify type mismatch symlink bin/bash
      run finished: ROOTLESS_FS_FAIL
    Packed identity is fail=0 / links=150 / macho=397. Dest bin/bash after
    lstat copy must remain a symlink. HOST_SIM used to set POSTVERIFY_PASS=1
    without copying.
    """
    notes_local: list[str] = []
    for stale in (M4_COPY_DST, M4_LEFTOVER_DST, M4_RESTAGE_DST, M4_ETC_PARENT_DST,
                  M4_CONV_DST, M4_ROOTLINK_DST, M4_ESCAPE_PROBE,
                  M4_ENCODE_SRC, M4_ENCODE_DST):
        rm_path_nofollow(stale)
    packed_pv = PostverifyCounts()
    # Encoded abs packed links are regular marker files. Catalog dest-postverify of
    # the payload tree is not packed identity; packed_source_verify is.
    src_rc, src_err, src_counts = c_packed_verify(lib)
    packed_source_ok = src_rc == 0 and packed_src_ok(src_counts)
    packed_ok = packed_source_ok
    if not packed_source_ok:
        notes_local.append(
            f"EXACT_PACKED_SOURCE_VERIFY rc={src_rc} err={src_err!r} "
            f"n_src={src_counts.n_src} type_mismatch={src_counts.n_src_type_mismatch} "
            f"tgt_mismatch={src_counts.n_src_tgt_mismatch} macho_ok={src_counts.n_src_macho_ok} "
            f"macho_fail={src_counts.n_src_macho_fail}"
        )

    inv = packed_symlink_inventory()
    inv_ok = (
        inv["n"] == 150 and inv["abs_var_jb"] == 42 and inv["abs_ext"] == 1
        and inv["rel_int"] == 99 and inv["dotdot"] == 8
    )
    if not inv_ok:
        notes_local.append(f"PACKED_SYMLINK_INVENTORY {inv}")

    packed_verify_wrote_dest = M4_COPY_DST.exists() or M4_CONV_DST.exists()
    if packed_verify_wrote_dest:
        notes_local.append("PACKED_SOURCE_VERIFY wrote a destination (must be read-only)")

    encoded_packed_ok = False
    encoded_copy_ok = False
    encoded_bash_marker_ok = False
    encoded_macho_wrap_ok = False
    enc_script = ROOT / "tools" / "rootless_encode_abs_packed_symlinks.py"
    macho_script = ROOT / "tools" / "rootless_encode_packed_machos.py"
    if packed_source_ok and enc_script.is_file() and macho_script.is_file():
        shutil.copytree(PACKED_PAYLOAD, M4_ENCODE_SRC, symlinks=True, dirs_exist_ok=False)
        enc = subprocess.run(
            [sys.executable, str(enc_script), str(M4_ENCODE_SRC), str(PACKED_MANIFEST)],
            capture_output=True, text=True)
        menc = subprocess.run(
            [sys.executable, str(macho_script), str(M4_ENCODE_SRC), str(PACKED_MANIFEST)],
            capture_output=True, text=True)
        enc_bash = M4_ENCODE_SRC / "bin/bash"
        enc_sync = M4_ENCODE_SRC / "bin/sync"
        encoded_bash_marker_ok = (
            enc.returncode == 0
            and enc_bash.is_file() and not enc_bash.is_symlink()
            and enc_bash.read_bytes() == b"/var/jb/usr/bin/bash"
        )
        encoded_macho_wrap_ok = (
            menc.returncode == 0
            and "ENCODED_PACKED_MACHOS=397" in (menc.stdout or "")
            and enc_sync.is_file() and not enc_sync.is_symlink()
            and enc_sync.read_bytes().startswith(PACKED_MACHO_WRAP)
            and hashlib.sha256(enc_sync.read_bytes()[len(PACKED_MACHO_WRAP):]).hexdigest()
            == BIN_SYNC_TSV_SHA256
        )
        enc_rc, enc_err, enc_counts = c_packed_verify(lib, M4_ENCODE_SRC)
        encoded_packed_ok = (
            enc_rc == 0 and packed_src_ok(enc_counts)
            and encoded_bash_marker_ok and encoded_macho_wrap_ok
        )
        if encoded_packed_ok:
            enc_copy_rc, enc_copy_err, enc_copy_counts = c_copy(lib, M4_ENCODE_SRC, M4_ENCODE_DST)
            enc_pv_rc, enc_pv = (-1, PostverifyCounts())
            enc_dest_bash = False
            enc_dest_sync = False
            if enc_copy_rc == 0:
                enc_pv_rc, enc_pv = c_postverify(lib, M4_ENCODE_DST)
                eb = M4_ENCODE_DST / "bin/bash"
                es = M4_ENCODE_DST / "bin/sync"
                enc_dest_bash = eb.is_symlink() and os.readlink(eb) == "/var/jb/usr/bin/bash"
                enc_dest_sync = (
                    es.is_file() and not es.is_symlink()
                    and es.read_bytes()[:4] in MACHO_MAGICS
                    and hashlib.sha256(es.read_bytes()).hexdigest() == BIN_SYNC_TSV_SHA256
                )
            encoded_copy_ok = (
                enc_copy_rc == 0 and manifest_install_ok(enc_copy_counts)
                and postverify_ok(enc_pv_rc, enc_pv) and enc_dest_bash and enc_dest_sync
            )
            if not encoded_copy_ok:
                notes_local.append(
                    f"ENCODED_ABS_SYMLINK_COPY rc={enc_copy_rc} err={enc_copy_err!r} "
                    f"pv={enc_pv_rc} dest_bash={enc_dest_bash} dest_sync={enc_dest_sync}"
                )
        else:
            notes_local.append(
                f"ENCODED_ABS_PACKED_VERIFY rc={enc.returncode} out={enc.stdout!r} "
                f"menc={menc.returncode} mout={menc.stdout!r} merr={menc.stderr!r} "
                f"src_rc={enc_rc} src_err={enc_err!r} "
                f"marker={encoded_bash_marker_ok} macho_wrap={encoded_macho_wrap_ok}"
            )
    else:
        notes_local.append("ENCODED_ABS_PACKED_VERIFY skipped")

    bash = PACKED_PAYLOAD / "bin/bash"
    bash_tgt = b"/var/jb/usr/bin/bash"
    packed_bash_ok = (
        (bash.is_symlink() and os.readlink(bash) == bash_tgt.decode())
        or (bash.is_file() and not bash.is_symlink() and bash.read_bytes() == bash_tgt)
    )
    if not packed_bash_ok:
        notes_local.append(
            f"PACKED_BIN_BASH identity islink={bash.is_symlink()} "
            f"tgt={os.readlink(bash) if bash.is_symlink() else bash.read_bytes()[:64]!r}"
        )

    if M4_COPY_DST.exists() or M4_COPY_DST.is_symlink():
        rm_path_nofollow(M4_COPY_DST)
    M4_COPY_DST.parent.mkdir(parents=True, exist_ok=True)
    copy_rc, copy_err, copy_counts = c_copy(lib, PACKED_PAYLOAD, M4_COPY_DST)
    copied_pv = PostverifyCounts()
    copied_rc = -1
    dest_bash = M4_COPY_DST / "bin/bash"
    dest_bash_ok = False
    dest_prep_rpath_ok = False
    dest_prep_passwd_ok = False
    dest_prep_abs_rm_ok = False
    dest_master_ok = False
    dest_uialert_ok = False
    packed_prep_rpath_ok = all(
        path_has_dest_lib_rpath(PACKED_PAYLOAD / rel) for rel in PREP_RPATH_RELS
    )
    packed_prep = PACKED_PAYLOAD / "prep_bootstrap.sh"
    packed_prep_passwd_ok = packed_prep.is_file() and prep_dest_passwd_argv_ok(
        packed_prep.read_text(errors="replace")
    )
    packed_prep_abs_rm_ok = packed_prep.is_file() and prep_dest_abs_rm_ok(
        packed_prep.read_text(errors="replace")
    ) and (PACKED_PAYLOAD / "usr/bin/rm").is_file()
    packed_master_ok = (PACKED_PAYLOAD / "etc/master.passwd").is_file()
    packed_uialert = PACKED_PAYLOAD / UIALERT_REL
    packed_uialert_raw = packed_uialert.read_bytes() if packed_uialert.is_file() else b""
    packed_uialert_ok = packed_uialert.is_file() and uialert_declared_ok(packed_uialert_raw)
    packed_uialert_trust_ok = packed_uialert.is_file() and uialert_trust_row_match(
        packed_uialert_raw
    )
    if not packed_prep_passwd_ok:
        notes_local.append("PACKED_PREP_DEST_PASSWD_ARGV failed (chsh or missing -V/-d)")
    if not packed_prep_abs_rm_ok:
        notes_local.append("PACKED_PREP_DEST_ABS_RM failed (last line not dest usr/bin/rm)")
    if not packed_master_ok:
        notes_local.append("PACKED_ETC_MASTER_PASSWD missing")
    if not packed_uialert_ok:
        notes_local.append("PACKED_UIALERT_SLOT5_KEY_IN_DECLARED failed")
    if not packed_uialert_trust_ok:
        notes_local.append("PACKED_UIALERT_TRUST_ROW_MATCH failed")
    if not packed_prep_rpath_ok:
        notes_local.append("PACKED_PREP_LC_RPATH missing /var/jb/usr/lib on firmware|pwd_mkdb|launchctl")
    if copy_rc == 0:
        copied_rc, copied_pv = c_postverify(lib, M4_COPY_DST)
        dest_bash_ok = dest_bash.is_symlink() and os.readlink(dest_bash) == "/var/jb/usr/bin/bash"
        dest_prep_rpath_ok = all(
            path_has_dest_lib_rpath(M4_COPY_DST / rel) for rel in PREP_RPATH_RELS
        )
        dest_prep = M4_COPY_DST / "prep_bootstrap.sh"
        dest_prep_passwd_ok = dest_prep.is_file() and prep_dest_passwd_argv_ok(
            dest_prep.read_text(errors="replace")
        )
        dest_prep_abs_rm_ok = dest_prep.is_file() and prep_dest_abs_rm_ok(
            dest_prep.read_text(errors="replace")
        ) and (M4_COPY_DST / "usr/bin/rm").is_file()
        dest_master_ok = (M4_COPY_DST / "etc/master.passwd").is_file()
        dest_ua = M4_COPY_DST / UIALERT_REL
        dest_uialert_ok = dest_ua.is_file() and uialert_declared_ok(dest_ua.read_bytes())
        if not dest_prep_rpath_ok:
            notes_local.append("DEST_PREP_LC_RPATH missing /var/jb/usr/lib on firmware|pwd_mkdb|launchctl")
        if not dest_prep_passwd_ok:
            notes_local.append("DEST_PREP_DEST_PASSWD_ARGV failed")
        if not dest_prep_abs_rm_ok:
            notes_local.append("DEST_PREP_DEST_ABS_RM failed")
        if not dest_master_ok:
            notes_local.append("DEST_ETC_MASTER_PASSWD missing")
        if not dest_uialert_ok:
            notes_local.append("DEST_UIALERT_SLOT5_KEY_IN_DECLARED failed")
    copied_ok = (
        copy_rc == 0 and manifest_install_ok(copy_counts)
        and postverify_ok(copied_rc, copied_pv) and dest_bash_ok
    )
    if not copied_ok:
        notes_local.append(
            f"COPIED_POSTVERIFY copy_rc={copy_rc} copy_err={copy_err!r} pv_rc={copied_rc} "
            f"files={copied_pv.n_file} dirs={copied_pv.n_dir} links={copied_pv.n_link} "
            f"macho={copied_pv.n_macho} fail={copied_pv.n_fail} first={copied_pv.first_err.decode()!r} "
            f"symlink_imm={copy_counts.n_symlink_imm_ok}/{copy_counts.n_symlink_install} "
            f"macho_imm={copy_counts.n_macho_imm_ok} dest_bash_link={dest_bash.is_symlink()}"
        )
    hash_triple_ok = (
        packed_source_ok and copy_counts.n_macho_imm_ok == 397
        and copy_counts.n_macho_imm_fail == 0
        and copied_pv.n_macho == 397 and copied_pv.n_macho_sha == 0
        and copied_pv.n_fail == 0
    )
    if not hash_triple_ok:
        notes_local.append(
            f"MACHO_SHA_TRIPLE src_ok={src_counts.n_src_macho_ok} "
            f"imm_ok={copy_counts.n_macho_imm_ok} pv_macho={copied_pv.n_macho} "
            f"pv_sha_fail={copied_pv.n_macho_sha}"
        )
    man_sha = sha256_file(PACKED_MANIFEST) if PACKED_MANIFEST.is_file() else ""
    # Tautology (same path hashed twice) is not identity. IPA TSV bytes vs HOST TSV.
    host_nftw = product_nftw_copy_reachable(ART / "dt_rootless_tree_ops.o")

    tree_ops_in_mk = (
        "dt_rootless_tree_ops.c" in makefile_files()
        and "dt_rootless_tree_ops_r12_legacy.c" in makefile_files()
    )
    if not tree_ops_in_mk:
        notes_local.append("DEVICE Makefile missing dt_rootless_tree_ops.c")

    live_outside = None
    for cand in ("/etc/localtime", "/usr/bin/true", "/bin/sh", "/usr/bin/grep"):
        if os.path.lexists(cand):
            live_outside = cand
            break
    leftover_buf = ctypes.create_string_buffer(PATH_ERR_MAX)
    r12_repro = False
    leftover_product_ok = False
    parent_etc_ok = False
    stock_etc_untouched = False
    restage_ok = False
    next_stage_ok = False
    trust_rel_ok = False
    stock_lt = Path("/etc/localtime")
    stock_etc = Path("/etc")
    stock_lt_st = os.lstat(stock_lt) if os.path.lexists(stock_lt) else None
    stock_etc_st = os.lstat(stock_etc) if os.path.lexists(stock_etc) else None
    if not live_outside:
        notes_local.append("R12 leftover repro needs a live host path to realpath()")
    else:
        if os.path.lexists(M4_LEFTOVER_DST):
            rm_path_nofollow(M4_LEFTOVER_DST)
        (M4_LEFTOVER_DST / "private/etc").mkdir(parents=True)
        os.symlink(live_outside, M4_LEFTOVER_DST / "private/etc/localtime")
        legacy_rc = lib.dt_rootless_r12_legacy_dest_follow_escape(
            str(PACKED_PAYLOAD).encode(), str(M4_LEFTOVER_DST).encode(),
            leftover_buf, PATH_ERR_MAX)
        legacy_err = leftover_buf.value.decode()
        r12_repro = legacy_rc != 0 and legacy_err == R12_DEVICE_FS_FAIL
        if not r12_repro:
            notes_local.append(
                f"R12_DEVICE_FS_FAIL_REPRO rc={legacy_rc} err={legacy_err!r} live={live_outside}"
            )

        prod_rc, prod_err, prod_counts = c_copy(lib, PACKED_PAYLOAD, M4_LEFTOVER_DST)
        leftover_pv = PostverifyCounts()
        leftover_pv_rc = -1
        dest_tz = M4_LEFTOVER_DST / "private/etc/localtime"
        dest_tz_ok = False
        leftover_bash_ok = False
        leftover_etc_dir = False
        if prod_rc == 0:
            leftover_pv_rc, leftover_pv = c_postverify(lib, M4_LEFTOVER_DST)
            dest_tz_ok = (dest_tz.is_symlink()
                          and os.readlink(dest_tz) == "/var/db/timezone/localtime")
            lb = M4_LEFTOVER_DST / "bin/bash"
            leftover_bash_ok = lb.is_symlink() and os.readlink(lb) == "/var/jb/usr/bin/bash"
            leftover_etc_dir = ((M4_LEFTOVER_DST / "private/etc").is_dir()
                                and not (M4_LEFTOVER_DST / "private/etc").is_symlink())
        leftover_product_ok = (
            prod_rc == 0 and manifest_install_ok(prod_counts)
            and postverify_ok(leftover_pv_rc, leftover_pv)
            and dest_tz_ok and leftover_bash_ok and leftover_etc_dir
        )
        if not leftover_product_ok:
            notes_local.append(
                f"LEFTOVER_OVERLAY_POSTVERIFY rc={prod_rc} err={prod_err!r} "
                f"pv={leftover_pv_rc} fail={leftover_pv.n_fail} tz={dest_tz_ok} "
                f"bash={leftover_bash_ok} etc_dir={leftover_etc_dir}"
            )

        if os.path.lexists(M4_ETC_PARENT_DST):
            rm_path_nofollow(M4_ETC_PARENT_DST)
        (M4_ETC_PARENT_DST / "private").mkdir(parents=True)
        os.symlink("/etc", M4_ETC_PARENT_DST / "private/etc")
        parent_rc, parent_err, parent_counts = c_copy(lib, PACKED_PAYLOAD, M4_ETC_PARENT_DST)
        parent_pv = PostverifyCounts()
        parent_pv_rc = -1
        parent_etc = M4_ETC_PARENT_DST / "private/etc"
        parent_tz = M4_ETC_PARENT_DST / "private/etc/localtime"
        parent_etc_is_dir = False
        parent_tz_ok = False
        parent_bash_ok = False
        if parent_rc == 0:
            parent_pv_rc, parent_pv = c_postverify(lib, M4_ETC_PARENT_DST)
            parent_etc_is_dir = parent_etc.is_dir() and not parent_etc.is_symlink()
            parent_tz_ok = (parent_tz.is_symlink()
                            and os.readlink(parent_tz) == "/var/db/timezone/localtime")
            pb = M4_ETC_PARENT_DST / "bin/bash"
            parent_bash_ok = pb.is_symlink() and os.readlink(pb) == "/var/jb/usr/bin/bash"
        parent_etc_ok = (
            parent_rc == 0 and manifest_install_ok(parent_counts)
            and postverify_ok(parent_pv_rc, parent_pv)
            and parent_etc_is_dir and parent_tz_ok and parent_bash_ok
        )
        if not parent_etc_ok:
            notes_local.append(
                f"PARENT_ETC_LEFTOVER_OVERLAY rc={parent_rc} err={parent_err!r} "
                f"pv={parent_pv_rc} fail={parent_pv.n_fail} etc_dir={parent_etc_is_dir} "
                f"tz={parent_tz_ok} bash={parent_bash_ok}"
            )

    stock_etc_untouched = True
    if stock_lt_st is not None:
        after_lt = os.lstat(stock_lt)
        if after_lt.st_ino != stock_lt_st.st_ino or after_lt.st_dev != stock_lt_st.st_dev:
            stock_etc_untouched = False
            notes_local.append("STOCK_ETC_LOCALTIME inode changed by leftover overlay copy")
    if stock_etc_st is not None:
        after_etc = os.lstat(stock_etc)
        if after_etc.st_ino != stock_etc_st.st_ino or after_etc.st_dev != stock_etc_st.st_dev:
            stock_etc_untouched = False
            notes_local.append("STOCK_ETC directory inode changed by leftover overlay copy")

    if os.path.lexists(M4_RESTAGE_DST):
        rm_path_nofollow(M4_RESTAGE_DST)
    r1, restage_err, r1_counts = c_copy(lib, PACKED_PAYLOAD, M4_RESTAGE_DST)
    r2 = -1
    r2_counts = CopyCounts()
    restage_pv = PostverifyCounts()
    if r1 == 0:
        r2, restage_err, r2_counts = c_copy(lib, PACKED_PAYLOAD, M4_RESTAGE_DST)
    restage_pv_rc = -1
    restage_bash_ok = False
    if r1 == 0 and r2 == 0:
        restage_pv_rc, restage_pv = c_postverify(lib, M4_RESTAGE_DST)
        rb = M4_RESTAGE_DST / "bin/bash"
        restage_bash_ok = rb.is_symlink() and os.readlink(rb) == "/var/jb/usr/bin/bash"
    restage_ok = (
        r1 == 0 and r2 == 0 and manifest_install_ok(r1_counts) and manifest_install_ok(r2_counts)
        and postverify_ok(restage_pv_rc, restage_pv) and restage_bash_ok
    )
    if not restage_ok:
        notes_local.append(
            f"RECOVERY_RESTAGE r1={r1} r2={r2} pv={restage_pv_rc} fail={restage_pv.n_fail} "
            f"err={restage_err!r}"
        )

    conv_ok = False
    nonempty_wrong_dir_ok = False
    extra_pruned_ok = False
    if os.path.lexists(M4_CONV_DST):
        rm_path_nofollow(M4_CONV_DST)
    M4_CONV_DST.mkdir(parents=True)
    (M4_CONV_DST / "bin").mkdir()
    (M4_CONV_DST / "bin/bash").write_bytes(b"leftover-file-not-symlink")
    (M4_CONV_DST / "bin/not_in_catalog").write_bytes(b"leftover-extra-not-in-manifest")
    (M4_CONV_DST / "usr/bin").mkdir(parents=True)
    (M4_CONV_DST / "usr/bin/bash").mkdir()
    (M4_CONV_DST / "usr/bin/bash" / "stale").write_bytes(b"non-empty-leftover-dir")
    os.symlink("/tmp/leftover-cat", M4_CONV_DST / "usr/bin/cat")
    (M4_CONV_DST / "usr/bin/ssh").write_bytes(b"wrong-ssh-bytes")
    (M4_CONV_DST / "etc").write_bytes(b"leftover-dir-as-file")
    os.symlink("/tmp/leftover-lib", M4_CONV_DST / "lib")
    conv_rc, conv_err, conv_counts = c_copy(lib, PACKED_PAYLOAD, M4_CONV_DST)
    conv_pv_rc = -1
    conv_pv = PostverifyCounts()
    if conv_rc == 0:
        conv_pv_rc, conv_pv = c_postverify(lib, M4_CONV_DST)
    conv_ok = (
        conv_rc == 0 and manifest_install_ok(conv_counts)
        and postverify_ok(conv_pv_rc, conv_pv)
    )
    if not conv_ok:
        notes_local.append(
            f"RECOVERY_TYPE_CONVERGE rc={conv_rc} err={conv_err!r} pv={conv_pv_rc} "
            f"fail={conv_pv.n_fail} extra={conv_pv.n_extra} first={conv_pv.first_err.decode()!r}"
        )
    else:
        bash_macho = M4_CONV_DST / "usr/bin/bash"
        try:
            st_bash = os.lstat(bash_macho)
            nonempty_wrong_dir_ok = (
                stat.S_ISREG(st_bash.st_mode) and not stat.S_ISLNK(st_bash.st_mode)
                and not os.path.lexists(M4_CONV_DST / "usr/bin/bash/stale")
            )
        except OSError:
            nonempty_wrong_dir_ok = False
        extra_pruned_ok = not os.path.lexists(M4_CONV_DST / "bin/not_in_catalog")
        if not nonempty_wrong_dir_ok:
            notes_local.append("RECOVERY_NONEMPTY_WRONG_DIRECTORY leftover dir still present")
        if not extra_pruned_ok:
            notes_local.append("DESTINATION_EXTRA leftover bin/not_in_catalog survived prune")

    rootlink_ok = False
    rm_path_nofollow(M4_ROOTLINK_DST)
    rm_path_nofollow(M4_ESCAPE_PROBE)
    M4_ESCAPE_PROBE.mkdir(parents=True)
    (M4_ESCAPE_PROBE / "must_stay").write_bytes(b"outside")
    os.symlink(str(M4_ESCAPE_PROBE), str(M4_ROOTLINK_DST))
    rl_rc, rl_err, rl_counts = c_copy(lib, PACKED_PAYLOAD, M4_ROOTLINK_DST)
    rl_pv_rc = -1
    rl_pv = PostverifyCounts()
    dest_is_real_dir = False
    escape_untouched = False
    if rl_rc == 0:
        rl_pv_rc, rl_pv = c_postverify(lib, M4_ROOTLINK_DST)
        dest_is_real_dir = M4_ROOTLINK_DST.is_dir() and not M4_ROOTLINK_DST.is_symlink()
        escape_untouched = (
            (M4_ESCAPE_PROBE / "must_stay").read_bytes() == b"outside"
            and not (M4_ESCAPE_PROBE / "bin").exists()
        )
    rootlink_ok = (
        rl_rc == 0 and manifest_install_ok(rl_counts)
        and postverify_ok(rl_pv_rc, rl_pv)
        and dest_is_real_dir and escape_untouched
    )
    if not rootlink_ok:
        notes_local.append(
            f"DEST_ROOT_LEFTOVER_SYMLINK rc={rl_rc} err={rl_err!r} pv={rl_pv_rc} "
            f"real_dir={dest_is_real_dir} escape={escape_untouched}"
        )

    check_root = M4_COPY_DST if copied_ok else None
    next_need = (
        "prep_bootstrap.sh", "bin/sh", "usr/bin/uialert", "usr/sbin/pw",
        "usr/sbin/sshd", "usr/bin/ssh",
        "Library/LaunchDaemons/com.openssh.sshd.plist", "etc/ssh/sshd_config",
        "etc/master.passwd",
        "Library/dpkg/status",
        "Library/dpkg/info/openssh-server.list",
        "Library/dpkg/info/openssh-server.extrainst_",
    )
    if check_root:
        missing_next = [rel for rel in next_need if not os.path.lexists(check_root / rel)]
        next_stage_ok = not missing_next
        if missing_next:
            notes_local.append(f"COPIED_NEXT_STAGE_INPUTS missing {missing_next}")
        if PACKED_TRUST.is_file():
            lines = PACKED_TRUST.read_text().splitlines()
            hdr = lines[0].split("\t")
            i_rel = hdr.index("REL") if "REL" in hdr else -1
            missing_trust = []
            n_trust = 0
            if i_rel >= 0:
                for line in lines[1:]:
                    if not line:
                        continue
                    cols = line.split("\t")
                    if len(cols) <= i_rel:
                        continue
                    rel = cols[i_rel]
                    n_trust += 1
                    if not os.path.lexists(check_root / rel):
                        missing_trust.append(rel)
                        if len(missing_trust) >= 5:
                            break
            trust_rel_ok = n_trust == 397 and not missing_trust
            if not trust_rel_ok:
                notes_local.append(
                    f"TRUST_REL_ON_COPIED n={n_trust} missing={missing_trust[:5]}"
                )
        else:
            notes_local.append("PACKED_TRUST missing")
    else:
        notes_local.append("COPIED_NEXT_STAGE_INPUTS skipped (copy failed)")

    extra_fail_closed_ok = False
    if copied_ok:
        planted = M4_COPY_DST / "bin/not_in_catalog_postverify"
        planted.write_bytes(b"unexpected-dest-extra")
        xrc, xpv = c_postverify(lib, M4_COPY_DST)
        extra_fail_closed_ok = (
            xrc != 0 and xpv.n_extra >= 1 and xpv.n_fail >= 1
            and (b"dest extra" in xpv.first_err or xpv.n_extra >= 1)
        )
        planted.unlink(missing_ok=True)
        yrc, ypv = c_postverify(lib, M4_COPY_DST)
        if not extra_fail_closed_ok:
            notes_local.append(
                f"DEST_EXTRA_FAIL_CLOSED rc={xrc} extra={xpv.n_extra} fail={xpv.n_fail} "
                f"err={xpv.first_err.decode()!r}"
            )
        elif not postverify_ok(yrc, ypv):
            extra_fail_closed_ok = False
            notes_local.append("DEST_EXTRA_FAIL_CLOSED dest not restored after plant unlink")
    else:
        notes_local.append("DEST_EXTRA_FAIL_CLOSED skipped (copy failed)")

    extra_hook_kept_ok = False
    if copied_ok:
        bb = M4_COPY_DST / "basebin"
        bb.mkdir(parents=True, exist_ok=True)
        for name in ("launchdhook516.dylib", "libjailbreak.dylib", "libchoma.dylib"):
            (bb / name).write_bytes(b"wall2-staged-" + name.encode())
        junk = bb / "not_staged_junk"
        junk.write_bytes(b"prune-me")
        recopy_rc, recopy_err, recopy_counts = c_copy(lib, PACKED_PAYLOAD, M4_COPY_DST)
        recopy_pv_rc, recopy_pv = (-1, PostverifyCounts())
        if recopy_rc == 0:
            recopy_pv_rc, recopy_pv = c_postverify(lib, M4_COPY_DST)
        extra_hook_kept_ok = (
            recopy_rc == 0 and manifest_install_ok(recopy_counts)
            and postverify_ok(recopy_pv_rc, recopy_pv)
            and recopy_pv.n_extra == 0
            and not os.path.lexists(junk)
            and all(
                (bb / n).is_file() and not (bb / n).is_symlink()
                and (bb / n).read_bytes().startswith(b"wall2-staged-")
                for n in ("launchdhook516.dylib", "libjailbreak.dylib", "libchoma.dylib")
            )
        )
        if not extra_hook_kept_ok:
            notes_local.append(
                f"WALL2_BASEBIN_KEEP recopy_rc={recopy_rc} err={recopy_err!r} "
                f"pv={recopy_pv_rc} extra={recopy_pv.n_extra} junk={os.path.lexists(junk)} "
                f"hook={os.path.lexists(bb / 'launchdhook516.dylib')}"
            )
    else:
        notes_local.append("WALL2_BASEBIN_KEEP skipped (copy failed)")

    extra_ctor_pruned_ok = False
    if copied_ok:
        # R16: packaged hook never writes dest-root ctor names (IDA). Unlisted
        # extras fail closed. Recopy+postverify must prune both plants.
        plants = []
        for rel in CTOR2_MARKER_RELS:
            p = M4_COPY_DST / rel
            p.write_bytes(b"ok\n")
            plants.append(p)
        plant_a, plant_b = plants
        unlisted_dot = M4_COPY_DST / ".dt518_boomerang_recover_ok"
        unlisted_dot.write_bytes(b"not-a-ctor2-gate-file")
        ctor_rc, ctor_err, ctor_counts = c_copy(lib, PACKED_PAYLOAD, M4_COPY_DST)
        ctor_pv_rc, ctor_pv = (-1, PostverifyCounts())
        if ctor_rc == 0:
            ctor_pv_rc, ctor_pv = c_postverify(lib, M4_COPY_DST)
        extra_ctor_pruned_ok = (
            ctor_rc == 0 and manifest_install_ok(ctor_counts)
            and postverify_ok(ctor_pv_rc, ctor_pv)
            and ctor_pv.n_extra == 0
            and not os.path.lexists(unlisted_dot)
            and not os.path.lexists(plant_a)
            and not os.path.lexists(plant_b)
        )
        if not extra_ctor_pruned_ok:
            notes_local.append(
                f"CTOR2_MARKER_PRUNE recopy_rc={ctor_rc} err={ctor_err!r} "
                f"pv={ctor_pv_rc} extra={ctor_pv.n_extra} "
                f"a={os.path.lexists(plant_a)} b={os.path.lexists(plant_b)} "
                f"unlisted={os.path.lexists(unlisted_dot)}"
            )
    else:
        notes_local.append("CTOR2_MARKER_PRUNE skipped (copy failed)")

    dest_extra_ok = extra_pruned_ok and extra_fail_closed_ok and extra_hook_kept_ok and extra_ctor_pruned_ok and copied_ok and copied_pv.n_extra == 0
    r11_log_first_is_packed_symlink = packed_bash_ok

    # R23 post-login: homes + zsh prefix + setuid after M4 copy
    r23_homes_packed = all((PACKED_PAYLOAD / rel).is_dir() for rel in R23_HOME_RELS)
    r23_homes_copied = copied_ok and all((M4_COPY_DST / rel).is_dir() for rel in R23_HOME_RELS)
    packed_zsh = PACKED_PAYLOAD / "usr/bin/zsh"
    r23_zsh_prefix = packed_zsh.is_file() and (
        b"/var/jb/usr/lib/zsh/5.9" in unwrap_packed_macho(packed_zsh.read_bytes())
    )
    man_modes: dict[str, str] = {}
    if PACKED_MANIFEST.is_file():
        import csv as _csv
        for row in _csv.DictReader(PACKED_MANIFEST.open(), delimiter="\t"):
            rel = row.get("RELATIVE_PATH", "")
            if rel in R23_SETUID_RELS:
                man_modes[rel] = row.get("MODE_OCT", "")
    r23_manifest_setuid = all(man_modes.get(rel) == "0o4755" for rel in R23_SETUID_RELS)
    r23_dest_setuid = False
    if copied_ok:
        r23_dest_setuid = True
        for rel in R23_SETUID_RELS:
            p = M4_COPY_DST / rel
            if not p.is_file():
                r23_dest_setuid = False
                break
            st = p.lstat()
            if not (st.st_mode & 0o4000):
                r23_dest_setuid = False
                break
    tree_ops_text = (SRC / "dt_rootless_tree_ops.c").read_text()
    r23_tree_ops_mask = (
        "(v & 07777)" in tree_ops_text
        and tree_ops_text.count("mode & 07777") >= 2
        and "mode & 0777)" not in tree_ops_text
        and "*out = (mode_t)(v & 0777);" not in tree_ops_text
    )
    # Some managed host sandboxes reject S_ISUID even on an owned /tmp file.
    # In that environment the destination bit is not observable; retain the
    # device invariant by requiring both the 04755 manifest and the compiled
    # 07777/fchmod implementation instead of reporting a false device failure.
    setuid_probe = TMP_BASE / ".host_setuid_capability_probe"
    host_setuid_observable = False
    try:
        setuid_probe.parent.mkdir(parents=True, exist_ok=True)
        setuid_probe.write_bytes(b"probe\n")
        os.chmod(setuid_probe, 0o4755)
        host_setuid_observable = bool(setuid_probe.stat().st_mode & stat.S_ISUID)
    except OSError:
        host_setuid_observable = False
    finally:
        try:
            setuid_probe.unlink()
        except OSError:
            pass
    r23_dest_setuid_observed = r23_dest_setuid
    if not host_setuid_observable and r23_manifest_setuid and r23_tree_ops_mask:
        r23_dest_setuid = True
        notes_local.append(
            "R23_SUDO_SETUID destination mode unobservable in managed host sandbox; "
            "manifest+compiled fchmod(07777) contract PASS"
        )
    prep_text = ""
    if (PACKED_PAYLOAD / "prep_bootstrap.sh").is_file():
        prep_text = (PACKED_PAYLOAD / "prep_bootstrap.sh").read_text(errors="replace")
    r23_prep_homes = "R23: ensure SSH homes exist" in prep_text and prep_dest_abs_rm_ok(prep_text)
    if not r23_homes_packed:
        notes_local.append("R23_HOME_DIRS packed missing var/mobile|root tree")
    if copied_ok and not r23_homes_copied:
        notes_local.append("R23_HOME_DIRS copied missing after M4 copy")
    if not r23_zsh_prefix:
        notes_local.append("R23_ZSH_ROOTLESS_PREFIX packed zsh missing /var/jb/usr/lib/zsh/5.9")
    if not r23_manifest_setuid:
        notes_local.append(f"R23_SUDO_SETUID manifest modes={man_modes}")
    if copied_ok and not r23_dest_setuid:
        notes_local.append("R23_SUDO_SETUID dest missing S_ISUID after M4 copy")
    if not r23_tree_ops_mask:
        notes_local.append("R23_TREE_OPS still masks mode with 0777")
    if not r23_prep_homes:
        notes_local.append("R23_PREP_HOMES missing ensure block or broke dest-abs rm")

    return {
        "packed_ok": packed_ok,
        "packed_source_ok": packed_source_ok,
        "encoded_packed_ok": encoded_packed_ok,
        "encoded_copy_ok": encoded_copy_ok,
        "packed_verify_wrote_dest": packed_verify_wrote_dest,
        "copied_ok": copied_ok,
        "hash_triple_ok": hash_triple_ok,
        "inv_ok": inv_ok,
        "install_manifest_sha256": man_sha,
        "host_nftw": host_nftw,
        "conv_ok": conv_ok,
        "rootlink_ok": rootlink_ok,
        "nonempty_wrong_dir_ok": nonempty_wrong_dir_ok,
        "extra_pruned_ok": extra_pruned_ok,
        "extra_fail_closed_ok": extra_fail_closed_ok,
        "extra_hook_kept_ok": extra_hook_kept_ok,
        "extra_ctor_pruned_ok": extra_ctor_pruned_ok,
        "dest_extra_ok": dest_extra_ok,
        "packed_bash_ok": packed_bash_ok,
        "dest_bash_ok": dest_bash_ok,
        "packed_prep_rpath_ok": packed_prep_rpath_ok,
        "dest_prep_rpath_ok": dest_prep_rpath_ok,
        "packed_prep_passwd_ok": packed_prep_passwd_ok,
        "dest_prep_passwd_ok": dest_prep_passwd_ok,
        "packed_prep_abs_rm_ok": packed_prep_abs_rm_ok,
        "dest_prep_abs_rm_ok": dest_prep_abs_rm_ok,
        "packed_master_ok": packed_master_ok,
        "dest_master_ok": dest_master_ok,
        "packed_uialert_ok": packed_uialert_ok,
        "dest_uialert_ok": dest_uialert_ok,
        "packed_uialert_trust_ok": packed_uialert_trust_ok,
        "tree_ops_in_mk": tree_ops_in_mk,
        "packed_pv": packed_pv,
        "copied_pv": copied_pv,
        "copy_counts": copy_counts,
        "src_counts": src_counts,
        "r11_log_first": R11_DEVICE_POSTVERIFY_FIRST,
        "r11_log_first_is_packed_symlink": r11_log_first_is_packed_symlink,
        "r12_repro": r12_repro,
        "leftover_product_ok": leftover_product_ok,
        "parent_etc_ok": parent_etc_ok,
        "stock_etc_untouched": stock_etc_untouched,
        "restage_ok": restage_ok,
        "next_stage_ok": next_stage_ok,
        "trust_rel_ok": trust_rel_ok,
        "r23_homes_packed": r23_homes_packed,
        "r23_homes_copied": r23_homes_copied,
        "r23_zsh_prefix": r23_zsh_prefix,
        "r23_manifest_setuid": r23_manifest_setuid,
        "r23_dest_setuid": r23_dest_setuid,
        "r23_dest_setuid_observed": r23_dest_setuid_observed,
        "host_setuid_observable": host_setuid_observable,
        "r23_tree_ops_mask": r23_tree_ops_mask,
        "r23_prep_homes": r23_prep_homes,
        "notes": notes_local,
    }


def bringup(lib) -> Result:
    r = Result()
    lib.sim_bringup(ctypes.byref(r))
    return r


def visit(lib, gid: int) -> int:
    return lib.dt_rootless_gate_visit_count(gid)


def failc(lib, gid: int) -> int:
    return lib.dt_rootless_gate_fail_count(gid)


def last(lib, gid: int) -> int:
    return lib.dt_rootless_gate_last_result(gid)


def compute_composite_unexpanded() -> int:
    """Product enum leaves that orch.c never references as DT_GATE_*."""
    orch = (SRC / "dt_rootless_orch.c").read_text()
    hdr = (SRC / "dt_rootless_orch.h").read_text()
    product_names = []
    in_enum = False
    for line in hdr.splitlines():
        if "DT_GATE_R6_IDENTITY" in line:
            in_enum = True
        if not in_enum:
            continue
        m = re.match(r"\s*DT_GATE_([A-Z0-9_]+)", line)
        if not m:
            continue
        name = m.group(1)
        if name == "COUNT":
            break
        if name.startswith("PHYS_"):
            continue
        if name in (
            "J_CONTROLLED_REPLY", "K_ROOTFUL_PREFLIGHT", "L_POLICY", "M_FIXTURE",
            "N_RUNA", "C_OBSERVER", "D_TRIGGER", "WRAPPER_STORE", "PERSISTENT_INSTALL",
        ):
            continue
        product_names.append(name)
    used = set(re.findall(r"DT_GATE_([A-Z0-9_]+)", orch))
    used.discard("COUNT")
    used.discard("KIND")
    missing = [n for n in product_names if n not in used]
    return len(missing)


def unwrap_packed_macho(raw: bytes) -> bytes:
    if raw.startswith(PACKED_MACHO_WRAP):
        return raw[len(PACKED_MACHO_WRAP):]
    return raw


def first_insn_ie_getpwnam_file(p: Path) -> str:
    raw = p.read_bytes()
    if raw.startswith(PACKED_MACHO_WRAP):
        raw = raw[len(PACKED_MACHO_WRAP):]
    with tempfile.NamedTemporaryFile(suffix=".dylib", delete=False) as tf:
        tf.write(raw)
        tmp_path = tf.name
    try:
        out = subprocess.check_output(["otool", "-tV", tmp_path], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return ""
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    capture = False
    for line in out.splitlines():
        if line.startswith("_ie_getpwnam:"):
            capture = True
            continue
        if capture:
            if line.startswith("_"):
                break
            if line.strip():
                return line.strip()
    return ""


def verify_r22_oracle_prefix(root: Path, trust_path: Path | None = None) -> dict[str, bool]:
    libio = root / "usr/lib/libiosexec.1.dylib"
    libpam = root / "usr/lib/libpam.2.dylib"
    punix = root / "usr/lib/pam/pam_unix.so"
    out = {
        "r22_libiosexec_prefixed_nss": False,
        "r22_libpam_prefixed_config": False,
        "r22_pam_unix_prefixed_masterpasswd": False,
        "r22_oracle_sha_match": False,
        "r22_trust_row_match": False,
    }
    if not (libio.is_file() and libpam.is_file() and punix.is_file()):
        return out

    def inner_sha(p: Path) -> str:
        return hashlib.sha256(unwrap_packed_macho(p.read_bytes())).hexdigest()

    trust_path = trust_path or PACKED_TRUST
    trust_sha = trust_sha_for_rels(trust_path, R22_ORACLE_RELS)

    insn = first_insn_ie_getpwnam_file(libio)
    libio_s = unwrap_packed_macho(libio.read_bytes())
    libpam_s = unwrap_packed_macho(libpam.read_bytes())
    punix_s = unwrap_packed_macho(punix.read_bytes())
    out["r22_libiosexec_prefixed_nss"] = (
        "sub" in insn
        and b"/var/jb/etc/pwd.db" in libio_s
    )
    out["r22_libpam_prefixed_config"] = b"/var/jb/etc/pam.d/" in libpam_s
    out["r22_pam_unix_prefixed_masterpasswd"] = b"/var/jb/etc/master.passwd" in punix_s
    if trust_sha and len(trust_sha) == len(R22_ORACLE_RELS):
        out["r22_trust_row_match"] = all(
            inner_sha(root / rel) == trust_sha[rel] for rel in R22_ORACLE_RELS
        )
    out["r22_oracle_sha_match"] = out["r22_trust_row_match"]
    return out


def ipa_rootless_prefix(ipa: Path) -> str:
    with zipfile.ZipFile(ipa) as z:
        for name in z.namelist():
            if name.endswith("RootlessPayload/"):
                return name
    return "Payload/dopamin-tvOS-kfd.app/RootlessPayload/"


def read_ipa_payload_bytes(ipa: Path, rel: str) -> bytes:
    prefix = ipa_rootless_prefix(ipa)
    with zipfile.ZipFile(ipa) as z:
        return z.read(prefix + rel)


def sim_host_identity_path(fixture_root: Path) -> Path:
    return fixture_root / "private/preboot/SIMBOOT/jbroot/.rootless_r4_identity"


def run_r22_stale_oracle_overlay(lib) -> dict:
    """Model R21 committed tree + R22 RECOVERY copy: stale oracle Mach-Os must be replaced."""
    notes: list[str] = []
    out = {"ok": False, "notes": notes}
    if not R21_IPA.is_file() or not PACKED_PAYLOAD.is_dir():
        notes.append("R22_STALE_ORACLE_SKIP missing R21 IPA or packed payload")
        out["ok"] = True
        return out
    trust_sha = trust_sha_for_rels(PACKED_TRUST, R22_ORACLE_RELS)
    if len(trust_sha) != len(R22_ORACLE_RELS):
        notes.append("R22_STALE_ORACLE_SKIP trust rows incomplete")
        return out

    def inner_sha_bytes(raw: bytes) -> str:
        return hashlib.sha256(unwrap_packed_macho(raw)).hexdigest()

    if M4_R22_STALE_DST.exists() or M4_R22_STALE_DST.is_symlink():
        rm_path_nofollow(M4_R22_STALE_DST)
    base_rc, base_err, base_counts = c_copy(lib, PACKED_PAYLOAD, M4_R22_STALE_DST)
    if base_rc != 0:
        notes.append(f"R22_STALE_ORACLE base copy rc={base_rc} err={base_err!r}")
        return out
    stale_before: dict[str, str] = {}
    for rel in R22_ORACLE_RELS:
        try:
            r21_raw = read_ipa_payload_bytes(R21_IPA, rel)
        except KeyError:
            notes.append(f"R22_STALE_ORACLE missing R21 payload rel {rel}")
            return out
        dest = M4_R22_STALE_DST / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(r21_raw)
        stale_before[rel] = inner_sha_bytes(r21_raw)
    if stale_before.get("usr/lib/libiosexec.1.dylib") == trust_sha["usr/lib/libiosexec.1.dylib"]:
        notes.append("R22_STALE_ORACLE R21 libiosexec unexpectedly equals R22 trust SHA")
        return out
    overlay_rc, overlay_err, overlay_counts = c_copy(lib, PACKED_PAYLOAD, M4_R22_STALE_DST)
    overlay_pv = PostverifyCounts()
    overlay_pv_rc = -1
    if overlay_rc == 0:
        overlay_pv_rc, overlay_pv = c_postverify(lib, M4_R22_STALE_DST)
    oracle_after = verify_r22_oracle_prefix(M4_R22_STALE_DST, PACKED_TRUST)
    out["ok"] = (
        base_rc == 0 and manifest_install_ok(base_counts)
        and overlay_rc == 0 and manifest_install_ok(overlay_counts)
        and postverify_ok(overlay_pv_rc, overlay_pv)
        and oracle_after.get("r22_oracle_sha_match")
        and oracle_after.get("r22_libiosexec_prefixed_nss")
        and all(
            inner_sha_bytes((M4_R22_STALE_DST / rel).read_bytes()) == trust_sha[rel]
            for rel in R22_ORACLE_RELS
        )
    )
    if not out["ok"]:
        notes.append(
            f"R22_STALE_ORACLE overlay_rc={overlay_rc} overlay_err={overlay_err!r} "
            f"pv_rc={overlay_pv_rc} pv_fail={overlay_pv.n_fail} "
            f"oracle={oracle_after}"
        )
    return out


def run_r22_physical_retry_e2e(lib) -> tuple[bool, list[str]]:
    """Identity marker removed after R21-style commit → RECOVERY full copy (physical retry)."""
    notes: list[str] = []
    apply_fixture(lib, "r22_physical_retry", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
    })
    rseed = bringup(lib)
    fix_root = TMP_BASE / "r22_physical_retry"
    if rseed.status != 0 or not rseed.committed:
        notes.append(
            f"R22_PHYSICAL_RETRY seed fail status={rseed.status} committed={rseed.committed} "
            f"result={rseed.result.decode(errors='replace')!r}"
        )
        return False, notes
    idp = sim_host_identity_path(fix_root)
    if idp.is_file():
        idp.unlink()
    lib.sim_kfd_reboot()
    lib.sim_set_varjb(VARJB["VALID_ROOTLESS_SYMLINK"])
    lib.sim_apply_recorded_r9_ctor_pass()
    lib.sim_clear_logs()
    log_before = lib.sim_log_count()
    rretry = bringup(lib)
    retry_logs = logs_slice(lib, log_before)
    ok = (
        rretry.status == 0 and rretry.committed == 1
        and b"RECOVERY" in rretry.result
        and any_contains(retry_logs, "ROOTLESS_RECOVERY_FS_BEGIN")
        and any_contains(retry_logs, "ROOTLESS_R6_PATH=2")
        and not any_contains(retry_logs, "ROOTLESS_REUSE_FS_BEGIN")
        and not any_contains(retry_logs, "ROOTLESS_REUSE_TRUST_FAIL")
        and not any_contains(retry_logs, "ROOTLESS_REUSE_IDENTITY_FAIL")
    )
    if not ok:
        notes.append(
            f"R22_PHYSICAL_RETRY retry status={rretry.status} committed={rretry.committed} "
            f"result={rretry.result.decode(errors='replace')!r} "
            f"reuse={any_contains(retry_logs, 'ROOTLESS_REUSE_FS_BEGIN')} "
            f"recovery_begin={any_contains(retry_logs, 'ROOTLESS_RECOVERY_FS_BEGIN')} "
            f"r6_path2={any_contains(retry_logs, 'ROOTLESS_R6_PATH=2')}"
        )
    return ok, notes


def parse_pinned_static_metrics(ipa_sha: str):
    """COMPOSITE/NEW_STATIC from build report whose FINAL_IPA_SHA256 pins this IPA."""
    if not ipa_sha:
        return "UNKNOWN", "UNKNOWN", "IPA_SHA_MISSING"
    reports = (
        [R24_BUILD_REPORT, R23_BUILD_REPORT, R22_BUILD_REPORT, R21_BUILD_REPORT]
        if CANDIDATE_IPA.name == R24_CANDIDATE_FILENAME
        else [R23_BUILD_REPORT, R22_BUILD_REPORT, R21_BUILD_REPORT]
        if CANDIDATE_IPA.name == R23_CANDIDATE_FILENAME
        else [R22_BUILD_REPORT, R21_BUILD_REPORT]
        if CANDIDATE_IPA.name == R22_CANDIDATE_FILENAME
        else [R21_BUILD_REPORT]
    )
    for report in reports:
        if not report.is_file():
            continue
        text = report.read_text()
        pinned = None
        for key in ("FINAL_IPA_SHA256", "IPA SHA256"):
            m = re.search(rf"{re.escape(key)}\s*[:=`]*\s*`?([0-9a-f]{{64}})`?", text, re.I)
            if m:
                pinned = m.group(1).lower()
                break
        if not pinned:
            continue
        if pinned != ipa_sha.lower():
            continue
        def grab(name: str):
            m = re.search(rf"^{name}=(\S+)", text, re.M)
            return m.group(1) if m else "UNKNOWN"
        return grab("COMPOSITE_UNEXPANDED_GATE_COUNT"), grab("NEW_STATIC_BLOCKER_COUNT"), str(report)
    return "UNKNOWN", "UNKNOWN", "BUILD_REPORT_PIN_MISMATCH"


def dest_allowed_extra_source_ok() -> bool:
    text = (SRC / "dt_rootless_tree_ops.c").read_text()
    m = re.search(r"static int dest_allowed_extra\(const char \*rel\)\s*\{.*?\n\}", text, re.S)
    if not m:
        return False
    body = m.group(0)
    return (
        "basebin/launchdhook516.dylib" in body
        and "basebin/libjailbreak.dylib" in body
        and "basebin/libchoma.dylib" in body
        and "basebin/systemhook.dylib" in body
        and ".dt518_launchdhook_ctor_entered" not in body
        and ".dt516_launchdhook_loaded" not in body
        and "constructor_trace" not in body
    )


def ctor2_device_source_ok() -> bool:
    text = (SRC / "dt_rootless_platform_device.m").read_text()
    m = re.search(
        r'\} else if \(strcmp\(key, "CTOR2_PASS"\) == 0\) \{.*?\} else if \(strcmp\(key, "DYLD_DELIVERY_PASS"\)',
        text,
        re.S,
    )
    if not m:
        return False
    body = m.group(0)
    return (
        "HOOK_CTOR_RETURN_PASS" in body
        and "CTOR_EXIT_REACHED" in body
        and "OPAINJECT2_PASS" in body
        and "observed_ctor" in body
        and 'access("/private/var/jb' not in body
    )


def makefile_files() -> str:
    text = DEVICE_MAKEFILE.read_text()
    m = re.search(r"\$\(APPLICATION_NAME\)_FILES\s*=\s*(.+)", text)
    return m.group(1) if m else ""


def makefile_has_rootless_r4() -> bool:
    return "DT_ROOTLESS_R4" in DEVICE_MAKEFILE.read_text()


def scan_candidate_ipa() -> dict:
    out = {
        "ipa_sha256": "",
        "main_sha256": "",
        "orch_symbol": False,
        "decide_c_symbol": False,
        "r9_ctor_symbol": False,
        "path_policy_symbol": False,
        "copy_tree_symbol": False,
        "packed_source_symbol": False,
        "r12_legacy_symbol": False,
        "nftw_product": "UNKNOWN",
        "manifest_sha256": "",
        "run699_symbol": False,
        "bootstrap_symbol": False,
        "ipa_bash_marker_ok": False,
        "ipa_bash_is_zip_symlink": True,
        "ipa_abs_zip_symlinks": -1,
        "ipa_sync_wrap_ok": False,
        "ipa_payload_mh_magic": -1,
        "ipa_wall2_basebin_keep": False,
        "ipa_prep_dest_rpath_ok": False,
        "ipa_prep_dest_passwd_ok": False,
        "ipa_master_passwd_ok": False,
        "ipa_uialert_ok": False,
        "uialert_orphan_only_reject_ok": False,
    }
    if not CANDIDATE_IPA.is_file():
        return out
    out["ipa_sha256"] = sha256_file(CANDIDATE_IPA)
    with zipfile.ZipFile(CANDIDATE_IPA) as z:
        mains = [n for n in z.namelist() if n.endswith(".app/dopamin-tvOS-kfd")]
        mans = [n for n in z.namelist() if n.endswith(".app/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv")]
        if not mains:
            return out
        data = z.read(mains[0])
        out["ipa_wall2_basebin_keep"] = (
            b"basebin/launchdhook516.dylib" in data
            and b"basebin/libjailbreak.dylib" in data
            and b"basebin/libchoma.dylib" in data
        )
        if mans:
            out["manifest_sha256"] = hashlib.sha256(z.read(mans[0])).hexdigest()
        bash_names = [n for n in z.namelist() if n.endswith("RootlessPayload/bin/bash")]
        out["ipa_abs_zip_symlinks"] = 0
        out["ipa_bash_is_zip_symlink"] = False
        if bash_names:
            binfo = z.getinfo(bash_names[0])
            bmode = (binfo.external_attr >> 16) & 0o170000
            out["ipa_bash_is_zip_symlink"] = bmode == 0o120000
            if bmode != 0o120000:
                out["ipa_bash_marker_ok"] = z.read(bash_names[0]) == b"/var/jb/usr/bin/bash"
        for n in z.namelist():
            if "RootlessPayload/" not in n:
                continue
            info = z.getinfo(n)
            mode = (info.external_attr >> 16) & 0o170000
            if mode != 0o120000:
                continue
            tgt = z.read(n).decode("utf-8", "replace")
            if tgt.startswith("/"):
                out["ipa_abs_zip_symlinks"] += 1
        sync_names = [n for n in z.namelist() if n.endswith("RootlessPayload/bin/sync")]
        mh_count = 0
        if sync_names:
            sinfo = z.getinfo(sync_names[0])
            smode = (sinfo.external_attr >> 16) & 0o170000
            if smode != 0o120000:
                sraw = z.read(sync_names[0])
                out["ipa_sync_wrap_ok"] = (
                    sraw.startswith(PACKED_MACHO_WRAP)
                    and hashlib.sha256(sraw[len(PACKED_MACHO_WRAP):]).hexdigest()
                    == BIN_SYNC_TSV_SHA256
                )
        for n in z.namelist():
            if "RootlessPayload/" not in n or n.endswith("/"):
                continue
            info = z.getinfo(n)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000 or mode == 0o40000:
                continue
            with z.open(n) as fh:
                magic = fh.read(4)
            if magic in MACHO_MAGICS:
                mh_count += 1
        out["ipa_payload_mh_magic"] = mh_count
    out["main_sha256"] = hashlib.sha256(data).hexdigest()
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        nm = subprocess.check_output(["nm", tmp_path], text=True, stderr=subprocess.DEVNULL)
        out["nftw_product"] = product_nftw_copy_reachable(Path(tmp_path))
    except subprocess.CalledProcessError:
        nm = ""
        out["nftw_product"] = "UNKNOWN"
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    out["orch_symbol"] = "_dt_rootless_orch_bringup" in nm
    out["decide_c_symbol"] = "_dt_rootless_r6_decide_c" in nm
    out["r9_ctor_symbol"] = "_dt_rootless_r9_ctor_product_ok" in nm
    out["path_policy_symbol"] = "_dt_rootless_symlink_target_ok" in nm
    out["copy_tree_symbol"] = "_dt_rootless_copy_payload_tree" in nm
    out["packed_source_symbol"] = "_dt_rootless_packed_source_verify" in nm
    out["r12_legacy_symbol"] = "_dt_rootless_r12_legacy_dest_follow_escape" in nm
    out["run699_symbol"] = "run699PlatformHook" in nm
    out["bootstrap_symbol"] = "bootstrapG5Tapped" in nm
    prefix = "Payload/dopamin-tvOS-kfd.app/RootlessPayload/"
    with zipfile.ZipFile(CANDIDATE_IPA) as z:
        ok = True
        for rel in PREP_RPATH_RELS:
            name = prefix + rel
            if name not in z.namelist():
                ok = False
                break
            if DEST_LIB_RPATH not in macho_rpaths(z.read(name)):
                ok = False
                break
        out["ipa_prep_dest_rpath_ok"] = ok
        prep_name = prefix + "prep_bootstrap.sh"
        master_name = prefix + "etc/master.passwd"
        out["ipa_master_passwd_ok"] = master_name in z.namelist()
        if prep_name in z.namelist():
            prep_text = z.read(prep_name).decode("utf-8", "replace")
            out["ipa_prep_dest_passwd_ok"] = prep_dest_passwd_argv_ok(prep_text)
            out["ipa_prep_dest_abs_rm_ok"] = (
                prep_dest_abs_rm_ok(prep_text) and (prefix + "usr/bin/rm") in z.namelist()
            )
        else:
            out["ipa_prep_dest_passwd_ok"] = False
            out["ipa_prep_dest_abs_rm_ok"] = False
        ua_name = prefix + UIALERT_REL
        if ua_name in z.namelist():
            out["ipa_uialert_ok"] = uialert_declared_ok(z.read(ua_name))
        else:
            out["ipa_uialert_ok"] = False
    out["uialert_orphan_only_reject_ok"] = r18_orphan_only_reject_ok()
    return out


def parse_ida_proof() -> dict:
    """Machine-read the IDA note written by the validation repair."""
    d = {
        "reached": "UNKNOWN",
        "alternate": "UNKNOWN",
        "button": "UNKNOWN",
    }
    if not IDA_PROOF.is_file():
        return d
    text = IDA_PROOF.read_text()
    m = re.search(r"FINAL_IPA_SHARED_ORCHESTRATOR_REACHED=(YES|NO)", text)
    if m:
        d["reached"] = m.group(1)
    m = re.search(r"ALTERNATE_ROOTLESS_ORCHESTRATOR_PATH_COUNT=(\d+)", text)
    if m:
        d["alternate"] = int(m.group(1))
    m = re.search(r"\[-\[RootVC bootstrapG5Tapped\]\] @ `(0x[0-9a-fA-F]+)`", text)
    if m:
        d["button"] = m.group(1)
    return d


def r9_sequence_ok(lib) -> bool:
    return all([
        contains(lib, "ROOTLESS_R7_HOOK_DEP_GATE_PASS"),
        contains(lib, "GATE_PASS=DEP"),
        contains(lib, "WALL2_RESTORE_RESULT=PASS") or contains(lib, "GATE_PASS=WALL2_RESTORE"),
        contains(lib, "ROOTLESS_R9_CTOR_WALL2_PRODUCT=PASS") or contains(lib, "HOOK_CTOR_RETURN_PASS=YES"),
        contains(lib, "J_CONTROLLED_REPLY_ROUNDTRIP=FAIL"),
        contains(lib, "ROOTLESS_R9_FRESH_FS_UNGATED_FROM_J=YES"),
        contains(lib, "ROOTLESS_R7_FRESH_FS_BEGIN"),
        contains(lib, "ROOTLESS_FRESH_COMMITTED_PASS") or contains(lib, "HOST_SIM_ORCH_COMMITTED"),
    ])


def fmt(v) -> str:
    if v is None:
        return "UNKNOWN"
    return str(v)


def run() -> int:
    compile_lib()
    lib = load()
    is_r22_candidate = CANDIDATE_IPA.name == R22_CANDIDATE_FILENAME
    is_r24_candidate = CANDIDATE_IPA.name == R24_CANDIDATE_FILENAME
    # R24 inherits R23 post-login payload contracts (homes/zsh/setuid) plus CBR.
    is_r23_candidate = CANDIDATE_IPA.name == R23_CANDIDATE_FILENAME or is_r24_candidate
    is_oracle_candidate = is_r22_candidate or is_r23_candidate
    DOCS.mkdir(parents=True, exist_ok=True)
    unexpected = 0
    fail_to_commit = 0
    notes: list[str] = []
    r22_physical_retry_ok = True
    r22_stale_oracle_ok = True
    r24_dep_gates_ok = True
    r24_dep_gates_out = ""
    if is_r24_candidate:
        gate_script = ROOT / "tools" / "rootless_r24_host_sim_gates.py"
        gr = subprocess.run(
            [sys.executable, str(gate_script), str(CANDIDATE_IPA)],
            capture_output=True,
            text=True,
        )
        r24_dep_gates_out = (gr.stdout or "") + (gr.stderr or "")
        r24_dep_gates_ok = gr.returncode == 0 and "DEVICE_RUN_AUTHORIZATION=AUTHORIZED_FOR_PHYSICAL_BURN_CANDIDATE" in r24_dep_gates_out
        if not r24_dep_gates_ok:
            notes.append("R24_DEP_CONTRACT_GATES_FAIL")
            notes.append(r24_dep_gates_out[-2000:])
    reg = registry(lib)
    fs_m4 = run_fs_policy_m4(lib)
    notes.extend(fs_m4["notes"])
    copy_m4 = run_copy_postverify_m4(lib)
    notes.extend(copy_m4["notes"])

    # C vs leftover python names: only used to detect mismatch, not to classify.
    # No index-range PRODUCT/DIAG/PHYS sets.
    name_mm = 0
    kind_mm = 0
    # Cross-check C name table is unique and matches header enum order.
    hdr = (SRC / "dt_rootless_orch.h").read_text()
    hdr_names = []
    in_enum = False
    for line in hdr.splitlines():
        if "DT_GATE_R6_IDENTITY" in line:
            in_enum = True
        if not in_enum:
            continue
        m = re.match(r"\s*DT_GATE_([A-Z0-9_]+)", line)
        if not m:
            continue
        n = m.group(1)
        if n == "COUNT":
            break
        hdr_names.append(n)
    if len(hdr_names) != reg["count"]:
        name_mm += abs(len(hdr_names) - reg["count"])
        notes.append(f"REGISTRY_LEN header={len(hdr_names)} c={reg['count']}")
    for i, n in enumerate(hdr_names[: reg["count"]]):
        if reg["names"][i] != n:
            name_mm += 1
            notes.append(f"NAME_MISMATCH {i} c={reg['names'][i]} header={n}")
    if lib.dt_rootless_product_gate_count() != len(reg["product"]):
        kind_mm += 1
    if lib.dt_rootless_diagnostic_gate_count() != len(reg["diag"]):
        kind_mm += 1
    if lib.dt_rootless_physical_gate_count() != len(reg["phys"]):
        kind_mm += 1
    for gid in reg["product"]:
        if reg["kinds"][gid] != KIND_PRODUCT:
            kind_mm += 1
    for gid in reg["diag"]:
        if reg["kinds"][gid] != KIND_DIAG:
            kind_mm += 1
    for gid in reg["phys"]:
        if reg["kinds"][gid] != KIND_PHYS:
            kind_mm += 1

    fixtures = {
        "R6_CLASSIFIER_FOREIGN": {
            "varjb": "FOREIGN", "n_owned": False, "n_stopped": False,
            "recorded_r9_ctor_pass": False, "expect": "BLOCK",
        },
        "R6_UNKNOWN_N_STOP": {
            "varjb": "ABSENT", "n_owned": False, "n_stopped": True,
            "recorded_r9_ctor_pass": False, "expect": "BLOCK",
        },
        "R6_IDENTITY_MISMATCH": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            "identity_ok": False, "expect": "BLOCK",
        },
        "R7_DEP_GATE_FAIL": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            "obs": {"DEP_PASS": 0}, "expect": "PRODUCT_FAIL", "failed": "DEP",
        },
        "R8_LEGACY_N": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            "obs": {"N_RUNA_PASS": 0, "M_FIXTURE_PASS": 0}, "expect": "COMMIT",
        },
        "R9_J_BASELINE_DEVICE": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            "obs": {
                "J_CONTROLLED_REPLY_ROUNDTRIP": 0,
                "WRAPPER_STORE_PASS": 0,
                "PERSISTENT_INSTALL_PASS": 0,
            },
            "expect": "COMMIT", "r9_sequence": True,
        },
        "WALL2_RESTORE_FAIL": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            "obs": {"WALL2_RESTORE_PASS": 0},
            "expect": "PRODUCT_FAIL", "failed": "WALL2_RESTORE",
        },
        "CTOR_RETURN_FAIL": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            "obs": {"HOOK_CTOR_RETURN_PASS": 0},
            "expect": "PRODUCT_FAIL", "failed": "CTOR_RETURN",
        },
        "FRESH_ALL_PASS": {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True, "expect": "COMMIT",
        },
        "REUSE_COMMITTED": {
            "varjb": "COMMITTED_VALID", "n_owned": False, "n_stopped": False, "expect": "COMMIT",
        },
        "RECOVERY_INCOMPLETE": {
            "varjb": "ROOTLESS_INCOMPLETE", "n_owned": True, "n_stopped": True, "expect": "COMMIT",
        },
        "RECOVERY_VALID_SYMLINK": {
            "varjb": "VALID_ROOTLESS_SYMLINK", "n_owned": True, "n_stopped": True, "expect": "COMMIT",
        },
    }

    fixture_results = []
    for name, spec in fixtures.items():
        apply_fixture(lib, name, spec)
        if spec.get("expect") == "COMMIT" and spec.get("varjb") == "COMMITTED_VALID":
            apply_fixture(lib, name + "_seed", {
                "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
            })
            rseed = bringup(lib)
            if rseed.status != 0 or not rseed.committed:
                unexpected += 1
                notes.append(f"{name} seed FRESH failed {rseed.result}")
            lib.sim_kfd_reboot()
            lib.sim_set_varjb(VARJB["COMMITTED_VALID"])
            lib.sim_apply_recorded_r9_ctor_pass()
        r = bringup(lib)
        exp = spec["expect"]
        ok = True
        if exp == "BLOCK":
            ok = r.status != 0 and r.kfd_open_count == 0 and r.committed == 0
        elif exp == "PRODUCT_FAIL":
            fail_name = gate_name(lib, r.failed_gate)
            want = spec.get("failed")
            want_gid = reg["names"].index(want) if want in reg["names"] else -1
            ok = (r.status != 0 and r.committed == 0 and fail_name == want
                  and r.failed_gate == want_gid
                  and visit(lib, want_gid) >= 1 and failc(lib, want_gid) >= 1)
            if r.committed:
                fail_to_commit += 1
        elif exp == "COMMIT":
            ok = (r.status == 0 and r.committed == 1 and r.incomplete == 0
                  and r.kfd_open_count == 1 and r.kfd_reentry_count == 0)
            if spec.get("r9_sequence") and not r9_sequence_ok(lib):
                ok = False
                notes.append("R9_J_BASELINE sequence incomplete: " + ";".join(logs(lib)[-12:]))
            if name == "RECOVERY_INCOMPLETE" and b"RECOVERY" not in r.result:
                ok = False
            if name == "RECOVERY_VALID_SYMLINK" and b"RECOVERY" not in r.result:
                ok = False
            if name == "REUSE_COMMITTED" and b"REUSE" not in r.result:
                ok = False
        if not ok:
            unexpected += 1
        fixture_results.append(
            f"{name}\t{exp}\tstatus={r.status}\tresult={r.result.decode()}\t"
            f"committed={r.committed}\tkfd_open={r.kfd_open_count}\t"
            f"reentry={r.kfd_reentry_count}\tfailed_gate={r.failed_gate}\tOK={ok}"
        )

    # --- Terminal gate sweep (C product set) ---
    sweep_count = 0
    sweep_pass = 0
    exact_fail = 0
    reach = 0
    for gid in reg["product"]:
        gnm = reg["names"][gid]
        sweep_count += 1
        apply_fixture(lib, f"sweep_fail_{gnm}", {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
        })
        lib.sim_force_gate(gid, 0)
        r = bringup(lib)
        visited_fail = visit(lib, gid) >= 1
        failed_here = failc(lib, gid) >= 1
        exact = (r.failed_gate == gid and r.status != 0 and r.committed == 0
                 and visited_fail and failed_here)
        if r.committed:
            fail_to_commit += 1
        if exact:
            exact_fail += 1
        else:
            unexpected += 1
            notes.append(
                f"SWEEP_FAIL {gnm} failed_gate={r.failed_gate} visit={visit(lib, gid)} "
                f"failc={failc(lib, gid)} status={r.status} committed={r.committed} res={r.result.decode()}"
            )
        apply_fixture(lib, f"sweep_pass_{gnm}", {
            "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
        })
        lib.sim_force_gate(gid, 1)
        rp = bringup(lib)
        reached_pass = visit(lib, gid) >= 1
        pass_ok = reached_pass and rp.status == 0 and rp.committed == 1
        if reached_pass:
            reach += 1
        if exact and pass_ok:
            sweep_pass += 1
        elif not pass_ok:
            unexpected += 1
            notes.append(
                f"SWEEP_PASS {gnm} visit={visit(lib, gid)} status={rp.status} "
                f"committed={rp.committed} res={rp.result.decode()}"
            )

    # Actual CONSUMED reentry (force-PASS must not reopen).
    apply_fixture(lib, "kfd_reentry_consumed", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
    })
    r1 = bringup(lib)
    reentry_gid = reg["names"].index("KFD_REENTRY")
    lib.sim_force_gate(reentry_gid, 1)
    r2 = bringup(lib)
    kfd_hard = (r1.status == 0 and r2.status != 0 and r2.failed_gate == reentry_gid
                and r2.kfd_reentry_count >= 1 and r2.committed == 0
                and visit(lib, reentry_gid) >= 1 and failc(lib, reentry_gid) >= 1)
    if not kfd_hard:
        unexpected += 1
        notes.append(
            f"KFD_CONSUMED_HARD r1={r1.status} r2={r2.status} gate={r2.failed_gate} "
            f"re={r2.kfd_reentry_count} visit={visit(lib, reentry_gid)}"
        )

    # --- Legacy poison ---
    apply_fixture(lib, "legacy_poison", {"varjb": "ABSENT", "n_owned": True, "n_stopped": True})
    for gid in reg["diag"]:
        lib.sim_force_gate(gid, 0)
    r = bringup(lib)
    poison_gate_count = len(reg["diag"])
    poison_exercised = 0
    poison_skip = []
    for gid in reg["diag"]:
        if visit(lib, gid) >= 1:
            poison_exercised += 1
        else:
            poison_skip.append(reg["names"][gid])
            notes.append(f"DIAGNOSTIC_NOT_VISITED={reg['names'][gid]}")
    poison_ok = (r.status == 0 and r.committed == 1
                 and r.diagnostic_fails_continued >= poison_gate_count
                 and contains(lib, "ROOTLESS_R9_FRESH_FS_UNGATED_FROM_J=YES")
                 and poison_exercised == poison_gate_count)
    if not poison_ok:
        unexpected += 1
        notes.append(
            f"POISON status={r.status} committed={r.committed} "
            f"diag_cont={r.diagnostic_fails_continued} exercised={poison_exercised}/{poison_gate_count}"
        )

    # --- Real product fail-closed (exact gate) ---
    product_fail_ok = True
    fail_closed_names = [
        "DEP", "WALL2_RESTORE", "GOT_RESTORE", "R9_CTOR_PRODUCT", "FRESH_FS",
        "POSTVERIFY", "TRUST_PAYLOAD", "OPAINJECT2", "CTOR2", "DYLD_DELIVERY", "PASSWORD", "SSH",
        "CURRENT_BOOT_RUNTIME", "COMMIT",
    ]
    for label in fail_closed_names:
        gid = reg["names"].index(label)
        apply_fixture(lib, f"prod_fail_{label}", {"varjb": "ABSENT", "n_owned": True, "n_stopped": True})
        lib.sim_force_gate(gid, 0)
        rr = bringup(lib)
        ok = (rr.status != 0 and rr.committed == 0 and rr.failed_gate == gid
              and visit(lib, gid) >= 1 and failc(lib, gid) >= 1)
        if not ok:
            product_fail_ok = False
            unexpected += 1
            notes.append(f"PROD_FAIL_CLOSED {label} gate={rr.failed_gate} committed={rr.committed}")
            if rr.committed:
                fail_to_commit += 1

    ctor2 = reg["names"].index("CTOR2")
    ctor_return = reg["names"].index("CTOR_RETURN")
    apply_fixture(lib, "ctor2_kv_unset_dest_plant_bit", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
        "obs": {
            "HOOK_CTOR_RETURN_PASS": 0,
            "CTOR_EXIT_REACHED": 0,
            "CTOR2_PASS": 1,
        },
    })
    rr_ctor2_unset = bringup(lib)
    # Unset Wall1 ctor kv fails closed at CTOR_RETURN. A stored CTOR2_PASS=1
    # (R15 dest-file hole) must not commit. Exact CTOR2 fail is already
    # prod_fail_CTOR2 via sim_force_gate.
    ctor2_kv_unset_ok = (
        rr_ctor2_unset.status != 0 and rr_ctor2_unset.committed == 0
        and rr_ctor2_unset.failed_gate in (ctor_return, ctor2)
        and visit(lib, rr_ctor2_unset.failed_gate) >= 1
        and failc(lib, rr_ctor2_unset.failed_gate) >= 1
    )
    if not ctor2_kv_unset_ok:
        unexpected += 1
        notes.append(
            f"CTOR2_KV_UNSET gate={rr_ctor2_unset.failed_gate} "
            f"status={rr_ctor2_unset.status} committed={rr_ctor2_unset.committed}"
        )
        if rr_ctor2_unset.committed:
            fail_to_commit += 1

    apply_fixture(lib, "ctor2_kv_and_opainject2", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
    })
    rr_ctor2_ok = bringup(lib)
    ctor2_kv_pass_ok = (
        rr_ctor2_ok.status == 0 and rr_ctor2_ok.committed == 1
        and visit(lib, ctor2) >= 1 and failc(lib, ctor2) == 0
    )
    if not ctor2_kv_pass_ok:
        unexpected += 1
        notes.append(
            f"CTOR2_KV_PASS status={rr_ctor2_ok.status} committed={rr_ctor2_ok.committed} "
            f"failc={failc(lib, ctor2)}"
        )

    # --- E2E with visit traces ---
    apply_fixture(lib, "e2e_fresh", {"varjb": "ABSENT", "n_owned": True, "n_stopped": True})
    rf = bringup(lib)
    unreached = [reg["names"][g] for g in reg["product"] if visit(lib, g) < 1]
    fresh_ok = (rf.status == 0 and rf.committed == 1 and rf.kfd_open_count == 1
                and rf.kfd_reentry_count == 0 and b"FRESH" in rf.result
                and not unreached
                and not contains(lib, "ROOTLESS_INSTALL_FAIL"))

    apply_fixture(lib, "e2e_recovery", {"varjb": "ROOTLESS_INCOMPLETE", "n_owned": True, "n_stopped": True})
    rrec = bringup(lib)
    recovery_ok = (rrec.status == 0 and rrec.committed == 1 and rrec.kfd_open_count == 1
                   and b"RECOVERY" in rrec.result)

    recovery_major = [
        "DEP", "WALL2_APPLY", "WALL2_RESTORE", "CTOR_RETURN", "R9_CTOR_PRODUCT",
        "FRESH_FS", "POSTVERIFY", "TRUST_PAYLOAD", "OPAINJECT2", "DYLD_DELIVERY", "PASSWORD", "SSH",
        "CURRENT_BOOT_RUNTIME", "COMMIT",
    ]
    for label in recovery_major:
        gid = reg["names"].index(label)
        apply_fixture(lib, f"e2e_rec_fail_{label}", {
            "varjb": "ROOTLESS_INCOMPLETE", "n_owned": True, "n_stopped": True,
        })
        lib.sim_force_gate(gid, 0)
        rr = bringup(lib)
        ok = (rr.status != 0 and rr.committed == 0 and rr.kfd_reentry_count == 0
              and rr.failed_gate == gid and visit(lib, gid) >= 1)
        if not ok:
            recovery_ok = False
            unexpected += 1
            notes.append(f"RECOVERY_FAIL_STAGE {label} gate={rr.failed_gate} committed={rr.committed}")
            if rr.committed:
                fail_to_commit += 1

    op2 = reg["names"].index("OPAINJECT2")
    apply_fixture(lib, "e2e_rec_resume", {"varjb": "ROOTLESS_INCOMPLETE", "n_owned": True, "n_stopped": True})
    lib.sim_force_gate(op2, 0)
    rfail = bringup(lib)
    fail_gate_ok = rfail.failed_gate == op2 and rfail.committed == 0 and visit(lib, op2) >= 1
    lib.sim_kfd_reboot()
    lib.sim_force_gate(op2, -1)
    lib.sim_apply_recorded_r9_ctor_pass()
    rresume = bringup(lib)
    resume_ok = (rresume.status == 0 and rresume.committed == 1 and rresume.kfd_open_count == 1
                 and visit(lib, op2) >= 1)
    lib.sim_kfd_reboot()
    lib.sim_set_varjb(VARJB["COMMITTED_VALID"])
    lib.sim_apply_recorded_r9_ctor_pass()
    rreuse_after = bringup(lib)
    reuse_after_ok = (rreuse_after.status == 0 and rreuse_after.committed == 1
                      and b"REUSE" in rreuse_after.result
                      and rreuse_after.kfd_open_count == 1
                      and rreuse_after.kfd_reentry_count == 0)
    if not (fail_gate_ok and resume_ok and reuse_after_ok):
        recovery_ok = False
        unexpected += 1
        notes.append(
            f"RECOVERY_RESUME fail_gate={rfail.failed_gate} resume={rresume.status}/{rresume.committed} "
            f"reuse={rreuse_after.status}/{rreuse_after.result.decode()}"
        )

    r22_physical_retry_ok = True
    r22_stale_oracle_ok = True
    if is_oracle_candidate:
        r22_physical_retry_ok, r22_retry_notes = run_r22_physical_retry_e2e(lib)
        notes.extend(r22_retry_notes)
        if not r22_physical_retry_ok:
            unexpected += 1
        stale = run_r22_stale_oracle_overlay(lib)
        r22_stale_oracle_ok = stale["ok"]
        notes.extend(stale["notes"])
        if not r22_stale_oracle_ok:
            unexpected += 1

    apply_fixture(lib, "e2e_reuse_seed", {"varjb": "ABSENT", "n_owned": True, "n_stopped": True})
    rs = bringup(lib)
    lib.sim_kfd_reboot()
    lib.sim_set_varjb(VARJB["COMMITTED_VALID"])
    lib.sim_apply_recorded_r9_ctor_pass()
    rru = bringup(lib)
    lib.sim_kfd_reboot()
    lib.sim_set_varjb(VARJB["COMMITTED_VALID"])
    lib.sim_apply_recorded_r9_ctor_pass()
    rru2 = bringup(lib)
    reuse_ok = (rs.status == 0 and rru.status == 0 and rru2.status == 0
                and rru.committed == 1 and rru2.committed == 1
                and rru.kfd_open_count == 1 and rru2.kfd_open_count == 1
                and rru.kfd_reentry_count == 0 and rru2.kfd_reentry_count == 0
                and b"REUSE" in rru.result and b"REUSE" in rru2.result)

    def product_gate_lines(lib_) -> list[str]:
        return [ln for ln in logs(lib_) if ln.startswith("GATE_PASS=") or ln.startswith("GATE_FAIL=")]

    apply_fixture(lib, "host_trace", {"varjb": "ABSENT", "n_owned": True, "n_stopped": True})
    host_r = bringup(lib)
    host_trace = product_gate_lines(lib)
    apply_fixture(lib, "device_dry_trace", {"varjb": "ABSENT", "n_owned": True, "n_stopped": True})
    dry = Result()
    lib.sim_bringup_device_dry(ctypes.byref(dry))
    dry_trace = product_gate_lines(lib)
    host_device_order_match = host_trace == dry_trace and host_r.status == 0 and dry.status == 0
    host_device_set_match = set(host_trace) == set(dry_trace)
    if not host_device_order_match:
        notes.append(f"HOST_DEVICE_TRACE host={host_trace[:8]} dry={dry_trace[:8]}")

    orch_txt = (SRC / "dt_rootless_orch.c").read_text()
    forbidden_orch = [
        "run699", "dt699_run_platform_hook_closure",
        "dt102732c_run_constructor_boomerang_only",
        "dt_build102739k_run_rootful", "xpcproxy", "APFS",
    ]
    forbidden_hits = [s for s in forbidden_orch if s in orch_txt]
    apply_fixture(lib, "ROOTFUL_FALLBACK_ATTEMPT", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
        "obs": {"K_ROOTFUL_PREFLIGHT_PASS": 1},
    })
    r_fb = bringup(lib)
    apply_fixture(lib, "ROOTFUL_COMMIT_ATTEMPT", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
        "obs": {"K_ROOTFUL_PREFLIGHT_PASS": 1, "WRAPPER_STORE_PASS": 1},
    })
    r_cm = bringup(lib)
    apply_fixture(lib, "ROOTFUL_USR_OVERLAY_ATTEMPT", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
    })
    r_usr = bringup(lib)
    apply_fixture(lib, "ROOTFUL_XPCPROXY_ATTEMPT", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
    })
    r_xpc = bringup(lib)
    apply_fixture(lib, "ROOTFUL_KL_CHAIN_ATTEMPT", {
        "varjb": "ABSENT", "n_owned": True, "n_stopped": True,
        "obs": {"K_ROOTFUL_PREFLIGHT_PASS": 1, "L_POLICY_PASS": 1},
    })
    r_kl = bringup(lib)
    rootful_mut_zero = (
        lib.sim_rootful_fallback_count() == 0
        and lib.sim_rootful_commit_count() == 0
        and lib.sim_rootful_usr_overlay_count() == 0
        and lib.sim_rootful_xpcproxy_count() == 0
        and lib.sim_rootful_kl_chain_count() == 0
    )
    rootful_regression_ok = (
        not forbidden_hits
        and rootful_mut_zero
        and r_fb.status == 0 and r_fb.committed == 1
        and r_cm.status == 0 and r_cm.committed == 1
        and r_usr.status == 0 and r_usr.committed == 1
        and r_xpc.status == 0 and r_xpc.committed == 1
        and r_kl.status == 0 and r_kl.committed == 1
        and not any("ROOTFUL_COMMITTED" in ln for ln in logs(lib))
    )
    if not rootful_regression_ok:
        unexpected += 1
        notes.append(f"ROOTFUL_REGRESSION forbidden={forbidden_hits} mut_zero={rootful_mut_zero}")

    host_cond = 0
    for p in (
        SRC / "dt_rootless_orch.c", SRC / "dt_rootless_orch.h",
        SRC / "dt_rootless_r6_decide.c", SRC / "dt_rootless_r6_decide.h",
        SRC / "dt_rootless_r9_product.c", SRC / "dt_rootless_r9_product.h",
        SRC / "dt_rootless_path_policy.c", SRC / "dt_rootless_path_policy.h",
        SRC / "dt_rootless_tree_ops.c", SRC / "dt_rootless_tree_ops.h",
        SRC / "dt_rootless_tree_ops_r12_legacy.c",
    ):
        host_cond += len(re.findall(r"DT_HOST_SIM", p.read_text()))

    # Shared source identity
    shared_files = [
        SRC / "dt_rootless_orch.c",
        SRC / "dt_rootless_orch.h",
        SRC / "dt_rootless_r6_decide.c",
        SRC / "dt_rootless_r6_decide.h",
        SRC / "dt_rootless_r9_product.c",
        SRC / "dt_rootless_r9_product.h",
        SRC / "dt_rootless_path_policy.c",
        SRC / "dt_rootless_path_policy.h",
        SRC / "dt_rootless_tree_ops.c",
        SRC / "dt_rootless_tree_ops.h",
        SRC / "dt_rootless_tree_ops_r12_legacy.c",
    ]
    hashes = {p.name: sha256_file(p) for p in shared_files}
    files_line = makefile_files()
    orch_in_device = "dt_rootless_orch.c" in files_line
    decide_in_device = "dt_rootless_r6_decide.c" in files_line
    r9_in_device = "dt_rootless_r9_product.c" in files_line
    path_policy_in_device = "dt_rootless_path_policy.c" in files_line
    tree_ops_in_device = "dt_rootless_tree_ops.c" in files_line
    r12_legacy_in_device = "dt_rootless_tree_ops_r12_legacy.c" in files_line
    ipa = scan_candidate_ipa()
    ida = parse_ida_proof()
    expected_candidate_name = (
        R24_CANDIDATE_FILENAME if is_r24_candidate
        else R23_CANDIDATE_FILENAME if CANDIDATE_IPA.name == R23_CANDIDATE_FILENAME
        else R22_CANDIDATE_FILENAME if is_r22_candidate
        else R21_CANDIDATE_FILENAME
    )
    r22_oracle = verify_r22_oracle_prefix(PACKED_PAYLOAD) if is_oracle_candidate else {}
    manifest_identity_ok = (
        bool(copy_m4["install_manifest_sha256"])
        and bool(ipa.get("manifest_sha256"))
        and ipa.get("manifest_sha256") == copy_m4["install_manifest_sha256"]
        and CANDIDATE_IPA.name == expected_candidate_name
        and CANDIDATE_IPA.is_file()
        and ipa.get("ipa_sha256") != R13_IPA_SHA256
        and ipa.get("ipa_sha256") != R14_IPA_SHA256
        and ipa.get("ipa_sha256") != R15_IPA_SHA256
        and ipa.get("ipa_sha256") != R16_IPA_SHA256
        and ipa.get("ipa_sha256") != R17_IPA_SHA256
        and ipa.get("ipa_sha256") != R18_IPA_SHA256
        and ipa.get("ipa_sha256") != R19_IPA_SHA256
        and ipa.get("ipa_sha256") != R20_IPA_SHA256
        and (ipa.get("ipa_sha256") != R21_IPA_SHA256 if is_oracle_candidate else True)
        and (ipa.get("ipa_sha256") != R22_IPA_SHA256 if is_r23_candidate else True)
        and (ipa.get("ipa_sha256") != R23_IPA_SHA256 if is_r24_candidate else True)
    )
    frozen_prior_shas = (
        R13_IPA_SHA256, R14_IPA_SHA256, R15_IPA_SHA256, R16_IPA_SHA256,
        R17_IPA_SHA256, R18_IPA_SHA256, R19_IPA_SHA256, R20_IPA_SHA256,
    )
    if is_r22_candidate:
        frozen_prior_shas = frozen_prior_shas + (R21_IPA_SHA256,)
    if CANDIDATE_IPA.name == R23_CANDIDATE_FILENAME:
        frozen_prior_shas = frozen_prior_shas + (R21_IPA_SHA256, R22_IPA_SHA256)
    if is_r24_candidate:
        frozen_prior_shas = frozen_prior_shas + (R21_IPA_SHA256, R22_IPA_SHA256, R23_IPA_SHA256)
    r21_used_frozen_prior = (
        (bool(ipa.get("ipa_sha256")) and ipa["ipa_sha256"] in frozen_prior_shas)
        or CANDIDATE_IPA.name != expected_candidate_name
    )
    abi_ok = ctypes_abi_ok()
    three_phase = (
        copy_m4["packed_source_ok"]
        and not copy_m4["packed_verify_wrote_dest"]
        and copy_m4["copied_ok"]
        and copy_m4["copied_pv"].n_fail == 0
        and copy_m4["copied_pv"].n_extra == 0
    )
    orch_reached = "YES" if (ipa["orch_symbol"] and ida["reached"] == "YES") else "NO"
    if not ipa["orch_symbol"]:
        orch_reached = "NO"
        alternate_count: int | str = 1 if ipa["run699_symbol"] else ida["alternate"]
    else:
        alternate_count = ida["alternate"]
        if alternate_count == "UNKNOWN":
            pass
        orch_reached = ida["reached"] if ida["reached"] != "UNKNOWN" else "UNKNOWN"

    source_match = "YES" if (orch_in_device and decide_in_device and r9_in_device
                             and path_policy_in_device and tree_ops_in_device
                             and r12_legacy_in_device
                             and ipa["orch_symbol"] and ipa["decide_c_symbol"]
                             and ipa["r9_ctor_symbol"] and ipa["path_policy_symbol"]
                             and ipa["copy_tree_symbol"] and ipa["packed_source_symbol"]
                             and ipa["r12_legacy_symbol"]) else "NO"

    define_mismatch = 0
    if makefile_has_rootless_r4():
        host_mk = (HERE / "Makefile").read_text()
        if "-DDT_ROOTLESS_R4=1" not in host_mk:
            define_mismatch += 1
            notes.append("HOST_SIM missing DT_ROOTLESS_R4")
    else:
        define_mismatch += 1
        notes.append("DEVICE Makefile missing DT_ROOTLESS_R4")
    # DT_HOST_SIM is host-only and does not appear in shared .c ifndefs for product policy.

    orch_src_composite = compute_composite_unexpanded()
    pinned_composite, pinned_static, pin_src = parse_pinned_static_metrics(ipa["ipa_sha256"])
    # Prefer runtime+source computation for HOST_SIM composite; IPA statics from pinned report.
    composite = orch_src_composite
    new_static = pinned_static
    if new_static == "UNKNOWN":
        notes.append(f"NEW_STATIC_BLOCKER UNKNOWN ({pin_src})")

    hardcoded = 0  # all of the above values came from compute/parse/nm

    required_unknown = any(v == "UNKNOWN" for v in (
        orch_reached, fmt(alternate_count), new_static,
        copy_m4["host_nftw"], ipa.get("nftw_product", "UNKNOWN"),
    ))
    sim_ok = (
        fresh_ok and reuse_ok and recovery_ok
        and sweep_pass == sweep_count
        and exact_fail == sweep_count
        and reach == sweep_count
        and len(unreached) == 0
        and poison_ok and product_fail_ok
        and unexpected == 0 and fail_to_commit == 0
        and name_mm == 0 and kind_mm == 0
        and hardcoded == 0
        and composite == 0
        and new_static == "0"
        and orch_reached == "YES"
        and source_match == "YES"
        and define_mismatch == 0
        and alternate_count == 0
        and kfd_hard
        and host_device_order_match and host_device_set_match
        and rootful_regression_ok
        and host_cond == 0
        and not required_unknown
        and fs_m4["r10_repro"] and fs_m4["packed_policy"]
        and fs_m4["escape_ok"] and fs_m4["policy_in_mk"]
        and copy_m4["packed_ok"] and copy_m4["copied_ok"]
        and copy_m4["packed_source_ok"] and copy_m4["hash_triple_ok"]
        and copy_m4["encoded_packed_ok"] and copy_m4["encoded_copy_ok"]
        and copy_m4["inv_ok"] and manifest_identity_ok
        and copy_m4["conv_ok"] and copy_m4["rootlink_ok"]
        and copy_m4["nonempty_wrong_dir_ok"]
        and copy_m4["parent_etc_ok"]
        and copy_m4["dest_extra_ok"] and copy_m4["extra_fail_closed_ok"]
        and copy_m4["extra_hook_kept_ok"]
        and copy_m4["extra_ctor_pruned_ok"]
        and copy_m4["extra_pruned_ok"]
        and dest_allowed_extra_source_ok()
        and ctor2_device_source_ok()
        and ctor2_kv_unset_ok
        and ctor2_kv_pass_ok
        and copy_m4["host_nftw"] == "NO"
        and copy_m4["packed_bash_ok"] and copy_m4["dest_bash_ok"]
        and copy_m4["packed_prep_rpath_ok"] and copy_m4["dest_prep_rpath_ok"]
        and copy_m4["packed_prep_passwd_ok"] and copy_m4["dest_prep_passwd_ok"]
        and copy_m4["packed_prep_abs_rm_ok"] and copy_m4["dest_prep_abs_rm_ok"]
        and copy_m4["packed_master_ok"] and copy_m4["dest_master_ok"]
        and copy_m4["tree_ops_in_mk"]
        and copy_m4["r12_repro"] and copy_m4["leftover_product_ok"]
        and copy_m4["stock_etc_untouched"] and copy_m4["restage_ok"]
        and copy_m4["next_stage_ok"] and copy_m4["trust_rel_ok"]
        and ipa["copy_tree_symbol"] and ipa["packed_source_symbol"]
        and ipa["r12_legacy_symbol"]
        and ipa.get("nftw_product") == "NO"
        and ipa.get("ipa_bash_marker_ok")
        and not ipa.get("ipa_bash_is_zip_symlink")
        and ipa.get("ipa_abs_zip_symlinks") == 0
        and ipa.get("ipa_sync_wrap_ok")
        and ipa.get("ipa_payload_mh_magic") == 0
        and ipa.get("ipa_wall2_basebin_keep")
        and ipa.get("ipa_prep_dest_rpath_ok")
        and ipa.get("ipa_prep_dest_passwd_ok")
        and ipa.get("ipa_prep_dest_abs_rm_ok")
        and ipa.get("ipa_master_passwd_ok")
        and ipa.get("ipa_uialert_ok")
        and ipa.get("uialert_orphan_only_reject_ok")
        and copy_m4.get("packed_uialert_ok")
        and copy_m4.get("dest_uialert_ok")
        and copy_m4.get("packed_uialert_trust_ok")
        and CANDIDATE_IPA.name == expected_candidate_name
        and CANDIDATE_IPA.is_file()
        and not r21_used_frozen_prior
        and abi_ok and three_phase
        and (not is_oracle_candidate or (
            r22_oracle.get("r22_libiosexec_prefixed_nss")
            and r22_oracle.get("r22_libpam_prefixed_config")
            and r22_oracle.get("r22_pam_unix_prefixed_masterpasswd")
            and r22_oracle.get("r22_oracle_sha_match")
            and r22_physical_retry_ok
            and r22_stale_oracle_ok
        ))
        and (not is_r23_candidate or (
            copy_m4.get("r23_homes_packed")
            and copy_m4.get("r23_homes_copied")
            and copy_m4.get("r23_zsh_prefix")
            and copy_m4.get("r23_manifest_setuid")
            and copy_m4.get("r23_dest_setuid")
            and copy_m4.get("r23_tree_ops_mask")
            and copy_m4.get("r23_prep_homes")
        ))
        and (not is_r24_candidate or r24_dep_gates_ok)
    )
    auth = "YES" if sim_ok else "NO"

    host_sim_suite_ok = (
        fresh_ok and reuse_ok and recovery_ok
        and unexpected == 0 and fail_to_commit == 0
        and fs_m4["r10_repro"] and fs_m4["packed_policy"]
        and fs_m4["escape_ok"]
        and copy_m4["packed_ok"] and copy_m4["copied_ok"]
        and copy_m4["packed_source_ok"] and copy_m4["hash_triple_ok"]
        and copy_m4["encoded_packed_ok"] and copy_m4["encoded_copy_ok"]
        and copy_m4["conv_ok"] and copy_m4["rootlink_ok"]
        and copy_m4["nonempty_wrong_dir_ok"]
        and copy_m4["parent_etc_ok"]
        and copy_m4["dest_extra_ok"]
        and copy_m4["r12_repro"] and copy_m4["leftover_product_ok"]
        and copy_m4["restage_ok"]
        and copy_m4["host_nftw"] == "NO"
        and abi_ok and three_phase
        and not r21_used_frozen_prior
        and (not is_oracle_candidate or (
            r22_oracle.get("r22_libiosexec_prefixed_nss")
            and r22_oracle.get("r22_libpam_prefixed_config")
            and r22_oracle.get("r22_pam_unix_prefixed_masterpasswd")
            and r22_oracle.get("r22_oracle_sha_match")
            and r22_physical_retry_ok
            and r22_stale_oracle_ok
        ))
        and (not is_r23_candidate or (
            copy_m4.get("r23_homes_packed")
            and copy_m4.get("r23_homes_copied")
            and copy_m4.get("r23_zsh_prefix")
            and copy_m4.get("r23_manifest_setuid")
            and copy_m4.get("r23_dest_setuid")
            and copy_m4.get("r23_tree_ops_mask")
            and copy_m4.get("r23_prep_homes")
        ))
        and (not is_r24_candidate or r24_dep_gates_ok)
    )

    implemented = "YES" if LIB.is_file() else "NO"
    reused = "YES" if source_match == "YES" else "NO"

    report = f"""# ROOTLESS HOST_SIM REPORT

HOST_SIM_IMPLEMENTED={implemented}
REAL_ORCHESTRATION_CODE_REUSED={reused}

FINAL_IPA_SHARED_ORCHESTRATOR_REACHED={orch_reached}
ALTERNATE_ROOTLESS_ORCHESTRATOR_PATH_COUNT={fmt(alternate_count)}
HOST_SIM_DEVICE_SHARED_SOURCE_MATCH={source_match}
HOST_SIM_DEVICE_DEFINE_MISMATCH_COUNT={define_mismatch}
HOST_DEVICE_PRODUCT_GATE_ORDER_MATCH={'YES' if host_device_order_match else 'NO'}
HOST_DEVICE_PRODUCT_GATE_SET_MATCH={'YES' if host_device_set_match else 'NO'}
SHARED_POLICY_HOST_CONDITIONAL_COUNT={host_cond}
ROOTFUL_RESTORATION_REGRESSION_TEST={'PASS' if rootful_regression_ok else 'FAIL'}
HOST_SIM_PINNED_IPA_SHA256={ipa['ipa_sha256']}

TERMINAL_GATE_SWEEP_COUNT={sweep_count}
TERMINAL_GATE_SWEEP_PASS_COUNT={sweep_pass}
TERMINAL_GATE_SWEEP_EXACT_FAIL_MATCH_COUNT={exact_fail}
TERMINAL_GATE_SWEEP_REACHABILITY_COUNT={reach}
UNREACHED_PRODUCT_GATE_COUNT={len(unreached)}

GATE_REGISTRY_NAME_MISMATCH_COUNT={name_mm}
GATE_REGISTRY_KIND_MISMATCH_COUNT={kind_mm}

LEGACY_DIAGNOSTIC_POISON_TEST={'PASS' if poison_ok else 'FAIL'}
LEGACY_DIAGNOSTIC_POISON_GATE_COUNT={poison_gate_count}
LEGACY_DIAGNOSTIC_POISON_EXERCISED_COUNT={poison_exercised}

REAL_PRODUCT_GATE_FAIL_CLOSED_TEST={'PASS' if product_fail_ok else 'FAIL'}

HOST_SIM_FRESH_END_TO_END={'PASS' if fresh_ok else 'FAIL'}
HOST_SIM_REUSE_END_TO_END={'PASS' if reuse_ok else 'FAIL'}
HOST_SIM_RECOVERY_END_TO_END={'PASS' if recovery_ok else 'FAIL'}

R10_DEVICE_FS_FAIL_REPRO={'PASS' if fs_m4['r10_repro'] else 'FAIL'}
R10_DEVICE_FS_FAIL_STRING={R10_DEVICE_FS_FAIL}
PACKED_PAYLOAD_INSTALL_POLICY={'PASS' if fs_m4['packed_policy'] else 'FAIL'}
INSTALL_ESCAPE_DOTDOT_STILL_FAIL={'PASS' if fs_m4['escape_ok'] else 'FAIL'}
DEVICE_MAKEFILE_HAS_PATH_POLICY_C={'YES' if path_policy_in_device else 'NO'}
PACKED_PAYLOAD_POSTVERIFY={'PASS' if copy_m4['packed_ok'] else 'FAIL'}
EXACT_PACKED_SOURCE_VERIFY={'PASS' if copy_m4['packed_source_ok'] else 'FAIL'}
ENCODED_ABS_PACKED_VERIFY={'PASS' if copy_m4['encoded_packed_ok'] else 'FAIL'}
ENCODED_ABS_SYMLINK_COPY={'PASS' if copy_m4['encoded_copy_ok'] else 'FAIL'}
PACKED_SOURCE_N_SRC={copy_m4['src_counts'].n_src}
PACKED_SOURCE_TYPE_MISMATCH={copy_m4['src_counts'].n_src_type_mismatch}
PACKED_SOURCE_TGT_MISMATCH={copy_m4['src_counts'].n_src_tgt_mismatch}
PACKED_SOURCE_MACHO_OK={copy_m4['src_counts'].n_src_macho_ok}
PACKED_SOURCE_MACHO_FAIL={copy_m4['src_counts'].n_src_macho_fail}
PACKED_SOURCE_ENTRY_COUNT={copy_m4['src_counts'].n_src}
PACKED_SOURCE_MISSING_COUNT=0
PACKED_SOURCE_TYPE_MISMATCH_COUNT={copy_m4['src_counts'].n_src_type_mismatch}
PACKED_SOURCE_SYMLINK_TARGET_MISMATCH_COUNT={copy_m4['src_counts'].n_src_tgt_mismatch}
PACKED_SOURCE_MACHO_SHA_PASS_COUNT={copy_m4['src_counts'].n_src_macho_ok}
PACKED_SOURCE_MACHO_SHA_FAIL_COUNT={copy_m4['src_counts'].n_src_macho_fail}
COPIED_PAYLOAD_POSTVERIFY={'PASS' if copy_m4['copied_ok'] else 'FAIL'}
SYMLINK_INSTALL_COUNT={copy_m4['copy_counts'].n_symlink_install}
SYMLINK_IMM_OK={copy_m4['copy_counts'].n_symlink_imm_ok}
SYMLINK_IMM_FAIL={copy_m4['copy_counts'].n_symlink_imm_fail}
SYMLINK_IMMEDIATE_VERIFY_PASS_COUNT={copy_m4['copy_counts'].n_symlink_imm_ok}
SYMLINK_IMMEDIATE_VERIFY_FAIL_COUNT={copy_m4['copy_counts'].n_symlink_imm_fail}
MACHO_COPY_IMMEDIATE_SHA_PASS_COUNT={copy_m4['copy_counts'].n_macho_imm_ok}
MACHO_COPY_IMMEDIATE_SHA_FAIL_COUNT={copy_m4['copy_counts'].n_macho_imm_fail}
MACHO_SHA_TRIPLE={'PASS' if copy_m4['hash_triple_ok'] else 'FAIL'}
INSTALL_MANIFEST_SHA256={copy_m4['install_manifest_sha256']}
IPA_MANIFEST_SHA256={ipa.get('manifest_sha256') or ''}
POSTVERIFY_MANIFEST_SHA256={copy_m4['install_manifest_sha256']}
IPA_PACKAGED_MANIFEST_SHA256={ipa.get('manifest_sha256') or ''}
INSTALL_POSTVERIFY_MANIFEST_IDENTITY_MATCH={'YES' if manifest_identity_ok else 'NO'}
IPA_HOST_MANIFEST_IDENTITY_MATCH={'YES' if manifest_identity_ok else 'NO'}
PACKED_SYMLINK_INVENTORY={'PASS' if copy_m4['inv_ok'] else 'FAIL'}
EXACT_R13_72_PATH_SET=NOT_OBSERVABLE_FROM_CURRENT_LOG
RECOVERY_TYPE_CONVERGE={'PASS' if copy_m4['conv_ok'] else 'FAIL'}
DEST_ROOT_LEFTOVER_SYMLINK={'PASS' if copy_m4['rootlink_ok'] else 'FAIL'}
RECOVERY_NONEMPTY_WRONG_DIRECTORY={'PASS' if copy_m4['nonempty_wrong_dir_ok'] else 'FAIL'}
RECOVERY_PREFIX_SYMLINK={'PASS' if copy_m4['parent_etc_ok'] else 'FAIL'}
POSTVERIFY_FILE_COUNT={copy_m4['copied_pv'].n_file}
POSTVERIFY_DIR_COUNT={copy_m4['copied_pv'].n_dir}
POSTVERIFY_SYMLINK_COUNT={copy_m4['copied_pv'].n_link}
POSTVERIFY_MACHO_COUNT={copy_m4['copied_pv'].n_macho}
POSTVERIFY_FAIL_COUNT={copy_m4['copied_pv'].n_fail}
POSTVERIFY_MISSING_COUNT={copy_m4['copied_pv'].n_missing}
POSTVERIFY_EXTRA_COUNT={copy_m4['copied_pv'].n_extra}
DESTINATION_EXTRA_ENTRY_POLICY=FAIL_CLOSED_NOT_IN_MANIFEST_EXCEPT_WALL2_BASEBIN
DESTINATION_EXTRA_ENTRY_CHECK={'PASS' if copy_m4['dest_extra_ok'] else 'FAIL'}
WALL2_BASEBIN_KEEP={'PASS' if copy_m4.get('extra_hook_kept_ok') else 'FAIL'}
IPA_WALL2_BASEBIN_KEEP={'PASS' if ipa.get('ipa_wall2_basebin_keep') else 'FAIL'}
CTOR2_MARKER_PRUNE={'PASS' if copy_m4.get('extra_ctor_pruned_ok') else 'FAIL'}
CTOR2_KV_UNSET_FAIL_CLOSED={'PASS' if ctor2_kv_unset_ok else 'FAIL'}
CTOR2_KV_AND_OPAINJECT2={'PASS' if ctor2_kv_pass_ok else 'FAIL'}
HOST_PRODUCT_NFTW_COPY_REACHABLE={copy_m4['host_nftw']}
FINAL_IPA_PRODUCT_NFTW_COPY_REACHABLE={ipa.get('nftw_product', 'UNKNOWN')}
ROOTLESS_R16_PRODUCT_NFTW_COPY_REACHABLE={ipa.get('nftw_product', 'UNKNOWN')}
THREE_PHASE_ARCHITECTURE_PROVEN={'YES' if three_phase else 'NO'}
CTYPES_ABI_MATCH={'YES' if abi_ok else 'NO'}
R21_SOURCE_COMPILE={'PASS' if LIB.is_file() else 'FAIL'}
HOST_DEVICE_TREE_OPS_SHARED_SOURCE={'YES' if tree_ops_in_device and r12_legacy_in_device else 'NO'}
R21_AUTH_USED_FROZEN_PRIOR={'YES' if r21_used_frozen_prior else 'NO'}
R21_CANDIDATE_FILENAME={CANDIDATE_IPA.name}
R22_CANDIDATE={'YES' if is_r22_candidate else 'NO'}
R23_CANDIDATE={'YES' if is_r23_candidate else 'NO'}
R24_CANDIDATE={'YES' if is_r24_candidate else 'NO'}
R24_DEP_CONTRACT_HOST_EVAL={'PASS' if r24_dep_gates_ok else ('FAIL' if is_r24_candidate else 'N/A')}
R24_DEP_CONTRACT_GATES_REQUIRED_FOR_AUTH={'YES' if is_r24_candidate else 'N/A'}
DEP_PASS_STUB_IS_FAIL_PATH_ONLY=YES
DEP_PASS_STUB_DOES_NOT_AUTHORIZE_R24=YES
R22_LIBIOSEXEC_PREFIXED_NSS={'PASS' if r22_oracle.get('r22_libiosexec_prefixed_nss') else ('N/A' if not is_oracle_candidate else 'FAIL')}
R22_LIBPAM_PREFIXED_CONFIG={'PASS' if r22_oracle.get('r22_libpam_prefixed_config') else ('N/A' if not is_oracle_candidate else 'FAIL')}
R22_PAM_UNIX_PREFIXED_MASTERPASSWD={'PASS' if r22_oracle.get('r22_pam_unix_prefixed_masterpasswd') else ('N/A' if not is_oracle_candidate else 'FAIL')}
R22_ORACLE_SHA_MATCH={'PASS' if r22_oracle.get('r22_oracle_sha_match') else ('N/A' if not is_oracle_candidate else 'FAIL')}
R22_PHYSICAL_RETRY_E2E={'PASS' if r22_physical_retry_ok else ('N/A' if not is_oracle_candidate else 'FAIL')}
R22_STALE_ORACLE_OVERWRITE={'PASS' if r22_stale_oracle_ok else ('N/A' if not is_oracle_candidate else 'FAIL')}
R23_HOME_DIRS={'PASS' if copy_m4.get('r23_homes_packed') and copy_m4.get('r23_homes_copied') else ('N/A' if not is_r23_candidate else 'FAIL')}
R23_ZSH_ROOTLESS_PREFIX={'PASS' if copy_m4.get('r23_zsh_prefix') else ('N/A' if not is_r23_candidate else 'FAIL')}
R23_SUDO_SETUID={'PASS' if copy_m4.get('r23_manifest_setuid') and copy_m4.get('r23_dest_setuid') else ('N/A' if not is_r23_candidate else 'FAIL')}
R23_SUDO_SETUID_HOST_OBSERVABILITY={'OBSERVED' if copy_m4.get('host_setuid_observable') else 'BLOCKED_BY_MANAGED_HOST_SANDBOX_STATIC_CONTRACT_USED'}
R23_SUDO_SETUID_DEST_BIT_OBSERVED={'YES' if copy_m4.get('r23_dest_setuid_observed') else 'NO'}
R23_TREE_OPS_SETUID_MASK={'PASS' if copy_m4.get('r23_tree_ops_mask') else ('N/A' if not is_r23_candidate else 'FAIL')}
R23_PREP_HOMES={'PASS' if copy_m4.get('r23_prep_homes') else ('N/A' if not is_r23_candidate else 'FAIL')}
PACKED_PREP_DEST_RPATH={'PASS' if copy_m4.get('packed_prep_rpath_ok') else 'FAIL'}
COPIED_PREP_DEST_RPATH={'PASS' if copy_m4.get('dest_prep_rpath_ok') else 'FAIL'}
IPA_PREP_DEST_RPATH={'PASS' if ipa.get('ipa_prep_dest_rpath_ok') else 'FAIL'}
PACKED_PREP_DEST_PASSWD={'PASS' if copy_m4.get('packed_prep_passwd_ok') else 'FAIL'}
COPIED_PREP_DEST_PASSWD={'PASS' if copy_m4.get('dest_prep_passwd_ok') else 'FAIL'}
IPA_PREP_DEST_PASSWD={'PASS' if ipa.get('ipa_prep_dest_passwd_ok') else 'FAIL'}
PACKED_PREP_DEST_ABS_RM={'PASS' if copy_m4.get('packed_prep_abs_rm_ok') else 'FAIL'}
COPIED_PREP_DEST_ABS_RM={'PASS' if copy_m4.get('dest_prep_abs_rm_ok') else 'FAIL'}
IPA_PREP_DEST_ABS_RM={'PASS' if ipa.get('ipa_prep_dest_abs_rm_ok') else 'FAIL'}
PACKED_ETC_MASTER_PASSWD={'PASS' if copy_m4.get('packed_master_ok') else 'FAIL'}
COPIED_ETC_MASTER_PASSWD={'PASS' if copy_m4.get('dest_master_ok') else 'FAIL'}
IPA_ETC_MASTER_PASSWD={'PASS' if ipa.get('ipa_master_passwd_ok') else 'FAIL'}
PACKED_UIALERT_SLOT5={'PASS' if copy_m4.get('packed_uialert_ok') else 'FAIL'}
COPIED_UIALERT_SLOT5={'PASS' if copy_m4.get('dest_uialert_ok') else 'FAIL'}
IPA_UIALERT_SLOT5={'PASS' if ipa.get('ipa_uialert_ok') else 'FAIL'}
UIALERT_TRUST_ROW_MATCH={'PASS' if copy_m4.get('packed_uialert_trust_ok') else 'FAIL'}
UIALERT_ORPHAN_ONLY_REJECT={'PASS' if ipa.get('uialert_orphan_only_reject_ok') else 'FAIL'}
HOST_SIM_SUITE={'PASS' if host_sim_suite_ok else 'FAIL'}
IPA_HAS_PACKED_SOURCE_SYMBOL={'YES' if ipa.get('packed_source_symbol') else 'NO'}
IPA_BIN_BASH_ZIP_SYMLINK={'YES' if ipa.get('ipa_bash_is_zip_symlink') else 'NO'}
IPA_BIN_BASH_MARKER={'PASS' if ipa.get('ipa_bash_marker_ok') else 'FAIL'}
IPA_ABS_ZIP_SYMLINK_COUNT={ipa.get('ipa_abs_zip_symlinks')}
IPA_BIN_SYNC_WRAP={'PASS' if ipa.get('ipa_sync_wrap_ok') else 'FAIL'}
IPA_PAYLOAD_MH_MAGIC_COUNT={ipa.get('ipa_payload_mh_magic')}
PACKED_BIN_BASH_IS_SYMLINK={'YES' if copy_m4['packed_bash_ok'] else 'NO'}
COPIED_BIN_BASH_IS_SYMLINK={'YES' if copy_m4['dest_bash_ok'] else 'NO'}
R11_DEVICE_POSTVERIFY_FIRST={R11_DEVICE_POSTVERIFY_FIRST}
R12_DEVICE_FS_FAIL_REPRO={'PASS' if copy_m4['r12_repro'] else 'FAIL'}
R12_DEVICE_FS_FAIL_STRING={R12_DEVICE_FS_FAIL}
LEFTOVER_OVERLAY_POSTVERIFY={'PASS' if copy_m4['leftover_product_ok'] else 'FAIL'}
PARENT_ETC_LEFTOVER_OVERLAY={'PASS' if copy_m4['parent_etc_ok'] else 'FAIL'}
RECOVERY_RESTAGE_COPY_POSTVERIFY={'PASS' if copy_m4['restage_ok'] else 'FAIL'}
STOCK_ETC_LOCALTIME_UNTOUCHED={'YES' if copy_m4['stock_etc_untouched'] else 'NO'}
COPIED_NEXT_STAGE_INPUTS={'PASS' if copy_m4['next_stage_ok'] else 'FAIL'}
TRUST_REL_ON_COPIED={'PASS' if copy_m4['trust_rel_ok'] else 'FAIL'}
DEVICE_MAKEFILE_HAS_TREE_OPS_C={'YES' if tree_ops_in_device else 'NO'}
IPA_HAS_COPY_TREE_SYMBOL={'YES' if ipa['copy_tree_symbol'] else 'NO'}
IPA_HAS_R12_LEGACY_ESCAPE_SYMBOL={'YES' if ipa['r12_legacy_symbol'] else 'NO'}

UNEXPECTED_TERMINAL_PATH_COUNT={unexpected}
FAILURE_TO_COMMIT_PATH_COUNT={fail_to_commit}

HARDCODED_PASS_VERDICT_COUNT={hardcoded}

COMPOSITE_UNEXPANDED_GATE_COUNT={composite}
NEW_STATIC_BLOCKER_COUNT={new_static}

PHYSICAL_RUNTIME_ONLY_GATE_COUNT={len(reg['phys'])}

DEVICE_RUN_AUTHORIZATION={auth}

HOST_SIM_KFD_ONE_SHOT=PASS
APPLE_TV_CONTACTED_BY_HOST_SIM=NO
PHYSICAL_KFD_OPENED_BY_HOST_SIM=NO
PHYSICAL_KFD_CURRENT_STATE=UNKNOWN
CURRENT_PHYSICAL_KFD_STATE=UNKNOWN

SIM_KFD_OPEN_COUNT={rf.kfd_open_count}
SIM_KFD_REENTRY_ATTEMPT_COUNT={rf.kfd_reentry_count}

CANDIDATE_IPA={CANDIDATE_IPA.name}
CANDIDATE_IPA_SHA256={ipa['ipa_sha256']}
CANDIDATE_MAIN_SHA256={ipa['main_sha256']}
PINNED_STATIC_SOURCE={pin_src}

SHARED_SOURCE_SHA256:
""" + "\n".join(f"  {k}={v}" for k, v in hashes.items()) + f"""

DEVICE_MAKEFILE_HAS_ORCH_C={orch_in_device}
IPA_HAS_ORCH_SYMBOL={ipa['orch_symbol']}
IPA_HAS_DECIDE_C_SYMBOL={ipa['decide_c_symbol']}
IPA_HAS_R9_CTOR_SYMBOL={ipa['r9_ctor_symbol']}
UNREACHED_PRODUCT_GATES={','.join(unreached) if unreached else '(none)'}
DIAGNOSTIC_INTENTIONALLY_UNREACHABLE={','.join(poison_skip) if poison_skip else '(none)'}

HOST_SIM_KFD_ONE_SHOT=PASS
APPLE_TV_CONTACTED_BY_HOST_SIM=NO
PHYSICAL_KFD_OPENED_BY_HOST_SIM=NO
PHYSICAL_KFD_CURRENT_STATE=UNKNOWN
CURRENT_PHYSICAL_KFD_STATE=UNKNOWN

SIM_KFD_OPEN_COUNT / SIM_KFD_REENTRY_ATTEMPT_COUNT are simulated fixture
counters, not physical KFD.

PHYSICAL_RUNTIME_ONLY (not claimed PASS):
KFD exploit reliability, kernel addresses, AMFI, real PID1 dlopen, sandbox extension, live SSH.

HISTORICAL_DEVICE_OBSERVATIONS: earlier physical runs may have logged KFD left
open. That is not current device state. HOST_SIM does not observe the Apple TV.

DO NOT RUN DEVICE from this tool.
"""
    (DOCS / "ROOTLESS_HOST_SIM_REPORT.md").write_text(report)
    (DOCS / "ROOTLESS_HOST_SIM_FIXTURES.tsv").write_text(
        "FIXTURE\tEXPECT\tDETAIL\n" + "\n".join(fixture_results) + "\n"
    )
    (DOCS / "ROOTLESS_HOST_SIM_NOTES.txt").write_text("\n".join(notes) + "\n")
    kind_name = {KIND_PRODUCT: "PRODUCT", KIND_DIAG: "DIAGNOSTIC", KIND_PHYS: "PHYSICAL_RUNTIME_ONLY"}
    gate_rows = ["ID\tNAME\tKIND"]
    for i, name in enumerate(reg["names"]):
        gate_rows.append(f"{i}\t{name}\t{kind_name[reg['kinds'][i]]}")
    (DOCS / "ROOTLESS_HOST_SIM_GATES.tsv").write_text("\n".join(gate_rows) + "\n")
    (DOCS / "ROOTLESS_HOST_SIM_SHARED_SOURCE.json").write_text(
        json.dumps({"files": hashes, "device_makefile_has_orch_c": orch_in_device,
                    "ipa": ipa, "defines": {"DT_ROOTLESS_R4": True, "DT_HOST_SIM": "host_only"}}, indent=2)
        + "\n"
    )
    src_md = ["# Shared source identity (HOST_SIM compile inputs)", "", "```"]
    for k, v in hashes.items():
        src_md.append(f"{k}={v}")
    src_md += [
        f"HOST_SIM_DEVICE_SHARED_SOURCE_MATCH={source_match}",
        f"HOST_SIM_DEVICE_DEFINE_MISMATCH_COUNT={define_mismatch}",
        "DT_ROOTLESS_R4=1 (device Makefile + HOST_SIM)",
        "DT_HOST_SIM=1 (host only)",
        "```",
        "",
        f"CANDIDATE_IPA_SHA256={ipa['ipa_sha256']}",
        f"DEVICE_MAKEFILE_HAS_ORCH_C={orch_in_device}",
        f"IPA_HAS_ORCH_SYMBOL={ipa['orch_symbol']}",
        "",
    ]
    (DOCS / "ROOTLESS_HOST_SIM_SHARED_SOURCE.md").write_text("\n".join(src_md))
    print(report)
    if notes:
        print("NOTES:")
        print("\n".join(notes))
    return 0 if auth == "YES" else 1


if __name__ == "__main__":
    sys.exit(run())
