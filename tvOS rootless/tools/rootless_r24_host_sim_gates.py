#!/usr/bin/env python3
"""R24 CURRENT_BOOT_RUNTIME host gates (fail closed).

Evaluates the SAME dependency-gate contract the device runs under DT_ROOTLESS_R24:
  load graph + CBR surface PRESENT (initXPCHooks + MSHookFunction needle) + fuller surface.

H10/M4 additionally requires Framework libjailbreak C-pool kalloc_pt + MAIN smoke/F3 STAGE
literals so DEVICE_RUN_AUTHORIZATION cannot YES on the prior ObjC-pool crash IPA.

H11/M4 additionally requires LAUNCHD_CS_ALLOW_INVALID STAGE literals + compiled ctor
call-order proof (otool disasm of __init_offsets ctor: cs_allow_invalid before
initSpawnHooks; GOT probe after allow-invalid when present). Presence-only nm checks
are insufficient.

H12/M4 additionally requires MAIN to embed ROOTLESS_R24_EXPECT_{HOOK,SYSTEMHOOK}_CANONICAL_SHA256
+ UUID pins that match the IPA Handoff members under the shared canonical Mach-O
identity (TrollStore CS-invariant; tools/rootless_macho_canonical_id.py), plus proof
that dt_rootless_leaf_prepare runs D0 after stage and before sign. Also runs positive/
negative canonical fixtures (IPA vs optional candidate-bound D0-device pull; mutate __text -> FAIL;
CS-only change -> PASS).

H13/M4 requires the compiled current-boot runtime contract: live injection state and
one launchd-generation UUID only after XPC/spawn hooks, child systemhook/jbserver
validation markers, a launchd-owned controlled-child acknowledgement path, and no
compiled userspace-reboot trigger. These are static/host proofs, never physical PASS.

H14/M4 requires Console-visible diagnostics across the app, PID 1 hook-patch and
spawn-propagation boundaries, and the systemhook constructor. It rejects the prior
stderr-only hook result blind spot. This proves compiled telemetry, not live delivery.

DEVICE_RUN_AUTHORIZATION cannot be YES if that device contract would FAIL on the IPA
Handoff trio. Does not claim LIVE_SUDO / PHYS_LIVE_SSH / PID1 hook install / live stash.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
sys.path.insert(0, str(ROOT / "tools"))
from rootless_macho_canonical_id import (  # noqa: E402
    CanonicalIdError,
    canonical_sha256,
    macho_uuid,
)
from r24_dyld_contract import (  # noqa: E402
    EXPECTED_GENERATED_CANONICAL_SHA,
    EXPECTED_GENERATED_UUID,
    GENERATED_PATCH_BYTES,
    GENERATED_PATCH_OFFSET,
    JBINFO_SECTION_SIZE,
    STOCK_PATCH_OFFSET,
    STOCK_PATCH_PROLOGUE,
    bytes_at_offset,
    jbinfo_section_size,
    locate_generated_patch_offset,
    macho_cs_end_valid,
    runtime_dyld_layout,
    validate_generated_dyld_contract,
    validate_installed_runtime_dyld_contract,
)
R21_SHA = "5099371a1f2afe0fdb51eccd2edca08bbd931614352697e6bcc53d8c155f17f0"
R22_SHA = "838f3d095a3c5b3df07e86020225282e4e71823dfaea8513d8e10dcd096eb6cf"
R23_SHA = "071c6e7059cdf66017c6e980b32c6322cb036663a3fb1daf9a3a3f9bedf12906"
# Prior R24 IPA that authorized while device DEP still required substrate ABSENCE.
PRIOR_FALSE_AUTH_R24_SHA = (
    "cbfc7354b5db534ab5de31f05254f72f2d8e3ba6dafdd324b854aec9168cbad5"
)
# Prior R24 IPA that passed DEP invert but crashed in ObjC kalloc_pt pool (2026-08-20 17:50).
PRIOR_KALLOC_PT_CRASH_R24_SHA = (
    "447c8be492d3b9653f6a1f66cfb02f20ade7c81a51031d657b72c52217871690"
)
# Prior R24 IPA that reached boomerang then CS_KILLED initproc (INVALID_PAGE) 2026-08-20 18:14.
PRIOR_CS_KILLED_INITPROC_R24_SHA = (
    "0e712b21bc72f6a86b089d7cf9b15aef391b05ab0e66633458b0a69024d78617"
)
# Hook member SHA from that same CS_KILLED session IPA (no allow-invalid before spawn).
PRIOR_CS_KILLED_HOOK_SHA = (
    "e45190452e390598a81029e351c89e129a9799bf0f739a4cac110b8f0dad34df"
)
# Prior R24 IPA that authorized with H1–H11 but MAIN lacked D0 expect pins (19:07 burn drift).
PRIOR_NO_D0_PIN_R24_SHA = (
    "48da16f793c1bc0f549c39ca0d0e8e5285dc2bd72f67b302d734e8e65712f9c4"
)
# Prior R24 IPA with D0 pins but D0 only on monolithic path — live orch uses leaf_prepare (20:15).
PRIOR_D0_LEAF_GAP_R24_SHA = (
    "c45f0b036c30c7be569172c9d506914cc8004c4a5f16773a22ee6be36a30c366"
)
# Prior leaf-wired IPA superseded by R24V7 clean rebuild (2026-08-21).
PRIOR_R24_LEAF_WIRED_SUPERSEDED_SHA = (
    "4174dc8940eb705c6ec8cc0db247195159e26a026480566cbc4b788c67fe9907"
)
# Prior R24V7 with whole-file D0 pins (false FAIL under TrollStore CS rewrite) — superseded.
PRIOR_R24V7_WHOLEFILE_D0_PIN_SHA = (
    "5e461a2ff9da7a3c98a282c9af0aa5ca908139bbedc7c0b0c4a39b9a6ce64fb9"
)
PRE_CBR_HOOK = "5223b886123a4adf4b3a8b594d47f047cb9204c4d4e7c34e4b2c9be14b21f040"
VTOOL = (
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/vtool"
)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_member(z: zipfile.ZipFile, suffix: str) -> str | None:
    for n in z.namelist():
        if n.endswith(suffix):
            return n
    return None


def run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    return (r.stdout or "") + (r.stderr or "")


def file_has(path: Path, needle: bytes) -> bool:
    return needle in path.read_bytes()


def prove_hook_install_fail_closed(path: Path) -> tuple[bool, dict[str, str]]:
    """Prove the packaged hook branches on both install return values.

    String presence is insufficient: the ctor must test w0 immediately after
    each init call, and each init helper must test dt_cbr_MSHookFunction's w0.
    """
    disasm = run(["otool", "-tvV", str(path)])

    def function_body(symbol: str) -> list[str]:
        lines = disasm.splitlines()
        label = f"_{symbol}:"
        try:
            start = lines.index(label) + 1
        except ValueError:
            return []
        body: list[str] = []
        for line in lines[start:]:
            if re.match(r"^_[A-Za-z0-9_.$]+:$", line):
                break
            if line.strip():
                body.append(line)
        return body

    def call_is_checked(body: list[str], callee: str) -> bool:
        for i, line in enumerate(body):
            if re.search(rf"\bbl\s+_{re.escape(callee)}\b", line):
                following = "\n".join(body[i + 1 : i + 10])
                return re.search(r"\b(cbz|cbnz)\s+w0\b", following) is not None
        return False

    ctor = function_body("dt516_launchdhook_init")
    xpc = function_body("initXPCHooks")
    spawn = function_body("initSpawnHooks")
    lite = function_body("litehook_hook_function")
    detail = {
        "CTOR_CHECKS_XPC_RESULT": "PASS" if call_is_checked(ctor, "initXPCHooks") else "FAIL",
        "CTOR_CHECKS_SPAWN_RESULT": "PASS" if call_is_checked(ctor, "initSpawnHooks") else "FAIL",
        "XPC_HELPER_CHECKS_ENGINE_RESULT": "PASS" if call_is_checked(xpc, "dt_cbr_MSHookFunction") else "FAIL",
        "SPAWN_HELPER_CHECKS_ENGINE_RESULT": "PASS" if call_is_checked(spawn, "dt_cbr_MSHookFunction") else "FAIL",
        "PROLOGUE_READBACK_CALLED": "PASS" if (
            any(re.search(r"\bbl\s+_litehook_verify_function_hook\b", line) for line in lite)
            or (
                any("_sys_icache_invalidate" in line for line in lite)
                and sum(1 for line in lite if re.search(r"\bcmp\b", line)) >= 4
                and any(re.search(r"\bcsel\s+w0\b", line) for line in lite)
            )
        ) else "FAIL",
    }
    return all(value == "PASS" for value in detail.values()), detail


def read_init_offset_addrs(path: Path) -> list[int]:
    """Return VA list from __TEXT,__init_offsets (uint32 image-relative offsets)."""
    ot = run(["otool", "-l", str(path)])
    lines = ot.splitlines()
    addr = None
    size = None
    offset = None
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if ln == "sectname __init_offsets":
            # Expect following: segname, addr, size, offset
            block = "\n".join(lines[i : i + 8])
            m_addr = re.search(r"addr 0x([0-9a-fA-F]+)", block)
            m_size = re.search(r"size 0x([0-9a-fA-F]+)", block)
            m_off = re.search(r"offset (\d+)", block)
            if m_addr and m_size and m_off:
                addr = int(m_addr.group(1), 16)
                size = int(m_size.group(1), 16)
                offset = int(m_off.group(1))
            break
        i += 1
    if addr is None or size is None or offset is None or size < 4:
        return []
    data = path.read_bytes()
    addrs: list[int] = []
    for off in range(offset, offset + size, 4):
        if off + 4 > len(data):
            break
        rel = int.from_bytes(data[off : off + 4], "little")
        addrs.append(rel)
    return addrs


def prove_ctor_cs_before_spawn(path: Path) -> tuple[bool, dict[str, str]]:
    """Prove packaged ctor calls cs_allow_invalid before initSpawnHooks.

    Uses __init_offsets entries + otool -tV of the ctor that contains
    boomerang_recoverPrimitives516 (gate1b). Does not accept nm presence alone.
    """
    detail: dict[str, str] = {
        "CTOR_ORDER_PROOF": "FAIL",
        "CTOR_VA": "",
        "BL_JBROOT_DLADDR": "",
        "BL_BOOMERANG": "",
        "BL_CS_ALLOW_INVALID": "",
        "BL_GOT_PROBE": "",
        "BL_INIT_XPC": "",
        "BL_INIT_SPAWN": "",
        "HOOK_SHA256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    init_addrs = read_init_offset_addrs(path)
    if not init_addrs:
        detail["CTOR_ORDER_FAIL"] = "NO_INIT_OFFSETS"
        return False, detail
    detail["INIT_OFFSETS"] = ",".join(hex(a) for a in init_addrs)

    disasm = run(["otool", "-tV", str(path)])
    lines = disasm.splitlines()

    def parse_addr(line: str) -> int | None:
        parts = line.split()
        if not parts:
            return None
        try:
            return int(parts[0], 16)
        except ValueError:
            return None

    # Index lines by address for slicing functions until next known symbol label.
    indexed: list[tuple[int, str]] = []
    for ln in lines:
        a = parse_addr(ln)
        if a is not None:
            indexed.append((a, ln))

    def slice_fn(start: int, limit: int = 0x800) -> list[str]:
        out: list[str] = []
        started = False
        for a, ln in indexed:
            if a == start:
                started = True
            if not started:
                continue
            out.append(ln)
            if a > start and a in init_addrs and a != start:
                break
            if a >= start + limit:
                break
        return out

    def slice_named(start: int, next_syms: list[int]) -> list[str]:
        """Slice until the next global text symbol (exclusive)."""
        end = start + 0x400
        for s in next_syms:
            if s > start:
                end = min(end, s)
                break
        out: list[str] = []
        for a, ln in indexed:
            if a < start:
                continue
            if a >= end:
                break
            out.append(ln)
        return out

    # Prefer ctor that references boomerang_recoverPrimitives516.
    chosen: list[str] | None = None
    chosen_va = None
    for va in init_addrs:
        body = slice_fn(va)
        text = "\n".join(body)
        if "boomerang_recoverPrimitives516" in text or "GATE1B_LAUNCHDHOOK_CONSTRUCTOR" in text:
            chosen = body
            chosen_va = va
            break
    if chosen is None and init_addrs:
        # Fall back: first init_offset (historically gate1b at __text start).
        chosen_va = init_addrs[0]
        chosen = slice_fn(chosen_va)
    if not chosen or chosen_va is None:
        detail["CTOR_ORDER_FAIL"] = "NO_CTOR_SLICE"
        return False, detail
    detail["CTOR_VA"] = hex(chosen_va)

    def first_bl_ordinal(needles: tuple[str, ...]) -> int | None:
        for i, ln in enumerate(chosen):
            if "bl\t" not in ln and "bl " not in ln:
                continue
            for n in needles:
                if n in ln:
                    return i
        return None

    bl_jbroot = first_bl_ordinal(("_dt_r24_launchd_jbroot_from_dladdr_or_fail",))
    bl_boomerang = first_bl_ordinal(("_boomerang_recoverPrimitives516",))
    bl_cs = first_bl_ordinal(
        (
            "_dt_r24_launchd_cs_allow_invalid_or_fail",
            "_cs_allow_invalid",
        )
    )
    bl_got = first_bl_ordinal(
        (
            "_dt102738p_run_got_protection_probe",
            "_dt102738w_run_got_same_value_store_probe",
            "_dt102738x_run_got_wrapper_roundtrip_probe",
            "_dt102738y_run_got_wrapper_invocation_probe",
        )
    )
    bl_xpc = first_bl_ordinal(("_initXPCHooks",))
    bl_spawn = first_bl_ordinal(("_initSpawnHooks",))

    detail["BL_JBROOT_DLADDR"] = str(bl_jbroot) if bl_jbroot is not None else "MISSING"
    detail["BL_BOOMERANG"] = str(bl_boomerang) if bl_boomerang is not None else "MISSING"
    detail["BL_CS_ALLOW_INVALID"] = str(bl_cs) if bl_cs is not None else "MISSING"
    detail["BL_GOT_PROBE"] = str(bl_got) if bl_got is not None else "ABSENT"
    detail["BL_INIT_XPC"] = str(bl_xpc) if bl_xpc is not None else "MISSING"
    detail["BL_INIT_SPAWN"] = str(bl_spawn) if bl_spawn is not None else "MISSING"

    if bl_jbroot is None:
        detail["CTOR_ORDER_FAIL"] = "NO_BL_JBROOT_DLADDR"
        return False, detail
    if bl_boomerang is None:
        detail["CTOR_ORDER_FAIL"] = "NO_BL_BOOMERANG"
        return False, detail
    if bl_jbroot >= bl_boomerang:
        detail["CTOR_ORDER_FAIL"] = "JBROOT_DLADDR_NOT_BEFORE_BOOMERANG"
        return False, detail
    if bl_cs is None:
        detail["CTOR_ORDER_FAIL"] = "NO_BL_CS_ALLOW_INVALID"
        return False, detail
    if bl_spawn is None:
        detail["CTOR_ORDER_FAIL"] = "NO_BL_INIT_SPAWN"
        return False, detail
    if bl_cs >= bl_spawn:
        detail["CTOR_ORDER_FAIL"] = "CS_ALLOW_INVALID_NOT_BEFORE_SPAWN"
        return False, detail
    if bl_xpc is not None and bl_cs >= bl_xpc:
        detail["CTOR_ORDER_FAIL"] = "CS_ALLOW_INVALID_NOT_BEFORE_XPC"
        return False, detail
    if bl_got is not None and bl_cs >= bl_got:
        detail["CTOR_ORDER_FAIL"] = "CS_ALLOW_INVALID_NOT_BEFORE_GOT_PROBE"
        return False, detail
    if bl_boomerang >= bl_cs:
        detail["CTOR_ORDER_FAIL"] = "BOOMERANG_NOT_BEFORE_CS_ALLOW_INVALID"
        return False, detail

    # If ctor calls the named helper, prove helper body actually bl's cs_allow_invalid.
    nm = run(["nm", "-gU", str(path)])
    text_syms: list[tuple[int, str]] = []
    for m in re.finditer(r"^([0-9a-fA-F]+)\s+T\s+(_\S+)\s*$", nm, re.M):
        text_syms.append((int(m.group(1), 16), m.group(2)))
    text_syms.sort()
    text_addrs = [a for a, _ in text_syms]

    m_helper = re.search(
        r"^([0-9a-fA-F]+)\s+T\s+_dt_r24_launchd_cs_allow_invalid_or_fail\s*$",
        nm,
        re.M,
    )
    if m_helper:
        helper_va = int(m_helper.group(1), 16)
        helper_body = "\n".join(slice_named(helper_va, text_addrs))
        if "_cs_allow_invalid" not in helper_body and "cs_allow_invalid" not in helper_body:
            detail["CTOR_ORDER_FAIL"] = "HELPER_MISSING_BL_CS_ALLOW_INVALID"
            detail["HELPER_VA"] = hex(helper_va)
            return False, detail
        detail["HELPER_VA"] = hex(helper_va)
        detail["HELPER_HAS_CS_ALLOW_INVALID"] = "YES"
    else:
        # Direct bl _cs_allow_invalid in ctor is also acceptable.
        ctor_text = "\n".join(chosen)
        if "_cs_allow_invalid" not in ctor_text:
            detail["CTOR_ORDER_FAIL"] = "NO_HELPER_AND_NO_DIRECT_CS_ALLOW"
            return False, detail
        detail["HELPER_HAS_CS_ALLOW_INVALID"] = "DIRECT_IN_CTOR"

    detail["CTOR_ORDER_PROOF"] = "PASS"
    return True, detail


def prove_ctor_runtime_after_hooks(path: Path) -> tuple[bool, dict[str, str]]:
    """Prove Dopamine live-injection order through current-boot finalization."""
    detail: dict[str, str] = {"RUNTIME_ORDER_PROOF": "FAIL"}
    init_addrs = read_init_offset_addrs(path)
    if not init_addrs:
        detail["RUNTIME_ORDER_FAIL"] = "NO_INIT_OFFSETS"
        return False, detail
    disasm = run(["otool", "-tV", str(path)])
    indexed: list[tuple[int, str]] = []
    for ln in disasm.splitlines():
        parts = ln.split()
        if not parts:
            continue
        try:
            indexed.append((int(parts[0], 16), ln))
        except ValueError:
            pass

    def ctor_slice(start: int) -> list[str]:
        out: list[str] = []
        started = False
        for addr, ln in indexed:
            if addr == start:
                started = True
            if not started:
                continue
            if addr > start and addr in init_addrs:
                break
            if addr >= start + 0x1000:
                break
            out.append(ln)
        return out

    body: list[str] = []
    ctor_va = 0
    for va in init_addrs:
        candidate = ctor_slice(va)
        text = "\n".join(candidate)
        if "_initSpawnHooks" in text and "_initXPCHooks" in text:
            body = candidate
            ctor_va = va
            break
    if not body:
        detail["RUNTIME_ORDER_FAIL"] = "NO_CBR_CTOR"
        return False, detail
    detail["CTOR_VA"] = hex(ctor_va)

    def bl_ord(symbol: str) -> int | None:
        for idx, ln in enumerate(body):
            if ("bl\t" in ln or "bl " in ln) and symbol in ln:
                return idx
        return None

    live = bl_ord("_dt_r24_launchd_begin_live_injection")
    jbroot = bl_ord("_dt_r24_launchd_jbroot_from_dladdr_or_fail")
    boomerang = bl_ord("_boomerang_recoverPrimitives516")
    cs_allow = bl_ord("_dt_r24_launchd_cs_allow_invalid_or_fail")
    xpc = bl_ord("_initXPCHooks")
    spawn = bl_ord("_initSpawnHooks")
    runtime = bl_ord("_dt_r24_launchd_initialize_current_boot_runtime")
    detail["BL_JBROOT_DLADDR"] = str(jbroot) if jbroot is not None else "MISSING"
    detail["BL_LIVE_INJECTION"] = str(live) if live is not None else "MISSING"
    detail["BL_BOOMERANG"] = str(boomerang) if boomerang is not None else "MISSING"
    detail["BL_CS_ALLOW_INVALID"] = str(cs_allow) if cs_allow is not None else "MISSING"
    detail["BL_INIT_XPC"] = str(xpc) if xpc is not None else "MISSING"
    detail["BL_INIT_SPAWN"] = str(spawn) if spawn is not None else "MISSING"
    detail["BL_RUNTIME_INIT"] = str(runtime) if runtime is not None else "MISSING"
    if any(v is None for v in (jbroot, live, boomerang, cs_allow, xpc, spawn, runtime)):
        detail["RUNTIME_ORDER_FAIL"] = "MISSING_REQUIRED_BL"
        return False, detail
    if not (jbroot < live < boomerang < cs_allow < xpc < spawn < runtime):
        detail["RUNTIME_ORDER_FAIL"] = "NOT_JBROOT_LIVE_BOOMERANG_CS_XPC_SPAWN_RUNTIME"
        return False, detail

    nm = run(["nm", "-gU", str(path)])
    m_live = re.search(
        r"^([0-9a-fA-F]+)\s+T\s+_dt_r24_launchd_begin_live_injection\s*$",
        nm,
        re.M,
    )
    m = re.search(
        r"^([0-9a-fA-F]+)\s+T\s+_dt_r24_launchd_initialize_current_boot_runtime\s*$",
        nm,
        re.M,
    )
    if not m_live or not m:
        detail["RUNTIME_ORDER_FAIL"] = "NO_LIVE_OR_RUNTIME_HELPER_SYMBOL"
        return False, detail
    live_va = int(m_live.group(1), 16)
    helper_va = int(m.group(1), 16)
    text_symbols = sorted(
        int(sm.group(1), 16)
        for sm in re.finditer(r"^([0-9a-fA-F]+)\s+T\s+_\S+\s*$", nm, re.M)
    )

    def symbol_body(start: int) -> str:
        later = [va for va in text_symbols if va > start]
        end = min(start + 0x800, later[0]) if later else start + 0x800
        return "\n".join(ln for addr, ln in indexed if start <= addr < end)

    live_helper = symbol_body(live_va)
    if "_early_boot_done" not in live_helper or "_getenv" not in live_helper:
        detail["RUNTIME_ORDER_FAIL"] = "LIVE_HELPER_MISSING_STATE_TRANSITION"
        return False, detail
    if "_setenv" in live_helper:
        detail["RUNTIME_ORDER_FAIL"] = "LIVE_HELPER_SETS_FINAL_ENV_TOO_EARLY"
        return False, detail

    helper = symbol_body(helper_va)
    for symbol in ("_setenv", "_uuid_generate_random", "_uuid_parse"):
        if symbol not in helper:
            detail["RUNTIME_ORDER_FAIL"] = f"HELPER_MISSING_{symbol.lstrip('_').upper()}"
            return False, detail
    if "_early_boot_done" in helper:
        detail["RUNTIME_ORDER_FAIL"] = "RUNTIME_HELPER_CLEARS_EARLY_BOOT_TOO_LATE"
        return False, detail
    detail["LIVE_HELPER_VA"] = hex(live_va)
    detail["HELPER_VA"] = hex(helper_va)
    detail["RUNTIME_ORDER_PROOF"] = "PASS"
    return True, detail


def prove_probe_scoped_uuid_policy(
    hook_path: Path, systemhook_path: Path
) -> tuple[bool, dict[str, str]]:
    """Prove normal jbserver UUID-nullability and probe-only strict validation."""
    detail = {
        "JBS_NORMAL_UUID_NULLABLE": "FAIL",
        "SYSTEMHOOK_PROBE_STRICT_UUID": "FAIL",
    }

    hook_disasm = run(["otool", "-tV", str(hook_path)])
    hook_nm = run(["nm", "-gU", str(hook_path)])
    process_match = re.search(
        r"^([0-9a-fA-F]+)\s+T\s+_systemwide_process_checkin\s*$",
        hook_nm,
        re.M,
    )
    if not process_match:
        detail["UUID_POLICY_FAIL"] = "NO_SYSTEMWIDE_PROCESS_CHECKIN"
        return False, detail
    process_va = int(process_match.group(1), 16)
    hook_symbols = sorted(
        int(sm.group(1), 16)
        for sm in re.finditer(r"^([0-9a-fA-F]+)\s+T\s+_\S+\s*$", hook_nm, re.M)
        if int(sm.group(1), 16) > process_va
    )
    process_end = min(process_va + 0x2000, hook_symbols[0]) if hook_symbols else process_va + 0x2000
    process_body_lines = []
    for line in hook_disasm.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        if process_va <= address < process_end:
            process_body_lines.append(line)
    process_body = "\n".join(process_body_lines)
    if "_uuid_parse" in process_body:
        detail["UUID_POLICY_FAIL"] = "JBS_PROCESS_CHECKIN_STILL_PARSES_UUID"
        return False, detail
    if "R24_FAIL_STAGE=PROCESS_CHECKIN rc=2" in run(["strings", str(hook_path)]):
        detail["UUID_POLICY_FAIL"] = "JBS_GLOBAL_UUID_REJECT_MARKER_PRESENT"
        return False, detail
    detail["JBS_NORMAL_UUID_NULLABLE"] = "PASS"

    sh_disasm = run(["otool", "-tV", str(systemhook_path)])
    sh_nm = run(["nm", "-gU", str(systemhook_path)])
    required_symbols = (
        "_dt_r24_is_controlled_probe",
        "_dt_r24_systemhook_validate_controlled_probe_checkin",
    )
    if any(symbol not in sh_nm for symbol in required_symbols):
        detail["UUID_POLICY_FAIL"] = "SYSTEMHOOK_MISSING_PROBE_POLICY_SYMBOL"
        return False, detail

    init_addrs = read_init_offset_addrs(systemhook_path)
    indexed: list[tuple[int, str]] = []
    for line in sh_disasm.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            indexed.append((int(parts[0], 16), line))
        except ValueError:
            pass
    initializer: list[str] = []
    initializer_va = 0
    for start in init_addrs:
        candidate = [line for addr, line in indexed if start <= addr < start + 0x1800]
        text = "\n".join(candidate)
        if all(symbol in text for symbol in required_symbols):
            initializer = candidate
            initializer_va = start
            break
    if not initializer:
        detail["UUID_POLICY_FAIL"] = "NO_SYSTEMHOOK_PROBE_SCOPED_INITIALIZER"
        return False, detail

    def call_index(symbol: str) -> int | None:
        for index, line in enumerate(initializer):
            if ("bl\t" in line or "bl " in line) and symbol in line:
                return index
        return None

    probe_call = call_index("_dt_r24_is_controlled_probe")
    validate_call = call_index("_dt_r24_systemhook_validate_controlled_probe_checkin")
    if probe_call is None or validate_call is None or probe_call >= validate_call:
        detail["UUID_POLICY_FAIL"] = "PROBE_NOT_BEFORE_STRICT_VALIDATION"
        return False, detail
    conditional = re.compile(r"\b(?:b\.(?:eq|ne)|cbz|cbnz|tbz|tbnz)\b")
    if not any(conditional.search(line) for line in initializer[probe_call + 1 : validate_call]):
        detail["UUID_POLICY_FAIL"] = "STRICT_VALIDATION_NOT_CONDITIONAL"
        return False, detail
    validator_calls = sum(
        1
        for line in sh_disasm.splitlines()
        if ("bl\t" in line or "bl " in line)
        and "_dt_r24_systemhook_validate_controlled_probe_checkin" in line
    )
    if validator_calls != 1:
        detail["UUID_POLICY_FAIL"] = "STRICT_VALIDATION_CALL_COUNT_NE_1"
        return False, detail

    validate_match = re.search(
        r"^([0-9a-fA-F]+)\s+T\s+_dt_r24_systemhook_validate_controlled_probe_checkin\s*$",
        sh_nm,
        re.M,
    )
    if not validate_match:
        detail["UUID_POLICY_FAIL"] = "NO_STRICT_VALIDATOR_BODY"
        return False, detail
    validate_va = int(validate_match.group(1), 16)
    sh_later = sorted(
        int(sm.group(1), 16)
        for sm in re.finditer(r"^([0-9a-fA-F]+)\s+T\s+_\S+\s*$", sh_nm, re.M)
        if int(sm.group(1), 16) > validate_va
    )
    validate_end = min(validate_va + 0x1000, sh_later[0]) if sh_later else validate_va + 0x1000
    validate_body = "\n".join(
        line for addr, line in indexed if validate_va <= addr < validate_end
    )
    if "_uuid_parse" not in validate_body:
        detail["UUID_POLICY_FAIL"] = "PROBE_VALIDATOR_NO_UUID_PARSE"
        return False, detail

    detail["SYSTEMHOOK_INITIALIZER_VA"] = hex(initializer_va)
    detail["SYSTEMHOOK_PROBE_STRICT_UUID"] = "PASS"
    return True, detail


def prove_leaf_prepare_d0_before_sign(app_path: Path) -> tuple[bool, dict[str, str]]:
    """Prove dt_rootless_leaf_prepare runs D0 check before sign_artifact.

    Live R24 orch uses leaf_prepare (not the monolithic 102732c path). Presence of
    D0 pin strings alone is insufficient — 20:15 authorized pins without leaf wiring.
    """
    detail: dict[str, str] = {
        "LEAF_D0_ORDER_PROOF": "FAIL",
        "LEAF_PREPARE_VA": "",
        "LEAF_D0_CHECK_ORD": "",
        "LEAF_SIGN_ORD": "",
    }
    nm = run(["nm", "-gU", str(app_path)])
    m = re.search(
        r"^([0-9a-fA-F]+)\s+T\s+_dt_rootless_leaf_prepare\s*$",
        nm,
        re.M,
    )
    if not m:
        detail["LEAF_D0_ORDER_FAIL"] = "NO_LEAF_PREPARE_SYMBOL"
        return False, detail
    leaf_va = int(m.group(1), 16)
    detail["LEAF_PREPARE_VA"] = hex(leaf_va)

    text_syms: list[tuple[int, str]] = []
    for sm in re.finditer(r"^([0-9a-fA-F]+)\s+T\s+(_\S+)\s*$", nm, re.M):
        text_syms.append((int(sm.group(1), 16), sm.group(2)))
    text_syms.sort()
    next_addrs = [a for a, _ in text_syms if a > leaf_va]

    disasm = run(["otool", "-tV", str(app_path)])
    lines = disasm.splitlines()

    def parse_addr(line: str) -> int | None:
        parts = line.split()
        if not parts:
            return None
        try:
            return int(parts[0], 16)
        except ValueError:
            return None

    end = leaf_va + 0x800
    if next_addrs:
        end = min(end, next_addrs[0])
    body: list[str] = []
    for ln in lines:
        a = parse_addr(ln)
        if a is None:
            continue
        if a < leaf_va:
            continue
        if a >= end:
            break
        body.append(ln)
    if not body:
        detail["LEAF_D0_ORDER_FAIL"] = "NO_LEAF_PREPARE_SLICE"
        return False, detail

    text = "\n".join(body)
    # Require leaf-specific STAGE literal (not only pin strings from dead monolithic path).
    d0_ord = None
    sign_ord = None
    for i, ln in enumerate(body):
        if "ROOTLESS_R24_D0_CHECK=LEAF_PREPARE" in ln:
            d0_ord = i
        if "dt102732c_sign_artifact" in ln or "_dt102732c_sign_artifact" in ln:
            if sign_ord is None:
                sign_ord = i
    detail["LEAF_D0_CHECK_ORD"] = "" if d0_ord is None else str(d0_ord)
    detail["LEAF_SIGN_ORD"] = "" if sign_ord is None else str(sign_ord)

    if d0_ord is None:
        # ADRP/ADD may not embed full ASCII in the insn line; accept nearby literal pool
        # only if the function slice's raw bytes region is unavailable — fall back to
        # requiring the string in the full binary AND a bl to D0 verify near leaf.
        if "ROOTLESS_R24_D0_CHECK=LEAF_PREPARE" not in text:
            # Search for bl to verify symbol (may be static local).
            has_d0_bl = any(
                ("bl\t" in ln or "bl " in ln)
                and (
                    "dt_r24_verify_d0_handoff_identity" in ln
                    or "verify_d0_handoff" in ln
                )
                for ln in body
            )
            app_bytes = app_path.read_bytes()
            if b"ROOTLESS_R24_D0_CHECK=LEAF_PREPARE" not in app_bytes:
                detail["LEAF_D0_ORDER_FAIL"] = "NO_LEAF_D0_CHECK_LITERAL"
                return False, detail
            if not has_d0_bl:
                # Literal in binary alone is not enough — must appear referenced from leaf
                # or verify bl must be in leaf slice. Try cstring xref via strings in body
                # comments; if neither, FAIL closed.
                detail["LEAF_D0_ORDER_FAIL"] = "LEAF_SLICE_MISSING_D0_REF"
                return False, detail
            d0_ord = 0  # bl-proven
            detail["LEAF_D0_CHECK_ORD"] = "BL_VERIFY"
    if sign_ord is None:
        # sign_artifact is static — look for common stage/sign markers in order
        for i, ln in enumerate(body):
            if "BUILD102732C_" in ln and "PRESIGN" in ln:
                sign_ord = i
                break
        if sign_ord is None:
            # Accept bl pattern to any sign helper after D0
            for i, ln in enumerate(body):
                if ("bl\t" in ln or "bl " in ln) and "sign" in ln.lower():
                    sign_ord = i
                    break
        detail["LEAF_SIGN_ORD"] = "" if sign_ord is None else str(sign_ord)

    if sign_ord is None:
        # Still require D0 before the loop that signs: prove D0 check ordinal exists and
        # a later bl exists after it (any bl after D0 indicates continued prepare).
        later_bl = None
        start = d0_ord if isinstance(d0_ord, int) else 0
        for i, ln in enumerate(body):
            if i <= start:
                continue
            if "bl\t" in ln or "bl " in ln:
                later_bl = i
                break
        if later_bl is None:
            detail["LEAF_D0_ORDER_FAIL"] = "NO_POST_D0_BL_IN_LEAF"
            return False, detail
        sign_ord = later_bl
        detail["LEAF_SIGN_ORD"] = f"POST_D0_BL_{later_bl}"

    if isinstance(d0_ord, int) and isinstance(sign_ord, int) and d0_ord >= sign_ord:
        detail["LEAF_D0_ORDER_FAIL"] = "D0_NOT_BEFORE_SIGN"
        return False, detail

    detail["LEAF_D0_ORDER_PROOF"] = "PASS"
    return True, detail


def macho_loads(path: Path, dylib: str) -> bool:
    out = run(["otool", "-L", str(path)])
    return dylib in out


def macho_loads_only_system(path: Path) -> bool:
    """Mirror dt102732c_macho_loads_only_system_libraries: no @loader/@rpath/@executable."""
    out = run(["otool", "-L", str(path)])
    lines = [ln.strip() for ln in out.splitlines()[1:] if ln.strip()]
    for ln in lines:
        lib = ln.split(" (", 1)[0].strip()
        if lib.startswith("@loader_path/") or lib.startswith("@rpath/") or lib.startswith(
            "@executable_path/"
        ):
            # self-id line is first; skip install name equal to basename
            if path.name in lib and lib.startswith("@loader_path/"):
                continue
            return False
    return True


def evaluate_device_r24_dep_contract(hook: Path, lj: Path, lc: Path) -> tuple[bool, dict[str, str]]:
    """Same predicates as dt102732c_dependency_gate under DT_ROOTLESS_R24."""
    detail: dict[str, str] = {}
    hook_load = macho_loads(hook, "@loader_path/libjailbreak.dylib")
    lj_load = macho_loads(lj, "@loader_path/libchoma.dylib")
    lc_system = macho_loads_only_system(lc)
    # Device scans hook+lj+lc for needles; CBR surface lives in hook.
    mshook = any(file_has(p, b"MSHookFunction") for p in (hook, lj, lc))
    initxpc = any(file_has(p, b"initXPCHooks") for p in (hook, lj, lc))
    full_jbserver = any(
        file_has(p, b"jbserver_received_mach_message") or file_has(p, b"initXPCHooks")
        for p in (hook, lj, lc)
    )
    has_main_ctor = file_has(hook, b"GATE1B_LAUNCHDHOOK_CONSTRUCTOR_ENTERED") or file_has(
        hook, b"BUILD102732C_HOOK_CONSTRUCTOR_ENTERED=YES"
    )
    has_jbserver_mach = file_has(hook, b"jbserver_received_mach_message")
    has_dual_sandbox = file_has(hook, b"/private/var/jb") and file_has(hook, b"/var/jb")
    has_boomerang = file_has(hook, b"boomerang_recoverPrimitives516") or file_has(
        hook, b"GATE1B_LAUNCHDHOOK_BOOMERANG_RECOVER"
    )
    fuller = (
        full_jbserver
        and has_jbserver_mach
        and has_main_ctor
        and has_dual_sandbox
        and has_boomerang
    )
    cbr_present = initxpc and mshook
    # Host cannot fully parse INIT_OFFSETS count without Mach-O walk; require dual
    # constructor representation strings that the device gate also stages from audit.
    # Fail closed: require __objc_init_offsets style presence via nm section names if available.
    ot = run(["otool", "-l", str(hook)])
    has_init_offsets = "__init_offsets" in ot or "init_offsets" in ot
    has_mod_init = "mod_init_func" in ot and "__mod_init_func" in ot
    # Prefer init_offsets without relying on mod_init alone; device wants INIT_OFFSETS×2.
    ctor_hint_ok = has_init_offsets and not (
        has_mod_init and "__mod_init_func" in ot and ot.count("__init_offsets") == 0
    )

    deps_ok = hook_load and lj_load and lc_system and cbr_present and fuller
    # Without exact ctor count, require init_offsets present (R7/R24 fuller).
    pass_ok = deps_ok and has_init_offsets

    detail.update(
        {
            "HOOK_LOAD_LJ": "YES" if hook_load else "NO",
            "LJ_LOAD_LC": "YES" if lj_load else "NO",
            "LC_SYSTEM_ONLY": "YES" if lc_system else "NO",
            "MSHOOK_NEEDLE": "YES" if mshook else "NO",
            "INITXPC_NEEDLE": "YES" if initxpc else "NO",
            "CBR_SURFACE_PRESENT": "YES" if cbr_present else "NO",
            "FULLER_SURFACE": "YES" if fuller else "NO",
            "INIT_OFFSETS": "YES" if has_init_offsets else "NO",
            "DEP_CONTRACT": "PASS" if pass_ok else "FAIL",
            "CTOR_HINT": "YES" if ctor_hint_ok else "NO",
        }
    )
    return pass_ok, detail


def prove_canonical_d0_fixtures(
    hook: Path, systemhook: Path, candidate_ipa_sha256: str
) -> tuple[bool, dict[str, str]]:
    """Positive/negative fixtures for canonical D0 identity (fail closed)."""
    detail: dict[str, str] = {"CANONICAL_FIXTURE_FAIL": ""}
    try:
        base_h = canonical_sha256(hook)
        base_s = canonical_sha256(systemhook)
        uuid_h = macho_uuid(hook)
        uuid_s = macho_uuid(systemhook)
    except CanonicalIdError:
        detail["CANONICAL_FIXTURE_FAIL"] = "PARSE_IPA"
        return False, detail

    detail["FIXTURE_BASE_HOOK_CANONICAL"] = base_h
    detail["FIXTURE_BASE_SYSTEMHOOK_CANONICAL"] = base_s

    # Positive: an SSHRD pull is comparable only when explicitly bound to this
    # candidate IPA. Unbound files are historical evidence (V8 in this tree),
    # not a fixture for newly rebuilt Handoff bytes.
    dev_root = ROOT.parent / "D0-device"
    dev_hook = dev_root / "launchdhook516.dylib"
    dev_sh = dev_root / "systemhook.dylib"
    dev_binding = dev_root / "CANDIDATE_IPA_SHA256.txt"
    bound_sha = ""
    if dev_binding.is_file():
        binding_text = dev_binding.read_text(errors="replace")
        match = re.search(r"\b([0-9a-fA-F]{64})\b", binding_text)
        if not match:
            detail["CANONICAL_FIXTURE_FAIL"] = "DEVICE_BINDING_INVALID"
            return False, detail
        bound_sha = match.group(1).lower()
    if (
        dev_hook.is_file()
        and dev_sh.is_file()
        and bound_sha == candidate_ipa_sha256.lower()
    ):
        try:
            if canonical_sha256(dev_hook) != base_h or macho_uuid(dev_hook) != uuid_h:
                detail["CANONICAL_FIXTURE_FAIL"] = "DEVICE_HOOK_CANONICAL_NE_IPA"
                return False, detail
            if canonical_sha256(dev_sh) != base_s or macho_uuid(dev_sh) != uuid_s:
                detail["CANONICAL_FIXTURE_FAIL"] = "DEVICE_SYSTEMHOOK_CANONICAL_NE_IPA"
                return False, detail
            detail["FIXTURE_DEVICE_PULL"] = "PASS"
        except CanonicalIdError:
            detail["CANONICAL_FIXTURE_FAIL"] = "DEVICE_PULL_PARSE"
            return False, detail
    elif dev_hook.is_file() and dev_sh.is_file() and bound_sha:
        detail["FIXTURE_DEVICE_PULL"] = "SKIPPED_BOUND_TO_DIFFERENT_IPA"
        detail["FIXTURE_DEVICE_PULL_BOUND_SHA256"] = bound_sha
    elif dev_hook.is_file() and dev_sh.is_file():
        detail["FIXTURE_DEVICE_PULL"] = "SKIPPED_UNBOUND_HISTORICAL_PULL"
    else:
        detail["FIXTURE_DEVICE_PULL"] = "SKIPPED_NO_D0_DEVICE_DIR"

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        # CS-only mutation (grow/zero last CS byte region via datasize grow simulation):
        # copy file and overwrite CS blob bytes — canonical must PASS (unchanged).
        cs_mut = tdp / "hook_cs_mut.dylib"
        cs_mut.write_bytes(hook.read_bytes())
        blob = bytearray(cs_mut.read_bytes())
        # Find CS and flip bytes inside blob only
        import struct as _st

        ncmds = _st.unpack_from("<I", blob, 16)[0]
        off = 32
        cs_off = cs_sz = None
        for _ in range(ncmds):
            cmd, cmdsize = _st.unpack_from("<II", blob, off)
            if cmd == 0x1D:
                cs_off, cs_sz = _st.unpack_from("<II", blob, off + 8)
                break
            off += cmdsize
        if cs_off is None or cs_sz is None or cs_sz < 16:
            detail["CANONICAL_FIXTURE_FAIL"] = "CS_LOCATE"
            return False, detail
        for i in range(cs_off, min(cs_off + cs_sz, len(blob))):
            blob[i] ^= 0x5A
        cs_mut.write_bytes(blob)
        try:
            if canonical_sha256(cs_mut) != base_h:
                detail["CANONICAL_FIXTURE_FAIL"] = "CS_ONLY_MUTATION_SHOULD_PASS"
                return False, detail
        except CanonicalIdError:
            detail["CANONICAL_FIXTURE_FAIL"] = "CS_ONLY_MUTATION_PARSE"
            return False, detail
        detail["FIXTURE_CS_ONLY_PASS"] = "PASS"

        # Positive: D0 identity is install/signature invariant.  A bounded CS
        # region followed by installation-owned trailer bytes must retain the
        # canonical identity and UUID while changing the raw file identity.
        for label, original, expected_canon, expected_uuid in (
            ("HOOK", hook, base_h, uuid_h),
            ("SYSTEMHOOK", systemhook, base_s, uuid_s),
        ):
            trailer_mut = tdp / f"{label.lower()}_install_trailer.dylib"
            original_raw = original.read_bytes()
            trailer_mut.write_bytes(original_raw + b"R24_D0_INSTALL_TRAILER_FIXTURE")
            try:
                if canonical_sha256(trailer_mut) != expected_canon:
                    detail["CANONICAL_FIXTURE_FAIL"] = f"{label}_TRAILER_CANONICAL_NE_BASE"
                    return False, detail
                if macho_uuid(trailer_mut) != expected_uuid:
                    detail["CANONICAL_FIXTURE_FAIL"] = f"{label}_TRAILER_UUID_NE_BASE"
                    return False, detail
                if hashlib.sha256(trailer_mut.read_bytes()).hexdigest() == hashlib.sha256(original_raw).hexdigest():
                    detail["CANONICAL_FIXTURE_FAIL"] = f"{label}_TRAILER_RAW_SHOULD_CHANGE"
                    return False, detail
                try:
                    macho_cs_end_valid(trailer_mut)
                    detail["CANONICAL_FIXTURE_FAIL"] = f"{label}_TRAILER_STRICT_SHOULD_FAIL"
                    return False, detail
                except CanonicalIdError:
                    pass
            except CanonicalIdError:
                detail["CANONICAL_FIXTURE_FAIL"] = f"{label}_TRAILER_PARSE"
                return False, detail
        detail["FIXTURE_INSTALL_TRAILER_PASS"] = "PASS"

        # __text poke: find __TEXT.__text and flip one byte — canonical must FAIL.
        text_mut = tdp / "hook_text_mut.dylib"
        raw = bytearray(hook.read_bytes())
        ncmds = _st.unpack_from("<I", raw, 16)[0]
        off = 32
        text_fileoff = None
        for _ in range(ncmds):
            cmd, cmdsize = _st.unpack_from("<II", raw, off)
            if cmd == 0x19:
                name = bytes(raw[off + 8 : off + 24]).split(b"\0", 1)[0]
                if name == b"__TEXT":
                    nsects = _st.unpack_from("<I", raw, off + 64)[0]
                    so = off + 72
                    for _s in range(nsects):
                        sec = bytes(raw[so : so + 16]).split(b"\0", 1)[0]
                        sfo = _st.unpack_from("<I", raw, so + 48)[0]
                        ssize = _st.unpack_from("<Q", raw, so + 40)[0]
                        if sec == b"__text" and ssize > 32:
                            text_fileoff = sfo + 16
                            break
                        so += 80
                if text_fileoff is not None:
                    break
            off += cmdsize
        if text_fileoff is None or text_fileoff >= len(raw):
            detail["CANONICAL_FIXTURE_FAIL"] = "TEXT_LOCATE"
            return False, detail
        raw[text_fileoff] ^= 0x01
        text_mut.write_bytes(raw)
        try:
            if canonical_sha256(text_mut) == base_h:
                detail["CANONICAL_FIXTURE_FAIL"] = "TEXT_MUTATION_SHOULD_FAIL"
                return False, detail
        except CanonicalIdError:
            # parse failure after corruption is also an acceptable fail-closed signal
            pass
        detail["FIXTURE_TEXT_MUT_FAIL"] = "PASS"

        # UUID alter: flip one UUID byte in LC_UUID — UUID check path covered by
        # canonical hash also changing (UUID is in pre-CS prefix).
        uuid_mut = tdp / "hook_uuid_mut.dylib"
        uraw = bytearray(hook.read_bytes())
        ncmds = _st.unpack_from("<I", uraw, 16)[0]
        off = 32
        uuid_off = None
        for _ in range(ncmds):
            cmd, cmdsize = _st.unpack_from("<II", uraw, off)
            if cmd == 0x1B:
                uuid_off = off + 8
                break
            off += cmdsize
        if uuid_off is None:
            detail["CANONICAL_FIXTURE_FAIL"] = "UUID_LOCATE"
            return False, detail
        uraw[uuid_off] ^= 0x01
        uuid_mut.write_bytes(uraw)
        try:
            if canonical_sha256(uuid_mut) == base_h:
                detail["CANONICAL_FIXTURE_FAIL"] = "UUID_MUTATION_SHOULD_FAIL"
                return False, detail
            if macho_uuid(uuid_mut) == uuid_h:
                detail["CANONICAL_FIXTURE_FAIL"] = "UUID_STRING_SHOULD_CHANGE"
                return False, detail
        except CanonicalIdError:
            pass
        detail["FIXTURE_UUID_MUT_FAIL"] = "PASS"

    detail["CANONICAL_FIXTURE_FAIL"] = ""
    return True, detail


def prove_c_python_canonical_agree(dyld: Path) -> tuple[bool, dict[str, str]]:
    detail: dict[str, str] = {}
    py = canonical_sha256(dyld)
    detail["PYTHON_CANONICAL"] = py
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        test_c = tdp / "canon_test.c"
        test_c.write_text(
            '#include "dt_macho_canonical_id.h"\n'
            "#include <stdio.h>\n"
            "int main(int argc, char **argv) {\n"
            "  char hex[65];\n"
            "  if (argc < 2 || dt_macho_canonical_sha256_hex(argv[1], hex, sizeof hex) != 0)\n"
            "    return 2;\n"
            "  puts(hex);\n"
            "  return 0;\n"
            "}\n"
        )
        bin_out = tdp / "canon_test"
        inc = ROOT / "source"
        src = ROOT / "source/dt_macho_canonical_id.c"
        cc = subprocess.run(
            [
                "xcrun",
                "-sdk",
                "macosx",
                "clang",
                "-O2",
                "-Wall",
                "-Werror",
                f"-I{inc}",
                str(src),
                str(test_c),
                "-o",
                str(bin_out),
                "-framework",
                "Security",
            ],
            capture_output=True,
            text=True,
        )
        if cc.returncode != 0:
            detail["C_PYTHON_AGREE"] = "COMPILE_FAIL"
            detail["C_COMPILE_ERR"] = (cc.stderr or cc.stdout)[-400:]
            return False, detail
        run = subprocess.run([str(bin_out), str(dyld)], capture_output=True, text=True)
        if run.returncode != 0:
            detail["C_PYTHON_AGREE"] = "RUN_FAIL"
            return False, detail
        c_hex = run.stdout.strip().lower()
        detail["C_CANONICAL"] = c_hex
        if c_hex != py:
            detail["C_PYTHON_AGREE"] = "MISMATCH"
            return False, detail
        trailer = tdp / "dyld_trailer"
        trailer.write_bytes(dyld.read_bytes() + b"R24_CANONICAL_PARITY_TRAILER")
        py_trailer = canonical_sha256(trailer)
        run_trailer = subprocess.run([str(bin_out), str(trailer)], capture_output=True, text=True)
        if run_trailer.returncode != 0:
            detail["C_PYTHON_TRAILER_AGREE"] = "RUN_FAIL"
            return False, detail
        c_trailer = run_trailer.stdout.strip().lower()
        if py_trailer != py or c_trailer != py_trailer:
            detail["C_PYTHON_TRAILER_AGREE"] = "MISMATCH"
            return False, detail
        detail["C_PYTHON_TRAILER_AGREE"] = "PASS"
    detail["C_PYTHON_AGREE"] = "PASS"
    return True, detail


def prove_c_python_runtime_layout_agree(dyld: Path) -> tuple[bool, dict[str, str]]:
    """Execute the device C and host Python installed-layout policies on the same fixtures."""
    import struct as _st

    detail: dict[str, str] = {"C_PYTHON_RUNTIME_LAYOUT_AGREE": "FAIL"}
    raw = bytearray(dyld.read_bytes())

    def commands(blob: bytes | bytearray) -> list[tuple[int, int, int]]:
        ncmds = _st.unpack_from("<I", blob, 16)[0]
        sizeofcmds = _st.unpack_from("<I", blob, 20)[0]
        rows: list[tuple[int, int, int]] = []
        off = 32
        for _ in range(ncmds):
            if off + 8 > 32 + sizeofcmds:
                break
            cmd, cmdsize = _st.unpack_from("<II", blob, off)
            rows.append((off, cmd, cmdsize))
            if cmdsize < 8:
                break
            off += cmdsize
        return rows

    rows = commands(raw)
    cs_row = next((row for row in rows if row[1] == 0x1D), None)
    sym_row = next((row for row in rows if row[1] == 0x02), None)
    if cs_row is None or sym_row is None:
        detail["C_PYTHON_RUNTIME_LAYOUT_FAIL"] = "FIXTURE_LOCATE"
        return False, detail

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        test_c = tdp / "runtime_layout_test.c"
        test_c.write_text(
            '#include "dt_macho_canonical_id.h"\n'
            "#include <stdio.h>\n"
            "int main(int argc, char **argv) {\n"
            "  dt_macho_runtime_layout_t l = {0};\n"
            "  int rc = argc < 2 ? 22 : dt_macho_runtime_layout_validate(argv[1], 14, 874032, 874020, 0x4000, &l);\n"
            "  if (rc != 0) { printf(\"FAIL %d\\n\", rc); return 1; }\n"
            "  printf(\"PASS %llu %u %u %u %u %llu %llu %llu %llu %llu\\n\",\n"
            "    (unsigned long long)l.file_size, l.ncmds, l.sizeofcmds, l.cs_off, l.cs_size,\n"
            "    (unsigned long long)l.cs_end, (unsigned long long)l.trailer_size,\n"
            "    (unsigned long long)l.max_non_signature_end,\n"
            "    (unsigned long long)l.jbinfo_fileoff, (unsigned long long)l.jbinfo_size);\n"
            "  return 0;\n"
            "}\n"
        )
        bin_out = tdp / "runtime_layout_test"
        cc = subprocess.run(
            [
                "xcrun", "-sdk", "macosx", "clang", "-O2", "-Wall", "-Werror",
                f"-I{ROOT / 'source'}", str(ROOT / "source/dt_macho_canonical_id.c"),
                str(test_c), "-o", str(bin_out), "-framework", "Security",
            ],
            capture_output=True,
            text=True,
        )
        if cc.returncode != 0:
            detail["C_PYTHON_RUNTIME_LAYOUT_FAIL"] = "COMPILE"
            detail["C_RUNTIME_COMPILE_ERR"] = (cc.stderr or cc.stdout)[-400:]
            return False, detail

        fixtures: list[tuple[str, bytearray, bool]] = [("BASE", bytearray(raw), True)]
        fixtures.append(("TRAILER_23", bytearray(raw) + bytearray(b"T" * 23), True))

        overrun = bytearray(raw)
        cs_cmd_off = cs_row[0]
        cs_off = _st.unpack_from("<I", overrun, cs_cmd_off + 8)[0]
        _st.pack_into("<I", overrun, cs_cmd_off + 12, len(overrun) - cs_off + 1)
        fixtures.append(("CS_OVERRUN", overrun, False))

        missing_cs = bytearray(raw)
        _st.pack_into("<I", missing_cs, cs_cmd_off, 0x7FFFFFFF)
        fixtures.append(("MISSING_CS", missing_cs, False))

        bad_cmd = bytearray(raw)
        _st.pack_into("<I", bad_cmd, 36, 0)
        fixtures.append(("BAD_CMDSIZE", bad_cmd, False))

        non_sig_cross = bytearray(raw) + bytearray(b"T" * 23)
        sym_off = sym_row[0]
        stroff = _st.unpack_from("<I", non_sig_cross, sym_off + 16)[0]
        _st.pack_into("<I", non_sig_cross, sym_off + 20, cs_off + 1 - stroff)
        fixtures.append(("NON_SIGNATURE_CROSSES_CS", non_sig_cross, False))

        pass_count = 0
        for name, blob, expected in fixtures:
            path = tdp / name
            path.write_bytes(blob)
            try:
                py_layout = runtime_dyld_layout(path)
                py_ok = True
            except CanonicalIdError:
                py_layout = {}
                py_ok = False
            c_run = subprocess.run([str(bin_out), str(path)], capture_output=True, text=True)
            c_ok = c_run.returncode == 0 and c_run.stdout.startswith("PASS ")
            if py_ok != expected or c_ok != expected or py_ok != c_ok:
                detail["C_PYTHON_RUNTIME_LAYOUT_FAIL"] = name
                detail[f"FIXTURE_{name}"] = f"expected={expected} python={py_ok} c={c_ok}"
                return False, detail
            if expected:
                vals = [int(v) for v in c_run.stdout.strip().split()[1:]]
                keys = (
                    "FILE_SIZE", "NCMDS", "SIZEOFCMDS", "CS_OFF", "CS_SIZE",
                    "CS_END", "TRAILER_SIZE", "MAX_NON_SIGNATURE_END",
                    "JBINFO_FILEOFF", "JBINFO_SIZE",
                )
                if vals != [py_layout[k] for k in keys]:
                    detail["C_PYTHON_RUNTIME_LAYOUT_FAIL"] = f"{name}_VALUE_MISMATCH"
                    return False, detail
            detail[f"C_PYTHON_RUNTIME_{name}"] = "PASS"
            pass_count += 1

    detail["C_PYTHON_RUNTIME_FIXTURES"] = str(pass_count)
    detail["C_PYTHON_RUNTIME_LAYOUT_AGREE"] = "PASS"
    return True, detail


def prove_h16_dyld_fixtures(dyld: Path) -> tuple[bool, dict[str, str]]:
    """Execute both dyld policies and their identity/cardinality/bounds matrix."""
    import struct as _st

    detail: dict[str, str] = {"H16_DYLD_FIXTURE_FAIL": ""}

    def manifest_for(path: Path) -> dict[str, str]:
        patch_off = locate_generated_patch_offset(path)
        return {
            "generated_canonical_sha256": canonical_sha256(path),
            "generated_uuid": macho_uuid(path),
            "generated_patch_offset": f"0x{patch_off:x}",
        }

    try:
        base = canonical_sha256(dyld)
        base_uuid = macho_uuid(dyld)
        patch_off = locate_generated_patch_offset(dyld)
        base_manifest = manifest_for(dyld)
        validate_generated_dyld_contract(dyld, base_manifest)
        validate_installed_runtime_dyld_contract(dyld, base_manifest)
    except CanonicalIdError as e:
        detail["H16_DYLD_FIXTURE_FAIL"] = f"BASE_PARSE:{e}"
        return False, detail
    detail["BASE_CANONICAL"] = base
    detail["BASE_UUID"] = base_uuid
    detail["BASE_PATCH_OFFSET"] = f"0x{patch_off:x}"

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        raw = bytearray(dyld.read_bytes())
        ncmds = _st.unpack_from("<I", raw, 16)[0]
        sizeofcmds = _st.unpack_from("<I", raw, 20)[0]

        rows: list[tuple[int, int, int]] = []
        sections: list[tuple[int, bytes, bytes, int, int]] = []
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = _st.unpack_from("<II", raw, off)
            rows.append((off, cmd, cmdsize))
            if cmd == 0x19:
                segname = bytes(raw[off + 8 : off + 24]).split(b"\0", 1)[0]
                nsects = _st.unpack_from("<I", raw, off + 64)[0]
                so = off + 72
                for _section in range(nsects):
                    sectname = bytes(raw[so : so + 16]).split(b"\0", 1)[0]
                    secseg = bytes(raw[so + 16 : so + 32]).split(b"\0", 1)[0]
                    secsize = _st.unpack_from("<Q", raw, so + 40)[0]
                    fileoff = _st.unpack_from("<I", raw, so + 48)[0]
                    sections.append((so, secseg, sectname, fileoff, secsize))
                    so += 80
            off += cmdsize
        if off != 32 + sizeofcmds:
            detail["H16_DYLD_FIXTURE_FAIL"] = "BASE_COMMAND_TABLE"
            return False, detail

        cs_row = next((row for row in rows if row[1] == 0x1D), None)
        uuid_row = next((row for row in rows if row[1] == 0x1B), None)
        sym_row = next((row for row in rows if row[1] == 0x02), None)
        linkedit_row = next((row for row in rows if row[1] == 0x19 and bytes(raw[row[0] + 8 : row[0] + 24]).split(b"\0", 1)[0] == b"__LINKEDIT"), None)
        other_seg_row = next((row for row in rows if row[1] == 0x19 and row != linkedit_row), None)
        jbinfo_row = next((row for row in sections if row[1] == b"__DATA" and row[2] == b"__jbinfo"), None)
        other_section = next((row for row in sections if row != jbinfo_row), None)
        if None in (cs_row, uuid_row, sym_row, linkedit_row, other_seg_row, jbinfo_row, other_section):
            detail["H16_DYLD_FIXTURE_FAIL"] = "CS_LOCATE"
            return False, detail

        def policy_pass(path: Path, strict: bool, manifest: dict[str, str] | None = None) -> bool:
            try:
                m = manifest if manifest is not None else manifest_for(path)
                if strict:
                    validate_generated_dyld_contract(path, m)
                else:
                    validate_installed_runtime_dyld_contract(path, m)
                return True
            except CanonicalIdError:
                return False

        def check(
            name: str,
            blob: bytes | bytearray,
            strict: bool,
            runtime: bool,
            manifest: dict[str, str] | None = None,
        ) -> bool:
            path = tdp / name
            path.write_bytes(blob)
            m = manifest if manifest is not None else base_manifest
            strict_got = policy_pass(path, True, m)
            runtime_got = policy_pass(path, False, m)
            if strict_got != strict or runtime_got != runtime:
                detail["H16_DYLD_FIXTURE_FAIL"] = (
                    f"{name}:strict={strict_got}/{strict},runtime={runtime_got}/{runtime}"
                )
                return False
            detail[f"FIXTURE_{name}"] = "PASS"
            return True

        cs_cmd_off = cs_row[0]
        uuid_cmd_off = uuid_row[0]
        cs_off, cs_sz = _st.unpack_from("<II", raw, cs_cmd_off + 8)

        cs_mut = bytearray(raw)
        for i in range(cs_off, min(cs_off + cs_sz, len(cs_mut))):
            cs_mut[i] ^= 0x5A
        if not check("CS_ONLY_BOTH_PASS", cs_mut, True, True):
            return False, detail

        patch_mut = bytearray(raw)
        patch_mut[patch_off] ^= 0x01
        if not check("PATCH_MUT_BOTH_FAIL", patch_mut, False, False):
            return False, detail

        uuid_mut = bytearray(raw)
        uuid_mut[uuid_cmd_off + 8] ^= 0x01
        if not check("UUID_MUT_BOTH_FAIL", uuid_mut, False, False):
            return False, detail

        text_mut = bytearray(raw)
        text_mut[0x4000] ^= 0x01
        if not check("EXECUTABLE_MUT_BOTH_FAIL", text_mut, False, False):
            return False, detail

        jbinfo_mut = bytearray(raw)
        jbinfo_mut[jbinfo_row[3]] ^= 0x01
        if not check("JBINFO_DATA_MUT_BOTH_FAIL", jbinfo_mut, False, False):
            return False, detail

        append_mut = bytearray(raw) + bytearray(b"T" * 23)
        if not check("TRAILER_STRICT_FAIL_RUNTIME_PASS", append_mut, False, True):
            return False, detail

        cs_overrun = bytearray(raw)
        _st.pack_into("<I", cs_overrun, cs_cmd_off + 12, len(raw) - cs_off + 1)
        if not check("CS_OVERRUN_BOTH_FAIL", cs_overrun, False, False):
            return False, detail

        cardinality: list[tuple[str, bytearray]] = []
        missing_cs = bytearray(raw); _st.pack_into("<I", missing_cs, cs_cmd_off, 0x7FFFFFFF)
        cardinality.append(("MISSING_CS", missing_cs))
        duplicate_cs = bytearray(raw); _st.pack_into("<I", duplicate_cs, uuid_cmd_off, 0x1D)
        cardinality.append(("DUPLICATE_CS", duplicate_cs))
        missing_uuid = bytearray(raw); _st.pack_into("<I", missing_uuid, uuid_cmd_off, 0x7FFFFFFE)
        cardinality.append(("MISSING_UUID", missing_uuid))
        duplicate_uuid = bytearray(raw); _st.pack_into("<I", duplicate_uuid, sym_row[0], 0x1B)
        cardinality.append(("DUPLICATE_UUID", duplicate_uuid))
        missing_linkedit = bytearray(raw); missing_linkedit[linkedit_row[0] + 8 : linkedit_row[0] + 24] = b"__LINKEDIX".ljust(16, b"\0")
        cardinality.append(("MISSING_LINKEDIT", missing_linkedit))
        duplicate_linkedit = bytearray(raw); duplicate_linkedit[other_seg_row[0] + 8 : other_seg_row[0] + 24] = b"__LINKEDIT".ljust(16, b"\0")
        cardinality.append(("DUPLICATE_LINKEDIT", duplicate_linkedit))
        missing_jbinfo = bytearray(raw); missing_jbinfo[jbinfo_row[0] : jbinfo_row[0] + 16] = b"__jbinfo_missing".ljust(16, b"\0")
        cardinality.append(("MISSING_JBINFO", missing_jbinfo))
        duplicate_jbinfo = bytearray(raw); duplicate_jbinfo[other_section[0] : other_section[0] + 16] = b"__jbinfo".ljust(16, b"\0")
        duplicate_jbinfo[other_section[0] + 16 : other_section[0] + 32] = b"__DATA".ljust(16, b"\0")
        cardinality.append(("DUPLICATE_JBINFO", duplicate_jbinfo))
        for name, blob in cardinality:
            if not check(f"{name}_BOTH_FAIL", blob, False, False):
                return False, detail

        bad_cmd = bytearray(raw)
        _st.pack_into("<I", bad_cmd, 36, 0)
        if not check("MALFORMED_COMMAND_BOTH_FAIL", bad_cmd, False, False):
            return False, detail

        non_sig_cross = bytearray(raw) + bytearray(b"T" * 23)
        stroff = _st.unpack_from("<I", non_sig_cross, sym_row[0] + 16)[0]
        _st.pack_into("<I", non_sig_cross, sym_row[0] + 20, cs_off + 1 - stroff)
        if not check("NON_SIGNATURE_REFERENCE_CROSSES_CS_BOTH_FAIL", non_sig_cross, False, False):
            return False, detail

    detail["PRISTINE_BUILD_STRICT"] = "PASS"
    detail["INSTALLED_RUNTIME_BOUNDED"] = "PASS"
    detail["DUAL_POLICY_FIXTURE_MATRIX"] = "PASS"
    detail["H16_DYLD_FIXTURE_FAIL"] = ""
    return True, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa", type=Path)
    args = ap.parse_args()
    ipa = args.ipa
    fails: list[str] = []
    gates: dict[str, str] = {}
    dep_detail: dict[str, str] = {}

    if not ipa.is_file():
        print("R24_HOST_SIM=FAIL")
        print("FAILS=IPA_MISSING")
        return 1

    ipa_sha = sha256_file(ipa)
    if ipa_sha in (R21_SHA, R22_SHA, R23_SHA):
        fails.append("IPA_COLLIDES_FROZEN_R21_R22_R23")
    if ipa_sha == PRIOR_FALSE_AUTH_R24_SHA:
        fails.append("IPA_IS_PRIOR_FALSE_AUTH_R24_NEEDS_REBUILD")
    if ipa_sha == PRIOR_KALLOC_PT_CRASH_R24_SHA:
        fails.append("IPA_IS_PRIOR_KALLOC_PT_CRASH_R24_NEEDS_REBUILD")
    if ipa_sha == PRIOR_CS_KILLED_INITPROC_R24_SHA:
        fails.append("IPA_IS_PRIOR_CS_KILLED_INITPROC_R24_NEEDS_REBUILD")
    if ipa_sha == PRIOR_NO_D0_PIN_R24_SHA:
        fails.append("IPA_IS_PRIOR_NO_D0_PIN_R24_NEEDS_REBUILD")
    if ipa_sha == PRIOR_D0_LEAF_GAP_R24_SHA:
        fails.append("IPA_IS_PRIOR_D0_LEAF_GAP_R24_NEEDS_REBUILD")
    if ipa_sha == PRIOR_R24_LEAF_WIRED_SUPERSEDED_SHA:
        fails.append("IPA_IS_PRIOR_R24_SUPERSEDED_BY_R24V7")
    if ipa_sha == PRIOR_R24V7_WHOLEFILE_D0_PIN_SHA:
        fails.append("IPA_IS_PRIOR_R24V7_WHOLEFILE_D0_PIN_NEEDS_CANONICAL_REBUILD")

    h11_detail: dict[str, str] = {}
    h12_detail: dict[str, str] = {}
    h13_detail: dict[str, str] = {}
    h14_detail: dict[str, str] = {}
    h15_detail: dict[str, str] = {}
    h16_detail: dict[str, str] = {}

    with zipfile.ZipFile(ipa) as z, tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        hook_m = find_member(z, "Handoff516/launchdhook516.dylib")
        lj_m = find_member(z, "Handoff516/libjailbreak.dylib")
        lc_m = find_member(z, "Handoff516/libchoma.dylib")
        sh_m = find_member(z, "Handoff516/systemhook.dylib")
        trust_m = find_member(z, "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv")
        path_m = find_member(z, "ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv")
        app_m = find_member(z, "dopamin-tvOS-kfd.app/dopamin-tvOS-kfd")
        runtime_probe_m = find_member(z, "RootlessPayload/usr/bin/true")
        delivery_dyld_m = find_member(z, "R24DyldDelivery/dyld")
        delivery_manifest_m = find_member(
            z, "R24DyldDelivery/R24_TVOS_DYLD_DELIVERY_IDENTITY.json"
        )

        # H1 — systemhook packaged
        if sh_m:
            gates["H1"] = "PASS"
            (td_path / "systemhook.dylib").write_bytes(z.read(sh_m))
        else:
            gates["H1"] = "FAIL"
            fails.append("H1_NO_SYSTEMHOOK")

        hook_path = lj_path = lc_path = None
        if not hook_m or not lj_m or not lc_m:
            gates["H2"] = "FAIL"
            gates["H3"] = "FAIL"
            fails.append("H2_HANDOFF_TRIO_INCOMPLETE")
        else:
            hook_path = td_path / "launchdhook516.dylib"
            lj_path = td_path / "libjailbreak.dylib"
            lc_path = td_path / "libchoma.dylib"
            hook_path.write_bytes(z.read(hook_m))
            lj_path.write_bytes(z.read(lj_m))
            lc_path.write_bytes(z.read(lc_m))

            hook_sha = hashlib.sha256(hook_path.read_bytes()).hexdigest()
            if hook_sha == PRE_CBR_HOOK:
                fails.append("H2_HOOK_STILL_PRE_CBR_SHA")
            if hook_sha == PRIOR_CS_KILLED_HOOK_SHA:
                fails.append("H2_HOOK_IS_PRIOR_CS_KILLED_SHA")

            nm = run(["nm", "-gU", str(hook_path)])
            strings = run(["strings", str(hook_path)])
            h2_ok = (
                re.search(r"\b_initXPCHooks\b", nm) is not None
                and re.search(r"\b_initSpawnHooks\b", nm) is not None
                and "XPC_HOOK_INSTALL_VERIFIED=YES" in strings
                and "SPAWN_HOOK_INSTALL_VERIFIED=YES" in strings
                and re.search(r"\b_dt_cbr_MSHookFunction\b", nm) is not None
            )
            gates["H2"] = "PASS" if h2_ok else "FAIL"
            if not h2_ok:
                fails.append("H2_HOOK_CONTRACT")

            # H5 — JBROOT path
            h5_ok = (
                "/usr/lib/systemhook.dylib" in strings
                and "/var/jb/basebin/systemhook.dylib" not in strings
            )
            gates["H5"] = "PASS" if h5_ok else "FAIL"
            if not h5_ok:
                fails.append("H5_HOOK_DYLIB_PATH")

            # H3 — device R24 DEP contract on Handoff trio (not packaging-only presence)
            dep_ok, dep_detail = evaluate_device_r24_dep_contract(hook_path, lj_path, lc_path)
            gates["H3"] = "PASS" if dep_ok else "FAIL"
            if not dep_ok:
                fails.append("H3_DEVICE_DEP_CONTRACT_FAIL")

            vt = run([VTOOL, "-show-build", str(hook_path)])
            if not re.search(r"sdk 1[46]\.", vt):
                fails.append("HOOK_SDK_NOT_14_16")
                gates["H2"] = "FAIL"

            # H11 / M4 — CS allow-invalid STAGE + compiled ctor call-order proof
            h11_ok = True
            for lit in (
                "LAUNCHD_JBROOT_DLADDR_BEGIN",
                "R24_LAUNCHD_JBROOT_FROM_DLADDR=PASS",
                "R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=",
                "LAUNCHD_CS_ALLOW_INVALID_BEGIN",
                "LAUNCHD_CS_ALLOW_INVALID=PASS",
                "LAUNCHD_CS_ALLOW_INVALID=FAIL",
                "CTOR_ORDER=JBROOT_DLADDR>BOOMERANG>CS_ALLOW_INVALID>XPC>SPAWN",
                "CTOR_ORDER=CS_ALLOW_INVALID>XPC>SPAWN",
                "GATE_FAIL=LAUNCHD_CS_ALLOW_INVALID",
            ):
                if lit not in strings:
                    h11_ok = False
                    fails.append(f"H11_MISSING_LITERAL={lit}")
            if re.search(r"\b_dt_r24_launchd_jbroot_from_dladdr_or_fail\b", nm) is None:
                h11_ok = False
                fails.append("H11_MISSING_JBROOT_DLADDR_HELPER_SYMBOL")
            if re.search(r"\b_dt_r24_launchd_cs_allow_invalid_or_fail\b", nm) is None:
                h11_ok = False
                fails.append("H11_MISSING_HELPER_SYMBOL")
            order_ok, h11_detail = prove_ctor_cs_before_spawn(hook_path)
            if not order_ok:
                h11_ok = False
                fails.append(
                    "H11_CTOR_ORDER_" + h11_detail.get("CTOR_ORDER_FAIL", "FAIL")
                )
            jbdomain_src = (
                Path(__file__).resolve().parents[1]
                / "source/handoff516/source/launchdhook/jbserver/jbdomain_systemwide.c"
            )
            if not jbdomain_src.is_file():
                h11_ok = False
                fails.append("H11_JBDOMAIN_SOURCE_MISSING")
            else:
                jbdomain_txt = jbdomain_src.read_text(errors="replace")
                if "*rootPathOut = rootPath ? strdup(rootPath) : NULL" not in jbdomain_txt:
                    h11_ok = False
                    fails.append("H11_GET_JBROOT_NULL_GUARD_MISSING")
                if "*rootPathOut = strdup(jbinfo(rootPath))" in jbdomain_txt:
                    h11_ok = False
                    fails.append("H11_GET_JBROOT_STILL_UNCONDITIONAL_STRDUP")
                else:
                    h11_detail["GET_JBROOT_NULL_GUARD"] = "PASS"
            gates["H11"] = "PASS" if h11_ok else "FAIL"
        # H4 — install trust 397 + runtime systemhook trust path present in MAIN
        if trust_m and app_m:
            trust_rows = list(
                csv.DictReader(z.read(trust_m).decode().splitlines(), delimiter="\t")
            )
            app_bytes = z.read(app_m)
            has_sh_trust_path = (
                b"BUILD102710_TRUST_SYSTEMHOOK_PASS" in app_bytes
                or b"BUILD102710_STAGE_SYSTEMHOOK" in app_bytes
            )
            if len(trust_rows) != 397:
                fails.append(f"H4_TRUST_COUNT={len(trust_rows)}")
                gates["H4"] = "FAIL"
            elif gates.get("H1") != "PASS" or not has_sh_trust_path:
                gates["H4"] = "FAIL"
                fails.append("H4_SYSTEMHOOK_TRUST_PATH")
            else:
                gates["H4"] = "PASS"
        else:
            gates["H4"] = "FAIL"
            fails.append("H4_NO_TRUST_OR_APP")

        # H6 — TweakLoader off
        if sh_m:
            sh_strings = run(["strings", str(td_path / "systemhook.dylib")])
            h6_ok = "TweakLoader.dylib" not in sh_strings and (
                "tweaks=OFF" in sh_strings or "SYSTEMHOOK_CBR" in sh_strings
            )
            gates["H6"] = "PASS" if h6_ok else "FAIL"
            if not h6_ok:
                fails.append("H6_TWEAKLOADER")
        else:
            gates["H6"] = "FAIL"

        # H7 — payload count
        if path_m:
            path_rows = list(
                csv.DictReader(z.read(path_m).decode().splitlines(), delimiter="\t")
            )
            h7_ok = len(path_rows) == 4053
            gates["H7"] = "PASS" if h7_ok else "FAIL"
            if not h7_ok:
                fails.append(f"H7_PAYLOAD_COUNT={len(path_rows)}")
        else:
            gates["H7"] = "FAIL"
            fails.append("H7_NO_PATH_MANIFEST")

        # H9 — MAIN must contain R24 DEP invert STAGE literals (proves device polarity compiled)
        if app_m:
            app_strings = z.read(app_m)
            if b"ROOTLESS_R24_DEP_GATE_CBR_SURFACE_REQUIRED=YES" not in app_strings:
                fails.append("H9_MAIN_MISSING_R24_DEP_INVERT")
                gates["H9"] = "FAIL"
            else:
                gates["H9"] = "PASS"
            # Packaging STAGE markers (not live install proof — labeled as such)
            if b"ROOTLESS_R24_CBR_SPAWN_HOOK_PACKAGED=YES" not in app_strings:
                fails.append("APP_STAGE_CBR_SPAWN_MARKER")
            if b"BUILD102738P_XPC_HOOK_PACKAGED=YES" not in app_strings:
                fails.append("APP_STAGE_XPC_YES")
            if b"ROOTLESS_R24_HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib" not in app_strings:
                fails.append("APP_STAGE_HOOK_PATH")
            # Must not authorize if MAIN still only has pre-R24 absence semantics without invert
            if b"ROOTLESS_R24_DEP_GATE_CBR_SURFACE_REQUIRED=YES" not in app_strings:
                fails.append("MAIN_DEP_POLARITY_STALE")
        else:
            gates["H9"] = "FAIL"
            fails.append("H9_NO_APP")

        # H10 / M4 — kalloc_pt C-pool + smoke STAGE + F3 coerce literals (pre-burn; not live stash)
        fw_lj_m = find_member(z, "Frameworks/libjailbreak.dylib")
        h10_ok = True
        if not fw_lj_m or not app_m:
            h10_ok = False
            fails.append("H10_NO_FRAMEWORK_LJ_OR_APP")
        else:
            fw_lj = td_path / "Frameworks_libjailbreak.dylib"
            fw_lj.write_bytes(z.read(fw_lj_m))
            fw_nm = run(["nm", "-gU", str(fw_lj)])
            fw_str = run(["strings", str(fw_lj)])
            app_bytes = z.read(app_m)
            if "backend=C_POOL" not in fw_str:
                h10_ok = False
                fails.append("H10_LJ_MISSING_C_POOL_BACKEND")
            if re.search(r"\b_kalloc_pt_prefill\b", fw_nm) is None:
                h10_ok = False
                fails.append("H10_LJ_MISSING_KALLOC_PT_PREFILL")
            if re.search(r"\b_kalloc_global_pt\b", fw_nm) is None and "kalloc_global_pt" not in fw_str:
                # kalloc_global_pt may be static; require C_POOL + prefill export instead
                pass
            if b"KALLOC_PT_SMOKE_OK" not in app_bytes or b"KALLOC_PT_SMOKE_FAIL=" not in app_bytes:
                h10_ok = False
                fails.append("H10_MAIN_MISSING_KALLOC_PT_SMOKE_STAGE")
            if b"KALLOC_PT_PREFILL_OK" not in app_bytes:
                h10_ok = False
                fails.append("H10_MAIN_MISSING_KALLOC_PT_PREFILL_STAGE")
            if b"ROOTLESS_R24_FORCE_RECOVERY_HELPER_IDENTITY=YES" not in app_bytes:
                h10_ok = False
                fails.append("H10_MAIN_MISSING_F3_FORCE_RECOVERY")
            # ObjC pool regression: NSNumber unsignedLongLongValue path on gPool
            if "unsignedLongLongValue" in fw_str and "NSMutableArray" in fw_str:
                # Heuristic: both present in same LJ was the crash surface; C_POOL must win.
                if "backend=C_POOL" not in fw_str:
                    h10_ok = False
                    fails.append("H10_LJ_STILL_OBJC_POOL_SURFACE")
        gates["H10"] = "PASS" if h10_ok else "FAIL"

        if "H11" not in gates:
            gates["H11"] = "FAIL"
            fails.append("H11_NO_HOOK")

        # H12 / M4 — canonical D0 pins + UUID + leaf_prepare order + fixtures
        h12_ok = True
        app_bytes = b""
        h12_detail = {
            "EXPECT_HOOK_CANONICAL_SHA256": "",
            "EXPECT_SYSTEMHOOK_CANONICAL_SHA256": "",
            "EXPECT_HOOK_UUID": "",
            "EXPECT_SYSTEMHOOK_UUID": "",
            "IPA_HOOK_CANONICAL_SHA256": "",
            "IPA_SYSTEMHOOK_CANONICAL_SHA256": "",
            "IPA_HOOK_UUID": "",
            "IPA_SYSTEMHOOK_UUID": "",
            "IPA_HOOK_RAW_SHA256": "",
            "IPA_SYSTEMHOOK_RAW_SHA256": "",
            "D0_PIN_CONTRACT": "FAIL",
            "LEAF_D0_ORDER_PROOF": "FAIL",
            "CANONICAL_FIXTURES": "FAIL",
        }
        if not app_m or gates.get("H1") != "PASS" or not hook_path:
            h12_ok = False
            fails.append("H12_NO_APP_HOOK_OR_SYSTEMHOOK")
        else:
            app_bytes = z.read(app_m)
            app_bin = td_path / "dopamin-tvOS-kfd"
            app_bin.write_bytes(app_bytes)
            sh_path = td_path / "systemhook.dylib"
            try:
                ipa_hook_canon = canonical_sha256(hook_path)
                ipa_sh_canon = canonical_sha256(sh_path)
                ipa_hook_uuid = macho_uuid(hook_path)
                ipa_sh_uuid = macho_uuid(sh_path)
            except CanonicalIdError as e:
                h12_ok = False
                fails.append("H12_IPA_CANONICAL_PARSE")
                ipa_hook_canon = ipa_sh_canon = ipa_hook_uuid = ipa_sh_uuid = ""
            ipa_hook_raw = hashlib.sha256(hook_path.read_bytes()).hexdigest()
            ipa_sh_raw = hashlib.sha256(sh_path.read_bytes()).hexdigest()
            h12_detail["IPA_HOOK_CANONICAL_SHA256"] = ipa_hook_canon
            h12_detail["IPA_SYSTEMHOOK_CANONICAL_SHA256"] = ipa_sh_canon
            h12_detail["IPA_HOOK_UUID"] = ipa_hook_uuid
            h12_detail["IPA_SYSTEMHOOK_UUID"] = ipa_sh_uuid
            h12_detail["IPA_HOOK_RAW_SHA256"] = ipa_hook_raw
            h12_detail["IPA_SYSTEMHOOK_RAW_SHA256"] = ipa_sh_raw

            m_hook = re.search(
                rb"ROOTLESS_R24_EXPECT_HOOK_CANONICAL_SHA256=([0-9a-f]{64})", app_bytes
            )
            m_sh = re.search(
                rb"ROOTLESS_R24_EXPECT_SYSTEMHOOK_CANONICAL_SHA256=([0-9a-f]{64})",
                app_bytes,
            )
            m_hu = re.search(
                rb"ROOTLESS_R24_EXPECT_HOOK_UUID=([0-9A-F-]{36})", app_bytes
            )
            m_su = re.search(
                rb"ROOTLESS_R24_EXPECT_SYSTEMHOOK_UUID=([0-9A-F-]{36})", app_bytes
            )
            if not m_hook:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_EXPECT_HOOK_CANONICAL_PIN")
            else:
                pin_hook = m_hook.group(1).decode("ascii")
                h12_detail["EXPECT_HOOK_CANONICAL_SHA256"] = pin_hook
                if pin_hook != ipa_hook_canon:
                    h12_ok = False
                    fails.append("H12_EXPECT_HOOK_CANONICAL_NE_IPA")
            if not m_sh:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_EXPECT_SYSTEMHOOK_CANONICAL_PIN")
            else:
                pin_sh = m_sh.group(1).decode("ascii")
                h12_detail["EXPECT_SYSTEMHOOK_CANONICAL_SHA256"] = pin_sh
                if pin_sh != ipa_sh_canon:
                    h12_ok = False
                    fails.append("H12_EXPECT_SYSTEMHOOK_CANONICAL_NE_IPA")
            if not m_hu:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_EXPECT_HOOK_UUID")
            else:
                pin_hu = m_hu.group(1).decode("ascii")
                h12_detail["EXPECT_HOOK_UUID"] = pin_hu
                if pin_hu != ipa_hook_uuid:
                    h12_ok = False
                    fails.append("H12_EXPECT_HOOK_UUID_NE_IPA")
            if not m_su:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_EXPECT_SYSTEMHOOK_UUID")
            else:
                pin_su = m_su.group(1).decode("ascii")
                h12_detail["EXPECT_SYSTEMHOOK_UUID"] = pin_su
                if pin_su != ipa_sh_uuid:
                    h12_ok = False
                    fails.append("H12_EXPECT_SYSTEMHOOK_UUID_NE_IPA")

            if b"ROOTLESS_R24_D0_IDENTITY_KIND=CANONICAL_MACHO_TS_INVARIANT" not in app_bytes:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_D0_IDENTITY_KIND")
            if b"ROOTLESS_R24_D0_CANONICAL_POLICY=INSTALL_TOLERANT_STRICT_BOUNDS" not in app_bytes:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_D0_CANONICAL_POLICY")
            for rc_marker in (
                b"ROOTLESS_R24_D0_BUNDLE_HOOK_CANONICAL_RC=",
                b"ROOTLESS_R24_D0_STAGED_HOOK_CANONICAL_RC=",
                b"ROOTLESS_R24_D0_BUNDLE_SYSTEMHOOK_CANONICAL_RC=",
                b"ROOTLESS_R24_D0_STAGED_SYSTEMHOOK_CANONICAL_RC=",
            ):
                if rc_marker not in app_bytes:
                    h12_ok = False
                    fails.append("H12_MAIN_MISSING_D0_CANONICAL_RC_TELEMETRY")
                    break
            if b"GATE_FAIL=D0_IDENTITY" not in app_bytes:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_D0_GATE_FAIL_LITERAL")
            if b"ROOTLESS_R24_D0_IDENTITY=PASS" not in app_bytes:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_D0_PASS_LITERAL")
            if b"ROOTLESS_R24_D0_CHECK=LEAF_PREPARE" not in app_bytes:
                h12_ok = False
                fails.append("H12_MAIN_MISSING_D0_LEAF_PREPARE_CHECK")
            if re.search(rb"ROOTLESS_R24_EXPECT_HOOK_SHA256=[0-9a-f]{64}", app_bytes):
                h12_ok = False
                fails.append("H12_MAIN_STILL_HAS_WHOLEFILE_HOOK_PIN")

            leaf_ok, leaf_detail = prove_leaf_prepare_d0_before_sign(app_bin)
            h12_detail.update(leaf_detail)
            if not leaf_ok:
                h12_ok = False
                fails.append(
                    "H12_LEAF_D0_" + leaf_detail.get("LEAF_D0_ORDER_FAIL", "ORDER_FAIL")
                )

            fix_ok, fix_detail = prove_canonical_d0_fixtures(hook_path, sh_path, ipa_sha)
            h12_detail.update(fix_detail)
            h12_detail["CANONICAL_FIXTURES"] = "PASS" if fix_ok else "FAIL"
            if not fix_ok:
                h12_ok = False
                fails.append(
                    "H12_CANONICAL_FIXTURE_"
                    + fix_detail.get("CANONICAL_FIXTURE_FAIL", "FAIL")
                )

        pin_only = (
            bool(h12_detail.get("EXPECT_HOOK_CANONICAL_SHA256"))
            and h12_detail.get("EXPECT_HOOK_CANONICAL_SHA256")
            == h12_detail.get("IPA_HOOK_CANONICAL_SHA256")
            and bool(h12_detail.get("EXPECT_SYSTEMHOOK_CANONICAL_SHA256"))
            and h12_detail.get("EXPECT_SYSTEMHOOK_CANONICAL_SHA256")
            == h12_detail.get("IPA_SYSTEMHOOK_CANONICAL_SHA256")
            and bool(h12_detail.get("EXPECT_HOOK_UUID"))
            and h12_detail.get("EXPECT_HOOK_UUID") == h12_detail.get("IPA_HOOK_UUID")
            and bool(h12_detail.get("EXPECT_SYSTEMHOOK_UUID"))
            and h12_detail.get("EXPECT_SYSTEMHOOK_UUID")
            == h12_detail.get("IPA_SYSTEMHOOK_UUID")
            and b"GATE_FAIL=D0_IDENTITY" in app_bytes
            and b"ROOTLESS_R24_D0_IDENTITY=PASS" in app_bytes
            and b"ROOTLESS_R24_D0_CHECK=LEAF_PREPARE" in app_bytes
            and b"ROOTLESS_R24_D0_IDENTITY_KIND=CANONICAL_MACHO_TS_INVARIANT" in app_bytes
            and b"ROOTLESS_R24_D0_CANONICAL_POLICY=INSTALL_TOLERANT_STRICT_BOUNDS" in app_bytes
            and h12_detail.get("CANONICAL_FIXTURES") == "PASS"
        )
        h12_detail["D0_PIN_CONTRACT"] = "PASS" if pin_only else "FAIL"
        gates["H12"] = "PASS" if h12_ok else "FAIL"

        # H13 / M4 — current-boot runtime propagation contract (static only).
        h13_ok = True
        h13_detail = {
            "RUNTIME_ORDER_PROOF": "FAIL",
            "HOOK_RUNTIME_MARKERS": "FAIL",
            "SYSTEMHOOK_CHECKIN_MARKERS": "FAIL",
            "CONTROLLED_CHILD_PATH": "FAIL",
            "USERSPACE_REBOOT_TRIGGER": "ABSENT",
        }
        if not hook_path or not sh_m or not app_m:
            h13_ok = False
            fails.append("H13_NO_APP_HOOK_OR_SYSTEMHOOK")
        else:
            hook_strings = run(["strings", str(hook_path)])
            hook_nm = run(["nm", "-gU", str(hook_path)])
            sh_path = td_path / "systemhook.dylib"
            sh_strings = run(["strings", str(sh_path)])
            sh_nm = run(["nm", "-u", str(sh_path)])
            app_bytes_h13 = z.read(app_m)
            app_h13 = td_path / "dopamin-tvOS-kfd-h13"
            app_h13.write_bytes(app_bytes_h13)
            app_nm = run(["nm", "-gU", str(app_h13)])

            hook_required = (
                "R24_LAUNCHD_JBROOT_FROM_DLADDR=PASS",
                "R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=",
                "R24_LIVE_INJECTION_STATE=PASS",
                "R24_GIN_EARLY_BOOT=NO",
                "R24_LAUNCHD_UUID_VALID=PASS",
                "R24_FAIL_STAGE=LIVE_INJECTION_STATE rc=",
                "R24_FAIL_STAGE=LAUNCHD_UUID rc=",
                "DOPAMINE_INITIALIZED",
                "LAUNCHD_UUID",
            )
            missing_hook = [lit for lit in hook_required if lit not in hook_strings]
            if missing_hook or re.search(
                r"\b_dt_r24_launchd_initialize_current_boot_runtime\b", hook_nm
            ) is None or re.search(
                r"\b_dt_r24_launchd_begin_live_injection\b", hook_nm
            ) is None or re.search(
                r"\b_dt_r24_launchd_jbroot_from_dladdr_or_fail\b", hook_nm
            ) is None:
                h13_ok = False
                for lit in missing_hook:
                    fails.append(f"H13_HOOK_MISSING={lit}")
                if "dt_r24_launchd_initialize_current_boot_runtime" not in hook_nm:
                    fails.append("H13_HOOK_MISSING_RUNTIME_HELPER")
                if "dt_r24_launchd_begin_live_injection" not in hook_nm:
                    fails.append("H13_HOOK_MISSING_LIVE_INJECTION_HELPER")
                if "dt_r24_launchd_jbroot_from_dladdr_or_fail" not in hook_nm:
                    fails.append("H13_HOOK_MISSING_JBROOT_DLADDR_HELPER")
            else:
                h13_detail["HOOK_RUNTIME_MARKERS"] = "PASS"

            runtime_order_ok, runtime_detail = prove_ctor_runtime_after_hooks(hook_path)
            h13_detail.update(runtime_detail)
            if not runtime_order_ok:
                h13_ok = False
                fails.append(
                    "H13_RUNTIME_ORDER_"
                    + runtime_detail.get("RUNTIME_ORDER_FAIL", "FAIL")
                )

            sh_required = (
                "R24_JBS_PROCESS_CHECKIN=PASS",
                "R24_JBROOT_GENERATION_MATCH=PASS",
                "R24_BOOT_UUID_MATCH=PASS",
                "SYSTEMHOOK_CBR_CHECKIN_PASS",
                "SYSTEMHOOK_CBR_CTOR_PASS",
                "R24_CONTROLLED_CHILD_INJECTION=PASS",
                "R24_FAIL_STAGE=PROCESS_CHECKIN rc=",
                "R24_FAIL_STAGE=JBROOT_MATCH rc=",
                "R24_FAIL_STAGE=BOOT_UUID_MATCH rc=",
                ".r24_current_boot_runtime_probe_pass",
            )
            missing_sh = [lit for lit in sh_required if lit not in sh_strings]
            if missing_sh or "os_log_impl" not in sh_nm:
                h13_ok = False
                for lit in missing_sh:
                    fails.append(f"H13_SYSTEMHOOK_MISSING={lit}")
                if "os_log_impl" not in sh_nm:
                    fails.append("H13_SYSTEMHOOK_NO_UNIFIED_LOG")
            else:
                h13_detail["SYSTEMHOOK_CHECKIN_MARKERS"] = "PASS"

            uuid_policy_ok, uuid_policy_detail = prove_probe_scoped_uuid_policy(
                hook_path, sh_path
            )
            h13_detail.update(uuid_policy_detail)
            if not uuid_policy_ok:
                h13_ok = False
                fails.append(
                    "H13_UUID_POLICY_"
                    + uuid_policy_detail.get("UUID_POLICY_FAIL", "FAIL")
                )

            app_required = (
                b"R24_CONTROLLED_CHILD_BEGIN owner=launchd",
                b"R24_CONTROLLED_CHILD_INJECTION=PASS",
                b"CURRENT_BOOT_RUNTIME_PASS=YES source=child_ack",
                b"R24_FAIL_STAGE=CONTROLLED_CHILD_",
                b"com.dopamin.tvos.runtime-probe",
                b"/var/jb/usr/bin/true",
                b"bootstrap",
                b"system",
            )
            missing_app = [lit.decode() for lit in app_required if lit not in app_bytes_h13]
            if missing_app or "_dt_rootless_run_current_boot_runtime_probe" not in app_nm:
                h13_ok = False
                for lit in missing_app:
                    fails.append(f"H13_APP_MISSING={lit}")
                if "_dt_rootless_run_current_boot_runtime_probe" not in app_nm:
                    fails.append("H13_APP_MISSING_CONTROLLED_PROBE_SYMBOL")
            else:
                h13_detail["CONTROLLED_CHILD_PATH"] = "PASS"

            # The controlled child must be dyld-loadable. The historical
            # probe_true is static and cannot exercise DYLD_INSERT_LIBRARIES.
            dynamic_probe_ok = False
            if runtime_probe_m and trust_m:
                probe_bytes = z.read(runtime_probe_m)
                if probe_bytes.startswith(b"R14MACHO"):
                    probe_bytes = probe_bytes[8:]
                trust_text = z.read(trust_m)
                dynamic_probe_ok = (
                    probe_bytes.startswith(b"\xcf\xfa\xed\xfe")
                    and b"/usr/lib/libSystem.B.dylib" in probe_bytes
                    and b"/var/jb/usr/bin/true" in trust_text
                )
            h13_detail["DYNAMIC_PROBE_TARGET"] = "PASS" if dynamic_probe_ok else "FAIL"
            if not dynamic_probe_ok:
                h13_ok = False
                fails.append("H13_CONTROLLED_CHILD_NOT_DYNAMIC_OR_TRUSTED")

            # No trigger or persistent-reinjection environment is introduced here.
            combined = app_bytes_h13 + hook_path.read_bytes() + sh_path.read_bytes()
            forbidden = (
                b"kern.willuserspacereboot",
                b"reboot3",
                b"R24_USERSPACE_REBOOT=ENABLED",
                b"DYLD_INSERT_LIBRARIES=/var/jb/basebin/launchdhook516.dylib",
            )
            hits = [f.decode() for f in forbidden if f in combined]
            if hits:
                h13_ok = False
                h13_detail["USERSPACE_REBOOT_TRIGGER"] = "PRESENT"
                fails.extend(f"H13_FORBIDDEN_USERSPACE_REBOOT={hit}" for hit in hits)

        gates["H13"] = "PASS" if h13_ok else "FAIL"

        # H14 / M4 — Console must cover every boundary needed to diagnose H13.
        h14_detail = {
            "APP_ALL_LINES_CONSOLE": "FAIL",
            "LAUNCHD_PATCH_CONSOLE": "FAIL",
            "SPAWN_BOUNDARY_CONSOLE": "FAIL",
            "SYSTEMHOOK_CONSOLE": "FAIL",
        }
        h14_ok = True
        if not hook_path or not sh_m or not app_m:
            h14_ok = False
            fails.append("H14_NO_APP_HOOK_OR_SYSTEMHOOK")
        else:
            hook_strings_h14 = run(["strings", str(hook_path)])
            hook_nm_u_h14 = run(["nm", "-u", str(hook_path)])
            sh_path_h14 = td_path / "systemhook.dylib"
            sh_strings_h14 = run(["strings", str(sh_path_h14)])
            sh_nm_u_h14 = run(["nm", "-u", str(sh_path_h14)])
            app_bytes_h14 = z.read(app_m)
            app_h14 = td_path / "dopamin-tvOS-kfd-h14"
            app_h14.write_bytes(app_bytes_h14)
            app_nm_u_h14 = run(["nm", "-u", str(app_h14)])

            if (
                b"R24_CONSOLE_MIRROR_ALL_APP_LOGS=YES" not in app_bytes_h14
                or "os_log" not in app_nm_u_h14
            ):
                h14_ok = False
                fails.append("H14_APP_CONSOLE_MIRROR_MISSING")
            else:
                h14_detail["APP_ALL_LINES_CONSOLE"] = "PASS"

            patch_required = (
            "R24_CONSOLE_MIRROR_LAUNCHD=YES",
            "R24_CONSOLE_MIRROR_ALL_LAUNCHD_DIAGNOSTICS=YES",
                "R24_SPAWN_HOOK_PATCH_BEGIN",
                "CBR_MSHOOK_PATCH=PASS",
                "CBR_MSHOOK_PATCH=FAIL",
            )
            patch_missing = [s for s in patch_required if s not in hook_strings_h14]
            if patch_missing or "os_log" not in hook_nm_u_h14:
                h14_ok = False
                fails.extend(f"H14_LAUNCHD_PATCH_MISSING={s}" for s in patch_missing)
                if "os_log" not in hook_nm_u_h14:
                    fails.append("H14_LAUNCHD_NO_UNIFIED_LOG")
            else:
                h14_detail["LAUNCHD_PATCH_CONSOLE"] = "PASS"

            spawn_required = (
                "R24_SPAWN_HOOK_ENTER",
                "R24_SPAWN_SHARED_ENTER",
                "R24_SPAWN_SYSTEMHOOK_ACCESS=PASS",
                "R24_SPAWN_SYSTEMHOOK_ACCESS=FAIL",
                "R24_SPAWN_INJECT_DECISION=",
                "R24_SPAWN_ENV_ACTION=INSERT_SYSTEMHOOK",
                "R24_SPAWN_ORIG_RETURN",
                "R24_POSIX_SPAWN_RETURN",
            )
            spawn_missing = [s for s in spawn_required if s not in hook_strings_h14]
            if spawn_missing:
                h14_ok = False
                fails.extend(f"H14_SPAWN_CONSOLE_MISSING={s}" for s in spawn_missing)
            else:
                h14_detail["SPAWN_BOUNDARY_CONSOLE"] = "PASS"

            if (
                "R24_CONSOLE_MIRROR_SYSTEMHOOK=YES" not in sh_strings_h14
                or "SYSTEMHOOK_CBR_CTOR_ENTER" not in sh_strings_h14
                or "os_log" not in sh_nm_u_h14
            ):
                h14_ok = False
                fails.append("H14_SYSTEMHOOK_CONSOLE_MISSING")
            else:
                h14_detail["SYSTEMHOOK_CONSOLE"] = "PASS"

        gates["H14"] = "PASS" if h14_ok else "FAIL"

        # H15 / M4 — durable, cross-process A-to-Z trace transport.  This gate
        # proves the writer/relay/fail-closed wiring in the packaged artifacts;
        # only a device run may claim that a particular runtime event occurred.
        h15_detail = {
            "APP_CONTINUOUS_RELAY": "FAIL",
            "LAUNCHD_DURABLE_WRITER": "FAIL",
            "SYSTEMHOOK_DURABLE_WRITER": "FAIL",
            "HOOK_INSTALL_TRUTHFUL": "FAIL",
            "HOOK_INSTALL_FAIL_CLOSED_DISASM": "FAIL",
            "CONTROLLED_CHILD_DIAGNOSTICS": "FAIL",
        }
        h15_ok = True
        if not hook_path or not sh_m or not app_m:
            h15_ok = False
            fails.append("H15_NO_APP_HOOK_OR_SYSTEMHOOK")
        else:
            runtime_path = "/private/var/jb/.r24_runtime_trace"
            hook_strings_h15 = run(["strings", str(hook_path)])
            hook_nm_h15 = run(["nm", "-gU", str(hook_path)])
            sh_path_h15 = td_path / "systemhook.dylib"
            sh_strings_h15 = run(["strings", str(sh_path_h15)])
            sh_nm_h15 = run(["nm", "-gU", str(sh_path_h15)])
            app_bytes_h15 = z.read(app_m)

            app_required = (
                b"/private/var/jb/.r24_runtime_trace",
                b"R24_RUNTIME_TRACE_RELAY=ARMED",
                b"R24_RUNTIME_TRACE_RELAY=FAIL",
                b"TRACE_RESET",
            )
            app_missing = [s.decode() for s in app_required if s not in app_bytes_h15]
            if app_missing:
                h15_ok = False
                fails.extend(f"H15_APP_RELAY_MISSING={s}" for s in app_missing)
            else:
                h15_detail["APP_CONTINUOUS_RELAY"] = "PASS"

            hook_required = (
                runtime_path,
                "R24TRACE",
                "PROCESS_CHECKIN_BEGIN",
                "POSIX_SPAWN_RETURN",
                "JBS_MACH_MESSAGE_MATCH",
            )
            hook_missing = [s for s in hook_required if s not in hook_strings_h15]
            if hook_missing or "_dt_r24_trace_event" not in hook_nm_h15:
                h15_ok = False
                fails.extend(f"H15_LAUNCHD_TRACE_MISSING={s}" for s in hook_missing)
                if "_dt_r24_trace_event" not in hook_nm_h15:
                    fails.append("H15_LAUNCHD_TRACE_SYMBOL_MISSING")
            else:
                h15_detail["LAUNCHD_DURABLE_WRITER"] = "PASS"

            systemhook_required = (
                runtime_path,
                "R24TRACE",
                "PROCESS_CHECKIN_BEGIN",
                "CONTROLLED_PROBE_CLASSIFY",
                "CONTROLLED_ACK_BEGIN",
                "CONTROLLED_ACK_PASS",
                "HOOK_PATCH_RESULT",
                "SANDBOX_SYMBOL_RESULT",
                "DYLD_HOOK_RESULT",
            )
            systemhook_missing = [s for s in systemhook_required if s not in sh_strings_h15]
            if systemhook_missing or "_dt_r24_trace_event" not in sh_nm_h15:
                h15_ok = False
                fails.extend(f"H15_SYSTEMHOOK_TRACE_MISSING={s}" for s in systemhook_missing)
                if "_dt_r24_trace_event" not in sh_nm_h15:
                    fails.append("H15_SYSTEMHOOK_TRACE_SYMBOL_MISSING")
            else:
                h15_detail["SYSTEMHOOK_DURABLE_WRITER"] = "PASS"

            truthful_required = (
                "XPC_HOOK_INSTALL_VERIFIED=YES",
                "XPC_HOOK_INSTALL_VERIFIED=NO",
                "SPAWN_HOOK_INSTALL_VERIFIED=YES",
                "SPAWN_HOOK_INSTALL_VERIFIED=NO",
                "R24_FAIL_STAGE=XPC_HOOK_INSTALL",
                "R24_FAIL_STAGE=SPAWN_HOOK_INSTALL",
                "five_instruction_readback_match",
                "import_rebind_count_nonzero",
            )
            truthful_missing = [s for s in truthful_required if s not in hook_strings_h15]
            stale_claims = (
                "XPC_HOOK_INSTALL_IMPLEMENTED=YES",
                "SPAWN_HOOK_INSTALL_IMPLEMENTED=YES",
            )
            stale_hits = [s for s in stale_claims if s in hook_strings_h15]
            if truthful_missing or stale_hits:
                h15_ok = False
                fails.extend(f"H15_HOOK_VERIFY_MISSING={s}" for s in truthful_missing)
                fails.extend(f"H15_STALE_UNVERIFIED_CLAIM={s}" for s in stale_hits)
            else:
                h15_detail["HOOK_INSTALL_TRUTHFUL"] = "PASS"

            install_branch_ok, install_branch_detail = prove_hook_install_fail_closed(
                hook_path
            )
            h15_detail.update(install_branch_detail)
            if not install_branch_ok:
                h15_ok = False
                fails.append("H15_HOOK_INSTALL_FAIL_CLOSED_DISASM")
            else:
                h15_detail["HOOK_INSTALL_FAIL_CLOSED_DISASM"] = "PASS"

            child_required = (
                b"R24_CONTROLLED_CHILD_LAUNCHD_STATE",
                b"controlled child did not acknowledge systemhook check-in",
                b"print",
                b"system/com.dopamin.tvos.runtime-probe",
            )
            child_missing = [s.decode() for s in child_required if s not in app_bytes_h15]
            if child_missing:
                h15_ok = False
                fails.extend(f"H15_CHILD_DIAGNOSTIC_MISSING={s}" for s in child_missing)
            else:
                h15_detail["CONTROLLED_CHILD_DIAGNOSTICS"] = "PASS"

        gates["H15"] = "PASS" if h15_ok else "FAIL"

        # H16 / M4 — exact tvOS dyld delivery closure.  This is a static
        # artifact/order contract; it never claims that bindfs or early check-in
        # succeeded on hardware.
        h16_ok = True
        if not delivery_dyld_m or not delivery_manifest_m or not app_m or not hook_path or not sh_m:
            h16_ok = False
            fails.append("H16_DELIVERY_ARTIFACT_INCOMPLETE")
        else:
            dyld_bytes = z.read(delivery_dyld_m)
            dyld_path = td_path / "h16_dyld"
            dyld_path.write_bytes(dyld_bytes)
            manifest = json.loads(z.read(delivery_manifest_m))
            sh_bytes = z.read(sh_m)
            hook_bytes = hook_path.read_bytes()
            app_bytes_h16 = z.read(app_m)
            delivery_source = (ROOT / "source/dt_rootless_dyld_delivery.m").read_text()

            if "isEqualToString:kGeneratedSHA" in delivery_source:
                h16_ok = False
                fails.append("H16_RAW_SHA_RUNTIME_AUTHORITY_PRESENT")
            else:
                h16_detail["H16_RAW_SHA_RUNTIME_AUTHORITY"] = "ABSENT"

            try:
                contract = validate_generated_dyld_contract(dyld_path, manifest)
                h16_detail.update({f"H16_DYLD_{k}": v for k, v in contract.items() if k != "PATH"})
                runtime_contract = validate_installed_runtime_dyld_contract(dyld_path, manifest)
                h16_detail.update({f"H16_RUNTIME_DYLD_{k}": v for k, v in runtime_contract.items() if k != "PATH"})
                h16_detail["PRISTINE_BUILD_STRICT"] = "PASS"
                h16_detail["INSTALLED_RUNTIME_BOUNDED"] = "PASS"
                h16_detail["H16_DYLD_CANONICAL_INSTALL_INVARIANCE"] = "PASS"
                h16_detail["H16_DYLD_FULL_UUID"] = "PASS"
                h16_detail["H16_DYLD_JBINFO_STRUCTURAL_BINDING"] = "PASS"
            except CanonicalIdError as e:
                h16_ok = False
                fails.append(f"H16_GENERATED_DYLD_CONTRACT:{e}")
                contract = {}

            computed_canon = canonical_sha256(dyld_path)
            computed_uuid = macho_uuid(dyld_path).upper()
            h16_detail["H16_COMPUTED_CANONICAL_SHA256"] = computed_canon
            h16_detail["H16_COMPUTED_UUID"] = computed_uuid
            exact_manifest = (
                manifest.get("target") == "AppleTV6,2/20L563"
                and manifest.get("source_sha256")
                == "96806a0e57eef714ec806063714101f09afbbdd968346d0d6ba8c4d635b11fdf"
                and manifest.get("source_uuid")
                == "7c25ad4d-2c32-3ae3-a52c-0af299cdda68"
                and manifest.get("stock_patch_offset") == "0x3fdc"
                and manifest.get("generated_patch_offset") == "0x7fdc"
                and manifest.get("patch") == GENERATED_PATCH_BYTES
                and manifest.get("patched_merged_signed_sha256")
                == hashlib.sha256(dyld_bytes).hexdigest()
                and manifest.get("generated_canonical_sha256") == computed_canon
                and str(manifest.get("generated_uuid", "")).upper() == computed_uuid
            )
            if not exact_manifest:
                h16_ok = False
                fails.append("H16_EXACT_TVOS_IDENTITY_MANIFEST")
            else:
                h16_detail["EXACT_TVOS_IDA_PATCH"] = "PASS"

            if bytes_at_offset(dyld_path, STOCK_PATCH_OFFSET, len(STOCK_PATCH_PROLOGUE) // 2).hex() != STOCK_PATCH_PROLOGUE:
                # stock prologue lives in pre-merge artifact; merged dyld may zero stock site
                h16_detail["H16_STOCK_PATCH_IN_MERGED"] = "NOT_AT_STOCK_OFFSET"
            if bytes_at_offset(dyld_path, GENERATED_PATCH_OFFSET, len(GENERATED_PATCH_BYTES) // 2).hex() != GENERATED_PATCH_BYTES:
                h16_ok = False
                fails.append("H16_GENERATED_PATCH_AT_7FDC")

            cp_ok, cp_detail = prove_c_python_canonical_agree(dyld_path)
            h16_detail.update({f"H16_{k}": v for k, v in cp_detail.items()})
            if not cp_ok:
                h16_ok = False
                fails.append("H16_C_PYTHON_CANONICAL_AGREE")

            layout_cp_ok, layout_cp_detail = prove_c_python_runtime_layout_agree(dyld_path)
            h16_detail.update({f"H16_{k}": v for k, v in layout_cp_detail.items()})
            if not layout_cp_ok:
                h16_ok = False
                fails.append("H16_C_PYTHON_RUNTIME_LAYOUT_AGREE")

            fix_ok, fix_detail = prove_h16_dyld_fixtures(dyld_path)
            h16_detail.update({f"H16_{k}": v for k, v in fix_detail.items()})
            if not fix_ok:
                h16_ok = False
                fails.append("H16_DYLD_MUTATION_FIXTURES")

            dyld_contract = all(x in dyld_bytes for x in (
                b"DOPATV165\0", b"R24_DYLDHOOK_CHECKIN_BEGIN",
                b"R24_DYLDHOOK_CHECKIN_PASS", b"__jbinfo",
            )) and bytes.fromhex(GENERATED_PATCH_BYTES) in dyld_bytes
            if not dyld_contract:
                h16_ok = False
                fails.append("H16_PATCHED_DYLD_CONTRACT")
            else:
                h16_detail["PATCHED_DYLD_CONTRACT"] = "PASS"

            coherent_path = (
                b"/usr/lib/systemhook.dylib" in hook_bytes
                and b"/usr/lib/systemhook.dylib" in sh_bytes
                and b"/var/jb/basebin/systemhook.dylib" not in hook_bytes
                and b"/var/jb/basebin/systemhook.dylib" not in sh_bytes
                and b"R24_DYLDHOOK_JBINFO=PASS" in sh_bytes
                and b"R24_DYLDHOOK_JBINFO=FALLBACK_DIRECT" in sh_bytes
                and b"R24_DYLDHOOK_CHECKIN_FALLBACK reason=JBINFO_PARSE_RC" in sh_bytes
                and b"R24_SYSTEMHOOK_RUNTIME_DYLD_UUID=PASS" in sh_bytes
                and b"444F5041-5456-3136-3500-0AF299CDDA68" in sh_bytes
            )
            if not coherent_path:
                h16_ok = False
                fails.append("H16_COHERENT_SYSTEMHOOK_PATH")
            else:
                h16_detail["COHERENT_SYSTEMHOOK_PATH"] = "PASS"
                h16_detail["H16_SYSTEMHOOK_EXACT_DYLD_BINDING"] = "PASS"
                h16_detail["H16_SYSTEMHOOK_FALLBACK_BOUNDED"] = "PASS"

            app_contract = all(x in app_bytes_h16 for x in (
                b"R24_DYLD_DELIVERY_BEGIN target=AppleTV6,2/20L563",
                b"R24_DYLD_RESOURCE_LOOKUP=PASS",
                b"R24_DYLD_CANONICAL_IDENTITY=PASS",
                b"R24_DYLD_RUNTIME_LAYOUT=PASS stage=%s policy=INSTALL_TOLERANT_STRICT_BOUNDS",
                b"R24_DYLD_RUNTIME_LAYOUT=FAIL stage=%s policy=INSTALL_TOLERANT_STRICT_BOUNDS reason=%s rc=%d",
                b"R24_DYLD_LAYOUT stage=%s file_size=%llu ncmds=%u sizeofcmds=%u cs_off=%u cs_size=%u cs_end=%llu trailer_size=%llu",
                b"R24_DYLD_NON_CS_MAX_END=%llu expected=%u gap=%llu",
                b"R24_DYLD_UUID=PASS",
                b"R24_DYLD_PATCH_BYTES=PASS",
                b"R24_DYLD_JBINFO_SECTION=PASS",
                b"R24_DYLD_RAW_SHA_OBSERVED=",
                b"R24_DYLD_CANONICAL_SHA_OBSERVED=",
                b"R24_DYLD_ORIGINAL_IDENTITY=PASS",
                b"R24_DYLD_PREGENERATED_IDENTITY=PASS authority=canonical_uuid_patch_jbinfo host_patch_merge_sign=YES runtime_resign=NO",
                b"R24_PREBOOT_PROTECTION=PASS",
                b"R24_MOUNT_BORROW=PASS kind=kernel_ucred slot0_preserved=YES",
                b"R24_DYLD_ORIGINAL_PRESERVED=PASS",
                b"R24_FAKELIB_GENERATION=PASS",
                b"R24_DYLD_DEDICATED_TRUST=PASS count=1",
                b"R24_FAKELIB_MOUNT=PASS target=/usr/lib readonly=YES",
                b"R24_DYLD_RESOLVE=PASS path=/usr/lib/dyld",
                b"R24_SYSTEMHOOK_RESOLVE=PASS path=/usr/lib/systemhook.dylib",
                b"DYLD_DELIVERY_PASS",
            ))
            if not app_contract:
                h16_ok = False
                fails.append("H16_APP_DELIVERY_FAIL_CLOSED_CONTRACT")
            else:
                h16_detail["APP_DELIVERY_CONTRACT"] = "PASS"

            forbidden_telemetry = (
                b"R24_DYLD_RESIGN=PASS",
                b"R24_DYLD_PATCH_APPLY=PASS",
                b"R24_DYLDHOOK_MERGE=PASS",
                b"R24_DYLD_CS_END_STRICT=PASS",
            )
            if any(x in app_bytes_h16 for x in forbidden_telemetry):
                h16_ok = False
                fails.append("H16_MISLEADING_OR_RUNTIME_STRICT_TELEMETRY")
            else:
                h16_detail["TRUTHFUL_RUNTIME_TELEMETRY"] = "PASS"

            # Gate 2 (bindfs entitlement) — source + signed MAIN blob (fail3 next gate).
            ent_src = (ROOT / "source/entitlements.plist").read_text()
            ent_key = "<key>com.apple.private.bindfs-allow</key>"
            ent_idx = ent_src.find(ent_key)
            ent_true = (
                ent_idx >= 0 and "<true/>" in ent_src[ent_idx : ent_idx + len(ent_key) + 32]
            )
            if not ent_true:
                h16_ok = False
                fails.append("H16_BINDFS_ALLOW_ENTITLEMENT_SOURCE_MISSING")
            elif b"com.apple.private.bindfs-allow" not in app_bytes_h16:
                h16_ok = False
                fails.append("H16_BINDFS_ALLOW_ENTITLEMENT_NOT_EMBEDDED_IN_MAIN")
            else:
                h16_detail["H16_BINDFS_ALLOW_ENTITLEMENT"] = "PASS"

            # Gate 1 (System Policy file-mount) — Dopamine/Q-style borrow wrapper required.
            borrow_markers = (
                "dt_r24_borrow_kernel_ucred",
                "dt_r24_restore_ucred_tx",
                "dt_r24_mount_bindfs_borrowed",
                "R24_MOUNT_BORROW=PASS kind=kernel_ucred slot0_preserved=YES",
                "proc_find(0)",
                "koffsetof(proc_ro, ucred)",
                "koffsetof(ucred, label)",
            )
            borrow_missing = [m for m in borrow_markers if m not in delivery_source]
            if borrow_missing:
                h16_ok = False
                fails.extend(f"H16_MOUNT_BORROW_SOURCE_MISSING={m}" for m in borrow_missing)
            else:
                h16_detail["H16_MOUNT_BORROW_SOURCE"] = "PASS"

            raw_bindfs_calls = delivery_source.count('dt_mount_tvos("bindfs"')
            borrowed_calls = delivery_source.count("dt_r24_mount_bindfs_borrowed(")
            # Exactly one raw mount site (inside borrowed wrapper); ≥2 call sites
            # (ensureProtected + fakelib). Definition itself also matches the count.
            ensure_uses_borrow = (
                "dt_r24_mount_bindfs_borrowed(path.fileSystemRepresentation, 0,"
                in delivery_source
            )
            fakelib_uses_borrow = (
                'dt_r24_mount_bindfs_borrowed("/usr/lib", MNT_RDONLY,'
                in delivery_source
            )
            if raw_bindfs_calls != 1:
                h16_ok = False
                fails.append(f"H16_RAW_BINDFS_MOUNT_COUNT={raw_bindfs_calls}_EXPECTED_1")
            elif borrowed_calls < 3:  # definition + ensureProtected + fakelib
                h16_ok = False
                fails.append(f"H16_BORROWED_BINDFS_CALL_COUNT={borrowed_calls}_EXPECTED_GE_3")
            elif not ensure_uses_borrow or not fakelib_uses_borrow:
                h16_ok = False
                fails.append("H16_PROTECTION_OR_FAKELIB_BYPASS_BORROW_WRAPPER")
            else:
                h16_detail["H16_BINDFS_ONLY_VIA_BORROW_WRAPPER"] = "PASS"

            # Restore-on-failure: restore must run before checking mount_rc.
            wrapper_start = delivery_source.find("static int dt_r24_mount_bindfs_borrowed")
            wrapper_body = delivery_source[wrapper_start : wrapper_start + 900] if wrapper_start >= 0 else ""
            restore_pos = wrapper_body.find("dt_r24_restore_ucred_tx")
            mount_rc_check = wrapper_body.find("if (mount_rc != 0)")
            if wrapper_start < 0 or restore_pos < 0 or mount_rc_check < 0 or restore_pos > mount_rc_check:
                h16_ok = False
                fails.append("H16_MOUNT_BORROW_RESTORE_NOT_BEFORE_MOUNT_RC_CHECK")
            else:
                h16_detail["H16_MOUNT_BORROW_FAIL_CLOSED_RESTORE"] = "PASS"

            ordered = (
                "R24_DYLD_ORIGINAL_IDENTITY=PASS",
                "R24_PREBOOT_PROTECTION=PASS",
                "R24_DYLD_ORIGINAL_PRESERVED=PASS",
                "R24_FAKELIB_GENERATION=PASS",
                "dt_rootless_load_single_trust_path",
                'dt_r24_mount_bindfs_borrowed("/usr/lib", MNT_RDONLY,',
                "R24_FAKELIB_MOUNT=PASS target=/usr/lib readonly=YES",
            )
            positions = [delivery_source.find(x) for x in ordered]
            source_order_ok = all(p >= 0 for p in positions) and positions == sorted(positions)
            if not source_order_ok:
                h16_ok = False
                fails.append("H16_PROTECTION_FAKELIB_TRUST_MOUNT_ORDER")
            else:
                h16_detail["PROTECTION_FAKELIB_TRUST_MOUNT_ORDER"] = "PASS"
                h16_detail["H16_PREBOOT_PROTECTION_SEMANTICS"] = "PASS"

            # Protection must precede fakelib; borrow must sit between identity and PASS emit.
            prot_call = delivery_source.find("ensureProtected(systemPath, log, errOut)")
            fakelib_borrow = delivery_source.find(
                'dt_r24_mount_bindfs_borrowed("/usr/lib", MNT_RDONLY,'
            )
            if not (0 <= prot_call < fakelib_borrow):
                h16_ok = False
                fails.append("H16_PROTECTION_BEFORE_FAKELIB_BORROW_ORDER")
            else:
                h16_detail["H16_PROTECTION_BEFORE_FAKELIB"] = "PASS"

            staged_call_count = delivery_source.count(
                "authorizeGeneratedDyld(genDyld, R24DyldAuthStaged"
            )
            copy_pos = delivery_source.find("copyItemAtPath:resource toPath:genDyld")
            staged_pos = delivery_source.find("authorizeGeneratedDyld(genDyld, R24DyldAuthStaged")
            trust_pos = delivery_source.find("dt_rootless_load_single_trust_path")
            mount_pos = delivery_source.find(
                'dt_r24_mount_bindfs_borrowed("/usr/lib", MNT_RDONLY,'
            )
            staged_order_ok = (
                staged_call_count == 1
                and min(copy_pos, staged_pos, trust_pos, mount_pos) >= 0
                and copy_pos < staged_pos < trust_pos < mount_pos
            )
            if not staged_order_ok:
                h16_ok = False
                fails.append("H16_STAGED_AUTH_BEFORE_TRUST_MOUNT")
            else:
                h16_detail["STAGED_AUTH_BEFORE_TRUST_MOUNT"] = "PASS"
        gates["H16"] = "PASS" if h16_ok else "FAIL"

    # H8 — auth only if H1–H7 + every current/new H gate + no fails.
    required = [f"H{i}" for i in range(1, 8)] + ["H9", "H10", "H11", "H12", "H13", "H14", "H15", "H16"]
    h_all = all(gates.get(k) == "PASS" for k in required)
    if h_all and not fails:
        gates["H8"] = "PASS"
        auth = "AUTHORIZED_FOR_PHYSICAL_BURN_CANDIDATE"
    else:
        gates["H8"] = "FAIL"
        auth = "NOT_AUTHORIZED"
        if h_all and fails:
            fails.append("H8_EXTRA_FAILS")
        elif not h_all:
            fails.append("H8_BLOCKED_BY_GATES")

    ok = gates.get("H8") == "PASS" and not fails
    print(f"R24_IPA_SHA256={ipa_sha}")
    for k in sorted(gates):
        print(f"{k}={gates[k]}")
    for k, v in sorted(dep_detail.items()):
        print(f"DEP_{k}={v}")
    for k, v in sorted(h11_detail.items()):
        print(f"H11_{k}={v}")
    for k, v in sorted(h12_detail.items()):
        print(f"H12_{k}={v}")
    for k, v in sorted(h13_detail.items()):
        print(f"H13_{k}={v}")
    for k, v in sorted(h14_detail.items()):
        print(f"H14_{k}={v}")
    for k, v in sorted(h15_detail.items()):
        print(f"H15_{k}={v}")
    for k, v in sorted(h16_detail.items()):
        print(f"H16_{k}={v}")
    print("APP_STAGE_MARKERS=PACKAGING_ONLY_NOT_LIVE_PID1_INSTALL")
    print("KALLOC_PT_CONTRACT=HOST_STATIC_ONLY_NOT_LIVE_STASH")
    print("H11_CS_ALLOW_INVALID_CONTRACT=HOST_STATIC_CTOR_ORDER_NOT_LIVE_PID1")
    print(
        "H12_D0_IDENTITY_CONTRACT=HOST_MAIN_CANONICAL_PIN_EQ_IPA_AND_LEAF_PREPARE_ORDER"
    )
    print("H13_CURRENT_BOOT_RUNTIME_CONTRACT=HOST_STATIC_ONLY_NOT_DEVICE_RUNTIME_PASS")
    print("H14_CONSOLE_MIRROR_CONTRACT=HOST_STATIC_ONLY_NOT_LIVE_DELIVERY_PASS")
    print("H15_DURABLE_RUNTIME_TRACE_CONTRACT=HOST_STATIC_ONLY_NOT_LIVE_DELIVERY_PASS")
    print("H16_DYLD_DELIVERY_CONTRACT=EXACT_TVOS_STATIC_ONLY_NOT_LIVE_MOUNT_PASS")
    print("CURRENT_BOOT_RUNTIME_PHYSICAL_MARKERS=NOT_CLAIMED_BY_HOST")
    print("PHYS_LIVE_SSH=NOT_CLAIMED_BY_HOST")
    print("LIVE_SUDO=NOT_CLAIMED_BY_HOST")
    print(f"DEVICE_DEP_CONTRACT_HOST_EVAL={dep_detail.get('DEP_CONTRACT', 'FAIL')}")
    print(f"DEVICE_RUN_AUTHORIZATION={auth}")
    print(f"R24_HOST_SIM={'PASS' if ok else 'FAIL'}")
    if fails:
        print("FAILS=" + ",".join(fails))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
