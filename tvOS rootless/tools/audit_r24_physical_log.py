#!/usr/bin/env python3
"""Deep audit of ROOTLESS R24 physical syslog dumps.

No code changes — evidence extraction only.
Focus: dopamin-tvOS-kfd + kernel denials + R24 lifecycle markers.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROC_FOCUS = re.compile(
    r"\b(dopamin-tvOS-kfd|kernel|Sandbox|amfid|kernelmanagerd|trustd)\b",
    re.I,
)
R24 = re.compile(r"\bR24_[A-Z0-9_.=+-]+")
STAGE_PASS = re.compile(r"\b(STAGE\s+)?([A-Z0-9_]+)=(PASS|FAIL|YES|NO)\b")
STAGE_LINE = re.compile(r"\bSTAGE\s+(.+)$")
DENY = re.compile(r"deny\((\d+)\)\s+(\S+)")
SYS_POLICY = re.compile(r"System Policy:\s*(.+)$")
ERRNO = re.compile(r"errno[=:]?\s*(-?\d+)", re.I)
FINISHED = re.compile(r"run finished:?\s*(.+)$", re.I)
ERROR_MARK = re.compile(r"(R24_.*ERROR|GATE_FAIL|DELIVERY_ERROR|mount borrow|bindfs)", re.I)
INTERESTING_KW = re.compile(
    r"(bindfs|file-mount|file-write|file-read|mach-lookup|process-exec|"
    r"sandbox|borrow|ucred|protection|fakelib|preboot|dyld|trust|"
    r"systemhook|launchd|jbroot|ROOTLESS|Wall2|PHYS|KFD|"
    r"deny\(|errno=|EPERM|EACCES|ENOENT)",
    re.I,
)

# Ordered lifecycle markers we care about for progress (first occurrence wins).
LIFECYCLE = [
    "BUILD102711_PHYSRW_LOCAL_HANDOFF_PASS",
    "BUILD102721_PREBOOT_RW_CONFIRMED",
    "build47 MNT_UPDATE",
    "ROOTLESS_R24_D0_IDENTITY=PASS",
    "R24_DYLD_DELIVERY_BEGIN",
    "R24_DYLD_CANONICAL_IDENTITY=PASS",
    "R24_DYLD_RUNTIME_LAYOUT=PASS",
    "R24_DYLD_PREGENERATED_IDENTITY=PASS",
    "R24_DYLD_ORIGINAL_IDENTITY=PASS",
    "R24_DYLD_STOCK_PATCH_PROLOGUE=PASS",
    "R24_MOUNT_BORROW=PASS",
    "R24_PREBOOT_PROTECTION=PASS",
    "R24_DYLD_ORIGINAL_PRESERVED=PASS",
    "R24_FAKELIB_GENERATION=PASS",
    "R24_DYLD_DEDICATED_TRUST=PASS",
    "R24_FAKELIB_MOUNT=PASS",
    "R24_DYLD_RESOLVE=PASS",
    "R24_SYSTEMHOOK_RESOLVE=PASS",
    "R24_DYLD_DELIVERY=PASS",
    "DYLD_DELIVERY_PASS",
]


def parse_line(raw: str) -> dict | None:
    # typical: level\tts\tprocess\tmessage  OR syslog variants
    parts = raw.rstrip("\n").split("\t")
    if len(parts) >= 4:
        level, ts, proc, msg = parts[0], parts[1], parts[2], "\t".join(parts[3:])
    elif len(parts) == 3:
        level, ts, msg = parts[0], parts[1], parts[2]
        proc = ""
    else:
        level, ts, proc, msg = "", "", "", raw.rstrip("\n")
    return {"raw": raw.rstrip("\n"), "level": level, "ts": ts, "proc": proc, "msg": msg}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    path = Path(args.log)
    lines = [parse_line(x) for x in path.read_text(errors="replace").splitlines()]
    lines = [x for x in lines if x]

    focus = []
    for i, L in enumerate(lines, 1):
        blob = f"{L['proc']}\t{L['msg']}"
        if "dopamin-tvOS-kfd" in L["proc"] or "dopamin-tvOS-kfd" in L["msg"]:
            focus.append((i, L))
        elif L["proc"] in ("kernel",) and INTERESTING_KW.search(L["msg"]):
            focus.append((i, L))
        elif SYS_POLICY.search(L["msg"]) or DENY.search(L["msg"]):
            if "dopamin" in L["msg"] or "bindfs" in L["msg"] or "file-mount" in L["msg"]:
                focus.append((i, L))

    r24_tokens = Counter()
    r24_first = {}
    r24_last = {}
    pass_fail = Counter()
    denials = []
    policies = []
    finished = []
    errors = []
    errno_hits = Counter()
    borrow_lines = []
    off_looking = []

    for i, L in enumerate(lines, 1):
        msg = L["msg"]
        proc = L["proc"]
        for m in R24.finditer(msg):
            tok = m.group(0)
            r24_tokens[tok] += 1
            r24_first.setdefault(tok, (i, L["ts"], msg[:240]))
            r24_last[tok] = (i, L["ts"], msg[:240])
        for m in STAGE_PASS.finditer(msg):
            key = f"{m.group(2)}={m.group(3)}"
            pass_fail[key] += 1
        for m in DENY.finditer(msg):
            denials.append((i, L["ts"], proc, m.group(0), msg[:300]))
        for m in SYS_POLICY.finditer(msg):
            policies.append((i, L["ts"], proc, m.group(1)[:300]))
        for m in FINISHED.finditer(msg):
            if "dopamin" in proc or "dopamin" in msg or "run finished" in msg.lower():
                finished.append((i, L["ts"], proc, m.group(0), msg[:300]))
        if ERROR_MARK.search(msg) and ("dopamin" in proc or "dopamin" in msg or "kernel" in proc):
            errors.append((i, L["ts"], proc, msg[:320]))
        for m in ERRNO.finditer(msg):
            if "dopamin" in proc or "bindfs" in msg or "protection" in msg or "borrow" in msg:
                errno_hits[m.group(1)] += 1
        if "MOUNT_BORROW" in msg or "mount borrow" in msg.lower():
            borrow_lines.append((i, L["ts"], proc, msg[:320]))

        # Off-looking heuristics for dopamin/kernel only
        if "dopamin-tvOS-kfd" in proc or ("kernel" in proc and "dopamin" in msg):
            low = msg.lower()
            if any(
                x in low
                for x in (
                    "error",
                    "fail",
                    "deny",
                    "errno=",
                    "not ",
                    "mismatch",
                    "missing",
                    "abort",
                    "invalid",
                    "timeout",
                    "unexpected",
                    "skip",
                    "warn",
                )
            ):
                # Filter pure PASS lines and duplicate mirrors
                if "=PASS" in msg and "FAIL" not in msg and "ERROR" not in msg and "deny" not in low:
                    continue
                if msg.startswith("[dopamin-tvOS-kfd]"):
                    continue  # mirrored duplicate
                off_looking.append((i, L["ts"], msg[:320]))

    # Lifecycle progress
    life_hits = []
    for marker in LIFECYCLE:
        hit = None
        for i, L in enumerate(lines, 1):
            if marker in L["msg"] and ("dopamin" in L["proc"] or "dopamin" in L["msg"]):
                hit = (i, L["ts"], L["msg"][:240])
                break
        life_hits.append((marker, hit))

    last_pass = None
    first_fail = None
    for marker, hit in life_hits:
        if hit and ("=PASS" in marker or marker.endswith("PASS") or "CONFIRMED" in marker or "BEGIN" in marker or "MNT_UPDATE" in marker):
            last_pass = (marker, hit)
        if hit is None and first_fail is None and marker.endswith("=PASS"):
            # first missing expected PASS after we started dyld delivery
            pass

    # Find terminal: last R24_* or run finished among focus
    terminal_candidates = []
    for i, L in focus[-80:]:
        if any(k in L["msg"] for k in ("run finished", "ERROR", "FAIL", "GATE", "DELIVERY", "deny")):
            terminal_candidates.append((i, L["ts"], L["msg"][:300]))

    # Unique R24 PASS / FAIL / ERROR tokens
    r24_pass = sorted(t for t in r24_tokens if t.endswith("=PASS") or "=PASS " in t or t.endswith("PASS"))
    r24_fail = sorted(t for t in r24_tokens if "FAIL" in t or "ERROR" in t)

    out_lines = []
    def w(s=""):
        out_lines.append(s)

    w(f"# fail4 audit: {path}")
    w(f"TOTAL_LINES={len(lines)}")
    w(f"FOCUS_LINES={len(focus)}")
    w()
    w("## LIFECYCLE_PROGRESS (first hit)")
    farthest = None
    for marker, hit in life_hits:
        if hit:
            w(f"HIT  {marker}")
            w(f"     line={hit[0]} ts={hit[1]} :: {hit[2]}")
            farthest = marker
        else:
            w(f"MISS {marker}")
    w()
    w(f"FARTHEST_HIT={farthest}")
    w()
    w("## RUN_FINISHED")
    for row in finished:
        w(f"line={row[0]} ts={row[1]} proc={row[2]} :: {row[4]}")
    w()
    w("## SYSTEM_POLICY")
    for row in policies:
        w(f"line={row[0]} ts={row[1]} proc={row[2]} :: {row[3]}")
    w()
    w("## DENY")
    for row in denials:
        if "dopamin" in row[4] or "bindfs" in row[4] or "file-mount" in row[4]:
            w(f"line={row[0]} ts={row[1]} proc={row[2]} {row[3]} :: {row[4]}")
    w()
    w("## ERROR_MARKERS (dopamin/kernel)")
    for row in errors:
        w(f"line={row[0]} ts={row[1]} proc={row[2]} :: {row[3]}")
    w()
    w("## MOUNT_BORROW_LINES")
    for row in borrow_lines:
        w(f"line={row[0]} ts={row[1]} proc={row[2]} :: {row[3]}")
    w()
    w("## R24_TOKEN_COUNTS (top 80)")
    for tok, n in r24_tokens.most_common(80):
        w(f"{n:4d}  {tok}")
    w()
    w("## R24_FAIL_OR_ERROR_TOKENS")
    for tok in r24_fail:
        fr = r24_first[tok]
        w(f"{tok}  first_line={fr[0]} ts={fr[1]} :: {fr[2]}")
    w()
    w("## R24_PASS_TOKENS_FIRST")
    for tok in sorted(t for t in r24_tokens if "=PASS" in t):
        fr = r24_first[tok]
        w(f"{tok}  first_line={fr[0]} ts={fr[1]}")
    w()
    w("## ERRNO_ON_DOPAMIN_RELATED")
    for e, n in errno_hits.most_common():
        w(f"errno={e} count={n}")
    w()
    w("## OFF_LOOKING_DOPAMIN (heuristic, de-duped mirrors)")
    w(f"COUNT={len(off_looking)}")
    for row in off_looking:
        w(f"line={row[0]} ts={row[1]} :: {row[2]}")
    w()
    w("## TERMINAL_WINDOW_LAST_FOCUS_HITS")
    for row in terminal_candidates[-40:]:
        w(f"line={row[0]} ts={row[1]} :: {row[2]}")
    w()
    w("## LAST_40_DOPAMIN_LINES")
    dop = [(i, L) for i, L in focus if "dopamin-tvOS-kfd" in L["proc"]]
    for i, L in dop[-40:]:
        if L["msg"].startswith("[dopamin-tvOS-kfd]"):
            continue
        w(f"line={i} ts={L['ts']} :: {L['msg'][:300]}")

    text = "\n".join(out_lines) + "\n"
    if args.out:
        Path(args.out).write_text(text)
        print(f"WROTE {args.out} bytes={len(text)}")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
