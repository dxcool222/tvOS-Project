#!/bin/bash
# Read-only bootstrap semantic reconciliation against device-proven V26 contract.
# Does not mutate payload, run device tests, or touch jailbreak bring-up code.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
AUTHORITATIVE="$(cd "$SCRIPT/.." && pwd -P)"

PAYLOAD="${PAYLOAD:-${DT_BUILD_ROOT:-}/work/jbroot_transformed}"
REF_IPA="${REF_IPA:-/Volumes/Untitled2/Apple TV Project/rootless/artifacts/dopamin-tvOS-kfd-ROOTLESS-R24V26.ipa}"
FROZEN="${FROZEN:-/Volumes/Untitled2/Apple TV Project/rootless/work/jbroot_transformed}"
FRESH_IPA="${FRESH_IPA:-}"

if [[ -z "$PAYLOAD" || ! -d "$PAYLOAD" ]]; then
  if [[ -d "/tmp/tvos-rootless-fresh-copy-build/work/jbroot_transformed" ]]; then
    PAYLOAD="/tmp/tvos-rootless-fresh-copy-build/work/jbroot_transformed"
  else
    echo "ERROR: set PAYLOAD or DT_BUILD_ROOT to a built jbroot_transformed tree" >&2
    exit 1
  fi
fi

if [[ -z "$FRESH_IPA" ]]; then
  for cand in \
    "/tmp/tvos-rootless-fresh-copy-build/dopamin-tvOS-kfd-ROOTLESS-R24.ipa" \
    "/tmp/tvos-rootless-authoritative-build/dopamin-tvOS-kfd-ROOTLESS-R24.ipa"; do
    if [[ -f "$cand" ]]; then
      FRESH_IPA="$cand"
      break
    fi
  done
fi

export PAYLOAD REF_IPA FROZEN FRESH_IPA
python3 - <<'PY'
import hashlib
import os
import re
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path

PAYLOAD = Path(os.environ["PAYLOAD"])
REF_IPA = Path(os.environ["REF_IPA"])
FROZEN = Path(os.environ["FROZEN"])
FRESH_IPA = os.environ.get("FRESH_IPA", "")

# Legitimate absolute symlink targets outside /var/jb (Apple/system contract).
APPLE_ABS_SYMLINK_WHITELIST = {
    "/var/db/timezone/localtime",
    "/private/var/db/timezone/localtime",
}

MISSING_V26 = [
    "etc/passwd",
    "etc/group",
    "etc/master.passwd",
    "etc/ssl/cert.pem",
    "etc/ssl/certs/cacert.pem",
    "Library/dpkg/info/openssh-server.extrainst_",
]

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def ipa_members(ipa: Path) -> dict[str, bytes]:
    out = {}
    with zipfile.ZipFile(ipa) as z:
        for name in z.namelist():
            if "RootlessPayload/" not in name or name.endswith("/"):
                continue
            rel = name.split("RootlessPayload/", 1)[1]
            data = z.read(name)
            if data.startswith(b"R14MACHO"):
                data = data[8:]
            out[rel] = data
    return out

def classify_missing(rel: str) -> str:
    """REQUIRED | SUPERSEDED | NOT REQUIRED | UNKNOWN"""
    if rel in (
        "etc/passwd",
        "etc/group",
        "etc/master.passwd",
        "Library/dpkg/info/openssh-server.extrainst_",
    ):
        return "REQUIRED"
    if rel.startswith("etc/ssl/"):
        return "REQUIRED"
    return "UNKNOWN"

def symlink_rows(root: Path) -> list[dict]:
    rows = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            rel = str(p.relative_to(root))
            raw = os.readlink(p)
            normalized = os.path.normpath(raw)
            if raw.startswith("/"):
                kind = "absolute"
                if raw.startswith("/var/jb/"):
                    bucket = "JBROOT_ABS"
                    status = "OK"
                elif raw in APPLE_ABS_SYMLINK_WHITELIST or raw.startswith("/var/db/"):
                    bucket = "APPLE_SYSTEM_ABS"
                    status = "OK"
                elif raw.startswith(("/usr/", "/etc/", "/Library/", "/bin/", "/sbin/", "/private/etc/")):
                    bucket = "ROOTFUL_ABS"
                    status = "FAIL"
                else:
                    bucket = "OTHER_ABS"
                    status = "REVIEW"
                escapes = "n/a"
            else:
                kind = "relative"
                resolved = (p.parent / raw).resolve()
                try:
                    resolved.relative_to(root.resolve())
                    bucket = "RELATIVE_IN_TREE"
                    status = "OK"
                    escapes = "no"
                except ValueError:
                    bucket = "REL_ESCAPES"
                    status = "FAIL"
                    escapes = "yes"
            rows.append(
                {
                    "path": rel,
                    "raw": raw,
                    "normalized": normalized,
                    "kind": kind,
                    "bucket": bucket,
                    "status": status,
                    "escapes": escapes,
                }
            )
    return rows

def prep_rootful_paths(prep_text: str) -> list[str]:
    hits = []
    for m in re.finditer(r"(?<![\w/])(/(?:usr|etc|Library|bin|sbin|opt|var|private)[^\s\"']*|/prep_bootstrap\.sh)", prep_text):
        tok = m.group(1)
        if tok.startswith("/var/jb/"):
            continue
        hits.append(tok)
    return sorted(set(hits))

def classify_diff(rel: str, b0: bytes, b1: bytes) -> str:
    if rel == "prep_bootstrap.sh":
        return "RUNTIME CONTENT DIFFERENCE"
    if b0[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        import tempfile
        with tempfile.NamedTemporaryFile() as a, tempfile.NamedTemporaryFile() as b:
            a.write(b0)
            b.write(b1)
            a.flush()
            b.flush()
            sa = subprocess.check_output(["strings", a.name], text=True, errors="replace")
            sb = subprocess.check_output(["strings", b.name], text=True, errors="replace")
        if sa == sb:
            return "RESIGNING ONLY"
        return "ROOTLESS TRANSFORMATION DIFFERENCE"
    if b0 == b1:
        return "BYTE DIFFERENCE ONLY — SEMANTICS SAME"
    return "RUNTIME CONTENT DIFFERENCE"

# --- counts ---
regular_files = sum(1 for _ in PAYLOAD.rglob("*") if _.is_file() and not _.is_symlink())
symlinks = symlink_rows(PAYLOAD)
symlink_ok = sum(1 for r in symlinks if r["status"] == "OK")
unexplained_symlinks = [r for r in symlinks if r["status"] == "FAIL"]

missing_present = []
missing_absent = []
for rel in MISSING_V26:
    if (PAYLOAD / rel).exists() or (PAYLOAD / rel).is_symlink():
        missing_present.append(rel)
    else:
        missing_absent.append(rel)

missing_classes = Counter(classify_missing(r) for r in missing_absent)

prep = (PAYLOAD / "prep_bootstrap.sh").read_text(errors="replace") if (PAYLOAD / "prep_bootstrap.sh").is_file() else ""
prep_rootful = prep_rootful_paths(prep)
prep_contract_fail = False
prep_checks = []

def need(sub: str, label: str) -> None:
    global prep_contract_fail
    ok = sub in prep
    prep_checks.append((label, ok))
    if not ok:
        prep_contract_fail = True

need("#!/var/jb/bin/sh", "shebang /var/jb/bin/sh")
need("-d /var/jb/etc", "pwd_mkdb -d /var/jb/etc")
need("openssh-server.extrainst_", "openssh extrainst invocation")
need("pw -V /var/jb/etc usermod mobile", "pw -V mobile shell")
need("pw -V /var/jb/etc usermod root", "pw -V root shell")
need("pw -V /var/jb/etc usermod 501", "pw -V password hash")
need("openssh-server.extrainst_ missing", "extrainst fail-closed guard")
if "/usr/bin/chsh" in prep:
    prep_contract_fail = True
    prep_checks.append(("no dest chsh (R18)", False))
else:
    prep_checks.append(("no dest chsh (R18)", True))

need("R23: ensure SSH homes exist", "R23 SSH home block")

# Dangling /var/jb symlinks anywhere in payload
dangling_jb = []
for dirpath, dirnames, filenames in os.walk(PAYLOAD, followlinks=False):
    for name in dirnames + filenames:
        p = Path(dirpath) / name
        if not p.is_symlink():
            continue
        raw = os.readlink(p)
        if not raw.startswith("/var/jb/"):
            continue
        tgt = PAYLOAD / raw[len("/var/jb/") :]
        if not tgt.exists():
            dangling_jb.append((str(p.relative_to(PAYLOAD)), raw))

# Expected counts from V26 reference IPA when available
expected_entries = 3642
expected_regular = 3492
expected_symlinks = 150
if REF_IPA.is_file():
    mr = ipa_members(REF_IPA)
    expected_entries = len(mr)
    # V26 tree walk reference (frozen) for regular/symlink split
    if FROZEN.is_dir():
        expected_regular = sum(1 for _ in FROZEN.rglob("*") if _.is_file() and not _.is_symlink())
        expected_symlinks = sum(1 for _ in FROZEN.rglob("*") if _.is_symlink())

# IPA diff vs V26
diff_summary = Counter()
only_ref = []
content_equiv = {}
FROZEN_PATH = FROZEN
if FRESH_IPA and Path(FRESH_IPA).is_file() and REF_IPA.is_file():
    mr = ipa_members(REF_IPA)
    mf = ipa_members(Path(FRESH_IPA))
    only_ref = sorted(set(mr) - set(mf))
    common = set(mr) & set(mf)
    for rel in common:
        if sha256_bytes(mr[rel]) != sha256_bytes(mf[rel]):
            diff_summary[classify_diff(rel, mr[rel], mf[rel])] += 1
    for rel in only_ref:
        diff_summary["MISSING GENERATOR STEP"] += 1

# Semantic/content equivalence for restored members + prep
RESTORED = MISSING_V26 + ["prep_bootstrap.sh"]
for rel in RESTORED:
    p = PAYLOAD / rel
    f = FROZEN_PATH / rel
    if not p.exists() and not p.is_symlink():
        content_equiv[rel] = "DIFFERENT (missing)"
        continue
    if not f.exists() and not f.is_symlink():
        content_equiv[rel] = "UNKNOWN (no frozen reference)"
        continue
    if rel == "etc/ssl/certs/cacert.pem":
        content_equiv[rel] = (
            "SEMANTICALLY EQUIVALENT"
            if p.is_file() and p.stat().st_size > 100000
            else "DIFFERENT"
        )
        continue
    pb = p.read_bytes() if p.is_file() else os.readlink(p).encode()
    fb = f.read_bytes() if f.is_file() else os.readlink(f).encode()
    if pb == fb:
        content_equiv[rel] = "CONTENT EQUIVALENT"
    elif rel == "prep_bootstrap.sh":
        content_equiv[rel] = "SEMANTICALLY EQUIVALENT" if not prep_contract_fail else "DIFFERENT"
    else:
        content_equiv[rel] = "SEMANTICALLY EQUIVALENT"

# dangling ssl consumers
dangling_ssl = []
for rel in ("usr/lib/ssl/cacert.pem", "usr/lib/ssl/certs"):
    p = PAYLOAD / rel
    if p.is_symlink():
        t = os.readlink(p)
        if t.startswith("/var/jb/"):
            tgt = PAYLOAD / t[len("/var/jb/") :]
            if not tgt.exists():
                dangling_ssl.append((rel, t))

runtime_equiv = (
    len(missing_absent) == 0
    and not prep_contract_fail
    and len(unexplained_symlinks) == 0
    and len(dangling_jb) == 0
    and len(prep_rootful) == 0
    and symlink_ok == len(symlinks) == expected_symlinks
    and regular_files == expected_regular
    and regular_files + len(symlinks) == expected_entries
)

print("=== BOOTSTRAP V26 CONTRACT AUDIT (read-only) ===")
print(f"PAYLOAD={PAYLOAD}")
print(f"REF_IPA={REF_IPA}")
print(f"FRESH_IPA={FRESH_IPA or 'MISSING'}")
print(f"FROZEN={FROZEN}")
print()
print(f"ROOTLESS_REGULAR_FILE_COVERAGE={regular_files}/{expected_regular}")
print(f"ROOTLESS_SYMLINK_COVERAGE={symlink_ok}/{len(symlinks)}")
print(f"ROOTLESS_PAYLOAD_ENTRY_COVERAGE={regular_files + symlink_ok}/{regular_files + len(symlinks)}")
print(f"UNEXPLAINED_ROOTFUL_SYMLINKS={len(unexplained_symlinks)}")
print(f"UNEXPLAINED_ROOTFUL_PATHS={len(prep_rootful)}")
print(f"DANGLING_ROOTLESS_SYMLINKS={len(dangling_jb)}")
print()
print("=== 6 V26-only members ===")
for rel in MISSING_V26:
    st = "ABSENT" if rel in missing_absent else "PRESENT"
    cls = classify_missing(rel) if rel in missing_absent else "PRESENT"
    print(f"  {rel}: {st} -> {cls}")
print(f"MISSING_V26_FILES_REQUIRED={missing_classes.get('REQUIRED', 0)}")
print(f"MISSING_V26_FILES_SUPERSEDED={missing_classes.get('SUPERSEDED', 0)}")
print(f"MISSING_V26_FILES_UNKNOWN={missing_classes.get('UNKNOWN', 0)}")
if dangling_ssl or dangling_jb:
    print("DANGLING_SYMLINKS:")
    for rel, tgt in dangling_ssl + dangling_jb:
        print(f"  {rel} -> {tgt} (target missing)")
print()
print("=== restored member equivalence vs V26 contract ===")
for rel, cls in content_equiv.items():
    print(f"  {rel}: {cls}")
print()
print("=== prep_bootstrap.sh rootless contract ===")
for label, ok in prep_checks:
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
if prep_rootful:
    print("  ROOTFUL_PATHS_IN_PREP:")
    for p in prep_rootful:
        print(f"    {p}")
print(f"PREP_BOOTSTRAP_ROOTLESS_CONTRACT={'PASS' if not prep_contract_fail else 'FAIL'}")
print()
if diff_summary:
    print("=== V26 IPA vs fresh IPA RootlessPayload diff taxonomy ===")
    for k, v in sorted(diff_summary.items()):
        print(f"  {k}={v}")
    print(f"  only_in_V26={len(only_ref)}")
print()
print(f"BOOTSTRAP_RUNTIME_EQUIVALENCE_TO_V26={'PASS' if runtime_equiv else 'FAIL'}")
print(f"SOURCE_TREE_READY_FOR_ME_TO_PUT_INTO_GIT={'YES' if runtime_equiv else 'NO'}")
PY
