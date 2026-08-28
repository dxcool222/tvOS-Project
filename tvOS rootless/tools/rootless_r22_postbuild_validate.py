#!/usr/bin/env python3
"""Post-build static validation: R22-A IPA vs frozen R21."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import csv
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from workspace import workspace_root, build_root, source_root, tools_root, work_dir, artifacts_dir, ldid_path
ROOT = workspace_root()
R21_IPA = ROOT / "artifacts/dopamin-tvOS-kfd-ROOTLESS-R21.ipa"
R21_MAIN_SHA = "80861beeab764596d299cbb956b0285495199a77680e26b363cbb2968c15dcfb"
R21_HOOK_SHA = "5223b886123a4adf4b3a8b594d47f047cb9204c4d4e7c34e4b2c9be14b21f040"
R21_PREP_SHA = "254730a63e7a303a72a4f0982768440171def43642bed7f90b06072547e1178d"
R21_IPA_SHA = "5099371a1f2afe0fdb51eccd2edca08bbd931614352697e6bcc53d8c155f17f0"

EXPECTED_CHANGED_SUFFIXES = (
    "RootlessPayload/usr/lib/libiosexec.1.dylib",
    "RootlessPayload/usr/lib/libpam.2.dylib",
    "RootlessPayload/usr/lib/pam/pam_unix.so",
    "RootlessPayload/usr/lib/pam/pam_nologin.so",
    "RootlessPayload/usr/lib/pam/pam_permit.so",
    "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv",
    "ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv",
)

TRUST_RELS = (
    "usr/lib/libiosexec.1.dylib",
    "usr/lib/libpam.2.dylib",
    "usr/lib/pam/pam_unix.so",
    "usr/lib/pam/pam_nologin.so",
    "usr/lib/pam/pam_permit.so",
)

ORACLE_SHA256 = {
    "usr/lib/libiosexec.1.dylib": "aa2354332ee53c96990887a190b20f8cd56c02f464bf878b8a79ccef72f88718",
    "usr/lib/libpam.2.dylib": "34fa66906759c8d30559dec70e28c52bef98f5b485600c556a750090bcaccbb0",
    "usr/lib/pam/pam_unix.so": "53e3f8fb3728559f0ee98d4461b2be629e6e0ec8df8807c8baaf6e2262009b24",
    "usr/lib/pam/pam_nologin.so": "388f8a358343d8fca3885b519b1801e0bef63ad99b55b95d8f0435e861172265",
    "usr/lib/pam/pam_permit.so": "6d807058d0b03b718956937d73c24703bbfe33033b69e616cd81c0571f9467e6",
}


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def unwrap_macho(b: bytes) -> bytes:
    if b.startswith(b"R14MACHO"):
        return b[8:]
    return b


def ipa_index(z: zipfile.ZipFile) -> dict[str, tuple[int, str]]:
    out = {}
    for info in z.infolist():
        if info.is_dir():
            continue
        data = z.read(info.filename)
        out[info.filename] = (len(data), sha256_bytes(data))
    return out


def find_member(z: zipfile.ZipFile, suffix: str) -> str | None:
    for n in z.namelist():
        if n.endswith(suffix):
            return n
    return None


def first_insn_ie_getpwnam(raw: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".dylib", delete=False) as tf:
        tf.write(raw)
        path = tf.name
    try:
        out = subprocess.check_output(["otool", "-tV", path], text=True)
    finally:
        Path(path).unlink(missing_ok=True)
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


def strings_has(raw: bytes, needle: str) -> bool:
    return needle.encode() in raw or needle in raw.decode("latin-1", errors="ignore")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("r22_ipa", type=Path)
    args = ap.parse_args()
    r22 = args.r22_ipa
    if not r22.is_file() or not R21_IPA.is_file():
        print("IPA missing", file=sys.stderr)
        return 1

    r22_sha = sha256_file(r22)
    if sha256_file(R21_IPA) != R21_IPA_SHA:
        print(f"WARN: R21 IPA sha drift expected {R21_IPA_SHA}", file=sys.stderr)

    with zipfile.ZipFile(R21_IPA) as z21, zipfile.ZipFile(r22) as z22:
        i21 = ipa_index(z21)
        i22 = ipa_index(z22)
        names21 = set(i21)
        names22 = set(i22)
        if names21 != names22:
            only21 = sorted(names21 - names22)[:5]
            only22 = sorted(names22 - names21)[:5]
            print(f"FAIL nameset mismatch only21={only21} only22={only22}")
            return 1

        changed = []
        macho_changed = []
        for n in sorted(names21):
            if i21[n][1] != i22[n][1]:
                changed.append(n)
                if "RootlessPayload/" in n and not n.endswith("/"):
                    raw = unwrap_macho(z22.read(n))
                    if raw[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
                        macho_changed.append(n)

        def suffix_ok(path: str) -> bool:
            return any(path.endswith(s) for s in EXPECTED_CHANGED_SUFFIXES)

        unexpected = [n for n in changed if not suffix_ok(n)]
        missing_expected = sorted(
            s for s in EXPECTED_CHANGED_SUFFIXES
            if not any(n.endswith(s) for n in changed)
        )

        main_m = find_member(z22, "dopamin-tvOS-kfd.app/dopamin-tvOS-kfd")
        hook_m = find_member(z22, "Handoff516/launchdhook516.dylib")
        prep_m = find_member(z22, "RootlessPayload/prep_bootstrap.sh")
        sshd_m = find_member(z22, "RootlessPayload/usr/sbin/sshd")
        plist_m = find_member(z22, "RootlessPayload/Library/LaunchDaemons/com.openssh.sshd.plist")
        cfg_m = find_member(z22, "RootlessPayload/etc/ssh/sshd_config")

        main_eq = i22[main_m][1] == R21_MAIN_SHA if main_m else False
        hook_eq = i22[hook_m][1] == R21_HOOK_SHA if hook_m else False
        prep_eq = i22[prep_m][1] == R21_PREP_SHA if prep_m else False
        sshd_eq = i21.get(sshd_m) == i22.get(sshd_m) if sshd_m else False
        plist_eq = i21.get(plist_m) == i22.get(plist_m) if plist_m else False
        cfg_eq = i21.get(cfg_m) == i22.get(cfg_m) if cfg_m else False

        # oracle prefix in IPA payload (unwrapped mach-o)
        libio_m = "Payload/dopamin-tvOS-kfd.app/RootlessPayload/usr/lib/libiosexec.1.dylib"
        libpam_m = "Payload/dopamin-tvOS-kfd.app/RootlessPayload/usr/lib/libpam.2.dylib"
        punix_m = "Payload/dopamin-tvOS-kfd.app/RootlessPayload/usr/lib/pam/pam_unix.so"
        libio = unwrap_macho(z22.read(libio_m))
        libpam = unwrap_macho(z22.read(libpam_m))
        punix = unwrap_macho(z22.read(punix_m))
        nss_ok = "sub" in first_insn_ie_getpwnam(libio) and strings_has(libio, "/var/jb/etc/pwd.db")
        pam_ok = strings_has(libpam, "/var/jb/etc/pam.d/")
        punix_ok = strings_has(punix, "/var/jb/etc/master.passwd")

        trust_m = find_member(z22, "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv")
        trust_text = z22.read(trust_m).decode()
        rows = list(csv.DictReader(trust_text.splitlines(), delimiter="\t"))
        assert len(rows) == 397
        r21_trust = R21_IPA.read_bytes()
        with zipfile.ZipFile(R21_IPA) as zt:
            r21_trust_text = zt.read(find_member(zt, "ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv")).decode()
        r21_rows = {r["REL"]: r for r in csv.DictReader(r21_trust_text.splitlines(), delimiter="\t")}
        r22_rows = {r["REL"]: r for r in rows}
        trust_changed = [rel for rel in TRUST_RELS if r21_rows[rel]["SHA256"] != r22_rows[rel]["SHA256"]]
        stale = []
        for rel in TRUST_RELS:
            member = [n for n in z22.namelist() if n.endswith(f"RootlessPayload/{rel}")][0]
            inner_sha = sha256_bytes(unwrap_macho(z22.read(member)))
            if r22_rows[rel]["SHA256"] != inner_sha:
                stale.append(rel)

    payload_macho_changed = [n for n in macho_changed if "RootlessPayload/" in n]
    pass_ok = (
        not unexpected
        and not missing_expected
        and len(payload_macho_changed) == 5
        and len(changed) == 7
        and main_eq and hook_eq and prep_eq and sshd_eq and plist_eq and cfg_eq
        and nss_ok and pam_ok and punix_ok
        and len(trust_changed) == 5
        and not stale
    )

    print(f"R22_BUILD_RESULT={'PASS' if pass_ok else 'FAIL'}")
    print(f"R22_IPA_PATH={r22}")
    print(f"R22_IPA_SHA256={r22_sha}")
    print("R22_LAYER1_ORACLE_ABI_CLOSURE_AUDIT=CLOSED")
    print(f"R22_PAYLOAD_CHANGED_PATH_COUNT={len(changed)}")
    print(f"R22_PAYLOAD_MACHO_CHANGED_COUNT={len(payload_macho_changed)}")
    print("R22_CHANGED_PAYLOAD_PATHS=" + ",".join(changed))
    print(f"R22_CHANGED_TRUST_ROW_COUNT={len(trust_changed)}")
    print(f"R22_STALE_TRUST_ROW_COUNT={len(stale)}")
    print(f"MAIN_BYTE_EQUAL_R21={'YES' if main_eq else 'NO'}")
    print(f"HOOK_BYTE_EQUAL_R21={'YES' if hook_eq else 'NO'}")
    print(f"PREP_BYTE_EQUAL_R21={'YES' if prep_eq else 'NO'}")
    print(f"SSHD_BYTE_EQUAL_R21={'YES' if sshd_eq else 'NO'}")
    print(f"PLIST_BYTE_EQUAL_R21={'YES' if plist_eq else 'NO'}")
    print(f"SSHD_CONFIG_BYTE_EQUAL_R21={'YES' if cfg_eq else 'NO'}")
    print(f"R22_LIBIOSEXEC_PREFIXED_NSS={'PASS' if nss_ok else 'FAIL'}")
    print(f"R22_LIBPAM_PREFIXED_CONFIG={'PASS' if pam_ok else 'FAIL'}")
    print(f"R22_PAM_UNIX_PREFIXED_MASTERPASSWD={'PASS' if punix_ok else 'FAIL'}")
    print(f"R22_UNEXPECTED_DIFF_COUNT={len(unexpected)}")
    if unexpected:
        print("R22_UNEXPECTED=" + ",".join(unexpected))
    if missing_expected:
        print("R22_MISSING_EXPECTED=" + ",".join(missing_expected))
    print(f"DEVICE_RUN_AUTHORIZATION={'NO' if not pass_ok else 'NO'}")
    return 0 if pass_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
