#!/usr/bin/env python3
import argparse, hashlib, json, struct, uuid
from pathlib import Path

EXPECTED_SHA = "96806a0e57eef714ec806063714101f09afbbdd968346d0d6ba8c4d635b11fdf"
EXPECTED_UUID = "7c25ad4d-2c32-3ae3-a52c-0af299cdda68"
PATCH_OFFSET = 0x3FDC
EXPECTED_PROLOGUE = bytes.fromhex("ff0301d1f65701a9f44f02a9fd7b03a9")
PATCH = bytes.fromhex("e01f80d2c0035fd6")
NEW_UUID_PREFIX = b"DOPATV165\0"
LC_UUID = 0x1B

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def locate_uuid(buf):
    magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from("<IiiIIIII", buf, 0)
    if magic != 0xFEEDFACF: raise SystemExit("not little-endian Mach-O64")
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", buf, off)
        if size < 8 or off + size > 32 + sizeofcmds: raise SystemExit("bad load command")
        if cmd == LC_UUID: return off + 8
        off += size
    raise SystemExit("LC_UUID missing")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source"); ap.add_argument("output"); ap.add_argument("manifest")
    a = ap.parse_args()
    src = Path(a.source); data = bytearray(src.read_bytes())
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA: raise SystemExit("exact tvOS dyld SHA mismatch")
    uoff = locate_uuid(data)
    old_uuid = str(uuid.UUID(bytes=bytes(data[uoff:uoff+16])))
    if old_uuid != EXPECTED_UUID: raise SystemExit("exact tvOS dyld UUID mismatch")
    if bytes(data[PATCH_OFFSET:PATCH_OFFSET+16]) != EXPECTED_PROLOGUE: raise SystemExit("IDA getAMFI prologue mismatch")
    data[PATCH_OFFSET:PATCH_OFFSET+len(PATCH)] = PATCH
    data[uoff:uoff+len(NEW_UUID_PREFIX)] = NEW_UUID_PREFIX
    Path(a.output).write_bytes(data)
    m = {"target":"AppleTV6,2/20L563","source_sha256":EXPECTED_SHA,
         "source_uuid":EXPECTED_UUID,"ida_symbol_vmaddr":"0x1cd07ffdc",
         "stock_patch_offset":"0x3fdc",
         "file_patch_offset":"0x3fdc",
         "verified_prologue":EXPECTED_PROLOGUE.hex(),
         "patch":PATCH.hex(),"patched_premerge_sha256":sha(a.output),
         "uuid_prefix":"DOPATV165\\0"}
    Path(a.manifest).write_text(json.dumps(m, indent=2)+"\n")
if __name__ == "__main__": main()
