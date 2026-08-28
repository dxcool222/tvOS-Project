#!/bin/bash
# Build host dt_sign_platform_hook and sign launchdhook516.dylib with CodeDirectory.platform != 0
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
ROOT="$(cd "$PROJECT/.." && pwd -P)"
DOPAMINE="${DOPAMINE:-$ROOT/Dopamine_Rootful-main}"
CHoma="$DOPAMINE/BaseBin/ChOma"
HOST_BIN="$PROJECT/.theos/obj/host/dt_sign_platform_hook"
CHoma_HOST="$PROJECT/.theos/obj/host/choma"

sha256_file() {
    shasum -a 256 "$1" | awk '{print $1}'
}

build_host_signer() {
    mkdir -p "$CHoma_HOST" "$PROJECT/.theos/obj/host"
    local srcs=("$CHoma"/src/*.c)
    xcrun clang -O2 -arch arm64 -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
        -I"$CHoma/src" \
        "${srcs[@]}" "$PROJECT/scripts/dt_sign_platform_hook.c" \
        -framework CoreFoundation -framework Security -o "$HOST_BIN"
}

sign_hook() {
    local input="$1"
    local output="$2"
    local ent="$3"
    local platform_id="${4:-13}"

    if [[ ! -f "$input" ]]; then
        echo "ERROR: missing input $input"
        exit 1
    fi

    build_host_signer

    echo "HOOK_SHA256_PRE_SIGN=$(sha256_file "$input")"
    set +e
    "$HOST_BIN" -i "$input" -o "$output" -e "$ent" -I launchdhook516.dylib -p "$platform_id"
    sign_rc=$?
    set -e
    echo "HOOK_SHA256_POST_SIGN=$(sha256_file "$output")"

    python3 - "$output" <<'PY'
import struct, sys
path = sys.argv[1]
data = open(path, 'rb').read()
magic = struct.pack('>I', 0xfade0c02)
idx = data.find(magic)
found = []
while idx != -1:
    plat = data[idx + 28]
    ver = struct.unpack('>I', data[idx+8:idx+12])[0]
    if ver >= 0x20100 and plat != 0:
        found.append(plat)
    idx = data.find(magic, idx + 1)
if found:
    print(f"PLATFORM_FLAG_VERIFIED_IN_MACHO=YES platform_bytes={found}")
else:
    print("PLATFORM_FLAG_VERIFIED_IN_MACHO=NO")
    sys.exit(1)
PY
    if [[ "$sign_rc" != "0" ]]; then
        echo "WARN: dt_sign_platform_hook exit=$sign_rc (output verified above)"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    sign_hook "${1:?input}" "${2:?output}" "${3:?entitlements}" "${4:-13}"
fi
