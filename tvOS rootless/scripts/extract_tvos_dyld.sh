#!/bin/bash
# Extract stock tvOS 16.5 (20L563) dyld from an IPSW or user-supplied Mach-O path.
# Output is validated by scripts/validate_tvos_dyld.sh against vendor/dyld/TVOS_20L563_DYLD_CONTRACT.json
set -euo pipefail
OUT="${1:-${DT_WORKSPACE_ROOT:-.}/vendor/dyld/user/dyld_filesystem_20L563}"
INPUT="${2:-}"
if [[ -z "$INPUT" ]]; then
  echo "Usage: $0 [output_path] <path-to-dyld-or-ipsw-component>" >&2
  echo "Expected SHA256: 96806a0e57eef714ec806063714101f09afbbdd968346d0d6ba8c4d635b11fdf" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUT")"
cp -p "$INPUT" "$OUT"
chmod 755 "$OUT"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
bash "$SCRIPT_DIR/validate_tvos_dyld.sh" "$OUT"
