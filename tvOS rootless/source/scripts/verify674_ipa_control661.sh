#!/bin/bash
set -euo pipefail
IPA="${1:?ipa path}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unzip -q -o "$IPA" -d "$TMP"
BIN="$TMP/Payload/dopamin-tvOS-kfd.app/Handoff674/Control661/dt_direct653_helper_control661"
[[ -f "$BIN" ]] || { echo "ERROR: control661 missing in IPA"; exit 1; }
file "$BIN" | rg -q 'Mach-O 64-bit executable arm64'
echo "CONTROL661_IPA_VERIFY=PASS"
