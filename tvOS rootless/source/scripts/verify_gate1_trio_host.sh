#!/bin/bash
# Host verification for Gate 1 isolated trio — read-only on frozen artifacts.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
OUT="$KFD/build/gate1/Handoff516"
REPORT="$KFD/docs/reports/BUILD102730_GATE1_HOST_VERIFICATION.txt"
PASS=1

hook="$OUT/launchdhook516.dylib"
lj="$OUT/libjailbreak.dylib"
lc="$OUT/libchoma.dylib"

fail() { echo "FAIL: $*"; PASS=0; }
ok() { echo "OK: $*"; }

: > "$REPORT"
log() { echo "$*" | tee -a "$REPORT"; }

log "BUILD102730_GATE1_HOST_VERIFICATION"
log "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""

for f in "$hook" "$lj" "$lc"; do
  [[ -f "$f" ]] || fail "missing $f"
done

# Frozen checks
FROZEN_LJ="$KFD/basebin/out/libjailbreak.dylib"
FROZEN_SHA=$(shasum -a 256 "$FROZEN_LJ" | awk '{print $1}')
GATE1_LJ_SHA=$(shasum -a 256 "$lj" | awk '{print $1}')
if [[ "$FROZEN_SHA" == "$GATE1_LJ_SHA" ]]; then
  fail "Gate1 libjailbreak SHA equals frozen basebin/out (must be distinct Handoff build)"
else
  ok "Gate1 libjailbreak SHA differs from frozen basebin/out"
fi

LAYOUT_LJ="$KFD/layout/Payload/dopamin-tvOS-kfd.app/Handoff516/libjailbreak.dylib"
if [[ -f "$LAYOUT_LJ" ]]; then
  LAYOUT_SHA=$(shasum -a 256 "$LAYOUT_LJ" | awk '{print $1}')
  if [[ "$LAYOUT_SHA" == "$GATE1_LJ_SHA" ]]; then
    fail "Gate1 libjailbreak overwrote layout Handoff copy (same SHA)"
  else
    ok "layout Handoff516 libjailbreak unchanged (SHA differs from Gate1)"
  fi
fi

log ""
log "=== MSHook / initXPCHooks ==="
if nm -um "$hook" 2>/dev/null | grep -q MSHookFunction; then
  fail "MSHookFunction import present"
else
  ok "UNDEFINED_MSHOOKFUNCTION_IMPORT=NO"
fi
if nm "$hook" 2>/dev/null | grep -q initXPCHooks; then
  fail "initXPCHooks symbol present"
else
  ok "INITXPCHOOKS_REFERENCE_PRESENT=NO"
fi
if nm "$hook" 2>/dev/null | grep -q xpc_receive_mach_msg_hook; then
  fail "xpc hook object linked"
else
  ok "XPC_HOOK_OBJECT_LINKED=NO"
fi

log ""
log "=== Required exports libjailbreak ==="
for sym in jbclient_boomerang_done jbclient_initialize_primitives_internal jbclient_xpc_set_custom_port get_jbroot; do
  if nm -gU "$lj" 2>/dev/null | grep -q "_$sym"; then
    ok "export $sym"
  else
    fail "missing export $sym"
  fi
done

log ""
log "=== LC_ID / LC_LOAD ==="
log "launchdhook LC_ID: $(otool -D "$hook" | tail -1)"
log "launchdhook LC_LOAD private:"
otool -L "$hook" | grep loader_path | tee -a "$REPORT"
log "libjailbreak LC_ID: $(otool -D "$lj" | tail -1)"
log "libjailbreak libchoma: $(otool -L "$lj" | grep choma | head -1)"
log "libchoma LC_ID: $(otool -D "$lc" | tail -1)"

if otool -l "$hook" | grep -A1 LC_LOAD_DYLIB | grep -q "launchdhook516.dylib"; then
  fail "hook self LC_LOAD present"
else
  ok "HOOK_SELF_LC_LOAD=NO"
fi

log ""
log "=== Constructors (__TEXT,__init_offsets) ==="
otool -s __TEXT __init_offsets "$hook" | tee -a "$REPORT"

log ""
log "=== Undefined symbols ==="
for bin in "$hook" "$lj" "$lc"; do
  log "--- $(basename "$bin") undefined ---"
  nm -um "$bin" 2>/dev/null | grep 'undefined' | tee -a "$REPORT" || true
done

UNRES=$( (nm -um "$hook" "$lj" "$lc" 2>/dev/null | grep undefined | grep -v 'from libSystem' | grep -v 'from libobjc' | grep -v 'from Foundation' | grep -v 'from Security' | grep -v 'from CoreServices' | grep -v 'from CoreFoundation' | grep -v 'from libcompression' | grep -v 'from libbsm' | grep -v ' dynamically looked up' | grep -v 'from libjailbreak' | grep -v 'from libchoma' || true) | wc -l | tr -d ' ')
log "UNRESOLVED_NON_SYSTEM_SYMBOL_COUNT=$UNRES"
if [[ "$UNRES" != "0" ]]; then
  fail "unresolved non-system symbols remain"
fi

log ""
log "=== SHA256 / UUID ==="
for f in "$hook" "$lj" "$lc"; do
  log "$(basename "$f") SHA256=$(shasum -a 256 "$f" | awk '{print $1}')"
  log "$(basename "$f") UUID=$(otool -l "$f" | awk '/uuid/ {print $2; exit}')"
done

log ""
if [[ "$PASS" == "1" ]]; then
  log "HOST_ACCEPTANCE_CRITERIA=PASS"
else
  log "HOST_ACCEPTANCE_CRITERIA=FAIL"
fi

exit $((1-PASS))
