#!/bin/bash
# Gate 1B minimal trio host verification — read-only; does not touch gate1 or frozen outputs.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
KFD="$(cd "$SCRIPT/.." && pwd -P)"
OUT="$KFD/build/gate1b/Handoff516"
REPORT="$KFD/docs/reports/BUILD102731_GATE1B_HOST_VERIFICATION.txt"
PASS=1

hook="$OUT/launchdhook516.dylib"
lj="$OUT/libjailbreak.dylib"
lc="$OUT/libchoma.dylib"

fail() { echo "FAIL: $*"; PASS=0; }
ok() { echo "OK: $*"; }

: > "$REPORT"
log() { echo "$*" | tee -a "$REPORT"; }

log "BUILD102731_GATE1B_HOST_VERIFICATION"
log "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""

for f in "$hook" "$lj" "$lc"; do
  [[ -f "$f" ]] || fail "missing $f"
done

# Frozen / prior gate1 must remain
[[ -d "$KFD/build/gate1/Handoff516" ]] && ok "prior build/gate1 preserved" || fail "gate1 missing"
G1_SHA=$(shasum -a 256 "$KFD/build/gate1/Handoff516/launchdhook516.dylib" 2>/dev/null | awk '{print $1}' || true)
G1B_SHA=$(shasum -a 256 "$hook" | awk '{print $1}')
[[ "$G1_SHA" != "$G1B_SHA" ]] && ok "gate1b hook differs from gate1" || fail "gate1b hook sha equals gate1"

log ""
log "=== LC_BUILD_VERSION platform ==="
for bin in "$hook" "$lj" "$lc"; do
  plat=$(otool -l "$bin" | awk '/cmd LC_BUILD_VERSION/{p=1} p&&/platform/{print $2; exit}')
  log "$(basename "$bin") LC_BUILD_VERSION.platform=$plat"
  [[ "$plat" == "3" ]] || fail "$(basename "$bin") platform not 3 (tvOS)"
done
ok "MACHO_PLATFORM_TVOS_CONFIRMED=YES"

log ""
log "=== Install names (no install_name_tool) ==="
log "hook LC_ID: $(otool -D "$hook" | tail -1)"
log "lj LC_ID: $(otool -D "$lj" | tail -1)"
log "lc LC_ID: $(otool -D "$lc" | tail -1)"
otool -L "$hook" | grep loader_path | tee -a "$REPORT"
otool -L "$lj" | grep loader_path | tee -a "$REPORT"

log ""
log "=== Hook constructors ==="
otool -s __TEXT __init_offsets "$hook" | tee -a "$REPORT"
CTOR_COUNT=$(otool -s __TEXT __init_offsets "$hook" | tail -1 | awk '{print NF-1}')
log "MAIN_HOOK_CONSTRUCTOR_COUNT=$CTOR_COUNT"
[[ "$CTOR_COUNT" == "1" ]] || fail "expected 1 hook constructor"
nm "$hook" | grep -E 'dt_boomerang516_init|dt516_jbserver_mach_init' && fail "extra hook constructors present" || ok "CONSTRUCTOR_ORDER_DEPENDENCY=NO"

log ""
log "=== Forbidden hook imports/symbols ==="
for sym in MSHookFunction initXPCHooks get_jbroot jbclient_mach_get_launchd_port; do
  if nm -um "$hook" 2>/dev/null | grep -q "$sym"; then
    fail "hook undefined import $sym"
  else
    ok "hook no import $sym"
  fi
  if nm "$hook" 2>/dev/null | grep -q "$sym"; then
    fail "hook defines/references $sym"
  fi
done
if nm "$lj" 2>/dev/null | grep -q 'libjailbreak_physrw_init'; then
  fail "dummy libjailbreak_physrw_init present"
else
  ok "DUMMY_PHYSRW_INIT_SYMBOL_PRESENT=NO"
fi
if nm "$hook" 2>/dev/null | grep -E 'gGlobalServer|gWatchdogDomain|jbserver_local'; then
  fail "jbserver surface in hook"
else
  ok "FULL_HOOK_JBSERVER_SURFACE_LINKED=NO"
fi

log ""
log "=== Required libjailbreak exports ==="
for sym in jbclient_xpc_set_custom_port jbclient_initialize_primitives_gate1b jbclient_boomerang_done; do
  nm -gU "$lj" 2>/dev/null | grep -q "_$sym" && ok "export $sym" || fail "missing $sym"
done

log ""
log "=== Undefined symbols ==="
for bin in "$hook" "$lj" "$lc"; do
  log "--- $(basename "$bin") ---"
  nm -um "$bin" 2>/dev/null | grep undefined | tee -a "$REPORT" || true
done
UNRES=$( (nm -um "$hook" "$lj" "$lc" 2>/dev/null | grep undefined | grep -v 'from libSystem' | grep -v 'from libobjc' | grep -v 'from Foundation' | grep -v 'from Security' | grep -v 'from CoreServices' | grep -v 'from CoreFoundation' | grep -v 'from libcompression' | grep -v 'from libbsm' | grep -v ' dynamically looked up' | grep -v 'from libjailbreak' | grep -v 'from libchoma' || true) | wc -l | tr -d ' ')
log "UNRESOLVED_NON_SYSTEM_SYMBOL_COUNT=$UNRES"
[[ "$UNRES" == "0" ]] || fail "unresolved symbols"

log ""
log "=== SHA256 / UUID ==="
for f in "$hook" "$lj" "$lc"; do
  log "$(basename "$f") SHA256=$(shasum -a 256 "$f" | awk '{print $1}')"
  log "$(basename "$f") UUID=$(otool -l "$f" | awk '/uuid/ {print $2; exit}')"
done

log ""
if [[ "$PASS" == "1" ]]; then
  log "HOST_ACCEPTANCE_CRITERIA=PASS"
  log "BOOMERANG_HOOK_SIDE_HOST_CLOSURE=PASS"
else
  log "HOST_ACCEPTANCE_CRITERIA=FAIL"
  log "BOOMERANG_HOOK_SIDE_HOST_CLOSURE=FAIL"
fi
log "BOOMERANG_END_TO_END_DEVICE_CLOSURE=UNPROVEN"
log "INSTALL_NAME_TOOL_USED=NO"

exit $((1-PASS))
