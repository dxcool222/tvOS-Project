#!/bin/bash
# ROOTLESS-R5 repair: build fuller launchdhook516 + libjailbreak with R4 rootPath/dual-sandbox,
# while keeping 102738P GOT/boomerang + frozen opainject/jbctl/libchoma.
# USB-only: does not use Desktop /tmp dopamine unless it already points at USB after setup.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=scripts/clean_project_env.sh
source "$SCRIPT/clean_project_env.sh"
KFD="$DT_KFD_ROOT"
DOPAMINE="$DT_DOPAMINE_ROOT"

SEED="$DT_BUILD_ROOT/build/102738P/Handoff516"
SEED_FW="$DT_BUILD_ROOT/build/102738P/Frameworks/libjailbreak.dylib"
OUT="$DT_BUILD_ROOT/build/rootless_r4/Handoff516"
FW_OUT="$DT_BUILD_ROOT/build/rootless_r4/Frameworks"
OBJ="$DT_BUILD_ROOT/build/rootless_r4/obj"
SRC="$KFD/handoff516/source"
MIN="$SRC/launchdhook/minimal"
GATE1_SRC="$SRC/libjailbreak"
LIBJB_DOP="$DOPAMINE/BaseBin/libjailbreak"
CHOMA_DOP="$DOPAMINE/BaseBin/ChOma"
SDK="${TVOS_SYSROOT:-$HOME/theos/sdks/AppleTVOS16.4.sdk}"
CC="xcrun -sdk appletvos clang"
VTOOL="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/vtool"
INSTALL_NAME_TOOL="${INSTALL_NAME_TOOL:-/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool}"
TVOS_MIN=14.0

[[ -d "$SEED" ]] || { echo "ERROR: missing seed $SEED (need 102738P Handoff516)" >&2; exit 1; }
[[ -d "$SDK" ]] || { echo "ERROR: missing SDK $SDK" >&2; exit 1; }

rm -rf "$KFD/build/rootless_r4"
mkdir -p "$OUT" "$FW_OUT" "$OBJ/hook" "$OBJ/libjb" "$OBJ/include/choma"

# Seed frozen KEEP binaries (opainject/jbctl/libchoma/entitlements)
cp -R "$SEED/." "$OUT/"
rm -f "$OUT/launchdhook516.dylib" "$OUT/libjailbreak.dylib" \
  "$OUT/hook_build_manifest.txt" "$OUT/BUILD102738P_RESOURCE_MANIFEST.txt"
cp "$OUT/libchoma.dylib" "$OUT/libchoma.dylib.bak" 2>/dev/null || true
# Ensure libchoma present from seed
[[ -f "$OUT/libchoma.dylib" ]] || cp "$KFD/basebin/out/libchoma.dylib" "$OUT/libchoma.dylib"
"$INSTALL_NAME_TOOL" -id "@loader_path/libchoma.dylib" "$OUT/libchoma.dylib" || true

# Headers for choma
cp "$CHOMA_DOP/src/"*.h "$OBJ/include/choma/" 2>/dev/null || true
mkdir -p "$KFD/build/rootless_r4/include/choma"
cp "$CHOMA_DOP/src/"*.h "$KFD/build/rootless_r4/include/choma/" 2>/dev/null || true

# R24 ABI: handoff info.h / primitives_external.h MUST win over freeze DOP2
# headers. Freeze info.h omits the tvOS inpcb/socket/protosw tail; compiling
# gSystemInfo against that layout while the app uses the larger DOP2 layout
# caused DTApplyTvOSInpcbOverrides to smash gPrimitives.kreadbuf (burn #1 IPS PC
# 0x3800000028).
#
# Quoted #include "info.h" resolves next to the .c first, so -I order cannot
# override freeze Dopamine headers when compiling $LIBJB_DOP/src/*.c in place.
# Stage sources and overlay R24 ABI headers beside them.
mkdir -p "$KFD/build/rootless_r4/include/libjailbreak"
cp -R "$SRC/include/libjailbreak/"*.h "$KFD/build/rootless_r4/include/libjailbreak/"
cp "$GATE1_SRC/core/info.h" "$KFD/build/rootless_r4/include/libjailbreak/info.h"
cp "$GATE1_SRC/core/primitives_external.h" "$KFD/build/rootless_r4/include/libjailbreak/primitives_external.h"
cp "$GATE1_SRC/core/info.h" "$SRC/include/libjailbreak/info.h"
cp "$GATE1_SRC/core/primitives_external.h" "$SRC/include/libjailbreak/primitives_external.h"

LJ_STAGE="$OBJ/lj_src"
rm -rf "$LJ_STAGE"
mkdir -p "$LJ_STAGE"
rsync -a \
  --include='*/' --include='*.c' --include='*.h' --include='*.m' --include='*.S' --exclude='*' \
  "$LIBJB_DOP/src/" "$LJ_STAGE/"
cp "$GATE1_SRC/core/info.h" "$LJ_STAGE/info.h"
cp "$GATE1_SRC/core/primitives_external.h" "$LJ_STAGE/primitives_external.h"

# Host sizeof gate before compiling dylib objects
python3 - "$LJ_STAGE" <<'PY'
import sys, subprocess, pathlib
stage=pathlib.Path(sys.argv[1])
src=r'''
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
typedef void* xpc_object_t;
#include "info.h"
int main(void){
  printf("STAGE_SYSTEM_INFO_SIZE=%#zx\n", sizeof(struct system_info));
  printf("STAGE_INPCB_OFF=%#zx\n", offsetof(struct system_info, kernelStruct.inpcb));
  return sizeof(struct system_info)==0x370 ? 0 : 1;
}
'''
path=pathlib.Path('/tmp/r24_abi_stage_probe.c')
path.write_text(src)
r=subprocess.run(['cc','-I'+str(stage),str(path),'-o','/tmp/r24_abi_stage_probe'],capture_output=True,text=True)
if r.returncode:
    sys.stderr.write(r.stderr); sys.exit(1)
out=subprocess.check_output(['/tmp/r24_abi_stage_probe'],text=True)
sys.stdout.write(out)
sys.exit(0 if '0x370' in out else 1)
PY

INC_LJ=(
  -I"$LJ_STAGE"
  -I"$KFD/build/rootless_r4/include/libjailbreak"
  -I"$KFD/build/rootless_r4/include"
  -I"$SRC/include/libjailbreak"
  -I"$GATE1_SRC/core"
  -I"$LIBJB_DOP/src"
  -I"$KFD/stubs"
  -I"$DOPAMINE/BaseBin/_external/include"
  -I"$CHOMA_DOP/src"
  -I"$KFD/build/rootless_r4/include/choma"
)

CFLAGS_LJ=(
  -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN"
  -O2 -Wno-error -Wno-deprecated-declarations -Wno-availability
  -D_DARWIN_UNLIMITED_SYSCALLS -fPIC
  "${INC_LJ[@]}"
)

compile_lj() {
  local src="$1" obj="$2"
  echo "  CC-LJ $(basename "$src")"
  $CC "${CFLAGS_LJ[@]}" -c "$src" -o "$obj"
}

echo "=== R5-REPAIR: rebuild Handoff libjailbreak with R4 jbroot.c ==="
BASE_OBJS=()
for pair in \
  "info.c" "primitives.c" "translation.c" "kernel.c" "jbserver.c" "jbserver_boomerang.c" \
  "physrw_pte.c" "trustcache.c" "kalloc_pt.m" \
  "dt_mach_thread_shim.c" "dt_kcall_arm64_tvos.c" "dt_kcall_fugu14_minimal.c" \
  "kcall_Fugu14.S" "dt_pmap_util.c" "dt_pte_kwrite_stub.c"; do
  objname=$(basename "$pair" | sed 's/\.[cmS]$/.o/')
  case "$pair" in
    dt_*) src="$KFD/stubs/$pair" ;;
    kcall_Fugu14.S) src="$LJ_STAGE/kcall_Fugu14.S" ;;
    kalloc_pt.m) src="$GATE1_SRC/server102737/kalloc_pt.m" ;;
    *) src="$LJ_STAGE/$pair" ;;
  esac
  compile_lj "$src" "$OBJ/libjb/$objname"
  BASE_OBJS+=("$OBJ/libjb/$objname")
done

GATE1_OBJS=()
for pair in \
  "$GATE1_SRC/jbclient_xpc.c" \
  "$GATE1_SRC/dt_jbclient_mach_tvos_stub.c" \
  "$GATE1_SRC/jbroot.c" \
  "$GATE1_SRC/signatures.c" \
  "$GATE1_SRC/dt_jbclient_primitives_tvos.c" \
  "$GATE1_SRC/client/dt_jbclient_primitives_gate1b.c" \
  "$GATE1_SRC/dt_gate1_util_exports.c" \
  "$GATE1_SRC/dt_gate1_string_util.c" \
  "$GATE1_SRC/dt_physrw_init_tvos_stub.c"; do
  obj="$OBJ/libjb/$(basename "$pair" .c).o"
  compile_lj "$pair" "$obj"
  GATE1_OBJS+=("$obj")
done

LIBJB_OUT="$OUT/libjailbreak.dylib"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/libjailbreak.dylib" \
  -lcompression -lbsm \
  -L"$OUT" -lchoma \
  -framework Foundation -framework CoreServices -framework Security \
  -Wl,-u,_libjailbreak_physrw_pte_init \
  -Wl,-u,_device_supports_physrw_pte \
  -Wl,-u,_kalloc_pt_is_initialized \
  -Wl,-u,_kalloc_pt_pool_count \
  -Wl,-u,_kalloc_pt_prefill \
  "${BASE_OBJS[@]}" "${GATE1_OBJS[@]}" \
  -o "$LIBJB_OUT"

# App Frameworks copy of LJ (keep install name style used by app)
cp "$LIBJB_OUT" "$FW_OUT/libjailbreak.dylib"
"$INSTALL_NAME_TOOL" -id "@executable_path/Frameworks/libjailbreak.dylib" "$FW_OUT/libjailbreak.dylib" || true
"$INSTALL_NAME_TOOL" -change "@loader_path/libchoma.dylib" "@executable_path/Frameworks/libchoma.dylib" "$FW_OUT/libjailbreak.dylib" || true

python3 - "$FW_OUT/libjailbreak.dylib" <<'PY'
import sys, subprocess
out=subprocess.check_output(['nm','-gU',sys.argv[1]],text=True)
syms={}
for line in out.splitlines():
    parts=line.split()
    if len(parts)>=3 and parts[2] in ('_gSystemInfo','_gPrimitives','_gUnusedDomain'):
        syms[parts[2]]=int(parts[0],16)
delta=syms['_gPrimitives']-syms['_gSystemInfo']
prim=syms['_gUnusedDomain']-syms['_gPrimitives']
print(f"DYLIB_gSystemInfo={syms['_gSystemInfo']:#x}")
print(f"DYLIB_gPrimitives={syms['_gPrimitives']:#x}")
print(f"DYLIB_DELTA_SYSTEMINFO_TO_PRIMITIVES={delta:#x}")
print(f"DYLIB_DELTA_PRIMITIVES_TO_UNUSED={prim:#x}")
if delta!=0x370 or prim!=0x60:
    raise SystemExit('ABI FAIL: Frameworks libjailbreak spacing mismatch')
print('FRAMEWORKS_LIBJAILBREAK_ABI_SPACING=PASS')
PY

echo "=== R5-REPAIR: fuller launchdhook516 (GOT + jbserver + R4 dual-path) ==="
# Stage complete libjailbreak headers: R4 jbroot.h + Dopamine util.h (proc_allow_all/killall/VM_FLAGS)
mkdir -p "$KFD/build/rootless_r4/include/libjailbreak"
cp -R "$SRC/include/libjailbreak/"*.h "$KFD/build/rootless_r4/include/libjailbreak/"
# App Frameworks + Handoff LJ export probe symbols from server102737 kalloc_pt.
cp "$GATE1_SRC/server102737/kalloc_pt.h" "$KFD/build/rootless_r4/include/libjailbreak/kalloc_pt.h"
cp "$GATE1_SRC/server102737/kalloc_pt.h" "$SRC/include/libjailbreak/kalloc_pt.h"
cp "$LIBJB_DOP/src/util.h" "$KFD/build/rootless_r4/include/libjailbreak/util.h"
# Re-assert R24 ABI headers after util overlay (freeze util must not displace them).
cp "$GATE1_SRC/core/info.h" "$KFD/build/rootless_r4/include/libjailbreak/info.h"
cp "$GATE1_SRC/core/primitives_external.h" "$KFD/build/rootless_r4/include/libjailbreak/primitives_external.h"
cp "$GATE1_SRC/core/info.h" "$SRC/include/libjailbreak/info.h"
cp "$GATE1_SRC/core/primitives_external.h" "$SRC/include/libjailbreak/primitives_external.h"
cat > "$KFD/build/rootless_r4/include/libjailbreak/jbroot_force.h" <<'EOF'
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libjailbreak/jbroot.h>
EOF

CBR="$SRC/launchdhook/cbr"
SHCBR="$SRC/systemhook_cbr"
RTRACE="$SRC/runtime_trace"
INC_HOOK=(
  -I"$KFD/build/rootless_r4/include"
  -I"$KFD/build/rootless_r4/include/choma"
  -I"$KFD/build/rootless_r4/include/libjailbreak"
  -I"$KFD/stubs"
  -I"$DOPAMINE/BaseBin/_external/include"
  -I"$LIBJB_DOP/src"
  -I"$SRC/include"
  -I"$SRC/include/jbserver"
  -I"$SRC/include/external"
  -I"$GATE1_SRC/client"
  -I"$CBR"
  -I"$SHCBR"
  -I"$RTRACE"
  -I"$KFD/stubs"
)
CFLAGS_HOOK=(
  -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN"
  -O2 -Wno-error -Wno-deprecated-declarations -Wno-availability
  -D_DARWIN_UNLIMITED_SYSCALLS -fPIC -fobjc-arc -fblocks
  -DDT_BUILD102732C_TELEMETRY=1
  -DDT_BUILD102735D_TRACE=1
  -DDT_BUILD102737D_TELEMETRY=1
  -DDT_BUILD102738P_TELEMETRY=1
  -DDT_ROOTLESS_R24_CBR=1
  -include "$KFD/build/rootless_r4/include/libjailbreak/jbroot_force.h"
  "${INC_HOOK[@]}"
)

HOOK_OBJS=()
compile_hook() {
  local src="$1" obj="$2"
  echo "  CC-HOOK $(basename "$src")"
  $CC "${CFLAGS_HOOK[@]}" -c "$src" -o "$obj"
  HOOK_OBJS+=("$obj")
}

# Minimal GOT + boomerang ctor surface (superset of 102738P)
compile_hook "$MIN/dt_launchdhook516_main_gate1b.m" "$OBJ/hook/main_gate1b.o"
compile_hook "$MIN/dt_launchdhook516_boomerang.c" "$OBJ/hook/boomerang_min.o"
compile_hook "$MIN/dt_launchdhook516_got_probe_102738p.c" "$OBJ/hook/got_probe.o"

# R24 CBR: XPC ingress + spawn inject (litehook; Theos 16.4)
compile_hook "$CBR/dt_cbr_mshook.c" "$OBJ/hook/dt_cbr_mshook.o"
compile_hook "$CBR/xpc_hook.c" "$OBJ/hook/xpc_hook.o"
compile_hook "$CBR/spawn_hook.c" "$OBJ/hook/spawn_hook.o"
compile_hook "$CBR/dt_r24_child_dyld_probe.c" "$OBJ/hook/dt_r24_child_dyld_probe.o"
compile_hook "$RTRACE/dt_runtime_trace.c" "$OBJ/hook/dt_runtime_trace.o"
compile_hook "$SHCBR/litehook.c" "$OBJ/hook/litehook.o"
compile_hook "$SHCBR/common.c" "$OBJ/hook/sh_common.o"
compile_hook "$SHCBR/envbuf.c" "$OBJ/hook/envbuf.o"
compile_hook "$KFD/stubs/syscall_shim.c" "$OBJ/hook/syscall_shim.o"

# Fuller jbserver surface (includes R4 dual-path jbdomain_systemwide.c)
compile_hook "$SRC/launchdhook/dt_jbserver_mach516.c" "$OBJ/hook/jbserver_mach516.o"
compile_hook "$SRC/launchdhook/jbserver/dt_jbdomain_watchdog_gate1.c" "$OBJ/hook/dt_jbdomain_watchdog_gate1.o"
for f in "$SRC/launchdhook/jbserver/"*.c; do
  base=$(basename "$f")
  [[ "$base" == "jbserver_mach.c" ]] && continue
  [[ "$base" == "jbdomain_watchdog.c" ]] && continue
  [[ "$base" == "dt_jbdomain_watchdog_gate1.c" ]] && continue
  compile_hook "$f" "$OBJ/hook/$base.o"
done

HOOK_OUT="$OUT/launchdhook516.dylib"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/launchdhook516.dylib" \
  -L"$OUT" -ljailbreak \
  "${HOOK_OBJS[@]}" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm -lobjc \
  -o "$HOOK_OUT"

"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o "$HOOK_OUT" "$HOOK_OUT" || true

echo "=== R24-CBR: systemhook.dylib (JBROOT path, tweaks OFF) ==="
mkdir -p "$OBJ/systemhook"
CFLAGS_SH=(
  -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN"
  -O2 -Wno-error -Wno-deprecated-declarations -Wno-availability
  -D_DARWIN_UNLIMITED_SYSCALLS -fPIC -fblocks
  -I"$SHCBR"
  -I"$RTRACE"
  -I"$KFD/generated"
  -I"$KFD/build/rootless_r4/include"
  -I"$KFD/build/rootless_r4/include/choma"
  -I"$KFD/build/rootless_r4/include/libjailbreak"
  -I"$DOPAMINE/BaseBin/_external/include"
  -I"$LIBJB_DOP/src"
  -I"$SRC/include"
  -I"$SRC/include/libjailbreak"
  -I"$GATE1_SRC"
  -I"$KFD/stubs"
)
SH_OBJS=()
for pair in main_cbr.c common.c envbuf.c litehook.c; do
  echo "  CC-SH $pair"
  $CC "${CFLAGS_SH[@]}" -c "$SHCBR/$pair" -o "$OBJ/systemhook/${pair%.c}.o"
  SH_OBJS+=("$OBJ/systemhook/${pair%.c}.o")
done
echo "  CC-SH dt_runtime_trace.c"
$CC "${CFLAGS_SH[@]}" -c "$RTRACE/dt_runtime_trace.c" -o "$OBJ/systemhook/dt_runtime_trace.o"
SH_OBJS+=("$OBJ/systemhook/dt_runtime_trace.o")
echo "  CC-SH syscall_shim.c"
$CC "${CFLAGS_SH[@]}" -c "$KFD/stubs/syscall_shim.c" -o "$OBJ/systemhook/syscall_shim.o"
SH_OBJS+=("$OBJ/systemhook/syscall_shim.o")
SH_OUT="$OUT/systemhook.dylib"
$CC -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib \
  -install_name "@loader_path/systemhook.dylib" \
  -L"$OUT" -ljailbreak \
  "${SH_OBJS[@]}" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm \
  -o "$SH_OUT"
"$VTOOL" -set-build-version tvos "$TVOS_MIN" "$TVOS_MIN" -replace -o "$SH_OUT" "$SH_OUT" || true

# Sign with launchdhook entitlements if ldid present
LDID="${LDID:-$(command -v ldid || true)}"
ENT="$KFD/handoff681/entitlements_launchdhook681.plist"
if [[ -n "$LDID" && -x "$LDID" && -f "$ENT" ]]; then
  "$LDID" -S"$ENT" "$HOOK_OUT" || true
  "$LDID" -S"$ENT" "$LIBJB_OUT" || true
  "$LDID" -S "$SH_OUT" || true
fi

# Host proofs before packaging
strings "$HOOK_OUT" | rg -q '/var/jb|/private/var/jb'
strings "$HOOK_OUT" | rg -q 'com.apple.app-sandbox.read'
strings "$HOOK_OUT" | rg -q 'GATE1B_LAUNCHDHOOK_CONSTRUCTOR_ENTERED|GATE1_LAUNCHDHOOK_CONSTRUCTOR_ENTERED'
strings "$HOOK_OUT" | rg -q 'GOT_PROTECTION|BUILD102738P_PROBE'
strings "$HOOK_OUT" | rg -q 'XPC_HOOK_INSTALL_VERIFIED=YES'
strings "$HOOK_OUT" | rg -q 'SPAWN_HOOK_INSTALL_VERIFIED=YES'
strings "$HOOK_OUT" | rg -q 'R24_FAIL_STAGE=XPC_HOOK_INSTALL'
strings "$HOOK_OUT" | rg -q 'R24_FAIL_STAGE=SPAWN_HOOK_INSTALL'
strings "$HOOK_OUT" | rg -q 'LAUNCHD_CS_ALLOW_INVALID_BEGIN'
strings "$HOOK_OUT" | rg -q 'LAUNCHD_CS_ALLOW_INVALID=PASS'
strings "$HOOK_OUT" | rg -q 'CTOR_ORDER=CS_ALLOW_INVALID>XPC>SPAWN'
nm -gU "$HOOK_OUT" | rg -q ' _dt_r24_launchd_cs_allow_invalid_or_fail$'
strings "$HOOK_OUT" | rg -q '/usr/lib/systemhook.dylib'
nm -gU "$HOOK_OUT" | rg -q ' _initXPCHooks$'
nm -gU "$HOOK_OUT" | rg -q ' _initSpawnHooks$'
nm -gU "$HOOK_OUT" | rg -q ' _dt_r24_launchd_begin_live_injection$'
nm -gU "$HOOK_OUT" | rg -q ' _dt_r24_launchd_initialize_current_boot_runtime$'
strings "$HOOK_OUT" | rg -q 'R24_LIVE_INJECTION_STATE=PASS'
strings "$HOOK_OUT" | rg -q 'R24_GIN_EARLY_BOOT=NO'
strings "$HOOK_OUT" | rg -q 'R24_LAUNCHD_UUID_VALID=PASS'
strings "$HOOK_OUT" | rg -q 'DOPAMINE_INITIALIZED'
strings "$HOOK_OUT" | rg -q 'LAUNCHD_UUID'
strings "$HOOK_OUT" | rg -q 'R24_CONSOLE_MIRROR_LAUNCHD=YES'
strings "$HOOK_OUT" | rg -q 'R24_CONSOLE_MIRROR_ALL_LAUNCHD_DIAGNOSTICS=YES'
strings "$HOOK_OUT" | rg -q 'R24_SPAWN_HOOK_PATCH_BEGIN'
strings "$HOOK_OUT" | rg -q 'CBR_MSHOOK_PATCH=PASS'
strings "$HOOK_OUT" | rg -q 'CBR_MSHOOK_PATCH=FAIL'
strings "$HOOK_OUT" | rg -q 'R24_SPAWN_HOOK_ENTER'
strings "$HOOK_OUT" | rg -q 'R24_CHILD_DYLD_PROBE=MERGED_DYLD_CONFIRMED'
strings "$HOOK_OUT" | rg -q 'R24_CHILD_DYLD_PROBE=STOCK_DYLD_CONFIRMED'
strings "$HOOK_OUT" | rg -q 'R24_CHILD_DYLD_PROBE=DYLD_INFO_NOT_READY'
strings "$HOOK_OUT" | rg -q 'R24_CHILD_DYLD_PROBE=TASK_ACCESS_FAILED'
strings "$HOOK_OUT" | rg -q 'R24_CHILD_DYLD_PROBE=REMOTE_READ_FAILED'
strings "$HOOK_OUT" | rg -q 'R24_CHILD_DYLD_PROBE=UNKNOWN_DYLD_UUID'
strings "$HOOK_OUT" | rg -q '/private/var/jb/.r24_runtime_trace'
nm -gU "$HOOK_OUT" | rg -q ' _dt_r24_trace_event$'
! strings "$HOOK_OUT" | rg -q '/var/jb/basebin/systemhook.dylib'
strings "$SH_OUT" | rg -q '/usr/lib/systemhook.dylib'
! strings "$SH_OUT" | rg -q '/var/jb/basebin/systemhook.dylib'
strings "$SH_OUT" | rg -q 'R24_DYLDHOOK_JBINFO=PASS'
strings "$SH_OUT" | rg -q 'R24_DYLDHOOK_JBINFO=FALLBACK_DIRECT'
strings "$SH_OUT" | rg -q 'SYSTEMHOOK_CBR_CTOR'
strings "$SH_OUT" | rg -q 'R24_CONSOLE_MIRROR_SYSTEMHOOK=YES'
strings "$SH_OUT" | rg -q 'R24_SPAWN_SHARED_ENTER'
strings "$SH_OUT" | rg -q 'R24_SPAWN_SYSTEMHOOK_ACCESS=PASS'
strings "$SH_OUT" | rg -q 'R24_SPAWN_SYSTEMHOOK_ACCESS=FAIL'
strings "$SH_OUT" | rg -q 'R24_SPAWN_INJECT_DECISION='
strings "$SH_OUT" | rg -q 'R24_SPAWN_ENV_ACTION=INSERT_SYSTEMHOOK'
strings "$SH_OUT" | rg -q 'R24_SPAWN_ORIG_RETURN'
strings "$SH_OUT" | rg -q 'R24_POSIX_SPAWN_RETURN'
strings "$SH_OUT" | rg -q 'R24_JBS_PROCESS_CHECKIN=PASS'
strings "$SH_OUT" | rg -q 'R24_JBROOT_GENERATION_MATCH=PASS'
strings "$SH_OUT" | rg -q 'R24_BOOT_UUID_MATCH=PASS'
strings "$SH_OUT" | rg -q 'R24_CONTROLLED_CHILD_INJECTION=PASS'
strings "$SH_OUT" | rg -q '.r24_current_boot_runtime_probe_pass'
strings "$SH_OUT" | rg -q '/private/var/jb/.r24_runtime_trace'
nm -gU "$SH_OUT" | rg -q ' _dt_r24_trace_event$'
nm -gU "$SH_OUT" | rg -q ' _dt_r24_is_controlled_probe$'
nm -gU "$SH_OUT" | rg -q ' _dt_r24_systemhook_validate_controlled_probe_checkin$'
! strings "$SH_OUT" | rg -q 'TweakLoader.dylib'
strings "$LIBJB_OUT" | rg -q '/var/jb'
strings "$LIBJB_OUT" | rg -q 'dopamin-tvos-102710/procursus'
nm -gU "$LIBJB_OUT" | rg -q ' _get_jbroot$'
nm -gU "$HOOK_OUT" | rg -q ' _initXPCHooks$'
nm -gU "$HOOK_OUT" | rg -q ' _initSpawnHooks$'
# Fail closed: SDK must be Theos 16.4-class (not Xcode 18.5)
"$VTOOL" -show-build "$HOOK_OUT" 2>/dev/null | rg -q 'sdk 1[46]\.' || {
  echo "ERROR: launchdhook SDK not 14.x/16.x (Theos AppleTVOS16.4 expected)" >&2
  "$VTOOL" -show-build "$HOOK_OUT" || true
  exit 1
}
"$VTOOL" -show-build "$SH_OUT" 2>/dev/null | rg -q 'sdk 1[46]\.' || {
  echo "ERROR: systemhook SDK not 14.x/16.x" >&2
  exit 1
}

# Reject stale minimal-only / pre-CBR hook hashes
NEW_SHA=$(shasum -a 256 "$HOOK_OUT" | awk '{print $1}')
SH_SHA=$(shasum -a 256 "$SH_OUT" | awk '{print $1}')
if [[ "$NEW_SHA" == "1aac987a875427fd4e1ffe67d2373f56cb0599ce856af31a094600d2d688141e" ]]; then
  echo "ERROR: rebuilt hook still matches stale minimal SHA" >&2
  exit 1
fi
if [[ "$NEW_SHA" == "5223b886123a4adf4b3a8b594d47f047cb9204c4d4e7c34e4b2c9be14b21f040" ]]; then
  echo "ERROR: hook SHA still matches pre-CBR R21/R23 hook — CBR sources not linked" >&2
  exit 1
fi

{
  echo "VARIANT=ROOTLESS_R24_CBR"
  echo "LAUNCHDHOOK516_BUILD_SOURCE=$SRC/launchdhook + $MIN + $CBR + $SHCBR + $GATE1_SRC/jbroot.c"
  echo "HOOK_ENGINE=litehook_theos_16.4"
  echo "HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib"
  echo "TWEAKLOADER=OFF"
  echo "launchdhook516.dylib=$NEW_SHA"
  echo "systemhook.dylib=$SH_SHA"
  echo "libjailbreak.dylib=$(shasum -a 256 "$LIBJB_OUT" | awk '{print $1}')"
  echo "libchoma.dylib=$(shasum -a 256 "$OUT/libchoma.dylib" | awk '{print $1}')"
  echo "dt_opainject516=$(shasum -a 256 "$OUT/dt_opainject516" | awk '{print $1}')"
  echo "dt_jbctl516=$(shasum -a 256 "$OUT/dt_jbctl516" | awk '{print $1}')"
} > "$OUT/ROOTLESS_R5_HANDOFF_MANIFEST.txt"
cp "$OUT/ROOTLESS_R5_HANDOFF_MANIFEST.txt" "$OUT/ROOTLESS_R24_CBR_HANDOFF_MANIFEST.txt"

bash "$KFD/scripts/write_hook_build_manifest.sh" "$HOOK_OUT" "$OUT/hook_build_manifest.txt" || true

echo "LAUNCHDHOOK516_NEW_SHA256=$NEW_SHA"
echo "SYSTEMHOOK_SHA256=$SH_SHA"
echo "ROOTLESS_R24_HANDOFF_OUT=$OUT"
ls -la "$OUT"/launchdhook516.dylib "$OUT"/systemhook.dylib "$OUT"/libjailbreak.dylib "$OUT"/dt_opainject516
