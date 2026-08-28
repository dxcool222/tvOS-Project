#import "dt_baked_offsets.h"
#undef T1SZ_BOOT
#import "info.h"
#import "DTRunLogger.h"
#import <sys/sysctl.h>
#import <string.h>

bool g_dt_baked_offsets_active = false;

static const uint64_t kStaticBase = 0xfffffff007004000ULL;

static bool sysctl_string(const char *name, char *buf, size_t bufsz)
{
    size_t len = bufsz;
    return sysctlbyname(name, buf, &len, NULL, 0) == 0 && len > 0;
}

bool DTApplyBakedOffsetsForCurrentDevice(void)
{
    char machine[64] = {0};
    char osversion[64] = {0};
    if (!sysctl_string("hw.machine", machine, sizeof(machine))) return false;
    if (!sysctl_string("kern.osversion", osversion, sizeof(osversion))) return false;

    // tvOS 16.5 AppleTV6,2 build 20L563 — IDA on kernelcache.j105a.20L563.macho
    if (strcmp(machine, "AppleTV6,2") != 0) return false;
    if (strcmp(osversion, "20L563") != 0) return false;

    g_dt_baked_offsets_active = true;

    gSystemInfo.kernelConstant.staticBase = kStaticBase;
    gSystemInfo.kernelConstant.T1SZ_BOOT = 25;
    gSystemInfo.kernelConstant.ARM_TT_L1_INDEX_MASK = 0x0000007000000000ULL;
    gSystemInfo.kernelConstant.PT_INDEX_MAX = 1;
    gSystemInfo.kernelConstant.kernel_el = 1;

    // kernelSymbol.* = full unslid VAs (ksymbol = slide + VA)
    gSystemInfo.kernelSymbol.cdevsw = 0xfffffff007878e60ULL;
    gSystemInfo.kernelSymbol.gPhysBase = 0xfffffff007152c00ULL;
    gSystemInfo.kernelSymbol.gPhysSize = 0xfffffff007152c08ULL;
    gSystemInfo.kernelSymbol.gVirtBase = 0xfffffff007150e18ULL;
    gSystemInfo.kernelSymbol.perfmon_devices = 0xfffffff0078ba900ULL;
    gSystemInfo.kernelSymbol.perfmon_dev_open = 0xfffffff007324698ULL;
    gSystemInfo.kernelSymbol.ptov_table = 0xfffffff0071069a8ULL;
    gSystemInfo.kernelSymbol.vn_kqfilter = 0xfffffff00736f394ULL;

    // Plan B kcall (IDA XPF byte-verified j105a 2026-06-19 — PLAN_B_BUILD1025_IDA_CLOSURE.txt)
    gSystemInfo.kernelSymbol.exception_return = 0xfffffff0071b98ecULL;
    gSystemInfo.kernelSymbol.proc_find = 0xfffffff0075e44acULL;
    gSystemInfo.kernelGadget.str_x8_x0 = 0xfffffff005bb0d54ULL;
    gSystemInfo.kernelGadget.kcall_return = 0xfffffff005de1e90ULL;
    gSystemInfo.kernelStruct.thread.machine_contextData = 0xF0;
    gSystemInfo.kernelStruct.thread.machine_kstackptr = 0x130;

    // phys-rw / physmap (IDA-verified tvOS 20L563)
    gSystemInfo.kernelSymbol.allproc = 0xfffffff0078d8a70ULL;
    gSystemInfo.kernelSymbol.cpu_ttep = 0xfffffff007128010ULL;
    gSystemInfo.kernelSymbol.pmap_enter_options_addr = 0xfffffff0072fc814ULL;
    gSystemInfo.kernelSymbol.pmap_remove_options = 0xfffffff00730268cULL;
    gSystemInfo.kernelSymbol.vm_first_phys = 0xfffffff007128148ULL;
    gSystemInfo.kernelSymbol.vm_first_phys_ppnum = 0xfffffff0078b9f30ULL;
    gSystemInfo.kernelSymbol.vm_page_array_beginning_addr = 0xfffffff007105938ULL;
    gSystemInfo.kernelSymbol.vm_page_array_ending_addr = 0xfffffff0078b9f28ULL;
    gSystemInfo.kernelSymbol.pv_head_table = 0xfffffff007105908ULL;
    gSystemInfo.kernelSymbol.pp_attr_table = 0;
    gSystemInfo.kernelSymbol.vm_last_phys = 0;

    // Tier 3 trust-cache (Build 26 — IDA kernelcache.j105a.20L563.macho)
    gSystemInfo.kernelSymbol.ppl_trust_cache_rt = 0xfffffff007143c10ULL;
    gSystemInfo.kernelSymbol.pmap_image4_trust_caches = 0;

    // Struct layout — tvOS XNU 22.5 (not Dopamine iOS jbinfo defaults)
    gSystemInfo.kernelStruct.proc.list_next = 0x0;
    gSystemInfo.kernelStruct.proc.list_prev = 0x8;
    gSystemInfo.kernelStruct.proc.task = 0x0;
    gSystemInfo.kernelStruct.proc.pid = 0x60;
    gSystemInfo.kernelStruct.proc.struct_size = 0x720;
    gSystemInfo.kernelStruct.proc.fd = 0xd8;
    gSystemInfo.kernelStruct.filedesc.ofiles_start = 0x20;
    gSystemInfo.kernelStruct.task.map = 0x28;
    gSystemInfo.kernelStruct.vm_map.hdr = 0x10;
    gSystemInfo.kernelStruct.vm_map.pmap = 0x40;
    gSystemInfo.kernelStruct.vm_map_links.prev = 0x0;
    gSystemInfo.kernelStruct.vm_map_links.next = 0x8;
    gSystemInfo.kernelStruct.vm_map_links.min = 0x10;
    gSystemInfo.kernelStruct.vm_map_links.max = 0x18;
    gSystemInfo.kernelStruct.pmap.tte = 0x0;
    gSystemInfo.kernelStruct.pmap.ttep = 0x8;
    gSystemInfo.kernelStruct.pmap.sw_asid = 0x8E;
    gSystemInfo.kernelStruct.pmap.type = 0x94;

    return true;
}

void DTApplyTvOSPmapStructOverrides(void)
{
    if (!g_dt_baked_offsets_active) return;

    // pmap_switch_internal @ 0xfffffff007302A08; pmap_set_nested @ 0xfffffff007305880
    gSystemInfo.kernelStruct.pmap.tte = 0x0;
    gSystemInfo.kernelStruct.pmap.ttep = 0x8;
    gSystemInfo.kernelStruct.pmap.sw_asid = 0x8E;
    gSystemInfo.kernelStruct.pmap.type = 0x94;
    gSystemInfo.kernelStruct.vm_map.pmap = 0x40;
    gSystemInfo.kernelStruct.proc.task = 0x0;
    gSystemInfo.kernelStruct.proc.pid = 0x60;
    gSystemInfo.kernelStruct.proc.struct_size = 0x720;
    gSystemInfo.kernelStruct.task.map = 0x28;
    /* IDA 200D38 LDR [task,#0x300] — port_name_to_thread itk_space; misaka off_task_itk_space=768 */
    gSystemInfo.kernelStruct.task.itk_space = 0x300;
    /* IDA 200AF0 LDR [ipc_port,#0x48] — ip_kobject on j105a/tvOS 20L563 */
    gSystemInfo.kernelStruct.ipc_port.kobject = 0x48;
}

void DTApplyTvOSTrustcacheOverrides(void)
{
    if (!g_dt_baked_offsets_active) return;

    gSystemInfo.kernelSymbol.ppl_trust_cache_rt = 0xfffffff007143c10ULL;
    gSystemInfo.kernelSymbol.pmap_image4_trust_caches = 0;

    gSystemInfo.kernelStruct.trustcache.nextptr = 0x0;
    gSystemInfo.kernelStruct.trustcache.prevptr = 0x8;
    gSystemInfo.kernelStruct.trustcache.size = 0x18;
    gSystemInfo.kernelStruct.trustcache.fileptr = 0x20;
    gSystemInfo.kernelStruct.trustcache.struct_size = 0x28;
}

void DTApplyTvOSProcStructOverrides(void)
{
    if (!g_dt_baked_offsets_active) return;

    // XNU 22.x / tvOS 16.5 — matches misaka _offsets_init 16.4+ and jbinfo iOS 16 branch
    gSystemInfo.kernelStruct.proc.task = 0x0;
    gSystemInfo.kernelStruct.proc.proc_ro = 0x18;
    gSystemInfo.kernelStruct.proc.pid = 0x60;
    gSystemInfo.kernelStruct.proc.svuid = 0x3C;
    gSystemInfo.kernelStruct.proc.svgid = 0x40;
    gSystemInfo.kernelStruct.proc.flag = 0x25C;
    gSystemInfo.kernelStruct.proc.struct_size = 0x720;

    gSystemInfo.kernelStruct.proc_ro.exists = true;
    gSystemInfo.kernelStruct.proc_ro.ucred = 0x20;
    gSystemInfo.kernelStruct.proc_ro.csflags = 0x1C;

    gSystemInfo.kernelStruct.ucred.label = 0x78;
}

void DTApplyTvOSInpcbOverrides(void)
{
    if (!g_dt_baked_offsets_active)
        return;

    // kernelcache.j105a.20L563 — matches Dopamine iOS 16.x / DarkSword expectations
    gSystemInfo.kernelStruct.inpcb.list_next = 0x20;
    gSystemInfo.kernelStruct.inpcb.list_prev = 0x28;
    gSystemInfo.kernelStruct.inpcb.pcbinfo   = 0x38;
    gSystemInfo.kernelStruct.inpcb.socket    = 0x40;
    gSystemInfo.kernelStruct.inpcb.icmp6filt = 0x150;
    gSystemInfo.kernelStruct.inpcb.chksum    = 0x158;
    gSystemInfo.kernelStruct.inpcbinfo.ipi_zone = 0x68;
    gSystemInfo.kernelStruct.kalloc_type_view.kt_zv_zv_name = 0x10;
    gSystemInfo.kernelStruct.socket.proto    = 0x18;
    gSystemInfo.kernelStruct.socket.usecount = 0x22c;
    gSystemInfo.kernelStruct.protosw.input = 0x28;
}

void DTLogBakedStructOffsets(void)
{
    if (!g_dt_baked_offsets_active)
        return;
    dt_run_log("[*] baked offsets active (AppleTV6,2 / 20L563)");
}
