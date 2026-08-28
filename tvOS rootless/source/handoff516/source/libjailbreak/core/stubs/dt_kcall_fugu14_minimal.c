// Minimal Fugu14 kcall return-thread support for arm64_kcall (tvOS libjailbreak).
#include "kcall_Fugu14.h"
#include "primitives.h"
#include "translation.h"
#include "kernel.h"
#include "util.h"
#include "dt_mach_thread_shim.h"

#include <mach/arm/thread_status.h>
#include <string.h>

uint64_t task_self(void);
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

Fugu14KcallThread gFugu14KcallThread;

uint64_t gUserReturnThreadContext = 0;
volatile uint64_t gUserReturnDidHappen = 0;

extern void pac_loop(void);

#define guard(cond) if (__builtin_expect(!!(cond), 1)) {}

uint64_t getUserReturnThreadContext(void)
{
    if (gUserReturnThreadContext != 0)
        return gUserReturnThreadContext;

    arm_thread_state64_t state;
    bzero(&state, sizeof(state));

    arm_thread_state64_set_pc_fptr(state, (void *)pac_loop);
    for (size_t i = 0; i < 29; i++)
        state.__x[i] = 0xDEADBEEF00ULL | i;

    thread_t chThread = 0;
    kern_return_t kr = dt_mach_thread_create_running(mach_task_self_, ARM_THREAD_STATE64,
        (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &chThread);
    guard(kr == KERN_SUCCESS) else {
        return 0;
    }

    dt_mach_thread_suspend(chThread);

    uint64_t returnThreadPtr = task_get_ipc_port_kobject(task_self(), chThread);
    guard(returnThreadPtr != 0) else {
        return 0;
    }

    uint64_t returnThreadACTContext = kread_ptr(returnThreadPtr + koffsetof(thread, machine_contextData));
    guard(returnThreadACTContext != 0) else {
        return 0;
    }

    gUserReturnThreadContext = returnThreadACTContext;
    return returnThreadACTContext;
}

int fugu14_kcall_init(int (^threadSigner)(mach_port_t threadPort))
{
    (void)threadSigner;
    return -1;
}

int jbclient_get_fugu14_kcall(void)
{
    return -1;
}

uint64_t fugu14_kcall(uint64_t func, int argc, const uint64_t *argv)
{
    (void)func;
    (void)argc;
    (void)argv;
    return (uint64_t)-1;
}

void fugu14_kexec(kRegisterState *threadState)
{
    (void)threadState;
}
