#include "dt_mach_thread_shim.h"

typedef kern_return_t (*dt_mach_thread_create_fn)(mach_port_t, thread_act_t *);
typedef kern_return_t (*dt_mach_thread_create_running_fn)(mach_port_t, thread_state_flavor_t,
    thread_state_t, mach_msg_type_number_t, thread_act_t *);
typedef kern_return_t (*dt_mach_thread_resume_fn)(thread_act_t);
typedef kern_return_t (*dt_mach_thread_suspend_fn)(thread_act_t);
typedef kern_return_t (*dt_mach_thread_abort_fn)(thread_act_t);

static void *dt_mach_resolve(const char *sym)
{
    return dlsym(RTLD_DEFAULT, sym);
}

kern_return_t dt_mach_thread_create(mach_port_t target_task, thread_act_t *new_thread)
{
    static dt_mach_thread_create_fn fn;
    if (!fn)
        fn = (dt_mach_thread_create_fn)dt_mach_resolve("thread_create");
    return fn ? fn(target_task, new_thread) : KERN_FAILURE;
}

kern_return_t dt_mach_thread_create_running(mach_port_t target_task, thread_state_flavor_t flavor,
    thread_state_t state, mach_msg_type_number_t state_count, thread_act_t *new_thread)
{
    static dt_mach_thread_create_running_fn fn;
    if (!fn)
        fn = (dt_mach_thread_create_running_fn)dt_mach_resolve("thread_create_running");
    return fn ? fn(target_task, flavor, state, state_count, new_thread) : KERN_FAILURE;
}

kern_return_t dt_mach_thread_resume(thread_act_t target_act)
{
    static dt_mach_thread_resume_fn fn;
    if (!fn)
        fn = (dt_mach_thread_resume_fn)dt_mach_resolve("thread_resume");
    return fn ? fn(target_act) : KERN_FAILURE;
}

kern_return_t dt_mach_thread_suspend(thread_act_t target_act)
{
    static dt_mach_thread_suspend_fn fn;
    if (!fn)
        fn = (dt_mach_thread_suspend_fn)dt_mach_resolve("thread_suspend");
    return fn ? fn(target_act) : KERN_FAILURE;
}

kern_return_t dt_mach_thread_abort(thread_act_t target_act)
{
    static dt_mach_thread_abort_fn fn;
    if (!fn)
        fn = (dt_mach_thread_abort_fn)dt_mach_resolve("thread_abort");
    return fn ? fn(target_act) : KERN_FAILURE;
}
