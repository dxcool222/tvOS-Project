#pragma once

#include <mach/mach.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

kern_return_t dt_mach_thread_create(mach_port_t target_task, thread_act_t *new_thread);
kern_return_t dt_mach_thread_create_running(mach_port_t target_task, thread_state_flavor_t flavor,
    thread_state_t state, mach_msg_type_number_t state_count, thread_act_t *new_thread);
kern_return_t dt_mach_thread_resume(thread_act_t target_act);
kern_return_t dt_mach_thread_suspend(thread_act_t target_act);
kern_return_t dt_mach_thread_abort(thread_act_t target_act);

#ifdef __cplusplus
}
#endif
