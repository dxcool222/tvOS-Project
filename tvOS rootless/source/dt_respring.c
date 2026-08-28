/*
 * Misaka J respring (IDA J.i64):
 *   respring() -> animation -> restartFrontboard()
 *   restartFrontboard() -> xpc_crasher("com.apple.frontboard.systemappservices")
 * KFD path also calls do_kclose when kfd handle is active.
 */

#include "dt_respring.h"
#include "kfd_tvos.h"
#include "dt_kernel_exploit_gate.h"
#include "syscall_shim.h"

#include <bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdio.h>
#include <string.h>

static kern_return_t dt_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option,
    mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_name_t rcv_name,
    mach_msg_timeout_t timeout, mach_port_name_t notify)
{
    return (kern_return_t)kfd_syscall(-31, msg, option, send_size, rcv_size, rcv_name, timeout, notify);
}

static mach_port_name_t dt_get_send_once(mach_port_name_t recv)
{
    mach_port_t so = MACH_PORT_NULL;
    mach_msg_type_name_t poly = MACH_MSG_TYPE_PORT_SEND_ONCE;
    kern_return_t kr = mach_port_extract_right(mach_task_self(), recv, MACH_MSG_TYPE_MAKE_SEND_ONCE, &so, &poly);
    if (kr != KERN_SUCCESS) {
        printf("[dt_respring] port right extraction failed: %s\n", mach_error_string(kr));
        return MACH_PORT_NULL;
    }
    return so;
}

static int dt_xpc_crasher(const char *service)
{
    mach_port_t sp = MACH_PORT_NULL;
    mach_port_name_t name = MACH_PORT_NULL;
    mach_port_name_t reply = MACH_PORT_NULL;

    kern_return_t kr = bootstrap_look_up(bootstrap_port, service, &sp);
    if (kr != KERN_SUCCESS || sp == MACH_PORT_NULL) {
        printf("[dt_respring] unable to look up %s: %s\n", service, mach_error_string(kr));
        return -1;
    }

    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name);
    if (kr != KERN_SUCCESS) {
        printf("[dt_respring] port allocation failed: %s\n", mach_error_string(kr));
        return -1;
    }

    mach_port_name_t send_once_a = dt_get_send_once(name);
    mach_port_name_t send_once_b = dt_get_send_once(name);

    kr = mach_port_insert_right(mach_task_self(), name, name, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        printf("[dt_respring] port right insertion failed: %s\n", mach_error_string(kr));
        return -1;
    }

    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
    if (kr != KERN_SUCCESS) {
        printf("[dt_respring] reply port allocation failed: %s\n", mach_error_string(kr));
        return -1;
    }

    /* Misaka _xpc_crasher @ 0x100007964 — 52-byte complex mach message, magic 0x77303077 ('w00t') */
    uint8_t buf[52];
    memset(buf, 0, sizeof(buf));
    *(uint32_t *)&buf[0] = 0x80000013u;
    *(uint32_t *)&buf[4] = 52u;
    *(uint32_t *)&buf[8] = sp;
    *(uint32_t *)&buf[20] = 0x77303077u;
    *(uint32_t *)&buf[24] = 2u;
    *(uint32_t *)&buf[28] = name;
    *(uint32_t *)&buf[36] = (*(uint32_t *)&buf[36] & 0xFF00FFFFu) | 0x100000u;
    *(uint32_t *)&buf[36] &= 0xFFFFFFu;
    *(uint32_t *)&buf[40] = reply;
    *(uint32_t *)&buf[48] = (*(uint32_t *)&buf[48] & 0xFF00FFFFu) | 0x140000u;
    *(uint32_t *)&buf[48] &= 0xFFFFFFu;

    kr = dt_mach_msg((mach_msg_header_t *)buf, MACH_SEND_MSG, 52, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[dt_respring] w00t message send failed: %s\n", mach_error_string(kr));
        return -1;
    }

    if (send_once_a) mach_port_deallocate(mach_task_self(), send_once_a);
    if (send_once_b) mach_port_deallocate(mach_task_self(), send_once_b);
    return 0;
}

static void dt_restart_frontboard(void)
{
    dt_xpc_crasher("com.apple.frontboard.systemappservices");
}

void dt_respring(void)
{
    if (dt_kernel_exploit_is_active()) {
        exploit_deinit();
    }
    dt_restart_frontboard();
}
