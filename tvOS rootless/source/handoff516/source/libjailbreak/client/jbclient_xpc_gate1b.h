#ifndef JBCLIENT_XPC_GATE1B_H
#define JBCLIENT_XPC_GATE1B_H

#include <xpc/xpc.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdbool.h>

extern mach_port_t gJBServerCustomPort;

void jbclient_xpc_set_custom_port(mach_port_t serverPort);

xpc_object_t jbserver_xpc_send_dict(xpc_object_t xdict);
xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t xargs);

int jbclient_root_get_physrw(bool singlePTE, uint64_t *singlePTEAsidPtr);
int jbclient_root_get_sysinfo(xpc_object_t *sysInfoOut);
int jbclient_boomerang_done(void);

int jbclient_initialize_primitives_gate1b(void);

#ifdef DT_BUILD102735D_TRACE
void dt_gate1b_client_trace_event(const char *event, int rc);
void dt_gate1b_client_trace_value(const char *event, int rc, long long value);
#endif

#endif
