#include "jbserver_boomerang.h"
#include "info.h"
#include "kernel.h"
#include "util.h"
#include "primitives.h"
#include "physrw.h"
#include "physrw_pte.h"
#include "jbserver_domains.h"
#include <bsm/audit.h>
#include <stdio.h>

#ifdef DT_BUILD102737D_TELEMETRY
int dt102737d_server_pte_request_reached;
int dt102737d_server_handoff_generated;
int dt102737d_server_reply_sent;
int dt102737d_server_client_pid;
int dt102737d_server_single_pte;
int dt102737d_server_last_stage;
int dt102737d_server_last_rc = -9999;
uint64_t dt102737d_server_asid_ptr;

#define DT102737D_STAGE_NONE 0
#define DT102737D_STAGE_PROC 1
#define DT102737D_STAGE_TASK 2
#define DT102737D_STAGE_VMMAP 3
#define DT102737D_STAGE_PMAP 4
#define DT102737D_STAGE_TTEP 5
#define DT102737D_STAGE_EXPAND 6
#define DT102737D_STAGE_MAGIC_PTE 7
#define DT102737D_STAGE_ASID 8
#define DT102737D_STAGE_SERIALIZE 9
#define DT102737D_STAGE_REPLY_CREATE 10
#define DT102737D_STAGE_REPLY_SEND 11

static const char *dt102737d_server_result_name(int r)
{
	switch (r) {
	case 0:
		return "PASS";
	case -1:
	case -2:
		return "PROC_FAIL";
	case -3:
		return "TASK_FAIL";
	case -4:
		return "VMMAP_FAIL";
	case -5:
		return "PMAP_FAIL";
	case -6:
		return "EXPAND_FAIL";
	case -7:
		return "MAGIC_PTE_FAIL";
	default:
		return "OTHER_FAIL";
	}
}
#endif

// Implements JBS_DOMAIN_ROOT, but only the functionality required for boomerang
// Exports symbols so that the logic can be reused by launchdhook

static bool boomerang_domain_allowed(audit_token_t clientToken)
{
	// This server is both used from launchd to boomerang and boomerang back to launchd
	// Ensure one of the participants in this communication is launchd
	return (audit_token_to_pid(clientToken) == 1) || (getpid() == 1);
}

int boomerang_get_physrw(audit_token_t *clientToken, bool singlePTE, uint64_t *singlePTEAsidPtr)
{
	int r = -1;
	pid_t pid = audit_token_to_pid(*clientToken);
#ifdef DT_BUILD102737D_TELEMETRY
	dt102737d_server_pte_request_reached = 1;
	dt102737d_server_handoff_generated = 0;
	dt102737d_server_reply_sent = 0;
	dt102737d_server_client_pid = pid;
	dt102737d_server_single_pte = singlePTE ? 1 : 0;
	dt102737d_server_last_stage = DT102737D_STAGE_NONE;
	dt102737d_server_last_rc = -9999;
	dt102737d_server_asid_ptr = 0;
	fprintf(stderr, "BUILD102737D_SERVER_GET_PHYSRW_REQUEST_RECEIVED=YES\n");
	fprintf(stderr, "BUILD102737D_SERVER_GET_PHYSRW_DOMAIN=%u\n", JBS_DOMAIN_ROOT);
	fprintf(stderr, "BUILD102737D_SERVER_GET_PHYSRW_ACTION=%u\n", JBS_ROOT_GET_PHYSRW);
	fprintf(stderr, "BUILD102737D_SERVER_SINGLE_PTE_VALUE=%s\n", singlePTE ? "YES" : "NO");
	fprintf(stderr, "BUILD102737D_SERVER_GET_PHYSRW_CLIENT_PID=%d\n", pid);
#endif

	thread_caffeinate_start();
	if (singlePTE) {
#ifdef DT_BUILD102737D_TELEMETRY
		fprintf(stderr, "BUILD102737D_SERVER_PHYSRW_PTE_HANDOFF_BEGIN=YES\n");
#endif
		r = physrw_pte_handoff(pid, singlePTEAsidPtr);
#ifdef DT_BUILD102737D_TELEMETRY
		if (singlePTEAsidPtr)
			dt102737d_server_asid_ptr = *singlePTEAsidPtr;
		dt102737d_server_handoff_generated = (r == 0) ? 1 : 0;
#endif
	}
	else {
		r = physrw_handoff(pid);
	}
	thread_caffeinate_stop();
#ifdef DT_BUILD102737D_TELEMETRY
	dt102737d_server_last_rc = r;
	fprintf(stderr, "BUILD102737D_SERVER_PTE_HANDOFF_RESULT=%s\n",
	    dt102737d_server_result_name(r));
	fprintf(stderr, "BUILD102737D_PTE_SERVER_HANDOFF_GENERATED=%s\n",
	    r == 0 ? "YES" : "NO");
	fprintf(stderr, "BUILD102737D_PTE_SERVER_LAST_RC=%d\n", r);
	fprintf(stderr, "BUILD102737D_PTE_CLIENT_ASID_PTR=0x%llx\n",
	    (unsigned long long)dt102737d_server_asid_ptr);
#endif

	return r;
}

int boomerang_sign_thread(audit_token_t *clientToken, mach_port_t threadPort)
{
	pid_t pid = audit_token_to_pid(*clientToken);
	uint64_t proc = proc_find(pid);
	if (proc) {
		int r = sign_kernel_thread(proc, threadPort);
		proc_rele(proc);
		return r;
	}
	return -1;
}

int boomerang_get_sysinfo(xpc_object_t *sysInfoOut)
{
	xpc_object_t sysInfo = xpc_dictionary_create_empty();
	SYSTEM_INFO_SERIALIZE(sysInfo);
	*sysInfoOut = sysInfo;
	return 0;
}

struct jbserver_domain gUnusedDomain = {
	.permissionHandler = NULL,
	.actions = {
		{ 0 },
	},
};

struct jbserver_domain gBoomerangDomain = {
	.permissionHandler = boomerang_domain_allowed,
	.actions = {
		// JBS_ROOT_GET_PHYSRW
		{
			.handler = boomerang_get_physrw,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "single-pte", .type = JBS_TYPE_BOOL, .out = false },
				{ .name = "single-pte-asid-ptr", .type = JBS_TYPE_UINT64, .out = true },
				{ 0 },
			},
		},
		// JBS_ROOT_SIGN_THREAD
		{
			.handler = boomerang_sign_thread,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "thread-port", .type = JBS_TYPE_UINT64, .out = false },
				{ 0 },
			},
		},
		// JBS_ROOT_GET_SYSINFO
		{
			.handler = boomerang_get_sysinfo,
			.args = (jbserver_arg[]){
				{ .name = "sysinfo", .type = JBS_TYPE_DICTIONARY, .out = true },
				{ 0 },
			},
		},
		{ 0 },
	},
};

struct jbserver_impl gBoomerangServer = {
	.maxDomain = 1,
	.domains = (struct jbserver_domain*[]){
		&gUnusedDomain,
		&gUnusedDomain,
		&gUnusedDomain,
		&gBoomerangDomain,
		NULL,
	}
};

int jbserver_received_boomerang_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg)
{
	int r = jbserver_received_xpc_message(server, xmsg);
	if (r != 0) {
		uint64_t action = xpc_dictionary_get_uint64(xmsg, "action");
		if (action == JBS_BOOMERANG_DONE) {
			xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);
			xpc_dictionary_set_uint64(xreply, "result", 0);
			xpc_pipe_routine_reply(xreply);
			xpc_release(xreply);
			return JBS_BOOMERANG_DONE;
		}
	}
	return r;
}
