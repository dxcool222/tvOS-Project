#include "jbserver.h"
#include "jbserver_domains.h"
#include "util.h"
#include <stdio.h>

#ifdef DT_BUILD102737D_TELEMETRY
extern int dt102737d_server_reply_sent;
extern int dt102737d_server_last_stage;
extern int dt102737d_server_last_rc;

#define DT102737D_STAGE_REPLY_CREATE 10
#define DT102737D_STAGE_REPLY_SEND 11

static bool dt102737d_is_get_physrw(uint64_t domainIdx, uint64_t actionIdx)
{
	return domainIdx == JBS_DOMAIN_ROOT && actionIdx == JBS_ROOT_GET_PHYSRW;
}

static void dt102737d_server_stage_result(const char *name, int stage, int rc, bool pass)
{
	dt102737d_server_last_stage = stage;
	dt102737d_server_last_rc = rc;
	fprintf(stderr, "BUILD102737D_PTE_STAGE_%s_RC=%d\n", name, rc);
	fprintf(stderr, "BUILD102737D_PTE_STAGE_%s_RESULT=%s\n", name,
	    pass ? "PASS" : "FAIL");
}
#endif

int jbserver_received_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg)
{
	if (xpc_get_type(xmsg) != XPC_TYPE_DICTIONARY) return -1;

	if (!xpc_dictionary_get_value(xmsg, "jb-domain")) return -1;
	if (!xpc_dictionary_get_value(xmsg, "action")) return -1;

	uint64_t domainIdx = xpc_dictionary_get_uint64(xmsg, "jb-domain");
	if (domainIdx == 0) return -1;
	struct jbserver_domain *domain = server->domains[0];
	for (int i = 1; i < domainIdx && domain; i++) {
		domain = server->domains[i];
	}
	if (!domain) return -1;

	audit_token_t clientToken = { 0 };
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

	if (domain->permissionHandler) {
		if (!domain->permissionHandler(clientToken)) return -2;
	}

	uint64_t actionIdx = xpc_dictionary_get_uint64(xmsg, "action");
	if (actionIdx == 0) return -1;
	struct jbserver_action *action = &domain->actions[0];
	for (int i = 1; i < actionIdx && action->handler; i++) {
		action = &domain->actions[i];
	}
	if (!action->handler) return -1;

	int (*handler)(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8) = action->handler;
	void *args[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	void *argsOut[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

	for (uint64_t i = 0; action->args[i].name && i < 8; i++) {
		jbserver_arg *argDesc = &action->args[i];
		if (!argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				args[i] = (void *)xpc_dictionary_get_bool(xmsg, argDesc->name);
				break;
				case JBS_TYPE_UINT64:
				args[i] = (void *)xpc_dictionary_get_uint64(xmsg, argDesc->name);
				break;
				case JBS_TYPE_FD:
				args[i] = (void *)(int64_t)xpc_dictionary_dup_fd(xmsg, argDesc->name);
				break;
				case JBS_TYPE_STRING:
				args[i] = (void *)xpc_dictionary_get_string(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DATA: { // Data occupies 2 arguments (buf, len)
					if (i < 7) {
						args[i] = (void *)xpc_dictionary_get_data(xmsg, argDesc->name, (size_t *)&args[i+1]); i++;
					}
					break;
				}
				case JBS_TYPE_ARRAY:
				args[i] = (void *)xpc_dictionary_get_array(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DICTIONARY:
				args[i] = (void *)xpc_dictionary_get_dictionary(xmsg, argDesc->name);
				break;
				case JBS_TYPE_XPC_GENERIC:
				args[i] = (void *)xpc_dictionary_get_value(xmsg, argDesc->name);
				break;
				case JBS_TYPE_CALLER_TOKEN:
				args[i] = (void *)&clientToken;
				break;
			}
		}
		else {
			args[i] = &argsOut[i];
		}
	}

	int result = handler(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);

#ifdef DT_BUILD102737D_TELEMETRY
	bool dt102737d_get_physrw = dt102737d_is_get_physrw(domainIdx, actionIdx);
	if (dt102737d_get_physrw) {
		dt102737d_server_last_stage = DT102737D_STAGE_REPLY_CREATE;
		fprintf(stderr, "BUILD102737D_PTE_STAGE_REPLY_DICTIONARY_BEGIN=YES\n");
	}
#endif
	xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);
#ifdef DT_BUILD102737D_TELEMETRY
	if (dt102737d_get_physrw)
		dt102737d_server_stage_result("REPLY_DICTIONARY",
		    DT102737D_STAGE_REPLY_CREATE, xreply ? 0 : -1, xreply != NULL);
#endif
	for (uint64_t i = 0; action->args[i].name && i < 8; i++) {
		jbserver_arg *argDesc = &action->args[i];
		if (argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				xpc_dictionary_set_bool(xreply, argDesc->name, (bool)argsOut[i]);
				break;
				case JBS_TYPE_UINT64:
				xpc_dictionary_set_uint64(xreply, argDesc->name, (uint64_t)argsOut[i]);
				break;
				case JBS_TYPE_FD: {
					xpc_dictionary_set_fd(xreply, argDesc->name, (int)(int64_t)argsOut[i]);
					close((int)(int64_t)argsOut[i]);
					break;
				}
				case JBS_TYPE_STRING: {
					if (argsOut[i]) {
						xpc_dictionary_set_string(xreply, argDesc->name, (char *)argsOut[i]);
						free(argsOut[i]);
					}
					break;
				}
				case JBS_TYPE_DATA: {
					if (i < 7) {
						if (argsOut[i] && action->args[i+1].name) {
							xpc_dictionary_set_data(xreply, argDesc->name, (const void *)argsOut[i], (size_t)argsOut[i+1]);
							free(argsOut[i]);
						}
					}
					break;
				}
				case JBS_TYPE_ARRAY:
				case JBS_TYPE_DICTIONARY:
				case JBS_TYPE_XPC_GENERIC: {
					if (argsOut[i]) {
						xpc_dictionary_set_value(xreply, argDesc->name, (xpc_object_t)argsOut[i]);
						xpc_release((xpc_object_t)argsOut[i]);
					}
					break;
				}
				default:
				break;
			}
		}
		else {
			if (argDesc->type == JBS_TYPE_FD) {
				close((int)(int64_t)args[i]);
			}
		}
	}
	xpc_dictionary_set_int64(xreply, "result", result);
#ifdef DT_BUILD102737D_TELEMETRY
	if (dt102737d_get_physrw) {
		dt102737d_server_last_stage = DT102737D_STAGE_REPLY_SEND;
		fprintf(stderr, "BUILD102737D_PTE_STAGE_REPLY_SEND_BEGIN=YES\n");
	}
#endif
	xpc_pipe_routine_reply(xreply);
#ifdef DT_BUILD102737D_TELEMETRY
	if (dt102737d_get_physrw) {
		dt102737d_server_reply_sent = 1;
		dt102737d_server_stage_result("REPLY_SEND", DT102737D_STAGE_REPLY_SEND,
		    0, true);
		fprintf(stderr, "BUILD102737D_PTE_SERVER_REPLY_SENT=YES\n");
	}
#endif
	xpc_release(xreply);

	return 0;
}
