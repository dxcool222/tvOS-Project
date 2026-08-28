#include <libjailbreak/jbserver.h>
#include <mach-o/dyld.h>
#include <mach/message.h>
#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <os/log.h>

#include "dt_cbr_mshook.h"
#include "xpc_hook.h"
#include "dt_runtime_trace.h"

/* Private libdispatch — same extern Dopamine xpc_hook.c uses. */
mach_msg_header_t *dispatch_mach_msg_get_msg(void *message, size_t *size_ptr);

int jbserver_received_mach_message(audit_token_t *auditToken, struct jbserver_mach_msg *jbsMachMsg);

int xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);
static int (*xpc_receive_mach_msg_orig)(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);

static int xpc_receive_mach_msg_hook(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut)
{
	size_t msgBufSize = 0;
	struct jbserver_mach_msg *jbsMachMsg =
	    (struct jbserver_mach_msg *)dispatch_mach_msg_get_msg(msg, &msgBufSize);
	bool wasProcessed = false;
	if (jbsMachMsg != NULL && msgBufSize >= sizeof(mach_msg_header_t)) {
		size_t msgSize = jbsMachMsg->hdr.msgh_size;
		if (msgSize <= msgBufSize && msgSize >= sizeof(struct jbserver_mach_msg) &&
		    jbsMachMsg->magic == JBSERVER_MACH_MAGIC) {
			(void)dt_r24_trace_event("LAUNCHD_XPC", "JBS_MACH_MESSAGE_MATCH", 0, 0,
			    "dispatch_mach_msg_get_msg");
			mach_msg_context_trailer_t *trailer =
			    (mach_msg_context_trailer_t *)((uint8_t *)jbsMachMsg +
							   round_msg(jbsMachMsg->hdr.msgh_size));
			jbserver_received_mach_message(&trailer->msgh_audit, jbsMachMsg);
			wasProcessed = true;
		}
	}

	int r = xpc_receive_mach_msg_orig(msg, a2, a3, a4, xOut);
	if (!wasProcessed && r == 0 && xOut && *xOut) {
		if (jbserver_received_xpc_message(&gGlobalServer, *xOut) == 0) {
			(void)dt_r24_trace_event("LAUNCHD_XPC", "JBS_XPC_MESSAGE_HANDLED", 0, 0,
			    "jbserver_received_xpc_message");
			xpc_release(*xOut);
			return 22;
		}
	}
	return r;
}

int initXPCHooks(void)
{
	os_log(OS_LOG_DEFAULT, "STAGE R24_XPC_HOOK_PATCH_BEGIN");
	int patch_result = dt_cbr_MSHookFunction((void *)xpc_receive_mach_msg,
	    (void *)xpc_receive_mach_msg_hook, (void **)&xpc_receive_mach_msg_orig);
	if (patch_result != 0) {
		fprintf(stderr, "XPC_HOOK_INSTALL_VERIFIED=NO rc=%d\n", patch_result);
		os_log(OS_LOG_DEFAULT, "STAGE XPC_HOOK_INSTALL_VERIFIED=NO rc=%{public}d",
		    patch_result);
		(void)dt_r24_trace_event("LAUNCHD_XPC", "HOOK_INSTALL_FAIL", patch_result, 0,
		    "xpc_receive_mach_msg");
		return patch_result;
	}
	fprintf(stderr, "XPC_HOOK_INSTALL_VERIFIED=YES\n");
	os_log(OS_LOG_DEFAULT, "STAGE XPC_HOOK_INSTALL_VERIFIED=YES");
	(void)dt_r24_trace_event("LAUNCHD_XPC", "HOOK_INSTALL_VERIFIED", 0, 0,
	    "xpc_receive_mach_msg import_rebind_count_nonzero");
#ifdef DT_BUILD102735D_TRACE
	extern void dt102735d_trace_event(const char *event, int rc);
	dt102735d_trace_event("XPC_HOOK_INSTALL_VERIFIED_YES", 0);
#endif
	return 0;
}
