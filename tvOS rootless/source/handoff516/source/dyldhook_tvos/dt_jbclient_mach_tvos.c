#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <libjailbreak/jbserver.h>

/* The tvOS SDK marks several public Mach declarations unavailable even though
 * the exact dyld carries the symbols used by Dopamine's iOS 16 hook.  Unique C
 * names avoid importing those availability attributes; asm labels preserve the
 * upstream ABI and are resolved by MachOMerger trampolines/reimplementations. */
extern kern_return_t dt_task_get_special_port(task_inspect_t, int, mach_port_t *)
    __asm("_task_get_special_port");
extern mach_msg_return_t dt_mach_msg(mach_msg_header_t *, mach_msg_option_t,
    mach_msg_size_t, mach_msg_size_t, mach_port_name_t, mach_msg_timeout_t,
    mach_port_name_t) __asm("_mach_msg");
extern mach_port_t dt_mig_get_reply_port(void) __asm("_mig_get_reply_port");
extern void dt_mach_msg_destroy(mach_msg_header_t *) __asm("_mach_msg_destroy");
extern kern_return_t dt_mach_port_deallocate(mach_port_t, mach_port_name_t)
    __asm("_mach_port_deallocate");
extern mach_port_t dt_task_self_trap(void) __asm("_task_self_trap");

static mach_port_t launchd_port(void)
{
	mach_port_t port = MACH_PORT_NULL;
	(void)dt_task_get_special_port(dt_task_self_trap(), TASK_BOOTSTRAP_PORT, &port);
	return port;
}

static kern_return_t send_message(mach_msg_header_t *hdr,
	struct jbserver_mach_msg_reply *reply)
{
	mach_port_t replyPort = dt_mig_get_reply_port();
	mach_port_t launchdPort = launchd_port();
	if (!replyPort || !launchdPort) return KERN_FAILURE;
	hdr->msgh_bits |= MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE);
	hdr->msgh_remote_port = launchdPort;
	hdr->msgh_local_port = replyPort;
	hdr->msgh_voucher_port = 0;
	hdr->msgh_id = 0x40000000 | 206;
	kern_return_t kr = dt_mach_msg(hdr, MACH_SEND_MSG, hdr->msgh_size,
	    0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
	if (kr == KERN_SUCCESS) {
		kr = dt_mach_msg(&reply->msg.hdr, MACH_RCV_MSG, 0,
		    reply->msg.hdr.msgh_size, replyPort, 0, MACH_PORT_NULL);
	}
	if (kr == KERN_SUCCESS) dt_mach_msg_destroy(&reply->msg.hdr);
	(void)dt_mach_port_deallocate(dt_task_self_trap(), launchdPort);
	return kr;
}

int jbclient_mach_process_checkin(char *rootOut, char *bootOut,
	char *extensionsOut, bool *fullyDebuggedOut)
{
	struct jbserver_mach_msg_checkin msg = {0};
	msg.base.hdr.msgh_size = sizeof(msg);
	msg.base.action = JBSERVER_MACH_CHECKIN;
	msg.base.magic = JBSERVER_MACH_MAGIC;
	uint8_t storage[sizeof(struct jbserver_mach_msg_checkin_reply)
	    + MAX_TRAILER_SIZE] = {0};
	struct jbserver_mach_msg_checkin_reply *reply = (void *)storage;
	reply->base.msg.hdr.msgh_size = sizeof(storage);
	kern_return_t kr = send_message(&msg.base.hdr,
	    (struct jbserver_mach_msg_reply *)reply);
	if (kr != KERN_SUCCESS) return kr;
	reply->jbRootPath[sizeof(reply->jbRootPath)-1] = '\0';
	reply->bootUUID[sizeof(reply->bootUUID)-1] = '\0';
	reply->sandboxExtensions[sizeof(reply->sandboxExtensions)-1] = '\0';
	if (rootOut) strcpy(rootOut, reply->jbRootPath);
	if (bootOut) strcpy(bootOut, reply->bootUUID);
	if (extensionsOut) strcpy(extensionsOut, reply->sandboxExtensions);
	if (fullyDebuggedOut) *fullyDebuggedOut = reply->fullyDebugged;
	return (int)reply->base.status;
}

int jbclient_mach_trust_file(int fd, struct siginfo *siginfo)
{
	struct jbserver_mach_msg_trust_fd msg = {0};
	msg.base.hdr.msgh_size = sizeof(msg);
	msg.base.action = JBSERVER_MACH_TRUST_FILE;
	msg.base.magic = JBSERVER_MACH_MAGIC;
	msg.fd = fd;
	msg.siginfoPopulated = siginfo != NULL;
	if (siginfo) memcpy(&msg.siginfo, siginfo, sizeof(*siginfo));
	uint8_t storage[sizeof(struct jbserver_mach_msg_trust_fd_reply)
	    + MAX_TRAILER_SIZE] = {0};
	struct jbserver_mach_msg_trust_fd_reply *reply = (void *)storage;
	reply->base.msg.hdr.msgh_size = sizeof(storage);
	kern_return_t kr = send_message(&msg.base.hdr,
	    (struct jbserver_mach_msg_reply *)reply);
	return kr == KERN_SUCCESS ? (int)reply->base.status : (int)kr;
}
