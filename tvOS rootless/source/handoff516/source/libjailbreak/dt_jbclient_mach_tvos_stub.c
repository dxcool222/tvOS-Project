/*
 * tvOS Gate1 stub — replaces Dopamine jbclient_mach.c (mach_msg unavailable on tvOS SDK).
 * Boomerang path uses jbclient_xpc_set_custom_port; fallback launchd bootstrap path unused.
 * REFERENCE: jbclient_mach.c (not compiled on tvOS).
 */
#include "jbclient_mach.h"
#include <mach/mach.h>

mach_port_t jbclient_mach_get_launchd_port(void)
{
	return MACH_PORT_NULL;
}

kern_return_t jbclient_mach_send_msg(mach_msg_header_t *hdr, struct jbserver_mach_msg_reply *reply)
{
	(void)hdr;
	(void)reply;
	return KERN_FAILURE;
}

int jbclient_mach_process_checkin(char *jbRootPathOut, char *bootUUIDOut,
	char *sandboxExtensionsOut, bool *fullyDebuggedOut)
{
	(void)jbRootPathOut;
	(void)bootUUIDOut;
	(void)sandboxExtensionsOut;
	(void)fullyDebuggedOut;
	return -1;
}

int jbclient_mach_fork_fix(pid_t childPid)
{
	(void)childPid;
	return -1;
}

int jbclient_mach_trust_file(int fd, struct siginfo *siginfo)
{
	(void)fd;
	(void)siginfo;
	return -1;
}
