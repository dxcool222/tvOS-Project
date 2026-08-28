#include "jbclient_xpc_gate1b.h"
#include "jbserver_domains.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xpc/xpc.h>
#include <xpc_private.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

mach_port_t gJBServerCustomPort = MACH_PORT_NULL;

#ifdef DT_BUILD102735D_TRACE
#ifdef DT_BUILD102737D_TELEMETRY
static const char *kDTGate1BClientTraceBuild = "102737";
static const char *kDTGate1BClientTraceName = ".dt102737_constructor_trace";
#else
static const char *kDTGate1BClientTraceBuild = "102735";
static const char *kDTGate1BClientTraceName = ".dt102735_constructor_trace";
#endif

static int dt_gate1b_client_append_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t wrote = write(fd, buf + off, len - off);
		if (wrote <= 0)
			return -1;
		off += (size_t)wrote;
	}
	return 0;
}

static int dt_gate1b_client_trace_path(char out[PATH_MAX])
{
	Dl_info info;
	memset(&info, 0, sizeof(info));
	if (!dladdr((const void *)&dt_gate1b_client_trace_path, &info) || !info.dli_fname)
		return -1;

	const char *loaded = info.dli_fname;
	static const char prefix[] = "/private/preboot/";
	if (strncmp(loaded, prefix, sizeof(prefix) - 1) != 0)
		return -2;

	const char *slash = strrchr(loaded, '/');
	if (!slash || strcmp(slash + 1, "libjailbreak.dylib") != 0)
		return -3;

	size_t dir_len = (size_t)(slash - loaded);
	size_t trace_len = strlen(kDTGate1BClientTraceName);
	if (dir_len + 1 + trace_len + 1 > PATH_MAX)
		return -4;

	memcpy(out, loaded, dir_len);
	out[dir_len] = '/';
	memcpy(out + dir_len + 1, kDTGate1BClientTraceName, trace_len);
	out[dir_len + 1 + trace_len] = 0;
	return 0;
}

static void dt_gate1b_client_trace_line(const char *event, int rc, bool has_value,
    long long value)
{
	if (!event || !event[0])
		return;

	char path[PATH_MAX];
	if (dt_gate1b_client_trace_path(path) != 0)
		return;

	int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return;

	struct stat st;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		return;
	}

	char line[256];
	int n;
	if (has_value) {
		n = snprintf(line, sizeof(line),
		    "BUILD=%s EVENT=%s RC=%d VALUE=%lld\n", kDTGate1BClientTraceBuild,
		    event, rc, value);
	} else {
		n = snprintf(line, sizeof(line), "BUILD=%s EVENT=%s RC=%d\n",
		    kDTGate1BClientTraceBuild, event, rc);
	}
	if (n > 0 && (size_t)n < sizeof(line))
		(void)dt_gate1b_client_append_all(fd, line, (size_t)n);
	close(fd);
}

void dt_gate1b_client_trace_event(const char *event, int rc)
{
	dt_gate1b_client_trace_line(event, rc, false, 0);
}

void dt_gate1b_client_trace_value(const char *event, int rc, long long value)
{
	dt_gate1b_client_trace_line(event, rc, true, value);
}
#endif

void jbclient_xpc_set_custom_port(mach_port_t serverPort)
{
	if (gJBServerCustomPort != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), gJBServerCustomPort);
	}
	gJBServerCustomPort = serverPort;
}

xpc_object_t jbserver_xpc_send_dict(xpc_object_t xdict)
{
	if (gJBServerCustomPort == MACH_PORT_NULL)
		return NULL;

	xpc_object_t xpipe = xpc_pipe_create_from_port(gJBServerCustomPort, 0);
	if (!xpipe)
		return NULL;

	xpc_object_t xreply = NULL;
	int err = xpc_pipe_routine_with_flags(xpipe, xdict, &xreply, 0);
	xpc_release(xpipe);
	if (err != 0)
		return NULL;
	return xreply;
}

xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t xargs)
{
	bool ownsXargs = false;
	if (!xargs) {
		xargs = xpc_dictionary_create_empty();
		ownsXargs = true;
	}

	xpc_dictionary_set_uint64(xargs, "jb-domain", domain);
	xpc_dictionary_set_uint64(xargs, "action", action);

	xpc_object_t xreply = jbserver_xpc_send_dict(xargs);
	if (ownsXargs)
		xpc_release(xargs);
	return xreply;
}

static xpc_object_t jbserver_xpc_send_with_rc(uint64_t domain, uint64_t action,
    xpc_object_t xargs, int *send_rc)
{
	if (send_rc)
		*send_rc = -1;
	bool ownsXargs = false;
	if (!xargs) {
		xargs = xpc_dictionary_create_empty();
		ownsXargs = true;
	}

	xpc_dictionary_set_uint64(xargs, "jb-domain", domain);
	xpc_dictionary_set_uint64(xargs, "action", action);

	if (gJBServerCustomPort == MACH_PORT_NULL) {
		if (ownsXargs)
			xpc_release(xargs);
		if (send_rc)
			*send_rc = -1001;
		return NULL;
	}

	xpc_object_t xpipe = xpc_pipe_create_from_port(gJBServerCustomPort, 0);
	if (!xpipe) {
		if (ownsXargs)
			xpc_release(xargs);
		if (send_rc)
			*send_rc = -1002;
		return NULL;
	}

	xpc_object_t xreply = NULL;
	int err = xpc_pipe_routine_with_flags(xpipe, xargs, &xreply, 0);
	xpc_release(xpipe);
	if (ownsXargs)
		xpc_release(xargs);
	if (send_rc)
		*send_rc = err;
	if (err != 0)
		return NULL;
	return xreply;
}

int jbclient_root_get_physrw(bool singlePTE, uint64_t *singlePTEAsidPtr)
{
#ifdef DT_BUILD102735D_TRACE
	dt_gate1b_client_trace_event("PTE_HANDOFF_CLIENT_SEND_BEGIN", 0);
#endif
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(xargs, "single-pte", singlePTE);
	int send_rc = -1;
	xpc_object_t xreply = jbserver_xpc_send_with_rc(JBS_DOMAIN_ROOT,
	    JBS_ROOT_GET_PHYSRW, xargs, &send_rc);
	xpc_release(xargs);
#ifdef DT_BUILD102735D_TRACE
	dt_gate1b_client_trace_event("PTE_HANDOFF_CLIENT_SEND_RC", send_rc);
#endif
	if (!xreply) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_PHYSRW_REQUEST_RC=-1\n");
		fprintf(stderr, "BUILD102732C_PHYSRW_PTE_HANDOFF_RECEIVED=NO\n");
		fprintf(stderr, "BUILD102732C_PTE_ASID_PTR=0x0\n");
#endif
#ifdef DT_BUILD102735D_TRACE
		dt_gate1b_client_trace_event("PTE_HANDOFF_REQUEST_FAIL", -1);
#endif
		return -1;
	}
	bool has_result = xpc_dictionary_get_value(xreply, "result") != NULL;
	bool has_asid = xpc_dictionary_get_value(xreply, "single-pte-asid-ptr") != NULL;
	uint64_t asidPtr = xpc_dictionary_get_uint64(xreply, "single-pte-asid-ptr");
	if (singlePTEAsidPtr)
		*singlePTEAsidPtr = asidPtr;
	int64_t result = xpc_dictionary_get_int64(xreply, "result");
#ifdef DT_BUILD102735D_TRACE
	dt_gate1b_client_trace_event("PTE_HANDOFF_CLIENT_REPLY_RECEIVED", 0);
	dt_gate1b_client_trace_value("PTE_HANDOFF_CLIENT_RESULT_VALUE", 0, result);
	dt_gate1b_client_trace_value("PTE_HANDOFF_CLIENT_ASID_PTR", 0,
	    (long long)asidPtr);
	if (!has_result || (singlePTE && !has_asid))
		dt_gate1b_client_trace_event("PTE_HANDOFF_CLIENT_DECODE_FAIL", -2);
#endif
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_PHYSRW_REQUEST_RC=%lld\n", (long long)result);
	fprintf(stderr, "BUILD102732C_PHYSRW_PTE_HANDOFF_RECEIVED=%s\n",
	    (result == 0 && asidPtr != 0) ? "YES" : "NO");
	fprintf(stderr, "BUILD102732C_PTE_ASID_PTR=0x%llx\n", (unsigned long long)asidPtr);
#endif
#ifdef DT_BUILD102735D_TRACE
	if (result == 0)
		dt_gate1b_client_trace_event("PTE_HANDOFF_REQUEST_PASS", 0);
	else
		dt_gate1b_client_trace_event("PTE_HANDOFF_REQUEST_FAIL", (int)result);
#endif
	xpc_release(xreply);
	return (int)result;
}

int jbclient_root_get_sysinfo(xpc_object_t *sysInfoOut)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_GET_SYSINFO, NULL);
	if (!xreply) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_SYSINFO_REQUEST_RC=-1\n");
		fprintf(stderr, "BUILD102732C_SYSINFO_RECEIVED=NO\n");
#endif
		return -1;
	}
	xpc_object_t sysInfo = xpc_dictionary_get_dictionary(xreply, "sysinfo");
	if (sysInfo && sysInfoOut)
		*sysInfoOut = xpc_copy(sysInfo);
	int result = (int)xpc_dictionary_get_int64(xreply, "result");
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_SYSINFO_REQUEST_RC=%d\n", result);
	fprintf(stderr, "BUILD102732C_SYSINFO_RECEIVED=%s\n",
	    (result == 0 && sysInfo != NULL) ? "YES" : "NO");
#endif
	xpc_release(xreply);
	return result;
}

int jbclient_boomerang_done(void)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_BOOMERANG_DONE, NULL);
	if (!xreply) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_BOOMERANG_DONE_SEND_RC=-1\n");
		fprintf(stderr, "BUILD102732C_BOOMERANG_DONE_SENT=NO\n");
#endif
		return -1;
	}
	int64_t result = xpc_dictionary_get_int64(xreply, "result");
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_BOOMERANG_DONE_SEND_RC=%lld\n", (long long)result);
	fprintf(stderr, "BUILD102732C_BOOMERANG_DONE_SENT=%s\n", result == 0 ? "YES" : "NO");
#endif
	xpc_release(xreply);
	return (int)result;
}
