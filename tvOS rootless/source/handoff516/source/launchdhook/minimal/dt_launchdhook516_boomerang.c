#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "jbclient_xpc_gate1b.h"

static int dt_r24_boomerang_console_fprintf(FILE *stream, const char *format, ...)
{
	char line[1024];
	va_list ap;
	va_start(ap, format);
	int length = vsnprintf(line, sizeof(line), format, ap);
	va_end(ap);
	if (length < 0)
		return length;
	fputs(line, stream);
	if (stream == stderr)
		os_log(OS_LOG_DEFAULT, "%{public}s", line);
	return length;
}

/* Keep the historical stderr trace while making Console the remote authority. */
#define fprintf(stream, ...) dt_r24_boomerang_console_fprintf((stream), __VA_ARGS__)

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

typedef kern_return_t (*dt_mach_ports_lookup_fn)(mach_port_t, mach_port_array_t *,
    mach_msg_type_number_t *);
typedef kern_return_t (*dt_mach_ports_register_fn)(mach_port_t, mach_port_array_t,
    mach_msg_type_number_t);

static dt_mach_ports_lookup_fn g_dt_mach_ports_lookup;
static dt_mach_ports_register_fn g_dt_mach_ports_register;
static bool g_dt_boomerang_symbols_resolved;

#ifdef DT_BUILD102735D_TRACE
#ifdef DT_BUILD102738P_TELEMETRY
static const char *kDT102735DTraceBuild = "102738";
static const char *kDT102735DTraceName = ".dt102737_constructor_trace";
#elif defined(DT_BUILD102737D_TELEMETRY)
static const char *kDT102735DTraceBuild = "102737";
static const char *kDT102735DTraceName = ".dt102737_constructor_trace";
#else
static const char *kDT102735DTraceBuild = "102735";
static const char *kDT102735DTraceName = ".dt102735_constructor_trace";
#endif

static int dt102735d_append_all(int fd, const char *buf, size_t len)
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

static int dt102735d_trace_path(char out[PATH_MAX])
{
	Dl_info info;
	memset(&info, 0, sizeof(info));
	if (!dladdr((const void *)&dt102735d_trace_path, &info) || !info.dli_fname)
		return -1;

	const char *loaded = info.dli_fname;
	static const char prefix[] = "/private/preboot/";
	if (strncmp(loaded, prefix, sizeof(prefix) - 1) != 0)
		return -2;

	const char *slash = strrchr(loaded, '/');
	if (!slash || strcmp(slash + 1, "launchdhook516.dylib") != 0)
		return -3;

	size_t dir_len = (size_t)(slash - loaded);
	size_t trace_len = strlen(kDT102735DTraceName);
	if (dir_len + 1 + trace_len + 1 > PATH_MAX)
		return -4;

	memcpy(out, loaded, dir_len);
	out[dir_len] = '/';
	memcpy(out + dir_len + 1, kDT102735DTraceName, trace_len);
	out[dir_len + 1 + trace_len] = 0;
	return 0;
}

static void dt102735d_trace_line(const char *event, int rc, bool has_value, long long value)
{
	if (!event || !event[0])
		return;

	char path[PATH_MAX];
	if (dt102735d_trace_path(path) != 0)
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
		    "BUILD=%s EVENT=%s RC=%d VALUE=%lld\n", kDT102735DTraceBuild, event, rc,
		    value);
	} else {
		n = snprintf(line, sizeof(line), "BUILD=%s EVENT=%s RC=%d\n",
		    kDT102735DTraceBuild, event, rc);
	}
	if (n > 0 && (size_t)n < sizeof(line))
		(void)dt102735d_append_all(fd, line, (size_t)n);
	close(fd);
}

void dt102735d_trace_event(const char *event, int rc)
{
	dt102735d_trace_line(event, rc, false, 0);
}

static void dt102735d_trace_value(const char *event, int rc, long long value)
{
	dt102735d_trace_line(event, rc, true, value);
}

#ifdef DT_BUILD102738P_TELEMETRY
void dt102738p_trace_event(const char *event, int rc)
{
	dt102735d_trace_event(event, rc);
}

void dt102738p_trace_value_u64(const char *event, int rc, uint64_t value)
{
	dt102735d_trace_value(event, rc, (long long)value);
}
#endif

static void dt102735d_trace_primitive_failure(int r)
{
	const char *event = "PRIMITIVES_INIT_FAIL";
	switch (r) {
	case -1:
		event = "PRIMITIVES_NON_ROOT";
		break;
	case -2:
		event = "PRIMITIVES_TARGET_GATE_FAIL";
		break;
	case -3:
		event = "PRIMITIVES_PTE_UNSUPPORTED";
		break;
	case -4:
		event = "PRIMITIVES_SYSINFO_FAIL";
		break;
	case -5:
		event = "PRIMITIVES_PTE_HANDOFF_FAIL";
		break;
	case -6:
		event = "PRIMITIVES_PTE_INIT_FAIL";
		break;
	case -7:
		event = "PRIMITIVES_TRANSLATION_FAIL";
		break;
	case -8:
		event = "PRIMITIVES_KCALL_INIT_FAIL";
		break;
	default:
		break;
	}
	dt102735d_trace_event(event, r);
}
#endif

#ifdef DT_BUILD102732C_TELEMETRY
static const char *dt102732c_yesno(bool v)
{
	return v ? "YES" : "NO";
}

static const char *dt102732c_passfail(bool v)
{
	return v ? "PASS" : "FAIL";
}
#endif

int dt_boomerang516_resolve_symbols(void)
{
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("SYMBOL_RESOLUTION_BEGIN", 0);
#endif
	if (g_dt_boomerang_symbols_resolved) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_SYMBOL_RESOLUTION_LOOKUP=PASS\n");
		fprintf(stderr, "BUILD102732C_SYMBOL_RESOLUTION_REGISTER=PASS\n");
#endif
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("SYMBOL_RESOLUTION_PASS", 0);
#endif
		return 0;
	}

	g_dt_mach_ports_lookup =
	    (dt_mach_ports_lookup_fn)dlsym(RTLD_DEFAULT, "mach_ports_lookup");
	g_dt_mach_ports_register =
	    (dt_mach_ports_register_fn)dlsym(RTLD_DEFAULT, "mach_ports_register");

	bool lookup_ok = g_dt_mach_ports_lookup != NULL;
	bool register_ok = g_dt_mach_ports_register != NULL;
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_SYMBOL_RESOLUTION_LOOKUP=%s\n",
	    dt102732c_passfail(lookup_ok));
	fprintf(stderr, "BUILD102732C_SYMBOL_RESOLUTION_REGISTER=%s\n",
	    dt102732c_passfail(register_ok));
#endif
	if (!lookup_ok || !register_ok) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("SYMBOL_RESOLUTION_FAIL", -100);
#endif
		return -100;
	}

	g_dt_boomerang_symbols_resolved = true;
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("SYMBOL_RESOLUTION_PASS", 0);
#endif
	return 0;
}

int boomerang_recoverPrimitives516(bool firstRetrieval, bool shouldEndBoomerang)
{
	(void)firstRetrieval;

	int sym = dt_boomerang516_resolve_symbols();
	if (sym != 0)
		return sym;

	mach_port_t *registeredPorts = NULL;
	mach_msg_type_number_t registeredPortsCount = 0;
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("MACH_PORTS_LOOKUP_BEGIN", 0);
#endif
	kern_return_t lookup_rc =
	    g_dt_mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount);
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_MACH_PORTS_LOOKUP_RC=%d\n", lookup_rc);
	fprintf(stderr, "BUILD102732C_REGISTERED_PORT_COUNT=%u\n", registeredPortsCount);
#endif
	if (lookup_rc != 0 || registeredPortsCount < 3) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_REGISTERED_PORT2=0\n");
		fprintf(stderr, "BUILD102732C_REGISTERED_PORT2_VALID=NO\n");
#endif
#ifdef DT_BUILD102735D_TRACE
		if (lookup_rc != 0)
			dt102735d_trace_event("MACH_PORTS_LOOKUP_FAIL", lookup_rc);
		else
			dt102735d_trace_value("REGISTERED_PORT_COUNT_FAIL", -1,
			    registeredPortsCount);
#endif
		return -1;
	}
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_value("REGISTERED_PORT_COUNT", 0, registeredPortsCount);
#endif

	mach_port_t boomerangPort = registeredPorts[2];
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_REGISTERED_PORT2=%u\n", boomerangPort);
	fprintf(stderr, "BUILD102732C_REGISTERED_PORT2_VALID=%s\n",
	    dt102732c_yesno(boomerangPort != MACH_PORT_NULL));
#endif
	if (boomerangPort == MACH_PORT_NULL) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_value("REGISTERED_PORT2_INVALID", -2, 0);
#endif
		return -2;
	}
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_value("REGISTERED_PORT2", 0, boomerangPort);
#endif

	jbclient_xpc_set_custom_port(boomerangPort);
	registeredPorts[2] = MACH_PORT_NULL;
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_CUSTOM_PORT_INSTALL=%s\n",
	    dt102732c_passfail(gJBServerCustomPort != MACH_PORT_NULL));
#endif
	kern_return_t register_rc =
	    g_dt_mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_PORTS_REGISTER_RESULT=%d\n", register_rc);
#endif
	if (register_rc != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("MACH_PORTS_REGISTER_FAIL", register_rc);
#endif
		return -3;
	}

	if (gJBServerCustomPort == MACH_PORT_NULL) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_CUSTOM_PORT_INSTALL=FAIL\n");
#endif
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CUSTOM_PORT_INSTALL_FAIL", -4);
#endif
		return -4;
	}
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("CUSTOM_PORT_INSTALL_PASS", 0);
	dt102735d_trace_event("PRIMITIVES_INIT_BEGIN", 0);
#endif

	int r = jbclient_initialize_primitives_gate1b();
	if (r != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_primitive_failure(r);
#endif
		return r;
	}
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("PRIMITIVES_INIT_PASS", 0);
#endif

	if (shouldEndBoomerang) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("BOOMERANG_DONE_SEND_BEGIN", 0);
#endif
		int bd = jbclient_boomerang_done();
		if (bd != 0) {
#ifdef DT_BUILD102735D_TRACE
			dt102735d_trace_event("BOOMERANG_DONE_SEND_FAIL", bd);
#endif
			return -200 + (bd < 0 ? -bd : bd);
		}
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("BOOMERANG_DONE_SEND_PASS", 0);
#endif
	}

	return 0;
}
