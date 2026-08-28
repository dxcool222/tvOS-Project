#include "jbclient_xpc_gate1b.h"
#include "physrw_pte.h"
#include "translation.h"
#include "kalloc_pt.h"
#include "info.h"
#include "primitives.h"
#include "kcall_arm64.h"
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool dt_gate1b_read_target(char *machine, size_t machine_len,
    char *osversion, size_t osversion_len)
{
	struct utsname name;
	if (uname(&name) != 0)
		return false;
	if (machine && machine_len > 0) {
		strncpy(machine, name.machine, machine_len - 1);
		machine[machine_len - 1] = 0;
	}

	size_t sz = osversion_len;
	if (sysctlbyname("kern.osversion", osversion, &sz, NULL, 0) != 0)
		return false;
	if (osversion && osversion_len > 0)
		osversion[osversion_len - 1] = 0;
	return true;
}

static bool dt_gate1b_target_is_appletv6_20l563(void)
{
	char machine[256] = { 0 };
	char osversion[32] = { 0 };
	if (!dt_gate1b_read_target(machine, sizeof(machine), osversion, sizeof(osversion)))
		return false;
	if (strcmp(machine, "AppleTV6,2") != 0)
		return false;
	return strcmp(osversion, "20L563") == 0;
}

int jbclient_initialize_primitives_gate1b(void)
{
	if (getuid() != 0)
		return -1;

	char target_model[256] = "UNAVAILABLE";
	char target_build[32] = "UNAVAILABLE";
	bool target_read = dt_gate1b_read_target(target_model, sizeof(target_model),
	    target_build, sizeof(target_build));
	bool target_ok = target_read
	    && strcmp(target_model, "AppleTV6,2") == 0
	    && strcmp(target_build, "20L563") == 0;
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_TARGET_MODEL=%s\n", target_model);
	fprintf(stderr, "BUILD102732C_TARGET_BUILD=%s\n", target_build);
	fprintf(stderr, "BUILD102732C_TARGET_GATE=%s\n", target_ok ? "PASS" : "FAIL");
#endif
	if (!target_ok)
		return -2;

	if (!device_supports_physrw_pte())
		return -3;

	xpc_object_t xSystemInfo = NULL;
	if (jbclient_root_get_sysinfo(&xSystemInfo) != 0)
		return -4;
	SYSTEM_INFO_DESERIALIZE(xSystemInfo);
	xpc_release(xSystemInfo);

	uint64_t asidPtr = 0;
#ifdef DT_BUILD102735D_TRACE
	dt_gate1b_client_trace_event("PTE_HANDOFF_REQUEST_BEGIN", 0);
	dt_gate1b_client_trace_value("PTE_HANDOFF_REQUEST_ARGUMENT_SINGLE_PTE", 0, 1);
#endif
	int physrwRc = jbclient_root_get_physrw(true, &asidPtr);
	if (physrwRc != 0)
		return -5;

	int pteRc = libjailbreak_physrw_pte_init(true, asidPtr);
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_PTE_INIT_RC=%d\n", pteRc);
#endif
	if (pteRc != 0)
		return -6;

	libjailbreak_translation_init();
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_TRANSLATION_PAGE_SIZE=%llu\n",
	    (unsigned long long)vm_real_kernel_page_size);
	fprintf(stderr, "BUILD102732C_TRANSLATION_INIT_RC=%d\n",
	    vm_real_kernel_page_size == 0 ? -7 : 0);
#endif
	if (vm_real_kernel_page_size == 0)
		return -7;

	if (__builtin_available(iOS 16.0, *)) {
		libjailbreak_kalloc_pt_init();
	}

	if (gPrimitives.kalloc_local) {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_KCALL_INIT_ATTEMPTED=YES\n");
#endif
		int kcallRc = arm64_kcall_init();
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_KCALL_INIT_RC=%d\n", kcallRc);
		fprintf(stderr, "BUILD102732C_KCALL_INIT_RESULT=%s\n",
		    kcallRc == 0 ? "PASS" : "FAIL");
#endif
		if (kcallRc != 0)
			return -8;
	} else {
#ifdef DT_BUILD102732C_TELEMETRY
		fprintf(stderr, "BUILD102732C_KCALL_INIT_ATTEMPTED=NO\n");
		fprintf(stderr, "BUILD102732C_KCALL_INIT_RC=0\n");
		fprintf(stderr, "BUILD102732C_KCALL_INIT_RESULT=NOT_REQUIRED\n");
#endif
	}

	return 0;
}
