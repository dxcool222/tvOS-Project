#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <mach-o/dyld.h>
#include <libjailbreak/info.h>
#include <os/log.h>

#include "../../systemhook_cbr/common.h"
#include "dt_cbr_mshook.h"
#include "spawn_hook.h"
#include "dt_runtime_trace.h"

extern char **environ;

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);

/* Dopamine early-boot gate: no inject until xpcproxy (jbserver XPC up). */
bool gInEarlyBoot = true;

void early_boot_done(void)
{
	gInEarlyBoot = false;
}

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
			       struct _posix_spawn_args_desc *desc,
			       char *const argv[restrict], char *const envp[restrict])
{
	/* CBR: no crashreporter pause (not linked). Orig via syscall in common.c. */
	return __posix_spawn_orig(pid, path, desc, argv, envp);
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
		       struct _posix_spawn_args_desc *desc, char *const argv[restrict],
		       char *const envp[restrict])
{
	os_log(OS_LOG_DEFAULT,
	    "STAGE R24_SPAWN_HOOK_ENTER path=%{public}s early_boot=%{public}s",
	    path ? path : "(null)", gInEarlyBoot ? "YES" : "NO");
	(void)dt_r24_trace_event("LAUNCHD_SPAWN", "HOOK_ENTER", 0, 0,
	    path ? path : "(null)");
	if (path) {
		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			/*
			 * Userspace reboot of launchd: reinsert via env already set;
			 * CBR deliberately skips Dopamine fakelib mount + update apply
			 * (no stock /usr overlay). Stash/recover remains Wall2/opainject.
			 */
			gInEarlyBoot = true;
			os_log(OS_LOG_DEFAULT,
			    "STAGE R24_SPAWN_HOOK_BYPASS reason=launchd_self_reexec path=%{public}s",
			    path);
			(void)dt_r24_trace_event("LAUNCHD_SPAWN", "BYPASS_SELF_REEXEC", 0, 0,
			    path);
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
		}
	}

	if (gInEarlyBoot) {
		if (path && !strcmp(path, "/usr/libexec/xpcproxy")) {
			early_boot_done();
		} else {
			os_log(OS_LOG_DEFAULT,
			    "STAGE R24_SPAWN_HOOK_BYPASS reason=early_boot path=%{public}s",
			    path ? path : "(null)");
			(void)dt_r24_trace_event("LAUNCHD_SPAWN", "BYPASS_EARLY_BOOT", 0, 0,
			    path ? path : "(null)");
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
		}
	}

	return posix_spawn_hook_shared(pid, path, desc, argv, envp,
				       (void *)__posix_spawn_orig_wrapper,
				       systemwide_trust_file_by_path,
				       platform_set_process_debugged,
				       jbsetting(jetsamMultiplier));
}

int initSpawnHooks(void)
{
	/* NULL result → litehook_hook_function; orig = syscall(SYS_posix_spawn). */
	os_log(OS_LOG_DEFAULT, "STAGE R24_CONSOLE_MIRROR_LAUNCHD=YES");
	os_log(OS_LOG_DEFAULT, "STAGE R24_SPAWN_HOOK_PATCH_BEGIN");
	int patch_result = dt_cbr_MSHookFunction((void *)__posix_spawn,
	    (void *)__posix_spawn_hook, NULL);
	if (patch_result != 0) {
		fprintf(stderr, "SPAWN_HOOK_INSTALL_VERIFIED=NO rc=%d\n", patch_result);
		os_log(OS_LOG_DEFAULT, "STAGE SPAWN_HOOK_INSTALL_VERIFIED=NO rc=%{public}d",
		    patch_result);
		(void)dt_r24_trace_event("LAUNCHD_SPAWN", "HOOK_INSTALL_FAIL", patch_result,
		    0, "__posix_spawn");
		return patch_result;
	}
	fprintf(stderr, "SPAWN_HOOK_INSTALL_VERIFIED=YES\n");
	os_log(OS_LOG_DEFAULT, "STAGE SPAWN_HOOK_INSTALL_VERIFIED=YES");
	(void)dt_r24_trace_event("LAUNCHD_SPAWN", "HOOK_INSTALL_VERIFIED", 0, 0,
	    "__posix_spawn five_instruction_readback_match");
#ifdef DT_BUILD102735D_TRACE
	extern void dt102735d_trace_event(const char *event, int rc);
	dt102735d_trace_event("SPAWN_HOOK_INSTALL_VERIFIED_YES", 0);
#endif
	return 0;
}
