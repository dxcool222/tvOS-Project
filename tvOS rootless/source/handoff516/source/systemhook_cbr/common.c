#include "common.h"
#include <xpc/xpc.h>
#include "launchd.h"
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "envbuf.h"
#include "private.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbserver_domains.h>
#include <math.h>
#include <errno.h>
#include <os/log.h>
#include "syscall_shim.h"
#include "dt_runtime_trace.h"
#ifdef DT_ROOTLESS_R24_CBR
#include "dt_r24_child_dyld_probe.h"
#endif

static void dt_r24_spawn_trace(const char *event, const char *path, int rc, int error_number,
			       const char *reason)
{
	char detail[768];
	snprintf(detail, sizeof(detail), "path=%s reason=%s", path ? path : "(null)",
	    reason ? reason : "-");
	(void)dt_r24_trace_event("SPAWN", event, rc, error_number, detail);
}

/* tvOS SDK marks posix_spawnattr_getflags unavailable; symbol exists. */
extern int dt_posix_spawnattr_getflags(const posix_spawnattr_t *attr, short *flags)
	__asm("_posix_spawnattr_getflags");

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *stringCopy = strdup(string);
	char *curString = strtok(stringCopy, separator);
	while (curString != NULL) {
		bool stop = false;
		enumBlock(curString, &stop);
		if (stop) break;
		curString = strtok(NULL, separator);
	}
	free(stringCopy);
}

static kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict])
{
	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return 0;
	}

	return (kSpawnConfigInject | kSpawnConfigTrust);
}

int __posix_spawn_orig(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict])
{
	return syscall(SYS_posix_spawn, pid, path, desc, argv, envp);
}

int __execve_orig(const char *path, char *const argv[], char *const envp[])
{
	return syscall(SYS_execve, path, argv, envp);
}

// 1. Ensure the binary about to be spawned and all of it's dependencies are trust cached
// 2. Insert "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib" into all binaries spawned
// 3. Increase Jetsam limit to more sane value (Multipler defined as JETSAM_MULTIPLIER)

static int spawn_exec_hook_common(const char *path,
								  char *const argv[restrict],
								  char *const envp[restrict],
			   struct _posix_spawn_args_desc *desc,
										int (*trust_binary)(const char *path),
									   double jetsamMultiplier,
									    int (^orig)(char *const envp[restrict]))
{
	if (!path) {
		os_log(OS_LOG_DEFAULT,
		    "STAGE R24_SPAWN_INJECT_DECISION=NO reason=null_path");
		dt_r24_spawn_trace("INJECT_DECISION_NO", path, 0, 0, "null_path");
		int null_path_rc = orig(envp);
		dt_r24_spawn_trace("ORIG_RETURN", path, null_path_rc,
		    null_path_rc ? errno : 0, "null_path");
		return null_path_rc;
	}
	os_log(OS_LOG_DEFAULT, "STAGE R24_SPAWN_SHARED_ENTER path=%{public}s", path);
	dt_r24_spawn_trace("SHARED_ENTER", path, 0, 0, "begin");

	posix_spawnattr_t attr = NULL;
	if (desc) attr = desc->attrp;

	kSpawnConfig spawnConfig = spawn_config_for_executable(path, argv);

	if (spawnConfig & kSpawnConfigTrust) {
		// Upload binary to trustcache if needed
		trust_binary(path);
	}

	const char *existingLibraryInserts = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
	__block bool systemHookAlreadyInserted = false;
	if (existingLibraryInserts) {
		string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
			if (!strcmp(existingLibraryInsert, HOOK_DYLIB_PATH)) {
				systemHookAlreadyInserted = true;
			}
		});
	}

	int JBEnvAlreadyInsertedCount = (int)systemHookAlreadyInserted;

	// Check if we can find at least one reason to not insert jailbreak related environment variables
	// In this case we also need to remove pre existing environment variables if they are already set
	bool shouldInsertJBEnv = true;
	bool hasSafeModeVariable = false;
	const char *injectionDecisionReason = "eligible";
	do {
		if (!(spawnConfig & kSpawnConfigInject)) {
			shouldInsertJBEnv = false;
			injectionDecisionReason = "process_blacklist";
			break;
		}

		// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		const char *safeModeValue = envbuf_getenv((const char **)envp, "_SafeMode");
		const char *msSafeModeValue = envbuf_getenv((const char **)envp, "_MSSafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				injectionDecisionReason = "safe_mode";
				break;
			}
		}
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				injectionDecisionReason = "safe_mode";
				break;
			}
		}

		int proctype = 0;
		if (posix_spawnattr_getprocesstype_np(&attr, &proctype) == 0) {
			if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
				// Do not inject hook into DriverKit drivers
				shouldInsertJBEnv = false;
				injectionDecisionReason = "driverkit";
				break;
			}
		}

		int hookAccess = access(HOOK_DYLIB_PATH, F_OK);
		if (hookAccess != 0) {
			// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
			int savedErrno = errno;
			os_log(OS_LOG_DEFAULT,
			    "STAGE R24_SPAWN_SYSTEMHOOK_ACCESS=FAIL path=%{public}s errno=%{public}d",
			    HOOK_DYLIB_PATH, savedErrno);
			shouldInsertJBEnv = false;
			injectionDecisionReason = "systemhook_missing";
			dt_r24_spawn_trace("SYSTEMHOOK_ACCESS_FAIL", path, hookAccess, savedErrno,
			    HOOK_DYLIB_PATH);
			break;
		}
		os_log(OS_LOG_DEFAULT,
		    "STAGE R24_SPAWN_SYSTEMHOOK_ACCESS=PASS path=%{public}s",
		    HOOK_DYLIB_PATH);
		dt_r24_spawn_trace("SYSTEMHOOK_ACCESS_PASS", path, 0, 0, HOOK_DYLIB_PATH);
	} while (0);
	os_log(OS_LOG_DEFAULT,
	    "STAGE R24_SPAWN_INJECT_DECISION=%{public}s reason=%{public}s path=%{public}s already_inserted=%{public}s safe_mode=%{public}s",
	    shouldInsertJBEnv ? "YES" : "NO", injectionDecisionReason, path,
	    systemHookAlreadyInserted ? "YES" : "NO", hasSafeModeVariable ? "YES" : "NO");
	dt_r24_spawn_trace(shouldInsertJBEnv ? "INJECT_DECISION_YES" : "INJECT_DECISION_NO",
	    path, 0, 0, injectionDecisionReason);

	// If systemhook is being injected and jetsam limits are set, increase them by a factor of jetsamMultiplier
	if (shouldInsertJBEnv) {
		uint8_t *attrStruct = (uint8_t *)attr;
		if (attrStruct) {
			if (jetsamMultiplier == 0 || isnan(jetsamMultiplier)) jetsamMultiplier = 3; // default value (3x)
			if (jetsamMultiplier > 1) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
				if (memlimit_active != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * jetsamMultiplier;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
				if (memlimit_inactive != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * jetsamMultiplier;
				}
			}
		}
	}

	int r = -1;

	if ((shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 1) || (!shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 0 && !hasSafeModeVariable)) {
		// we're already good, just call orig
		os_log(OS_LOG_DEFAULT,
		    "STAGE R24_SPAWN_ENV_ACTION=UNCHANGED path=%{public}s", path);
		dt_r24_spawn_trace("ENV_UNCHANGED", path, 0, 0,
		    systemHookAlreadyInserted ? "already_inserted" : "not_eligible");
		r = orig(envp);
	}
	else {
		// the state we want to be in is not the state we are in right now

		char **envc = envbuf_mutcopy((const char **)envp);

		if (shouldInsertJBEnv) {
			if (!systemHookAlreadyInserted) {
				char newLibraryInsert[strlen(HOOK_DYLIB_PATH) + (existingLibraryInserts ? (strlen(existingLibraryInserts) + 1) : 0) + 1];
				strcpy(newLibraryInsert, HOOK_DYLIB_PATH);
				if (existingLibraryInserts) {
					strcat(newLibraryInsert, ":");
					strcat(newLibraryInsert, existingLibraryInserts);
				}
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);
				os_log(OS_LOG_DEFAULT,
				    "STAGE R24_SPAWN_ENV_ACTION=INSERT_SYSTEMHOOK path=%{public}s hook=%{public}s",
				    path, HOOK_DYLIB_PATH);
				dt_r24_spawn_trace("ENV_INSERT_SYSTEMHOOK", path, 0, 0,
				    HOOK_DYLIB_PATH);
			}
		}
		else {
			if (systemHookAlreadyInserted && existingLibraryInserts) {
				if (!strcmp(existingLibraryInserts, HOOK_DYLIB_PATH)) {
					envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
				}
				else {
					char *newLibraryInsert = malloc(strlen(existingLibraryInserts)+1);
					newLibraryInsert[0] = '\0';

					__block bool first = true;
					string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
						if (strcmp(existingLibraryInsert, HOOK_DYLIB_PATH) != 0) {
							if (first) {
								strcpy(newLibraryInsert, existingLibraryInsert);
								first = false;
							}
							else {
								strcat(newLibraryInsert, ":");
								strcat(newLibraryInsert, existingLibraryInsert);
							}
						}
					});
					envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);

					free(newLibraryInsert);
				}
			}
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
		}

		r = orig(envc);

		envbuf_free(envc);
	}
	os_log(OS_LOG_DEFAULT, "STAGE R24_SPAWN_ORIG_RETURN path=%{public}s rc=%{public}d",
	    path, r);
	dt_r24_spawn_trace("ORIG_RETURN", path, r, r ? errno : 0,
	    shouldInsertJBEnv ? "injection_requested" : injectionDecisionReason);

	return r;
}

int posix_spawn_hook_shared(pid_t *restrict pid, 
					   const char *restrict path,
			 struct _posix_spawn_args_desc *desc,
						  	    char *const argv[restrict],
					   			char *const envp[restrict],
					   				  void *orig,
					   				  int (*trust_binary)(const char *path),
					   				  int (*set_process_debugged)(uint64_t pid, bool fullyDebugged),
					   				 double jetsamMultiplier)
{
	int (*posix_spawn_orig)(pid_t *restrict, const char *restrict, struct _posix_spawn_args_desc *, char *const[restrict], char *const[restrict]) = orig;

	int r = spawn_exec_hook_common(path, argv, envp, desc, trust_binary, jetsamMultiplier, ^int(char *const envp_patched[restrict]) {
		return posix_spawn_orig(pid, path, desc, argv, envp_patched);
	});
	os_log(OS_LOG_DEFAULT,
	    "STAGE R24_POSIX_SPAWN_RETURN path=%{public}s rc=%{public}d pid=%{public}d",
	    path ? path : "(null)", r, (r == 0 && pid) ? *pid : -1);
	char return_detail[768];
	snprintf(return_detail, sizeof(return_detail), "path=%s child_pid=%d",
	    path ? path : "(null)", (r == 0 && pid) ? *pid : -1);
	(void)dt_r24_trace_event("SPAWN", "POSIX_SPAWN_RETURN", r, r ? errno : 0,
	    return_detail);

#ifdef DT_ROOTLESS_R24_CBR
	if (r == 0 && pid && *pid > 1) {
		dt_r24_schedule_child_dyld_uuid_probe(*pid, path, envp);
	}
#endif

	if (r == 0 && pid && desc) {
		posix_spawnattr_t attr = desc->attrp;
		short flags = 0;
		if (dt_posix_spawnattr_getflags(&attr, &flags) == 0) {
			if (flags & POSIX_SPAWN_START_SUSPENDED) {
				// If something spawns a process as suspended, ensure mapping invalid pages in it is possible
				// Normally it would only be possible after systemhook.dylib enables it
				// Fixes Frida issues
				int r = set_process_debugged(*pid, false);
			}
		}
	}

	return r;
}

int execve_hook_shared(const char *path,
					   char *const argv[],
					   char *const envp[],
			 				 void *orig,
			 				 int (*trust_binary)(const char *path))
{
	int (*execve_orig)(const char *, char *const[], char *const[]) = orig;

	int r = spawn_exec_hook_common(path, argv, envp, NULL, trust_binary, 0, ^int(char *const envp_patched[restrict]){
		return execve_orig(path, argv, envp_patched);
	});

	return r;
}
