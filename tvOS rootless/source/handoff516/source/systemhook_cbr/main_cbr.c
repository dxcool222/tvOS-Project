/*
 * R24 CURRENT_BOOT_RUNTIME systemhook — Dopamine responsibilities, tvOS rootless path.
 * HOOK_DYLIB_PATH=/usr/lib/systemhook.dylib via current-generation fakelib.
 * Tweaks / TweakLoader intentionally OFF for CBR.
 * Prefer Dopamine's dyldhook __jbinfo; retain its xpcproxy-compatible direct
 * check-in fallback when early bootstrap-port check-in is unavailable.
 */
#include "common.h"
#include "litehook.h"
#include "private.h"
#include "envbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <limits.h>
#include <os/log.h>
#include <uuid/uuid.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <sandbox.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/codesign.h>
#include "syscall_shim.h"
#include "dt_runtime_trace.h"
#include "dt_dyld_jbinfo.h"
#include "dt_rootless_r24_dyld_identity.h"
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize,
		     audit_token_t *token);

bool gFullyDebugged = false;
static void *gLibSandboxHandle;
char *JB_BootUUID = NULL;
char *JB_RootPath = NULL;
char *get_jbroot(void) { return JB_RootPath; }

static void dt_r24_systemhook_stage(const char *stage);

static char gExecutablePath[PATH_MAX];
static char *JB_SandboxExtensions = NULL;

static const struct mach_header_64 *dt_r24_get_dyld_header(void)
{
	task_dyld_info_data_t info = {0};
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&info, &count)
	    != KERN_SUCCESS) return NULL;
	struct dyld_all_image_infos *images = (void *)info.all_image_info_addr;
	return images ? (const struct mach_header_64 *)images->dyldImageLoadAddress : NULL;
}

static int dt_r24_parse_dyldhook_jbinfo(void)
{
	const struct mach_header_64 *header = dt_r24_get_dyld_header();
	if (!header) return -1;
	uuid_t imageUUID = {0};
	if (!_dyld_get_image_uuid((const struct mach_header *)header, imageUUID)) return -2;
	if (memcmp(imageUUID, ROOTLESS_R24_GENERATED_DYLD_UUID, 16) != 0) return -3;
	unsigned long size = 0;
	struct dyld_jbinfo *info = (void *)getsectiondata(header, "__DATA", "__jbinfo", &size);
	if (!info || size < sizeof(*info)) return -4;
	char uuid_line[96];
	snprintf(uuid_line, sizeof(uuid_line),
	    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
	    imageUUID[0], imageUUID[1], imageUUID[2], imageUUID[3],
	    imageUUID[4], imageUUID[5], imageUUID[6], imageUUID[7],
	    imageUUID[8], imageUUID[9], imageUUID[10], imageUUID[11],
	    imageUUID[12], imageUUID[13], imageUUID[14], imageUUID[15]);
	char jbinfo_line[128];
	snprintf(jbinfo_line, sizeof(jbinfo_line),
	    "R24_SYSTEMHOOK_RUNTIME_JBINFO_SECTION=PASS size=0x%lx", size);
	dt_r24_systemhook_stage(jbinfo_line);
	char dyld_uuid_line[128];
	snprintf(dyld_uuid_line, sizeof(dyld_uuid_line),
	    "R24_SYSTEMHOOK_RUNTIME_DYLD_UUID=PASS uuid=%s", uuid_line);
	dt_r24_systemhook_stage(dyld_uuid_line);
	if (info->state != DYLD_STATE_CHECKED_IN) return -5;
	if (!info->jbRootPath || !info->jbRootPath[0]) return -6;
	JB_RootPath = info->jbRootPath;
	JB_BootUUID = info->bootUUID;
	JB_SandboxExtensions = info->sandboxExtensions;
	gFullyDebugged = info->fullyDebugged;
	return 0;
}

#define DT_R24_RUNTIME_PROBE_ENV "R24_RUNTIME_PROBE"
#define DT_R24_RUNTIME_PROBE_PATH "/var/jb/usr/bin/true"
#define DT_R24_RUNTIME_PROBE_ACK "/private/var/jb/.r24_current_boot_runtime_probe_pass"

static void dt_r24_systemhook_stage(const char *stage)
{
	if (!stage || !stage[0])
		return;
	fprintf(stderr, "%s\n", stage);
	os_log(OS_LOG_DEFAULT, "STAGE %{public}s", stage);
	(void)dt_r24_trace_event("SYSTEMHOOK", stage, 0, 0, gExecutablePath[0] ? gExecutablePath : "path_not_loaded");
}

static kern_return_t dt_r24_systemhook_patch(const char *name, void *source, void *target)
{
	kern_return_t kr = litehook_hook_function(source, target);
	char detail[256];
	snprintf(detail, sizeof(detail), "name=%s source=%p target=%p verified=%s",
	    name ? name : "(null)", source, target, kr == KERN_SUCCESS ? "YES" : "NO");
	(void)dt_r24_trace_event("SYSTEMHOOK", "HOOK_PATCH_RESULT", (int)kr, 0, detail);
	os_log(OS_LOG_DEFAULT,
	    "STAGE SYSTEMHOOK_PATCH name=%{public}s result=%{public}s kr=%{public}d",
	    name ? name : "(null)", kr == KERN_SUCCESS ? "PASS" : "FAIL", (int)kr);
	return kr;
}

__attribute__((noinline)) int dt_r24_systemhook_validate_controlled_probe_checkin(void)
{
	if (!JB_RootPath || !JB_RootPath[0]) {
		dt_r24_systemhook_stage("R24_FAIL_STAGE=JBROOT_MATCH rc=1");
		return -1;
	}

	char alias_root[PATH_MAX];
	char server_root[PATH_MAX];
	if (!realpath("/var/jb", alias_root) || !realpath(JB_RootPath, server_root)) {
		dt_r24_systemhook_stage("R24_FAIL_STAGE=JBROOT_MATCH rc=2");
		return -2;
	}
	if (strcmp(alias_root, server_root) != 0) {
		dt_r24_systemhook_stage("R24_FAIL_STAGE=JBROOT_MATCH rc=3");
		return -3;
	}
	dt_r24_systemhook_stage("R24_JBROOT_GENERATION_MATCH=PASS");

	const char *inherited_uuid = getenv("LAUNCHD_UUID");
	uuid_t inherited_parsed;
	uuid_t server_parsed;
	if (!inherited_uuid || !JB_BootUUID
	    || uuid_parse(inherited_uuid, inherited_parsed) != 0
	    || uuid_parse(JB_BootUUID, server_parsed) != 0) {
		dt_r24_systemhook_stage("R24_FAIL_STAGE=BOOT_UUID_MATCH rc=1");
		return -4;
	}
	if (strcmp(inherited_uuid, JB_BootUUID) != 0) {
		dt_r24_systemhook_stage("R24_FAIL_STAGE=BOOT_UUID_MATCH rc=2");
		return -5;
	}
	dt_r24_systemhook_stage("R24_BOOT_UUID_MATCH=PASS");
	return 0;
}

__attribute__((noinline)) bool dt_r24_is_controlled_probe(void)
{
	const char *probe = getenv(DT_R24_RUNTIME_PROBE_ENV);
	char canonical_probe[PATH_MAX];
	canonical_probe[0] = '\0';
	if (!realpath(DT_R24_RUNTIME_PROBE_PATH, canonical_probe))
		return false;
	return probe && strcmp(probe, "1") == 0
	    && gExecutablePath[0] && strcmp(gExecutablePath, canonical_probe) == 0;
}

static int dt_r24_write_controlled_probe_ack(void)
{
	(void)dt_r24_trace_event("SYSTEMHOOK", "CONTROLLED_ACK_BEGIN", 0, 0,
	    DT_R24_RUNTIME_PROBE_ACK);
	int fd = open(DT_R24_RUNTIME_PROBE_ACK,
	              O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, 0644);
	if (fd < 0) {
		(void)dt_r24_trace_event("SYSTEMHOOK", "CONTROLLED_ACK_OPEN_FAIL", -1, errno,
		    DT_R24_RUNTIME_PROBE_ACK);
		dt_r24_systemhook_stage("R24_FAIL_STAGE=CONTROLLED_CHILD_ACK rc=1");
		return -1;
	}
	static const char ack[] = "pass\n";
	ssize_t nw = write(fd, ack, sizeof(ack) - 1);
	int saved_errno = errno;
	if (close(fd) != 0 && nw == (ssize_t)(sizeof(ack) - 1)) {
		saved_errno = errno;
		nw = -1;
	}
	if (nw != (ssize_t)(sizeof(ack) - 1)) {
		(void)unlink(DT_R24_RUNTIME_PROBE_ACK);
		(void)saved_errno;
		dt_r24_systemhook_stage("R24_FAIL_STAGE=CONTROLLED_CHILD_ACK rc=2");
		(void)dt_r24_trace_event("SYSTEMHOOK", "CONTROLLED_ACK_WRITE_FAIL", -2,
		    saved_errno, DT_R24_RUNTIME_PROBE_ACK);
		return -2;
	}
	dt_r24_systemhook_stage("R24_CONTROLLED_CHILD_INJECTION=PASS");
	(void)dt_r24_trace_event("SYSTEMHOOK", "CONTROLLED_ACK_PASS", 0, 0,
	    DT_R24_RUNTIME_PROBE_ACK);
	return 0;
}

static int load_executable_path(void)
{
	char executablePath[PATH_MAX];
	uint32_t bufsize = PATH_MAX;
	if (_NSGetExecutablePath(executablePath, &bufsize) == 0) {
		if (realpath(executablePath, gExecutablePath) != NULL)
			return 0;
	}
	return -1;
}

void consume_tokenized_sandbox_extensions(char *sandboxExtensions)
{
	if (!sandboxExtensions || sandboxExtensions[0] == '\0')
		return;

	char *it = sandboxExtensions;
	char *last = sandboxExtensions;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

void *(*sandbox_apply_orig)(void *) = NULL;
void *sandbox_apply_hook(void *a1)
{
	void *r = sandbox_apply_orig(a1);
	consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
	return r;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	(void)pacSalt;
	if (!dyld || !*dyld)
		return -1;
	void **dyldFuncPtrs = *dyld;
	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *),
		       false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		*orig = dyldFuncPtrs[idx];
		dyldFuncPtrs[idx] = hook;
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *),
			   false, VM_PROT_READ);
		return 0;
	}
	return -1;
}

void *(*dyld_dlsym_orig)(void *dyld, void *handle, const char *name);
void *dyld_dlsym_hook(void *dyld, void *handle, const char *name)
{
	if (handle == gLibSandboxHandle && !strcmp(name, "sandbox_apply"))
		return sandbox_apply_hook;
	__attribute__((musttail)) return dyld_dlsym_orig(dyld, handle, name);
}

int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv != 0)
		return rv;
	if (ops == CS_OPS_STATUS && useraddr && usersize == sizeof(uint32_t)) {
		uint32_t *csflag = (uint32_t *)useraddr;
		*csflag |= CS_VALID;
		*csflag &= ~CS_DEBUGGED;
		if (pid == getpid() && gFullyDebugged)
			*csflag |= CS_DEBUGGED;
	}
	return rv;
}

int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize,
			  audit_token_t *token)
{
	int rv = syscall(SYS_csops_audittoken, pid, ops, useraddr, usersize, token);
	if (rv != 0)
		return rv;
	if (ops == CS_OPS_STATUS && useraddr && usersize == sizeof(uint32_t)) {
		uint32_t *csflag = (uint32_t *)useraddr;
		*csflag |= CS_VALID;
		*csflag &= ~CS_DEBUGGED;
		if (pid == getpid() && gFullyDebugged)
			*csflag |= CS_DEBUGGED;
	}
	return rv;
}

int necp_match_policy_hook(uint8_t *parameters, size_t parameters_size, void *returned_result)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_match_policy, parameters, parameters_size, returned_result);
}

int necp_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_open, flags);
}

int necp_client_action_hook(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len,
			    uint8_t *buffer, size_t buffer_size)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_client_action, necp_fd, action, client_id, client_id_len, buffer,
		       buffer_size);
}

int necp_session_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_open, flags);
}

int necp_session_action_hook(int necp_fd, uint32_t action, uint8_t *in_buffer,
			     size_t in_buffer_length, uint8_t *out_buffer,
			     size_t out_buffer_length)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_action, necp_fd, action, in_buffer, in_buffer_length,
		       out_buffer, out_buffer_length);
}

/* CBR: never enable TweakLoader / ElleKit tweaks. */
bool should_enable_tweaks(void)
{
	return false;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
		       struct _posix_spawn_args_desc *desc, char *const argv[restrict],
		       char *const envp[restrict])
{
	return posix_spawn_hook_shared(pid, path, desc, argv, envp, (void *)__posix_spawn_orig,
				       jbclient_trust_file_by_path,
				       jbclient_platform_set_process_debugged,
				       jbclient_jbsettings_get_double("jetsamMultiplier"));
}

int __execve_hook(const char *path, char *const argv[], char *const envp[])
{
	return execve_hook_shared(path, argv, envp, (void *)__execve_orig,
				  jbclient_trust_file_by_path);
}

__attribute__((constructor)) static void initializer(void)
{
	dt_r24_systemhook_stage("R24_CONSOLE_MIRROR_SYSTEMHOOK=YES");
	dt_r24_systemhook_stage("SYSTEMHOOK_CBR_CTOR_ENTER");

	int dyld_info_result = dt_r24_parse_dyldhook_jbinfo();
	int checkin_result = 0;
	if (dyld_info_result == 0) {
		(void)dt_r24_trace_event("SYSTEMHOOK", "DYLDHOOK_JBINFO_PASS", 0, 0,
		    "source=__DATA,__jbinfo uuid=" ROOTLESS_R24_GENERATED_DYLD_UUID_STR);
		dt_r24_systemhook_stage("R24_DYLDHOOK_JBINFO=PASS");
	} else {
		char fallback[128];
		snprintf(fallback, sizeof(fallback), "parse_rc=%d fallback=direct", dyld_info_result);
		(void)dt_r24_trace_event("SYSTEMHOOK", "DYLDHOOK_JBINFO_FALLBACK",
		    dyld_info_result, 0, fallback);
		dt_r24_systemhook_stage("R24_DYLDHOOK_JBINFO=FALLBACK_DIRECT");
		dt_r24_systemhook_stage("R24_DYLDHOOK_CHECKIN_FALLBACK reason=JBINFO_PARSE_RC");
		(void)dt_r24_trace_event("SYSTEMHOOK", "PROCESS_CHECKIN_BEGIN", 0, 0,
		    "jbclient_process_checkin");
		checkin_result = jbclient_process_checkin(&JB_RootPath, &JB_BootUUID,
		    &JB_SandboxExtensions, &gFullyDebugged);
		if (checkin_result == 0)
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
	}
	if (checkin_result == 0) {
		char checkin_detail[1024];
		snprintf(checkin_detail, sizeof(checkin_detail),
		    "jbroot=%s boot_uuid=%s extensions=%s fully_debugged=%s",
		    JB_RootPath ? JB_RootPath : "(null)",
		    JB_BootUUID ? JB_BootUUID : "(null)",
		    JB_SandboxExtensions ? "present" : "null", gFullyDebugged ? "YES" : "NO");
		(void)dt_r24_trace_event("SYSTEMHOOK", "PROCESS_CHECKIN_PASS", 0, 0,
		    checkin_detail);
		dt_r24_systemhook_stage("R24_JBS_PROCESS_CHECKIN=PASS");
		dt_r24_systemhook_stage("SYSTEMHOOK_CBR_CHECKIN_PASS");
	} else {
		(void)dt_r24_trace_event("SYSTEMHOOK", "PROCESS_CHECKIN_FAIL", checkin_result,
		    errno, "jbclient_process_checkin");
		dt_r24_systemhook_stage("R24_FAIL_STAGE=PROCESS_CHECKIN rc=1");
		dt_r24_systemhook_stage("SYSTEMHOOK_CBR_CHECKIN_FAIL");
		return;
	}

	/* Normal Dopamine check-in permits a nullable boot UUID.  The controlled
	 * qualification child is deliberately stricter and proves root/UUID match. */
	int executable_path_result = load_executable_path();
	bool controlled_probe = executable_path_result == 0 && dt_r24_is_controlled_probe();
	char probe_detail[1024];
	snprintf(probe_detail, sizeof(probe_detail),
	    "path_result=%d path=%s env=%s controlled=%s", executable_path_result,
	    gExecutablePath[0] ? gExecutablePath : "(unavailable)",
	    getenv(DT_R24_RUNTIME_PROBE_ENV) ? getenv(DT_R24_RUNTIME_PROBE_ENV) : "(null)",
	    controlled_probe ? "YES" : "NO");
	(void)dt_r24_trace_event("SYSTEMHOOK", "CONTROLLED_PROBE_CLASSIFY", 0, 0,
	    probe_detail);
	if (controlled_probe
	    && dt_r24_systemhook_validate_controlled_probe_checkin() != 0)
		return;

	const char *dyldInsertLibraries = getenv("DYLD_INSERT_LIBRARIES");
	if (dyldInsertLibraries && !strcmp(dyldInsertLibraries, HOOK_DYLIB_PATH))
		unsetenv("DYLD_INSERT_LIBRARIES");

	(void)dt_r24_systemhook_patch("__posix_spawn", (void *)__posix_spawn,
	    (void *)__posix_spawn_hook);
	(void)dt_r24_systemhook_patch("__execve", (void *)__execve, (void *)__execve_hook);

	gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_FIRST | RTLD_LOCAL | RTLD_LAZY);
	if (gLibSandboxHandle)
		sandbox_apply_orig = dlsym(gLibSandboxHandle, "sandbox_apply");
	(void)dt_r24_trace_event("SYSTEMHOOK", "SANDBOX_SYMBOL_RESULT",
	    sandbox_apply_orig ? 0 : -1, sandbox_apply_orig ? 0 : errno,
	    sandbox_apply_orig ? "sandbox_apply=present" : "sandbox_apply=missing");

	void ***gDyldPtr =
	    litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	int dyld_hook_result = gDyldPtr
	    ? dyld_hook_routine(*gDyldPtr, 17, (void *)&dyld_dlsym_hook,
	        (void **)&dyld_dlsym_orig, 0x839D)
	    : -1;
	(void)dt_r24_trace_event("SYSTEMHOOK", "DYLD_HOOK_RESULT", dyld_hook_result, 0,
	    gDyldPtr ? "gDyld=present index=17" : "gDyld=missing index=17");

	if (executable_path_result == 0) {
		(void)dt_r24_systemhook_patch("csops", (void *)csops, (void *)csops_hook);
		(void)dt_r24_systemhook_patch("csops_audittoken", (void *)csops_audittoken,
		    (void *)csops_audittoken_hook);
		(void)dt_r24_systemhook_patch("necp_match_policy", (void *)necp_match_policy,
		    (void *)necp_match_policy_hook);
		(void)dt_r24_systemhook_patch("necp_open", (void *)necp_open,
		    (void *)necp_open_hook);
		(void)dt_r24_systemhook_patch("necp_client_action", (void *)necp_client_action,
		    (void *)necp_client_action_hook);
		(void)dt_r24_systemhook_patch("necp_session_open", (void *)necp_session_open,
		    (void *)necp_session_open_hook);
		(void)dt_r24_systemhook_patch("necp_session_action", (void *)necp_session_action,
		    (void *)necp_session_action_hook);

		if (should_enable_tweaks()) {
			/* unreachable in CBR — kept for structural parity with Dopamine */
		}

		jbclient_cs_revalidate();
	}

	dt_r24_systemhook_stage("SYSTEMHOOK_CBR_CTOR_PASS");
	if (controlled_probe)
		(void)dt_r24_write_controlled_probe_ack();
}
