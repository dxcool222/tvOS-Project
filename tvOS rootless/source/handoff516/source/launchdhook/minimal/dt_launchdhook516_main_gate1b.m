#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <os/log.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <uuid/uuid.h>

#include "jbclient_xpc_gate1b.h"
#include <libjailbreak/codesign.h>
#include <libjailbreak/info.h>
#include <libjailbreak/kernel.h>
#include <libjailbreak/util.h>
#include "dt_runtime_trace.h"

#define DT516_HOOK_MARKER "/private/var/jb/.dt516_launchdhook_loaded"
#define DT518_CTOR_MARKER "/private/var/jb/.dt518_launchdhook_ctor_entered"
#define DT518_BOOMERANG_OK_MARKER "/private/var/jb/.dt518_boomerang_recover_ok"

static int dt_r24_console_fprintf(FILE *stream, const char *format, ...)
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

/* Every diagnostic written to launchd's stderr also reaches unified logging. */
#define fprintf(stream, ...) dt_r24_console_fprintf((stream), __VA_ARGS__)

/* Host H11 fingerprint: compiled ctor order contract (string presence + disasm). */
__attribute__((used)) static const char kDtR24CtorOrderFingerprint[] =
    "CTOR_ORDER=JBROOT_DLADDR>BOOMERANG>CS_ALLOW_INVALID>XPC>SPAWN";
/* Keep prior token so older static greps still see CS>XPC>SPAWN adjacency. */
__attribute__((used)) static const char kDtR24CtorOrderCsXpcSpawn[] =
    "CTOR_ORDER=CS_ALLOW_INVALID>XPC>SPAWN";

extern int dt_boomerang516_resolve_symbols(void);
extern int boomerang_recoverPrimitives516(bool firstRetrieval, bool shouldEndBoomerang);
#ifdef DT_ROOTLESS_R24_CBR
extern int initXPCHooks(void);
extern int initSpawnHooks(void);
extern void early_boot_done(void);
extern bool gInEarlyBoot;
#endif
#ifdef DT_BUILD102735D_TRACE
extern void dt102735d_trace_event(const char *event, int rc);
#endif
#ifdef DT_BUILD102738P_TELEMETRY
#ifdef DT_BUILD102738Y_TELEMETRY
extern int dt102738y_run_got_wrapper_invocation_probe(void);
#elif defined(DT_BUILD102738X_TELEMETRY)
extern int dt102738x_run_got_wrapper_roundtrip_probe(void);
#elif defined(DT_BUILD102738W_TELEMETRY)
extern int dt102738w_run_got_same_value_store_probe(void);
#else
extern int dt102738p_run_got_protection_probe(void);
#endif
#endif

#ifdef DT_BUILD102732C_TELEMETRY
static void dt102732c_emit_no_mutation_markers(void)
{
	fprintf(stderr, "BUILD102732C_GOT_ACCESSED=NO\n");
	fprintf(stderr, "BUILD102732C_GOT_POINTER_READ=NO\n");
	fprintf(stderr, "BUILD102732C_GOT_POINTER_WRITTEN=NO\n");
	fprintf(stderr, "BUILD102732C_LAUNCHD_PROTECTION_CHANGED=NO\n");
	fprintf(stderr, "BUILD102732C_MACH_VM_PROTECT_GOT_CALLED=NO\n");
	fprintf(stderr, "BUILD102732C_XPC_HOOK_INSTALLED=NO\n");
	fprintf(stderr, "BUILD102732C_INITXPCHOOKS_CALLED=NO\n");
	fprintf(stderr, "BUILD102732C_MSHOOKFUNCTION_CALLED=NO\n");
	fprintf(stderr, "BUILD102732C_STAGE_B_ACTIVE=NO\n");
	fprintf(stderr, "BUILD102732C_STAGE_C_ACTIVE=NO\n");
}

static void dt102732c_emit_constructor_fail(void)
{
	fprintf(stderr, "BUILD102732C_HOOK_CONSTRUCTOR_RETURNED=NO\n");
	fprintf(stderr, "BUILD102732C_HOOK_CONSTRUCTOR_RESULT=FAIL\n");
}
#endif

static void dt516_write_marker(const char *path)
{
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd >= 0) {
		const char *msg = "ok\n";
		write(fd, msg, strlen(msg));
		close(fd);
	}
}

static void dt518_write_fail_marker(int err)
{
	char path[128];
	snprintf(path, sizeof(path), "/private/var/jb/.dt518_boomerang_recover_fail_%d", err);
	dt516_write_marker(path);
}

/*
 * Emit STAGE to stderr + unified log (process: launchd) + 102735D file trace.
 * App DTRunLogger is unavailable inside launchdhook; os_log is the greppable channel.
 */
static void dt_r24_launchd_stage(const char *stage)
{
	if (!stage || !stage[0])
		return;
	fprintf(stderr, "%s\n", stage);
	(void)dt_r24_trace_event("LAUNCHDHOOK", stage, 0, 0, "stage");
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event(stage, 0);
#endif
	/* Keep fingerprint live so LTO cannot drop the string. */
	(void)kDtR24CtorOrderFingerprint[0];
	(void)kDtR24CtorOrderCsXpcSpawn[0];
}

#ifdef DT_ROOTLESS_R24_CBR
/*
 * Dopamine launchdhook main.m: set jailbreakInfo.rootPath from this dylib's path
 * (<JBROOT>/basebin/launchdhook*.dylib → 2× dirname) before boomerang/hooks.
 * On-device layout proven fail4: .../procursus/basebin/launchdhook516.dylib.
 * Exported for H11/H13 ctor-order disasm. Fail-closed: never leave NULL rootPath.
 */
__attribute__((noinline)) int dt_r24_launchd_jbroot_from_dladdr_or_fail(void)
{
	dt_r24_launchd_stage("LAUNCHD_JBROOT_DLADDR_BEGIN");

	Dl_info selfInfo;
	if (dladdr((const void *)&dt_r24_launchd_jbroot_from_dladdr_or_fail, &selfInfo) == 0 ||
	    selfInfo.dli_fname == NULL || selfInfo.dli_fname[0] == '\0') {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=1");
		return -1;
	}

	@autoreleasepool {
		NSString *selfPath = [NSString stringWithUTF8String:selfInfo.dli_fname];
		if (selfPath.length == 0) {
			dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=2");
			return -2;
		}
		if (![selfPath.lastPathComponent isEqualToString:@"launchdhook516.dylib"]) {
			dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=3");
			return -3;
		}
		if (![selfPath.stringByDeletingLastPathComponent.lastPathComponent
			isEqualToString:@"basebin"]) {
			dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=4");
			return -4;
		}
		NSString *jbroot =
		    selfPath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
		if (jbroot.length == 0) {
			dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=5");
			return -5;
		}
		if (gSystemInfo.jailbreakInfo.rootPath) {
			free(gSystemInfo.jailbreakInfo.rootPath);
			gSystemInfo.jailbreakInfo.rootPath = NULL;
		}
		gSystemInfo.jailbreakInfo.rootPath = strdup(jbroot.fileSystemRepresentation);
		if (!gSystemInfo.jailbreakInfo.rootPath || !gSystemInfo.jailbreakInfo.rootPath[0]) {
			dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_JBROOT_DLADDR rc=6");
			return -6;
		}
		fprintf(stderr, "R24_LAUNCHD_JBROOT_PATH=%s\n", gSystemInfo.jailbreakInfo.rootPath);
		os_log(OS_LOG_DEFAULT, "STAGE R24_LAUNCHD_JBROOT_PATH=%{public}s",
		    gSystemInfo.jailbreakInfo.rootPath);
	}

	dt_r24_launchd_stage("R24_LAUNCHD_JBROOT_FROM_DLADDR=PASS");
	return 0;
}

/*
 * Dopamine order: after boomerang, before hooks.
 * Match Dopamine_Rootful launchdhook main.m: cs_allow_invalid(proc_self(), false).
 * On arm64 (AppleTV6,2) false still runs the full flag path (non-arm64e).
 * Exported name is required for host H11 ctor-order disasm (not presence-only).
 */
int dt_r24_launchd_cs_allow_invalid_or_fail(void)
{
	dt_r24_launchd_stage("LAUNCHD_CS_ALLOW_INVALID_BEGIN");

	uint64_t proc = proc_self();
	if (!proc) {
		dt_r24_launchd_stage("LAUNCHD_CS_ALLOW_INVALID=FAIL");
		dt_r24_launchd_stage("GATE_FAIL=LAUNCHD_CS_ALLOW_INVALID");
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("LAUNCHD_CS_ALLOW_INVALID_FAIL_PROC", -1);
#endif
		return -1;
	}

	uint32_t before = proc_getcsflags(proc);
#ifdef DT_BUILD102735D_TRACE
	/* RC carries flags (trace_value is file-local/static in boomerang.c). */
	dt102735d_trace_event("LAUNCHD_CSFLAGS_BEFORE", (int)before);
#endif
	fprintf(stderr, "LAUNCHD_CSFLAGS_BEFORE=0x%x\n", before);
	os_log(OS_LOG_DEFAULT, "STAGE LAUNCHD_CSFLAGS_BEFORE=0x%{public}x", before);

	/* Dopamine uses false; arm64 path clears CS_KILL|CS_HARD and sets CS_DEBUGGED. */
	(void)cs_allow_invalid(proc, false);

	uint32_t after = proc_getcsflags(proc);
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("LAUNCHD_CSFLAGS_AFTER", (int)after);
#endif
	fprintf(stderr, "LAUNCHD_CSFLAGS_AFTER=0x%x\n", after);
	os_log(OS_LOG_DEFAULT, "STAGE LAUNCHD_CSFLAGS_AFTER=0x%{public}x", after);

	const bool kill_cleared = (after & CS_KILL) == 0;
	const bool hard_cleared = (after & CS_HARD) == 0;
	const bool debugged_set = (after & CS_DEBUGGED) != 0;
	if (!kill_cleared || !hard_cleared || !debugged_set) {
		dt_r24_launchd_stage("LAUNCHD_CS_ALLOW_INVALID=FAIL");
		dt_r24_launchd_stage("GATE_FAIL=LAUNCHD_CS_ALLOW_INVALID");
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("LAUNCHD_CS_ALLOW_INVALID_FAIL_FLAGS", (int)after);
#endif
		return -2;
	}

	dt_r24_launchd_stage("LAUNCHD_CS_ALLOW_INVALID=PASS");
	/* Force fingerprint into binary + unified log for H11/M4. */
	dt_r24_launchd_stage(kDtR24CtorOrderFingerprint);
	dt_r24_launchd_stage(kDtR24CtorOrderCsXpcSpawn);
	return 0;
}

/*
 * Dopamine live-injection boundary.  A launchdhook injected into the already
 * running launchd is not in early boot.  This transition must precede
 * boomerang recovery, cs_allow_invalid, and hook installation.  Do not set
 * DOPAMINE_INITIALIZED here: upstream does that only after hooks are installed.
 */
__attribute__((noinline)) int dt_r24_launchd_begin_live_injection(void)
{
	if (getenv("DOPAMINE_INITIALIZED") != NULL) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LIVE_INJECTION_STATE rc=1");
		return -1;
	}

	early_boot_done();
	if (gInEarlyBoot) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LIVE_INJECTION_STATE rc=2");
		return -2;
	}

	dt_r24_launchd_stage("R24_LIVE_INJECTION_STATE=PASS");
	dt_r24_launchd_stage("R24_GIN_EARLY_BOOT=NO");
	return 0;
}

/*
 * Finish the current userspace-boot environment after XPC/spawn hooks exist,
 * matching Dopamine's DOPAMINE_INITIALIZED and LAUNCHD_UUID placement.  This
 * CBR build deliberately has no launchd self-reexec or userspace-reboot path.
 */
__attribute__((noinline)) int dt_r24_launchd_initialize_current_boot_runtime(void)
{
	if (getenv("DOPAMINE_INITIALIZED") != NULL) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LIVE_INJECTION_STATE rc=3");
		return -1;
	}
	if (gInEarlyBoot) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LIVE_INJECTION_STATE rc=4");
		return -2;
	}

	if (setenv("DOPAMINE_INITIALIZED", "1", 1) != 0) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LIVE_INJECTION_STATE rc=5");
		return -3;
	}

	uuid_t launchd_uuid;
	char launchd_uuid_string[37];
	uuid_generate_random(launchd_uuid);
	uuid_unparse_lower(launchd_uuid, launchd_uuid_string);
	if (setenv("LAUNCHD_UUID", launchd_uuid_string, 1) != 0) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_UUID rc=1");
		return -4;
	}

	uuid_t parsed_uuid;
	const char *installed_uuid = getenv("LAUNCHD_UUID");
	if (!installed_uuid || uuid_parse(installed_uuid, parsed_uuid) != 0) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=LAUNCHD_UUID rc=2");
		return -5;
	}

	dt_r24_launchd_stage("R24_LAUNCHD_UUID_VALID=PASS");
	return 0;
}
#endif

__attribute__((constructor)) static void dt516_launchdhook_init(void)
{
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("CTOR_ENTER", 0);
#else
	dt516_write_marker(DT518_CTOR_MARKER);
#endif
	fprintf(stderr, "GATE1B_LAUNCHDHOOK_CONSTRUCTOR_ENTERED\n");
	dt_r24_launchd_stage("R24_CONSOLE_MIRROR_ALL_LAUNCHD_DIAGNOSTICS=YES");
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_HOOK_CONSTRUCTOR_ENTERED=YES\n");
#ifndef DT_BUILD102738P_TELEMETRY
	dt102732c_emit_no_mutation_markers();
#endif
#endif

#ifdef DT_ROOTLESS_R24_CBR
	/*
	 * Dopamine parity: jbroot from dylib path before boomerang/hooks.
	 * Fail-closed — NULL jbinfo(rootPath) + CHECKIN is the V17 2nd-run SIGSEGV.
	 */
	if (dt_r24_launchd_jbroot_from_dladdr_or_fail() != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CTOR_RETURN_FAIL", -2403);
#endif
#ifdef DT_BUILD102732C_TELEMETRY
		dt102732c_emit_constructor_fail();
#endif
		return;
	}
	/* Dopamine parity: live-injection state is established before boomerang. */
	if (dt_r24_launchd_begin_live_injection() != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CTOR_RETURN_FAIL", -2400);
#endif
#ifdef DT_BUILD102732C_TELEMETRY
		dt102732c_emit_constructor_fail();
#endif
		return;
	}
#endif

	int sym = dt_boomerang516_resolve_symbols();
	if (sym != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CTOR_RETURN_FAIL", sym);
#else
		dt518_write_fail_marker(sym);
#endif
		fprintf(stderr, "GATE1B_LAUNCHDHOOK_SYMBOL_RESOLVE_FAIL err=%d\n", sym);
#ifdef DT_BUILD102732C_TELEMETRY
		dt102732c_emit_constructor_fail();
#endif
		return;
	}

	int err = boomerang_recoverPrimitives516(true, true);
	if (err != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CTOR_RETURN_FAIL", err);
#else
		dt518_write_fail_marker(err);
#endif
		fprintf(stderr, "GATE1B_LAUNCHDHOOK_BOOMERANG_RECOVER_BLOCKED err=%d\n", err);
#ifdef DT_BUILD102732C_TELEMETRY
		dt102732c_emit_constructor_fail();
#endif
		return;
	}

#ifdef DT_ROOTLESS_R24_CBR
	/*
	 * Blueprint default: boomerang → cs_allow_invalid(+verify) → GOT probe → hooks.
	 * Fail-closed: never call initSpawnHooks / prologue patch without PASS.
	 */
	if (dt_r24_launchd_cs_allow_invalid_or_fail() != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CTOR_RETURN_FAIL", -2401);
#endif
#ifdef DT_BUILD102732C_TELEMETRY
		dt102732c_emit_constructor_fail();
#endif
		return;
	}
#endif

#ifdef DT_BUILD102738P_TELEMETRY
#ifdef DT_BUILD102738Y_TELEMETRY
	int probe_err = dt102738y_run_got_wrapper_invocation_probe();
#elif defined(DT_BUILD102738X_TELEMETRY)
	int probe_err = dt102738x_run_got_wrapper_roundtrip_probe();
#elif defined(DT_BUILD102738W_TELEMETRY)
	int probe_err = dt102738w_run_got_same_value_store_probe();
#else
	int probe_err = dt102738p_run_got_protection_probe();
#endif
	dt102735d_trace_event("CTOR_EXIT_REACHED", probe_err);
	if (probe_err != 0) {
		dt102735d_trace_event("CTOR_RETURN_FAIL", probe_err);
		return;
	}
#endif

#ifdef DT_ROOTLESS_R24_CBR
	/*
	 * Blueprint: boomerang → cs_allow_invalid → initXPCHooks → initSpawnHooks.
	 * Must run after primitives exist (Fix setuid / trust need KRW).
	 */
	int xpc_hook_result = initXPCHooks();
	if (xpc_hook_result != 0) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=XPC_HOOK_INSTALL");
		return;
	}
	dt_r24_launchd_stage("XPC_HOOK_INSTALL_VERIFIED=YES");
	int spawn_hook_result = initSpawnHooks();
	if (spawn_hook_result != 0) {
		dt_r24_launchd_stage("R24_FAIL_STAGE=SPAWN_HOOK_INSTALL");
		return;
	}
	dt_r24_launchd_stage("SPAWN_HOOK_INSTALL_VERIFIED=YES");
	dt_r24_launchd_stage("CBR_XPC_SPAWN_HOOKS_ARMED=YES");
	if (dt_r24_launchd_initialize_current_boot_runtime() != 0) {
#ifdef DT_BUILD102735D_TRACE
		dt102735d_trace_event("CTOR_RETURN_FAIL", -2402);
#endif
		return;
	}
#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("CBR_XPC_SPAWN_HOOKS_ARMED_YES", 0);
#endif
#endif

#ifdef DT_BUILD102735D_TRACE
	dt102735d_trace_event("CTOR_RETURN_PASS", 0);
#else
	dt516_write_marker(DT518_BOOMERANG_OK_MARKER);
	dt516_write_marker(DT516_HOOK_MARKER);
#endif
	fprintf(stderr, "GATE1B_LAUNCHDHOOK_BOOMERANG_RECOVER_OK\n");
	fprintf(stderr, "GATE1B_LAUNCHDHOOK_LOADED\n");
#ifdef DT_BUILD102732C_TELEMETRY
	fprintf(stderr, "BUILD102732C_HOOK_CONSTRUCTOR_RETURNED=YES\n");
	fprintf(stderr, "BUILD102732C_HOOK_CONSTRUCTOR_RESULT=PASS\n");
#endif
}
