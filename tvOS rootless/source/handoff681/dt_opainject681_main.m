#import <stdio.h>
#import <stdlib.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
#import <mach/task_special_ports.h>
#import <xpc/xpc.h>
#import <xpc_private.h>
#endif
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <sys/utsname.h>
#import <errno.h>
#import <string.h>
#import <limits.h>
#import <spawn.h>
#import <fcntl.h>
#import "dyld.h"
#import "task_utils.h"
#import "sandbox.h"
#import <CoreFoundation/CoreFoundation.h>
#import "shellcode_inject.h"
#import "rop_inject.h"

#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE (4 * PATH_MAX)
#endif

#if defined(DT_BUILD102739A_OBSERVER) || defined(DT_BUILD102739B_RETURN_OBSERVER) \
    || defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
#if defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI) || defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
#define DT102739_OBSERVER_PREFIX "BUILD102739J"
#define DT102739_IDENTITY_PREFIX "BUILD102739J"
#define DT102739_RESOLUTION_PREFIX "BUILD102739J"
#define DT102739_ARGUMENT_PREFIX "BUILD102739J"
#elif defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI)
#define DT102739_OBSERVER_PREFIX "BUILD102739I"
#define DT102739_IDENTITY_PREFIX "BUILD102739I"
#define DT102739_RESOLUTION_PREFIX "BUILD102739I"
#define DT102739_ARGUMENT_PREFIX "BUILD102739I"
#else
#define DT102739_OBSERVER_PREFIX "BUILD102739H"
#define DT102739_IDENTITY_PREFIX "BUILD102739H"
#define DT102739_RESOLUTION_PREFIX "BUILD102739H"
#define DT102739_ARGUMENT_PREFIX "BUILD102739H"
#endif
typedef struct {
	uint64_t entry_count;
	uint64_t return_count;
	uint64_t success_return_count;
	uint64_t xout_argument_count;
	uint64_t success_xout_count;
	uint64_t success_object_count;
	uint64_t dictionary_object_count;
	uint64_t domain_key_present_count;
	uint64_t action_key_present_count;
	uint64_t domain_action_envelope_count;
	uint64_t exact_controlled_probe_count;
	uint64_t domain_nonzero_count;
	uint64_t systemwide_domain_candidate_count;
	uint64_t audit_token_capture_count;
	uint64_t captured_pid;
	uint64_t captured_euid;
	uint64_t domain_resolution_attempt_count;
	uint64_t domain_resolution_success_count;
	uint64_t permission_check_count;
	uint64_t permission_allow_count;
	uint64_t action_nonzero_count;
	uint64_t action_resolution_attempt_count;
	uint64_t action_resolution_success_count;
	uint64_t handler_invocation_count;
	uint64_t handler_pointer_capture_count;
	uint64_t handler_pointer_nonnull_count;
	uint64_t args_zero_initialized_count;
	uint64_t argsout_zero_initialized_count;
	uint64_t arg_descriptor_scan_count;
	uint64_t arg_descriptor_root_path_count;
	uint64_t arg_descriptor_string_type_count;
	uint64_t arg_descriptor_out_count;
	uint64_t output_slot_bind_count;
	uint64_t arg_terminator_found_count;
	uint64_t marshalling_complete_count;
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
	uint64_t handler_call_attempt_count;
	uint64_t handler_return_count;
	uint64_t handler_arg0_output_slot_match_count;
	uint64_t handler_args1_through_7_null_count;
	uint64_t handler_output_write_count;
	uint64_t argsout0_sentinel_match_count;
	uint64_t argsout_tail_null_count;
	uint64_t handler_result_match_count;
	uint64_t controlled_handler_complete_count;
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
	uint64_t original_receive_call_count;
	uint64_t original_receive_return_count;
	uint64_t original_receive_last_result;
	uint64_t reply_create_attempt_count;
	uint64_t reply_create_success_count;
	uint64_t reply_create_failed_precommit_count;
	uint64_t reply_identity_failed_precommit_count;
	uint64_t root_path_set_count;
	uint64_t result_set_count;
	uint64_t root_path_exists_count;
	uint64_t root_path_type_match_count;
	uint64_t result_exists_count;
	uint64_t result_type_match_count;
	uint64_t reply_readback_match_count;
	uint64_t reply_readback_failed_precommit_count;
	uint64_t precommit_xout_match_count;
	uint64_t precommit_xout_mismatch_count;
	uint64_t precommit_reply_release_count;
	uint64_t precommit_fallback_count;
	uint64_t reply_send_attempt_count;
	uint64_t reply_send_return_count;
	uint64_t server_reply_send_rc;
	uint64_t server_reply_release_count;
	uint64_t committed_xout_match_count;
	uint64_t committed_xout_mismatch_count;
	uint64_t input_consume_release_count;
	uint64_t committed_consume_path_complete_count;
	uint64_t server_committed_lifecycle_pass_count;
	uint64_t wrapper_return_22_count;
#endif
#endif
} dt102739c_output_telemetry_t;
#define DT102739B_LAUNCHD_PATH "/sbin/launchd"
#define DT102739B_LAUNCHD_GOT_OFFSET 0x65018ULL
#define DT102739B_POLL_INTERVAL_US 20000U
#define DT102739B_POLL_ATTEMPTS 100U
#elif defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
#define DT102739_OBSERVER_PREFIX "BUILD102739G"
#define DT102739_IDENTITY_PREFIX "BUILD102739G"
#define DT102739_RESOLUTION_PREFIX "BUILD102739G"
typedef struct {
	uint64_t entry_count;
	uint64_t return_count;
	uint64_t success_return_count;
	uint64_t xout_argument_count;
	uint64_t success_xout_count;
	uint64_t success_object_count;
	uint64_t dictionary_object_count;
	uint64_t domain_key_present_count;
	uint64_t action_key_present_count;
	uint64_t domain_action_envelope_count;
	uint64_t exact_controlled_probe_count;
	uint64_t domain_nonzero_count;
	uint64_t systemwide_domain_candidate_count;
	uint64_t audit_token_capture_count;
	uint64_t captured_pid;
	uint64_t captured_euid;
	uint64_t domain_resolution_attempt_count;
	uint64_t domain_resolution_success_count;
	uint64_t permission_check_count;
	uint64_t permission_allow_count;
	uint64_t action_nonzero_count;
	uint64_t action_resolution_attempt_count;
	uint64_t action_resolution_success_count;
	uint64_t handler_invocation_count;
} dt102739c_output_telemetry_t;
#define DT102739B_LAUNCHD_PATH "/sbin/launchd"
#define DT102739B_LAUNCHD_GOT_OFFSET 0x65018ULL
#define DT102739B_POLL_INTERVAL_US 20000U
#define DT102739B_POLL_ATTEMPTS 100U
#elif defined(DT_BUILD102739F_CALLER_IDENTITY)
#define DT102739_OBSERVER_PREFIX "BUILD102739F"
#define DT102739_IDENTITY_PREFIX "BUILD102739F"
typedef struct {
	uint64_t entry_count;
	uint64_t return_count;
	uint64_t success_return_count;
	uint64_t xout_argument_count;
	uint64_t success_xout_count;
	uint64_t success_object_count;
	uint64_t dictionary_object_count;
	uint64_t domain_key_present_count;
	uint64_t action_key_present_count;
	uint64_t domain_action_envelope_count;
	uint64_t exact_controlled_probe_count;
	uint64_t domain_nonzero_count;
	uint64_t systemwide_domain_candidate_count;
	uint64_t audit_token_capture_count;
	uint64_t captured_pid;
	uint64_t captured_euid;
} dt102739c_output_telemetry_t;
#define DT102739B_LAUNCHD_PATH "/sbin/launchd"
#define DT102739B_LAUNCHD_GOT_OFFSET 0x65018ULL
#define DT102739B_POLL_INTERVAL_US 20000U
#define DT102739B_POLL_ATTEMPTS 100U
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
#define DT102739_OBSERVER_PREFIX "BUILD102739E"
typedef struct {
	uint64_t entry_count;
	uint64_t return_count;
	uint64_t success_return_count;
	uint64_t xout_argument_count;
	uint64_t success_xout_count;
	uint64_t success_object_count;
	uint64_t dictionary_object_count;
	uint64_t domain_key_present_count;
	uint64_t action_key_present_count;
	uint64_t domain_action_envelope_count;
	uint64_t exact_controlled_probe_count;
} dt102739c_output_telemetry_t;
#define DT102739B_LAUNCHD_PATH "/sbin/launchd"
#define DT102739B_LAUNCHD_GOT_OFFSET 0x65018ULL
#define DT102739B_POLL_INTERVAL_US 20000U
#define DT102739B_POLL_ATTEMPTS 100U
#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
#define DT102739_OBSERVER_PREFIX "BUILD102739C"
typedef struct {
	uint64_t entry_count;
	uint64_t return_count;
	uint64_t success_return_count;
	uint64_t xout_argument_count;
	uint64_t success_xout_count;
	uint64_t success_object_count;
} dt102739c_output_telemetry_t;
#define DT102739B_LAUNCHD_PATH "/sbin/launchd"
#define DT102739B_LAUNCHD_GOT_OFFSET 0x65018ULL
#define DT102739B_POLL_INTERVAL_US 20000U
#define DT102739B_POLL_ATTEMPTS 100U
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
#define DT102739_OBSERVER_PREFIX "BUILD102739B"
typedef struct {
	uint64_t entry_count;
	uint64_t return_count;
} dt102739b_return_telemetry_t;
#define DT102739B_LAUNCHD_PATH "/sbin/launchd"
#define DT102739B_LAUNCHD_GOT_OFFSET 0x65018ULL
#define DT102739B_POLL_INTERVAL_US 20000U
#define DT102739B_POLL_ATTEMPTS 100U
#else
#define DT102739_OBSERVER_PREFIX "BUILD102739A"
#endif

#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
#define DT102739_TRIGGER_PREFIX "BUILD102739J"
#define DT102739_TRIGGER_VALUE "BUILD102739J"
#define DT102739_TRIGGER_DOMAIN 1ULL
#define DT102739_TRIGGER_ACTION 1ULL
static pid_t g_dt102739f_trigger_pid = -1;
static uid_t g_dt102739f_trigger_euid = (uid_t)-1;
static bool g_dt102739j_reply_present = false;
static bool g_dt102739j_reply_dictionary = false;
static bool g_dt102739j_root_exists = false;
static bool g_dt102739j_root_type_string = false;
static bool g_dt102739j_root_matches = false;
static bool g_dt102739j_result_exists = false;
static bool g_dt102739j_result_type_int64 = false;
static bool g_dt102739j_result_matches = false;
static uint64_t g_dt102739j_client_reply_release_count = 0;
#elif defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI)
#define DT102739_TRIGGER_PREFIX "BUILD102739I"
#define DT102739_TRIGGER_VALUE "BUILD102739I"
#define DT102739_TRIGGER_DOMAIN 1ULL
#define DT102739_TRIGGER_ACTION 1ULL
static pid_t g_dt102739f_trigger_pid = -1;
static uid_t g_dt102739f_trigger_euid = (uid_t)-1;
#elif defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
#define DT102739_TRIGGER_PREFIX "BUILD102739H"
#define DT102739_TRIGGER_VALUE "BUILD102739H"
#define DT102739_TRIGGER_DOMAIN 1ULL
#define DT102739_TRIGGER_ACTION 1ULL
static pid_t g_dt102739f_trigger_pid = -1;
static uid_t g_dt102739f_trigger_euid = (uid_t)-1;
#elif defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
#define DT102739_TRIGGER_PREFIX "BUILD102739G"
#define DT102739_TRIGGER_VALUE "BUILD102739G"
#define DT102739_TRIGGER_DOMAIN 1ULL
#define DT102739_TRIGGER_ACTION 1ULL
static pid_t g_dt102739f_trigger_pid = -1;
static uid_t g_dt102739f_trigger_euid = (uid_t)-1;
#elif defined(DT_BUILD102739F_CALLER_IDENTITY)
#define DT102739_TRIGGER_PREFIX "BUILD102739F"
#define DT102739_TRIGGER_VALUE "BUILD102739F"
#define DT102739_TRIGGER_DOMAIN 1ULL
#define DT102739_TRIGGER_ACTION 1ULL
static pid_t g_dt102739f_trigger_pid = -1;
static uid_t g_dt102739f_trigger_euid = (uid_t)-1;
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
#define DT102739_TRIGGER_PREFIX "BUILD102739E"
#define DT102739_TRIGGER_VALUE "BUILD102739E"
#define DT102739_TRIGGER_DOMAIN 0ULL
#define DT102739_TRIGGER_ACTION 0ULL
#else
#define DT102739_TRIGGER_PREFIX "BUILD102739D"
#define DT102739_TRIGGER_VALUE "BUILD102739D"
#define DT102739_TRIGGER_DOMAIN 0ULL
#define DT102739_TRIGGER_ACTION 0ULL
#endif
static int dt102739d_send_one_launchd_request(void)
{
	mach_port_t bootstrapPort = MACH_PORT_NULL;
	kern_return_t portRc = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
	bool portValid = portRc == KERN_SUCCESS && MACH_PORT_VALID(bootstrapPort);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BOOTSTRAP_PORT_RC=%d\n", portRc);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BOOTSTRAP_PORT_VALID=%s\n",
		portValid ? "YES" : "NO");
	if (!portValid)
		return 30;

	xpc_object_t pipe = xpc_pipe_create_from_port(bootstrapPort, 0);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BOOTSTRAP_PIPE_CREATED=%s\n",
		pipe ? "YES" : "NO");
	if (!pipe) {
		mach_port_deallocate(mach_task_self(), bootstrapPort);
		return 31;
	}

	/* Match Dopamine's proven client envelope.  The transparent launchd hook
	 * must still forward this dictionary unchanged to the original function. */
	xpc_object_t request = xpc_dictionary_create_empty();
	if (!request) {
		xpc_release(pipe);
		mach_port_deallocate(mach_task_self(), bootstrapPort);
		fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_DICTIONARY_CREATED=NO\n");
		return 32;
	}
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_DICTIONARY_CREATED=YES\n");
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
	g_dt102739f_trigger_pid = getpid();
	g_dt102739f_trigger_euid = geteuid();
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TRIGGER_PID=%d\n", g_dt102739f_trigger_pid);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TRIGGER_EUID=%u\n", g_dt102739f_trigger_euid);
#endif
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_DOMAIN=%llu\n",
		(unsigned long long)DT102739_TRIGGER_DOMAIN);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_ACTION=%llu\n",
		(unsigned long long)DT102739_TRIGGER_ACTION);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_COUNT=1\n");
	xpc_dictionary_set_uint64(request, "jb-domain", DT102739_TRIGGER_DOMAIN);
	xpc_dictionary_set_uint64(request, "action", DT102739_TRIGGER_ACTION);
	xpc_dictionary_set_string(request, "dt-probe", DT102739_TRIGGER_VALUE);

	xpc_object_t reply = NULL;
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_TIMEOUT_GUARD_SECONDS=3\n");
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_SEND_ATTEMPTED=YES\n");
	(void)alarm(3);
	int sendRc = xpc_pipe_routine_with_flags(pipe, request, &reply, 0);
	(void)alarm(0);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_SEND_RC=%d\n", sendRc);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_REPLY_PRESENT=%s\n",
		reply ? "YES" : "NO");
	#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
	g_dt102739j_reply_present = reply != NULL;
	if (reply != NULL) {
		g_dt102739j_reply_dictionary = xpc_get_type(reply) == XPC_TYPE_DICTIONARY;
		if (g_dt102739j_reply_dictionary) {
			xpc_object_t rootValue = xpc_dictionary_get_value(reply, "root-path");
			xpc_object_t resultValue = xpc_dictionary_get_value(reply, "result");
			g_dt102739j_root_exists = rootValue != NULL;
			g_dt102739j_result_exists = resultValue != NULL;
			g_dt102739j_root_type_string = g_dt102739j_root_exists
				&& xpc_get_type(rootValue) == XPC_TYPE_STRING;
			g_dt102739j_result_type_int64 = g_dt102739j_result_exists
				&& xpc_get_type(resultValue) == XPC_TYPE_INT64;
			const char *rootPath = g_dt102739j_root_type_string
				? xpc_dictionary_get_string(reply, "root-path") : NULL;
			g_dt102739j_root_matches = rootPath != NULL
				&& strcmp(rootPath, "BUILD102739J_CONTROLLED_OUTPUT") == 0;
			g_dt102739j_result_matches = g_dt102739j_result_type_int64
				&& xpc_dictionary_get_int64(reply, "result") == 0;
		}
	}
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_IS_DICTIONARY=%s\n",
		g_dt102739j_reply_dictionary ? "YES" : "NO");
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_ROOT_PATH_EXISTS=%s\n",
		g_dt102739j_root_exists ? "YES" : "NO");
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_ROOT_PATH_TYPE_STRING=%s\n",
		g_dt102739j_root_type_string ? "YES" : "NO");
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_ROOT_PATH_MATCH=%s\n",
		g_dt102739j_root_matches ? "YES" : "NO");
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_RESULT_EXISTS=%s\n",
		g_dt102739j_result_exists ? "YES" : "NO");
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_RESULT_TYPE_INT64=%s\n",
		g_dt102739j_result_type_int64 ? "YES" : "NO");
	fprintf(stderr, "BUILD102739J_TRIGGER_REPLY_RESULT=%lld\n",
		(long long)(g_dt102739j_result_matches ? 0 : -1));
	#endif
	if (reply) {
		xpc_release(reply);
	#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
		g_dt102739j_client_reply_release_count++;
		fprintf(stderr, "BUILD102739J_CLIENT_REPLY_RELEASE_DELTA=1\n");
	#endif
	}
	xpc_release(request);
	xpc_release(pipe);
	mach_port_deallocate(mach_task_self(), bootstrapPort);
	return sendRc;
}
#endif

static int dt102739a_read_file_uuid(const char *path, uint8_t uuid[16])
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	struct mach_header_64 mh = {0};
	if (pread(fd, &mh, sizeof(mh), 0) != sizeof(mh) || mh.magic != MH_MAGIC_64
		|| mh.ncmds == 0 || mh.ncmds > 128 || mh.sizeofcmds > 0x10000) {
		close(fd);
		return -EINVAL;
	}
	uint8_t *commands = calloc(1, mh.sizeofcmds);
	if (!commands) {
		close(fd);
		return -ENOMEM;
	}
	ssize_t n = pread(fd, commands, mh.sizeofcmds, sizeof(mh));
	close(fd);
	if (n != (ssize_t)mh.sizeofcmds) {
		free(commands);
		return -EIO;
	}
	uint8_t *cursor = commands;
	uint8_t *end = commands + mh.sizeofcmds;
	int rc = -ENOENT;
	for (uint32_t i = 0; i < mh.ncmds; i++) {
		if (cursor + sizeof(struct load_command) > end)
			break;
		struct load_command *lc = (struct load_command *)cursor;
		if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end)
			break;
		if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
			memcpy(uuid, ((struct uuid_command *)lc)->uuid, 16);
			rc = 0;
			break;
		}
		cursor += lc->cmdsize;
	}
	free(commands);
	return rc;
}

static int dt102739a_observe_counter(task_t task, vm_address_t allImageInfo,
	const char *hookPath, const char *symbolName)
{
	uint8_t diskUuid[16] = {0};
	int diskUuidRc = dt102739a_read_file_uuid(hookPath, diskUuid);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_DISK_UUID_READ_RC=%d\n", diskUuidRc);
	if (diskUuidRc != 0)
		return 11;

	vm_address_t image = getRemoteImageAddress(task, allImageInfo, hookPath);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_HOOK_IMAGE_ADDRESS=0x%llx\n", (uint64_t)image);
	if (!image) {
		fprintf(stderr, DT102739_OBSERVER_PREFIX "_HOOK_IMAGE_RESOLUTION=FAIL\n");
		return 12;
	}
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_HOOK_IMAGE_RESOLUTION=PASS\n");

	struct mach_header_64 mh = {0};
	if (task_read(task, image, &mh, sizeof(mh)) != KERN_SUCCESS
		|| mh.magic != MH_MAGIC_64 || mh.filetype != MH_DYLIB
		|| mh.ncmds == 0 || mh.ncmds > 128 || mh.sizeofcmds > 0x10000) {
		fprintf(stderr, DT102739_OBSERVER_PREFIX "_REMOTE_MACHO_VALIDATION=FAIL\n");
		return 13;
	}
	vm_address_t cursor = image + sizeof(mh);
	vm_address_t commandsEnd = cursor + mh.sizeofcmds;
	uint8_t remoteUuid[16] = {0};
	bool uuidFound = false;
	vm_address_t dataStart = 0, dataEnd = 0;
	for (uint32_t i = 0; i < mh.ncmds; i++) {
		struct load_command lc = {0};
		if (cursor + sizeof(lc) > commandsEnd
			|| task_read(task, cursor, &lc, sizeof(lc)) != KERN_SUCCESS
			|| lc.cmdsize < sizeof(lc) || cursor + lc.cmdsize > commandsEnd) {
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_REMOTE_MACHO_VALIDATION=FAIL\n");
			return 13;
		}
		if (lc.cmd == LC_UUID && lc.cmdsize >= sizeof(struct uuid_command)) {
			struct uuid_command uc = {0};
			if (task_read(task, cursor, &uc, sizeof(uc)) != KERN_SUCCESS)
				return 13;
			memcpy(remoteUuid, uc.uuid, 16);
			uuidFound = true;
		}
		cursor += lc.cmdsize;
	}
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_REMOTE_MACHO_VALIDATION=PASS\n");
	/* Resolve first, then derive/validate the containing writable data segment
	 * in a second bounded command pass using the image slide. */
	vm_address_t symbol = remoteDlSym(task, image, symbolName);
	#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
	    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
	    defined(DT_BUILD102739F_CALLER_IDENTITY)
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TELEMETRY_SYMBOL_ADDRESS=0x%llx\n", (uint64_t)symbol);
	#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	fprintf(stderr, "BUILD102739E_TELEMETRY_SYMBOL_ADDRESS=0x%llx\n", (uint64_t)symbol);
	#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
	fprintf(stderr, "BUILD102739C_TELEMETRY_SYMBOL_ADDRESS=0x%llx\n", (uint64_t)symbol);
	#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
	fprintf(stderr, "BUILD102739B_TELEMETRY_SYMBOL_ADDRESS=0x%llx\n", (uint64_t)symbol);
	#else
	fprintf(stderr, "BUILD102739A_COUNTER_SYMBOL_ADDRESS=0x%llx\n", (uint64_t)symbol);
	#endif
	if (!symbol || (symbol & 7) != 0) {
		#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
		    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
		    defined(DT_BUILD102739F_CALLER_IDENTITY)
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_TELEMETRY_SYMBOL_RESOLUTION=FAIL\n");
		#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
		fprintf(stderr, "BUILD102739E_TELEMETRY_SYMBOL_RESOLUTION=FAIL\n");
		#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
		fprintf(stderr, "BUILD102739C_TELEMETRY_SYMBOL_RESOLUTION=FAIL\n");
		#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
		fprintf(stderr, "BUILD102739B_TELEMETRY_SYMBOL_RESOLUTION=FAIL\n");
		#else
		fprintf(stderr, "BUILD102739A_COUNTER_SYMBOL_RESOLUTION=FAIL\n");
		#endif
		return 14;
	}
	struct segment_command_64 firstSeg = {0};
	cursor = image + sizeof(mh);
	bool firstFound = false;
	for (uint32_t i = 0; i < mh.ncmds; i++) {
		struct load_command lc = {0};
		if (cursor + sizeof(lc) > commandsEnd
			|| task_read(task, cursor, &lc, sizeof(lc)) != KERN_SUCCESS
			|| lc.cmdsize < sizeof(lc) || cursor + lc.cmdsize > commandsEnd)
			return 13;
		if (lc.cmd == LC_SEGMENT_64 && lc.cmdsize >= sizeof(struct segment_command_64)) {
			if (task_read(task, cursor, &firstSeg, sizeof(firstSeg)) != KERN_SUCCESS)
				return 13;
			firstFound = true;
			break;
		}
		cursor += lc.cmdsize;
	}
	if (!firstFound)
		return 13;
	uint64_t slide = image - firstSeg.vmaddr;
	cursor = image + sizeof(mh);
	for (uint32_t i = 0; i < mh.ncmds; i++) {
		struct load_command lc = {0};
		if (cursor + sizeof(lc) > commandsEnd
			|| task_read(task, cursor, &lc, sizeof(lc)) != KERN_SUCCESS
			|| lc.cmdsize < sizeof(lc) || cursor + lc.cmdsize > commandsEnd)
			return 13;
		if (lc.cmd == LC_SEGMENT_64 && lc.cmdsize >= sizeof(struct segment_command_64)) {
			struct segment_command_64 seg = {0};
			if (task_read(task, cursor, &seg, sizeof(seg)) != KERN_SUCCESS)
				return 13;
			vm_address_t start = seg.vmaddr + slide;
			vm_address_t end = start + seg.vmsize;
			size_t telemetrySize =
			#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
			    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
			    defined(DT_BUILD102739F_CALLER_IDENTITY)
				sizeof(dt102739c_output_telemetry_t);
			#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
				sizeof(dt102739c_output_telemetry_t);
			#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
				sizeof(dt102739c_output_telemetry_t);
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
				sizeof(dt102739b_return_telemetry_t);
#else
				sizeof(uint64_t);
#endif
			if (end >= start && seg.vmsize >= telemetrySize
				&& (seg.initprot & VM_PROT_WRITE) && symbol >= start
				&& symbol <= end - telemetrySize) {
				dataStart = start;
				dataEnd = end;
			}
		}
		cursor += lc.cmdsize;
	}
	bool uuidOk = uuidFound && memcmp(diskUuid, remoteUuid, 16) == 0;
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_HOOK_UUID_MATCH=%s\n", uuidOk ? "PASS" : "FAIL");
	#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
	    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
	    defined(DT_BUILD102739F_CALLER_IDENTITY)
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TELEMETRY_IN_WRITABLE_DATA=%s\n",
		(dataStart && symbol >= dataStart && symbol < dataEnd) ? "YES" : "NO");
	#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	fprintf(stderr, "BUILD102739E_TELEMETRY_IN_WRITABLE_DATA=%s\n",
		(dataStart && symbol >= dataStart && symbol < dataEnd) ? "YES" : "NO");
	#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
	fprintf(stderr, "BUILD102739C_TELEMETRY_IN_WRITABLE_DATA=%s\n",
		(dataStart && symbol >= dataStart && symbol < dataEnd) ? "YES" : "NO");
	#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
	fprintf(stderr, "BUILD102739B_TELEMETRY_IN_WRITABLE_DATA=%s\n",
		(dataStart && symbol >= dataStart && symbol < dataEnd) ? "YES" : "NO");
	#else
	fprintf(stderr, "BUILD102739A_COUNTER_IN_WRITABLE_DATA=%s\n",
		(dataStart && symbol >= dataStart && symbol < dataEnd) ? "YES" : "NO");
	#endif
	if (!uuidOk || !dataStart)
		return 15;
	#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
	    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
	    defined(DT_BUILD102739F_CALLER_IDENTITY)
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TELEMETRY_SYMBOL_RESOLUTION=PASS\n");
	#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	fprintf(stderr, "BUILD102739E_TELEMETRY_SYMBOL_RESOLUTION=PASS\n");
	#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
	fprintf(stderr, "BUILD102739C_TELEMETRY_SYMBOL_RESOLUTION=PASS\n");
	#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
	fprintf(stderr, "BUILD102739B_TELEMETRY_SYMBOL_RESOLUTION=PASS\n");
	#else
	fprintf(stderr, "BUILD102739A_COUNTER_SYMBOL_RESOLUTION=PASS\n");
	#endif

#ifdef DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER
	vm_address_t launchdImage = getRemoteImageAddress(task, allImageInfo,
		DT102739B_LAUNCHD_PATH);
	vm_address_t wrapper = remoteDlSym(task, image,
		"_dt102738y_counting_wrapper");
	vm_address_t gotSlot = launchdImage
		? launchdImage + DT102739B_LAUNCHD_GOT_OFFSET : 0;
	uint64_t gotPointer = 0;
	kern_return_t gotReadRc = gotSlot
		? task_read(task, gotSlot, &gotPointer, sizeof(gotPointer))
		: KERN_INVALID_ADDRESS;
	bool gotMatches = launchdImage && wrapper && gotReadRc == KERN_SUCCESS
		&& gotPointer == (uint64_t)wrapper;
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_LAUNCHD_IMAGE_ADDRESS=0x%llx\n",
		(uint64_t)launchdImage);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_WRAPPER_SYMBOL_ADDRESS=0x%llx\n",
		(uint64_t)wrapper);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_GOT_SLOT_ADDRESS=0x%llx\n",
		(uint64_t)gotSlot);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_GOT_READ_RC=%d\n", gotReadRc);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_GOT_POINTER=0x%llx\n",
		gotPointer);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_GOT_POINTER_MATCH=%s\n",
		gotMatches ? "YES" : "NO");
	if (!gotMatches)
		return 19;

	dt102739c_output_telemetry_t telemetry = {0};
	#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
	dt102739c_output_telemetry_t baseline = {0};
	kern_return_t baselineReadRc = task_read(task, symbol, &baseline,
		sizeof(baseline));
	bool baselineInvariants = baselineReadRc == KERN_SUCCESS
		&& baseline.return_count <= baseline.entry_count
		&& baseline.success_return_count <= baseline.return_count
		&& baseline.xout_argument_count <= baseline.return_count
		&& baseline.success_xout_count <= baseline.success_return_count
		&& baseline.success_xout_count <= baseline.xout_argument_count
		&& baseline.success_object_count <= baseline.success_xout_count
#ifdef DT_BUILD102739E_DICTIONARY_CLASSIFIER
		&& baseline.dictionary_object_count <= baseline.success_object_count
		&& baseline.domain_key_present_count <= baseline.dictionary_object_count
		&& baseline.action_key_present_count <= baseline.dictionary_object_count
		&& baseline.domain_action_envelope_count <= baseline.domain_key_present_count
		&& baseline.domain_action_envelope_count <= baseline.action_key_present_count
		&& baseline.exact_controlled_probe_count <= baseline.domain_action_envelope_count
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
		&& baseline.domain_nonzero_count <= baseline.domain_action_envelope_count
		&& baseline.systemwide_domain_candidate_count <= baseline.domain_nonzero_count
		&& baseline.audit_token_capture_count <= baseline.exact_controlled_probe_count
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
		&& baseline.domain_resolution_success_count <= baseline.domain_resolution_attempt_count
		&& baseline.domain_resolution_attempt_count <= baseline.exact_controlled_probe_count
		&& baseline.permission_allow_count <= baseline.permission_check_count
		&& baseline.permission_check_count <= baseline.domain_resolution_success_count
		&& baseline.action_nonzero_count <= baseline.permission_allow_count
			&& baseline.action_resolution_success_count <= baseline.action_resolution_attempt_count
			&& baseline.action_resolution_attempt_count <= baseline.action_nonzero_count
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
			&& baseline.handler_pointer_capture_count <= baseline.action_resolution_success_count
			&& baseline.handler_pointer_nonnull_count <= baseline.handler_pointer_capture_count
			&& baseline.args_zero_initialized_count <= baseline.handler_pointer_nonnull_count
			&& baseline.argsout_zero_initialized_count <= baseline.handler_pointer_nonnull_count
			&& baseline.arg_descriptor_scan_count <= baseline.handler_pointer_nonnull_count
			&& baseline.arg_descriptor_root_path_count <= baseline.arg_descriptor_scan_count
			&& baseline.arg_descriptor_string_type_count <= baseline.arg_descriptor_scan_count
			&& baseline.arg_descriptor_out_count <= baseline.arg_descriptor_scan_count
			&& baseline.output_slot_bind_count <= baseline.arg_descriptor_out_count
				&& baseline.arg_terminator_found_count <= baseline.handler_pointer_nonnull_count
				&& baseline.marshalling_complete_count <= baseline.handler_pointer_nonnull_count
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
				&& baseline.handler_call_attempt_count <= baseline.marshalling_complete_count
				&& baseline.handler_invocation_count <= baseline.handler_call_attempt_count
				&& baseline.handler_return_count <= baseline.handler_invocation_count
				&& baseline.handler_arg0_output_slot_match_count <= baseline.handler_call_attempt_count
				&& baseline.handler_args1_through_7_null_count <= baseline.handler_invocation_count
				&& baseline.handler_output_write_count <= baseline.handler_invocation_count
				&& baseline.argsout0_sentinel_match_count <= baseline.handler_return_count
				&& baseline.argsout_tail_null_count <= baseline.handler_return_count
				&& baseline.handler_result_match_count <= baseline.handler_return_count
					&& baseline.controlled_handler_complete_count <= baseline.handler_return_count
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
					&& baseline.original_receive_return_count <= baseline.original_receive_call_count
					&& baseline.original_receive_call_count <= baseline.entry_count
					&& baseline.reply_create_success_count <= baseline.reply_create_attempt_count
					&& baseline.reply_send_return_count <= baseline.reply_send_attempt_count
					&& baseline.server_reply_release_count <= baseline.reply_send_return_count
					&& baseline.input_consume_release_count <= baseline.server_reply_release_count
					&& baseline.committed_consume_path_complete_count <= baseline.input_consume_release_count
					&& baseline.server_committed_lifecycle_pass_count <= baseline.committed_consume_path_complete_count
					&& baseline.wrapper_return_22_count <= baseline.committed_consume_path_complete_count
#endif
#endif
#endif
#endif
#endif
#endif
		;
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BASELINE_READ_RC=%d\n", baselineReadRc);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BASELINE_INVARIANTS=%s\n",
		baselineInvariants ? "PASS" : "FAIL");
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BASELINE_ENTRY_COUNT=%llu\n",
		(unsigned long long)baseline.entry_count);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_BASELINE_RETURN_COUNT=%llu\n",
		(unsigned long long)baseline.return_count);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_BASELINE_EXACT_PROBE_COUNT=%llu\n",
		(unsigned long long)baseline.exact_controlled_probe_count);
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	fprintf(stderr, "BUILD102739E_BASELINE_EXACT_PROBE_COUNT=%llu\n",
		(unsigned long long)baseline.exact_controlled_probe_count);
#endif
	if (!baselineInvariants)
		return 16;
	int triggerSendRc = dt102739d_send_one_launchd_request();
	#endif
	kern_return_t telemetryReadRc = KERN_FAILURE;
	unsigned int pollAttempt = 0;
	bool invariantsOk = false;
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POLL_INTERVAL_US=%u\n",
		DT102739B_POLL_INTERVAL_US);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POLL_ATTEMPT_LIMIT=%u\n",
		DT102739B_POLL_ATTEMPTS);
	do {
		telemetryReadRc = task_read(task, symbol, &telemetry, sizeof(telemetry));
		invariantsOk = telemetryReadRc == KERN_SUCCESS
			&& telemetry.return_count <= telemetry.entry_count
			&& telemetry.success_return_count <= telemetry.return_count
			&& telemetry.xout_argument_count <= telemetry.return_count
			&& telemetry.success_xout_count <= telemetry.success_return_count
			&& telemetry.success_xout_count <= telemetry.xout_argument_count
			&& telemetry.success_object_count <= telemetry.success_xout_count
#ifdef DT_BUILD102739E_DICTIONARY_CLASSIFIER
			&& telemetry.dictionary_object_count <= telemetry.success_object_count
			&& telemetry.domain_key_present_count <= telemetry.dictionary_object_count
			&& telemetry.action_key_present_count <= telemetry.dictionary_object_count
			&& telemetry.domain_action_envelope_count <= telemetry.domain_key_present_count
			&& telemetry.domain_action_envelope_count <= telemetry.action_key_present_count
			&& telemetry.exact_controlled_probe_count <= telemetry.domain_action_envelope_count
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
			&& telemetry.domain_nonzero_count <= telemetry.domain_action_envelope_count
			&& telemetry.systemwide_domain_candidate_count <= telemetry.domain_nonzero_count
			&& telemetry.audit_token_capture_count <= telemetry.exact_controlled_probe_count
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
			&& telemetry.domain_resolution_success_count <= telemetry.domain_resolution_attempt_count
			&& telemetry.domain_resolution_attempt_count <= telemetry.exact_controlled_probe_count
			&& telemetry.permission_allow_count <= telemetry.permission_check_count
			&& telemetry.permission_check_count <= telemetry.domain_resolution_success_count
			&& telemetry.action_nonzero_count <= telemetry.permission_allow_count
				&& telemetry.action_resolution_success_count <= telemetry.action_resolution_attempt_count
				&& telemetry.action_resolution_attempt_count <= telemetry.action_nonzero_count
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
				&& telemetry.handler_pointer_capture_count <= telemetry.action_resolution_success_count
				&& telemetry.handler_pointer_nonnull_count <= telemetry.handler_pointer_capture_count
				&& telemetry.args_zero_initialized_count <= telemetry.handler_pointer_nonnull_count
				&& telemetry.argsout_zero_initialized_count <= telemetry.handler_pointer_nonnull_count
				&& telemetry.arg_descriptor_scan_count <= telemetry.handler_pointer_nonnull_count
				&& telemetry.arg_descriptor_root_path_count <= telemetry.arg_descriptor_scan_count
				&& telemetry.arg_descriptor_string_type_count <= telemetry.arg_descriptor_scan_count
				&& telemetry.arg_descriptor_out_count <= telemetry.arg_descriptor_scan_count
				&& telemetry.output_slot_bind_count <= telemetry.arg_descriptor_out_count
					&& telemetry.arg_terminator_found_count <= telemetry.handler_pointer_nonnull_count
					&& telemetry.marshalling_complete_count <= telemetry.handler_pointer_nonnull_count
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
					&& telemetry.handler_call_attempt_count <= telemetry.marshalling_complete_count
					&& telemetry.handler_invocation_count <= telemetry.handler_call_attempt_count
					&& telemetry.handler_return_count <= telemetry.handler_invocation_count
					&& telemetry.handler_arg0_output_slot_match_count <= telemetry.handler_call_attempt_count
					&& telemetry.handler_args1_through_7_null_count <= telemetry.handler_invocation_count
					&& telemetry.handler_output_write_count <= telemetry.handler_invocation_count
					&& telemetry.argsout0_sentinel_match_count <= telemetry.handler_return_count
					&& telemetry.argsout_tail_null_count <= telemetry.handler_return_count
					&& telemetry.handler_result_match_count <= telemetry.handler_return_count
						&& telemetry.controlled_handler_complete_count <= telemetry.handler_return_count
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
						&& telemetry.original_receive_return_count <= telemetry.original_receive_call_count
						&& telemetry.original_receive_call_count <= telemetry.entry_count
						&& telemetry.reply_create_success_count <= telemetry.reply_create_attempt_count
						&& telemetry.reply_send_return_count <= telemetry.reply_send_attempt_count
						&& telemetry.server_reply_release_count <= telemetry.reply_send_return_count
						&& telemetry.input_consume_release_count <= telemetry.server_reply_release_count
						&& telemetry.committed_consume_path_complete_count <= telemetry.input_consume_release_count
						&& telemetry.server_committed_lifecycle_pass_count <= telemetry.committed_consume_path_complete_count
						&& telemetry.wrapper_return_22_count <= telemetry.committed_consume_path_complete_count
#endif
#endif
#endif
#endif
#endif
#endif
			;
		if (telemetryReadRc != KERN_SUCCESS
		#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
			#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
				|| ((telemetry.wrapper_return_22_count > baseline.wrapper_return_22_count
					|| telemetry.precommit_fallback_count > baseline.precommit_fallback_count)
					&& invariantsOk)
			#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
			|| (telemetry.exact_controlled_probe_count
				> baseline.exact_controlled_probe_count && invariantsOk)
			#else
			|| (telemetry.return_count > baseline.return_count && invariantsOk)
			#endif
		#else
			|| (telemetry.return_count > 0 && invariantsOk
				&& telemetry.success_object_count > 0)
		#endif
			|| pollAttempt >= DT102739B_POLL_ATTEMPTS)
			break;
		usleep(DT102739B_POLL_INTERVAL_US);
		pollAttempt++;
	} while (true);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_TELEMETRY_READ_RC=%d\n", telemetryReadRc);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_POLL_ATTEMPTS_USED=%u\n", pollAttempt);
	if (telemetryReadRc != KERN_SUCCESS) {
		fprintf(stderr, DT102739_OBSERVER_PREFIX "_TELEMETRY_READ=FAIL\n");
		return 16;
	}
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_TELEMETRY_READ=PASS\n");
	fprintf(stderr, "BUILD102739C_POST_WALL2_ENTRY_COUNT=%llu\n",
		(unsigned long long)telemetry.entry_count);
	fprintf(stderr, "BUILD102739C_POST_WALL2_RETURN_COUNT=%llu\n",
		(unsigned long long)telemetry.return_count);
	fprintf(stderr, "BUILD102739C_SUCCESS_RETURN_COUNT=%llu\n",
		(unsigned long long)telemetry.success_return_count);
	fprintf(stderr, "BUILD102739C_XOUT_ARGUMENT_COUNT=%llu\n",
		(unsigned long long)telemetry.xout_argument_count);
	fprintf(stderr, "BUILD102739C_SUCCESS_XOUT_COUNT=%llu\n",
		(unsigned long long)telemetry.success_xout_count);
	fprintf(stderr, "BUILD102739C_SUCCESS_OBJECT_COUNT=%llu\n",
		(unsigned long long)telemetry.success_object_count);
	fprintf(stderr, "BUILD102739C_COUNTER_INVARIANTS=%s\n",
		invariantsOk ? "PASS" : "FAIL");
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DICTIONARY_OBJECT_COUNT=%llu\n",
		(unsigned long long)telemetry.dictionary_object_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DOMAIN_KEY_PRESENT_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_key_present_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_ACTION_KEY_PRESENT_COUNT=%llu\n",
		(unsigned long long)telemetry.action_key_present_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DOMAIN_ACTION_ENVELOPE_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_action_envelope_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_EXACT_CONTROLLED_PROBE_COUNT=%llu\n",
		(unsigned long long)telemetry.exact_controlled_probe_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DOMAIN_NONZERO_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_nonzero_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_SYSTEMWIDE_DOMAIN_CANDIDATE_COUNT=%llu\n",
		(unsigned long long)telemetry.systemwide_domain_candidate_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_AUDIT_TOKEN_CAPTURE_COUNT=%llu\n",
		(unsigned long long)telemetry.audit_token_capture_count);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TOKEN_PID=%llu\n",
		(unsigned long long)telemetry.captured_pid);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TOKEN_EUID=%llu\n",
		(unsigned long long)telemetry.captured_euid);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_COUNTER_INVARIANTS=%s\n",
		invariantsOk ? "PASS" : "FAIL");
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_DOMAIN_RESOLUTION_ATTEMPT_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_resolution_attempt_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_DOMAIN_RESOLUTION_SUCCESS_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_resolution_success_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_PERMISSION_CHECK_COUNT=%llu\n",
		(unsigned long long)telemetry.permission_check_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_PERMISSION_ALLOW_COUNT=%llu\n",
		(unsigned long long)telemetry.permission_allow_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_ACTION_NONZERO_COUNT=%llu\n",
		(unsigned long long)telemetry.action_nonzero_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_ACTION_RESOLUTION_ATTEMPT_COUNT=%llu\n",
		(unsigned long long)telemetry.action_resolution_attempt_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_ACTION_RESOLUTION_SUCCESS_COUNT=%llu\n",
		(unsigned long long)telemetry.action_resolution_success_count);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_HANDLER_INVOCATION_COUNT=%llu\n",
		(unsigned long long)telemetry.handler_invocation_count);
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_HANDLER_POINTER_CAPTURE_COUNT=%llu\n",
		(unsigned long long)telemetry.handler_pointer_capture_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_HANDLER_POINTER_NONNULL_COUNT=%llu\n",
		(unsigned long long)telemetry.handler_pointer_nonnull_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGS_ZERO_INITIALIZED_COUNT=%llu\n",
		(unsigned long long)telemetry.args_zero_initialized_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGSOUT_ZERO_INITIALIZED_COUNT=%llu\n",
		(unsigned long long)telemetry.argsout_zero_initialized_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DESCRIPTOR_SCAN_COUNT=%llu\n",
		(unsigned long long)telemetry.arg_descriptor_scan_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DESCRIPTOR_ROOT_PATH_COUNT=%llu\n",
		(unsigned long long)telemetry.arg_descriptor_root_path_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DESCRIPTOR_STRING_TYPE_COUNT=%llu\n",
		(unsigned long long)telemetry.arg_descriptor_string_type_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DESCRIPTOR_OUT_COUNT=%llu\n",
		(unsigned long long)telemetry.arg_descriptor_out_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_OUTPUT_SLOT_BIND_COUNT=%llu\n",
		(unsigned long long)telemetry.output_slot_bind_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_TERMINATOR_FOUND_COUNT=%llu\n",
		(unsigned long long)telemetry.arg_terminator_found_count);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_MARSHALLING_COMPLETE_COUNT=%llu\n",
			(unsigned long long)telemetry.marshalling_complete_count);
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
		fprintf(stderr, "BUILD102739I_HANDLER_CALL_ATTEMPT_COUNT=%llu\n",
			(unsigned long long)telemetry.handler_call_attempt_count);
		fprintf(stderr, "BUILD102739I_HANDLER_RETURN_COUNT=%llu\n",
			(unsigned long long)telemetry.handler_return_count);
		fprintf(stderr, "BUILD102739I_HANDLER_ARG0_OUTPUT_SLOT_MATCH_COUNT=%llu\n",
			(unsigned long long)telemetry.handler_arg0_output_slot_match_count);
		fprintf(stderr, "BUILD102739I_HANDLER_ARGS1_THROUGH_7_NULL_COUNT=%llu\n",
			(unsigned long long)telemetry.handler_args1_through_7_null_count);
		fprintf(stderr, "BUILD102739I_HANDLER_OUTPUT_WRITE_COUNT=%llu\n",
			(unsigned long long)telemetry.handler_output_write_count);
		fprintf(stderr, "BUILD102739I_ARGSOUT0_SENTINEL_MATCH_COUNT=%llu\n",
			(unsigned long long)telemetry.argsout0_sentinel_match_count);
		fprintf(stderr, "BUILD102739I_ARGSOUT_TAIL_NULL_COUNT=%llu\n",
			(unsigned long long)telemetry.argsout_tail_null_count);
		fprintf(stderr, "BUILD102739I_HANDLER_RESULT_MATCH_COUNT=%llu\n",
			(unsigned long long)telemetry.handler_result_match_count);
		fprintf(stderr, "BUILD102739I_CONTROLLED_HANDLER_COMPLETE_COUNT=%llu\n",
			(unsigned long long)telemetry.controlled_handler_complete_count);
#endif
#endif
#endif
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	fprintf(stderr, "BUILD102739E_DICTIONARY_OBJECT_COUNT=%llu\n",
		(unsigned long long)telemetry.dictionary_object_count);
	fprintf(stderr, "BUILD102739E_DOMAIN_KEY_PRESENT_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_key_present_count);
	fprintf(stderr, "BUILD102739E_ACTION_KEY_PRESENT_COUNT=%llu\n",
		(unsigned long long)telemetry.action_key_present_count);
	fprintf(stderr, "BUILD102739E_DOMAIN_ACTION_ENVELOPE_COUNT=%llu\n",
		(unsigned long long)telemetry.domain_action_envelope_count);
	fprintf(stderr, "BUILD102739E_EXACT_CONTROLLED_PROBE_COUNT=%llu\n",
		(unsigned long long)telemetry.exact_controlled_probe_count);
	fprintf(stderr, "BUILD102739E_COUNTER_INVARIANTS=%s\n",
		invariantsOk ? "PASS" : "FAIL");
#endif
	#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
	bool monotonic = telemetry.entry_count >= baseline.entry_count
		&& telemetry.return_count >= baseline.return_count
		&& telemetry.success_return_count >= baseline.success_return_count
		&& telemetry.xout_argument_count >= baseline.xout_argument_count
		&& telemetry.success_xout_count >= baseline.success_xout_count
		&& telemetry.success_object_count >= baseline.success_object_count
#ifdef DT_BUILD102739E_DICTIONARY_CLASSIFIER
		&& telemetry.dictionary_object_count >= baseline.dictionary_object_count
		&& telemetry.domain_key_present_count >= baseline.domain_key_present_count
		&& telemetry.action_key_present_count >= baseline.action_key_present_count
		&& telemetry.domain_action_envelope_count >= baseline.domain_action_envelope_count
		&& telemetry.exact_controlled_probe_count >= baseline.exact_controlled_probe_count
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
		&& telemetry.domain_nonzero_count >= baseline.domain_nonzero_count
		&& telemetry.systemwide_domain_candidate_count >= baseline.systemwide_domain_candidate_count
		&& telemetry.audit_token_capture_count >= baseline.audit_token_capture_count
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
		&& telemetry.domain_resolution_attempt_count >= baseline.domain_resolution_attempt_count
		&& telemetry.domain_resolution_success_count >= baseline.domain_resolution_success_count
		&& telemetry.permission_check_count >= baseline.permission_check_count
		&& telemetry.permission_allow_count >= baseline.permission_allow_count
		&& telemetry.action_nonzero_count >= baseline.action_nonzero_count
		&& telemetry.action_resolution_attempt_count >= baseline.action_resolution_attempt_count
		&& telemetry.action_resolution_success_count >= baseline.action_resolution_success_count
			&& telemetry.handler_invocation_count >= baseline.handler_invocation_count
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
			&& telemetry.handler_pointer_capture_count >= baseline.handler_pointer_capture_count
			&& telemetry.handler_pointer_nonnull_count >= baseline.handler_pointer_nonnull_count
			&& telemetry.args_zero_initialized_count >= baseline.args_zero_initialized_count
			&& telemetry.argsout_zero_initialized_count >= baseline.argsout_zero_initialized_count
			&& telemetry.arg_descriptor_scan_count >= baseline.arg_descriptor_scan_count
			&& telemetry.arg_descriptor_root_path_count >= baseline.arg_descriptor_root_path_count
			&& telemetry.arg_descriptor_string_type_count >= baseline.arg_descriptor_string_type_count
			&& telemetry.arg_descriptor_out_count >= baseline.arg_descriptor_out_count
			&& telemetry.output_slot_bind_count >= baseline.output_slot_bind_count
				&& telemetry.arg_terminator_found_count >= baseline.arg_terminator_found_count
				&& telemetry.marshalling_complete_count >= baseline.marshalling_complete_count
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
				&& telemetry.handler_call_attempt_count >= baseline.handler_call_attempt_count
				&& telemetry.handler_return_count >= baseline.handler_return_count
				&& telemetry.handler_arg0_output_slot_match_count >= baseline.handler_arg0_output_slot_match_count
				&& telemetry.handler_args1_through_7_null_count >= baseline.handler_args1_through_7_null_count
				&& telemetry.handler_output_write_count >= baseline.handler_output_write_count
				&& telemetry.argsout0_sentinel_match_count >= baseline.argsout0_sentinel_match_count
				&& telemetry.argsout_tail_null_count >= baseline.argsout_tail_null_count
				&& telemetry.handler_result_match_count >= baseline.handler_result_match_count
					&& telemetry.controlled_handler_complete_count >= baseline.controlled_handler_complete_count
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
					&& telemetry.original_receive_call_count >= baseline.original_receive_call_count
					&& telemetry.original_receive_return_count >= baseline.original_receive_return_count
					&& telemetry.reply_create_attempt_count >= baseline.reply_create_attempt_count
					&& telemetry.reply_create_success_count >= baseline.reply_create_success_count
					&& telemetry.reply_create_failed_precommit_count >= baseline.reply_create_failed_precommit_count
					&& telemetry.reply_identity_failed_precommit_count >= baseline.reply_identity_failed_precommit_count
					&& telemetry.root_path_set_count >= baseline.root_path_set_count
					&& telemetry.result_set_count >= baseline.result_set_count
					&& telemetry.root_path_exists_count >= baseline.root_path_exists_count
					&& telemetry.root_path_type_match_count >= baseline.root_path_type_match_count
					&& telemetry.result_exists_count >= baseline.result_exists_count
					&& telemetry.result_type_match_count >= baseline.result_type_match_count
					&& telemetry.reply_readback_match_count >= baseline.reply_readback_match_count
					&& telemetry.reply_readback_failed_precommit_count >= baseline.reply_readback_failed_precommit_count
					&& telemetry.precommit_xout_match_count >= baseline.precommit_xout_match_count
					&& telemetry.precommit_xout_mismatch_count >= baseline.precommit_xout_mismatch_count
					&& telemetry.precommit_reply_release_count >= baseline.precommit_reply_release_count
					&& telemetry.precommit_fallback_count >= baseline.precommit_fallback_count
					&& telemetry.reply_send_attempt_count >= baseline.reply_send_attempt_count
					&& telemetry.reply_send_return_count >= baseline.reply_send_return_count
					&& telemetry.server_reply_release_count >= baseline.server_reply_release_count
					&& telemetry.committed_xout_match_count >= baseline.committed_xout_match_count
					&& telemetry.committed_xout_mismatch_count >= baseline.committed_xout_mismatch_count
					&& telemetry.input_consume_release_count >= baseline.input_consume_release_count
					&& telemetry.committed_consume_path_complete_count >= baseline.committed_consume_path_complete_count
					&& telemetry.server_committed_lifecycle_pass_count >= baseline.server_committed_lifecycle_pass_count
					&& telemetry.wrapper_return_22_count >= baseline.wrapper_return_22_count
#endif
#endif
#endif
#endif
#endif
#endif
		;
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_COUNTERS_MONOTONIC=%s\n",
		monotonic ? "YES" : "NO");
	if (!monotonic)
		return 18;
	uint64_t entryDelta = telemetry.entry_count - baseline.entry_count;
	uint64_t returnDelta = telemetry.return_count - baseline.return_count;
	uint64_t successReturnDelta = telemetry.success_return_count
		- baseline.success_return_count;
	uint64_t successObjectDelta = telemetry.success_object_count
		- baseline.success_object_count;
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_TRIGGER_SEND_COMPLETED_RC=%d\n", triggerSendRc);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_ENTRY_DELTA=%llu\n",
		(unsigned long long)entryDelta);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_RETURN_DELTA=%llu\n",
		(unsigned long long)returnDelta);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_SUCCESS_RETURN_DELTA=%llu\n",
		(unsigned long long)successReturnDelta);
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_SUCCESS_OBJECT_DELTA=%llu\n",
		(unsigned long long)successObjectDelta);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
	uint64_t successXoutDelta = telemetry.success_xout_count
		- baseline.success_xout_count;
	uint64_t dictionaryDelta = telemetry.dictionary_object_count
		- baseline.dictionary_object_count;
	uint64_t domainKeyDelta = telemetry.domain_key_present_count
		- baseline.domain_key_present_count;
	uint64_t actionKeyDelta = telemetry.action_key_present_count
		- baseline.action_key_present_count;
	uint64_t envelopeDelta = telemetry.domain_action_envelope_count
		- baseline.domain_action_envelope_count;
	uint64_t exactProbeDelta = telemetry.exact_controlled_probe_count
		- baseline.exact_controlled_probe_count;
	uint64_t domainNonzeroDelta = telemetry.domain_nonzero_count
		- baseline.domain_nonzero_count;
	uint64_t systemwideDomainDelta = telemetry.systemwide_domain_candidate_count
		- baseline.systemwide_domain_candidate_count;
	uint64_t auditTokenDelta = telemetry.audit_token_capture_count
		- baseline.audit_token_capture_count;
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_SUCCESS_XOUT_DELTA=%llu\n",
		(unsigned long long)successXoutDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DICTIONARY_OBJECT_DELTA=%llu\n",
		(unsigned long long)dictionaryDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DOMAIN_KEY_PRESENT_DELTA=%llu\n",
		(unsigned long long)domainKeyDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_ACTION_KEY_PRESENT_DELTA=%llu\n",
		(unsigned long long)actionKeyDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DOMAIN_ACTION_ENVELOPE_DELTA=%llu\n",
		(unsigned long long)envelopeDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_EXACT_CONTROLLED_PROBE_DELTA=%llu\n",
		(unsigned long long)exactProbeDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_DOMAIN_NONZERO_DELTA=%llu\n",
		(unsigned long long)domainNonzeroDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_SYSTEMWIDE_DOMAIN_CANDIDATE_DELTA=%llu\n",
		(unsigned long long)systemwideDomainDelta);
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_AUDIT_TOKEN_CAPTURE_DELTA=%llu\n",
		(unsigned long long)auditTokenDelta);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
	uint64_t domainResolutionAttemptDelta = telemetry.domain_resolution_attempt_count
		- baseline.domain_resolution_attempt_count;
	uint64_t domainResolutionSuccessDelta = telemetry.domain_resolution_success_count
		- baseline.domain_resolution_success_count;
	uint64_t permissionCheckDelta = telemetry.permission_check_count
		- baseline.permission_check_count;
	uint64_t permissionAllowDelta = telemetry.permission_allow_count
		- baseline.permission_allow_count;
	uint64_t actionNonzeroDelta = telemetry.action_nonzero_count
		- baseline.action_nonzero_count;
	uint64_t actionResolutionAttemptDelta = telemetry.action_resolution_attempt_count
		- baseline.action_resolution_attempt_count;
	uint64_t actionResolutionSuccessDelta = telemetry.action_resolution_success_count
		- baseline.action_resolution_success_count;
	uint64_t handlerInvocationDelta = telemetry.handler_invocation_count
		- baseline.handler_invocation_count;
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_DOMAIN_RESOLUTION_ATTEMPT_DELTA=%llu\n",
		(unsigned long long)domainResolutionAttemptDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_DOMAIN_RESOLUTION_SUCCESS_DELTA=%llu\n",
		(unsigned long long)domainResolutionSuccessDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_PERMISSION_CHECK_DELTA=%llu\n",
		(unsigned long long)permissionCheckDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_PERMISSION_ALLOW_DELTA=%llu\n",
		(unsigned long long)permissionAllowDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_ACTION_NONZERO_DELTA=%llu\n",
		(unsigned long long)actionNonzeroDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_ACTION_RESOLUTION_ATTEMPT_DELTA=%llu\n",
		(unsigned long long)actionResolutionAttemptDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_ACTION_RESOLUTION_SUCCESS_DELTA=%llu\n",
		(unsigned long long)actionResolutionSuccessDelta);
	fprintf(stderr, DT102739_RESOLUTION_PREFIX "_HANDLER_INVOCATION_DELTA=%llu\n",
		(unsigned long long)handlerInvocationDelta);
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
	uint64_t handlerPointerCaptureDelta = telemetry.handler_pointer_capture_count
		- baseline.handler_pointer_capture_count;
	uint64_t handlerPointerNonnullDelta = telemetry.handler_pointer_nonnull_count
		- baseline.handler_pointer_nonnull_count;
	uint64_t argsZeroDelta = telemetry.args_zero_initialized_count
		- baseline.args_zero_initialized_count;
	uint64_t argsoutZeroDelta = telemetry.argsout_zero_initialized_count
		- baseline.argsout_zero_initialized_count;
	uint64_t descriptorScanDelta = telemetry.arg_descriptor_scan_count
		- baseline.arg_descriptor_scan_count;
	uint64_t descriptorRootPathDelta = telemetry.arg_descriptor_root_path_count
		- baseline.arg_descriptor_root_path_count;
	uint64_t descriptorStringTypeDelta = telemetry.arg_descriptor_string_type_count
		- baseline.arg_descriptor_string_type_count;
	uint64_t descriptorOutDelta = telemetry.arg_descriptor_out_count
		- baseline.arg_descriptor_out_count;
	uint64_t outputSlotBindDelta = telemetry.output_slot_bind_count
		- baseline.output_slot_bind_count;
	uint64_t terminatorFoundDelta = telemetry.arg_terminator_found_count
		- baseline.arg_terminator_found_count;
	uint64_t marshallingCompleteDelta = telemetry.marshalling_complete_count
		- baseline.marshalling_complete_count;
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_HANDLER_POINTER_CAPTURE_DELTA=%llu\n",
		(unsigned long long)handlerPointerCaptureDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_HANDLER_POINTER_NONNULL_DELTA=%llu\n",
		(unsigned long long)handlerPointerNonnullDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGS_ZERO_INITIALIZED_DELTA=%llu\n",
		(unsigned long long)argsZeroDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGSOUT_ZERO_INITIALIZED_DELTA=%llu\n",
		(unsigned long long)argsoutZeroDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DESCRIPTOR_SCAN_DELTA=%llu\n",
		(unsigned long long)descriptorScanDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DESCRIPTOR_COUNT=%llu\n",
		(unsigned long long)descriptorScanDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_NAME_ROOT_PATH_DELTA=%llu\n",
		(unsigned long long)descriptorRootPathDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_TYPE_STRING_DELTA=%llu\n",
		(unsigned long long)descriptorStringTypeDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_DIRECTION_OUT_DELTA=%llu\n",
		(unsigned long long)descriptorOutDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_OUTPUT_SLOT_BIND_DELTA=%llu\n",
		(unsigned long long)outputSlotBindDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARG_TERMINATOR_FOUND_DELTA=%llu\n",
		(unsigned long long)terminatorFoundDelta);
		fprintf(stderr, DT102739_ARGUMENT_PREFIX "_MARSHALLING_COMPLETE_DELTA=%llu\n",
			(unsigned long long)marshallingCompleteDelta);
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
		uint64_t handlerCallAttemptDelta = telemetry.handler_call_attempt_count
			- baseline.handler_call_attempt_count;
		uint64_t handlerReturnDelta = telemetry.handler_return_count
			- baseline.handler_return_count;
		uint64_t handlerArg0MatchDelta = telemetry.handler_arg0_output_slot_match_count
			- baseline.handler_arg0_output_slot_match_count;
		uint64_t handlerTailNullDelta = telemetry.handler_args1_through_7_null_count
			- baseline.handler_args1_through_7_null_count;
		uint64_t handlerOutputWriteDelta = telemetry.handler_output_write_count
			- baseline.handler_output_write_count;
		uint64_t argsout0SentinelDelta = telemetry.argsout0_sentinel_match_count
			- baseline.argsout0_sentinel_match_count;
		uint64_t argsoutTailNullDelta = telemetry.argsout_tail_null_count
			- baseline.argsout_tail_null_count;
		uint64_t handlerResultMatchDelta = telemetry.handler_result_match_count
			- baseline.handler_result_match_count;
			uint64_t controlledCompleteDelta = telemetry.controlled_handler_complete_count
				- baseline.controlled_handler_complete_count;
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_HANDLER_CALL_ATTEMPT_DELTA=%llu\n",
				(unsigned long long)handlerCallAttemptDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_HANDLER_RETURN_DELTA=%llu\n",
				(unsigned long long)handlerReturnDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_HANDLER_ARG0_OUTPUT_SLOT_MATCH_DELTA=%llu\n",
				(unsigned long long)handlerArg0MatchDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_HANDLER_ARGS1_THROUGH_7_NULL_DELTA=%llu\n",
				(unsigned long long)handlerTailNullDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_HANDLER_OUTPUT_WRITE_DELTA=%llu\n",
				(unsigned long long)handlerOutputWriteDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_ARGSOUT0_SENTINEL_MATCH_DELTA=%llu\n",
				(unsigned long long)argsout0SentinelDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_ARGSOUT_TAIL_NULL_DELTA=%llu\n",
				(unsigned long long)argsoutTailNullDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_HANDLER_RESULT_MATCH_DELTA=%llu\n",
				(unsigned long long)handlerResultMatchDelta);
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_CONTROLLED_HANDLER_COMPLETE_DELTA=%llu\n",
				(unsigned long long)controlledCompleteDelta);
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
#define DT102739J_DELTA(field) (telemetry.field - baseline.field)
#define DT102739J_PRINT_DELTA(name, field) \
			fprintf(stderr, "BUILD102739J_" name "_DELTA=%llu\n", \
				(unsigned long long)DT102739J_DELTA(field))
			DT102739J_PRINT_DELTA("ORIGINAL_RECEIVE_CALL", original_receive_call_count);
			DT102739J_PRINT_DELTA("ORIGINAL_RECEIVE_RETURN", original_receive_return_count);
			fprintf(stderr, "BUILD102739J_ORIGINAL_RECEIVE_RESULT=%lld\n",
				(long long)(int64_t)telemetry.original_receive_last_result);
			DT102739J_PRINT_DELTA("REPLY_CREATE_ATTEMPT", reply_create_attempt_count);
			DT102739J_PRINT_DELTA("REPLY_CREATE_SUCCESS", reply_create_success_count);
			DT102739J_PRINT_DELTA("REPLY_CREATE_FAILED_PRECOMMIT", reply_create_failed_precommit_count);
			DT102739J_PRINT_DELTA("REPLY_IDENTITY_FAILED_PRECOMMIT", reply_identity_failed_precommit_count);
			DT102739J_PRINT_DELTA("ROOT_PATH_SET", root_path_set_count);
			DT102739J_PRINT_DELTA("RESULT_SET", result_set_count);
			DT102739J_PRINT_DELTA("ROOT_PATH_EXISTS", root_path_exists_count);
			DT102739J_PRINT_DELTA("ROOT_PATH_TYPE_MATCH", root_path_type_match_count);
			DT102739J_PRINT_DELTA("RESULT_EXISTS", result_exists_count);
			DT102739J_PRINT_DELTA("RESULT_TYPE_MATCH", result_type_match_count);
			DT102739J_PRINT_DELTA("REPLY_READBACK_MATCH", reply_readback_match_count);
			DT102739J_PRINT_DELTA("REPLY_READBACK_FAILED_PRECOMMIT", reply_readback_failed_precommit_count);
			DT102739J_PRINT_DELTA("PRECOMMIT_XOUT_MATCH", precommit_xout_match_count);
			DT102739J_PRINT_DELTA("PRECOMMIT_XOUT_MISMATCH", precommit_xout_mismatch_count);
			DT102739J_PRINT_DELTA("PRECOMMIT_REPLY_RELEASE", precommit_reply_release_count);
			DT102739J_PRINT_DELTA("PRECOMMIT_FALLBACK", precommit_fallback_count);
			DT102739J_PRINT_DELTA("REPLY_SEND_ATTEMPT", reply_send_attempt_count);
			DT102739J_PRINT_DELTA("REPLY_SEND_RETURN", reply_send_return_count);
			fprintf(stderr, "BUILD102739J_SERVER_REPLY_SEND_RC=%lld\n",
				(long long)(int64_t)telemetry.server_reply_send_rc);
			DT102739J_PRINT_DELTA("SERVER_REPLY_RELEASE", server_reply_release_count);
			DT102739J_PRINT_DELTA("COMMITTED_XOUT_MATCH_BEFORE_RELEASE", committed_xout_match_count);
			DT102739J_PRINT_DELTA("COMMITTED_XOUT_MISMATCH_BEFORE_RELEASE", committed_xout_mismatch_count);
			DT102739J_PRINT_DELTA("INPUT_CONSUME_RELEASE", input_consume_release_count);
			DT102739J_PRINT_DELTA("COMMITTED_CONSUME_PATH_COMPLETE", committed_consume_path_complete_count);
			DT102739J_PRINT_DELTA("SERVER_COMMITTED_LIFECYCLE_PASS", server_committed_lifecycle_pass_count);
			DT102739J_PRINT_DELTA("WRAPPER_RETURN_22", wrapper_return_22_count);
#undef DT102739J_PRINT_DELTA
#undef DT102739J_DELTA
#endif
#endif
#endif
#endif
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	uint64_t successXoutDelta = telemetry.success_xout_count
		- baseline.success_xout_count;
	uint64_t dictionaryDelta = telemetry.dictionary_object_count
		- baseline.dictionary_object_count;
	uint64_t domainKeyDelta = telemetry.domain_key_present_count
		- baseline.domain_key_present_count;
	uint64_t actionKeyDelta = telemetry.action_key_present_count
		- baseline.action_key_present_count;
	uint64_t envelopeDelta = telemetry.domain_action_envelope_count
		- baseline.domain_action_envelope_count;
	uint64_t exactProbeDelta = telemetry.exact_controlled_probe_count
		- baseline.exact_controlled_probe_count;
	fprintf(stderr, "BUILD102739E_SUCCESS_XOUT_DELTA=%llu\n",
		(unsigned long long)successXoutDelta);
	fprintf(stderr, "BUILD102739E_DICTIONARY_OBJECT_DELTA=%llu\n",
		(unsigned long long)dictionaryDelta);
	fprintf(stderr, "BUILD102739E_DOMAIN_KEY_PRESENT_DELTA=%llu\n",
		(unsigned long long)domainKeyDelta);
	fprintf(stderr, "BUILD102739E_ACTION_KEY_PRESENT_DELTA=%llu\n",
		(unsigned long long)actionKeyDelta);
	fprintf(stderr, "BUILD102739E_DOMAIN_ACTION_ENVELOPE_DELTA=%llu\n",
		(unsigned long long)envelopeDelta);
	fprintf(stderr, "BUILD102739E_EXACT_CONTROLLED_PROBE_DELTA=%llu\n",
		(unsigned long long)exactProbeDelta);
#endif
	#endif

	uint64_t finalGotPointer = 0;
	kern_return_t finalGotReadRc = task_read(task, gotSlot, &finalGotPointer,
		sizeof(finalGotPointer));
	bool finalGotMatches = finalGotReadRc == KERN_SUCCESS
		&& finalGotPointer == (uint64_t)wrapper;
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_FINAL_GOT_READ_RC=%d\n", finalGotReadRc);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_FINAL_GOT_POINTER=0x%llx\n",
		finalGotPointer);
	fprintf(stderr, DT102739_OBSERVER_PREFIX "_FINAL_GOT_POINTER_MATCH=%s\n",
		finalGotMatches ? "YES" : "NO");
	if (!finalGotMatches)
		return 19;
	fprintf(stderr, "BUILD102739C_OUTPUT_CONTRACT_OBSERVED=%s\n",
		invariantsOk && telemetry.success_object_count > 0 ? "YES" : "NO");
	if (!invariantsOk)
		return 18;
	#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
	if (entryDelta == 0) {
		fprintf(stderr, DT102739_TRIGGER_PREFIX "_DETERMINISTIC_INVOCATION=NO\n");
		return 20;
	}
	if (returnDelta != entryDelta) {
		fprintf(stderr, DT102739_TRIGGER_PREFIX "_DETERMINISTIC_RETURN_PATH=FAIL\n");
		return 21;
	}
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_DETERMINISTIC_INVOCATION=YES\n");
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_DETERMINISTIC_RETURN_PATH=PASS\n");
	if (successObjectDelta == 0) {
		fprintf(stderr, DT102739_TRIGGER_PREFIX "_OUTPUT_CONTRACT=INCONCLUSIVE\n");
		return 17;
	}
	fprintf(stderr, DT102739_TRIGGER_PREFIX "_OUTPUT_CONTRACT=PASS\n");
	#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
	    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
	bool pidMatches = g_dt102739f_trigger_pid >= 0
		&& telemetry.captured_pid == (uint64_t)g_dt102739f_trigger_pid;
	bool euidMatches = g_dt102739f_trigger_euid != (uid_t)-1
		&& telemetry.captured_euid == (uint64_t)g_dt102739f_trigger_euid;
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TOKEN_PID_MATCH=%s\n",
		pidMatches ? "YES" : "NO");
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_TOKEN_EUID_MATCH=%s\n",
		euidMatches ? "YES" : "NO");
	if (exactProbeDelta != 1 || domainNonzeroDelta != 1
		|| systemwideDomainDelta != 1 || auditTokenDelta != 1
		|| !pidMatches || !euidMatches) {
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_READ_ONLY_CALLER_IDENTITY=FAIL\n");
		return 22;
	}
	#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
		fprintf(stderr, "BUILD102739J_NONPROBE_RETURN_UNCHANGED=YES\n");
		fprintf(stderr, "BUILD102739J_NONPROBE_OWNERSHIP_UNCHANGED=YES\n");
	#else
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_ORIGINAL_RETURN_PRESERVED=YES\n");
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_OBJECT_OWNERSHIP_UNCHANGED=YES\n");
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_NO_REPLY_CREATED=YES\n");
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_NO_XPC_RELEASE=YES\n");
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_NO_RETURN_22=YES\n");
	#endif
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_REAL_JBROOT_HANDLER_INVOKED=NO\n");
#else
		fprintf(stderr, DT102739_IDENTITY_PREFIX "_NO_HANDLER_DISPATCH=YES\n");
#endif
	fprintf(stderr, DT102739_IDENTITY_PREFIX "_READ_ONLY_CALLER_IDENTITY=PASS\n");
	#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
	    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
			uint64_t expectedHandlerInvocationDelta =
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
				1;
#else
				0;
#endif
			if (domainResolutionAttemptDelta != 1 || domainResolutionSuccessDelta != 1
				|| permissionCheckDelta != 1 || permissionAllowDelta != 1
				|| actionNonzeroDelta != 1 || actionResolutionAttemptDelta != 1
				|| actionResolutionSuccessDelta != 1
				|| handlerInvocationDelta != expectedHandlerInvocationDelta) {
			fprintf(stderr, DT102739_RESOLUTION_PREFIX "_READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION=FAIL\n");
			return 23;
		}
		fprintf(stderr, DT102739_RESOLUTION_PREFIX "_GET_JBROOT_DESCRIPTOR_RESOLVED=YES\n");
		fprintf(stderr, DT102739_RESOLUTION_PREFIX "_READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION=PASS\n");
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
		if (handlerPointerCaptureDelta != 1 || handlerPointerNonnullDelta != 1
			|| argsZeroDelta != 1 || argsoutZeroDelta != 1
			|| descriptorScanDelta != 1 || descriptorRootPathDelta != 1
			|| descriptorStringTypeDelta != 1 || descriptorOutDelta != 1
			|| outputSlotBindDelta != 1 || terminatorFoundDelta != 1
				|| marshallingCompleteDelta != 1
				|| handlerInvocationDelta != expectedHandlerInvocationDelta) {
				fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ACTION_ARGUMENT_MARSHALLING=FAIL\n");
				return 24;
			}
			fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGUMENT_DESCRIPTOR_COUNT=1\n");
			fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGUMENT_DESCRIPTOR_NAME=root-path\n");
			fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGUMENT_DESCRIPTOR_TYPE=JBS_TYPE_STRING\n");
			fprintf(stderr, DT102739_ARGUMENT_PREFIX "_ARGUMENT_DESCRIPTOR_DIRECTION=OUT\n");
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
			if (handlerCallAttemptDelta != 1 || handlerReturnDelta != 1
				|| handlerArg0MatchDelta != 1 || handlerTailNullDelta != 1
				|| handlerOutputWriteDelta != 1 || argsout0SentinelDelta != 1
				|| argsoutTailNullDelta != 1 || handlerResultMatchDelta != 1
				|| controlledCompleteDelta != 1) {
				fprintf(stderr, "BUILD102739I_CONTROLLED_ACTION_HANDLER_ABI=FAIL\n");
				return 25;
			}
			#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
#define DT102739J_EXPECT_DELTA(field, value) \
	((telemetry.field - baseline.field) == (value))
				bool serverLifecyclePass =
					DT102739J_EXPECT_DELTA(original_receive_call_count, 1)
					&& DT102739J_EXPECT_DELTA(original_receive_return_count, 1)
					&& (int64_t)telemetry.original_receive_last_result == 0
					&& DT102739J_EXPECT_DELTA(reply_create_attempt_count, 1)
					&& DT102739J_EXPECT_DELTA(reply_create_success_count, 1)
					&& DT102739J_EXPECT_DELTA(reply_create_failed_precommit_count, 0)
					&& DT102739J_EXPECT_DELTA(reply_identity_failed_precommit_count, 0)
					&& DT102739J_EXPECT_DELTA(root_path_set_count, 1)
					&& DT102739J_EXPECT_DELTA(result_set_count, 1)
					&& DT102739J_EXPECT_DELTA(root_path_exists_count, 1)
					&& DT102739J_EXPECT_DELTA(root_path_type_match_count, 1)
					&& DT102739J_EXPECT_DELTA(result_exists_count, 1)
					&& DT102739J_EXPECT_DELTA(result_type_match_count, 1)
					&& DT102739J_EXPECT_DELTA(reply_readback_match_count, 1)
					&& DT102739J_EXPECT_DELTA(reply_readback_failed_precommit_count, 0)
					&& DT102739J_EXPECT_DELTA(precommit_xout_match_count, 1)
					&& DT102739J_EXPECT_DELTA(precommit_xout_mismatch_count, 0)
					&& DT102739J_EXPECT_DELTA(precommit_reply_release_count, 0)
					&& DT102739J_EXPECT_DELTA(precommit_fallback_count, 0)
					&& DT102739J_EXPECT_DELTA(reply_send_attempt_count, 1)
					&& DT102739J_EXPECT_DELTA(reply_send_return_count, 1)
					&& ((int64_t)telemetry.server_reply_send_rc == 0
						|| (int64_t)telemetry.server_reply_send_rc == 32)
					&& DT102739J_EXPECT_DELTA(server_reply_release_count, 1)
					&& DT102739J_EXPECT_DELTA(committed_xout_match_count, 1)
					&& DT102739J_EXPECT_DELTA(committed_xout_mismatch_count, 0)
					&& DT102739J_EXPECT_DELTA(input_consume_release_count, 1)
					&& DT102739J_EXPECT_DELTA(committed_consume_path_complete_count, 1)
					&& DT102739J_EXPECT_DELTA(server_committed_lifecycle_pass_count, 1)
					&& DT102739J_EXPECT_DELTA(wrapper_return_22_count, 1);
#undef DT102739J_EXPECT_DELTA
				bool clientLifecyclePass = triggerSendRc == 0
					&& g_dt102739j_reply_present && g_dt102739j_reply_dictionary
					&& g_dt102739j_root_exists && g_dt102739j_root_type_string
					&& g_dt102739j_root_matches && g_dt102739j_result_exists
					&& g_dt102739j_result_type_int64 && g_dt102739j_result_matches
					&& g_dt102739j_client_reply_release_count == 1;
				fprintf(stderr, "BUILD102739J_SERVER_COMMITTED_LIFECYCLE=%s\n",
					serverLifecyclePass ? "PASS" : "FAIL");
				fprintf(stderr, "BUILD102739J_CLIENT_REPLY_LIFECYCLE=%s\n",
					clientLifecyclePass ? "PASS" : "FAIL");
				fprintf(stderr, "BUILD102739J_INPUT_CONSUMED_AFTER_REPLY_ATTEMPT=%s\n",
					serverLifecyclePass ? "YES" : "NO");
				fprintf(stderr, "BUILD102739J_RETURN_22_AFTER_INPUT_CONSUME=%s\n",
					serverLifecyclePass ? "YES" : "NO");
				fprintf(stderr, "BUILD102739J_CONTROLLED_ROUNDTRIP_COMPLETE=%s\n",
					serverLifecyclePass && clientLifecyclePass ? "YES" : "NO");
				fprintf(stderr, "BUILD102739J_BOOTSTRAP_TOUCHED=NO\n");
				if (!serverLifecyclePass || !clientLifecyclePass) {
					fprintf(stderr, "BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP=FAIL\n");
					return 26;
				}
				fprintf(stderr, "BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP=PASS\n");
			#else
				fprintf(stderr, "BUILD102739I_HANDLER_RESULT=0\n");
				fprintf(stderr, "BUILD102739I_REPLY_CREATED=NO\n");
			fprintf(stderr, "BUILD102739I_REPLY_SENT=NO\n");
			fprintf(stderr, "BUILD102739I_BOOTSTRAP_TOUCHED=NO\n");
				fprintf(stderr, "BUILD102739I_CONTROLLED_ACTION_HANDLER_ABI=PASS\n");
			#endif
#else
			fprintf(stderr, "BUILD102739H_HANDLER_INVOKED=NO\n");
			fprintf(stderr, "BUILD102739H_REPLY_CREATED=NO\n");
			fprintf(stderr, "BUILD102739H_BOOTSTRAP_TOUCHED=NO\n");
			fprintf(stderr, "BUILD102739H_READ_ONLY_ACTION_ARGUMENT_MARSHALLING=PASS\n");
#endif
#endif
	#endif
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
	if (exactProbeDelta != 1) {
		fprintf(stderr, "BUILD102739E_READ_ONLY_DICTIONARY_CLASSIFICATION=FAIL\n");
		return 22;
	}
	fprintf(stderr, "BUILD102739E_ORIGINAL_RETURN_PRESERVED=YES\n");
	fprintf(stderr, "BUILD102739E_READ_ONLY_DICTIONARY_CLASSIFICATION=PASS\n");
#endif
	return 0;
	#else
	if (telemetry.return_count == 0 || telemetry.success_object_count == 0)
		return 17;
	return 0;
	#endif
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
	vm_address_t launchdImage = getRemoteImageAddress(task, allImageInfo,
		DT102739B_LAUNCHD_PATH);
	vm_address_t wrapper = remoteDlSym(task, image,
		"_dt102738y_counting_wrapper");
	vm_address_t gotSlot = launchdImage
		? launchdImage + DT102739B_LAUNCHD_GOT_OFFSET : 0;
	uint64_t gotPointer = 0;
	kern_return_t gotReadRc = gotSlot
		? task_read(task, gotSlot, &gotPointer, sizeof(gotPointer))
		: KERN_INVALID_ADDRESS;
	bool gotMatches = launchdImage && wrapper && gotReadRc == KERN_SUCCESS
		&& gotPointer == (uint64_t)wrapper;
	fprintf(stderr, "BUILD102739B_LAUNCHD_IMAGE_ADDRESS=0x%llx\n",
		(uint64_t)launchdImage);
	fprintf(stderr, "BUILD102739B_WRAPPER_SYMBOL_ADDRESS=0x%llx\n",
		(uint64_t)wrapper);
	fprintf(stderr, "BUILD102739B_POST_WALL2_GOT_SLOT_ADDRESS=0x%llx\n",
		(uint64_t)gotSlot);
	fprintf(stderr, "BUILD102739B_POST_WALL2_GOT_READ_RC=%d\n", gotReadRc);
	fprintf(stderr, "BUILD102739B_POST_WALL2_GOT_POINTER=0x%llx\n",
		gotPointer);
	fprintf(stderr, "BUILD102739B_POST_WALL2_GOT_POINTER_MATCH=%s\n",
		gotMatches ? "YES" : "NO");
	if (!gotMatches)
		return 19;

	dt102739b_return_telemetry_t telemetry = {0, 0};
	kern_return_t returnReadRc = KERN_FAILURE;
	kern_return_t entryReadRc = KERN_FAILURE;
	unsigned int pollAttempt = 0;
	fprintf(stderr, "BUILD102739B_POLL_INTERVAL_US=%u\n",
		DT102739B_POLL_INTERVAL_US);
	fprintf(stderr, "BUILD102739B_POLL_ATTEMPT_LIMIT=%u\n",
		DT102739B_POLL_ATTEMPTS);
	/* Return-first then entry preserves the meaningful entry >= return
	 * relationship if launchd traffic arrives between the two reads.  A
	 * bounded helper-side wait adds no work or wait inside PID 1. */
	returnReadRc = task_read(task, symbol + sizeof(uint64_t),
		&telemetry.return_count, sizeof(telemetry.return_count));
	entryReadRc = task_read(task, symbol,
		&telemetry.entry_count, sizeof(telemetry.entry_count));
	fprintf(stderr, "BUILD102739B_BASELINE_RETURN_READ_RC=%d\n", returnReadRc);
	fprintf(stderr, "BUILD102739B_BASELINE_ENTRY_READ_RC=%d\n", entryReadRc);
	fprintf(stderr, "BUILD102739B_BASELINE_ENTRY_COUNT=%llu\n",
		(unsigned long long)telemetry.entry_count);
	fprintf(stderr, "BUILD102739B_BASELINE_RETURN_COUNT=%llu\n",
		(unsigned long long)telemetry.return_count);
	while (returnReadRc == KERN_SUCCESS && entryReadRc == KERN_SUCCESS
		&& telemetry.return_count == 0
		&& pollAttempt < DT102739B_POLL_ATTEMPTS) {
		usleep(DT102739B_POLL_INTERVAL_US);
		pollAttempt++;
		returnReadRc = task_read(task, symbol + sizeof(uint64_t),
			&telemetry.return_count, sizeof(telemetry.return_count));
		entryReadRc = task_read(task, symbol,
			&telemetry.entry_count, sizeof(telemetry.entry_count));
		if (returnReadRc != KERN_SUCCESS || entryReadRc != KERN_SUCCESS
			|| telemetry.return_count > 0)
			break;
	}
	fprintf(stderr, "BUILD102739B_RETURN_COUNT_READ_RC=%d\n", returnReadRc);
	fprintf(stderr, "BUILD102739B_ENTRY_COUNT_READ_RC=%d\n", entryReadRc);
	fprintf(stderr, "BUILD102739B_POLL_ATTEMPTS_USED=%u\n", pollAttempt);
	if (returnReadRc != KERN_SUCCESS || entryReadRc != KERN_SUCCESS) {
		fprintf(stderr, "BUILD102739B_TELEMETRY_READ=FAIL\n");
		return 16;
	}
	fprintf(stderr, "BUILD102739B_TELEMETRY_READ=PASS\n");
	fprintf(stderr, "BUILD102739B_POST_WALL2_ENTRY_COUNT=%llu\n",
		(unsigned long long)telemetry.entry_count);
	fprintf(stderr, "BUILD102739B_POST_WALL2_RETURN_COUNT=%llu\n",
		(unsigned long long)telemetry.return_count);
	uint64_t finalGotPointer = 0;
	kern_return_t finalGotReadRc = task_read(task, gotSlot, &finalGotPointer,
		sizeof(finalGotPointer));
	bool finalGotMatches = finalGotReadRc == KERN_SUCCESS
		&& finalGotPointer == (uint64_t)wrapper;
	fprintf(stderr, "BUILD102739B_FINAL_GOT_READ_RC=%d\n", finalGotReadRc);
	fprintf(stderr, "BUILD102739B_FINAL_GOT_POINTER=0x%llx\n",
		finalGotPointer);
	fprintf(stderr, "BUILD102739B_FINAL_GOT_POINTER_MATCH=%s\n",
		finalGotMatches ? "YES" : "NO");
	if (!finalGotMatches)
		return 19;
	fprintf(stderr, "BUILD102739B_RETURN_PATH_OBSERVED=%s\n",
		telemetry.return_count > 0 && telemetry.entry_count >= telemetry.return_count
			? "YES" : "NO");
	if (telemetry.return_count == 0)
		return 17;
	return telemetry.entry_count >= telemetry.return_count ? 0 : 18;
#else
	uint64_t count = 0;
	kern_return_t readRc = task_read(task, symbol, &count, sizeof(count));
	fprintf(stderr, "BUILD102739A_COUNTER_READ_RC=%d\n", readRc);
	if (readRc != KERN_SUCCESS) {
		fprintf(stderr, "BUILD102739A_COUNTER_READ=FAIL\n");
		return 16;
	}
	fprintf(stderr, "BUILD102739A_COUNTER_READ=PASS\n");
	fprintf(stderr, "BUILD102739A_POST_WALL2_INVOCATION_COUNT=%llu\n",
		(unsigned long long)count);
	fprintf(stderr, "BUILD102739A_POST_WALL2_INVOCATION_OBSERVED=%s\n",
		count > 0 ? "YES" : "NO");
	return count > 0 ? 0 : 17;
#endif
}
#endif

#ifdef DT_BUILD102736C_TASKPORT_REPAIR
typedef int (*dt102736c_proc_pidpath_fn)(int pid, void *buffer, uint32_t buffersize);

static const char *dt102736c_yesno(bool value)
{
	return value ? "YES" : "NO";
}

static int dt102736c_proc_pidpath(pid_t pid, char *path, size_t pathSize)
{
	if (!path || pathSize == 0)
		return -EINVAL;
	path[0] = '\0';
	dt102736c_proc_pidpath_fn proc_pidpath_fn =
		(dt102736c_proc_pidpath_fn)dlsym(RTLD_DEFAULT, "proc_pidpath");
	if (!proc_pidpath_fn)
		return -ENOENT;
	errno = 0;
	int rc = proc_pidpath_fn((int)pid, path, (uint32_t)pathSize);
	if (rc <= 0) {
		int e = errno;
		path[0] = '\0';
		return e ? -e : rc;
	}
	path[pathSize - 1] = '\0';
	return rc;
}

static bool dt102736c_path_is_launchd(const char *path)
{
	static const char suffix[] = "/sbin/launchd";
	if (!path || !path[0])
		return false;
	size_t pathLen = strlen(path);
	size_t suffixLen = strlen(suffix);
	return pathLen >= suffixLen && strcmp(path + pathLen - suffixLen, suffix) == 0;
}

static bool dt102736c_log_target_identity(pid_t targetPid, const char *source)
{
	char targetPath[PROC_PIDPATHINFO_MAXSIZE];
	int pathRc = dt102736c_proc_pidpath(targetPid, targetPath, sizeof(targetPath));
	bool isLaunchd = (targetPid == 1) && pathRc > 0 && dt102736c_path_is_launchd(targetPath);
	fprintf(stderr, "BUILD102736C_TARGET_PID=%d\n", targetPid);
	fprintf(stderr, "BUILD102736C_TARGET_PID_SOURCE=%s\n", source ? source : "UNKNOWN");
	fprintf(stderr, "BUILD102736C_TARGET_PID_PATH=%s\n", pathRc > 0 ? targetPath : "");
	fprintf(stderr, "BUILD102736C_TARGET_PID_PATH_RC=%d\n", pathRc);
	fprintf(stderr, "BUILD102736C_TARGET_IS_LAUNCHD=%s\n", dt102736c_yesno(isLaunchd));
	return isLaunchd;
}

static bool dt102736c_validate_task_port(task_t procTask, task_dyld_info_data_t *dyldInfoOut)
{
	mach_port_type_t portType = 0;
	kern_return_t typeRc = mach_port_type(mach_task_self(), procTask, &portType);
	bool validMacro = MACH_PORT_VALID(procTask);
	bool hasSend = typeRc == KERN_SUCCESS && (portType & MACH_PORT_TYPE_SEND);
	fprintf(stderr, "BUILD102736C_TASK_PORT_NAME=%u\n", procTask);
	fprintf(stderr, "BUILD102736C_MACH_PORT_VALID_MACRO=%s\n", dt102736c_yesno(validMacro));
	fprintf(stderr, "BUILD102736C_MACH_PORT_TYPE_RC=%d\n", typeRc);
	fprintf(stderr, "BUILD102736C_MACH_PORT_TYPE=0x%x\n", portType);
	fprintf(stderr, "BUILD102736C_TASK_PORT_HAS_SEND_RIGHT=%s\n", dt102736c_yesno(hasSend));

	bool taskInfoAttempted = validMacro && hasSend;
	fprintf(stderr, "BUILD102736C_TASK_INFO_ATTEMPTED=%s\n",
		dt102736c_yesno(taskInfoAttempted));
	kern_return_t taskInfoRc = KERN_INVALID_NAME;
	if (taskInfoAttempted) {
		task_dyld_info_data_t dyldInfo;
		mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
		memset(&dyldInfo, 0, sizeof(dyldInfo));
		taskInfoRc = task_info(procTask, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		if (taskInfoRc == KERN_SUCCESS && dyldInfoOut)
			*dyldInfoOut = dyldInfo;
	}
	fprintf(stderr, "BUILD102736C_TASK_INFO_RC=%d\n", taskInfoRc);
	bool usable = validMacro && hasSend && taskInfoRc == KERN_SUCCESS;
	fprintf(stderr, "BUILD102736C_TASK_PORT_CONFIRMED_USABLE=%s\n", dt102736c_yesno(usable));
	return usable;
}
#endif


char* resolvePath(char* pathToResolve)
{
	if(strlen(pathToResolve) == 0) return NULL;
	if(pathToResolve[0] == '/')
	{
		return strdup(pathToResolve);
	}
	else
	{
		char absolutePath[PATH_MAX];
		if (realpath(pathToResolve, absolutePath) == NULL) {
			perror("[resolvePath] realpath");
			return NULL;
		}
		return strdup(absolutePath);
	}
}

extern int posix_spawnattr_set_ptrauth_task_port_np(posix_spawnattr_t * __restrict attr, mach_port_t port);
void spawnPacChild(int argc, char *argv[])
{
	char** argsToPass = malloc(sizeof(char*) * (argc + 2));
	for(int i = 0; i < argc; i++)
	{
		argsToPass[i] = argv[i];
	}
	argsToPass[argc] = "pac";
	argsToPass[argc+1] = NULL;

	pid_t targetPid = atoi(argv[1]);
	mach_port_t task;
	kern_return_t kr = KERN_SUCCESS;
	kr = task_for_pid(mach_task_self(), targetPid, &task);
	if(kr != KERN_SUCCESS) {
		printf("[spawnPacChild] Failed to obtain task port.\n");
		return;
	}
	printf("[spawnPacChild] Got task port %d for pid %d\n", task, targetPid);

	posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
	posix_spawnattr_set_ptrauth_task_port_np(&attr, task);

	uint32_t executablePathSize = 0;
	_NSGetExecutablePath(NULL, &executablePathSize);
	char *executablePath = malloc(executablePathSize);
	_NSGetExecutablePath(executablePath, &executablePathSize);

	int status = -200;
	pid_t pid;
	int rc = posix_spawn(&pid, executablePath, NULL, &attr, argsToPass, NULL);

	posix_spawnattr_destroy(&attr);
	free(argsToPass);
	free(executablePath);

	if(rc != KERN_SUCCESS)
	{
		printf("[spawnPacChild] posix_spawn failed: %d (%s)\n", rc, mach_error_string(rc));
		return;
	}

	do
	{
		if (waitpid(pid, &status, 0) != -1) {
			printf("[spawnPacChild] Child returned %d\n", WEXITSTATUS(status));
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));

	return;
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool
	{
		setlinebuf(stdout);
		setlinebuf(stderr);
		if (argc < 3 || argc > 5)
		{
			printf("Usage: opainject <pid> <path/to/dylib> [post-consume]\n");
			return -1;
		}
		bool observeCounter = false;
#if defined(DT_BUILD102739A_OBSERVER) || defined(DT_BUILD102739B_RETURN_OBSERVER) \
	|| defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
		for (int ai = 3; ai < argc; ai++) {
			if (argv[ai] && strcmp(argv[ai], "observe-counter") == 0)
				observeCounter = true;
		}
		if (observeCounter)
			fprintf(stderr, DT102739_OBSERVER_PREFIX "_OBSERVER_MODE=READ_ONLY\n");
#ifdef DT_BUILD102739D_DETERMINISTIC_TRIGGER
		if (observeCounter) {
			fprintf(stderr, DT102739_TRIGGER_PREFIX "_OBSERVER_MODE=READ_ONLY_REMOTE_TELEMETRY_PLUS_LOCAL_XPC_TRIGGER\n");
			fprintf(stderr, DT102739_TRIGGER_PREFIX "_REMOTE_DLOPEN_ATTEMPTED=NO\n");
			fprintf(stderr, DT102739_TRIGGER_PREFIX "_REMOTE_WRITE_ATTEMPTED=NO\n");
		}
#endif
#endif

#ifdef __arm64e__
		char* pacArg = NULL;
		if(argc >= 4)
		{
			pacArg = argv[argc - 1];
		}
		if (!pacArg || (strcmp("pac", pacArg) != 0))
		{
			spawnPacChild(argc, argv);
			return 0;
		}
#endif

		bool skipSandboxFixup = false;
		for (int ai = 3; ai < argc; ai++) {
			if (argv[ai] && strcmp(argv[ai], "post-consume") == 0) {
				skipSandboxFixup = true;
				break;
			}
		}
			if (skipSandboxFixup) {
				fprintf(stderr, "KCALL681_OPAINJECT_SKIP_SANDBOX_POST_KCALL\n");
			}

			printf("OPAINJECT HERE WE ARE\n");
			printf("RUNNING AS %d\n", getuid());

			pid_t targetPid = atoi(argv[1]);
			fprintf(stderr, "BUILD102734C_OPAINJECT_TARGET_PID=%d\n", targetPid);
			fprintf(stderr, "BUILD102734C_OPAINJECT_RAW_PATH=%s\n", argv[2] ? argv[2] : "");
			fprintf(stderr, "BUILD102734C_OPAINJECT_SKIP_SANDBOX_POST_KCALL=%s\n",
				skipSandboxFixup ? "YES" : "NO");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
			fprintf(stderr, "BUILD102736C_OPAINJECT_RAW_PATH=%s\n", argv[2] ? argv[2] : "");
			fprintf(stderr, "BUILD102736C_OPAINJECT_SKIP_SANDBOX_POST_KCALL=%s\n",
				skipSandboxFixup ? "YES" : "NO");
			bool targetIsLaunchd = dt102736c_log_target_identity(targetPid, "ARGV_PID");
			if (!targetIsLaunchd) {
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_RC=-1\n");
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_OUTPUT_AFTER=0\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102736C_OPAINJECT_FAILURE_BRANCH=WRONG_TARGET_PID\n");
				return -5;
			}
#endif
			kern_return_t kret = 0;
			task_t procTask = MACH_PORT_NULL;
			char* dylibPath = resolvePath(argv[2]);
			if(!dylibPath) {
				fprintf(stderr, "BUILD102734C_OPAINJECT_RESOLVED_PATH=\n");
				fprintf(stderr, "BUILD102734C_OPAINJECT_PATH_RESOLUTION=FAIL\n");
				fprintf(stderr, "BUILD102734C_TASK_FOR_PID_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102734C_TASK_FOR_PID_RC=-1\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT=0\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT_VALID=NO\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT_VALIDATION_METHOD=MACH_PORT_VALID\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102734C_OPAINJECT_FAILURE_BRANCH=PATH_RESOLUTION\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_RC=-1\n");
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_OUTPUT_AFTER=0\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102736C_OPAINJECT_FAILURE_BRANCH=PATH_RESOLUTION\n");
#endif
				return -3;
			}
			fprintf(stderr, "BUILD102734C_OPAINJECT_RESOLVED_PATH=%s\n", dylibPath);
			fprintf(stderr, "BUILD102734C_OPAINJECT_PATH_RESOLUTION=PASS\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
			fprintf(stderr, "BUILD102736C_OPAINJECT_RESOLVED_PATH=%s\n", dylibPath);
			fprintf(stderr, "BUILD102736C_OPAINJECT_PATH_RESOLUTION=PASS\n");
#endif
			if(access(dylibPath, R_OK) < 0)
			{
				printf("ERROR: Can't access passed dylib at %s\n", dylibPath);
				fprintf(stderr, "BUILD102734C_TASK_FOR_PID_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102734C_TASK_FOR_PID_RC=-1\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT=0\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT_VALID=NO\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT_VALIDATION_METHOD=MACH_PORT_VALID\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102734C_OPAINJECT_FAILURE_BRANCH=OTHER\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_RC=-1\n");
				fprintf(stderr, "BUILD102736C_TASK_FOR_PID_OUTPUT_AFTER=0\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102736C_OPAINJECT_FAILURE_BRANCH=PATH_ACCESS\n");
#endif
				return -4;
			}

			// get task port
			fprintf(stderr, "BUILD102734C_TASK_FOR_PID_ATTEMPTED=YES\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
			void *tfpSymbol = dlsym(RTLD_DEFAULT, "task_for_pid");
			if (!tfpSymbol)
				tfpSymbol = (void *)(uintptr_t)&task_for_pid;
			task_t procTaskBefore = procTask;
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_SYMBOL_ADDRESS=%p\n", tfpSymbol);
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_OUTPUT_BEFORE=%u\n", procTaskBefore);
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_ATTEMPTED=YES\n");
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_ATTEMPT=1\n");
#endif
			kret = task_for_pid(mach_task_self(), targetPid, &procTask);
			fprintf(stderr, "BUILD102734C_TASK_FOR_PID_RC=%d\n", kret);
			fprintf(stderr, "BUILD102734C_TASK_PORT=%u\n", procTask);
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_RC=%d\n", kret);
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_OUTPUT_AFTER=%u\n", procTask);
			fprintf(stderr, "BUILD102736C_TASK_FOR_PID_OUTPUT_CHANGED=%s\n",
				dt102736c_yesno(procTask != procTaskBefore));
			fprintf(stderr, "BUILD102736C_TASK_PORT=%u\n", procTask);
#endif
			if(kret != KERN_SUCCESS)
			{
				printf("ERROR: task_for_pid failed with error code %d (%s)\n", kret, mach_error_string(kret));
				fprintf(stderr, "BUILD102734C_TASK_PORT_VALID=NO\n");
				fprintf(stderr, "BUILD102734C_TASK_PORT_VALIDATION_METHOD=MACH_PORT_VALID\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102734C_OPAINJECT_FAILURE_BRANCH=TASK_FOR_PID\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
				(void)dt102736c_validate_task_port(procTask, NULL);
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102736C_OPAINJECT_FAILURE_BRANCH=TASK_FOR_PID\n");
#endif
#if defined(DT_BUILD102739A_OBSERVER) || defined(DT_BUILD102739B_RETURN_OBSERVER) \
	|| defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
				if (observeCounter)
					fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_OBSERVER_TASK_PORT=FAIL\n");
#endif
				return -2;
			}
			bool taskPortValid = MACH_PORT_VALID(procTask);
			fprintf(stderr, "BUILD102734C_TASK_PORT_VALID=%s\n", taskPortValid ? "YES" : "NO");
			fprintf(stderr, "BUILD102734C_TASK_PORT_VALIDATION_METHOD=MACH_PORT_VALID\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
			task_dyld_info_data_t dyldInfo;
			memset(&dyldInfo, 0, sizeof(dyldInfo));
			bool taskPortUsable = dt102736c_validate_task_port(procTask, &dyldInfo);
			if(!taskPortUsable)
#else
			if(!taskPortValid)
#endif
			{
				printf("ERROR: Got invalid task port (%d)\n", procTask);
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102734C_OPAINJECT_FAILURE_BRANCH=INVALID_TASK_PORT\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_ATTEMPTED=NO\n");
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_RC=-1\n");
				fprintf(stderr, "BUILD102736C_OPAINJECT_FAILURE_BRANCH=INVALID_TASK_PORT\n");
#endif
#if defined(DT_BUILD102739A_OBSERVER) || defined(DT_BUILD102739B_RETURN_OBSERVER) \
	|| defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
				if (observeCounter)
					fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_OBSERVER_TASK_PORT=FAIL\n");
#endif
				return -3;
			}

		printf("Got task port %d for pid %d!\n", procTask, targetPid);

			// get aslr slide
#ifndef DT_BUILD102736C_TASKPORT_REPAIR
			task_dyld_info_data_t dyldInfo;
				uint32_t count = TASK_DYLD_INFO_COUNT;
				task_info(procTask, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
#endif

#if defined(DT_BUILD102739A_OBSERVER) || defined(DT_BUILD102739B_RETURN_OBSERVER) \
	|| defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
				if (observeCounter) {
					fprintf(stderr, DT102739_OBSERVER_PREFIX "_POST_WALL2_OBSERVER_TASK_PORT=PASS\n");
					fprintf(stderr, DT102739_OBSERVER_PREFIX "_REMOTE_DLOPEN_ATTEMPTED=NO\n");
					fprintf(stderr, DT102739_OBSERVER_PREFIX "_REMOTE_WRITE_ATTEMPTED=NO\n");
					int observeRc = dt102739a_observe_counter(procTask,
						dyldInfo.all_image_info_addr, dylibPath,
						#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
							"_g_dt102739j_reply_telemetry");
						#elif defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI)
							"_g_dt102739i_handler_telemetry");
					#elif defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
						"_g_dt102739h_argument_telemetry");
					#elif defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
						"_g_dt102739g_domain_action_telemetry");
					#elif defined(DT_BUILD102739F_CALLER_IDENTITY)
						"_g_dt102739f_caller_identity_telemetry");
					#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
						"_g_dt102739e_dictionary_telemetry");
					#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
						"_g_dt102739c_output_telemetry");
					#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
						"_g_dt102739b_return_telemetry");
					#else
						"_g_dt102739a_invocation_count");
					#endif
					fprintf(stderr, DT102739_OBSERVER_PREFIX "_OBSERVER_RESULT=%s\n",
						observeRc == 0 ? "PASS" :
							(observeRc == 17 ? "INCONCLUSIVE" : "FAIL"));
					mach_port_deallocate(mach_task_self(), procTask);
					free(dylibPath);
					return observeRc;
				}
#endif
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_ATTEMPTED=YES\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_ATTEMPTED=YES\n");
#endif
				int injectRc = injectDylibViaRop(procTask, targetPid, dylibPath,
					dyldInfo.all_image_info_addr, skipSandboxFixup);
				fprintf(stderr, "BUILD102734C_REMOTE_DLOPEN_RC=%d\n", injectRc);
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
				fprintf(stderr, "BUILD102736C_REMOTE_DLOPEN_RC=%d\n", injectRc);
#endif
				if (injectRc != 0) {
					fprintf(stderr, "BUILD102734C_OPAINJECT_FAILURE_BRANCH=REMOTE_DLOPEN\n");
#ifdef DT_BUILD102736C_TASKPORT_REPAIR
					fprintf(stderr, "BUILD102736C_OPAINJECT_FAILURE_BRANCH=REMOTE_DLOPEN\n");
#endif
					mach_port_deallocate(mach_task_self(), procTask);
					return injectRc;
				}

			mach_port_deallocate(mach_task_self(), procTask);
			
			return 0;
	}
}
