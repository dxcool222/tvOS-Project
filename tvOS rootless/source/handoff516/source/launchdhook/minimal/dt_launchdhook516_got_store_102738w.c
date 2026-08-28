#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <bsm/audit.h>
#include <xpc/xpc.h>
#include <xpc_private.h>

#define DT102738P_STATIC_BASE          0x100000000ULL
#define DT102738P_STATIC_CALLSITE      0x100040660ULL
#define DT102738P_STATIC_STUB          0x10004E9E8ULL
#define DT102738P_STATIC_GOT_SLOT      0x100065018ULL
#define DT102738P_STATIC_DATA_CONST    0x100064000ULL
#define DT102738P_DATA_CONST_SIZE      0x8000ULL
#define DT102738P_STATIC_GOT_START     0x100064000ULL
#define DT102738P_GOT_SIZE             0x1080ULL
#define DT102738P_PAGE_SIZE            0x4000ULL

static const uint8_t kDT102738PLaunchdUUID[16] = {
    0x7D, 0xC1, 0x76, 0x0B, 0x26, 0xC8, 0x35, 0x62,
    0xA6, 0x54, 0x8A, 0x31, 0xEE, 0xE1, 0xF7, 0x5F,
};

extern void dt102738p_trace_event(const char *event, int rc);
extern void dt102738p_trace_value_u64(const char *event, int rc, uint64_t value);

#ifdef DT_BUILD102738X_TELEMETRY
typedef int (*dt102738x_receive_fn_t)(void *, void *, void *, void *, xpc_object_t *);
static uint64_t g_dt102738x_original_receive = 0;

__attribute__((noinline, used)) static int
dt102738x_transparent_wrapper(void *msg, void *a2, void *a3, void *a4,
    xpc_object_t *xOut)
{
    dt102738x_receive_fn_t original = (dt102738x_receive_fn_t)(uintptr_t)
        __atomic_load_n(&g_dt102738x_original_receive, __ATOMIC_ACQUIRE);
    return original(msg, a2, a3, a4, xOut);
}
#elif defined(DT_BUILD102738Y_TELEMETRY)
typedef int (*dt102738y_receive_fn_t)(void *, void *, void *, void *, xpc_object_t *);
static uint64_t g_dt102738y_original_receive = 0;
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
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
} dt102739h_argument_telemetry_t;

#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
__attribute__((visibility("default"), used, aligned(16)))
dt102739h_argument_telemetry_t g_dt102739j_reply_telemetry = {0};
#define DT102739H_TELEMETRY g_dt102739j_reply_telemetry
#define DT102739GH_PROBE_VALUE "BUILD102739J"
#elif defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI)
__attribute__((visibility("default"), used, aligned(16)))
dt102739h_argument_telemetry_t g_dt102739i_handler_telemetry = {0};
#define DT102739H_TELEMETRY g_dt102739i_handler_telemetry
#define DT102739GH_PROBE_VALUE "BUILD102739I"
#else
__attribute__((visibility("default"), used, aligned(16)))
dt102739h_argument_telemetry_t g_dt102739h_argument_telemetry = {0};
#define DT102739H_TELEMETRY g_dt102739h_argument_telemetry
#define DT102739GH_PROBE_VALUE "BUILD102739H"
#endif
#define g_dt102739g_domain_action_telemetry DT102739H_TELEMETRY

typedef enum {
    DT102739H_TYPE_BOOL = 0,
    DT102739H_TYPE_UINT64 = 1,
    DT102739H_TYPE_STRING = 2,
    DT102739H_TYPE_DATA = 3,
    DT102739H_TYPE_ARRAY = 4,
    DT102739H_TYPE_DICTIONARY = 5,
    DT102739H_TYPE_FD = 6,
    DT102739H_TYPE_CALLER_TOKEN = 7,
    DT102739H_TYPE_XPC_GENERIC = 8,
} dt102739h_type_t;

typedef struct {
    const char *name;
    dt102739h_type_t type;
    bool out;
} dt102739h_arg_t;

typedef struct {
    void *handler;
    dt102739h_arg_t *args;
} dt102739g_action_t;
#else
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
} dt102739g_domain_action_telemetry_t;

__attribute__((visibility("default"), used, aligned(16)))
dt102739g_domain_action_telemetry_t g_dt102739g_domain_action_telemetry = {0};
#define DT102739GH_PROBE_VALUE "BUILD102739G"

typedef struct {
    void *handler;
    const char *output_name;
} dt102739g_action_t;
#endif

typedef struct {
    bool (*permission_handler)(audit_token_t);
    dt102739g_action_t actions[2];
} dt102739g_domain_t;

__attribute__((noinline)) static bool
dt102739g_systemwide_domain_allowed(audit_token_t client_token)
{
    (void)client_token;
    return true;
}

#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
static char kDT102739IControlledOutput[] = "BUILD102739J_CONTROLLED_OUTPUT";
#else
static char kDT102739IControlledOutput[] = "BUILD102739I_CONTROLLED_OUTPUT";
#endif

typedef int (*dt102739i_handler_fn_t)(void *, void *, void *, void *,
    void *, void *, void *, void *);

__attribute__((noinline)) static int
dt102739i_controlled_handler(void *a1, void *a2, void *a3, void *a4,
    void *a5, void *a6, void *a7, void *a8)
{
    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.handler_invocation_count,
        1, __ATOMIC_RELAXED);
    bool tail_null = a2 == NULL && a3 == NULL && a4 == NULL && a5 == NULL
        && a6 == NULL && a7 == NULL && a8 == NULL;
    if (tail_null) {
        __atomic_fetch_add(
            &g_dt102739g_domain_action_telemetry.handler_args1_through_7_null_count,
            1, __ATOMIC_RELAXED);
    }
    if (a1 == NULL || !tail_null)
        return -1;

    *(char **)a1 = kDT102739IControlledOutput;
    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.handler_output_write_count,
        1, __ATOMIC_RELAXED);
    return 0;
}
#endif

__attribute__((noinline)) static int
dt102739g_unreachable_get_jbroot(char **root_path_out)
{
    (void)root_path_out;
    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.handler_invocation_count,
        1, __ATOMIC_RELAXED);
    return -1;
}

/* This immutable table mirrors the iOS indexing contract only.  The action
 * target is deliberately unreachable in 102739G and does not consult jbinfo. */
static dt102739g_domain_t g_dt102739g_systemwide_domain = {
    .permission_handler = dt102739g_systemwide_domain_allowed,
    .actions = {
#if defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI)
        {
            .handler = dt102739i_controlled_handler,
            .args = (dt102739h_arg_t[]){
                { .name = "root-path", .type = DT102739H_TYPE_STRING, .out = true },
                { 0 },
            },
        },
#elif defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
        {
            .handler = dt102739g_unreachable_get_jbroot,
            .args = (dt102739h_arg_t[]){
                { .name = "root-path", .type = DT102739H_TYPE_STRING, .out = true },
                { 0 },
            },
        },
#else
        { .handler = dt102739g_unreachable_get_jbroot, .output_name = "root-path" },
#endif
        { 0 },
    },
};
static dt102739g_domain_t *const g_dt102739g_domains[] = {
    &g_dt102739g_systemwide_domain,
    NULL,
};

#define g_dt102738y_invocation_count g_dt102739g_domain_action_telemetry.entry_count
#define DT102739_SUCCESS_RETURN_COUNT g_dt102739g_domain_action_telemetry.success_return_count
#define DT102739_XOUT_ARGUMENT_COUNT g_dt102739g_domain_action_telemetry.xout_argument_count
#define DT102739_SUCCESS_XOUT_COUNT g_dt102739g_domain_action_telemetry.success_xout_count
#define DT102739_SUCCESS_OBJECT_COUNT g_dt102739g_domain_action_telemetry.success_object_count
#define DT102739_RETURN_COUNT g_dt102739g_domain_action_telemetry.return_count
#define DT102739_IDENTITY_TELEMETRY g_dt102739g_domain_action_telemetry
#elif defined(DT_BUILD102739F_CALLER_IDENTITY)
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
} dt102739f_caller_identity_telemetry_t;

/* BUILD102739F keeps the 102739E read-only classifier contract and adds
 * exact-probe-gated caller identity capture through libxpc/libbsm APIs. */
__attribute__((visibility("default"), used, aligned(16)))
dt102739f_caller_identity_telemetry_t g_dt102739f_caller_identity_telemetry = {0};
#define g_dt102738y_invocation_count g_dt102739f_caller_identity_telemetry.entry_count
#define DT102739_SUCCESS_RETURN_COUNT g_dt102739f_caller_identity_telemetry.success_return_count
#define DT102739_XOUT_ARGUMENT_COUNT g_dt102739f_caller_identity_telemetry.xout_argument_count
#define DT102739_SUCCESS_XOUT_COUNT g_dt102739f_caller_identity_telemetry.success_xout_count
#define DT102739_SUCCESS_OBJECT_COUNT g_dt102739f_caller_identity_telemetry.success_object_count
#define DT102739_RETURN_COUNT g_dt102739f_caller_identity_telemetry.return_count
#define DT102739_IDENTITY_TELEMETRY g_dt102739f_caller_identity_telemetry
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
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
} dt102739e_dictionary_telemetry_t;

/* BUILD102739E extends the proven read-only output contract.  The wrapper
 * classifies only the controlled dictionary after the original function has
 * succeeded; it never retains, releases, replaces, or consumes the object. */
__attribute__((visibility("default"), used, aligned(16)))
dt102739e_dictionary_telemetry_t g_dt102739e_dictionary_telemetry = {0};
#define g_dt102738y_invocation_count g_dt102739e_dictionary_telemetry.entry_count
#define DT102739_SUCCESS_RETURN_COUNT g_dt102739e_dictionary_telemetry.success_return_count
#define DT102739_XOUT_ARGUMENT_COUNT g_dt102739e_dictionary_telemetry.xout_argument_count
#define DT102739_SUCCESS_XOUT_COUNT g_dt102739e_dictionary_telemetry.success_xout_count
#define DT102739_SUCCESS_OBJECT_COUNT g_dt102739e_dictionary_telemetry.success_object_count
#define DT102739_RETURN_COUNT g_dt102739e_dictionary_telemetry.return_count
#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
typedef struct {
    uint64_t entry_count;
    uint64_t return_count;
    uint64_t success_return_count;
    uint64_t xout_argument_count;
    uint64_t success_xout_count;
    uint64_t success_object_count;
} dt102739c_output_telemetry_t;

/* Read-only output-contract observer ABI.  The wrapper records only guarded
 * scalar classifications; launchd retains all XPC object ownership. */
__attribute__((visibility("default"), used, aligned(16)))
dt102739c_output_telemetry_t g_dt102739c_output_telemetry = {0};
#define g_dt102738y_invocation_count g_dt102739c_output_telemetry.entry_count
#define DT102739_SUCCESS_RETURN_COUNT g_dt102739c_output_telemetry.success_return_count
#define DT102739_XOUT_ARGUMENT_COUNT g_dt102739c_output_telemetry.xout_argument_count
#define DT102739_SUCCESS_XOUT_COUNT g_dt102739c_output_telemetry.success_xout_count
#define DT102739_SUCCESS_OBJECT_COUNT g_dt102739c_output_telemetry.success_object_count
#define DT102739_RETURN_COUNT g_dt102739c_output_telemetry.return_count
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
typedef struct {
    uint64_t entry_count;
    uint64_t return_count;
} dt102739b_return_telemetry_t;

/* Read-only post-Wall-2 return-path observer ABI.  Keep both naturally
 * aligned counters in one validated writable-data record. */
__attribute__((visibility("default"), used, aligned(16)))
dt102739b_return_telemetry_t g_dt102739b_return_telemetry = {0, 0};
#define g_dt102738y_invocation_count g_dt102739b_return_telemetry.entry_count
#elif defined(DT_BUILD102739A_OBSERVER)
/* Read-only post-Wall-2 observer ABI.  Keep this in data and externally
 * visible so the helper can resolve it from the already-loaded image. */
__attribute__((visibility("default"), used, aligned(8)))
uint64_t g_dt102739a_invocation_count = 0;
#define g_dt102738y_invocation_count g_dt102739a_invocation_count
#else
static uint64_t g_dt102738y_invocation_count = 0;
#endif

__attribute__((noinline, used)) static int
dt102738y_counting_wrapper(void *msg, void *a2, void *a3, void *a4,
    xpc_object_t *xOut)
{
    __atomic_fetch_add(&g_dt102738y_invocation_count, 1, __ATOMIC_RELAXED);
    dt102738y_receive_fn_t original = (dt102738y_receive_fn_t)(uintptr_t)
        __atomic_load_n(&g_dt102738y_original_receive, __ATOMIC_ACQUIRE);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY) || \
    defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER) || \
    defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
    bool j_exact_probe = false;
    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.original_receive_call_count,
        1, __ATOMIC_RELAXED);
#endif
    int result = original(msg, a2, a3, a4, xOut);
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.original_receive_return_count,
        1, __ATOMIC_RELAXED);
    __atomic_store_n(&g_dt102739g_domain_action_telemetry.original_receive_last_result,
        (uint64_t)(int64_t)result, __ATOMIC_RELAXED);
#endif
    if (result == 0) {
        __atomic_fetch_add(&DT102739_SUCCESS_RETURN_COUNT, 1,
            __ATOMIC_RELAXED);
    }
    if (xOut != NULL) {
        __atomic_fetch_add(&DT102739_XOUT_ARGUMENT_COUNT, 1,
            __ATOMIC_RELAXED);
    }
    if (result == 0 && xOut != NULL) {
        __atomic_fetch_add(&DT102739_SUCCESS_XOUT_COUNT, 1,
            __ATOMIC_RELAXED);
        if (*xOut != NULL) {
            __atomic_fetch_add(&DT102739_SUCCESS_OBJECT_COUNT,
                1, __ATOMIC_RELAXED);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
            xpc_object_t object = *xOut;
            if (xpc_get_type(object) == XPC_TYPE_DICTIONARY) {
                __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.dictionary_object_count,
                    1, __ATOMIC_RELAXED);
                xpc_object_t domain_value = xpc_dictionary_get_value(object,
                    "jb-domain");
                xpc_object_t action_value = xpc_dictionary_get_value(object,
                    "action");
                if (domain_value != NULL) {
                    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.domain_key_present_count,
                        1, __ATOMIC_RELAXED);
                }
                if (action_value != NULL) {
                    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.action_key_present_count,
                        1, __ATOMIC_RELAXED);
                }
                if (domain_value != NULL && action_value != NULL) {
                    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.domain_action_envelope_count,
                        1, __ATOMIC_RELAXED);
                    uint64_t domain_index = xpc_dictionary_get_uint64(object,
                        "jb-domain");
                    uint64_t action_index = xpc_dictionary_get_uint64(object,
                        "action");
                    const char *probe = xpc_dictionary_get_string(object,
                        "dt-probe");
                    if (domain_index != 0) {
                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.domain_nonzero_count,
                            1, __ATOMIC_RELAXED);
                    }
                    if (domain_index == 1) {
                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.systemwide_domain_candidate_count,
                            1, __ATOMIC_RELAXED);
                    }
                    if (domain_index == 1 && action_index == 1 && probe != NULL
                        && strcmp(probe, DT102739GH_PROBE_VALUE) == 0) {
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
                        j_exact_probe = true;
#endif
                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.exact_controlled_probe_count,
                            1, __ATOMIC_RELAXED);
                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.domain_resolution_attempt_count,
                            1, __ATOMIC_RELAXED);

                        dt102739g_domain_t *domain = g_dt102739g_domains[0];
                        for (uint64_t i = 1; i < domain_index && domain; i++) {
                            domain = g_dt102739g_domains[i];
                        }
                        if (domain != NULL) {
                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.domain_resolution_success_count,
                                1, __ATOMIC_RELAXED);

                            audit_token_t client_token = {0};
                            xpc_dictionary_get_audit_token(object, &client_token);
                            __atomic_store_n(&g_dt102739g_domain_action_telemetry.captured_pid,
                                (uint64_t)audit_token_to_pid(client_token), __ATOMIC_RELAXED);
                            __atomic_store_n(&g_dt102739g_domain_action_telemetry.captured_euid,
                                (uint64_t)audit_token_to_euid(client_token), __ATOMIC_RELAXED);
                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.audit_token_capture_count,
                                1, __ATOMIC_RELAXED);

                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.permission_check_count,
                                1, __ATOMIC_RELAXED);
                            bool (*permission_handler)(audit_token_t) =
                                *(bool (* volatile *)(audit_token_t))
                                    &domain->permission_handler;
                            if (permission_handler == NULL
                                || permission_handler(client_token)) {
                                __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.permission_allow_count,
                                    1, __ATOMIC_RELAXED);
                                if (action_index != 0) {
                                    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.action_nonzero_count,
                                        1, __ATOMIC_RELAXED);
                                    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.action_resolution_attempt_count,
                                        1, __ATOMIC_RELAXED);
                                    dt102739g_action_t *action = &domain->actions[0];
                                    for (uint64_t i = 1; i < action_index
                                        && action->handler != NULL; i++) {
                                        action = &domain->actions[i];
                                    }
                                    if (action->handler != NULL
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
                                        && action->args != NULL
#else
                                        && action->output_name != NULL
                                        && strcmp(action->output_name, "root-path") == 0
#endif
                                        ) {
                                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.action_resolution_success_count,
                                            1, __ATOMIC_RELAXED);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
                                        void *handler = *(void * volatile *)&action->handler;
                                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.handler_pointer_capture_count,
                                            1, __ATOMIC_RELAXED);
                                        if (handler != NULL) {
                                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.handler_pointer_nonnull_count,
                                                1, __ATOMIC_RELAXED);
                                        }

                                        void *args[8] = { NULL, NULL, NULL, NULL,
                                            NULL, NULL, NULL, NULL };
                                        void *args_out[8] = { NULL, NULL, NULL, NULL,
                                            NULL, NULL, NULL, NULL };
                                        bool args_zero = true;
                                        bool argsout_zero = true;
                                        for (uint64_t i = 0; i < 8; i++) {
                                            args_zero = args_zero && args[i] == NULL;
                                            argsout_zero = argsout_zero && args_out[i] == NULL;
                                        }
                                        if (args_zero) {
                                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.args_zero_initialized_count,
                                                1, __ATOMIC_RELAXED);
                                        }
                                        if (argsout_zero) {
                                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.argsout_zero_initialized_count,
                                                1, __ATOMIC_RELAXED);
                                        }

                                        uint64_t descriptor_count = 0;
                                        bool root_path = false;
                                        bool string_type = false;
                                        bool output_direction = false;
                                        bool output_bound = false;
                                        for (; descriptor_count < 8
                                            && action->args[descriptor_count].name != NULL;
                                            descriptor_count++) {
                                            dt102739h_arg_t *arg_desc =
                                                &action->args[descriptor_count];
                                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.arg_descriptor_scan_count,
                                                1, __ATOMIC_RELAXED);
                                            if (descriptor_count == 0
                                                && strcmp(arg_desc->name, "root-path") == 0) {
                                                root_path = true;
                                                __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.arg_descriptor_root_path_count,
                                                    1, __ATOMIC_RELAXED);
                                            }
                                            if (arg_desc->type == DT102739H_TYPE_STRING) {
                                                string_type = true;
                                                __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.arg_descriptor_string_type_count,
                                                    1, __ATOMIC_RELAXED);
                                            }
                                            if (arg_desc->out) {
                                                output_direction = true;
                                                __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.arg_descriptor_out_count,
                                                    1, __ATOMIC_RELAXED);
                                                args[descriptor_count] = &args_out[descriptor_count];
                                                output_bound = args[descriptor_count]
                                                    == &args_out[descriptor_count];
                                                if (output_bound) {
                                                    __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.output_slot_bind_count,
                                                        1, __ATOMIC_RELAXED);
                                                }
                                            }
                                        }
                                        bool terminator_found = descriptor_count < 8
                                            && action->args[descriptor_count].name == NULL;
                                        if (terminator_found) {
                                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.arg_terminator_found_count,
                                                1, __ATOMIC_RELAXED);
                                        }
                                        bool marshalling_complete = handler != NULL
                                            && args_zero && argsout_zero
                                            && descriptor_count == 1 && root_path && string_type
                                            && output_direction && output_bound && terminator_found;
                                        if (marshalling_complete) {
                                            __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.marshalling_complete_count,
                                                1, __ATOMIC_RELAXED);
                                        }
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
                                        if (marshalling_complete) {
                                            bool arg0_matches = args[0] == &args_out[0];
                                            if (arg0_matches) {
                                                __atomic_fetch_add(
                                                    &g_dt102739g_domain_action_telemetry.handler_arg0_output_slot_match_count,
                                                    1, __ATOMIC_RELAXED);
                                            }
                                            __atomic_fetch_add(
                                                &g_dt102739g_domain_action_telemetry.handler_call_attempt_count,
                                                1, __ATOMIC_RELAXED);
                                            dt102739i_handler_fn_t controlled_handler =
                                                (dt102739i_handler_fn_t)handler;
                                            int handler_result = controlled_handler(args[0], args[1],
                                                args[2], args[3], args[4], args[5], args[6], args[7]);
                                            __atomic_fetch_add(
                                                &g_dt102739g_domain_action_telemetry.handler_return_count,
                                                1, __ATOMIC_RELAXED);
                                            bool result_matches = handler_result == 0;
                                            if (result_matches) {
                                                __atomic_fetch_add(
                                                    &g_dt102739g_domain_action_telemetry.handler_result_match_count,
                                                    1, __ATOMIC_RELAXED);
                                            }
                                            bool sentinel_matches = args_out[0]
                                                == kDT102739IControlledOutput;
                                            if (sentinel_matches) {
                                                __atomic_fetch_add(
                                                    &g_dt102739g_domain_action_telemetry.argsout0_sentinel_match_count,
                                                    1, __ATOMIC_RELAXED);
                                            }
                                            bool output_tail_null = true;
                                            for (uint64_t i = 1; i < 8; i++)
                                                output_tail_null = output_tail_null && args_out[i] == NULL;
                                            if (output_tail_null) {
                                                __atomic_fetch_add(
                                                    &g_dt102739g_domain_action_telemetry.argsout_tail_null_count,
                                                    1, __ATOMIC_RELAXED);
                                            }
                                            if (arg0_matches && result_matches && sentinel_matches
                                                && output_tail_null) {
                                                __atomic_fetch_add(
                                                    &g_dt102739g_domain_action_telemetry.controlled_handler_complete_count,
                                                    1, __ATOMIC_RELAXED);
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
                                                xpc_object_t received_object = object;
                                                __atomic_fetch_add(
                                                    &g_dt102739g_domain_action_telemetry.reply_create_attempt_count,
                                                    1, __ATOMIC_RELAXED);
                                                xpc_object_t created_reply =
                                                    xpc_dictionary_create_reply(received_object);
                                                if (created_reply == NULL) {
                                                    __atomic_fetch_add(
                                                        &g_dt102739g_domain_action_telemetry.reply_create_failed_precommit_count,
                                                        1, __ATOMIC_RELAXED);
                                                } else if (created_reply == received_object) {
                                                    __atomic_fetch_add(
                                                        &g_dt102739g_domain_action_telemetry.reply_identity_failed_precommit_count,
                                                        1, __ATOMIC_RELAXED);
                                                    xpc_release(created_reply);
                                                    __atomic_fetch_add(
                                                        &g_dt102739g_domain_action_telemetry.precommit_reply_release_count,
                                                        1, __ATOMIC_RELAXED);
                                                } else {
                                                    __atomic_fetch_add(
                                                        &g_dt102739g_domain_action_telemetry.reply_create_success_count,
                                                        1, __ATOMIC_RELAXED);
                                                    xpc_dictionary_set_string(created_reply, "root-path",
                                                        kDT102739IControlledOutput);
                                                    __atomic_fetch_add(
                                                        &g_dt102739g_domain_action_telemetry.root_path_set_count,
                                                        1, __ATOMIC_RELAXED);
                                                    xpc_dictionary_set_int64(created_reply, "result", 0);
                                                    __atomic_fetch_add(
                                                        &g_dt102739g_domain_action_telemetry.result_set_count,
                                                        1, __ATOMIC_RELAXED);

                                                    xpc_object_t root_value = xpc_dictionary_get_value(
                                                        created_reply, "root-path");
                                                    xpc_object_t result_value = xpc_dictionary_get_value(
                                                        created_reply, "result");
                                                    bool root_exists = root_value != NULL;
                                                    bool result_exists = result_value != NULL;
                                                    bool root_type_matches = root_exists
                                                        && xpc_get_type(root_value) == XPC_TYPE_STRING;
                                                    bool result_type_matches = result_exists
                                                        && xpc_get_type(result_value) == XPC_TYPE_INT64;
                                                    if (root_exists)
                                                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.root_path_exists_count,
                                                            1, __ATOMIC_RELAXED);
                                                    if (result_exists)
                                                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.result_exists_count,
                                                            1, __ATOMIC_RELAXED);
                                                    if (root_type_matches)
                                                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.root_path_type_match_count,
                                                            1, __ATOMIC_RELAXED);
                                                    if (result_type_matches)
                                                        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.result_type_match_count,
                                                            1, __ATOMIC_RELAXED);
                                                    const char *root_string = root_type_matches
                                                        ? xpc_dictionary_get_string(created_reply, "root-path") : NULL;
                                                    bool readback_matches = root_string != NULL
                                                        && strcmp(root_string, kDT102739IControlledOutput) == 0
                                                        && result_type_matches
                                                        && xpc_dictionary_get_int64(created_reply, "result") == 0;
                                                    if (!readback_matches) {
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.reply_readback_failed_precommit_count,
                                                            1, __ATOMIC_RELAXED);
                                                        xpc_release(created_reply);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.precommit_reply_release_count,
                                                            1, __ATOMIC_RELAXED);
                                                    } else if (*xOut != received_object) {
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.reply_readback_match_count,
                                                            1, __ATOMIC_RELAXED);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.precommit_xout_mismatch_count,
                                                            1, __ATOMIC_RELAXED);
                                                        xpc_release(created_reply);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.precommit_reply_release_count,
                                                            1, __ATOMIC_RELAXED);
                                                    } else {
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.reply_readback_match_count,
                                                            1, __ATOMIC_RELAXED);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.precommit_xout_match_count,
                                                            1, __ATOMIC_RELAXED);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.reply_send_attempt_count,
                                                            1, __ATOMIC_RELAXED);
                                                        int send_rc = xpc_pipe_routine_reply(created_reply);
                                                        __atomic_store_n(
                                                            &g_dt102739g_domain_action_telemetry.server_reply_send_rc,
                                                            (uint64_t)(int64_t)send_rc, __ATOMIC_RELAXED);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.reply_send_return_count,
                                                            1, __ATOMIC_RELAXED);
                                                        xpc_release(created_reply);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.server_reply_release_count,
                                                            1, __ATOMIC_RELAXED);

                                                        bool committed_xout_matches = *xOut == received_object;
                                                        if (committed_xout_matches) {
                                                            __atomic_fetch_add(
                                                                &g_dt102739g_domain_action_telemetry.committed_xout_match_count,
                                                                1, __ATOMIC_RELAXED);
                                                        } else {
                                                            __atomic_fetch_add(
                                                                &g_dt102739g_domain_action_telemetry.committed_xout_mismatch_count,
                                                                1, __ATOMIC_RELAXED);
                                                        }
                                                        xpc_release(received_object);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.input_consume_release_count,
                                                            1, __ATOMIC_RELAXED);
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.committed_consume_path_complete_count,
                                                            1, __ATOMIC_RELAXED);
                                                        if (committed_xout_matches
                                                            && (send_rc == 0 || send_rc == 32)) {
                                                            __atomic_fetch_add(
                                                                &g_dt102739g_domain_action_telemetry.server_committed_lifecycle_pass_count,
                                                                1, __ATOMIC_RELAXED);
                                                        }
                                                        __atomic_fetch_add(
                                                            &g_dt102739g_domain_action_telemetry.wrapper_return_22_count,
                                                            1, __ATOMIC_RELAXED);
                                                        __atomic_fetch_add(&DT102739_RETURN_COUNT, 1,
                                                            __ATOMIC_RELEASE);
                                                        return 22;
                                                    }
                                                }
#endif
                                            }
                                        }
#endif
#endif
                                    }
                                }
                            }
                        }
                    }
                }
            }
#elif defined(DT_BUILD102739F_CALLER_IDENTITY)
            xpc_object_t object = *xOut;
            if (xpc_get_type(object) == XPC_TYPE_DICTIONARY) {
                __atomic_fetch_add(
                    &g_dt102739f_caller_identity_telemetry.dictionary_object_count,
                    1, __ATOMIC_RELAXED);
                xpc_object_t domainValue = xpc_dictionary_get_value(object,
                    "jb-domain");
                xpc_object_t actionValue = xpc_dictionary_get_value(object,
                    "action");
                if (domainValue != NULL) {
                    __atomic_fetch_add(
                        &g_dt102739f_caller_identity_telemetry.domain_key_present_count,
                        1, __ATOMIC_RELAXED);
                }
                if (actionValue != NULL) {
                    __atomic_fetch_add(
                        &g_dt102739f_caller_identity_telemetry.action_key_present_count,
                        1, __ATOMIC_RELAXED);
                }
                if (domainValue != NULL && actionValue != NULL) {
                    __atomic_fetch_add(
                        &g_dt102739f_caller_identity_telemetry.domain_action_envelope_count,
                        1, __ATOMIC_RELAXED);
                    uint64_t domain = xpc_dictionary_get_uint64(object,
                        "jb-domain");
                    uint64_t action = xpc_dictionary_get_uint64(object,
                        "action");
                    const char *probe = xpc_dictionary_get_string(object,
                        "dt-probe");
                    if (domain != 0) {
                        __atomic_fetch_add(
                            &g_dt102739f_caller_identity_telemetry.domain_nonzero_count,
                            1, __ATOMIC_RELAXED);
                    }
                    if (domain == 1) {
                        __atomic_fetch_add(
                            &g_dt102739f_caller_identity_telemetry.systemwide_domain_candidate_count,
                            1, __ATOMIC_RELAXED);
                    }
                    if (domain == 1 && action == 1 && probe != NULL
                        && strcmp(probe, "BUILD102739F") == 0) {
                        audit_token_t clientToken = {0};
                        xpc_dictionary_get_audit_token(object, &clientToken);
                        pid_t pid = audit_token_to_pid(clientToken);
                        uid_t euid = audit_token_to_euid(clientToken);
                        __atomic_store_n(
                            &g_dt102739f_caller_identity_telemetry.captured_pid,
                            (uint64_t)pid, __ATOMIC_RELAXED);
                        __atomic_store_n(
                            &g_dt102739f_caller_identity_telemetry.captured_euid,
                            (uint64_t)euid, __ATOMIC_RELAXED);
                        __atomic_fetch_add(
                            &g_dt102739f_caller_identity_telemetry.exact_controlled_probe_count,
                            1, __ATOMIC_RELAXED);
                        __atomic_fetch_add(
                            &g_dt102739f_caller_identity_telemetry.audit_token_capture_count,
                            1, __ATOMIC_RELAXED);
                    }
                }
            }
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
            xpc_object_t object = *xOut;
            if (xpc_get_type(object) == XPC_TYPE_DICTIONARY) {
                __atomic_fetch_add(
                    &g_dt102739e_dictionary_telemetry.dictionary_object_count,
                    1, __ATOMIC_RELAXED);
                xpc_object_t domainValue = xpc_dictionary_get_value(object,
                    "jb-domain");
                xpc_object_t actionValue = xpc_dictionary_get_value(object,
                    "action");
                if (domainValue != NULL) {
                    __atomic_fetch_add(
                        &g_dt102739e_dictionary_telemetry.domain_key_present_count,
                        1, __ATOMIC_RELAXED);
                }
                if (actionValue != NULL) {
                    __atomic_fetch_add(
                        &g_dt102739e_dictionary_telemetry.action_key_present_count,
                        1, __ATOMIC_RELAXED);
                }
                if (domainValue != NULL && actionValue != NULL) {
                    __atomic_fetch_add(
                        &g_dt102739e_dictionary_telemetry.domain_action_envelope_count,
                        1, __ATOMIC_RELAXED);
                    uint64_t domain = xpc_dictionary_get_uint64(object,
                        "jb-domain");
                    uint64_t action = xpc_dictionary_get_uint64(object,
                        "action");
                    const char *probe = xpc_dictionary_get_string(object,
                        "dt-probe");
                    if (domain == 0 && action == 0 && probe != NULL
                        && strcmp(probe, "BUILD102739E") == 0) {
                        __atomic_fetch_add(
                            &g_dt102739e_dictionary_telemetry.exact_controlled_probe_count,
                            1, __ATOMIC_RELAXED);
                    }
                }
            }
#endif
        }
    }
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
    if (j_exact_probe) {
        __atomic_fetch_add(&g_dt102739g_domain_action_telemetry.precommit_fallback_count,
            1, __ATOMIC_RELAXED);
    }
#endif
    /* Commit completion last so every counted return has already been fully
     * classified before the read-only helper observes it. */
    __atomic_fetch_add(&DT102739_RETURN_COUNT, 1,
        __ATOMIC_RELEASE);
    return result;
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
    int result = original(msg, a2, a3, a4, xOut);
    __atomic_fetch_add(&g_dt102739b_return_telemetry.return_count, 1,
        __ATOMIC_RELAXED);
    return result;
#else
    return original(msg, a2, a3, a4, xOut);
#endif
}
#endif

typedef struct {
    mach_vm_address_t start;
    mach_vm_size_t size;
    vm_prot_t current;
    vm_prot_t maximum;
} dt102738p_region_t;

typedef struct {
    mach_vm_address_t start;
    mach_vm_size_t size;
    vm_prot_t current;
    vm_prot_t maximum;
    natural_t depth;
    boolean_t is_submap;
} dt102738p_recurse_region_t;

__attribute__((noinline, used)) static uint64_t
dt102738w_atomic_load_pointer(const uint64_t *slot)
{
    return __atomic_load_n(slot, __ATOMIC_RELAXED);
}

__attribute__((noinline, used)) static void
dt102738w_atomic_store_same_value(uint64_t *slot, uint64_t value)
{
    __atomic_store_n(slot, value, __ATOMIC_RELAXED);
}

#ifdef DT_BUILD102738X_TELEMETRY
__attribute__((noinline, used)) static uint64_t
dt102738x_atomic_load_pointer(const uint64_t *slot)
{
    return __atomic_load_n(slot, __ATOMIC_ACQUIRE);
}

__attribute__((noinline, used)) static void
dt102738x_atomic_store_pointer(uint64_t *slot, uint64_t value)
{
    __atomic_store_n(slot, value, __ATOMIC_RELEASE);
}

static bool dt102738x_pointer_in_launchdhook_text(uintptr_t pointer)
{
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh || mh->magic != MH_MAGIC_64 || !name)
            continue;
        const char *base = strrchr(name, '/');
        base = base ? base + 1 : name;
        if (strcmp(base, "launchdhook516.dylib") != 0)
            continue;

        const uint8_t *cursor = (const uint8_t *)(mh + 1);
        const uint8_t *commands_end = cursor + mh->sizeofcmds;
        for (uint32_t command_index = 0; command_index < mh->ncmds; command_index++) {
            if (cursor + sizeof(struct load_command) > commands_end)
                return false;
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(struct load_command)
                || cursor + lc->cmdsize > commands_end)
                return false;
            if (lc->cmd == LC_SEGMENT_64
                && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)lc;
                if (strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
                    uintptr_t start = (uintptr_t)(seg->vmaddr + slide);
                    uintptr_t end = start + (uintptr_t)seg->vmsize;
                    return end >= start && pointer >= start && pointer < end;
                }
            }
            cursor += lc->cmdsize;
        }
        return false;
    }
    return false;
}
#elif defined(DT_BUILD102738Y_TELEMETRY)
__attribute__((noinline, used)) static uint64_t
dt102738y_atomic_load_pointer(const uint64_t *slot)
{
    return __atomic_load_n(slot, __ATOMIC_ACQUIRE);
}

__attribute__((noinline, used)) static void
dt102738y_atomic_store_pointer(uint64_t *slot, uint64_t value)
{
    __atomic_store_n(slot, value, __ATOMIC_RELEASE);
}

static bool dt102738y_pointer_in_launchdhook_text(uintptr_t pointer)
{
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh || mh->magic != MH_MAGIC_64 || !name)
            continue;
        const char *base = strrchr(name, '/');
        base = base ? base + 1 : name;
        if (strcmp(base, "launchdhook516.dylib") != 0)
            continue;

        const uint8_t *cursor = (const uint8_t *)(mh + 1);
        const uint8_t *commands_end = cursor + mh->sizeofcmds;
        for (uint32_t command_index = 0; command_index < mh->ncmds; command_index++) {
            if (cursor + sizeof(struct load_command) > commands_end)
                return false;
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(struct load_command)
                || cursor + lc->cmdsize > commands_end)
                return false;
            if (lc->cmd == LC_SEGMENT_64
                && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)lc;
                if (strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
                    uintptr_t start = (uintptr_t)(seg->vmaddr + slide);
                    uintptr_t end = start + (uintptr_t)seg->vmsize;
                    return end >= start && pointer >= start && pointer < end;
                }
            }
            cursor += lc->cmdsize;
        }
        return false;
    }
    return false;
}
#endif

__attribute__((noinline, naked)) static volatile kern_return_t
dt102738p_mach_vm_protect(mach_port_name_t target, mach_vm_address_t address,
    mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#if defined(__arm64__)
    __asm("mov x16, #-14");
    __asm("svc 0x80");
    __asm("ret");
#else
    (void)target;
    (void)address;
    (void)size;
    (void)set_maximum;
    (void)new_protection;
    __asm("brk #1");
#endif
}

static int dt102738p_query_region(mach_vm_address_t address, dt102738p_region_t *out)
{
    if (!out)
        return -1;

    vm_address_t region_address = (vm_address_t)address;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region_address, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name);
    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);
    if (kr != KERN_SUCCESS)
        return (int)kr;
    if (region_address > address || region_size < sizeof(uint64_t)
        || address - region_address > region_size - sizeof(uint64_t))
        return -2;

    out->start = region_address;
    out->size = region_size;
    out->current = info.protection;
    out->maximum = info.max_protection;
    return 0;
}

static int dt102738p_query_executable_leaf(mach_vm_address_t address,
    dt102738p_recurse_region_t *out)
{
    if (!out)
        return -1;

    vm_address_t region_address = (vm_address_t)address;
    vm_size_t region_size = 0;
    vm_region_submap_short_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t depth = 99999;
    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region_address,
        &region_size, &depth, (vm_region_recurse_info_t)&info, &count);

    out->start = region_address;
    out->size = region_size;
    out->current = info.protection;
    out->maximum = info.max_protection;
    out->depth = depth;
    out->is_submap = info.is_submap;

    if (kr != KERN_SUCCESS)
        return (int)kr;
    if (region_address > address || region_size < sizeof(uint64_t)
        || address - region_address > region_size - sizeof(uint64_t))
        return -2;
    return 0;
}

static int64_t dt102738p_sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static bool dt102738p_stub_resolves_slot(uintptr_t stub, uintptr_t slot)
{
    const volatile uint32_t *insn = (const volatile uint32_t *)stub;
    uint32_t adrp = insn[0];
    uint32_t ldr = insn[1];
    uint32_t br = insn[2];

    if ((adrp & 0x9F00001FU) != 0x90000010U)
        return false;
    if ((ldr & 0xFFC003FFU) != 0xF9400210U)
        return false;
    if (br != 0xD61F0200U)
        return false;

    uint64_t imm21 = ((uint64_t)((adrp >> 5) & 0x7FFFFU) << 2)
        | ((adrp >> 29) & 0x3U);
    int64_t page_delta = dt102738p_sign_extend(imm21, 21) * 0x1000LL;
    uintptr_t page = (stub & ~(uintptr_t)0xFFF) + page_delta;
    uintptr_t resolved = page + (((ldr >> 10) & 0xFFFU) * sizeof(uint64_t));
    return resolved == slot;
}

static bool dt102738p_callsite_targets_stub(uintptr_t callsite, uintptr_t stub)
{
    uint32_t bl = *(const volatile uint32_t *)callsite;
    if ((bl & 0xFC000000U) != 0x94000000U)
        return false;
    int64_t imm26 = dt102738p_sign_extend(bl & 0x03FFFFFFU, 26);
    return callsite + (imm26 * 4LL) == stub;
}

static int dt102738p_fail(const char *event, int rc)
{
    if (event)
        dt102738p_trace_event(event, rc);
    dt102738p_trace_event("GOT_PROBE_TERMINAL_FAIL", rc);
    return rc;
}

#ifdef DT_BUILD102738Y_TELEMETRY
#define DT102738Y_OBSERVE_POLL_US 10000U
/*
 * Keep the launchd constructor nonblocking, as proven by frozen BUILD102738X.
 * Wall 2 cannot be restored until the synchronous remote dlopen returns, so a
 * constructor-side observation window leaves launchd under the temporary
 * cfprefsd policy and can turn its normal sync(2) timer into a policy kill.
 * Sample the counter once, then unconditionally restore the original pointer
 * and mapping protection. A zero count is an honest inconclusive/fail result.
 */
#define DT102738Y_OBSERVE_MAX_POLLS 0U

static kern_return_t dt102738y_protect_with_retry(mach_vm_address_t page,
    vm_prot_t protection, bool *retried, kern_return_t *retry_rc)
{
    kern_return_t first = dt102738p_mach_vm_protect(mach_task_self(), page,
        DT102738P_PAGE_SIZE, false, protection);
    if (retried)
        *retried = false;
    if (retry_rc)
        *retry_rc = KERN_FAILURE;
    if (first != KERN_SUCCESS) {
        if (retried)
            *retried = true;
        kern_return_t second = dt102738p_mach_vm_protect(mach_task_self(), page,
            DT102738P_PAGE_SIZE, false, protection);
        if (retry_rc)
            *retry_rc = second;
    }
    return first;
}

static int dt102738y_finish_installed_probe(uintptr_t slot, uintptr_t page,
    const dt102738p_region_t *initial, uint64_t pointer_before,
    uint64_t wrapper_pointer, kern_return_t install_rw_rc,
    int install_during_query_rc, const dt102738p_region_t *install_during,
    uint64_t pointer_during, bool wrapper_store_attempted,
    uint64_t wrapper_readback, kern_return_t install_restore_first_rc,
    bool install_restore_retried, kern_return_t install_restore_retry_rc)
{
    bool install_restore_ok = install_restore_first_rc == KERN_SUCCESS
        || (install_restore_retried && install_restore_retry_rc == KERN_SUCCESS);
    dt102738p_region_t installed = {0};
    int installed_query_rc = dt102738p_query_region(slot, &installed);
    uint64_t installed_pointer = dt102738y_atomic_load_pointer(
        (const uint64_t *)slot);

    dt102738p_trace_event("GOT_RW_TRANSITION", (int)install_rw_rc);
    dt102738p_trace_value_u64("GOT_DURING_QUERY_RC", install_during_query_rc,
        (uint64_t)(int64_t)install_during_query_rc);
    dt102738p_trace_value_u64("GOT_DURING_CURRENT_PROT", install_during_query_rc,
        install_during ? install_during->current : 0);
    dt102738p_trace_value_u64("GOT_DURING_MAX_PROT", install_during_query_rc,
        install_during ? install_during->maximum : 0);
    dt102738p_trace_value_u64("GOT_POINTER_DURING", install_during_query_rc,
        pointer_during);
    dt102738p_trace_value_u64("GOT_WRAPPER_STORE_ATTEMPTED", 0,
        wrapper_store_attempted ? 1 : 0);
    dt102738p_trace_value_u64("GOT_WRAPPER_READBACK",
        wrapper_store_attempted ? 0 : -73826, wrapper_readback);
    dt102738p_trace_event("GOT_INSTALL_PROTECTION_RESTORE_FIRST",
        (int)install_restore_first_rc);
    dt102738p_trace_value_u64("GOT_INSTALL_PROTECTION_RESTORE_RETRIED", 0,
        install_restore_retried ? 1 : 0);
    if (install_restore_retried)
        dt102738p_trace_event("GOT_INSTALL_PROTECTION_RESTORE_RETRY",
            (int)install_restore_retry_rc);
    dt102738p_trace_value_u64("GOT_INSTALLED_QUERY_RC", installed_query_rc,
        (uint64_t)(int64_t)installed_query_rc);
    dt102738p_trace_value_u64("GOT_INSTALLED_CURRENT_PROT", installed_query_rc,
        installed.current);
    dt102738p_trace_value_u64("GOT_INSTALLED_MAX_PROT", installed_query_rc,
        installed.maximum);
    dt102738p_trace_value_u64("GOT_INSTALLED_POINTER", installed_query_rc,
        installed_pointer);

    bool install_ok = install_rw_rc == KERN_SUCCESS
        && install_during_query_rc == 0 && install_during
        && install_during->current == (VM_PROT_READ | VM_PROT_WRITE)
        && install_during->maximum == initial->maximum
        && pointer_during == pointer_before && wrapper_store_attempted
        && wrapper_readback == wrapper_pointer && install_restore_ok
        && installed_query_rc == 0 && installed.current == initial->current
        && installed.maximum == initial->maximum
        && installed_pointer == wrapper_pointer;

    /* The counter was reset before the wrapper was published.  Keep that
     * pre-publication zero as the baseline so an immediate call is not lost. */
    uint64_t invocation_before = 0;
    uint64_t invocation_after = __atomic_load_n(&g_dt102738y_invocation_count,
        __ATOMIC_ACQUIRE);
    uint32_t polls = 0;
    if (install_ok) {
        dt102738p_trace_event("GOT_WRAPPER_INSTALL_PASS", 0);
        dt102738p_trace_event("GOT_WRAPPER_STORE_PASS", 0);
#ifdef DT_BUILD102738Z_PERSISTENT
        /*
         * Match Dopamine's launchd-hook lifetime: publish the transparent
         * wrapper, restore the GOT page protection, and return from the
         * constructor with the replacement still installed.  The app can
         * then restore Wall 2 before any post-install observation.
         */
        dt102738p_trace_value_u64("GOT_WRAPPER_INVOCATION_COUNT_AT_RETURN", 0,
            invocation_after);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
        dt102738p_trace_event("BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES", 0);
        dt102738p_trace_value_u64("BUILD102739_ENTRY_COUNT_AT_CTOR_RETURN", 0,
            invocation_after);
        dt102738p_trace_value_u64("BUILD102739_RETURN_COUNT_AT_CTOR_RETURN", 0,
            __atomic_load_n(&DT102739_IDENTITY_TELEMETRY.return_count,
                __ATOMIC_ACQUIRE));
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
        dt102738p_trace_event("BUILD102739E_DICTIONARY_TELEMETRY_EXPORTED_YES", 0);
        dt102738p_trace_value_u64("BUILD102739E_ENTRY_COUNT_AT_CTOR_RETURN", 0,
            invocation_after);
        dt102738p_trace_value_u64("BUILD102739E_RETURN_COUNT_AT_CTOR_RETURN", 0,
            __atomic_load_n(&g_dt102739e_dictionary_telemetry.return_count,
                __ATOMIC_ACQUIRE));
#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
        dt102738p_trace_event("BUILD102739C_OUTPUT_TELEMETRY_EXPORTED_YES", 0);
        dt102738p_trace_value_u64("BUILD102739C_ENTRY_COUNT_AT_CTOR_RETURN", 0,
            invocation_after);
        dt102738p_trace_value_u64("BUILD102739C_RETURN_COUNT_AT_CTOR_RETURN", 0,
            __atomic_load_n(&g_dt102739c_output_telemetry.return_count,
                __ATOMIC_ACQUIRE));
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
        dt102738p_trace_event("BUILD102739B_RETURN_TELEMETRY_EXPORTED_YES", 0);
        dt102738p_trace_value_u64("BUILD102739B_ENTRY_COUNT_AT_CTOR_RETURN", 0,
            invocation_after);
        dt102738p_trace_value_u64("BUILD102739B_RETURN_COUNT_AT_CTOR_RETURN", 0,
            __atomic_load_n(&g_dt102739b_return_telemetry.return_count,
                __ATOMIC_ACQUIRE));
#elif defined(DT_BUILD102739A_OBSERVER)
        dt102738p_trace_event("BUILD102739A_COUNTER_EXPORTED_YES", 0);
        dt102738p_trace_value_u64("BUILD102739A_COUNTER_AT_CTOR_RETURN", 0,
            invocation_after);
#endif
        dt102738p_trace_event("GOT_WRAPPER_PERSISTENT_INSTALL_PASS", 0);
        dt102738p_trace_event("GOT_PROTECTION_RESTORE_PASS", 0);
        dt102738p_trace_event("GOT_PROTECTION_TEST_PASS", 0);
        dt102738p_trace_event("GOT_PROBE_TERMINAL_PASS", 0);
        return 0;
#else
        while (polls < DT102738Y_OBSERVE_MAX_POLLS
            && invocation_after == invocation_before) {
            usleep(DT102738Y_OBSERVE_POLL_US);
            polls++;
            invocation_after = __atomic_load_n(&g_dt102738y_invocation_count,
                __ATOMIC_ACQUIRE);
        }
#endif
    }

    /* Restore the original pointer even when installation validation failed. */
    bool cleanup_rw_retried = false;
    kern_return_t cleanup_rw_retry_rc = KERN_FAILURE;
    kern_return_t cleanup_rw_first_rc = dt102738y_protect_with_retry(page,
        VM_PROT_READ | VM_PROT_WRITE, &cleanup_rw_retried, &cleanup_rw_retry_rc);
    bool cleanup_rw_ok = cleanup_rw_first_rc == KERN_SUCCESS
        || (cleanup_rw_retried && cleanup_rw_retry_rc == KERN_SUCCESS);
    dt102738p_region_t cleanup_during = {0};
    int cleanup_during_query_rc = cleanup_rw_ok
        ? dt102738p_query_region(slot, &cleanup_during) : -1;
    uint64_t cleanup_pointer_before = dt102738y_atomic_load_pointer(
        (const uint64_t *)slot);
    bool original_restore_attempted = false;
    uint64_t original_restore_readback = cleanup_pointer_before;
    if (cleanup_rw_ok && cleanup_during_query_rc == 0
        && cleanup_during.current == (VM_PROT_READ | VM_PROT_WRITE)
        && cleanup_during.maximum == initial->maximum
        && cleanup_pointer_before == wrapper_pointer) {
        dt102738y_atomic_store_pointer((uint64_t *)slot, pointer_before);
        original_restore_attempted = true;
        original_restore_readback = dt102738y_atomic_load_pointer(
            (const uint64_t *)slot);
    }

    bool cleanup_restore_retried = false;
    kern_return_t cleanup_restore_retry_rc = KERN_FAILURE;
    kern_return_t cleanup_restore_first_rc = dt102738y_protect_with_retry(page,
        initial->current, &cleanup_restore_retried, &cleanup_restore_retry_rc);
    bool cleanup_restore_ok = cleanup_restore_first_rc == KERN_SUCCESS
        || (cleanup_restore_retried
            && cleanup_restore_retry_rc == KERN_SUCCESS);

    dt102738p_region_t final = {0};
    int final_query_rc = dt102738p_query_region(slot, &final);
    uint64_t pointer_after = dt102738y_atomic_load_pointer((const uint64_t *)slot);
    bool final_state_ok = cleanup_restore_ok && final_query_rc == 0
        && final.current == initial->current
        && final.maximum == initial->maximum
        && pointer_after == pointer_before;

    dt102738p_trace_value_u64("GOT_WRAPPER_INVOCATION_COUNT_BEFORE", 0,
        invocation_before);
    dt102738p_trace_value_u64("GOT_WRAPPER_INVOCATION_COUNT_AFTER", 0,
        invocation_after);
    dt102738p_trace_value_u64("GOT_WRAPPER_OBSERVE_POLLS", 0, polls);
    dt102738p_trace_value_u64("GOT_WRAPPER_OBSERVE_POLL_US", 0,
        DT102738Y_OBSERVE_POLL_US);
    dt102738p_trace_event("GOT_CLEANUP_RW_FIRST", (int)cleanup_rw_first_rc);
    dt102738p_trace_value_u64("GOT_CLEANUP_RW_RETRIED", 0,
        cleanup_rw_retried ? 1 : 0);
    if (cleanup_rw_retried)
        dt102738p_trace_event("GOT_CLEANUP_RW_RETRY", (int)cleanup_rw_retry_rc);
    dt102738p_trace_value_u64("GOT_CLEANUP_DURING_QUERY_RC",
        cleanup_during_query_rc, (uint64_t)(int64_t)cleanup_during_query_rc);
    dt102738p_trace_value_u64("GOT_CLEANUP_POINTER_BEFORE",
        cleanup_during_query_rc, cleanup_pointer_before);
    dt102738p_trace_value_u64("GOT_ORIGINAL_RESTORE_ATTEMPTED", 0,
        original_restore_attempted ? 1 : 0);
    dt102738p_trace_value_u64("GOT_ORIGINAL_RESTORE_READBACK",
        original_restore_attempted ? 0 : -73827, original_restore_readback);
    dt102738p_trace_event("GOT_RESTORE_FIRST", (int)cleanup_restore_first_rc);
    dt102738p_trace_value_u64("GOT_RESTORE_RETRIED", 0,
        cleanup_restore_retried ? 1 : 0);
    if (cleanup_restore_retried)
        dt102738p_trace_event("GOT_RESTORE_RETRY",
            (int)cleanup_restore_retry_rc);
    dt102738p_trace_value_u64("GOT_FINAL_QUERY_RC", final_query_rc,
        (uint64_t)(int64_t)final_query_rc);
    dt102738p_trace_value_u64("GOT_FINAL_CURRENT_PROT", final_query_rc,
        final.current);
    dt102738p_trace_value_u64("GOT_FINAL_MAX_PROT", final_query_rc,
        final.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_AFTER", final_query_rc,
        pointer_after);

    if (!final_state_ok) {
        dt102738p_trace_event("GOT_PROTECTION_RESTORE_FATAL", -73845);
        return dt102738p_fail(NULL, -73845);
    }
    if (!install_ok)
        return dt102738p_fail("GOT_WRAPPER_INSTALL_VALIDATION_FAIL", -73841);
    if (!original_restore_attempted || original_restore_readback != pointer_before)
        return dt102738p_fail("GOT_ORIGINAL_RESTORE_READBACK_FAIL", -73842);
    if (invocation_after <= invocation_before)
        return dt102738p_fail("GOT_WRAPPER_NOT_INVOKED_FAIL", -73843);

    dt102738p_trace_event("GOT_WRAPPER_INVOKED_PASS", 0);
    dt102738p_trace_event("GOT_ORIGINAL_RESTORE_PASS", 0);
    dt102738p_trace_event("GOT_WRAPPER_INVOCATION_PROOF_PASS", 0);
    dt102738p_trace_event("GOT_POINTER_UNCHANGED_PASS", 0);
    dt102738p_trace_event("GOT_PROTECTION_RESTORE_PASS", 0);
    dt102738p_trace_event("GOT_PROTECTION_TEST_PASS", 0);
    dt102738p_trace_event("GOT_PROBE_TERMINAL_PASS", 0);
    return 0;
}
#endif

#ifdef DT_BUILD102738Y_TELEMETRY
int dt102738y_run_got_wrapper_invocation_probe(void)
#elif defined(DT_BUILD102738X_TELEMETRY)
int dt102738x_run_got_wrapper_roundtrip_probe(void)
#else
int dt102738w_run_got_same_value_store_probe(void)
#endif
{
#ifdef DT_BUILD102738Z_PERSISTENT
    dt102738p_trace_event("BUILD102738Z_PROBE_ENTER", 0);
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
    dt102738p_trace_event("BUILD102739J_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739J_SCOPE_CONTROLLED_REPLY_ROUNDTRIP", 0);
#elif defined(DT_BUILD102739I_CONTROLLED_HANDLER_ABI)
    dt102738p_trace_event("BUILD102739I_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739I_SCOPE_CONTROLLED_ACTION_HANDLER_ABI", 0);
#elif defined(DT_BUILD102739H_ARGUMENT_MARSHALLING)
    dt102738p_trace_event("BUILD102739H_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739H_SCOPE_READ_ONLY_ACTION_ARGUMENT_MARSHALLING", 0);
#elif defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
    dt102738p_trace_event("BUILD102739G_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739G_SCOPE_READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION", 0);
#elif defined(DT_BUILD102739F_CALLER_IDENTITY)
    dt102738p_trace_event("BUILD102739F_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739F_SCOPE_READ_ONLY_CALLER_IDENTITY", 0);
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
    dt102738p_trace_event("BUILD102739E_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739E_SCOPE_READ_ONLY_DICTIONARY_CLASSIFIER", 0);
#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
    dt102738p_trace_event("BUILD102739C_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739C_SCOPE_OUTPUT_CONTRACT_OBSERVER", 0);
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
    dt102738p_trace_event("BUILD102739B_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739B_SCOPE_POST_ORIGINAL_RETURN_OBSERVER", 0);
#elif defined(DT_BUILD102739A_OBSERVER)
    dt102738p_trace_event("BUILD102739A_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102739A_SCOPE_POST_WALL2_READ_ONLY_OBSERVER", 0);
#endif
    dt102738p_trace_event("BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES", 0);
#elif defined(DT_BUILD102738Y_TELEMETRY)
    dt102738p_trace_event("BUILD102738Y_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102738Y_COUNTING_WRAPPER_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("GOT_POINTER_WRITE_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("GOT_CONTROLLED_INVOCATION_PROBE_YES", 0);
    dt102738p_trace_event("XPC_MESSAGE_PARSING_IMPLEMENTED_NO", 0);
#elif defined(DT_BUILD102738X_TELEMETRY)
    dt102738p_trace_event("BUILD102738X_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102738X_TRANSPARENT_WRAPPER_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("GOT_POINTER_WRITE_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("GOT_POINTER_ROUNDTRIP_ONLY_YES", 0);
    dt102738p_trace_event("XPC_MESSAGE_PARSING_IMPLEMENTED_NO", 0);
#else
    dt102738p_trace_event("BUILD102738W_PROBE_ENTER", 0);
    dt102738p_trace_event("BUILD102738W_SAME_VALUE_STORE_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("GOT_POINTER_WRITE_IMPLEMENTED_YES", 0);
    dt102738p_trace_event("GOT_POINTER_REPLACED_NO", 0);
    dt102738p_trace_event("XPC_HOOK_INSTALL_IMPLEMENTED_NO", 0);
#endif

    if (getpid() != 1)
        return dt102738p_fail("PID1_IDENTITY_FAIL", -73801);
    const char *image_name = _dyld_get_image_name(0);
    if (!image_name || strcmp(image_name, "/sbin/launchd") != 0)
        return dt102738p_fail("LAUNCHD_PATH_FAIL", -73802);
    dt102738p_trace_event("PID1_IDENTITY_PASS", 0);

    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    if (!mh || mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64
        || mh->filetype != MH_EXECUTE || mh->ncmds == 0 || mh->ncmds > 128
        || mh->sizeofcmds > 0x10000)
        return dt102738p_fail("LAUNCHD_MACHO_HEADER_FAIL", -73803);

    bool uuid_ok = false;
    bool text_ok = false;
    bool data_const_ok = false;
    bool got_ok = false;
    uint64_t got_start = 0;
    uint64_t got_size = 0;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    const uint8_t *commands_end = cursor + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > commands_end)
            return dt102738p_fail("LAUNCHD_MACHO_COMMAND_FAIL", -73804);
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > commands_end)
            return dt102738p_fail("LAUNCHD_MACHO_COMMAND_FAIL", -73805);

        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            uuid_ok = memcmp(uc->uuid, kDT102738PLaunchdUUID,
                sizeof(kDT102738PLaunchdUUID)) == 0;
        } else if (lc->cmd == LC_SEGMENT_64
            && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
                text_ok = seg->vmaddr == DT102738P_STATIC_BASE
                    && seg->vmsize == 0x64000ULL
                    && seg->maxprot == (VM_PROT_READ | VM_PROT_EXECUTE)
                    && seg->initprot == (VM_PROT_READ | VM_PROT_EXECUTE);
            } else if (strncmp(seg->segname, "__DATA_CONST", sizeof(seg->segname)) == 0) {
                data_const_ok = seg->vmaddr == DT102738P_STATIC_DATA_CONST
                    && seg->vmsize == DT102738P_DATA_CONST_SIZE
                    && seg->maxprot == (VM_PROT_READ | VM_PROT_WRITE);
                const struct section_64 *section =
                    (const struct section_64 *)(seg + 1);
                size_t required = sizeof(*seg) + ((size_t)seg->nsects * sizeof(*section));
                if (required > seg->cmdsize)
                    return dt102738p_fail("LAUNCHD_MACHO_SECTION_FAIL", -73806);
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strncmp(section[s].sectname, "__got",
                            sizeof(section[s].sectname)) == 0
                        && strncmp(section[s].segname, "__DATA_CONST",
                            sizeof(section[s].segname)) == 0) {
                        got_start = section[s].addr;
                        got_size = section[s].size;
                        got_ok = got_start == DT102738P_STATIC_GOT_START
                            && got_size == DT102738P_GOT_SIZE;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }

    if (!uuid_ok)
        return dt102738p_fail("LAUNCHD_UUID_FAIL", -73807);
    dt102738p_trace_event("LAUNCHD_UUID_PASS", 0);
    if (!text_ok || !data_const_ok || !got_ok)
        return dt102738p_fail("LAUNCHD_MACHO_GEOMETRY_FAIL", -73808);
    if ((uintptr_t)mh != (uintptr_t)(DT102738P_STATIC_BASE + slide))
        return dt102738p_fail("LAUNCHD_SLIDE_GEOMETRY_FAIL", -73809);
    dt102738p_trace_event("LAUNCHD_MACHO_GEOMETRY_PASS", 0);

    uintptr_t slot = (uintptr_t)(DT102738P_STATIC_GOT_SLOT + slide);
    uintptr_t got_runtime_start = (uintptr_t)(got_start + slide);
    uintptr_t got_runtime_end = got_runtime_start + (uintptr_t)got_size;
    if (slot < got_runtime_start || slot > got_runtime_end - sizeof(uint64_t))
        return dt102738p_fail("GOT_SLOT_RANGE_FAIL", -73810);
    if ((slot & (sizeof(uint64_t) - 1U)) != 0)
        return dt102738p_fail("GOT_SLOT_ALIGNMENT_FAIL", -73819);
    dt102738p_trace_event("GOT_SLOT_RANGE_PASS", 0);

    uintptr_t stub = (uintptr_t)(DT102738P_STATIC_STUB + slide);
    uintptr_t callsite = (uintptr_t)(DT102738P_STATIC_CALLSITE + slide);
    if (!dt102738p_stub_resolves_slot(stub, slot)
        || !dt102738p_callsite_targets_stub(callsite, stub))
        return dt102738p_fail("GOT_STUB_REFERENCE_FAIL", -73811);
    dt102738p_trace_event("GOT_STUB_REFERENCE_PASS", 0);

    vm_size_t host_page_size_value = 0;
    kern_return_t page_kr = host_page_size(mach_host_self(), &host_page_size_value);
    if (page_kr != KERN_SUCCESS || host_page_size_value != DT102738P_PAGE_SIZE)
        return dt102738p_fail("GOT_PAGE_SIZE_FAIL", -73812);

    uintptr_t page = slot & ~(uintptr_t)(DT102738P_PAGE_SIZE - 1ULL);
    dt102738p_region_t initial = {0};
    int initial_query_rc = dt102738p_query_region(slot, &initial);
    if (initial_query_rc != 0 || initial.current != VM_PROT_READ
        || initial.maximum != (VM_PROT_READ | VM_PROT_WRITE)
        || page < initial.start || page + DT102738P_PAGE_SIZE > initial.start + initial.size)
        return dt102738p_fail("GOT_INITIAL_PROTECTION_FAIL", -73813);

#ifdef DT_BUILD102738Y_TELEMETRY
    uint64_t pointer_before = dt102738y_atomic_load_pointer((const uint64_t *)slot);
#elif defined(DT_BUILD102738X_TELEMETRY)
    uint64_t pointer_before = dt102738x_atomic_load_pointer((const uint64_t *)slot);
#else
    uint64_t pointer_before = dt102738w_atomic_load_pointer((const uint64_t *)slot);
#endif
    dt102738p_trace_value_u64("GOT_RUNTIME_SLOT", 0, slot);
    dt102738p_trace_value_u64("GOT_PAGE_START", 0, page);
    dt102738p_trace_value_u64("GOT_PAGE_SIZE", 0, host_page_size_value);
    dt102738p_trace_value_u64("GOT_INITIAL_CURRENT_PROT", 0, initial.current);
    dt102738p_trace_value_u64("GOT_INITIAL_MAX_PROT", 0, initial.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_BEFORE", 0, pointer_before);

    dt102738p_region_t pointer_basic = {0};
    int pointer_basic_rc = pointer_before
        ? dt102738p_query_region((mach_vm_address_t)pointer_before, &pointer_basic) : -1;
    dt102738p_trace_event("GOT_POINTER_BASIC_QUERY_DIAGNOSTIC_ONLY", pointer_basic_rc);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_QUERY_RC", pointer_basic_rc,
        (uint64_t)(int64_t)pointer_basic_rc);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_START", pointer_basic_rc,
        pointer_basic.start);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_SIZE", pointer_basic_rc,
        pointer_basic.size);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_CURRENT_PROT", pointer_basic_rc,
        pointer_basic.current);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_MAX_PROT", pointer_basic_rc,
        pointer_basic.maximum);

    dt102738p_recurse_region_t pointer_leaf = {0};
    int pointer_recurse_rc = pointer_before
        ? dt102738p_query_executable_leaf((mach_vm_address_t)pointer_before,
            &pointer_leaf) : -1;
    dt102738p_trace_event("BUILD102738R_POINTER_VALIDATOR_REPAIR", 0);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_QUERY_RC", pointer_recurse_rc,
        (uint64_t)(int64_t)pointer_recurse_rc);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_START", pointer_recurse_rc,
        pointer_leaf.start);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_SIZE", pointer_recurse_rc,
        pointer_leaf.size);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_DEPTH", pointer_recurse_rc,
        pointer_leaf.depth);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_IS_SUBMAP", pointer_recurse_rc,
        pointer_leaf.is_submap ? 1 : 0);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_CURRENT_PROT", pointer_recurse_rc,
        pointer_leaf.current);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_MAX_PROT", pointer_recurse_rc,
        pointer_leaf.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_CONTAINS_POINTER",
        pointer_recurse_rc, pointer_recurse_rc == 0 ? 1 : 0);

    if (!pointer_before)
        return dt102738p_fail("GOT_POINTER_NULL_FAIL", -73814);
    if (pointer_recurse_rc != 0)
        return dt102738p_fail("GOT_POINTER_RECURSE_QUERY_FAIL", -73814);
    if (pointer_leaf.is_submap)
        return dt102738p_fail("GOT_POINTER_RECURSE_LEAF_FAIL", -73814);
    if (!(pointer_leaf.current & VM_PROT_EXECUTE))
        return dt102738p_fail("GOT_POINTER_EXEC_MAPPING_FAIL", -73814);

    dt102738p_trace_event("GOT_POINTER_RECURSE_MAPPING_PASS", 0);
    dt102738p_trace_event("GOT_POINTER_EXEC_MAPPING_PASS", 0);
#ifdef DT_BUILD102738Y_TELEMETRY
    uint64_t wrapper_pointer = (uint64_t)(uintptr_t)&dt102738y_counting_wrapper;
    dt102738p_recurse_region_t wrapper_leaf = {0};
    int wrapper_query_rc = dt102738p_query_executable_leaf(wrapper_pointer,
        &wrapper_leaf);
    bool wrapper_in_hook_text =
        dt102738y_pointer_in_launchdhook_text((uintptr_t)wrapper_pointer);
    dt102738p_trace_value_u64("GOT_WRAPPER_POINTER", 0, wrapper_pointer);
    dt102738p_trace_value_u64("GOT_WRAPPER_QUERY_RC", wrapper_query_rc,
        (uint64_t)(int64_t)wrapper_query_rc);
    dt102738p_trace_value_u64("GOT_WRAPPER_CURRENT_PROT", wrapper_query_rc,
        wrapper_leaf.current);
    dt102738p_trace_value_u64("GOT_WRAPPER_IN_HOOK_TEXT", 0,
        wrapper_in_hook_text ? 1 : 0);
    if (!wrapper_pointer || wrapper_pointer == pointer_before)
        return dt102738p_fail("GOT_WRAPPER_POINTER_IDENTITY_FAIL", -73823);
    if (wrapper_query_rc != 0 || wrapper_leaf.is_submap
        || !(wrapper_leaf.current & VM_PROT_EXECUTE))
        return dt102738p_fail("GOT_WRAPPER_EXEC_MAPPING_FAIL", -73824);
    if (!wrapper_in_hook_text)
        return dt102738p_fail("GOT_WRAPPER_IMAGE_RANGE_FAIL", -73825);
    dt102738p_trace_event("GOT_WRAPPER_POINTER_DIFFERS_PASS", 0);
    dt102738p_trace_event("GOT_WRAPPER_EXEC_MAPPING_PASS", 0);
    dt102738p_trace_event("GOT_WRAPPER_IN_HOOK_IMAGE_PASS", 0);
    __atomic_store_n(&g_dt102738y_invocation_count, 0, __ATOMIC_RELEASE);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION) || \
    defined(DT_BUILD102739F_CALLER_IDENTITY)
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.success_return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.xout_argument_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.success_xout_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.success_object_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.dictionary_object_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.domain_key_present_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.action_key_present_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.domain_action_envelope_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.exact_controlled_probe_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.domain_nonzero_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.systemwide_domain_candidate_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.audit_token_capture_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.captured_pid, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.captured_euid, 0,
        __ATOMIC_RELEASE);
#if defined(DT_BUILD102739H_ARGUMENT_MARSHALLING) || \
    defined(DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION)
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.domain_resolution_attempt_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.domain_resolution_success_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.permission_check_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.permission_allow_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.action_nonzero_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.action_resolution_attempt_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.action_resolution_success_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_invocation_count, 0,
        __ATOMIC_RELEASE);
#ifdef DT_BUILD102739H_ARGUMENT_MARSHALLING
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_pointer_capture_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_pointer_nonnull_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.args_zero_initialized_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.argsout_zero_initialized_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.arg_descriptor_scan_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.arg_descriptor_root_path_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.arg_descriptor_string_type_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.arg_descriptor_out_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.output_slot_bind_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.arg_terminator_found_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.marshalling_complete_count, 0,
        __ATOMIC_RELEASE);
#ifdef DT_BUILD102739I_CONTROLLED_HANDLER_ABI
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_call_attempt_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_arg0_output_slot_match_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_args1_through_7_null_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_output_write_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.argsout0_sentinel_match_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.argsout_tail_null_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.handler_result_match_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.controlled_handler_complete_count, 0,
        __ATOMIC_RELEASE);
#ifdef DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP
#define DT102739J_RESET_FIELD(field) \
    __atomic_store_n(&DT102739_IDENTITY_TELEMETRY.field, 0, __ATOMIC_RELEASE)
    DT102739J_RESET_FIELD(original_receive_call_count);
    DT102739J_RESET_FIELD(original_receive_return_count);
    DT102739J_RESET_FIELD(original_receive_last_result);
    DT102739J_RESET_FIELD(reply_create_attempt_count);
    DT102739J_RESET_FIELD(reply_create_success_count);
    DT102739J_RESET_FIELD(reply_create_failed_precommit_count);
    DT102739J_RESET_FIELD(reply_identity_failed_precommit_count);
    DT102739J_RESET_FIELD(root_path_set_count);
    DT102739J_RESET_FIELD(result_set_count);
    DT102739J_RESET_FIELD(root_path_exists_count);
    DT102739J_RESET_FIELD(root_path_type_match_count);
    DT102739J_RESET_FIELD(result_exists_count);
    DT102739J_RESET_FIELD(result_type_match_count);
    DT102739J_RESET_FIELD(reply_readback_match_count);
    DT102739J_RESET_FIELD(reply_readback_failed_precommit_count);
    DT102739J_RESET_FIELD(precommit_xout_match_count);
    DT102739J_RESET_FIELD(precommit_xout_mismatch_count);
    DT102739J_RESET_FIELD(precommit_reply_release_count);
    DT102739J_RESET_FIELD(precommit_fallback_count);
    DT102739J_RESET_FIELD(reply_send_attempt_count);
    DT102739J_RESET_FIELD(reply_send_return_count);
    DT102739J_RESET_FIELD(server_reply_send_rc);
    DT102739J_RESET_FIELD(server_reply_release_count);
    DT102739J_RESET_FIELD(committed_xout_match_count);
    DT102739J_RESET_FIELD(committed_xout_mismatch_count);
    DT102739J_RESET_FIELD(input_consume_release_count);
    DT102739J_RESET_FIELD(committed_consume_path_complete_count);
    DT102739J_RESET_FIELD(server_committed_lifecycle_pass_count);
    DT102739J_RESET_FIELD(wrapper_return_22_count);
#undef DT102739J_RESET_FIELD
#endif
#endif
#endif
#endif
#elif defined(DT_BUILD102739E_DICTIONARY_CLASSIFIER)
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.success_return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.xout_argument_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.success_xout_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.success_object_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.dictionary_object_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.domain_key_present_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.action_key_present_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.domain_action_envelope_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739e_dictionary_telemetry.exact_controlled_probe_count, 0,
        __ATOMIC_RELEASE);
#elif defined(DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER)
    __atomic_store_n(&g_dt102739c_output_telemetry.return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739c_output_telemetry.success_return_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739c_output_telemetry.xout_argument_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739c_output_telemetry.success_xout_count, 0,
        __ATOMIC_RELEASE);
    __atomic_store_n(&g_dt102739c_output_telemetry.success_object_count, 0,
        __ATOMIC_RELEASE);
#elif defined(DT_BUILD102739B_RETURN_OBSERVER)
    __atomic_store_n(&g_dt102739b_return_telemetry.return_count, 0,
        __ATOMIC_RELEASE);
#endif
    __atomic_store_n(&g_dt102738y_original_receive, pointer_before,
        __ATOMIC_RELEASE);
#elif defined(DT_BUILD102738X_TELEMETRY)
    uint64_t wrapper_pointer = (uint64_t)(uintptr_t)&dt102738x_transparent_wrapper;
    dt102738p_recurse_region_t wrapper_leaf = {0};
    int wrapper_query_rc = dt102738p_query_executable_leaf(wrapper_pointer,
        &wrapper_leaf);
    bool wrapper_in_hook_text =
        dt102738x_pointer_in_launchdhook_text((uintptr_t)wrapper_pointer);
    dt102738p_trace_value_u64("GOT_WRAPPER_POINTER", 0, wrapper_pointer);
    dt102738p_trace_value_u64("GOT_WRAPPER_QUERY_RC", wrapper_query_rc,
        (uint64_t)(int64_t)wrapper_query_rc);
    dt102738p_trace_value_u64("GOT_WRAPPER_CURRENT_PROT", wrapper_query_rc,
        wrapper_leaf.current);
    dt102738p_trace_value_u64("GOT_WRAPPER_IN_HOOK_TEXT", 0,
        wrapper_in_hook_text ? 1 : 0);
    if (!wrapper_pointer || wrapper_pointer == pointer_before)
        return dt102738p_fail("GOT_WRAPPER_POINTER_IDENTITY_FAIL", -73823);
    if (wrapper_query_rc != 0 || wrapper_leaf.is_submap
        || !(wrapper_leaf.current & VM_PROT_EXECUTE))
        return dt102738p_fail("GOT_WRAPPER_EXEC_MAPPING_FAIL", -73824);
    if (!wrapper_in_hook_text)
        return dt102738p_fail("GOT_WRAPPER_IMAGE_RANGE_FAIL", -73825);
    dt102738p_trace_event("GOT_WRAPPER_POINTER_DIFFERS_PASS", 0);
    dt102738p_trace_event("GOT_WRAPPER_EXEC_MAPPING_PASS", 0);
    dt102738p_trace_event("GOT_WRAPPER_IN_HOOK_IMAGE_PASS", 0);
    __atomic_store_n(&g_dt102738x_original_receive, pointer_before,
        __ATOMIC_RELEASE);
#endif
    dt102738p_trace_value_u64("GOT_RW_REQUEST_PROT", 0,
        VM_PROT_READ | VM_PROT_WRITE);
    dt102738p_trace_value_u64("GOT_RW_SET_MAXIMUM", 0, 0);

    /* No trace I/O is permitted while the page is writable. */
    kern_return_t rw_rc = dt102738p_mach_vm_protect(mach_task_self(), page,
        DT102738P_PAGE_SIZE, false, VM_PROT_READ | VM_PROT_WRITE);
    dt102738p_region_t during = {0};
    int during_query_rc = -1;
    uint64_t pointer_during = 0;
    uint64_t pointer_prestore = 0;
    uint64_t pointer_readback = 0;
    bool store_attempted = false;
#if defined(DT_BUILD102738X_TELEMETRY) || defined(DT_BUILD102738Y_TELEMETRY)
    uint64_t wrapper_readback = 0;
    uint64_t original_restore_readback = 0;
    bool wrapper_store_attempted = false;
    bool original_restore_attempted = false;
#endif
    kern_return_t restore_first_rc = KERN_FAILURE;
    kern_return_t restore_retry_rc = KERN_FAILURE;
    bool restore_retried = false;
    if (rw_rc == KERN_SUCCESS) {
        during_query_rc = dt102738p_query_region(slot, &during);
        pointer_during =
#ifdef DT_BUILD102738Y_TELEMETRY
            dt102738y_atomic_load_pointer((const uint64_t *)slot);
#elif defined(DT_BUILD102738X_TELEMETRY)
            dt102738x_atomic_load_pointer((const uint64_t *)slot);
#else
            dt102738w_atomic_load_pointer((const uint64_t *)slot);
#endif
        pointer_prestore = pointer_during;
        if (during_query_rc == 0
            && during.current == (VM_PROT_READ | VM_PROT_WRITE)
            && during.maximum == initial.maximum
            && pointer_prestore == pointer_before) {
#ifdef DT_BUILD102738Y_TELEMETRY
            dt102738y_atomic_store_pointer((uint64_t *)slot, wrapper_pointer);
            wrapper_store_attempted = true;
            wrapper_readback = dt102738y_atomic_load_pointer((const uint64_t *)slot);
#elif defined(DT_BUILD102738X_TELEMETRY)
            dt102738x_atomic_store_pointer((uint64_t *)slot, wrapper_pointer);
            wrapper_store_attempted = true;
            wrapper_readback = dt102738x_atomic_load_pointer((const uint64_t *)slot);
            dt102738x_atomic_store_pointer((uint64_t *)slot, pointer_before);
            original_restore_attempted = true;
            original_restore_readback =
                dt102738x_atomic_load_pointer((const uint64_t *)slot);
#else
            dt102738w_atomic_store_same_value((uint64_t *)slot, pointer_before);
            store_attempted = true;
            pointer_readback = dt102738w_atomic_load_pointer((const uint64_t *)slot);
#endif
        }
        restore_first_rc = dt102738p_mach_vm_protect(mach_task_self(), page,
            DT102738P_PAGE_SIZE, false, initial.current);
        if (restore_first_rc != KERN_SUCCESS) {
            restore_retried = true;
            restore_retry_rc = dt102738p_mach_vm_protect(mach_task_self(), page,
                DT102738P_PAGE_SIZE, false, initial.current);
        }
    }

#ifdef DT_BUILD102738Y_TELEMETRY
    return dt102738y_finish_installed_probe(slot, page, &initial, pointer_before,
        wrapper_pointer, rw_rc, during_query_rc, &during, pointer_during,
        wrapper_store_attempted, wrapper_readback, restore_first_rc,
        restore_retried, restore_retry_rc);
#endif

    dt102738p_region_t final = {0};
    int final_query_rc = dt102738p_query_region(slot, &final);
    uint64_t pointer_after =
#ifdef DT_BUILD102738X_TELEMETRY
        dt102738x_atomic_load_pointer((const uint64_t *)slot);
#else
        dt102738w_atomic_load_pointer((const uint64_t *)slot);
#endif
    bool restore_call_ok = rw_rc != KERN_SUCCESS
        || restore_first_rc == KERN_SUCCESS
        || (restore_retried && restore_retry_rc == KERN_SUCCESS);
    bool final_state_ok = final_query_rc == 0
        && final.current == initial.current
        && final.maximum == initial.maximum
        && pointer_after == pointer_before;

    dt102738p_trace_event("GOT_RW_TRANSITION", (int)rw_rc);
    dt102738p_trace_value_u64("GOT_DURING_QUERY_RC", during_query_rc, during_query_rc);
    dt102738p_trace_value_u64("GOT_DURING_CURRENT_PROT", during_query_rc, during.current);
    dt102738p_trace_value_u64("GOT_DURING_MAX_PROT", during_query_rc, during.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_DURING", during_query_rc, pointer_during);
    dt102738p_trace_value_u64("GOT_PRESTORE_POINTER", during_query_rc, pointer_prestore);
#ifdef DT_BUILD102738X_TELEMETRY
    dt102738p_trace_value_u64("GOT_WRAPPER_STORE_ATTEMPTED", 0,
        wrapper_store_attempted ? 1 : 0);
    dt102738p_trace_value_u64("GOT_WRAPPER_READBACK",
        wrapper_store_attempted ? 0 : -73826, wrapper_readback);
    dt102738p_trace_value_u64("GOT_ORIGINAL_RESTORE_ATTEMPTED", 0,
        original_restore_attempted ? 1 : 0);
    dt102738p_trace_value_u64("GOT_ORIGINAL_RESTORE_READBACK",
        original_restore_attempted ? 0 : -73827, original_restore_readback);
#else
    dt102738p_trace_value_u64("GOT_SAME_VALUE_STORE_ATTEMPTED", 0,
        store_attempted ? 1 : 0);
    dt102738p_trace_value_u64("GOT_SAME_VALUE_STORE_READBACK",
        store_attempted ? 0 : -73820, pointer_readback);
#endif
    dt102738p_trace_event("GOT_RESTORE_FIRST", (int)restore_first_rc);
    dt102738p_trace_value_u64("GOT_RESTORE_RETRIED", 0, restore_retried ? 1 : 0);
    if (restore_retried)
        dt102738p_trace_event("GOT_RESTORE_RETRY", (int)restore_retry_rc);
    dt102738p_trace_value_u64("GOT_FINAL_QUERY_RC", final_query_rc, final_query_rc);
    dt102738p_trace_value_u64("GOT_FINAL_CURRENT_PROT", final_query_rc, final.current);
    dt102738p_trace_value_u64("GOT_FINAL_MAX_PROT", final_query_rc, final.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_AFTER", final_query_rc, pointer_after);

    if (rw_rc == KERN_SUCCESS && (!restore_call_ok || !final_state_ok)) {
        dt102738p_trace_event("GOT_PROTECTION_RESTORE_FATAL", -73815);
        return dt102738p_fail(NULL, -73815);
    }
    if (rw_rc != KERN_SUCCESS)
        return dt102738p_fail("GOT_RW_TRANSITION_FAIL", -73816);
    if (during_query_rc != 0
        || during.current != (VM_PROT_READ | VM_PROT_WRITE)
        || during.maximum != initial.maximum)
        return dt102738p_fail("GOT_DURING_PROTECTION_FAIL", -73817);
    if (pointer_prestore != pointer_before)
        return dt102738p_fail("GOT_PRESTORE_POINTER_CHANGED_FAIL", -73820);
#ifdef DT_BUILD102738X_TELEMETRY
    if (!wrapper_store_attempted)
        return dt102738p_fail("GOT_WRAPPER_STORE_NOT_ATTEMPTED_FAIL", -73826);
    if (wrapper_readback != wrapper_pointer)
        return dt102738p_fail("GOT_WRAPPER_READBACK_FAIL", -73828);
    if (!original_restore_attempted)
        return dt102738p_fail("GOT_ORIGINAL_RESTORE_NOT_ATTEMPTED_FAIL", -73827);
    if (original_restore_readback != pointer_before)
        return dt102738p_fail("GOT_ORIGINAL_RESTORE_READBACK_FAIL", -73829);
#else
    if (!store_attempted)
        return dt102738p_fail("GOT_SAME_VALUE_STORE_NOT_ATTEMPTED_FAIL", -73821);
    if (pointer_readback != pointer_before)
        return dt102738p_fail("GOT_SAME_VALUE_STORE_READBACK_FAIL", -73822);
#endif
    if (pointer_during != pointer_before || pointer_after != pointer_before)
        return dt102738p_fail("GOT_POINTER_CHANGED_FATAL", -73818);

    dt102738p_trace_event("GOT_PRESTORE_MATCH_PASS", 0);
#ifdef DT_BUILD102738X_TELEMETRY
    dt102738p_trace_event("GOT_WRAPPER_STORE_PASS", 0);
    dt102738p_trace_event("GOT_ORIGINAL_RESTORE_PASS", 0);
    dt102738p_trace_event("GOT_WRAPPER_ROUNDTRIP_PASS", 0);
#else
    dt102738p_trace_event("GOT_SAME_VALUE_STORE_PASS", 0);
#endif
    dt102738p_trace_event("GOT_POINTER_UNCHANGED_PASS", 0);
    dt102738p_trace_event("GOT_PROTECTION_RESTORE_PASS", 0);
    dt102738p_trace_event("GOT_PROTECTION_TEST_PASS", 0);
    dt102738p_trace_event("GOT_PROBE_TERMINAL_PASS", 0);
    return 0;
}
