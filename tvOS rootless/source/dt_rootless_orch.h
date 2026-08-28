#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DT_GATE_KIND_PRODUCT = 0,
    DT_GATE_KIND_DIAGNOSTIC = 1,
    DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY = 2,
} dt_gate_kind_t;

typedef enum {
    DT_KFD_CLOSED = 0,
    DT_KFD_OPEN = 1,
    DT_KFD_CONSUMED = 2,
} dt_kfd_sim_state_t;

/* Product / diagnostic / physical-only terminal predicates. Keep expanded. */
typedef enum {
    DT_GATE_R6_IDENTITY = 0,
    DT_GATE_R6_PAYLOAD_COUNT,
    DT_GATE_R6_TRUST_COUNT,
    DT_GATE_R6_CLASSIFY_BLOCK,
    DT_GATE_KFD_OPEN,
    DT_GATE_KFD_REENTRY,
    DT_GATE_DEP,
    DT_GATE_TRUST_TRIO,
    DT_GATE_BOOMERANG,
    DT_GATE_STASH_PORT,
    DT_GATE_WALL2_APPLY,
    DT_GATE_OPAINJECT1,
    DT_GATE_WALL2_RESTORE,
    DT_GATE_REMOTE_DLOPEN,
    DT_GATE_CTOR_RETURN,
    DT_GATE_CTOR_EXIT,
    DT_GATE_PRIMITIVES,
    DT_GATE_BOOMERANG_DONE,
    DT_GATE_BOOMERANG_WAIT,
    DT_GATE_GOT_PROBE,
    DT_GATE_GOT_RESTORE,
    DT_GATE_GOT_RESTORE_FATAL,
    DT_GATE_R9_CTOR_PRODUCT,
    DT_GATE_FRESH_FS,
    DT_GATE_POSTVERIFY,
    DT_GATE_TRUST_PAYLOAD,
    DT_GATE_OPAINJECT2,
    DT_GATE_CTOR2,
    DT_GATE_DYLD_DELIVERY,
    DT_GATE_PASSWORD,
    DT_GATE_SSH,
    DT_GATE_CURRENT_BOOT_RUNTIME,
    DT_GATE_COMMIT,
    /* Diagnostics — FAIL must not stop DT_ROOTLESS_R4 product. */
    DT_GATE_J_CONTROLLED_REPLY,
    DT_GATE_K_ROOTFUL_PREFLIGHT,
    DT_GATE_L_POLICY,
    DT_GATE_M_FIXTURE,
    DT_GATE_N_RUNA,
    DT_GATE_C_OBSERVER,
    DT_GATE_D_TRIGGER,
    DT_GATE_WRAPPER_STORE,
    DT_GATE_PERSISTENT_INSTALL,
    /* Physical-runtime-only: never fake PASS. */
    DT_GATE_PHYS_KFD_EXPLOIT,
    DT_GATE_PHYS_KERNEL_ADDRS,
    DT_GATE_PHYS_AMFI,
    DT_GATE_PHYS_PID1_DLOPEN,
    DT_GATE_PHYS_SANDBOX_EXT,
    DT_GATE_PHYS_LIVE_SSH,
    DT_GATE_COUNT
} dt_gate_id_t;

typedef struct dt_rootless_plat dt_rootless_plat_t;

struct dt_rootless_plat {
    void *ctx;
    void (*log)(void *ctx, const char *line);
    int (*get_int)(void *ctx, const char *key, int default_value);
    int (*obs_bool)(void *ctx, const char *key, int default_value); /* 1/0/-1 unknown */
    int (*gate_forced)(void *ctx, int gate_id); /* 1 force pass, 0 force fail, -1 none */
    int (*kfd_open)(void *ctx);
    int (*kfd_close)(void *ctx);
    int (*kfd_state)(void *ctx);
    int (*kfd_open_count)(void *ctx);
    int (*kfd_reentry_count)(void *ctx);
    int (*fs_stage)(void *ctx, int r6_path); /* 0 ok */
    int (*write_incomplete)(void *ctx);
    int (*commit)(void *ctx);
    int (*is_committed)(void *ctx);
    int (*has_incomplete)(void *ctx);
};

typedef struct {
    int status;                 /* 0 = product would commit path ok */
    int r6_path;
    int r6_state;
    int committed;
    int incomplete;
    int kfd_open_count;
    int kfd_reentry_count;
    int kfd_state;
    int failed_gate;            /* dt_gate_id_t or -1 */
    char result[128];
    int product_gate_fails;
    int diagnostic_fails_continued;
} dt_rootless_orch_result_t;

const char *dt_rootless_gate_name(int gate_id);
dt_gate_kind_t dt_rootless_gate_kind(int gate_id);
int dt_rootless_gate_count(void);
int dt_rootless_product_gate_count(void);
int dt_rootless_diagnostic_gate_count(void);
int dt_rootless_physical_gate_count(void);

/* Per-bringup instrumentation. Reset automatically at orch_bringup entry. */
void dt_rootless_gate_stats_reset(void);
int dt_rootless_gate_visit_count(int gate_id);
int dt_rootless_gate_fail_count(int gate_id);
int dt_rootless_gate_last_result(int gate_id); /* 1 pass, 0 fail, -1 never/unknown */

/* Same Bring-Up sequence HOST_SIM compiles; device must BL this from bootstrapG5Tapped. */
int dt_rootless_orch_bringup(dt_rootless_plat_t *plat, dt_rootless_orch_result_t *out);

#ifdef __cplusplus
}
#endif
