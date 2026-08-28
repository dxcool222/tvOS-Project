#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int restore_r;
    int inject_r;
    int remote_dlopen_rc;
    int boomerang_wait_rc;
    bool ctor_return_pass;
    bool ctor_exit_reached;
    bool primitives_init_pass;
    bool boomerang_done_send_pass;
    bool got_probe_terminal_pass;
    bool got_restore_pass;
    bool got_restore_fatal;
} dt_rootless_r9_ctor_inputs_t;

/*
 * Shared R9 product ctor/Wall2/GOT-protection gate.
 * Used by dt_kcall_planb.m (device) and HOST_SIM.
 */
bool dt_rootless_r9_ctor_product_ok(const dt_rootless_r9_ctor_inputs_t *in);

/* Product policy under DT_ROOTLESS_R4. Device and HOST_SIM agree. */
bool dt_rootless_product_executes_j_controlled_reply(void);
bool dt_rootless_product_requires_rootful_wrapper_store(void);
bool dt_rootless_product_requires_rootful_persistent_install(void);
bool dt_rootless_product_executes_n_runa_mutation(void);
bool dt_rootless_product_j_failure_is_terminal(bool ctor_product_ok,
                                               bool j_legacy_handler_pass);

#ifdef __cplusplus
}
#endif
