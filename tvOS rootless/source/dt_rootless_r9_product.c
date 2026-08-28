#include "dt_rootless_r9_product.h"

bool dt_rootless_r9_ctor_product_ok(const dt_rootless_r9_ctor_inputs_t *in)
{
    if (!in)
        return false;
    return in->restore_r == 0
        && in->inject_r == 0
        && in->remote_dlopen_rc == 0
        && in->ctor_return_pass
        && in->ctor_exit_reached
        && in->primitives_init_pass
        && in->boomerang_done_send_pass
        && in->boomerang_wait_rc == 0
        && in->got_probe_terminal_pass
        && in->got_restore_pass
        && !in->got_restore_fatal;
}

bool dt_rootless_product_executes_j_controlled_reply(void)
{
#ifdef DT_ROOTLESS_R4
    return false;
#else
    return true;
#endif
}

bool dt_rootless_product_requires_rootful_wrapper_store(void)
{
#ifdef DT_ROOTLESS_R4
    return false;
#else
    return true;
#endif
}

bool dt_rootless_product_requires_rootful_persistent_install(void)
{
#ifdef DT_ROOTLESS_R4
    return false;
#else
    return true;
#endif
}

bool dt_rootless_product_executes_n_runa_mutation(void)
{
#ifdef DT_ROOTLESS_R4
    return false;
#else
    return true;
#endif
}

bool dt_rootless_product_j_failure_is_terminal(bool ctor_product_ok,
                                               bool j_legacy_handler_pass)
{
    if (dt_rootless_product_executes_j_controlled_reply())
        return !j_legacy_handler_pass;
    /* R9: obsolete J telemetry cannot terminal-stop rootless. */
    (void)j_legacy_handler_pass;
    return !ctor_product_ok;
}
