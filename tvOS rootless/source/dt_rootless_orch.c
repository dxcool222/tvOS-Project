#include "dt_rootless_orch.h"
#include "dt_rootless_r6_decide.h"
#include "dt_rootless_r9_product.h"

#include <stdio.h>
#include <string.h>

static const struct {
    const char *name;
    dt_gate_kind_t kind;
} kGates[DT_GATE_COUNT] = {
    { "R6_IDENTITY", DT_GATE_KIND_PRODUCT },
    { "R6_PAYLOAD_COUNT", DT_GATE_KIND_PRODUCT },
    { "R6_TRUST_COUNT", DT_GATE_KIND_PRODUCT },
    { "R6_CLASSIFY_BLOCK", DT_GATE_KIND_PRODUCT },
    { "KFD_OPEN", DT_GATE_KIND_PRODUCT },
    { "KFD_REENTRY", DT_GATE_KIND_PRODUCT },
    { "DEP", DT_GATE_KIND_PRODUCT },
    { "TRUST_TRIO", DT_GATE_KIND_PRODUCT },
    { "BOOMERANG", DT_GATE_KIND_PRODUCT },
    { "STASH_PORT", DT_GATE_KIND_PRODUCT },
    { "WALL2_APPLY", DT_GATE_KIND_PRODUCT },
    { "OPAINJECT1", DT_GATE_KIND_PRODUCT },
    { "WALL2_RESTORE", DT_GATE_KIND_PRODUCT },
    { "REMOTE_DLOPEN", DT_GATE_KIND_PRODUCT },
    { "CTOR_RETURN", DT_GATE_KIND_PRODUCT },
    { "CTOR_EXIT", DT_GATE_KIND_PRODUCT },
    { "PRIMITIVES", DT_GATE_KIND_PRODUCT },
    { "BOOMERANG_DONE", DT_GATE_KIND_PRODUCT },
    { "BOOMERANG_WAIT", DT_GATE_KIND_PRODUCT },
    { "GOT_PROBE", DT_GATE_KIND_PRODUCT },
    { "GOT_RESTORE", DT_GATE_KIND_PRODUCT },
    { "GOT_RESTORE_FATAL", DT_GATE_KIND_PRODUCT },
    { "R9_CTOR_PRODUCT", DT_GATE_KIND_PRODUCT },
    { "FRESH_FS", DT_GATE_KIND_PRODUCT },
    { "POSTVERIFY", DT_GATE_KIND_PRODUCT },
    { "TRUST_PAYLOAD", DT_GATE_KIND_PRODUCT },
    { "OPAINJECT2", DT_GATE_KIND_PRODUCT },
    { "CTOR2", DT_GATE_KIND_PRODUCT },
    { "DYLD_DELIVERY", DT_GATE_KIND_PRODUCT },
    { "PASSWORD", DT_GATE_KIND_PRODUCT },
    { "SSH", DT_GATE_KIND_PRODUCT },
    { "CURRENT_BOOT_RUNTIME", DT_GATE_KIND_PRODUCT },
    { "COMMIT", DT_GATE_KIND_PRODUCT },
    { "J_CONTROLLED_REPLY", DT_GATE_KIND_DIAGNOSTIC },
    { "K_ROOTFUL_PREFLIGHT", DT_GATE_KIND_DIAGNOSTIC },
    { "L_POLICY", DT_GATE_KIND_DIAGNOSTIC },
    { "M_FIXTURE", DT_GATE_KIND_DIAGNOSTIC },
    { "N_RUNA", DT_GATE_KIND_DIAGNOSTIC },
    { "C_OBSERVER", DT_GATE_KIND_DIAGNOSTIC },
    { "D_TRIGGER", DT_GATE_KIND_DIAGNOSTIC },
    { "WRAPPER_STORE", DT_GATE_KIND_DIAGNOSTIC },
    { "PERSISTENT_INSTALL", DT_GATE_KIND_DIAGNOSTIC },
    { "PHYS_KFD_EXPLOIT", DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY },
    { "PHYS_KERNEL_ADDRS", DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY },
    { "PHYS_AMFI", DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY },
    { "PHYS_PID1_DLOPEN", DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY },
    { "PHYS_SANDBOX_EXT", DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY },
    { "PHYS_LIVE_SSH", DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY },
};

const char *dt_rootless_gate_name(int gate_id)
{
    if (gate_id < 0 || gate_id >= DT_GATE_COUNT)
        return "UNKNOWN";
    return kGates[gate_id].name;
}

dt_gate_kind_t dt_rootless_gate_kind(int gate_id)
{
    if (gate_id < 0 || gate_id >= DT_GATE_COUNT)
        return DT_GATE_KIND_PRODUCT;
    return kGates[gate_id].kind;
}

int dt_rootless_gate_count(void)
{
    return DT_GATE_COUNT;
}

int dt_rootless_product_gate_count(void)
{
    int n = 0;
    for (int i = 0; i < DT_GATE_COUNT; i++)
        if (kGates[i].kind == DT_GATE_KIND_PRODUCT)
            n++;
    return n;
}

int dt_rootless_diagnostic_gate_count(void)
{
    int n = 0;
    for (int i = 0; i < DT_GATE_COUNT; i++)
        if (kGates[i].kind == DT_GATE_KIND_DIAGNOSTIC)
            n++;
    return n;
}

int dt_rootless_physical_gate_count(void)
{
    int n = 0;
    for (int i = 0; i < DT_GATE_COUNT; i++)
        if (kGates[i].kind == DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY)
            n++;
    return n;
}

static int g_visit[DT_GATE_COUNT];
static int g_fail[DT_GATE_COUNT];
static int g_last[DT_GATE_COUNT];

void dt_rootless_gate_stats_reset(void)
{
    memset(g_visit, 0, sizeof(g_visit));
    memset(g_fail, 0, sizeof(g_fail));
    for (int i = 0; i < DT_GATE_COUNT; i++)
        g_last[i] = -1;
}

int dt_rootless_gate_visit_count(int gate_id)
{
    if (gate_id < 0 || gate_id >= DT_GATE_COUNT)
        return 0;
    return g_visit[gate_id];
}

int dt_rootless_gate_fail_count(int gate_id)
{
    if (gate_id < 0 || gate_id >= DT_GATE_COUNT)
        return 0;
    return g_fail[gate_id];
}

int dt_rootless_gate_last_result(int gate_id)
{
    if (gate_id < 0 || gate_id >= DT_GATE_COUNT)
        return -1;
    return g_last[gate_id];
}

static void record_gate(int gate, int result)
{
    if (gate < 0 || gate >= DT_GATE_COUNT)
        return;
    g_visit[gate]++;
    g_last[gate] = result;
    if (result == 0)
        g_fail[gate]++;
}

static void slog(dt_rootless_plat_t *plat, const char *line)
{
    if (plat && plat->log)
        plat->log(plat->ctx, line);
}

static int forced(dt_rootless_plat_t *plat, int gate)
{
    if (plat && plat->gate_forced)
        return plat->gate_forced(plat->ctx, gate);
    return -1;
}

/* 1 = treat as pass, 0 = treat as fail. Physical-only never auto-pass. */
static int eval_bool_gate(dt_rootless_plat_t *plat, int gate, int observed_pass)
{
    int f = forced(plat, gate);
    int result;
    if (f == 0)
        result = 0;
    else if (f == 1)
        result = 1;
    else if (kGates[gate].kind == DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY)
        result = -1; /* unknown / not claimed */
    else
        result = observed_pass ? 1 : 0;
    record_gate(gate, result);
    return result;
}

static void fail_out(dt_rootless_orch_result_t *out, int gate, const char *result)
{
    out->status = -1;
    out->failed_gate = gate;
    out->product_gate_fails = 1;
    snprintf(out->result, sizeof(out->result), "%s", result);
}

int dt_rootless_orch_bringup(dt_rootless_plat_t *plat, dt_rootless_orch_result_t *out)
{
    dt_rootless_gate_stats_reset();
    memset(out, 0, sizeof(*out));
    out->failed_gate = -1;
    snprintf(out->result, sizeof(out->result), "INCOMPLETE");

    if (!plat) {
        fail_out(out, DT_GATE_R6_IDENTITY, "PLAT_NULL");
        return -1;
    }

    slog(plat, "ROOTLESS_R6_ENTRY=YES");
    slog(plat, "HOST_SIM_ORCH_BEGIN");

    int identity_ok = plat->get_int(plat->ctx, "IDENTITY_OK", 1);
    if (eval_bool_gate(plat, DT_GATE_R6_IDENTITY, identity_ok) != 1) {
        slog(plat, "ROOTLESS_R6_PATH=BLOCK");
        fail_out(out, DT_GATE_R6_IDENTITY, "ROOTLESS_R6_IDENTITY_FILE_MISMATCH");
        return -1;
    }
    slog(plat, "ROOTLESS_R6_IDENTITY_FILE_OK=YES");

    int payload = plat->get_int(plat->ctx, "PAYLOAD_COUNT", 4053);
    int trust = plat->get_int(plat->ctx, "TRUST_COUNT", 397);
    int payload_ok = eval_bool_gate(plat, DT_GATE_R6_PAYLOAD_COUNT, payload == 4053);
    int trust_ok = eval_bool_gate(plat, DT_GATE_R6_TRUST_COUNT, trust == 397);
    if (payload_ok != 1) {
        slog(plat, "ROOTLESS_R6_PATH=BLOCK");
        fail_out(out, DT_GATE_R6_PAYLOAD_COUNT, "ROOTLESS_R6_VARIANT_SELF_CHECK_FAIL");
        return -1;
    }
    if (trust_ok != 1) {
        slog(plat, "ROOTLESS_R6_PATH=BLOCK");
        fail_out(out, DT_GATE_R6_TRUST_COUNT, "ROOTLESS_R6_VARIANT_SELF_CHECK_FAIL");
        return -1;
    }

    int varjb = plat->get_int(plat->ctx, "VARJB", DT_VARJB_ABSENT);
    bool n_owned = plat->get_int(plat->ctx, "N_PROJECT_OWNED_LEGACY", 0) != 0;
    bool n_stopped = plat->get_int(plat->ctx, "N_STOPPED", 0) != 0;
    dt_rootless_r6_decision_c_t dec = dt_rootless_r6_decide_c(varjb, n_owned, n_stopped);
    out->r6_state = dec.state;
    out->r6_path = dec.path;
    {
        char buf[96];
        snprintf(buf, sizeof(buf), "ROOTLESS_R6_PATH=%d state=%d kfd=%d",
                 dec.path, dec.state, dec.kfd_would_open ? 1 : 0);
        slog(plat, buf);
    }

    int classify_ok = (dec.path != DT_R6_PATH_BLOCK && dec.kfd_would_open);
    if (eval_bool_gate(plat, DT_GATE_R6_CLASSIFY_BLOCK, classify_ok) != 1) {
        slog(plat, "ROOTLESS_R6_KFD_WOULD_OPEN=NO");
        fail_out(out, DT_GATE_R6_CLASSIFY_BLOCK, "ROOTLESS_R6_BLOCK");
        return -1;
    }

    slog(plat, "ROOTLESS_R6_KFD_BEGIN");
    if (plat->kfd_state(plat->ctx) == DT_KFD_CONSUMED) {
        slog(plat, "SIM_KFD_REENTRY_ATTEMPT");
        (void)plat->kfd_open(plat->ctx); /* counts reentry */
        out->kfd_reentry_count = plat->kfd_reentry_count(plat->ctx);
        out->kfd_open_count = plat->kfd_open_count(plat->ctx);
        out->kfd_state = plat->kfd_state(plat->ctx);
        /* Product: CONSUMED is always a hard fail. Force-PASS cannot reopen KFD. */
        record_gate(DT_GATE_KFD_REENTRY, 0);
        fail_out(out, DT_GATE_KFD_REENTRY, "KFD_REENTRY_HARD_FAIL");
        return -1;
    }
    /* First open this boot: evaluate reentry as PASS (not consumed). Force-FAIL still applies. */
    if (eval_bool_gate(plat, DT_GATE_KFD_REENTRY, 1) != 1) {
        fail_out(out, DT_GATE_KFD_REENTRY, "KFD_REENTRY_HARD_FAIL");
        return -1;
    }

    int already = plat->kfd_state(plat->ctx) == DT_KFD_OPEN;
    int kfd_rc = already ? 0 : plat->kfd_open(plat->ctx);
    if (already)
        slog(plat, "ROOTLESS_R6_KFD_ALREADY_ACTIVE=YES");
    out->kfd_open_count = plat->kfd_open_count(plat->ctx);
    out->kfd_reentry_count = plat->kfd_reentry_count(plat->ctx);
    out->kfd_state = plat->kfd_state(plat->ctx);
    if (eval_bool_gate(plat, DT_GATE_KFD_OPEN, kfd_rc == 0 && out->kfd_state == DT_KFD_OPEN) != 1) {
        fail_out(out, DT_GATE_KFD_OPEN, "ROOTLESS_R6_KFD_OPEN_FAIL");
        return -1;
    }
    slog(plat, "ROOTLESS_R6_KFD_OPEN_OK");
    slog(plat, "ROOTLESS_R6_WALL2_BEGIN");

    int product_seq[] = {
        DT_GATE_DEP, DT_GATE_TRUST_TRIO, DT_GATE_BOOMERANG, DT_GATE_STASH_PORT,
        DT_GATE_WALL2_APPLY, DT_GATE_OPAINJECT1, DT_GATE_WALL2_RESTORE,
        DT_GATE_REMOTE_DLOPEN, DT_GATE_CTOR_RETURN, DT_GATE_CTOR_EXIT,
        DT_GATE_PRIMITIVES, DT_GATE_BOOMERANG_DONE, DT_GATE_BOOMERANG_WAIT,
        DT_GATE_GOT_PROBE, DT_GATE_GOT_RESTORE, DT_GATE_GOT_RESTORE_FATAL,
    };
    const char *obs_keys[] = {
        "DEP_PASS", "TRUST_TRIO_PASS", "BOOMERANG_PASS", "STASH_PORT_PASS",
        "WALL2_APPLY_PASS", "OPAINJECT1_PASS", "WALL2_RESTORE_PASS",
        "REMOTE_DLOPEN_PASS", "HOOK_CTOR_RETURN_PASS", "CTOR_EXIT_REACHED",
        "PRIMITIVES_INIT_PASS", "BOOMERANG_DONE_SEND_PASS", "BOOMERANG_WAIT_PASS",
        "PROBE_TERMINAL_PASS", "PROTECTION_RESTORE_PASS", "PROTECTION_RESTORE_FATAL_INVERT",
    };
    for (unsigned i = 0; i < sizeof(product_seq) / sizeof(product_seq[0]); i++) {
        int gate = product_seq[i];
        int observed;
        if (gate == DT_GATE_GOT_RESTORE_FATAL) {
            /* Fail-closed if fatal==YES. Default not fatal. */
            int fatal = plat->obs_bool(plat->ctx, "PROTECTION_RESTORE_FATAL", 0);
            observed = (fatal != 1);
        } else {
            observed = plat->obs_bool(plat->ctx, obs_keys[i], 1) == 1;
        }
        if (eval_bool_gate(plat, gate, observed) != 1) {
            if (plat->write_incomplete)
                plat->write_incomplete(plat->ctx);
            out->incomplete = plat->has_incomplete ? plat->has_incomplete(plat->ctx) : 1;
            out->kfd_state = plat->kfd_state(plat->ctx);
            {
                char buf[96];
                snprintf(buf, sizeof(buf), "GATE_FAIL=%s", dt_rootless_gate_name(gate));
                slog(plat, buf);
            }
            fail_out(out, gate, dt_rootless_gate_name(gate));
            slog(plat, "FAILURE_AFTER_KFD_REENTRY_ALLOWED=NO");
            return -1;
        }
        {
            char buf[96];
            snprintf(buf, sizeof(buf), "GATE_PASS=%s", dt_rootless_gate_name(gate));
            slog(plat, buf);
        }
        if (gate == DT_GATE_DEP)
            slog(plat, "ROOTLESS_R7_HOOK_DEP_GATE_PASS");
        if (gate == DT_GATE_WALL2_RESTORE)
            slog(plat, "WALL2_RESTORE_RESULT=PASS");
        if (gate == DT_GATE_CTOR_RETURN)
            slog(plat, "HOOK_CTOR_RETURN_PASS=YES");
    }

    dt_rootless_r9_ctor_inputs_t cin;
    memset(&cin, 0, sizeof(cin));
    cin.restore_r = plat->obs_bool(plat->ctx, "WALL2_RESTORE_PASS", 1) == 1 ? 0 : -1;
    cin.inject_r = plat->obs_bool(plat->ctx, "OPAINJECT1_PASS", 1) == 1 ? 0 : -1;
    cin.remote_dlopen_rc = plat->obs_bool(plat->ctx, "REMOTE_DLOPEN_PASS", 1) == 1 ? 0 : -1;
    cin.boomerang_wait_rc = plat->obs_bool(plat->ctx, "BOOMERANG_WAIT_PASS", 1) == 1 ? 0 : -1;
    cin.ctor_return_pass = plat->obs_bool(plat->ctx, "HOOK_CTOR_RETURN_PASS", 1) == 1;
    cin.ctor_exit_reached = plat->obs_bool(plat->ctx, "CTOR_EXIT_REACHED", 1) == 1;
    cin.primitives_init_pass = plat->obs_bool(plat->ctx, "PRIMITIVES_INIT_PASS", 1) == 1;
    cin.boomerang_done_send_pass = plat->obs_bool(plat->ctx, "BOOMERANG_DONE_SEND_PASS", 1) == 1;
    cin.got_probe_terminal_pass = plat->obs_bool(plat->ctx, "PROBE_TERMINAL_PASS", 1) == 1;
    cin.got_restore_pass = plat->obs_bool(plat->ctx, "PROTECTION_RESTORE_PASS", 1) == 1;
    cin.got_restore_fatal = plat->obs_bool(plat->ctx, "PROTECTION_RESTORE_FATAL", 0) == 1;

    /* If individual ctor leaves were force-failed, reflect that in inputs. */
    if (forced(plat, DT_GATE_WALL2_RESTORE) == 0)
        cin.restore_r = -1;
    if (forced(plat, DT_GATE_CTOR_RETURN) == 0)
        cin.ctor_return_pass = false;

    bool ctor_ok = dt_rootless_r9_ctor_product_ok(&cin);
    slog(plat, ctor_ok ? "ROOTLESS_R9_CTOR_WALL2_PRODUCT=PASS"
                       : "ROOTLESS_R9_CTOR_WALL2_PRODUCT=FAIL");
    slog(plat, "ROOTLESS_PRODUCT_EXECUTES_J_CONTROLLED_REPLY_TEST=NO");
    slog(plat, "ROOTLESS_PRODUCT_REQUIRES_ROOTFUL_WRAPPER_STORE=NO");
    slog(plat, "ROOTLESS_PRODUCT_REQUIRES_ROOTFUL_PERSISTENT_INSTALL=NO");

    int j_legacy = plat->obs_bool(plat->ctx, "J_CONTROLLED_REPLY_ROUNDTRIP", 0) == 1;
    slog(plat, j_legacy ? "J_CONTROLLED_REPLY_ROUNDTRIP=PASS"
                        : "J_CONTROLLED_REPLY_ROUNDTRIP=FAIL");
    if (!dt_rootless_product_j_failure_is_terminal(ctor_ok, j_legacy)) {
        slog(plat, "ROOTLESS_R9_FRESH_FS_UNGATED_FROM_J=YES");
        slog(plat, "BUILD102739J_RESULT=SKIPPED_PRODUCT_NOT_TERMINAL");
    }

    if (eval_bool_gate(plat, DT_GATE_R9_CTOR_PRODUCT, ctor_ok) != 1
        || dt_rootless_product_j_failure_is_terminal(ctor_ok, j_legacy)) {
        if (plat->write_incomplete)
            plat->write_incomplete(plat->ctx);
        out->incomplete = 1;
        fail_out(out, DT_GATE_R9_CTOR_PRODUCT, "ROOTLESS_CTOR_OR_WALL2_PRODUCT_FAIL");
        slog(plat, "FAILURE_AFTER_KFD_REENTRY_ALLOWED=NO");
        return -1;
    }

    /* Legacy diagnostics: may FAIL; must not terminate product. */
    static const int kDiag[] = {
        DT_GATE_J_CONTROLLED_REPLY, DT_GATE_K_ROOTFUL_PREFLIGHT, DT_GATE_L_POLICY,
        DT_GATE_M_FIXTURE, DT_GATE_N_RUNA, DT_GATE_C_OBSERVER, DT_GATE_D_TRIGGER,
        DT_GATE_WRAPPER_STORE, DT_GATE_PERSISTENT_INSTALL,
    };
    static const char *kDiagKeys[] = {
        "J_CONTROLLED_REPLY_ROUNDTRIP", "K_ROOTFUL_PREFLIGHT_PASS", "L_POLICY_PASS",
        "M_FIXTURE_PASS", "N_RUNA_PASS", "C_OBSERVER_PASS", "D_TRIGGER_PASS",
        "WRAPPER_STORE_PASS", "PERSISTENT_INSTALL_PASS",
    };
    for (unsigned i = 0; i < sizeof(kDiag) / sizeof(kDiag[0]); i++) {
        int observed = plat->obs_bool(plat->ctx, kDiagKeys[i], 0) == 1;
        int pass = eval_bool_gate(plat, kDiag[i], observed);
        if (pass != 1) {
            out->diagnostic_fails_continued++;
            char buf[160];
            snprintf(buf, sizeof(buf), "LEGACY_DIAGNOSTIC_FAIL_CONTINUED=%s",
                     dt_rootless_gate_name(kDiag[i]));
            slog(plat, buf);
            if (dt_rootless_product_executes_j_controlled_reply()
                && kDiag[i] == DT_GATE_J_CONTROLLED_REPLY) {
                fail_out(out, kDiag[i], "ROOTFUL_BOOTSTRAP_PREFLIGHT_J_BASELINE_FAIL");
                return -1;
            }
            if (dt_rootless_product_executes_n_runa_mutation()
                && kDiag[i] == DT_GATE_N_RUNA) {
                fail_out(out, kDiag[i], "PERSISTENT_CONTROL_FIXTURE_PROOF_FAIL");
                return -1;
            }
        }
    }

    /* Production: REUSE validates committed identity (dt_rootless_run_reuse_fs_stage).
     * FRESH/RECOVERY may write incomplete then restage. Never poison REUSE with incomplete. */
    if (dec.path == DT_R6_PATH_REUSE)
        slog(plat, "ROOTLESS_REUSE_FS_BEGIN");
    else if (dec.path == DT_R6_PATH_RECOVERY)
        slog(plat, "ROOTLESS_RECOVERY_FS_BEGIN");
    else
        slog(plat, "ROOTLESS_R7_FRESH_FS_BEGIN");

    if (dec.path != DT_R6_PATH_REUSE && plat->write_incomplete)
        plat->write_incomplete(plat->ctx);
    int fs_rc = plat->fs_stage(plat->ctx, dec.path);
    if (eval_bool_gate(plat, DT_GATE_FRESH_FS, fs_rc == 0) != 1) {
        out->incomplete = 1;
        fail_out(out, DT_GATE_FRESH_FS,
                 dec.path == DT_R6_PATH_REUSE ? "ROOTLESS_REUSE_IDENTITY_FAIL" : "ROOTLESS_FS_FAIL");
        slog(plat, "FAILURE_AFTER_KFD_REENTRY_ALLOWED=NO");
        return -1;
    }

    int post_seq[] = {
        DT_GATE_POSTVERIFY, DT_GATE_TRUST_PAYLOAD, DT_GATE_OPAINJECT2,
        DT_GATE_CTOR2, DT_GATE_DYLD_DELIVERY, DT_GATE_PASSWORD, DT_GATE_SSH,
        DT_GATE_CURRENT_BOOT_RUNTIME,
    };
    const char *post_keys[] = {
        "POSTVERIFY_PASS", "TRUST_PAYLOAD_PASS", "OPAINJECT2_PASS",
        "CTOR2_PASS", "DYLD_DELIVERY_PASS", "PASSWORD_PASS", "SSH_PASS",
        "CURRENT_BOOT_RUNTIME_PASS",
    };
    for (unsigned i = 0; i < sizeof(post_seq) / sizeof(post_seq[0]); i++) {
        int observed = plat->obs_bool(plat->ctx, post_keys[i], 1) == 1;
        if (eval_bool_gate(plat, post_seq[i], observed) != 1) {
            out->incomplete = plat->has_incomplete ? plat->has_incomplete(plat->ctx) : 1;
            fail_out(out, post_seq[i], dt_rootless_gate_name(post_seq[i]));
            slog(plat, "FAILURE_AFTER_KFD_REENTRY_ALLOWED=NO");
            return -1;
        }
    }

    slog(plat, "ROOTLESS_PRODUCT_EXECUTES_N_RUNA_MUTATION=NO");

    /* Physical-runtime-only: record, never claim PASS. */
    slog(plat, "PHYSICAL_RUNTIME_ONLY=KFD_EXPLOIT,KERNEL_ADDRS,AMFI,PID1_DLOPEN,SANDBOX_EXT,LIVE_SSH");
    for (int gi = 0; gi < DT_GATE_COUNT; gi++) {
        if (kGates[gi].kind == DT_GATE_KIND_PHYSICAL_RUNTIME_ONLY)
            (void)eval_bool_gate(plat, gi, 0);
    }

    int commit_ok = 1;
    if (eval_bool_gate(plat, DT_GATE_COMMIT, commit_ok) != 1) {
        fail_out(out, DT_GATE_COMMIT, "ROOTLESS_COMMIT_FAIL");
        out->incomplete = 1;
        return -1;
    }
    if (plat->commit(plat->ctx) != 0) {
        record_gate(DT_GATE_COMMIT, 0);
        fail_out(out, DT_GATE_COMMIT, "ROOTLESS_COMMIT_FAIL");
        out->incomplete = 1;
        return -1;
    }

    plat->kfd_close(plat->ctx);
    out->committed = plat->is_committed(plat->ctx);
    out->incomplete = plat->has_incomplete(plat->ctx);
    out->kfd_state = plat->kfd_state(plat->ctx);
    out->kfd_open_count = plat->kfd_open_count(plat->ctx);
    out->kfd_reentry_count = plat->kfd_reentry_count(plat->ctx);
    out->status = 0;
    snprintf(out->result, sizeof(out->result),
             dec.path == DT_R6_PATH_REUSE ? "ROOTLESS_REUSE_COMMITTED_PASS"
             : dec.path == DT_R6_PATH_RECOVERY ? "ROOTLESS_RECOVERY_COMMITTED_PASS"
                                               : "ROOTLESS_FRESH_COMMITTED_PASS");
    slog(plat, out->result);
    slog(plat, "HOST_SIM_ORCH_COMMITTED");
    return 0;
}
