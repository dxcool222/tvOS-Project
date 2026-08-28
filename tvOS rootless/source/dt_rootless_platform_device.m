#import "dt_rootless_platform_device.h"
#import "dt_rootless_phys_leaves.h"
#import "dt_rootless_r6_decide.h"
#import "dt_rootless_state.h"
#import "dt_rootless_bringup.h"
#import "dt_rootless_install.h"
#import "dt_rootless_dyld_delivery.h"
#import "dt_build102739n.h"
#import "dt_build681_client.h"
#import "dt_build710_preboot.h"
#import "DTRunLogger.h"
#import "DTKFDConfig.h"
#import "DTBootstrap.h"
#import "dt_do_fun.h"
#import "dt_baked_offsets.h"
#import "dt_kfund_import.h"
#import "dt_exploit_lifecycle.h"
#import "dt_kernel_exploit.h"
#import "kfd_tvos.h"
#import "info.h"

#import <Foundation/Foundation.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>

#define DT_R10_OBS_MAX 64

typedef struct {
    char key[64];
    int value;
} dt_r10_kv_t;

typedef struct {
    int kfd_state;
    int kfd_open_count;
    int kfd_reentry_count;
    int classified;
    int identity_ok;
    int payload_count;
    int trust_count;
    int varjb;
    int n_owned;
    int n_stopped;
    int prepared;
    int observed_ctor;
    dt_rootless_r9_ctor_inputs_t ctor;
    dt_r10_kv_t obs[DT_R10_OBS_MAX];
    int nobs;
    int fs_done;
    int postverify_ok;
    int trust_ok;
    int dry_run; /* never physical KFD */
} dt_r10_dev_ctx_t;

static dt_r10_dev_ctx_t g_dev;

static void plat_log(void *p, const char *line)
{
    (void)p;
    NSString *s = [NSString stringWithUTF8String:line ? line : ""];
    [[DTRunLogger shared] log:s];
    [[DTRunLogger shared] logStage:s];
}

static int kv_get(dt_r10_dev_ctx_t *s, const char *key, int def)
{
    for (int i = 0; i < s->nobs; i++)
        if (strcmp(s->obs[i].key, key) == 0)
            return s->obs[i].value;
    return def;
}

static void kv_set(dt_r10_dev_ctx_t *s, const char *key, int value)
{
    for (int i = 0; i < s->nobs; i++) {
        if (strcmp(s->obs[i].key, key) == 0) {
            s->obs[i].value = value;
            return;
        }
    }
    if (s->nobs < DT_R10_OBS_MAX) {
        snprintf(s->obs[s->nobs].key, sizeof(s->obs[s->nobs].key), "%s", key);
        s->obs[s->nobs].value = value;
        s->nobs++;
    }
}

static NSInteger dt_r10_count_manifest_rows(NSString *name)
{
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:nil];
    if (!path.length)
        path = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:name];
    NSString *text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!text.length)
        return -1;
    NSInteger rows = 0;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if (!line.length)
            continue;
        if ([line hasPrefix:@"PATH\t"] || [line hasPrefix:@"RELATIVE_PATH\t"])
            continue;
        rows++;
    }
    return rows;
}

static void dt_r10_classify(dt_r10_dev_ctx_t *s)
{
    if (s->classified)
        return;
    NSString *idPath = [[NSBundle mainBundle] pathForResource:@"ROOTLESS_VARIANT_IDENTITY" ofType:@"txt"];
    if (!idPath.length)
        idPath = [[[NSBundle mainBundle] bundlePath]
                  stringByAppendingPathComponent:@"ROOTLESS_VARIANT_IDENTITY.txt"];
    NSString *idText = [NSString stringWithContentsOfFile:idPath encoding:NSUTF8StringEncoding error:nil];
    s->identity_ok = ([idText containsString:@"ROOTLESS_VARIANT=R6"]
                      && [idText containsString:@"COMPILED_ROOTLESS_MARKER=ROOTLESS_R6_BEGIN"]) ? 1 : 0;
    s->payload_count = (int)dt_r10_count_manifest_rows(@"ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv");
    s->trust_count = (int)dt_r10_count_manifest_rows(@"ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv");

    NSString *varDetail = nil;
    s->varjb = (int)dt_rootless_classify_var_jb(&varDetail);
    NSString *nVerdict = nil;
    DTBuild102739NDispatch nDisp = dt_build102739n_classify_before_chain(nil, &nVerdict);
    s->n_stopped = (nDisp == DTBuild102739NDispatchStop) ? 1 : 0;
    s->n_owned = dt_build102739n_probe_project_owned_legacy(nil, nil) ? 1 : 0;
#if defined(DT_ROOTLESS_R24)
    /* F3: helper content identity change under REUSE is unsafe across R23→R24 basebin. */
    NSString *persisted = dt_build102739n_last_persisted_diagnostic_result();
    BOOL helperIdChanged =
        [persisted isEqualToString:@"PERSISTED_HELPER_CONTENT_IDENTITY_CHANGED"]
        || [persisted isEqualToString:@"PERSISTED_HELPER_PROVENANCE_CHANGED"]
        || [persisted isEqualToString:@"PERSISTED_HELPER_BASIC_METADATA_CHANGED"]
        || [nVerdict containsString:@"PERSISTED_MANIFEST_OR_HELPER"];
    if (s->varjb == DT_VARJB_COMMITTED_VALID && helperIdChanged) {
        s->varjb = DT_VARJB_ROOTLESS_INCOMPLETE;
        plat_log(s, "ROOTLESS_R24_FORCE_RECOVERY_HELPER_IDENTITY=YES");
    }
#endif
    s->classified = 1;
    plat_log(s, [[NSString stringWithFormat:@"REAL_DEVICE_CLASSIFY varjb=%d n_owned=%d n_stopped=%d",
                  s->varjb, s->n_owned, s->n_stopped] UTF8String]);
}

static int plat_get_int(void *p, const char *key, int def)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    dt_r10_classify(s);
    if (strcmp(key, "IDENTITY_OK") == 0)
        return s->identity_ok;
    if (strcmp(key, "PAYLOAD_COUNT") == 0)
        return s->payload_count;
    if (strcmp(key, "TRUST_COUNT") == 0)
        return s->trust_count;
    if (strcmp(key, "VARJB") == 0)
        return s->varjb;
    if (strcmp(key, "N_PROJECT_OWNED_LEGACY") == 0)
        return s->n_owned;
    if (strcmp(key, "N_STOPPED") == 0)
        return s->n_stopped;
    return kv_get(s, key, def);
}

static void (^dev_log_block(void))(NSString *)
{
    return ^(NSString *line) {
        plat_log(&g_dev, line.UTF8String);
    };
}

static int run_leaf_bool(dt_r10_dev_ctx_t *s, const char *key)
{
    int cached = kv_get(s, key, -99);
    if (cached != -99)
        return cached;

    if (s->dry_run) {
        /* Dry-run: product keys default PASS; diagnostics default FAIL. Never KFD. */
        int v = 1;
        if (strstr(key, "J_CONTROLLED") || strstr(key, "K_ROOTFUL") || strstr(key, "L_POLICY")
            || strstr(key, "M_FIXTURE") || strstr(key, "N_RUNA") || strstr(key, "C_OBSERVER")
            || strstr(key, "D_TRIGGER") || strstr(key, "WRAPPER") || strstr(key, "PERSISTENT")
            || strstr(key, "FATAL"))
            v = 0;
        kv_set(s, key, v);
        return v;
    }

    void (^log)(NSString *) = dev_log_block();
    int ok = 0;
    if (strcmp(key, "DEP_PASS") == 0) {
        ok = dt_rootless_leaf_dep_gate(log) == 0;
        s->prepared = 1;
    } else if (strcmp(key, "TRUST_TRIO_PASS") == 0) {
        ok = dt_rootless_leaf_trust_trio(log) == 0;
    } else if (strcmp(key, "BOOMERANG_PASS") == 0) {
        ok = dt_rootless_leaf_boomerang(log) == 0;
    } else if (strcmp(key, "STASH_PORT_PASS") == 0) {
        ok = dt_rootless_leaf_stash_port(log) == 0;
    } else if (strcmp(key, "WALL2_APPLY_PASS") == 0) {
        ok = dt_rootless_leaf_wall2_apply(log) == 0;
    } else if (strcmp(key, "OPAINJECT1_PASS") == 0) {
        ok = dt_rootless_leaf_opainject1(log) == 0;
    } else if (strcmp(key, "WALL2_RESTORE_PASS") == 0) {
        ok = dt_rootless_leaf_wall2_restore(log) == 0;
    } else if (strcmp(key, "REMOTE_DLOPEN_PASS") == 0
               || strcmp(key, "HOOK_CTOR_RETURN_PASS") == 0
               || strcmp(key, "CTOR_EXIT_REACHED") == 0
               || strcmp(key, "PRIMITIVES_INIT_PASS") == 0
               || strcmp(key, "BOOMERANG_DONE_SEND_PASS") == 0
               || strcmp(key, "BOOMERANG_WAIT_PASS") == 0
               || strcmp(key, "PROBE_TERMINAL_PASS") == 0
               || strcmp(key, "PROTECTION_RESTORE_PASS") == 0
               || strcmp(key, "PROTECTION_RESTORE_FATAL") == 0) {
        if (!s->observed_ctor) {
            dt_rootless_r9_ctor_inputs_t cin = {0};
            (void)dt_rootless_leaf_observe_ctor(log, &cin);
            s->ctor = cin;
            s->observed_ctor = 1;
            kv_set(s, "REMOTE_DLOPEN_PASS", cin.remote_dlopen_rc == 0);
            kv_set(s, "HOOK_CTOR_RETURN_PASS", cin.ctor_return_pass ? 1 : 0);
            kv_set(s, "CTOR_EXIT_REACHED", cin.ctor_exit_reached ? 1 : 0);
            kv_set(s, "PRIMITIVES_INIT_PASS", cin.primitives_init_pass ? 1 : 0);
            kv_set(s, "BOOMERANG_DONE_SEND_PASS", cin.boomerang_done_send_pass ? 1 : 0);
            kv_set(s, "BOOMERANG_WAIT_PASS", cin.boomerang_wait_rc == 0);
            kv_set(s, "PROBE_TERMINAL_PASS", cin.got_probe_terminal_pass ? 1 : 0);
            kv_set(s, "PROTECTION_RESTORE_PASS", cin.got_restore_pass ? 1 : 0);
            kv_set(s, "PROTECTION_RESTORE_FATAL", cin.got_restore_fatal ? 1 : 0);
            kv_set(s, "WALL2_RESTORE_PASS", cin.restore_r == 0);
            kv_set(s, "OPAINJECT1_PASS", cin.inject_r == 0);
        }
        return kv_get(s, key, 0);
    } else if (strcmp(key, "POSTVERIFY_PASS") == 0) {
        ok = s->postverify_ok;
    } else if (strcmp(key, "TRUST_PAYLOAD_PASS") == 0) {
        ok = s->trust_ok;
    } else if (strcmp(key, "OPAINJECT2_PASS") == 0) {
        NSString *cap = nil;
        NSString *hp = dt710_resolve_hook_path();
        int rc = dt681_spawn_opainject_launchd(hp.fileSystemRepresentation, log, &cap);
        ok = (rc == 0);
    } else if (strcmp(key, "CTOR2_PASS") == 0) {
        /* R16 POSTFRESH_HOOK_CONTINUITY. Gate name stays CTOR2.
         * Packaged launchdhook writes Wall1 sibling
         * basebin/.dt102737_constructor_trace (IDA), not dest-root
         * .dt518_launchdhook_ctor_entered / .dt516_launchdhook_loaded.
         * 23:00: this-run Wall1 HOOK_CTOR_RETURN_PASS / CTOR_EXIT_REACHED
         * then OPAINJECT2 KCALL681_REMOTE_DLOPEN_WORKING then dest-file
         * CTOR2 failed. Do not claim a second constructor after FRESH.
         * Fail closed if Wall1 observe never ran this bringup. */
        ok = s->observed_ctor
            && kv_get(s, "HOOK_CTOR_RETURN_PASS", 0) == 1
            && kv_get(s, "CTOR_EXIT_REACHED", 0) == 1
            && kv_get(s, "OPAINJECT2_PASS", 0) == 1;
    } else if (strcmp(key, "DYLD_DELIVERY_PASS") == 0) {
        NSString *err = nil;
        ok = dt_rootless_prepare_dyld_delivery(log, &err) == 0;
        if (!ok && err.length)
            plat_log(s, [[NSString stringWithFormat:@"R24_DYLD_DELIVERY_ERROR=%@", err] UTF8String]);
    } else if (strcmp(key, "PASSWORD_PASS") == 0) {
        NSString *err = nil;
        ok = dt_rootless_run_prep_bootstrap(log, &err) == 0;
    } else if (strcmp(key, "SSH_PASS") == 0) {
        ok = (access("/private/var/jb/usr/bin/ssh", X_OK) == 0)
            && (access("/private/var/jb/usr/sbin/sshd", X_OK) == 0)
            && (access("/private/var/jb/Library/LaunchDaemons/com.openssh.sshd.plist", F_OK) == 0)
            && (access("/private/var/jb/etc/ssh/sshd_config", F_OK) == 0);
    } else if (strcmp(key, "CURRENT_BOOT_RUNTIME_PASS") == 0) {
        NSString *err = nil;
        ok = dt_rootless_run_current_boot_runtime_probe(log, &err) == 0;
        if (!ok && err.length)
            plat_log(s, [[NSString stringWithFormat:@"R24_CURRENT_BOOT_RUNTIME_ERROR=%@", err] UTF8String]);
    } else if (strcmp(key, "J_CONTROLLED_REPLY_ROUNDTRIP") == 0
               || strcmp(key, "K_ROOTFUL_PREFLIGHT_PASS") == 0
               || strcmp(key, "L_POLICY_PASS") == 0
               || strcmp(key, "M_FIXTURE_PASS") == 0
               || strcmp(key, "N_RUNA_PASS") == 0
               || strcmp(key, "C_OBSERVER_PASS") == 0
               || strcmp(key, "D_TRIGGER_PASS") == 0
               || strcmp(key, "WRAPPER_STORE_PASS") == 0
               || strcmp(key, "PERSISTENT_INSTALL_PASS") == 0) {
        /* Product path must not execute restored rootful diagnostics. */
        ok = 0;
    } else {
        ok = 1;
    }
    kv_set(s, key, ok ? 1 : 0);
    return ok ? 1 : 0;
}

static int plat_obs_bool(void *p, const char *key, int def)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    int cached = kv_get(s, key, -99);
    if (cached != -99)
        return cached;
    if (!key)
        return def;
    return run_leaf_bool(s, key);
}

static int plat_gate_forced(void *p, int gate)
{
    (void)p;
    (void)gate;
    return -1;
}

static uint64_t map_kread(DTKFDKreadMethod m)
{
    return m == DTKFDKreadSemOpen ? DT_KREAD_SEM_OPEN : DT_KREAD_KQUEUE_WORKLOOP_CTL;
}

static uint64_t map_kwrite(DTKFDKwriteMethod m)
{
    return m == DTKFDKwriteDup ? DT_KWRITE_DUP : DT_KWRITE_SEM_OPEN;
}

static int plat_kfd_open(void *p)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    if (s->kfd_state == DT_KFD_CONSUMED) {
        s->kfd_reentry_count++;
        plat_log(s, "SIM_KFD_REENTRY_ATTEMPT");
        return -1;
    }
    if (s->dry_run) {
        s->kfd_state = DT_KFD_OPEN;
        s->kfd_open_count++;
        plat_log(s, "REAL_DEVICE_DRY_KFD_OPEN=YES");
        return 0;
    }
    if (dt_kernel_exploit_is_active()) {
        if (s->kfd_open_count == 0)
            s->kfd_open_count = 1;
        s->kfd_state = DT_KFD_OPEN;
        plat_log(s, "ROOTLESS_R6_KERNEL_EXPLOIT_ALREADY_ACTIVE=YES");
        return 0;
    }
    if (s->kfd_state == DT_KFD_OPEN)
        return 0;

    void (^log)(NSString *) = dev_log_block();
    DTKFDConfig *cfg = [DTKFDConfig misakaDefaults];
    [DTBootstrap setRemountWritable:NO];
    char machine[64] = {0};
    char osversion[64] = {0};
    size_t len = sizeof(machine);
    sysctlbyname("hw.machine", machine, &len, NULL, 0);
    len = sizeof(osversion);
    sysctlbyname("kern.osversion", osversion, &len, NULL, 0);
    plat_log(s, [[NSString stringWithFormat:@"device: %s build: %s", machine, osversion] UTF8String]);

    if (DTApplyBakedOffsetsForCurrentDevice()) {
        log(@"offsets: wh1te4ever baked table (AppleTV6,2 / 20L563)");
    } else if (dt_import_kfd_offsets() == 0) {
        log(@"offsets: will use kfund_offsets.plist");
    } else {
        log(@"offsets: patchfind + auto-save (J fallback)");
    }

    if (dt_exploit_lifecycle_run(cfg, log) != 0) {
        plat_log(s, "ERROR: kernel exploit init failed");
        if (dt_kernel_exploit_requires_restart_for_fallback())
            plat_log(s, "ERROR: kernel state poisoned — restart before KFD fallback");
        return -1;
    }
    dt_apply_post_exploit_system_info();
    if (!dt_do_fun(log)) {
        plat_log(s, "do_fun failed");
        dt_kernel_exploit_deinit();
        return -1;
    }
    s->kfd_state = DT_KFD_OPEN;
    s->kfd_open_count++;
    return 0;
}

static int plat_kfd_close(void *p)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    if (s->kfd_state == DT_KFD_OPEN) {
        if (!s->dry_run && dt_kernel_exploit_is_active())
            dt_kernel_exploit_deinit();
        s->kfd_state = DT_KFD_CONSUMED;
        dt_rootless_leaf_cleanup();
    }
    return 0;
}

static int plat_kfd_state(void *p)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    if (!s->dry_run && dt_kernel_exploit_is_active() && s->kfd_state != DT_KFD_CONSUMED)
        return DT_KFD_OPEN;
    return s->kfd_state;
}

static int plat_kfd_open_count(void *p)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    return s->kfd_open_count;
}

static int plat_kfd_reentry_count(void *p)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    return s->kfd_reentry_count;
}

static int plat_fs_stage(void *p, int r6_path)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    if (s->dry_run) {
        s->fs_done = 1;
        s->postverify_ok = 1;
        s->trust_ok = 1;
        return 0;
    }
    void (^log)(NSString *) = dev_log_block();
    NSString *verdict = nil;
    int rc;
    if (r6_path == DT_R6_PATH_REUSE)
        rc = dt_rootless_run_reuse_fs_stage(log, &verdict);
    else
        rc = dt_rootless_run_fresh_fs_stage(log, &verdict);
    s->fs_done = (rc == 0);
    /* Fresh/reuse already ran postverify/trust internally when they succeeded. */
    s->postverify_ok = (rc == 0) ? 1 : 0;
    s->trust_ok = (rc == 0) ? 1 : 0;
    kv_set(s, "POSTVERIFY_PASS", s->postverify_ok);
    kv_set(s, "TRUST_PAYLOAD_PASS", s->trust_ok);
    if (verdict.length)
        plat_log(s, verdict.UTF8String);
    return rc;
}

static int plat_write_incomplete(void *p)
{
    (void)p;
    if (g_dev.dry_run)
        return 0;
    return dt_rootless_write_incomplete_marker() ? 0 : -1;
}

static int plat_commit(void *p)
{
    dt_r10_dev_ctx_t *s = p ? (dt_r10_dev_ctx_t *)p : &g_dev;
    if (s->dry_run)
        return 0;
    void (^log)(NSString *) = dev_log_block();
    NSString *verdict = nil;
    int rc = dt_rootless_run_commit_last(log, @{
        @"orchestrator": @"dt_rootless_orch_bringup",
        @"backend": @"REAL_DEVICE",
    }, &verdict);
    if (verdict.length)
        plat_log(s, verdict.UTF8String);
    return rc;
}

static int plat_is_committed(void *p)
{
    (void)p;
    if (g_dev.dry_run)
        return 1;
    NSString *err = nil;
    return dt_rootless_verify_committed(nil, &err) ? 1 : 0;
}

static int plat_has_incomplete(void *p)
{
    (void)p;
    if (g_dev.dry_run)
        return 0;
    NSString *root = dt_rootless_expected_jbroot();
    if (!root.length)
        return 0;
    NSString *path = [root stringByAppendingPathComponent:@".rootless_r4_incomplete"];
    return [[NSFileManager defaultManager] fileExistsAtPath:path] ? 1 : 0;
}

static void dt_r10_bind(dt_rootless_plat_t *plat, dt_r10_dev_ctx_t *ctx)
{
    memset(plat, 0, sizeof(*plat));
    plat->ctx = ctx;
    plat->log = plat_log;
    plat->get_int = plat_get_int;
    plat->obs_bool = plat_obs_bool;
    plat->gate_forced = plat_gate_forced;
    plat->kfd_open = plat_kfd_open;
    plat->kfd_close = plat_kfd_close;
    plat->kfd_state = plat_kfd_state;
    plat->kfd_open_count = plat_kfd_open_count;
    plat->kfd_reentry_count = plat_kfd_reentry_count;
    plat->fs_stage = plat_fs_stage;
    plat->write_incomplete = plat_write_incomplete;
    plat->commit = plat_commit;
    plat->is_committed = plat_is_committed;
    plat->has_incomplete = plat_has_incomplete;
}

void dt_rootless_device_bind_dry(dt_rootless_plat_t *plat, void *ctx)
{
    dt_r10_dev_ctx_t *s = ctx ? (dt_r10_dev_ctx_t *)ctx : &g_dev;
    memset(s, 0, sizeof(*s));
    s->dry_run = 1;
    s->identity_ok = 1;
    s->payload_count = 4053;
    s->trust_count = 397;
    s->classified = 1;
    dt_r10_bind(plat, s);
}

int dt_rootless_device_bringup(dt_rootless_orch_result_t *out)
{
    memset(&g_dev, 0, sizeof(g_dev));
    dt_rootless_plat_t plat;
    dt_r10_bind(&plat, &g_dev);
    plat_log(&g_dev, "ROOTLESS_R14_DEVICE_ENTRY=dt_rootless_device_bringup");
    plat_log(&g_dev, "ROOTLESS_R14_SHARED_ORCH=dt_rootless_orch_bringup");
    plat_log(&g_dev, "ROOTLESS_R14_PRODUCT_NFTW_COPY_REACHABLE=NO");
    int rc = dt_rootless_orch_bringup(&plat, out);
    if (rc != 0)
        dt_rootless_leaf_cleanup();
    return rc;
}
