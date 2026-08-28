#import "dt_rootless_bringup.h"
#import "dt_rootless_state.h"
#import "dt_rootless_install.h"
#import "dt_rootless_trust.h"
#import "dt_build710_preboot.h"
#import "dt_darksword_stages.h"
#import "darksword_tvos.h"
#import "DTRunLogger.h"

NSString *const kDTRootlessPayloadDirName = @"RootlessPayload";
NSString *const kDTRootlessTrustManifestName = @"ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv";

/* Authoritative rootless variant identity (in addition to frozen 102738 baseline IDs). */
__attribute__((used))
static const char kDTRootlessVariantIdentity[] =
    "ROOTLESS_VARIANT=R6\n"
    "ROOTLESS_ARCH=appletvos-arm64-rootless\n"
    "ROOTLESS_PAYLOAD_SCHEMA=R6_PATH_MANIFEST_V1\n"
    "ROOTLESS_SCOPE=FULL_TREE_INSTALL_PLUS_FULLER_HANDOFF516\n"
    "COMPILED_ROOTLESS_MARKER=ROOTLESS_R6_BEGIN\n";

static void dt_rb_log(void (^log)(NSString *), NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log) log(line);
}

static NSString *dt_rb_bundle_path(NSString *name)
{
    return [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:name];
}

int dt_rootless_run_fresh_fs_stage(void (^log)(NSString *), NSString **verdictOut)
{
    (void)kDTRootlessVariantIdentity;
    dt_rb_log(log, @"ROOTLESS_R7_FRESH_FS_BEGIN");
    dt_rb_log(log, @"ROOTLESS_FRESH_FS_BEGIN");
    dt_rb_log(log, @"ROOTLESS_VARIANT=R6");
    dt_rb_log(log, @"COMPILED_ROOTLESS_MARKER=ROOTLESS_R6_BEGIN");
    NSString *err = nil;

    if (!dt710_resolve_preboot_root().length) {
        if (verdictOut) *verdictOut = @"ROOTLESS_PREBOOT_UNRESOLVED";
        return -1;
    }
    dt710_log_preboot_paths(log);

    if (!dt_rootless_ensure_symlink(log, &err)) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_VAR_JB_BLOCK:%@", err ?: @""];
        return -1;
    }
    dt_rb_log(log, @"ROOTLESS_R7_VAR_JB_CREATED");

    NSString *payload = dt_rb_bundle_path(kDTRootlessPayloadDirName);
    if (![[NSFileManager defaultManager] fileExistsAtPath:payload]) {
        /* Host-prepared tree may be staged beside identity for engineering builds */
        payload = [dt_rootless_expected_jbroot() stringByAppendingPathComponent:@".rootless_r4_payload_staging"];
    }
    NSString *pathManifest = dt_rb_bundle_path(@"ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv");
    if (![[NSFileManager defaultManager] fileExistsAtPath:pathManifest]) {
        pathManifest = [payload stringByAppendingPathComponent:@"../ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"].stringByStandardizingPath;
    }
    dt_rb_log(log, @"ROOTLESS_R7_PAYLOAD_COPY_BEGIN");
    dt_rb_log(log, [NSString stringWithFormat:@"ROOTLESS_PACKED_SOURCE_ROOT=%@", payload]);
    if (dt_rootless_install_transformed_tree(payload, pathManifest, log, &err) != 0) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_INSTALL_FAIL:%@", err ?: @""];
        return -1;
    }
    dt_rb_log(log, @"ROOTLESS_R7_PAYLOAD_COPY_COMPLETE");
    if (dt_rootless_postverify_payload_tree(dt_rootless_expected_jbroot(), pathManifest, log, &err) != 0) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_POSTVERIFY_FAIL:%@", err ?: @""];
        return -1;
    }
    dt_rb_log(log, @"ROOTLESS_R7_POSTVERIFY_PASS");
    if (dt_rootless_rewrite_dpkg_db(dt_rootless_expected_jbroot(), log, &err) != 0) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_DPKG_FAIL:%@", err ?: @""];
        return -1;
    }
    if (dt_rootless_install_openssh_addon(payload, log, &err) != 0) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_OPENSSH_FAIL:%@", err ?: @""];
        return -1;
    }

    NSString *manifest = dt_rb_bundle_path(kDTRootlessTrustManifestName);
    if (![[NSFileManager defaultManager] fileExistsAtPath:manifest]) {
        manifest = [[dt_rootless_expected_jbroot() stringByAppendingPathComponent:@"basebin"]
            stringByAppendingPathComponent:kDTRootlessTrustManifestName];
    }
    if (dt_rootless_load_trust_manifest(manifest, log, &err) != 0) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_TRUST_FAIL:%@", err ?: @""];
        return -1;
    }

    dt_rb_log(log, @"ROOTLESS_FRESH_FS_OK (caller must opainject + password/account + SSH + commit LAST)");
    if (verdictOut) *verdictOut = @"ROOTLESS_FRESH_FS_OK";
    return 0;
}

int dt_rootless_run_reuse_fs_stage(void (^log)(NSString *), NSString **verdictOut)
{
    dt_rb_log(log, @"ROOTLESS_REUSE_FS_BEGIN");
    NSString *err = nil;
    if (!dt_rootless_verify_committed(log, &err)) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_REUSE_IDENTITY_FAIL:%@", err ?: @""];
        return -1;
    }
    if (!dt_rootless_ensure_symlink(log, &err)) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_REUSE_VAR_JB_FAIL:%@", err ?: @""];
        return -1;
    }
    NSString *manifest = dt_rb_bundle_path(kDTRootlessTrustManifestName);
    if (![[NSFileManager defaultManager] fileExistsAtPath:manifest]) {
        manifest = [[dt_rootless_expected_jbroot() stringByAppendingPathComponent:@"basebin"]
            stringByAppendingPathComponent:kDTRootlessTrustManifestName];
    }
    if (dt_rootless_load_trust_manifest(manifest, log, &err) != 0) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_REUSE_TRUST_FAIL:%@", err ?: @""];
        return -1;
    }
    dt_rb_log(log, @"ROOTLESS_REUSE_FS_OK (caller must opainject + password/account-if-needed + SSH)");
    if (verdictOut) *verdictOut = @"ROOTLESS_REUSE_FS_OK";
    return 0;
}

int dt_rootless_run_commit_last(void (^log)(NSString *), NSDictionary *extra, NSString **verdictOut)
{
    NSString *err = nil;
    if (!dt_rootless_commit_identity(log, extra, &err)) {
        if (verdictOut) *verdictOut = [NSString stringWithFormat:@"ROOTLESS_COMMIT_FAIL:%@", err ?: @""];
        return -1;
    }
    if (darksword_is_active())
        dt_ds_stage("DARKSWORD_R24_A_TO_Z_PASS");
    if (verdictOut) *verdictOut = @"ROOTLESS_COMMITTED";
    return 0;
}
