#import "dt_rootless_install.h"
#import "dt_rootless_path_policy.h"
#import "dt_rootless_tree_ops.h"
#import "dt_rootless_state.h"
#import "DTRunLogger.h"
#import "spawn_root.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static void dt_rl_log(void (^log)(NSString *), NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log) log(line);
}

static BOOL dt_rl_copy_tree(NSString *src, NSString *dst, NSString *manifest,
                            dt_rootless_copy_counts_t *counts, NSError **err)
{
    char pathErr[DT_ROOTLESS_PATH_ERR_MAX];
    pathErr[0] = 0;
    if (dt_rootless_copy_payload_tree(src.fileSystemRepresentation,
                                      dst.fileSystemRepresentation,
                                      manifest.fileSystemRepresentation,
                                      counts, pathErr, sizeof(pathErr)) != 0) {
        if (err) *err = [NSError errorWithDomain:@"dt_rootless" code:1
            userInfo:@{NSLocalizedDescriptionKey: @(pathErr[0] ? pathErr : "copy failed")}];
        return NO;
    }
    return YES;
}

int dt_rootless_install_transformed_tree(NSString *payloadRoot, NSString *manifestPath,
                                         void (^log)(NSString *), NSString **errOut)
{
    dt_rootless_copy_counts_t packed = {0};
    dt_rootless_copy_counts_t inst = {0};
    char pathErr[DT_ROOTLESS_PATH_ERR_MAX];
    NSString *jbroot = dt_rootless_expected_jbroot();
    if (!jbroot.length || !payloadRoot.length || !manifestPath.length) {
        if (errOut) *errOut = @"jbroot/payload/manifest missing";
        return -1;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:payloadRoot]) {
        if (errOut) *errOut = [NSString stringWithFormat:@"payload missing: %@", payloadRoot];
        return -1;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:manifestPath]) {
        if (errOut) *errOut = @"payload path manifest missing/empty";
        return -1;
    }
    pathErr[0] = 0;
    if (dt_rootless_packed_source_verify(payloadRoot.fileSystemRepresentation,
                                         manifestPath.fileSystemRepresentation,
                                         &packed, pathErr, sizeof(pathErr)) != 0
            || packed.n_src != 4053 || packed.n_src_type_mismatch || packed.n_src_tgt_mismatch
            || packed.n_src_macho_fail || packed.n_src_macho_ok != 397) {
        dt_rl_log(log, [NSString stringWithFormat:
            @"ROOTLESS_PACKED_SOURCE_VERIFY n_src=%lu type_mismatch=%lu tgt_mismatch=%lu macho_ok=%lu macho_fail=%lu",
            packed.n_src, packed.n_src_type_mismatch, packed.n_src_tgt_mismatch,
            packed.n_src_macho_ok, packed.n_src_macho_fail]);
        if (errOut) *errOut = @(pathErr[0] ? pathErr : "packed source verify");
        return -1;
    }
    dt_rl_log(log, [NSString stringWithFormat:
        @"ROOTLESS_PACKED_SOURCE_VERIFY n_src=%lu type_mismatch=%lu tgt_mismatch=%lu macho_ok=%lu macho_fail=%lu",
        packed.n_src, packed.n_src_type_mismatch, packed.n_src_tgt_mismatch,
        packed.n_src_macho_ok, packed.n_src_macho_fail]);
    if (!dt_rootless_write_incomplete_marker()) {
        if (errOut) *errOut = @"incomplete marker write failed";
        return -1;
    }
    NSError *err = nil;
    if (!dt_rl_copy_tree(payloadRoot, jbroot, manifestPath, &inst, &err)) {
        if (errOut) *errOut = err.localizedDescription ?: @"copy failed";
        return -1;
    }
    dt_rl_log(log, [NSString stringWithFormat:
        @"ROOTLESS_MANIFEST_INSTALL symlink=%lu imm_ok=%lu imm_fail=%lu macho_imm_ok=%lu macho_imm_fail=%lu",
        inst.n_symlink_install, inst.n_symlink_imm_ok, inst.n_symlink_imm_fail,
        inst.n_macho_imm_ok, inst.n_macho_imm_fail]);
    dt_rl_log(log, [NSString stringWithFormat:@"ROOTLESS_INSTALL_TREE_OK jbroot=%@", jbroot]);
    return 0;
}

static NSString *dt_rl_rewrite_text_paths(NSString *text)
{
    /* Rootful absolute package paths -> rootless visible paths */
    NSString *out = text;
    out = [out stringByReplacingOccurrencesOfString:@"\n/usr/" withString:@"\n/var/jb/usr/"];
    out = [out stringByReplacingOccurrencesOfString:@"\n/Library/" withString:@"\n/var/jb/Library/"];
    out = [out stringByReplacingOccurrencesOfString:@"\n/bin/" withString:@"\n/var/jb/bin/"];
    out = [out stringByReplacingOccurrencesOfString:@"\n/sbin/" withString:@"\n/var/jb/sbin/"];
    out = [out stringByReplacingOccurrencesOfString:@"\n/etc/" withString:@"\n/var/jb/etc/"];
    if ([out hasPrefix:@"/usr/"])
        out = [@"/var/jb" stringByAppendingString:out];
    else if ([out hasPrefix:@"/Library/"])
        out = [@"/var/jb" stringByAppendingString:out];
    out = [out stringByReplacingOccurrencesOfString:@"Architecture: appletvos-arm64\n"
                                         withString:@"Architecture: appletvos-arm64-rootless\n"];
    out = [out stringByReplacingOccurrencesOfString:@"Architecture: appletvos-arm64\r\n"
                                         withString:@"Architecture: appletvos-arm64-rootless\r\n"];
    return out;
}

int dt_rootless_rewrite_dpkg_db(NSString *jbroot, void (^log)(NSString *), NSString **errOut)
{
    if (!jbroot.length) jbroot = dt_rootless_expected_jbroot();
    NSString *infoDir = [jbroot stringByAppendingPathComponent:@"Library/dpkg/info"];
    NSString *status = [jbroot stringByAppendingPathComponent:@"Library/dpkg/status"];
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm fileExistsAtPath:infoDir]) {
        if (errOut) *errOut = @"dpkg info dir missing";
        return -1;
    }
    NSError *err = nil;
    NSArray *files = [fm contentsOfDirectoryAtPath:infoDir error:&err];
    if (!files) {
        if (errOut) *errOut = err.localizedDescription ?: @"dpkg info listing failed";
        return -1;
    }
    NSUInteger rewritten = 0;
    for (NSString *name in files) {
        if (!([name hasSuffix:@".list"] || [name hasSuffix:@".md5sums"] || [name hasSuffix:@".conffiles"]
              || [name hasSuffix:@".postinst"] || [name hasSuffix:@".preinst"]
              || [name hasSuffix:@".prerm"] || [name hasSuffix:@".postrm"]))
            continue;
        NSString *path = [infoDir stringByAppendingPathComponent:name];
        NSError *readErr = nil;
        NSString *text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&readErr];
        if (!text) {
            if (errOut) *errOut = [NSString stringWithFormat:@"dpkg read fail %@: %@", name,
                                   readErr.localizedDescription ?: @"nil"];
            return -1;
        }
        NSString *next = dt_rl_rewrite_text_paths(text);
        if (![next isEqualToString:text]) {
            NSError *writeErr = nil;
            if (![next writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeErr]) {
                if (errOut) *errOut = [NSString stringWithFormat:@"dpkg write fail %@: %@", name,
                                       writeErr.localizedDescription ?: @"nil"];
                return -1;
            }
            rewritten++;
        }
    }
    if ([fm fileExistsAtPath:status]) {
        NSError *readErr = nil;
        NSString *text = [NSString stringWithContentsOfFile:status encoding:NSUTF8StringEncoding error:&readErr];
        if (!text) {
            if (errOut) *errOut = [NSString stringWithFormat:@"dpkg status read fail: %@",
                                   readErr.localizedDescription ?: @"nil"];
            return -1;
        }
        NSString *next = dt_rl_rewrite_text_paths(text);
        if (![next isEqualToString:text]) {
            NSError *writeErr = nil;
            if (![next writeToFile:status atomically:YES encoding:NSUTF8StringEncoding error:&writeErr]) {
                if (errOut) *errOut = [NSString stringWithFormat:@"dpkg status write fail: %@",
                                       writeErr.localizedDescription ?: @"nil"];
                return -1;
            }
            rewritten++;
        }
    }
    dt_rl_log(log, [NSString stringWithFormat:@"ROOTLESS_DPKG_REWRITE files=%lu", (unsigned long)rewritten]);
    return 0;
}

int dt_rootless_install_openssh_addon(NSString *payloadRoot, void (^log)(NSString *), NSString **errOut)
{
    /* OpenSSH files are already merged into the host-built payload tree. */
    NSArray *need = @[
        @"usr/sbin/sshd",
        @"usr/bin/ssh",
        @"Library/dpkg/info/openssh-server.list",
    ];
    NSString *jbroot = dt_rootless_expected_jbroot();
    for (NSString *rel in need) {
        NSString *p = [jbroot stringByAppendingPathComponent:rel];
        if (![[NSFileManager defaultManager] fileExistsAtPath:p]) {
            /* try payload */
            p = [payloadRoot stringByAppendingPathComponent:rel];
            if (![[NSFileManager defaultManager] fileExistsAtPath:p]) {
                if (errOut) *errOut = [NSString stringWithFormat:@"OpenSSH missing %@", rel];
                return -1;
            }
        }
    }
    dt_rl_log(log, @"ROOTLESS_OPENSSH_ADDON_OK packages=openssh-client,openssh-server,openssh-sftp-server=9.7p1-2");
    return 0;
}

int dt_rootless_run_prep_bootstrap(void (^log)(NSString *), NSString **errOut)
{
    NSString *jbroot = dt_rootless_expected_jbroot();
    if (!jbroot.length) {
        if (errOut) *errOut = @"jbroot missing";
        return -1;
    }
    /* Prefer public alias path used by rewritten prep_bootstrap.sh */
    NSString *prepAlias = @"/var/jb/prep_bootstrap.sh";
    NSString *prepJb = [jbroot stringByAppendingPathComponent:@"prep_bootstrap.sh"];
    NSString *prep = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:prepAlias])
        prep = prepAlias;
    else if ([[NSFileManager defaultManager] fileExistsAtPath:prepJb])
        prep = prepJb;

    if (!prep) {
        /* Dopamine model: successful FRESH deletes prep_bootstrap.sh → REUSE skips prompt. */
        dt_rl_log(log, @"ROOTLESS_PREP_BOOTSTRAP_SKIP=ABSENT (REUSE or already finalized)");
        return 0;
    }

    NSString *shAlias = @"/var/jb/bin/sh";
    NSString *shJb = [jbroot stringByAppendingPathComponent:@"bin/sh"];
    NSString *sh = [[NSFileManager defaultManager] fileExistsAtPath:shAlias] ? shAlias : shJb;
    NSString *uialert = @"/var/jb/usr/bin/uialert";
    NSString *pw = @"/var/jb/usr/sbin/pw";
    if (![[NSFileManager defaultManager] fileExistsAtPath:sh]) {
        if (errOut) *errOut = [NSString stringWithFormat:@"prep shell missing %@", sh];
        return -1;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:uialert]) {
        if (errOut) *errOut = @"prep uialert missing /var/jb/usr/bin/uialert";
        return -1;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:pw]) {
        if (errOut) *errOut = @"prep pw missing /var/jb/usr/sbin/pw";
        return -1;
    }

    dt_rl_log(log, [NSString stringWithFormat:@"ROOTLESS_PREP_BOOTSTRAP_BEGIN script=%@", prep]);
    dt_rl_log(log, @"ROOTLESS_PASSWORD_UI=uialert (KEEP prep_bootstrap.sh)");
    int st = 0;
    NSError *spawnErr = nil;
    /* Persona-root spawn — matches trusted finalize path; required for pw usermod. */
    int rc = dt_spawn_root(sh, @[prep], &st, &spawnErr);
    if (rc != 0) {
        if (errOut) *errOut = [NSString stringWithFormat:@"prep spawn rc=%d err=%@", rc, spawnErr.localizedDescription ?: @""];
        dt_rl_log(log, [NSString stringWithFormat:@"ROOTLESS_PREP_BOOTSTRAP_SPAWN_FAIL %@", *errOut]);
        return -1;
    }
    if (st != 0) {
        if (errOut) *errOut = [NSString stringWithFormat:@"prep_bootstrap.sh exit=%d", st];
        dt_rl_log(log, [NSString stringWithFormat:@"ROOTLESS_PREP_BOOTSTRAP_FAIL exit=%d", st]);
        return -1;
    }
    /* Script self-deletes on success; if still present, treat as incomplete finalize. */
    if ([[NSFileManager defaultManager] fileExistsAtPath:prepAlias]
            || [[NSFileManager defaultManager] fileExistsAtPath:prepJb]) {
        if (errOut) *errOut = @"prep_bootstrap.sh still present after exit 0";
        return -1;
    }
    dt_rl_log(log, @"ROOTLESS_PREP_BOOTSTRAP_OK password_account_finalized=YES");
    return 0;
}

static BOOL dt_r24_runtime_probe_ack_is_valid(void)
{
    static const char ackPath[] = "/private/var/jb/.r24_current_boot_runtime_probe_pass";
    int fd = open(ackPath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return NO;
    struct stat st;
    char buf[8] = {0};
    int statRc = fstat(fd, &st);
    ssize_t nr = read(fd, buf, sizeof(buf));
    int closeRc = close(fd);
    return statRc == 0 && closeRc == 0 && nr == 5 && memcmp(buf, "pass\n", 5) == 0
        && S_ISREG(st.st_mode) && st.st_uid == 0;
}

static void dt_r24_runtime_probe_bootout(NSString *launchctl)
{
    int status = 0;
    NSError *err = nil;
    (void)dt_spawn_root(launchctl,
                        @[@"bootout", @"system/com.dopamin.tvos.runtime-probe"],
                        &status, &err);
}

int dt_rootless_run_current_boot_runtime_probe(void (^log)(NSString *), NSString **errOut)
{
    static NSString *const label = @"com.dopamin.tvos.runtime-probe";
    static NSString *const ack = @"/private/var/jb/.r24_current_boot_runtime_probe_pass";
    NSString *jbroot = dt_rootless_expected_jbroot();
    NSString *launchctl = @"/var/jb/usr/bin/launchctl";
    NSString *probe = @"/var/jb/usr/bin/true";
    NSString *rm = @"/var/jb/usr/bin/rm";
    NSFileManager *fm = NSFileManager.defaultManager;

    if (!jbroot.length || access(launchctl.fileSystemRepresentation, X_OK) != 0
        || access(probe.fileSystemRepresentation, X_OK) != 0
        || access(rm.fileSystemRepresentation, X_OK) != 0) {
        if (errOut) *errOut = @"current-boot runtime prerequisite missing";
        dt_rl_log(log, @"R24_FAIL_STAGE=CONTROLLED_CHILD_PREFLIGHT rc=1");
        return -1;
    }

    int status = 0;
    NSError *spawnErr = nil;
    (void)dt_spawn_root(rm, @[@"-f", ack], &status, &spawnErr);
    if (access(ack.fileSystemRepresentation, F_OK) == 0) {
        if (errOut) *errOut = @"stale runtime probe acknowledgement could not be removed";
        dt_rl_log(log, @"R24_FAIL_STAGE=CONTROLLED_CHILD_PREFLIGHT rc=2");
        return -2;
    }

    dt_r24_runtime_probe_bootout(launchctl);

    NSString *plistPath = [NSTemporaryDirectory()
        stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@.plist",
                                        label, NSUUID.UUID.UUIDString]];
    NSDictionary *job = @{
        @"Label" : label,
        @"ProgramArguments" : @[probe],
        @"RunAtLoad" : @YES,
        @"KeepAlive" : @NO,
        @"UserName" : @"root",
        @"EnvironmentVariables" : @{@"R24_RUNTIME_PROBE" : @"1"},
    };
    NSError *plistErr = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:job
        format:NSPropertyListXMLFormat_v1_0 options:0 error:&plistErr];
    if (!plistData || ![plistData writeToFile:plistPath options:NSDataWritingAtomic error:&plistErr]) {
        if (errOut) *errOut = [NSString stringWithFormat:@"runtime probe plist: %@",
                               plistErr.localizedDescription ?: @"write failed"];
        dt_rl_log(log, @"R24_FAIL_STAGE=CONTROLLED_CHILD_PREFLIGHT rc=3");
        return -3;
    }

    dt_rl_log(log, @"R24_CONTROLLED_CHILD_BEGIN owner=launchd program=/var/jb/usr/bin/true");
    [[DTRunLogger shared] relayRuntimeTraceNow];
    status = 0;
    spawnErr = nil;
    int spawnRc = dt_spawn_root(launchctl, @[@"bootstrap", @"system", plistPath],
                                &status, &spawnErr);
    if (spawnRc != 0 || status != 0) {
        [fm removeItemAtPath:plistPath error:nil];
        dt_r24_runtime_probe_bootout(launchctl);
        if (errOut) *errOut = [NSString stringWithFormat:
            @"launchctl bootstrap rc=%d status=%d err=%@", spawnRc, status,
            spawnErr.localizedDescription ?: @""];
        dt_rl_log(log, [NSString stringWithFormat:
            @"R24_FAIL_STAGE=CONTROLLED_CHILD_LAUNCH rc=%d", spawnRc ?: status]);
        return -4;
    }

    BOOL acked = NO;
    for (NSUInteger i = 0; i < 100; i++) {
        [[DTRunLogger shared] relayRuntimeTraceNow];
        if (dt_r24_runtime_probe_ack_is_valid()) {
            acked = YES;
            break;
        }
        usleep(50000);
    }

    [[DTRunLogger shared] relayRuntimeTraceNow];
    int printStatus = 0;
    NSError *printError = nil;
    NSString *printOutput = nil;
    int printRc = dt_spawn_root_capture(launchctl,
        @[@"print", @"system/com.dopamin.tvos.runtime-probe"], &printStatus,
        &printOutput, &printError);
    dt_rl_log(log, [NSString stringWithFormat:
        @"R24_CONTROLLED_CHILD_LAUNCHD_STATE rc=%d status=%d error=%@ output=%@",
        printRc, printStatus, printError.localizedDescription ?: @"-",
        printOutput.length ? printOutput : @"-"]);

    dt_r24_runtime_probe_bootout(launchctl);
    [[DTRunLogger shared] relayRuntimeTraceNow];
    [fm removeItemAtPath:plistPath error:nil];
    if (!acked) {
        if (errOut) *errOut = @"controlled child did not acknowledge systemhook check-in";
        dt_rl_log(log, @"R24_FAIL_STAGE=CONTROLLED_CHILD_ACK rc=3");
        return -5;
    }

    dt_rl_log(log, @"R24_CONTROLLED_CHILD_INJECTION=PASS");
    dt_rl_log(log, @"CURRENT_BOOT_RUNTIME_PASS=YES source=child_ack");
    return 0;
}

int dt_rootless_postverify_payload_tree(NSString *jbroot, NSString *manifestPath,
                                        void (^log)(NSString *), NSString **errOut)
{
    dt_rootless_postverify_counts_t pv;
    memset(&pv, 0, sizeof(pv));
    if (!jbroot.length || !manifestPath.length) {
        if (errOut) *errOut = @"postverify args missing";
        return -1;
    }
    int rc = dt_rootless_postverify_payload_tree_c(jbroot.fileSystemRepresentation,
                                                   manifestPath.fileSystemRepresentation,
                                                   &pv);
    if (pv.n_fail || rc != 0) {
        dt_rl_log(log, [NSString stringWithFormat:
            @"ROOTLESS_POSTVERIFY_FAIL files=%lu dirs=%lu links=%lu macho=%lu fail=%lu type_symlink=%lu macho_type=%lu macho_sha=%lu missing=%lu extra=%lu",
            pv.n_file, pv.n_dir, pv.n_link, pv.n_macho, pv.n_fail,
            pv.n_type_symlink, pv.n_macho_type, pv.n_macho_sha, pv.n_missing, pv.n_extra]);
        if (errOut) *errOut = @(pv.first_err[0] ? pv.first_err : "postverify failed");
        return -1;
    }
    dt_rl_log(log, [NSString stringWithFormat:
        @"ROOTLESS_POSTVERIFY_OK files=%lu dirs=%lu links=%lu macho=%lu extra=%lu",
        pv.n_file, pv.n_dir, pv.n_link, pv.n_macho, pv.n_extra]);
    return 0;
}
