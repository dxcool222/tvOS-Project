#import "dt_build674_client.h"
#import "frozen661_embed.h"

#import "DTRunLogger.h"
#import "dt_physrw.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"

#import <CommonCrypto/CommonCrypto.h>
#import <codesign.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <spawn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/select.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

static NSString *const kDT674Control661Bundled =
    @"Handoff674/Control661/dt_direct653_helper_control661";
static NSString *const kDT674Control661Stage =
    @"/private/var/jb/usr/bin/dt_direct653_helper_control661";

static NSString *const kDT674Helper672Bundled = @"Handoff653/dt_direct653_helper";
static NSString *const kDT674Helper672Stage =
    @"/private/var/jb/usr/bin/dt_direct653_helper_672_b";

static NSString *const kDT674ToolBundled = @"Handoff672/dt_tool672_probe";
static NSString *const kDT674ToolStage = @"/private/var/jb/usr/bin/dt_tool672_probe";

static NSString *const kDT674ExpectedControl661SHA =
    @"a564572385df3f4551a5da63ca2a135ddc018cff0e04a97644a6078cfb23cabc";
static NSString *const kDT674ExpectedControl661CDHash =
    @"1f9378adb7180b85efb6f456311e9d6ed0536613";
static const unsigned long long kDT674ExpectedControl661Size = 51984ULL;
static NSString *const kDT674Reference672HelperSHA =
    @"b195df57aa1cfa8fde2058698303c8b7b33df874575aaafae86dd8c32c39822d";
static NSString *const kDT674Reference672HelperCDHash =
    @"6614c28031980962d95e58551e012a802db64d4a";

typedef void (^dt674_log_fn)(NSString *line);
typedef int (*dt674_spawn_fn)(pid_t *, const char *,
                              const posix_spawn_file_actions_t *,
                              const posix_spawnattr_t *,
                              char *const[], char *const[]);
typedef int (*dt674_spawn_fa_init_fn)(posix_spawn_file_actions_t *);
typedef int (*dt674_spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
typedef int (*dt674_spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
typedef int (*dt674_spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

typedef struct {
    BOOL ran;
    BOOL app_pass;
    BOOL stdout_present;
    int spawn_ret;
    int spawn_errno;
    pid_t child_pid;
    int child_wtermsig;
    int child_exit;
    BOOL child_signaled;
    BOOL child_exited;
} dt674_case_result_t;

static BOOL dt674_cdhash_file(NSString *path, NSString **hexOut);

static void dt674_log(dt674_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt674_emit(dt674_log_fn log, NSString *marker)
{
    dt674_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

static BOOL dt674_mkdir_p(NSString *path, mode_t mode)
{
    if (!path.length)
        return NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:path])
        return YES;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length && ![parent isEqualToString:path])
        (void)dt674_mkdir_p(parent, mode);
    return mkdir(path.fileSystemRepresentation, mode) == 0 || errno == EEXIST;
}

static BOOL dt674_sha256_bytes(const void *bytes, size_t len, NSString **hexOut)
{
    if (!bytes || !len)
        return NO;

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes, (CC_LONG)len, digest);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];

    if (hexOut)
        *hexOut = hex;
    return YES;
}

static BOOL dt674_sha256_file(NSString *path, NSString **hexOut)
{
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh)
        return NO;

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    while (true) {
        @autoreleasepool {
            NSData *chunk = [fh readDataOfLength:65536];
            if (!chunk.length)
                break;
            CC_SHA256_Update(&ctx, chunk.bytes, (CC_LONG)chunk.length);
        }
    }
    [fh closeFile];

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];

    if (hexOut)
        *hexOut = hex;
    return YES;
}

static unsigned long long dt674_file_size(NSString *path)
{
    NSDictionary *attrs = [[NSFileManager defaultManager]
        attributesOfItemAtPath:path error:nil];
    NSNumber *size = attrs[NSFileSize];
    return size ? size.unsignedLongLongValue : 0;
}

static void dt674_log_bundle_drift(dt674_log_fn log, NSString *path)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL exists = [fm fileExistsAtPath:path];
    NSString *bundleSha = nil;
    NSString *bundleCdhash = nil;

    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_BUNDLE_PATH=%@", path]);
    dt674_emit(log, exists ? @"KCALL674_BUNDLE_EXISTS=YES" : @"KCALL674_BUNDLE_EXISTS=NO");
    if (!exists) {
        dt674_emit(log, @"KCALL674_BUNDLE_DRIFT=UNKNOWN_MISSING");
        return;
    }

    (void)dt674_sha256_file(path, &bundleSha);
    (void)dt674_cdhash_file(path, &bundleCdhash);
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_BUNDLE_SHA256=%@", bundleSha ?: @""]);
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_BUNDLE_CDHASH=%@", bundleCdhash ?: @""]);
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_BUNDLE_SIZE=%llu",
        dt674_file_size(path)]);

    if (bundleSha.length &&
        [bundleSha isEqualToString:kDT674ExpectedControl661SHA]) {
        dt674_emit(log, @"KCALL674_BUNDLE_DRIFT=NO");
        return;
    }

    if (bundleCdhash.length &&
        [bundleCdhash isEqualToString:kDT674ExpectedControl661CDHash]) {
        dt674_emit(log, @"KCALL674_BUNDLE_DRIFT=RAW_SHA_ONLY");
        return;
    }

    if (bundleSha.length &&
        [bundleSha isEqualToString:kDT674Reference672HelperSHA]) {
        dt674_emit(log, @"KCALL674_BUNDLE_DRIFT=672_HELPER_BYTES_AT_CONTROL661_PATH");
        return;
    }

    if (bundleCdhash.length &&
        [bundleCdhash isEqualToString:kDT674Reference672HelperCDHash]) {
        dt674_emit(log, @"KCALL674_BUNDLE_DRIFT=672_HELPER_CDHASH_AT_CONTROL661_PATH");
        return;
    }

    dt674_emit(log, @"KCALL674_BUNDLE_DRIFT=YES");
}

static BOOL dt674_verify_control661_embed(dt674_log_fn log, NSString **detailOut)
{
    NSString *bundlePath = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:kDT674Control661Bundled];
    NSString *embedSha = nil;
    NSString *embedCdhash = nil;
    NSString *tmpPath = nil;

    dt674_emit(log, @"KCALL674_EMBED_SOURCE=COMPILED_FROZEN661");
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_LEN=%zu",
        kDT674Frozen661EmbedLen]);
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_SHA256_EXPECTED=%@",
        kDT674ExpectedControl661SHA]);
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_CDHASH_EXPECTED=%@",
        kDT674ExpectedControl661CDHash]);

    if (kDT674Frozen661EmbedLen != kDT674ExpectedControl661Size) {
        if (detailOut)
            *detailOut = @"compiled frozen661 embed size mismatch";
        dt674_emit(log, @"KCALL674_EMBED_FAIL_REASON=EMBED_SIZE_MISMATCH");
        dt674_emit(log, @"FROZEN_661_BLOB_EMBED=FAIL");
        return NO;
    }

    if (!dt674_sha256_bytes(kDT674Frozen661Embed, kDT674Frozen661EmbedLen, &embedSha) ||
        !embedSha.length ||
        ![embedSha isEqualToString:kDT674ExpectedControl661SHA]) {
        if (detailOut)
            *detailOut = @"compiled frozen661 embed sha256 mismatch";
        dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_SHA256_ACTUAL=%@",
            embedSha ?: @""]);
        dt674_emit(log, @"KCALL674_EMBED_FAIL_REASON=EMBED_SHA_MISMATCH");
        dt674_emit(log, @"FROZEN_661_BLOB_EMBED=FAIL");
        return NO;
    }

    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_SHA256_ACTUAL=%@", embedSha]);

    tmpPath = [NSTemporaryDirectory()
        stringByAppendingPathComponent:@"dt674_frozen661_embed_verify"];
    NSData *embedData = [NSData dataWithBytes:kDT674Frozen661Embed
                                       length:kDT674Frozen661EmbedLen];
    if (![embedData writeToFile:tmpPath atomically:YES]) {
        if (detailOut)
            *detailOut = @"compiled frozen661 embed temp write failed";
        dt674_emit(log, @"KCALL674_EMBED_FAIL_REASON=TEMP_WRITE");
        dt674_emit(log, @"FROZEN_661_BLOB_EMBED=FAIL");
        return NO;
    }

    if (!dt674_cdhash_file(tmpPath, &embedCdhash) ||
        !embedCdhash.length ||
        ![embedCdhash isEqualToString:kDT674ExpectedControl661CDHash]) {
        if (detailOut)
            *detailOut = @"compiled frozen661 embed cdhash mismatch";
        dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_CDHASH_ACTUAL=%@",
            embedCdhash ?: @""]);
        dt674_emit(log, @"KCALL674_EMBED_FAIL_REASON=EMBED_CDHASH_MISMATCH");
        [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
        dt674_emit(log, @"FROZEN_661_BLOB_EMBED=FAIL");
        return NO;
    }

    [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_EMBED_CDHASH_ACTUAL=%@", embedCdhash]);
    dt674_log_bundle_drift(log, bundlePath);
    dt674_emit(log, @"FROZEN_661_BLOB_EMBED=PASS");
    return YES;
}

static BOOL dt674_cdhash_file(NSString *path, NSString **hexOut)
{
    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0)
        return NO;
    if (hexOut)
        *hexOut = dt_cdhash_hex_string(hash);
    return YES;
}

static BOOL dt674_trust_staged(NSString *path, dt674_log_fn log, int *tcRetOut)
{
    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0) {
        if (tcRetOut)
            *tcRetOut = -1;
        return NO;
    }

    cdhash_t *hashes = calloc(1, sizeof(cdhash_t));
    if (!hashes) {
        if (tcRetOut)
            *tcRetOut = ENOMEM;
        return NO;
    }
    memcpy(hashes[0], hash, sizeof(cdhash_t));

    uint32_t uploaded = 0;
    uint32_t skipped = 0;
    int r = dt_trustcache_upload_cdhashes(hashes, 1, &uploaded, &skipped);
    if (r == 0 && !dt_cdhash_trustcached(hashes[0]))
        r = EIO;
    free(hashes);

    if (tcRetOut)
        *tcRetOut = r;

    dt674_log(log, [NSString stringWithFormat:
        @"KCALL674_TRUSTCACHE_UPLOADED=%u skipped=%u", uploaded, skipped]);
    return r == 0;
}

static BOOL dt674_stage_frozen661(dt674_log_fn log, NSString **detailOut)
{
    if (!dt674_mkdir_p(@"/private/var/jb/usr/bin", 0755)) {
        if (detailOut)
            *detailOut = @"jbroot mkdir failed";
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:kDT674Control661Stage error:nil];

    NSData *embedData = [NSData dataWithBytes:kDT674Frozen661Embed
                                       length:kDT674Frozen661EmbedLen];
    if (!embedData.length ||
        ![embedData writeToFile:kDT674Control661Stage atomically:YES]) {
        if (detailOut)
            *detailOut = @"frozen661 stage write failed";
        return NO;
    }

    if (chmod(kDT674Control661Stage.fileSystemRepresentation, 0755) != 0) {
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"chmod failed errno=%d", errno];
        return NO;
    }

    dt674_emit(log, @"KCALL674_STAGE_SOURCE=COMPILED_FROZEN661");
    return YES;
}

static BOOL dt674_stage_bundled(NSString *bundledRel, NSString *installed,
                                dt674_log_fn log, NSString **detailOut)
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:bundledRel];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:bundled]) {
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"bundled missing: %@", bundledRel];
        return NO;
    }

    if (!dt674_mkdir_p(@"/private/var/jb/usr/bin", 0755)) {
        if (detailOut)
            *detailOut = @"jbroot mkdir failed";
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:installed error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:bundled toPath:installed error:&copyErr]) {
        if (detailOut)
            *detailOut = copyErr.localizedDescription ?: @"stage copy failed";
        return NO;
    }

    if (chmod(installed.fileSystemRepresentation, 0755) != 0) {
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"chmod failed errno=%d", errno];
        return NO;
    }
    return YES;
}

static BOOL dt674_read_pipe(int readFd, double timeoutSec, NSMutableString **textOut)
{
    NSMutableString *buf = [NSMutableString string];
    char chunk[512];
    fd_set readfds;
    struct timeval tv;
    double deadline = [[NSDate date] timeIntervalSince1970] + timeoutSec;

    while ([[NSDate date] timeIntervalSince1970] < deadline) {
        FD_ZERO(&readfds);
        FD_SET(readFd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        int sel = select(readFd + 1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(readFd, &readfds)) {
            ssize_t n = read(readFd, chunk, sizeof(chunk) - 1);
            if (n > 0) {
                chunk[n] = '\0';
                [buf appendString:[NSString stringWithUTF8String:chunk]];
            } else if (n == 0) {
                break;
            } else if (errno != EINTR) {
                break;
            }
        } else if (sel < 0 && errno != EINTR) {
            break;
        }
    }

    if (textOut)
        *textOut = buf;
    return buf.length > 0;
}

static void dt674_log_stdout_lines(dt674_log_fn log, NSString *text)
{
    for (NSString *line in [text componentsSeparatedByCharactersInSet:
         [NSCharacterSet newlineCharacterSet]]) {
        if (line.length)
            dt674_log(log, line);
    }
}

static BOOL dt674_case_spawn(NSString *caseId, NSString *stagePath,
                             NSString *stdout_needle, dt674_log_fn log,
                             dt674_spawn_fn spawn, dt674_spawn_fa_init_fn fa_init,
                             dt674_spawn_fa_destroy_fn fa_destroy,
                             dt674_spawn_fa_adddup2_fn fa_dup2,
                             dt674_spawn_fa_addclose_fn fa_close,
                             dt674_case_result_t *out)
{
    int pipefd[2] = { -1, -1 };
    int tcRet = -1;
    NSString *sha = nil;
    NSString *cdhash = nil;
    NSString *detail = nil;
    dt674_case_result_t result = {0};
    posix_spawn_file_actions_t actions;
    BOOL actionsInited = NO;
    NSMutableString *stdoutBuf = nil;
    int waitStatus = 0;

    memset(out, 0, sizeof(*out));
    out->ran = YES;

    dt674_emit(log, [NSString stringWithFormat:@"KCALL674_CASE=%@", caseId]);
    dt674_log(log, [NSString stringWithFormat:@"KCALL674_STAGE_PATH=%@", stagePath]);

    if (!dt674_sha256_file(stagePath, &sha)) {
        detail = @"stage sha256 failed";
        goto finish;
    }
    dt674_log(log, [NSString stringWithFormat:@"KCALL674_STAGE_SHA256=%@", sha]);

    if (!dt674_cdhash_file(stagePath, &cdhash)) {
        detail = @"stage cdhash failed";
        goto finish;
    }
    dt674_log(log, [NSString stringWithFormat:@"KCALL674_STAGE_CDHASH=%@", cdhash]);

    if (!dt674_trust_staged(stagePath, log, &tcRet)) {
        detail = @"trustcache failed";
        goto finish;
    }
    dt674_log(log, [NSString stringWithFormat:@"KCALL674_TRUSTCACHE_RET=%d", tcRet]);

    if (pipe(pipefd) != 0) {
        detail = @"pipe create failed";
        goto finish;
    }

    if (fa_init(&actions) != 0) {
        detail = @"posix_spawn_file_actions_init failed";
        close(pipefd[0]);
        close(pipefd[1]);
        goto finish;
    }
    actionsInited = YES;
    (void)fa_close(&actions, pipefd[0]);
    (void)fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
    (void)fa_dup2(&actions, pipefd[1], STDERR_FILENO);
    (void)fa_close(&actions, pipefd[1]);

    dt674_emit(log, @"KCALL674_SPAWN_BEGIN");

    char *argv[] = { (char *)stagePath.UTF8String, NULL };
    pid_t child = 0;
    int spawnRet = spawn(&child, stagePath.UTF8String, &actions, NULL, argv, environ);
    fa_destroy(&actions);
    actionsInited = NO;
    close(pipefd[1]);

    result.spawn_ret = spawnRet;
    result.spawn_errno = spawnRet != 0 ? errno : 0;
    result.child_pid = child;

    dt674_log(log, [NSString stringWithFormat:@"KCALL674_SPAWN_RET=%d", spawnRet]);
    dt674_log(log, [NSString stringWithFormat:@"KCALL674_SPAWN_ERRNO=%d", result.spawn_errno]);
    dt674_log(log, [NSString stringWithFormat:@"KCALL674_CHILD_PID=%d", (int)child]);

    if (spawnRet == 0 && child > 0) {
        result.stdout_present = dt674_read_pipe(pipefd[0], 15.0, &stdoutBuf);
        if (stdoutBuf.length)
            dt674_log_stdout_lines(log, stdoutBuf);
    }
    close(pipefd[0]);
    pipefd[0] = pipefd[1] = -1;

    if (spawnRet == 0 && child > 0) {
        if (waitpid(child, &waitStatus, 0) < 0) {
            detail = @"waitpid failed";
            goto finish;
        }
        if (WIFEXITED(waitStatus)) {
            result.child_exited = YES;
            result.child_exit = WEXITSTATUS(waitStatus);
        } else if (WIFSIGNALED(waitStatus)) {
            result.child_signaled = YES;
            result.child_wtermsig = WTERMSIG(waitStatus);
        }
    }

    dt674_log(log, [NSString stringWithFormat:@"KCALL674_CHILD_WTERMSIG=%d",
        result.child_wtermsig]);
    dt674_emit(log, result.stdout_present ? @"KCALL674_STDOUT_PRESENT=YES"
                                          : @"KCALL674_STDOUT_PRESENT=NO");

    {
        NSString *prefix = [NSString stringWithFormat:@"CASE_%@", caseId];
        dt674_log(log, [NSString stringWithFormat:@"%@_SPAWN_RET=%d", prefix,
            result.spawn_ret]);
        dt674_log(log, [NSString stringWithFormat:@"%@_ERRNO=%d", prefix,
            result.spawn_errno]);
        dt674_log(log, [NSString stringWithFormat:@"%@_PID=%d", prefix,
            (int)result.child_pid]);
        dt674_log(log, [NSString stringWithFormat:@"%@_WTERMSIG=%d", prefix,
            result.child_wtermsig]);
        dt674_emit(log, [NSString stringWithFormat:@"%@_STDOUT_PRESENT=%@",
            prefix, result.stdout_present ? @"YES" : @"NO"]);
        dt674_log(log, [NSString stringWithFormat:@"%@_ATTACH_PROFILE=KERNEL_MANUAL",
            prefix]);
        dt674_log(log, [NSString stringWithFormat:@"%@_WALLA=OPEN", prefix]);
        dt674_log(log, [NSString stringWithFormat:@"%@_UNSIGNED_DISPLAY=OPEN", prefix]);
    }

    {
        BOOL markerHit = result.stdout_present && stdout_needle.length &&
            [stdoutBuf containsString:stdout_needle];
        BOOL spawnOk = spawnRet == 0 && child > 0 && !result.child_signaled;

        dt674_emit(log, [NSString stringWithFormat:@"CASE_%@_MARKER_HIT=%@",
            caseId, markerHit ? @"YES" : @"NO"]);
        if (result.child_exited)
            dt674_emit(log, [NSString stringWithFormat:@"CASE_%@_CHILD_EXIT=%d",
                caseId, result.child_exit]);
        else if (result.child_signaled)
            dt674_emit(log, [NSString stringWithFormat:@"CASE_%@_CHILD_SIGNAL=%d",
                caseId, result.child_wtermsig]);
        else
            dt674_emit(log, [NSString stringWithFormat:@"CASE_%@_CHILD_EXIT=OPEN", caseId]);

        /* Gate: attach OR stdout marker — not exit code alone (helpers may fail
         * post-smoke self-tests while kernel attach already succeeded). */
        if (spawnOk && markerHit)
            result.app_pass = YES;
    }

finish:
    if (actionsInited)
        fa_destroy(&actions);
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    if (detail.length)
        dt674_log(log, [NSString stringWithFormat:@"[*] build674 case %@ detail=%@", caseId, detail]);
    *out = result;
    return result.app_pass;
}

static NSString *dt674_case_label(BOOL pass)
{
    return pass ? @"PASS" : @"FAIL";
}

static void dt674_emit_decision_matrix(dt674_log_fn log, BOOL aPass, BOOL bPass, BOOL cPass)
{
    if (aPass && !bPass)
        dt674_emit(log, @"BINARY_SPECIFIC_DIFFERENTIAL=CONFIRMED");
    if (!aPass && !bPass)
        dt674_emit(log, @"SPAWNER_SESSION_STATE_REGRESSION=CONFIRMED_OR_STRONGLY_INDICATED");
    if (aPass && !bPass && cPass)
        dt674_emit(log, @"672_HELPER_SPECIFIC_DIFFERENCE=CONFIRMED");
    if (aPass && !bPass && !cPass) {
        dt674_emit(log, @"NEW_ARTIFACT_ACCEPTANCE_CLASS=LIKELY");
        dt674_emit(log, @"EXACT_CAUSE=BINARY_VS_SESSION_STATE_OPEN");
    }
    if (aPass && bPass && cPass)
        dt674_emit(log, @"PRIOR_672_FAILURE=TRANSIENT_OR_SESSION_STATE");
}

static NSString *dt674_root_cause_class(BOOL aPass, BOOL bPass, BOOL cPass)
{
    if (aPass && bPass && cPass)
        return @"PRIOR_672_FAILURE_TRANSIENT_OR_SESSION_STATE";
    if (!aPass && !bPass)
        return @"SPAWNER_SESSION_STATE_REGRESSION";
    if (aPass && !bPass && cPass)
        return @"672_HELPER_SPECIFIC_DIFFERENCE";
    if (aPass && !bPass && !cPass)
        return @"NEW_ARTIFACT_ACCEPTANCE_LIKELY";
    if (aPass && !bPass)
        return @"BINARY_SPECIFIC_DIFFERENTIAL";
    if (!aPass)
        return @"SPAWNER_SESSION_STATE_REGRESSION";
    if (aPass && bPass && !cPass)
        return @"TOOL_DIRECT_SPAWN_PRECHECK_FAIL";
    return @"OPEN";
}

static NSString *dt674_next_step(NSString *rootCause)
{
    if ([rootCause isEqualToString:@"BINARY_SPECIFIC_DIFFERENTIAL"])
        return @"COMPARE_MACHO_SIGNATURE_DIFFERENCES";
    if ([rootCause isEqualToString:@"SPAWNER_SESSION_STATE_REGRESSION"])
        return @"READONLY_SPAWNER_CRED_SLOT0_TELEMETRY";
    if ([rootCause isEqualToString:@"672_HELPER_SPECIFIC_DIFFERENCE"])
        return @"FOCUS_672_HELPER_SPECIFIC_DIFFERENCE";
    if ([rootCause isEqualToString:@"NEW_ARTIFACT_ACCEPTANCE_LIKELY"])
        return @"FOCUS_NEW_BINARY_IDENTITY_ACCEPTANCE";
    if ([rootCause isEqualToString:@"PRIOR_672_FAILURE_TRANSIENT_OR_SESSION_STATE"])
        return @"RECHECK_RUNTIME_STATE";
    if ([rootCause isEqualToString:@"TOOL_DIRECT_SPAWN_PRECHECK_FAIL"])
        return @"FOCUS_NEW_BINARY_IDENTITY_ACCEPTANCE";
    return @"FIX_674_PREFLIGHT_AND_RUN_SAME_SESSION_DIFFERENTIAL";
}

int dt_build674_run_ab_differential(void (^log)(NSString *line), NSString **summaryOut)
{
    NSString *detail = nil;
    NSString *summary = @"BUILD674_FAIL";
    dt674_case_result_t caseA = {0};
    dt674_case_result_t caseB = {0};
    dt674_case_result_t caseC = {0};
    BOOL preflightOk = NO;
    dt674_spawn_fn spawn = NULL;
    dt674_spawn_fa_init_fn fa_init = NULL;
    dt674_spawn_fa_destroy_fn fa_destroy = NULL;
    dt674_spawn_fa_adddup2_fn fa_dup2 = NULL;
    dt674_spawn_fa_addclose_fn fa_close = NULL;
    uint32_t csflags = 0;
    NSString *rootCause = nil;

    dt674_emit(log, @"KCALL674_BEGIN");
    dt674_emit(log, @"SAME_SESSION_ORDER=BEGIN");
    dt674_emit(log, @"NEW_HELPER_BINARY_CORRELATION=CONFIRMED");
    dt674_emit(log, @"EXACT_CAUSE=BINARY_VS_SESSION_STATE_OPEN");
    dt674_emit(log, @"674_DIFFERENTIAL_NOT_RUN=TRUE");

    if (!dt_kernel_exploit_is_active()) {
        detail = @"kfd not active";
        dt674_log(log, @"KCALL674_PREFLIGHT_KFD_OK=0");
        goto finish;
    }
    dt674_emit(log, @"KCALL674_PREFLIGHT_KFD_OK");

    if (getuid() != 0 || getgid() != 0) {
        detail = @"requires uid=0 gid=0";
        goto finish;
    }
    dt674_emit(log, @"KCALL674_PREFLIGHT_UID0_OK");
    dt674_emit(log, @"KCALL674_PREFLIGHT_GID0_OK");

    if (csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags)) != 0 ||
        (csflags & CS_PLATFORM_BINARY) == 0) {
        detail = @"CS_PLATFORM_BINARY not set";
        goto finish;
    }
    dt674_emit(log, @"KCALL674_PREFLIGHT_PLATFORM_OK");

    if (!dt674_mkdir_p(@"/private/var/jb", 0755) ||
        ![[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/jb"]) {
        detail = @"/private/var/jb missing";
        goto finish;
    }
    dt674_emit(log, @"KCALL674_PREFLIGHT_JBROOT_OK");

    if (!dt674_verify_control661_embed(log, &detail))
        goto finish;

    spawn = (dt674_spawn_fn)dlsym(RTLD_DEFAULT, "posix_spawn");
    fa_init = (dt674_spawn_fa_init_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_init");
    fa_destroy = (dt674_spawn_fa_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
    fa_dup2 = (dt674_spawn_fa_adddup2_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_adddup2");
    fa_close = (dt674_spawn_fa_addclose_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_addclose");
    if (!spawn || !fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
        detail = @"posix_spawn unavailable";
        goto finish;
    }

    preflightOk = YES;
    dt674_emit(log, @"STAGED_IDENTITY_LOGGING=READY");

    if (!dt674_stage_frozen661(log, &detail))
        goto finish;
    (void)dt674_case_spawn(@"A", kDT674Control661Stage, @"KCALL653_HELPER_ALIVE=1", log,
                           spawn, fa_init, fa_destroy, fa_dup2, fa_close, &caseA);

    if (!dt674_stage_bundled(kDT674Helper672Bundled, kDT674Helper672Stage, log, &detail))
        goto finish;
    (void)dt674_case_spawn(@"B", kDT674Helper672Stage, @"KCALL653_HELPER_ALIVE=1", log,
                           spawn, fa_init, fa_destroy, fa_dup2, fa_close, &caseB);

    if (!dt674_stage_bundled(kDT674ToolBundled, kDT674ToolStage, log, &detail))
        goto finish;
    (void)dt674_case_spawn(@"C", kDT674ToolStage, @"KCALL672_TOOL_ALIVE=1", log,
                           spawn, fa_init, fa_destroy, fa_dup2, fa_close, &caseC);

    dt674_emit(log, @"SAME_SESSION_ORDER=PASS");
    dt674_emit(log, @"STAGED_IDENTITY_LOGGING=PASS");
    dt674_emit(log, @"674_DIFFERENTIAL_NOT_RUN=FALSE");

    dt674_emit(log, [NSString stringWithFormat:@"CASE_A_FROZEN_661=%@",
        dt674_case_label(caseA.app_pass)]);
    dt674_emit(log, [NSString stringWithFormat:@"CASE_B_672_HELPER=%@",
        dt674_case_label(caseB.app_pass)]);
    dt674_emit(log, [NSString stringWithFormat:@"CASE_C_DIRECT_TOOL=%@",
        dt674_case_label(caseC.app_pass)]);

    dt674_log(log, @"CASE_A_ATTACH_PROFILE=KERNEL_MANUAL");
    dt674_log(log, @"CASE_B_ATTACH_PROFILE=KERNEL_MANUAL");
    dt674_log(log, @"CASE_C_ATTACH_PROFILE=KERNEL_MANUAL");
    dt674_log(log, [NSString stringWithFormat:@"CASE_A_UNSIGNED=%@",
        caseA.app_pass ? @"NO" : @"OPEN"]);
    dt674_log(log, [NSString stringWithFormat:@"CASE_B_UNSIGNED=%@",
        caseB.app_pass ? @"NO" : @"OPEN"]);
    dt674_log(log, [NSString stringWithFormat:@"CASE_C_UNSIGNED=%@",
        caseC.app_pass ? @"NO" : @"OPEN"]);

    dt674_emit(log, @"KERNEL_BUCKET_CLASSIFIER=MANUAL_FROM_KERNEL_LOG");

    rootCause = dt674_root_cause_class(caseA.app_pass, caseB.app_pass, caseC.app_pass);
    dt674_emit_decision_matrix(log, caseA.app_pass, caseB.app_pass, caseC.app_pass);
    dt674_emit(log, [NSString stringWithFormat:@"ROOT_CAUSE_CLASS=%@", rootCause]);
    dt674_emit(log, [NSString stringWithFormat:@"NEXT=%@", dt674_next_step(rootCause)]);

    if (caseA.app_pass && !caseB.app_pass && caseC.app_pass)
        dt674_emit(log, @"APP_DIRECT_TOOL_SPAWN_PRECHECK=PASS");
    else
        dt674_emit(log, @"APP_DIRECT_TOOL_SPAWN_PRECHECK=NOT_RUN_OR_FAIL");

    dt674_emit(log, @"APP_DIRECT_TOOL_SPAWN_ARCHITECTURE=NOT_AUTHORIZED");
    dt674_emit(log, @"BUILD_READY=YES_FOR_MANUAL_674_A_B_C_DIFFERENTIAL");

    summary = [NSString stringWithFormat:
        @"674 A/B/C A=%@ B=%@ C=%@ ROOT=%@",
        dt674_case_label(caseA.app_pass),
        dt674_case_label(caseB.app_pass),
        dt674_case_label(caseC.app_pass),
        rootCause];
    dt674_emit(log, @"KCALL674_RESULT=OK");

finish:
    if (!preflightOk || detail.length) {
        if (detail.length)
            dt674_log(log, [NSString stringWithFormat:@"[*] build674 detail=%@", detail]);
        if (!caseC.ran || !caseB.ran || !caseA.ran || !preflightOk)
            dt674_emit(log, @"KCALL674_RESULT=FAIL");
        if (!preflightOk)
            dt674_emit(log, @"BUILD_READY=NO");
    }
    if (summaryOut)
        *summaryOut = summary;
    return (caseA.ran && caseB.ran && caseC.ran && preflightOk) ? 0 : -1;
}
