#import "dt_build653_client.h"

#import "DTRunLogger.h"
#import "dt_physrw.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"

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

static NSString *const kDT653HelperBundledRel = @"Handoff653/dt_direct653_helper";
static NSString *const kDT653HelperInstalled =
    @"/private/var/jb/usr/bin/dt_direct653_helper";
static NSString *const kDT672ToolBundledRel = @"Handoff672/dt_tool672_probe";
static NSString *const kDT672ToolInstalled =
    @"/private/var/jb/usr/bin/dt_tool672_probe";

typedef void (^dt653_log_fn)(NSString *line);
typedef int (*dt653_spawn_fn)(pid_t *, const char *,
                              const posix_spawn_file_actions_t *,
                              const posix_spawnattr_t *,
                              char *const[], char *const[]);
typedef int (*dt653_spawn_fa_init_fn)(posix_spawn_file_actions_t *);
typedef int (*dt653_spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
typedef int (*dt653_spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
typedef int (*dt653_spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

static void dt653_log(dt653_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt653_emit(dt653_log_fn log, NSString *marker)
{
    dt653_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

static BOOL dt653_mkdir_p(NSString *path, mode_t mode)
{
    if (!path.length)
        return NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:path])
        return YES;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length && ![parent isEqualToString:path])
        (void)dt653_mkdir_p(parent, mode);
    return mkdir(path.fileSystemRepresentation, mode) == 0 || errno == EEXIST;
}

static BOOL dt653_is_directory(NSString *path)
{
    struct stat st;
    if (stat(path.fileSystemRepresentation, &st) != 0)
        return NO;
    return S_ISDIR(st.st_mode);
}

static BOOL dt653_platform_flag_set(dt653_log_fn log)
{
    uint32_t csflags = 0;
    int csErr = csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    dt653_log(log, [NSString stringWithFormat:@"KCALL653_CSOPS_RET=%d csflags=0x%x",
        csErr, csflags]);
    if (csErr != 0)
        return NO;
    return (csflags & CS_PLATFORM_BINARY) != 0;
}

static BOOL dt653_trust_helper(NSString *path, dt653_log_fn log, NSString **detailOut)
{
    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0) {
        if (detailOut)
            *detailOut = @"helper cdhash extract failed";
        return NO;
    }

    cdhash_t *hashes = calloc(1, sizeof(cdhash_t));
    if (!hashes) {
        if (detailOut)
            *detailOut = @"cdhash alloc failed";
        return NO;
    }
    memcpy(hashes[0], hash, sizeof(cdhash_t));

    uint32_t uploaded = 0;
    uint32_t skipped = 0;
    int r = dt_trustcache_upload_cdhashes(hashes, 1, &uploaded, &skipped);
    if (r == 0 && !dt_cdhash_trustcached(hashes[0]))
        r = EIO;
    free(hashes);

    dt653_log(log, [NSString stringWithFormat:
        @"KCALL653_TRUSTCACHE_RESULT=%d uploaded=%u skipped=%u", r, uploaded, skipped]);

    if (r != 0 && detailOut)
        *detailOut = @"trustcache upload/verify failed";
    return r == 0;
}

static BOOL dt653_copy_helper(dt653_log_fn log, NSString **detailOut)
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:kDT653HelperBundledRel];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:bundled]) {
        if (detailOut)
            *detailOut = @"bundled dt_direct653_helper missing or not executable";
        return NO;
    }

    if (!dt653_mkdir_p(@"/private/var/jb/usr/bin", 0755)) {
        if (detailOut)
            *detailOut = @"jbroot mkdir failed";
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:kDT653HelperInstalled error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:bundled toPath:kDT653HelperInstalled error:&copyErr]) {
        if (detailOut)
            *detailOut = copyErr.localizedDescription ?: @"helper copy failed";
        return NO;
    }

    dt653_emit(log, @"KCALL653_STAGE_HELPER_COPY_OK");

    if (chmod(kDT653HelperInstalled.fileSystemRepresentation, 0755) != 0) {
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"chmod failed errno=%d", errno];
        return NO;
    }
    dt653_emit(log, @"KCALL653_STAGE_HELPER_CHMOD_OK");
    return YES;
}

static BOOL dt672_copy_tool(dt653_log_fn log, NSString **detailOut)
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:kDT672ToolBundledRel];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:bundled]) {
        if (detailOut)
            *detailOut = @"bundled dt_tool672_probe missing or not executable";
        return NO;
    }

    if (!dt653_mkdir_p(@"/private/var/jb/usr/bin", 0755)) {
        if (detailOut)
            *detailOut = @"jbroot mkdir failed";
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:kDT672ToolInstalled error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:bundled toPath:kDT672ToolInstalled error:&copyErr]) {
        if (detailOut)
            *detailOut = copyErr.localizedDescription ?: @"tool copy failed";
        return NO;
    }

    dt653_emit(log, @"KCALL672_STAGE_TOOL_COPY_OK");

    if (chmod(kDT672ToolInstalled.fileSystemRepresentation, 0755) != 0) {
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"tool chmod failed errno=%d", errno];
        return NO;
    }
    dt653_emit(log, @"KCALL672_STAGE_TOOL_CHMOD_OK");
    return YES;
}

static void dt653_log_helper_stdout_lines(dt653_log_fn log, NSString *text)
{
    NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:
        [NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        if (!line.length)
            continue;
        dt653_log(log, line);
    }
}

static BOOL dt653_pipe_complete(NSString *text, BOOL *alive653, BOOL *done653,
                                BOOL *worker661, BOOL *result661Ok,
                                BOOL *tool672, BOOL *result672Ok)
{
    if (alive653)
        *alive653 = [text containsString:@"KCALL653_HELPER_ALIVE=1"];
    if (done653)
        *done653 = [text containsString:@"KCALL653_HELPER_DONE=1"];
    if (worker661)
        *worker661 = [text containsString:@"KCALL661_READ_WORKER_DONE"];
    if (result661Ok)
        *result661Ok = [text containsString:@"KCALL661_RESULT=OK"];
    if (tool672)
        *tool672 = [text containsString:@"KCALL672_TOOL_DONE=1"];
    if (result672Ok)
        *result672Ok = [text containsString:@"KCALL672_RESULT=OK"];
    return text.length > 0;
}

static BOOL dt653_read_pipe_output(int readFd, double timeoutSec, NSMutableString **textOut,
                                   BOOL *alive653, BOOL *done653, BOOL *worker661,
                                   BOOL *result661Ok, BOOL *tool672, BOOL *result672Ok)
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

        BOOL a = NO, d = NO, w = NO, r661 = NO, t672 = NO, r672 = NO;
        if (dt653_pipe_complete(buf, &a, &d, &w, &r661, &t672, &r672) && a && d && w && r661 && t672 && r672)
            break;
    }

    if (textOut)
        *textOut = buf;
    dt653_pipe_complete(buf, alive653, done653, worker661, result661Ok, tool672, result672Ok);
    return buf.length > 0;
}

static void dt653_emit_kernel_review_checklist(dt653_log_fn log)
{
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_BEGIN");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_P9=failed to set executable path");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_P6=failed to upcall to containermanagerd for a platform app");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_P7=attempting to use a container without a code signing identity");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_P8=outside of container && not a driver && !i_can_has_debugger");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_OP129=process-exec denied while updating label");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_LAUNCHD=only launchd is allowed to spawn untrusted binaries");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_SB_KILL=Sandbox: hook..execve() killing");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_AMFI=AMFI: hook..execve() killing");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_ATTACH_OK=%s[%d] ==> container");
    dt653_log(log, @"KCALL653_KERNEL_REVIEW_END");
}

static void dt653_classify(dt653_log_fn log, int spawnRet, int spawnErrno, pid_t childPid,
                           BOOL stdoutPresent, BOOL markerAlive, BOOL markerDone,
                           BOOL waitOk, int waitStatus)
{
    if (spawnRet == 0 && childPid > 0)
        dt653_emit(log, @"KCALL653_CLASS_USERSPACE_SPAWN_OK");
    else
        dt653_emit(log, @"KCALL653_CLASS_USERSPACE_SPAWN_FAIL");

    dt653_log(log, [NSString stringWithFormat:@"KCALL653_CLASS_SPAWN_ERRNO=%d", spawnErrno]);

    if (stdoutPresent)
        dt653_emit(log, @"KCALL653_CLASS_HELPER_STDOUT_PRESENT");
    else
        dt653_emit(log, @"KCALL653_CLASS_HELPER_STDOUT_MISSING");

    if (markerAlive && markerDone)
        dt653_emit(log, @"KCALL653_CLASS_HELPER_MARKER_PRESENT");
    else if (markerAlive)
        dt653_emit(log, @"KCALL653_CLASS_HELPER_MARKER_PARTIAL");
    else
        dt653_emit(log, @"KCALL653_CLASS_HELPER_MARKER_MISSING");

    if (!waitOk)
        dt653_emit(log, @"KCALL653_CLASS_HELPER_WAIT_TIMEOUT");
    else if (WIFEXITED(waitStatus))
        dt653_log(log, [NSString stringWithFormat:@"KCALL653_CLASS_CHILD_EXIT=%d",
            WEXITSTATUS(waitStatus)]);
    else
        dt653_emit(log, @"KCALL653_CLASS_CHILD_SIGNAL");

    dt653_emit_kernel_review_checklist(log);
}

static void dt661_classify_run(dt653_log_fn log, BOOL worker661, BOOL result661Ok)
{
    if (worker661)
        dt653_emit(log, @"KCALL661_READ_WORKER_CAPTURE_OK");
    else
        dt653_emit(log, @"KCALL661_READ_WORKER_CAPTURE_FAIL");

    if (result661Ok)
        dt653_emit(log, @"KCALL661_PIPE_OK=1");
    else
        dt653_emit(log, @"KCALL661_PIPE_OK=0");
}

static void dt672_classify_run(dt653_log_fn log, BOOL tool672, BOOL result672Ok)
{
    if (tool672)
        dt653_emit(log, @"KCALL672_TOOL_STDOUT_CAPTURE_OK");
    else
        dt653_emit(log, @"KCALL672_TOOL_STDOUT_CAPTURE_FAIL");

    if (result672Ok)
        dt653_emit(log, @"KCALL672_PIPE_OK=1");
    else
        dt653_emit(log, @"KCALL672_PIPE_OK=0");
}

BOOL dt_build653_cleanup_staged(NSString **detailOut)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    if ([fm fileExistsAtPath:kDT653HelperInstalled]) {
        if (![fm removeItemAtPath:kDT653HelperInstalled error:&err]) {
            if (detailOut)
                *detailOut = err.localizedDescription ?: @"helper remove failed";
            return NO;
        }
    }
    if ([fm fileExistsAtPath:kDT672ToolInstalled]) {
        if (![fm removeItemAtPath:kDT672ToolInstalled error:&err]) {
            if (detailOut)
                *detailOut = err.localizedDescription ?: @"tool remove failed";
            return NO;
        }
    }
    [[DTRunLogger shared] log:@"KCALL653_CLEANUP_OK"];
    [[DTRunLogger shared] logStage:@"KCALL653_CLEANUP_OK"];
    return YES;
}

int dt_build653_run(void (^log)(NSString *line), NSString **verdictOut)
{
    return dt_build653_run_full(log, verdictOut, NULL, NULL);
}

int dt_build653_run_full(void (^log)(NSString *line), NSString **verdict653Out,
                         NSString **verdict661Out, NSString **verdict672Out)
{
    NSString *detail = nil;
    NSString *final653 = @"KCALL653_RESULT=FAIL";
    NSString *final661 = @"KCALL661_RESULT=FAIL";
    NSString *final672 = @"KCALL672_RESULT=FAIL";
    NSMutableString *helperOut = nil;
    int pipefd[2] = { -1, -1 };
    if (verdict653Out)
        *verdict653Out = final653;
    if (verdict661Out)
        *verdict661Out = final661;
    if (verdict672Out)
        *verdict672Out = final672;

    dt653_emit(log, @"KCALL653_BEGIN");
    dt653_emit(log, @"KCALL661_BEGIN");
    dt653_emit(log, @"KCALL672_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        detail = @"kfd not active";
        dt653_log(log, @"KCALL653_PREFLIGHT_KFD_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_KFD_OK");

    if (getuid() != 0) {
        detail = @"requires uid=0";
        dt653_log(log, @"KCALL653_PREFLIGHT_UID0_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_UID0_OK");

    if (getgid() != 0) {
        detail = @"requires gid=0";
        dt653_log(log, @"KCALL653_PREFLIGHT_GID0_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_GID0_OK");

    if (!dt653_platform_flag_set(log)) {
        detail = @"CS_PLATFORM_BINARY not set — run exploit/platformize first";
        dt653_log(log, @"KCALL653_PREFLIGHT_PLATFORM_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_PLATFORM_OK");

    if (!dt653_is_directory(@"/private/var/jb")) {
        detail = @"/private/var/jb missing — run G2 extract first";
        dt653_log(log, @"KCALL653_PREFLIGHT_JBROOT_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_JBROOT_OK");

    if (!dt653_mkdir_p(@"/private/var/jb/usr/bin", 0755)) {
        detail = @"/private/var/jb/usr/bin mkdir failed";
        goto finish;
    }

    if (!dt653_copy_helper(log, &detail))
        goto finish;

    if (!dt672_copy_tool(log, &detail))
        goto finish;

    if (![[NSFileManager defaultManager] fileExistsAtPath:kDT653HelperInstalled]) {
        detail = @"staged helper missing after copy";
        dt653_log(log, @"KCALL653_PREFLIGHT_HELPER_EXISTS=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_HELPER_EXISTS");

    if (![[NSFileManager defaultManager] isExecutableFileAtPath:kDT653HelperInstalled]) {
        detail = @"staged helper not executable";
        dt653_log(log, @"KCALL653_PREFLIGHT_HELPER_X_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_HELPER_X_OK");

    if (![[NSFileManager defaultManager] fileExistsAtPath:kDT672ToolInstalled]) {
        detail = @"staged tool missing after copy";
        dt653_log(log, @"KCALL672_PREFLIGHT_TOOL_EXISTS=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL672_PREFLIGHT_TOOL_EXISTS");

    if (![[NSFileManager defaultManager] isExecutableFileAtPath:kDT672ToolInstalled]) {
        detail = @"staged tool not executable";
        dt653_log(log, @"KCALL672_PREFLIGHT_TOOL_X_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL672_PREFLIGHT_TOOL_X_OK");

    if (!dt653_trust_helper(kDT653HelperInstalled, log, &detail)) {
        dt653_log(log, @"KCALL653_PREFLIGHT_TRUSTCACHE_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PREFLIGHT_TRUSTCACHE_OK");

    if (!dt653_trust_helper(kDT672ToolInstalled, log, &detail)) {
        dt653_log(log, @"KCALL672_PREFLIGHT_TRUSTCACHE_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL672_PREFLIGHT_TRUSTCACHE_OK");

    dt653_spawn_fn spawn = (dt653_spawn_fn)dlsym(RTLD_DEFAULT, "posix_spawn");
    dt653_spawn_fa_init_fn fa_init =
        (dt653_spawn_fa_init_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_init");
    dt653_spawn_fa_destroy_fn fa_destroy =
        (dt653_spawn_fa_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
    dt653_spawn_fa_adddup2_fn fa_dup2 =
        (dt653_spawn_fa_adddup2_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_adddup2");
    dt653_spawn_fa_addclose_fn fa_close =
        (dt653_spawn_fa_addclose_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_addclose");
    if (!spawn) {
        detail = @"posix_spawn unavailable";
        goto finish;
    }
    if (!fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
        detail = @"posix_spawn_file_actions unavailable (dlsym)";
        goto finish;
    }

    if (pipe(pipefd) != 0) {
        detail = [NSString stringWithFormat:@"pipe create failed errno=%d", errno];
        dt653_log(log, @"KCALL653_PIPE_CREATE_OK=0");
        goto finish;
    }
    dt653_emit(log, @"KCALL653_PIPE_CREATE_OK");

    posix_spawn_file_actions_t actions;
    if (fa_init(&actions) != 0) {
        detail = @"posix_spawn_file_actions_init failed";
        close(pipefd[0]);
        close(pipefd[1]);
        goto finish;
    }
    (void)fa_close(&actions, pipefd[0]);
    (void)fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
    (void)fa_dup2(&actions, pipefd[1], STDERR_FILENO);
    (void)fa_close(&actions, pipefd[1]);

    dt653_emit(log, @"KCALL653_SPAWN_BEGIN");

    char *argv[] = {
        (char *)kDT653HelperInstalled.UTF8String,
        NULL
    };
    pid_t childPid = 0;
    int spawnRet = spawn(&childPid, kDT653HelperInstalled.UTF8String, &actions, NULL, argv, environ);
    fa_destroy(&actions);
    close(pipefd[1]);

    int spawnErrno = spawnRet != 0 ? errno : 0;

    dt653_log(log, [NSString stringWithFormat:@"KCALL653_SPAWN_RET=%d", spawnRet]);
    dt653_log(log, [NSString stringWithFormat:@"KCALL653_SPAWN_ERRNO=%d", spawnErrno]);
    dt653_log(log, [NSString stringWithFormat:@"KCALL653_CHILD_PID=%d", (int)childPid]);

    BOOL stdoutPresent = NO;
    BOOL markerAlive = NO;
    BOOL markerDone = NO;
    BOOL worker661 = NO;
    BOOL result661Ok = NO;
    BOOL tool672 = NO;
    BOOL result672Ok = NO;
    BOOL waitOk = NO;
    int waitStatus = 0;
    if (spawnRet == 0 && childPid > 0) {
        dt653_emit(log, @"KCALL653_PIPE_SPAWN_STDOUT_OK");
        dt653_emit(log, @"KCALL653_HELPER_STDOUT_BEGIN");

        stdoutPresent = dt653_read_pipe_output(pipefd[0], 20.0, &helperOut, &markerAlive,
                                               &markerDone, &worker661, &result661Ok,
                                               &tool672, &result672Ok);
        if (helperOut.length)
            dt653_log_helper_stdout_lines(log, helperOut);

        dt653_emit(log, @"KCALL653_HELPER_STDOUT_END");
        close(pipefd[0]);
        pipefd[0] = -1;

        if (waitpid(childPid, &waitStatus, WNOHANG) == 0) {
            for (int i = 0; i < 40; i++) {
                if (waitpid(childPid, &waitStatus, WNOHANG) != 0) {
                    waitOk = YES;
                    break;
                }
                usleep(250000);
            }
            if (!waitOk)
                (void)waitpid(childPid, &waitStatus, 0);
            waitOk = YES;
        } else {
            waitOk = YES;
        }
    } else {
        close(pipefd[0]);
        pipefd[0] = -1;
    }

    dt653_classify(log, spawnRet, spawnErrno, childPid, stdoutPresent, markerAlive, markerDone,
                   waitOk, waitStatus);
    dt661_classify_run(log, worker661, result661Ok);
    dt672_classify_run(log, tool672, result672Ok);

    if (spawnRet == 0 && childPid > 0 && markerAlive && markerDone && waitOk &&
        WIFEXITED(waitStatus) && WEXITSTATUS(waitStatus) == 0) {
        final653 = @"KCALL653_RESULT=OK";
    } else {
        final653 = @"KCALL653_RESULT=FAIL";
        if (!detail.length) {
            if (spawnRet != 0)
                detail = [NSString stringWithFormat:@"posix_spawn failed errno=%d", spawnErrno];
            else if (!markerAlive || !markerDone)
                detail = @"helper stdout markers incomplete";
            else
                detail = @"spawn/wait/653 criteria not met";
        }
    }

    if (spawnRet == 0 && childPid > 0 && worker661 && result661Ok && waitOk &&
        WIFEXITED(waitStatus) && WEXITSTATUS(waitStatus) == 0) {
        final661 = @"KCALL661_RESULT=OK";
    } else if (spawnRet != 0 || childPid <= 0) {
        final661 = @"KCALL661_RESULT=FAIL";
        if (!detail.length)
            detail = @"661 spawn/pipe failed";
    } else if ([helperOut containsString:@"KCALL661_RESULT=FAIL"]) {
        final661 = @"KCALL661_RESULT=FAIL";
        if (!detail.length)
            detail = @"661 read worker reported FAIL";
    } else {
        final661 = @"KCALL661_RESULT=FAIL";
        if (!detail.length)
            detail = @"661 read worker sections incomplete";
    }

    if (spawnRet == 0 && childPid > 0 && tool672 && result672Ok && waitOk &&
        WIFEXITED(waitStatus) && WEXITSTATUS(waitStatus) == 0) {
        final672 = @"KCALL672_RESULT=OK";
    } else if (spawnRet != 0 || childPid <= 0) {
        final672 = @"KCALL672_RESULT=FAIL";
        if (!detail.length)
            detail = @"672 spawn/pipe failed";
    } else if ([helperOut containsString:@"KCALL672_RESULT=FAIL"]) {
        final672 = @"KCALL672_RESULT=FAIL";
        if (!detail.length)
            detail = @"672 tool runner reported FAIL";
    } else {
        final672 = @"KCALL672_RESULT=FAIL";
        if (!detail.length)
            detail = @"672 tool runner sections incomplete";
    }

finish:
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    if (detail.length)
        dt653_log(log, [NSString stringWithFormat:@"[*] build653/661/672 detail=%@", detail]);
    if (verdict653Out)
        *verdict653Out = final653;
    if (verdict661Out)
        *verdict661Out = final661;
    if (verdict672Out)
        *verdict672Out = final672;
    dt653_log(log, final653);
    dt653_log(log, final661);
    dt653_log(log, final672);
    dt653_emit(log, final672);
    return ([final653 isEqualToString:@"KCALL653_RESULT=OK"] &&
            [final661 isEqualToString:@"KCALL661_RESULT=OK"] &&
            [final672 isEqualToString:@"KCALL672_RESULT=OK"]) ? 0 : -1;
}
