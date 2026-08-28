#import "dt_build681_client.h"
#import "dt_build681_boomerang.h"
#import "dt_kcall_planb.h"
#import "dt_physrw.h"
#import "dt_build710_preboot.h"
#import "DTRunLogger.h"
#import "spawn_root.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"

#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <stdlib.h>
#import <string.h>
#import <poll.h>
#import <signal.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

static NSString *const kDT681HandoffBundledDir = @"Handoff516";
static NSString *const kDT681JbctlName = @"dt_jbctl516";
static NSString *const kDT681OpainjectName = @"dt_opainject516";
static NSString *const kDT681LaunchdhookName = @"launchdhook516.dylib";

typedef void (^dt681_log_fn)(NSString *line);

static int dt681_stage_basebin_impl(dt681_log_fn log, BOOL preserve_launchdhook);
static int dt681_upload_handoff_trustcache_impl(dt681_log_fn log, BOOL hook_trustcache_from_staged);
static int dt681_spawn_opainject_impl(const char *dylibPath, dt681_log_fn log, NSString **stderrOut);

static void dt681_log(dt681_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt681_emit(dt681_log_fn log, NSString *marker)
{
    dt681_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

static BOOL dt681_mkdir_p(NSString *path, mode_t mode)
{
    if (!path.length)
        return NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:path])
        return YES;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length && ![parent isEqualToString:path])
        (void)dt681_mkdir_p(parent, mode);
    return mkdir(path.fileSystemRepresentation, mode) == 0 || errno == EEXIST;
}

static NSString *dt681_bundled_artifact_path(NSString *name)
{
    return [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:[kDT681HandoffBundledDir stringByAppendingPathComponent:name]];
}

static BOOL dt681_copy_bundle_artifact(NSString *name, NSString *dest, dt681_log_fn log)
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:[kDT681HandoffBundledDir stringByAppendingPathComponent:name]];
    if (![[NSFileManager defaultManager] fileExistsAtPath:bundled]) {
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 missing bundle artifact %@", bundled]);
        return NO;
    }
    NSError *err = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:dest])
        [[NSFileManager defaultManager] removeItemAtPath:dest error:nil];
    if (![[NSFileManager defaultManager] copyItemAtPath:bundled toPath:dest error:&err]) {
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 copy %@ -> %@ err=%@",
            name, dest, err.localizedDescription]);
        return NO;
    }
    chmod(dest.fileSystemRepresentation, 0755);
    return YES;
}

int dt681_stage_handoff_basebin(void (^log)(NSString *line))
{
    return dt681_stage_basebin_impl(log, NO);
}

int dt681_stage_handoff_basebin_ex(void (^log)(NSString *line), BOOL preserve_launchdhook)
{
    return dt681_stage_basebin_impl(log, preserve_launchdhook);
}

int dt681_stage_basebin_impl(dt681_log_fn log, BOOL preserve_launchdhook)
{
    int r = dt710_stage_preboot_handoff_stack(log, preserve_launchdhook);
    if (r != 0)
        return r;
    dt681_emit(log, @"KCALL681_BASEBIN_STAGE_OK");
    dt681_emit(log, @"BUILD102710_PREBOOT_BASEBIN_STAGE_OK");
    return 0;
}

static int dt681_upload_path_trustcache(NSString *path, NSString *okMarker, dt681_log_fn log)
{
    if (!path.length || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 trustcache missing %@", path]);
        return -1;
    }

    cdhash_t cdhash = {0};
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, cdhash) != 0) {
        dt681_emit(log, @"KCALL681_TRUSTCACHE_CDHash_FAIL");
        return -2;
    }

    uint32_t uploaded = 0;
    int tc_r = dt_trustcache_upload_cdhashes_force(&cdhash, 1, &uploaded);
    if (tc_r != 0) {
        dt681_emit(log, [NSString stringWithFormat:@"KCALL681_TRUSTCACHE_UPLOAD_FAIL_%d", tc_r]);
        return tc_r;
    }
    if (!dt_cdhash_trustcached(cdhash)) {
        dt681_emit(log, @"KCALL681_TRUSTCACHE_VERIFY_FAIL");
        return -3;
    }

    dt681_emit(log, okMarker);
    return 0;
}

int dt681_upload_handoff_trustcache_impl(dt681_log_fn log, BOOL hook_trustcache_from_staged)
{
    /* Blueprint 681 §0c + device proof: jbroot spawn hits Wall-A @ 21:24:24.227516.
     * Default: trustcache from bundled Handoff516 paths.
     * BUILD102707 preserve mode: hook entry uses authoritative jbroot staged file. */
    static struct {
        NSString *name;
        NSString *okMarker;
    } const kItems[] = {
        { kDT681LaunchdhookName, @"KCALL681_TRUSTCACHE_LAUNCHDHOOK_OK" },
        { kDT681JbctlName, @"KCALL681_TRUSTCACHE_JBCTL_OK" },
        { kDT681OpainjectName, @"KCALL681_TRUSTCACHE_OPAINJECT_OK" },
    };

    for (size_t i = 0; i < sizeof(kItems) / sizeof(kItems[0]); i++) {
        NSString *tcPath = nil;
        if (hook_trustcache_from_staged && [kItems[i].name isEqualToString:kDT681LaunchdhookName])
            tcPath = dt710_resolve_hook_path();
        else
            tcPath = dt681_bundled_artifact_path(kItems[i].name);
        int tc_r = dt681_upload_path_trustcache(tcPath, kItems[i].okMarker, log);
        if (tc_r != 0)
            return tc_r;
    }

    if (dt710_upload_final_preboot_trust_closure(log, hook_trustcache_from_staged) != 0)
        return -710;

    dt681_emit(log, @"KCALL681_TRUSTCACHE_BASEBIN_OK");
    return 0;
}

typedef int (*dt681_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *, char *const[], char *const[]);
typedef int (*dt681_spawnattr_init_fn)(posix_spawnattr_t *);
typedef int (*dt681_spawnattr_destroy_fn)(posix_spawnattr_t *);
typedef int (*dt681_spawnattr_set_ports_fn)(posix_spawnattr_t *, mach_port_t[], uint32_t);
typedef int (*dt681_spawn_fa_init_fn)(posix_spawn_file_actions_t *);
typedef int (*dt681_spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
typedef int (*dt681_spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
typedef int (*dt681_spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

static BOOL dt681_load_spawn_shims(dt681_spawn_fn *spawnOut,
    dt681_spawnattr_init_fn *attrInitOut,
    dt681_spawnattr_destroy_fn *attrDestroyOut,
    dt681_spawnattr_set_ports_fn *setPortsOut,
    dt681_spawn_fa_init_fn *faInitOut,
    dt681_spawn_fa_destroy_fn *faDestroyOut,
    dt681_spawn_fa_adddup2_fn *faDup2Out,
    dt681_spawn_fa_addclose_fn *faCloseOut)
{
    void *lib = RTLD_DEFAULT;
    if (spawnOut)
        *spawnOut = (dt681_spawn_fn)dlsym(lib, "posix_spawn");
    if (attrInitOut)
        *attrInitOut = (dt681_spawnattr_init_fn)dlsym(lib, "posix_spawnattr_init");
    if (attrDestroyOut)
        *attrDestroyOut = (dt681_spawnattr_destroy_fn)dlsym(lib, "posix_spawnattr_destroy");
    if (setPortsOut)
        *setPortsOut = (dt681_spawnattr_set_ports_fn)dlsym(lib, "posix_spawnattr_set_registered_ports_np");
    if (faInitOut)
        *faInitOut = (dt681_spawn_fa_init_fn)dlsym(lib, "posix_spawn_file_actions_init");
    if (faDestroyOut)
        *faDestroyOut = (dt681_spawn_fa_destroy_fn)dlsym(lib, "posix_spawn_file_actions_destroy");
    if (faDup2Out)
        *faDup2Out = (dt681_spawn_fa_adddup2_fn)dlsym(lib, "posix_spawn_file_actions_adddup2");
    if (faCloseOut)
        *faCloseOut = (dt681_spawn_fa_addclose_fn)dlsym(lib, "posix_spawn_file_actions_addclose");
    return spawnOut && *spawnOut && attrInitOut && *attrInitOut && attrDestroyOut && *attrDestroyOut
        && faInitOut && *faInitOut && faDestroyOut && *faDestroyOut && faDup2Out && *faDup2Out
        && faCloseOut && *faCloseOut;
}

static void dt681_log_jbctl_stderr(dt681_log_fn log, NSString *text)
{
    if (!text.length)
        return;
    dt681_log(log, [NSString stringWithFormat:@"[*] build681 jbctl stderr: %@", text]);
    for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *trim = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (!trim.length)
            continue;
        if ([trim hasPrefix:@"STAGE "])
            trim = [trim substringFromIndex:6];
        if ([trim hasPrefix:@"KCALL681_JBCTL"])
            dt681_emit(log, trim);
    }
}

static int dt681_spawn_jbctl_stash(mach_port_t boomerangPort, dt681_log_fn log, NSString **stderrOut)
{
    dt681_spawn_fn spawn = NULL;
    dt681_spawnattr_init_fn attr_init = NULL;
    dt681_spawnattr_destroy_fn attr_destroy = NULL;
    dt681_spawnattr_set_ports_fn set_ports = NULL;
    dt681_spawn_fa_init_fn fa_init = NULL;
    dt681_spawn_fa_destroy_fn fa_destroy = NULL;
    dt681_spawn_fa_adddup2_fn fa_dup2 = NULL;
    dt681_spawn_fa_addclose_fn fa_close = NULL;

    if (!dt681_load_spawn_shims(&spawn, &attr_init, &attr_destroy, &set_ports,
            &fa_init, &fa_destroy, &fa_dup2, &fa_close)) {
        dt681_log(log, @"[!] build681 spawn shims unavailable");
        return -1;
    }

    posix_spawnattr_t attr;
    attr_init(&attr);
    if (set_ports) {
        mach_port_t ports[3] = { MACH_PORT_NULL, MACH_PORT_NULL, boomerangPort };
        set_ports(&attr, ports, 3);
    }

    int pipefd[2] = { -1, -1 };
    if (pipe(pipefd) != 0) {
        attr_destroy(&attr);
        return -1;
    }

    posix_spawn_file_actions_t fa;
    fa_init(&fa);
    fa_dup2(&fa, pipefd[1], STDERR_FILENO);
    fa_close(&fa, pipefd[0]);

    NSString *jbctlPath = dt681_bundled_artifact_path(kDT681JbctlName);
    if (![[NSFileManager defaultManager] fileExistsAtPath:jbctlPath]) {
        fa_destroy(&fa);
        attr_destroy(&attr);
        close(pipefd[1]);
        close(pipefd[0]);
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 missing bundled jbctl %@", jbctlPath]);
        return -4;
    }

    pid_t child = 0;
    const char *jbctl = jbctlPath.UTF8String;
    char *const argv[] = { (char *const)jbctl, (char *)"internal", (char *)"launchd_stash_port", NULL };

    dt681_log(log, [NSString stringWithFormat:@"[*] build681 jbctl spawn path=%@", jbctlPath]);
    int spawn_r = spawn(&child, jbctl, &fa, &attr, argv, environ);
    fa_destroy(&fa);
    attr_destroy(&attr);
    close(pipefd[1]);

    if (spawn_r != 0) {
        close(pipefd[0]);
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 jbctl spawn errno=%d", errno]);
        return spawn_r;
    }

    NSMutableData *errData = [NSMutableData data];
    char buf[512];
    int status = 0;
    pid_t waited = 0;
    const int kJbctlWaitMs = 8000;
    int elapsedMs = 0;

    while (elapsedMs < kJbctlWaitMs) {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child)
            break;
        if (waited < 0 && errno != EINTR) {
            close(pipefd[0]);
            return -2;
        }

        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
        int pr = poll(&pfd, 1, 100);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = read(pipefd[0], buf, sizeof(buf));
            if (n > 0)
                [errData appendBytes:buf length:(NSUInteger)n];
        }
        elapsedMs += 100;
    }

    if (waited != child) {
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) == -1) {
            if (errno != EINTR) {
                close(pipefd[0]);
                return -2;
            }
        }
        while (read(pipefd[0], buf, sizeof(buf)) > 0) { }
        close(pipefd[0]);
        if (errData.length)
            dt681_log_jbctl_stderr(log, [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding]);
        dt681_log(log, @"[!] build681 jbctl wait timeout=8000ms (likely task_for_pid/mach_ports_register block)");
        return -5;
    }

    ssize_t n = 0;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        [errData appendBytes:buf length:(NSUInteger)n];
    close(pipefd[0]);

    NSString *stderrText = errData.length
        ? [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding] : nil;
    if (stderrText.length)
        dt681_log_jbctl_stderr(log, stderrText);
    if (stderrOut && stderrText.length)
        *stderrOut = stderrText;

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFSIGNALED(status)) {
            dt681_log(log, [NSString stringWithFormat:
                @"[!] build681 jbctl signal=%d status=0x%x (Wall-A=SIGKILL/9)",
                WTERMSIG(status), status]);
        } else {
            dt681_log(log, [NSString stringWithFormat:@"[!] build681 jbctl exit status=0x%x", status]);
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : -3;
    }

    dt681_emit(log, @"KCALL681_JBCTL_STASH_PORT_OK");
    return 0;
}

int dt681_spawn_opainject_impl(const char *dylibPath, dt681_log_fn log, NSString **stderrOut)
{
    NSString *opainjectPath = dt681_bundled_artifact_path(kDT681OpainjectName);
    if (![[NSFileManager defaultManager] fileExistsAtPath:opainjectPath]) {
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 missing bundled opainject %@", opainjectPath]);
        return -4;
    }

    dt681_log(log, [NSString stringWithFormat:@"[*] build681 opainject spawn path=%@", opainjectPath]);
    int exitStatus = 0;
    int waitStatus = -1;
    NSString *capture = nil;
    NSError *err = nil;
#if DT_BUILD_NUM == 102734 || DT_BUILD_NUM == 102736
    int r = dt_spawn_plain_capture_status(opainjectPath,
        @[
            @"1",
            [NSString stringWithUTF8String:dylibPath],
            @"post-consume",
        ],
        &exitStatus, &waitStatus, &capture, &err);
#if DT_BUILD_NUM == 102736
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102736C_OPAINJECT_WAIT_STATUS=%d", waitStatus]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102736C_OPAINJECT_EXIT_CODE=%d", exitStatus]);
#else
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102734C_OPAINJECT_WAIT_STATUS=%d", waitStatus]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102734C_OPAINJECT_EXIT_CODE=%d", exitStatus]);
#endif
#else
    int r = dt_spawn_plain_capture(opainjectPath,
        @[
            @"1",
            [NSString stringWithUTF8String:dylibPath],
            @"post-consume",
        ],
        &exitStatus, &capture, &err);
#endif
    if (stderrOut && capture.length)
        *stderrOut = capture;
    if (r != 0) {
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 opainject spawn err=%@", err]);
        return r;
    }

    if (capture.length) {
        if ([capture containsString:@"KCALL681_OPAINJECT_SKIP_SANDBOX_POST_KCALL"])
            dt681_emit(log, @"KCALL681_OPAINJECT_SKIP_SANDBOX_POST_KCALL");
        if ([capture containsString:@"KCALL681_REMOTE_DLOPEN_WORKING"])
            dt681_emit(log, @"KCALL681_REMOTE_DLOPEN_WORKING");
        if ([capture containsString:@"KCALL681_FILE_MAP_EXECUTABLE_BLOCKED"])
            dt681_emit(log, @"KCALL681_FILE_MAP_EXECUTABLE_BLOCKED");
    }

    if (exitStatus != 0) {
        dt681_log(log, [NSString stringWithFormat:@"[!] build681 opainject exit=%d", exitStatus]);
        return exitStatus;
    }
    return 0;
}

int dt681_upload_handoff_trustcache(void (^log)(NSString *line))
{
    return dt681_upload_handoff_trustcache_impl(log, NO);
}

int dt681_upload_handoff_trustcache_ex(void (^log)(NSString *line), BOOL hook_trustcache_from_staged)
{
    return dt681_upload_handoff_trustcache_impl(log, hook_trustcache_from_staged);
}

int dt681_upload_jbctl_opainject_trustcache(void (^log)(NSString *line))
{
    static struct {
        NSString *name;
        NSString *okMarker;
    } const kItems[] = {
        { kDT681JbctlName, @"KCALL681_TRUSTCACHE_JBCTL_OK" },
        { kDT681OpainjectName, @"KCALL681_TRUSTCACHE_OPAINJECT_OK" },
    };

    for (size_t i = 0; i < sizeof(kItems) / sizeof(kItems[0]); i++) {
        NSString *bundled = dt681_bundled_artifact_path(kItems[i].name);
        int tc_r = dt681_upload_path_trustcache(bundled, kItems[i].okMarker, log);
        if (tc_r != 0)
            return tc_r;
    }

    dt681_emit(log, @"KCALL681_TRUSTCACHE_JBCTL_OPAINJECT_OK");
    return 0;
}

int dt681_spawn_opainject_launchd(const char *dylibPath, void (^log)(NSString *line),
    NSString **captureOut)
{
    return dt681_spawn_opainject_impl(dylibPath, log, captureOut);
}

int dt681_observe_launchd_counter(const char *hookPath, void (^log)(NSString *line),
    NSString **captureOut)
{
    NSString *opainjectPath = dt681_bundled_artifact_path(kDT681OpainjectName);
    if (!hookPath || ![[NSFileManager defaultManager] fileExistsAtPath:opainjectPath])
        return -1;
    int exitStatus = 0;
    NSString *capture = nil;
    NSError *err = nil;
    dt681_emit(log, @"BUILD102739A_POST_WALL2_OBSERVER_SPAWN_BEGIN");
    int spawnRc = dt_spawn_plain_capture(opainjectPath,
        @[ @"1", [NSString stringWithUTF8String:hookPath], @"observe-counter" ],
        &exitStatus, &capture, &err);
    if (captureOut)
        *captureOut = capture;
    if (capture.length) {
        for (NSString *line in [capture componentsSeparatedByCharactersInSet:
                [NSCharacterSet newlineCharacterSet]]) {
            if ([line hasPrefix:@"BUILD102739A_"])
                dt681_emit(log, line);
        }
    }
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739A_OBSERVER_SPAWN_RC=%d", spawnRc]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739A_OBSERVER_EXIT_CODE=%d", exitStatus]);
    if (spawnRc != 0) {
        dt681_log(log, [NSString stringWithFormat:@"[!] 102739A observer spawn err=%@", err]);
        return spawnRc;
    }
    return exitStatus;
}

int dt681_observe_launchd_return_telemetry(const char *hookPath,
    void (^log)(NSString *line), NSString **captureOut)
{
    NSString *opainjectPath = dt681_bundled_artifact_path(kDT681OpainjectName);
    if (!hookPath || ![[NSFileManager defaultManager] fileExistsAtPath:opainjectPath])
        return -1;
    int exitStatus = 0;
    NSString *capture = nil;
    NSError *err = nil;
    dt681_emit(log, @"BUILD102739B_POST_WALL2_OBSERVER_SPAWN_BEGIN");
    int spawnRc = dt_spawn_plain_capture(opainjectPath,
        @[ @"1", [NSString stringWithUTF8String:hookPath], @"observe-counter" ],
        &exitStatus, &capture, &err);
    if (captureOut)
        *captureOut = capture;
    if (capture.length) {
        for (NSString *line in [capture componentsSeparatedByCharactersInSet:
                [NSCharacterSet newlineCharacterSet]]) {
            if ([line hasPrefix:@"BUILD102739B_"])
                dt681_emit(log, line);
        }
    }
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739B_OBSERVER_SPAWN_RC=%d",
        spawnRc]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739B_OBSERVER_EXIT_CODE=%d",
        exitStatus]);
    if (spawnRc != 0) {
        dt681_log(log, [NSString stringWithFormat:@"[!] 102739B observer spawn err=%@",
            err]);
        return spawnRc;
    }
    return exitStatus;
}

int dt681_observe_launchd_output_telemetry(const char *hookPath,
    void (^log)(NSString *line), NSString **captureOut)
{
    NSString *opainjectPath = dt681_bundled_artifact_path(kDT681OpainjectName);
    if (!hookPath || ![[NSFileManager defaultManager] fileExistsAtPath:opainjectPath])
        return -1;
    int exitStatus = 0;
    NSString *capture = nil;
    NSError *err = nil;
    dt681_emit(log, @"BUILD102739C_POST_WALL2_OBSERVER_SPAWN_BEGIN");
    int spawnRc = dt_spawn_plain_capture(opainjectPath,
        @[ @"1", [NSString stringWithUTF8String:hookPath], @"observe-counter" ],
        &exitStatus, &capture, &err);
    if (captureOut)
        *captureOut = capture;
#ifdef DT_BUILD102739J_VARIANT
    NSUInteger captureBytes = [capture lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739J_OBSERVER_CAPTURE_BYTES=%lu",
        (unsigned long)captureBytes]);
    dt681_emit(log, @"BUILD102739J_OBSERVER_CAPTURE_TRUNCATED=NO");
#endif
    if (capture.length) {
        for (NSString *line in [capture componentsSeparatedByCharactersInSet:
                [NSCharacterSet newlineCharacterSet]]) {
#ifdef DT_BUILD102739J_VARIANT
            if ([line hasPrefix:@"BUILD102739J_"])
                dt681_emit(log, line);
            else
#endif
            if ([line hasPrefix:@"BUILD102739C_"])
                dt681_emit(log, line);
#ifdef DT_BUILD102739D_VARIANT
            else if ([line hasPrefix:@"BUILD102739D_"])
                dt681_emit(log, line);
#endif
#ifdef DT_BUILD102739E_VARIANT
            else if ([line hasPrefix:@"BUILD102739E_"])
                dt681_emit(log, line);
#endif
#ifdef DT_BUILD102739F_VARIANT
            else if ([line hasPrefix:@"BUILD102739F_"])
                dt681_emit(log, line);
#endif
        }
    }
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739C_OBSERVER_SPAWN_RC=%d",
        spawnRc]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739C_OBSERVER_EXIT_CODE=%d",
        exitStatus]);
#ifdef DT_BUILD102739D_VARIANT
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739D_OBSERVER_SPAWN_RC=%d",
        spawnRc]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739D_OBSERVER_EXIT_CODE=%d",
        exitStatus]);
#endif
#ifdef DT_BUILD102739F_VARIANT
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739F_OBSERVER_SPAWN_RC=%d",
        spawnRc]);
    dt681_emit(log, [NSString stringWithFormat:@"BUILD102739F_OBSERVER_EXIT_CODE=%d",
        exitStatus]);
#endif
    if (spawnRc != 0) {
        dt681_log(log, [NSString stringWithFormat:@"[!] 102739C observer spawn err=%@",
            err]);
        return spawnRc;
    }
    return exitStatus;
}

int dt_build681_run_phase6_1(void (^log)(NSString *line), NSString **verdictOut)
{
    dt681_emit(log, @"KCALL681_PHASE6_1_BEGIN");

    if (!dt_kernel_exploit_is_active()) {
        if (verdictOut)
            *verdictOut = @"KCALL681_KFD_INACTIVE";
        return -1;
    }

    if (dt681_stage_basebin_impl(log, NO) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL681_BASEBIN_STAGE_FAIL";
        return -2;
    }

    if (dt681_upload_handoff_trustcache_impl(log, NO) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL681_TRUSTCACHE_FAIL";
        return -3;
    }

    /* Step 0d TFP1: verified in jbctl/opainject children, not the sideloaded app (678 §1.1). */

    dt681_boomerang_info_t boomerang = {0};
    if (dt681_boomerang_start(&boomerang, log) != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL681_BOOMERANG_START_FAIL";
        return -5;
    }

    if (!dt710_verify_path_coherence(log)) {
        if (verdictOut)
            *verdictOut = @"BUILD102710_PATH_COHERENCE_FAIL";
        dt681_boomerang_cleanup(&boomerang);
        return -10;
    }

    const char *dylibPath = dt710_resolve_hook_path().fileSystemRepresentation;

    /*
     * Dopamine injectLaunchdHook order (678 §1.1 / DOJailbreaker.m): jbctl stash on
     * stock launchd, then opainject. tvOS kcall 53D540+55106C replaces opainject
     * sandboxFixup and must run after stash, before opainject — not before jbctl.
     * Kernel IDA: AMFI task_for_pid gate @ 0xFFFFFFF005C89F88 checks caller
     * entitlements only; leaving cfprefsd on launchd pre-stash poisons bgioq (~19s
     * sync deny → 0xFFFFFFF0075F12C0 panic) per Run C/D device + 540F44 audit loop.
     */
    dt681_emit(log, @"KCALL681_JBCTL_BEFORE_KERNEL_PREINJECT");
    NSString *stashVerdict = nil;
    if (dt681_kcall_stash_boomerang_port(boomerang.serverPort, log, &stashVerdict) != 0) {
        if (verdictOut)
            *verdictOut = stashVerdict ?: @"KCALL684_KCALL_STASH_FAIL";
        dt681_boomerang_cleanup(&boomerang);
        return -7;
    }

    NSString *kernelVerdict = nil;
    if (dt681_launchd_sandbox_unblock(dylibPath, log, &kernelVerdict) != 0) {
        if (verdictOut)
            *verdictOut = kernelVerdict ?: @"KCALL681_KERNEL_PREINJECT_FAIL";
        dt681_boomerang_cleanup(&boomerang);
        return -6;
    }

    NSString *injectErr = nil;
    if (dt681_spawn_opainject_impl(dylibPath, log, &injectErr) != 0) {
        if (injectErr.length)
            dt681_log(log, [NSString stringWithFormat:@"[*] build681 opainject stderr: %@", injectErr]);
        if (verdictOut)
            *verdictOut = @"KCALL681_OPAINJECT_FAIL";
        dt681_boomerang_cleanup(&boomerang);
        return -8;
    }

    int wait_r = dt681_boomerang_wait(&boomerang, log);
    dt681_boomerang_cleanup(&boomerang);

    if (wait_r != 0) {
        if (verdictOut)
            *verdictOut = @"KCALL681_BOOMERANG_TIMEOUT";
        return -9;
    }

    if (verdictOut)
        *verdictOut = @"KCALL681_PHASE6_1_PASS";
    dt681_emit(log, @"KCALL681_PHASE6_1_PASS");
    return 0;
}
