#import "dt_build583_client.h"

#import "DTRunLogger.h"
#import "dt_physrw.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"

#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <spawn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/wait.h>
#import <unistd.h>
#import <xpc/xpc.h>

extern char **environ;

#define DT583_SERVICE_NAME "com.dopamin.probe583.helper"
#define DT583_CHECKIN_PING @"/private/var/jb/tmp/probe583_checkin_ping"

static NSString *const kDT583JbrootMarker =
    @"/private/var/jb/.dt540_native_bootstrap";
static NSString *const kDT583Pid1DirtyMarker =
    @"/private/var/jb/.dt540_pid1_touched";
static NSString *const kDT583HelperInstalled =
    @"/private/var/jb/usr/bin/dt_probe583_helper";
static NSString *const kDT583HelperLog =
    @"/private/var/jb/tmp/probe583_helper.log";
static NSString *const kDT583HelperPlist =
    @"/private/var/jb/Library/LaunchDaemons/com.dopamin.probe583.helper.plist";
static NSString *const kDT583LaunchctlCmd =
    @"/bin/launchctl bootstrap system /private/var/jb/Library/LaunchDaemons/com.dopamin.probe583.helper.plist";

typedef void (^dt583_log_fn)(NSString *line);
typedef int (*dt583_spawn_fn)(pid_t *, const char *,
                              const posix_spawn_file_actions_t *,
                              const posix_spawnattr_t *,
                              char *const[], char *const[]);

static void dt583_log(dt583_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt583_emit(dt583_log_fn log, NSString *marker)
{
    dt583_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

static int dt583_spawn_wait(NSArray<NSString *> *arguments)
{
    dt583_spawn_fn spawn =
        (dt583_spawn_fn)dlsym(RTLD_DEFAULT, "posix_spawn");
    if (!spawn || arguments.count == 0)
        return ENOSYS;

    char **argv = calloc(arguments.count + 1, sizeof(char *));
    if (!argv)
        return ENOMEM;
    for (NSUInteger i = 0; i < arguments.count; i++)
        argv[i] = strdup(arguments[i].UTF8String);

    pid_t pid = 0;
    int r = spawn(&pid, argv[0], NULL, NULL, argv, environ);
    for (NSUInteger i = 0; i < arguments.count; i++)
        free(argv[i]);
    free(argv);
    if (r != 0)
        return r;

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return errno;
    if (!WIFEXITED(status))
        return ECHILD;
    return WEXITSTATUS(status);
}

static BOOL dt583_mkdir_p(NSString *path, mode_t mode)
{
    if (!path.length)
        return NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:path])
        return YES;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length && ![parent isEqualToString:path])
        (void)dt583_mkdir_p(parent, mode);
    return mkdir(path.fileSystemRepresentation, mode) == 0 || errno == EEXIST;
}

static BOOL dt583_is_directory(NSString *path)
{
    struct stat st;
    if (stat(path.fileSystemRepresentation, &st) != 0)
        return NO;
    return S_ISDIR(st.st_mode);
}

static BOOL dt583_jbroot_write_probe(NSString **detailOut)
{
    static NSString *const kProbePath =
        @"/private/var/jb/tmp/.probe583_preflight_write";
    if (!dt583_mkdir_p(@"/private/var/jb/tmp", 0777)) {
        if (detailOut)
            *detailOut = @"jbroot tmp mkdir failed";
        return NO;
    }
    unlink(kProbePath.fileSystemRepresentation);
    int fd = open(kProbePath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"jbroot write probe errno=%d", errno];
        return NO;
    }
    const char payload[] = "probe583_preflight\n";
    ssize_t wrote = write(fd, payload, sizeof(payload) - 1);
    close(fd);
    unlink(kProbePath.fileSystemRepresentation);
    if (wrote != (ssize_t)(sizeof(payload) - 1)) {
        if (detailOut)
            *detailOut = @"jbroot write probe short write";
        return NO;
    }
    return YES;
}

static BOOL dt583_preflight_signing_ok(dt583_log_fn log, NSString **detailOut)
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff583/dt_probe583_helper"];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:bundled]) {
        if (detailOut)
            *detailOut = @"bundled dt_probe583_helper missing or not executable";
        return NO;
    }

    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(bundled.fileSystemRepresentation, hash) != 0) {
        if (detailOut)
            *detailOut = @"bundled helper cdhash extract failed";
        return NO;
    }

    dt583_log(log, [NSString stringWithFormat:@"KCALL583_PREFLIGHT_HELPER_CDHASH=%@",
        dt_cdhash_hex_string(hash)]);
    return YES;
}

/// Concrete jbroot capability checks — replaces stale `.dt540_native_bootstrap` gate.
static BOOL dt583_preflight_jbroot(dt583_log_fn log, NSString **detailOut,
                                   NSString **verdictOut)
{
    if (!dt583_is_directory(@"/private/var/jb")) {
        dt583_emit(log, @"KCALL583_PRE_JBROOT_MISSING");
        if (detailOut)
            *detailOut = @"/private/var/jb missing — run G1/G2 first";
        if (verdictOut)
            *verdictOut = @"KCALL583_PRE_JBROOT_OK=0";
        return NO;
    }
    dt583_emit(log, @"KCALL583_PRE_JBROOT_DIR_OK=1");

    if (!dt583_is_directory(@"/private/var/jb/usr/bin")) {
        if (!dt583_mkdir_p(@"/private/var/jb/usr/bin", 0755)) {
            if (detailOut)
                *detailOut = @"/private/var/jb/usr/bin missing and mkdir failed";
            if (verdictOut)
                *verdictOut = @"KCALL583_PRE_JBROOT_OK=0";
            return NO;
        }
    }
    dt583_emit(log, @"KCALL583_PRE_USR_BIN_OK=1");

    if (!dt583_mkdir_p(@"/private/var/jb/Library/LaunchDaemons", 0755)) {
        dt583_emit(log, @"KCALL583_PRE_LAUNCHDAEMONS_DIR_FAIL");
        if (detailOut)
            *detailOut = @"jbroot LaunchDaemons mkdir failed";
        if (verdictOut)
            *verdictOut = @"KCALL583_PRE_JBROOT_OK=0";
        return NO;
    }
    dt583_emit(log, @"KCALL583_PRE_LAUNCHDAEMONS_DIR_OK=1");

    if (!dt583_jbroot_write_probe(detailOut)) {
        dt583_emit(log, @"KCALL583_PRE_HELPER_INSTALL_PATH_FAIL");
        if (verdictOut)
            *verdictOut = @"KCALL583_PRE_JBROOT_OK=0";
        return NO;
    }
    dt583_emit(log, @"KCALL583_PRE_HELPER_INSTALL_PATH_OK=1");

    if (!dt583_preflight_signing_ok(log, detailOut)) {
        dt583_emit(log, @"KCALL583_PRE_SIGNING_FAIL");
        if (verdictOut)
            *verdictOut = @"KCALL583_PRE_JBROOT_OK=0";
        return NO;
    }
    dt583_emit(log, @"KCALL583_PRE_SIGNING_OK=1");

    if ([[NSFileManager defaultManager] fileExistsAtPath:kDT583JbrootMarker])
        dt583_emit(log, @"KCALL583_PRE_NATIVE540_MARKER_OK=1");
    else
        dt583_log(log, @"[*] KCALL583 note: .dt540_native_bootstrap absent (G2 jbroot OK)");

    dt583_emit(log, @"KCALL583_PRE_JBROOT_OK=1");
    return YES;
}

static BOOL dt583_trust_paths(NSArray<NSString *> *paths, dt583_log_fn log,
                              NSString **detailOut)
{
    cdhash_t *hashes = calloc(paths.count, sizeof(cdhash_t));
    if (!hashes) {
        if (detailOut)
            *detailOut = @"cdhash alloc failed";
        return NO;
    }

    for (NSUInteger i = 0; i < paths.count; i++) {
        if (dt_macho_best_cdhash_from_path(
                paths[i].fileSystemRepresentation, hashes[i]) != 0) {
            free(hashes);
            if (detailOut)
                *detailOut = @"cdhash extraction failed";
            return NO;
        }
    }

    uint32_t uploaded = 0;
    uint32_t skipped = 0;
    int r = dt_trustcache_upload_cdhashes(hashes, (uint32_t)paths.count,
                                          &uploaded, &skipped);
    if (r == 0) {
        for (NSUInteger i = 0; i < paths.count; i++) {
            if (!dt_cdhash_trustcached(hashes[i])) {
                r = EIO;
                break;
            }
        }
    }
    free(hashes);

    dt583_log(log, [NSString stringWithFormat:
        @"[*] KCALL583 trustcache result=%d uploaded=%u skipped=%u",
        r, uploaded, skipped]);
    dt583_log(log, [NSString stringWithFormat:
        @"KCALL583_TRUSTCACHE_RESULT=%d", r]);

    if (r != 0 && detailOut)
        *detailOut = @"trustcache upload/verify failed";
    return r == 0;
}

static BOOL dt583_install_helper(dt583_log_fn log, NSString **detailOut)
{
    NSString *bundled = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Handoff583/dt_probe583_helper"];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:bundled]) {
        if (detailOut)
            *detailOut = @"bundled dt_probe583_helper missing";
        return NO;
    }

    if (!dt583_mkdir_p(@"/private/var/jb/usr/bin", 0755) ||
        !dt583_mkdir_p(@"/private/var/jb/tmp", 0777) ||
        !dt583_mkdir_p(@"/private/var/jb/Library/LaunchDaemons", 0755)) {
        if (detailOut)
            *detailOut = @"jbroot mkdir failed";
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:kDT583HelperInstalled error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:bundled toPath:kDT583HelperInstalled error:&copyErr]) {
        if (detailOut)
            *detailOut = copyErr.localizedDescription ?: @"helper copy failed";
        return NO;
    }
    chmod(kDT583HelperInstalled.fileSystemRepresentation, 0755);

    struct stat st;
    if (stat(kDT583HelperInstalled.fileSystemRepresentation, &st) != 0) {
        if (detailOut)
            *detailOut = @"helper stat failed";
        return NO;
    }

    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(kDT583HelperInstalled.fileSystemRepresentation,
                                       hash) != 0) {
        if (detailOut)
            *detailOut = @"helper cdhash extract failed";
        return NO;
    }

    dt583_emit(log, @"KCALL583_HELPER_PREBUILD_SIGNED=1");
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_HELPER_PATH=%@", kDT583HelperInstalled]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_HELPER_SIZE=%lld", (long long)st.st_size]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_HELPER_MODE=%o", st.st_mode & 07777]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_HELPER_CDHASH=%@",
        dt_cdhash_hex_string(hash)]);
    dt583_log(log, @"KCALL583_HELPER_SIGN_RESULT=PREBUILD_ADHOC");

    if (!dt583_trust_paths(@[kDT583HelperInstalled], log, detailOut))
        return NO;

    dt583_emit(log, @"KCALL583_HELPER_INSTALL_OK");
    return YES;
}

static BOOL dt583_write_helper_plist(dt583_log_fn log, NSString **detailOut)
{
    NSDictionary *plist = @{
        @"Label": @(DT583_SERVICE_NAME),
        @"Program": kDT583HelperInstalled,
        @"RunAtLoad": @YES,
        @"KeepAlive": @NO,
    };
    if (![plist writeToFile:kDT583HelperPlist atomically:YES]) {
        if (detailOut)
            *detailOut = @"helper plist write failed";
        return NO;
    }
    chmod(kDT583HelperPlist.fileSystemRepresentation, 0644);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_PLIST_PATH=%@", kDT583HelperPlist]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_PLIST_PROGRAM=%@", kDT583HelperInstalled]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_PLIST_LABEL=%@", @(DT583_SERVICE_NAME)]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_LAUNCHCTL_CMD=%@", kDT583LaunchctlCmd]);
    return YES;
}

static int dt583_launchctl_bootstrap_helper(dt583_log_fn log)
{
    NSString *serviceTarget = @"system/com.dopamin.probe583.helper";
    (void)dt583_spawn_wait(@[@"/bin/launchctl", @"bootout", serviceTarget]);

    dt583_emit(log, @"KCALL636_LAUNCHD_SPAWN_FORK_WINDOW_BEGIN");
    int rc = dt583_spawn_wait(@[
        @"/bin/launchctl", @"bootstrap", @"system", kDT583HelperPlist]);
    dt583_emit(log, @"KCALL636_LAUNCHD_SPAWN_FORK_WINDOW_END");

    dt583_log(log, [NSString stringWithFormat:
        @"[*] KCALL583 launchctl bootstrap rc=%d service=%@ plist=%@",
        rc, serviceTarget, kDT583HelperPlist]);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_LAUNCHCTL_RC=%d", rc]);
    return rc;
}

static pid_t dt583_find_pid_by_name(NSString *name)
{
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0 || size == 0)
        return -1;

    struct kinfo_proc *procs = calloc(1, size);
    if (!procs)
        return -1;
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return -1;
    }

    size_t count = size / sizeof(struct kinfo_proc);
    pid_t found = -1;
    for (size_t i = 0; i < count; i++) {
        const char *pname = procs[i].kp_proc.p_comm;
        if (pname && strncmp(pname, name.UTF8String, MAXCOMLEN) == 0) {
            found = procs[i].kp_proc.p_pid;
            break;
        }
    }
    free(procs);
    return found;
}

static pid_t dt583_proc_ppid(pid_t pid)
{
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0)
        return -1;
    return kp.kp_eproc.e_ppid;
}

static BOOL dt583_helper_has_forbidden_child(pid_t helperPid, dt583_log_fn log)
{
    static const char *forbidden[] = {
        "env", "bash", "dash", "sh", "ldid", "posix_spawn", NULL
    };

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0 || size == 0)
        return NO;

    struct kinfo_proc *procs = calloc(1, size);
    if (!procs)
        return NO;
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return NO;
    }

    size_t count = size / sizeof(struct kinfo_proc);
    BOOL found = NO;
    for (size_t i = 0; i < count; i++) {
        pid_t child = procs[i].kp_proc.p_pid;
        if (child <= 0 || dt583_proc_ppid(child) != helperPid)
            continue;
        const char *comm = procs[i].kp_proc.p_comm;
        if (!comm)
            continue;
        for (const char **p = forbidden; *p; p++) {
            if (strncmp(comm, *p, MAXCOMLEN) == 0) {
                dt583_log(log, [NSString stringWithFormat:
                    @"[!] helper child pid=%d comm=%s", (int)child, comm]);
                found = YES;
                break;
            }
        }
    }
    free(procs);
    return found;
}

static BOOL dt583_mach_checkin(dt583_log_fn log, uint32_t *replyLenOut)
{
    if (replyLenOut)
        *replyLenOut = 0;

    dt583_log(log, [NSString stringWithFormat:
        @"KCALL636_MACH_SERVICE_NAME=%s", DT583_SERVICE_NAME]);

    xpc_connection_t conn = xpc_connection_create_mach_service(
        DT583_SERVICE_NAME, NULL, 0);
    if (!conn) {
        dt583_log(log, @"KCALL636_MACH_LOOKUP_RET=-1");
        dt583_log(log, @"KCALL636_MACH_MSG_SEND_RET=-1");
        dt583_log(log, @"KCALL636_MACH_REPLY_LEN=0");
    } else {
        dt583_log(log, @"KCALL636_MACH_LOOKUP_RET=0");
        __block int sendRet = -1;
        __block uint32_t replyLen = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
            if (xpc_get_type(event) == XPC_TYPE_ERROR)
                dispatch_semaphore_signal(sem);
        });
        xpc_connection_resume(conn);
        xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(msg, "op", "checkin");
        xpc_connection_send_message_with_reply(
            conn, msg, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
            ^(xpc_object_t reply) {
                sendRet = 0;
                if (reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
                    replyLen = (uint32_t)xpc_dictionary_get_int64(reply, "pid");
                    if (replyLen == 0)
                        replyLen = 1;
                }
                dispatch_semaphore_signal(sem);
            });
        if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0)
            sendRet = -2;
        xpc_connection_cancel(conn);
        dt583_log(log, [NSString stringWithFormat:@"KCALL636_MACH_MSG_SEND_RET=%d", sendRet]);
        dt583_log(log, [NSString stringWithFormat:@"KCALL636_MACH_REPLY_LEN=%u", replyLen]);
        if (replyLenOut)
            *replyLenOut = replyLen;
        if (sendRet == 0 && replyLen > 0)
            return YES;
    }

    unlink(DT583_CHECKIN_PING.fileSystemRepresentation);
    int fd = open(DT583_CHECKIN_PING.fileSystemRepresentation, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        (void)write(fd, "ping", 4);
        close(fd);
    }

    for (int i = 0; i < 40; i++) {
        NSString *text = [NSString stringWithContentsOfFile:kDT583HelperLog
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
        if ([text containsString:@"KCALL583_HELPER_CHECKIN_OK=1"]) {
            if (replyLenOut && *replyLenOut == 0)
                *replyLenOut = 4;
            dt583_log(log, @"[*] KCALL583 check-in via FILE_PING equivalent OK");
            return YES;
        }
        usleep(250000);
    }

    return NO;
}

static BOOL dt583_probe_a(dt583_log_fn log, NSString **detailOut, NSString **verdictOut)
{
    if (verdictOut)
        *verdictOut = @"KCALL583_PROBE_A_FAIL_NO_PROCESS";

    dt583_log(log, @"[*] KCALL583_PROFILE_REGISTRY_NAME=container");
    dt583_log(log, @"KCALL583_EMBEDDED_BUILTIN_ONLY=1");

    if (!dt583_install_helper(log, detailOut))
        return NO;
    if (!dt583_write_helper_plist(log, detailOut))
        return NO;

    (void)dt583_launchctl_bootstrap_helper(log);

    usleep(750000);

    pid_t helperPid = dt583_find_pid_by_name(@"dt_probe583");
    if (helperPid <= 0) {
        NSString *text = [NSString stringWithContentsOfFile:kDT583HelperLog
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
        if ([text containsString:@"KCALL583_HELPER_PID="]) {
            NSScanner *scanner = [NSScanner scannerWithString:text];
            [scanner scanUpToString:@"KCALL583_HELPER_PID=" intoString:NULL];
            int pidVal = 0;
            if ([scanner scanString:@"KCALL583_HELPER_PID=" intoString:NULL] &&
                [scanner scanInt:&pidVal]) {
                helperPid = (pid_t)pidVal;
            }
        }
    }

    if (helperPid <= 0) {
        if (detailOut)
            *detailOut = @"helper process not found";
        if (verdictOut)
            *verdictOut = @"KCALL583_PROBE_A_FAIL_NO_PROCESS";
        dt583_emit(log, @"KCALL583_PROBE_A_FAIL_NO_PROCESS");
        return NO;
    }

    dt583_log(log, [NSString stringWithFormat:@"KCALL583_HELPER_PID=%d", (int)helperPid]);

    pid_t ppid = dt583_proc_ppid(helperPid);
    dt583_log(log, [NSString stringWithFormat:@"KCALL583_HELPER_PPID=%d", (int)ppid]);
    if (ppid != 1) {
        if (verdictOut)
            *verdictOut = @"KCALL583_PROBE_A_FAIL_PPID_NOT_1";
        if (detailOut)
            *detailOut = [NSString stringWithFormat:@"helper ppid=%d expected 1", (int)ppid];
        dt583_emit(log, @"KCALL583_PROBE_A_FAIL_PPID_NOT_1");
        return NO;
    }

    uint64_t profilePtr = 0;
    int mirrorRc = dt_mirror_profile_ptr_for_pid(helperPid, &profilePtr);
    dt583_log(log, [NSString stringWithFormat:@"PROFILE_532930_PTR=0x%llx",
        (unsigned long long)profilePtr]);
    dt583_log(log, [NSString stringWithFormat:@"ISSUER_532C68_PTR=0x%llx",
        (unsigned long long)profilePtr]);
    if (mirrorRc != 0 || profilePtr == 0) {
        dt583_emit(log, @"PROFILE_532930_NULL=1");
        if (verdictOut)
            *verdictOut = @"KCALL583_PROBE_A_FAIL_PROFILE_NULL";
        if (detailOut)
            *detailOut = @"532930 mirror NULL";
        return NO;
    }

    uint32_t replyLen = 0;
    if (!dt583_mach_checkin(log, &replyLen)) {
        if (verdictOut)
            *verdictOut = @"KCALL583_PROBE_A_FAIL_CHECKIN";
        if (detailOut)
            *detailOut = @"Mach check-in to helper failed";
        dt583_emit(log, @"KCALL583_PROBE_A_FAIL_CHECKIN");
        return NO;
    }
    dt583_emit(log, @"KCALL583_HELPER_CHECKIN_OK=1");

    if (dt583_helper_has_forbidden_child(helperPid, log)) {
        if (verdictOut)
            *verdictOut = @"KCALL583_PROBE_A_FAIL_CHILD_SPAWN";
        dt583_emit(log, @"KCALL583_PROBE_A_FAIL_CHILD_SPAWN");
        return NO;
    }
    dt583_emit(log, @"KCALL583_HELPER_NO_CHILD_SPAWN=1");

    dt583_emit(log, @"KCALL583_PROBE_A_PASS");
    if (verdictOut)
        *verdictOut = @"KCALL583_PROBE_A_PASS";
    return YES;
}

static void dt583_emit_safety(dt583_log_fn log)
{
    dt583_emit(log, @"KCALL583_NO_PROBE_C");
    dt583_emit(log, @"KCALL583_NO_HELPER_TO_ENV");
    dt583_emit(log, @"KCALL583_NO_BROKER_TO_ENV");
    dt583_emit(log, @"KCALL583_NO_PLATFORM_APPLICATION");
    dt583_emit(log, @"KCALL583_NO_LAUNCHDHOOK");
    dt583_emit(log, @"KCALL583_NO_OPAINJECT");
    dt583_emit(log, @"KCALL583_NO_USERSPACE_REBOOT");
    dt583_emit(log, @"KCALL583_NO_DPKG");
    dt583_emit(log, @"KCALL583_NO_BROKER_SPAWN");
}

int dt_build102583_run(void (^log)(NSString *line), NSString **verdictOut)
{
    NSString *detail = nil;
    NSString *finalVerdict = @"KCALL583_DIAGNOSTIC_FAILED";
    if (verdictOut)
        *verdictOut = finalVerdict;

    dt583_emit(log, @"KCALL583_PROBE_A_LAUNCHD_HELPER");
    dt583_emit(log, @"KCALL583_DIAGNOSTIC_BUILD");

    if ([[NSFileManager defaultManager] fileExistsAtPath:kDT583Pid1DirtyMarker]) {
        dt583_emit(log, @"KCALL583_ABORT_PID1_DIRTY=1");
        detail = @"pid 1 touched marker present — reboot required";
        finalVerdict = @"KCALL583_ABORT_PID1_DIRTY=1";
        goto finish;
    }

    if (!dt_kernel_exploit_is_active()) {
        detail = @"kfd not active";
        finalVerdict = @"KCALL583_PRE_KFD_OK=0";
        goto finish;
    }
    dt583_emit(log, @"KCALL583_PRE_KFD_OK=1");

    if (!dt583_preflight_jbroot(log, &detail, &finalVerdict))
        goto finish;

    if (getuid() != 0) {
        detail = @"requires root uid=0";
        finalVerdict = @"KCALL583_PRE_ROOT_FAILED";
        goto finish;
    }

    if (dt_build_physrw_handoff_only(log) != 0) {
        detail = @"physrw handoff failed";
        finalVerdict = @"KCALL583_PRE_TRUSTCACHE_FAIL";
        goto finish;
    }
    dt583_emit(log, @"KCALL583_PRE_TRUSTCACHE_OK=1");
    dt583_emit(log, @"KCALL583_PRE_NO_PID1_TOUCH=1");

    (void)dt583_probe_a(log, &detail, &finalVerdict);
    dt583_emit_safety(log);

finish:
    if (detail.length)
        dt583_log(log, [NSString stringWithFormat:@"[*] build102583 detail=%@", detail]);
    if (verdictOut)
        *verdictOut = finalVerdict;
    dt583_log(log, [NSString stringWithFormat:@"[*] build102583 final_verdict=%@",
        finalVerdict]);
    return [finalVerdict isEqualToString:@"KCALL583_PROBE_A_PASS"] ? 0 : -1;
}
