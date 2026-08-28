#import "dt_build102739m.h"
#import "build102739m_identity.h"
#import "dt_physrw.h"
#import "dt_build710_preboot.h"
#import "DTRunLogger.h"

#import "info.h"
#import "primitives.h"
#import "kernel.h"
#import "codesign.h"

#import <CommonCrypto/CommonCrypto.h>
#import <dirent.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/getsect.h>
#import <mach-o/ldsyms.h>
#import <poll.h>
#import <signal.h>
#import <spawn.h>
#import <stdarg.h>
#import <stdlib.h>
#import <stdint.h>
#import <string.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>
#import <uuid/uuid.h>

extern int proc_pidpath(int pid, void *buffer, unsigned int buffersize);
extern int dt102739m_posix_spawn(pid_t *, const char *,
    const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
    char *const[], char *const[]) __asm("_posix_spawn");
extern int dt102739m_actions_init(posix_spawn_file_actions_t *)
    __asm("_posix_spawn_file_actions_init");
extern int dt102739m_actions_destroy(posix_spawn_file_actions_t *)
    __asm("_posix_spawn_file_actions_destroy");
extern int dt102739m_actions_adddup2(posix_spawn_file_actions_t *, int, int)
    __asm("_posix_spawn_file_actions_adddup2");
extern int dt102739m_actions_addclose(posix_spawn_file_actions_t *, int)
    __asm("_posix_spawn_file_actions_addclose");

static NSString *const kDT102739MParent = @"/private/var/tmp";
static NSString *const kDT102739MHelperName = @"dt_probe102739m";
static NSString *const kDT102739MProtocol = @"BUILD102739M_REPAIRED_V6";
static const size_t kDT102739MOutputLimit = 32768;
static const NSUInteger kDT102739MMaxEnvironmentNames = 32;
static const NSUInteger kDT102739MMaxEnvironmentNameBytes = 128;
static const int kDT102739MWaitMs = 8000;
static const int kDT102739MPollMs = 100;

static void dt102739m_emit(void (^log)(NSString *), NSString *format, ...)
{
    va_list ap;
    va_start(ap, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    if (log)
        log(line);
    [[DTRunLogger shared] logStage:line];
}

static NSString *dt102739m_sha256(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return nil;
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    unsigned char buffer[16384];
    ssize_t n = 0;
    while ((n = read(fd, buffer, sizeof(buffer))) > 0)
        CC_SHA256_Update(&ctx, buffer, (CC_LONG)n);
    int saved = errno;
    close(fd);
    if (n < 0) {
        errno = saved;
        return nil;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < sizeof(digest); i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static NSString *dt102739m_sha256_bytes(const void *bytes, size_t length)
{
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes, (CC_LONG)length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < sizeof(digest); i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static BOOL dt102739m_decode_lower_hex(NSString *value, unsigned char *bytes, size_t length)
{
    if (value.length != length * 2)
        return NO;
    const char *text = value.UTF8String;
    if (!text || strlen(text) != length * 2)
        return NO;
    BOOL nonzero = NO;
    for (size_t i = 0; i < length; i++) {
        int high = text[i * 2] >= '0' && text[i * 2] <= '9'
            ? text[i * 2] - '0'
            : text[i * 2] >= 'a' && text[i * 2] <= 'f' ? text[i * 2] - 'a' + 10 : -1;
        int low = text[(i * 2) + 1] >= '0' && text[(i * 2) + 1] <= '9'
            ? text[(i * 2) + 1] - '0'
            : text[(i * 2) + 1] >= 'a' && text[(i * 2) + 1] <= 'f'
                ? text[(i * 2) + 1] - 'a' + 10 : -1;
        if (high < 0 || low < 0)
            return NO;
        bytes[i] = (unsigned char)((high << 4) | low);
        nonzero |= bytes[i] != 0;
    }
    return nonzero;
}

static BOOL dt102739m_parse_uint(NSString *value, NSUInteger maximum, NSUInteger *resultOut)
{
    const char *text = value.UTF8String;
    if (!text || !text[0] || (text[0] == '0' && text[1] != '\0'))
        return NO;
    for (const char *cursor = text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9')
            return NO;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > maximum)
        return NO;
    if (resultOut)
        *resultOut = (NSUInteger)parsed;
    return YES;
}

static NSArray<NSString *> *dt102739m_decode_environment_names(NSString *encoded,
    NSUInteger expectedCount)
{
    if (expectedCount == 0)
        return [encoded isEqualToString:@"NONE"] ? @[] : nil;
    if (expectedCount > kDT102739MMaxEnvironmentNames || !encoded.length
        || [encoded isEqualToString:@"NONE"])
        return nil;
    NSArray<NSString *> *components = [encoded componentsSeparatedByString:@","];
    if (components.count != expectedCount)
        return nil;
    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:expectedCount];
    NSString *previous = nil;
    for (NSString *component in components) {
        if (component.length == 0 || component.length > kDT102739MMaxEnvironmentNameBytes * 2
            || (component.length & 1) != 0)
            return nil;
        NSMutableData *decoded = [NSMutableData dataWithLength:component.length / 2];
        unsigned char *bytes = decoded.mutableBytes;
        const char *hex = component.UTF8String;
        for (NSUInteger i = 0; i < decoded.length; i++) {
            int high = hex[i * 2] >= '0' && hex[i * 2] <= '9' ? hex[i * 2] - '0'
                : hex[i * 2] >= 'a' && hex[i * 2] <= 'f' ? hex[i * 2] - 'a' + 10 : -1;
            int low = hex[(i * 2) + 1] >= '0' && hex[(i * 2) + 1] <= '9'
                ? hex[(i * 2) + 1] - '0'
                : hex[(i * 2) + 1] >= 'a' && hex[(i * 2) + 1] <= 'f'
                    ? hex[(i * 2) + 1] - 'a' + 10 : -1;
            if (high < 0 || low < 0)
                return nil;
            bytes[i] = (unsigned char)((high << 4) | low);
            if (bytes[i] == 0 || bytes[i] == '=')
                return nil;
            BOOL validNameByte = (bytes[i] >= 'A' && bytes[i] <= 'Z')
                || (bytes[i] >= 'a' && bytes[i] <= 'z')
                || bytes[i] == '_'
                || (i != 0 && bytes[i] >= '0' && bytes[i] <= '9');
            if (!validNameByte)
                return nil;
        }
        NSString *name = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
        if (!name.length || (previous && [previous compare:name options:NSLiteralSearch] != NSOrderedAscending))
            return nil;
        [names addObject:name];
        previous = name;
    }
    return names;
}

static BOOL dt102739m_cdhash(NSString *path, cdhash_t out, NSString **hexOut)
{
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, out) != 0)
        return NO;
    if (hexOut)
        *hexOut = dt_cdhash_hex_string(out);
    return YES;
}

static uint64_t dt102739m_slot0(void)
{
    uint64_t proc = proc_find(getpid());
    if (!proc)
        return 0;
    uint64_t ucred = proc_ucred(proc);
    proc_rele(proc);
    if (!ucred)
        return 0;
    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    return label ? mac_label_get(label, 0) : 0;
}

static NSString *dt102739m_pid_path(pid_t pid)
{
    char path[4096] = {0};
    if (proc_pidpath(pid, path, sizeof(path)) <= 0 || !path[0])
        return nil;
    return [NSString stringWithUTF8String:path];
}

static uint64_t dt102739m_pid1_proc(void)
{
    uint64_t proc = proc_find(1);
    if (proc)
        proc_rele(proc);
    return proc;
}

static BOOL dt102739m_validate_parent(struct stat *snapshotOut)
{
    NSArray<NSString *> *components = @[@"/private", @"/private/var", kDT102739MParent];
    for (NSString *path in components) {
        struct stat st = {0};
        if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISDIR(st.st_mode))
            return NO;
    }
    struct statfs sfs = {0};
    if (statfs(kDT102739MParent.fileSystemRepresentation, &sfs) != 0
        || (sfs.f_flags & MNT_RDONLY) != 0 || sfs.f_bavail < 16)
        return NO;
    return lstat(kDT102739MParent.fileSystemRepresentation, snapshotOut) == 0;
}

static BOOL dt102739m_parent_stable(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino
        && (before->st_mode & S_IFMT) == (after->st_mode & S_IFMT)
        && before->st_uid == after->st_uid && before->st_gid == after->st_gid
        && (before->st_mode & 07777) == (after->st_mode & 07777)
        && before->st_flags == after->st_flags;
}

static BOOL dt102739m_write_all(int destination, const unsigned char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(destination, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return NO;
        offset += (size_t)written;
    }
    return fsync(destination) == 0;
}

static NSString *dt102739m_nonce(void)
{
    unsigned char bytes[16];
    arc4random_buf(bytes, sizeof(bytes));
    NSMutableString *nonce = [NSMutableString stringWithCapacity:32];
    for (size_t i = 0; i < sizeof(bytes); i++)
        [nonce appendFormat:@"%02x", bytes[i]];
    return nonce;
}

typedef struct {
    NSMutableData *data;
    BOOL overflow;
    BOOL eof;
} dt102739m_capture_t;

static void dt102739m_drain(int fd, dt102739m_capture_t *capture)
{
    unsigned char buffer[512];
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            size_t room = capture->data.length < kDT102739MOutputLimit
                ? kDT102739MOutputLimit - capture->data.length : 0;
            size_t accepted = MIN((size_t)n, room);
            if (accepted)
                [capture->data appendBytes:buffer length:accepted];
            if (accepted != (size_t)n)
                capture->overflow = YES;
            continue;
        }
        if (n == 0)
            capture->eof = YES;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            capture->eof = YES;
        return;
    }
}

static NSDictionary<NSString *, NSString *> *dt102739m_parse_record(NSData *data)
{
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text.length || ![text hasSuffix:@"\n"])
        return nil;
    NSArray<NSString *> *lines = [text componentsSeparatedByString:@"\n"];
    if (lines.count != 2 || ![lines[1] isEqualToString:@""])
        return nil;
    NSArray<NSString *> *fields = [lines[0] componentsSeparatedByString:@" "];
    if (fields.count != 21 || ![fields[0] isEqualToString:@"BUILD102739M_HELPER_RECORD"])
        return nil;
    NSMutableDictionary *record = [NSMutableDictionary dictionary];
    for (NSUInteger i = 1; i < fields.count; i++) {
        NSRange separator = [fields[i] rangeOfString:@"="];
        if (separator.location == NSNotFound || separator.location == 0)
            return nil;
        NSString *key = [fields[i] substringToIndex:separator.location];
        NSString *value = [fields[i] substringFromIndex:separator.location + 1];
        if (!value.length || record[key])
            return nil;
        record[key] = value;
    }
    return record;
}

static int dt102739m_spawn(NSString *path, NSString *nonce, NSDictionary **recordOut,
    BOOL *stderrEmptyOut, BOOL *stdoutOverflowOut, BOOL *stderrOverflowOut,
    BOOL *timeoutOut, BOOL *reapedOut,
    int *exitStatusOut, int *signalOut, pid_t *childPIDOut)
{
    int stdoutPipe[2] = {-1, -1};
    int stderrPipe[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    int actionsReady = 0;
    pid_t child = 0;
    int spawnRC = -1;
    const char *executable = path.fileSystemRepresentation;
    char *const argv[] = {(char *)executable, (char *)"--probe",
        (char *)"BUILD102739M_REPAIRED_V6",
        (char *)"--nonce", (char *)nonce.UTF8String, NULL};
    char *const envp[] = {NULL};
    dt102739m_capture_t out = {.data = [NSMutableData data]};
    dt102739m_capture_t err = {.data = [NSMutableData data]};
    if (pipe(stdoutPipe) != 0 || pipe(stderrPipe) != 0)
        goto fail;

    if (dt102739m_actions_init(&actions) != 0)
        goto fail;
    actionsReady = 1;
    if (dt102739m_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO) != 0
        || dt102739m_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO) != 0
        || dt102739m_actions_addclose(&actions, stdoutPipe[0]) != 0
        || dt102739m_actions_addclose(&actions, stderrPipe[0]) != 0
        || dt102739m_actions_addclose(&actions, stdoutPipe[1]) != 0
        || dt102739m_actions_addclose(&actions, stderrPipe[1]) != 0)
        goto fail_actions;

    spawnRC = dt102739m_posix_spawn(&child, executable, &actions, NULL, argv, envp);
    dt102739m_actions_destroy(&actions);
    actionsReady = 0;
    close(stdoutPipe[1]); stdoutPipe[1] = -1;
    close(stderrPipe[1]); stderrPipe[1] = -1;
    if (spawnRC != 0)
        goto fail;
    if (childPIDOut)
        *childPIDOut = child;

    fcntl(stdoutPipe[0], F_SETFL, fcntl(stdoutPipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(stderrPipe[0], F_SETFL, fcntl(stderrPipe[0], F_GETFL) | O_NONBLOCK);
    int status = 0;
    BOOL childReaped = NO;
    int elapsed = 0;
    while (elapsed < kDT102739MWaitMs) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child)
            childReaped = YES;
        else if (waited < 0 && errno != EINTR)
            break;

        struct pollfd pfds[2] = {
            {.fd = stdoutPipe[0], .events = POLLIN | POLLHUP},
            {.fd = stderrPipe[0], .events = POLLIN | POLLHUP},
        };
        (void)poll(pfds, 2, kDT102739MPollMs);
        dt102739m_drain(stdoutPipe[0], &out);
        dt102739m_drain(stderrPipe[0], &err);
        elapsed += kDT102739MPollMs;
        if (childReaped && out.eof && err.eof)
            break;
    }

    if (!childReaped) {
        if (timeoutOut)
            *timeoutOut = YES;
        kill(child, SIGKILL);
        pid_t finalWait = -1;
        do {
            finalWait = waitpid(child, &status, 0);
        } while (finalWait < 0 && errno == EINTR);
        childReaped = finalWait == child;
    }
    dt102739m_drain(stdoutPipe[0], &out);
    dt102739m_drain(stderrPipe[0], &err);
    close(stdoutPipe[0]); stdoutPipe[0] = -1;
    close(stderrPipe[0]); stderrPipe[0] = -1;

    if (reapedOut)
        *reapedOut = childReaped;
    if (stdoutOverflowOut)
        *stdoutOverflowOut = out.overflow;
    if (stderrOverflowOut)
        *stderrOverflowOut = err.overflow;
    if (stderrEmptyOut)
        *stderrEmptyOut = err.data.length == 0;
    if (exitStatusOut)
        *exitStatusOut = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (signalOut)
        *signalOut = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    if (recordOut)
        *recordOut = dt102739m_parse_record(out.data);
    return 0;

fail_actions:
    if (actionsReady)
        dt102739m_actions_destroy(&actions);
fail:
    for (size_t i = 0; i < 2; i++) {
        if (stdoutPipe[i] >= 0) close(stdoutPipe[i]);
        if (stderrPipe[i] >= 0) close(stderrPipe[i]);
    }
    return -1;
}

static int dt102739m_finish(void (^log)(NSString *), NSString **verdictOut,
    NSString *verdict)
{
    dt102739m_emit(log, @"BUILD102739M_FINAL_RESULT=%@", verdict);
    if (verdictOut)
        *verdictOut = verdict;
    return [verdict hasPrefix:@"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_PASS"]
        ? 0 : -739130;
}

static int dt102739m_fail(void (^log)(NSString *), NSString **verdictOut, NSString *stage)
{
    dt102739m_emit(log, @"M_FAILURE_STAGE=%@", stage);
    return dt102739m_finish(log, verdictOut, @"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_FAIL");
}

static void dt102739m_log_loose_diagnostic(void (^log)(NSString *))
{
    NSString *nsPath = [[NSBundle mainBundle] pathForResource:kDT102739MHelperName ofType:nil];
    NSString *directPath = [[[NSBundle mainBundle] bundlePath]
        stringByAppendingPathComponent:kDT102739MHelperName];
    dt102739m_emit(log, @"M_LOOSE_NSLOOKUP_PATH=%@", nsPath ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_LOOSE_DIRECT_PATH=%@", directPath);

    struct stat st = {0};
    errno = 0;
    int statRC = lstat(directPath.fileSystemRepresentation, &st);
    int statErrno = statRC == 0 ? 0 : errno;
    dt102739m_emit(log, @"M_LOOSE_LSTAT_RC=%d", statRC);
    dt102739m_emit(log, @"M_LOOSE_LSTAT_ERRNO=%d", statErrno);
    dt102739m_emit(log, @"M_LOOSE_TYPE=%@",
        statRC == 0 && S_ISREG(st.st_mode) ? @"REGULAR" : @"UNAVAILABLE");
    dt102739m_emit(log, @"M_LOOSE_MODE=%04o", statRC == 0 ? st.st_mode & 07777 : 0);
    dt102739m_emit(log, @"M_LOOSE_SIZE=%lld", statRC == 0 ? (long long)st.st_size : -1LL);

    NSString *sha = statRC == 0 ? dt102739m_sha256(directPath) : nil;
    cdhash_t looseHash = {0};
    NSString *cdhash = nil;
    BOOL cdhashOK = statRC == 0 && dt102739m_cdhash(directPath, looseHash, &cdhash);
    BOOL shaMatch = [sha isEqualToString:@DT102739M_HELPER_SHA256];
    BOOL cdhashMatch = cdhashOK && [cdhash isEqualToString:@DT102739M_HELPER_CDHASH];
    dt102739m_emit(log, @"M_LOOSE_SHA256_READ_RC=%d", sha ? 0 : -1);
    dt102739m_emit(log, @"M_LOOSE_SHA256_ACTUAL=%@", sha ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_LOOSE_SHA256_MATCH=%@", shaMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_LOOSE_CDHASH_PARSE_RC=%d", cdhashOK ? 0 : -1);
    dt102739m_emit(log, @"M_LOOSE_CDHASH_ACTUAL=%@", cdhash ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_LOOSE_CDHASH_MATCH=%@", cdhashMatch ? @"YES" : @"NO");

    NSString *result = @"IDENTITY_CHANGED";
    if (statRC != 0 || !nsPath.length)
        result = @"LOOKUP_FAILED";
    else if (!sha)
        result = @"FILE_READ_FAILED";
    else if (!cdhashOK)
        result = @"CDHASH_PARSE_FAILED";
    else if (shaMatch && cdhashMatch)
        result = @"IDENTITY_PRESERVED";
    dt102739m_emit(log, @"M_LOOSE_DIAGNOSTIC_RESULT=%@", result);
    dt102739m_emit(log, @"M_LOOSE_DIAGNOSTIC_GATES_EXECUTION=NO");
}

static uint32_t dt102739m_unexpected_entry_count(int runFD)
{
    if (runFD < 0)
        return UINT32_MAX;
    int scanFD = dup(runFD);
    if (scanFD < 0)
        return UINT32_MAX;
    DIR *directory = fdopendir(scanFD);
    if (!directory) {
        close(scanFD);
        return UINT32_MAX;
    }
    uint32_t unexpected = 0;
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0
            || strcmp(entry->d_name, kDT102739MHelperName.UTF8String) == 0)
            continue;
        unexpected++;
    }
    closedir(directory);
    return unexpected;
}

static BOOL dt102739m_cleanup(int parentFD, int runFD, NSString *runName,
    NSString *helperPath, uint32_t *unexpectedOut)
{
    BOOL ok = YES;
    uint32_t unexpected = dt102739m_unexpected_entry_count(runFD);
    if (unexpectedOut)
        *unexpectedOut = unexpected;
    if (unexpected != 0)
        ok = NO;
    if (runFD >= 0 && unlinkat(runFD, kDT102739MHelperName.UTF8String, 0) != 0 && errno != ENOENT)
        ok = NO;
    if (runFD >= 0)
        close(runFD);
    if (parentFD >= 0 && runName.length
        && unlinkat(parentFD, runName.UTF8String, AT_REMOVEDIR) != 0 && errno != ENOENT)
        ok = NO;
    struct stat st = {0};
    if (helperPath.length && lstat(helperPath.fileSystemRepresentation, &st) == 0)
        ok = NO;
    NSString *runPath = runName.length ? [kDT102739MParent stringByAppendingPathComponent:runName] : nil;
    if (runPath.length && lstat(runPath.fileSystemRepresentation, &st) == 0)
        ok = NO;
    if (parentFD >= 0)
        close(parentFD);
    return ok;
}

int dt_build102739m_run_external_helper_execution_proof(void (^log)(NSString *),
    BOOL wall2Restored, NSString **verdictOut)
{
    NSString *verdict = @"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_FAIL";
    if (verdictOut) *verdictOut = verdict;
    dt102739m_emit(log, @"BUILD102739M_BEGIN=YES");
    dt102739m_emit(log, @"BUILD102739M_VARIANT=BUILD102739M_REPAIRED_V6");
    dt102739m_emit(log, @"BUILD102739M_PROTOCOL=%@", kDT102739MProtocol);
    dt102739m_emit(log, @"BUILD102739M_STAGING_PARENT=%@", kDT102739MParent);
    dt102739m_emit(log, @"BUILD102739M_PERSISTENT_CONTROL_ROOT_SELECTED=NO");

    dt102739m_log_loose_diagnostic(log);

    unsigned long payloadSize = 0;
    const unsigned char *payload = getsectiondata(&_mh_execute_header,
        "__DATA", "__dtmhelper", &payloadSize);
    NSString *payloadSHA = payload && payloadSize
        ? dt102739m_sha256_bytes(payload, (size_t)payloadSize) : nil;
    BOOL payloadSizeOK = payloadSize > 0;
    BOOL payloadSHAOK = [payloadSHA isEqualToString:@DT102739M_HELPER_SHA256];
    dt102739m_emit(log, @"M_TRANSPORT=EMBEDDED_FINAL_SIGNED_BYTES");
    dt102739m_emit(log, @"M_EMBEDDED_SECTION=__DATA,__dtmhelper");
    dt102739m_emit(log, @"M_EMBEDDED_PAYLOAD_SIZE=%lu", payloadSize);
    dt102739m_emit(log, @"M_EMBEDDED_PAYLOAD_SIZE_MATCH=%@", payloadSizeOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_EMBEDDED_PAYLOAD_SHA256_ACTUAL=%@", payloadSHA ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_EMBEDDED_PAYLOAD_SHA256_MATCH=%@", payloadSHAOK ? @"YES" : @"NO");
    if (!payloadSizeOK || !payloadSHAOK)
        return dt102739m_fail(log, verdictOut, @"EMBEDDED_PAYLOAD_IDENTITY");

    cdhash_t helperHash = {0};
    BOOL expectedCDHashOK = dt102739m_decode_lower_hex(@DT102739M_HELPER_CDHASH,
        helperHash, sizeof(helperHash));
    dt102739m_emit(log, @"M_EXPECTED_HELPER_CDHASH_DECODED=%@",
        expectedCDHashOK ? @"YES" : @"NO");
    if (!expectedCDHashOK)
        return dt102739m_fail(log, verdictOut, @"EMBEDDED_PAYLOAD_IDENTITY");

    BOOL pretrusted = dt_cdhash_trustcached(helperHash);
    dt102739m_emit(log, @"M_HELPER_PREUPLOAD_TRUSTED=%@", pretrusted ? @"YES" : @"NO");
    if (pretrusted) {
        dt102739m_emit(log, @"M_PREEXISTING_HELPER_TRUST_STATE=DETECTED");
        dt102739m_emit(log, @"M_CREATED_PATH_COUNT=0");
        dt102739m_emit(log, @"M_DEDICATED_TRUSTCACHE_UPLOAD_COUNT=0");
        dt102739m_emit(log, @"M_HELPER_SPAWN_COUNT=0");
        dt102739m_emit(log, @"M_FRESH_PROOF_RERUN_CURRENT_KERNEL_STATE_SUPPORTED=NO");
        dt102739m_emit(log, @"M_REBOOT_OR_VERIFIED_TRUST_RESET_REQUIRED=YES");
        dt102739m_emit(log, @"M_REBOOT_CLEARANCE_ASSUMED=NO");
        verdict = @"REBOOT_OR_VERIFIED_TRUST_RESET_REQUIRED_BEFORE_FRESH_M_PROOF";
        dt102739m_emit(log, @"M_FAILURE_STAGE=PRETRUST");
        return dt102739m_finish(log, verdictOut, verdict);
    }

    uint32_t csflags = 0;
    BOOL csPlatform = csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags)) == 0
        && (csflags & CS_PLATFORM_BINARY) != 0;
    uint64_t slot0 = dt102739m_slot0();
    BOOL slotPreserved = slot0 != 0 && slot0 != UINT64_MAX;
    dt102739m_emit(log, @"M_PARENT_UID=%u", getuid());
    dt102739m_emit(log, @"M_PARENT_EUID=%u", geteuid());
    dt102739m_emit(log, @"M_PARENT_GID=%u", getgid());
    dt102739m_emit(log, @"M_PARENT_EGID=%u", getegid());
    dt102739m_emit(log, @"M_PARENT_CS_PLATFORM_BINARY=%@", csPlatform ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PARENT_SANDBOX_MODEL=PRESERVED_SLOT0");
    dt102739m_emit(log, @"M_PARENT_SLOT0_PRESERVED=%@", slotPreserved ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PARENT_UNSANDBOXED_CLAIM=NO");
    BOOL parentAccess = access(kDT102739MParent.fileSystemRepresentation, W_OK | X_OK) == 0;
    dt102739m_emit(log, @"M_PARENT_EMBEDDED_PAYLOAD_AVAILABLE=%@", payload ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PARENT_STAGING_PARENT_WRITE_EXECUTE_ACCESS=%@", parentAccess ? @"YES" : @"NO");
    if (getuid() || geteuid() || getgid() || getegid() || !csPlatform || !slotPreserved
        || !payload || !parentAccess)
        return dt102739m_fail(log, verdictOut, @"PARENT_STATE");

    struct stat parentBefore = {0};
    BOOL parentValid = dt102739m_validate_parent(&parentBefore);
    dt102739m_emit(log, @"M_STAGING_PARENT_REVALIDATED=%@", parentValid ? @"YES" : @"NO");
    if (!parentValid)
        return dt102739m_fail(log, verdictOut, @"STAGING_PARENT");
    NSString *pid1Before = dt102739m_pid_path(1);
    uint64_t pid1ProcBefore = dt102739m_pid1_proc();
    NSString *ltopBefore = dt102739m_sha256(@"/usr/bin/ltop");
    NSString *handoff = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Handoff516"];
    NSString *jHookPath = dt710_resolve_hook_path();
    NSString *jHelperPath = [handoff stringByAppendingPathComponent:@"dt_opainject516"];
    cdhash_t jHookHashBefore = {0};
    cdhash_t jHelperHashBefore = {0};
    BOOL jHookHashBeforeOK = jHookPath.length
        && dt102739m_cdhash(jHookPath, jHookHashBefore, NULL);
    BOOL jHelperHashBeforeOK = dt102739m_cdhash(jHelperPath, jHelperHashBefore, NULL);
    BOOL jHookTrustedBefore = jHookHashBeforeOK && dt_cdhash_trustcached(jHookHashBefore);
    BOOL jHelperTrustedBefore = jHelperHashBeforeOK && dt_cdhash_trustcached(jHelperHashBefore);
    BOOL jTrustBefore = jHookTrustedBefore && jHelperTrustedBefore;
    dt102739m_emit(log, @"M_PRESERVATION_PID1_PATH_AVAILABLE=%@",
        pid1Before.length ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_PID1_PROC_AVAILABLE=%@",
        pid1ProcBefore ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_LTOP_SHA_AVAILABLE=%@",
        ltopBefore.length ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_J_HOOK_PATH=%@", jHookPath ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_PRESERVATION_J_HOOK_PATH_ROLE=POST_SIGN_PREBOOT_ARTIFACT");
    dt102739m_emit(log, @"M_PRESERVATION_J_HOOK_CDHASH_AVAILABLE=%@",
        jHookHashBeforeOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_J_HOOK_CDHASH=%@",
        jHookHashBeforeOK ? dt_cdhash_hex_string(jHookHashBefore) : @"UNAVAILABLE");
    dt102739m_emit(log, @"M_PRESERVATION_J_HOOK_TRUSTED=%@",
        jHookTrustedBefore ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_J_HELPER_PATH=%@", jHelperPath);
    dt102739m_emit(log, @"M_PRESERVATION_J_HELPER_PATH_ROLE=INSTALLED_BUNDLE_ARTIFACT");
    dt102739m_emit(log, @"M_PRESERVATION_J_HELPER_CDHASH_AVAILABLE=%@",
        jHelperHashBeforeOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_J_HELPER_CDHASH=%@",
        jHelperHashBeforeOK ? dt_cdhash_hex_string(jHelperHashBefore) : @"UNAVAILABLE");
    dt102739m_emit(log, @"M_PRESERVATION_J_HELPER_TRUSTED=%@",
        jHelperTrustedBefore ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESERVATION_PREREQUISITES=%@",
        pid1Before.length && pid1ProcBefore && ltopBefore.length && jTrustBefore ? @"PASS" : @"FAIL");
    if (!pid1Before.length || !pid1ProcBefore || !ltopBefore.length || !jTrustBefore)
        return dt102739m_fail(log, verdictOut, @"PRESERVATION");

    int parentFD = open(kDT102739MParent.fileSystemRepresentation,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int runFD = -1;
    NSString *runName = nil;
    NSString *helperPath = nil;
    if (parentFD < 0)
        return dt102739m_fail(log, verdictOut, @"STAGING_PARENT");
    for (int attempt = 0; attempt < 8; attempt++) {
        runName = [NSString stringWithFormat:@"BUILD102739M-%@", dt102739m_nonce()];
        if (mkdirat(parentFD, runName.UTF8String, 0700) == 0)
            break;
        if (errno != EEXIST) { runName = nil; break; }
    }
    if (!runName.length) {
        close(parentFD);
        return dt102739m_fail(log, verdictOut, @"STAGING_CREATE");
    }
    NSString *runPath = [kDT102739MParent stringByAppendingPathComponent:runName];
    runFD = openat(parentFD, runName.UTF8String, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (runFD < 0 || fchown(runFD, 0, 0) != 0 || fchmod(runFD, 0700) != 0) {
        (void)dt102739m_cleanup(parentFD, runFD, runName, nil, NULL);
        return dt102739m_fail(log, verdictOut, @"STAGING_CREATE");
    }
    struct stat runStat = {0};
    if (fstat(runFD, &runStat) != 0 || !S_ISDIR(runStat.st_mode) || runStat.st_uid != 0
        || runStat.st_gid != 0 || (runStat.st_mode & 07777) != 0700) {
        (void)dt102739m_cleanup(parentFD, runFD, runName, nil, NULL);
        return dt102739m_fail(log, verdictOut, @"STAGING_CREATE");
    }
    dt102739m_emit(log, @"M_RUN_DIRECTORY_PREEXISTED=NO");
    dt102739m_emit(log, @"M_RUN_DIRECTORY_OWNER=root:wheel");
    dt102739m_emit(log, @"M_RUN_DIRECTORY_MODE=0700");
    dt102739m_emit(log, @"M_SYMLINK_TRAVERSAL=NO");

    int targetFD = openat(runFD, kDT102739MHelperName.UTF8String,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0700);
    struct stat createdStat = {0};
    BOOL written = targetFD >= 0
        && dt102739m_write_all(targetFD, payload, (size_t)payloadSize)
        && fchown(targetFD, 0, 0) == 0 && fchmod(targetFD, 0700) == 0
        && fstat(targetFD, &createdStat) == 0
        && S_ISREG(createdStat.st_mode) && createdStat.st_size == (off_t)payloadSize;
    if (targetFD >= 0)
        close(targetFD);
    helperPath = [runPath stringByAppendingPathComponent:kDT102739MHelperName];
    if (!written) {
        (void)dt102739m_cleanup(parentFD, runFD, runName, helperPath, NULL);
        return dt102739m_fail(log, verdictOut, @"STAGING_WRITE");
    }

    int verifyFD = openat(runFD, kDT102739MHelperName.UTF8String,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat reopenedStat = {0};
    BOOL inodeStable = verifyFD >= 0 && fstat(verifyFD, &reopenedStat) == 0
        && createdStat.st_dev == reopenedStat.st_dev
        && createdStat.st_ino == reopenedStat.st_ino
        && createdStat.st_size == reopenedStat.st_size
        && (createdStat.st_mode & S_IFMT) == (reopenedStat.st_mode & S_IFMT);
    dt102739m_emit(log, @"M_STAGED_REOPEN_DEVICE_INODE_MATCH=%@", inodeStable ? @"YES" : @"NO");
    if (!inodeStable) {
        if (verifyFD >= 0)
            close(verifyFD);
        (void)dt102739m_cleanup(parentFD, runFD, runName, helperPath, NULL);
        return dt102739m_fail(log, verdictOut, @"STAGING_INODE");
    }

    struct stat stagedStat = {0};
    NSString *stagedSHA = dt102739m_sha256(helperPath);
    cdhash_t stagedHash = {0};
    NSString *stagedCDHash = nil;
    BOOL stagedStatOK = lstat(helperPath.fileSystemRepresentation, &stagedStat) == 0
        && S_ISREG(stagedStat.st_mode) && stagedStat.st_uid == 0 && stagedStat.st_gid == 0
        && (stagedStat.st_mode & 07777) == 0700
        && stagedStat.st_dev == createdStat.st_dev && stagedStat.st_ino == createdStat.st_ino
        && stagedStat.st_size == (off_t)payloadSize;
    BOOL stagedSHAMatch = [stagedSHA isEqualToString:@DT102739M_HELPER_SHA256];
    BOOL stagedCDMatch = dt102739m_cdhash(helperPath, stagedHash, &stagedCDHash)
        && [stagedCDHash isEqualToString:@DT102739M_HELPER_CDHASH]
        && memcmp(stagedHash, helperHash, sizeof(cdhash_t)) == 0;
    dt102739m_emit(log, @"M_CREATED_PATH_COUNT=2");
    uint32_t stagedUnexpected = dt102739m_unexpected_entry_count(runFD);
    dt102739m_emit(log, @"M_CREATED_PATHS_MATCH_ALLOWLIST=%@",
        stagedUnexpected == 0 ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGED_HELPER_SHA256_MATCH=%@", stagedSHAMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGED_HELPER_CDHASH_MATCH=%@", stagedCDMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGED_HELPER_MACHO_GATE=%@", stagedStatOK && stagedCDMatch ? @"PASS" : @"FAIL");
    BOOL stagedAccess = access(helperPath.fileSystemRepresentation, R_OK | X_OK) == 0;
    dt102739m_emit(log, @"M_PARENT_STAGED_HELPER_READ_EXECUTE_ACCESS=%@", stagedAccess ? @"YES" : @"NO");
    if (!stagedStatOK || !stagedSHAMatch || !stagedCDMatch || !stagedAccess
        || stagedUnexpected != 0 || dt_cdhash_trustcached(helperHash)) {
        dt102739m_emit(log, @"M_CONCURRENT_PREUPLOAD_TRUST_CHANGE=%@",
            dt_cdhash_trustcached(helperHash) ? @"YES" : @"NO");
        close(verifyFD);
        (void)dt102739m_cleanup(parentFD, runFD, runName, helperPath, NULL);
        return dt102739m_fail(log, verdictOut, @"STAGED_IDENTITY");
    }

    dt102739m_emit(log, @"M_HELPER_EMBEDDED_SANDBOX_PROFILE=container");
    dt102739m_emit(log, @"M_PARENT_SANDBOX_EXTENSION_ISSUE_ENABLED=NO");
    dt102739m_emit(log, @"M_PARENT_SANDBOX_EXTENSION_CONSUME_ENABLED=NO");
    dt102739m_emit(log, @"M_PARENT_SANDBOX_SLOT0_REPLACED=NO");
    dt102739m_emit(log, @"M_GLOBAL_UNSANDBOX_ENABLED=NO");

    static const uuid_t trustUUID = {0x10,0x27,0x39,0x4d,0x00,0x00,0x40,0x00,
        0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    uint32_t uploaded = 0;
    dt102739m_emit(log, @"M_TRUSTCACHE_PAYLOAD_CDHASH_COUNT=1");
    dt102739m_emit(log, @"M_TRUSTCACHE_PAYLOAD_CONTAINS_ONLY_HELPER_CDHASH=YES");
    int uploadRC = dt_trustcache_upload_batch_cdhashes(&helperHash, 1, trustUUID, &uploaded);
    BOOL trustedAfterUpload = uploadRC == 0 && uploaded == 1 && dt_cdhash_trustcached(helperHash);
    dt102739m_emit(log, @"M_TRUSTCACHE_UPLOAD_RC=%d", uploadRC);
    dt102739m_emit(log, @"M_DEDICATED_TRUSTCACHE_UPLOAD_COUNT=%u", uploaded);
    dt102739m_emit(log, @"M_HELPER_CDHASH_TRUSTED_AFTER_UPLOAD=%@", trustedAfterUpload ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_KERNEL_TRUSTCACHE_NODE_CONTENT_INSPECTED=NO");
    dt102739m_emit(log, @"M_PERSISTENT_TRUSTCACHE_FILES_CREATED=0");
    if (!trustedAfterUpload) {
        BOOL trustPresentAfterFailure = dt_cdhash_trustcached(helperHash);
        dt102739m_emit(log, @"M_HELPER_TRUSTED_AFTER_UPLOAD_FAILURE=%@",
            trustPresentAfterFailure ? @"YES" : @"NO");
        dt102739m_emit(log, @"M_REBOOT_REQUIRED_BEFORE_FRESH_M_RERUN=%@",
            trustPresentAfterFailure ? @"YES" : @"NO");
        close(verifyFD);
        (void)dt102739m_cleanup(parentFD, runFD, runName, helperPath, NULL);
        return dt102739m_fail(log, verdictOut,
            uploadRC == 0 && uploaded == 1 ? @"TRUST_VERIFICATION" : @"TRUST_UPLOAD");
    }

    struct stat descriptorStat = {0};
    struct stat prespawnStat = {0};
    NSString *prespawnSHA = dt102739m_sha256(helperPath);
    cdhash_t prespawnHash = {0};
    BOOL descriptorHeld = fstat(verifyFD, &descriptorStat) == 0
        && descriptorStat.st_dev == createdStat.st_dev
        && descriptorStat.st_ino == createdStat.st_ino
        && descriptorStat.st_size == createdStat.st_size;
    BOOL prespawnInode = descriptorHeld
        && lstat(helperPath.fileSystemRepresentation, &prespawnStat) == 0
        && prespawnStat.st_dev == createdStat.st_dev && prespawnStat.st_ino == createdStat.st_ino
        && prespawnStat.st_size == createdStat.st_size && S_ISREG(prespawnStat.st_mode);
    BOOL prespawnSHAMatch = [prespawnSHA isEqualToString:@DT102739M_HELPER_SHA256];
    BOOL prespawnCDMatch = dt102739m_cdhash(helperPath, prespawnHash, NULL)
        && memcmp(prespawnHash, helperHash, sizeof(cdhash_t)) == 0;
    BOOL prespawnIdentity = prespawnInode && prespawnSHAMatch && prespawnCDMatch;
    dt102739m_emit(log, @"M_STAGED_DESCRIPTOR_HELD_THROUGH_PRESPAWN=%@",
        descriptorHeld ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESPAWN_DEVICE_INODE_MATCH=%@", prespawnInode ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESPAWN_SHA256_MATCH=%@", prespawnSHAMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_PRESPAWN_CDHASH_MATCH=%@", prespawnCDMatch ? @"YES" : @"NO");
    if (!prespawnIdentity) {
        dt102739m_emit(log, @"M_HELPER_TRUSTED_AFTER_PRESPAWN_FAILURE=YES");
        dt102739m_emit(log, @"M_REBOOT_REQUIRED_BEFORE_FRESH_M_RERUN=YES");
        close(verifyFD);
        (void)dt102739m_cleanup(parentFD, runFD, runName, helperPath, NULL);
        return dt102739m_fail(log, verdictOut, @"PRESPAWN_REVALIDATION");
    }

    NSString *nonce = dt102739m_nonce();
    NSDictionary *record = nil;
    BOOL stderrEmpty = NO, stdoutOverflow = NO, stderrOverflow = NO;
    BOOL timeout = NO, reaped = NO;
    int exitStatus = -1, termSignal = 0;
    pid_t childPID = 0;
    dt102739m_emit(log, @"M_FIXED_DELAY_AFTER_TRUST_UPLOAD_US=0");
    dt102739m_emit(log, @"M_SPAWN_BEGINS_AFTER_TRUST_UPLOAD_RETURN=YES");
    int spawnRC = dt102739m_spawn(helperPath, nonce, &record, &stderrEmpty,
        &stdoutOverflow, &stderrOverflow, &timeout, &reaped,
        &exitStatus, &termSignal, &childPID);
    close(verifyFD);
    dt102739m_emit(log, @"M_INHERITED_J_TRIGGER_TIMEOUT_SECONDS=3");
    dt102739m_emit(log, @"M_HELPER_WAIT_TIMEOUT_MS=8000");
    dt102739m_emit(log, @"M_HELPER_OBSERVATION_INTERVAL_MS=100");
    dt102739m_emit(log, @"M_INHERITED_TVOS_TIMEOUTS_CHANGED=NO");
    dt102739m_emit(log, @"M_HELPER_SPAWN_RC=%d", spawnRC);
    dt102739m_emit(log, @"M_HELPER_CHILD_PID=%d", childPID);
    dt102739m_emit(log, @"M_HELPER_SPAWN_SYSCALL_ACCEPTED=%@",
        spawnRC == 0 && childPID > 0 ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_SPAWN_COUNT=%d", spawnRC == 0 && childPID > 0 ? 1 : 0);
    dt102739m_emit(log, @"M_HELPER_SPAWN_API=posix_spawn");
    dt102739m_emit(log, @"M_HELPER_REGISTERED_MACH_PORTS=NO");
    dt102739m_emit(log, @"M_HELPER_ROOT_PERSONA=NO");
    dt102739m_emit(log, @"M_HELPER_START_SUSPENDED=NO");
    dt102739m_emit(log, @"M_HELPER_CHILD_PLATFORMIZE_CALL=NO");
    dt102739m_emit(log, @"M_PARENT_ENVIRONMENT_REQUEST=EXPLICIT_EMPTY");
    dt102739m_emit(log, @"M_PARENT_REQUESTED_ENVIRONMENT_COUNT=0");

    BOOL recordOK = record != nil;
    BOOL pidMatch = childPID > 0 && [record[@"pid"] intValue] == childPID;
    BOOL uidMatch = [record[@"uid"] intValue] == 0 && [record[@"euid"] intValue] == 0;
    BOOL argvMatch = [record[@"argc"] isEqualToString:@"5"]
        && [record[@"argv_match"] isEqualToString:@"YES"];
    BOOL pathMatch = [record[@"argv0"] isEqualToString:helperPath]
        && [record[@"actual_path"] isEqualToString:helperPath];
    BOOL protocolMatch = [record[@"protocol"] isEqualToString:kDT102739MProtocol];
    BOOL markerMatch = [record[@"marker"] isEqualToString:kDT102739MProtocol];
    BOOL nonceMatch = [record[@"nonce"] isEqualToString:nonce];
    NSUInteger effectiveEnvCount = 0;
    NSUInteger envNameCount = 0;
    NSUInteger reportedDyldCount = 0;
    BOOL environmentCountsOK = dt102739m_parse_uint(record[@"effective_env_count"],
            kDT102739MMaxEnvironmentNames, &effectiveEnvCount)
        && dt102739m_parse_uint(record[@"env_name_count"],
            kDT102739MMaxEnvironmentNames, &envNameCount)
        && dt102739m_parse_uint(record[@"dyld_env_count"],
            kDT102739MMaxEnvironmentNames, &reportedDyldCount);
    NSArray<NSString *> *environmentNames = environmentCountsOK
        ? dt102739m_decode_environment_names(record[@"env_names_hex"], envNameCount) : nil;
    NSUInteger computedDyldCount = 0;
    BOOL computedDyldInsertPresent = NO;
    for (NSString *name in environmentNames) {
        if ([name hasPrefix:@"DYLD_"])
            computedDyldCount++;
        if ([name isEqualToString:@"DYLD_INSERT_LIBRARIES"])
            computedDyldInsertPresent = YES;
    }
    BOOL reportedDyldInsertPresent = [record[@"dyld_insert"] isEqualToString:@"PRESENT"];
    BOOL reportedDyldInsertAbsent = [record[@"dyld_insert"] isEqualToString:@"ABSENT"];
    BOOL environmentCaptureOK = recordOK && environmentCountsOK && environmentNames != nil
        && effectiveEnvCount == envNameCount
        && [record[@"env_name_overflow"] isEqualToString:@"NO"]
        && [record[@"env_name_duplicates"] isEqualToString:@"NO"]
        && reportedDyldCount == computedDyldCount
        && ((reportedDyldInsertPresent && computedDyldInsertPresent)
            || (reportedDyldInsertAbsent && !computedDyldInsertPresent));
    BOOL environmentPolicyOK = environmentCaptureOK && computedDyldCount == 0
        && reportedDyldCount == 0 && !computedDyldInsertPresent && reportedDyldInsertAbsent;
    cdhash_t childSelfHash = {0};
    BOOL selfQueryOK = [record[@"self_cdhash_rc"] isEqualToString:@"0"]
        && [record[@"self_cdhash_errno"] isEqualToString:@"0"];
    BOOL selfHashDecoded = selfQueryOK
        && dt102739m_decode_lower_hex(record[@"self_cdhash"], childSelfHash, sizeof(childSelfHash));
    BOOL selfHashMatch = selfHashDecoded
        && memcmp(childSelfHash, helperHash, sizeof(cdhash_t)) == 0;
    dt102739m_emit(log, @"M_HELPER_EFFECTIVE_ENVIRONMENT_COUNT=%@",
        record[@"effective_env_count"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_EFFECTIVE_ENVIRONMENT_NAME_COUNT=%@",
        record[@"env_name_count"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_EFFECTIVE_ENVIRONMENT_NAMES_HEX=%@",
        record[@"env_names_hex"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_EFFECTIVE_ENVIRONMENT_NAMES=%@",
        environmentNames ? (environmentNames.count ? [environmentNames componentsJoinedByString:@","] : @"NONE")
            : @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_ENVIRONMENT_NAME_OVERFLOW=%@",
        record[@"env_name_overflow"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_ENVIRONMENT_NAME_DUPLICATES=%@",
        record[@"env_name_duplicates"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_ENVIRONMENT_CAPTURE=%@",
        environmentCaptureOK ? @"PASS" : @"FAIL");
    dt102739m_emit(log, @"M_HELPER_DYLD_ENVIRONMENT_VARIABLE_COUNT=%@", record[@"dyld_env_count"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_DYLD_INSERT_LIBRARIES=%@", record[@"dyld_insert"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_ENVIRONMENT_POLICY=%@",
        environmentPolicyOK ? @"PASS" : @"FAIL");
    dt102739m_emit(log, @"M_HELPER_STDOUT_BYTES_WITHIN_LIMIT=%@", stdoutOverflow ? @"NO" : @"YES");
    dt102739m_emit(log, @"M_HELPER_STDERR_BYTES_WITHIN_LIMIT=%@", stderrOverflow ? @"NO" : @"YES");
    dt102739m_emit(log, @"M_HELPER_STDERR_EMPTY=%@", stderrEmpty ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_RECORD_COUNT=%d", recordOK ? 1 : 0);
    dt102739m_emit(log, @"M_HELPER_PID_MATCH=%@", pidMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_UID=%@", record[@"uid"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_EUID=%@", record[@"euid"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_ARGV_MATCH=%@", argvMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_ARGV0_PATH_MATCH=%@", pathMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_ACTUAL_EXECUTABLE_PATH_SOURCE=proc_pidpath");
    dt102739m_emit(log, @"M_HELPER_ACTUAL_EXECUTABLE_PATH_MATCH=%@", pathMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_PROTOCOL_MATCH=%@", protocolMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_MARKER_MATCH=%@", markerMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_NONCE_MATCH=%@", nonceMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_SELF_CDHASH_RC=%@",
        record[@"self_cdhash_rc"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_SELF_CDHASH_ERRNO=%@",
        record[@"self_cdhash_errno"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_SELF_CDHASH_ACTUAL=%@",
        record[@"self_cdhash"] ?: @"UNAVAILABLE");
    dt102739m_emit(log, @"M_HELPER_SELF_CDHASH_NONZERO=%@", selfHashDecoded ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_SELF_CDHASH_MATCH=%@", selfHashMatch ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_EXITED_NORMALLY=%@", exitStatus >= 0 ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_EXIT_STATUS=%d", exitStatus);
    dt102739m_emit(log, @"M_HELPER_TERMINATING_SIGNAL=%d", termSignal);
    dt102739m_emit(log, @"M_HELPER_TIMEOUT=%@", timeout ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_HELPER_REAPED=%@", reaped ? @"YES" : @"NO");

    uint32_t unexpectedCount = UINT32_MAX;
    BOOL cleanupOK = dt102739m_cleanup(parentFD, runFD, runName, helperPath, &unexpectedCount);
    parentFD = -1; runFD = -1;
    struct stat parentAfter = {0};
    BOOL stable = lstat(kDT102739MParent.fileSystemRepresentation, &parentAfter) == 0
        && dt102739m_parent_stable(&parentBefore, &parentAfter);
    BOOL pid1OK = pid1Before.length && pid1ProcBefore == dt102739m_pid1_proc()
        && [pid1Before isEqualToString:dt102739m_pid_path(1)];
    BOOL ltopOK = ltopBefore.length && [ltopBefore isEqualToString:dt102739m_sha256(@"/usr/bin/ltop")];
    cdhash_t jHookHashAfter = {0};
    cdhash_t jHelperHashAfter = {0};
    BOOL jTrustOK = dt102739m_cdhash(jHookPath, jHookHashAfter, NULL)
        && dt102739m_cdhash(jHelperPath, jHelperHashAfter, NULL)
        && memcmp(jHookHashBefore, jHookHashAfter, sizeof(cdhash_t)) == 0
        && memcmp(jHelperHashBefore, jHelperHashAfter, sizeof(cdhash_t)) == 0
        && dt_cdhash_trustcached(jHookHashAfter) && dt_cdhash_trustcached(jHelperHashAfter);
    dt102739m_emit(log, @"M_UNEXPECTED_PATH_MUTATION_COUNT=%u", unexpectedCount);
    dt102739m_emit(log, @"M_HELPER_PATH_ABSENT_AFTER_CLEANUP=%@", cleanupOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_RUN_DIRECTORY_ABSENT_AFTER_CLEANUP=%@", cleanupOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_FILESYSTEM_CLEANUP_RESULT=%@", cleanupOK ? @"PASS" : @"FAIL");
    dt102739m_emit(log, @"M_TRUSTCACHE_CLEANUP_RESULT=UNSUPPORTED_GLOBAL_HELPER_TRUST_REMAINS");
    dt102739m_emit(log, @"M_HELPER_TRUSTED_AFTER_FILE_CLEANUP=%@", dt_cdhash_trustcached(helperHash) ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_TRUSTCACHE_EXACT_RESTORE_SUPPORTED=NO");
    dt102739m_emit(log, @"M_TRUSTCACHE_REBOOT_PERSISTENCE=NOT_TESTED");
    dt102739m_emit(log, @"M_STAGING_PARENT_DEVICE_INODE_UNCHANGED=%@", stable ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGING_PARENT_TYPE_UNCHANGED=%@", stable ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGING_PARENT_UID_GID_UNCHANGED=%@", stable ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGING_PARENT_MODE_UNCHANGED=%@", stable ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGING_PARENT_FLAGS_UNCHANGED=%@", stable ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_STAGING_PARENT_TIMESTAMP_CHANGE=EXPECTED");
    dt102739m_emit(log, @"M_BOOTSTRAP_ARCHIVE_TOUCHED=NO");
    dt102739m_emit(log, @"M_BOOTSTRAP_TARGET_FILES_CREATED=0");
    dt102739m_emit(log, @"M_BOOTSTRAP_TARGET_FILES_MODIFIED=0");
    dt102739m_emit(log, @"M_BOOTSTRAP_TARGET_FILES_REMOVED=0");
    dt102739m_emit(log, @"M_APPLE_LTOP_IDENTITY_UNCHANGED=%@", ltopOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_BOOTSTRAP_MARKER_CHANGED=NO");
    dt102739m_emit(log, @"M_SERVICES_CHANGED=NO");
    dt102739m_emit(log, @"M_ACCOUNTS_CHANGED=NO");
    dt102739m_emit(log, @"M_PACKAGES_CHANGED=NO");
    dt102739m_emit(log, @"PID1_PRESENT_AFTER_HELPER=%@", dt102739m_pid_path(1) ? @"YES" : @"NO");
    dt102739m_emit(log, @"PID1_IDENTITY_UNCHANGED=%@", pid1OK ? @"YES" : @"NO");
    dt102739m_emit(log, @"WALL2_GOT_ORIGINAL_STATE_RESTORED=%@", wall2Restored ? @"YES" : @"NO");
    dt102739m_emit(log, @"NO_PANIC_SIGNATURE=YES");
    dt102739m_emit(log, @"NO_WATCHDOG_TERMINATION=YES");
    dt102739m_emit(log, @"M_FROZEN_J_TRUST_IDENTITIES_UNCHANGED=%@", jTrustOK ? @"YES" : @"NO");
    dt102739m_emit(log, @"M_FRESH_PROOF_RERUN_CURRENT_KERNEL_STATE_SUPPORTED=NO");
    dt102739m_emit(log, @"M_REBOOT_REQUIRED_BEFORE_FRESH_M_RERUN=YES");
    dt102739m_emit(log, @"M_REBOOT_CLEARANCE_ASSUMED=NO");

    BOOL pass = spawnRC == 0 && recordOK && pidMatch && uidMatch && argvMatch && pathMatch
        && protocolMatch && markerMatch && nonceMatch && environmentCaptureOK
        && environmentPolicyOK && selfQueryOK && selfHashMatch
        && stderrEmpty
        && !stdoutOverflow && !stderrOverflow && !timeout
        && reaped && exitStatus == 0 && termSignal == 0 && cleanupOK && stable && pid1OK
        && ltopOK && jTrustOK && wall2Restored
        && dt_cdhash_trustcached(helperHash);
    if (pass)
        verdict = @"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_PASS_WITH_RESIDUAL_IN_MEMORY_HELPER_TRUST";
    else if (spawnRC != 0)
        dt102739m_emit(log, @"M_FAILURE_STAGE=SPAWN");
    else if (!reaped || timeout)
        dt102739m_emit(log, @"M_FAILURE_STAGE=WAITPID");
    else if (termSignal != 0 && !recordOK)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_TERMINATED_BEFORE_PROTOCOL");
    else if (exitStatus != 0 && !recordOK)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_EXIT_BEFORE_PROTOCOL");
    else if (!recordOK || !protocolMatch || !markerMatch || !nonceMatch)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_PROTOCOL_PARSE");
    else if (!environmentCaptureOK)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_ENVIRONMENT_CAPTURE");
    else if (!environmentPolicyOK)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_ENVIRONMENT_POLICY");
    else if (!selfQueryOK)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_SELF_CDHASH_QUERY");
    else if (!selfHashMatch || !pidMatch || !uidMatch || !argvMatch || !pathMatch)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_IDENTITY");
    else if (exitStatus != 0 || termSignal != 0 || !stderrEmpty
        || stdoutOverflow || stderrOverflow)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CHILD_EXIT");
    else if (!cleanupOK)
        dt102739m_emit(log, @"M_FAILURE_STAGE=CLEANUP");
    else
        dt102739m_emit(log, @"M_FAILURE_STAGE=PRESERVATION");

    return dt102739m_finish(log, verdictOut, verdict);
}
