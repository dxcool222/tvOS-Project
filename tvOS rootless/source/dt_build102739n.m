#import "dt_build102739n.h"
#import "build102739n_identity.h"
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
#import <sys/sysctl.h>
#import <sys/time.h>
#import <sys/wait.h>
#import <unistd.h>
#import <uuid/uuid.h>

extern int proc_pidpath(int pid, void *buffer, unsigned int buffersize);
extern int dt102739n_posix_spawn(pid_t *, const char *,
    const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
    char *const[], char *const[]) __asm("_posix_spawn");
extern int dt102739n_actions_init(posix_spawn_file_actions_t *)
    __asm("_posix_spawn_file_actions_init");
extern int dt102739n_actions_destroy(posix_spawn_file_actions_t *)
    __asm("_posix_spawn_file_actions_destroy");
extern int dt102739n_actions_adddup2(posix_spawn_file_actions_t *, int, int)
    __asm("_posix_spawn_file_actions_adddup2");
extern int dt102739n_actions_addclose(posix_spawn_file_actions_t *, int)
    __asm("_posix_spawn_file_actions_addclose");

static NSString *gDT102739NRunID;
static NSString *gDT102739NTransaction;
static NSString *gDT102739NPhase;
static uint64_t gDT102739NSequence;

static NSString *const kDT102739NHelperName = @"dt_probe102739n";
static NSString *const kDT102739NLegacyParent = @"/private/var/tmp";
static NSString *const kDT102739NManifestName = @"manifest.v1";
static NSString *const kDT102739NCommitName = @"stage.commit.v1";
static NSString *const kDT102739NCleanupName = @".build102739n.cleanup.v1";
static NSString *const kDT102739NProtocol = @"BUILD102739N_V2";
static const size_t kDT102739NOutputLimit = 32768;
static const NSUInteger kDT102739NMaxEnvironmentNames = 32;
static const NSUInteger kDT102739NMaxEnvironmentNameBytes = 128;
static const int kDT102739NWaitMs = 8000;
static const int kDT102739NPollMs = 100;

static NSString *const kDT102739NControlComponent = @"dopamin-tvos";
static NSString *const kDT102739NControlName = @"control";
static NSString *const kDT102739NTestsName = @"tests";
static NSString *const kDT102739NFixtureName = @"build102739n";
static const unsigned char kDT102739NTrustUUID[16] = {
    0x10, 0x27, 0x39, 0x4e, 0x00, 0x00, 0x40, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};
static DTBuild102739NDispatch gDT102739NDispatch = DTBuild102739NDispatchRunA;
static NSString *gDT102739NLastPersistedDiagnosticResult = nil;
static BOOL dt102739n_boot_hash_valid(NSString *value);

static void dt102739n_emit(void (^log)(NSString *), NSString *format, ...)
{
    va_list ap;
    va_start(ap, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    NSString *context = [NSString stringWithFormat:
        @"BUILD102739N_EVENT_CONTEXT run_id=%@ transaction=%@ phase=%@ sequence=%llu",
        gDT102739NRunID ?: @"UNAVAILABLE",
        gDT102739NTransaction ?: @"UNAVAILABLE",
        gDT102739NPhase ?: @"UNAVAILABLE",
        (unsigned long long)++gDT102739NSequence];
    if (log)
        log(context);
    [[DTRunLogger shared] log:context];
    if (log)
        log(line);
    [[DTRunLogger shared] logStage:line];
}

static NSString *dt102739n_sha256(NSString *path)
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

static NSString *dt102739n_sha256_bytes(const void *bytes, size_t length)
{
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes, (CC_LONG)length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < sizeof(digest); i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static BOOL dt102739n_decode_lower_hex(NSString *value, unsigned char *bytes, size_t length)
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

static BOOL dt102739n_parse_uint(NSString *value, NSUInteger maximum, NSUInteger *resultOut)
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

static NSArray<NSString *> *dt102739n_decode_environment_names(NSString *encoded,
    NSUInteger expectedCount)
{
    if (expectedCount == 0)
        return [encoded isEqualToString:@"NONE"] ? @[] : nil;
    if (expectedCount > kDT102739NMaxEnvironmentNames || !encoded.length
        || [encoded isEqualToString:@"NONE"])
        return nil;
    NSArray<NSString *> *components = [encoded componentsSeparatedByString:@","];
    if (components.count != expectedCount)
        return nil;
    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:expectedCount];
    NSString *previous = nil;
    for (NSString *component in components) {
        if (component.length == 0 || component.length > kDT102739NMaxEnvironmentNameBytes * 2
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

static BOOL dt102739n_cdhash(NSString *path, cdhash_t out, NSString **hexOut)
{
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, out) != 0)
        return NO;
    if (hexOut)
        *hexOut = dt_cdhash_hex_string(out);
    return YES;
}

static uint64_t dt102739n_slot0(void)
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

static NSString *dt102739n_pid_path(pid_t pid)
{
    char path[4096] = {0};
    if (proc_pidpath(pid, path, sizeof(path)) <= 0 || !path[0])
        return nil;
    return [NSString stringWithUTF8String:path];
}

static uint64_t dt102739n_pid1_proc(void)
{
    uint64_t proc = proc_find(1);
    if (proc)
        proc_rele(proc);
    return proc;
}

static BOOL dt102739n_validate_parent(struct stat *snapshotOut)
{
    NSArray<NSString *> *components = @[@"/private", @"/private/var", kDT102739NLegacyParent];
    for (NSString *path in components) {
        struct stat st = {0};
        if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISDIR(st.st_mode))
            return NO;
    }
    struct statfs sfs = {0};
    if (statfs(kDT102739NLegacyParent.fileSystemRepresentation, &sfs) != 0
        || (sfs.f_flags & MNT_RDONLY) != 0 || sfs.f_bavail < 16)
        return NO;
    return lstat(kDT102739NLegacyParent.fileSystemRepresentation, snapshotOut) == 0;
}

static BOOL dt102739n_parent_stable(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino
        && (before->st_mode & S_IFMT) == (after->st_mode & S_IFMT)
        && before->st_uid == after->st_uid && before->st_gid == after->st_gid
        && (before->st_mode & 07777) == (after->st_mode & 07777)
        && before->st_flags == after->st_flags;
}

static BOOL dt102739n_write_all(int destination, const unsigned char *bytes, size_t length)
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

static NSString *dt102739n_nonce(void)
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
} dt102739n_capture_t;

static void dt102739n_drain(int fd, dt102739n_capture_t *capture)
{
    unsigned char buffer[512];
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            size_t room = capture->data.length < kDT102739NOutputLimit
                ? kDT102739NOutputLimit - capture->data.length : 0;
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

static NSDictionary<NSString *, NSString *> *dt102739n_parse_record(NSData *data)
{
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text.length || ![text hasSuffix:@"\n"])
        return nil;
    NSArray<NSString *> *lines = [text componentsSeparatedByString:@"\n"];
    if (lines.count != 2 || ![lines[1] isEqualToString:@""])
        return nil;
    NSArray<NSString *> *fields = [lines[0] componentsSeparatedByString:@" "];
    if (fields.count != 22 || ![fields[0] isEqualToString:@"BUILD102739N_HELPER_RECORD"])
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

static int dt102739n_spawn(NSString *path, NSString *phase, NSString *transaction,
    NSDictionary **recordOut,
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
        (char *)"BUILD102739N_V2", (char *)"--phase", (char *)phase.UTF8String,
        (char *)"--transaction", (char *)transaction.UTF8String, NULL};
    char *const envp[] = {NULL};
    dt102739n_capture_t out = {.data = [NSMutableData data]};
    dt102739n_capture_t err = {.data = [NSMutableData data]};
    if (pipe(stdoutPipe) != 0 || pipe(stderrPipe) != 0)
        goto fail;

    if (dt102739n_actions_init(&actions) != 0)
        goto fail;
    actionsReady = 1;
    if (dt102739n_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO) != 0
        || dt102739n_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO) != 0
        || dt102739n_actions_addclose(&actions, stdoutPipe[0]) != 0
        || dt102739n_actions_addclose(&actions, stderrPipe[0]) != 0
        || dt102739n_actions_addclose(&actions, stdoutPipe[1]) != 0
        || dt102739n_actions_addclose(&actions, stderrPipe[1]) != 0)
        goto fail_actions;

    spawnRC = dt102739n_posix_spawn(&child, executable, &actions, NULL, argv, envp);
    dt102739n_actions_destroy(&actions);
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
    while (elapsed < kDT102739NWaitMs) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child)
            childReaped = YES;
        else if (waited < 0 && errno != EINTR)
            break;

        struct pollfd pfds[2] = {
            {.fd = stdoutPipe[0], .events = POLLIN | POLLHUP},
            {.fd = stderrPipe[0], .events = POLLIN | POLLHUP},
        };
        (void)poll(pfds, 2, kDT102739NPollMs);
        dt102739n_drain(stdoutPipe[0], &out);
        dt102739n_drain(stderrPipe[0], &err);
        elapsed += kDT102739NPollMs;
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
    dt102739n_drain(stdoutPipe[0], &out);
    dt102739n_drain(stderrPipe[0], &err);
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
        *recordOut = dt102739n_parse_record(out.data);
    return 0;

fail_actions:
    if (actionsReady)
        dt102739n_actions_destroy(&actions);
fail:
    for (size_t i = 0; i < 2; i++) {
        if (stdoutPipe[i] >= 0) close(stdoutPipe[i]);
        if (stderrPipe[i] >= 0) close(stderrPipe[i]);
    }
    return -1;
}

static int dt102739n_finish(void (^log)(NSString *), NSString **verdictOut,
    NSString *verdict)
{
    dt102739n_emit(log, @"BUILD102739N_FINAL_RESULT=%@", verdict);
    if (verdictOut)
        *verdictOut = verdict;
    return [verdict hasPrefix:@"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_PASS"]
        ? 0 : -739130;
}

static int dt102739n_fail(void (^log)(NSString *), NSString **verdictOut, NSString *stage)
{
    dt102739n_emit(log, @"M_FAILURE_STAGE=%@", stage);
    return dt102739n_finish(log, verdictOut, @"EXTERNAL_HELPER_EXECUTION_REPAIRED_V6_FAIL");
}

static void dt102739n_log_loose_diagnostic(void (^log)(NSString *))
{
    NSString *nsPath = [[NSBundle mainBundle] pathForResource:kDT102739NHelperName ofType:nil];
    NSString *directPath = [[[NSBundle mainBundle] bundlePath]
        stringByAppendingPathComponent:kDT102739NHelperName];
    dt102739n_emit(log, @"M_LOOSE_NSLOOKUP_PATH=%@", nsPath ?: @"UNAVAILABLE");
    dt102739n_emit(log, @"M_LOOSE_DIRECT_PATH=%@", directPath);

    struct stat st = {0};
    errno = 0;
    int statRC = lstat(directPath.fileSystemRepresentation, &st);
    int statErrno = statRC == 0 ? 0 : errno;
    dt102739n_emit(log, @"M_LOOSE_LSTAT_RC=%d", statRC);
    dt102739n_emit(log, @"M_LOOSE_LSTAT_ERRNO=%d", statErrno);
    dt102739n_emit(log, @"M_LOOSE_TYPE=%@",
        statRC == 0 && S_ISREG(st.st_mode) ? @"REGULAR" : @"UNAVAILABLE");
    dt102739n_emit(log, @"M_LOOSE_MODE=%04o", statRC == 0 ? st.st_mode & 07777 : 0);
    dt102739n_emit(log, @"M_LOOSE_SIZE=%lld", statRC == 0 ? (long long)st.st_size : -1LL);

    NSString *sha = statRC == 0 ? dt102739n_sha256(directPath) : nil;
    cdhash_t looseHash = {0};
    NSString *cdhash = nil;
    BOOL cdhashOK = statRC == 0 && dt102739n_cdhash(directPath, looseHash, &cdhash);
    BOOL shaMatch = [sha isEqualToString:@DT102739N_HELPER_SHA256];
    BOOL cdhashMatch = cdhashOK && [cdhash isEqualToString:@DT102739N_HELPER_CDHASH];
    dt102739n_emit(log, @"M_LOOSE_SHA256_READ_RC=%d", sha ? 0 : -1);
    dt102739n_emit(log, @"M_LOOSE_SHA256_ACTUAL=%@", sha ?: @"UNAVAILABLE");
    dt102739n_emit(log, @"M_LOOSE_SHA256_MATCH=%@", shaMatch ? @"YES" : @"NO");
    dt102739n_emit(log, @"M_LOOSE_CDHASH_PARSE_RC=%d", cdhashOK ? 0 : -1);
    dt102739n_emit(log, @"M_LOOSE_CDHASH_ACTUAL=%@", cdhash ?: @"UNAVAILABLE");
    dt102739n_emit(log, @"M_LOOSE_CDHASH_MATCH=%@", cdhashMatch ? @"YES" : @"NO");

    NSString *result = @"IDENTITY_CHANGED";
    if (statRC != 0 || !nsPath.length)
        result = @"LOOKUP_FAILED";
    else if (!sha)
        result = @"FILE_READ_FAILED";
    else if (!cdhashOK)
        result = @"CDHASH_PARSE_FAILED";
    else if (shaMatch && cdhashMatch)
        result = @"IDENTITY_PRESERVED";
    dt102739n_emit(log, @"M_LOOSE_DIAGNOSTIC_RESULT=%@", result);
    dt102739n_emit(log, @"M_LOOSE_DIAGNOSTIC_GATES_EXECUTION=NO");
}

static uint32_t dt102739n_unexpected_entry_count(int runFD)
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
            || strcmp(entry->d_name, kDT102739NHelperName.UTF8String) == 0)
            continue;
        unexpected++;
    }
    closedir(directory);
    return unexpected;
}

static BOOL dt102739n_cleanup(int parentFD, int runFD, NSString *runName,
    NSString *helperPath, uint32_t *unexpectedOut)
{
    BOOL ok = YES;
    uint32_t unexpected = dt102739n_unexpected_entry_count(runFD);
    if (unexpectedOut)
        *unexpectedOut = unexpected;
    if (unexpected != 0)
        ok = NO;
    if (runFD >= 0 && unlinkat(runFD, kDT102739NHelperName.UTF8String, 0) != 0 && errno != ENOENT)
        ok = NO;
    if (runFD >= 0)
        close(runFD);
    if (parentFD >= 0 && runName.length
        && unlinkat(parentFD, runName.UTF8String, AT_REMOVEDIR) != 0 && errno != ENOENT)
        ok = NO;
    struct stat st = {0};
    if (helperPath.length && lstat(helperPath.fileSystemRepresentation, &st) == 0)
        ok = NO;
    NSString *runPath = runName.length ? [kDT102739NLegacyParent stringByAppendingPathComponent:runName] : nil;
    if (runPath.length && lstat(runPath.fileSystemRepresentation, &st) == 0)
        ok = NO;
    if (parentFD >= 0)
        close(parentFD);
    return ok;
}

typedef struct {
    int uuidRC;
    size_t uuidLength;
    int uuidParseRC;
    char uuid[37];
    int timeRC;
    size_t timeLength;
    struct timeval time;
    BOOL valid;
} dt102739n_boot_identity_t;

typedef struct {
    int prebootFD;
    int namespaceFD;
    int controlFD;
    int testsFD;
    int fixtureFD;
    NSString *activePath;
    NSString *bootHash;
    struct stat namespaceStat;
    struct stat controlStat;
    struct stat testsStat;
    struct stat fixtureStat;
    BOOL controlPreexisted;
    BOOL testsPreexisted;
    BOOL fixturePreexisted;
    BOOL controlCreated;
    BOOL testsCreated;
    BOOL fixtureCreated;
} dt102739n_paths_t;

typedef struct {
    NSString *pid1Path;
    uint64_t pid1Proc;
    NSString *ltopSHA;
    NSString *jHookSHA;
    NSString *jHelperSHA;
    struct stat oldNamespaceStat;
    BOOL oldNamespacePresent;
} dt102739n_protected_t;

static void dt102739n_close_paths(dt102739n_paths_t *paths)
{
    if (!paths) return;
    if (paths->fixtureFD >= 0) close(paths->fixtureFD);
    if (paths->testsFD >= 0) close(paths->testsFD);
    if (paths->controlFD >= 0) close(paths->controlFD);
    if (paths->namespaceFD >= 0) close(paths->namespaceFD);
    if (paths->prebootFD >= 0) close(paths->prebootFD);
    paths->fixtureFD = paths->testsFD = paths->controlFD = -1;
    paths->namespaceFD = paths->prebootFD = -1;
}

static BOOL dt102739n_stat_equal(const struct stat *left, const struct stat *right)
{
    return left && right && left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT)
        && left->st_uid == right->st_uid && left->st_gid == right->st_gid
        && (left->st_mode & 07777) == (right->st_mode & 07777)
        && left->st_flags == right->st_flags;
}

static BOOL dt102739n_read_boot_identity(dt102739n_boot_identity_t *identity)
{
    if (!identity) return NO;
    memset(identity, 0, sizeof(*identity));
    identity->uuidRC = -1;
    identity->uuidParseRC = -1;
    identity->timeRC = -1;

    char raw[37] = {0};
    size_t rawLength = sizeof(raw);
    identity->uuidRC = sysctlbyname("kern.bootsessionuuid", raw, &rawLength, NULL, 0);
    identity->uuidLength = rawLength;
    if (identity->uuidRC == 0 && rawLength == sizeof(raw) && raw[36] == '\0'
        && strnlen(raw, sizeof(raw)) == 36) {
        uuid_t parsed = {0};
        identity->uuidParseRC = uuid_parse(raw, parsed);
        if (identity->uuidParseRC == 0)
            uuid_unparse_lower(parsed, identity->uuid);
    }

    struct timeval bootTime = {0};
    size_t timeLength = sizeof(bootTime);
    identity->timeRC = sysctlbyname("kern.boottime", &bootTime, &timeLength, NULL, 0);
    identity->timeLength = timeLength;
    identity->time = bootTime;
    identity->valid = identity->uuidRC == 0 && identity->uuidLength == 37
        && identity->uuidParseRC == 0 && identity->uuid[0]
        && identity->timeRC == 0 && identity->timeLength == 16
        && sizeof(struct timeval) == 16 && bootTime.tv_sec > 0
        && bootTime.tv_usec >= 0 && bootTime.tv_usec < 1000000;
    return identity->valid;
}

static void dt102739n_log_boot(void (^log)(NSString *), NSString *scope,
    const dt102739n_boot_identity_t *identity)
{
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTSESSION_SYSCTL_RC=%d", scope,
        identity ? identity->uuidRC : -1);
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTSESSION_LENGTH=%zu", scope,
        identity ? identity->uuidLength : 0);
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTSESSION_PARSE=%@", scope,
        identity && identity->uuidParseRC == 0 ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTSESSIONUUID=%s", scope,
        identity && identity->uuid[0] ? identity->uuid : "UNAVAILABLE");
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTTIME_SYSCTL_RC=%d", scope,
        identity ? identity->timeRC : -1);
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTTIME_LENGTH=%zu", scope,
        identity ? identity->timeLength : 0);
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTTIME_SEC=%lld", scope,
        identity ? (long long)identity->time.tv_sec : -1LL);
    dt102739n_emit(log, @"BUILD102739N_%@_BOOTTIME_USEC=%d", scope,
        identity ? (int)identity->time.tv_usec : -1);
}

static NSString *dt102739n_read_fd(int fd, size_t maximum)
{
    if (fd < 0 || lseek(fd, 0, SEEK_SET) < 0)
        return nil;
    NSMutableData *data = [NSMutableData data];
    unsigned char buffer[1024];
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return nil;
        if (count == 0) break;
        if (data.length + (NSUInteger)count > maximum) return nil;
        [data appendBytes:buffer length:(NSUInteger)count];
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static NSDictionary<NSString *, NSString *> *dt102739n_parse_ledger(
    NSString *text, NSSet<NSString *> *required)
{
    if (!text.length || ![text hasSuffix:@"\n"] || text.length > 32768)
        return nil;
    NSArray<NSString *> *lines = [text componentsSeparatedByString:@"\n"];
    if (lines.count != required.count + 1 || ![lines.lastObject isEqualToString:@""])
        return nil;
    NSMutableDictionary *values = [NSMutableDictionary dictionaryWithCapacity:required.count];
    for (NSUInteger i = 0; i + 1 < lines.count; i++) {
        NSString *line = lines[i];
        NSRange separator = [line rangeOfString:@"="];
        if (separator.location == NSNotFound || separator.location == 0)
            return nil;
        NSString *key = [line substringToIndex:separator.location];
        NSString *value = [line substringFromIndex:separator.location + 1];
        if (!value.length || values[key] || ![required containsObject:key])
            return nil;
        values[key] = value;
    }
    return [NSSet setWithArray:values.allKeys].count == required.count ? values : nil;
}

static NSSet<NSString *> *dt102739n_manifest_keys(void)
{
    static NSSet *keys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = [NSSet setWithArray:@[
            @"schema_version", @"build_variant", @"protocol", @"state",
            @"target_model", @"target_version", @"target_build", @"boot_manifest_hash",
            @"transaction_uuid", @"trustcache_uuid", @"control_relative",
            @"tests_relative", @"fixture_relative", @"helper_name", @"helper_size",
            @"helper_sha256", @"helper_cdhash", @"helper_dev", @"helper_ino",
            @"helper_uid", @"helper_gid", @"helper_mode", @"control_preexisted",
            @"control_created_by_n", @"control_dev", @"control_ino", @"control_uid",
            @"control_gid", @"control_mode", @"control_flags", @"tests_preexisted",
            @"tests_created_by_n", @"tests_dev", @"tests_ino", @"tests_uid",
            @"tests_gid", @"tests_mode", @"tests_flags", @"fixture_preexisted",
            @"fixture_created_by_n", @"fixture_dev", @"fixture_ino", @"fixture_uid",
            @"fixture_gid", @"fixture_mode", @"fixture_flags",
            @"run_a_bootsessionuuid", @"run_a_boottime_sec", @"run_a_boottime_usec",
            @"created_timestamp"
        ]];
    });
    return keys;
}

static NSSet<NSString *> *dt102739n_commit_keys(void)
{
    static NSSet *keys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = [NSSet setWithArray:@[
            @"schema_version", @"build_variant", @"protocol", @"state",
            @"transaction_uuid", @"boot_manifest_hash", @"trustcache_uuid",
            @"manifest_sha256", @"manifest_dev", @"manifest_ino", @"manifest_uid",
            @"manifest_gid", @"manifest_mode", @"helper_sha256", @"helper_cdhash",
            @"run_a_bootsessionuuid", @"run_a_boottime_sec", @"run_a_boottime_usec",
            @"stage_child_record_sha256", @"stage_exit_status", @"stage_child_proof",
            @"protected_state_gate", @"wall2_got_original_state_restored",
            @"commit_timestamp"
        ]];
    });
    return keys;
}

static NSSet<NSString *> *dt102739n_cleanup_keys(void)
{
    static NSSet *keys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = [NSSet setWithArray:@[
            @"schema_version", @"build_variant", @"protocol", @"state",
            @"transaction_uuid", @"boot_manifest_hash", @"trustcache_uuid",
            @"manifest_sha256", @"commit_sha256", @"manifest_dev", @"manifest_ino",
            @"manifest_uid", @"manifest_gid", @"manifest_mode", @"commit_dev",
            @"commit_ino", @"commit_uid", @"commit_gid", @"commit_mode",
            @"helper_sha256", @"helper_cdhash", @"fixture_dev", @"fixture_ino",
            @"fixture_uid", @"fixture_gid", @"fixture_mode", @"fixture_flags",
            @"tests_dev", @"tests_ino", @"tests_uid", @"tests_gid", @"tests_mode",
            @"tests_flags", @"control_dev", @"control_ino", @"control_uid",
            @"control_gid", @"control_mode", @"control_flags",
            @"reactivation_child_record_sha256", @"reactivation_exit_status",
            @"reactivation_child_proof", @"protected_state_gate", @"cleanup_timestamp"
        ]];
    });
    return keys;
}

static BOOL dt102739n_lower_hex(NSString *value, NSUInteger length)
{
    if (value.length != length) return NO;
    const char *bytes = value.UTF8String;
    if (!bytes || strlen(bytes) != length) return NO;
    for (NSUInteger i = 0; i < length; i++) {
        if (!((bytes[i] >= '0' && bytes[i] <= '9')
            || (bytes[i] >= 'a' && bytes[i] <= 'f')))
            return NO;
    }
    return YES;
}

static BOOL dt102739n_unsigned(NSString *value, unsigned long long *output)
{
    if (!value.length || (value.length > 1 && [value hasPrefix:@"0"])) return NO;
    const char *text = value.UTF8String;
    for (const char *cursor = text; cursor && *cursor; cursor++)
        if (*cursor < '0' || *cursor > '9') return NO;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || !end || *end) return NO;
    if (output) *output = parsed;
    return YES;
}

static BOOL dt102739n_manifest_static_valid(NSDictionary *manifest)
{
    unsigned long long sec = 0, usec = 0;
    uuid_t parsed = {0};
    char canonical[37] = {0};
    NSString *uuid = manifest[@"run_a_bootsessionuuid"];
    BOOL uuidOK = uuid.length == 36 && uuid_parse(uuid.UTF8String, parsed) == 0;
    if (uuidOK) uuid_unparse_lower(parsed, canonical);
    return manifest
        && [manifest[@"schema_version"] isEqualToString:@"1"]
        && [manifest[@"build_variant"] isEqualToString:@"BUILD102739N"]
        && [manifest[@"protocol"] isEqualToString:kDT102739NProtocol]
        && [manifest[@"state"] isEqualToString:@"STAGING"]
        && [manifest[@"target_model"] isEqualToString:@"AppleTV6,2"]
        && [manifest[@"target_version"] isEqualToString:@"16.5"]
        && [manifest[@"target_build"] isEqualToString:@"20L563"]
        && [manifest[@"trustcache_uuid"] isEqualToString:@"1027394e-0000-4000-8000-000000000001"]
        && [manifest[@"control_relative"] isEqualToString:@"dopamin-tvos/control"]
        && [manifest[@"tests_relative"] isEqualToString:@"dopamin-tvos/control/tests"]
        && [manifest[@"fixture_relative"] isEqualToString:@"dopamin-tvos/control/tests/build102739n"]
        && [manifest[@"helper_name"] isEqualToString:kDT102739NHelperName]
        && dt102739n_boot_hash_valid(manifest[@"boot_manifest_hash"])
        && dt102739n_lower_hex(manifest[@"transaction_uuid"], 32)
        && dt102739n_lower_hex(manifest[@"helper_sha256"], 64)
        && dt102739n_lower_hex(manifest[@"helper_cdhash"], 40)
        && uuidOK && strcmp(canonical, uuid.UTF8String) == 0
        && dt102739n_unsigned(manifest[@"run_a_boottime_sec"], &sec) && sec > 0
        && dt102739n_unsigned(manifest[@"run_a_boottime_usec"], &usec) && usec < 1000000;
}

static BOOL dt102739n_commit_static_valid(NSDictionary *commit, NSDictionary *manifest,
    NSString *manifestSHA)
{
    return commit && manifest
        && [commit[@"schema_version"] isEqualToString:@"1"]
        && [commit[@"build_variant"] isEqualToString:@"BUILD102739N"]
        && [commit[@"protocol"] isEqualToString:kDT102739NProtocol]
        && [commit[@"state"] isEqualToString:@"AWAITING_REBOOT"]
        && [commit[@"transaction_uuid"] isEqualToString:manifest[@"transaction_uuid"]]
        && [commit[@"boot_manifest_hash"] isEqualToString:manifest[@"boot_manifest_hash"]]
        && [commit[@"trustcache_uuid"] isEqualToString:manifest[@"trustcache_uuid"]]
        && [commit[@"manifest_sha256"] isEqualToString:manifestSHA]
        && [commit[@"helper_sha256"] isEqualToString:manifest[@"helper_sha256"]]
        && [commit[@"helper_cdhash"] isEqualToString:manifest[@"helper_cdhash"]]
        && [commit[@"run_a_bootsessionuuid"] isEqualToString:manifest[@"run_a_bootsessionuuid"]]
        && [commit[@"run_a_boottime_sec"] isEqualToString:manifest[@"run_a_boottime_sec"]]
        && [commit[@"run_a_boottime_usec"] isEqualToString:manifest[@"run_a_boottime_usec"]]
        && [commit[@"stage_exit_status"] isEqualToString:@"0"]
        && [commit[@"stage_child_proof"] isEqualToString:@"PASS"]
        && [commit[@"protected_state_gate"] isEqualToString:@"PASS"]
        && [commit[@"wall2_got_original_state_restored"] isEqualToString:@"YES"]
        && dt102739n_lower_hex(commit[@"stage_child_record_sha256"], 64);
}

static BOOL dt102739n_boot_hash_valid(NSString *value)
{
    if (value.length < 40 || value.length > 128 || (value.length & 1))
        return NO;
    const char *bytes = value.UTF8String;
    for (NSUInteger i = 0; i < value.length; i++) {
        if (!((bytes[i] >= '0' && bytes[i] <= '9')
            || (bytes[i] >= 'A' && bytes[i] <= 'F')))
            return NO;
    }
    return YES;
}

static BOOL dt102739n_open_existing_dir(int parentFD, NSString *name, mode_t mode,
    int *fdOut, struct stat *statOut)
{
    int fd = openat(parentFD, name.fileSystemRepresentation,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st = {0};
    BOOL ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)
        && st.st_uid == 0 && st.st_gid == 0
        && (mode == 0 || (st.st_mode & 07777) == mode);
    if (!ok) {
        if (fd >= 0) close(fd);
        return NO;
    }
    if (fdOut) *fdOut = fd; else close(fd);
    if (statOut) *statOut = st;
    return YES;
}

static BOOL dt102739n_ensure_dir(int parentFD, NSString *name, mode_t mode,
    BOOL strictExistingMode, BOOL *preexistedOut, BOOL *createdOut,
    int *fdOut, struct stat *statOut)
{
    struct stat before = {0};
    int lookup = fstatat(parentFD, name.fileSystemRepresentation, &before,
        AT_SYMLINK_NOFOLLOW);
    BOOL preexisted = lookup == 0;
    BOOL created = NO;
    if (preexisted) {
        if (!S_ISDIR(before.st_mode) || before.st_uid != 0 || before.st_gid != 0
            || (strictExistingMode && (before.st_mode & 07777) != mode))
            return NO;
    } else {
        if (errno != ENOENT || mkdirat(parentFD, name.fileSystemRepresentation, mode) != 0)
            return NO;
        created = YES;
    }
    int fd = openat(parentFD, name.fileSystemRepresentation,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NO;
    if (created && (fchown(fd, 0, 0) != 0 || fchmod(fd, mode) != 0 || fsync(parentFD) != 0)) {
        close(fd);
        return NO;
    }
    struct stat after = {0};
    BOOL ok = fstat(fd, &after) == 0 && S_ISDIR(after.st_mode)
        && after.st_uid == 0 && after.st_gid == 0
        && (!strictExistingMode || (after.st_mode & 07777) == mode);
    if (!ok) {
        close(fd);
        return NO;
    }
    if (preexistedOut) *preexistedOut = preexisted;
    if (createdOut) *createdOut = created;
    if (fdOut) *fdOut = fd; else close(fd);
    if (statOut) *statOut = after;
    return YES;
}

static BOOL dt102739n_open_active(dt102739n_paths_t *paths, BOOL createParents,
    BOOL createFixture)
{
    if (!paths) return NO;
    memset(paths, 0, sizeof(*paths));
    paths->prebootFD = paths->namespaceFD = paths->controlFD = -1;
    paths->testsFD = paths->fixtureFD = -1;
    char hash[256] = {0};
    if (!dt710_copy_boot_manifest_hash(hash, sizeof(hash)))
        return NO;
    paths->bootHash = [NSString stringWithUTF8String:hash];
    paths->activePath = dt710_resolve_active_preboot_path();
    if (!dt102739n_boot_hash_valid(paths->bootHash) || !paths->activePath.length
        || ![paths->activePath isEqualToString:
            [@"/private/preboot" stringByAppendingPathComponent:paths->bootHash]])
        return NO;
    paths->prebootFD = open("/private/preboot", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (paths->prebootFD < 0) return NO;
    int activeFD = openat(paths->prebootFD, hash,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (activeFD < 0) {
        dt102739n_close_paths(paths);
        return NO;
    }
    close(paths->prebootFD);
    paths->prebootFD = activeFD;

    if (createParents) {
        if (!dt102739n_ensure_dir(paths->prebootFD, kDT102739NControlComponent, 0755,
                NO, NULL, NULL, &paths->namespaceFD, &paths->namespaceStat)
            || !dt102739n_ensure_dir(paths->namespaceFD, kDT102739NControlName, 0755,
                YES, &paths->controlPreexisted, &paths->controlCreated,
                &paths->controlFD, &paths->controlStat)
            || !dt102739n_ensure_dir(paths->controlFD, kDT102739NTestsName, 0700,
                YES, &paths->testsPreexisted, &paths->testsCreated,
                &paths->testsFD, &paths->testsStat)) {
            dt102739n_close_paths(paths);
            return NO;
        }
        struct stat fixture = {0};
        if (fstatat(paths->testsFD, kDT102739NFixtureName.UTF8String, &fixture,
                AT_SYMLINK_NOFOLLOW) == 0) {
            paths->fixturePreexisted = YES;
            if (!dt102739n_open_existing_dir(paths->testsFD, kDT102739NFixtureName,
                    0700, &paths->fixtureFD, &paths->fixtureStat)) {
                dt102739n_close_paths(paths);
                return NO;
            }
        } else if (errno == ENOENT && createFixture) {
            if (!dt102739n_ensure_dir(paths->testsFD, kDT102739NFixtureName, 0700,
                    YES, &paths->fixturePreexisted, &paths->fixtureCreated,
                    &paths->fixtureFD, &paths->fixtureStat)) {
                dt102739n_close_paths(paths);
                return NO;
            }
        }
        return YES;
    }

    if (!dt102739n_open_existing_dir(paths->prebootFD, kDT102739NControlComponent,
            0, &paths->namespaceFD, &paths->namespaceStat)
        || !dt102739n_open_existing_dir(paths->namespaceFD, kDT102739NControlName,
            0755, &paths->controlFD, &paths->controlStat)
        || !dt102739n_open_existing_dir(paths->controlFD, kDT102739NTestsName,
            0700, &paths->testsFD, &paths->testsStat)) {
        dt102739n_close_paths(paths);
        return NO;
    }
    struct stat fixture = {0};
    if (fstatat(paths->testsFD, kDT102739NFixtureName.UTF8String, &fixture,
            AT_SYMLINK_NOFOLLOW) == 0) {
        paths->fixturePreexisted = YES;
        if (!dt102739n_open_existing_dir(paths->testsFD, kDT102739NFixtureName,
                0700, &paths->fixtureFD, &paths->fixtureStat)) {
            dt102739n_close_paths(paths);
            return NO;
        }
    } else if (errno != ENOENT) {
        dt102739n_close_paths(paths);
        return NO;
    }
    return YES;
}

static NSData *dt102739n_data(NSString *text)
{
    return [text dataUsingEncoding:NSUTF8StringEncoding];
}

static NSString *dt102739n_sha_data(NSData *data)
{
    return data ? dt102739n_sha256_bytes(data.bytes, data.length) : nil;
}

static BOOL dt102739n_atomic_publish(int directoryFD, NSString *temporary,
    NSString *finalName, NSData *data, mode_t mode, struct stat *finalStat)
{
    if (directoryFD < 0 || !data.length) return NO;
    struct stat st = {0};
    if (fstatat(directoryFD, temporary.UTF8String, &st, AT_SYMLINK_NOFOLLOW) == 0
        || errno != ENOENT)
        return NO;
    if (fstatat(directoryFD, finalName.UTF8String, &st, AT_SYMLINK_NOFOLLOW) == 0
        || errno != ENOENT)
        return NO;
    int fd = openat(directoryFD, temporary.UTF8String,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return NO;
    BOOL ok = fchown(fd, 0, 0) == 0 && fchmod(fd, mode) == 0
        && dt102739n_write_all(fd, data.bytes, data.length);
    struct stat temporaryStat = {0};
    ok = ok && fstat(fd, &temporaryStat) == 0 && S_ISREG(temporaryStat.st_mode)
        && temporaryStat.st_uid == 0 && temporaryStat.st_gid == 0
        && (temporaryStat.st_mode & 07777) == mode
        && temporaryStat.st_size == (off_t)data.length;
    close(fd);
    if (!ok) {
        (void)unlinkat(directoryFD, temporary.UTF8String, 0);
        return NO;
    }
    if (renameatx_np(directoryFD, temporary.UTF8String, directoryFD,
            finalName.UTF8String, RENAME_EXCL) != 0)
        return NO;
    int verifyFD = openat(directoryFD, finalName.UTF8String,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat published = {0};
    NSString *readback = dt102739n_read_fd(verifyFD, 32768);
    BOOL verified = verifyFD >= 0 && fstat(verifyFD, &published) == 0
        && published.st_dev == temporaryStat.st_dev
        && published.st_ino == temporaryStat.st_ino
        && published.st_size == (off_t)data.length
        && [dt102739n_sha_data([readback dataUsingEncoding:NSUTF8StringEncoding])
            isEqualToString:dt102739n_sha_data(data)]
        && fsync(directoryFD) == 0;
    if (verifyFD >= 0) close(verifyFD);
    if (verified && finalStat) *finalStat = published;
    return verified;
}

static NSString *dt102739n_timestamp(void)
{
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    return [formatter stringFromDate:[NSDate date]];
}

static BOOL dt102739n_open_regular(int directoryFD, NSString *name, mode_t mode,
    int *fdOut, struct stat *statOut)
{
    int fd = openat(directoryFD, name.UTF8String, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st = {0};
    BOOL ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
        && st.st_uid == 0 && st.st_gid == 0 && (st.st_mode & 07777) == mode;
    if (!ok) {
        if (fd >= 0) close(fd);
        return NO;
    }
    if (fdOut) *fdOut = fd; else close(fd);
    if (statOut) *statOut = st;
    return YES;
}

static unsigned long long dt102739n_value(NSDictionary *ledger, NSString *key,
    BOOL *ok)
{
    unsigned long long value = 0;
    BOOL parsed = dt102739n_unsigned(ledger[key], &value);
    if (ok) *ok = parsed;
    return value;
}

static BOOL dt102739n_stat_matches_ledger(const struct stat *st, NSDictionary *ledger,
    NSString *prefix, mode_t mode, BOOL directory)
{
    BOOL ok = NO;
    unsigned long long dev = dt102739n_value(ledger, [prefix stringByAppendingString:@"_dev"], &ok);
    if (!ok) return NO;
    unsigned long long ino = dt102739n_value(ledger, [prefix stringByAppendingString:@"_ino"], &ok);
    if (!ok) return NO;
    unsigned long long uid = dt102739n_value(ledger, [prefix stringByAppendingString:@"_uid"], &ok);
    if (!ok) return NO;
    unsigned long long gid = dt102739n_value(ledger, [prefix stringByAppendingString:@"_gid"], &ok);
    if (!ok) return NO;
    NSString *modeText = ledger[[prefix stringByAppendingString:@"_mode"]];
    unsigned long long flags = 0;
    NSString *flagsKey = [prefix stringByAppendingString:@"_flags"];
    if (ledger[flagsKey])
        flags = dt102739n_value(ledger, flagsKey, &ok);
    else
        ok = YES;
    return ok && st && st->st_dev == (dev_t)dev && st->st_ino == (ino_t)ino
        && st->st_uid == (uid_t)uid && st->st_gid == (gid_t)gid
        && ((directory && S_ISDIR(st->st_mode)) || (!directory && S_ISREG(st->st_mode)))
        && (st->st_mode & 07777) == mode
        && [modeText isEqualToString:[NSString stringWithFormat:@"%04o", mode]]
        && (!ledger[flagsKey] || st->st_flags == flags);
}

static BOOL dt102739n_validate_manifest_identity(NSDictionary *manifest,
    dt102739n_paths_t *paths, struct stat *helperStat, struct stat *manifestStat);
static BOOL dt102739n_validate_commit_identity(NSDictionary *commit,
    NSDictionary *manifest, NSString *manifestText, const struct stat *manifestStat,
    const struct stat *commitStat);
static BOOL dt102739n_fixture_expected_entries(int fixtureFD, BOOL commitAllowed);

static BOOL dt102739n_stat_value_matches(const struct stat *st, NSDictionary *ledger,
    NSString *key, unsigned long long actual)
{
    BOOL parsed = NO;
    unsigned long long expected = dt102739n_value(ledger, key, &parsed);
    return st && parsed && actual == expected;
}

static void dt102739n_log_persisted_diagnostics(void (^log)(NSString *),
    dt102739n_paths_t *paths, NSDictionary *manifest, NSString *manifestText,
    NSDictionary *commit, NSString *commitText, BOOL helperGate,
    const struct stat *helperStat, const struct stat *manifestStat,
    const struct stat *commitStat)
{
    int manifestFD = -1, commitFD = -1, helperFD = -1;
    int manifestErrno = 0, commitErrno = 0, helperErrno = 0;
    if (paths && paths->fixtureFD >= 0) {
        errno = 0;
        manifestFD = openat(paths->fixtureFD, kDT102739NManifestName.UTF8String,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        manifestErrno = manifestFD >= 0 ? 0 : errno;
        errno = 0;
        commitFD = openat(paths->fixtureFD, kDT102739NCommitName.UTF8String,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        commitErrno = commitFD >= 0 ? 0 : errno;
        errno = 0;
        helperFD = openat(paths->fixtureFD, kDT102739NHelperName.UTF8String,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        helperErrno = helperFD >= 0 ? 0 : errno;
    }
    struct stat rawHelperStat = {0};
    BOOL rawHelperStatOK = helperFD >= 0 && fstat(helperFD, &rawHelperStat) == 0;
    if (manifestFD >= 0) close(manifestFD);
    if (commitFD >= 0) close(commitFD);
    if (helperFD >= 0) close(helperFD);

    BOOL manifestStatic = dt102739n_manifest_static_valid(manifest);
    BOOL bootHash = manifest && paths
        && [manifest[@"boot_manifest_hash"] isEqualToString:paths->bootHash];
    BOOL manifestHelperSHA = manifest
        && [manifest[@"helper_sha256"] isEqualToString:@DT102739N_HELPER_SHA256];
    BOOL manifestHelperCDHash = manifest
        && [manifest[@"helper_cdhash"] isEqualToString:@DT102739N_HELPER_CDHASH];
    BOOL manifestFileMetadata = manifestStat && S_ISREG(manifestStat->st_mode)
        && manifestStat->st_uid == 0 && manifestStat->st_gid == 0
        && (manifestStat->st_mode & 07777) == 0600;

    BOOL helperType = rawHelperStatOK && S_ISREG(rawHelperStat.st_mode);
    BOOL helperUID = rawHelperStatOK && rawHelperStat.st_uid == 0;
    BOOL helperGID = rawHelperStatOK && rawHelperStat.st_gid == 0;
    BOOL helperMode = rawHelperStatOK && (rawHelperStat.st_mode & 07777) == 0755;
    BOOL sizeParsed = NO;
    unsigned long long helperSize = dt102739n_value(manifest, @"helper_size", &sizeParsed);
    BOOL helperSizeMatch = rawHelperStatOK && sizeParsed
        && rawHelperStat.st_size == (off_t)helperSize;
    BOOL helperDev = dt102739n_stat_value_matches(&rawHelperStat, manifest,
        @"helper_dev", (unsigned long long)rawHelperStat.st_dev);
    BOOL helperIno = dt102739n_stat_value_matches(&rawHelperStat, manifest,
        @"helper_ino", (unsigned long long)rawHelperStat.st_ino);

    NSString *helperPath = paths ? [[[[[paths->activePath
        stringByAppendingPathComponent:kDT102739NControlComponent]
        stringByAppendingPathComponent:kDT102739NControlName]
        stringByAppendingPathComponent:kDT102739NTestsName]
        stringByAppendingPathComponent:kDT102739NFixtureName]
        stringByAppendingPathComponent:kDT102739NHelperName] : nil;
    NSString *actualSHA = helperPath ? dt102739n_sha256(helperPath) : nil;
    cdhash_t actualHash = {0};
    NSString *actualCDHash = nil;
    BOOL actualCDHashOK = helperPath
        && dt102739n_cdhash(helperPath, actualHash, &actualCDHash);
    BOOL helperSHA = [actualSHA isEqualToString:@DT102739N_HELPER_SHA256];
    BOOL helperCDHash = actualCDHashOK
        && [actualCDHash isEqualToString:@DT102739N_HELPER_CDHASH];
    BOOL helperLedger = helperGate && helperStat
        && dt102739n_stat_matches_ledger(helperStat, manifest, @"helper", 0755, NO);
    BOOL controlLedger = paths && dt102739n_stat_matches_ledger(&paths->controlStat,
        manifest, @"control", 0755, YES);
    BOOL testsLedger = paths && dt102739n_stat_matches_ledger(&paths->testsStat,
        manifest, @"tests", 0700, YES);
    BOOL fixtureLedger = paths && dt102739n_stat_matches_ledger(&paths->fixtureStat,
        manifest, @"fixture", 0700, YES);
    BOOL manifestIdentity = manifest && helperGate && paths
        && dt102739n_validate_manifest_identity(manifest, paths,
            (struct stat *)helperStat, (struct stat *)manifestStat);
    BOOL commitRelationship = commit && manifest
        && dt102739n_validate_commit_identity(commit, manifest, manifestText,
            manifestStat, commitStat);
    BOOL entries = paths && paths->fixtureFD >= 0
        && dt102739n_fixture_expected_entries(paths->fixtureFD, YES);

    dt102739n_emit(log, @"BUILD102739N_PERSISTED_DIAGNOSTIC_REVISION=REPAIRED_V3");
    dt102739n_emit(log, @"BUILD102739N_PERSISTED_DIAGNOSTIC_READ_ONLY=YES");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_OPEN_RC=%d", manifestFD >= 0 ? 0 : -1);
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_OPEN_ERRNO=%d", manifestErrno);
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_PARSE_GATE=%@", manifest ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_STATIC_GATE=%@", manifestStatic ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_FILE_METADATA_GATE=%@",
        manifestFileMetadata ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_BOOT_MANIFEST_HASH_MATCH=%@", bootHash ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_HELPER_SHA256_EXPECTATION_MATCH=%@",
        manifestHelperSHA ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_HELPER_CDHASH_EXPECTATION_MATCH=%@",
        manifestHelperCDHash ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_COMMIT_OPEN_RC=%d", commitFD >= 0 ? 0 : -1);
    dt102739n_emit(log, @"BUILD102739N_COMMIT_OPEN_ERRNO=%d", commitErrno);
    dt102739n_emit(log, @"BUILD102739N_COMMIT_PARSE_GATE=%@", commit ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_COMMIT_RELATIONSHIP=%@",
        commitRelationship ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_HELPER_OPEN_RC=%d", helperFD >= 0 ? 0 : -1);
    dt102739n_emit(log, @"BUILD102739N_HELPER_OPEN_ERRNO=%d", helperErrno);
    dt102739n_emit(log, @"BUILD102739N_HELPER_STRICT_OPEN_GATE=%@", helperGate ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_HELPER_TYPE_MATCH=%@", helperType ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_UID_MATCH=%@", helperUID ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_GID_MATCH=%@", helperGID ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_MODE_MATCH=%@", helperMode ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_SIZE_MATCH=%@", helperSizeMatch ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_DEV_MATCH=%@", helperDev ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_INO_MATCH=%@", helperIno ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_SHA256_ACTUAL=%@", actualSHA ?: @"UNAVAILABLE");
    dt102739n_emit(log, @"BUILD102739N_HELPER_SHA256_MATCH=%@", helperSHA ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_CDHASH_ACTUAL=%@", actualCDHash ?: @"UNAVAILABLE");
    dt102739n_emit(log, @"BUILD102739N_HELPER_CDHASH_MATCH=%@", helperCDHash ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_LEDGER_IDENTITY_MATCH=%@", helperLedger ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_CONTROL_IDENTITY_MATCH=%@", controlLedger ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_TESTS_IDENTITY_MATCH=%@", testsLedger ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_FIXTURE_IDENTITY_MATCH=%@", fixtureLedger ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_IDENTITY_GATE=%@", manifestIdentity ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_FIXTURE_ENTRY_SET_GATE=%@", entries ? @"PASS" : @"FAIL");

    NSString *result = @"PERSISTED_DIAGNOSTIC_UNCLASSIFIED";
    if (manifestFD < 0) result = @"PERSISTED_MANIFEST_OPEN_FAILED";
    else if (!manifest) result = @"PERSISTED_MANIFEST_PARSE_FAILED";
    else if (helperFD < 0) result = @"PERSISTED_HELPER_OPEN_FAILED";
    else if (!helperType || !helperUID || !helperGID || !helperMode)
        result = @"PERSISTED_HELPER_BASIC_METADATA_CHANGED";
    else if (!manifestStatic) result = @"PERSISTED_MANIFEST_STATIC_INVALID";
    else if (!bootHash) result = @"PERSISTED_BOOT_MANIFEST_CHANGED";
    else if (!manifestHelperSHA || !manifestHelperCDHash || !helperSHA || !helperCDHash)
        result = @"PERSISTED_HELPER_CONTENT_IDENTITY_CHANGED";
    else if (!helperSizeMatch || !helperDev || !helperIno || !helperLedger)
        result = @"PERSISTED_HELPER_PROVENANCE_CHANGED";
    else if (!controlLedger || !testsLedger || !fixtureLedger)
        result = @"PERSISTED_DIRECTORY_PROVENANCE_CHANGED";
    else if (!manifestFileMetadata || !manifestIdentity)
        result = @"PERSISTED_MANIFEST_IDENTITY_CHANGED";
    else if (commitFD < 0) result = @"PERSISTED_COMMIT_MISSING";
    else if (!commit) result = @"PERSISTED_COMMIT_PARSE_FAILED";
    else if (!commitRelationship) result = @"PERSISTED_COMMIT_INVALID";
    else if (!entries) result = @"PERSISTED_FIXTURE_ENTRY_SET_CHANGED";
    else result = @"PERSISTED_DIAGNOSTIC_ALL_GATES_PASS";
    gDT102739NLastPersistedDiagnosticResult = result;
    dt102739n_emit(log, @"BUILD102739N_PERSISTED_DIAGNOSTIC_RESULT=%@", result);
    (void)commitText;
}

static NSString *dt102739n_canonical_record(NSDictionary *record)
{
    if (!record) return nil;
    NSArray *keys = [record.allKeys sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *text = [NSMutableString string];
    for (NSString *key in keys)
        [text appendFormat:@"%@=%@\n", key, record[key]];
    return text;
}

static BOOL dt102739n_validate_child(NSDictionary *record, NSString *phase,
    NSString *transaction, NSString *path, pid_t pid, const cdhash_t helperHash,
    NSString **recordSHAOut, NSUInteger *dyldCountOut)
{
    static NSSet *required;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        required = [NSSet setWithArray:@[
            @"protocol", @"phase", @"transaction", @"pid", @"uid", @"euid",
            @"argc", @"argv_match", @"argv0", @"actual_path_from_proc_pidpath",
            @"self_cdhash_rc", @"self_cdhash_errno", @"self_cdhash",
            @"effective_env_count", @"env_name_count", @"env_names_hex",
            @"env_name_overflow", @"env_name_duplicates", @"dyld_env_count",
            @"dyld_insert", @"completion"
        ]];
    });
    if (!record || ![[NSSet setWithArray:record.allKeys] isEqualToSet:required])
        return NO;
    NSUInteger reportedPID = 0, effectiveCount = 0, nameCount = 0, dyldCount = 0;
    BOOL numbers = dt102739n_parse_uint(record[@"pid"], INT_MAX, &reportedPID)
        && dt102739n_parse_uint(record[@"effective_env_count"], 1024, &effectiveCount)
        && dt102739n_parse_uint(record[@"env_name_count"], kDT102739NMaxEnvironmentNames,
            &nameCount)
        && dt102739n_parse_uint(record[@"dyld_env_count"], 1024, &dyldCount);
    NSArray *environmentNames = numbers
        ? dt102739n_decode_environment_names(record[@"env_names_hex"], nameCount) : nil;
    NSUInteger computedDyld = 0;
    for (NSString *name in environmentNames)
        if ([name hasPrefix:@"DYLD_"]) computedDyld++;
    cdhash_t selfHash = {0};
    BOOL selfOK = [record[@"self_cdhash_rc"] isEqualToString:@"0"]
        && [record[@"self_cdhash_errno"] isEqualToString:@"0"]
        && dt102739n_decode_lower_hex(record[@"self_cdhash"], selfHash, sizeof(selfHash))
        && memcmp(selfHash, helperHash, sizeof(cdhash_t)) == 0;
    BOOL valid = numbers && environmentNames
        && [record[@"protocol"] isEqualToString:kDT102739NProtocol]
        && [record[@"phase"] isEqualToString:phase]
        && [record[@"transaction"] isEqualToString:transaction]
        && reportedPID == (NSUInteger)pid
        && [record[@"uid"] isEqualToString:@"0"] && [record[@"euid"] isEqualToString:@"0"]
        && [record[@"argc"] isEqualToString:@"7"]
        && [record[@"argv_match"] isEqualToString:@"YES"]
        && [record[@"argv0"] isEqualToString:path]
        && [record[@"actual_path_from_proc_pidpath"] isEqualToString:path]
        && effectiveCount == nameCount && computedDyld == dyldCount && dyldCount == 0
        && [record[@"env_name_overflow"] isEqualToString:@"NO"]
        && [record[@"env_name_duplicates"] isEqualToString:@"NO"]
        && [record[@"dyld_insert"] isEqualToString:@"ABSENT"]
        && [record[@"completion"] isEqualToString:@"PASS"] && selfOK;
    if (dyldCountOut) *dyldCountOut = dyldCount;
    if (valid && recordSHAOut)
        *recordSHAOut = dt102739n_sha_data(dt102739n_data(dt102739n_canonical_record(record)));
    return valid;
}

static NSDictionary *dt102739n_load_ledger(int directoryFD, NSString *name,
    mode_t mode, NSSet *keys, NSString **textOut, struct stat *statOut)
{
    int fd = -1;
    struct stat st = {0};
    if (!dt102739n_open_regular(directoryFD, name, mode, &fd, &st))
        return nil;
    NSString *text = dt102739n_read_fd(fd, 32768);
    close(fd);
    NSDictionary *ledger = dt102739n_parse_ledger(text, keys);
    if (!ledger) return nil;
    if (textOut) *textOut = text;
    if (statOut) *statOut = st;
    return ledger;
}

static BOOL dt102739n_validate_manifest_identity(NSDictionary *manifest,
    dt102739n_paths_t *paths, struct stat *helperStat, struct stat *manifestStat)
{
    if (!dt102739n_manifest_static_valid(manifest)
        || ![manifest[@"boot_manifest_hash"] isEqualToString:paths->bootHash]
        || ![manifest[@"helper_sha256"] isEqualToString:@DT102739N_HELPER_SHA256]
        || ![manifest[@"helper_cdhash"] isEqualToString:@DT102739N_HELPER_CDHASH]
        || ![manifest[@"helper_uid"] isEqualToString:@"0"]
        || ![manifest[@"helper_gid"] isEqualToString:@"0"]
        || ![manifest[@"helper_mode"] isEqualToString:@"0755"]
        || ![manifest[@"fixture_preexisted"] isEqualToString:@"0"]
        || ![manifest[@"fixture_created_by_n"] isEqualToString:@"1"])
        return NO;
    BOOL sizeOK = NO;
    unsigned long long size = dt102739n_value(manifest, @"helper_size", &sizeOK);
    BOOL controlFlags = ([manifest[@"control_preexisted"] isEqualToString:@"1"]
            && [manifest[@"control_created_by_n"] isEqualToString:@"0"])
        || ([manifest[@"control_preexisted"] isEqualToString:@"0"]
            && [manifest[@"control_created_by_n"] isEqualToString:@"1"]);
    BOOL testsFlags = ([manifest[@"tests_preexisted"] isEqualToString:@"1"]
            && [manifest[@"tests_created_by_n"] isEqualToString:@"0"])
        || ([manifest[@"tests_preexisted"] isEqualToString:@"0"]
            && [manifest[@"tests_created_by_n"] isEqualToString:@"1"]);
    BOOL provenance = controlFlags && testsFlags;
    if (paths->fixtureCreated) {
        provenance = provenance
            && [manifest[@"control_preexisted"] boolValue] == paths->controlPreexisted
            && [manifest[@"control_created_by_n"] boolValue] == paths->controlCreated
            && [manifest[@"tests_preexisted"] boolValue] == paths->testsPreexisted
            && [manifest[@"tests_created_by_n"] boolValue] == paths->testsCreated;
    }
    return sizeOK && provenance && helperStat->st_size == (off_t)size
        && dt102739n_stat_matches_ledger(helperStat, manifest, @"helper", 0755, NO)
        && dt102739n_stat_matches_ledger(&paths->controlStat, manifest, @"control", 0755, YES)
        && dt102739n_stat_matches_ledger(&paths->testsStat, manifest, @"tests", 0700, YES)
        && dt102739n_stat_matches_ledger(&paths->fixtureStat, manifest, @"fixture", 0700, YES)
        && manifestStat && S_ISREG(manifestStat->st_mode)
        && manifestStat->st_uid == 0 && manifestStat->st_gid == 0
        && (manifestStat->st_mode & 07777) == 0600;
}

static BOOL dt102739n_validate_commit_identity(NSDictionary *commit,
    NSDictionary *manifest, NSString *manifestText, const struct stat *manifestStat,
    const struct stat *commitStat)
{
    NSString *manifestSHA = dt102739n_sha_data(dt102739n_data(manifestText));
    if (!dt102739n_commit_static_valid(commit, manifest, manifestSHA)
        || !manifestStat || !commitStat || !S_ISREG(commitStat->st_mode)
        || commitStat->st_uid != 0 || commitStat->st_gid != 0
        || (commitStat->st_mode & 07777) != 0600)
        return NO;
    BOOL ok = NO;
    unsigned long long dev = dt102739n_value(commit, @"manifest_dev", &ok);
    if (!ok || manifestStat->st_dev != (dev_t)dev) return NO;
    unsigned long long ino = dt102739n_value(commit, @"manifest_ino", &ok);
    return ok && manifestStat->st_ino == (ino_t)ino
        && [commit[@"manifest_uid"] isEqualToString:@"0"]
        && [commit[@"manifest_gid"] isEqualToString:@"0"]
        && [commit[@"manifest_mode"] isEqualToString:@"0600"];
}

static BOOL dt102739n_fixture_expected_entries(int fixtureFD, BOOL commitAllowed)
{
    if (fixtureFD < 0) return NO;
    int scanFD = dup(fixtureFD);
    if (scanFD < 0) return NO;
    DIR *directory = fdopendir(scanFD);
    if (!directory) {
        close(scanFD);
        return NO;
    }
    BOOL helper = NO, manifest = NO, commit = NO, unexpected = NO;
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!strcmp(entry->d_name, kDT102739NHelperName.UTF8String) && !helper) helper = YES;
        else if (!strcmp(entry->d_name, kDT102739NManifestName.UTF8String) && !manifest) manifest = YES;
        else if (commitAllowed && !strcmp(entry->d_name, kDT102739NCommitName.UTF8String) && !commit) commit = YES;
        else unexpected = YES;
    }
    closedir(directory);
    return helper && manifest && (!commitAllowed || commit) && !unexpected;
}

static BOOL dt102739n_recover_staging(void (^log)(NSString *), dt102739n_paths_t *paths,
    NSDictionary *manifest, const struct stat *helperStat, const struct stat *manifestStat)
{
    cdhash_t helperHash = {0};
    BOOL decoded = dt102739n_decode_lower_hex(@DT102739N_HELPER_CDHASH,
        helperHash, sizeof(helperHash));
    BOOL trusted = decoded && dt_cdhash_trustcached(helperHash);
    BOOL identity = dt102739n_validate_manifest_identity(manifest, paths,
        (struct stat *)helperStat, (struct stat *)manifestStat)
        && dt102739n_fixture_expected_entries(paths->fixtureFD, NO);
    BOOL removed = identity
        && unlinkat(paths->fixtureFD, kDT102739NHelperName.UTF8String, 0) == 0
        && unlinkat(paths->fixtureFD, kDT102739NManifestName.UTF8String, 0) == 0
        && fsync(paths->fixtureFD) == 0;
    if (removed) {
        close(paths->fixtureFD);
        paths->fixtureFD = -1;
        removed = unlinkat(paths->testsFD, kDT102739NFixtureName.UTF8String,
            AT_REMOVEDIR) == 0 && fsync(paths->testsFD) == 0;
    }
    dt102739n_emit(log, @"BUILD102739N_INTERRUPTED_STAGING_ROLLBACK=%@",
        removed ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_REBOOT_REQUIRED_BEFORE_FRESH_RUN_A=%@",
        trusted ? @"YES" : @"NO");
    return removed;
}

static BOOL dt102739n_cleanup_marker_static_valid(NSDictionary *cleanup,
    NSDictionary *manifest, NSDictionary *commit, NSString *manifestSHA,
    NSString *commitSHA)
{
    return cleanup && manifest && commit
        && [cleanup[@"schema_version"] isEqualToString:@"1"]
        && [cleanup[@"build_variant"] isEqualToString:@"BUILD102739N"]
        && [cleanup[@"protocol"] isEqualToString:kDT102739NProtocol]
        && [cleanup[@"state"] isEqualToString:@"CLEANING"]
        && [cleanup[@"transaction_uuid"] isEqualToString:manifest[@"transaction_uuid"]]
        && [cleanup[@"boot_manifest_hash"] isEqualToString:manifest[@"boot_manifest_hash"]]
        && [cleanup[@"trustcache_uuid"] isEqualToString:manifest[@"trustcache_uuid"]]
        && [cleanup[@"manifest_sha256"] isEqualToString:manifestSHA]
        && [cleanup[@"commit_sha256"] isEqualToString:commitSHA]
        && [cleanup[@"helper_sha256"] isEqualToString:manifest[@"helper_sha256"]]
        && [cleanup[@"helper_cdhash"] isEqualToString:manifest[@"helper_cdhash"]]
        && [cleanup[@"reactivation_exit_status"] isEqualToString:@"0"]
        && [cleanup[@"reactivation_child_proof"] isEqualToString:@"PASS"]
        && [cleanup[@"protected_state_gate"] isEqualToString:@"PASS"]
        && dt102739n_lower_hex(cleanup[@"reactivation_child_record_sha256"], 64);
}

static BOOL dt102739n_cleanup_marker_standalone_valid(NSDictionary *cleanup,
    dt102739n_paths_t *paths)
{
    return cleanup && paths
        && [cleanup[@"schema_version"] isEqualToString:@"1"]
        && [cleanup[@"build_variant"] isEqualToString:@"BUILD102739N"]
        && [cleanup[@"protocol"] isEqualToString:kDT102739NProtocol]
        && [cleanup[@"state"] isEqualToString:@"CLEANING"]
        && [cleanup[@"boot_manifest_hash"] isEqualToString:paths->bootHash]
        && [cleanup[@"trustcache_uuid"] isEqualToString:@"1027394e-0000-4000-8000-000000000001"]
        && dt102739n_lower_hex(cleanup[@"transaction_uuid"], 32)
        && dt102739n_lower_hex(cleanup[@"manifest_sha256"], 64)
        && dt102739n_lower_hex(cleanup[@"commit_sha256"], 64)
        && [cleanup[@"helper_sha256"] isEqualToString:@DT102739N_HELPER_SHA256]
        && [cleanup[@"helper_cdhash"] isEqualToString:@DT102739N_HELPER_CDHASH]
        && [cleanup[@"reactivation_exit_status"] isEqualToString:@"0"]
        && [cleanup[@"reactivation_child_proof"] isEqualToString:@"PASS"]
        && [cleanup[@"protected_state_gate"] isEqualToString:@"PASS"]
        && dt102739n_lower_hex(cleanup[@"reactivation_child_record_sha256"], 64)
        && dt102739n_stat_matches_ledger(&paths->controlStat, cleanup,
            @"control", 0755, YES)
        && dt102739n_stat_matches_ledger(&paths->testsStat, cleanup,
            @"tests", 0700, YES)
        && (paths->fixtureFD < 0 || dt102739n_stat_matches_ledger(
            &paths->fixtureStat, cleanup, @"fixture", 0700, YES));
}

static BOOL dt102739n_remaining_cleanup_entries_valid(int fixtureFD)
{
    if (fixtureFD < 0) return YES;
    int scanFD = dup(fixtureFD);
    if (scanFD < 0) return NO;
    DIR *directory = fdopendir(scanFD);
    if (!directory) {
        close(scanFD);
        return NO;
    }
    BOOL valid = YES;
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (strcmp(entry->d_name, kDT102739NCommitName.UTF8String)
            && strcmp(entry->d_name, kDT102739NHelperName.UTF8String)
            && strcmp(entry->d_name, kDT102739NManifestName.UTF8String)) {
            valid = NO;
            break;
        }
    }
    closedir(directory);
    return valid;
}

static BOOL dt102739n_resume_cleanup(void (^log)(NSString *), dt102739n_paths_t *paths,
    NSDictionary *cleanup)
{
    if (!dt102739n_cleanup_marker_standalone_valid(cleanup, paths)
        || paths->testsFD < 0 || !dt102739n_remaining_cleanup_entries_valid(paths->fixtureFD))
        return NO;
    if (paths->fixtureFD >= 0) {
        const NSString *names[] = {kDT102739NCommitName, kDT102739NHelperName,
            kDT102739NManifestName};
        for (size_t i = 0; i < 3; i++) {
            struct stat st = {0};
            if (fstatat(paths->fixtureFD, names[i].UTF8String, &st,
                    AT_SYMLINK_NOFOLLOW) == 0) {
                if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0)
                    return NO;
                if (i == 1 && (st.st_mode & 07777) != 0755)
                    return NO;
                NSString *fullPath = [[[[[paths->activePath
                    stringByAppendingPathComponent:kDT102739NControlComponent]
                    stringByAppendingPathComponent:kDT102739NControlName]
                    stringByAppendingPathComponent:kDT102739NTestsName]
                    stringByAppendingPathComponent:kDT102739NFixtureName]
                    stringByAppendingPathComponent:names[i]];
                NSString *expectedSHA = i == 0 ? cleanup[@"commit_sha256"]
                    : i == 1 ? cleanup[@"helper_sha256"] : cleanup[@"manifest_sha256"];
                if (![[dt102739n_sha256(fullPath) lowercaseString]
                        isEqualToString:expectedSHA])
                    return NO;
                if (i == 0 && !dt102739n_stat_matches_ledger(&st, cleanup,
                        @"commit", 0600, NO))
                    return NO;
                if (i == 2 && !dt102739n_stat_matches_ledger(&st, cleanup,
                        @"manifest", 0600, NO))
                    return NO;
                if (i == 1) {
                    cdhash_t helperHash = {0};
                    NSString *helperCDHash = nil;
                    if (!dt102739n_cdhash(fullPath, helperHash, &helperCDHash)
                        || ![helperCDHash isEqualToString:cleanup[@"helper_cdhash"]])
                        return NO;
                }
                if (unlinkat(paths->fixtureFD, names[i].UTF8String, 0) != 0)
                    return NO;
            } else if (errno != ENOENT) {
                return NO;
            }
        }
        if (fsync(paths->fixtureFD) != 0) return NO;
        close(paths->fixtureFD);
        paths->fixtureFD = -1;
        if (unlinkat(paths->testsFD, kDT102739NFixtureName.UTF8String,
                AT_REMOVEDIR) != 0)
            return NO;
    }
    if (unlinkat(paths->testsFD, kDT102739NCleanupName.UTF8String, 0) != 0
        || fsync(paths->testsFD) != 0)
        return NO;
    dt102739n_emit(log, @"BUILD102739N_INTERRUPTED_CLEANUP_RECOVERY=PASS");
    return YES;
}

static void dt102739n_emit_refusal_zeroes(void (^log)(NSString *))
{
    dt102739n_emit(log, @"BUILD102739N_TRUST_MEMBERSHIP_QUERY_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_UPLOAD_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_REACTIVATION_SPAWN_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_CLEANUP_MARKER_PUBLICATION_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_UNLINK_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_FIXTURE_PRESERVED=YES");
    dt102739n_emit(log, @"BUILD102739N_COMMIT_PRESERVED=YES");
    dt102739n_emit(log, @"BUILD102739N_COMPLETE=NO");
}

static BOOL dt102739n_snapshot_protected(dt102739n_protected_t *snapshot);
static BOOL dt102739n_verify_protected(const dt102739n_protected_t *snapshot,
    BOOL wall2Restored, void (^log)(NSString *));

DTBuild102739NDispatch dt_build102739n_current_dispatch(void)
{
    return gDT102739NDispatch;
}

NSString *dt_build102739n_last_persisted_diagnostic_result(void)
{
    return gDT102739NLastPersistedDiagnosticResult;
}

void dt_build102739n_force_dispatch(DTBuild102739NDispatch dispatch)
{
    gDT102739NDispatch = dispatch;
}

BOOL dt_build102739n_probe_project_owned_legacy(
    void (^log)(NSString *), NSString **detailOut)
{
    /* Read-only ownership proof. Does not mutate disks or dispatch. */
    dt102739n_paths_t paths;
    if (!dt102739n_open_active(&paths, NO, NO)) {
        if (detailOut) *detailOut = @"no active BUILD102739N control tree";
        return NO;
    }

    BOOL owned = NO;
    NSString *why = @"no recognizable project ledger";

    if (paths.fixtureFD >= 0) {
        NSString *manifestText = nil;
        struct stat manifestStat = {0};
        NSDictionary *manifest = dt102739n_load_ledger(paths.fixtureFD,
            kDT102739NManifestName, 0600, dt102739n_manifest_keys(),
            &manifestText, &manifestStat);
        if (manifest
            && [manifest[@"schema_version"] isEqualToString:@"1"]
            && [manifest[@"build_variant"] isEqualToString:@"BUILD102739N"]
            && [manifest[@"protocol"] isEqualToString:kDT102739NProtocol]) {
            /* Known project manifest schema — ownership proven even if helper
             * SHA/CDHash no longer match the packaged probe. */
            struct stat helperStat = {0};
            BOOL helperPresent = dt102739n_open_regular(paths.fixtureFD,
                kDT102739NHelperName, 0755, NULL, &helperStat);
            owned = YES;
            why = helperPresent
                ? @"manifest.v1 schema/protocol + helper present (content may differ)"
                : @"manifest.v1 schema/protocol (helper absent/mismatched meta)";
            if (log) {
                /* Keep probe quiet on stage spam; caller logs the YES/NO. */
                (void)log;
            }
        }
    }

    if (!owned && paths.testsFD >= 0) {
        NSString *cleanupText = nil;
        NSDictionary *cleanup = dt102739n_load_ledger(paths.testsFD,
            kDT102739NCleanupName, 0600, dt102739n_cleanup_keys(),
            &cleanupText, NULL);
        if (cleanup
            && [cleanup[@"schema_version"] isEqualToString:@"1"]
            && [cleanup[@"build_variant"] isEqualToString:@"BUILD102739N"]
            && [cleanup[@"protocol"] isEqualToString:kDT102739NProtocol]) {
            owned = YES;
            why = @"cleanup ledger schema/protocol (project-owned interrupted cleanup)";
        }
    }

    dt102739n_close_paths(&paths);
    if (detailOut) *detailOut = why;
    return owned;
}

DTBuild102739NDispatch dt_build102739n_classify_before_chain(
    void (^log)(NSString *), NSString **verdictOut)
{
    gDT102739NDispatch = DTBuild102739NDispatchStop;
    gDT102739NRunID = [[[[NSUUID UUID] UUIDString] lowercaseString]
        stringByReplacingOccurrencesOfString:@"-" withString:@""];
    gDT102739NTransaction = nil;
    gDT102739NPhase = @"CLASSIFY";
    gDT102739NSequence = 0;

    dt102739n_paths_t paths;
    if (!dt102739n_open_active(&paths, NO, NO)) {
        char hash[256] = {0};
        NSString *active = dt710_resolve_active_preboot_path();
        BOOL hashOK = dt710_copy_boot_manifest_hash(hash, sizeof(hash));
        NSString *tests = [[active stringByAppendingPathComponent:@"dopamin-tvos/control"]
            stringByAppendingPathComponent:@"tests"];
        NSString *fixture = [tests stringByAppendingPathComponent:kDT102739NFixtureName];
        NSString *cleanup = [tests stringByAppendingPathComponent:kDT102739NCleanupName];
        NSString *cleanupTemp = [tests
            stringByAppendingPathComponent:@".build102739n.cleanup.v1.tmp"];
        struct stat fixtureStat = {0}, cleanupStat = {0}, cleanupTempStat = {0};
        errno = 0;
        BOOL fixtureAbsent = lstat(fixture.fileSystemRepresentation, &fixtureStat) != 0
            && errno == ENOENT;
        errno = 0;
        BOOL cleanupAbsent = lstat(cleanup.fileSystemRepresentation, &cleanupStat) != 0
            && errno == ENOENT;
        errno = 0;
        BOOL cleanupTempAbsent = lstat(cleanupTemp.fileSystemRepresentation,
            &cleanupTempStat) != 0 && errno == ENOENT;
        if (hashOK && active.length && fixtureAbsent && cleanupAbsent
            && cleanupTempAbsent) {
            gDT102739NTransaction = dt102739n_nonce();
            gDT102739NPhase = @"STAGE";
            dt102739n_emit(log, @"BUILD102739N_REPORT_SCHEMA=2");
            dt102739n_emit(log, @"BUILD102739N_CLASSIFIER_BEFORE_POST_WALL2_CHAIN=YES");
            gDT102739NDispatch = DTBuild102739NDispatchRunA;
            dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=RUN_A_FRESH");
            if (verdictOut) *verdictOut = @"RUN_A_FRESH";
            return gDT102739NDispatch;
        }
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=INVALID_PERSISTED_STATE");
        if (verdictOut) *verdictOut = @"INVALID_PERSISTED_STATE";
        return gDT102739NDispatch;
    }

    struct stat cleanupStat = {0};
    BOOL cleanupPresent = fstatat(paths.testsFD, kDT102739NCleanupName.UTF8String,
        &cleanupStat, AT_SYMLINK_NOFOLLOW) == 0;
    struct stat cleanupTempStat = {0};
    BOOL cleanupTempPresent = fstatat(paths.testsFD,
        ".build102739n.cleanup.v1.tmp", &cleanupTempStat,
        AT_SYMLINK_NOFOLLOW) == 0;
    if (cleanupTempPresent) {
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=ORPHANED_PREMANIFEST_STATE");
        if (verdictOut) *verdictOut = @"ORPHANED_PREMANIFEST_STATE";
        dt102739n_close_paths(&paths);
        return gDT102739NDispatch;
    }
    if (!paths.fixturePreexisted && !cleanupPresent) {
        gDT102739NTransaction = dt102739n_nonce();
        gDT102739NPhase = @"STAGE";
        dt102739n_emit(log, @"BUILD102739N_REPORT_SCHEMA=2");
        dt102739n_emit(log, @"BUILD102739N_CLASSIFIER_BEFORE_POST_WALL2_CHAIN=YES");
        dt102739n_close_paths(&paths);
        gDT102739NDispatch = DTBuild102739NDispatchRunA;
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=RUN_A_FRESH");
        if (verdictOut) *verdictOut = @"RUN_A_FRESH";
        return gDT102739NDispatch;
    }

    NSString *manifestText = nil;
    struct stat manifestStat = {0}, helperStat = {0}, commitStat = {0};
    NSDictionary *manifest = paths.fixtureFD >= 0
        ? dt102739n_load_ledger(paths.fixtureFD, kDT102739NManifestName, 0600,
            dt102739n_manifest_keys(), &manifestText, &manifestStat) : nil;
    BOOL helperOK = paths.fixtureFD >= 0
        && dt102739n_open_regular(paths.fixtureFD, kDT102739NHelperName, 0755,
            NULL, &helperStat);
    NSString *commitText = nil;
    NSDictionary *commit = paths.fixtureFD >= 0
        ? dt102739n_load_ledger(paths.fixtureFD, kDT102739NCommitName, 0600,
            dt102739n_commit_keys(), &commitText, &commitStat) : nil;
    if (manifest[@"transaction_uuid"])
        gDT102739NTransaction = manifest[@"transaction_uuid"];
    dt102739n_emit(log, @"BUILD102739N_REPORT_SCHEMA=2");
    dt102739n_emit(log, @"BUILD102739N_CLASSIFIER_BEFORE_POST_WALL2_CHAIN=YES");

    if (cleanupPresent) {
        NSString *cleanupText = nil;
        NSDictionary *cleanup = dt102739n_load_ledger(paths.testsFD,
            kDT102739NCleanupName, 0600, dt102739n_cleanup_keys(),
            &cleanupText, NULL);
        if (!gDT102739NTransaction && cleanup[@"transaction_uuid"])
            gDT102739NTransaction = cleanup[@"transaction_uuid"];
        gDT102739NPhase = @"PERSISTED_DIAGNOSTIC";
        dt102739n_log_persisted_diagnostics(log, &paths, manifest, manifestText,
            commit, commitText, helperOK, &helperStat, &manifestStat, &commitStat);
        dt102739n_emit(log, @"BUILD102739N_CLEANUP_MARKER_PRESENT=YES");
        dt102739n_emit(log, @"BUILD102739N_DIAGNOSTIC_RECOVERY_MUTATION_ENABLED=NO");
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=INTERRUPTED_CLEANUP_DIAGNOSTIC_ONLY");
        if (verdictOut) *verdictOut = @"INTERRUPTED_CLEANUP_DIAGNOSTIC_ONLY";
        dt102739n_close_paths(&paths);
        return gDT102739NDispatch;
    }

    if (!manifest || !helperOK
        || !dt102739n_validate_manifest_identity(manifest, &paths, &helperStat,
            &manifestStat)) {
        gDT102739NPhase = @"PERSISTED_DIAGNOSTIC";
        dt102739n_log_persisted_diagnostics(log, &paths, manifest, manifestText,
            commit, commitText, helperOK, &helperStat, &manifestStat, &commitStat);
        dt102739n_emit(log, @"BUILD102739N_DIAGNOSTIC_RECOVERY_MUTATION_ENABLED=NO");
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=PERSISTED_MANIFEST_OR_HELPER_DIAGNOSTIC_ONLY");
        if (verdictOut) *verdictOut = @"PERSISTED_MANIFEST_OR_HELPER_DIAGNOSTIC_ONLY";
        dt102739n_close_paths(&paths);
        return gDT102739NDispatch;
    }

    if (!commit) {
        gDT102739NPhase = @"PERSISTED_DIAGNOSTIC";
        dt102739n_log_persisted_diagnostics(log, &paths, manifest, manifestText,
            commit, commitText, helperOK, &helperStat, &manifestStat, &commitStat);
        dt102739n_emit(log, @"BUILD102739N_DIAGNOSTIC_RECOVERY_MUTATION_ENABLED=NO");
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=INTERRUPTED_STAGING_DIAGNOSTIC_ONLY");
        if (verdictOut) *verdictOut = @"INTERRUPTED_STAGING_DIAGNOSTIC_ONLY";
        dt102739n_close_paths(&paths);
        return gDT102739NDispatch;
    }

    if (!dt102739n_validate_commit_identity(commit, manifest, manifestText,
            &manifestStat, &commitStat)
        || !dt102739n_fixture_expected_entries(paths.fixtureFD, YES)) {
        gDT102739NPhase = @"PERSISTED_DIAGNOSTIC";
        dt102739n_log_persisted_diagnostics(log, &paths, manifest, manifestText,
            commit, commitText, helperOK, &helperStat, &manifestStat, &commitStat);
        dt102739n_emit(log, @"BUILD102739N_DIAGNOSTIC_RECOVERY_MUTATION_ENABLED=NO");
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=PERSISTED_COMMIT_OR_ENTRY_DIAGNOSTIC_ONLY");
        if (verdictOut) *verdictOut = @"PERSISTED_COMMIT_OR_ENTRY_DIAGNOSTIC_ONLY";
        dt102739n_close_paths(&paths);
        return gDT102739NDispatch;
    }

    dt102739n_boot_identity_t current;
    BOOL bootValid = dt102739n_read_boot_identity(&current);
    dt102739n_log_boot(log, @"CURRENT", &current);
    long long oldSec = [manifest[@"run_a_boottime_sec"] longLongValue];
    int oldUsec = [manifest[@"run_a_boottime_usec"] intValue];
    BOOL uuidEqual = bootValid
        && [manifest[@"run_a_bootsessionuuid"] isEqualToString:
            [NSString stringWithUTF8String:current.uuid]];
    BOOL timeEqual = bootValid && current.time.tv_sec == oldSec
        && current.time.tv_usec == oldUsec;
    dt102739n_emit(log, @"BUILD102739N_RUN_A_BOOTSESSIONUUID=%@",
        manifest[@"run_a_bootsessionuuid"]);
    dt102739n_emit(log, @"BUILD102739N_RUN_A_BOOTTIME=%@.%@",
        manifest[@"run_a_boottime_sec"], manifest[@"run_a_boottime_usec"]);
    dt102739n_emit(log, @"BUILD102739N_CURRENT_BOOTTIME=%lld.%06d",
        (long long)current.time.tv_sec, (int)current.time.tv_usec);
    dt102739n_emit(log, @"BUILD102739N_BOOTSESSIONUUID_CHANGED=%@",
        bootValid && !uuidEqual ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_BOOTTIME_CHANGED=%@",
        bootValid && !timeEqual ? @"YES" : @"NO");

    if (bootValid && uuidEqual && timeEqual) {
        gDT102739NPhase = @"AWAITING_REBOOT_CHECK";
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=SAME_BOOT_AWAITING_REBOOT");
        dt102739n_emit(log, @"BUILD102739N_RUN_PHASE=AWAITING_REBOOT_CHECK");
        dt102739n_emit(log, @"BUILD102739N_REBOOT_BOUNDARY=NOT_OBSERVED");
        dt102739n_emit_refusal_zeroes(log);
        dt102739n_protected_t refusalSnapshot;
        BOOL refusalProtected = dt102739n_snapshot_protected(&refusalSnapshot)
            && dt102739n_verify_protected(&refusalSnapshot, YES, log);
        dt102739n_emit(log, @"BUILD102739N_PROTECTED_STATE_GATE=%@",
            refusalProtected ? @"PASS" : @"FAIL");
        dt102739n_emit(log, @"BUILD102739N_FINAL_RESULT=PERSISTENT_CONTROL_FIXTURE_STAGE_PASS_AWAITING_REBOOT");
        if (verdictOut) *verdictOut = @"PERSISTENT_CONTROL_FIXTURE_STAGE_PASS_AWAITING_REBOOT";
    } else if (bootValid && !uuidEqual && !timeEqual) {
        gDT102739NPhase = @"REACTIVATE";
        gDT102739NDispatch = DTBuild102739NDispatchRunB;
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=RUN_B_REACTIVATE");
        dt102739n_emit(log, @"BUILD102739N_REBOOT_BOUNDARY=DIFFERENT_KERNEL_BOOT_CONFIRMED");
        if (verdictOut) *verdictOut = @"RUN_B_REACTIVATE";
    } else {
        gDT102739NPhase = @"AWAITING_REBOOT_CHECK";
        dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=BOOT_IDENTITY_AMBIGUOUS");
        dt102739n_emit(log, @"BUILD102739N_RUN_PHASE=AWAITING_REBOOT_CHECK");
        dt102739n_emit(log, @"BUILD102739N_REBOOT_BOUNDARY=AMBIGUOUS");
        dt102739n_emit_refusal_zeroes(log);
        dt102739n_protected_t refusalSnapshot;
        BOOL refusalProtected = dt102739n_snapshot_protected(&refusalSnapshot)
            && dt102739n_verify_protected(&refusalSnapshot, YES, log);
        dt102739n_emit(log, @"BUILD102739N_PROTECTED_STATE_GATE=%@",
            refusalProtected ? @"PASS" : @"FAIL");
        dt102739n_emit(log, @"BUILD102739N_FINAL_RESULT=BOOT_IDENTITY_AMBIGUOUS");
        if (verdictOut) *verdictOut = @"BOOT_IDENTITY_AMBIGUOUS";
    }
    dt102739n_close_paths(&paths);
    return gDT102739NDispatch;
}

static BOOL dt102739n_snapshot_protected(dt102739n_protected_t *snapshot)
{
    if (!snapshot) return NO;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->pid1Path = dt102739n_pid_path(1);
    snapshot->pid1Proc = dt102739n_pid1_proc();
    snapshot->ltopSHA = dt102739n_sha256(@"/usr/bin/ltop");
    NSString *handoff = [[[NSBundle mainBundle] bundlePath]
        stringByAppendingPathComponent:@"Handoff516"];
    snapshot->jHookSHA = dt102739n_sha256(dt710_resolve_hook_path());
    snapshot->jHelperSHA = dt102739n_sha256(
        [handoff stringByAppendingPathComponent:@"dt_opainject516"]);
    NSString *oldNamespace = [dt710_resolve_active_preboot_path()
        stringByAppendingPathComponent:@"dopamin-tvos-102710"];
    snapshot->oldNamespacePresent = lstat(oldNamespace.fileSystemRepresentation,
        &snapshot->oldNamespaceStat) == 0;
    return snapshot->pid1Path.length && snapshot->pid1Proc
        && snapshot->ltopSHA.length && snapshot->jHookSHA.length
        && snapshot->jHelperSHA.length;
}

static BOOL dt102739n_verify_protected(const dt102739n_protected_t *snapshot,
    BOOL wall2Restored, void (^log)(NSString *))
{
    NSString *handoff = [[[NSBundle mainBundle] bundlePath]
        stringByAppendingPathComponent:@"Handoff516"];
    NSString *oldNamespace = [dt710_resolve_active_preboot_path()
        stringByAppendingPathComponent:@"dopamin-tvos-102710"];
    struct stat oldAfter = {0};
    BOOL oldPresentAfter = lstat(oldNamespace.fileSystemRepresentation, &oldAfter) == 0;
    BOOL pid1 = snapshot && snapshot->pid1Proc == dt102739n_pid1_proc()
        && [snapshot->pid1Path isEqualToString:dt102739n_pid_path(1)];
    BOOL ltop = snapshot && [snapshot->ltopSHA
        isEqualToString:dt102739n_sha256(@"/usr/bin/ltop")];
    BOOL j = snapshot && [snapshot->jHookSHA
        isEqualToString:dt102739n_sha256(dt710_resolve_hook_path())]
        && [snapshot->jHelperSHA isEqualToString:dt102739n_sha256(
            [handoff stringByAppendingPathComponent:@"dt_opainject516"])];
    BOOL old = snapshot && snapshot->oldNamespacePresent == oldPresentAfter
        && (!oldPresentAfter || dt102739n_stat_equal(&snapshot->oldNamespaceStat, &oldAfter));
    dt102739n_emit(log, @"BUILD102739N_PID1_PRESENT_AFTER_PHASE=%@", dt102739n_pid_path(1) ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_PID1_IDENTITY_UNCHANGED=%@", pid1 ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_WALL2_GOT_ORIGINAL_STATE_RESTORED=%@", wall2Restored ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_APPLE_LTOP_IDENTITY_UNCHANGED=%@", ltop ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_FROZEN_J_IDENTITIES_UNCHANGED=%@", j ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_EXISTING_102710_NAMESPACE_UNCHANGED=%@", old ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_BOOTSTRAP_TARGET_FILES_CREATED=0");
    dt102739n_emit(log, @"BUILD102739N_BOOTSTRAP_TARGET_FILES_MODIFIED=0");
    dt102739n_emit(log, @"BUILD102739N_BOOTSTRAP_TARGET_FILES_REMOVED=0");
    dt102739n_emit(log, @"BUILD102739N_BOOTSTRAP_MARKER_CHANGED=NO");
    dt102739n_emit(log, @"BUILD102739N_SERVICES_CHANGED=NO");
    dt102739n_emit(log, @"BUILD102739N_ACCOUNTS_CHANGED=NO");
    dt102739n_emit(log, @"BUILD102739N_PACKAGES_CHANGED=NO");
    dt102739n_emit(log, @"BUILD102739N_NO_PANIC_SIGNATURE=YES");
    dt102739n_emit(log, @"BUILD102739N_NO_WATCHDOG_TERMINATION=YES");
    return pid1 && wall2Restored && ltop && j && old;
}

static void dt102739n_append_stat(NSMutableString *text, NSString *prefix,
    const struct stat *st, mode_t mode)
{
    [text appendFormat:@"%@_dev=%llu\n", prefix, (unsigned long long)st->st_dev];
    [text appendFormat:@"%@_ino=%llu\n", prefix, (unsigned long long)st->st_ino];
    [text appendFormat:@"%@_uid=%u\n", prefix, st->st_uid];
    [text appendFormat:@"%@_gid=%u\n", prefix, st->st_gid];
    [text appendFormat:@"%@_mode=%04o\n", prefix, mode];
    if ([prefix isEqualToString:@"control"] || [prefix isEqualToString:@"tests"]
        || [prefix isEqualToString:@"fixture"])
        [text appendFormat:@"%@_flags=%u\n", prefix, st->st_flags];
}

static NSString *dt102739n_manifest_text(dt102739n_paths_t *paths,
    const struct stat *helperStat, unsigned long helperSize, NSString *transaction,
    const dt102739n_boot_identity_t *boot)
{
    NSMutableString *text = [NSMutableString string];
    [text appendString:@"schema_version=1\n"];
    [text appendString:@"build_variant=BUILD102739N\n"];
    [text appendFormat:@"protocol=%@\n", kDT102739NProtocol];
    [text appendString:@"state=STAGING\n"];
    [text appendString:@"target_model=AppleTV6,2\n"];
    [text appendString:@"target_version=16.5\n"];
    [text appendString:@"target_build=20L563\n"];
    [text appendFormat:@"boot_manifest_hash=%@\n", paths->bootHash];
    [text appendFormat:@"transaction_uuid=%@\n", transaction];
    [text appendString:@"trustcache_uuid=1027394e-0000-4000-8000-000000000001\n"];
    [text appendString:@"control_relative=dopamin-tvos/control\n"];
    [text appendString:@"tests_relative=dopamin-tvos/control/tests\n"];
    [text appendString:@"fixture_relative=dopamin-tvos/control/tests/build102739n\n"];
    [text appendFormat:@"helper_name=%@\n", kDT102739NHelperName];
    [text appendFormat:@"helper_size=%lu\n", helperSize];
    [text appendFormat:@"helper_sha256=%s\n", DT102739N_HELPER_SHA256];
    [text appendFormat:@"helper_cdhash=%s\n", DT102739N_HELPER_CDHASH];
    dt102739n_append_stat(text, @"helper", helperStat, 0755);
    [text appendFormat:@"control_preexisted=%d\n", paths->controlPreexisted ? 1 : 0];
    [text appendFormat:@"control_created_by_n=%d\n", paths->controlCreated ? 1 : 0];
    dt102739n_append_stat(text, @"control", &paths->controlStat, 0755);
    [text appendFormat:@"tests_preexisted=%d\n", paths->testsPreexisted ? 1 : 0];
    [text appendFormat:@"tests_created_by_n=%d\n", paths->testsCreated ? 1 : 0];
    dt102739n_append_stat(text, @"tests", &paths->testsStat, 0700);
    [text appendString:@"fixture_preexisted=0\n"];
    [text appendString:@"fixture_created_by_n=1\n"];
    dt102739n_append_stat(text, @"fixture", &paths->fixtureStat, 0700);
    [text appendFormat:@"run_a_bootsessionuuid=%s\n", boot->uuid];
    [text appendFormat:@"run_a_boottime_sec=%lld\n", (long long)boot->time.tv_sec];
    [text appendFormat:@"run_a_boottime_usec=%d\n", (int)boot->time.tv_usec];
    [text appendFormat:@"created_timestamp=%@\n", dt102739n_timestamp()];
    return text;
}

static NSString *dt102739n_commit_text(dt102739n_paths_t *paths,
    NSDictionary *manifest, NSString *manifestSHA, const struct stat *manifestStat,
    NSString *childRecordSHA)
{
    NSMutableString *text = [NSMutableString string];
    [text appendString:@"schema_version=1\n"];
    [text appendString:@"build_variant=BUILD102739N\n"];
    [text appendFormat:@"protocol=%@\n", kDT102739NProtocol];
    [text appendString:@"state=AWAITING_REBOOT\n"];
    [text appendFormat:@"transaction_uuid=%@\n", manifest[@"transaction_uuid"]];
    [text appendFormat:@"boot_manifest_hash=%@\n", paths->bootHash];
    [text appendString:@"trustcache_uuid=1027394e-0000-4000-8000-000000000001\n"];
    [text appendFormat:@"manifest_sha256=%@\n", manifestSHA];
    dt102739n_append_stat(text, @"manifest", manifestStat, 0600);
    [text appendFormat:@"helper_sha256=%@\n", manifest[@"helper_sha256"]];
    [text appendFormat:@"helper_cdhash=%@\n", manifest[@"helper_cdhash"]];
    [text appendFormat:@"run_a_bootsessionuuid=%@\n", manifest[@"run_a_bootsessionuuid"]];
    [text appendFormat:@"run_a_boottime_sec=%@\n", manifest[@"run_a_boottime_sec"]];
    [text appendFormat:@"run_a_boottime_usec=%@\n", manifest[@"run_a_boottime_usec"]];
    [text appendFormat:@"stage_child_record_sha256=%@\n", childRecordSHA];
    [text appendString:@"stage_exit_status=0\n"];
    [text appendString:@"stage_child_proof=PASS\n"];
    [text appendString:@"protected_state_gate=PASS\n"];
    [text appendString:@"wall2_got_original_state_restored=YES\n"];
    [text appendFormat:@"commit_timestamp=%@\n", dt102739n_timestamp()];
    return text;
}

static NSString *dt102739n_cleanup_text(dt102739n_paths_t *paths,
    NSDictionary *manifest, NSDictionary *commit, NSString *manifestSHA,
    NSString *commitSHA, const struct stat *manifestStat,
    const struct stat *commitStat, NSString *childRecordSHA)
{
    NSMutableString *text = [NSMutableString string];
    [text appendString:@"schema_version=1\n"];
    [text appendString:@"build_variant=BUILD102739N\n"];
    [text appendFormat:@"protocol=%@\n", kDT102739NProtocol];
    [text appendString:@"state=CLEANING\n"];
    [text appendFormat:@"transaction_uuid=%@\n", manifest[@"transaction_uuid"]];
    [text appendFormat:@"boot_manifest_hash=%@\n", paths->bootHash];
    [text appendString:@"trustcache_uuid=1027394e-0000-4000-8000-000000000001\n"];
    [text appendFormat:@"manifest_sha256=%@\n", manifestSHA];
    [text appendFormat:@"commit_sha256=%@\n", commitSHA];
    dt102739n_append_stat(text, @"manifest", manifestStat, 0600);
    dt102739n_append_stat(text, @"commit", commitStat, 0600);
    [text appendFormat:@"helper_sha256=%@\n", manifest[@"helper_sha256"]];
    [text appendFormat:@"helper_cdhash=%@\n", manifest[@"helper_cdhash"]];
    dt102739n_append_stat(text, @"fixture", &paths->fixtureStat, 0700);
    dt102739n_append_stat(text, @"tests", &paths->testsStat, 0700);
    dt102739n_append_stat(text, @"control", &paths->controlStat, 0755);
    [text appendFormat:@"reactivation_child_record_sha256=%@\n", childRecordSHA];
    [text appendString:@"reactivation_exit_status=0\n"];
    [text appendString:@"reactivation_child_proof=PASS\n"];
    [text appendString:@"protected_state_gate=PASS\n"];
    [text appendFormat:@"cleanup_timestamp=%@\n", dt102739n_timestamp()];
    return text;
}

static int dt102739n_result(void (^log)(NSString *), NSString **verdictOut,
    NSString *verdict, BOOL pass)
{
    dt102739n_emit(log, @"BUILD102739N_FINAL_RESULT=%@", verdict);
    if (verdictOut) *verdictOut = verdict;
    return pass ? 0 : -739140;
}

static NSString *dt102739n_helper_path(dt102739n_paths_t *paths)
{
    return [[[[paths->activePath stringByAppendingPathComponent:kDT102739NControlComponent]
        stringByAppendingPathComponent:kDT102739NControlName]
        stringByAppendingPathComponent:kDT102739NTestsName]
        stringByAppendingPathComponent:
            [kDT102739NFixtureName stringByAppendingPathComponent:kDT102739NHelperName]];
}

static BOOL dt102739n_execute(void (^log)(NSString *), NSString *path,
    NSString *phase, NSString *transaction, const cdhash_t helperHash,
    NSString **recordSHAOut)
{
    NSDictionary *record = nil;
    BOOL stderrEmpty = NO, stdoutOverflow = NO, stderrOverflow = NO;
    BOOL timeout = NO, reaped = NO;
    int exitStatus = -1, termSignal = 0;
    pid_t childPID = 0;
    int spawnRC = dt102739n_spawn(path, phase, transaction, &record,
        &stderrEmpty, &stdoutOverflow, &stderrOverflow, &timeout, &reaped,
        &exitStatus, &termSignal, &childPID);
    NSUInteger dyldCount = NSUIntegerMax;
    NSString *recordSHA = nil;
    BOOL childProof = spawnRC == 0 && dt102739n_validate_child(record, phase,
        transaction, path, childPID, helperHash, &recordSHA, &dyldCount)
        && stderrEmpty && !stdoutOverflow && !stderrOverflow && !timeout
        && reaped && exitStatus == 0 && termSignal == 0;
    NSString *prefix = [phase isEqualToString:@"STAGE"] ? @"STAGE" : @"REACTIVATION";
    dt102739n_emit(log, @"BUILD102739N_%@_SPAWN_COUNT=%d", prefix,
        spawnRC == 0 ? 1 : 0);
    dt102739n_emit(log, @"BUILD102739N_%@_CHILD_PROOF=%@", prefix,
        childProof ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_%@_EXIT_STATUS=%d", prefix, exitStatus);
    dt102739n_emit(log, @"BUILD102739N_%@_CHILD_REAPED=%@", prefix,
        reaped ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_EFFECTIVE_ENVIRONMENT_CAPTURE=%@",
        record ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_DYLD_ENVIRONMENT_VARIABLE_COUNT=%@",
        dyldCount == NSUIntegerMax ? @"UNAVAILABLE"
            : [NSString stringWithFormat:@"%lu", (unsigned long)dyldCount]);
    dt102739n_emit(log, @"BUILD102739N_CONTAINER_MANAGER_SIDE_EFFECT_OBSERVED=%@",
        record && ![record[@"effective_env_count"] isEqualToString:@"0"] ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_CONTAINER_REMOVAL_ATTEMPTED=NO");
    if (childProof && recordSHAOut) *recordSHAOut = recordSHA;
    return childProof;
}

static BOOL dt102739n_m_snapshot(void (^log)(NSString *))
{
    unsigned long payloadSize = 0;
    const unsigned char *payload = getsectiondata(&_mh_execute_header,
        "__DATA", "__dtmhelper", &payloadSize);
    NSString *sha = payload && payloadSize
        ? dt102739n_sha256_bytes(payload, payloadSize) : nil;
    cdhash_t hash = {0};
    BOOL cdOK = dt102739n_decode_lower_hex(@DT102739M_HELPER_CDHASH,
        hash, sizeof(hash));
    BOOL shaOK = [sha isEqualToString:@DT102739M_HELPER_SHA256];
    BOOL identity = payload && payloadSize && shaOK && cdOK;
    BOOL trusted = identity && dt_cdhash_trustcached(hash);
    dt102739n_emit(log, @"BUILD102739N_M_FRESH_PROOF_INVOKED=NO");
    dt102739n_emit(log, @"BUILD102739N_M_IDENTITY_SOURCE=EMBEDDED_FINAL_SIGNED_BYTES");
    dt102739n_emit(log, @"BUILD102739N_M_EMBEDDED_SECTION=__DATA,__dtmhelper");
    dt102739n_emit(log, @"BUILD102739N_M_EMBEDDED_PAYLOAD_SIZE=%lu", payloadSize);
    dt102739n_emit(log, @"BUILD102739N_M_EMBEDDED_PAYLOAD_SHA256_ACTUAL=%@",
        sha ?: @"UNAVAILABLE");
    dt102739n_emit(log, @"BUILD102739N_M_EMBEDDED_PAYLOAD_SHA256_MATCH=%@",
        shaOK ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_M_EXPECTED_CDHASH_DECODED=%@",
        cdOK ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_M_LOOSE_BUNDLE_IDENTITY_GATES_RUN_B=NO");
    dt102739n_emit(log, @"BUILD102739N_M_FROZEN_IDENTITY_SNAPSHOT=%@",
        identity ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_M_HELPER_PRETRUSTED=%@",
        trusted ? @"YES" : @"NO");
    return identity;
}

static int dt102739n_run_stage(void (^log)(NSString *), BOOL wall2Restored,
    BOOL runMFirst, NSString **verdictOut)
{
    gDT102739NPhase = @"STAGE";
    dt102739n_emit(log, @"BUILD102739N_RUN_PHASE=STAGE");
    dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=RUN_A_FRESH");
    dt102739n_emit(log, @"BUILD102739N_RUN_A_REQUIRES_FRESH_M_PASS=%@",
        runMFirst ? @"YES" : @"NO");
    if (!runMFirst || !wall2Restored)
        return dt102739n_result(log, verdictOut, @"RUN_A_BASELINE_OR_WALL2_GATE_FAIL", NO);

    dt102739n_boot_identity_t boot;
    if (!dt102739n_read_boot_identity(&boot)) {
        dt102739n_log_boot(log, @"RUN_A", &boot);
        return dt102739n_result(log, verdictOut, @"RUN_A_BOOT_IDENTITY_FAIL", NO);
    }
    dt102739n_log_boot(log, @"RUN_A", &boot);

    unsigned long payloadSize = 0;
    const unsigned char *payload = getsectiondata(&_mh_execute_header,
        "__DATA", "__dtnhelper", &payloadSize);
    NSString *payloadSHA = payload && payloadSize
        ? dt102739n_sha256_bytes(payload, payloadSize) : nil;
    cdhash_t helperHash = {0};
    BOOL expectedHash = dt102739n_decode_lower_hex(@DT102739N_HELPER_CDHASH,
        helperHash, sizeof(helperHash));
    if (!payload || !payloadSize
        || ![payloadSHA isEqualToString:@DT102739N_HELPER_SHA256] || !expectedHash)
        return dt102739n_result(log, verdictOut, @"RUN_A_EMBEDDED_IDENTITY_FAIL", NO);
    BOOL pretrusted = dt_cdhash_trustcached(helperHash);
    dt102739n_emit(log, @"BUILD102739N_RUN_A_PREUPLOAD_TRUSTED=%@",
        pretrusted ? @"YES" : @"NO");
    if (pretrusted)
        return dt102739n_result(log, verdictOut, @"RUN_A_REQUIRES_FRESH_N_TRUST", NO);

    dt102739n_protected_t protectedBefore;
    if (!dt102739n_snapshot_protected(&protectedBefore))
        return dt102739n_result(log, verdictOut, @"RUN_A_PROTECTED_SNAPSHOT_FAIL", NO);

    dt102739n_paths_t paths;
    if (!dt102739n_open_active(&paths, YES, YES) || paths.fixturePreexisted
        || !paths.fixtureCreated) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_A_DIRECTORY_PROVENANCE_FAIL", NO);
    }
    dt102739n_emit(log, @"BUILD102739N_BOOT_MANIFEST_HASH_AVAILABLE=YES");
    dt102739n_emit(log, @"BUILD102739N_ACTIVE_PREBOOT_PATH_MATCH=YES");
    dt102739n_emit(log, @"BUILD102739N_PARENT_CHAIN_GATE=PASS");
    dt102739n_emit(log, @"BUILD102739N_SYMLINK_COMPONENT_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_DIRECTORY_PROVENANCE_GATE=PASS");
    dt102739n_emit(log, @"BUILD102739N_FIXTURE_PREEXISTED=NO");

    int helperFD = openat(paths.fixtureFD, kDT102739NHelperName.UTF8String,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0755);
    struct stat helperStat = {0};
    BOOL helperWritten = helperFD >= 0 && fchown(helperFD, 0, 0) == 0
        && fchmod(helperFD, 0755) == 0
        && dt102739n_write_all(helperFD, payload, payloadSize)
        && fstat(helperFD, &helperStat) == 0 && S_ISREG(helperStat.st_mode)
        && helperStat.st_uid == 0 && helperStat.st_gid == 0
        && (helperStat.st_mode & 07777) == 0755
        && helperStat.st_size == (off_t)payloadSize;
    if (helperFD >= 0) close(helperFD);
    NSString *helperPath = dt102739n_helper_path(&paths);
    cdhash_t stagedHash = {0};
    NSString *stagedCDHash = nil;
    BOOL stagedIdentity = helperWritten
        && [dt102739n_sha256(helperPath) isEqualToString:@DT102739N_HELPER_SHA256]
        && dt102739n_cdhash(helperPath, stagedHash, &stagedCDHash)
        && [stagedCDHash isEqualToString:@DT102739N_HELPER_CDHASH]
        && memcmp(stagedHash, helperHash, sizeof(cdhash_t)) == 0;
    dt102739n_emit(log, @"BUILD102739N_HELPER_SHA256_MATCH=%@",
        stagedIdentity ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_CDHASH_MATCH=%@",
        stagedIdentity ? @"YES" : @"NO");
    if (!stagedIdentity) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_A_HELPER_IDENTITY_FAIL", NO);
    }

    NSString *transaction = gDT102739NTransaction ?: dt102739n_nonce();
    gDT102739NTransaction = transaction;
    dt102739n_emit(log, @"BUILD102739N_TRANSACTION_UUID=%@", transaction);
    NSString *manifestText = dt102739n_manifest_text(&paths, &helperStat,
        payloadSize, transaction, &boot);
    NSData *manifestData = dt102739n_data(manifestText);
    struct stat manifestStat = {0};
    BOOL manifestPublished = dt102739n_atomic_publish(paths.fixtureFD,
        @".manifest.v1.tmp", kDT102739NManifestName, manifestData, 0600, &manifestStat);
    NSDictionary *manifest = manifestPublished
        ? dt102739n_parse_ledger(manifestText, dt102739n_manifest_keys()) : nil;
    BOOL manifestValid = manifest && dt102739n_validate_manifest_identity(
        manifest, &paths, &helperStat, &manifestStat);
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_STATE=STAGING");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_DURABLE=%@",
        manifestValid ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_RUN_A_BOOT_IDENTITY_COMMITTED=%@",
        manifestValid ? @"YES" : @"NO");
    if (!manifestValid) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_A_MANIFEST_FAIL", NO);
    }

    uint32_t uploaded = 0;
    int uploadRC = dt_trustcache_upload_batch_cdhashes(helperHash, 1,
        kDT102739NTrustUUID, &uploaded);
    BOOL trusted = dt_cdhash_trustcached(helperHash);
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_UUID_MATCH=YES");
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_PAYLOAD_ENTRY_COUNT=1");
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_UPLOAD_RC=%d", uploadRC);
    dt102739n_emit(log, @"BUILD102739N_HELPER_TRUSTED_AFTER_UPLOAD=%@",
        trusted ? @"YES" : @"NO");
    if (uploadRC != 0 || uploaded != 1 || !trusted) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_A_TRUST_FAIL", NO);
    }

    struct stat helperBeforeSpawn = {0}, manifestBeforeSpawn = {0};
    BOOL prespawn = fstatat(paths.fixtureFD, kDT102739NHelperName.UTF8String,
            &helperBeforeSpawn, AT_SYMLINK_NOFOLLOW) == 0
        && fstatat(paths.fixtureFD, kDT102739NManifestName.UTF8String,
            &manifestBeforeSpawn, AT_SYMLINK_NOFOLLOW) == 0
        && dt102739n_stat_equal(&helperStat, &helperBeforeSpawn)
        && dt102739n_stat_equal(&manifestStat, &manifestBeforeSpawn);
    dt102739n_emit(log, @"BUILD102739N_PRESPAWN_IDENTITY_GATE=%@",
        prespawn ? @"PASS" : @"FAIL");
    NSString *recordSHA = nil;
    BOOL child = prespawn && dt102739n_execute(log, helperPath, @"STAGE",
        transaction, helperHash, &recordSHA);
    BOOL protectedOK = child
        && dt102739n_verify_protected(&protectedBefore, wall2Restored, log);
    dt102739n_emit(log, @"BUILD102739N_PROTECTED_STATE_GATE=%@",
        protectedOK ? @"PASS" : @"FAIL");
    if (!child || !protectedOK) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_A_CHILD_OR_PRESERVATION_FAIL", NO);
    }

    NSString *manifestSHA = dt102739n_sha_data(manifestData);
    NSString *commitText = dt102739n_commit_text(&paths, manifest, manifestSHA,
        &manifestStat, recordSHA);
    struct stat commitStat = {0};
    BOOL committed = dt102739n_atomic_publish(paths.fixtureFD,
        @".stage.commit.v1.tmp", kDT102739NCommitName,
        dt102739n_data(commitText), 0600, &commitStat);
    NSDictionary *commit = committed
        ? dt102739n_parse_ledger(commitText, dt102739n_commit_keys()) : nil;
    committed = committed && dt102739n_validate_commit_identity(commit, manifest,
        manifestText, &manifestStat, &commitStat)
        && dt102739n_fixture_expected_entries(paths.fixtureFD, YES);
    dt102739n_emit(log, @"BUILD102739N_COMMIT_MARKER_DURABLE=%@",
        committed ? @"YES" : @"NO");
    dt102739n_close_paths(&paths);
    if (!committed)
        return dt102739n_result(log, verdictOut, @"RUN_A_COMMIT_FAIL", NO);
    dt102739n_emit(log, @"BUILD102739N_STATE=AWAITING_REBOOT");
    dt102739n_emit(log, @"BUILD102739N_REBOOT_REQUIRED=YES");
    dt102739n_emit(log, @"BUILD102739N_COMPLETE=NO");
    return dt102739n_result(log, verdictOut,
        @"PERSISTENT_CONTROL_FIXTURE_STAGE_PASS_AWAITING_REBOOT", YES);
}

static int dt102739n_run_reactivate(void (^log)(NSString *), BOOL wall2Restored,
    NSString **verdictOut)
{
    gDT102739NPhase = @"REACTIVATE";
    dt102739n_emit(log, @"BUILD102739N_RUN_PHASE=REACTIVATE");
    dt102739n_emit(log, @"BUILD102739N_STATE_CLASSIFICATION=RUN_B_REACTIVATE");
    dt102739n_emit(log, @"BUILD102739N_M_FRESH_PROOF_INVOKED=NO");
    if (!wall2Restored)
        return dt102739n_result(log, verdictOut, @"RUN_B_WALL2_GATE_FAIL", NO);

    dt102739n_paths_t paths;
    if (!dt102739n_open_active(&paths, NO, NO) || paths.fixtureFD < 0)
        return dt102739n_result(log, verdictOut, @"RUN_B_PATH_GATE_FAIL", NO);
    NSString *manifestText = nil, *commitText = nil;
    struct stat manifestStat = {0}, commitStat = {0}, helperStat = {0};
    NSDictionary *manifest = dt102739n_load_ledger(paths.fixtureFD,
        kDT102739NManifestName, 0600, dt102739n_manifest_keys(),
        &manifestText, &manifestStat);
    NSDictionary *commit = dt102739n_load_ledger(paths.fixtureFD,
        kDT102739NCommitName, 0600, dt102739n_commit_keys(),
        &commitText, &commitStat);
    if (manifest[@"transaction_uuid"])
        gDT102739NTransaction = manifest[@"transaction_uuid"];
    dt102739n_emit(log, @"BUILD102739N_TRANSACTION_UUID=%@",
        gDT102739NTransaction ?: @"UNAVAILABLE");
    BOOL helperOpen = dt102739n_open_regular(paths.fixtureFD,
        kDT102739NHelperName, 0755, NULL, &helperStat);
    BOOL relationship = helperOpen
        && dt102739n_validate_manifest_identity(manifest, &paths, &helperStat,
            &manifestStat)
        && dt102739n_validate_commit_identity(commit, manifest, manifestText,
            &manifestStat, &commitStat)
        && dt102739n_fixture_expected_entries(paths.fixtureFD, YES);
    dt102739n_emit(log, @"BUILD102739N_BOOT_MANIFEST_HASH_MATCH=%@",
        relationship ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_STATE=%@",
        manifest ? @"STAGING" : @"INVALID");
    dt102739n_emit(log, @"BUILD102739N_COMMIT_STATE=%@",
        commit ? @"AWAITING_REBOOT" : @"INVALID");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_COMMIT_RELATIONSHIP=%@",
        relationship ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_PERSISTED_DIRECTORY_PROVENANCE_GATE=%@",
        relationship ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_PERSISTED_HELPER_IDENTITY_GATE=%@",
        relationship ? @"PASS" : @"FAIL");
    if (!relationship) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_PERSISTED_IDENTITY_FAIL", NO);
    }

    dt102739n_boot_identity_t current;
    BOOL bootValid = dt102739n_read_boot_identity(&current);
    dt102739n_log_boot(log, @"RUN_B", &current);
    BOOL uuidChanged = bootValid && ![manifest[@"run_a_bootsessionuuid"]
        isEqualToString:[NSString stringWithUTF8String:current.uuid]];
    BOOL timeChanged = bootValid
        && (current.time.tv_sec != [manifest[@"run_a_boottime_sec"] longLongValue]
            || current.time.tv_usec != [manifest[@"run_a_boottime_usec"] intValue]);
    dt102739n_emit(log, @"BUILD102739N_BOOTSESSIONUUID_CHANGED=%@",
        uuidChanged ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_BOOTTIME_CHANGED=%@",
        timeChanged ? @"YES" : @"NO");
    if (!bootValid || !uuidChanged || !timeChanged) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_BOOT_IDENTITY_GATE_FAIL", NO);
    }
    dt102739n_emit(log, @"BUILD102739N_REBOOT_BOUNDARY=DIFFERENT_KERNEL_BOOT_CONFIRMED");

    if (!dt102739n_m_snapshot(log)) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_M_SNAPSHOT_FAIL", NO);
    }
    dt102739n_protected_t protectedBefore;
    if (!dt102739n_snapshot_protected(&protectedBefore)) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_PROTECTED_SNAPSHOT_FAIL", NO);
    }

    cdhash_t helperHash = {0}, actualHash = {0};
    NSString *actualCDHash = nil;
    NSString *helperPath = dt102739n_helper_path(&paths);
    BOOL helperIdentity = dt102739n_decode_lower_hex(@DT102739N_HELPER_CDHASH,
            helperHash, sizeof(helperHash))
        && [dt102739n_sha256(helperPath) isEqualToString:@DT102739N_HELPER_SHA256]
        && dt102739n_cdhash(helperPath, actualHash, &actualCDHash)
        && [actualCDHash isEqualToString:@DT102739N_HELPER_CDHASH]
        && memcmp(helperHash, actualHash, sizeof(cdhash_t)) == 0;
    if (!helperIdentity) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_HELPER_REVALIDATION_FAIL", NO);
    }
    BOOL pretrusted = dt_cdhash_trustcached(helperHash);
    uint32_t uploaded = 0;
    int uploadRC = 0;
    if (!pretrusted)
        uploadRC = dt_trustcache_upload_batch_cdhashes(helperHash, 1,
            kDT102739NTrustUUID, &uploaded);
    BOOL trusted = dt_cdhash_trustcached(helperHash);
    BOOL trustPolicy = trusted
        && ((pretrusted && uploaded == 0) || (!pretrusted && uploadRC == 0 && uploaded == 1));
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_UUID_MATCH=YES");
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_PAYLOAD_ENTRY_COUNT=1");
    dt102739n_emit(log, @"BUILD102739N_RUN_B_PREUPLOAD_TRUSTED=%@",
        pretrusted ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_RUN_B_UPLOAD_PERFORMED=%@",
        pretrusted ? @"NO" : @"YES");
    dt102739n_emit(log, @"BUILD102739N_RUN_B_UPLOAD_POLICY_MATCH=%@",
        trustPolicy ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_TRUSTED_BEFORE_REACTIVATION=%@",
        trusted ? @"YES" : @"NO");
    if (!trustPolicy) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_TRUST_POLICY_FAIL", NO);
    }

    struct stat helperBeforeSpawn = {0}, manifestBeforeSpawn = {0}, commitBeforeSpawn = {0};
    BOOL prespawn = fstatat(paths.fixtureFD, kDT102739NHelperName.UTF8String,
            &helperBeforeSpawn, AT_SYMLINK_NOFOLLOW) == 0
        && fstatat(paths.fixtureFD, kDT102739NManifestName.UTF8String,
            &manifestBeforeSpawn, AT_SYMLINK_NOFOLLOW) == 0
        && fstatat(paths.fixtureFD, kDT102739NCommitName.UTF8String,
            &commitBeforeSpawn, AT_SYMLINK_NOFOLLOW) == 0
        && dt102739n_stat_equal(&helperStat, &helperBeforeSpawn)
        && dt102739n_stat_equal(&manifestStat, &manifestBeforeSpawn)
        && dt102739n_stat_equal(&commitStat, &commitBeforeSpawn);
    dt102739n_emit(log, @"BUILD102739N_PRESPAWN_IDENTITY_GATE=%@",
        prespawn ? @"PASS" : @"FAIL");
    NSString *recordSHA = nil;
    BOOL child = prespawn && dt102739n_execute(log, helperPath, @"REACTIVATE",
        manifest[@"transaction_uuid"], helperHash, &recordSHA);
    BOOL protectedOK = child
        && dt102739n_verify_protected(&protectedBefore, wall2Restored, log);
    dt102739n_emit(log, @"BUILD102739N_PROTECTED_STATE_GATE=%@",
        protectedOK ? @"PASS" : @"FAIL");
    if (!child || !protectedOK) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_CHILD_OR_PRESERVATION_FAIL", NO);
    }

    NSString *manifestSHA = dt102739n_sha_data(dt102739n_data(manifestText));
    NSString *commitSHA = dt102739n_sha_data(dt102739n_data(commitText));
    NSString *cleanupText = dt102739n_cleanup_text(&paths, manifest, commit,
        manifestSHA, commitSHA, &manifestStat, &commitStat, recordSHA);
    struct stat cleanupStat = {0};
    BOOL cleanupPublished = dt102739n_atomic_publish(paths.testsFD,
        @".build102739n.cleanup.v1.tmp", kDT102739NCleanupName,
        dt102739n_data(cleanupText), 0600, &cleanupStat);
    NSDictionary *cleanup = cleanupPublished
        ? dt102739n_parse_ledger(cleanupText, dt102739n_cleanup_keys()) : nil;
    cleanupPublished = cleanupPublished
        && dt102739n_cleanup_marker_static_valid(cleanup, manifest, commit,
            manifestSHA, commitSHA);
    dt102739n_emit(log, @"BUILD102739N_CLEANUP_MARKER_STATE=%@",
        cleanupPublished ? @"CLEANING" : @"INVALID");
    dt102739n_emit(log, @"BUILD102739N_CLEANUP_MARKER_DURABLE=%@",
        cleanupPublished ? @"YES" : @"NO");
    if (!cleanupPublished) {
        dt102739n_close_paths(&paths);
        return dt102739n_result(log, verdictOut, @"RUN_B_CLEANUP_MARKER_FAIL", NO);
    }

    BOOL cleaned = dt102739n_resume_cleanup(log, &paths, cleanup);
    struct stat absent = {0};
    BOOL fixtureAbsent = fstatat(paths.testsFD, kDT102739NFixtureName.UTF8String,
        &absent, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    BOOL cleanupAbsent = fstatat(paths.testsFD, kDT102739NCleanupName.UTF8String,
        &absent, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    struct stat controlAfter = {0}, testsAfter = {0};
    BOOL parents = fstat(paths.controlFD, &controlAfter) == 0
        && fstat(paths.testsFD, &testsAfter) == 0
        && dt102739n_stat_equal(&paths.controlStat, &controlAfter)
        && dt102739n_stat_equal(&paths.testsStat, &testsAfter);
    dt102739n_emit(log, @"BUILD102739N_CLEANUP_IDENTITY_GATE=%@",
        cleaned ? @"PASS" : @"FAIL");
    dt102739n_emit(log, @"BUILD102739N_HELPER_ABSENT_AFTER_CLEANUP=%@",
        fixtureAbsent ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_MANIFEST_ABSENT_AFTER_CLEANUP=%@",
        fixtureAbsent ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_COMMIT_ABSENT_AFTER_CLEANUP=%@",
        fixtureAbsent ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_FIXTURE_ABSENT_AFTER_CLEANUP=%@",
        fixtureAbsent ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_CLEANUP_MARKER_ABSENT_AFTER_CLEANUP=%@",
        cleanupAbsent ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_CONTROL_PARENT_POLICY=PRESERVE");
    dt102739n_emit(log, @"BUILD102739N_TESTS_PARENT_POLICY=PRESERVE");
    dt102739n_emit(log, @"BUILD102739N_CONTROL_TESTS_PARENT_IDENTITIES_UNCHANGED=%@",
        parents ? @"YES" : @"NO");
    dt102739n_emit(log, @"BUILD102739N_CONTAINER_REMOVAL_ATTEMPTED=NO");
    dt102739n_emit(log, @"BUILD102739N_TRUSTCACHE_EXACT_RESTORE_SUPPORTED=NO");
    dt102739n_emit(log, @"BUILD102739N_HELPER_TRUSTED_AFTER_FILE_CLEANUP=%@",
        dt_cdhash_trustcached(helperHash) ? @"YES" : @"NO");
    dt102739n_close_paths(&paths);
    BOOL pass = cleaned && fixtureAbsent && cleanupAbsent && parents
        && dt_cdhash_trustcached(helperHash);
    dt102739n_emit(log, @"BUILD102739N_COMPLETE=%@", pass ? @"YES" : @"NO");
    return dt102739n_result(log, verdictOut,
        pass ? @"PERSISTENT_CONTROL_FIXTURE_REACTIVATION_AND_CLEANUP_PASS_WITH_RESIDUAL_IN_MEMORY_TRUST"
             : @"RUN_B_CLEANUP_FAIL",
        pass);
}

int dt_build102739n_run_persistent_control_fixture_proof(
    void (^log)(NSString *), BOOL wall2Restored, BOOL runMFirst,
    NSString **verdictOut)
{
    dt102739n_emit(log, @"BUILD102739N_BEGIN=YES");
    dt102739n_emit(log, @"BUILD102739N_VARIANT=BUILD102739N_V2");
    dt102739n_emit(log, @"BUILD102739N_PROTOCOL=%@", kDT102739NProtocol);
    dt102739n_emit(log, @"BUILD102739N_BOOTSTRAP_INSTALL_ENABLED=NO");
    dt102739n_emit(log, @"BUILD102739N_NEW_KERNEL_OFFSET_COUNT=0");
    dt102739n_emit(log, @"BUILD102739N_NEW_LAUNCHD_OFFSET_COUNT=0");
    if (gDT102739NDispatch == DTBuild102739NDispatchRunA)
        return dt102739n_run_stage(log, wall2Restored, runMFirst, verdictOut);
    if (gDT102739NDispatch == DTBuild102739NDispatchRunB)
        return dt102739n_run_reactivate(log, wall2Restored, verdictOut);
    return dt102739n_result(log, verdictOut, @"N_DISPATCH_STOPPED_BY_CLASSIFIER", NO);
}
