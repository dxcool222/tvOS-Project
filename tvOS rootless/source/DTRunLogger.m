#import "DTRunLogger.h"
#import <os/log.h>

#ifndef DT_BUILD_NUM
#define DT_BUILD_NUM 0
#endif
#import <stdarg.h>
#import <stdio.h>
#import <unistd.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <sys/sysctl.h>

static const NSUInteger kMaxLogFileBytes = 4 * 1024 * 1024;
static NSString *const kDTConsoleMirrorContract = @"R24_CONSOLE_MIRROR_ALL_APP_LOGS=YES";
static const char *kDTRuntimeTracePath = "/private/var/jb/.r24_runtime_trace";

static os_log_t s_log_run;
static os_log_t s_log_stage;

@implementation DTRunLogger {
    dispatch_queue_t _queue;
    FILE *_fp;
    BOOL _opened;
    BOOL _emitting;
    dispatch_queue_t _runtimeTraceQueue;
    dispatch_source_t _runtimeTraceTimer;
    off_t _runtimeTraceOffset;
    dev_t _runtimeTraceDevice;
    ino_t _runtimeTraceInode;
    NSMutableData *_runtimeTracePartial;
}

+ (void)initialize
{
    if (self != [DTRunLogger class]) return;
    s_log_run = os_log_create("com.dopamin.tvos.kfd", "run");
    s_log_stage = os_log_create("com.dopamin.tvos.kfd", "stage");
}

+ (instancetype)shared
{
    static DTRunLogger *l;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ l = [DTRunLogger new]; });
    return l;
}

+ (NSString *)logFilePath
{
    NSString *home = NSHomeDirectory();
    return [home stringByAppendingPathComponent:@"Documents/kfd_run.log"];
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.dopamin.tvos.kfd.runlogger", DISPATCH_QUEUE_SERIAL);
        _runtimeTraceQueue = dispatch_queue_create("com.dopamin.tvos.kfd.runtime-trace-relay", DISPATCH_QUEUE_SERIAL);
        _runtimeTracePartial = [NSMutableData data];
    }
    return self;
}

- (void)relayRuntimeTraceLocked
{
    int fd = open(kDTRuntimeTracePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return;

    struct stat st = {0};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return;
    }
    if (_runtimeTraceInode != st.st_ino || _runtimeTraceDevice != st.st_dev
        || st.st_size < _runtimeTraceOffset) {
        _runtimeTraceOffset = 0;
        _runtimeTraceDevice = st.st_dev;
        _runtimeTraceInode = st.st_ino;
        [_runtimeTracePartial setLength:0];
    }

    uint8_t buffer[16384];
    for (unsigned pass = 0; pass < 64; pass++) {
        ssize_t nr = pread(fd, buffer, sizeof(buffer), _runtimeTraceOffset);
        if (nr <= 0) break;
        _runtimeTraceOffset += nr;
        [_runtimeTracePartial appendBytes:buffer length:(NSUInteger)nr];

        while (_runtimeTracePartial.length) {
            const uint8_t *bytes = _runtimeTracePartial.bytes;
            const void *newline = memchr(bytes, '\n', _runtimeTracePartial.length);
            if (!newline) break;
            NSUInteger rowLength = (const uint8_t *)newline - bytes;
            NSData *rowData = [_runtimeTracePartial subdataWithRange:NSMakeRange(0, rowLength)];
            NSString *row = [[NSString alloc] initWithData:rowData encoding:NSUTF8StringEncoding];
            [_runtimeTracePartial replaceBytesInRange:NSMakeRange(0, rowLength + 1)
                                           withBytes:NULL length:0];
            if (row.length) {
                [self writeRaw:[NSString stringWithFormat:@"%@ %@\n", [self timestamp], row]
                         flush:NO];
                [self emitConsole:row type:[self consoleTypeForLine:row]];
            }
        }
    }
    close(fd);
}

- (BOOL)prepareRuntimeTraceForInjection:(NSError **)error
{
    __block BOOL ok = NO;
    __block int failureErrno = 0;
    dispatch_sync(_runtimeTraceQueue, ^{
        int fd = open(kDTRuntimeTracePath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0666);
        if (fd < 0) {
            failureErrno = errno;
            return;
        }
        struct stat st = {0};
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0
            || fchmod(fd, 0666) != 0) {
            failureErrno = errno ?: EPERM;
            close(fd);
            return;
        }
        char reset[256];
        int length = snprintf(reset, sizeof(reset),
            "R24TRACE component=APP pid=%d event=TRACE_RESET rc=0 errno=0 detail=before_pid1_injection\n",
            getpid());
        if (length <= 0 || write(fd, reset, (size_t)length) != length || fsync(fd) != 0) {
            failureErrno = errno ?: EIO;
            close(fd);
            return;
        }
        close(fd);
        _runtimeTraceOffset = 0;
        _runtimeTraceDevice = st.st_dev;
        _runtimeTraceInode = st.st_ino;
        [_runtimeTracePartial setLength:0];
        [self relayRuntimeTraceLocked];

        if (!_runtimeTraceTimer) {
            _runtimeTraceTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                        _runtimeTraceQueue);
            dispatch_source_set_timer(_runtimeTraceTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
                                      100 * NSEC_PER_MSEC, 20 * NSEC_PER_MSEC);
            __weak DTRunLogger *weakSelf = self;
            dispatch_source_set_event_handler(_runtimeTraceTimer, ^{
                [weakSelf relayRuntimeTraceLocked];
            });
            dispatch_resume(_runtimeTraceTimer);
        }
        ok = YES;
    });
    if (!ok && error) {
        *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:failureErrno ?: EIO
                                 userInfo:@{NSFilePathErrorKey:
                                                [NSString stringWithUTF8String:kDTRuntimeTracePath]}];
    }
    [self logStage:ok ? @"R24_RUNTIME_TRACE_RELAY=ARMED"
                      : [NSString stringWithFormat:@"R24_RUNTIME_TRACE_RELAY=FAIL errno=%d",
                                                   failureErrno]];
    return ok;
}

- (void)relayRuntimeTraceNow
{
    dispatch_sync(_runtimeTraceQueue, ^{
        [self relayRuntimeTraceLocked];
    });
}

/// Unified logging path — visible in macOS Console.app when the Apple TV is connected.
- (void)emitConsole:(NSString *)line type:(os_log_type_t)type
{
    if (!line.length) return;
    os_log_with_type(s_log_run, type, "%{public}@", line);
    NSLog(@"[dopamin-tvOS-kfd] %@", line);
}

- (void)emitStageConsole:(NSString *)stage
{
    if (!stage.length) return;
    NSString *line = [NSString stringWithFormat:@"STAGE %@", stage];
    os_log_with_type(s_log_stage, OS_LOG_TYPE_DEFAULT, "%{public}@", line);
    NSLog(@"[dopamin-tvOS-kfd] %@", line);
}

- (NSString *)timestamp
{
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    return [f stringFromDate:[NSDate date]];
}

- (void)rotateIfNeeded
{
    if (!_fp) return;
    long pos = ftell(_fp);
    if (pos >= 0 && (NSUInteger)pos > kMaxLogFileBytes) {
        fclose(_fp);
        _fp = NULL;
        NSString *path = [DTRunLogger logFilePath];
        [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
        _fp = fopen(path.fileSystemRepresentation, "a");
        if (_fp) {
            setvbuf(_fp, NULL, _IONBF, 0);
            fprintf(_fp, "=== log rotated (size cap) %s ===\n", self.timestamp.UTF8String);
            fflush(_fp);
        }
    }
}

- (void)openFileIfNeeded
{
    if (_fp) return;
    NSString *path = [DTRunLogger logFilePath];
    NSString *dir = [path stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    _fp = fopen(path.fileSystemRepresentation, "a");
    if (_fp) {
        setvbuf(_fp, NULL, _IONBF, 0);
    }
}

- (void)writeRaw:(NSString *)text flush:(BOOL)hardFlush
{
    if (!text.length) return;
    dispatch_sync(_queue, ^{
        [self openFileIfNeeded];
        [self rotateIfNeeded];
        if (!_fp) return;
        fputs(text.UTF8String, _fp);
        fflush(_fp);
        if (hardFlush) {
            fsync(fileno(_fp));
        }
    });
}

- (BOOL)shouldMirrorToConsole:(NSString *)line
{
    /*
     * R24 physical bring-up must remain diagnosable without SSH.  The on-disk
     * app-container log is still retained, but it is no longer the only copy
     * of ordinary (non-STAGE) lines: every line is mirrored to unified logging.
     */
    (void)line;
    (void)kDTConsoleMirrorContract;
    return YES;
}

- (os_log_type_t)consoleTypeForLine:(NSString *)line
{
    if ([line hasPrefix:@"[!]"] || [line hasPrefix:@"ERROR"] || [line containsString:@" failed"] || [line containsString:@"EXCEPTION"])
        return OS_LOG_TYPE_ERROR;
    return OS_LOG_TYPE_DEFAULT;
}

- (void)emit:(NSString *)line hardFlush:(BOOL)hardFlush
{
    if (!line.length || _emitting) return;
    _emitting = YES;
    @try {
        NSString *row = [NSString stringWithFormat:@"%@ %@\n", [self timestamp], line];
        [self writeRaw:row flush:hardFlush];
        if ([self shouldMirrorToConsole:line]) {
            [self emitConsole:line type:[self consoleTypeForLine:line]];
        }
    } @finally {
        _emitting = NO;
    }
}

- (void)open
{
    if (_opened) return;
    _opened = YES;
    char machine[64] = {0};
    char osversion[64] = {0};
    size_t len = sizeof(machine);
    sysctlbyname("hw.machine", machine, &len, NULL, 0);
    len = sizeof(osversion);
    sysctlbyname("kern.osversion", osversion, &len, NULL, 0);
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    NSString *ver = info[@"CFBundleShortVersionString"] ?: @"?";
    NSString *build = info[@"CFBundleVersion"] ?: @"?";
    NSString *codeBuild = [NSString stringWithFormat:@"%d", DT_BUILD_NUM];
    NSString *banner = [NSString stringWithFormat:@"session open v%@ plist %@ code build %@ %s/%s",
        ver, build, codeBuild, machine, osversion];
    [self writeRaw:[NSString stringWithFormat:
        @"\n========== session %@ plist %@ code build %@ (%@) %@ %s/%s ==========\n",
        ver, build, codeBuild, [self timestamp], [DTRunLogger logFilePath], machine, osversion]
        flush:YES];
    [self emitConsole:banner type:OS_LOG_TYPE_INFO];
    [self emitConsole:kDTConsoleMirrorContract type:OS_LOG_TYPE_INFO];
    [self emit:[NSString stringWithFormat:@"log file: %@", [DTRunLogger logFilePath]] hardFlush:YES];
}

- (void)beginExploitRun
{
    [self emitStageConsole:@"========== exploit run begin =========="];
    [self emit:@"========== exploit run begin ==========" hardFlush:YES];
}

- (void)log:(NSString *)line
{
    [self emit:line hardFlush:NO];
}

- (void)logStage:(NSString *)stage
{
    if (!stage.length) return;
    dispatch_sync(_queue, ^{
        [self openFileIfNeeded];
        [self rotateIfNeeded];
        if (_fp) {
            NSString *row = [NSString stringWithFormat:@"%@ STAGE %@\n", [self timestamp], stage];
            fputs(row.UTF8String, _fp);
            fflush(_fp);
            fsync(fileno(_fp));
        }
    });
    [self emitStageConsole:stage];
    void (^handler)(NSString *) = self.uiStageHandler;
    if (handler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(stage);
        });
    }
}

@end

void dt_run_log(const char *fmt, ...)
{
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *fmtStr = [NSString stringWithUTF8String:fmt];
    NSString *line = fmtStr ? [[NSString alloc] initWithFormat:fmtStr arguments:ap] : @"";
    va_end(ap);
    if (line.length) {
        [[DTRunLogger shared] log:line];
    }
}

void dt_run_log_stage(const char *stage)
{
    if (!stage) return;
    [[DTRunLogger shared] logStage:[NSString stringWithUTF8String:stage]];
}
