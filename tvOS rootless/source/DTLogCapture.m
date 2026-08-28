#import "DTLogCapture.h"
#import "DTRunLogger.h"
#import <unistd.h>
#import <fcntl.h>
#import <dispatch/dispatch.h>

@implementation DTLogCapture {
    int _stdoutPipe[2];
    int _stderrPipe[2];
    int _savedStdout;
    int _savedStderr;
    dispatch_source_t _stdoutSource;
    dispatch_source_t _stderrSource;
    dispatch_queue_t _readQueue;
    void (^_handler)(NSString *);
    BOOL _running;
}

+ (instancetype)sharedCapture
{
    static DTLogCapture *c;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ c = [DTLogCapture new]; });
    return c;
}

- (void)emitLine:(NSData *)data
{
    if (!data.length) return;
    NSString *chunk = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!chunk.length) return;
    NSArray *parts = [chunk componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *line in parts) {
        if (!line.length) continue;
        // Skip our own syslog + stage lines (NSLog/printf feedback during capture).
        if ([line containsString:@"[dopamin-tvOS-kfd]"]) continue;
        if ([line containsString:@"STAGE "]) continue;
        [[DTRunLogger shared] log:line];
    }
}

- (void)startReadSource:(int)fd intoSource:(dispatch_source_t *)outSource
{
    int readFd = fd;
    dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)readFd, 0, _readQueue);
    dispatch_source_set_event_handler(src, ^{
        char buf[4096];
        ssize_t n = read(readFd, buf, sizeof(buf));
        if (n > 0) {
            NSData *d = [NSData dataWithBytes:buf length:(NSUInteger)n];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self emitLine:d];
            });
        }
    });
    dispatch_source_set_cancel_handler(src, ^{
        close(readFd);
    });
    dispatch_resume(src);
    *outSource = src;
}

- (void)startWithHandler:(void (^)(NSString *))handler
{
    if (_running) return;
    _handler = [handler copy];
    _readQueue = dispatch_queue_create("com.dopamin.tvos.kfd.logcapture", DISPATCH_QUEUE_SERIAL);

    pipe(_stdoutPipe);
    pipe(_stderrPipe);
    _savedStdout = dup(STDOUT_FILENO);
    _savedStderr = dup(STDERR_FILENO);
    dup2(_stdoutPipe[1], STDOUT_FILENO);
    dup2(_stderrPipe[1], STDERR_FILENO);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    close(_stdoutPipe[1]);
    close(_stderrPipe[1]);

    dispatch_source_t outSrc = NULL;
    dispatch_source_t errSrc = NULL;
    [self startReadSource:_stdoutPipe[0] intoSource:&outSrc];
    [self startReadSource:_stderrPipe[0] intoSource:&errSrc];
    _stdoutSource = outSrc;
    _stderrSource = errSrc;
    _running = YES;
}

- (void)stop
{
    if (!_running) return;
    fflush(stdout);
    fflush(stderr);
    if (_savedStdout >= 0) {
        dup2(_savedStdout, STDOUT_FILENO);
        close(_savedStdout);
        _savedStdout = -1;
    }
    if (_savedStderr >= 0) {
        dup2(_savedStderr, STDERR_FILENO);
        close(_savedStderr);
        _savedStderr = -1;
    }
    if (_stdoutSource) {
        dispatch_source_cancel(_stdoutSource);
        _stdoutSource = nil;
    }
    if (_stderrSource) {
        dispatch_source_cancel(_stderrSource);
        _stderrSource = nil;
    }
    _running = NO;
    _handler = nil;
}

@end
