#import <Foundation/Foundation.h>

/// Run log at ~/Documents/kfd_run.log (on-disk) plus unified logging for Console.app.
/// Every logStage: emits os_log + NSLog as "[dopamin-tvOS-kfd] STAGE <label>" (subsystem com.dopamin.tvos.kfd).
@interface DTRunLogger : NSObject

+ (instancetype)shared;
+ (NSString *)logFilePath;

/// App launch: open log file, write banner (does not truncate prior runs).
- (void)open;

/// New exploit attempt separator + flush.
- (void)beginExploitRun;

/// Create/reset the root-owned cross-process trace before PID 1 injection and
/// keep relaying appended launchdhook/systemhook/jbserver rows to Console.app.
- (BOOL)prepareRuntimeTraceForInjection:(NSError * _Nullable * _Nullable)error;
- (void)relayRuntimeTraceNow;

- (void)log:(NSString *)line;
- (void)logStage:(NSString *)stage;

/// Receives short stage labels for on-screen status (file/syslog keep full detail).
@property (nonatomic, copy, nullable) void (^uiStageHandler)(NSString *stage);

@end

#ifdef __cplusplus
extern "C" {
#endif

void dt_run_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void dt_run_log_stage(const char *stage);

#ifdef __cplusplus
}
#endif
