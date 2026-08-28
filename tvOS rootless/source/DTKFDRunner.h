#import <Foundation/Foundation.h>

@class DTKFDConfig;

NS_ASSUME_NONNULL_BEGIN

@interface DTKFDRunner : NSObject
+ (BOOL)isActive;
- (void)runWithConfig:(DTKFDConfig *)config
                  log:(nullable void (^)(NSString *line))log
           completion:(void (^)(BOOL ok, NSString *summary))completion;
- (void)run583ProbeAWithConfig:(DTKFDConfig *)config
                           log:(nullable void (^)(NSString *line))log
                    completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run653DirectHelperTelemetryWithConfig:(DTKFDConfig *)config
                                        log:(nullable void (^)(NSString *line))log
                                 completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run674ABDifferentialWithConfig:(DTKFDConfig *)config
                                   log:(nullable void (^)(NSString *line))log
                            completion:(void (^)(BOOL ok, NSString *summary))completion;
- (void)run681Phase6_1LaunchdInjectWithConfig:(DTKFDConfig *)config
                                        log:(nullable void (^)(NSString *line))log
                                 completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run688aWall2ExperimentWithConfig:(DTKFDConfig *)config
                                     log:(nullable void (^)(NSString *line))log
                              completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run691BaselineValidatorWithConfig:(DTKFDConfig *)config
                                    log:(nullable void (^)(NSString *line))log
                             completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run692ContradictionDiagnosticWithConfig:(DTKFDConfig *)config
                                          log:(nullable void (^)(NSString *line))log
                                   completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run694Wall2RestoreProbeWithConfig:(DTKFDConfig *)config
                                    log:(nullable void (^)(NSString *line))log
                             completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run699PlatformHookClosureWithConfig:(DTKFDConfig *)config
                                      log:(nullable void (^)(NSString *line))log
                               completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)run697B4FileDiagnosticWithConfig:(DTKFDConfig *)config
                                   log:(nullable void (^)(NSString *line))log
                            completion:(void (^)(BOOL ok, NSString *verdict))completion;
- (void)closeWithLog:(nullable void (^)(NSString *line))log
          completion:(void (^)(void))completion;
@end

NS_ASSUME_NONNULL_END
