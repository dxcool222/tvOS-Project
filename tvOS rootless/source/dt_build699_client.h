#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// BUILD102699 — platform hook signing identity closure + gated launchd Wall1 test.
int dt_build699_run_platform_hook_closure(void (^ _Nullable log)(NSString *line),
                                            NSString * _Nullable * _Nullable verdictOut);

NS_ASSUME_NONNULL_END
