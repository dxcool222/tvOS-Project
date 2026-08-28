#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102698 — launchd-context Wall 1 correlation diagnostic (one opainject attempt).
int dt_build698_run_launchd_wall1_diagnostic(void (^ _Nullable log)(NSString *line),
                                              NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
