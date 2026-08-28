#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Build 102583 — Probe A launchd helper diagnostic only (no Probe C).
int dt_build102583_run(void (^ _Nullable log)(NSString *line),
                       NSString ** _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
