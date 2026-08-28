#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102692 — read-only 532C68 contradiction probe (no Wall 2 mutation).
int dt_build692_run_diagnostic(void (^ _Nullable log)(NSString *line),
                               NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
