#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102674 — same-session A/B/C binary identity differential (one spawn each).
int dt_build674_run_ab_differential(void (^ _Nullable log)(NSString *line),
                                    NSString ** _Nullable summaryOut);

#ifdef __cplusplus
}
#endif
