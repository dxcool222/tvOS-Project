#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102691 — corrected read-only baseline validator (direct fmsg kread + RO zone).
/// No 53D540, 55106C, restore, opainject, or AMFI. Returns 0 on KCALL691_BASELINE_VALIDATOR_PASS.
int dt_build691_run_baseline(void (^ _Nullable log)(NSString *line),
                             NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
