#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102690 — read-only launchd policy baseline validator (audit §P).
/// No 53D540, 55106C, restore, opainject, or AMFI. Returns 0 on KCALL690_BASELINE_VALIDATOR_PASS.
int dt_build690_run_baseline(void (^ _Nullable log)(NSString *line),
                             NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
