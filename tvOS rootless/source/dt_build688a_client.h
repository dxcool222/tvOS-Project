#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102688A — strict Wall 2-only device experiment (no opainject, no stash).
int dt_build688a_run_wall2(void (^ _Nullable log)(NSString *line),
                           NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
