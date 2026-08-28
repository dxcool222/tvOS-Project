#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102696 B4-FILE gated dynamic diagnostic (diagnostic only).
int dt_build696_run_b4file_diagnostic(void (^ _Nullable log)(NSString *line),
                                      NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
