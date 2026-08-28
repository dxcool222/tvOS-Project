#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102697 B4-FILE D1-corrected diagnostic continuation (diagnostic only).
int dt_build697_run_b4file_diagnostic(void (^ _Nullable log)(NSString *line),
                                      NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
