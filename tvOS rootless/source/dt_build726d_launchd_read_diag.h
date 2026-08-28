#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102726D — read-only launchd userspace read-path diagnostic. No writes.
int dt_build726d_run_readonly_launchd_read_diag(void (^log)(NSString *line), NSString **verdictOut);

#ifdef __cplusplus
}
#endif
