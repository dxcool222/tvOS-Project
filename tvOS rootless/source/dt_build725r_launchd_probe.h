#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102725R — read-only launchd base / GOT / protection telemetry. No writes.
int dt_build725r_run_readonly_launchd_probe(void (^log)(NSString *line), NSString **verdictOut);

#ifdef __cplusplus
}
#endif
