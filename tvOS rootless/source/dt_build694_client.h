#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102694 Wall 2 isolated apply→consume→restore→compare→sync probe.
/// No opainject, AMFI, or userspace reboot. Returns 0 on KCALL694_WALL2_RESTORE_SYNC_PASS.
int dt_build694_run_wall2_restore_probe(void (^ _Nullable log)(NSString *line),
                                        NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
