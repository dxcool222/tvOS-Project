#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102727R — read-only Mach-O parse/contract rejection telemetry. No acceptance changes.
int dt_build727r_run_readonly_launchd_contract_telemetry(void (^log)(NSString *line),
    NSString **verdictOut);

#ifdef __cplusplus
}
#endif
