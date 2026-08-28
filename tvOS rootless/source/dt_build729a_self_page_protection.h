#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102729A — self-process mach_vm_protect control (disposable page only).
int dt_build729a_run_self_page_protection_control(void (^log)(NSString *line), NSString **verdictOut);

#ifdef __cplusplus
}
#endif
