#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Build 102672 — direct spawn (653) + read worker (661) + jbroot tool runner (672).
int dt_build653_run(void (^ _Nullable log)(NSString *line),
                    NSString ** _Nullable verdictOut);

/// Full run; 661/672 verdicts written when non-NULL.
int dt_build653_run_full(void (^ _Nullable log)(NSString *line),
                         NSString ** _Nullable verdict653Out,
                         NSString ** _Nullable verdict661Out,
                         NSString ** _Nullable verdict672Out);

/// Remove staged helper + tool (no LaunchDaemon artifacts).
BOOL dt_build653_cleanup_staged(NSString ** _Nullable detailOut);

#ifdef __cplusplus
}
#endif
