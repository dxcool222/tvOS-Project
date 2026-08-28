#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Build 99 §42.9: DIAG only — full proc/ucred/label/slot chain pre-consume + same EXT triple as build98.
/// No functional EXT/HMAC/type/op129 changes.
int dt_build99_issue_consume_jbroot_extensions(void (^ _Nullable log)(NSString *line));

#ifdef __cplusplus
}
#endif
