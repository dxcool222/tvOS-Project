#pragma once

#import <Foundation/Foundation.h>

/// Build 97 — IDA §36.4: issue+consume read + read-write + executable on /private/var/jb/
/// Requires slot0 profile non-NULL (§36.2 Option A: privesc preserves slot0).
/// Returns 0 on success; negative errno on failure.
int dt_build97_issue_consume_jbroot_extensions(void (^ _Nullable log)(NSString *line));
