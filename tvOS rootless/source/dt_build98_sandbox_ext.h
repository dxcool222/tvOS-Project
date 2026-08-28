#pragma once

#import <Foundation/Foundation.h>

/// Build 98 — diagnostic only (ChatGPT + §39.8): branch-pin logging for 55106C consume.
/// Same triple EXT as build97; NO functional changes. Aborts on first consume fail.
/// Returns 0 on success; negative errno on failure.
int dt_build98_issue_consume_jbroot_extensions(void (^ _Nullable log)(NSString *line));
