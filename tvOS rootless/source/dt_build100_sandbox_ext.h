#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Build 100 §26: read EXT issue → ctx proof log → consume → abort (no sign/trust/spawn).
/// Returns 0 when proof logging completed (consume fail is expected), negative on hard error.
int dt_build100_issue_consume_read_proof(void (^ _Nullable log)(NSString *line));

#ifdef __cplusplus
}
#endif
