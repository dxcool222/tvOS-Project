#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef NS_ENUM(NSInteger, DTRootlessVarJbState) {
    DTRootlessVarJbAbsent = 0,
    DTRootlessVarJbValidRootlessSymlink,
    DTRootlessVarJbStaleProjectSymlink,
    DTRootlessVarJbStaleProjectDirectory,
    DTRootlessVarJbLegacyRootful,
    DTRootlessVarJbRootlessIncomplete,
    DTRootlessVarJbForeign,
    DTRootlessVarJbCommittedValid,
};

NSString *dt_rootless_expected_jbroot(void);
NSString *dt_rootless_identity_path(void);
NSString *dt_rootless_var_jb_path(void);

DTRootlessVarJbState dt_rootless_classify_var_jb(NSString **detailOut);
BOOL dt_rootless_ensure_symlink(void (^log)(NSString *), NSString **errOut);
BOOL dt_rootless_write_incomplete_marker(void);
BOOL dt_rootless_commit_identity(void (^log)(NSString *), NSDictionary *extra, NSString **errOut);
BOOL dt_rootless_verify_committed(void (^log)(NSString *), NSString **errOut);
NSString *dt_rootless_state_name(DTRootlessVarJbState state);

#ifdef __cplusplus
}
#endif
