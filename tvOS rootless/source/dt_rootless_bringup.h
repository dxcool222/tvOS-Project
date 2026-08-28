#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * FRESH rootless filesystem/ABI adaptation stage.
 * Caller must already have: KFD open + Wall2 done.
 * Does NOT open/close KFD. Does NOT replace opainject — caller invokes opainject after.
 */
int dt_rootless_run_fresh_fs_stage(void (^log)(NSString *), NSString **verdictOut);

/**
 * REUSE validation + trust reload preparation (no KFD open/close).
 */
int dt_rootless_run_reuse_fs_stage(void (^log)(NSString *), NSString **verdictOut);

/** After opainject + SSH smoke: commit LAST. */
int dt_rootless_run_commit_last(void (^log)(NSString *), NSDictionary *extra, NSString **verdictOut);

/** Bundled payload directory name inside the .app */
FOUNDATION_EXPORT NSString *const kDTRootlessPayloadDirName;
FOUNDATION_EXPORT NSString *const kDTRootlessTrustManifestName;

#ifdef __cplusplus
}
#endif
