#pragma once

#import <Foundation/Foundation.h>
#import "dt_rootless_state.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef NS_ENUM(NSInteger, DTRootlessR6Path) {
    DTRootlessR6PathFresh = 0,
    DTRootlessR6PathReuse = 1,
    DTRootlessR6PathRecovery = 2,
    DTRootlessR6PathBlock = 3,
};

typedef NS_ENUM(NSInteger, DTRootlessR6State) {
    DTRootlessR6StateAbsent = 0,
    DTRootlessR6StateValid,
    DTRootlessR6StateLegacyRootful,
    DTRootlessR6StateIncomplete,
    DTRootlessR6StateForeign,
    DTRootlessR6StateStaleProject,
};

typedef struct {
    DTRootlessR6State state;
    DTRootlessR6Path path;
    BOOL kfdWouldOpen;
    BOOL overrideLegacyNStop;
} DTRootlessR6Decision;

NSString * _Nonnull dt_rootless_r6_state_name(DTRootlessR6State state);
NSString * _Nonnull dt_rootless_r6_path_name(DTRootlessR6Path path);

/**
 * Pure decision table used by production dispatch and host fixtures.
 *
 * nProjectOwnedLegacy: positive BUILD102739N project ownership even when
 * helper SHA/CDHash/ledger identity mismatch (does NOT include unknown junk).
 * nStopVerdict: classifier returned Stop with this verdict string (may be nil).
 */
DTRootlessR6Decision dt_rootless_r6_decide(DTRootlessVarJbState varjb,
                                           BOOL nProjectOwnedLegacy,
                                           NSString * _Nullable nStopVerdict);

/**
 * Authoritative pre-KFD Bring-Up gate for DT_ROOTLESS_R4 builds.
 * Logs ROOTLESS_R6_* markers. Returns 0 to continue (KFD may open), -1 to BLOCK.
 * On continue after legacy N Stop, forces N dispatch to RunA when appropriate.
 */
int dt_rootless_r6_pre_kfd_dispatch(void (^ _Nullable log)(NSString *line),
                                    NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
