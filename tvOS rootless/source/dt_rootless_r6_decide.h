#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Numeric values MUST match DTRootlessVarJbState / DTRootlessR6State / DTRootlessR6Path
 * in dt_rootless_state.h and dt_rootless_r6.h. Single decision table used by
 * production dt_rootless_r6.m and HOST_SIM.
 */
enum {
    DT_VARJB_ABSENT = 0,
    DT_VARJB_VALID_ROOTLESS_SYMLINK = 1,
    DT_VARJB_STALE_PROJECT_SYMLINK = 2,
    DT_VARJB_STALE_PROJECT_DIRECTORY = 3,
    DT_VARJB_LEGACY_ROOTFUL = 4,
    DT_VARJB_ROOTLESS_INCOMPLETE = 5,
    DT_VARJB_FOREIGN = 6,
    DT_VARJB_COMMITTED_VALID = 7,
};

enum {
    DT_R6_STATE_ABSENT = 0,
    DT_R6_STATE_VALID = 1,
    DT_R6_STATE_LEGACY_ROOTFUL = 2,
    DT_R6_STATE_INCOMPLETE = 3,
    DT_R6_STATE_FOREIGN = 4,
    DT_R6_STATE_STALE_PROJECT = 5,
};

enum {
    DT_R6_PATH_FRESH = 0,
    DT_R6_PATH_REUSE = 1,
    DT_R6_PATH_RECOVERY = 2,
    DT_R6_PATH_BLOCK = 3,
};

typedef struct {
    int state;
    int path;
    bool kfd_would_open;
    bool override_legacy_n_stop;
} dt_rootless_r6_decision_c_t;

/* Production decision table (source of truth for R6 routing). */
dt_rootless_r6_decision_c_t dt_rootless_r6_decide_c(int varjb,
                                                    bool n_project_owned_legacy,
                                                    bool n_stopped);

#ifdef __cplusplus
}
#endif
