#include "dt_rootless_r6_decide.h"

#include <stdbool.h>

dt_rootless_r6_decision_c_t dt_rootless_r6_decide_c(int varjb,
                                                    bool n_project_owned_legacy,
                                                    bool n_stopped)
{
    dt_rootless_r6_decision_c_t d;
    d.state = DT_R6_STATE_ABSENT;
    d.path = DT_R6_PATH_FRESH;
    d.kfd_would_open = true;
    d.override_legacy_n_stop = false;

    /* FOREIGN always fail-closed — never overridden by legacy N ownership. */
    if (varjb == DT_VARJB_FOREIGN) {
        d.state = DT_R6_STATE_FOREIGN;
        d.path = DT_R6_PATH_BLOCK;
        d.kfd_would_open = false;
        return d;
    }

    if (varjb == DT_VARJB_COMMITTED_VALID) {
        d.state = DT_R6_STATE_VALID;
        d.path = DT_R6_PATH_REUSE;
        d.kfd_would_open = true;
        if (n_stopped)
            d.override_legacy_n_stop = true;
        return d;
    }

    if (varjb == DT_VARJB_VALID_ROOTLESS_SYMLINK) {
        d.state = DT_R6_STATE_INCOMPLETE;
        d.path = DT_R6_PATH_RECOVERY;
        d.kfd_would_open = true;
        if (n_stopped)
            d.override_legacy_n_stop = true;
        return d;
    }

    if (varjb == DT_VARJB_ROOTLESS_INCOMPLETE) {
        d.state = DT_R6_STATE_INCOMPLETE;
        d.path = DT_R6_PATH_RECOVERY;
        d.kfd_would_open = true;
        if (n_stopped)
            d.override_legacy_n_stop = true;
        return d;
    }

    if (varjb == DT_VARJB_STALE_PROJECT_SYMLINK
        || varjb == DT_VARJB_STALE_PROJECT_DIRECTORY) {
        d.state = DT_R6_STATE_STALE_PROJECT;
        d.path = DT_R6_PATH_RECOVERY;
        d.kfd_would_open = true;
        if (n_stopped)
            d.override_legacy_n_stop = true;
        return d;
    }

    if (varjb == DT_VARJB_LEGACY_ROOTFUL) {
        d.state = DT_R6_STATE_LEGACY_ROOTFUL;
        d.path = DT_R6_PATH_FRESH;
        d.kfd_would_open = true;
        d.override_legacy_n_stop = true;
        return d;
    }

    if (varjb == DT_VARJB_ABSENT) {
        if (n_project_owned_legacy) {
            d.state = DT_R6_STATE_LEGACY_ROOTFUL;
            d.path = DT_R6_PATH_FRESH;
            d.kfd_would_open = true;
            d.override_legacy_n_stop = true;
            return d;
        }
        d.state = DT_R6_STATE_ABSENT;
        d.path = DT_R6_PATH_FRESH;
        d.kfd_would_open = true;
        if (n_stopped) {
            d.state = DT_R6_STATE_FOREIGN;
            d.path = DT_R6_PATH_BLOCK;
            d.kfd_would_open = false;
            d.override_legacy_n_stop = false;
            return d;
        }
        return d;
    }

    d.state = DT_R6_STATE_FOREIGN;
    d.path = DT_R6_PATH_BLOCK;
    d.kfd_would_open = false;
    return d;
}
