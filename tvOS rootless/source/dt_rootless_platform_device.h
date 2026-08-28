#pragma once

#include "dt_rootless_orch.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Bind REAL_DEVICE platform and run shared dt_rootless_orch_bringup. */
int dt_rootless_device_bringup(dt_rootless_orch_result_t *out);

/** Dry-run bind (no KFD). Used by HOST_SIM gate-order comparison. */
void dt_rootless_device_bind_dry(dt_rootless_plat_t *plat, void *ctx);

#ifdef __cplusplus
}
#endif
