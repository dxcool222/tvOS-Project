#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/// DarkSword stage markers (DS00…, DARKSWORD_DO_FUN_PASS, DARKSWORD_R24_A_TO_Z_PASS).
/// Full R24 A→Z completion is emitted only at ROOTLESS commit (dt_rootless_run_commit_last).
void dt_ds_stage(const char *marker);

#ifdef __cplusplus
}
#endif
