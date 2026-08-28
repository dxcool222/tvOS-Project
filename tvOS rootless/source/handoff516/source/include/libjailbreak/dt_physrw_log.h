#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/// Optional log sink from libjailbreak (app registers dt_run_log bridge before pte init).
typedef void (*dt_physrw_log_fn)(const char *line);
/// Short labels routed to dt_run_log_stage (Console: STAGE … via os_log subsystem com.dopamin.tvos.kfd).
typedef void (*dt_physrw_stage_fn)(const char *stage);

void dt_physrw_set_log_fn(dt_physrw_log_fn fn);
void dt_physrw_set_stage_fn(dt_physrw_stage_fn fn);

/// Log to stage sink + [phys] file line (safe from libjailbreak).
void dt_physrw_log_stage(const char *msg);

/// Log pmap+0/+8, sw_asid candidates, and computed sw_asid page PA (requires kread active).
void dt_physrw_log_pmap_debug(void);

#ifdef __cplusplus
}
#endif
