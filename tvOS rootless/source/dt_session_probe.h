#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "dt_pmap_probe.h"

/// Monotonic exploit-cycle counter (incremented at exploit_init enter).
unsigned dt_session_cycle(void);

/// Full snapshot tagged for Console grep: `[probe] …`
void dt_session_probe_snapshot(const char *tag);

/// Lifecycle hooks — each emits STAGE + [probe] lines.
void dt_session_probe_exploit_init_enter(void);
void dt_session_probe_exploit_init_exit(int kopen_result);
void dt_session_probe_exploit_deinit_enter(void);
void dt_session_probe_exploit_deinit_exit(int deinit_result);

void dt_session_probe_physrw_init_enter(void);
void dt_session_probe_physrw_init_exit(int result);

void dt_session_probe_build26_enter(void);
void dt_session_probe_build26_exit(int result, unsigned pre_count, unsigned post_count);

/// Route phys-rw stage strings (alloc_pt, expand) to logger + STAGE.
void dt_session_probe_phys_stage(const char *stage);

#ifdef __cplusplus
}
#endif
