#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*dt_pte_kwrite64_fn)(uint64_t kaddr, uint64_t val);

void dt_pte_kwrite_register(dt_pte_kwrite64_fn fn);
void dt_pte_kwrite_unregister(void);
bool dt_pte_kwrite_ready(void);

/// Zero-slot PTE commits: registered backend (perf sem kwrite on build 22), else dup kwrite64.
int dt_pte_kwrite64(uint64_t kaddr, uint64_t val);

/// Build 22: register sem/perf kwrite64 from active kfd as PTE backend (no IOSurface).
void dt_pte_kwrite_register_perf(void);
void dt_pte_kwrite_unregister_perf(void);
bool dt_pte_kwrite_perf_is_ready(void);

#ifdef __cplusplus
}
#endif
