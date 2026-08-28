#ifndef DT_KCALL_ARM64_TVOS_H
#define DT_KCALL_ARM64_TVOS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Populated after arm64_kcall_init() succeeds.
typedef struct {
    uint64_t kernel_stack_kva;
    uint64_t scratch_kva;          /// independent 0x4000 scratch page (Strategy B)
    uint64_t stack_page_base;      /// first 0x4000 stack backing page
    uint64_t thread_kptr;
    uint64_t act_context_kptr;
    uint64_t aligned_state_uptr;   /// userspace page backing bootstrap handoff
} dt_tvos_kcall_debug_t;

void dt_tvos_kcall_get_debug(dt_tvos_kcall_debug_t *out);

#ifdef __cplusplus
}
#endif

#endif
