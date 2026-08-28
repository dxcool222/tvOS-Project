#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool proc_cached;
    bool task_cached;
    bool map_cached;
    bool pmap_cached;
    uint64_t proc;
    uint64_t task;
    uint64_t map;
    uint64_t pmap;
} dt_pmap_cache_snapshot_t;

void dt_pmap_cache_snapshot(dt_pmap_cache_snapshot_t *out);

#ifdef __cplusplus
}
#endif
