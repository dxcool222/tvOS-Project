#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Loaded kfund_offsets.plist values (misaka/J format).
typedef struct {
    bool valid;
    char kern_version[512];
    uint64_t cdevsw;
    uint64_t gPhysBase;
    uint64_t gPhysSize;
    uint64_t gVirtBase;
    uint64_t perfmon_dev_open;
    uint64_t perfmon_devices;
    uint64_t ptov_table;
    uint64_t vn_kqfilter;
    uint64_t proc_object_size;
} dt_kfund_offsets_t;

/// Load ~/Documents/kfund_offsets.plist once; verify kern_version. Returns 0 on success, -1 if missing/mismatch.
int dt_import_kfd_offsets(void);

/// True after first dt_import_kfd_offsets call in this process (success or failure).
bool dt_kfund_import_was_attempted(void);

/// Cached import result (does not reload).
const dt_kfund_offsets_t *dt_kfund_offsets_cached(void);

/// Apply cached kfund plist phys symbols into gSystemInfo (does not touch runtime slide/base/primitives).
void dt_apply_saved_phys_offsets_to_system_info(void);

/// Post-exploit system-info completion: saved plist symbols + reconcile base from staticBase+slide.
void dt_apply_post_exploit_system_info(void);

/// Legacy name — calls dt_apply_saved_phys_offsets_to_system_info() only.
void dt_apply_kfd_offsets_to_system_info(void);

/// Populate kfund cache from dynamic_system_info (misaka absolute VA format).
void dt_kfund_cache_from_dynamic_info(void);

/// Internal: fill g_kfund from absolute symbol values (used by kfd_tvos.m).
void dt_kfund_load_cache(uint64_t cdevsw, uint64_t gPhysBase, uint64_t gPhysSize,
    uint64_t gVirtBase, uint64_t perfmon_dev_open, uint64_t perfmon_devices,
    uint64_t ptov_table, uint64_t vn_kqfilter, uint64_t proc_object_size);

/// Returns true if ~/Documents/kfund_offsets.plist exists.
bool dt_kfund_plist_on_disk(void);

/// Save ~/Documents/kfund_offsets.plist (misaka/J format). Returns 0 on success.
int dt_save_kfd_offsets(void);

#ifdef __cplusplus
}
#endif
