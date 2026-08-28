#pragma once

#include <stdint.h>

struct kfd;

/// misaka do_dynamic_patchfinder equivalent when no plist/baked: XPF perfkrw+struct on kernelcache file.
/// Fills dynamic_system_info + kfund cache. Returns 0 on success.
int dt_dynamic_patchfinder_from_kernelfile(uint64_t kbase);

/// Live-kread path placeholder: KASLR already done, apply baked/dynamic defaults if file XPF unavailable.
int dt_dynamic_patchfinder_after_kaslr(struct kfd *kfd, uint64_t kbase);
