#pragma once

#include <stdint.h>

/// Apple LC_BUILD_VERSION minos/sdk encoding: (major << 16) | (minor << 8) | patch
#define DT_PACK_BUILD_VERSION(major, minor, patch) \
    (((uint32_t)(major) << 16) | ((uint32_t)(minor) << 8) | ((uint32_t)(patch)))

static inline uint32_t dt_pack_build_version(uint32_t major, uint32_t minor, uint32_t patch)
{
    return DT_PACK_BUILD_VERSION(major, minor, patch);
}
