#pragma once

#include <stdbool.h>

/// AppleTV6,2 / tvOS 16.5 — force socket→proto→protosw slide path (never iOS17+ pcbinfo/zone).
#define DT_DARKSWORD_SLIDE_PATH_TVOS_PRE17 1

void dt_darksword_log_platform_banner(void);
bool dt_darksword_target_is_appletv62_20l563(void);
