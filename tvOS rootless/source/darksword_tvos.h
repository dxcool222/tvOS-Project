#pragma once

#include <stdbool.h>

/// Dopamine DarkSword kernel exploit — fills gPrimitives + kernel slide.
int darksword_exploit_init(const char *flavor);
int darksword_exploit_deinit(void);
bool darksword_is_active(void);

/// Set after successful PCB corruption; process restart required before KFD fallback.
bool darksword_kernel_state_may_be_poisoned(void);
