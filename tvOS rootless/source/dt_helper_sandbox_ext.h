#pragma once

/// Build 102.4 — helper-side sandbox extension triple on /private/var/jb/
/// IDA: kernel class strings @ 583409A read, 58340BA rw, 588E4FF executable
/// IDA: consume MIG 6 → 55106C; 5510E8 CBZ if 532C68 profile NULL
/// Returns 0 if all three consume handles > 0; negative on failure.
int dt_helper_issue_consume_jbroot_extensions(void);
