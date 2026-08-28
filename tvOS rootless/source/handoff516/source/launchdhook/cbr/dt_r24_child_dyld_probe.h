#pragma once

#include <sys/types.h>

/*
 * Proof-only diagnostic: asynchronously classify which dyld Mach-O is mapped
 * in a newly spawned child.  Never blocks the launchd spawn hook path.
 */
void dt_r24_schedule_child_dyld_uuid_probe(pid_t child_pid, const char *spawn_path,
                                           char *const envp[]);
