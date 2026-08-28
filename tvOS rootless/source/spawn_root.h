#import <Foundation/Foundation.h>
#import <spawn.h>

#import "dt_holdspawn_cmd_fd.h"

#define DT_POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1

extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t * _Nonnull, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t * _Nonnull, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t * _Nonnull, uid_t);

/// Persona 99 → uid/gid 0 spawn. Returns 0 on successful wait; spawn errno otherwise.
int dt_spawn_root(NSString *binaryPath, NSArray<NSString *> *args, int *exitStatusOut, NSError **errorOut);

/// Same as dt_spawn_root but captures child stdout+stderr (max ~8 KiB).
int dt_spawn_root_capture(NSString *binaryPath,
                          NSArray<NSString *> *args,
                          int *exitStatusOut,
                          NSString * _Nullable * _Nullable stdoutOut,
                          NSError **errorOut);

/// Plain posix_spawn (no persona attrs); captures child stdout+stderr (max ~8 KiB).
int dt_spawn_plain_capture(NSString *binaryPath,
                           NSArray<NSString *> *args,
                           int *exitStatusOut,
                           NSString * _Nullable * _Nullable stdoutOut,
                           NSError **errorOut);

/// Plain posix_spawn capture with raw wait status for exact child-exit telemetry.
int dt_spawn_plain_capture_status(NSString *binaryPath,
                                  NSArray<NSString *> *args,
                                  int *exitStatusOut,
                                  int *waitStatusOut,
                                  NSString * _Nullable * _Nullable stdoutOut,
                                  NSError **errorOut);

/// Persona root spawn without waiting; reads initial stdout (max ~4 KiB, ~2s).
/// Returns 0 when spawn succeeds; child pid in *pidOut.
int dt_spawn_root_start(NSString *binaryPath,
                        NSArray<NSString *> *args,
                        pid_t *pidOut,
                        NSString * _Nullable * _Nullable initialStdoutOut,
                        NSError **errorOut);

/// Plain posix_spawn (no persona) without waiting; reads initial stdout (max ~4 KiB, ~2s).
int dt_spawn_plain_start(NSString *binaryPath,
                         NSArray<NSString *> *args,
                         pid_t *pidOut,
                         NSString * _Nullable * _Nullable initialStdoutOut,
                         NSError **errorOut);

/// Spawn holdSpawn broker: stdout/stderr captured on *stdoutRdOut (stay open), cmd pipe write on *cmdWrOut.
/// Child reads spawn commands on kDT633CmdFd (63). Returns 0 when broker cmd-fd preflight is seen.
int dt_spawn_hold_probe_start(NSString *binaryPath,
                              pid_t *pidOut,
                              int *stdoutRdOut,
                              int *cmdWrOut,
                              NSString * _Nullable * _Nullable initialStdoutOut,
                              NSError **errorOut);
