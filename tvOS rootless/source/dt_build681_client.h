#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BUILD102681 Phase 6.1 — Dopamine injectLaunchdHook + tvOS 53D540/kcall55106C pre-inject.
/// Requires active KFD, root, phys R/W, jbroot basebin staged, trustcache.
int dt_build681_run_phase6_1(void (^ _Nullable log)(NSString *line),
                              NSString * _Nullable * _Nullable verdictOut);

/// Reusable handoff staging (BUILD102698 / proven 681 lane).
int dt681_stage_handoff_basebin(void (^ _Nullable log)(NSString *line));
/// BUILD102707 — stage basebin; when preserve_launchdhook=YES skip launchdhook516.dylib copy.
int dt681_stage_handoff_basebin_ex(void (^ _Nullable log)(NSString *line), BOOL preserve_launchdhook);
int dt681_upload_handoff_trustcache(void (^ _Nullable log)(NSString *line));
/// BUILD102707 — when hook_trustcache_from_staged=YES use jbroot staged hook path for hook tc only.
int dt681_upload_handoff_trustcache_ex(void (^ _Nullable log)(NSString *line), BOOL hook_trustcache_from_staged);
/// 681 lane jbctl+opainject only (BUILD102701+ runtime platform diag — no pre-sign hook tc).
int dt681_upload_jbctl_opainject_trustcache(void (^ _Nullable log)(NSString *line));
int dt681_spawn_opainject_launchd(const char *dylibPath,
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable captureOut);
/// BUILD102739A — reacquire TFP1 after Wall 2 restoration and read only the
/// exported launchdhook counter.  This does not inject or execute remote code.
int dt681_observe_launchd_counter(const char *hookPath,
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable captureOut);
/// BUILD102739B — reuse the proven read-only observer transport to read the
/// exported entry/return telemetry snapshot after Wall 2 restoration.
int dt681_observe_launchd_return_telemetry(const char *hookPath,
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable captureOut);
/// BUILD102739C — read the guarded return/xOut output-contract counters after
/// Wall 2 restoration without injecting, writing, or calling into PID 1.
int dt681_observe_launchd_output_telemetry(const char *hookPath,
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable captureOut);

#ifdef __cplusplus
}
#endif
