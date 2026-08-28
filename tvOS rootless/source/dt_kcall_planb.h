#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Plan B build102.5.2 — kcall calibration + kernel-scratch return fix (Fix A).
/// Stops after proc_pid probe; no 55106C / consume / dash until calibration OK.
///
/// IDA j105a (MCP 2026-06-19):
///   _proc_pid @ 0xFFFFFFF0075E4F88 — LDR W0,[X1,#0x60]; NULL→-1; kernproc→0
///   kcall_return @ 0xFFFFFFF005DE1E90 — STR X0,[X19]; RET
///   Fix A: X19 = kernelStack+0x7000 (Fugu14 scratch), readback kread64(scratch)
///
/// verdictOut values include:
///   KCALL_UNAVAILABLE, KCALL_CALIBRATION_OK, KCALL_CALIBRATION_FAIL,
///   KCALL_PROC_KPTR_FAIL, KCALL_TARGET_VA_FAIL, KCALL_RETURN_CAPTURE_FAIL,
///   KCALL_PROC_PID_ARG_FAIL, KCALL_THREAD_OFFSETS_FAIL,
///   KCALL_SAFE_PROBE_OK, KCALL_SAFE_PROBE_FAIL.
/// dashAllowedOut always NO on 102.5.2 (calibration-only build).
int dt_build1025_planb_diagnostic(void (^ _Nullable log)(NSString *line),
                                  NSString * _Nullable helperPath,
                                  NSString * _Nullable * _Nullable verdictOut,
                                  BOOL * _Nullable dashAllowedOut);

/// BUILD102681 Phase 6.1 steps 2–5 on launchd (IDA gate order):
/// kcall init + M1–M6 calibration → proc_find(1) → kcall 53D540 → issue → kcall 55106C ×2.
/// Phase 6.0 prerequisite: calibration must pass before launchd kernel kcalls (678 §Phase 6.0).
/// Returns 0 when read+exec consume handles are both > 0.
int dt681_launchd_sandbox_unblock(const char *dylibPath,
                                  void (^ _Nullable log)(NSString *line),
                                  NSString * _Nullable * _Nullable verdictOut);

/// IDA j105a: task+0x2E0/2E8/2F0 itk_registered[0..2]; kcall mach_ports_register @ 1FFF20.
/// Replaces jbctl mach_ports_lookup/register on launchd (tvOS AMFI/system-task-ports split).
int dt681_kcall_stash_boomerang_port(mach_port_t boomerangPort,
                                     void (^ _Nullable log)(NSString *line),
                                     NSString * _Nullable * _Nullable verdictOut);

/// BUILD102689 Wall 2 snapshot fix: tri-state unix/mach/mig baseline→53D540→consume×2→restore→compare→observe.
/// No opainject, no stash, no AMFI. Returns 0 on KCALL689_WALL2_PASS.
int dt688a_run_wall2_experiment(const char *consume_path,
                                  void (^ _Nullable log)(NSString *line),
                                  NSString * _Nullable * _Nullable verdictOut);

/// BUILD102690 read-only baseline policy validator (audit §O/P). No restore or mutation.
/// Returns 0 on KCALL690_BASELINE_VALIDATOR_PASS.
int dt690_run_baseline_validator(void (^ _Nullable log)(NSString *line),
                                 NSString * _Nullable * _Nullable verdictOut);

/// BUILD102691 corrected read-only baseline (direct fmsg kread + RO zone validation).
/// Never kcalls proc_get_filter_message_flag. Returns 0 on KCALL691_BASELINE_VALIDATOR_PASS.
int dt691_run_baseline_validator(void (^ _Nullable log)(NSString *line),
                                 NSString * _Nullable * _Nullable verdictOut);

/// BUILD102692 read-only 532C68 contradiction probe + _proc_ucred pointer-return calibration.
/// No 53D540/55106C/532A80/filter_msg/5329AC. Returns 0 on KCALL692_DIAG_PASS.
int dt692_run_contradiction_diagnostic(void (^ _Nullable log)(NSString *line),
                                       NSString * _Nullable * _Nullable verdictOut);

/// BUILD102694 Wall 2 isolated apply→consume→restore→compare→sync survival probe.
/// Returns 0 on KCALL694_WALL2_RESTORE_SYNC_PASS.
int dt694_run_wall2_restore_sync_probe(void (^ _Nullable log)(NSString *line),
                                       NSString * _Nullable * _Nullable verdictOut);

/// BUILD102696 B4-FILE gated dynamic diagnostic (vnode/blob/zone8/LV count). Diagnostic only.
/// Returns 0 on BUILD102696_DIAGNOSTIC_PASS.
int dt696_run_b4file_diagnostic(void (^ _Nullable log)(NSString *line),
                                  NSString * _Nullable * _Nullable verdictOut);

/// BUILD102697 B4-FILE D1-corrected diagnostic continuation (diagnostic only).
int dt697_run_b4file_diagnostic(void (^ _Nullable log)(NSString *line),
                                  NSString * _Nullable * _Nullable verdictOut);

/// BUILD102698 launchd-context Wall 1 correlation diagnostic (diagnostic only).
int dt698_run_launchd_wall1_diagnostic(void (^ _Nullable log)(NSString *line),
                                        NSString * _Nullable * _Nullable verdictOut);
/// BUILD102707 — when preserve_signed_hook=YES skip hook restage; use staged hook tc identity.
int dt698_run_launchd_wall1_diagnostic_ex(void (^ _Nullable log)(NSString *line),
                                           NSString * _Nullable * _Nullable verdictOut,
                                           BOOL preserve_signed_hook);

/// BUILD102699 native platform-signing closure + gated 698 launchd correlation.
int dt699_run_platform_hook_closure(void (^ _Nullable log)(NSString *line),
                                     NSString * _Nullable * _Nullable verdictOut);

#ifdef __cplusplus
}
#endif
