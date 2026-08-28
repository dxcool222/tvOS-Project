#import "DTKFDRunner.h"
#import "DTKFDConfig.h"
#import "DTBootstrap.h"
#import "dt_session_probe.h"
#import "DTRunLogger.h"
#import "dt_do_fun.h"
#import "dt_kfund_import.h"
#import "dt_baked_offsets.h"
#import "dt_physrw.h"
#import "dt_exploit_lifecycle.h"
#import "dt_kernel_exploit.h"
#import "dt_build583_client.h"
#import "dt_build653_client.h"
#import "dt_build674_client.h"
#import "dt_build681_client.h"
#import "dt_build688a_client.h"
#import "dt_build690_client.h"
#import "dt_build691_client.h"
#import "dt_build692_client.h"
#import "dt_build694_client.h"
#import "dt_build697_client.h"
#import "dt_build698_client.h"
#import "dt_build699_client.h"
#import "kfd_tvos.h"

#import "info.h"
#import "primitives.h"
#import <kernel.h>
#import <sys/sysctl.h>

extern int exploit_deinit(void);

static void DTLog(void (^log)(NSString *), NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log) log(line);
}

static void DTStage(NSString *stage)
{
    [[DTRunLogger shared] logStage:stage];
}

@implementation DTKFDRunner

+ (BOOL)isActive
{
    return dt_kernel_exploit_is_active();
}

- (void)closeWithLog:(void (^)(NSString *line))log completion:(void (^)(void))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        dt_session_probe_snapshot("close_kfd_begin");
        if (dt_kernel_exploit_is_active()) {
            DTStage(@"closing kernel exploit");
            dt_kernel_exploit_deinit();
            DTLog(log, @"[*] kernel exploit closed");
            DTStage(@"kernel exploit closed");
        } else {
            DTLog(log, @"[*] close: no active kernel exploit");
        }
        dt_session_probe_snapshot("close_kfd_end");
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion();
            });
        }
    });
}

- (void)runWithConfig:(DTKFDConfig *)config log:(void (^)(NSString *line))log completion:(void (^)(BOOL ok, NSString *summary))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *summary = @"failed";
        DTKFDConfig *cfg = config ?: [DTKFDConfig misakaDefaults];

        @try {
            [DTBootstrap setRemountWritable:NO];
            char machine[64] = {0};
            char osversion[64] = {0};
            size_t len = sizeof(machine);
            sysctlbyname("hw.machine", machine, &len, NULL, 0);
            len = sizeof(osversion);
            sysctlbyname("kern.osversion", osversion, &len, NULL, 0);
            DTStage(@"starting");
            DTLog(log, [NSString stringWithFormat:@"device: %s build: %s", machine, osversion]);

            if (DTApplyBakedOffsetsForCurrentDevice()) {
                DTLog(log, @"offsets: wh1te4ever baked table (AppleTV6,2 / 20L563)");
                DTStage(@"offsets baked");
            } else if (dt_import_kfd_offsets() == 0) {
                DTLog(log, @"offsets: will use kfund_offsets.plist");
                DTStage(@"offsets plist");
            } else {
                DTLog(log, @"offsets: kopen will patchfind + auto-save (J fallback)");
                DTStage(@"offsets patchfind");
            }

            DTLog(log, [NSString stringWithFormat:@"config: %@", cfg.summaryString]);
            if (dt_exploit_lifecycle_run(cfg, log) != 0) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(NO, summary);
                });
                return;
            }

            dt_apply_post_exploit_system_info();

            DTStage(@"do_fun");
            DTLog(log, @"[*] kopen OK — running do_fun (misaka/J post-exploit)");
            if (!dt_do_fun(log)) {
                DTStage(@"do_fun failed");
                dt_kernel_exploit_deinit();
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(NO, summary);
                });
                return;
            }
            DTStage(@"do_fun OK");
            if (dt_build_rootful_remount_ok()) {
                [DTBootstrap setRemountWritable:YES];
            } else {
                DTLog(log, @"[*] build70 remountWritable=0 — rootful remount not available on this boot");
                [[DTRunLogger shared] logStage:@"build70 remountWritable gate closed"];
            }
            dt_session_probe_snapshot("do_fun_OK_before_kfd_active");

            uint64_t slide = dt_kernel_exploit_slide();
            uint32_t magic = (uint32_t)kread64(dt_kernel_exploit_base());
            success = YES;
            summary = [NSString stringWithFormat:@"slide 0x%llx · magic 0x%x", slide, magic];
            DTLog(log, @"[*] kernel exploit left open (tap Close to release)");
            DTStage(@"kernel exploit active");
        } @catch (NSException *e) {
            DTStage(@"exception");
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            [DTBootstrap setRemountWritable:NO];
            if (dt_kernel_exploit_is_active())
                dt_kernel_exploit_deinit();
        }

        if (!success)
            [DTBootstrap setRemountWritable:NO];

        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, summary);
        });
    });
}

- (void)run583ProbeAWithConfig:(DTKFDConfig *)config
                           log:(void (^)(NSString *line))log
                    completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL583_DIAGNOSTIC_FAILED";

        @try {
            DTStage(@"build102583 probe A begin");
            DTLog(log, @"[*] Build102583 — Probe A launchd→helper diagnostic only");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL583_PRE_KFD_OK=0";
                DTLog(log, @"[!] 583 blocked: kfd not active — run Exploit first");
                goto finish;
            }

            if (dt_build_physrw_handoff_only(log) != 0) {
                verdict = @"KCALL583_PRE_KFD_OK=0";
                DTLog(log, @"[!] physrw handoff failed");
                goto finish;
            }

            if (getuid() != 0) {
                uint64_t proc = proc_find(getpid());
                if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
                    DTLog(log, @"[+] build102583 root esc OK uid=0");
                }
                if (proc)
                    proc_rele(proc);
            }

            NSString *runVerdict = nil;
            if (dt_build102583_run(log, &runVerdict) != 0) {
                verdict = runVerdict ?: @"KCALL583_DIAGNOSTIC_FAILED";
                goto finish;
            }

            verdict = runVerdict ?: @"KCALL583_PROBE_A_PASS";
            success = [verdict isEqualToString:@"KCALL583_PROBE_A_PASS"];
            DTLog(log, @"[*] kfd left open after 583 Probe A diagnostic");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL583_DIAGNOSTIC_FAILED";
        }

finish:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run653DirectHelperTelemetryWithConfig:(DTKFDConfig *)config
                                        log:(void (^)(NSString *line))log
                                 completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL653_RESULT=FAIL";

        @try {
            DTStage(@"build672 tool runner begin");
            DTLog(log, @"[*] Build672 — direct spawn (653) + read worker (661) + jbroot tool runner (672)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL653_PREFLIGHT_KFD_OK=0";
                DTLog(log, @"[!] 672 blocked: kfd not active — run Exploit first");
                goto finish653;
            }

            if (dt_build_physrw_handoff_only(log) != 0) {
                verdict = @"KCALL653_PREFLIGHT_KFD_OK=0";
                DTLog(log, @"[!] physrw handoff failed");
                goto finish653;
            }

            if (getuid() != 0) {
                uint64_t proc = proc_find(getpid());
                if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
                    DTLog(log, @"[+] build672 root esc OK uid=0");
                }
                if (proc)
                    proc_rele(proc);
            }

            NSString *verdict653 = nil;
            NSString *verdict661 = nil;
            NSString *verdict672 = nil;
            if (dt_build653_run_full(log, &verdict653, &verdict661, &verdict672) != 0) {
                verdict = verdict672.length ? verdict672 :
                    (verdict661.length ? verdict661 : (verdict653 ?: @"KCALL672_RESULT=FAIL"));
                goto finish653;
            }

            verdict = [NSString stringWithFormat:@"%@ %@ %@",
                verdict653 ?: @"KCALL653_RESULT=OK",
                verdict661 ?: @"KCALL661_RESULT=OK",
                verdict672 ?: @"KCALL672_RESULT=OK"];
            success = [verdict653 isEqualToString:@"KCALL653_RESULT=OK"] &&
                      [verdict661 isEqualToString:@"KCALL661_RESULT=OK"] &&
                      [verdict672 isEqualToString:@"KCALL672_RESULT=OK"];
            DTLog(log, @"[*] kfd left open after 672 tool runner");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL653_RESULT=FAIL";
        }

finish653:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run674ABDifferentialWithConfig:(DTKFDConfig *)config
                                   log:(void (^)(NSString *line))log
                            completion:(void (^)(BOOL ok, NSString *summary))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *summary = @"BUILD674_FAIL";

        @try {
            DTStage(@"build674 A/B/C differential begin");
            DTLog(log, @"[*] Build674 — same-session binary identity A/B/C differential");

            if (!dt_kernel_exploit_is_active()) {
                summary = @"KCALL674_PREFLIGHT_KFD_OK=0";
                DTLog(log, @"[!] 674 blocked: kfd not active");
                goto finish674;
            }

            if (dt_build_physrw_handoff_only(log) != 0) {
                summary = @"KCALL674_PREFLIGHT_KFD_OK=0";
                goto finish674;
            }

            if (getuid() != 0) {
                uint64_t proc = proc_find(getpid());
                if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
                    DTLog(log, @"[+] build674 root esc OK uid=0");
                }
                if (proc)
                    proc_rele(proc);
            }

            NSString *out = nil;
            success = (dt_build674_run_ab_differential(log, &out) == 0);
            summary = out ?: summary;
            DTLog(log, @"[*] kfd left open after 674 A/B/C differential");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            summary = @"KCALL674_RESULT=FAIL";
        }

finish674:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, summary);
        });
    });
}

- (void)run681Phase6_1LaunchdInjectWithConfig:(DTKFDConfig *)config
                                        log:(void (^)(NSString *line))log
                                 completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL681_FAIL";

        @try {
            DTStage(@"build681 Phase 6.1 launchd inject begin");
            DTLog(log, @"[*] Build681 — Phase 6.1 opainject+boomerang+kcall consume (IDA gate order)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL681_KFD_INACTIVE";
                DTLog(log, @"[!] 681 blocked: kfd not active — run exploit first");
                goto finish681;
            }

            if (dt_build_physrw_handoff_only(log) != 0) {
                verdict = @"KCALL681_PHYSRW_FAIL";
                goto finish681;
            }

            if (getuid() != 0) {
                uint64_t proc = proc_find(getpid());
                if (proc && dt_build_phys_root_esc(proc, log) == 0 && getuid() == 0) {
                    DTLog(log, @"[+] build681 root esc OK uid=0");
                }
                if (proc)
                    proc_rele(proc);
            }

            if (getuid() != 0) {
                verdict = @"KCALL681_ROOT_FAIL";
                goto finish681;
            }

            int priv_r = -1;
            uint64_t self_proc = proc_find(getpid());
            if (self_proc) {
                priv_r = dt_build97_privesc_preserve_slot0(self_proc, log);
                proc_rele(self_proc);
            }
            if (priv_r != 0) {
                verdict = @"KCALL681_BUILD97_FAIL";
                goto finish681;
            }

            NSString *out = nil;
            success = (dt_build681_run_phase6_1(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 681 Phase 6.1");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL681_EXCEPTION";
        }

finish681:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run688aWall2ExperimentWithConfig:(DTKFDConfig *)config
                                     log:(void (^)(NSString *line))log
                              completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL689_FAIL";

        @try {
            DTStage(@"build689 Wall 2 experiment begin");
            DTLog(log, @"[*] Build689 — tri-state policy snapshot fix (no opainject)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL689_KFD_INACTIVE";
                DTLog(log, @"[!] 689 blocked: kfd not active — run exploit first");
                goto finish688a;
            }

            NSString *out = nil;
            success = (dt_build688a_run_wall2(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 689 Wall 2 experiment");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL689_EXCEPTION";
        }

finish688a:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run691BaselineValidatorWithConfig:(DTKFDConfig *)config
                                    log:(void (^)(NSString *line))log
                             completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL691_FAIL";

        @try {
            DTStage(@"build691 baseline validator begin");
            DTLog(log, @"[*] Build691 — corrected read-only policy baseline validator");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL691_KFD_INACTIVE";
                DTLog(log, @"[!] 691 blocked: kfd not active — run exploit first");
                goto finish691;
            }

            NSString *out = nil;
            success = (dt_build691_run_baseline(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 691 baseline validator");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL691_EXCEPTION";
        }

finish691:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run692ContradictionDiagnosticWithConfig:(DTKFDConfig *)config
                                          log:(void (^)(NSString *line))log
                                   completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL692_FAIL";

        @try {
            DTStage(@"build692 contradiction diagnostic begin");
            DTLog(log, @"[*] Build692 — read-only 532C68 probe (no mutation)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL692_KFD_INACTIVE";
                DTLog(log, @"[!] 692 blocked: kfd not active — run exploit first");
                goto finish692;
            }

            NSString *out = nil;
            success = (dt_build692_run_diagnostic(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 692 diagnostic");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL692_EXCEPTION";
        }

finish692:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run694Wall2RestoreProbeWithConfig:(DTKFDConfig *)config
                                    log:(void (^)(NSString *line))log
                             completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"KCALL694_FAIL";

        @try {
            DTStage(@"build694 Wall 2 restore probe begin");
            DTLog(log, @"[*] Build694 — apply/consume/restore/compare/sync (no opainject)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL694_KFD_INACTIVE";
                DTLog(log, @"[!] 694 blocked: kfd not active — run exploit first");
                goto finish694;
            }

            NSString *out = nil;
            success = (dt_build694_run_wall2_restore_probe(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 694 Wall 2 probe");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL694_EXCEPTION";
        }

finish694:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run699PlatformHookClosureWithConfig:(DTKFDConfig *)config
                                      log:(void (^)(NSString *line))log
                               completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"BUILD102699_DIAGNOSTIC_FAIL";

        @try {
            DTStage(@"build699 platform hook closure begin");
            DTLog(log, @"[*] Build699 — native platform signing + gated launchd Wall1");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL699_KFD_INACTIVE";
                DTLog(log, @"[!] 699 blocked: kfd not active — run exploit first");
                goto finish699;
            }

            NSString *out = nil;
            success = (dt_build699_run_platform_hook_closure(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 699 platform hook closure");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL699_EXCEPTION";
        }

finish699:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run698LaunchdWall1DiagnosticWithConfig:(DTKFDConfig *)config
                                        log:(void (^)(NSString *line))log
                                 completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"BUILD102698_DIAGNOSTIC_FAIL";

        @try {
            DTStage(@"build698 launchd Wall1 diagnostic begin");
            DTLog(log, @"[*] Build698 — launchd-context Wall 1 correlation (one opainject)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL698_KFD_INACTIVE";
                DTLog(log, @"[!] 698 blocked: kfd not active — run exploit first");
                goto finish698;
            }

            NSString *out = nil;
            success = (dt_build698_run_launchd_wall1_diagnostic(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 698 launchd Wall1 diagnostic");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL698_EXCEPTION";
        }

finish698:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run697B4FileDiagnosticWithConfig:(DTKFDConfig *)config
                                   log:(void (^)(NSString *line))log
                            completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    (void)config;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL success = NO;
        NSString *verdict = @"BUILD102697_DIAGNOSTIC_FAIL";

        @try {
            DTStage(@"build697 B4-FILE diagnostic begin");
            DTLog(log, @"[*] Build697 — D1-corrected B4-FILE diagnostic (no bypass)");

            if (!dt_kernel_exploit_is_active()) {
                verdict = @"KCALL697_KFD_INACTIVE";
                DTLog(log, @"[!] 697 blocked: kfd not active — run exploit first");
                goto finish697;
            }

            NSString *out = nil;
            success = (dt_build697_run_b4file_diagnostic(log, &out) == 0);
            verdict = out ?: verdict;
            DTLog(log, @"[*] kfd left open after 697 B4-FILE diagnostic");
            DTStage(@"kfd active");
        } @catch (NSException *e) {
            DTLog(log, [NSString stringWithFormat:@"EXCEPTION: %@", e]);
            verdict = @"KCALL697_EXCEPTION";
        }

finish697:
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(success, verdict);
        });
    });
}

- (void)run696B4FileDiagnosticWithConfig:(DTKFDConfig *)config
                                   log:(void (^)(NSString *line))log
                            completion:(void (^)(BOOL ok, NSString *verdict))completion
{
    [self run697B4FileDiagnosticWithConfig:config log:log completion:completion];
}

@end
