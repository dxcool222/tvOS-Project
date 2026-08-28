#import "dt_rootless_r6.h"
#import "dt_rootless_r6_decide.h"
#import "dt_build102739n.h"
#import "DTRunLogger.h"

#import <Foundation/Foundation.h>

/* Packaged R5/R6 expected accounting (self-check before KFD). */
static const NSInteger kDTRootlessR6ExpectedPayloadEntries = 4053;
static const NSInteger kDTRootlessR6ExpectedTrustEntries = 397;

NSString *dt_rootless_r6_state_name(DTRootlessR6State state)
{
    switch (state) {
        case DTRootlessR6StateAbsent: return @"ABSENT";
        case DTRootlessR6StateValid: return @"VALID";
        case DTRootlessR6StateLegacyRootful: return @"LEGACY_ROOTFUL";
        case DTRootlessR6StateIncomplete: return @"INCOMPLETE";
        case DTRootlessR6StateForeign: return @"FOREIGN";
        case DTRootlessR6StateStaleProject: return @"STALE_PROJECT";
    }
    return @"UNKNOWN";
}

NSString *dt_rootless_r6_path_name(DTRootlessR6Path path)
{
    switch (path) {
        case DTRootlessR6PathFresh: return @"FRESH";
        case DTRootlessR6PathReuse: return @"REUSE";
        case DTRootlessR6PathRecovery: return @"RECOVERY";
        case DTRootlessR6PathBlock: return @"BLOCK";
    }
    return @"UNKNOWN";
}

static void dt_r6_emit(void (^log)(NSString *), NSString *line)
{
    [[DTRunLogger shared] log:line];
    [[DTRunLogger shared] logStage:line];
    if (log) log(line);
}

DTRootlessR6Decision dt_rootless_r6_decide(DTRootlessVarJbState varjb,
                                           BOOL nProjectOwnedLegacy,
                                           NSString *nStopVerdict)
{
    /* Same table compiled into HOST_SIM (dt_rootless_r6_decide.c). */
    dt_rootless_r6_decision_c_t c =
        dt_rootless_r6_decide_c((int)varjb,
                                nProjectOwnedLegacy ? true : false,
                                nStopVerdict.length ? true : false);
    DTRootlessR6Decision d;
    d.state = (DTRootlessR6State)c.state;
    d.path = (DTRootlessR6Path)c.path;
    d.kfdWouldOpen = c.kfd_would_open ? YES : NO;
    d.overrideLegacyNStop = c.override_legacy_n_stop ? YES : NO;
    return d;
}

static NSInteger dt_r6_count_manifest_rows(NSString *name)
{
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:nil];
    if (!path.length)
        path = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:name];
    NSString *text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!text.length) return -1;
    NSInteger rows = 0;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if (!line.length) continue;
        if ([line hasPrefix:@"PATH\t"] || [line hasPrefix:@"RELATIVE_PATH\t"]) continue;
        rows++;
    }
    return rows;
}

int dt_rootless_r6_pre_kfd_dispatch(void (^log)(NSString *), NSString **verdictOut)
{
    dt_r6_emit(log, @"ROOTLESS_R6_ENTRY=YES");
    dt_r6_emit(log, @"ROOTLESS_R6_BUILD_VARIANT=R6");
    dt_r6_emit(log, @"ROOTLESS_R6_CLASSIFICATION_BEGIN");

    /* Authoritative packaged identity — must not remain R5-labeled. */
    {
        NSString *idPath = [[NSBundle mainBundle] pathForResource:@"ROOTLESS_VARIANT_IDENTITY" ofType:@"txt"];
        if (!idPath.length)
            idPath = [[[NSBundle mainBundle] bundlePath]
                      stringByAppendingPathComponent:@"ROOTLESS_VARIANT_IDENTITY.txt"];
        NSString *idText = [NSString stringWithContentsOfFile:idPath encoding:NSUTF8StringEncoding error:nil];
        if (![idText containsString:@"ROOTLESS_VARIANT=R6"]
                || ![idText containsString:@"COMPILED_ROOTLESS_MARKER=ROOTLESS_R6_BEGIN"]) {
            NSString *v = @"ROOTLESS_R6_IDENTITY_FILE_MISMATCH";
            dt_r6_emit(log, v);
            if (verdictOut) *verdictOut = v;
            dt_r6_emit(log, @"ROOTLESS_R6_PATH=BLOCK");
            dt_r6_emit(log, @"ROOTLESS_R6_KFD_WOULD_OPEN=NO");
            return -1;
        }
        dt_r6_emit(log, @"ROOTLESS_R6_IDENTITY_FILE_OK=YES");
    }

    NSInteger payloadCount = dt_r6_count_manifest_rows(@"ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv");
    NSInteger trustCount = dt_r6_count_manifest_rows(@"ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv");
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_PAYLOAD_ENTRY_COUNT=%ld", (long)payloadCount]);
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_TRUST_ENTRY_COUNT=%ld", (long)trustCount]);

    if (payloadCount != kDTRootlessR6ExpectedPayloadEntries
            || trustCount != kDTRootlessR6ExpectedTrustEntries) {
        NSString *v = [NSString stringWithFormat:
            @"ROOTLESS_R6_VARIANT_SELF_CHECK_FAIL payload=%ld trust=%ld expected=%ld/%ld",
            (long)payloadCount, (long)trustCount,
            (long)kDTRootlessR6ExpectedPayloadEntries,
            (long)kDTRootlessR6ExpectedTrustEntries];
        dt_r6_emit(log, v);
        if (verdictOut) *verdictOut = v;
        dt_r6_emit(log, @"ROOTLESS_R6_PATH=BLOCK");
        dt_r6_emit(log, @"ROOTLESS_R6_KFD_WOULD_OPEN=NO");
        return -1;
    }

    NSString *varDetail = nil;
    DTRootlessVarJbState varjb = dt_rootless_classify_var_jb(&varDetail);
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_VAR_JB=%@ detail=%@",
                     dt_rootless_state_name(varjb), varDetail ?: @""]);

    /* Legacy N inspection — may Stop; R6 decides whether that is terminal. */
    NSString *nVerdict = nil;
    DTBuild102739NDispatch nDisp =
        dt_build102739n_classify_before_chain(log, &nVerdict);
    BOOL nStopped = (nDisp == DTBuild102739NDispatchStop) ? YES : NO;
    BOOL nOwned = dt_build102739n_probe_project_owned_legacy(log, nil);
#if defined(DT_ROOTLESS_R24)
    NSString *persisted = dt_build102739n_last_persisted_diagnostic_result();
    BOOL helperIdChanged =
        [persisted isEqualToString:@"PERSISTED_HELPER_CONTENT_IDENTITY_CHANGED"]
        || [persisted isEqualToString:@"PERSISTED_HELPER_PROVENANCE_CHANGED"]
        || [persisted isEqualToString:@"PERSISTED_HELPER_BASIC_METADATA_CHANGED"]
        || [nVerdict containsString:@"PERSISTED_MANIFEST_OR_HELPER"];
    if (varjb == DTRootlessVarJbCommittedValid && helperIdChanged) {
        varjb = DTRootlessVarJbRootlessIncomplete;
        dt_r6_emit(log, @"ROOTLESS_R24_FORCE_RECOVERY_HELPER_IDENTITY=YES");
    }
#endif
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_N_DISPATCH=%ld verdict=%@",
                     (long)nDisp, nVerdict ?: @"nil"]);
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_N_PROJECT_OWNED_LEGACY=%@",
                     nOwned ? @"YES" : @"NO"]);

    NSString *stopVerdict = nStopped ? (nVerdict ?: @"N_STOP") : nil;
    DTRootlessR6Decision dec = dt_rootless_r6_decide(varjb, nOwned, stopVerdict);

    /* When N did not Stop, still map state for logs; keep N dispatch. */
    if (!nStopped && dec.path != DTRootlessR6PathBlock) {
        /* Prefer rootless path mapping; do not force override. */
        dec.overrideLegacyNStop = NO;
    }

    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_STATE=%@",
                     dt_rootless_r6_state_name(dec.state)]);
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_PATH=%@",
                     dt_rootless_r6_path_name(dec.path)]);
    dt_r6_emit(log, [NSString stringWithFormat:@"ROOTLESS_R6_KFD_WOULD_OPEN=%@",
                     dec.kfdWouldOpen ? @"YES" : @"NO"]);

    if (dec.path == DTRootlessR6PathBlock || !dec.kfdWouldOpen) {
        NSString *v = [NSString stringWithFormat:@"ROOTLESS_R6_BLOCK state=%@ n=%@",
                       dt_rootless_r6_state_name(dec.state), nVerdict ?: @"nil"];
        if (verdictOut) *verdictOut = v;
        return -1;
    }

    if (nStopped && dec.overrideLegacyNStop) {
        dt_r6_emit(log, [NSString stringWithFormat:
            @"ROOTLESS_R6_LEGACY_N_OVERRIDDEN verdict=%@ -> RunA (non-terminal)",
            nVerdict ?: @"nil"]);
        dt_build102739n_force_dispatch(DTBuild102739NDispatchRunA);
    }

    if (verdictOut) {
        *verdictOut = [NSString stringWithFormat:@"%@:%@",
                       dt_rootless_r6_state_name(dec.state),
                       dt_rootless_r6_path_name(dec.path)];
    }
    return 0;
}
