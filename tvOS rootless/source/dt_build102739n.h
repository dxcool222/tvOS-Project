#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, DTBuild102739NDispatch) {
    DTBuild102739NDispatchRunA = 0,
    DTBuild102739NDispatchRunB = 1,
    DTBuild102739NDispatchStop = 2,
};

DTBuild102739NDispatch dt_build102739n_classify_before_chain(
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut);

DTBuild102739NDispatch dt_build102739n_current_dispatch(void);

/** Last BUILD102739N_PERSISTED_DIAGNOSTIC_RESULT from classify (nil if none). */
NSString * _Nullable dt_build102739n_last_persisted_diagnostic_result(void);

/** Force dispatch after rootless R6 overrides a non-terminal legacy Stop. */
void dt_build102739n_force_dispatch(DTBuild102739NDispatch dispatch);

/**
 * Positive project-ownership probe for old BUILD102739N persisted state.
 * YES only when known ledger schema/protocol parses under the project control
 * path (helper content mismatch still counts as owned). Unknown junk = NO.
 */
BOOL dt_build102739n_probe_project_owned_legacy(
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable detailOut);

int dt_build102739n_run_persistent_control_fixture_proof(
    void (^ _Nullable log)(NSString *line),
    BOOL wall2Restored,
    BOOL runMFirst,
    NSString * _Nullable * _Nullable verdictOut);
