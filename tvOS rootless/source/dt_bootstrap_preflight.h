#import <Foundation/Foundation.h>

/// BUILD102739K: inspect the pinned CF1900 rootful payload destinations without
/// creating, modifying, removing, or loading any bootstrap object.
int dt_build102739k_run_rootful_bootstrap_preflight(
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut);

/// BUILD102739L: resolve the K inventory against the pinned OTA and package
/// policy without creating, modifying, removing, or loading bootstrap state.
int dt_build102739l_run_rootful_bootstrap_policy_preflight(
    void (^ _Nullable log)(NSString *line),
    NSString * _Nullable * _Nullable verdictOut);
