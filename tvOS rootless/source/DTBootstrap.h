#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DTBootstrap : NSObject

+ (BOOL)remountWritable;
+ (void)setRemountWritable:(BOOL)writable;

/// G1: probe markers under /var/jb only.
+ (void)runG1ProbeWithCompletion:(void (^)(BOOL ok, NSString *detail))completion;

/// G2: copy embedded bootstrap_g2/ tree into /var/jb (bash + dash + Tier-1 dylibs). No exec.
+ (void)runG2ExtractWithCompletion:(void (^)(BOOL ok, NSString *detail))completion;

/// G3: walk /var/jb symlinks (lstat only); rewrite absolute targets outside jb → /var/jb+path.
+ (void)runG3SymlinkAuditWithCompletion:(void (^)(BOOL ok, NSString *detail))completion;

/// G4: smoke bundled Tools/ldid (ldid -h) as root after remount gate. Hard abort on failure.
+ (void)runG4LdidSmokeWithCompletion:(void (^)(BOOL ok, NSString *detail))completion;

/// G5: build102.5 Plan B kcall consume probe (dash only if handles > 0).
+ (void)runG5SignSmokeWithCompletion:(void (^)(BOOL ok, NSString *detail))completion;

/// Rollback: delete /var/jb only (G1 probes + G2 tree). Stock paths untouched.
+ (void)runRollbackWithCompletion:(void (^)(BOOL ok, NSString *detail))completion;

@end

NS_ASSUME_NONNULL_END
