#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DTRootHelperClient : NSObject

/// Bundled `.app/bootstraphelper` path.
+ (NSString *)helperBundledPath;

/// Legacy alias for helperBundledPath.
+ (NSString *)helperPath;

+ (BOOL)helperInstalled;

/// `/var/jb/usr/bin/dt_helper` (production helper after G5 install).
+ (NSString *)jbHelperPath;

/// jb helper exists, executable, and trustcached.
+ (BOOL)jbHelperReady;

+ (int)runCommand:(NSString *)command args:(NSArray<NSString *> *)args error:(NSError **)error;

/// Runs `/var/jb/usr/bin/dt_helper` via persona-root spawn; captures combined stdout/stderr.
+ (int)runCommand:(NSString *)command
             args:(NSArray<NSString *> *)args
        stdoutOut:(NSString * _Nullable * _Nullable)stdoutOut
       exitStatus:(int *)exitStatus
            error:(NSError **)error;

/// Spawn helper at path with `ping` args; plain or persona per usePersona.
+ (int)runPingAtPath:(NSString *)path
          usePersona:(BOOL)usePersona
           stdoutOut:(NSString * _Nullable * _Nullable)stdoutOut
          exitStatus:(int *)exitStatus
               error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
