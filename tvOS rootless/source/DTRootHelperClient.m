#import "DTRootHelperClient.h"
#import "dt_physrw.h"
#import "spawn_root.h"

@implementation DTRootHelperClient

+ (NSString *)helperBundledPath
{
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURL *url = [[NSBundle mainBundle] URLForAuxiliaryExecutable:@"bootstraphelper"];
        if (url.path.length)
            path = url.path;
        else
            path = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"bootstraphelper"];
    });
    return path;
}

+ (NSString *)helperPath
{
    return [self helperBundledPath];
}

+ (NSString *)jbHelperPath
{
    return @"/var/jb/usr/bin/dt_helper";
}

+ (BOOL)helperInstalled
{
    return [[NSFileManager defaultManager] isExecutableFileAtPath:[self helperBundledPath]];
}

+ (BOOL)jbHelperReady
{
    NSString *path = [self jbHelperPath];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:path])
        return NO;

    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0)
        return NO;
    return dt_cdhash_trustcached(hash);
}

+ (int)runCommand:(NSString *)command args:(NSArray<NSString *> *)args error:(NSError **)error
{
    int exitStatus = -1;
    int r = [self runCommand:command args:args stdoutOut:NULL exitStatus:&exitStatus error:error];
    if (r != 0)
        return r;
    return exitStatus;
}

+ (int)runCommand:(NSString *)command
             args:(NSArray<NSString *> *)args
        stdoutOut:(NSString **)stdoutOut
       exitStatus:(int *)exitStatus
            error:(NSError **)error
{
    NSString *helper = [self jbHelperPath];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:helper]) {
        if (error) {
            *error = [NSError errorWithDomain:@"dopamin-tvOS-kfd" code:1
                                     userInfo:@{NSLocalizedDescriptionKey :
                                                    @"dt_helper missing or not executable — run G5 preflight install"}];
        }
        return -1;
    }

    NSMutableArray<NSString *> *fullArgs = [NSMutableArray arrayWithObject:command];
    if (args.count)
        [fullArgs addObjectsFromArray:args];

    int st = -1;
    NSString *out = nil;
    int r = dt_spawn_root_capture(helper, fullArgs, &st, stdoutOut ? &out : NULL, error);
    if (stdoutOut)
        *stdoutOut = out;
    if (exitStatus)
        *exitStatus = st;
    return r;
}

+ (int)runPingAtPath:(NSString *)path
          usePersona:(BOOL)usePersona
           stdoutOut:(NSString **)stdoutOut
          exitStatus:(int *)exitStatus
               error:(NSError **)error
{
    if (path.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"dopamin-tvOS-kfd" code:1
                                     userInfo:@{NSLocalizedDescriptionKey : @"helper path empty"}];
        }
        return -1;
    }

    int st = -1;
    NSString *out = nil;
    int r;
    if (usePersona)
        r = dt_spawn_root_capture(path, @[@"ping"], &st, stdoutOut ? &out : NULL, error);
    else
        r = dt_spawn_plain_capture(path, @[@"ping"], &st, stdoutOut ? &out : NULL, error);

    if (stdoutOut)
        *stdoutOut = out;
    if (exitStatus)
        *exitStatus = st;
    return r;
}

@end
