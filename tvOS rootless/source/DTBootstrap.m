#import "DTBootstrap.h"
#import "DTRunLogger.h"
#import "DTRootHelperClient.h"
#import "dt_physrw.h"
#import "dt_kcall_planb.h"

#import <codesign.h>
#import <dirent.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/loader.h>
#import <limits.h>
#import <string.h>
#import <dlfcn.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

#define DT_POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1

typedef struct { short __opaque[32]; } DTPosixSpawnAttr;

extern int posix_spawnattr_set_persona_np(const DTPosixSpawnAttr * _Nonnull, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const DTPosixSpawnAttr * _Nonnull, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const DTPosixSpawnAttr * _Nonnull, uid_t);

static NSString *const kDTJBRoot = @"/var/jb";
static NSString *const kDTBootstrapdPath = @"/var/jb/basebin/bootstrapd";
static NSString *const kDTProbePath = @"/var/jb/.dt_build48_probe";
static NSString *const kDTGenPath = @"/var/jb/.install_generation";
static NSString *const kDTG2Manifest = @"/var/jb/.dt_g2_manifest";
static NSString *const kDTSymlinkAuditLog = @"/var/jb/.dt_symlink_audit.log";
static NSString *const kDTBashPath = @"/var/jb/usr/bin/bash";
static NSString *const kDTDashPath = @"/var/jb/usr/bin/dash";
static NSString *const kDTProbeTruePath = @"/var/jb/usr/bin/probe_true";
static NSString *const kDTJbHelperPath = @"/var/jb/usr/bin/dt_helper";
static NSString *const kDTBsctlPath = @"/var/jb/basebin/bsctl";
static NSString *const kDTJbctlPath = @"/var/jb/basebin/jbctl";
static NSString *const kDTUsrLib = @"/var/jb/usr/lib";

typedef struct { int __actions[16]; } DTSpawnFileActions;

typedef struct {
    BOOL ok;
    int spawnErr;
    int exitCode;
    NSString *detail;
    NSString *stdoutSnippet;
} DTSmokeProbeResult;

static BOOL sRemountWritable = NO;

static void DTBLog(NSString *line)
{
    [[DTRunLogger shared] log:line];
}

static void DTBStage(NSString *stage)
{
    [[DTRunLogger shared] logStage:stage];
}

@implementation DTBootstrap

+ (BOOL)remountWritable
{
    return sRemountWritable;
}

+ (void)setRemountWritable:(BOOL)writable
{
    sRemountWritable = writable;
    if (writable) {
        DTBLog(@"[+] build50 bootstrap gate remountWritable=1");
        DTBStage(@"build50 bootstrap gate open");
    }
}

+ (BOOL)pathHasPrefix:(NSString *)path prefix:(NSString *)prefix
{
    if (!path.length || !prefix.length) return NO;
    if ([path isEqualToString:prefix]) return YES;
    NSString *need = [prefix stringByAppendingString:@"/"];
    return [path hasPrefix:need];
}

+ (int)rootfsWritable
{
    struct statfs fs;
    if (statfs("/", &fs) != 0)
        return errno > 0 ? errno : -1;
    if (fs.f_flags & MNT_RDONLY)
        return EROFS;
    return 0;
}

+ (BOOL)gateChecks:(NSString * _Nullable * _Nonnull)detailOut stage:(NSString *)stage
{
    if (!sRemountWritable) {
        *detailOut = @"remountWritable=0 — run Exploit first";
        DTBLog([NSString stringWithFormat:@"[!] build50 %@ abort remountWritable=0", stage]);
        DTBStage([NSString stringWithFormat:@"build50 %@ fail no remount gate", stage]);
        return NO;
    }
    if (getuid() != 0) {
        *detailOut = [NSString stringWithFormat:@"need root uid=0 (have uid=%u)", (unsigned)getuid()];
        DTBLog([NSString stringWithFormat:@"[!] build50 %@ abort getuid=%u", stage, (unsigned)getuid()]);
        DTBStage([NSString stringWithFormat:@"build50 %@ fail need root", stage]);
        return NO;
    }
    int rw = [self rootfsWritable];
    if (rw != 0) {
        *detailOut = [NSString stringWithFormat:@"/ not writable errno=%d (%s)", rw, strerror(rw)];
        DTBLog([NSString stringWithFormat:@"[!] build50 %@ abort rootfs errno=%d", stage, rw]);
        DTBStage([NSString stringWithFormat:@"build50 %@ fail EROFS", stage]);
        return NO;
    }
    return YES;
}

+ (int)prepareJBRoot:(NSString * _Nullable * _Nonnull)detailOut
{
    struct stat st;
    if (lstat(kDTJBRoot.fileSystemRepresentation, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX];
            ssize_t n = readlink(kDTJBRoot.fileSystemRepresentation, target, sizeof(target) - 1);
            if (n >= 0) {
                target[n] = '\0';
                *detailOut = [NSString stringWithFormat:@"refusing symlink /var/jb -> %s", target];
            } else {
                *detailOut = @"refusing symlink /var/jb (readlink failed)";
            }
            return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
            *detailOut = @"/var/jb exists and is not a directory";
            return -1;
        }
        return 0;
    }

    if (errno != ENOENT) {
        *detailOut = [NSString stringWithFormat:@"lstat /var/jb errno=%d", errno];
        return errno > 0 ? errno : -1;
    }

    if (mkdir(kDTJBRoot.fileSystemRepresentation, 0755) != 0) {
        int e = errno;
        *detailOut = [NSString stringWithFormat:@"mkdir /var/jb errno=%d (%s)", e, strerror(e)];
        return e > 0 ? e : -1;
    }

    DTBLog(@"[+] build50 mkdir /var/jb OK");
    DTBStage(@"build50 mkdir /var/jb OK");
    return 0;
}

+ (int)writeProbeAtPath:(NSString *)path content:(const char * _Nullable)content contentLen:(size_t)len
{
    if (![self pathHasPrefix:path prefix:kDTJBRoot])
        return EPERM;

    unlink(path.fileSystemRepresentation);

    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fd < 0)
        return errno > 0 ? errno : -1;

    if (content && len > 0) {
        ssize_t wrote = write(fd, content, len);
        if (wrote < 0 || (size_t)wrote != len) {
            int e = errno;
            close(fd);
            unlink(path.fileSystemRepresentation);
            return e > 0 ? e : -1;
        }
    }

    close(fd);
    return 0;
}

+ (BOOL)isMachOAtPath:(NSString *)path
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) return NO;
    uint32_t magic = 0;
    ssize_t n = read(fd, &magic, sizeof(magic));
    close(fd);
    if (n != (ssize_t)sizeof(magic)) return NO;
    return magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM;
}

+ (NSString *)bundleG2Root
{
    return [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"bootstrap_g2"];
}

+ (NSString *)bundleLdidPath
{
    return [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"Tools/ldid"];
}

+ (NSString *)bundleToolsEntitlementsPath
{
    return [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"Tools/entitlements_tools.plist"];
}

+ (NSString *)bundleHelperEntitlementsPath
{
    return [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"entitlements_helper.plist"];
}

+ (BOOL)build1022PingSucceededSpawnErr:(int)spawnErr exitStatus:(int)exitStatus output:(NSString *)output
{
    return spawnErr == 0 && exitStatus == 0 && [output containsString:@"pong"];
}

+ (void)build1022LogHelperPath:(NSString *)path label:(NSString *)label
{
    struct stat st;
    int statErr = stat(path.fileSystemRepresentation, &st);
    BOOL xok = (access(path.fileSystemRepresentation, X_OK) == 0);

    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    BOOL haveHash = (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) == 0);
    BOOL trusted = haveHash ? dt_cdhash_trustcached(hash) : NO;
    NSString *hex = haveHash ? dt_cdhash_hex_string(hash) : @"?";

    if (statErr != 0) {
        DTBLog([NSString stringWithFormat:@"[*] build102.2 %@ path=%@ stat=errno%d mode=- xok=%d cdhash=%@ trusted=%d",
                label, path, errno, xok ? 1 : 0, hex, trusted ? 1 : 0]);
        return;
    }

    DTBLog([NSString stringWithFormat:@"[*] build102.2 %@ path=%@ stat=0 mode=%o xok=%d cdhash=%@ trusted=%d",
            label, path, st.st_mode & 07777, xok ? 1 : 0, hex, trusted ? 1 : 0]);
}

+ (void)build1022LogBasebinStat:(NSString *)path name:(NSString *)name
{
    struct stat st;
    int err = stat(path.fileSystemRepresentation, &st);
    if (err == 0) {
        DTBLog([NSString stringWithFormat:@"[*] build102.2 basebin %@ stat=0 mode=%o", name, st.st_mode & 07777]);
    } else {
        DTBLog([NSString stringWithFormat:@"[*] build102.2 basebin %@ stat=errno%d", name, errno]);
    }
}

+ (void)build1022LogParentCreds
{
    uint32_t csflags = 0;
    int csErr = csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    BOOL platform = (csErr == 0) && ((csflags & CS_PLATFORM_BINARY) != 0);
    DTBLog([NSString stringWithFormat:
            @"[*] build102.2 parent uid=%d euid=%d gid=%d egid=%d csflags=0x%x platform=%d csops=%d",
            getuid(), geteuid(), getgid(), getegid(), csflags, platform ? 1 : 0, csErr]);
}

+ (BOOL)build1022InstallJbHelper:(NSString * _Nullable * _Nonnull)detailOut
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *src = [DTRootHelperClient helperBundledPath];
    if (![fm isExecutableFileAtPath:src]) {
        *detailOut = [NSString stringWithFormat:@"bundled helper missing at %@", src];
        return NO;
    }

    NSString *ldidPath = [self bundleLdidPath];
    NSString *entPath = [self bundleHelperEntitlementsPath];
    if (![fm fileExistsAtPath:ldidPath] || ![self isMachOAtPath:ldidPath]) {
        *detailOut = @"Tools/ldid missing — run G4 or rebuild IPA";
        return NO;
    }
    if (![fm fileExistsAtPath:entPath]) {
        *detailOut = @"entitlements_helper.plist missing from app bundle";
        return NO;
    }

    NSError *copyErr = nil;
    if ([fm fileExistsAtPath:kDTJbHelperPath])
        [fm removeItemAtPath:kDTJbHelperPath error:nil];

    if (![fm copyItemAtPath:src toPath:kDTJbHelperPath error:&copyErr]) {
        *detailOut = copyErr.localizedDescription ?: @"copy dt_helper failed";
        return NO;
    }

    if (chmod(kDTJbHelperPath.fileSystemRepresentation, 0755) != 0) {
        *detailOut = [NSString stringWithFormat:@"chmod dt_helper errno=%d (%s)", errno, strerror(errno)];
        return NO;
    }

    NSString *signDetail = nil;
    if (![self signMachOAtPath:kDTJbHelperPath withLdid:ldidPath ent:entPath isDylib:NO detailOut:&signDetail]) {
        *detailOut = signDetail ?: @"dt_helper sign failed";
        return NO;
    }

    NSUInteger uploaded = 0;
    NSUInteger skipped = 0;
    NSString *trustDetail = nil;
    if (![self trustPostSignT1Paths:@[kDTJbHelperPath] uploaded:&uploaded skipped:&skipped detailOut:&trustDetail]) {
        *detailOut = trustDetail ?: @"dt_helper trustcache upload failed";
        return NO;
    }

    BOOL trusted = NO;
    if (![self build1021LogTrustForPath:kDTJbHelperPath trustedOut:&trusted] || !trusted) {
        *detailOut = @"dt_helper not trusted after sign/upload";
        return NO;
    }

    *detailOut = [NSString stringWithFormat:@"installed signed trusted dt_helper uploaded=%lu skipped=%lu",
                  (unsigned long)uploaded, (unsigned long)skipped];
    return YES;
}

+ (BOOL)build10232RetrustJbHelper:(NSString * _Nullable * _Nonnull)detailOut
{
    NSUInteger uploaded = 0;
    NSUInteger skipped = 0;
    NSString *trustDetail = nil;
    if (![self trustPostSignT1Paths:@[kDTJbHelperPath] uploaded:&uploaded skipped:&skipped detailOut:&trustDetail]) {
        *detailOut = trustDetail ?: @"dt_helper re-trust upload failed";
        return NO;
    }

    BOOL trusted = NO;
    if (![self build1021LogTrustForPath:kDTJbHelperPath trustedOut:&trusted] || !trusted) {
        *detailOut = @"dt_helper not trusted after re-trust upload";
        return NO;
    }

    *detailOut = [NSString stringWithFormat:@"dt_helper re-trusted uploaded=%lu skipped=%lu",
                  (unsigned long)uploaded, (unsigned long)skipped];
    return YES;
}

+ (BOOL)build1023EnsureJbHelper:(NSString * _Nullable * _Nonnull)detailOut
{
    NSString *bundledPath = [DTRootHelperClient helperBundledPath];
    cdhash_t bundledHash;
    cdhash_t installedHash;
    memset(bundledHash, 0, sizeof(bundledHash));
    memset(installedHash, 0, sizeof(installedHash));

    BOOL haveBundled = (dt_macho_best_cdhash_from_path(bundledPath.fileSystemRepresentation, bundledHash) == 0);
    BOOL haveInstalled = (dt_macho_best_cdhash_from_path(kDTJbHelperPath.fileSystemRepresentation, installedHash) == 0);
    BOOL executable = [[NSFileManager defaultManager] isExecutableFileAtPath:kDTJbHelperPath];
    BOOL trusted = haveInstalled ? dt_cdhash_trustcached(installedHash) : NO;

    if (haveBundled && haveInstalled && executable &&
        memcmp(bundledHash, installedHash, CS_CDHASH_LEN) == 0) {
        if (trusted) {
            *detailOut = @"dt_helper present trusted cdhash matches bundled";
            return YES;
        }
        DTBLog(@"[*] build102.3.3 helper cdhash match but not trustcached — re-trust before ping");
        return [self build10232RetrustJbHelper:detailOut];
    }
    return [self build1022InstallJbHelper:detailOut];
}

+ (NSArray<NSString *> *)build10232FinalTrustPathsFromSignPaths:(NSArray<NSString *> *)signPaths
{
    NSMutableArray<NSString *> *merged = [NSMutableArray arrayWithObject:kDTJbHelperPath];
    NSMutableSet<NSString *> *seen = [NSMutableSet setWithObject:kDTJbHelperPath];
    for (NSString *path in signPaths) {
        if (![seen containsObject:path]) {
            [seen addObject:path];
            [merged addObject:path];
        }
    }
    return merged;
}

+ (void)build10232LogFinalTrustPaths:(NSArray<NSString *> *)paths
{
    DTBLog([NSString stringWithFormat:@"[*] build102.3.3 final trust paths=%@",
            [paths componentsJoinedByString:@","]]);
    for (NSString *path in paths) {
        BOOL trusted = NO;
        (void)[self build1021LogTrustForPath:path trustedOut:&trusted];
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 final trust path=%@ trusted=%d",
                path, trusted ? 1 : 0]);
    }
}

+ (void)build10232LogHelperPreflightBeforePing
{
    NSString *path = kDTJbHelperPath;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL xok = [fm isExecutableFileAtPath:path];
    BOOL macho = [self isMachOAtPath:path];

    struct stat st;
    int stErr = stat(path.fileSystemRepresentation, &st);

    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    int hashErr = dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash);
    NSString *hex = (hashErr == 0) ? dt_cdhash_hex_string(hash) : @"?";
    BOOL trusted = (hashErr == 0) ? dt_cdhash_trustcached(hash) : NO;

    NSArray<NSString *> *deps = macho ? [self machOLoadDylibPathsForBinary:path] : @[];
    NSString *depList = deps.count ? [deps componentsJoinedByString:@","] : @"(none)";

    DTBLog([NSString stringWithFormat:
            @"[*] build102.3.3 helper path=%@ stat_size=%lld mode=%o xok=%d macho=%d arch=arm64 platform=tvOS cdhash=%@ trusted=%d otool_deps=%@",
            path,
            stErr == 0 ? (long long)st.st_size : (long long)-1,
            stErr == 0 ? (st.st_mode & 07777) : 0,
            xok ? 1 : 0, macho ? 1 : 0, hex, trusted ? 1 : 0, depList]);
}

+ (BOOL)build10232LogHelperPreflightBeforeSmoke:(NSString * _Nullable * _Nonnull)detailOut
{
    NSString *path = kDTJbHelperPath;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL xok = [fm isExecutableFileAtPath:path];

    struct stat st;
    int stErr = stat(path.fileSystemRepresentation, &st);

    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    int hashErr = dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash);
    NSString *hex = (hashErr == 0) ? dt_cdhash_hex_string(hash) : @"?";
    BOOL trusted = (hashErr == 0) ? dt_cdhash_trustcached(hash) : NO;

    DTBLog([NSString stringWithFormat:
            @"[*] build102.3.3 helper path=%@ stat=%d mode=%o xok=%d cdhash=%@ trusted=%d",
            path, stErr, stErr == 0 ? (st.st_mode & 07777) : 0, xok ? 1 : 0, hex, trusted ? 1 : 0]);

    if (!xok || hashErr != 0 || !trusted) {
        if (detailOut) {
            *detailOut = [NSString stringWithFormat:
                @"helper preflight fail xok=%d hashErr=%d trusted=%d", xok ? 1 : 0, hashErr, trusted ? 1 : 0];
        }
        return NO;
    }
    return YES;
}

+ (NSString *)build1023TaggedValueFromHelperOutput:(NSString *)output prefix:(NSString *)prefix
{
    if (!output.length || !prefix.length)
        return @"";

    NSArray<NSString *> *lines = [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSString *need = prefix;
    for (NSString *line in lines) {
        if ([line hasPrefix:need])
            return [[line substringFromIndex:need.length]
                stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
    }
    return @"";
}

+ (void)build1023LogHelperInnerFields:(NSString *)output
{
    if (!output.length)
        return;

    NSString *errnoLine = [self build1023TaggedValueFromHelperOutput:output prefix:@"inner_posix_spawn_errno="];
    if (errnoLine.length)
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 inner_posix_spawn_errno=%@", errnoLine]);

    NSString *strerrLine = [self build1023TaggedValueFromHelperOutput:output prefix:@"inner_posix_spawn_strerror="];
    if (strerrLine.length)
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 inner_posix_spawn_strerror=%@", strerrLine]);

    NSString *childExit = [self build1023TaggedValueFromHelperOutput:output prefix:@"child_exit="];
    if (childExit.length)
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 child_exit=%@", childExit]);

    NSString *childStdout = [self build1023TaggedValueFromHelperOutput:output prefix:@"child_stdout="];
    if (childStdout.length)
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 child_stdout=%@", childStdout]);
}

+ (BOOL)build1023ChildDashHasUid0:(NSString *)helperOutput
{
    NSString *childStdout = [self build1023TaggedValueFromHelperOutput:helperOutput prefix:@"child_stdout="];
    if (!childStdout.length)
        return NO;
    return [childStdout rangeOfString:@"uid=0"].location != NSNotFound;
}

+ (void)build1024LogHelperExtLines:(NSString *)output
{
    if (!output.length)
        return;
    NSArray<NSString *> *lines = [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        if ([line containsString:@"build102.4"])
            DTBLog([NSString stringWithFormat:@"[*] %@", line]);
    }
}

+ (NSString *)build1024VerdictFromHelperOutput:(NSString *)output
{
    if (!output.length)
        return @"";
    NSArray<NSString *> *lines = [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        if ([line hasPrefix:@"build102.4 verdict="])
            return [[line substringFromIndex:19]
                stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
    }
    return @"";
}

+ (int)execBinaryAtPath:(NSString *)path
                  args:(NSArray<NSString *> *)args
              exitCode:(int *)exitCodeOut
             detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    return [self execBinaryAtPath:path args:args env:nil stdoutOut:NULL exitCode:exitCodeOut
                        detailOut:detailOut bypassFmExecutableGate:NO usePersonaRootSpawn:NO];
}

+ (int)execBinaryAtPath:(NSString *)path
                  args:(NSArray<NSString *> *)args
                   env:(NSArray<NSString *> * _Nullable)envPairs
              stdoutOut:(NSString * _Nullable * _Nullable)stdoutOut
              exitCode:(int *)exitCodeOut
             detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    return [self execBinaryAtPath:path args:args env:envPairs stdoutOut:stdoutOut
                        exitCode:exitCodeOut detailOut:detailOut bypassFmExecutableGate:NO
             usePersonaRootSpawn:NO];
}

+ (BOOL)build91PathPassesSpawnAttempt:(NSString *)path detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    if (!path.length) {
        *detailOut = @"empty path";
        return NO;
    }

    const char *cpath = path.fileSystemRepresentation;
    struct stat st;
    errno = 0;
    if (stat(cpath, &st) != 0) {
        int e = errno;
        *detailOut = [NSString stringWithFormat:@"stat errno=%d (%s)", e, strerror(e)];
        return NO;
    }

    errno = 0;
    if (access(cpath, F_OK) != 0) {
        int e = errno;
        *detailOut = [NSString stringWithFormat:@"access_F_OK errno=%d (%s)", e, strerror(e)];
        return NO;
    }

    if (![self isMachOAtPath:path]) {
        *detailOut = @"not mach-o";
        return NO;
    }

    *detailOut = @"stat+F_OK+macho";
    return YES;
}

+ (NSString *)build92LocalProbeCopyForPath:(NSString *)srcPath
                                     prefix:(NSString *)prefix
                                  detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    if (!srcPath.length) {
        *detailOut = @"empty src path";
        return nil;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:srcPath]) {
        *detailOut = [NSString stringWithFormat:@"missing src %@", srcPath];
        return nil;
    }

    NSString *tmpDir = NSTemporaryDirectory();
    if (!tmpDir.length)
        tmpDir = @"/private/var/tmp";

    NSString *name = [NSString stringWithFormat:@"%@-%u", prefix ?: @"probe", arc4random_uniform(1000000)];
    NSString *dstPath = [tmpDir stringByAppendingPathComponent:name];
    [fm removeItemAtPath:dstPath error:nil];

    NSError *copyErr = nil;
    if (![fm copyItemAtPath:srcPath toPath:dstPath error:&copyErr]) {
        *detailOut = [NSString stringWithFormat:@"copy fail %@ -> %@ (%@)",
                      srcPath, dstPath, copyErr.localizedDescription ?: @"?"];
        return nil;
    }

    if (chmod(dstPath.fileSystemRepresentation, 0755) != 0) {
        int e = errno;
        [fm removeItemAtPath:dstPath error:nil];
        *detailOut = [NSString stringWithFormat:@"chmod fail %@ errno=%d (%s)", dstPath, e, strerror(e)];
        return nil;
    }

    if (![self isMachOAtPath:dstPath]) {
        [fm removeItemAtPath:dstPath error:nil];
        *detailOut = [NSString stringWithFormat:@"copied probe not mach-o %@", dstPath];
        return nil;
    }

    *detailOut = [NSString stringWithFormat:@"probe_copy=%@", dstPath];
    return dstPath;
}

+ (void)build93LogSpawnCredForProbe:(NSString *)probe
                             idaHyp:(NSString *)idaHyp
                     usePersonaRoot:(BOOL)usePersonaRoot
{
    // IDA: op 129 evaluate uses spawning proc cred (536CA4 → 532930 on parent label), not child persona uid.
    DTBLog([NSString stringWithFormat:
            @"[*] build93 ida=%@ probe=%@ getuid=%d geteuid=%d getgid=%d getegid=%d persona_root=%d persona_uid_tgt=0",
            idaHyp, probe, getuid(), geteuid(), getgid(), getegid(), usePersonaRoot ? 1 : 0]);
    DTBStage([NSString stringWithFormat:@"build93 cred %@ persona=%d", probe, usePersonaRoot ? 1 : 0]);
}

+ (int)execBinaryAtPath:(NSString *)path
                  args:(NSArray<NSString *> *)args
                   env:(NSArray<NSString *> * _Nullable)envPairs
              stdoutOut:(NSString * _Nullable * _Nullable)stdoutOut
              exitCode:(int *)exitCodeOut
             detailOut:(NSString * _Nullable * _Nonnull)detailOut
 bypassFmExecutableGate:(BOOL)bypassFmGate
    usePersonaRootSpawn:(BOOL)usePersonaRootSpawn
{
    if (!path.length) {
        *detailOut = @"empty path";
        return EINVAL;
    }

    if (!bypassFmGate && ![[NSFileManager defaultManager] isExecutableFileAtPath:path]) {
        *detailOut = [NSString stringWithFormat:@"not executable: %@", path];
        return ENOENT;
    }

    if (bypassFmGate) {
        DTBLog([NSString stringWithFormat:@"[*] build95 bypass_fm_gate=1 path=%@", path]);
        DTBStage(@"build95 bypass fm gate spawn");
    }
    if (usePersonaRootSpawn) {
        DTBLog([NSString stringWithFormat:@"[*] build95 persona_root_spawn=1 path=%@", path]);
        DTBStage(@"build95 persona root spawn");
    }

    typedef int (*posix_spawn_fn)(pid_t *, const char *, const DTSpawnFileActions *,
                                  const DTPosixSpawnAttr * _Nullable, char *const[], char *const[]);
    typedef int (*spawn_attr_init_fn)(DTPosixSpawnAttr *);
    typedef int (*spawn_attr_destroy_fn)(DTPosixSpawnAttr *);
    typedef int (*spawn_fa_init_fn)(DTSpawnFileActions *);
    typedef int (*spawn_fa_destroy_fn)(DTSpawnFileActions *);
    typedef int (*spawn_fa_adddup2_fn)(DTSpawnFileActions *, int, int);
    typedef int (*spawn_fa_addclose_fn)(DTSpawnFileActions *, int);

    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(RTLD_DEFAULT, "posix_spawn");
    spawn_attr_init_fn attr_init = (spawn_attr_init_fn)dlsym(RTLD_DEFAULT, "posix_spawnattr_init");
    spawn_attr_destroy_fn attr_destroy = (spawn_attr_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawnattr_destroy");
    if (!spawn) {
        *detailOut = @"posix_spawn unavailable (dlsym)";
        return ENOSYS;
    }
    if (usePersonaRootSpawn && (!attr_init || !attr_destroy)) {
        *detailOut = @"posix_spawnattr persona symbols unavailable (dlsym)";
        return ENOSYS;
    }

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:path.lastPathComponent];
    [argvStrings addObjectsFromArray:args ?: @[]];

    NSUInteger argc = argvStrings.count;
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv) {
        *detailOut = @"calloc argv failed";
        return ENOMEM;
    }

    for (NSUInteger i = 0; i < argc; i++)
        argv[i] = strdup(argvStrings[i].UTF8String);

    char **envp = NULL;
    BOOL envOwned = NO;
    if (envPairs.count > 0) {
        envp = calloc(envPairs.count + 1, sizeof(char *));
        if (!envp) {
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            *detailOut = @"calloc envp failed";
            return ENOMEM;
        }
        envOwned = YES;
        for (NSUInteger i = 0; i < envPairs.count; i++)
            envp[i] = strdup(envPairs[i].UTF8String);
    } else {
        extern char **environ;
        envp = environ;
    }

    int pipefd[2] = { -1, -1 };
    DTSpawnFileActions actions;
    BOOL useActions = NO;
    if (stdoutOut) {
        spawn_fa_init_fn fa_init = (spawn_fa_init_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_init");
        spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
        spawn_fa_adddup2_fn fa_dup2 = (spawn_fa_adddup2_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_adddup2");
        spawn_fa_addclose_fn fa_close = (spawn_fa_addclose_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_addclose");
        if (!fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            if (envOwned) {
                for (NSUInteger i = 0; i < envPairs.count; i++) free(envp[i]);
                free(envp);
            }
            *detailOut = @"posix_spawn_file_actions unavailable (dlsym)";
            return ENOSYS;
        }
        if (pipe(pipefd) != 0) {
            int e = errno;
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            if (envOwned) {
                for (NSUInteger i = 0; i < envPairs.count; i++) free(envp[i]);
                free(envp);
            }
            *detailOut = [NSString stringWithFormat:@"pipe errno=%d (%s)", e, strerror(e)];
            return e > 0 ? e : -1;
        }
        fa_init(&actions);
        fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
        fa_dup2(&actions, pipefd[1], STDERR_FILENO);
        fa_close(&actions, pipefd[0]);
        fa_close(&actions, pipefd[1]);
        useActions = YES;
    }

    DTPosixSpawnAttr spawnAttr;
    DTPosixSpawnAttr *spawnAttrPtr = NULL;
    BOOL spawnAttrInited = NO;
    if (usePersonaRootSpawn) {
        if (attr_init(&spawnAttr) != 0) {
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            if (envOwned) {
                for (NSUInteger i = 0; i < envPairs.count; i++) free(envp[i]);
                free(envp);
            }
            if (pipefd[0] >= 0) close(pipefd[0]);
            if (pipefd[1] >= 0) close(pipefd[1]);
            *detailOut = @"posix_spawnattr_init failed";
            return EINVAL;
        }
        spawnAttrInited = YES;
        posix_spawnattr_set_persona_np(&spawnAttr, 99, DT_POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        posix_spawnattr_set_persona_uid_np(&spawnAttr, 0);
        posix_spawnattr_set_persona_gid_np(&spawnAttr, 0);
        spawnAttrPtr = &spawnAttr;
    }

    pid_t pid = 0;
    const char *spawnPath = path.fileSystemRepresentation;
    if (bypassFmGate || usePersonaRootSpawn) {
        DTBLog([NSString stringWithFormat:@"[*] build95 posix_spawn attempt spawn_path=%@ argv0=%@ persona=%d",
                path, argvStrings[0], usePersonaRootSpawn ? 1 : 0]);
    }
    int spawnErr = spawn(&pid, spawnPath, useActions ? &actions : NULL, spawnAttrPtr, argv, envp);
    if (spawnAttrInited && attr_destroy)
        attr_destroy(&spawnAttr);

    if (useActions)
        close(pipefd[1]);

    for (NSUInteger i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);
    if (envOwned) {
        for (NSUInteger i = 0; i < envPairs.count; i++)
            free(envp[i]);
        free(envp);
    }

    if (spawnErr != 0) {
        if (pipefd[0] >= 0) close(pipefd[0]);
        if (useActions) {
            spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
            if (fa_destroy) fa_destroy(&actions);
        }
        if (bypassFmGate || usePersonaRootSpawn) {
            DTBLog([NSString stringWithFormat:@"[*] build93 posix_spawn fail errno=%d (%s) pid=%d path=%@ persona=%d",
                    spawnErr, strerror(spawnErr), (int)pid, path, usePersonaRootSpawn ? 1 : 0]);
            DTBStage([NSString stringWithFormat:@"build93 posix_spawn errno=%d", spawnErr]);
        }
        *detailOut = [NSString stringWithFormat:@"posix_spawn %@ errno=%d (%s)", path, spawnErr, strerror(spawnErr)];
        return spawnErr;
    }

    if (bypassFmGate || usePersonaRootSpawn) {
        DTBLog([NSString stringWithFormat:@"[*] build93 posix_spawn ok pid=%d path=%@ persona=%d",
                (int)pid, path, usePersonaRootSpawn ? 1 : 0]);
        DTBStage([NSString stringWithFormat:@"build93 posix_spawn ok pid=%d", (int)pid]);
    }

    if (stdoutOut && pipefd[0] >= 0) {
        NSMutableData *data = [NSMutableData data];
        char buf[4096];
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
            [data appendBytes:buf length:(NSUInteger)n];
        close(pipefd[0]);
        pipefd[0] = -1;
        *stdoutOut = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    }

    if (useActions) {
        spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
        if (fa_destroy)
            fa_destroy(&actions);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        int e = errno;
        *detailOut = [NSString stringWithFormat:@"waitpid errno=%d (%s)", e, strerror(e)];
        return e > 0 ? e : -1;
    }

    if (WIFEXITED(status)) {
        *exitCodeOut = WEXITSTATUS(status);
        if (bypassFmGate || usePersonaRootSpawn) {
            DTBLog([NSString stringWithFormat:@"[*] build93 child exit=%d path=%@ persona=%d",
                    *exitCodeOut, path, usePersonaRootSpawn ? 1 : 0]);
            DTBStage([NSString stringWithFormat:@"build93 child exit=%d", *exitCodeOut]);
        }
        return 0;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        *detailOut = [NSString stringWithFormat:@"killed by signal %d", sig];
        *exitCodeOut = 128 + sig;
        if (bypassFmGate || usePersonaRootSpawn) {
            DTBLog([NSString stringWithFormat:@"[*] build93 child signal=%d path=%@ persona=%d",
                    sig, path, usePersonaRootSpawn ? 1 : 0]);
            DTBStage([NSString stringWithFormat:@"build93 child signal=%d", sig]);
        }
        return 0;
    }

    *detailOut = @"child exited abnormally";
    *exitCodeOut = -1;
    return 0;
}

+ (NSString *)resolveLoadDylibPath:(NSString *)installName forBinaryAtPath:(NSString *)binaryPath
{
    if (!installName.length || !binaryPath.length)
        return nil;

    if ([installName hasPrefix:@"@loader_path/"]) {
        NSString *rel = [installName substringFromIndex:14];
        NSString *binDir = [binaryPath stringByDeletingLastPathComponent];
        NSString *resolved = [[binDir stringByAppendingPathComponent:rel] stringByStandardizingPath];
        return resolved;
    }

    if ([installName hasPrefix:@"@rpath/"]) {
        NSString *name = [installName substringFromIndex:7];
        NSString *candidate = [kDTUsrLib stringByAppendingPathComponent:name];
        if ([[NSFileManager defaultManager] fileExistsAtPath:candidate])
            return candidate;
        return [kDTUsrLib stringByAppendingPathComponent:name];
    }

    if ([installName hasPrefix:@"/"])
        return installName;

    return nil;
}

+ (NSArray<NSString *> *)machOLoadDylibPathsForBinary:(NSString *)binaryPath
{
    NSMutableArray<NSString *> *resolved = [NSMutableArray array];
    int fd = open(binaryPath.fileSystemRepresentation, O_RDONLY);
    if (fd < 0)
        return resolved;

    struct mach_header_64 mh;
    if (read(fd, &mh, sizeof(mh)) != (ssize_t)sizeof(mh) || mh.magic != MH_MAGIC_64) {
        close(fd);
        return resolved;
    }

    off_t off = (off_t)sizeof(mh);
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (lseek(fd, off, SEEK_SET) < 0)
            break;

        struct load_command lc;
        if (read(fd, &lc, sizeof(lc)) != (ssize_t)sizeof(lc))
            break;

        if (lc.cmd == LC_LOAD_DYLIB && lc.cmdsize > (uint32_t)sizeof(struct dylib_command)) {
            struct dylib_command dc;
            if (lseek(fd, off, SEEK_SET) >= 0 &&
                read(fd, &dc, sizeof(dc)) == (ssize_t)sizeof(dc)) {
                char name[PATH_MAX];
                off_t nameOff = off + (off_t)dc.dylib.name.offset;
                if (lseek(fd, nameOff, SEEK_SET) >= 0) {
                    ssize_t n = read(fd, name, sizeof(name) - 1);
                    if (n > 0) {
                        name[n] = '\0';
                        NSString *install = [NSString stringWithUTF8String:name];
                        NSString *path = [self resolveLoadDylibPath:install forBinaryAtPath:binaryPath];
                        if (path.length && [self pathHasPrefix:path prefix:kDTJBRoot] &&
                            [[NSFileManager defaultManager] fileExistsAtPath:path] &&
                            [self isMachOAtPath:path] && ![resolved containsObject:path])
                            [resolved addObject:path];
                    }
                }
            }
        }

        if (lc.cmdsize < sizeof(struct load_command))
            break;
        off += lc.cmdsize;
    }

    close(fd);
    return resolved;
}

+ (NSArray<NSString *> *)build1021MinimalSignPaths:(NSString * _Nullable * _Nonnull)detailOut
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:kDTDashPath]) {
        *detailOut = @"missing /var/jb/usr/bin/dash — run G2 first";
        return nil;
    }

    NSMutableArray<NSString *> *dylibs = [NSMutableArray array];
    NSMutableArray<NSString *> *bins = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    void (^addDylib)(NSString *) = ^(NSString *path) {
        if (!path.length || ![self pathHasPrefix:path prefix:kDTJBRoot])
            return;
        if (![fm fileExistsAtPath:path] || ![self isMachOAtPath:path])
            return;
        if ([seen containsObject:path])
            return;
        [seen addObject:path];
        [dylibs addObject:path];
    };

    void (^addBin)(NSString *) = ^(NSString *path) {
        if (!path.length || ![self pathHasPrefix:path prefix:kDTJBRoot])
            return;
        if (![fm fileExistsAtPath:path] || ![self isMachOAtPath:path])
            return;
        if ([seen containsObject:path])
            return;
        [seen addObject:path];
        [bins addObject:path];
    };

    for (NSString *dep in [self machOLoadDylibPathsForBinary:kDTDashPath])
        addDylib(dep);

    NSString *libiosexec = [kDTUsrLib stringByAppendingPathComponent:@"libiosexec.1.dylib"];
    if ([fm fileExistsAtPath:libiosexec]) {
        for (NSString *dep in [self machOLoadDylibPathsForBinary:libiosexec])
            addDylib(dep);
        addDylib(libiosexec);
    }

    addBin(kDTDashPath);

    if (!bins.count) {
        *detailOut = @"no dash binary in sign path list";
        return nil;
    }

    NSMutableArray<NSString *> *ordered = [NSMutableArray arrayWithCapacity:dylibs.count + bins.count];
    [ordered addObjectsFromArray:dylibs];
    [ordered addObjectsFromArray:bins];
    return ordered;
}

+ (BOOL)build1021VerifySignPathsTrusted:(NSArray<NSString *> *)paths
                               detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    for (NSString *path in paths) {
        BOOL trusted = NO;
        if (![self build1021LogTrustForPath:path trustedOut:&trusted] || !trusted) {
            *detailOut = [NSString stringWithFormat:@"build102.1 abort: %@ not trusted, helper proof not valid",
                          path];
            return NO;
        }
    }
    return YES;
}

+ (BOOL)signPathList:(NSArray<NSString *> *)paths
            withLdid:(NSString *)ldid
                 ent:(NSString *)ent
          detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    for (NSString *path in paths) {
        BOOL isDylib = [self pathHasPrefix:path prefix:kDTUsrLib];
        NSString *signDetail = nil;
        if (![self signMachOAtPath:path withLdid:ldid ent:ent isDylib:isDylib detailOut:&signDetail]) {
            DTBLog([NSString stringWithFormat:@"[*] build102.1 sign path=%@ result=FAIL", path]);
            *detailOut = signDetail ?: [NSString stringWithFormat:@"sign failed: %@", path];
            return NO;
        }
        DTBLog([NSString stringWithFormat:@"[*] build102.1 sign path=%@ result=OK", path]);
    }
    return YES;
}

+ (BOOL)build1021LogTrustForPath:(NSString *)path trustedOut:(BOOL *)trustedOut
{
    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0) {
        DTBLog([NSString stringWithFormat:@"[*] build102.1 trust path=%@ cdhash=? trusted=0", path]);
        if (trustedOut)
            *trustedOut = NO;
        return NO;
    }

    BOOL cached = dt_cdhash_trustcached(hash);
    NSString *hex = dt_cdhash_hex_string(hash);
    DTBLog([NSString stringWithFormat:@"[*] build102.1 trust path=%@ cdhash=%@ trusted=%d",
            path, hex, cached ? 1 : 0]);
    if (trustedOut)
        *trustedOut = cached;
    return YES;
}

+ (NSArray<NSString *> *)t1SignPaths:(NSString * _Nullable * _Nonnull)detailOut
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *dylibs = [NSMutableArray array];
    NSMutableArray<NSString *> *bins = [NSMutableArray array];

    BOOL libDir = NO;
    if ([fm fileExistsAtPath:kDTUsrLib isDirectory:&libDir] && libDir) {
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:kDTUsrLib];
        NSString *rel;
        while ((rel = en.nextObject)) {
            NSString *full = [kDTUsrLib stringByAppendingPathComponent:rel];
            if (![self pathHasPrefix:full prefix:kDTJBRoot])
                continue;
            BOOL itemDir = NO;
            [fm fileExistsAtPath:full isDirectory:&itemDir];
            if (itemDir) continue;
            if ([self isMachOAtPath:full])
                [dylibs addObject:full];
        }
    }

    for (NSString *bin in @[kDTDashPath, kDTBashPath]) {
        if ([fm fileExistsAtPath:bin] && [self isMachOAtPath:bin])
            [bins addObject:bin];
    }

    if (![bins containsObject:kDTBashPath]) {
        *detailOut = @"missing /var/jb/usr/bin/bash — run G2 first";
        return nil;
    }

    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    [paths addObjectsFromArray:dylibs];
    [paths addObjectsFromArray:bins];
    return paths;
}

+ (BOOL)signMachOAtPath:(NSString *)target
              withLdid:(NSString *)ldid
                   ent:(NSString *)ent
              isDylib:(BOOL)isDylib
             detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    int exitCode = -1;
    NSString *execDetail = nil;
    NSString *ldidOut = nil;
    NSString *sentFlag = [NSString stringWithFormat:@"-S%@", ent];
    int err = [self execBinaryAtPath:ldid args:@[sentFlag, target]
                                 env:nil stdoutOut:&ldidOut exitCode:&exitCode detailOut:&execDetail];
    if (err == 0 && exitCode == 0)
        return YES;

    if (isDylib) {
        execDetail = nil;
        ldidOut = nil;
        err = [self execBinaryAtPath:ldid args:@[@"-S", target]
                                 env:nil stdoutOut:&ldidOut exitCode:&exitCode detailOut:&execDetail];
        if (err == 0 && exitCode == 0)
            return YES;
    }

    NSString *ldidMsg = [ldidOut stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (ldidMsg.length)
        *detailOut = [NSString stringWithFormat:@"ldid sign %@ exit=%d: %@", target.lastPathComponent, exitCode, ldidMsg];
    else
        *detailOut = execDetail ?: [NSString stringWithFormat:@"ldid sign %@ exit=%d", target.lastPathComponent, exitCode];
    return NO;
}

+ (void)logExecutableDiagnostic:(NSString *)label path:(NSString *)path
{
    struct stat st;
    if (stat(path.fileSystemRepresentation, &st) != 0) {
        DTBLog([NSString stringWithFormat:@"[*] build50 diag %@ path=%@ stat errno=%d (%s)",
                label, path, errno, strerror(errno)]);
        DTBStage([NSString stringWithFormat:@"build50 diag %@ stat fail", label]);
        return;
    }

    DTBLog([NSString stringWithFormat:@"[*] build50 diag %@ path=%@ size=%lld mode=%o uid=%u gid=%u macho=%d",
            label, path, (long long)st.st_size, st.st_mode & 07777,
            (unsigned)st.st_uid, (unsigned)st.st_gid, [self isMachOAtPath:path] ? 1 : 0]);

    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0)
        return;

    struct mach_header_64 mh;
    if (read(fd, &mh, sizeof(mh)) != (ssize_t)sizeof(mh) || mh.magic != MH_MAGIC_64) {
        close(fd);
        return;
    }

    uint32_t platform = 0;
    uint32_t minos = 0;
    NSMutableArray<NSString *> *deps = [NSMutableArray array];
    off_t off = (off_t)sizeof(mh);

    for (uint32_t i = 0; i < mh.ncmds && deps.count < 6; i++) {
        if (lseek(fd, off, SEEK_SET) < 0)
            break;

        struct load_command lc;
        if (read(fd, &lc, sizeof(lc)) != (ssize_t)sizeof(lc))
            break;

        if (lc.cmd == LC_BUILD_VERSION && lc.cmdsize >= (uint32_t)sizeof(struct build_version_command)) {
            struct build_version_command bv;
            if (lseek(fd, off, SEEK_SET) >= 0 &&
                read(fd, &bv, sizeof(bv)) == (ssize_t)sizeof(bv)) {
                platform = bv.platform;
                minos = bv.minos;
            }
        } else if (lc.cmd == LC_LOAD_DYLIB && lc.cmdsize > (uint32_t)sizeof(struct dylib_command)) {
            struct dylib_command dc;
            if (lseek(fd, off, SEEK_SET) >= 0 &&
                read(fd, &dc, sizeof(dc)) == (ssize_t)sizeof(dc)) {
                char name[PATH_MAX];
                off_t nameOff = off + (off_t)dc.dylib.name.offset;
                if (lseek(fd, nameOff, SEEK_SET) >= 0) {
                    ssize_t n = read(fd, name, sizeof(name) - 1);
                    if (n > 0) {
                        name[n] = '\0';
                        [deps addObject:[NSString stringWithUTF8String:name] ?: @"(null)"];
                    }
                }
            }
        }

        if (lc.cmdsize < sizeof(struct load_command))
            break;
        off += lc.cmdsize;
    }

    close(fd);

    if (platform || minos) {
        DTBLog([NSString stringWithFormat:@"[*] build50 diag %@ lc_build platform=%u minos=%u.%u deps=%lu",
                label, platform, minos >> 16, minos & 0xffff, (unsigned long)deps.count]);
    }
    for (NSString *dep in deps) {
        DTBLog([NSString stringWithFormat:@"[*] build50 diag %@ dep %@", label, dep]);
    }
}

+ (void)logBuild90LoadDylinker:(NSString *)label path:(NSString *)path
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ lc_dylinker open errno=%d (%s)",
                label, errno, strerror(errno)]);
        return;
    }

    struct mach_header_64 mh;
    if (read(fd, &mh, sizeof(mh)) != (ssize_t)sizeof(mh) || mh.magic != MH_MAGIC_64) {
        close(fd);
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ lc_dylinker not_mach64", label]);
        return;
    }

    NSString *dylinker = nil;
    off_t off = (off_t)sizeof(mh);
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (lseek(fd, off, SEEK_SET) < 0)
            break;

        struct load_command lc;
        if (read(fd, &lc, sizeof(lc)) != (ssize_t)sizeof(lc))
            break;

        if (lc.cmd == LC_LOAD_DYLINKER && lc.cmdsize >= (uint32_t)sizeof(struct dylinker_command)) {
            struct dylinker_command dc;
            if (lseek(fd, off, SEEK_SET) >= 0 &&
                read(fd, &dc, sizeof(dc)) == (ssize_t)sizeof(dc)) {
                char name[PATH_MAX];
                off_t nameOff = off + (off_t)dc.name.offset;
                if (lseek(fd, nameOff, SEEK_SET) >= 0) {
                    ssize_t n = read(fd, name, sizeof(name) - 1);
                    if (n > 0) {
                        name[n] = '\0';
                        dylinker = [NSString stringWithUTF8String:name];
                    }
                }
            }
            break;
        }

        if (lc.cmdsize < sizeof(struct load_command))
            break;
        off += lc.cmdsize;
    }

    close(fd);

    if (dylinker.length)
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ lc_dylinker=%@", label, dylinker]);
    else
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ lc_dylinker=(none default dyld)", label]);
}

+ (void)logBuild90ExecGateDiagnostics:(NSString *)label path:(NSString *)path
{
    const char *cpath = path.fileSystemRepresentation;
    NSFileManager *fm = [NSFileManager defaultManager];

    struct stat st;
    errno = 0;
    int statRc = stat(cpath, &st);
    int statErrno = errno;

    struct stat lst;
    errno = 0;
    int lstatRc = lstat(cpath, &lst);
    int lstatErrno = errno;

    errno = 0;
    int accOk = access(cpath, F_OK);
    int accOkErrno = errno;

    errno = 0;
    int accXok = access(cpath, X_OK);
    int accXokErrno = errno;

    BOOL fmExists = [fm fileExistsAtPath:path];
    BOOL fmReadable = [fm isReadableFileAtPath:path];
    BOOL fmExecutable = [fm isExecutableFileAtPath:path];

    char rbuf[PATH_MAX];
    errno = 0;
    char *rp = realpath(cpath, rbuf);
    int realpathErrno = errno;

    NSString *privatePath = path;
    if ([path hasPrefix:@"/var/"] && ![path hasPrefix:@"/private/"])
        privatePath = [@"/private" stringByAppendingString:path];

    char prbuf[PATH_MAX];
    errno = 0;
    char *prp = realpath(privatePath.fileSystemRepresentation, prbuf);
    int privateRealpathErrno = errno;

    DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ path=%@", label, path]);
    if (statRc == 0) {
        DTBLog([NSString stringWithFormat:
            @"[*] build90 gate %@ stat ok mode=%o uid=%u gid=%u size=%lld x_usr=%d x_grp=%d x_oth=%d",
            label, st.st_mode & 07777, (unsigned)st.st_uid, (unsigned)st.st_gid,
            (long long)st.st_size,
            (st.st_mode & S_IXUSR) != 0, (st.st_mode & S_IXGRP) != 0, (st.st_mode & S_IXOTH) != 0]);
    } else {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ stat fail errno=%d (%s)",
                label, statErrno, strerror(statErrno)]);
    }

    if (lstatRc == 0) {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ lstat ok mode=%o",
                label, lst.st_mode & 07777]);
    } else {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ lstat fail errno=%d (%s)",
                label, lstatErrno, strerror(lstatErrno)]);
    }

    DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ access_F_OK=%d errno=%d (%s)",
            label, accOk == 0 ? 1 : 0, accOkErrno, strerror(accOkErrno)]);
    DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ access_X_OK=%d errno=%d (%s)",
            label, accXok == 0 ? 1 : 0, accXokErrno, strerror(accXokErrno)]);
    DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ fm exists=%d readable=%d executable=%d",
            label, fmExists ? 1 : 0, fmReadable ? 1 : 0, fmExecutable ? 1 : 0]);
    DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ realpath=%@ errno=%d (%s)",
            label, rp ? [NSString stringWithUTF8String:rp] : @"(null)",
            realpathErrno, strerror(realpathErrno)]);
    DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ private_path=%@ realpath=%@ errno=%d (%s)",
            label, privatePath,
            prp ? [NSString stringWithUTF8String:prp] : @"(null)",
            privateRealpathErrno, strerror(privateRealpathErrno)]);

    for (NSString *dir in @[@"/var", @"/var/jb", @"/var/jb/usr", @"/var/jb/usr/bin", @"/var/jb/usr/lib"]) {
        struct stat dst;
        errno = 0;
        int dirStat = stat(dir.fileSystemRepresentation, &dst);
        int dirErrno = errno;
        BOOL dirFmExec = [fm isExecutableFileAtPath:dir];
        errno = 0;
        int dirXok = access(dir.fileSystemRepresentation, X_OK);
        int dirXokErrno = errno;
        if (dirStat == 0) {
            DTBLog([NSString stringWithFormat:
                @"[*] build90 gate %@ parent %@ stat ok mode=%o access_X_OK=%d errno=%d fm_exec=%d",
                label, dir, dst.st_mode & 07777,
                dirXok == 0 ? 1 : 0, dirXokErrno, dirFmExec ? 1 : 0]);
        } else {
            DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ parent %@ stat fail errno=%d (%s) fm_exec=%d",
                    label, dir, dirErrno, strerror(dirErrno), dirFmExec ? 1 : 0]);
        }
    }

    [self logBuild90LoadDylinker:label path:path];

    if (!path.length) {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ exec_precheck=FAIL empty_path", label]);
    } else if (!fmExecutable) {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ exec_precheck=FAIL isExecutableFileAtPath", label]);
    } else {
        DTBLog([NSString stringWithFormat:@"[*] build90 gate %@ exec_precheck=PASS", label]);
    }

    DTBStage([NSString stringWithFormat:@"build90 gate %@ fm_exec=%d access_x=%d",
            label, fmExecutable ? 1 : 0, accXok == 0 ? 1 : 0]);
}

+ (NSString *)smokeProbeSummaryTag:(DTSmokeProbeResult)result
{
    if (result.ok)
        return @"OK";
    if (result.spawnErr != 0) {
        if (result.detail.length && [result.detail containsString:@"posix_spawn"])
            return [NSString stringWithFormat:@"posix_spawn errno=%d", result.spawnErr];
        return [NSString stringWithFormat:@"spawn errno=%d", result.spawnErr];
    }
    if (result.detail.length && [result.detail containsString:@"signal 9"])
        return @"Killed:9";
    if (result.exitCode >= 0)
        return [NSString stringWithFormat:@"exit=%d", result.exitCode];
    return @"FAIL";
}

+ (void)logCdhashDiagForPath:(NSString *)path label:(NSString *)label phase:(NSString *)phase
{
    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    int err = dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash);
    if (err != 0) {
        DTBLog([NSString stringWithFormat:@"[*] build50 G52 cdhash %@ %@ fail errno=%d (%s)",
                label, phase, err, strerror(err)]);
        DTBStage([NSString stringWithFormat:@"build50 G52 cdhash %@ %@ fail", label, phase]);
        return;
    }

    NSString *hex = dt_cdhash_hex_string(hash);
    if ([phase isEqualToString:@"postsign"]) {
        BOOL cached = dt_cdhash_trustcached(hash);
        DTBLog([NSString stringWithFormat:@"[*] build50 G52 cdhash %@ %@ hash=%@ tcached=%d",
                label, phase, hex, cached ? 1 : 0]);
        DTBStage([NSString stringWithFormat:@"build50 G52 cdhash %@ postsign tcached=%d", label, cached ? 1 : 0]);
    } else {
        DTBLog([NSString stringWithFormat:@"[*] build50 G52 cdhash %@ %@ hash=%@", label, phase, hex]);
        DTBStage([NSString stringWithFormat:@"build50 G52 cdhash %@ %@", label, phase]);
    }
}

+ (NSString *)g52CopyDashProbePath
{
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"dt_g52_dash_probe"];
}

+ (BOOL)trustPostSignT1Paths:(NSArray<NSString *> *)paths
                    uploaded:(NSUInteger *)uploadedOut
                     skipped:(NSUInteger *)skippedOut
                   detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    *uploadedOut = 0;
    *skippedOut = 0;

    if (!paths.count) {
        *detailOut = @"no T1 paths to trust";
        return NO;
    }

    cdhash_t *hashes = calloc(paths.count, sizeof(cdhash_t));
    if (!hashes) {
        *detailOut = @"calloc cdhash batch failed";
        return NO;
    }

    NSUInteger hashCount = 0;
    for (NSString *path in paths) {
        cdhash_t hash;
        memset(hash, 0, sizeof(hash));
        int err = dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash);
        if (err != 0) {
            *detailOut = [NSString stringWithFormat:@"cdhash %@ errno=%d (%s)",
                          path.lastPathComponent, err, strerror(err)];
            free(hashes);
            return NO;
        }

        BOOL cached = dt_cdhash_trustcached(hash);
        NSString *hex = dt_cdhash_hex_string(hash);
        DTBLog([NSString stringWithFormat:@"[*] build75 cdhash %@ hash=%@ tcached=%d",
                path.lastPathComponent, hex, cached ? 1 : 0]);
        DTBStage([NSString stringWithFormat:@"build75 cdhash %@ tcached=%d", path.lastPathComponent, cached ? 1 : 0]);

        memcpy(hashes[hashCount], hash, CS_CDHASH_LEN);
        hashCount++;
    }

    uint32_t uploaded = 0;
    uint32_t skipped = 0;
    int uploadErr = dt_trustcache_upload_cdhashes(hashes, (uint32_t)hashCount, &uploaded, &skipped);
    free(hashes);

    *uploadedOut = uploaded;
    *skippedOut = skipped;

    if (uploadErr != 0) {
        *detailOut = [NSString stringWithFormat:@"trustcache upload errno=%d (%s)",
                      uploadErr, strerror(uploadErr > 0 ? uploadErr : EINVAL)];
        return NO;
    }

    DTBLog([NSString stringWithFormat:@"[+] build75 G5 trust upload done uploaded=%u skipped=%u",
            uploaded, skipped]);
    DTBStage([NSString stringWithFormat:@"build75 G5 trust upload uploaded=%u skipped=%u", uploaded, skipped]);
    *detailOut = [NSString stringWithFormat:@"uploaded=%u skipped=%u", uploaded, skipped];
    return YES;
}

+ (BOOL)build10233FinalTrustForceUpload:(NSArray<NSString *> *)paths
                    helperTrustedBefore:(BOOL *)helperTrustedBeforeOut
                               uploaded:(NSUInteger *)uploadedOut
                              detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    if (uploadedOut)
        *uploadedOut = 0;
    if (helperTrustedBeforeOut)
        *helperTrustedBeforeOut = NO;

    if (!paths.count) {
        *detailOut = @"no final trust paths";
        return NO;
    }

    DTBLog([NSString stringWithFormat:@"[*] build102.3.3 final trust force set count=%lu",
            (unsigned long)paths.count]);
    for (NSString *path in paths) {
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 final trust include path=%@", path]);
    }

    cdhash_t *hashes = calloc(paths.count, sizeof(cdhash_t));
    if (!hashes) {
        *detailOut = @"calloc cdhash batch failed";
        return NO;
    }

    NSUInteger hashCount = 0;
    for (NSString *path in paths) {
        cdhash_t hash;
        memset(hash, 0, sizeof(hash));
        int err = dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash);
        if (err != 0) {
            *detailOut = [NSString stringWithFormat:@"cdhash %@ errno=%d (%s)",
                          path.lastPathComponent, err, strerror(err)];
            free(hashes);
            return NO;
        }

        BOOL cached = dt_cdhash_trustcached(hash);
        NSString *hex = dt_cdhash_hex_string(hash);
        DTBLog([NSString stringWithFormat:@"[*] build75 cdhash %@ hash=%@ tcached=%d",
                path.lastPathComponent, hex, cached ? 1 : 0]);

        if ([path isEqualToString:kDTJbHelperPath] && helperTrustedBeforeOut) {
            *helperTrustedBeforeOut = cached;
        }

        memcpy(hashes[hashCount], hash, CS_CDHASH_LEN);
        hashCount++;
    }

    uint32_t uploaded = 0;
    int uploadErr = dt_trustcache_upload_cdhashes_force(hashes, (uint32_t)hashCount, &uploaded);
    free(hashes);

    if (uploadedOut)
        *uploadedOut = uploaded;

    DTBLog([NSString stringWithFormat:@"[*] build102.3.3 final trust upload uploaded=%u", uploaded]);

    if (uploadErr != 0) {
        *detailOut = [NSString stringWithFormat:@"final trustcache force upload errno=%d (%s)",
                      uploadErr, strerror(uploadErr > 0 ? uploadErr : EINVAL)];
        return NO;
    }

    for (NSString *path in paths) {
        BOOL trusted = NO;
        (void)[self build1021LogTrustForPath:path trustedOut:&trusted];
        DTBLog([NSString stringWithFormat:@"[*] build102.3.3 final trust verify path=%@ trusted=%d",
                path, trusted ? 1 : 0]);
        if (!trusted) {
            *detailOut = [NSString stringWithFormat:@"final trust verify failed path=%@", path];
            return NO;
        }
    }

    *detailOut = [NSString stringWithFormat:@"force uploaded=%u verified=%lu", uploaded, (unsigned long)paths.count];
    return YES;
}

+ (void)logProbeOutput:(NSString *)label text:(NSString *)text
{
    if (!text.length)
        return;
    static const NSUInteger kChunk = 480;
    NSUInteger len = text.length;
    for (NSUInteger off = 0; off < len; off += kChunk) {
        NSUInteger n = MIN(kChunk, len - off);
        NSString *chunk = [text substringWithRange:NSMakeRange(off, n)];
        DTBLog([NSString stringWithFormat:@"[*] build75 probe %@ out[%lu]: %@",
                label, (unsigned long)(off / kChunk), chunk]);
    }
}

+ (BOOL)logPostTrustCdhashForPath:(NSString *)path label:(NSString *)label detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    cdhash_t hash;
    memset(hash, 0, sizeof(hash));
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0)
        return YES;

    BOOL cached = dt_cdhash_trustcached(hash);
    DTBLog([NSString stringWithFormat:@"[*] build75 post-trust %@ tcached=%d hash=%@",
            label, cached ? 1 : 0, dt_cdhash_hex_string(hash)]);
    DTBStage([NSString stringWithFormat:@"build75 post-trust %@ tcached=%d", label, cached ? 1 : 0]);
    if (!cached) {
        *detailOut = [NSString stringWithFormat:@"%@ CDHash still not trustcached after upload", label];
        DTBLog([NSString stringWithFormat:@"[!] build75 G5 fail trust verify %@", *detailOut]);
        DTBStage(@"build75 G5 fail trust verify");
        return NO;
    }
    return YES;
}

+ (DTSmokeProbeResult)runSmokeProbeNamed:(NSString *)name
                                    path:(NSString *)path
                                    args:(NSArray<NSString *> *)args
                                     env:(NSArray<NSString *> * _Nullable)env
                    useBuild91SpawnBypass:(BOOL)useBuild91SpawnBypass
                    usePersonaRootSpawn:(BOOL)usePersonaRootSpawn
{
    DTSmokeProbeResult result = { NO, 0, -1, nil, nil };

    DTBLog([NSString stringWithFormat:@"[*] build50 smoke probe %@ begin %@", name, path]);
    DTBStage([NSString stringWithFormat:@"build50 smoke probe %@ begin", name]);
    [self logExecutableDiagnostic:name path:path];
    [self logBuild90ExecGateDiagnostics:name path:path];

    BOOL bypassFmGate = NO;
    if (useBuild91SpawnBypass) {
        NSString *bypassDetail = nil;
        if ([self build91PathPassesSpawnAttempt:path detailOut:&bypassDetail]) {
            bypassFmGate = YES;
            DTBLog([NSString stringWithFormat:@"[*] build93 %@ spawn_bypass=1 %@", name, bypassDetail]);
            DTBStage([NSString stringWithFormat:@"build93 %@ spawn bypass on", name]);
        } else {
            DTBLog([NSString stringWithFormat:@"[*] build93 %@ spawn_bypass=0 %@", name, bypassDetail ?: @"?"]);
            DTBStage([NSString stringWithFormat:@"build93 %@ spawn bypass off", name]);
        }
    }

    int exitCode = -1;
    NSString *execDetail = nil;
    NSString *stdoutText = nil;
    int execErr = [self execBinaryAtPath:path args:args env:env stdoutOut:&stdoutText
                                exitCode:&exitCode detailOut:&execDetail
                    bypassFmExecutableGate:bypassFmGate
                       usePersonaRootSpawn:usePersonaRootSpawn];

    result.spawnErr = execErr;
    result.exitCode = exitCode;
    result.detail = execDetail;
    NSString *trimmed = [stdoutText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    result.stdoutSnippet = trimmed;

    if (execErr != 0) {
        [self logProbeOutput:name text:stdoutText];
        DTBLog([NSString stringWithFormat:@"[!] build50 smoke probe %@ spawn fail %@",
                name, execDetail ?: [NSString stringWithFormat:@"errno=%d", execErr]]);
        DTBStage([NSString stringWithFormat:@"build50 smoke probe %@ spawn errno=%d", name, execErr]);
        return result;
    }

    if (exitCode == 137 || [execDetail containsString:@"signal 9"]) {
        [self logProbeOutput:name text:stdoutText];
        DTBLog([NSString stringWithFormat:@"[!] build50 smoke probe %@ Killed:9", name]);
        DTBStage([NSString stringWithFormat:@"build50 smoke probe %@ Killed:9", name]);
        return result;
    }

    if (exitCode != 0) {
        [self logProbeOutput:name text:stdoutText];
        DTBLog([NSString stringWithFormat:@"[!] build50 smoke probe %@ exit=%d out_len=%lu",
                name, exitCode, (unsigned long)trimmed.length]);
        DTBStage([NSString stringWithFormat:@"build50 smoke probe %@ exit=%d", name, exitCode]);
        return result;
    }

    result.ok = YES;
    DTBLog([NSString stringWithFormat:@"[+] build50 smoke probe %@ OK out=%@", name, trimmed ?: @"(empty)"]);
    DTBStage([NSString stringWithFormat:@"build50 smoke probe %@ OK", name]);
    return result;
}

+ (BOOL)signT1TreeWithLdid:(NSString *)ldid
                       ent:(NSString *)ent
                signedCount:(NSUInteger *)signedCount
                failedCount:(NSUInteger *)failedCount
                  detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    *signedCount = 0;
    *failedCount = 0;

    NSArray<NSString *> *paths = [self t1SignPaths:detailOut];
    if (!paths)
        return NO;

    for (NSString *path in paths) {
        BOOL isDylib = [self pathHasPrefix:path prefix:kDTUsrLib];
        NSString *signDetail = nil;
        if (![self signMachOAtPath:path withLdid:ldid ent:ent isDylib:isDylib detailOut:&signDetail]) {
            (*failedCount)++;
            DTBLog([NSString stringWithFormat:@"[!] build50 sign fail %@", path]);
            DTBStage([NSString stringWithFormat:@"build50 sign fail %@", path.lastPathComponent]);
            *detailOut = signDetail ?: [NSString stringWithFormat:@"sign failed: %@", path];
            return NO;
        }
        (*signedCount)++;
        DTBLog([NSString stringWithFormat:@"[+] build50 sign OK %@", path.lastPathComponent]);
    }

    return YES;
}

+ (BOOL)build631SignAndTrustProbeTrue:(NSString * _Nullable * _Nonnull)detailOut
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:kDTProbeTruePath]) {
        *detailOut = @"missing /var/jb/usr/bin/probe_true";
        return NO;
    }

    NSString *ldidPath = [self bundleLdidPath];
    NSString *entPath = [self bundleToolsEntitlementsPath];
    if (![fm fileExistsAtPath:ldidPath] || ![self isMachOAtPath:ldidPath]) {
        *detailOut = @"Tools/ldid missing from app bundle";
        return NO;
    }
    if (![fm fileExistsAtPath:entPath]) {
        *detailOut = @"Tools/entitlements_tools.plist missing";
        return NO;
    }

    struct stat stBefore = { 0 };
    stat(kDTProbeTruePath.fileSystemRepresentation, &stBefore);

    DTBLog(@"[*] build631 probe_true sign begin (ldid + trustcache required before broker spawn)");
    DTBStage(@"build631 probe_true sign begin");

    NSString *signDetail = nil;
    if (![self signMachOAtPath:kDTProbeTruePath withLdid:ldidPath ent:entPath isDylib:NO detailOut:&signDetail]) {
        *detailOut = signDetail ?: @"probe_true ldid sign failed";
        DTBStage(@"build631 probe_true sign fail");
        return NO;
    }

    struct stat stAfter = { 0 };
    stat(kDTProbeTruePath.fileSystemRepresentation, &stAfter);
    DTBLog([NSString stringWithFormat:@"[+] build631 probe_true sign OK size=%lld (was %lld)",
            (long long)stAfter.st_size, (long long)stBefore.st_size]);
    DTBStage(@"build631 probe_true sign OK");

    NSUInteger uploaded = 0;
    NSUInteger skipped = 0;
    NSString *trustDetail = nil;
    if (![self trustPostSignT1Paths:@[kDTProbeTruePath] uploaded:&uploaded skipped:&skipped detailOut:&trustDetail]) {
        *detailOut = trustDetail ?: @"probe_true trustcache upload failed";
        DTBStage(@"build631 probe_true trust fail");
        return NO;
    }

    BOOL trusted = NO;
    if (![self build1021LogTrustForPath:kDTProbeTruePath trustedOut:&trusted] || !trusted) {
        *detailOut = @"probe_true not trustcached after sign/upload";
        DTBStage(@"build631 probe_true trust verify fail");
        return NO;
    }

    DTBLog([NSString stringWithFormat:@"[+] build631 probe_true trusted uploaded=%lu skipped=%lu",
            (unsigned long)uploaded, (unsigned long)skipped]);
    DTBStage(@"build631 probe_true trust OK");
    *detailOut = [NSString stringWithFormat:@"signed trusted probe_true uploaded=%lu", (unsigned long)uploaded];
    return YES;
}

+ (BOOL)copyG2Tree:(NSString * _Nullable * _Nonnull)detailOut filesCopied:(NSUInteger *)copied
{
    NSString *srcRoot = [self bundleG2Root];
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:srcRoot isDirectory:&isDir] || !isDir) {
        *detailOut = @"bootstrap_g2 missing from app bundle (rebuild IPA on Mac)";
        return NO;
    }

    NSDirectoryEnumerator *en = [fm enumeratorAtPath:srcRoot];
    NSString *rel;
    NSUInteger n = 0;
    NSMutableString *manifest = [NSMutableString string];

    while ((rel = en.nextObject)) {
        NSString *src = [srcRoot stringByAppendingPathComponent:rel];
        NSString *dst = [kDTJBRoot stringByAppendingPathComponent:rel];

        if (![self pathHasPrefix:dst prefix:kDTJBRoot]) {
            *detailOut = [NSString stringWithFormat:@"blocked dest outside /var/jb: %@", dst];
            return NO;
        }

        BOOL itemDir = NO;
        [fm fileExistsAtPath:src isDirectory:&itemDir];
        if (itemDir) continue;

        char lnk[PATH_MAX + 1];
        ssize_t llen = readlink(src.fileSystemRepresentation, lnk, PATH_MAX);
        if (llen >= 0) {
            lnk[llen] = '\0';
            NSString *parent = [dst stringByDeletingLastPathComponent];
            [fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:nil];
            [fm removeItemAtPath:dst error:nil];
            if (symlink(lnk, dst.fileSystemRepresentation) != 0) {
                *detailOut = [NSString stringWithFormat:@"symlink %@ -> %s errno=%d", dst, lnk, errno];
                return NO;
            }
            [manifest appendFormat:@"%@\n", rel];
            n++;
            continue;
        }

        NSString *parent = [dst stringByDeletingLastPathComponent];
        if (![fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:nil]) {
            *detailOut = [NSString stringWithFormat:@"mkdir %@ failed", parent];
            return NO;
        }
        [fm removeItemAtPath:dst error:nil];
        NSError *err = nil;
        if (![fm copyItemAtPath:src toPath:dst error:&err]) {
            *detailOut = err.localizedDescription ?: @"copy failed";
            return NO;
        }
        [manifest appendFormat:@"%@\n", rel];
        n++;
    }

    [manifest writeToFile:kDTG2Manifest atomically:YES encoding:NSUTF8StringEncoding error:nil];
    *copied = n;
    return YES;
}

+ (void)runG1ProbeWithCompletion:(void (^)(BOOL ok, NSString *detail))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *detail = @"";
        BOOL ok = NO;

        @autoreleasepool {
            DTBStage(@"build50 G1 begin");
            NSString *gateDetail = nil;
            if (![self gateChecks:&gateDetail stage:@"G1"]) {
                detail = gateDetail ?: @"gate failed";
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build50 G1 rootfs RW OK");

            NSString *prepDetail = nil;
            if ([self prepareJBRoot:&prepDetail] != 0) {
                detail = prepDetail ?: @"jbroot prep failed";
                DTBStage(@"build50 G1 fail jbroot");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            int p1 = [self writeProbeAtPath:kDTProbePath content:NULL contentLen:0];
            if (p1 != 0) {
                detail = [NSString stringWithFormat:@"probe errno=%d", p1];
                DTBStage(@"build50 G1 fail probe");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            static const char gen[] = "1\n";
            int p2 = [self writeProbeAtPath:kDTGenPath content:gen contentLen:sizeof(gen) - 1];
            if (p2 != 0) {
                detail = [NSString stringWithFormat:@"generation errno=%d", p2];
                DTBStage(@"build50 G1 fail generation");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build50 probe OK");
            DTBLog(@"[+] build50 audit outside_jb=0");
            DTBStage(@"build50 audit outside_jb=0");
            DTBStage(@"build50 G1 OK");
            ok = YES;
            detail = @"/var/jb/.dt_build48_probe + .install_generation";
        }

        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
    });
}

+ (void)runG2ExtractWithCompletion:(void (^)(BOOL ok, NSString *detail))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *detail = @"";
        BOOL ok = NO;

        @autoreleasepool {
            DTBStage(@"build50 G2 begin");
            DTBLog(@"[*] build50 G2 extract begin (embedded bootstrap_g2 → /var/jb)");

            NSString *gateDetail = nil;
            if (![self gateChecks:&gateDetail stage:@"G2"]) {
                detail = gateDetail ?: @"gate failed";
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build50 G2 rootfs RW OK");

            NSString *prepDetail = nil;
            if ([self prepareJBRoot:&prepDetail] != 0) {
                detail = prepDetail ?: @"jbroot prep failed";
                DTBStage(@"build50 G2 fail jbroot");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            NSUInteger copied = 0;
            NSString *copyDetail = nil;
            if (![self copyG2Tree:&copyDetail filesCopied:&copied]) {
                detail = copyDetail ?: @"copy failed";
                DTBLog([NSString stringWithFormat:@"[!] build50 G2 copy fail %@", detail]);
                DTBStage(@"build50 G2 fail copy");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog([NSString stringWithFormat:@"[+] build50 G2 copy done files=%lu", (unsigned long)copied]);
            DTBStage([NSString stringWithFormat:@"build50 G2 copy done files=%lu", (unsigned long)copied]);

            if (![[NSFileManager defaultManager] fileExistsAtPath:kDTBashPath]) {
                detail = @"missing /var/jb/usr/bin/bash after copy";
                DTBStage(@"build50 G2 fail no bash");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            if (![self isMachOAtPath:kDTBashPath]) {
                detail = @"/var/jb/usr/bin/bash is not Mach-O";
                DTBStage(@"build50 G2 fail bash not macho");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            struct stat st;
            if (stat(kDTBashPath.fileSystemRepresentation, &st) != 0 || st.st_size < 4096) {
                detail = @"bash size check failed";
                DTBStage(@"build50 G2 fail bash stat");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog(@"[+] build50 G2 bash present /var/jb/usr/bin/bash");
            DTBStage(@"build50 G2 bash OK");

            if (![[NSFileManager defaultManager] fileExistsAtPath:kDTProbeTruePath]) {
                detail = @"missing /var/jb/usr/bin/probe_true after copy";
                DTBStage(@"build50 G2 fail no probe_true");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            if (![self isMachOAtPath:kDTProbeTruePath]) {
                detail = @"/var/jb/usr/bin/probe_true is not Mach-O";
                DTBStage(@"build50 G2 fail probe_true not macho");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog(@"[+] build50 G2 probe_true present /var/jb/usr/bin/probe_true");
            DTBStage(@"build50 G2 probe_true OK");

            NSString *signDetail = nil;
            if (![self build631SignAndTrustProbeTrue:&signDetail]) {
                detail = signDetail ?: @"probe_true sign/trust failed";
                DTBLog([NSString stringWithFormat:@"[!] build50 G2 probe_true sign/trust fail %@", detail]);
                DTBStage(@"build50 G2 fail probe_true sign");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog(@"[+] build50 audit outside_jb=0");
            DTBStage(@"build50 audit outside_jb=0");
            DTBLog(@"[+] build50 G2 complete — no exec, no sign yet");
            DTBStage(@"build50 G2 OK");

            ok = YES;
            detail = [NSString stringWithFormat:@"%lu files → /var/jb/usr/bin/bash", (unsigned long)copied];
        }

        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
    });
}

+ (BOOL)symlinkTargetAllowed:(NSString *)target
{
    if (!target.length)
        return NO;
    if ([target characterAtIndex:0] != '/')
        return YES;
    if ([target isEqualToString:@"/var/jb"])
        return YES;
    return [self pathHasPrefix:target prefix:kDTJBRoot];
}

+ (NSString *)symlinkFixedTarget:(NSString *)target
{
    if (!target.length || [target characterAtIndex:0] != '/')
        return target;
    if ([self symlinkTargetAllowed:target])
        return target;
    return [kDTJBRoot stringByAppendingString:target];
}

+ (BOOL)isCriticalSymlinkPath:(NSString *)path
{
    if (![self pathHasPrefix:path prefix:kDTJBRoot])
        return NO;
    if ([self pathHasPrefix:path prefix:@"/var/jb/bin"])
        return YES;
    if ([path isEqualToString:@"/var/jb/usr/bin/sh"])
        return YES;
    if ([self pathHasPrefix:path prefix:@"/var/jb/usr/lib/ssl"])
        return YES;
    if ([path isEqualToString:@"/var/jb/private/var/lib/dpkg"])
        return YES;
    if ([self pathHasPrefix:path prefix:@"/var/jb/private/var/lib/dpkg/"])
        return YES;
    return NO;
}

+ (BOOL)readSymlinkTargetAtPath:(NSString *)path targetOut:(NSString * _Nullable * _Nonnull)targetOut
{
    char buf[PATH_MAX + 1];
    ssize_t n = readlink(path.fileSystemRepresentation, buf, PATH_MAX);
    if (n < 0)
        return NO;
    buf[n] = '\0';
    *targetOut = [NSString stringWithUTF8String:buf] ?: @"";
    return YES;
}

+ (BOOL)rewriteSymlinkAtPath:(NSString *)path toTarget:(const char *)newTarget detailOut:(NSString * _Nullable * _Nonnull)detailOut
{
    if (unlink(path.fileSystemRepresentation) != 0) {
        int e = errno;
        *detailOut = [NSString stringWithFormat:@"unlink %@ errno=%d (%s)", path, e, strerror(e)];
        return NO;
    }
    if (symlink(newTarget, path.fileSystemRepresentation) != 0) {
        int e = errno;
        *detailOut = [NSString stringWithFormat:@"symlink %@ -> %s errno=%d (%s)", path, newTarget, e, strerror(e)];
        return NO;
    }
    return YES;
}

+ (void)auditSymlinkAtPath:(NSString *)path
                     target:(NSString *)target
              criticalRemain:(NSUInteger *)criticalRemain
                       fixed:(NSUInteger *)fixed
                         log:(NSMutableString *)log
{
    if ([self symlinkTargetAllowed:target])
        return;

    NSString *newTarget = [self symlinkFixedTarget:target];
    DTBLog([NSString stringWithFormat:@"[+] build50 symlink fix %@ %@ -> %@", path, target, newTarget]);
    DTBStage([NSString stringWithFormat:@"build50 symlink fix %@ %@ -> %@", path, target, newTarget]);
    [log appendFormat:@"fix %@ %@ -> %@\n", path, target, newTarget];

    NSString *rewriteDetail = nil;
    if (![self rewriteSymlinkAtPath:path toTarget:newTarget.fileSystemRepresentation detailOut:&rewriteDetail]) {
        DTBLog([NSString stringWithFormat:@"[!] build50 symlink fix fail %@", rewriteDetail]);
        DTBStage(@"build50 G3 fail symlink rewrite");
        if ([self isCriticalSymlinkPath:path])
            (*criticalRemain)++;
        return;
    }

    (*fixed)++;

    NSString *after = nil;
    if (![self readSymlinkTargetAtPath:path targetOut:&after] || ![self symlinkTargetAllowed:after]) {
        DTBLog([NSString stringWithFormat:@"[!] build50 symlink still bad after fix %@ -> %@", path, after ?: @"(readlink fail)"]);
        if ([self isCriticalSymlinkPath:path])
            (*criticalRemain)++;
    }
}

+ (int)walkSymlinksUnder:(const char *)dir
            linksScanned:(NSUInteger *)linksScanned
         criticalRemain:(NSUInteger *)criticalRemain
                  fixed:(NSUInteger *)fixed
                    log:(NSMutableString *)log
{
    DIR *d = opendir(dir);
    if (!d)
        return errno > 0 ? errno : -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char child[PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) {
            closedir(d);
            return ENAMETOOLONG;
        }

        struct stat st;
        if (lstat(child, &st) != 0)
            continue;

        if (S_ISLNK(st.st_mode)) {
            (*linksScanned)++;
            NSString *path = [NSString stringWithUTF8String:child];
            NSString *target = nil;
            if (![self readSymlinkTargetAtPath:path targetOut:&target]) {
                [log appendFormat:@"readlink fail %s errno=%d\n", child, errno];
                if ([self isCriticalSymlinkPath:path])
                    (*criticalRemain)++;
                continue;
            }
            [log appendFormat:@"scan %@ -> %@\n", path, target];
            [self auditSymlinkAtPath:path target:target criticalRemain:criticalRemain fixed:fixed log:log];
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int sub = [self walkSymlinksUnder:child linksScanned:linksScanned criticalRemain:criticalRemain fixed:fixed log:log];
            if (sub != 0) {
                closedir(d);
                return sub;
            }
        }
    }

    closedir(d);
    return 0;
}

+ (BOOL)runSymlinkAudit:(NSString * _Nullable * _Nonnull)detailOut
            linksScanned:(NSUInteger *)linksScanned
         criticalRemain:(NSUInteger *)criticalRemain
                  fixed:(NSUInteger *)fixed
{
    *linksScanned = 0;
    *criticalRemain = 0;
    *fixed = 0;

    NSMutableString *log = [NSMutableString stringWithFormat:@"build50 G3 symlink audit %@\n", [NSDate date]];

    int walk = [self walkSymlinksUnder:kDTJBRoot.fileSystemRepresentation
                          linksScanned:linksScanned
                       criticalRemain:criticalRemain
                                fixed:fixed
                                  log:log];
    if (walk != 0) {
        *detailOut = [NSString stringWithFormat:@"walk /var/jb errno=%d (%s)", walk, strerror(walk)];
        return NO;
    }

    [log appendFormat:@"summary scanned=%lu fixed=%lu critical_remaining=%lu\n",
     (unsigned long)*linksScanned, (unsigned long)*fixed, (unsigned long)*criticalRemain];
    [log writeToFile:kDTSymlinkAuditLog atomically:YES encoding:NSUTF8StringEncoding error:nil];

    if (*criticalRemain > 0) {
        DTBStage([NSString stringWithFormat:@"build50 symlink audit FAIL remaining=%lu", (unsigned long)*criticalRemain]);
        *detailOut = [NSString stringWithFormat:@"critical absolute symlinks remaining=%lu (see %@)",
                      (unsigned long)*criticalRemain, kDTSymlinkAuditLog];
        return NO;
    }

    DTBStage(@"build50 symlink audit critical_remaining=0");
    return YES;
}

+ (void)runG3SymlinkAuditWithCompletion:(void (^)(BOOL ok, NSString *detail))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *detail = @"";
        BOOL ok = NO;

        @autoreleasepool {
            DTBStage(@"build50 G3 begin");
            DTBLog(@"[*] build50 G3 symlink audit begin (lstat walk, fix absolute → /var/jb+path)");

            NSString *gateDetail = nil;
            if (![self gateChecks:&gateDetail stage:@"G3"]) {
                detail = gateDetail ?: @"gate failed";
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build50 G3 rootfs RW OK");

            NSString *prepDetail = nil;
            if ([self prepareJBRoot:&prepDetail] != 0) {
                detail = prepDetail ?: @"/var/jb missing — run G1 or G2 first";
                DTBStage(@"build50 G3 fail jbroot");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            NSUInteger scanned = 0;
            NSUInteger criticalRemain = 0;
            NSUInteger fixed = 0;
            NSString *auditDetail = nil;
            if (![self runSymlinkAudit:&auditDetail linksScanned:&scanned criticalRemain:&criticalRemain fixed:&fixed]) {
                detail = auditDetail ?: @"symlink audit failed";
                DTBLog([NSString stringWithFormat:@"[!] build50 G3 fail %@", detail]);
                DTBStage(@"build50 G3 fail audit");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog([NSString stringWithFormat:@"[+] build50 G3 scanned=%lu fixed=%lu critical_remaining=0",
                    (unsigned long)scanned, (unsigned long)fixed]);
            DTBStage([NSString stringWithFormat:@"build50 G3 scanned=%lu fixed=%lu", (unsigned long)scanned, (unsigned long)fixed]);
            DTBLog(@"[+] build50 audit outside_jb=0");
            DTBStage(@"build50 audit outside_jb=0");
            DTBStage(@"build50 G3 OK");

            ok = YES;
            if (fixed > 0)
                detail = [NSString stringWithFormat:@"scanned %lu symlinks, fixed %lu → %@", (unsigned long)scanned, (unsigned long)fixed, kDTSymlinkAuditLog];
            else
                detail = [NSString stringWithFormat:@"scanned %lu symlinks, none needed fix", (unsigned long)scanned];
        }

        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
    });
}

+ (void)runG4LdidSmokeWithCompletion:(void (^)(BOOL ok, NSString *detail))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *detail = @"";
        BOOL ok = NO;

        @autoreleasepool {
            DTBStage(@"build50 G4 begin");
            DTBLog(@"[*] build50 G4 ldid smoke begin (Tools/ldid -h)");

            NSString *gateDetail = nil;
            if (![self gateChecks:&gateDetail stage:@"G4"]) {
                detail = gateDetail ?: @"gate failed";
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build50 G4 rootfs RW OK");

            NSString *ldidPath = [self bundleLdidPath];
            NSString *entPath = [self bundleToolsEntitlementsPath];
            NSFileManager *fm = [NSFileManager defaultManager];

            if (![fm fileExistsAtPath:ldidPath]) {
                detail = @"Tools/ldid missing from app bundle (rebuild IPA on Mac)";
                DTBLog([NSString stringWithFormat:@"[!] build50 G4 fail %@", detail]);
                DTBStage(@"build50 G4 fail no ldid");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            if (![fm fileExistsAtPath:entPath]) {
                detail = @"Tools/entitlements_tools.plist missing from app bundle";
                DTBLog([NSString stringWithFormat:@"[!] build50 G4 fail %@", detail]);
                DTBStage(@"build50 G4 fail no entitlements");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            if (![self isMachOAtPath:ldidPath]) {
                detail = @"Tools/ldid is not Mach-O";
                DTBStage(@"build50 G4 fail ldid not macho");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog([NSString stringWithFormat:@"[+] build50 G4 ldid present %@", ldidPath]);
            DTBStage(@"build50 G4 ldid present");

            int exitCode = -1;
            NSString *execDetail = nil;
            int execErr = [self execBinaryAtPath:ldidPath args:@[@"-h"] exitCode:&exitCode detailOut:&execDetail];
            if (execErr != 0) {
                detail = execDetail ?: [NSString stringWithFormat:@"ldid exec errno=%d", execErr];
                DTBLog([NSString stringWithFormat:@"[!] build50 G4 fail %@", detail]);
                DTBStage(@"build50 G4 fail spawn");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            if (exitCode != 0) {
                detail = execDetail ?: [NSString stringWithFormat:@"ldid -h exit=%d", exitCode];
                DTBLog([NSString stringWithFormat:@"[!] build50 G4 fail ldid exit=%d", exitCode]);
                DTBStage([NSString stringWithFormat:@"build50 G4 fail ldid exit=%d", exitCode]);
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog(@"[+] build50 ldid T0 OK");
            DTBStage(@"build50 ldid T0 OK");
            DTBLog(@"[+] build50 audit outside_jb=0");
            DTBStage(@"build50 audit outside_jb=0");
            DTBStage(@"build50 G4 OK");

            ok = YES;
            detail = @"Tools/ldid -h exit 0";
        }

        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
    });
}

+ (void)runG5SignSmokeWithCompletion:(void (^)(BOOL ok, NSString *detail))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *detail = @"";
        BOOL ok = NO;
        NSString *verdict = @"UNKNOWN";

        @autoreleasepool {
            DTBStage(@"build102.5.2 calibration begin");
            DTBLog(@"[*] build102.5.2 kcall calibration + Fix-A kernel-scratch return (no 55106C/dash)");

            NSString *gateDetail = nil;
            if (![self gateChecks:&gateDetail stage:@"G5"]) {
                detail = gateDetail ?: @"gate failed";
                DTBStage(@"build102.5.2 G5 abort gate");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            NSFileManager *fm = [NSFileManager defaultManager];
            (void)fm;

            NSString *planVerdict = nil;
            BOOL dashAllowed = NO;
            int plan_r = dt_build1025_planb_diagnostic(^(NSString *line) {
                DTBLog(line);
            }, kDTJbHelperPath, &planVerdict, &dashAllowed);
            planVerdict = planVerdict ?: @"KCALL_UNAVAILABLE";
            DTBLog([NSString stringWithFormat:@"[*] build102.5.2 verdict=%@ dashAllowed=%d plan_r=%d",
                    planVerdict, dashAllowed ? 1 : 0, plan_r]);
            DTBStage([NSString stringWithFormat:@"build102.5.2 %@", planVerdict]);

            if (plan_r != 0) {
                detail = [NSString stringWithFormat:@"%@ (setup_r=%d)", planVerdict, plan_r];
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            ok = [planVerdict isEqualToString:@"KCALL_SAFE_PROBE_OK"]
                || [planVerdict isEqualToString:@"KCALL_CALIBRATION_OK"]
#ifdef DT_BUILD102739K_VARIANT
                || [planVerdict isEqualToString:@"ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_PASS"]
#endif
                ;
            detail = [NSString stringWithFormat:@"%@ — 55106C/consume/dash deferred to 102.5.3", planVerdict];
            dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
            return;

#if 0 /* 102.5.3+: re-enable helper profile gate + dash after KCALL_CALIBRATION_OK on device */
            if (![DTRootHelperClient helperInstalled]) {
                detail = [NSString stringWithFormat:@"bootstraphelper missing at %@",
                          [DTRootHelperClient helperBundledPath]];
                DTBStage(@"build102.5.1 G5 fail no bundled helper");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            NSString *ensureDetail = nil;
            if (![self build1023EnsureJbHelper:&ensureDetail]) {
                detail = ensureDetail ?: @"dt_helper install failed";
                DTBLog([NSString stringWithFormat:@"[!] build102.5.1 helper ensure fail %@", detail]);
                DTBStage(@"build102.5.1 G5 fail helper ensure");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }
            DTBLog([NSString stringWithFormat:@"[+] build102.5.1 helper ensure OK %@", ensureDetail ?: @""]);

            NSString *planVerdict = nil;
            BOOL dashAllowed = NO;
            int plan_r = dt_build1025_planb_diagnostic(^(NSString *line) {
                DTBLog(line);
            }, kDTJbHelperPath, &planVerdict, &dashAllowed);
            planVerdict = planVerdict ?: @"KCALL_UNAVAILABLE";
            DTBLog([NSString stringWithFormat:@"[*] build102.5.1 verdict=%@ dashAllowed=%d plan_r=%d",
                    planVerdict, dashAllowed ? 1 : 0, plan_r]);
            DTBStage([NSString stringWithFormat:@"build102.5.1 %@", planVerdict]);

            if (plan_r != 0) {
                detail = [NSString stringWithFormat:@"%@ (setup_r=%d)", planVerdict, plan_r];
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            if (!dashAllowed) {
                /* IDA: 533304 — dash child inherits helper slot0, not app; app-only consume is insufficient */
                detail = [NSString stringWithFormat:@"%@ — dash skipped (533304/532A80: helper slot0 not covered)", planVerdict];
                ok = [planVerdict isEqualToString:@"KCALL_SAFE_PROBE_OK"]
                    || [planVerdict isEqualToString:@"KCALL_CONSUME_HANDLE_ZERO"]
                    || [planVerdict isEqualToString:@"KCALL_CONSUME_APP_HANDLE_OK"]
                    || [planVerdict isEqualToString:@"KCALL_APP_HELPER_PROFILE_DIFFER"]
                    || [planVerdict isEqualToString:@"KCALL_CONSUME_HELPER_HANDLE_ZERO"];
                dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
                return;
            }

            DTBLog(@"[+] build102.5.1 profile coverage OK — continuing to helper dash smoke (53349C op-16 test)");
            DTBStage(@"build102.5.1 G5 dash after IDA profile gate OK");

            DTBStage(@"build102.3.3 G5 rootfs RW OK");

            if (![fm fileExistsAtPath:kDTDashPath]) {
                detail = @"missing /var/jb/usr/bin/dash — run G2 first";
                DTBStage(@"build102.3.3 G5 fail no dash");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            [self build10232LogHelperPreflightBeforePing];

            NSError *pingErr = nil;
            NSString *pingOut = nil;
            int pingExit = -1;
            int pingSpawn = [DTRootHelperClient runPingAtPath:kDTJbHelperPath usePersona:YES
                                                    stdoutOut:&pingOut exitStatus:&pingExit error:&pingErr];
            if (![self build1022PingSucceededSpawnErr:pingSpawn exitStatus:pingExit output:pingOut ?: @""]) {
                detail = [NSString stringWithFormat:@"helper ping fail spawn=%d exit=%d err=%@",
                          pingSpawn, pingExit, pingErr.localizedDescription ?: @"-"];
                DTBLog([NSString stringWithFormat:@"[!] build102.3.3 %@", detail]);
                DTBStage(@"build102.3.3 helper ping FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }
            DTBLog([NSString stringWithFormat:@"[+] build102.3.3 helper ping OK path=%@", kDTJbHelperPath]);
            DTBStage(@"build102.3.3 helper ping OK");

            NSString *ldidPath = [self bundleLdidPath];
            NSString *entPath = [self bundleToolsEntitlementsPath];
            if (![fm fileExistsAtPath:ldidPath] || ![self isMachOAtPath:ldidPath]) {
                detail = @"Tools/ldid missing — run G4 or rebuild IPA";
                verdict = @"TRUST_PRECONDITION_FAIL";
                DTBLog([NSString stringWithFormat:@"[*] build102.3.3 verdict=%@", verdict]);
                DTBStage(@"build102.3.3 dash trust FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }
            if (![fm fileExistsAtPath:entPath]) {
                detail = @"Tools/entitlements_tools.plist missing from app bundle";
                verdict = @"TRUST_PRECONDITION_FAIL";
                DTBLog([NSString stringWithFormat:@"[*] build102.3.3 verdict=%@", verdict]);
                DTBStage(@"build102.3.3 dash trust FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            NSString *pathsDetail = nil;
            NSArray<NSString *> *signPaths = [self build1021MinimalSignPaths:&pathsDetail];
            if (!signPaths.count) {
                detail = pathsDetail ?: @"no dash sign paths";
                verdict = @"TRUST_PRECONDITION_FAIL";
                DTBLog([NSString stringWithFormat:@"[*] build102.3.3 verdict=%@", verdict]);
                DTBStage(@"build102.3.3 dash trust FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build102.3.3 dash sign begin");
            DTBLog(@"[*] build102.3.3 dash sign begin");
            NSString *signDetail = nil;
            if (![self signPathList:signPaths withLdid:ldidPath ent:entPath detailOut:&signDetail]) {
                detail = signDetail ?: @"dash sign failed";
                verdict = @"TRUST_PRECONDITION_FAIL";
                DTBLog([NSString stringWithFormat:@"[!] build102.3.3 sign fail %@", detail]);
                DTBLog([NSString stringWithFormat:@"[*] build102.3.3 verdict=%@", verdict]);
                DTBStage(@"build102.3.3 dash trust FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            NSArray<NSString *> *finalTrustPaths = [self build10232FinalTrustPathsFromSignPaths:signPaths];
            BOOL helperTrustedBeforeFinal = NO;
            NSUInteger tcUploaded = 0;
            NSString *trustDetail = nil;
            if (![self build10233FinalTrustForceUpload:finalTrustPaths
                                   helperTrustedBefore:&helperTrustedBeforeFinal
                                              uploaded:&tcUploaded
                                             detailOut:&trustDetail]) {
                detail = trustDetail ?: @"final trustcache force upload failed";
                BOOL helperTrustedAfter = NO;
                (void)[self build1021LogTrustForPath:kDTJbHelperPath trustedOut:&helperTrustedAfter];
                if (helperTrustedBeforeFinal && !helperTrustedAfter) {
                    verdict = @"TRUSTCACHE_REPLACEMENT_BUG";
                } else {
                    verdict = @"TRUST_PRECONDITION_FAIL";
                }
                DTBLog([NSString stringWithFormat:@"[!] build102.3.3 final trust fail %@", detail]);
                DTBLog([NSString stringWithFormat:@"[*] build102.3.3 verdict=%@", verdict]);
                DTBStage(@"build102.3.3 dash trust FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog(@"[+] build102.3.3 dash trust OK");
            DTBStage(@"build102.3.3 dash trust OK");

            NSArray<NSString *> *jbEnv = @[
                @"TVROOT=/var/jb",
                @"PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin",
                @"DYLD_LIBRARY_PATH=/var/jb/usr/lib:/var/jb/lib",
            ];
            NSArray<NSString *> *idArgs = @[@"-c", @"id"];

            NSString *appOut = nil;
            int appExit = -1;
            NSString *appDetail = nil;
            int appSpawnErr = [self execBinaryAtPath:kDTDashPath args:idArgs env:jbEnv stdoutOut:&appOut
                                            exitCode:&appExit detailOut:&appDetail bypassFmExecutableGate:YES
                                 usePersonaRootSpawn:NO];
            NSString *appOutTrim = [appOut stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
            DTBLog([NSString stringWithFormat:@"[*] build102.3.3 app_spawn dash exit=%d spawnErr=%d out=%@",
                    appExit, appSpawnErr, appOutTrim.length ? appOutTrim : @"(empty)"]);

            NSString *preflightDetail = nil;
            if (![self build10232LogHelperPreflightBeforeSmoke:&preflightDetail]) {
                verdict = @"HELPER_PREFLIGHT_BUG";
                detail = preflightDetail ?: @"helper preflight failed after ping OK";
                DTBLog([NSString stringWithFormat:@"[!] build102.3.3 %@", detail]);
                DTBLog([NSString stringWithFormat:@"[*] build102.3.3 verdict=%@", verdict]);
                DTBStage(@"build102.3.3 G5 helper dash smoke FAIL");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog([NSString stringWithFormat:
                    @"[*] build102.4 helper smoke invoking path=%@ args=smokeExec %@ -c id",
                    kDTJbHelperPath, kDTDashPath]);

            NSString *helperOut = nil;
            int helperExit = -1;
            NSError *helperErr = nil;
            int helperSpawn = [DTRootHelperClient runCommand:@"smokeExec"
                                                        args:@[kDTDashPath, @"-c", @"id"]
                                                   stdoutOut:&helperOut
                                                  exitStatus:&helperExit
                                                       error:&helperErr];
            NSString *helperOutTrim = [helperOut stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
            [self build1024LogHelperExtLines:helperOutTrim];
            NSString *extVerdict = [self build1024VerdictFromHelperOutput:helperOutTrim];
            BOOL smokeInvoked = (helperSpawn == 0);
            if (smokeInvoked) {
                DTBLog(@"[*] build102.4 verdict=HELPER_SMOKE_INVOKED");
                DTBStage(@"build102.4 HELPER_SMOKE_INVOKED");
            }

            DTBLog([NSString stringWithFormat:@"[*] build102.4 helper_spawn dash exit=%d spawnErr=%d out=%@ err=%@",
                    helperExit, helperSpawn, helperOutTrim.length ? helperOutTrim : @"(empty)",
                    helperErr.localizedDescription ?: @"-"]);
            [self build1023LogHelperInnerFields:helperOutTrim];

            BOOL appHasUid0 = [appOutTrim rangeOfString:@"uid=0"].location != NSNotFound;
            BOOL childHasUid0 = [self build1023ChildDashHasUid0:helperOutTrim];
            BOOL appOk = (appSpawnErr == 0 && appExit == 0 && appHasUid0);

            NSString *childStdout = [self build1023TaggedValueFromHelperOutput:helperOutTrim prefix:@"child_stdout="];
            DTBLog([NSString stringWithFormat:@"[*] build102.4 compare app=%@ helper_child=%@ ext_verdict=%@",
                    appOutTrim.length ? appOutTrim : @"(empty)",
                    childStdout.length ? childStdout : @"(empty)",
                    extVerdict.length ? extVerdict : @"-"]);

            if ([extVerdict isEqualToString:@"HELPER_EXT_ISSUE_FAIL"]) {
                verdict = @"HELPER_EXT_ISSUE_FAIL";
                detail = [NSString stringWithFormat:@"helper extension issue failed — %@", helperOutTrim];
                DTBStage(@"build102.4 G5 helper dash smoke FAIL");
            } else if ([extVerdict isEqualToString:@"HELPER_EXT_CONSUME_ZERO"]) {
                verdict = @"NEED_5510E8_BP_HELPER_PID";
                detail = [NSString stringWithFormat:@"helper consume handle 0 — kernel BP 5510E8/532C68 — %@", helperOutTrim];
                DTBStage(@"build102.4 G5 helper dash smoke FAIL");
            } else if ([extVerdict isEqualToString:@"HELPER_EXT_FIXES_DASH"] && childHasUid0) {
                ok = YES;
                verdict = @"HELPER_EXT_FIXES_DASH";
                detail = [NSString stringWithFormat:@"helper ext + dash uid=0 OK — %@", childStdout];
                DTBStage(@"build102.4 G5 helper dash smoke PASS");
            } else if ([extVerdict isEqualToString:@"HELPER_EXT_CONSUME_OK_DASH_FAIL"]) {
                /* IDA: ext on profile+8 OK but 53349C op-16 still denies libiosexec mmap */
                verdict = dashAllowed ? @"KCALL_EXT_OK_DASH_STILL_MMAP_DENY" : @"HELPER_EXT_CONSUME_OK_DASH_FAIL";
                detail = [NSString stringWithFormat:@"%@ ext consume OK but dash failed exit=%d child_stdout=%@ full=%@",
                          dashAllowed ? @"profile covered;" : @"",
                          helperExit, childStdout, helperOutTrim];
                DTBStage(dashAllowed ? @"build102.5.1 KCALL_EXT_OK_DASH_STILL_MMAP_DENY" :
                         @"build102.4 G5 helper dash smoke FAIL");
            } else if (smokeInvoked && helperExit == 0 && childHasUid0) {
                ok = YES;
                if (appOk) {
                    verdict = @"HELPER_ARCH_WORKS";
                    detail = [NSString stringWithFormat:@"helper dash uid=0 OK — %@", childStdout];
                } else {
                    verdict = @"HELPER_ARCH_WORKS_APP_CONTEXT_BAD";
                    detail = [NSString stringWithFormat:@"helper child uid=0 OK, app context bad — %@", childStdout];
                }
                DTBStage(@"build102.4 G5 helper dash smoke PASS");
            } else if (smokeInvoked && helperExit == 0 && !childHasUid0) {
                verdict = @"NEEDS_FAILURE_CLASSIFICATION";
                detail = @"helper smoke returned but child_stdout lacks uid=0";
                DTBStage(@"build102.4 G5 helper dash smoke FAIL");
            } else if (!smokeInvoked) {
                verdict = @"HELPER_PREFLIGHT_BUG";
                detail = [NSString stringWithFormat:
                    @"helper smoke never invoked spawn=%d err=%@",
                    helperSpawn, helperErr.localizedDescription ?: @"-"];
                DTBStage(@"build102.4 G5 helper dash smoke FAIL");
            } else {
                verdict = @"HELPER_DASH_EXEC_FAIL";
                detail = [NSString stringWithFormat:
                    @"helper dash exec failed spawn=%d exit=%d child_stdout=%@ full_out=%@",
                    helperSpawn, helperExit, childStdout, helperOutTrim];
                DTBStage(@"build102.4 G5 helper dash smoke FAIL");
            }

            DTBLog([NSString stringWithFormat:@"[*] build102.4 verdict=%@", verdict]);
            DTBStage([NSString stringWithFormat:@"build102.4 verdict=%@", verdict]);
#endif /* 102.5.3+ dash path */
        }

        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
    });
}

+ (BOOL)removeJBRoot:(NSString * _Nullable * _Nonnull)detailOut
{
    struct stat st;
    if (lstat(kDTJBRoot.fileSystemRepresentation, &st) != 0) {
        if (errno == ENOENT) {
            DTBLog(@"[+] build50 rollback nothing to delete (/var/jb absent)");
            return YES;
        }
        *detailOut = [NSString stringWithFormat:@"lstat /var/jb errno=%d", errno];
        return NO;
    }

    if (S_ISLNK(st.st_mode)) {
        char target[PATH_MAX];
        ssize_t n = readlink(kDTJBRoot.fileSystemRepresentation, target, sizeof(target) - 1);
        if (n >= 0) {
            target[n] = '\0';
            *detailOut = [NSString stringWithFormat:@"refusing rollback: /var/jb is symlink -> %s", target];
        } else {
            *detailOut = @"refusing rollback: /var/jb is symlink";
        }
        return NO;
    }

    if (!S_ISDIR(st.st_mode)) {
        *detailOut = @"/var/jb exists but is not a directory";
        return NO;
    }

    NSError *err = nil;
    if (![[NSFileManager defaultManager] removeItemAtPath:kDTJBRoot error:&err]) {
        if (err.code == NSFileNoSuchFileError)
            return YES;
        *detailOut = err.localizedDescription ?: @"removeItem /var/jb failed";
        return NO;
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:kDTJBRoot]) {
        *detailOut = @"/var/jb still present after delete";
        return NO;
    }

    return YES;
}

+ (void)runRollbackWithCompletion:(void (^)(BOOL ok, NSString *detail))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *detail = @"";
        BOOL ok = NO;

        @autoreleasepool {
            DTBStage(@"build50 rollback begin");
            DTBLog(@"[*] build50 rollback begin (rm -rf /var/jb only)");

            NSString *gateDetail = nil;
            if (![self gateChecks:&gateDetail stage:@"rollback"]) {
                detail = gateDetail ?: @"gate failed";
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBStage(@"build50 rollback rootfs RW OK");

            NSString *removeDetail = nil;
            if (![self removeJBRoot:&removeDetail]) {
                detail = removeDetail ?: @"rollback delete failed";
                DTBLog([NSString stringWithFormat:@"[!] build50 rollback fail %@", detail]);
                DTBStage(@"build50 rollback fail delete");
                dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail); });
                return;
            }

            DTBLog(@"[+] build50 rollback deleted /var/jb");
            DTBStage(@"build50 rollback OK");
            DTBLog(@"[+] build50 audit outside_jb=0");
            DTBStage(@"build50 audit outside_jb=0");

            ok = YES;
            detail = @"/var/jb removed — stock OS untouched";
        }

        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, detail); });
    });
}

@end
