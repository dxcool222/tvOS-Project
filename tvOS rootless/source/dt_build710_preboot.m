#import "dt_build710_preboot.h"
#import "DTRunLogger.h"
#import "dt_physrw.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit.h"

#import <CommonCrypto/CommonCrypto.h>
#import <IOKit/IOKitLib.h>
#import <codesign.h>
#import <errno.h>
#import <kernel.h>
#import <limits.h>
#import <primitives.h>
#import <string.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <unistd.h>

#ifndef kIOMainPortDefault
#define kIOMainPortDefault kIOMasterPortDefault
#endif

static NSString *const kDT710ExperimentDir = @"dopamin-tvos-102710";
static NSString *const kDT710ProcursusDir = @"procursus";
static NSString *const kDT710BasebinDir = @"basebin";
static NSString *const kDT710HandoffDir = @"Handoff516";
static NSString *const kDT710HookName = @"launchdhook516.dylib";
static NSString *const kDT710LibjailbreakName = @"libjailbreak.dylib";
static NSString *const kDT710LibchomaName = @"libchoma.dylib";
static NSString *const kDT710SystemhookName = @"systemhook.dylib";

typedef void (^dt710_log_fn)(NSString *line);

static void dt710_log(dt710_log_fn log, NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt710_emit(dt710_log_fn log, NSString *marker)
{
    dt710_log(log, marker);
    [[DTRunLogger shared] logStage:marker];
}

static NSString *dt710_hex_for_bytes(const UInt8 *bytes, CFIndex length)
{
    if (!bytes || length <= 0)
        return nil;

    NSMutableString *hex = [NSMutableString stringWithCapacity:(NSUInteger)length * 2];
    static const char *digits = "0123456789ABCDEF";
    for (CFIndex i = 0; i < length; i++) {
        unsigned char b = bytes[i];
        [hex appendFormat:@"%c%c", digits[(b >> 4) & 0xF], digits[b & 0xF]];
    }
    return hex;
}

static NSString *dt710_boot_manifest_hash_string(void)
{
    static NSString *hash = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
        if (!chosen)
            return;

        CFTypeRef prop = IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"),
            kCFAllocatorDefault, 0);
        IOObjectRelease(chosen);
        if (!prop)
            return;

        if (CFGetTypeID(prop) == CFDataGetTypeID()) {
            CFDataRef data = (CFDataRef)prop;
            hash = [dt710_hex_for_bytes(CFDataGetBytePtr(data), CFDataGetLength(data)) copy];
        } else if (CFGetTypeID(prop) == CFStringGetTypeID()) {
            hash = [(__bridge NSString *)prop copy];
        }
        CFRelease(prop);
    });
    return hash;
}

BOOL dt710_copy_boot_manifest_hash(char *out, size_t outSize)
{
    if (!out || outSize == 0)
        return NO;
    out[0] = 0;

    NSString *hash = dt710_boot_manifest_hash_string();
    if (!hash.length)
        return NO;

    const char *utf8 = hash.UTF8String;
    if (!utf8 || strlen(utf8) + 1 > outSize)
        return NO;
    strlcpy(out, utf8, outSize);
    return YES;
}

NSString *dt710_resolve_active_preboot_path(void)
{
    NSString *hash = dt710_boot_manifest_hash_string();
    if (!hash.length)
        return nil;
    return [@"/private/preboot" stringByAppendingPathComponent:hash];
}

NSString *dt710_resolve_preboot_root(void)
{
    NSString *active = dt710_resolve_active_preboot_path();
    if (!active.length)
        return nil;
    return [[[active stringByAppendingPathComponent:kDT710ExperimentDir]
        stringByAppendingPathComponent:kDT710ProcursusDir] copy];
}

NSString *dt710_resolve_basebin_path(void)
{
    NSString *root = dt710_resolve_preboot_root();
    if (!root.length)
        return nil;
    return [root stringByAppendingPathComponent:kDT710BasebinDir];
}

NSString *dt710_resolve_hook_path(void)
{
    return [dt710_resolve_basebin_path() stringByAppendingPathComponent:kDT710HookName];
}

NSString *dt710_resolve_libjailbreak_path(void)
{
    return [dt710_resolve_basebin_path() stringByAppendingPathComponent:kDT710LibjailbreakName];
}

NSString *dt710_resolve_libchoma_path(void)
{
    return [dt710_resolve_basebin_path() stringByAppendingPathComponent:kDT710LibchomaName];
}

NSString *dt710_resolve_systemhook_path(void)
{
    return [dt710_resolve_basebin_path() stringByAppendingPathComponent:kDT710SystemhookName];
}

static NSString *dt710_bundled_handoff_artifact(NSString *name)
{
    return [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:[kDT710HandoffDir stringByAppendingPathComponent:name]];
}

static NSString *dt710_sha256_file(NSString *path)
{
    NSInputStream *stream = [NSInputStream inputStreamWithFileAtPath:path];
    if (!stream)
        return nil;
    [stream open];

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    uint8_t buf[16384];
    for (;;) {
        NSInteger n = [stream read:buf maxLength:sizeof(buf)];
        if (n < 0) {
            [stream close];
            return nil;
        }
        if (n == 0)
            break;
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
    }
    [stream close];

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static NSString *dt710_cdhash_file(NSString *path)
{
    cdhash_t hash = {0};
    if (!path.length || dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0)
        return @"UNAVAILABLE";
    return dt_cdhash_hex_string(hash);
}

static NSString *dt717_mode_string(mode_t mode)
{
    return [NSString stringWithFormat:@"0%o", mode & 07777];
}

static NSString *dt717_statfs_flags_string(const struct statfs *sfs)
{
    if (!sfs)
        return @"UNAVAILABLE";
    return [NSString stringWithFormat:@"0x%x", sfs->f_flags];
}

static void dt717_log_nserror_chain(dt710_log_fn log, NSError *err, NSString *prefix)
{
    if (!err) {
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_DOMAIN=NONE", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_CODE=0", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_DESCRIPTION=NONE", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_USERINFO=NONE", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_DOMAIN=NONE", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_CODE=0", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_DESCRIPTION=NONE", prefix]);
        return;
    }

    dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_DOMAIN=%@", prefix, err.domain ?: @"NONE"]);
    dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_CODE=%ld", prefix, (long)err.code]);
    dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_DESCRIPTION=%@",
        prefix, err.localizedDescription ?: @""]);
    dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_USERINFO=%@",
        prefix, err.userInfo ?: @{}]);

    NSError *underlying = err.userInfo[NSUnderlyingErrorKey];
    if (underlying) {
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_DOMAIN=%@",
            prefix, underlying.domain ?: @"NONE"]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_CODE=%ld",
            prefix, (long)underlying.code]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_DESCRIPTION=%@",
            prefix, underlying.localizedDescription ?: @""]);
    } else {
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_DOMAIN=NONE", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_CODE=0", prefix]);
        dt710_emit(log, [NSString stringWithFormat:@"%@_NSError_UNDERLYING_DESCRIPTION=NONE", prefix]);
    }
}

static void dt717_log_segment_probe(dt710_log_fn log, NSString *segment)
{
    const char *path = segment.fileSystemRepresentation;
    struct stat st = {0};
    int lstat_rc = lstat(path, &st);
    struct statfs sfs = {0};
    int statfs_rc = statfs(path, &sfs);

    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_PATH=%@", segment]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_EXISTS=%@",
        (lstat_rc == 0) ? @"YES" : @"NO"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_LSTAT_RESULT=%d", lstat_rc]);
    if (lstat_rc == 0) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_MODE=%@",
            dt717_mode_string(st.st_mode)]);
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_UID=%u", st.st_uid]);
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_GID=%u", st.st_gid]);
    } else {
        dt710_emit(log, @"BUILD102717_SEGMENT_MODE=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_SEGMENT_UID=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_SEGMENT_GID=UNAVAILABLE");
    }
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_ACCESS_W_OK=%@",
        (access(path, W_OK) == 0) ? @"YES" : @"NO"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_STATFS_FLAGS=%@",
        statfs_rc == 0 ? dt717_statfs_flags_string(&sfs) : @"UNAVAILABLE"]);
}

static void dt717_log_segment_mkdir(dt710_log_fn log, NSString *segment, int *out_rc, int *out_errno)
{
    const char *path = segment.fileSystemRepresentation;
    int rc = mkdir(path, 0755);
    int saved = errno;
    if (out_rc)
        *out_rc = rc;
    if (out_errno)
        *out_errno = saved;

    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_MKDIR_PATH=%@", segment]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_MKDIR_RC=%d", rc]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_MKDIR_ERRNO=%d", saved]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_SEGMENT_MKDIR_ERRSTR=%s",
        saved ? strerror(saved) : "OK"]);
}

static NSString *dt717_deepest_existing_parent(NSString *path)
{
    if (!path.length)
        return nil;
    NSString *cursor = [path copy];
    while (cursor.length > 0) {
        struct stat st = {0};
        if (lstat(cursor.fileSystemRepresentation, &st) == 0)
            return cursor;
        NSString *parent = [cursor stringByDeletingLastPathComponent];
        if (!parent.length || [parent isEqualToString:cursor])
            break;
        cursor = parent;
    }
    return nil;
}

static void dt717_log_deepest_parent(dt710_log_fn log, NSString *target)
{
    NSString *parent = dt717_deepest_existing_parent(target);
    if (!parent.length) {
        dt710_emit(log, @"BUILD102717_DEEPEST_EXISTING_PARENT=NONE");
        dt710_emit(log, @"BUILD102717_PARENT_MODE=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_UID=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_GID=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_ACCESS_W_OK=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_STATFS_FLAGS=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_STATFS_FSTYPENAME=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_STATFS_MNTFROM=UNAVAILABLE");
        dt710_emit(log, @"BUILD102717_PARENT_STATFS_MNTON=UNAVAILABLE");
        return;
    }

    struct stat st = {0};
    struct statfs sfs = {0};
    int st_rc = lstat(parent.fileSystemRepresentation, &st);
    int sfs_rc = statfs(parent.fileSystemRepresentation, &sfs);

    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_DEEPEST_EXISTING_PARENT=%@", parent]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_MODE=%@",
        st_rc == 0 ? dt717_mode_string(st.st_mode) : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_UID=%@",
        st_rc == 0 ? [NSString stringWithFormat:@"%u", st.st_uid] : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_GID=%@",
        st_rc == 0 ? [NSString stringWithFormat:@"%u", st.st_gid] : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_ACCESS_W_OK=%@",
        (access(parent.fileSystemRepresentation, W_OK) == 0) ? @"YES" : @"NO"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_STATFS_FLAGS=%@",
        sfs_rc == 0 ? dt717_statfs_flags_string(&sfs) : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_STATFS_FSTYPENAME=%@",
        sfs_rc == 0 ? [NSString stringWithUTF8String:sfs.f_fstypename] ?: @"UNAVAILABLE" : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_STATFS_MNTFROM=%@",
        sfs_rc == 0 ? [NSString stringWithUTF8String:sfs.f_mntfromname] ?: @"UNAVAILABLE" : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PARENT_STATFS_MNTON=%@",
        sfs_rc == 0 ? [NSString stringWithUTF8String:sfs.f_mntonname] ?: @"UNAVAILABLE" : @"UNAVAILABLE"]);
}

static uint64_t dt717_read_sandbox_slot0(void)
{
    if (!dt_kernel_exploit_is_active())
        return 0;

    uint64_t proc = proc_find(getpid());
    if (!proc)
        return 0;

    uint64_t ucred = proc_ucred(proc);
    proc_rele(proc);
    if (!ucred)
        return 0;

    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    if (!label)
        return 0;

    return mac_label_get(label, 0);
}

static void dt717_log_pre_mkdir_state(dt710_log_fn log)
{
    uint32_t csflags = 0;
    int cs_rc = csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    uint64_t slot0 = dt717_read_sandbox_slot0();

    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_UID=%u", getuid()]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_EUID=%u", geteuid()]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_GID=%u", getgid()]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_EGID=%u", getegid()]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_CSFLAGS=%@",
        cs_rc == 0 ? [NSString stringWithFormat:@"0x%x", csflags] : @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_SANDBOX_SLOT0=0x%llx",
        (unsigned long long)slot0]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_SANDBOX_SLOT0_IS_NULL=%@",
        slot0 == 0 ? @"YES" : @"NO"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_SANDBOX_SLOT0_IS_MINUS1=%@",
        slot0 == (uint64_t)-1LL ? @"YES" : @"NO"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_KFD_ACTIVE=%@",
        dt_kernel_exploit_is_active() ? @"YES" : @"NO"]);
}

static NSArray<NSString *> *dt717_canonical_segments(NSString *basebin)
{
    NSString *active = dt710_resolve_active_preboot_path();
    if (!active.length || !basebin.length)
        return @[];

    NSString *experiment = [active stringByAppendingPathComponent:kDT710ExperimentDir];
    NSString *procursus = dt710_resolve_preboot_root();
    return @[
        @"/private/preboot",
        active,
        experiment,
        procursus ?: [experiment stringByAppendingPathComponent:kDT710ProcursusDir],
        basebin,
    ];
}

static NSString *dt717_classify_failure(int segment_errno, int ns_errno, uint32_t parent_flags,
    NSString *first_failing)
{
    (void)first_failing;
    int probe_errno = segment_errno ? segment_errno : ns_errno;
    if (parent_flags & MNT_RDONLY)
        return @"FILESYSTEM_RO";
    if (probe_errno == EROFS)
        return @"FILESYSTEM_RO";
    if (probe_errno == ENOENT)
        return @"PATH_PARENT_MISSING";
    if (probe_errno == EACCES)
        return @"OWNERSHIP_MODE";
    if (probe_errno == EPERM)
        return @"NOT_PROVEN";
    if (probe_errno != 0)
        return @"OTHER";
    return @"NOT_PROVEN";
}

static NSString *dt717_sandbox_confidence(int segment_errno, int ns_errno, uint64_t slot0, uint32_t parent_flags)
{
    if (slot0 == (uint64_t)-1LL || slot0 == 0)
        return @"DISPROVEN";
    if ((parent_flags & MNT_RDONLY))
        return @"DISPROVEN";
    int e = segment_errno ? segment_errno : ns_errno;
    if (e == EROFS)
        return @"DISPROVEN";
    if ((e == EPERM || e == EACCES) && slot0 != 0 && slot0 != (uint64_t)-1LL)
        return @"STRONGLY_SUPPORTED";
    return @"NOT_CLOSED";
}

static BOOL dt717_probe_segments(dt710_log_fn log, NSString *basebin,
    NSString **firstFailingOut, int *firstErrnoOut)
{
    NSArray<NSString *> *segments = dt717_canonical_segments(basebin);
    if (segments.count != 5) {
        dt710_emit(log, @"BUILD102717_FIRST_FAILING_COMPONENT=SEGMENT_LIST_UNAVAILABLE");
        if (firstFailingOut)
            *firstFailingOut = @"SEGMENT_LIST_UNAVAILABLE";
        if (firstErrnoOut)
            *firstErrnoOut = EINVAL;
        return NO;
    }

    for (NSUInteger i = 0; i < segments.count; i++) {
        NSString *segment = segments[i];
        dt717_log_segment_probe(log, segment);

        struct stat st = {0};
        if (lstat(segment.fileSystemRepresentation, &st) == 0)
            continue;

        int mk_rc = 0;
        int mk_errno = 0;
        dt717_log_segment_mkdir(log, segment, &mk_rc, &mk_errno);
        if (mk_rc != 0 && mk_errno != EEXIST) {
            dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_FIRST_FAILING_COMPONENT=%@", segment]);
            if (firstFailingOut)
                *firstFailingOut = segment;
            if (firstErrnoOut)
                *firstErrnoOut = mk_errno;
            return NO;
        }
    }

    if (firstFailingOut)
        *firstFailingOut = nil;
    if (firstErrnoOut)
        *firstErrnoOut = 0;
    return YES;
}

static BOOL dt710_mkdir_p(NSString *path, dt710_log_fn log)
{
    if (!path.length)
        return NO;

    dt710_emit(log, @"BUILD102717_PREBOOT_MKDIR_DIAG_BEGIN");

    NSString *first_failing = nil;
    int segment_errno = 0;
    int ns_errno = 0;
    uint32_t parent_statfs_flags = 0;

    dt717_log_pre_mkdir_state(log);
    dt717_log_deepest_parent(log, path);

    NSString *deepest = dt717_deepest_existing_parent(path);
    if (deepest.length) {
        struct statfs sfs = {0};
        if (statfs(deepest.fileSystemRepresentation, &sfs) == 0)
            parent_statfs_flags = sfs.f_flags;
    }

    (void)dt717_probe_segments(log, path, &first_failing, &segment_errno);

    NSError *err = nil;
    BOOL created = [[NSFileManager defaultManager] createDirectoryAtPath:path
        withIntermediateDirectories:YES attributes:nil error:&err];
    if (!created) {
        dt717_log_nserror_chain(log, err, @"BUILD102717_MKDIR");
        ns_errno = (int)err.code;
        if (err.domain == NSPOSIXErrorDomain)
            ns_errno = (int)err.code;
        else if (err.userInfo[NSUnderlyingErrorKey]) {
            NSError *underlying = err.userInfo[NSUnderlyingErrorKey];
            if ([underlying.domain isEqualToString:NSPOSIXErrorDomain])
                ns_errno = (int)underlying.code;
        }
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_MKDIR_ERRNO=%d", ns_errno]);
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_MKDIR_ERRSTR=%s",
            ns_errno ? strerror(ns_errno) : "UNKNOWN"]);
    } else {
        dt717_log_nserror_chain(log, nil, @"BUILD102717_MKDIR");
        dt710_emit(log, @"BUILD102717_MKDIR_ERRNO=0");
        dt710_emit(log, @"BUILD102717_MKDIR_ERRSTR=OK");
    }

    uint64_t slot0 = dt717_read_sandbox_slot0();
    NSString *failure_class = dt717_classify_failure(segment_errno, ns_errno, parent_statfs_flags, first_failing);
    NSString *sandbox_conf = dt717_sandbox_confidence(segment_errno, ns_errno, slot0, parent_statfs_flags);

    dt710_emit(log, @"BUILD102717_PHYSRW_SKIP_PASS=SEE_BUILD102716_PHYSRW_SKIP_HANDOFF_PASS");
    dt710_emit(log, @"BUILD102717_PATH_COHERENCE_PASS=SEE_BUILD102710_PATH_COHERENCE_PASS");
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_DEEPEST_EXISTING_PARENT=%@",
        deepest ?: @"NONE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_FIRST_FAILING_COMPONENT=%@",
        first_failing ?: @"NONE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_NSError_DOMAIN=%@",
        err.domain ?: @"NONE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_NSError_CODE=%ld",
        err ? (long)err.code : 0]);
    NSError *underlying = err.userInfo[NSUnderlyingErrorKey];
    if (underlying) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_UNDERLYING_ERROR=%@:%ld:%@",
            underlying.domain, (long)underlying.code, underlying.localizedDescription ?: @""]);
    } else {
        dt710_emit(log, @"BUILD102717_UNDERLYING_ERROR=NONE");
    }
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_SANDBOX_SLOT0=0x%llx",
        (unsigned long long)slot0]);
    uint32_t csflags = 0;
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_UID=%u", getuid()]);
    if (csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags)) == 0) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PRE_MKDIR_CSFLAGS=0x%x", csflags]);
    } else {
        dt710_emit(log, @"BUILD102717_PRE_MKDIR_CSFLAGS=UNAVAILABLE");
    }
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_PREBOOT_STATFS_FLAGS=0x%x", parent_statfs_flags]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102717_FAILURE_CLASS=%@", failure_class]);
    dt710_emit(log, [NSString stringWithFormat:@"SANDBOX_CAUSE_CONFIDENCE=%@", sandbox_conf]);
    dt710_emit(log, @"BUILD102717_PREBOOT_MKDIR_DIAG_END");

    if (created)
        return YES;
    return [[NSFileManager defaultManager] fileExistsAtPath:path];
}

static int dt710_copy_artifact(NSString *name, NSString *dest, dt710_log_fn log,
    NSString *pathKey, NSString *shaKey, NSString *cdhashKey)
{
    NSString *src = dt710_bundled_handoff_artifact(name);
    if (!src.length || !dest.length || ![[NSFileManager defaultManager] fileExistsAtPath:src]) {
        dt710_log(log, [NSString stringWithFormat:@"[!] BUILD102710_STAGE_MISSING_SOURCE=%@",
            src ?: @""]);
        return -1;
    }

    NSDictionary *srcAttrs = [[NSFileManager defaultManager] attributesOfItemAtPath:src error:nil];
    unsigned long long srcSize = [srcAttrs fileSize];
    if (srcSize == 0)
        return -2;

    [[NSFileManager defaultManager] removeItemAtPath:dest error:nil];
    unlink([[dest stringByAppendingString:@".choma.tmp"] fileSystemRepresentation]);

    NSError *err = nil;
    if (![[NSFileManager defaultManager] copyItemAtPath:src toPath:dest error:&err]) {
        dt710_log(log, [NSString stringWithFormat:@"[!] BUILD102710_STAGE_COPY_FAIL %@ -> %@ err=%@",
            src, dest, err.localizedDescription ?: @""]);
        [[NSFileManager defaultManager] removeItemAtPath:dest error:nil];
        return -3;
    }
    chmod(dest.fileSystemRepresentation, 0755);

    NSDictionary *dstAttrs = [[NSFileManager defaultManager] attributesOfItemAtPath:dest error:nil];
    if (![dstAttrs fileSize] || [dstAttrs fileSize] != srcSize) {
        dt710_log(log, [NSString stringWithFormat:@"[!] BUILD102710_STAGE_SIZE_MISMATCH %@ src=%llu dst=%llu",
            name, srcSize, (unsigned long long)[dstAttrs fileSize]]);
        [[NSFileManager defaultManager] removeItemAtPath:dest error:nil];
        return -4;
    }

    NSString *sha = dt710_sha256_file(dest) ?: @"UNAVAILABLE";
    NSString *cdhash = dt710_cdhash_file(dest);
    dt710_emit(log, [NSString stringWithFormat:@"%@=%@", pathKey, dest]);
    dt710_emit(log, [NSString stringWithFormat:@"%@=%@", shaKey, sha]);
    dt710_emit(log, [NSString stringWithFormat:@"%@=%@", cdhashKey, cdhash]);
    return 0;
}

void dt710_log_preboot_paths(dt710_log_fn log)
{
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_PREBOOT_ACTIVE_PATH=%@",
        dt710_resolve_active_preboot_path() ?: @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_PREBOOT_JBROOT=%@",
        dt710_resolve_preboot_root() ?: @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_PREBOOT_BASEBIN=%@",
        dt710_resolve_basebin_path() ?: @"UNAVAILABLE"]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_PREBOOT_HOOK=%@",
        dt710_resolve_hook_path() ?: @"UNAVAILABLE"]);
}

void dt710_log_var_jb_compat_state(dt710_log_fn log)
{
    NSString *path = @"/private/var/jb";
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        dt710_emit(log, @"BUILD102710_VAR_JB_COMPAT_STATE=retain existing /private/var/jb compatibility tree; path missing on this run");
        dt710_emit(log, @"BUILD102710_VAR_JB_EXISTS=NO");
        dt710_emit(log, @"BUILD102710_VAR_JB_TYPE=MISSING");
        dt710_emit(log, @"BUILD102710_VAR_JB_TARGET=N/A");
        return;
    }

    NSString *type = @"OTHER";
    NSString *target = @"N/A";
    if (S_ISDIR(st.st_mode)) {
        type = @"DIRECTORY";
    } else if (S_ISLNK(st.st_mode)) {
        type = @"SYMLINK";
        char buf[PATH_MAX] = {0};
        ssize_t n = readlink(path.fileSystemRepresentation, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            target = [NSString stringWithUTF8String:buf] ?: @"UNAVAILABLE";
        }
    }

    dt710_emit(log, @"BUILD102710_VAR_JB_COMPAT_STATE=retain existing /private/var/jb compatibility tree while hook loads from preboot");
    dt710_emit(log, @"BUILD102710_VAR_JB_EXISTS=YES");
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_VAR_JB_TYPE=%@", type]);
    dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_VAR_JB_TARGET=%@", target]);
}

int dt710_stage_preboot_handoff_stack(dt710_log_fn log, BOOL preserve_launchdhook)
{
    dt710_log_preboot_paths(log);
    dt710_log_var_jb_compat_state(log);

    NSString *root = dt710_resolve_preboot_root();
    NSString *basebin = dt710_resolve_basebin_path();
    if (!root.length || !basebin.length) {
        dt710_emit(log, @"BUILD102710_PREBOOT_PATH_RESOLVE_FAIL");
        return -1;
    }
    if (!dt710_mkdir_p(basebin, log)) {
        dt710_emit(log, @"BUILD102710_PREBOOT_BASEBIN_MKDIR_FAIL");
        return -2;
    }

    if (!preserve_launchdhook) {
        int r = dt710_copy_artifact(kDT710HookName, dt710_resolve_hook_path(), log,
            @"BUILD102710_STAGE_HOOK_PATH",
            @"BUILD102710_STAGE_HOOK_SHA256",
            @"BUILD102710_STAGE_HOOK_PRE_SIGN_CDHASH");
        if (r != 0)
            return -10 + r;
    } else {
        NSString *hook = dt710_resolve_hook_path();
        if (![[NSFileManager defaultManager] fileExistsAtPath:hook]) {
            dt710_emit(log, @"BUILD102710_STAGE_HOOK_PRESERVE_MISSING");
            return -20;
        }
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_STAGE_HOOK_PATH=%@", hook]);
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_STAGE_HOOK_SHA256=%@",
            dt710_sha256_file(hook) ?: @"UNAVAILABLE"]);
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_STAGE_HOOK_PRE_SIGN_CDHASH=%@",
            dt710_cdhash_file(hook)]);
    }

    int lj = dt710_copy_artifact(kDT710LibjailbreakName, dt710_resolve_libjailbreak_path(), log,
        @"BUILD102710_STAGE_LIBJAILBREAK_PATH",
        @"BUILD102710_STAGE_LIBJAILBREAK_SHA256",
        @"BUILD102710_STAGE_LIBJAILBREAK_CDHASH");
    if (lj != 0)
        return -30 + lj;

    int lc = dt710_copy_artifact(kDT710LibchomaName, dt710_resolve_libchoma_path(), log,
        @"BUILD102710_STAGE_LIBCHOMA_PATH",
        @"BUILD102710_STAGE_LIBCHOMA_SHA256",
        @"BUILD102710_STAGE_LIBCHOMA_CDHASH");
    if (lc != 0)
        return -40 + lc;

    /* R24 CBR: systemhook under JBROOT basebin for DYLD_INSERT_LIBRARIES. */
    if ([[NSFileManager defaultManager] fileExistsAtPath:dt710_bundled_handoff_artifact(kDT710SystemhookName)]) {
        int sh = dt710_copy_artifact(kDT710SystemhookName, dt710_resolve_systemhook_path(), log,
            @"BUILD102710_STAGE_SYSTEMHOOK_PATH",
            @"BUILD102710_STAGE_SYSTEMHOOK_SHA256",
            @"BUILD102710_STAGE_SYSTEMHOOK_CDHASH");
        if (sh != 0)
            return -50 + sh;
    } else {
        dt710_emit(log, @"BUILD102710_STAGE_SYSTEMHOOK_ABSENT");
    }

    dt710_emit(log, @"BUILD102710_PREBOOT_BASEBIN_STAGE_PASS");
    return 0;
}

static int dt710_upload_trust_for_path(NSString *path, NSString *marker, dt710_log_fn log)
{
    if (!path.length || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_TRUST_MISSING_PATH=%@",
            path ?: @""]);
        return -1;
    }

    cdhash_t hash = {0};
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, hash) != 0) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_TRUST_CDHASH_FAIL=%@", path]);
        return -2;
    }

    uint32_t uploaded = 0;
    int r = dt_trustcache_upload_cdhashes_force(&hash, 1, &uploaded);
    if (r != 0) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_TRUST_UPLOAD_FAIL_%d", r]);
        return r;
    }
    if (!dt_cdhash_trustcached(hash)) {
        dt710_emit(log, [NSString stringWithFormat:@"BUILD102710_TRUST_VERIFY_FAIL=%@",
            dt_cdhash_hex_string(hash)]);
        return -3;
    }

    dt710_emit(log, [NSString stringWithFormat:@"%@=%@", marker, dt_cdhash_hex_string(hash)]);
    return 0;
}

int dt710_upload_final_preboot_trust_closure(dt710_log_fn log, BOOL include_hook)
{
    if (include_hook) {
        int hook = dt710_upload_trust_for_path(dt710_resolve_hook_path(),
            @"BUILD102710_TRUST_HOOK_PASS", log);
        if (hook != 0)
            return -10 + hook;
    }

    int lj = dt710_upload_trust_for_path(dt710_resolve_libjailbreak_path(),
        @"BUILD102710_TRUST_LIBJAILBREAK_PASS", log);
    if (lj != 0)
        return -20 + lj;

    int lc = dt710_upload_trust_for_path(dt710_resolve_libchoma_path(),
        @"BUILD102710_TRUST_LIBCHOMA_PASS", log);
    if (lc != 0)
        return -30 + lc;

    NSString *shPath = dt710_resolve_systemhook_path();
    if ([[NSFileManager defaultManager] fileExistsAtPath:shPath]) {
        int sh = dt710_upload_trust_for_path(shPath, @"BUILD102710_TRUST_SYSTEMHOOK_PASS", log);
        if (sh != 0)
            return -40 + sh;
    }

    dt710_emit(log, @"BUILD102710_PREBOOT_DEPENDENCY_TRUST_CLOSURE_PASS");
    return 0;
}

BOOL dt710_verify_path_coherence(dt710_log_fn log)
{
    NSString *hook = dt710_resolve_hook_path() ?: @"";
    dt710_emit(log, @"BUILD102710_PATH_COHERENCE_BEGIN");
    dt710_emit(log, [NSString stringWithFormat:@"HOOK_STAGE_PATH=%@", hook]);
    dt710_emit(log, [NSString stringWithFormat:@"HOOK_SIGN_PATH=%@", hook]);
    dt710_emit(log, [NSString stringWithFormat:@"HOOK_TRUST_PATH=%@", hook]);
    dt710_emit(log, [NSString stringWithFormat:@"HOOK_READ_CONSUME_PATH=%@", hook]);
    dt710_emit(log, [NSString stringWithFormat:@"HOOK_EXEC_CONSUME_PATH=%@", hook]);
    dt710_emit(log, [NSString stringWithFormat:@"HOOK_OPAINJECT_ARGV_PATH=%@", hook]);

    BOOL ok = hook.length > 0
        && [hook hasPrefix:@"/private/preboot/"]
        && [hook hasSuffix:@"/procursus/basebin/launchdhook516.dylib"];
    dt710_emit(log, ok ? @"BUILD102710_PATH_COHERENCE_PASS"
                       : @"BUILD102710_PATH_COHERENCE_FAIL");
    return ok;
}
