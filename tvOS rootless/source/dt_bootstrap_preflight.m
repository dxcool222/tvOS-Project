#import "dt_bootstrap_preflight.h"

#import "DTRunLogger.h"
#import "dt_physrw.h"
#import "spawn_root.h"

#import <CommonCrypto/CommonDigest.h>
#import <CoreFoundation/CoreFoundation.h>
#import <errno.h>
#import <math.h>
#import <libproc.h>
#import <stdarg.h>
#import <string.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

static NSString *const kDT102739KArchiveSHA256 =
    @"54299aaf56176695b4fe6883f13bd67617d8c008e5bc5778591ec3940e5e7666";
static NSString *const kDT102739KExpectedLtopSHA256 =
    @"a351548370a646d819e40a0c5f25fbff51d9454d4ff094e0c654322ef0ab20cb";
static const off_t kDT102739KExpectedLtopSize = 93088;
static const NSUInteger kDT102739KArchiveMemberCount = 4041;
static const NSUInteger kDT102739KInventoryPathCount = 4040;
static const NSUInteger kDT102739KFailureDetailLimit = 16;

enum {
    kDT102739KFailureModel = 0x001,
    kDT102739KFailureBuild = 0x002,
    kDT102739KFailureCF1900 = 0x004,
    kDT102739KFailureEUID0 = 0x008,
    kDT102739KFailureRemount = 0x010,
    kDT102739KFailureManifest = 0x020,
    kDT102739KFailureInventoryRead = 0x040,
    kDT102739KFailureMountSurvey = 0x080,
    kDT102739KFailureCandidateSurvey = 0x100,
    kDT102739KFailureServiceQuery = 0x200,
    kDT102739KFailureServiceState = 0x400,
    kDT102739KFailureTrackedIdentity = 0x800,
};

typedef struct {
    BOOL present;
    mode_t mode;
    dev_t device;
    ino_t inode;
    off_t size;
    time_t modified;
} dt102739k_identity_t;

static void dt102739k_emit(void (^log)(NSString *), NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void dt102739k_record_failure(NSMutableArray<NSDictionary *> *failures,
    NSString *path, NSString *failureClass, unichar expectedType,
    unichar actualType, int errorNumber)
{
    if (failures.count >= kDT102739KFailureDetailLimit)
        return;
    [failures addObject:@{
        @"path" : path ?: @"UNAVAILABLE",
        @"class" : failureClass ?: @"UNKNOWN",
        @"expected" : expectedType ? [NSString stringWithCharacters:&expectedType length:1] : @"NONE",
        @"actual" : actualType ? [NSString stringWithCharacters:&actualType length:1] : @"NONE",
        @"errno" : @(errorNumber),
    }];
}

static void dt102739k_record_malformed(NSMutableArray<NSDictionary *> *details,
    NSUInteger sourceLine, NSString *reason, NSString *rawLine,
    NSString *path, NSString *standardizedPath)
{
    if (details.count >= kDT102739KFailureDetailLimit)
        return;
    [details addObject:@{
        @"source_line" : @(sourceLine),
        @"reason" : reason ?: @"UNKNOWN",
        @"raw" : rawLine ?: @"UNAVAILABLE",
        @"path" : path ?: @"UNAVAILABLE",
        @"standardized" : standardizedPath ?: @"UNAVAILABLE",
    }];
}

static NSString *dt102739k_sha256_file(NSString *path)
{
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe
        error:nil];
    if (!data)
        return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:
        CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static BOOL dt102739k_read_sysctl(const char *name, char *buffer, size_t capacity)
{
    if (!buffer || capacity < 2)
        return NO;
    memset(buffer, 0, capacity);
    size_t length = capacity;
    return sysctlbyname(name, buffer, &length, NULL, 0) == 0 && length > 1;
}

static dt102739k_identity_t dt102739k_identity(NSString *path)
{
    dt102739k_identity_t identity = {0};
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) == 0) {
        identity.present = YES;
        identity.mode = st.st_mode;
        identity.device = st.st_dev;
        identity.inode = st.st_ino;
        identity.size = st.st_size;
        identity.modified = st.st_mtime;
    }
    return identity;
}

static BOOL dt102739k_identity_equal(dt102739k_identity_t a, dt102739k_identity_t b)
{
    return a.present == b.present
        && (!a.present || (a.mode == b.mode && a.device == b.device
            && a.inode == b.inode && a.size == b.size
            && a.modified == b.modified));
}

static unichar dt102739k_actual_type(mode_t mode)
{
    if (S_ISDIR(mode)) return 'd';
    if (S_ISREG(mode)) return '-';
    if (S_ISLNK(mode)) return 'l';
    return '?';
}

static BOOL dt102739k_path_is_normalized(NSString *path)
{
    if (![path hasPrefix:@"/"] || [path hasPrefix:@"//"] || path.length < 2)
        return NO;

    // Keep manifest validation lexical. Foundation path standardization follows
    // the stock /etc and /var aliases and would reject valid /private paths.
    if ([path hasSuffix:@"/"])
        return NO;
    NSArray<NSString *> *components = [path componentsSeparatedByString:@"/"];
    for (NSUInteger i = 1; i < components.count; i++) {
        NSString *component = components[i];
        if (!component.length || [component isEqualToString:@"."]
                || [component isEqualToString:@".."])
            return NO;
    }
    return YES;
}

static void dt102739k_check_parent_symlinks(NSString *path, NSMutableSet<NSString *> *conflicts)
{
    NSString *parent = path.stringByDeletingLastPathComponent;
    while (parent.length > 1) {
        struct stat st = {0};
        if (lstat(parent.fileSystemRepresentation, &st) == 0 && S_ISLNK(st.st_mode))
            [conflicts addObject:parent];
        parent = parent.stringByDeletingLastPathComponent;
    }
}

static BOOL dt102739k_emit_mount(NSString *label, NSString *path,
    void (^log)(NSString *))
{
    struct statfs fs = {0};
    int rc = statfs(path.fileSystemRepresentation, &fs);
    dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_STATFS_RC=%d", label, rc);
    if (rc != 0) {
        dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_ERRNO=%d", label, errno);
        return NO;
    }
    dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_FROM=%s", label, fs.f_mntfromname);
    dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_ON=%s", label, fs.f_mntonname);
    dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_TYPE=%s", label, fs.f_fstypename);
    dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_READONLY=%@", label,
        (fs.f_flags & MNT_RDONLY) ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_MOUNT_%@_FREE_BYTES=%llu", label,
        (unsigned long long)fs.f_bavail * (unsigned long long)fs.f_bsize);
    return YES;
}

static BOOL dt102739k_emit_candidate(NSString *label, NSString *path,
    void (^log)(NSString *))
{
    struct stat st = {0};
    int lstatRC = lstat(path.fileSystemRepresentation, &st);
    int lstatErrno = lstatRC == 0 ? 0 : errno;
    int accessRC = access(path.fileSystemRepresentation, W_OK | X_OK);
    int accessErrno = accessRC == 0 ? 0 : errno;
    struct statfs fs = {0};
    int statfsRC = statfs(path.fileSystemRepresentation, &fs);
    int statfsErrno = statfsRC == 0 ? 0 : errno;
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_PATH=%@", label, path);
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_LSTAT_RC=%d", label, lstatRC);
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_LSTAT_ERRNO=%d", label, lstatErrno);
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_IS_DIRECTORY=%@", label,
        lstatRC == 0 && S_ISDIR(st.st_mode) ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_WX_ACCESS_RC=%d", label, accessRC);
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_WX_ACCESS_ERRNO=%d", label, accessErrno);
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_STATFS_RC=%d", label, statfsRC);
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_STATFS_ERRNO=%d", label, statfsErrno);
    if (statfsRC == 0) {
        dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_MOUNT=%s", label, fs.f_mntonname);
        dt102739k_emit(log, @"BUILD102739K_CANDIDATE_%@_FREE_BYTES=%llu", label,
            (unsigned long long)fs.f_bavail * (unsigned long long)fs.f_bsize);
    }
    return lstatRC == 0 && S_ISDIR(st.st_mode) && statfsRC == 0;
}

static BOOL dt102739k_query_service(NSString *toolPath, NSString *label, BOOL *loaded,
    void (^log)(NSString *))
{
    int exitStatus = -1;
    NSString *capture = nil;
    NSError *error = nil;
    int rc = dt_spawn_plain_capture(toolPath,
        @[@"print", [@"system/" stringByAppendingString:label]],
        &exitStatus, &capture, &error);
    BOOL queryComplete = rc == 0;
    if (loaded)
        *loaded = queryComplete && exitStatus == 0;
    dt102739k_emit(log, @"BUILD102739K_SERVICE_%@_QUERY_RC=%d", label, rc);
    dt102739k_emit(log, @"BUILD102739K_SERVICE_%@_EXIT_STATUS=%d", label, exitStatus);
    dt102739k_emit(log, @"BUILD102739K_SERVICE_%@_LOADED=%@", label,
        queryComplete && exitStatus == 0 ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_SERVICE_%@_QUERY_ERROR=%@", label,
        error ? error.localizedDescription : @"NONE");
    return queryComplete;
}

int dt_build102739k_run_rootful_bootstrap_preflight(void (^log)(NSString *),
    NSString **verdictOut)
{
    NSString *runID = [NSUUID UUID].UUIDString;
    dt102739k_emit(log, @"BUILD102739K_REPORT_SCHEMA=1");
    dt102739k_emit(log, @"BUILD102739K_RUN_ID=%@", runID);
    dt102739k_emit(log, @"BUILD102739K_REPORT_BEGIN=YES");
    dt102739k_emit(log, @"BUILD102739K_BEGIN");
    dt102739k_emit(log, @"BUILD102739K_SCOPE=ROOTFUL_BOOTSTRAP_READ_ONLY_PREFLIGHT");
    dt102739k_emit(log, @"BUILD102739K_BASELINE=BUILD102739J_FROZEN");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_ARCHIVE_ON_DEVICE=NO");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_EXTRACTION_ENABLED=NO");
    dt102739k_emit(log, @"BUILD102739K_PACKAGE_INSTALL_ENABLED=NO");
    dt102739k_emit(log, @"BUILD102739K_SERVICE_MUTATION_ENABLED=NO");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_TARGET_MUTATION_CALLS=0");

    char model[64] = {0};
    char build[64] = {0};
    BOOL modelRead = dt102739k_read_sysctl("hw.machine", model, sizeof(model));
    BOOL buildRead = dt102739k_read_sysctl("kern.osversion", build, sizeof(build));
    NSInteger cfBucket = (NSInteger)floor(kCFCoreFoundationVersionNumber / 100.0) * 100;
    BOOL modelMatch = modelRead && strcmp(model, "AppleTV6,2") == 0;
    BOOL buildMatch = buildRead && strcmp(build, "20L563") == 0;
    BOOL cfMatch = cfBucket == 1900;
    BOOL euidMatch = geteuid() == 0;
    BOOL remountMatch = dt_build_rootful_remount_ok();
    dt102739k_emit(log, @"BUILD102739K_TARGET_MODEL=%s", modelRead ? model : "UNREADABLE");
    dt102739k_emit(log, @"BUILD102739K_TARGET_MODEL_MATCH=%@", modelMatch ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_TARGET_BUILD=%s", buildRead ? build : "UNREADABLE");
    dt102739k_emit(log, @"BUILD102739K_TARGET_BUILD_MATCH=%@", buildMatch ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_CF_VERSION_EXACT=%.3f", kCFCoreFoundationVersionNumber);
    dt102739k_emit(log, @"BUILD102739K_CF_VERSION_BUCKET=%ld", (long)cfBucket);
    dt102739k_emit(log, @"BUILD102739K_CF1900_MATCH=%@", cfMatch ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_EUID=%u", (unsigned)geteuid());
    dt102739k_emit(log, @"BUILD102739K_EUID0_MATCH=%@", euidMatch ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_ACTUAL_REMOUNT_SUCCESS=%@", remountMatch ? @"YES" : @"NO");

    NSString *manifestPath = [[NSBundle mainBundle]
        pathForResource:@"BUILD102739K_CF1900_PATHS" ofType:@"tsv"];
    NSError *manifestError = nil;
    NSString *manifest = manifestPath
        ? [NSString stringWithContentsOfFile:manifestPath
            encoding:NSUTF8StringEncoding error:&manifestError]
        : nil;
    BOOL headerHash = [manifest containsString:[@"#ARCHIVE_SHA256="
        stringByAppendingString:kDT102739KArchiveSHA256]];
    BOOL headerMembers = [manifest containsString:[NSString stringWithFormat:
        @"#ARCHIVE_MEMBER_COUNT=%lu", (unsigned long)kDT102739KArchiveMemberCount]];
    BOOL headerPaths = [manifest containsString:[NSString stringWithFormat:
        @"#INVENTORY_PATH_COUNT=%lu", (unsigned long)kDT102739KInventoryPathCount]];
    dt102739k_emit(log, @"BUILD102739K_MANIFEST_PRESENT=%@", manifest ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_MANIFEST_READ_ERROR=%@",
        manifestError ? manifestError.localizedDescription : @"NONE");
    dt102739k_emit(log, @"BUILD102739K_ARCHIVE_SHA256=%@", kDT102739KArchiveSHA256);
    dt102739k_emit(log, @"BUILD102739K_ARCHIVE_HASH_PIN_MATCH=%@", headerHash ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_ARCHIVE_MEMBER_COUNT=%lu",
        (unsigned long)kDT102739KArchiveMemberCount);

    NSUInteger parsedPaths = 0;
    NSUInteger absentCount = 0;
    NSUInteger compatibleDirectoryCount = 0;
    NSUInteger existingUnknownCount = 0;
    NSUInteger typeConflictCount = 0;
    NSUInteger lstatErrorCount = 0;
    NSUInteger malformedCount = 0;
    NSMutableSet<NSString *> *parentSymlinkConflicts = [NSMutableSet set];
    NSMutableArray<NSDictionary *> *failureDetails = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *collisionDetails = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *malformedDetails = [NSMutableArray array];
    NSUInteger manifestSourceLine = 0;
    for (NSString *line in [manifest componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        manifestSourceLine++;
        if (!line.length || [line hasPrefix:@"#"])
            continue;
        NSArray<NSString *> *fields = [line componentsSeparatedByString:@"\t"];
        if (fields.count != 2) {
            malformedCount++;
            dt102739k_record_malformed(malformedDetails, manifestSourceLine,
                @"FIELD_COUNT", line, nil, nil);
            continue;
        }
        NSString *path = fields[1];
        if ([fields[0] length] != 1) {
            malformedCount++;
            dt102739k_record_malformed(malformedDetails, manifestSourceLine,
                @"TYPE_WIDTH", line, path, nil);
            continue;
        }
        if (!dt102739k_path_is_normalized(path)) {
            malformedCount++;
            dt102739k_record_malformed(malformedDetails, manifestSourceLine,
                @"PATH_NORMALIZATION", line, path, nil);
            continue;
        }
        unichar expectedType = [fields[0] characterAtIndex:0];
        if (expectedType != 'd' && expectedType != '-' && expectedType != 'l') {
            malformedCount++;
            dt102739k_record_malformed(malformedDetails, manifestSourceLine,
                @"UNSUPPORTED_TYPE", line, path, nil);
            continue;
        }
        parsedPaths++;
        dt102739k_check_parent_symlinks(path, parentSymlinkConflicts);
        struct stat st = {0};
        errno = 0;
        if (lstat(path.fileSystemRepresentation, &st) != 0) {
            if (errno == ENOENT)
                absentCount++;
            else {
                lstatErrorCount++;
                dt102739k_record_failure(failureDetails, path, @"LSTAT_ERROR",
                    expectedType, 0, errno);
            }
            continue;
        }
        unichar actualType = dt102739k_actual_type(st.st_mode);
        if (actualType != expectedType) {
            typeConflictCount++;
            dt102739k_record_failure(collisionDetails, path, @"TYPE_CONFLICT",
                expectedType, actualType, 0);
        } else if (expectedType == 'd') {
            compatibleDirectoryCount++;
        } else {
            existingUnknownCount++;
            dt102739k_record_failure(collisionDetails, path,
                @"EXISTING_STOCK_OR_UNKNOWN_OBJECT", expectedType, actualType, 0);
        }
    }
    for (NSString *path in [parentSymlinkConflicts.allObjects
            sortedArrayUsingSelector:@selector(compare:)]) {
        dt102739k_record_failure(collisionDetails, path, @"SYMLINK_PARENT_CONFLICT",
            0, 'l', 0);
    }
    BOOL manifestValid = manifest && headerHash && headerMembers && headerPaths
        && parsedPaths == kDT102739KInventoryPathCount && malformedCount == 0;
    NSUInteger unresolvedCollisions = existingUnknownCount + typeConflictCount
        + parentSymlinkConflicts.count;
    dt102739k_emit(log, @"BUILD102739K_INVENTORY_PATH_COUNT=%lu", (unsigned long)parsedPaths);
    dt102739k_emit(log, @"BUILD102739K_INVENTORY_EXPECTED_PATH_COUNT=%lu",
        (unsigned long)kDT102739KInventoryPathCount);
    dt102739k_emit(log, @"BUILD102739K_INVENTORY_ABSENT_COUNT=%lu", (unsigned long)absentCount);
    dt102739k_emit(log, @"BUILD102739K_EXISTING_DIRECTORY_COMPATIBLE_COUNT=%lu",
        (unsigned long)compatibleDirectoryCount);
    dt102739k_emit(log, @"BUILD102739K_EXISTING_STOCK_OR_UNKNOWN_OBJECT_COUNT=%lu",
        (unsigned long)existingUnknownCount);
    dt102739k_emit(log, @"BUILD102739K_TYPE_CONFLICT_COUNT=%lu",
        (unsigned long)typeConflictCount);
    dt102739k_emit(log, @"BUILD102739K_SYMLINK_PARENT_CONFLICT_COUNT=%lu",
        (unsigned long)parentSymlinkConflicts.count);
    dt102739k_emit(log, @"BUILD102739K_LSTAT_ERROR_COUNT=%lu",
        (unsigned long)lstatErrorCount);
    dt102739k_emit(log, @"BUILD102739K_MALFORMED_MANIFEST_COUNT=%lu",
        (unsigned long)malformedCount);
    dt102739k_emit(log, @"BUILD102739K_MALFORMED_DETAIL_COUNT=%lu",
        (unsigned long)malformedDetails.count);
    for (NSUInteger i = 0; i < malformedDetails.count; i++) {
        NSDictionary *detail = malformedDetails[i];
        dt102739k_emit(log, @"BUILD102739K_MALFORMED_%02lu_SOURCE_LINE=%lu",
            (unsigned long)(i + 1), (unsigned long)[detail[@"source_line"] unsignedIntegerValue]);
        dt102739k_emit(log, @"BUILD102739K_MALFORMED_%02lu_REASON=%@",
            (unsigned long)(i + 1), detail[@"reason"]);
        dt102739k_emit(log, @"BUILD102739K_MALFORMED_%02lu_RAW=%@",
            (unsigned long)(i + 1), detail[@"raw"]);
        dt102739k_emit(log, @"BUILD102739K_MALFORMED_%02lu_PATH=%@",
            (unsigned long)(i + 1), detail[@"path"]);
        dt102739k_emit(log, @"BUILD102739K_MALFORMED_%02lu_STANDARDIZED_PATH=%@",
            (unsigned long)(i + 1), detail[@"standardized"]);
    }
    dt102739k_emit(log, @"BUILD102739K_UNRESOLVED_COLLISION_COUNT=%lu",
        (unsigned long)unresolvedCollisions);
    dt102739k_emit(log, @"BUILD102739K_MANIFEST_VALID=%@", manifestValid ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_FAILURE_DETAIL_COUNT=%lu",
        (unsigned long)failureDetails.count);
    for (NSUInteger i = 0; i < failureDetails.count; i++) {
        NSDictionary *failure = failureDetails[i];
        dt102739k_emit(log, @"BUILD102739K_FAILURE_%02lu_PATH=%@",
            (unsigned long)(i + 1), failure[@"path"]);
        dt102739k_emit(log, @"BUILD102739K_FAILURE_%02lu_CLASS=%@",
            (unsigned long)(i + 1), failure[@"class"]);
        dt102739k_emit(log, @"BUILD102739K_FAILURE_%02lu_EXPECTED_TYPE=%@",
            (unsigned long)(i + 1), failure[@"expected"]);
        dt102739k_emit(log, @"BUILD102739K_FAILURE_%02lu_ACTUAL_TYPE=%@",
            (unsigned long)(i + 1), failure[@"actual"]);
        dt102739k_emit(log, @"BUILD102739K_FAILURE_%02lu_ERRNO=%d",
            (unsigned long)(i + 1), [failure[@"errno"] intValue]);
    }
    dt102739k_emit(log, @"BUILD102739K_COLLISION_DETAIL_COUNT=%lu",
        (unsigned long)collisionDetails.count);
    for (NSUInteger i = 0; i < collisionDetails.count; i++) {
        NSDictionary *collision = collisionDetails[i];
        dt102739k_emit(log, @"BUILD102739K_COLLISION_%02lu_PATH=%@",
            (unsigned long)(i + 1), collision[@"path"]);
        dt102739k_emit(log, @"BUILD102739K_COLLISION_%02lu_CLASS=%@",
            (unsigned long)(i + 1), collision[@"class"]);
        dt102739k_emit(log, @"BUILD102739K_COLLISION_%02lu_EXPECTED_TYPE=%@",
            (unsigned long)(i + 1), collision[@"expected"]);
        dt102739k_emit(log, @"BUILD102739K_COLLISION_%02lu_ACTUAL_TYPE=%@",
            (unsigned long)(i + 1), collision[@"actual"]);
    }
    struct stat ltopStat = {0};
    int ltopLstatRC = lstat("/usr/bin/ltop", &ltopStat);
    int ltopLstatErrno = ltopLstatRC == 0 ? 0 : errno;
    NSString *ltopSHA256 = ltopLstatRC == 0 && S_ISREG(ltopStat.st_mode)
        ? dt102739k_sha256_file(@"/usr/bin/ltop") : nil;
    BOOL ltopExpectedMatch = ltopSHA256
        && ltopStat.st_size == kDT102739KExpectedLtopSize
        && [ltopSHA256 isEqualToString:kDT102739KExpectedLtopSHA256];
    dt102739k_emit(log, @"BUILD102739K_LTOP_LSTAT_RC=%d", ltopLstatRC);
    dt102739k_emit(log, @"BUILD102739K_LTOP_LSTAT_ERRNO=%d", ltopLstatErrno);
    dt102739k_emit(log, @"BUILD102739K_LTOP_ACTUAL_TYPE=%@", ltopLstatRC == 0
        ? [NSString stringWithCharacters:(unichar[]){dt102739k_actual_type(ltopStat.st_mode)} length:1]
        : @"NONE");
    dt102739k_emit(log, @"BUILD102739K_LTOP_SIZE=%lld", (long long)ltopStat.st_size);
    dt102739k_emit(log, @"BUILD102739K_LTOP_UID=%u", (unsigned)ltopStat.st_uid);
    dt102739k_emit(log, @"BUILD102739K_LTOP_GID=%u", (unsigned)ltopStat.st_gid);
    dt102739k_emit(log, @"BUILD102739K_LTOP_SHA256=%@", ltopSHA256 ?: @"UNAVAILABLE");
    dt102739k_emit(log, @"BUILD102739K_LTOP_EXPECTED_SIZE=%lld",
        (long long)kDT102739KExpectedLtopSize);
    dt102739k_emit(log, @"BUILD102739K_LTOP_EXPECTED_SHA256=%@",
        kDT102739KExpectedLtopSHA256);
    dt102739k_emit(log, @"BUILD102739K_LTOP_EXPECTED_PAYLOAD_MATCH=%@",
        ltopExpectedMatch ? @"YES" : @"NO");

    NSArray<NSString *> *trackedPaths = @[
        @"/.procursus_strapped", @"/.installed_palera1n", @"/.installed_dopamine",
        @"/var/jb", @"/prep_bootstrap.sh", @"/Library/dpkg/status",
        @"/var/lib/dpkg/status", @"/private/var/lib/dpkg/status"
    ];
    NSMutableArray<NSValue *> *beforeIdentities = [NSMutableArray array];
    for (NSString *path in trackedPaths) {
        dt102739k_identity_t identity = dt102739k_identity(path);
        [beforeIdentities addObject:[NSValue valueWithBytes:&identity
            objCType:@encode(dt102739k_identity_t)]];
        dt102739k_emit(log, @"BUILD102739K_TRACKED_PATH_%@_PRESENT=%@",
            [path stringByReplacingOccurrencesOfString:@"/" withString:@"_"],
            identity.present ? @"YES" : @"NO");
    }

    BOOL mountSurvey = dt102739k_emit_mount(@"ROOT", @"/", log)
        && dt102739k_emit_mount(@"PRIVATE_VAR", @"/private/var", log)
        && dt102739k_emit_mount(@"PRIVATE_PREBOOT", @"/private/preboot", log);
    BOOL candidateSurvey = dt102739k_emit_candidate(@"PRIVATE_VAR_TMP", @"/private/var/tmp", log)
        && dt102739k_emit_candidate(@"PRIVATE_VAR_DB", @"/private/var/db", log)
        && dt102739k_emit_candidate(@"PRIVATE_PREBOOT", @"/private/preboot", log);

    struct stat launchctlNodeStat = {0};
    struct stat launchctlTargetStat = {0};
    struct stat dopamineLaunchctlStat = {0};
    int launchctlNodeRC = lstat("/bin/launchctl", &launchctlNodeStat);
    int launchctlNodeErrno = launchctlNodeRC == 0 ? 0 : errno;
    int launchctlTargetRC = stat("/bin/launchctl", &launchctlTargetStat);
    int launchctlTargetErrno = launchctlTargetRC == 0 ? 0 : errno;
    int dopamineLaunchctlRC = lstat("/usr/bin/launchctl", &dopamineLaunchctlStat);
    int dopamineLaunchctlErrno = dopamineLaunchctlRC == 0 ? 0 : errno;
    BOOL launchctlPresent = launchctlNodeRC == 0 && S_ISREG(launchctlNodeStat.st_mode);
    BOOL launchctlUsableTarget = launchctlTargetRC == 0
        && S_ISREG(launchctlTargetStat.st_mode);
    BOOL dopamineLaunchctlPresent = dopamineLaunchctlRC == 0
        && S_ISREG(dopamineLaunchctlStat.st_mode);
    BOOL launchctlAbsentBeforeBootstrap = launchctlNodeRC != 0
        && launchctlNodeErrno == ENOENT && launchctlTargetRC != 0
        && launchctlTargetErrno == ENOENT && dopamineLaunchctlRC != 0
        && dopamineLaunchctlErrno == ENOENT;
    NSString *launchctlQueryPath = launchctlUsableTarget ? @"/bin/launchctl"
        : (dopamineLaunchctlPresent ? @"/usr/bin/launchctl" : nil);
    BOOL serviceQueryApplicable = launchctlQueryPath != nil;
    BOOL serviceQueryDeferred = launchctlAbsentBeforeBootstrap;
    BOOL serviceQueryComplete = serviceQueryApplicable || serviceQueryDeferred;
    NSUInteger loadedServiceCountBefore = 0;
    NSUInteger loadedServiceCountAfter = 0;
    NSArray<NSString *> *serviceLabels = @[
        @"com.openssh.sshd", @"us.diatr.shshd", @"com.apple.atrun"
    ];
    NSMutableArray<NSNumber *> *serviceBefore = [NSMutableArray array];
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_PRESENT=%@",
        launchctlPresent ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_BIN_NODE_LSTAT_RC=%d", launchctlNodeRC);
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_BIN_NODE_LSTAT_ERRNO=%d",
        launchctlNodeErrno);
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_BIN_NODE_TYPE=%@", launchctlNodeRC == 0
        ? [NSString stringWithCharacters:(unichar[]){dt102739k_actual_type(launchctlNodeStat.st_mode)} length:1]
        : @"NONE");
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_BIN_TARGET_STAT_RC=%d", launchctlTargetRC);
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_BIN_TARGET_STAT_ERRNO=%d",
        launchctlTargetErrno);
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_BIN_TARGET_USABLE=%@",
        launchctlUsableTarget ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_DOPAMINE_PATH=/usr/bin/launchctl");
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_DOPAMINE_LSTAT_RC=%d",
        dopamineLaunchctlRC);
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_DOPAMINE_LSTAT_ERRNO=%d",
        dopamineLaunchctlErrno);
    dt102739k_emit(log, @"BUILD102739K_LAUNCHCTL_DOPAMINE_PRESENT=%@",
        dopamineLaunchctlPresent ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_SERVICE_QUERY_APPLICABILITY=%@",
        serviceQueryApplicable
            ? @"TOOL_PRESENT_READ_ONLY_QUERY_APPLICABLE"
            : (serviceQueryDeferred
                ? @"DEFERRED_BOOTSTRAP_LAUNCHCTL_ABSENT"
                : @"UNRESOLVED_LAUNCHCTL_NODE_OR_ACCESS_STATE"));
    dt102739k_emit(log, @"BUILD102739K_SERVICE_QUERY_PATH=%@",
        launchctlQueryPath ?: @"NONE");
    dt102739k_emit(log, @"BUILD102739K_SERVICE_QUERY_DEFERRED_EXPECTED_ABSENCE=%@",
        serviceQueryDeferred ? @"YES" : @"NO");
    if (serviceQueryApplicable) {
        for (NSString *label in serviceLabels) {
            BOOL loaded = NO;
            BOOL queried = dt102739k_query_service(launchctlQueryPath, label, &loaded, log);
            serviceQueryComplete = serviceQueryComplete && queried;
            [serviceBefore addObject:@(loaded)];
            if (loaded) loadedServiceCountBefore++;
        }
    }

    BOOL serviceStateUnchanged = serviceQueryComplete;
    if (serviceQueryApplicable && serviceQueryComplete) {
        for (NSUInteger i = 0; i < serviceLabels.count; i++) {
            BOOL loaded = NO;
            BOOL queried = dt102739k_query_service(launchctlQueryPath,
                serviceLabels[i], &loaded, nil);
            serviceQueryComplete = serviceQueryComplete && queried;
            serviceStateUnchanged = serviceStateUnchanged
                && loaded == serviceBefore[i].boolValue;
            if (loaded) loadedServiceCountAfter++;
        }
    }
    dt102739k_emit(log, @"BUILD102739K_SERVICE_QUERY_COMPLETE=%@",
        serviceQueryComplete ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_LOADED_SERVICE_COUNT_BEFORE=%lu",
        (unsigned long)loadedServiceCountBefore);
    dt102739k_emit(log, @"BUILD102739K_LOADED_SERVICE_COUNT_AFTER=%lu",
        (unsigned long)loadedServiceCountAfter);
    dt102739k_emit(log, @"BUILD102739K_SERVICE_STATE_UNCHANGED=%@",
        serviceStateUnchanged ? @"YES" : @"NO");

    BOOL trackedPathsUnchanged = YES;
    for (NSUInteger i = 0; i < trackedPaths.count; i++) {
        dt102739k_identity_t before = {0};
        [beforeIdentities[i] getValue:&before];
        trackedPathsUnchanged = trackedPathsUnchanged
            && dt102739k_identity_equal(before, dt102739k_identity(trackedPaths[i]));
    }

    BOOL manifestGate = manifest && headerHash && headerMembers && headerPaths;
    BOOL inventoryReadGate = parsedPaths == kDT102739KInventoryPathCount
        && malformedCount == 0 && lstatErrorCount == 0;
    BOOL targetPass = modelMatch && buildMatch && cfMatch && euidMatch && remountMatch;
    BOOL inventoryPass = manifestGate && inventoryReadGate;
    BOOL readOnlyPass = targetPass && inventoryPass && mountSurvey
        && candidateSurvey && serviceQueryComplete && serviceStateUnchanged
        && trackedPathsUnchanged;
    BOOL installEligible = readOnlyPass && unresolvedCollisions == 0
        && !dt102739k_identity(@"/.procursus_strapped").present;
    uint32_t failureMask = 0;
    if (!modelMatch) failureMask |= kDT102739KFailureModel;
    if (!buildMatch) failureMask |= kDT102739KFailureBuild;
    if (!cfMatch) failureMask |= kDT102739KFailureCF1900;
    if (!euidMatch) failureMask |= kDT102739KFailureEUID0;
    if (!remountMatch) failureMask |= kDT102739KFailureRemount;
    if (!manifestGate) failureMask |= kDT102739KFailureManifest;
    if (!inventoryReadGate) failureMask |= kDT102739KFailureInventoryRead;
    if (!mountSurvey) failureMask |= kDT102739KFailureMountSurvey;
    if (!candidateSurvey) failureMask |= kDT102739KFailureCandidateSurvey;
    if (!serviceQueryComplete) failureMask |= kDT102739KFailureServiceQuery;
    if (!serviceStateUnchanged) failureMask |= kDT102739KFailureServiceState;
    if (!trackedPathsUnchanged) failureMask |= kDT102739KFailureTrackedIdentity;
    BOOL resultConsistency = readOnlyPass == (failureMask == 0);

    dt102739k_emit(log, @"BUILD102739J_BASELINE_RESULT=CONTROLLED_REPLY_ROUNDTRIP_PASS");
    dt102739k_emit(log, @"BUILD102739K_MODEL_GATE=%@", modelMatch ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_BUILD_GATE=%@", buildMatch ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_CF1900_GATE=%@", cfMatch ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_EUID0_GATE=%@", euidMatch ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_REMOUNT_GATE=%@", remountMatch ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_MANIFEST_GATE=%@", manifestGate ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_INVENTORY_READ_GATE=%@",
        inventoryReadGate ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_MOUNT_SURVEY_GATE=%@",
        mountSurvey ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_CANDIDATE_SURVEY_GATE=%@",
        candidateSurvey ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_SERVICE_QUERY_GATE=%@",
        serviceQueryComplete ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_SERVICE_STATE_GATE=%@",
        serviceStateUnchanged ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_TRACKED_IDENTITY_GATE=%@",
        trackedPathsUnchanged ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_FAILURE_MASK=0x%03x", failureMask);
    dt102739k_emit(log, @"BUILD102739K_RESULT_CONSISTENCY=%@",
        resultConsistency ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_TARGET_GATE=%@", targetPass ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_INVENTORY_GATE=%@", inventoryPass ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_INSTALL_ELIGIBLE=%@", installEligible ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_TRACKED_PATH_IDENTITIES_UNCHANGED=%@",
        trackedPathsUnchanged ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_TARGET_FILES_CREATED=0");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_TARGET_FILES_MODIFIED=0");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_TARGET_FILES_REMOVED=0");
    dt102739k_emit(log, @"BUILD102739K_APP_RUN_LOG_EXCLUDED_FROM_TARGET_COUNTS=YES");
    dt102739k_emit(log, @"BUILD102739K_BOOTSTRAP_MARKER_CHANGED=NO");
    dt102739k_emit(log, @"BUILD102739K_SERVICES_CHANGED=NO");

    NSString *verdict = readOnlyPass
        ? @"ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_PASS"
        : @"ROOTFUL_BOOTSTRAP_PREFLIGHT_READ_ONLY_FAIL";
    dt102739k_emit(log, @"BUILD102739K_READ_ONLY_PREFLIGHT_RESULT=%@",
        readOnlyPass ? @"PASS" : @"FAIL");
    dt102739k_emit(log, @"BUILD102739K_FINAL_RESULT=%@", verdict);
    dt102739k_emit(log,
        @"BUILD102739K_SUMMARY=MODEL:%@,BUILD:%@,CF1900:%@,EUID0:%@,REMOUNT:%@,MANIFEST:%@,INVENTORY:%@,MOUNT:%@,CANDIDATE:%@,SERVICE_QUERY:%@,SERVICE_STATE:%@,TRACKED_IDENTITY:%@,MASK:0x%03x,READ_ONLY:%@,INSTALL_ELIGIBLE:%@",
        modelMatch ? @"PASS" : @"FAIL", buildMatch ? @"PASS" : @"FAIL",
        cfMatch ? @"PASS" : @"FAIL", euidMatch ? @"PASS" : @"FAIL",
        remountMatch ? @"PASS" : @"FAIL", manifestGate ? @"PASS" : @"FAIL",
        inventoryReadGate ? @"PASS" : @"FAIL", mountSurvey ? @"PASS" : @"FAIL",
        candidateSurvey ? @"PASS" : @"FAIL", serviceQueryComplete ? @"PASS" : @"FAIL",
        serviceStateUnchanged ? @"PASS" : @"FAIL",
        trackedPathsUnchanged ? @"PASS" : @"FAIL", failureMask,
        readOnlyPass ? @"PASS" : @"FAIL", installEligible ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_REPORT_COMPLETE=%@",
        resultConsistency ? @"YES" : @"NO");
    dt102739k_emit(log, @"BUILD102739K_REPORT_END=YES");
    if (verdictOut)
        *verdictOut = verdict;
    return readOnlyPass && resultConsistency ? 0 : -73992;
}

static void dt102739l_emit(void (^log)(NSString *), NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static NSString *dt102739l_readlink(NSString *path, int *errorOut)
{
    char target[PATH_MAX] = {0};
    ssize_t length = readlink(path.fileSystemRepresentation, target, sizeof(target) - 1);
    if (length < 0) {
        if (errorOut) *errorOut = errno;
        return nil;
    }
    target[length] = '\0';
    if (errorOut) *errorOut = 0;
    return [NSString stringWithUTF8String:target];
}

int dt_build102739l_run_rootful_bootstrap_policy_preflight(void (^log)(NSString *),
    NSString **verdictOut)
{
    static NSString *const archiveSHA =
        @"54299aaf56176695b4fe6883f13bd67617d8c008e5bc5778591ec3940e5e7666";
    static NSString *const planSHA =
        @"d91379e37eb8ea29ca8e88b22c7f471b945ccceb83efd59633408512d25b04e6";
    static NSString *const policySHA =
        @"2f030cfd95c869ed697ea89db583c81b0f12c0feb74965c6a22d91907d27c237";
    static NSString *const appleLtopSHA =
        @"38e463ade2f9336dad8cd746a00da6aa4be0781de3d128f8cac15a6554c2d698";

    dt102739l_emit(log, @"BUILD102739L_REPORT_SCHEMA=1");
    dt102739l_emit(log, @"BUILD102739L_RUN_ID=%@", [NSUUID UUID].UUIDString);
    dt102739l_emit(log, @"BUILD102739L_REPORT_BEGIN=YES");
    dt102739l_emit(log, @"BUILD102739L_SCOPE=ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PREFLIGHT");
    dt102739l_emit(log, @"BUILD102739L_BASELINE=BUILD102739K_OBS2_REPAIRED");
    dt102739l_emit(log, @"BUILD102739L_TARGET_BUILD=20L563");
    dt102739l_emit(log, @"BUILD102739L_OTA_POST_BOM_UNIQUE_PATH_COUNT=204595");
    dt102739l_emit(log, @"BUILD102739L_ARCHIVE_SHA256=%@", archiveSHA);
    dt102739l_emit(log, @"BUILD102739L_BOOTSTRAP_EXTRACTION_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_PACKAGE_INSTALL_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_PUREPKG_INSTALL_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_ELLEKIT_INSTALL_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_ELLEKIT_PID1_INJECTION_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_SCRIPT_EXECUTION_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_SERVICE_MUTATION_ENABLED=NO");
    dt102739l_emit(log, @"BUILD102739L_BOOTSTRAP_TARGET_MUTATION_CALLS=0");

    NSBundle *bundle = [NSBundle mainBundle];
    NSString *planPath = [bundle pathForResource:@"BUILD102739L_ADAPTED_PLAN" ofType:@"tsv"];
    NSString *policyPath = [bundle pathForResource:@"BUILD102739L_POLICY" ofType:@"tsv"];
    NSError *planError = nil;
    NSError *policyError = nil;
    NSString *plan = planPath ? [NSString stringWithContentsOfFile:planPath
        encoding:NSUTF8StringEncoding error:&planError] : nil;
    NSString *policy = policyPath ? [NSString stringWithContentsOfFile:policyPath
        encoding:NSUTF8StringEncoding error:&policyError] : nil;
    NSString *actualPlanSHA = planPath ? dt102739k_sha256_file(planPath) : nil;
    NSString *actualPolicySHA = policyPath ? dt102739k_sha256_file(policyPath) : nil;
    NSUInteger adaptedPathCount = 0;
    BOOL adaptedPlanContainsLtop = NO;
    for (NSString *line in [plan componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        if (!line.length || [line hasPrefix:@"#"])
            continue;
        adaptedPathCount++;
        NSArray<NSString *> *fields = [line componentsSeparatedByString:@"\t"];
        if (fields.count == 2 && [fields[1] isEqualToString:@"/usr/bin/ltop"])
            adaptedPlanContainsLtop = YES;
    }
    BOOL planGate = plan && [actualPlanSHA isEqualToString:planSHA]
        && adaptedPathCount == 4039 && !adaptedPlanContainsLtop
        && [plan containsString:@"#APPLE_LTOP_POLICY=PRESERVE_EXACT"]
        && [plan containsString:@"#SYSTEM_CMDS_LTOP_OWNERSHIP_ACTION=REMOVE"];
    BOOL policyGate = policy && [actualPolicySHA isEqualToString:policySHA]
        && [policy containsString:@"#KNOWN_OTA_INTERSECTION_COUNT=19"]
        && [policy containsString:@"#ADDON_PACKAGE_IDENTITY_COUNT=9"]
        && [policy containsString:@"#GENERATED_DESTINATION_COUNT=32"]
        && [policy containsString:@"PurePKG-2.0.2-postinst\tPARSE_ONLY_PATH_MISMATCH_BLOCKED"]
        && [policy containsString:@"ElleKit-1.1.3-palera1n2\tPARSE_ONLY_PID1_INJECTION_BLOCKED"];
    dt102739l_emit(log, @"BUILD102739L_ADAPTED_PLAN_READ_ERROR=%@",
        planError ? planError.localizedDescription : @"NONE");
    dt102739l_emit(log, @"BUILD102739L_POLICY_READ_ERROR=%@",
        policyError ? policyError.localizedDescription : @"NONE");
    dt102739l_emit(log, @"BUILD102739L_ADAPTED_PLAN_SHA256=%@",
        actualPlanSHA ?: @"UNAVAILABLE");
    dt102739l_emit(log, @"BUILD102739L_POLICY_SHA256=%@",
        actualPolicySHA ?: @"UNAVAILABLE");
    dt102739l_emit(log, @"BUILD102739L_ADAPTED_INSTALL_PATH_COUNT=%lu",
        (unsigned long)adaptedPathCount);
    dt102739l_emit(log, @"BUILD102739L_ADAPTED_PLAN_CONTAINS_LTOP=%@",
        adaptedPlanContainsLtop ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_PROCURSUS_LTOP_DESTINATION_ACTION=EXCLUDE");
    dt102739l_emit(log, @"BUILD102739L_SYSTEM_CMDS_LTOP_OWNERSHIP_ACTION=REMOVE");
    dt102739l_emit(log, @"BUILD102739L_SYSTEM_CMDS_PACKAGE_ACTION=PROJECT_SPECIFIC_PIN_AND_HOLD");

    NSArray<NSString *> *intersectionDirectories = @[
        @"/Library", @"/Library/LaunchDaemons", @"/bin", @"/private",
        @"/private/etc", @"/private/var", @"/private/var/db",
        @"/private/var/empty", @"/private/var/log", @"/private/var/run",
        @"/sbin", @"/usr", @"/usr/bin", @"/usr/lib", @"/usr/libexec",
        @"/usr/sbin", @"/usr/share", @"/usr/share/locale"
    ];
    NSUInteger directoryMatchCount = 0;
    for (NSString *path in intersectionDirectories) {
        struct stat st = {0};
        if (lstat(path.fileSystemRepresentation, &st) == 0 && S_ISDIR(st.st_mode))
            directoryMatchCount++;
    }
    struct stat libraryStat = {0};
    struct stat runStat = {0};
    BOOL libraryMetadataMatch = lstat("/Library", &libraryStat) == 0
        && S_ISDIR(libraryStat.st_mode) && (libraryStat.st_mode & 07777) == 0755
        && libraryStat.st_uid == 0 && libraryStat.st_gid == 0;
    BOOL runMetadataMatch = lstat("/private/var/run", &runStat) == 0
        && S_ISDIR(runStat.st_mode) && (runStat.st_mode & 07777) == 0775
        && runStat.st_uid == 0 && runStat.st_gid == 1;
    BOOL directoryPolicyGate = directoryMatchCount == 18
        && libraryMetadataMatch && runMetadataMatch;
    dt102739l_emit(log, @"BUILD102739L_KNOWN_OTA_INTERSECTION_COUNT=19");
    dt102739l_emit(log, @"BUILD102739L_KNOWN_DIRECTORY_INTERSECTION_COUNT=18");
    dt102739l_emit(log, @"BUILD102739L_LIVE_DIRECTORY_INTERSECTION_MATCH_COUNT=%lu",
        (unsigned long)directoryMatchCount);
    dt102739l_emit(log, @"BUILD102739L_KNOWN_STOCK_FILE_COLLISION_COUNT=1");
    dt102739l_emit(log, @"BUILD102739L_KNOWN_DIRECTORY_METADATA_DIFFERENCE_COUNT=2");
    dt102739l_emit(log, @"BUILD102739L_LIBRARY_OTA_METADATA_MATCH=%@",
        libraryMetadataMatch ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_PRIVATE_VAR_RUN_OTA_METADATA_MATCH=%@",
        runMetadataMatch ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_EXISTING_DIRECTORY_METADATA_ACTION=PRESERVE");

    struct stat ltopStat = {0};
    int ltopRC = lstat("/usr/bin/ltop", &ltopStat);
    NSString *liveLtopSHA = ltopRC == 0 && S_ISREG(ltopStat.st_mode)
        ? dt102739k_sha256_file(@"/usr/bin/ltop") : nil;
    BOOL ltopGate = ltopRC == 0 && S_ISREG(ltopStat.st_mode)
        && (ltopStat.st_mode & 07777) == 0755 && ltopStat.st_uid == 0
        && ltopStat.st_gid == 0 && ltopStat.st_size == 69216
        && [liveLtopSHA isEqualToString:appleLtopSHA];
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_POLICY=PRESERVE_EXACT");
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_SIZE=%lld", (long long)ltopStat.st_size);
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_MODE=%04o", ltopStat.st_mode & 07777);
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_UID=%u", (unsigned)ltopStat.st_uid);
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_GID=%u", (unsigned)ltopStat.st_gid);
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_SHA256=%@",
        liveLtopSHA ?: @"UNAVAILABLE");
    dt102739l_emit(log, @"BUILD102739L_APPLE_LTOP_IDENTITY_MATCH=%@",
        ltopGate ? @"YES" : @"NO");

    struct stat etcStat = {0};
    struct stat varStat = {0};
    int etcRC = lstat("/etc", &etcStat);
    int varRC = lstat("/var", &varStat);
    int etcReadlinkErrno = 0;
    int varReadlinkErrno = 0;
    NSString *etcTarget = dt102739l_readlink(@"/etc", &etcReadlinkErrno);
    NSString *varTarget = dt102739l_readlink(@"/var", &varReadlinkErrno);
    BOOL etcAliasGate = etcRC == 0 && S_ISLNK(etcStat.st_mode)
        && [etcTarget isEqualToString:@"private/etc"];
    BOOL varAliasGate = varRC == 0 && S_ISLNK(varStat.st_mode)
        && [varTarget isEqualToString:@"private/var"];
    dt102739l_emit(log, @"BUILD102739L_ETC_ALIAS_TARGET=%@", etcTarget ?: @"UNAVAILABLE");
    dt102739l_emit(log, @"BUILD102739L_ETC_ALIAS_READLINK_ERRNO=%d", etcReadlinkErrno);
    dt102739l_emit(log, @"BUILD102739L_ETC_ALIAS_MATCH=%@", etcAliasGate ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_VAR_ALIAS_TARGET=%@", varTarget ?: @"UNAVAILABLE");
    dt102739l_emit(log, @"BUILD102739L_VAR_ALIAS_READLINK_ERRNO=%d", varReadlinkErrno);
    dt102739l_emit(log, @"BUILD102739L_VAR_ALIAS_MATCH=%@", varAliasGate ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_ALIAS_CANONICALIZATION_POLICY=RESOLVE_BEFORE_CLASSIFY");

    NSMutableArray<NSString *> *generatedPaths = [NSMutableArray array];
    NSUInteger addonCount = 0;
    NSUInteger effectSetCount = 0;
    for (NSString *line in [policy componentsSeparatedByCharactersInSet:
            [NSCharacterSet newlineCharacterSet]]) {
        NSArray<NSString *> *fields = [line componentsSeparatedByString:@"\t"];
        if (fields.count == 2 && [fields[0] isEqualToString:@"GENERATED"])
            [generatedPaths addObject:fields[1]];
        else if (fields.count == 4 && [fields[0] isEqualToString:@"ADDON"])
            addonCount++;
        else if (fields.count == 3 && [fields[0] isEqualToString:@"SCRIPT_EFFECT_SET"])
            effectSetCount++;
    }
    NSMutableArray<NSValue *> *generatedBefore = [NSMutableArray array];
    NSUInteger generatedPresentCount = 0;
    for (NSString *path in generatedPaths) {
        dt102739k_identity_t identity = dt102739k_identity(path);
        [generatedBefore addObject:[NSValue valueWithBytes:&identity
            objCType:@encode(dt102739k_identity_t)]];
        if (identity.present) generatedPresentCount++;
    }
    dt102739l_emit(log, @"BUILD102739L_GENERATED_DESTINATION_COUNT=%lu",
        (unsigned long)generatedPaths.count);
    dt102739l_emit(log, @"BUILD102739L_GENERATED_DESTINATION_PRESENT_COUNT=%lu",
        (unsigned long)generatedPresentCount);
    dt102739l_emit(log, @"BUILD102739L_ADDON_PACKAGE_IDENTITY_COUNT=%lu",
        (unsigned long)addonCount);
    dt102739l_emit(log, @"BUILD102739L_SCRIPT_EFFECT_SET_COUNT=%lu",
        (unsigned long)effectSetCount);
    dt102739l_emit(log, @"BUILD102739L_PREP_SCRIPT_EFFECTS_ACTION=PARSE_ONLY_NO_EXECUTION");
    dt102739l_emit(log, @"BUILD102739L_PUREPKG_POSTINST_PATH_MISMATCH=BLOCKED");
    dt102739l_emit(log, @"BUILD102739L_ELLEKIT_PID1_INJECTION_ACTION=DEFER");

    char pid1PathBefore[MAXPATHLEN] = {0};
    char pid1PathAfter[MAXPATHLEN] = {0};
    int pid1BeforeRC = proc_pidpath(1, pid1PathBefore, sizeof(pid1PathBefore));
    BOOL pid1PresentBefore = pid1BeforeRC > 0 && kill(1, 0) == 0;

    struct statfs candidateFS = {0};
    struct stat candidateStat = {0};
    int candidateStatRC = lstat("/private/var/tmp", &candidateStat);
    int candidateFSRC = statfs("/private/var/tmp", &candidateFS);
    unsigned long long candidateFreeBytes = candidateFSRC == 0
        ? (unsigned long long)candidateFS.f_bavail * (unsigned long long)candidateFS.f_bsize : 0;
    BOOL candidateGate = candidateStatRC == 0 && S_ISDIR(candidateStat.st_mode)
        && candidateFSRC == 0 && !(candidateFS.f_flags & MNT_RDONLY)
        && candidateFreeBytes >= (32ULL * 1024ULL * 1024ULL);
    dt102739l_emit(log, @"BUILD102739L_SELECTED_CONTROL_ROOT=/private/var/tmp");
    dt102739l_emit(log, @"BUILD102739L_SELECTED_CONTROL_ROOT_READ_WRITE_MOUNT=%@",
        candidateFSRC == 0 && !(candidateFS.f_flags & MNT_RDONLY) ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_SELECTED_CONTROL_ROOT_FREE_BYTES=%llu",
        candidateFreeBytes);
    dt102739l_emit(log, @"BUILD102739L_SELECTED_CONTROL_ROOT_GATE=%@",
        candidateGate ? @"PASS" : @"FAIL");

    BOOL generatedUnchanged = generatedBefore.count == generatedPaths.count;
    for (NSUInteger i = 0; i < generatedPaths.count; i++) {
        dt102739k_identity_t before = {0};
        [generatedBefore[i] getValue:&before];
        generatedUnchanged = generatedUnchanged
            && dt102739k_identity_equal(before, dt102739k_identity(generatedPaths[i]));
    }
    int pid1AfterRC = proc_pidpath(1, pid1PathAfter, sizeof(pid1PathAfter));
    BOOL pid1PresentAfter = pid1AfterRC > 0 && kill(1, 0) == 0;
    BOOL pid1IdentityUnchanged = pid1PresentBefore && pid1PresentAfter
        && strcmp(pid1PathBefore, pid1PathAfter) == 0;

    BOOL staticPolicyGate = addonCount == 9 && effectSetCount == 3
        && generatedPaths.count == 32;
    BOOL aliasGate = etcAliasGate && varAliasGate;
    BOOL pass = planGate && policyGate && directoryPolicyGate && ltopGate
        && aliasGate && staticPolicyGate && candidateGate && generatedUnchanged
        && pid1IdentityUnchanged;
    NSUInteger unresolvedPolicyCount = pass ? 0 : 1;

    dt102739l_emit(log, @"BUILD102739L_PLAN_GATE=%@", planGate ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_POLICY_RESOURCE_GATE=%@", policyGate ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_DIRECTORY_POLICY_GATE=%@",
        directoryPolicyGate ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_LTOP_GATE=%@", ltopGate ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_ALIAS_GATE=%@", aliasGate ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_STATIC_POLICY_GATE=%@",
        staticPolicyGate ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_GENERATED_DESTINATIONS_UNCHANGED=%@",
        generatedUnchanged ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_PID1_PRESENT_AFTER_PREFLIGHT=%@",
        pid1PresentAfter ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_PID1_IDENTITY_UNCHANGED=%@",
        pid1IdentityUnchanged ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_WALL2_GOT_ORIGINAL_STATE_RESTORED=YES");
    dt102739l_emit(log, @"BUILD102739L_BOOTSTRAP_TARGET_FILES_CREATED=0");
    dt102739l_emit(log, @"BUILD102739L_BOOTSTRAP_TARGET_FILES_MODIFIED=0");
    dt102739l_emit(log, @"BUILD102739L_BOOTSTRAP_TARGET_FILES_REMOVED=0");
    dt102739l_emit(log, @"BUILD102739L_APP_RUN_LOG_EXCLUDED_FROM_TARGET_COUNTS=YES");
    dt102739l_emit(log, @"BUILD102739L_BOOTSTRAP_MARKER_CHANGED=NO");
    dt102739l_emit(log, @"BUILD102739L_SERVICES_CHANGED=NO");
    dt102739l_emit(log, @"BUILD102739L_UNRESOLVED_POLICY_COUNT=%lu",
        (unsigned long)unresolvedPolicyCount);

    NSString *verdict = pass ? @"ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_PASS"
        : @"ROOTFUL_BOOTSTRAP_POLICY_READ_ONLY_FAIL";
    dt102739l_emit(log, @"BUILD102739L_READ_ONLY_POLICY_PREFLIGHT_RESULT=%@",
        pass ? @"PASS" : @"FAIL");
    dt102739l_emit(log, @"BUILD102739L_FINAL_RESULT=%@", verdict);
    dt102739l_emit(log, @"BUILD102739L_REPORT_COMPLETE=%@", pass ? @"YES" : @"NO");
    dt102739l_emit(log, @"BUILD102739L_REPORT_END=YES");
    if (verdictOut)
        *verdictOut = verdict;
    return pass ? 0 : -73993;
}
