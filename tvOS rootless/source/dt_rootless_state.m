#import "dt_rootless_state.h"
#import "dt_build710_preboot.h"
#import "DTRunLogger.h"

#import <sys/stat.h>
#import <unistd.h>

static NSString *const kDTRootlessIdentityName = @".installed_dopamin_rootless_r4";
static NSString *const kDTRootlessIncompleteName = @".rootless_r4_incomplete";
static NSString *const kDTRootlessIdentityVersion = @"R4";

NSString *dt_rootless_var_jb_path(void)
{
    return @"/private/var/jb";
}

NSString *dt_rootless_expected_jbroot(void)
{
    return dt710_resolve_preboot_root();
}

NSString *dt_rootless_identity_path(void)
{
    NSString *root = dt_rootless_expected_jbroot();
    if (!root.length)
        return nil;
    return [root stringByAppendingPathComponent:kDTRootlessIdentityName];
}

NSString *dt_rootless_state_name(DTRootlessVarJbState state)
{
    switch (state) {
        case DTRootlessVarJbAbsent: return @"ABSENT";
        case DTRootlessVarJbValidRootlessSymlink: return @"VALID_ROOTLESS_SYMLINK";
        case DTRootlessVarJbStaleProjectSymlink: return @"STALE_PROJECT_SYMLINK";
        case DTRootlessVarJbStaleProjectDirectory: return @"STALE_PROJECT_DIRECTORY";
        case DTRootlessVarJbLegacyRootful: return @"LEGACY_ROOTFUL";
        case DTRootlessVarJbRootlessIncomplete: return @"ROOTLESS_INCOMPLETE";
        case DTRootlessVarJbForeign: return @"FOREIGN";
        case DTRootlessVarJbCommittedValid: return @"COMMITTED_VALID";
    }
    return @"UNKNOWN";
}

static BOOL dt_rootless_path_has_legacy_markers(NSString *path)
{
    NSArray *markers = @[
        @"/.procursus_strapped",
        @"/.installed_dopamine",
        @"/.installed_palera1n",
        @"/usr/.jbroot_rootful_marker",
    ];
    NSFileManager *fm = NSFileManager.defaultManager;
    for (NSString *m in markers) {
        if ([fm fileExistsAtPath:[path stringByAppendingString:m]])
            return YES;
    }
    /* DopaminUsr volume name never appears as /var/jb target normally; treat
       non-preboot project paths without identity as legacy/foreign below. */
    return NO;
}

DTRootlessVarJbState dt_rootless_classify_var_jb(NSString **detailOut)
{
    NSString *varjb = dt_rootless_var_jb_path();
    NSString *expected = dt_rootless_expected_jbroot();
    NSFileManager *fm = NSFileManager.defaultManager;

    if (!expected.length) {
        if (detailOut) *detailOut = @"expected JBROOT unresolved (boot-manifest-hash)";
        return DTRootlessVarJbForeign;
    }

    struct stat st;
    if (lstat(varjb.fileSystemRepresentation, &st) != 0) {
        if (detailOut) *detailOut = @"/private/var/jb absent";
        if ([fm fileExistsAtPath:[expected stringByAppendingPathComponent:kDTRootlessIncompleteName]])
            return DTRootlessVarJbRootlessIncomplete;
        return DTRootlessVarJbAbsent;
    }

    if (S_ISLNK(st.st_mode)) {
        char buf[1024];
        ssize_t n = readlink(varjb.fileSystemRepresentation, buf, sizeof(buf) - 1);
        if (n < 0) {
            if (detailOut) *detailOut = @"readlink failed";
            return DTRootlessVarJbForeign;
        }
        buf[n] = 0;
        NSString *target = @(buf);
        if ([target isEqualToString:expected]) {
            if ([fm fileExistsAtPath:dt_rootless_identity_path()]) {
                if (detailOut) *detailOut = target;
                return DTRootlessVarJbCommittedValid;
            }
            if ([fm fileExistsAtPath:[expected stringByAppendingPathComponent:kDTRootlessIncompleteName]]) {
                if (detailOut) *detailOut = @"symlink ok but incomplete";
                return DTRootlessVarJbRootlessIncomplete;
            }
            if (detailOut) *detailOut = target;
            return DTRootlessVarJbValidRootlessSymlink;
        }
        /* Project preboot family but wrong boot hash */
        if ([target containsString:@"/dopamin-tvos-102710/procursus"]) {
            if (detailOut) *detailOut = [NSString stringWithFormat:@"stale symlink -> %@", target];
            return DTRootlessVarJbStaleProjectSymlink;
        }
        if (detailOut) *detailOut = [NSString stringWithFormat:@"FOREIGN symlink -> %@", target];
        return DTRootlessVarJbForeign;
    }

    if (S_ISDIR(st.st_mode)) {
        if (dt_rootless_path_has_legacy_markers(varjb)) {
            if (detailOut) *detailOut = @"legacy rootful directory markers under /var/jb";
            return DTRootlessVarJbLegacyRootful;
        }
        /* Positive project ownership required before STALE_PROJECT_DIRECTORY.
         * Mere presence of a directory at /var/jb is NOT ownership proof (M4). */
        BOOL owned = [fm fileExistsAtPath:dt_rootless_identity_path()]
            || [fm fileExistsAtPath:[expected stringByAppendingPathComponent:kDTRootlessIncompleteName]]
            || [fm fileExistsAtPath:[varjb stringByAppendingPathComponent:kDTRootlessIncompleteName]]
            || [fm fileExistsAtPath:[varjb stringByAppendingPathComponent:kDTRootlessIdentityName]]
            || [fm fileExistsAtPath:[varjb stringByAppendingPathComponent:@"basebin/launchdhook516.dylib"]];
        if (!owned) {
            if (detailOut) *detailOut = @"FOREIGN directory at /var/jb (no project identity/incomplete/basebin proof)";
            return DTRootlessVarJbForeign;
        }
        if (detailOut) *detailOut = @"project-owned directory at /var/jb (stale layout)";
        return DTRootlessVarJbStaleProjectDirectory;
    }

    if (detailOut) *detailOut = @"unexpected /var/jb node type";
    return DTRootlessVarJbForeign;
}

BOOL dt_rootless_ensure_symlink(void (^log)(NSString *), NSString **errOut)
{
    NSString *detail = nil;
    DTRootlessVarJbState st = dt_rootless_classify_var_jb(&detail);
    NSString *expected = dt_rootless_expected_jbroot();
    NSString *varjb = dt_rootless_var_jb_path();
    NSFileManager *fm = NSFileManager.defaultManager;

    void (^emit)(NSString *) = ^(NSString *line) {
        [[DTRunLogger shared] log:line];
        if (log) log(line);
    };

    emit([NSString stringWithFormat:@"ROOTLESS_VAR_JB_STATE=%@ detail=%@",
          dt_rootless_state_name(st), detail ?: @""]);

    if (st == DTRootlessVarJbForeign) {
        if (errOut) *errOut = detail ?: @"FOREIGN /var/jb blocked (no destructive repair)";
        return NO;
    }
    if (st == DTRootlessVarJbCommittedValid || st == DTRootlessVarJbValidRootlessSymlink) {
        return YES;
    }
    if (!expected.length) {
        if (errOut) *errOut = @"JBROOT unresolved";
        return NO;
    }

    NSError *err = nil;
    if (st == DTRootlessVarJbStaleProjectDirectory || st == DTRootlessVarJbLegacyRootful) {
        /* Project-owned or legacy-rootful directory: rename aside (preserve;
         * do not delete Dopamin* volumes / manifests). Then create symlink. */
        NSString *aside = [NSString stringWithFormat:@"%@.legacy_%ld", varjb, (long)time(NULL)];
        if (![fm moveItemAtPath:varjb toPath:aside error:&err]) {
            if (errOut) *errOut = err.localizedDescription ?: @"failed to move legacy/stale project /var/jb";
            return NO;
        }
        emit([NSString stringWithFormat:@"ROOTLESS_LEGACY_VAR_JB_MOVED=%@", aside]);
    } else if (st == DTRootlessVarJbStaleProjectSymlink || st == DTRootlessVarJbRootlessIncomplete) {
        unlink(varjb.fileSystemRepresentation);
    }

    /* ensure parent /private/var exists */
    [fm createDirectoryAtPath:expected withIntermediateDirectories:YES attributes:nil error:nil];
    if (![fm createSymbolicLinkAtPath:varjb withDestinationPath:expected error:&err]) {
        /* race: already correct */
        NSString *now = nil;
        DTRootlessVarJbState again = dt_rootless_classify_var_jb(&now);
        if (again == DTRootlessVarJbValidRootlessSymlink || again == DTRootlessVarJbCommittedValid)
            return YES;
        if (errOut) *errOut = err.localizedDescription ?: @"symlink create failed";
        return NO;
    }
    emit([NSString stringWithFormat:@"ROOTLESS_VAR_JB_SYMLINK=%@ -> %@", varjb, expected]);
    return YES;
}

BOOL dt_rootless_write_incomplete_marker(void)
{
    NSString *root = dt_rootless_expected_jbroot();
    if (!root.length) return NO;
    NSString *path = [root stringByAppendingPathComponent:kDTRootlessIncompleteName];
    return [@"incomplete\n" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

BOOL dt_rootless_commit_identity(void (^log)(NSString *), NSDictionary *extra, NSString **errOut)
{
    NSString *path = dt_rootless_identity_path();
    NSString *root = dt_rootless_expected_jbroot();
    if (!path.length || !root.length) {
        if (errOut) *errOut = @"identity path unresolved";
        return NO;
    }
    NSMutableDictionary *iddict = [@{
        @"version": kDTRootlessIdentityVersion,
        @"jbroot": root,
        @"var_jb": dt_rootless_var_jb_path(),
        @"product_bootstrap_sha256":
            @"64b980e1794177fcfcbea232b54677e34f3d07c230c44a4473a0f7167a7c582f",
        @"committed_at": [NSDate date].description,
    } mutableCopy];
    if (extra) [iddict addEntriesFromDictionary:extra];

    NSError *err = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:iddict
        format:NSPropertyListXMLFormat_v1_0 options:0 error:&err];
    if (!data) {
        if (errOut) *errOut = err.localizedDescription ?: @"plist encode failed";
        return NO;
    }
    if (![data writeToFile:path options:NSDataWritingAtomic error:&err]) {
        if (errOut) *errOut = err.localizedDescription ?: @"identity write failed";
        return NO;
    }
    NSString *inc = [root stringByAppendingPathComponent:kDTRootlessIncompleteName];
    [[NSFileManager defaultManager] removeItemAtPath:inc error:nil];
    if (log) log([NSString stringWithFormat:@"ROOTLESS_COMMITTED identity=%@", path]);
    [[DTRunLogger shared] log:[NSString stringWithFormat:@"ROOTLESS_COMMITTED identity=%@", path]];
    return YES;
}

BOOL dt_rootless_verify_committed(void (^log)(NSString *), NSString **errOut)
{
    NSString *detail = nil;
    DTRootlessVarJbState st = dt_rootless_classify_var_jb(&detail);
    if (log) log([NSString stringWithFormat:@"ROOTLESS_REUSE_STATE=%@ %@", dt_rootless_state_name(st), detail ?: @""]);
    if (st != DTRootlessVarJbCommittedValid) {
        if (errOut) *errOut = detail ?: dt_rootless_state_name(st);
        return NO;
    }
    NSDictionary *iddict = [NSDictionary dictionaryWithContentsOfFile:dt_rootless_identity_path()];
    NSString *expected = dt_rootless_expected_jbroot();
    if (![iddict[@"jbroot"] isEqualToString:expected]) {
        if (errOut) *errOut = @"identity jbroot mismatch vs current bootHash";
        return NO;
    }
    if (![iddict[@"version"] isEqualToString:kDTRootlessIdentityVersion]) {
        if (errOut) *errOut = @"identity version mismatch";
        return NO;
    }
    return YES;
}
