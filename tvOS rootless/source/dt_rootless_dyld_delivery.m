#import "dt_rootless_dyld_delivery.h"
#import "dt_rootless_state.h"
#import "dt_rootless_trust.h"
#import "dt_build710_preboot.h"
#import "dt_macho_canonical_id.h"
#import "dt_rootless_r24_dyld_identity.h"

#import <uuid/uuid.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/loader.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>

#import "info.h"
#import "kernel.h"
#import "primitives.h"

static const uuid_t kDyldTrustUUID = {
    0x10,0x27,0x39,0x4f,0x44,0x59,0x4c,0x44,0x80,0,0,0,0,0,0,1
};

extern int dt_mount_tvos(const char *, const char *, int, void *) __asm("_mount");

static void emit(void (^log)(NSString *), NSString *line) { if (log) log(line); }
static BOOL fail(NSString **errOut, NSString *s) { if (errOut) *errOut=s; return NO; }

/*
 * Dopamine reference: BaseBin/jbctl mount_unsandboxed + jbdomain_root root_steal_ucred(0).
 * tvOS adaptation: inline self-borrow on MAIN (physrw already live) — same credential
 * transaction Q proved on 20L563 (proc_ro+0x20, ucred.label+0x78, raw slot0 cell).
 * Exact kern slot0 snapshot/restore (not hard-coded -1) per BUILD102739Q audit.
 */
typedef struct {
    uint64_t proc;
    uint64_t proc_ro;
    uint64_t org_ucred;
    uint64_t kern_proc;
    uint64_t kern_ucred;
    uint64_t kern_label;
    uint64_t org_kern_slot0;
    BOOL cred_changed;
    BOOL slot_changed;
} dt_r24_ucred_tx_t;

static BOOL dt_r24_kwrite64_readback(uint64_t kaddr, uint64_t value)
{
    /* Exact Q pattern: write success + readback match, one retry. */
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        if (kwrite64(kaddr, value) == 0 && kread64(kaddr) == value)
            return YES;
    }
    return NO;
}

static int dt_r24_restore_ucred_tx(dt_r24_ucred_tx_t *tx)
{
    BOOL cred_ok = YES;
    BOOL slot_ok = YES;
    if (tx->cred_changed && tx->proc_ro && tx->org_ucred) {
        cred_ok = dt_r24_kwrite64_readback(tx->proc_ro + koffsetof(proc_ro, ucred),
            tx->org_ucred);
        if (cred_ok)
            tx->cred_changed = NO;
    }
    if (tx->slot_changed && tx->kern_label) {
        slot_ok = dt_r24_kwrite64_readback(tx->kern_label + sizeof(uint64_t),
            tx->org_kern_slot0);
        if (slot_ok)
            tx->slot_changed = NO;
    }
    return (cred_ok && slot_ok) ? 0 : -1;
}

static int dt_r24_borrow_kernel_ucred(dt_r24_ucred_tx_t *tx, NSString **errOut)
{
    memset(tx, 0, sizeof(*tx));
    if (!gSystemInfo.kernelStruct.proc_ro.exists
        || koffsetof(proc, proc_ro) != 0x18
        || koffsetof(proc_ro, ucred) != 0x20
        || koffsetof(ucred, label) != 0x78) {
        fail(errOut, @"mount borrow layout mismatch (proc_ro/ucred/label)");
        return -1;
    }

    pid_t self_pid = getpid();
    tx->proc = proc_find(self_pid);
    tx->kern_proc = proc_find(0);
    if (!tx->proc || !tx->kern_proc) {
        fail(errOut, @"mount borrow proc_find failed");
        return -1;
    }
    if ((pid_t)kread32(tx->proc + koffsetof(proc, pid)) != self_pid) {
        fail(errOut, @"mount borrow pid mismatch");
        return -1;
    }

    tx->proc_ro = kread_ptr(tx->proc + koffsetof(proc, proc_ro));
    tx->org_ucred = proc_ucred(tx->proc);
    tx->kern_ucred = proc_ucred(tx->kern_proc);
    uint64_t org_label = tx->org_ucred
        ? kread_ptr(tx->org_ucred + koffsetof(ucred, label)) : 0;
    tx->kern_label = tx->kern_ucred
        ? kread_ptr(tx->kern_ucred + koffsetof(ucred, label)) : 0;
    if (!tx->proc_ro || !tx->org_ucred || !tx->kern_ucred
        || tx->org_ucred == tx->kern_ucred || !org_label || !tx->kern_label) {
        fail(errOut, @"mount borrow credential snapshot incomplete");
        return -1;
    }

    uint64_t org_slot0 = kread64(org_label + sizeof(uint64_t));
    tx->org_kern_slot0 = kread64(tx->kern_label + sizeof(uint64_t));
    if (org_slot0 == 0 || org_slot0 == UINT64_MAX) {
        fail(errOut, @"mount borrow caller slot0 invalid");
        return -1;
    }

    tx->cred_changed = YES;
    if (!dt_r24_kwrite64_readback(tx->proc_ro + koffsetof(proc_ro, ucred),
            tx->kern_ucred)) {
        (void)dt_r24_restore_ucred_tx(tx);
        fail(errOut, @"mount borrow ucred write/readback failed");
        return -1;
    }

    tx->slot_changed = YES;
    if (!dt_r24_kwrite64_readback(tx->kern_label + sizeof(uint64_t), org_slot0)) {
        (void)dt_r24_restore_ucred_tx(tx);
        fail(errOut, @"mount borrow slot0 write/readback failed");
        return -1;
    }
    return 0;
}

static int dt_r24_mount_bindfs_borrowed(const char *dir, int flags, void *data,
    void (^log)(NSString *), NSString **errOut)
{
    dt_r24_ucred_tx_t tx = {0};
    if (dt_r24_borrow_kernel_ucred(&tx, errOut) != 0)
        return -1;

    errno = 0;
    int mount_rc = dt_mount_tvos("bindfs", dir, flags, data);
    int mount_errno = errno;
    int restore_rc = dt_r24_restore_ucred_tx(&tx);
    if (restore_rc != 0) {
        fail(errOut, @"mount borrow restore failed after bindfs");
        errno = EPERM;
        return -1;
    }
    if (mount_rc != 0) {
        errno = mount_errno ? mount_errno : EPERM;
        return mount_rc;
    }
    emit(log, @"R24_MOUNT_BORROW=PASS kind=kernel_ucred slot0_preserved=YES");
    return 0;
}

static NSString *fileSHA(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return nil;
    CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    uint8_t buf[65536]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
    close(fd); if (n < 0) return nil;
    uint8_t out[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(out, &ctx);
    NSMutableString *hex = [NSMutableString stringWithCapacity:64];
    for (unsigned i=0;i<sizeof(out);i++) [hex appendFormat:@"%02x",out[i]];
    return hex;
}

static NSString *canonicalSHA(NSString *path)
{
    char hex[65] = {0};
    if (dt_macho_canonical_sha256_hex(path.fileSystemRepresentation, hex, sizeof(hex)) != 0)
        return nil;
    return [NSString stringWithUTF8String:hex];
}

static BOOL readUUID(NSString *path, uuid_t out)
{
    char ustr[37] = {0};
    if (dt_macho_uuid_string(path.fileSystemRepresentation, ustr, sizeof(ustr)) != 0)
        return NO;
    return uuid_parse(ustr, out) == 0;
}

typedef NS_ENUM(NSInteger, R24DyldAuthStage) {
    R24DyldAuthLookup = 1,
    R24DyldAuthPackaged,
    R24DyldAuthStaged,
    R24DyldAuthReuseOverlay,
    R24DyldAuthPostMount,
};

static const char *runtimeLayoutFailureReason(int rc)
{
    switch (rc) {
        case DT_MACHO_RUNTIME_LAYOUT_HEADER: return "HEADER";
        case DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE: return "COMMAND_TABLE";
        case DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE: return "FILE_RANGE";
        case DT_MACHO_RUNTIME_LAYOUT_CARDINALITY: return "CARDINALITY";
        case DT_MACHO_RUNTIME_LAYOUT_CS_BOUNDS: return "CS_BOUNDS";
        case DT_MACHO_RUNTIME_LAYOUT_LINKEDIT_BOUNDS: return "LINKEDIT_BOUNDS";
        case DT_MACHO_RUNTIME_LAYOUT_NON_SIGNATURE_BOUNDARY: return "NON_SIGNATURE_BOUNDARY";
        case DT_MACHO_RUNTIME_LAYOUT_JBINFO_BOUNDS: return "JBINFO_BOUNDS";
        case DT_MACHO_RUNTIME_LAYOUT_SYMBOL_BOUNDS: return "SYMBOL_BOUNDS";
        default: return "READ_OR_UNCLASSIFIED";
    }
}

static BOOL authorizeGeneratedDyld(NSString *path, R24DyldAuthStage stage, void (^log)(NSString *),
    NSString **errOut)
{
    const char *stageName = "UNKNOWN";
    switch (stage) {
        case R24DyldAuthLookup: stageName = "LOOKUP"; break;
        case R24DyldAuthPackaged: stageName = "PACKAGED"; break;
        case R24DyldAuthStaged: stageName = "STAGED"; break;
        case R24DyldAuthReuseOverlay: stageName = "REUSE"; break;
        case R24DyldAuthPostMount: stageName = "POST_MOUNT"; break;
    }

    if (!path.length) {
        emit(log, [NSString stringWithFormat:@"R24_DYLD_RESOURCE_LOOKUP=FAIL stage=%s", stageName]);
        return fail(errOut, @"packaged patched dyld resource missing");
    }
    emit(log, [NSString stringWithFormat:@"R24_DYLD_RESOURCE_LOOKUP=PASS stage=%s path=%@", stageName, path]);

    NSString *observedRaw = fileSHA(path);
    NSString *observedCanonical = canonicalSHA(path);
    char uuidObs[37] = {0};
    (void)dt_macho_uuid_string(path.fileSystemRepresentation, uuidObs, sizeof(uuidObs));

    emit(log, [NSString stringWithFormat:@"R24_DYLD_RAW_SHA_OBSERVED=%@",
        observedRaw ?: @"nil"]);
    emit(log, [NSString stringWithFormat:@"R24_DYLD_CANONICAL_SHA_OBSERVED=%@",
        observedCanonical ?: @"nil"]);
    emit(log, [NSString stringWithFormat:@"R24_DYLD_UUID_OBSERVED=%s",
        uuidObs[0] ? uuidObs : "nil"]);

    if (!observedRaw.length) {
        emit(log, @"R24_DYLD_RAW_SHA_NIL=YES");
        return fail(errOut, @"generated dyld raw SHA read/hash failed");
    }
    emit(log, @"R24_DYLD_RAW_SHA_NIL=NO");

    if (!observedCanonical.length) {
        return fail(errOut, @"generated dyld canonical identity parse failed");
    }
    if (![observedCanonical isEqualToString:@ROOTLESS_R24_GENERATED_DYLD_CANONICAL_SHA256_HEX]) {
        emit(log, [NSString stringWithFormat:@"R24_DYLD_CANONICAL_IDENTITY=FAIL expected=%@ observed=%@",
            @ROOTLESS_R24_GENERATED_DYLD_CANONICAL_SHA256_HEX, observedCanonical]);
        return fail(errOut, @"generated dyld canonical identity mismatch");
    }
    emit(log, @"R24_DYLD_CANONICAL_IDENTITY=PASS");

    dt_macho_runtime_layout_t layout = {0};
    int layoutRC = dt_macho_runtime_layout_validate(path.fileSystemRepresentation,
        (uint32_t)ROOTLESS_R24_GENERATED_DYLD_NCMDS,
        (uint32_t)ROOTLESS_R24_GENERATED_DYLD_CS_OFF,
        (uint64_t)ROOTLESS_R24_GENERATED_DYLD_MAX_NON_SIGNATURE_END,
        (uint64_t)ROOTLESS_R24_JBINFO_SECTION_SIZE,
        &layout);
    if (layoutRC != 0) {
        emit(log, [NSString stringWithFormat:
            @"R24_DYLD_RUNTIME_LAYOUT=FAIL stage=%s policy=INSTALL_TOLERANT_STRICT_BOUNDS reason=%s rc=%d",
            stageName, runtimeLayoutFailureReason(layoutRC), layoutRC]);
        return fail(errOut, @"generated dyld installed-runtime layout invalid");
    }
    emit(log, [NSString stringWithFormat:
        @"R24_DYLD_LAYOUT stage=%s file_size=%llu ncmds=%u sizeofcmds=%u cs_off=%u cs_size=%u cs_end=%llu trailer_size=%llu",
        stageName, (unsigned long long)layout.file_size, layout.ncmds, layout.sizeofcmds,
        layout.cs_off, layout.cs_size, (unsigned long long)layout.cs_end,
        (unsigned long long)layout.trailer_size]);
    emit(log, [NSString stringWithFormat:
        @"R24_DYLD_NON_CS_MAX_END=%llu expected=%u gap=%llu",
        (unsigned long long)layout.max_non_signature_end,
        (unsigned)ROOTLESS_R24_GENERATED_DYLD_MAX_NON_SIGNATURE_END,
        (unsigned long long)((uint64_t)layout.cs_off - layout.max_non_signature_end)]);
    emit(log, [NSString stringWithFormat:
        @"R24_DYLD_RUNTIME_LAYOUT=PASS stage=%s policy=INSTALL_TOLERANT_STRICT_BOUNDS",
        stageName]);

    if (strcasecmp(uuidObs, ROOTLESS_R24_GENERATED_DYLD_UUID_STR) != 0) {
        emit(log, [NSString stringWithFormat:@"R24_DYLD_UUID=FAIL expected=%@ observed=%s",
            @ROOTLESS_R24_GENERATED_DYLD_UUID_STR, uuidObs]);
        return fail(errOut, @"generated dyld UUID mismatch");
    }
    emit(log, [NSString stringWithFormat:@"R24_DYLD_UUID=PASS uuid=%@", @ROOTLESS_R24_GENERATED_DYLD_UUID_STR]);

    if (dt_macho_bytes_match_hex(path.fileSystemRepresentation,
            (uint32_t)ROOTLESS_R24_GENERATED_PATCH_OFFSET,
            ROOTLESS_R24_GENERATED_PATCH_BYTES_HEX) != 0) {
        emit(log, [NSString stringWithFormat:@"R24_DYLD_PATCH_BYTES=FAIL generated_offset=0x%x",
            (unsigned)ROOTLESS_R24_GENERATED_PATCH_OFFSET]);
        return fail(errOut, @"generated dyld patch bytes mismatch");
    }
    emit(log, [NSString stringWithFormat:
        @"R24_DYLD_PATCH_BYTES=PASS generated_offset=0x%x bytes=%@",
        (unsigned)ROOTLESS_R24_GENERATED_PATCH_OFFSET,
        @ROOTLESS_R24_GENERATED_PATCH_BYTES_HEX]);

    if (dt_macho_jbinfo_section_valid(path.fileSystemRepresentation,
            (uint64_t)ROOTLESS_R24_JBINFO_SECTION_SIZE) != 0) {
        emit(log, @"R24_DYLD_JBINFO_SECTION=FAIL");
        return fail(errOut, @"generated dyld __jbinfo section invalid");
    }
    emit(log, [NSString stringWithFormat:
        @"R24_DYLD_JBINFO_SECTION=PASS segment=__DATA section=__jbinfo size=0x%x",
        (unsigned)ROOTLESS_R24_JBINFO_SECTION_SIZE]);

    emit(log, [NSString stringWithFormat:@"R24_DYLD_RAW_SHA_TELEMETRY=%@ expected_raw=%@ expected_canonical=%@",
        observedRaw, @ROOTLESS_R24_GENERATED_DYLD_RAW_SHA256_HEX,
        @ROOTLESS_R24_GENERATED_DYLD_CANONICAL_SHA256_HEX]);
    return YES;
}

static BOOL mountedFakelib(NSString *expectedSource)
{
    struct statfs s={0};
    if (statfs("/usr/lib", &s)!=0) return NO;
    return strcmp(s.f_mntonname,"/usr/lib")==0 && (s.f_flags&MNT_RDONLY)
        && strcmp(s.f_mntfromname,expectedSource.fileSystemRepresentation)==0;
}

static BOOL ensureProtected(NSString *path, void (^log)(NSString *), NSString **errOut)
{
    struct statfs s={0};
    if (statfs(path.fileSystemRepresentation,&s)!=0)
        return fail(errOut,[NSString stringWithFormat:@"protection statfs %@ errno=%d",path,errno]);
    if (strcmp(s.f_mntonname,path.fileSystemRepresentation)==0) return YES;
    /* Dopamine ensure_protected → mount_unsandboxed("bindfs", path, 0, path). */
    if (dt_r24_mount_bindfs_borrowed(path.fileSystemRepresentation, 0,
            (void *)path.fileSystemRepresentation, log, errOut) != 0) {
        if (errOut && *errOut)
            return NO;
        return fail(errOut,[NSString stringWithFormat:@"protection bindfs %@ errno=%d",path,errno]);
    }
    memset(&s,0,sizeof(s));
    if (statfs(path.fileSystemRepresentation,&s)!=0
        || strcmp(s.f_mntonname,path.fileSystemRepresentation)!=0)
        return fail(errOut,[NSString stringWithFormat:@"protection verify %@",path]);
    return YES;
}

static BOOL replaceSymlink(NSString *path, NSString *target, NSString **errOut)
{
    NSFileManager *fm=NSFileManager.defaultManager;
    [fm removeItemAtPath:path error:nil];
    NSError *e=nil;
    if (![fm createSymbolicLinkAtPath:path withDestinationPath:target error:&e])
        return fail(errOut,[NSString stringWithFormat:@"symlink %@: %@",path,e]);
    return YES;
}

int dt_rootless_prepare_dyld_delivery(void (^log)(NSString *), NSString **errOut)
{
    emit(log,@"R24_DYLD_DELIVERY_BEGIN target=AppleTV6,2/20L563");
    if (geteuid()!=0) { fail(errOut,@"dyld delivery requires euid 0"); return -1; }
    NSString *jbroot=dt_rootless_expected_jbroot();
    if (!jbroot.length) { fail(errOut,@"current JBROOT unavailable"); return -2; }
    NSString *fakelib=[jbroot stringByAppendingPathComponent:@"basebin/.fakelib"];
    NSString *gen=[jbroot stringByAppendingPathComponent:@"basebin/gen"];
    NSString *genDyld=[gen stringByAppendingPathComponent:@"dyld"];
    NSString *systemhook=[jbroot stringByAppendingPathComponent:@"basebin/systemhook.dylib"];
    NSString *resource=[NSBundle.mainBundle pathForResource:@"dyld" ofType:nil
        inDirectory:@"R24DyldDelivery"];
    if (!authorizeGeneratedDyld(resource, R24DyldAuthPackaged, log, errOut))
        return -3;
    emit(log,@"R24_DYLD_PREGENERATED_IDENTITY=PASS authority=canonical_uuid_patch_jbinfo host_patch_merge_sign=YES runtime_resign=NO");
    if (![[NSFileManager defaultManager] fileExistsAtPath:systemhook]) {
        fail(errOut,@"current-generation systemhook missing"); return -4;
    }

    if (mountedFakelib(fakelib)) {
        if (!authorizeGeneratedDyld(@"/usr/lib/dyld", R24DyldAuthReuseOverlay, log, errOut))
            return -5;
        emit(log,@"R24_DYLD_DELIVERY=PASS mode=REUSE readonly=YES");
        return 0;
    }

    uuid_t stockUUID={0};
    static const uint8_t expectedUUID[16]={0x7c,0x25,0xad,0x4d,0x2c,0x32,0x3a,0xe3,
        0xa5,0x2c,0x0a,0xf2,0x99,0xcd,0xda,0x68};
    if (![fileSHA(@"/usr/lib/dyld") isEqualToString:@ROOTLESS_R24_STOCK_DYLD_SHA256_HEX]
        || !readUUID(@"/usr/lib/dyld",stockUUID)
        || memcmp(stockUUID,expectedUUID,16)!=0) {
        fail(errOut,@"stock tvOS dyld identity mismatch before mutation"); return -6;
    }
    emit(log,@"R24_DYLD_ORIGINAL_IDENTITY=PASS sha256=96806a0e57eef714ec806063714101f09afbbdd968346d0d6ba8c4d635b11fdf uuid=7C25AD4D-2C32-3AE3-A52C-0AF299CDDA68");
    emit(log, [NSString stringWithFormat:@"R24_DYLD_STOCK_PATCH_PROLOGUE=PASS stock_offset=0x%x bytes=%@",
        (unsigned)ROOTLESS_R24_STOCK_PATCH_OFFSET, @ROOTLESS_R24_STOCK_PATCH_PROLOGUE_HEX]);

    NSString *active=dt710_resolve_active_preboot_path();
    NSString *systemPath=[active stringByAppendingPathComponent:@"System"];
    NSString *usrPath=[active stringByAppendingPathComponent:@"usr"];
    if (!active.length
        || !ensureProtected(systemPath, log, errOut)
        || !ensureProtected(usrPath, log, errOut))
        return -7;
    emit(log,@"R24_PREBOOT_PROTECTION=PASS scope=current_generation System=bindfs usr=bindfs");

    NSFileManager *fm=NSFileManager.defaultManager; NSError *e=nil;
    if (![fm createDirectoryAtPath:gen withIntermediateDirectories:YES attributes:nil error:&e]) {
        fail(errOut,[NSString stringWithFormat:@"create gen: %@",e]); return -8;
    }
    NSString *origDyld=[gen stringByAppendingPathComponent:@"dyld.orig"];
    [fm removeItemAtPath:origDyld error:nil];
    if (![fm copyItemAtPath:@"/usr/lib/dyld" toPath:origDyld error:&e]
        || ![fileSHA(origDyld) isEqualToString:@ROOTLESS_R24_STOCK_DYLD_SHA256_HEX]) {
        fail(errOut,[NSString stringWithFormat:@"preserve stock dyld: %@",e]); return -9;
    }
    emit(log,@"R24_DYLD_ORIGINAL_PRESERVED=PASS path=basebin/gen/dyld.orig");
    [fm removeItemAtPath:fakelib error:nil];
    if (![fm copyItemAtPath:@"/usr/lib" toPath:fakelib error:&e]) {
        fail(errOut,[NSString stringWithFormat:@"copy /usr/lib: %@",e]); return -10;
    }
    [fm removeItemAtPath:genDyld error:nil];
    if (![fm copyItemAtPath:resource toPath:genDyld error:&e] || chmod(genDyld.fileSystemRepresentation,0755)!=0) {
        fail(errOut,[NSString stringWithFormat:@"stage patched dyld: %@",e]); return -11;
    }
    if (!authorizeGeneratedDyld(genDyld, R24DyldAuthStaged, log, errOut))
        return -17;
    if (!replaceSymlink([fakelib stringByAppendingPathComponent:@"dyld"],genDyld,errOut)
        || !replaceSymlink([fakelib stringByAppendingPathComponent:@"systemhook.dylib"],systemhook,errOut))
        return -12;
    emit(log,@"R24_FAKELIB_GENERATION=PASS dyld=current systemhook=current");

    NSString *trustErr=nil;
    if (dt_rootless_load_single_trust_path(genDyld,kDyldTrustUUID,log,&trustErr)!=0) {
        fail(errOut,trustErr ?: @"dedicated dyld trust failed"); return -13;
    }
    /* Dopamine fakelib_set_mounted → mount_unsandboxed bindfs /usr/lib. */
    if (dt_r24_mount_bindfs_borrowed("/usr/lib", MNT_RDONLY,
            (void *)fakelib.fileSystemRepresentation, log, errOut) != 0) {
        if (!(errOut && *errOut))
            fail(errOut,[NSString stringWithFormat:@"bindfs /usr/lib failed errno=%d",errno]);
        return -14;
    }
    if (!mountedFakelib(fakelib)) {
        fail(errOut,@"/usr/lib overlay not readonly/current"); return -15;
    }
    if (!authorizeGeneratedDyld(@"/usr/lib/dyld", R24DyldAuthPostMount, log, errOut)
        || access("/usr/lib/systemhook.dylib",R_OK)!=0) {
        if (!*errOut) fail(errOut,@"post-mount dyld/systemhook identity mismatch");
        return -16;
    }
    emit(log,@"R24_FAKELIB_MOUNT=PASS target=/usr/lib readonly=YES");
    emit(log,@"R24_DYLD_RESOLVE=PASS path=/usr/lib/dyld uuid_prefix=DOPATV165");
    emit(log,@"R24_SYSTEMHOOK_RESOLVE=PASS path=/usr/lib/systemhook.dylib generation=current");
    emit(log,@"R24_DYLD_DELIVERY=PASS mode=FRESH current_generation=YES");
    return 0;
}
