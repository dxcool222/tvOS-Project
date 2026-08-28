#import "dt_rootless_trust.h"
#import "dt_rootless_state.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"

#import <codesign.h>
#import <stdlib.h>
#import <string.h>
#import <uuid/uuid.h>

static const uuid_t kDTRootlessR4TrustUUID = {
    0x10, 0x27, 0x39, 0x4f, 0x00, 0x00, 0x40, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
};

static int dt_rl_hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static BOOL dt_rl_parse_cdhash(NSString *hex, cdhash_t out)
{
    if (hex.length != 40) return NO;
    const char *s = hex.UTF8String;
    for (int i = 0; i < 20; i++) {
        int a = dt_rl_hex_nibble(s[i * 2]);
        int b = dt_rl_hex_nibble(s[i * 2 + 1]);
        if (a < 0 || b < 0) return NO;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return YES;
}

int dt_rootless_load_trust_manifest(NSString *manifestPath, void (^log)(NSString *), NSString **errOut)
{
    if (!manifestPath.length || ![[NSFileManager defaultManager] fileExistsAtPath:manifestPath]) {
        if (errOut) *errOut = @"trust manifest missing";
        return -1;
    }
    NSString *text = [NSString stringWithContentsOfFile:manifestPath encoding:NSUTF8StringEncoding error:nil];
    if (!text) {
        if (errOut) *errOut = @"trust manifest unreadable";
        return -1;
    }
    NSArray *lines = [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
    if (lines.count < 2) {
        if (errOut) *errOut = @"trust manifest empty";
        return -1;
    }
    NSArray *hdr = [lines[0] componentsSeparatedByString:@"\t"];
    NSInteger cdIdx = [hdr indexOfObject:@"CDHASH"];
    NSInteger relIdx = [hdr indexOfObject:@"REL"];
    NSInteger incIdx = [hdr indexOfObject:@"TRUSTCACHE_INCLUDED"];
    if (cdIdx == NSNotFound) {
        if (errOut) *errOut = @"CDHASH column missing";
        return -1;
    }
    if (relIdx == NSNotFound) {
        if (errOut) *errOut = @"REL column missing";
        return -1;
    }

    NSString *jbroot = dt_rootless_expected_jbroot();
    if (!jbroot.length) {
        /* Prefer public alias when boot-hash unresolved mid-path (should not happen after FS stage). */
        jbroot = @"/private/var/jb";
    }

    NSMutableArray<NSString *> *hexes = [NSMutableArray array];
    NSMutableSet<NSString *> *seenRel = [NSMutableSet set];
    NSMutableSet<NSString *> *seenCd = [NSMutableSet set];
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *line = lines[i];
        if (!line.length) continue;
        NSArray *cols = [line componentsSeparatedByString:@"\t"];
        if (cols.count <= (NSUInteger)cdIdx || cols.count <= (NSUInteger)relIdx) {
            if (errOut) *errOut = [NSString stringWithFormat:@"truncated trust row %lu", (unsigned long)i];
            return -1;
        }
        if (incIdx != NSNotFound && cols.count > (NSUInteger)incIdx) {
            if (![cols[incIdx] isEqualToString:@"YES"]) continue;
        }
        NSString *rel = cols[relIdx];
        NSString *cd = cols[cdIdx];
        if (!rel.length) {
            if (errOut) *errOut = [NSString stringWithFormat:@"empty REL row %lu", (unsigned long)i];
            return -1;
        }
        if ([seenRel containsObject:rel]) {
            if (errOut) *errOut = [NSString stringWithFormat:@"duplicate REL %@", rel];
            return -1;
        }
        [seenRel addObject:rel];
        if (cd.length != 40) {
            if (errOut) *errOut = [NSString stringWithFormat:@"bad CDHASH row %lu", (unsigned long)i];
            return -1;
        }
        if ([cd isEqualToString:@"TBD"] || [cd isEqualToString:@"APPROX"] || [cd isEqualToString:@"PLANNED_HASH"]) {
            if (errOut) *errOut = @"stale placeholder CDHASH";
            return -1;
        }
        NSString *cdLower = cd.lowercaseString;
        if ([seenCd containsObject:cdLower]) {
            if (errOut) *errOut = [NSString stringWithFormat:@"duplicate CDHASH %@", cdLower];
            return -1;
        }
        [seenCd addObject:cdLower];

        /* Fail-closed: manifest CDHash must match the on-disk Mach-O being trusted. */
        NSString *onDisk = [jbroot stringByAppendingPathComponent:rel];
        if (![[NSFileManager defaultManager] fileExistsAtPath:onDisk]) {
            NSString *alias = [@"/private/var/jb" stringByAppendingPathComponent:rel];
            if ([[NSFileManager defaultManager] fileExistsAtPath:alias])
                onDisk = alias;
            else {
                if (errOut) *errOut = [NSString stringWithFormat:@"trust target missing %@", rel];
                return -1;
            }
        }
        cdhash_t live = {0};
        if (dt_macho_best_cdhash_from_path(onDisk.fileSystemRepresentation, live) != 0) {
            if (errOut) *errOut = [NSString stringWithFormat:@"trust CDHash unreadable %@", rel];
            return -1;
        }
        NSString *liveHex = dt_cdhash_hex_string(live).lowercaseString;
        if (![liveHex isEqualToString:cdLower]) {
            if (errOut) *errOut = [NSString stringWithFormat:
                @"trust CDHash mismatch %@ manifest=%@ live=%@", rel, cdLower, liveHex];
            return -1;
        }

        [hexes addObject:cdLower];
    }
    if (hexes.count == 0) {
        if (errOut) *errOut = @"no trust entries";
        return -1;
    }

    cdhash_t *batch = calloc(hexes.count, sizeof(cdhash_t));
    if (!batch) {
        if (errOut) *errOut = @"oom";
        return -1;
    }
    for (NSUInteger i = 0; i < hexes.count; i++) {
        if (!dt_rl_parse_cdhash(hexes[i], batch[i])) {
            free(batch);
            if (errOut) *errOut = @"cdhash parse fail";
            return -1;
        }
    }

    uint32_t uploaded = 0;
    int rc = dt_trustcache_upload_batch_cdhashes(batch, (uint32_t)hexes.count,
        kDTRootlessR4TrustUUID, &uploaded);
    free(batch);
    if (rc != 0 || uploaded != (uint32_t)hexes.count) {
        if (errOut) *errOut = [NSString stringWithFormat:@"trust upload rc=%d uploaded=%u want=%lu",
            rc, uploaded, (unsigned long)hexes.count];
        return rc != 0 ? rc : -1;
    }
    NSString *msg = [NSString stringWithFormat:@"ROOTLESS_TRUST_LOADED count=%lu", (unsigned long)hexes.count];
    [[DTRunLogger shared] log:msg];
    if (log) log(msg);
    return 0;
}

int dt_rootless_load_single_trust_path(NSString *path, const unsigned char uuid[16],
                                      void (^log)(NSString *), NSString **errOut)
{
    if (!path.length || !uuid || access(path.fileSystemRepresentation, R_OK) != 0) {
        if (errOut) *errOut = @"single trust target missing";
        return -1;
    }
    cdhash_t cdhash = {0};
    if (dt_macho_best_cdhash_from_path(path.fileSystemRepresentation, cdhash) != 0) {
        if (errOut) *errOut = @"single trust CDHash unreadable";
        return -1;
    }
    uint32_t uploaded = 0;
    int rc = dt_trustcache_upload_batch_cdhashes(&cdhash, 1, uuid, &uploaded);
    if (rc != 0 || uploaded != 1) {
        if (errOut) *errOut = [NSString stringWithFormat:
            @"single trust upload rc=%d uploaded=%u", rc, uploaded];
        return rc != 0 ? rc : -1;
    }
    NSString *line = [NSString stringWithFormat:
        @"R24_DYLD_DEDICATED_TRUST=PASS count=1 cdhash=%@",
        dt_cdhash_hex_string(cdhash)];
    [[DTRunLogger shared] log:line];
    if (log) log(line);
    return 0;
}
