#import "dt_build99_sandbox_ext.h"

#import <dlfcn.h>
#import <errno.h>
#import <stdarg.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

#import "DTRunLogger.h"
#import "dt_physrw.h"

/// IDA §39.3 / §41.2 — consume type hex @ token[0x41..0x42] (55125C MOV W25,#0x41)
static const size_t kDTB99TokenTypeOff = 0x41;
static const size_t kDTB99TokenMinLen = 0x41;
static const size_t kDTB99TokenDumpLen = 0x50;

/// Same triple as build97/build98 (unchanged — diag only)
static const char *const kDTB99ClassRead = "com.apple.app-sandbox.read";
static const char *const kDTB99ClassReadWrite = "com.apple.app-sandbox.read-write";
static const char *const kDTB99ClassExecutable = "com.apple.sandbox.executable";
static const char *const kDTB99ExtPath = "/private/var/jb/";

typedef struct {
    const char *tag;
    const char *class_name;
} dt_b99_ext_step_t;

static const dt_b99_ext_step_t kDTB99Steps[] = {
    { "read",       kDTB99ClassRead },
    { "read-write", kDTB99ClassReadWrite },
    { "executable", kDTB99ClassExecutable },
};

static void dt_b99_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (log)
        log(msg);
    [[DTRunLogger shared] log:msg];
}

static int dt_b99_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int dt_b99_token_type_byte(const char *token, size_t len, int *hi_out, int *lo_out)
{
    if (!token || len < kDTB99TokenTypeOff + 2)
        return -1;
    int hi = dt_b99_hex_nibble(token[kDTB99TokenTypeOff]);
    int lo = dt_b99_hex_nibble(token[kDTB99TokenTypeOff + 1]);
    if (hi_out)
        *hi_out = hi;
    if (lo_out)
        *lo_out = lo;
    if (hi < 0 || lo < 0)
        return -1;
    return (hi << 4) | lo;
}

static NSString *dt_b99_token_hex_prefix(const char *token, size_t len)
{
    size_t n = len < kDTB99TokenDumpLen ? len : kDTB99TokenDumpLen;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n * 2];
    for (size_t i = 0; i < n; i++)
        [hex appendFormat:@"%02x", (unsigned char)token[i]];
    return hex;
}

static void dt_b99_log_token_diag(void (^log)(NSString *line), const char *when,
                                  const char *tag, const char *token, size_t tok_len)
{
    int hi = -1, lo = -1;
    int type_byte = dt_b99_token_type_byte(token, tok_len, &hi, &lo);
    NSString *prefix = dt_b99_token_hex_prefix(token, tok_len);

    dt_b99_log(log, @"[*] build99 token %s %s len=%zu min=%zu dump_0x%zx=%@",
               when, tag, tok_len, kDTB99TokenMinLen, kDTB99TokenDumpLen, prefix);

    if (tok_len >= kDTB99TokenTypeOff + 2) {
        dt_b99_log(log, @"[*] build99 token %s %s @[0x%zx]=0x%02x '%c%c' hi=%d lo=%d",
                   when, tag, kDTB99TokenTypeOff,
                   type_byte >= 0 ? (unsigned)type_byte : 0,
                   token[kDTB99TokenTypeOff], token[kDTB99TokenTypeOff + 1],
                   hi, lo);
    } else {
        dt_b99_log(log, @"[!] build99 token %s %s truncated len=%zu need>=%zu for type@0x%zx",
                   when, tag, tok_len, kDTB99TokenTypeOff + 2, kDTB99TokenTypeOff);
    }

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 token %s %s len=%zu type=%d",
                                    when, tag, tok_len, type_byte]];
}

static int dt_b99_issue_consume_one(void (^log)(NSString *line),
                                    char *(*issue_file)(const char *, const char *, uint32_t),
                                    int64_t (*consume)(const char *),
                                    const dt_b99_ext_step_t *step)
{
    const char *tag = step->tag;

    errno = 0;
    dt_b99_log(log, @"[*] build99 EXT issue %@ class=%s path=%s", @(tag), step->class_name, kDTB99ExtPath);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 EXT issue %@ begin", @(tag)]];

    char *token = issue_file(step->class_name, kDTB99ExtPath, 0);
    int issue_errno = errno;
    if (!token) {
        dt_b99_log(log, @"[!] build99 EXT issue %@ NULL errno=%d (%s)",
                   @(tag), issue_errno, issue_errno ? strerror(issue_errno) : "ok");
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 EXT issue %@ fail errno=%d",
                                        @(tag), issue_errno]];
        return issue_errno ? -issue_errno : -EIO;
    }

    size_t tok_len = strlen(token);
    dt_b99_log(log, @"[+] build99 EXT issue %@ OK token_len=%zu", @(tag), tok_len);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 EXT issue %@ OK", @(tag)]];

    dt_b99_log_token_diag(log, "post-issue", tag, token, tok_len);

    /* §42.9: full chain immediately before sandbox_extension_consume (no syscall yet) */
    dt_build99_log_consume_chain("pre-consume");
    dt_b99_log(log, @"[*] build99 pre-consume chain logged — kernel BP @ 5510E8 then 532C68/532930/82A6B4 §42.8");

    errno = 0;
    int64_t handle = consume(token);
    int consume_errno = errno;

    dt_b99_log(log, @"[*] build99 EXT consume %@ handle=%lld errno=%d (%s)",
               @(tag), (long long)handle, consume_errno,
               consume_errno ? strerror(consume_errno) : "ok");
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 EXT consume %@ h=%lld errno=%d",
                                    @(tag), (long long)handle, consume_errno]];

    free(token);

    if (handle <= 0) {
        dt_b99_log(log, @"[!] build99 EXT consume %@ FAIL — compare chain log vs kernel BP (exit A/B/C §42.3)",
                   @(tag));
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 EXT consume %@ fail", @(tag)]];
        return consume_errno ? -consume_errno : -EIO;
    }

    dt_b99_log(log, @"[+] build99 EXT consume %@ OK handle=%lld", @(tag), (long long)handle);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build99 EXT consume %@ OK", @(tag)]];
    return 0;
}

int dt_build99_issue_consume_jbroot_extensions(void (^log)(NSString *line))
{
    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt_b99_log(log, @"[!] build99 EXT dlopen failed: %s", dlerror() ?: "?");
        [[DTRunLogger shared] logStage:@"build99 EXT fail dlopen"];
        return -ENOENT;
    }

    char *(*issue_file)(const char *, const char *, uint32_t) =
        (char *(*)(const char *, const char *, uint32_t))dlsym(lib, "sandbox_extension_issue_file");
    int64_t (*consume)(const char *) = (int64_t (*)(const char *))dlsym(lib, "sandbox_extension_consume");

    if (!issue_file || !consume) {
        dt_b99_log(log, @"[!] build99 EXT dlsym issue=%p consume=%p", issue_file, consume);
        [[DTRunLogger shared] logStage:@"build99 EXT fail dlsym"];
        dlclose(lib);
        return -ENOSYS;
    }

    dt_b99_log(log, @"[*] build99 DIAG EXT triple (§42.9 chain log only — no functional fix)");
    dt_b99_log(log, @"[*] build99 grep: build99 chain pre-consume proc ucred label s0");
    [[DTRunLogger shared] logStage:@"build99 EXT diag begin"];

    for (size_t i = 0; i < sizeof(kDTB99Steps) / sizeof(kDTB99Steps[0]); i++) {
        int r = dt_b99_issue_consume_one(log, issue_file, consume, &kDTB99Steps[i]);
        if (r != 0) {
            dlclose(lib);
            return r;
        }
    }

    dt_b99_log(log, @"[+] build99 EXT triple OK (unexpected if consume still fails — use BP compare)");
    [[DTRunLogger shared] logStage:@"build99 EXT triple OK"];
    dlclose(lib);
    return 0;
}
