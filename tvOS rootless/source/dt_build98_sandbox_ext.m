#import "dt_build98_sandbox_ext.h"

#import <dlfcn.h>
#import <errno.h>
#import <stdarg.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

#import "DTRunLogger.h"
#import "dt_physrw.h"

/// IDA §39.3 — consume type hex @ token[0x41..0x42] (55125C MOV W25,#0x41)
static const size_t kDTB98TokenTypeOff = 0x41;
/// IDA §39.3 — HMAC body @ token+0x40 (5517B8); min len 0x41 (5517A8)
static const size_t kDTB98TokenMinLen = 0x41;
/// ChatGPT + §39.8 — log prefix bytes for branch-pin
static const size_t kDTB98TokenDumpLen = 0x50;

/// Same triple as build97 §36.4 (unchanged classes/path)
static const char *const kDTB98ClassRead = "com.apple.app-sandbox.read";
static const char *const kDTB98ClassReadWrite = "com.apple.app-sandbox.read-write";
static const char *const kDTB98ClassExecutable = "com.apple.sandbox.executable";
static const char *const kDTB98ExtPath = "/private/var/jb/";

typedef struct {
    const char *tag;
    const char *class_name;
} dt_b98_ext_step_t;

static const dt_b98_ext_step_t kDTB98Steps[] = {
    { "read",       kDTB98ClassRead },
    { "read-write", kDTB98ClassReadWrite },
    { "executable", kDTB98ClassExecutable },
};

static void dt_b98_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (log)
        log(msg);
    [[DTRunLogger shared] log:msg];
}

/// Kernel 551268 hex decode: strchr("0123456789abcdef", c)
static int dt_b98_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/// IDA 55125C–55127C: 2 hex chars @ offset 0x41 → type byte for 551430 switch
static int dt_b98_token_type_byte(const char *token, size_t len, int *hi_out, int *lo_out)
{
    if (!token || len < kDTB98TokenTypeOff + 2)
        return -1;
    int hi = dt_b98_hex_nibble(token[kDTB98TokenTypeOff]);
    int lo = dt_b98_hex_nibble(token[kDTB98TokenTypeOff + 1]);
    if (hi_out)
        *hi_out = hi;
    if (lo_out)
        *lo_out = lo;
    if (hi < 0 || lo < 0)
        return -1;
    return (hi << 4) | lo;
}

static NSString *dt_b98_token_hex_prefix(const char *token, size_t len)
{
    size_t n = len < kDTB98TokenDumpLen ? len : kDTB98TokenDumpLen;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n * 2];
    for (size_t i = 0; i < n; i++)
        [hex appendFormat:@"%02x", (unsigned char)token[i]];
    return hex;
}

static void dt_b98_log_token_diag(void (^log)(NSString *line), const char *when,
                                  const char *tag, const char *token, size_t tok_len)
{
    int hi = -1, lo = -1;
    int type_byte = dt_b98_token_type_byte(token, tok_len, &hi, &lo);
    NSString *prefix = dt_b98_token_hex_prefix(token, tok_len);

    dt_b98_log(log, @"[*] build98 token %s %s len=%zu min=%zu dump_0x%zx=%@",
               when, tag, tok_len, kDTB98TokenMinLen, kDTB98TokenDumpLen, prefix);

    if (tok_len >= kDTB98TokenTypeOff + 2) {
        dt_b98_log(log, @"[*] build98 token %s %s @[0x%zx]=0x%02x '%c%c' hi=%d lo=%d (551430 case=%d=file)",
                   when, tag, kDTB98TokenTypeOff,
                   type_byte >= 0 ? (unsigned)type_byte : 0,
                   token[kDTB98TokenTypeOff], token[kDTB98TokenTypeOff + 1],
                   hi, lo, type_byte);
    } else {
        dt_b98_log(log, @"[!] build98 token %s %s truncated len=%zu need>=%zu for type@0x%zx",
                   when, tag, tok_len, kDTB98TokenTypeOff + 2, kDTB98TokenTypeOff);
    }

    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 token %s %s len=%zu type=%d",
                                    when, tag, tok_len, type_byte]];
}

static int dt_b98_issue_consume_one(void (^log)(NSString *line),
                                    char *(*issue_file)(const char *, const char *, uint32_t),
                                    int64_t (*consume)(const char *),
                                    const dt_b98_ext_step_t *step)
{
    const char *tag = step->tag;

    errno = 0;
    dt_b98_log(log, @"[*] build98 EXT issue %@ class=%s path=%s", @(tag), step->class_name, kDTB98ExtPath);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 EXT issue %@ begin", @(tag)]];

    char *token = issue_file(step->class_name, kDTB98ExtPath, 0);
    int issue_errno = errno;
    if (!token) {
        dt_b98_log(log, @"[!] build98 EXT issue %@ NULL errno=%d (%s)",
                   @(tag), issue_errno, issue_errno ? strerror(issue_errno) : "ok");
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 EXT issue %@ fail errno=%d",
                                        @(tag), issue_errno]];
        return issue_errno ? -issue_errno : -EIO;
    }

    size_t tok_len = strlen(token);
    dt_b98_log(log, @"[+] build98 EXT issue %@ OK token_len=%zu", @(tag), tok_len);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 EXT issue %@ OK", @(tag)]];

    dt_b98_log_token_diag(log, "post-issue", tag, token, tok_len);

    dt_build89_log_mac_label_slots("build98 pre-consume");
    dt_b98_log(log, @"[*] build98 pre-consume slot0 logged (compare 5510E8 X0 on kernel BP — §39.8)");

    errno = 0;
    int64_t handle = consume(token);
    int consume_errno = errno;

    dt_b98_log(log, @"[*] build98 EXT consume %@ handle=%lld errno=%d (%s)",
               @(tag), (long long)handle, consume_errno,
               consume_errno ? strerror(consume_errno) : "ok");
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 EXT consume %@ h=%lld errno=%d",
                                    @(tag), (long long)handle, consume_errno]];

    free(token);

    if (handle <= 0) {
        dt_b98_log(log, @"[!] build98 EXT consume %@ FAIL — §39.7: errno=0→5510E8 profile NULL or 551478 mismatch; errno=0x16→551794 HMAC",
                   @(tag));
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 EXT consume %@ fail", @(tag)]];
        return consume_errno ? -consume_errno : -EIO;
    }

    dt_b98_log(log, @"[+] build98 EXT consume %@ OK handle=%lld", @(tag), (long long)handle);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build98 EXT consume %@ OK", @(tag)]];
    return 0;
}

int dt_build98_issue_consume_jbroot_extensions(void (^log)(NSString *line))
{
    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt_b98_log(log, @"[!] build98 EXT dlopen failed: %s", dlerror() ?: "?");
        [[DTRunLogger shared] logStage:@"build98 EXT fail dlopen"];
        return -ENOENT;
    }

    char *(*issue_file)(const char *, const char *, uint32_t) =
        (char *(*)(const char *, const char *, uint32_t))dlsym(lib, "sandbox_extension_issue_file");
    int64_t (*consume)(const char *) = (int64_t (*)(const char *))dlsym(lib, "sandbox_extension_consume");

    if (!issue_file || !consume) {
        dt_b98_log(log, @"[!] build98 EXT dlsym issue=%p consume=%p", issue_file, consume);
        [[DTRunLogger shared] logStage:@"build98 EXT fail dlsym"];
        dlclose(lib);
        return -ENOSYS;
    }

    dt_b98_log(log, @"[*] build98 DIAG EXT triple (no functional change — §39.8 branch-pin)");
    dt_b98_log(log, @"[*] build98 NOTE: 5510E8 X0 needs kernel BP; userspace logs slot0+token@0x41 only");
    [[DTRunLogger shared] logStage:@"build98 EXT diag begin"];

    for (size_t i = 0; i < sizeof(kDTB98Steps) / sizeof(kDTB98Steps[0]); i++) {
        int r = dt_b98_issue_consume_one(log, issue_file, consume, &kDTB98Steps[i]);
        if (r != 0) {
            dlclose(lib);
            return r;
        }
    }

    dt_b98_log(log, @"[+] build98 EXT triple OK (unexpected if build97 failed — recheck device log)");
    [[DTRunLogger shared] logStage:@"build98 EXT triple OK"];
    dlclose(lib);
    return 0;
}
