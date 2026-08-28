#import "dt_build100_sandbox_ext.h"

#import <dlfcn.h>
#import <errno.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

#import "DTRunLogger.h"
#import "dt_physrw.h"

static const size_t kDTB100TokenTypeOff = 0x41;
static const size_t kDTB100TokenMinLen = 0x41;

static const char *const kDTB100ClassRead = "com.apple.app-sandbox.read";
static const char *const kDTB100ExtPath = "/private/var/jb/";

static void dt_b100_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (log)
        log(msg);
    [[DTRunLogger shared] log:msg];
}

static int dt_b100_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int dt_b100_token_type_byte(const char *token, size_t len)
{
    if (!token || len < kDTB100TokenTypeOff + 2)
        return -1;
    int hi = dt_b100_hex_nibble(token[kDTB100TokenTypeOff]);
    int lo = dt_b100_hex_nibble(token[kDTB100TokenTypeOff + 1]);
    if (hi < 0 || lo < 0)
        return -1;
    return (hi << 4) | lo;
}

int dt_build100_issue_consume_read_proof(void (^log)(NSString *line))
{
    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt_b100_log(log, @"[!] build101 EXT dlopen failed: %s", dlerror() ?: "?");
        [[DTRunLogger shared] logStage:@"build101 EXT fail dlopen"];
        return -ENOENT;
    }

    char *(*issue_file)(const char *, const char *, uint32_t) =
        (char *(*)(const char *, const char *, uint32_t))dlsym(lib, "sandbox_extension_issue_file");
    int64_t (*consume)(const char *) = (int64_t (*)(const char *))dlsym(lib, "sandbox_extension_consume");

    if (!issue_file || !consume) {
        dt_b100_log(log, @"[!] build101 EXT dlsym issue=%p consume=%p", issue_file, consume);
        [[DTRunLogger shared] logStage:@"build101 EXT fail dlsym"];
        dlclose(lib);
        return -ENOSYS;
    }

    dt_b100_log(log, @"[*] build101 DIAG read EXT (§28 fix itk_space 0x300 — no sign/trust/spawn)");
    dt_b100_log(log, @"[*] build101 grep: build101 chain pre-consume thread_kptr ctx_proc mirror532C68");
    [[DTRunLogger shared] logStage:@"build101 EXT diag begin"];

    errno = 0;
    dt_b100_log(log, @"[*] build101 issue read class=%s path=%s", kDTB100ClassRead, kDTB100ExtPath);
    char *token = issue_file(kDTB100ClassRead, kDTB100ExtPath, 0);
    int issue_errno = errno;
    if (!token) {
        dt_b100_log(log, @"[!] build101 issue read NULL errno=%d (%s)",
            issue_errno, issue_errno ? strerror(issue_errno) : "ok");
        [[DTRunLogger shared] logStage:@"build101 issue read fail"];
        dlclose(lib);
        return issue_errno ? -issue_errno : -EIO;
    }

    size_t tok_len = strlen(token);
    int type_byte = dt_b100_token_type_byte(token, tok_len);
    dt_b100_log(log, @"issue read: token_len=%zu type=%d flags=0", tok_len, type_byte);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build101 issue read OK len=%zu", tok_len]];

    int proof_r = dt_build100_log_ctx_proof(log);
    if (proof_r != 0) {
        dt_b100_log(log, @"[!] build101 ctx proof log failed (%d)", proof_r);
        free(token);
        dlclose(lib);
        return proof_r;
    }

    errno = 0;
    int64_t handle = consume(token);
    int consume_errno = errno;
    free(token);

    dt_b100_log(log, @"consume read: handle=%lld errno=%d (%s)",
        (long long)handle, consume_errno, consume_errno ? strerror(consume_errno) : "ok");
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build101 consume read h=%lld errno=%d",
                                    (long long)handle, consume_errno]];

    dlclose(lib);

    dt_b100_log(log, @"[*] build101 ctx proof consume done — expect handle=0 errno=0 if §23 holds");
    [[DTRunLogger shared] logStage:@"build101 proof complete"];
    return 0;
}
