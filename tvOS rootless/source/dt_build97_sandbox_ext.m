#import "dt_build97_sandbox_ext.h"

#import <dlfcn.h>
#import <errno.h>
#import <stdarg.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

#import "DTRunLogger.h"

/// IDA §36.3 blob ref_base+8×0x43 @ 0xFFFFFFF00583409A — op20 file-read* (53A0A8 W1=0x14)
static const char *const kDTB97ClassRead = "com.apple.app-sandbox.read";

/// IDA §36.3 blob ref_base+8×0x47 @ 0xFFFFFFF0058340BA — op28 file-write* (53A0A8 W1=0x1C)
static const char *const kDTB97ClassReadWrite = "com.apple.app-sandbox.read-write";

/// IDA §29.4 / kernel 0xFFFFFFF00588E4FF / blob ref_base+8×0x51 — op129 + op16
static const char *const kDTB97ClassExecutable = "com.apple.sandbox.executable";

/// §31.4 / §36.4 prefix for 550190
static const char *const kDTB97ExtPath = "/private/var/jb/";

typedef struct {
    const char *tag;
    const char *class_name;
    const char *ida_op_note;
} dt_b97_ext_step_t;

static const dt_b97_ext_step_t kDTB97Steps[] = {
    { "read",        kDTB97ClassRead,        "op20/53A0A8 W1=0x14" },
    { "read-write",  kDTB97ClassReadWrite,   "op28/53A0A8 W1=0x1C" },
    { "executable",  kDTB97ClassExecutable,  "op129+op16/550190" },
};

static void dt_b97_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (log)
        log(msg);
    [[DTRunLogger shared] log:msg];
}

static int dt_b97_issue_consume_one(void (^log)(NSString *line),
                                    char *(*issue_file)(const char *, const char *, uint32_t),
                                    int64_t (*consume)(const char *),
                                    const dt_b97_ext_step_t *step)
{
    errno = 0;
    dt_b97_log(log, @"[*] build97 EXT issue %@ class=%s path=%s (%s)",
               @(step->tag), step->class_name, kDTB97ExtPath, step->ida_op_note);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build97 EXT issue %@ begin", @(step->tag)]];

    char *token = issue_file(step->class_name, kDTB97ExtPath, 0);
    int issue_errno = errno;
    if (!token) {
        dt_b97_log(log, @"[!] build97 EXT issue %@ NULL errno=%d (%s)",
                   @(step->tag), issue_errno, issue_errno ? strerror(issue_errno) : "ok");
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build97 EXT issue %@ fail errno=%d",
                                        @(step->tag), issue_errno]];
        return issue_errno ? -issue_errno : -EIO;
    }

    size_t tok_len = strlen(token);
    dt_b97_log(log, @"[+] build97 EXT issue %@ OK token_len=%zu", @(step->tag), tok_len);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build97 EXT issue %@ OK", @(step->tag)]];

    errno = 0;
    int64_t handle = consume(token);
    int consume_errno = errno;
    free(token);

    if (handle <= 0) {
        dt_b97_log(log, @"[!] build97 EXT consume %@ fail handle=%lld errno=%d (%s) — slot0 NULL?",
                   @(step->tag), (long long)handle, consume_errno,
                   consume_errno ? strerror(consume_errno) : "ok");
        [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build97 EXT consume %@ fail h=%lld errno=%d",
                                        @(step->tag), (long long)handle, consume_errno]];
        return consume_errno ? -consume_errno : -EIO;
    }

    dt_b97_log(log, @"[+] build97 EXT consume %@ OK handle=%lld (W1=6→55106C)", @(step->tag), (long long)handle);
    [[DTRunLogger shared] logStage:[NSString stringWithFormat:@"build97 EXT consume %@ OK h=%lld",
                                    @(step->tag), (long long)handle]];
    return 0;
}

int dt_build97_issue_consume_jbroot_extensions(void (^log)(NSString *line))
{
    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        dt_b97_log(log, @"[!] build97 EXT dlopen failed: %s", dlerror() ?: "?");
        [[DTRunLogger shared] logStage:@"build97 EXT fail dlopen"];
        return -ENOENT;
    }

    char *(*issue_file)(const char *, const char *, uint32_t) =
        (char *(*)(const char *, const char *, uint32_t))dlsym(lib, "sandbox_extension_issue_file");
    int64_t (*consume)(const char *) = (int64_t (*)(const char *))dlsym(lib, "sandbox_extension_consume");

    if (!issue_file || !consume) {
        dt_b97_log(log, @"[!] build97 EXT dlsym issue=%p consume=%p", issue_file, consume);
        [[DTRunLogger shared] logStage:@"build97 EXT fail dlsym"];
        dlclose(lib);
        return -ENOSYS;
    }

    dt_b97_log(log, @"[*] build97 EXT triple begin path=%s (§36.4)", kDTB97ExtPath);
    [[DTRunLogger shared] logStage:@"build97 EXT triple begin"];

    for (size_t i = 0; i < sizeof(kDTB97Steps) / sizeof(kDTB97Steps[0]); i++) {
        int r = dt_b97_issue_consume_one(log, issue_file, consume, &kDTB97Steps[i]);
        if (r != 0) {
            dlclose(lib);
            return r;
        }
    }

    dt_b97_log(log, @"[+] build97 EXT triple OK read+read-write+executable");
    [[DTRunLogger shared] logStage:@"build97 EXT triple OK"];
    dlclose(lib);
    return 0;
}
