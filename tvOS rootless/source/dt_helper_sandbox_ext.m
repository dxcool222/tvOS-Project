#import "dt_helper_sandbox_ext.h"

#import <dlfcn.h>
#import <errno.h>
#import <stdint.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

/// Issue flags: 0 only. flags=0x4 (PREFIXMATCH) → kernel 5508A4 EOPNOTSUPP (build102.4).
static const uint32_t kDT103ExtFlags = 0;

/// build97 / kernel §36.4 prefix path
static const char *const kDT1024ExtPath = "/private/var/jb/";

static const char *const kDT1024ClassRead = "com.apple.app-sandbox.read";
static const char *const kDT1024ClassReadWrite = "com.apple.app-sandbox.read-write";
static const char *const kDT1024ClassExecutable = "com.apple.sandbox.executable";

typedef struct {
    const char *class_name;
} dt_helper_ext_step_t;

static const dt_helper_ext_step_t kDT1024Steps[] = {
    { kDT1024ClassRead },
    { kDT1024ClassReadWrite },
    { kDT1024ClassExecutable },
};

static void dt1024_print_token(const char *token)
{
    if (!token) {
        printf("token=(null)\n");
        return;
    }
    size_t len = strlen(token);
    if (len <= 64) {
        printf("token=%s\n", token);
        return;
    }
    printf("token=%.32s...len=%zu\n", token, len);
}

static int dt1024_issue_consume_one(char *(*issue_file)(const char *, const char *, uint32_t),
                                    int64_t (*consume)(const char *),
                                    const char *class_name)
{
    errno = 0;
    printf("build103 helper ext issue class=%s path=%s flags=0x%x errno=%d\n",
           class_name, kDT1024ExtPath, kDT103ExtFlags, 0);
    fflush(stdout);

    char *token = issue_file(class_name, kDT1024ExtPath, kDT103ExtFlags);
    int issue_errno = errno;
    printf("build103 helper ext issue class=%s path=%s ", class_name, kDT1024ExtPath);
    dt1024_print_token(token);
    printf(" errno=%d\n", issue_errno);
    fflush(stdout);

    if (!token) {
        printf("build103 verdict=HELPER_EXT_ISSUE_FAIL\n");
        fflush(stdout);
        return issue_errno ? -issue_errno : -EIO;
    }

    errno = 0;
    int64_t handle = consume(token);
    int consume_errno = errno;
    free(token);

    printf("build103 helper ext consume class=%s handle=%lld errno=%d\n",
           class_name, (long long)handle, consume_errno);
    fflush(stdout);

    if (handle <= 0) {
        printf("build103 verdict=HELPER_EXT_CONSUME_ZERO\n");
        fflush(stdout);
        return consume_errno ? -consume_errno : -ENOENT;
    }

    return 0;
}

int dt_helper_issue_consume_jbroot_extensions(void)
{
    printf("build103 helper ext begin\n");
    fflush(stdout);

    void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (!lib) {
        printf("build102.4 helper ext dlopen fail err=%s\n", dlerror() ?: "?");
        printf("build103 verdict=HELPER_EXT_ISSUE_FAIL\n");
        fflush(stdout);
        return -ENOENT;
    }

    char *(*issue_file)(const char *, const char *, uint32_t) =
        (char *(*)(const char *, const char *, uint32_t))dlsym(lib, "sandbox_extension_issue_file");
    int64_t (*consume)(const char *) = (int64_t (*)(const char *))dlsym(lib, "sandbox_extension_consume");

    if (!issue_file || !consume) {
        printf("build102.4 helper ext dlsym issue=%p consume=%p\n", issue_file, consume);
        printf("build103 verdict=HELPER_EXT_ISSUE_FAIL\n");
        fflush(stdout);
        dlclose(lib);
        return -ENOSYS;
    }

    for (size_t i = 0; i < sizeof(kDT1024Steps) / sizeof(kDT1024Steps[0]); i++) {
        int r = dt1024_issue_consume_one(issue_file, consume, kDT1024Steps[i].class_name);
        if (r != 0) {
            dlclose(lib);
            return r;
        }
    }

    printf("build103 helper ext all handles OK\n");
    fflush(stdout);
    dlclose(lib);
    return 0;
}
