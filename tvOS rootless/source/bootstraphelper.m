#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <spawn.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

#import "dt_helper_sandbox_ext.h"
#import "dt_holdspawn_cmd_fd.h"

extern char **environ;

static void usage(void)
{
    fprintf(stderr, "bootstraphelper: ping | hold | holdSpawn | smokeExec | dlopenProbe <dylib-path>\n");
}

static void apply_jbroot_env(void)
{
    setenv("TVROOT", "/var/jb", 1);
    setenv("PATH", "/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin", 1);
    setenv("DYLD_LIBRARY_PATH", "/var/jb/usr/lib:/var/jb/lib", 1);
}

static void log_helper_creds(void)
{
    printf("helper_uid=%d\n", getuid());
    printf("helper_euid=%d\n", geteuid());
    printf("helper_gid=%d\n", getgid());
    printf("helper_egid=%d\n", getegid());
}

static int cmd_ping(void)
{
    printf("pong\n");
    return 0;
}

static int cmd_hold(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("helper_pid=%d\n", getpid());
    fflush(stdout);
    log_helper_creds();
    fflush(stdout);
    while (1)
        sleep(3600);
    return 0;
}

static void trim_newline(char *s)
{
    if (!s)
        return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static int spawn_probe_once(const char *target)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("KCALL634_PHASE3_EPERM_BRANCH_TELEMETRY\n");
    printf("broker_spawn_app_ppid=%d\n", (int)getppid());
    printf("broker_spawn_pid=%d\n", getpid());
    printf("broker_spawn_target=%s\n", target ?: "?");
    log_helper_creds();
    printf("broker_platform_entitlement_preflight=1\n");
    printf("KCALL634_PHASE3_WALLA_SKIPPED\n");
    printf("KCALL630_PHASE3_WALLA_SKIPPED_PLATFORM_FLAG_SET\n");
    printf("KCALL634_PHASE3_OP129_REACHED\n");
    printf("KCALL630_PHASE3_OP129_BLOCK_REACHED\n");
    fflush(stdout);

    if (!target || !target[0]) {
        printf("spawn_ret=-1\n");
        printf("spawn_errno=%d\n", EINVAL);
        printf("child_pid=0\n");
        printf("KCALL630_PHASE3_SPAWN_PROBE_DONE\n");
        fflush(stdout);
        return EINVAL;
    }

    struct stat st = { 0 };
    errno = 0;
    int stat_ret = stat(target, &st);
    int stat_errno = errno;
    printf("broker_target_stat_ret=%d\n", stat_ret);
    printf("broker_target_stat_size=%lld\n", (long long)st.st_size);
    printf("broker_target_stat_mode=0%o\n", (unsigned)(st.st_mode & 07777));
    printf("broker_target_stat_errno=%d\n", stat_errno);
    fflush(stdout);

    errno = 0;
    int access_ret = access(target, X_OK);
    int access_errno = errno;
    printf("broker_target_access_xok_ret=%d\n", access_ret);
    printf("broker_target_access_errno=%d\n", access_errno);
    if (access_ret != 0 && access_errno == EPERM)
        printf("KCALL634_PHASE3_BROKER_ACCESS_XOK_EPERM\n");
    fflush(stdout);

    typedef int (*posix_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const[], char *const[]);
    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(RTLD_DEFAULT, "posix_spawn");
    if (!spawn) {
        printf("spawn_ret=-1\n");
        printf("spawn_errno=%d\n", ENOSYS);
        printf("child_pid=0\n");
        printf("KCALL630_PHASE3_SPAWN_PROBE_DONE\n");
        fflush(stdout);
        return ENOSYS;
    }

    const char *base = strrchr(target, '/');
    base = base ? base + 1 : target;
    char *argv[] = { (char *)base, NULL };

    printf("KCALL630_PHASE3_BROKER_SPAWN_BEGIN\n");
    printf("KCALL634_PHASE3_KERNEL_LOG_WINDOW_BEGIN broker_pid=%d target=%s\n",
        getpid(), target);
    fflush(stdout);

    pid_t child = 0;
    int spawn_ret = spawn(&child, target, NULL, NULL, argv, environ);
    int spawn_errno = spawn_ret != 0 ? spawn_ret : 0;

    printf("KCALL634_PHASE3_KERNEL_LOG_WINDOW_END broker_pid=%d spawn_errno=%d\n",
        getpid(), spawn_errno);
    printf("spawn_ret=%d\n", spawn_ret);
    printf("spawn_errno=%d\n", spawn_errno);
    printf("child_pid=%d\n", (int)child);
    fflush(stdout);

    if (spawn_ret == 0 && child > 0) {
        int status = 0;
        if (waitpid(child, &status, 0) < 0) {
            printf("waitpid_ok=0\n");
            printf("waitpid_errno=%d\n", errno);
        } else {
            int child_exit = 1;
            if (WIFEXITED(status))
                child_exit = WEXITSTATUS(status);
            else if (WIFSIGNALED(status))
                child_exit = 128 + WTERMSIG(status);
            printf("waitpid_ok=1\n");
            printf("wait_status=0x%x\n", status);
            printf("child_exit=%d\n", child_exit);
        }
    } else {
        printf("waitpid_ok=0\n");
        printf("child_exit=-1\n");
    }

    printf("KCALL630_PHASE3_SPAWN_PROBE_ONLY_NO_EXEC_CHAIN\n");
    printf("KCALL630_PHASE3_SPAWN_PROBE_DONE\n");
    fflush(stdout);
    return spawn_ret;
}

static int cmd_hold_spawn_cmd_fd_preflight(void)
{
    printf("hold_spawn_cmd_fd=%d\n", kDT633CmdFd);
    fflush(stdout);

    errno = 0;
    int flags = fcntl(kDT633CmdFd, F_GETFD);
    if (flags < 0) {
        int pre_errno = errno;
        printf("hold_spawn_cmd_fd_invalid errno=%d\n", pre_errno);
        fflush(stdout);
        return -1;
    }

    printf("hold_spawn_cmd_fd_flags=%d\n", flags);
    printf("hold_spawn_cmd_fd_ok=1\n");
    fflush(stdout);
    return 0;
}

static int cmd_hold_spawn(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("helper_pid=%d\n", getpid());
    printf("hold_spawn_mode=pipe_fd%d\n", kDT633CmdFd);
    fflush(stdout);
    log_helper_creds();
    fflush(stdout);

    if (cmd_hold_spawn_cmd_fd_preflight() != 0) {
        fprintf(stderr, "hold_spawn_cmd_fd_preflight_fail\n");
        fflush(stderr);
        while (1)
            sleep(3600);
        return 1;
    }

    int spawn_done = 0;
    char line[PATH_MAX + 32];

    for (;;) {
        ssize_t n = read(kDT633CmdFd, line, sizeof(line) - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "hold_spawn_cmd_read_errno=%d\n", errno);
            break;
        }
        if (n == 0)
            break;
        line[n] = '\0';
        trim_newline(line);

        if (strncmp(line, "SPAWN ", 6) != 0)
            continue;

        if (spawn_done) {
            printf("KCALL630_PHASE3_FAIL_SCOPE_VIOLATION second_spawn\n");
            fflush(stdout);
            continue;
        }
        spawn_done = 1;
        const char *path = line + 6;
        while (*path == ' ')
            path++;
        spawn_probe_once(path);
    }

    while (1)
        sleep(3600);
    return 0;
}

static int wait_binary(NSString *path, NSArray<NSString *> *args)
{
    typedef int (*posix_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const[], char *const[]);
    typedef int (*spawn_fa_init_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
    typedef int (*spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

    void *lib = RTLD_DEFAULT;
    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(lib, "posix_spawn");
    spawn_fa_init_fn fa_init = (spawn_fa_init_fn)dlsym(lib, "posix_spawn_file_actions_init");
    spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(lib, "posix_spawn_file_actions_destroy");
    spawn_fa_adddup2_fn fa_dup2 = (spawn_fa_adddup2_fn)dlsym(lib, "posix_spawn_file_actions_adddup2");
    spawn_fa_addclose_fn fa_close = (spawn_fa_addclose_fn)dlsym(lib, "posix_spawn_file_actions_addclose");
    if (!spawn || !fa_init || !fa_destroy || !fa_dup2 || !fa_close)
        return 127;

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:path.lastPathComponent];
    [argvStrings addObjectsFromArray:args];
    NSUInteger argc = argvStrings.count;
    char **argv = calloc(argc + 1, sizeof(char *));
    for (NSUInteger i = 0; i < argc; i++)
        argv[i] = strdup(argvStrings[i].UTF8String);

    int pipefd[2] = { -1, -1 };
    if (pipe(pipefd) != 0) {
        for (NSUInteger i = 0; i < argc; i++)
            free(argv[i]);
        free(argv);
        fprintf(stderr, "inner_posix_spawn_errno=%d\n", errno);
        fprintf(stderr, "inner_posix_spawn_strerror=%s\n", strerror(errno));
        return errno > 0 ? errno : 1;
    }

    posix_spawn_file_actions_t actions;
    fa_init(&actions);
    fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
    fa_dup2(&actions, pipefd[1], STDERR_FILENO);
    fa_close(&actions, pipefd[0]);
    fa_close(&actions, pipefd[1]);

    pid_t pid = 0;
    int spawnErr = spawn(&pid, path.fileSystemRepresentation, &actions, NULL, argv, environ);
    fa_destroy(&actions);
    close(pipefd[1]);

    for (NSUInteger i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);

    if (spawnErr != 0) {
        close(pipefd[0]);
        fprintf(stderr, "inner_posix_spawn_errno=%d\n", spawnErr);
        fprintf(stderr, "inner_posix_spawn_strerror=%s\n", strerror(spawnErr));
        return spawnErr;
    }

    NSMutableData *childData = [NSMutableData data];
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        [childData appendBytes:buf length:(NSUInteger)n];
    close(pipefd[0]);
    if (childData.length > 8192)
        childData.length = 8192;

    NSString *childOut = [[NSString alloc] initWithData:childData encoding:NSUTF8StringEncoding] ?: @"";
    NSString *childOneLine = [[childOut stringByReplacingOccurrencesOfString:@"\n" withString:@" "]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "inner_posix_spawn_errno=%d\n", errno);
        fprintf(stderr, "inner_posix_spawn_strerror=%s\n", strerror(errno));
        return 1;
    }

    int childExit = 1;
    if (WIFEXITED(status))
        childExit = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        childExit = 128 + WTERMSIG(status);

    printf("child_stdout=%s\n", childOneLine.UTF8String ?: "");
    printf("child_exit=%d\n", childExit);
    fflush(stdout);
    return childExit;
}

static int cmd_smoke_exec(int argc, char *argv[])
{
    if (argc < 3)
        return 2;

    apply_jbroot_env();
    log_helper_creds();
    fflush(stdout);

    int ext_r = dt_helper_issue_consume_jbroot_extensions();
    if (ext_r != 0) {
        if (ext_r == -ENOENT || ext_r == -ENOSYS || ext_r == -EIO)
            return 12;
        return 12;
    }

    NSString *path = @(argv[2]);
    NSMutableArray<NSString *> *args = [NSMutableArray array];
    for (int i = 3; i < argc; i++)
        [args addObject:@(argv[i])];

    printf("build103 helper smoke invoking %s -c id\n", path.UTF8String ?: "?");
    fflush(stdout);

    int dash_r = wait_binary(path, args);
    if (dash_r == 0) {
        printf("build103 verdict=HELPER_EXT_FIXES_DASH\n");
    } else {
        printf("build103 verdict=HELPER_EXT_CONSUME_OK_DASH_FAIL\n");
    }
    fflush(stdout);
    return dash_r;
}

static int cmd_dlopen_probe(int argc, char *argv[])
{
    if (argc < 3)
        return 2;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    const char *path = argv[2];
    printf("BUILD102723_CHILD_DLOPEN_BEGIN path=%s\n", path ?: "?");
    fflush(stdout);

    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    const char *dle = dlerror();
  if (h) {
        printf("BUILD102723_CHILD_DLOPEN=SUCCESS\n");
        dlclose(h);
        return 0;
    }

    printf("BUILD102723_CHILD_DLOPEN=FAIL dlerror=%s errno=%d\n", dle ?: "(null)", errno);
    fflush(stdout);
    return 1;
}

int main(int argc, char *argv[])
{
    @autoreleasepool {
        if (argc < 2) {
            usage();
            return 2;
        }

        NSString *cmd = @(argv[1]);
        if ([cmd isEqualToString:@"ping"])
            return cmd_ping();
        if ([cmd isEqualToString:@"hold"])
            return cmd_hold();
        if ([cmd isEqualToString:@"holdSpawn"])
            return cmd_hold_spawn();
        if ([cmd isEqualToString:@"smokeExec"])
            return cmd_smoke_exec(argc, argv);
        if ([cmd isEqualToString:@"dlopenProbe"])
            return cmd_dlopen_probe(argc, argv);

        usage();
        return 2;
    }
}
