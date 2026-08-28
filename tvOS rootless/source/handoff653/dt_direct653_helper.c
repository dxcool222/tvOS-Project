#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define DT661_JBROOT "/private/var/jb"
#define DT661_SELF "/private/var/jb/usr/bin/dt_direct653_helper"
#define DT661_OPTIONAL_CFG "/private/var/jb/.installed_dopamine9630"
#define DT661_READ_CHUNK 256
#define DT672_TOOL "/private/var/jb/usr/bin/dt_tool672_probe"

typedef struct {
    int __opaque[32];
} dt672_spawn_actions_t;

typedef int (*dt672_spawn_fn)(pid_t *, const char *, const dt672_spawn_actions_t *,
                              const void *, char *const[], char *const[]);
typedef int (*dt672_spawn_fa_init_fn)(dt672_spawn_actions_t *);
typedef int (*dt672_spawn_fa_destroy_fn)(dt672_spawn_actions_t *);
typedef int (*dt672_spawn_fa_adddup2_fn)(dt672_spawn_actions_t *, int, int);
typedef int (*dt672_spawn_fa_addclose_fn)(dt672_spawn_actions_t *, int);

extern char **environ;

static void dt_emit(const char *line)
{
    printf("%s\n", line);
    fflush(stdout);
}

static void dt_emit_kv(const char *key, int value)
{
    char line[160];
    snprintf(line, sizeof(line), "%s=%d", key, value);
    dt_emit(line);
}

static void dt_emit_errno_pair(const char *ret_key, int ret, const char *errno_key)
{
    dt_emit_kv(ret_key, ret);
    dt_emit_kv(errno_key, ret == 0 ? 0 : errno);
}

static void dt653_smoke_markers(int argc, char **argv)
{
    char line[160];

    dt_emit("KCALL653_HELPER_ALIVE=1");
    snprintf(line, sizeof(line), "KCALL653_HELPER_PID=%d", getpid());
    dt_emit(line);
    snprintf(line, sizeof(line), "KCALL653_HELPER_PPID=%d", getppid());
    dt_emit(line);
    snprintf(line, sizeof(line), "KCALL653_HELPER_UID=%d", getuid());
    dt_emit(line);
    snprintf(line, sizeof(line), "KCALL653_HELPER_GID=%d", getgid());
    dt_emit(line);
    if (argc > 0 && argv[0]) {
        snprintf(line, sizeof(line), "KCALL653_HELPER_ARGV0=%s", argv[0]);
        dt_emit(line);
    } else {
        dt_emit("KCALL653_HELPER_ARGV0=");
    }
    dt_emit("KCALL653_HELPER_DONE=1");
}

static int dt661_read_chunk(const char *path)
{
    char buf[DT661_READ_CHUNK + 1];
    ssize_t n;
    int fd;
    size_t i;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        dt_emit_errno_pair("KCALL661_OPEN_R_RET", -1, "KCALL661_OPEN_R_ERRNO");
        dt_emit_kv("KCALL661_READ_BYTES", 0);
        return -1;
    }

    dt_emit_kv("KCALL661_OPEN_R_RET", 0);
    dt_emit_kv("KCALL661_OPEN_R_ERRNO", 0);

    n = read(fd, buf, DT661_READ_CHUNK);
    close(fd);
    if (n < 0) {
        dt_emit_kv("KCALL661_READ_BYTES", 0);
        dt_emit_errno_pair("KCALL661_OPEN_R_RET", -1, "KCALL661_OPEN_R_ERRNO");
        return -1;
    }

    dt_emit_kv("KCALL661_READ_BYTES", (int)n);
    dt_emit("KCALL661_OUTPUT_BEGIN");
    for (i = 0; i < (size_t)n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 32 && c < 127 && c != '\\')
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    putchar('\n');
    fflush(stdout);
    dt_emit("KCALL661_OUTPUT_END");
    return 0;
}

static int dt661_probe_path(const char *path, int required)
{
    struct stat st;
    char line[512];
    int sr;

    snprintf(line, sizeof(line), "KCALL661_TARGET_PATH=%s", path);
    dt_emit(line);

    sr = stat(path, &st);
    dt_emit_errno_pair("KCALL661_STAT_RET", sr, "KCALL661_STAT_ERRNO");
    if (sr != 0) {
        if (required)
            return -1;
        dt_emit("KCALL661_PROBE_SKIP=ENOENT");
        return 0;
    }

    dt_emit_kv("KCALL661_STAT_MODE", (int)(st.st_mode & 07777));
    dt_emit_kv("KCALL661_STAT_UID", (int)st.st_uid);
    dt_emit_kv("KCALL661_STAT_GID", (int)st.st_gid);
    dt_emit_kv("KCALL661_STAT_SIZE", (int)st.st_size);

    if (S_ISREG(st.st_mode))
        return dt661_read_chunk(path);

    dt_emit("KCALL661_OPEN_R_RET=-1");
    dt_emit("KCALL661_OPEN_R_ERRNO=21");
    dt_emit_kv("KCALL661_READ_BYTES", 0);
    return 0;
}

static int dt661_read_worker(void)
{
    int fail = 0;

    dt_emit("KCALL661_BEGIN");
    dt_emit("KCALL661_READ_WORKER_BEGIN");

    if (dt661_probe_path(DT661_JBROOT, 1) != 0)
        fail = 1;
    if (dt661_probe_path(DT661_SELF, 1) != 0)
        fail = 1;
    (void)dt661_probe_path(DT661_OPTIONAL_CFG, 0);

    dt_emit("KCALL661_READ_WORKER_DONE");
    dt_emit(fail ? "KCALL661_RESULT=FAIL" : "KCALL661_RESULT=OK");
    return fail;
}

static int dt672_tool_runner(void)
{
    struct stat st;
    char line[512];
    char *tool_argv[] = { (char *)DT672_TOOL, NULL };
    int pipefd[2] = { -1, -1 };
    dt672_spawn_actions_t actions;
    dt672_spawn_fn spawn;
    dt672_spawn_fa_init_fn fa_init;
    dt672_spawn_fa_destroy_fn fa_destroy;
    dt672_spawn_fa_adddup2_fn fa_dup2;
    dt672_spawn_fa_addclose_fn fa_close;
    pid_t child = 0;
    int status = 0;
    int spawn_ret;
    int fail = 0;

    spawn = (dt672_spawn_fn)dlsym(RTLD_DEFAULT, "posix_spawn");
    fa_init = (dt672_spawn_fa_init_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_init");
    fa_destroy = (dt672_spawn_fa_destroy_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
    fa_dup2 = (dt672_spawn_fa_adddup2_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_adddup2");
    fa_close = (dt672_spawn_fa_addclose_fn)dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_addclose");
    if (!spawn || !fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
        dt_emit("KCALL672_SPAWN_DLSYM_FAIL=1");
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }
    dt_emit("KCALL672_SPAWN_DLSYM_OK=1");

    dt_emit("KCALL672_BEGIN");
    snprintf(line, sizeof(line), "KCALL672_TOOL_PATH=%s", DT672_TOOL);
    dt_emit(line);

    if (stat(DT672_TOOL, &st) != 0) {
        dt_emit_errno_pair("KCALL672_STAT_RET", -1, "KCALL672_STAT_ERRNO");
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }

    dt_emit_kv("KCALL672_STAT_RET", 0);
    dt_emit_kv("KCALL672_STAT_ERRNO", 0);
    dt_emit_kv("KCALL672_STAT_MODE", (int)(st.st_mode & 07777));
    if (!S_ISREG(st.st_mode) || (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        dt_emit("KCALL672_PREFLIGHT_X_OK=0");
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }
    dt_emit("KCALL672_PREFLIGHT_X_OK=1");

    if (pipe(pipefd) != 0) {
        dt_emit_errno_pair("KCALL672_PIPE_RET", -1, "KCALL672_PIPE_ERRNO");
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }
    dt_emit_kv("KCALL672_PIPE_RET", 0);

    if (fa_init(&actions) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }
    (void)fa_close(&actions, pipefd[0]);
    (void)fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
    (void)fa_dup2(&actions, pipefd[1], STDERR_FILENO);
    (void)fa_close(&actions, pipefd[1]);

    dt_emit("KCALL672_EXEC_BEGIN");

    spawn_ret = spawn(&child, DT672_TOOL, &actions, NULL, tool_argv, environ);
    fa_destroy(&actions);
    close(pipefd[1]);
    pipefd[1] = -1;

    dt_emit_kv("KCALL672_SPAWN_RET", spawn_ret);
    dt_emit_kv("KCALL672_SPAWN_ERRNO", spawn_ret == 0 ? 0 : errno);
    dt_emit_kv("KCALL672_CHILD_PID", spawn_ret == 0 ? (int)child : 0);

    if (spawn_ret != 0 || child <= 0) {
        close(pipefd[0]);
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }

    {
        char chunk[512];
        ssize_t n;

        dt_emit("KCALL672_TOOL_STDOUT_BEGIN");
        while ((n = read(pipefd[0], chunk, sizeof(chunk) - 1)) > 0) {
            chunk[n] = '\0';
            fputs(chunk, stdout);
            fflush(stdout);
        }
        dt_emit("KCALL672_TOOL_STDOUT_END");
    }
    close(pipefd[0]);
    pipefd[0] = -1;

    if (waitpid(child, &status, 0) < 0) {
        dt_emit_errno_pair("KCALL672_WAIT_RET", -1, "KCALL672_WAIT_ERRNO");
        dt_emit("KCALL672_RESULT=FAIL");
        return 1;
    }

    dt_emit_kv("KCALL672_WAIT_RET", 0);
    dt_emit_kv("KCALL672_WAIT_ERRNO", 0);

    if (WIFEXITED(status)) {
        dt_emit_kv("KCALL672_EXEC_EXIT", WEXITSTATUS(status));
        if (WEXITSTATUS(status) != 0)
            fail = 1;
    } else if (WIFSIGNALED(status)) {
        dt_emit_kv("KCALL672_EXEC_SIGNAL", WTERMSIG(status));
        fail = 1;
    } else {
        dt_emit("KCALL672_EXEC_EXIT=-1");
        fail = 1;
    }

    dt_emit(fail ? "KCALL672_RESULT=FAIL" : "KCALL672_RESULT=OK");
    return fail;
}

int main(int argc, char **argv)
{
    int fail = 0;

    dt653_smoke_markers(argc, argv);
    if (dt661_read_worker() != 0)
        fail = 1;
    if (dt672_tool_runner() != 0)
        fail = 1;
    return fail ? 1 : 0;
}
