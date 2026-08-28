#include <stdio.h>
#include <unistd.h>

static void dt_emit(const char *line)
{
    printf("%s\n", line);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    char line[160];

    dt_emit("KCALL672_TOOL_ALIVE=1");
    snprintf(line, sizeof(line), "KCALL672_TOOL_PID=%d", getpid());
    dt_emit(line);
    snprintf(line, sizeof(line), "KCALL672_TOOL_PPID=%d", getppid());
    dt_emit(line);
    snprintf(line, sizeof(line), "KCALL672_TOOL_UID=%d", getuid());
    dt_emit(line);
    snprintf(line, sizeof(line), "KCALL672_TOOL_GID=%d", getgid());
    dt_emit(line);
    if (argc > 0 && argv[0]) {
        snprintf(line, sizeof(line), "KCALL672_TOOL_ARGV0=%s", argv[0]);
        dt_emit(line);
    } else {
        dt_emit("KCALL672_TOOL_ARGV0=");
    }
    dt_emit("KCALL672_TOOL_DONE=1");
    return 0;
}
