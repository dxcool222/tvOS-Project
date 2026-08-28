#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define DT583_LOG "/private/var/jb/tmp/probe583_helper.log"
#define DT583_PING "/private/var/jb/tmp/probe583_checkin_ping"
#define DT583_PROFILE_NAME "container"

static void dt583_append_log(const char *line)
{
    FILE *f = fopen(DT583_LOG, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", line);
    fclose(f);
}

static void dt583_write_alive_log(void)
{
    unlink(DT583_LOG);
    dt583_append_log("KCALL583_HELPER_ALIVE=1");
    dt583_append_log("KCALL583_PROFILE_REGISTRY_NAME=" DT583_PROFILE_NAME);

    char line[128];
    snprintf(line, sizeof(line), "KCALL583_HELPER_PID=%d", getpid());
    dt583_append_log(line);
    snprintf(line, sizeof(line), "KCALL583_HELPER_PPID=%d", getppid());
    dt583_append_log(line);
    snprintf(line, sizeof(line), "uid=%d euid=%d gid=%d egid=%d",
        getuid(), geteuid(), getgid(), getegid());
    dt583_append_log(line);
    dt583_append_log("service=com.dopamin.probe583.helper");
    dt583_append_log("KCALL583_HELPER_CHECKIN_MODE=FILE_PING");
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    dt583_write_alive_log();
    unlink(DT583_PING);

    for (int i = 0; i < 120; i++) {
        if (access(DT583_PING, F_OK) == 0) {
            dt583_append_log("KCALL583_HELPER_CHECKIN_OK=1");
            unlink(DT583_PING);
            break;
        }
        usleep(250000);
    }

    sleep(30);
    return 0;
}
