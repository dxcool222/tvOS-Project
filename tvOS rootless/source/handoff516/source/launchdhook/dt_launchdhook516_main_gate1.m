#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#import "libjailbreak.h"
#import "jbserver_boomerang.h"

#define DT516_HOOK_MARKER "/private/var/jb/.dt516_launchdhook_loaded"
#define DT518_CTOR_MARKER "/private/var/jb/.dt518_launchdhook_ctor_entered"
#define DT518_BOOMERANG_OK_MARKER "/private/var/jb/.dt518_boomerang_recover_ok"

extern int boomerang_recoverPrimitives516(bool firstRetrieval, bool shouldEndBoomerang);

static void dt516_write_marker(const char *path)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
        const char *msg = "ok\n";
        write(fd, msg, strlen(msg));
        close(fd);
    }
}

static void dt518_write_fail_marker(int err)
{
    char path[128];
    snprintf(path, sizeof(path), "/private/var/jb/.dt518_boomerang_recover_fail_%d", err);
    dt516_write_marker(path);
}

__attribute__((constructor)) static void dt516_launchdhook_init(void)
{
    dt516_write_marker(DT518_CTOR_MARKER);
    fprintf(stderr, "GATE1_LAUNCHDHOOK_CONSTRUCTOR_ENTERED\n");

    int err = boomerang_recoverPrimitives516(true, true);
    if (err != 0) {
        dt518_write_fail_marker(err);
        fprintf(stderr, "GATE1_LAUNCHDHOOK_BOOMERANG_RECOVER_BLOCKED err=%d\n", err);
        return;
    }
    dt516_write_marker(DT518_BOOMERANG_OK_MARKER);
    fprintf(stderr, "GATE1_LAUNCHDHOOK_BOOMERANG_RECOVER_OK\n");

    dt516_write_marker(DT516_HOOK_MARKER);
    fprintf(stderr, "GATE1_LAUNCHDHOOK_LOADED\n");
}
