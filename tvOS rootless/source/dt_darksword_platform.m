#import "dt_darksword_platform.h"
#include <stdio.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <string.h>

void dt_darksword_log_platform_banner(void)
{
    struct utsname name;
    char osversion[64] = {0};
    size_t len = sizeof(osversion);
    uname(&name);
    sysctlbyname("kern.osversion", osversion, &len, NULL, 0);

    printf("DARKSWORD_PLATFORM=tvOS\n");
    printf("DARKSWORD_TARGET=%s\n", name.machine);
    printf("DARKSWORD_OS=16.5\n");
    printf("DARKSWORD_BUILD=%s\n", osversion);
    printf("DARKSWORD_SLIDE_PATH=TVOS_PRE17_SOCKET_PROTO\n");
    printf("DARKSWORD_ARM64E=0\n");
    printf("DARKSWORD_PAC=0\n");
    printf("DARKSWORD_PPL=0\n");
}

bool dt_darksword_target_is_appletv62_20l563(void)
{
    char machine[64] = {0};
    char osversion[64] = {0};
    size_t len = sizeof(machine);
    if (sysctlbyname("hw.machine", machine, &len, NULL, 0) != 0)
        return false;
    len = sizeof(osversion);
    if (sysctlbyname("kern.osversion", osversion, &len, NULL, 0) != 0)
        return false;
    return strcmp(machine, "AppleTV6,2") == 0 && strcmp(osversion, "20L563") == 0;
}
