#import "DTDeviceInfo.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <net/if.h>

@implementation DTDeviceInfo

+ (NSString *)localIPv4
{
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) return @"?";
    NSString *ip = nil;
    for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
        char host[INET_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (!inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host))) continue;
        if (strncmp(host, "169.254.", 8) == 0) continue;
        ip = [NSString stringWithUTF8String:host];
        if (ifa->ifa_name && strcmp(ifa->ifa_name, "en0") == 0) break;
    }
    freeifaddrs(ifap);
    return ip ?: @"?";
}

+ (void)logBannerTo:(void (^)(NSString *))log
{
    if (!log) return;
    NSString *ver = UIDevice.currentDevice.systemVersion;
    log([NSString stringWithFormat:@"[*] systemVersion: %@", ver]);
    log([NSString stringWithFormat:@"[*] ip addr: %@", [self localIPv4]]);
    log(@"[*] Please pair using the IP address.");

    char kv[512] = {0};
    size_t len = sizeof(kv);
    if (sysctlbyname("kern.version", kv, &len, NULL, 0) == 0) {
        log([NSString stringWithFormat:@"[*] kern.version: %s", kv]);
    }
}

@end
