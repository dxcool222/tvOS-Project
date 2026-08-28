#import "dt_kfund_import.h"
#import "dt_baked_offsets.h"
#import "DTRunLogger.h"
#undef T1SZ_BOOT
#import "info.h"

#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <string.h>

static dt_kfund_offsets_t g_kfund = {0};
static bool g_kfund_attempted = false;

static bool sysctl_kern_version(char *buf, size_t bufsz)
{
    size_t len = bufsz;
    return sysctlbyname("kern.version", buf, &len, NULL, 0) == 0 && len > 0;
}

static uint64_t plist_u64(id val)
{
    if (!val) return 0;
    if ([val respondsToSelector:@selector(unsignedLongLongValue)])
        return [val unsignedLongLongValue];
    return 0;
}

bool dt_kfund_import_was_attempted(void)
{
    return g_kfund_attempted;
}

int dt_import_kfd_offsets(void)
{
    if (g_kfund_attempted) {
        dt_run_log("[probe] kfund import skipped attempted=1 valid=%d", g_kfund.valid ? 1 : 0);
        return g_kfund.valid ? 0 : -1;
    }
    g_kfund_attempted = true;
    dt_run_log("[probe] kfund import first attempt plist_disk=%d", dt_kfund_plist_on_disk() ? 1 : 0);

    NSString *home = NSHomeDirectory();
    NSString *path = [home stringByAppendingPathComponent:@"Documents/kfund_offsets.plist"];
    if (access(path.UTF8String, F_OK) != 0) {
        dt_run_log("[probe] kfund import fail no plist");
        return -1;
    }

    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!dict)
        return -1;

    NSString *plistKv = dict[@"kern_version"];
    char liveKv[512] = {0};
    if (!sysctl_kern_version(liveKv, sizeof(liveKv)))
        return -1;
    if (!plistKv || strcmp(plistKv.UTF8String, liveKv) != 0) {
        dt_run_log("[probe] kfund import fail kern_version mismatch");
        return -1;
    }

    g_kfund.valid = true;
    strlcpy(g_kfund.kern_version, liveKv, sizeof(g_kfund.kern_version));
    g_kfund.cdevsw = plist_u64(dict[@"off_cdevsw"]);
    g_kfund.gPhysBase = plist_u64(dict[@"off_gPhysBase"]);
    g_kfund.gPhysSize = plist_u64(dict[@"off_gPhysSize"]);
    g_kfund.gVirtBase = plist_u64(dict[@"off_gVirtBase"]);
    g_kfund.perfmon_dev_open = plist_u64(dict[@"off_perfmon_dev_open"]);
    g_kfund.perfmon_devices = plist_u64(dict[@"off_perfmon_devices"]);
    g_kfund.ptov_table = plist_u64(dict[@"off_ptov_table"]);
    g_kfund.vn_kqfilter = plist_u64(dict[@"off_vn_kqfilter"]);
    g_kfund.proc_object_size = plist_u64(dict[@"off_proc_object_size"]);

    dt_run_log("[probe] kfund import OK gVirtBase=0x%llx proc_size=0x%llx",
        g_kfund.gVirtBase, g_kfund.proc_object_size);
    printf("[!] Found saved kfd offsets (kfund_offsets.plist)\n");
    printf("gPhysBase: 0x%llx proc_object_size: 0x%llx\n",
           g_kfund.gPhysBase, g_kfund.proc_object_size);
    return 0;
}

const dt_kfund_offsets_t *dt_kfund_offsets_cached(void)
{
    return &g_kfund;
}

bool dt_kfund_plist_on_disk(void)
{
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kfund_offsets.plist"];
    return access(path.UTF8String, F_OK) == 0;
}

void dt_apply_saved_phys_offsets_to_system_info(void)
{
    static const uint64_t kStaticBase = 0xfffffff007004000ULL;
    if (!g_kfund.valid)
        return;

    if (!gSystemInfo.kernelConstant.staticBase)
        gSystemInfo.kernelConstant.staticBase = kStaticBase;

    // jbinfo ksymbol() = slide + kernelSymbol — store full unslid link VAs (same as plist/dynamic_info).
    // Never writes kernelConstant.slide, .base, or gPrimitives.
#define SYM(field, val) do { if (val) gSystemInfo.kernelSymbol.field = (val); } while (0)
    SYM(cdevsw, g_kfund.cdevsw);
    SYM(gPhysBase, g_kfund.gPhysBase);
    SYM(gPhysSize, g_kfund.gPhysSize);
    SYM(gVirtBase, g_kfund.gVirtBase);
    SYM(perfmon_dev_open, g_kfund.perfmon_dev_open);
    SYM(perfmon_devices, g_kfund.perfmon_devices);
    SYM(ptov_table, g_kfund.ptov_table);
    SYM(vn_kqfilter, g_kfund.vn_kqfilter);
#undef SYM

    if (g_kfund.proc_object_size)
        gSystemInfo.kernelStruct.proc.struct_size = (uint32_t)g_kfund.proc_object_size;
}

void dt_apply_post_exploit_system_info(void)
{
    dt_apply_saved_phys_offsets_to_system_info();

    uint64_t sbase = gSystemInfo.kernelConstant.staticBase;
    uint64_t slide = gSystemInfo.kernelConstant.slide;
    if (sbase && slide)
        gSystemInfo.kernelConstant.base = sbase + slide;
}

void dt_apply_kfd_offsets_to_system_info(void)
{
    dt_apply_saved_phys_offsets_to_system_info();
}

void dt_kfund_cache_from_dynamic_info(void)
{
    extern void dt_kfund_cache_from_dynamic_info_impl(void);
    dt_kfund_cache_from_dynamic_info_impl();
}

void dt_kfund_load_cache(uint64_t cdevsw, uint64_t gPhysBase, uint64_t gPhysSize,
    uint64_t gVirtBase, uint64_t perfmon_dev_open, uint64_t perfmon_devices,
    uint64_t ptov_table, uint64_t vn_kqfilter, uint64_t proc_object_size)
{
    char liveKv[512] = {0};
    if (!sysctl_kern_version(liveKv, sizeof(liveKv)))
        return;

    g_kfund.valid = true;
    g_kfund_attempted = true;
    strlcpy(g_kfund.kern_version, liveKv, sizeof(g_kfund.kern_version));
    g_kfund.cdevsw = cdevsw;
    g_kfund.gPhysBase = gPhysBase;
    g_kfund.gPhysSize = gPhysSize;
    g_kfund.gVirtBase = gVirtBase;
    g_kfund.perfmon_dev_open = perfmon_dev_open;
    g_kfund.perfmon_devices = perfmon_devices;
    g_kfund.ptov_table = ptov_table;
    g_kfund.vn_kqfilter = vn_kqfilter;
    g_kfund.proc_object_size = proc_object_size;
}

int dt_save_kfd_offsets(void)
{
    if (!g_kfund.valid)
        return -1;

    NSString *home = NSHomeDirectory();
    NSString *path = [home stringByAppendingPathComponent:@"Documents/kfund_offsets.plist"];

    NSDictionary *dict = @{
        @"kern_version": [NSString stringWithUTF8String:g_kfund.kern_version],
        @"off_cdevsw": @(g_kfund.cdevsw),
        @"off_gPhysBase": @(g_kfund.gPhysBase),
        @"off_gPhysSize": @(g_kfund.gPhysSize),
        @"off_gVirtBase": @(g_kfund.gVirtBase),
        @"off_perfmon_dev_open": @(g_kfund.perfmon_dev_open),
        @"off_perfmon_devices": @(g_kfund.perfmon_devices),
        @"off_ptov_table": @(g_kfund.ptov_table),
        @"off_vn_kqfilter": @(g_kfund.vn_kqfilter),
        @"off_proc_object_size": @(g_kfund.proc_object_size),
    };

    printf("[!] Saving kfd offsets\n");
    if (![dict writeToFile:path atomically:YES]) {
        printf("failed to save offsets: %s\n", path.UTF8String);
        return -1;
    }
    printf("saved offsets for kfd: %s\n", path.UTF8String);
    g_kfund_attempted = true;
    return 0;
}
