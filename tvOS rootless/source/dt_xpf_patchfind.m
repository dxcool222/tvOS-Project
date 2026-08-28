#import "DTKernelPath.h"
#import "dt_kfund_import.h"

#import <xpf/xpf.h>
#undef T1SZ_BOOT
#import "info.h"

/// XPF perfkrw patchfind (Dopamine iOS path) — fills gSystemInfo only.
int dt_xpf_patchfind_perfkrw(uint64_t kbase, uint64_t *out_static_base)
{
    NSString *kernelPath = DTAccessibleKernelPath();
    if (!kernelPath) {
        printf("[!] dynamic patchfinder: no kernelcache file\n");
        return -1;
    }

    printf("[!] Starting dynamic patchfinder (XPF / Dopamine perfkrw)\n");
    printf("kernelcache: %s\n", kernelPath.UTF8String);

    jbinfo_initialize_hardcoded_offsets();

    int xr = xpf_start_with_kernel_path(kernelPath.UTF8String);
    if (xr != 0) {
        printf("XPF start failed: %s\n", xpf_get_error());
        xpf_stop();
        return -1;
    }

    char *sets[] = { "translation", "struct", "perfkrw", NULL };
    xpc_object_t offsetDict = xpf_construct_offset_dictionary((const char **)sets);
    if (!offsetDict) {
        printf("XPF patchfind failed: %s\n", xpf_get_error());
        xpf_stop();
        return -1;
    }

    xpc_dictionary_set_uint64(offsetDict, "kernelConstant.staticBase", gXPF.kernelBase);
    jbinfo_initialize_dynamic_offsets(offsetDict);
    xpf_stop();

    uint64_t static_base = gXPF.kernelBase ? gXPF.kernelBase : 0xfffffff007004000ULL;
    gSystemInfo.kernelConstant.staticBase = static_base;
    if (kbase >= static_base)
        gSystemInfo.kernelConstant.slide = kbase - static_base;

    if (out_static_base)
        *out_static_base = static_base;
    return 0;
}
