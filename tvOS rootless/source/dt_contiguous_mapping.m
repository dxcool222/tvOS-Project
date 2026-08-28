#import "dt_contiguous_mapping.h"
#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <mach/mach.h>

static IOSurfaceRef DTAllocatePurpleGfxMemWithSize(size_t size)
{
    NSDictionary *surfaceProperties = @{
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
        @"IOSurfaceAllocSize" : [NSNumber numberWithUnsignedLongLong:(unsigned long long)size],
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)surfaceProperties);
}

static BOOL DTSurfaceIsContiguous(IOSurfaceRef surface)
{
    if (!surface)
        return NO;

    vm_address_t mem_addr = (vm_address_t)IOSurfaceGetBaseAddress(surface);
    vm_size_t mem_size = (vm_size_t)IOSurfaceGetAllocSize(surface);
    vm_region_submap_short_info_data_64_t info = {0};
    uint32_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t depth = 9999999;

    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &mem_addr, &mem_size, &depth,
        (vm_region_recurse_info_t)&info, &count);
    return (kr == KERN_SUCCESS && info.share_mode == SM_EMPTY && info.object_id != 0);
}

bool dt_contiguous_mapping_works(void)
{
    IOSurfaceRef surface = DTAllocatePurpleGfxMemWithSize(0x8000);
    if (!surface) {
        printf("[!] PurpleGfxMem allocation failed\n");
        return false;
    }

    BOOL contiguous = DTSurfaceIsContiguous(surface);
    printf("[*] PurpleGfxMem preflight: surface=%p contiguous=%d\n", surface, contiguous);
    CFRelease(surface);
    return contiguous;
}
