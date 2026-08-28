// IOSurface / IOMemoryDescriptor layout for tvOS 16.5 (20L563) / T8010 (AppleTV6,2)
// Kernel: kernelcache.j105a.20L563.macho — IDA MCP verified (do NOT use Dopamine iOS offsets)
//
// IOSurface (kext prelink, OSMetaClass size 0x490 @ sub_FFFFFFF005CE2F4C):
//   fPixelFormat              @ +0xA4   sub_FFFFFFF005CE3644
//   fAllocSize                @ +0xAC
//   fMemoryDescriptor         @ +0x28   sub_FFFFFFF005CE332C store, sub_FFFFFFF005CE840C release (NOT Dopamine +0x38)
//   fIndexedTimestampPtr      @ +0x368  sub_FFFFFFF005CEEA08 *(a1+872) (NOT Dopamine +0x360)
//   fRanges                   @ +0x3E0  sub_FFFFFFF005CE840C / sub_FFFFFFF005CED620
//   fRangeCount               @ +0x3E8  sub_FFFFFFF005CF5E9C
//
// IOSurfaceRootUserClient (size 0x138 @ sub_FFFFFFF005CF8A88):
//   client table base         @ +0x100  sub_FFFFFFF005CFCD78 *(a1+256) (NOT Dopamine +0x118)
//   client table count        @ +0x108  sub_FFFFFFF005CFCD78 *(a1+264)
//   owner / root token        @ +0x110  sub_FFFFFFF005CFCD78 *(a1+272)
//   client lookup lock        @ +0xD8    sub_FFFFFFF005CFCEE0 *(a1+216)
//
// IOSurfaceClient: fSurface @ +0x40  sub_FFFFFFF005CF11F4
// IOSurfaceSendRight: fSurface @ +0x18  sub_FFFFFFF005CF2708 et al.
//
// IOMemoryDescriptor (kernel IOKit, OSMetaClass size 0x60 @ IOMemoryDescriptor::MetaClass::MetaClass):
//   _flags                    @ +0x20   __ZN18IOMemoryDescriptor8getFlagsEv @ 0xfffffff0077B1CFC
//   _map / map list head      @ +0x28   __ZN18IOMemoryDescriptor12setPurgeableEjPj (Dopamine "memRef" write target)
//   _length                   @ +0x50   __ZNK18IOMemoryDescriptor9getLengthEv @ 0xfffffff0077A8738
//   _ranges                   @ +0x60   IOGeneralMemoryDescriptor::free @ 0xfffffff0077AB63C
//   _wireCount / wired        @ +0x88   IOGeneralMemoryDescriptor::free @ 0xfffffff0077AB814
//   _mapper / prepare aux     @ +0x18   setPurgeable / performOperation (cleared by kmap exploit path)
//   _virtualMap               @ +0x70   IOGeneralMemoryDescriptor::initWithOptions
//   _direction                @ +0x90   IOGeneralMemoryDescriptor::free / redirect
//
// Magic 0x1EA5CACE is userspace spray only (kfd krkw sentinel), not in kernel binary.

#ifndef DT_IOSURFACE_KERNEL_OFFSETS_H
#define DT_IOSURFACE_KERNEL_OFFSETS_H

#define DT_IOSURFACE_MAGIC                 0x1EA5CACEu
#define DT_IOSURFACE_KRKW_OBJECT_SIZE      0x490u

// IOSurface object
#define DT_IOSURFACE_OFF_PIXEL_FORMAT      0xA4u
#define DT_IOSURFACE_OFF_ALLOC_SIZE        0xACu
#define DT_IOSURFACE_OFF_MEM_DESC          0x28u   // was 0x38 in Dopamine iOS primitives_IOSurface.m
#define DT_IOSURFACE_OFF_USE_COUNT_PTR     0xC0u
#define DT_IOSURFACE_OFF_READ_DISPLACEMENT 0x14u
#define DT_IOSURFACE_OFF_INDEXED_TS_PTR    0x368u  // was 0x360 in Dopamine iOS
#define DT_IOSURFACE_OFF_RANGES            0x3E0u
#define DT_IOSURFACE_OFF_RANGE_COUNT       0x3E8u

// IOSurfaceRootUserClient (external method context)
#define DT_IOSURFACE_UC_OFF_CLIENT_ARRAY   0x100u  // was 0x118 in Dopamine
#define DT_IOSURFACE_UC_OFF_CLIENT_COUNT   0x108u
#define DT_IOSURFACE_UC_OFF_OWNER          0x110u
#define DT_IOSURFACE_UC_OFF_LOCK           0xD8u
#define DT_IOSURFACE_UC_SELECTOR_CREATE    6u
#define DT_IOSURFACE_UC_SELECTOR_RELEASE   1u
#define DT_IOSURFACE_UC_SELECTOR_SET_TS    33u

// IOSurfaceClient / SendRight
#define DT_IOSURFACE_CLIENT_OFF_SURFACE    0x40u
#define DT_IOSURFACE_SENDRIGHT_OFF_SURFACE 0x18u

// IOMemoryDescriptor (kernel IOKit __TEXT_EXEC)
#define DT_IOMD_OFF_FLAGS                  0x20u
#define DT_IOMD_OFF_MAP                    0x28u   // Dopamine IOMemoryDescriptor_set_memRef target
#define DT_IOMD_OFF_MAPPER                 0x18u   // kmap clears to 0
#define DT_IOMD_OFF_LENGTH                 0x50u
#define DT_IOMD_OFF_RANGES                 0x60u
#define DT_IOMD_OFF_VIRTUAL_MAP            0x70u   // kmap clears to 0
#define DT_IOMD_OFF_WIRED                  0x88u
#define DT_IOMD_OFF_DIRECTION              0x90u   // kmap clears to 0

#endif
