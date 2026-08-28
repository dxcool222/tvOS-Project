#include "kalloc_pt.h"
#include "primitives.h"
#include "translation.h"
#include "util.h"

#include <os/lock.h>
#include <stdio.h>
#include <string.h>

/*
 * R24 F1: plain C pool — no NSMutableArray/NSNumber.
 * Crash 2026-08-20 17:50: SIGSEGV in objc_msgSend$unsignedLongLongValue on gPool.
 */

#define KALLOC_PT_POOL_CAP 64

static uint64_t s_pool[KALLOC_PT_POOL_CAP];
static unsigned s_pool_count = 0;
static os_unfair_lock s_pool_lock = OS_UNFAIR_LOCK_INIT;
static bool s_kalloc_pt_initialized = false;
static unsigned s_kalloc_pt_init_count = 0;

bool kalloc_pt_is_initialized(void)
{
    return s_kalloc_pt_initialized;
}

unsigned kalloc_pt_pool_count(void)
{
    os_unfair_lock_lock(&s_pool_lock);
    unsigned n = s_pool_count;
    os_unfair_lock_unlock(&s_pool_lock);
    return n;
}

static bool kalloc_pt_kva_is_canonical(uint64_t kva)
{
    if (kva < 0x10000ULL)
        return false;
    if ((kva & 0x3FFFULL) != 0)
        return false;
    if ((kva >> 48) != 0xFFFFULL)
        return false;
    return true;
}

int kalloc_global_pt(uint64_t *kaddrOut, uint64_t size)
{
    if (!kaddrOut)
        return -1;
    if (size == 0)
        return -1;
    if (size > vm_real_kernel_page_size)
        return -1;

    os_unfair_lock_lock(&s_pool_lock);
    if (s_pool_count > 0) {
        uint64_t kva = s_pool[0];
        memmove(&s_pool[0], &s_pool[1], (s_pool_count - 1) * sizeof(uint64_t));
        s_pool_count--;
        os_unfair_lock_unlock(&s_pool_lock);
        if (!kalloc_pt_kva_is_canonical(kva))
            return -1;
        *kaddrOut = kva;
        return 0;
    }
    os_unfair_lock_unlock(&s_pool_lock);

    uint64_t allocPA = alloc_page_table_unassigned();
    uint64_t allocVA = phystokv(allocPA);
    if (allocVA && kalloc_pt_kva_is_canonical(allocVA)) {
        *kaddrOut = allocVA;
        return 0;
    }
    return -1;
}

int kfree_global_pt(uint64_t kaddr, uint64_t size)
{
    (void)size;
    if (!kaddr)
        return -1;
    if (!kalloc_pt_kva_is_canonical(kaddr))
        return -1;

    os_unfair_lock_lock(&s_pool_lock);
    if (s_pool_count >= KALLOC_PT_POOL_CAP) {
        os_unfair_lock_unlock(&s_pool_lock);
        return -1;
    }
    s_pool[s_pool_count++] = kaddr;
    os_unfair_lock_unlock(&s_pool_lock);
    return 0;
}

void libjailbreak_kalloc_pt_init(void)
{
    os_unfair_lock_lock(&s_pool_lock);
    s_kalloc_pt_init_count++;
    /* Keep existing pooled KVAs across re-init; do not wipe mid-bringup. */
    s_kalloc_pt_initialized = true;
    os_unfair_lock_unlock(&s_pool_lock);
    gPrimitives.kalloc_global = kalloc_global_pt;
    gPrimitives.kfree_global = kfree_global_pt;
    printf("[probe] kalloc_pt init count=%u pool=%u backend=C_POOL\n",
        s_kalloc_pt_init_count, kalloc_pt_pool_count());
}

int kalloc_pt_prefill(unsigned count)
{
    if (count == 0)
        return -1;

    unsigned seeded = 0;
    for (unsigned i = 0; i < count; i++) {
        uint64_t allocPA = alloc_page_table_unassigned();
        if (!allocPA)
            break;
        uint64_t allocVA = phystokv(allocPA);
        if (!allocVA || !kalloc_pt_kva_is_canonical(allocVA))
            break;
        os_unfair_lock_lock(&s_pool_lock);
        if (s_pool_count >= KALLOC_PT_POOL_CAP) {
            os_unfair_lock_unlock(&s_pool_lock);
            break;
        }
        s_pool[s_pool_count++] = allocVA;
        os_unfair_lock_unlock(&s_pool_lock);
        seeded++;
    }
    return (int)seeded;
}
