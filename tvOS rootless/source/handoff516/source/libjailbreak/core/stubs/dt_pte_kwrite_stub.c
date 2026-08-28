#include "dt_pte_kwrite.h"
#include "primitives.h"

static dt_pte_kwrite64_fn g_pte_kwrite64 = NULL;

void dt_pte_kwrite_register(dt_pte_kwrite64_fn fn)
{
    g_pte_kwrite64 = fn;
}

void dt_pte_kwrite_unregister(void)
{
    g_pte_kwrite64 = NULL;
}

bool dt_pte_kwrite_ready(void)
{
    return g_pte_kwrite64 != NULL;
}

int dt_pte_kwrite64(uint64_t kaddr, uint64_t val)
{
    if (g_pte_kwrite64)
        return g_pte_kwrite64(kaddr, val);
    return kwrite64(kaddr, val);
}
