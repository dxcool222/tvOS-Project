#include "dt_pte_kwrite.h"
#include "primitives.h"

extern void dt_run_log_stage(const char *stage);

static int dt_pte_kwrite64_perf(uint64_t kaddr, uint64_t val)
{
    return kwrite64(kaddr, val);
}

void dt_pte_kwrite_register_perf(void)
{
    dt_pte_kwrite_register(dt_pte_kwrite64_perf);
    dt_run_log_stage("build23 pte backend perf");
}

void dt_pte_kwrite_unregister_perf(void)
{
    dt_pte_kwrite_unregister();
}

bool dt_pte_kwrite_perf_is_ready(void)
{
    return dt_pte_kwrite_ready();
}
