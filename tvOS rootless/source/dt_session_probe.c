#include "dt_session_probe.h"
#include "dt_pmap_probe.h"
#include "kfd_tvos.h"
#include "dt_kfund_import.h"

#include <kalloc_pt.h>
#include <primitives.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

extern uint64_t gKfd;

extern bool kalloc_pt_is_initialized(void);
extern unsigned kalloc_pt_pool_count(void);

void dt_run_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void dt_run_log_stage(const char *stage);

static unsigned s_cycle = 0;

static void probe_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    dt_run_log("%s", buf);
}

static void probe_stage(const char *stage)
{
    dt_run_log_stage(stage);
}

unsigned dt_session_cycle(void)
{
    return s_cycle;
}

void dt_session_probe_snapshot(const char *tag)
{
    dt_pmap_cache_snapshot_t pmap = {0};
    dt_pmap_cache_snapshot(&pmap);

    const dt_kfund_offsets_t *kf = dt_kfund_offsets_cached();
    bool plist_disk = dt_kfund_plist_on_disk();

    probe_log("[probe] snapshot tag=%s cycle=%u pid=%d gKfd=0x%llx active=%d",
        tag ? tag : "?", s_cycle, (int)getpid(), (unsigned long long)gKfd,
        dt_kfd_is_active() ? 1 : 0);

    probe_log("[probe] kfund attempted=%d valid=%d plist_disk=%d",
        dt_kfund_import_was_attempted() ? 1 : 0,
        (kf && kf->valid) ? 1 : 0,
        plist_disk ? 1 : 0);

    probe_log("[probe] pmap_cache proc=%d task=%d map=%d pmap=%d "
        "val proc=0x%llx task=0x%llx map=0x%llx pmap=0x%llx",
        pmap.proc_cached ? 1 : 0, pmap.task_cached ? 1 : 0,
        pmap.map_cached ? 1 : 0, pmap.pmap_cached ? 1 : 0,
        (unsigned long long)pmap.proc, (unsigned long long)pmap.task,
        (unsigned long long)pmap.map, (unsigned long long)pmap.pmap);

    probe_log("[probe] primitives kread=%p kwrite=%p physread=%p physwrite=%p "
        "kalloc=%p kfree=%p vtophys=%p",
        (void *)gPrimitives.kreadbuf, (void *)gPrimitives.kwritebuf,
        (void *)gPrimitives.physreadbuf, (void *)gPrimitives.physwritebuf,
        (void *)gPrimitives.kalloc_global, (void *)gPrimitives.kfree_global,
        (void *)gPrimitives.vtophys);

    probe_log("[probe] kalloc_pt init=%d pool_count=%u",
        kalloc_pt_is_initialized() ? 1 : 0, kalloc_pt_pool_count());
}

void dt_session_probe_exploit_init_enter(void)
{
    s_cycle++;
    probe_stage("build51 probe exploit_init enter");
    probe_log("[probe] exploit_init enter cycle=%u (same process — reinstall resets statics)", s_cycle);
    dt_session_probe_snapshot("exploit_init_enter");
}

void dt_session_probe_exploit_init_exit(int kopen_result)
{
    probe_log("[probe] exploit_init exit cycle=%u kopen_result=%d gKfd=0x%llx",
        s_cycle, kopen_result, (unsigned long long)gKfd);
    dt_session_probe_snapshot("exploit_init_exit");
    probe_stage(kopen_result == 0 ? "build51 probe exploit_init OK" : "build51 probe exploit_init fail");
}

void dt_session_probe_exploit_deinit_enter(void)
{
    probe_stage("build51 probe exploit_deinit enter");
    probe_log("[probe] exploit_deinit enter cycle=%u gKfd=0x%llx", s_cycle, (unsigned long long)gKfd);
    dt_session_probe_snapshot("exploit_deinit_enter");
}

void dt_session_probe_exploit_deinit_exit(int deinit_result)
{
    probe_log("[probe] exploit_deinit exit cycle=%u result=%d gKfd=0x%llx active=%d",
        s_cycle, deinit_result, (unsigned long long)gKfd, dt_kfd_is_active() ? 1 : 0);
    dt_session_probe_snapshot("exploit_deinit_exit");
    probe_stage(deinit_result == 0 ? "build51 probe exploit_deinit OK" : "build51 probe exploit_deinit fail");
}

void dt_session_probe_physrw_init_enter(void)
{
    probe_stage("build51 probe physrw_init enter");
    dt_session_probe_snapshot("physrw_init_enter");
}

void dt_session_probe_physrw_init_exit(int result)
{
    probe_log("[probe] physrw_init exit result=%d physread=%p physwrite=%p",
        result, (void *)gPrimitives.physreadbuf, (void *)gPrimitives.physwritebuf);
    dt_session_probe_snapshot("physrw_init_exit");
    probe_stage(result == 0 ? "build51 probe physrw_init OK" : "build51 probe physrw_init fail");
}

void dt_session_probe_build26_enter(void)
{
    probe_stage("build51 probe build26 enter");
    dt_session_probe_snapshot("build26_enter");
}

void dt_session_probe_build26_exit(int result, unsigned pre_count, unsigned post_count)
{
    probe_log("[probe] build26 exit result=%d pre_count=%u post_count=%u kalloc_pool=%u",
        result, pre_count, post_count, kalloc_pt_pool_count());
    dt_session_probe_snapshot("build26_exit");
    if (result == 0)
        probe_stage("build51 probe build26 OK");
    else {
        char stage[64];
        snprintf(stage, sizeof(stage), "build51 probe build26 fail %d", result);
        probe_stage(stage);
    }
}

void dt_session_probe_phys_stage(const char *stage)
{
    if (!stage || !stage[0]) return;
    dt_run_log_stage(stage);
    probe_log("[probe] phys %s", stage);
}
