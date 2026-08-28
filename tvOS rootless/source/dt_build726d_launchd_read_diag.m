#import "dt_build726d_launchd_read_diag.h"
#import "dt_baked_offsets.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit_gate.h"
#import "primitives.h"
#import "kernel.h"
#import "info.h"

#import <errno.h>
#import <mach-o/loader.h>
#import <stdarg.h>
#import <stdbool.h>
#import <stdint.h>
#import <string.h>
#import <unistd.h>

#ifndef DT_BUILD_NUM
#define DT_BUILD_NUM 0
#endif

enum {
    kDT726DKnownControlValue   = 0x102726D0DEADBEEFULL,
    kDT726DTtepClassMask       = 0xf000000000000000ULL,
    kDT726DMaxEntriesProbed    = 5,
    kDT726DDirectVtophysEntries = 3,
};

static void dt726d_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:msg];
    if (log)
        log(msg);
}

static void dt726d_stage(const char *marker)
{
    [[DTRunLogger shared] logStage:[NSString stringWithUTF8String:marker]];
}

static bool dt726d_kva_canonical(uint64_t kva)
{
    return kva >= 0xfffff00000000000ULL;
}

static bool dt726d_user_ptr_plausible(uint64_t ua)
{
    if (!ua || ua >= 0xfffff00000000000ULL)
        return false;
    return true;
}

static int dt726d_physrw_ready(void)
{
    return dt_phys716_phys_ready()
        && gPrimitives.physreadbuf != NULL
        && gPrimitives.vtophys != NULL;
}

/// Telemetry wrapper only — does not alter proc_vreadbuf behavior.
static int dt726d_proc_vread_telemetry(uint64_t proc, uint64_t ua, void *buf, size_t len, int *errno_out)
{
    if (errno_out)
        *errno_out = 0;
    if (!proc || !buf || !len)
        return -1;
    if (!dt726d_user_ptr_plausible(ua))
        return -2;

    errno = 0;
    int rc = proc_vreadbuf(proc, (const void *)(uintptr_t)ua, buf, len);
    if (errno_out)
        *errno_out = errno;
    return rc;
}

static const char *dt726d_ttep_class_name(uint64_t ttep)
{
    if (!ttep)
        return "UNKNOWN";
    bool physical = !(bool)(ttep & kDT726DTtepClassMask);
    return physical ? "PHYSICAL" : "VIRTUAL";
}

static int dt726d_resolve_chain(uint64_t proc, uint64_t *task_out, uint64_t *map_out,
    uint64_t *pmap_out, uint64_t *ttep_raw_out, uint64_t *ttep_vread_out)
{
    if (!proc || !task_out || !map_out || !pmap_out || !ttep_raw_out || !ttep_vread_out)
        return -1;

    *task_out = 0;
    *map_out = 0;
    *pmap_out = 0;
    *ttep_raw_out = 0;
    *ttep_vread_out = 0;

    uint64_t task = proc_task(proc);
    if (!task || !dt726d_kva_canonical(task))
        return -10;

    uint64_t map = kread_ptr(task + koffsetof(task, map));
    if (!map || !dt726d_kva_canonical(map))
        return -11;

    uint64_t pmap = kread_ptr(map + koffsetof(vm_map, pmap));
    if (!pmap || !dt726d_kva_canonical(pmap))
        return -12;

    uint64_t ttep_raw = kread64(pmap + koffsetof(pmap, ttep));
    uint64_t ttep_vread = kread_ptr(pmap + koffsetof(pmap, ttep));

    *task_out = task;
    *map_out = map;
    *pmap_out = pmap;
    *ttep_raw_out = ttep_raw;
    *ttep_vread_out = ttep_vread;
    return 0;
}

int dt_build726d_run_readonly_launchd_read_diag(void (^log)(NSString *line), NSString **verdictOut)
{
    (void)DT_BUILD_NUM;

    dt726d_stage("BUILD102726D_BEGIN");
    dt726d_stage("BUILD102726D_SCOPE=READ_ONLY_LAUNCHD_USERSPACE_READ_PATH_DIAGNOSTIC");
    dt726d_stage("BUILD102726D_WALL2_ACTIVE=NO");
    dt726d_stage("BUILD102726D_OPAINJECT_ACTIVE=NO");
    dt726d_stage("BUILD102726D_HOOK_LOAD_ATTEMPTED=NO");

    bool phys_ready = dt726d_physrw_ready();
    dt726d_log(log, @"[*] BUILD102726D_PHYSRW_READY=%@", phys_ready ? @"YES" : @"NO");
    dt726d_log(log, @"[*] BUILD102726D_PRIM_KREADBUF=0x%llx", (unsigned long long)(uintptr_t)gPrimitives.kreadbuf);
    dt726d_log(log, @"[*] BUILD102726D_PRIM_KWRITEBUF=0x%llx", (unsigned long long)(uintptr_t)gPrimitives.kwritebuf);
    dt726d_log(log, @"[*] BUILD102726D_PRIM_PHYSREADBUF=0x%llx", (unsigned long long)(uintptr_t)gPrimitives.physreadbuf);
    dt726d_log(log, @"[*] BUILD102726D_PRIM_PHYSWRITEBUF=0x%llx", (unsigned long long)(uintptr_t)gPrimitives.physwritebuf);
    dt726d_log(log, @"[*] BUILD102726D_PRIM_VTOPHYS=0x%llx", (unsigned long long)(uintptr_t)gPrimitives.vtophys);

    if (!phys_ready || !dt_kernel_exploit_is_active() || !g_dt_baked_offsets_active) {
        dt726d_stage("BUILD102726D_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102726D_PREREQUISITE_FAIL";
        return -1;
    }

    dt726d_log(log, @"[*] BUILD102726D_TTEP_CLASSIFICATION_RULE=physical=!(ttep&0xF000000000000000)");

    uint64_t self_proc = proc_find((int)getpid());
    uint64_t pid1_proc = proc_find(1);

    uint64_t self_task = 0, self_map = 0, self_pmap = 0, self_ttep_raw = 0, self_ttep_vread = 0;
    uint64_t pid1_task = 0, pid1_map = 0, pid1_pmap = 0, pid1_ttep_raw = 0, pid1_ttep_vread = 0;

    int self_chain_rc = self_proc ? dt726d_resolve_chain(self_proc, &self_task, &self_map,
        &self_pmap, &self_ttep_raw, &self_ttep_vread) : -1;
    int pid1_chain_rc = pid1_proc ? dt726d_resolve_chain(pid1_proc, &pid1_task, &pid1_map,
        &pid1_pmap, &pid1_ttep_raw, &pid1_ttep_vread) : -1;

    dt726d_log(log, @"[*] BUILD102726D_SELF_PROC=0x%llx", (unsigned long long)self_proc);
    dt726d_log(log, @"[*] BUILD102726D_SELF_TASK=0x%llx", (unsigned long long)self_task);
    dt726d_log(log, @"[*] BUILD102726D_SELF_MAP=0x%llx", (unsigned long long)self_map);
    dt726d_log(log, @"[*] BUILD102726D_SELF_PMAP=0x%llx", (unsigned long long)self_pmap);
    dt726d_log(log, @"[*] BUILD102726D_SELF_TTEP_RAW=0x%llx", (unsigned long long)self_ttep_raw);

    dt726d_log(log, @"[*] BUILD102726D_PID1_PROC=0x%llx", (unsigned long long)pid1_proc);
    dt726d_log(log, @"[*] BUILD102726D_PID1_TASK=0x%llx", (unsigned long long)pid1_task);
    dt726d_log(log, @"[*] BUILD102726D_PID1_MAP=0x%llx", (unsigned long long)pid1_map);
    dt726d_log(log, @"[*] BUILD102726D_PID1_PMAP=0x%llx", (unsigned long long)pid1_pmap);
    dt726d_log(log, @"[*] BUILD102726D_PID1_TTEP_RAW=0x%llx", (unsigned long long)pid1_ttep_raw);

    dt726d_log(log, @"[*] BUILD102726D_SELF_TTEP_CLASS=%s", dt726d_ttep_class_name(self_ttep_vread));
    dt726d_log(log, @"[*] BUILD102726D_PID1_TTEP_CLASS=%s", dt726d_ttep_class_name(pid1_ttep_vread));

    if (self_chain_rc != 0 || pid1_chain_rc != 0 || !self_proc || !pid1_proc) {
        dt726d_stage("BUILD102726D_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102726D_PREREQUISITE_FAIL";
        return -2;
    }

    uint64_t self_known = kDT726DKnownControlValue;
    uint64_t self_readback = 0;
    int self_errno = 0;
    int self_vread_rc = dt726d_proc_vread_telemetry(self_proc, (uint64_t)(uintptr_t)&self_known,
        &self_readback, sizeof(self_readback), &self_errno);

    dt726d_log(log, @"[*] BUILD102726D_SELF_CONTROL_VA=0x%llx", (unsigned long long)(uintptr_t)&self_known);
    dt726d_log(log, @"[*] BUILD102726D_SELF_CONTROL_EXPECTED=0x%llx", (unsigned long long)kDT726DKnownControlValue);
    dt726d_log(log, @"[*] BUILD102726D_SELF_PROC_VREAD_RC=%d", self_vread_rc);
    dt726d_log(log, @"[*] BUILD102726D_SELF_PROC_VREAD_ERRNO=%d", self_errno);
    dt726d_log(log, @"[*] BUILD102726D_SELF_CONTROL_READBACK=0x%llx", (unsigned long long)self_readback);
    dt726d_log(log, @"[*] BUILD102726D_SELF_CONTROL_MATCH=%@",
        (self_vread_rc == 0 && self_readback == kDT726DKnownControlValue) ? @"YES" : @"NO");

    bool self_pass = (self_vread_rc == 0 && self_readback == kDT726DKnownControlValue);

    uint64_t sentinel = pid1_map + koffsetof(vm_map, hdr);
    uint64_t entry = kread_ptr(pid1_map + koffsetof(vm_map, hdr) + koffsetof(vm_map_links, next));

    unsigned entry_index = 0;
    unsigned entries_logged = 0;
    uint64_t pid1_control_entry = 0;
    uint64_t pid1_control_va = 0;
    uint32_t pid1_control_word = 0;
    int pid1_control_rc = -1;
    int pid1_control_errno = 0;
    bool any_pid1_read_pass = false;
    bool any_pid1_magic = false;

    bool direct_vtophys_ok = (gPrimitives.vtophys != NULL && pid1_ttep_vread != 0);
    if (!direct_vtophys_ok)
        dt726d_log(log, @"[*] BUILD102726D_DIRECT_VTOPHYS_TELEMETRY=UNAVAILABLE");
    else
        dt726d_log(log, @"[*] BUILD102726D_DIRECT_VTOPHYS_TELEMETRY=IMPLEMENTED");

    while (entry != sentinel && entries_logged < kDT726DMaxEntriesProbed) {
        if (!entry || !dt726d_kva_canonical(entry))
            break;

        uint64_t start = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, min));
        uint64_t end = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, max));
        if (start >= end || !dt726d_user_ptr_plausible(start))
            break;

        uint64_t flags = kread64(entry + koffsetof(vm_map_entry, flags));
        uint32_t magic = 0;
        int entry_errno = 0;
        int entry_rc = dt726d_proc_vread_telemetry(pid1_proc, start, &magic, sizeof(magic), &entry_errno);

        dt726d_log(log, @"[*] BUILD102726D_ENTRY_INDEX=%u", entry_index);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_KVA=0x%llx", (unsigned long long)entry);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_START=0x%llx", (unsigned long long)start);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_END=0x%llx", (unsigned long long)end);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_FLAGS=0x%llx", (unsigned long long)flags);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_VREAD_RC=%d", entry_rc);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_VREAD_ERRNO=%d", entry_errno);
        dt726d_log(log, @"[*] BUILD102726D_ENTRY_MAGIC=0x%x", magic);

        if (direct_vtophys_ok && entries_logged < kDT726DDirectVtophysEntries) {
            errno = 0;
            uint64_t pa = gPrimitives.vtophys(pid1_ttep_vread, start);
            int vt_errno = errno;
            dt726d_log(log, @"[*] BUILD102726D_ENTRY%u_VA=0x%llx", entries_logged,
                (unsigned long long)start);
            dt726d_log(log, @"[*] BUILD102726D_ENTRY%u_PA=0x%llx", entries_logged,
                (unsigned long long)pa);
            (void)vt_errno;
        }

        if (entry_rc == 0) {
            any_pid1_read_pass = true;
            if (magic == MH_MAGIC_64)
                any_pid1_magic = true;
        }

        if (entries_logged == 0) {
            pid1_control_entry = entry;
            pid1_control_va = start;
            pid1_control_word = magic;
            pid1_control_rc = entry_rc;
            pid1_control_errno = entry_errno;
        }

        entry_index++;
        entries_logged++;
        entry = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, next));
    }

    dt726d_log(log, @"[*] BUILD102726D_PID1_CONTROL_ENTRY=0x%llx", (unsigned long long)pid1_control_entry);
    dt726d_log(log, @"[*] BUILD102726D_PID1_CONTROL_VA=0x%llx", (unsigned long long)pid1_control_va);
    dt726d_log(log, @"[*] BUILD102726D_PID1_PROC_VREAD_RC=%d", pid1_control_rc);
    dt726d_log(log, @"[*] BUILD102726D_PID1_PROC_VREAD_ERRNO=%d", pid1_control_errno);
    dt726d_log(log, @"[*] BUILD102726D_PID1_CONTROL_WORD=0x%x", pid1_control_word);

    bool pid1_fail = !any_pid1_read_pass;
    const char *pid1_class = dt726d_ttep_class_name(pid1_ttep_vread);
    bool pid1_virtual = (strcmp(pid1_class, "VIRTUAL") == 0);
    bool kread_null = (gPrimitives.kreadbuf == NULL);

    const char *result = "INCONCLUSIVE";

    if (!self_pass && pid1_fail) {
        result = "SELF_AND_PID1_FAIL";
    } else if (self_pass && pid1_fail && pid1_virtual && kread_null) {
        result = "PID1_TTEP_VIRTUAL_NO_BACKEND";
    } else if (self_pass && any_pid1_read_pass && !any_pid1_magic) {
        result = "PID1_READ_PASS_BASE_GEOMETRY_SUSPECT";
    } else if (self_pass && pid1_fail) {
        result = "SELF_PASS_PID1_FAIL";
    } else if (self_pass && any_pid1_read_pass) {
        result = "SELF_AND_PID1_READ_PASS";
    }

    dt726d_log(log, @"[*] BUILD102726D_MAX_ENTRIES_PROBED=%u", entries_logged);
    dt726d_stage([NSString stringWithFormat:@"BUILD102726D_RESULT=%s", result].UTF8String);
    if (verdictOut)
        *verdictOut = [NSString stringWithFormat:@"BUILD102726D_%s", result];
    return 0;
}
