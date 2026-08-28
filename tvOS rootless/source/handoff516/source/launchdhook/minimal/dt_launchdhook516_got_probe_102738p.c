#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define DT102738P_STATIC_BASE          0x100000000ULL
#define DT102738P_STATIC_CALLSITE      0x100040660ULL
#define DT102738P_STATIC_STUB          0x10004E9E8ULL
#define DT102738P_STATIC_GOT_SLOT      0x100065018ULL
#define DT102738P_STATIC_DATA_CONST    0x100064000ULL
#define DT102738P_DATA_CONST_SIZE      0x8000ULL
#define DT102738P_STATIC_GOT_START     0x100064000ULL
#define DT102738P_GOT_SIZE             0x1080ULL
#define DT102738P_PAGE_SIZE            0x4000ULL

static const uint8_t kDT102738PLaunchdUUID[16] = {
    0x7D, 0xC1, 0x76, 0x0B, 0x26, 0xC8, 0x35, 0x62,
    0xA6, 0x54, 0x8A, 0x31, 0xEE, 0xE1, 0xF7, 0x5F,
};

extern void dt102738p_trace_event(const char *event, int rc);
extern void dt102738p_trace_value_u64(const char *event, int rc, uint64_t value);

typedef struct {
    mach_vm_address_t start;
    mach_vm_size_t size;
    vm_prot_t current;
    vm_prot_t maximum;
} dt102738p_region_t;

typedef struct {
    mach_vm_address_t start;
    mach_vm_size_t size;
    vm_prot_t current;
    vm_prot_t maximum;
    natural_t depth;
    boolean_t is_submap;
} dt102738p_recurse_region_t;

__attribute__((noinline, naked)) static volatile kern_return_t
dt102738p_mach_vm_protect(mach_port_name_t target, mach_vm_address_t address,
    mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#if defined(__arm64__)
    __asm("mov x16, #-14");
    __asm("svc 0x80");
    __asm("ret");
#else
    (void)target;
    (void)address;
    (void)size;
    (void)set_maximum;
    (void)new_protection;
    __asm("brk #1");
#endif
}

static int dt102738p_query_region(mach_vm_address_t address, dt102738p_region_t *out)
{
    if (!out)
        return -1;

    vm_address_t region_address = (vm_address_t)address;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region_address, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name);
    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);
    if (kr != KERN_SUCCESS)
        return (int)kr;
    if (region_address > address || region_size < sizeof(uint64_t)
        || address - region_address > region_size - sizeof(uint64_t))
        return -2;

    out->start = region_address;
    out->size = region_size;
    out->current = info.protection;
    out->maximum = info.max_protection;
    return 0;
}

static int dt102738p_query_executable_leaf(mach_vm_address_t address,
    dt102738p_recurse_region_t *out)
{
    if (!out)
        return -1;

    vm_address_t region_address = (vm_address_t)address;
    vm_size_t region_size = 0;
    vm_region_submap_short_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t depth = 99999;
    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region_address,
        &region_size, &depth, (vm_region_recurse_info_t)&info, &count);

    out->start = region_address;
    out->size = region_size;
    out->current = info.protection;
    out->maximum = info.max_protection;
    out->depth = depth;
    out->is_submap = info.is_submap;

    if (kr != KERN_SUCCESS)
        return (int)kr;
    if (region_address > address || region_size < sizeof(uint64_t)
        || address - region_address > region_size - sizeof(uint64_t))
        return -2;
    return 0;
}

static int64_t dt102738p_sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static bool dt102738p_stub_resolves_slot(uintptr_t stub, uintptr_t slot)
{
    const volatile uint32_t *insn = (const volatile uint32_t *)stub;
    uint32_t adrp = insn[0];
    uint32_t ldr = insn[1];
    uint32_t br = insn[2];

    if ((adrp & 0x9F00001FU) != 0x90000010U)
        return false;
    if ((ldr & 0xFFC003FFU) != 0xF9400210U)
        return false;
    if (br != 0xD61F0200U)
        return false;

    uint64_t imm21 = ((uint64_t)((adrp >> 5) & 0x7FFFFU) << 2)
        | ((adrp >> 29) & 0x3U);
    int64_t page_delta = dt102738p_sign_extend(imm21, 21) * 0x1000LL;
    uintptr_t page = (stub & ~(uintptr_t)0xFFF) + page_delta;
    uintptr_t resolved = page + (((ldr >> 10) & 0xFFFU) * sizeof(uint64_t));
    return resolved == slot;
}

static bool dt102738p_callsite_targets_stub(uintptr_t callsite, uintptr_t stub)
{
    uint32_t bl = *(const volatile uint32_t *)callsite;
    if ((bl & 0xFC000000U) != 0x94000000U)
        return false;
    int64_t imm26 = dt102738p_sign_extend(bl & 0x03FFFFFFU, 26);
    return callsite + (imm26 * 4LL) == stub;
}

static int dt102738p_fail(const char *event, int rc)
{
    if (event)
        dt102738p_trace_event(event, rc);
    dt102738p_trace_event("GOT_PROBE_TERMINAL_FAIL", rc);
    return rc;
}

int dt102738p_run_got_protection_probe(void)
{
    dt102738p_trace_event("BUILD102738P_PROBE_ENTER", 0);
    dt102738p_trace_event("GOT_POINTER_WRITE_IMPLEMENTED_NO", 0);
#ifndef DT_ROOTLESS_R24_CBR
    /* R24 CBR installs XPC hooks after this probe; do not emit contradictory NO. */
    dt102738p_trace_event("XPC_HOOK_INSTALL_IMPLEMENTED_NO", 0);
#endif

    if (getpid() != 1)
        return dt102738p_fail("PID1_IDENTITY_FAIL", -73801);
    const char *image_name = _dyld_get_image_name(0);
    if (!image_name || strcmp(image_name, "/sbin/launchd") != 0)
        return dt102738p_fail("LAUNCHD_PATH_FAIL", -73802);
    dt102738p_trace_event("PID1_IDENTITY_PASS", 0);

    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    if (!mh || mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64
        || mh->filetype != MH_EXECUTE || mh->ncmds == 0 || mh->ncmds > 128
        || mh->sizeofcmds > 0x10000)
        return dt102738p_fail("LAUNCHD_MACHO_HEADER_FAIL", -73803);

    bool uuid_ok = false;
    bool text_ok = false;
    bool data_const_ok = false;
    bool got_ok = false;
    uint64_t got_start = 0;
    uint64_t got_size = 0;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    const uint8_t *commands_end = cursor + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > commands_end)
            return dt102738p_fail("LAUNCHD_MACHO_COMMAND_FAIL", -73804);
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > commands_end)
            return dt102738p_fail("LAUNCHD_MACHO_COMMAND_FAIL", -73805);

        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            uuid_ok = memcmp(uc->uuid, kDT102738PLaunchdUUID,
                sizeof(kDT102738PLaunchdUUID)) == 0;
        } else if (lc->cmd == LC_SEGMENT_64
            && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
                text_ok = seg->vmaddr == DT102738P_STATIC_BASE
                    && seg->vmsize == 0x64000ULL
                    && seg->maxprot == (VM_PROT_READ | VM_PROT_EXECUTE)
                    && seg->initprot == (VM_PROT_READ | VM_PROT_EXECUTE);
            } else if (strncmp(seg->segname, "__DATA_CONST", sizeof(seg->segname)) == 0) {
                data_const_ok = seg->vmaddr == DT102738P_STATIC_DATA_CONST
                    && seg->vmsize == DT102738P_DATA_CONST_SIZE
                    && seg->maxprot == (VM_PROT_READ | VM_PROT_WRITE);
                const struct section_64 *section =
                    (const struct section_64 *)(seg + 1);
                size_t required = sizeof(*seg) + ((size_t)seg->nsects * sizeof(*section));
                if (required > seg->cmdsize)
                    return dt102738p_fail("LAUNCHD_MACHO_SECTION_FAIL", -73806);
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strncmp(section[s].sectname, "__got",
                            sizeof(section[s].sectname)) == 0
                        && strncmp(section[s].segname, "__DATA_CONST",
                            sizeof(section[s].segname)) == 0) {
                        got_start = section[s].addr;
                        got_size = section[s].size;
                        got_ok = got_start == DT102738P_STATIC_GOT_START
                            && got_size == DT102738P_GOT_SIZE;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }

    if (!uuid_ok)
        return dt102738p_fail("LAUNCHD_UUID_FAIL", -73807);
    dt102738p_trace_event("LAUNCHD_UUID_PASS", 0);
    if (!text_ok || !data_const_ok || !got_ok)
        return dt102738p_fail("LAUNCHD_MACHO_GEOMETRY_FAIL", -73808);
    if ((uintptr_t)mh != (uintptr_t)(DT102738P_STATIC_BASE + slide))
        return dt102738p_fail("LAUNCHD_SLIDE_GEOMETRY_FAIL", -73809);
    dt102738p_trace_event("LAUNCHD_MACHO_GEOMETRY_PASS", 0);

    uintptr_t slot = (uintptr_t)(DT102738P_STATIC_GOT_SLOT + slide);
    uintptr_t got_runtime_start = (uintptr_t)(got_start + slide);
    uintptr_t got_runtime_end = got_runtime_start + (uintptr_t)got_size;
    if (slot < got_runtime_start || slot > got_runtime_end - sizeof(uint64_t))
        return dt102738p_fail("GOT_SLOT_RANGE_FAIL", -73810);
    dt102738p_trace_event("GOT_SLOT_RANGE_PASS", 0);

    uintptr_t stub = (uintptr_t)(DT102738P_STATIC_STUB + slide);
    uintptr_t callsite = (uintptr_t)(DT102738P_STATIC_CALLSITE + slide);
    if (!dt102738p_stub_resolves_slot(stub, slot)
        || !dt102738p_callsite_targets_stub(callsite, stub))
        return dt102738p_fail("GOT_STUB_REFERENCE_FAIL", -73811);
    dt102738p_trace_event("GOT_STUB_REFERENCE_PASS", 0);

    vm_size_t host_page_size_value = 0;
    kern_return_t page_kr = host_page_size(mach_host_self(), &host_page_size_value);
    if (page_kr != KERN_SUCCESS || host_page_size_value != DT102738P_PAGE_SIZE)
        return dt102738p_fail("GOT_PAGE_SIZE_FAIL", -73812);

    uintptr_t page = slot & ~(uintptr_t)(DT102738P_PAGE_SIZE - 1ULL);
    dt102738p_region_t initial = {0};
    int initial_query_rc = dt102738p_query_region(slot, &initial);
    if (initial_query_rc != 0 || initial.current != VM_PROT_READ
        || initial.maximum != (VM_PROT_READ | VM_PROT_WRITE)
        || page < initial.start || page + DT102738P_PAGE_SIZE > initial.start + initial.size)
        return dt102738p_fail("GOT_INITIAL_PROTECTION_FAIL", -73813);

    uint64_t pointer_before = *(const volatile uint64_t *)slot;
    dt102738p_trace_value_u64("GOT_RUNTIME_SLOT", 0, slot);
    dt102738p_trace_value_u64("GOT_PAGE_START", 0, page);
    dt102738p_trace_value_u64("GOT_PAGE_SIZE", 0, host_page_size_value);
    dt102738p_trace_value_u64("GOT_INITIAL_CURRENT_PROT", 0, initial.current);
    dt102738p_trace_value_u64("GOT_INITIAL_MAX_PROT", 0, initial.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_BEFORE", 0, pointer_before);

    dt102738p_region_t pointer_basic = {0};
    int pointer_basic_rc = pointer_before
        ? dt102738p_query_region((mach_vm_address_t)pointer_before, &pointer_basic) : -1;
    dt102738p_trace_event("GOT_POINTER_BASIC_QUERY_DIAGNOSTIC_ONLY", pointer_basic_rc);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_QUERY_RC", pointer_basic_rc,
        (uint64_t)(int64_t)pointer_basic_rc);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_START", pointer_basic_rc,
        pointer_basic.start);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_SIZE", pointer_basic_rc,
        pointer_basic.size);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_CURRENT_PROT", pointer_basic_rc,
        pointer_basic.current);
    dt102738p_trace_value_u64("GOT_POINTER_BASIC_MAX_PROT", pointer_basic_rc,
        pointer_basic.maximum);

    dt102738p_recurse_region_t pointer_leaf = {0};
    int pointer_recurse_rc = pointer_before
        ? dt102738p_query_executable_leaf((mach_vm_address_t)pointer_before,
            &pointer_leaf) : -1;
    dt102738p_trace_event("BUILD102738R_POINTER_VALIDATOR_REPAIR", 0);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_QUERY_RC", pointer_recurse_rc,
        (uint64_t)(int64_t)pointer_recurse_rc);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_START", pointer_recurse_rc,
        pointer_leaf.start);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_SIZE", pointer_recurse_rc,
        pointer_leaf.size);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_DEPTH", pointer_recurse_rc,
        pointer_leaf.depth);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_IS_SUBMAP", pointer_recurse_rc,
        pointer_leaf.is_submap ? 1 : 0);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_CURRENT_PROT", pointer_recurse_rc,
        pointer_leaf.current);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_MAX_PROT", pointer_recurse_rc,
        pointer_leaf.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_RECURSE_CONTAINS_POINTER",
        pointer_recurse_rc, pointer_recurse_rc == 0 ? 1 : 0);

    if (!pointer_before)
        return dt102738p_fail("GOT_POINTER_NULL_FAIL", -73814);
    if (pointer_recurse_rc != 0)
        return dt102738p_fail("GOT_POINTER_RECURSE_QUERY_FAIL", -73814);
    if (pointer_leaf.is_submap)
        return dt102738p_fail("GOT_POINTER_RECURSE_LEAF_FAIL", -73814);
    if (!(pointer_leaf.current & VM_PROT_EXECUTE))
        return dt102738p_fail("GOT_POINTER_EXEC_MAPPING_FAIL", -73814);

    dt102738p_trace_event("GOT_POINTER_RECURSE_MAPPING_PASS", 0);
    dt102738p_trace_event("GOT_POINTER_EXEC_MAPPING_PASS", 0);
    dt102738p_trace_value_u64("GOT_RW_REQUEST_PROT", 0,
        VM_PROT_READ | VM_PROT_WRITE);
    dt102738p_trace_value_u64("GOT_RW_SET_MAXIMUM", 0, 0);

    /* No trace I/O and no pointer store are permitted while the page is writable. */
    kern_return_t rw_rc = dt102738p_mach_vm_protect(mach_task_self(), page,
        DT102738P_PAGE_SIZE, false, VM_PROT_READ | VM_PROT_WRITE);
    dt102738p_region_t during = {0};
    int during_query_rc = -1;
    uint64_t pointer_during = 0;
    kern_return_t restore_first_rc = KERN_FAILURE;
    kern_return_t restore_retry_rc = KERN_FAILURE;
    bool restore_retried = false;
    if (rw_rc == KERN_SUCCESS) {
        during_query_rc = dt102738p_query_region(slot, &during);
        pointer_during = *(const volatile uint64_t *)slot;
        restore_first_rc = dt102738p_mach_vm_protect(mach_task_self(), page,
            DT102738P_PAGE_SIZE, false, initial.current);
        if (restore_first_rc != KERN_SUCCESS) {
            restore_retried = true;
            restore_retry_rc = dt102738p_mach_vm_protect(mach_task_self(), page,
                DT102738P_PAGE_SIZE, false, initial.current);
        }
    }

    dt102738p_region_t final = {0};
    int final_query_rc = dt102738p_query_region(slot, &final);
    uint64_t pointer_after = *(const volatile uint64_t *)slot;
    bool restore_call_ok = rw_rc != KERN_SUCCESS
        || restore_first_rc == KERN_SUCCESS
        || (restore_retried && restore_retry_rc == KERN_SUCCESS);
    bool final_state_ok = final_query_rc == 0
        && final.current == initial.current
        && final.maximum == initial.maximum
        && pointer_after == pointer_before;

    dt102738p_trace_event("GOT_RW_TRANSITION", (int)rw_rc);
    dt102738p_trace_value_u64("GOT_DURING_QUERY_RC", during_query_rc, during_query_rc);
    dt102738p_trace_value_u64("GOT_DURING_CURRENT_PROT", during_query_rc, during.current);
    dt102738p_trace_value_u64("GOT_DURING_MAX_PROT", during_query_rc, during.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_DURING", during_query_rc, pointer_during);
    dt102738p_trace_event("GOT_RESTORE_FIRST", (int)restore_first_rc);
    dt102738p_trace_value_u64("GOT_RESTORE_RETRIED", 0, restore_retried ? 1 : 0);
    if (restore_retried)
        dt102738p_trace_event("GOT_RESTORE_RETRY", (int)restore_retry_rc);
    dt102738p_trace_value_u64("GOT_FINAL_QUERY_RC", final_query_rc, final_query_rc);
    dt102738p_trace_value_u64("GOT_FINAL_CURRENT_PROT", final_query_rc, final.current);
    dt102738p_trace_value_u64("GOT_FINAL_MAX_PROT", final_query_rc, final.maximum);
    dt102738p_trace_value_u64("GOT_POINTER_AFTER", final_query_rc, pointer_after);

    if (rw_rc == KERN_SUCCESS && (!restore_call_ok || !final_state_ok)) {
        dt102738p_trace_event("GOT_PROTECTION_RESTORE_FATAL", -73815);
        return dt102738p_fail(NULL, -73815);
    }
    if (rw_rc != KERN_SUCCESS)
        return dt102738p_fail("GOT_RW_TRANSITION_FAIL", -73816);
    if (during_query_rc != 0
        || during.current != (VM_PROT_READ | VM_PROT_WRITE)
        || during.maximum != initial.maximum)
        return dt102738p_fail("GOT_DURING_PROTECTION_FAIL", -73817);
    if (pointer_during != pointer_before || pointer_after != pointer_before)
        return dt102738p_fail("GOT_POINTER_CHANGED_FATAL", -73818);

    dt102738p_trace_event("GOT_POINTER_UNCHANGED_PASS", 0);
    dt102738p_trace_event("GOT_PROTECTION_RESTORE_PASS", 0);
    dt102738p_trace_event("GOT_PROTECTION_TEST_PASS", 0);
    dt102738p_trace_event("GOT_PROBE_TERMINAL_PASS", 0);
    return 0;
}
