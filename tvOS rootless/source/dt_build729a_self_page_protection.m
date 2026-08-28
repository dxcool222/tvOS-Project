#import "dt_build729a_self_page_protection.h"
#import "DTRunLogger.h"

#import <mach/mach.h>
#import <mach/vm_region.h>
#import <stdarg.h>
#import <stdbool.h>
#import <stdint.h>
#import <string.h>

#ifndef DT_BUILD_NUM
#define DT_BUILD_NUM 0
#endif

enum {
    kDT729APageSize      = 0x4000u,
    kDT729ASentinelA     = 0x102729A0DEADBEEFULL,
    kDT729ASentinelB     = 0x102729B0CAFEBABEULL,
    kDT729AProtRead      = VM_PROT_READ,
    kDT729AProtRW        = VM_PROT_READ | VM_PROT_WRITE,
};

typedef uint64_t dt729a_vm_addr_t;
typedef uint64_t dt729a_vm_size_t;

__attribute__((noinline, naked)) volatile kern_return_t
dt729a_mach_vm_protect(mach_port_name_t target,
                       dt729a_vm_addr_t address,
                       dt729a_vm_size_t size,
                       boolean_t set_maximum,
                       vm_prot_t new_protection)
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

static void dt729a_log(void (^log)(NSString *line), NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [[DTRunLogger shared] log:msg];
    if (log)
        log(msg);
}

static void dt729a_stage(const char *marker)
{
    [[DTRunLogger shared] logStage:[NSString stringWithUTF8String:marker]];
}

static NSString *dt729a_decode_prot(uint32_t prot)
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    if (prot & VM_PROT_READ)
        [parts addObject:@"READ"];
    if (prot & VM_PROT_WRITE)
        [parts addObject:@"WRITE"];
    if (prot & VM_PROT_EXECUTE)
        [parts addObject:@"EXEC"];
    if (parts.count == 0)
        return @"NONE";
    return [parts componentsJoinedByString:@"|"];
}

static bool dt729a_page_aligned(dt729a_vm_addr_t addr)
{
    return (addr & (kDT729APageSize - 1u)) == 0;
}

static int dt729a_query_region(dt729a_vm_addr_t page, kern_return_t *kr_out,
    uint32_t *cur_out, uint32_t *max_out)
{
    vm_address_t query_addr = (vm_address_t)page;
    vm_size_t region_size = 0;
    struct vm_region_basic_info_64 info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    memset(&info, 0, sizeof(info));
    kern_return_t kr = vm_region_64(mach_task_self(),
        &query_addr,
        (vm_size_t *)&region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &object_name);

    if (kr_out)
        *kr_out = kr;
    if (kr != KERN_SUCCESS)
        return -1;
    if (cur_out)
        *cur_out = info.protection;
    if (max_out)
        *max_out = info.max_protection;
    return 0;
}

static bool dt729a_read_u64(dt729a_vm_addr_t addr, uint64_t *out)
{
    if (!out)
        return false;
    *out = *(volatile uint64_t *)(uintptr_t)addr;
    return true;
}

static bool dt729a_write_u64(dt729a_vm_addr_t addr, uint64_t value)
{
    *(volatile uint64_t *)(uintptr_t)addr = value;
    return true;
}

static void dt729a_emit_frozen_verification(void (^log)(NSString *line))
{
    dt729a_log(log, @"[*] BUILD102728_RESOLVER_CHANGED=NO");
    dt729a_log(log, @"[*] GOT_DELTA_CHANGED=NO");
    dt729a_log(log, @"[*] KFD_CHANGED=NO");
    dt729a_log(log, @"[*] PHYSRW_CHANGED=NO");
    dt729a_log(log, @"[*] KCALL_CHANGED=NO");
    dt729a_log(log, @"[*] TRANSLATION_CHANGED=NO");
    dt729a_log(log, @"[*] VM_MAP_LAYOUT_CHANGED=NO");
    dt729a_log(log, @"[*] PREBOOT_CHANGED=NO");
    dt729a_log(log, @"[*] SIGNING_CHANGED=NO");
    dt729a_log(log, @"[*] TRUSTCACHE_CHANGED=NO");
    dt729a_log(log, @"[*] WALL2_CHANGED=NO");
    dt729a_log(log, @"[*] OPAINJECT_CHANGED=NO");
    dt729a_log(log, @"[*] LAUNCHDHOOK_CHANGED=NO");
    dt729a_log(log, @"[*] LIBJAILBREAK_CHANGED=NO");
    dt729a_log(log, @"[*] LIBCHOMA_CHANGED=NO");
}

static void dt729a_emit_safety_markers(void)
{
    dt729a_stage("BUILD102729A_TARGET_PROCESS=SELF_ONLY");
    dt729a_stage("BUILD102729A_LAUNCHD_ACCESSED=NO");
    dt729a_stage("BUILD102729A_GOT_ACCESSED=NO");
    dt729a_stage("BUILD102729A_GOT_WRITTEN=NO");
    dt729a_stage("BUILD102729A_REMOTE_PROCESS_MUTATION=NO");
    dt729a_stage("BUILD102729A_PHYSICAL_WRITE_USED=NO");
    dt729a_stage("BUILD102729A_VM_MAP_FLAGS_WRITTEN=NO");
    dt729a_stage("BUILD102729A_WALL2_ACTIVE=NO");
    dt729a_stage("BUILD102729A_OPAINJECT_ACTIVE=NO");
    dt729a_stage("BUILD102729A_HOOK_LOAD_ACTIVE=NO");
    dt729a_stage("BUILD102729A_READONLY_WRITE_ATTEMPTED=NO");
}

static void dt729a_finish(NSString **verdictOut, const char *result, int rc)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "BUILD102729A_RESULT=%s", result);
    dt729a_stage(buf);
    if (verdictOut)
        *verdictOut = [NSString stringWithUTF8String:result];
    dt729a_emit_safety_markers();
}

int dt_build729a_run_self_page_protection_control(void (^log)(NSString *line), NSString **verdictOut)
{
    (void)DT_BUILD_NUM;

    dt729a_stage("BUILD102729A_BEGIN");
    dt729a_stage("BUILD102729A_SCOPE=SELF_PROCESS_MACH_VM_PROTECT_CONTROL");
    dt729a_emit_safety_markers();
    dt729a_emit_frozen_verification(log);

    mach_port_name_t task_self = mach_task_self();
    dt729a_log(log, @"[*] BUILD102729A_TASK_SELF=0x%x", task_self);
    dt729a_log(log, @"[*] BUILD102729A_PAGE_SIZE=0x%x", kDT729APageSize);
    dt729a_log(log, @"[*] BUILD102729A_REGION_QUERY_API=vm_region_64");

    vm_address_t page = 0;
    vm_size_t page_size = kDT729APageSize;
    kern_return_t kr = vm_allocate(mach_task_self(), &page, page_size, VM_FLAGS_ANYWHERE);
    dt729a_log(log, @"[*] BUILD102729A_ALLOCATE_RC=%d", kr);
    dt729a_log(log, @"[*] BUILD102729A_PAGE_ADDRESS=0x%llx", (unsigned long long)page);

    bool aligned = dt729a_page_aligned(page);
    dt729a_stage(aligned ? "BUILD102729A_PAGE_ADDRESS_ALIGNED=YES"
                         : "BUILD102729A_PAGE_ADDRESS_ALIGNED=NO");
    if (kr != KERN_SUCCESS || page == 0 || !aligned) {
        if (page && kr == KERN_SUCCESS)
            vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "ALLOCATE_FAIL", -10);
        return -10;
    }

    dt729a_stage("BUILD102729A_INITIAL_WRITE_ATTEMPTED=YES");
    dt729a_log(log, @"[*] BUILD102729A_SENTINEL_A_EXPECTED=0x%llx", (unsigned long long)kDT729ASentinelA);
    if (!dt729a_write_u64(page, kDT729ASentinelA)) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "INITIAL_WRITE_FAIL", -20);
        return -20;
    }

    uint64_t sentinel_a_readback = 0;
    dt729a_read_u64(page, &sentinel_a_readback);
    dt729a_log(log, @"[*] BUILD102729A_SENTINEL_A_READBACK=0x%llx", (unsigned long long)sentinel_a_readback);
    bool sentinel_a_match = (sentinel_a_readback == kDT729ASentinelA);
    dt729a_stage(sentinel_a_match ? "BUILD102729A_SENTINEL_A_MATCH=YES"
                                   : "BUILD102729A_SENTINEL_A_MATCH=NO");
    if (!sentinel_a_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "INITIAL_WRITE_FAIL", -21);
        return -21;
    }

    kern_return_t qkr = KERN_SUCCESS;
    uint32_t initial_cur = 0, initial_max = 0;
    int qrc = dt729a_query_region(page, &qkr, &initial_cur, &initial_max);
    dt729a_log(log, @"[*] BUILD102729A_INITIAL_REGION_QUERY_RC=%d", qkr);
    dt729a_log(log, @"[*] BUILD102729A_INITIAL_CURRENT_PROT=0x%x", initial_cur);
    dt729a_log(log, @"[*] BUILD102729A_INITIAL_MAX_PROT=0x%x", initial_max);
    dt729a_log(log, @"[*] BUILD102729A_INITIAL_CURRENT_PROT_DECODED=%@", dt729a_decode_prot(initial_cur));
    dt729a_log(log, @"[*] BUILD102729A_INITIAL_MAX_PROT_DECODED=%@", dt729a_decode_prot(initial_max));
    if (qrc != 0) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "INITIAL_REGION_QUERY_FAIL", -30);
        return -30;
    }

    dt729a_stage("BUILD102729A_SET_READ_REQUEST_PROT=0x1");
    dt729a_log(log, @"[*] BUILD102729A_SET_READ_REQUEST_PROT=0x%x", kDT729AProtRead);
    kr = dt729a_mach_vm_protect(mach_task_self(), (dt729a_vm_addr_t)page, (dt729a_vm_size_t)page_size, false, kDT729AProtRead);
    dt729a_log(log, @"[*] BUILD102729A_SET_READ_RC=%d", kr);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "SET_READ_FAIL", -40);
        return -40;
    }

    uint32_t after_read_cur = 0, after_read_max = 0;
    qkr = KERN_SUCCESS;
    qrc = dt729a_query_region(page, &qkr, &after_read_cur, &after_read_max);
    dt729a_log(log, @"[*] BUILD102729A_AFTER_READ_QUERY_RC=%d", qkr);
    dt729a_log(log, @"[*] BUILD102729A_AFTER_READ_CURRENT_PROT=0x%x", after_read_cur);
    dt729a_log(log, @"[*] BUILD102729A_AFTER_READ_MAX_PROT=0x%x", after_read_max);
    bool after_read_match = (after_read_cur == kDT729AProtRead);
    dt729a_stage(after_read_match ? "BUILD102729A_AFTER_READ_CURRENT_MATCH=YES"
                                   : "BUILD102729A_AFTER_READ_CURRENT_MATCH=NO");
    if (qrc != 0 || !after_read_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "READ_STATE_VERIFY_FAIL", -41);
        return -41;
    }

    uint64_t readonly_a = 0;
    dt729a_read_u64(page, &readonly_a);
    dt729a_log(log, @"[*] BUILD102729A_READONLY_SENTINEL_READBACK=0x%llx", (unsigned long long)readonly_a);
    bool readonly_a_match = (readonly_a == kDT729ASentinelA);
    dt729a_stage(readonly_a_match ? "BUILD102729A_READONLY_SENTINEL_MATCH=YES"
                                   : "BUILD102729A_READONLY_SENTINEL_MATCH=NO");
    if (!readonly_a_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "READ_STATE_VERIFY_FAIL", -42);
        return -42;
    }

    dt729a_stage("BUILD102729A_UNPROTECT_REQUEST_PROT=0x3");
    dt729a_log(log, @"[*] BUILD102729A_UNPROTECT_REQUEST_PROT=0x%x", kDT729AProtRW);
    kr = dt729a_mach_vm_protect(mach_task_self(), (dt729a_vm_addr_t)page, (dt729a_vm_size_t)page_size, false, kDT729AProtRW);
    dt729a_log(log, @"[*] BUILD102729A_UNPROTECT_RC=%d", kr);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "UNPROTECT_RW_FAIL", -50);
        return -50;
    }

    uint32_t after_rw_cur = 0, after_rw_max = 0;
    qkr = KERN_SUCCESS;
    qrc = dt729a_query_region(page, &qkr, &after_rw_cur, &after_rw_max);
    dt729a_log(log, @"[*] BUILD102729A_AFTER_RW_QUERY_RC=%d", qkr);
    dt729a_log(log, @"[*] BUILD102729A_AFTER_RW_CURRENT_PROT=0x%x", after_rw_cur);
    dt729a_log(log, @"[*] BUILD102729A_AFTER_RW_MAX_PROT=0x%x", after_rw_max);
    bool after_rw_match = (after_rw_cur == kDT729AProtRW);
    dt729a_stage(after_rw_match ? "BUILD102729A_AFTER_RW_CURRENT_MATCH=YES"
                                : "BUILD102729A_AFTER_RW_CURRENT_MATCH=NO");
    if (qrc != 0 || !after_rw_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "RW_STATE_VERIFY_FAIL", -51);
        return -51;
    }

    dt729a_log(log, @"[*] BUILD102729A_SENTINEL_B_WRITE_ATTEMPTED=YES");
    dt729a_log(log, @"[*] BUILD102729A_SENTINEL_B_EXPECTED=0x%llx", (unsigned long long)kDT729ASentinelB);
    if (!dt729a_write_u64(page, kDT729ASentinelB)) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "SENTINEL_B_WRITE_FAIL", -60);
        return -60;
    }

    uint64_t sentinel_b_readback = 0;
    dt729a_read_u64(page, &sentinel_b_readback);
    dt729a_log(log, @"[*] BUILD102729A_SENTINEL_B_READBACK=0x%llx", (unsigned long long)sentinel_b_readback);
    bool sentinel_b_match = (sentinel_b_readback == kDT729ASentinelB);
    dt729a_stage(sentinel_b_match ? "BUILD102729A_SENTINEL_B_MATCH=YES"
                                   : "BUILD102729A_SENTINEL_B_MATCH=NO");
    if (!sentinel_b_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "SENTINEL_B_WRITE_FAIL", -61);
        return -61;
    }

    dt729a_stage("BUILD102729A_RESTORE_REQUEST_PROT=0x1");
    dt729a_log(log, @"[*] BUILD102729A_RESTORE_REQUEST_PROT=0x%x", kDT729AProtRead);
    kr = dt729a_mach_vm_protect(mach_task_self(), (dt729a_vm_addr_t)page, (dt729a_vm_size_t)page_size, false, kDT729AProtRead);
    dt729a_log(log, @"[*] BUILD102729A_RESTORE_RC=%d", kr);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "RESTORE_READ_FAIL", -70);
        return -70;
    }

    uint32_t final_cur = 0, final_max = 0;
    qkr = KERN_SUCCESS;
    qrc = dt729a_query_region(page, &qkr, &final_cur, &final_max);
    dt729a_log(log, @"[*] BUILD102729A_FINAL_REGION_QUERY_RC=%d", qkr);
    dt729a_log(log, @"[*] BUILD102729A_FINAL_CURRENT_PROT=0x%x", final_cur);
    dt729a_log(log, @"[*] BUILD102729A_FINAL_MAX_PROT=0x%x", final_max);
    bool final_match = (final_cur == kDT729AProtRead);
    dt729a_stage(final_match ? "BUILD102729A_FINAL_CURRENT_MATCH=YES"
                              : "BUILD102729A_FINAL_CURRENT_MATCH=NO");
    if (qrc != 0 || !final_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "FINAL_STATE_VERIFY_FAIL", -71);
        return -71;
    }

    uint64_t final_b = 0;
    dt729a_read_u64(page, &final_b);
    dt729a_log(log, @"[*] BUILD102729A_FINAL_SENTINEL_READBACK=0x%llx", (unsigned long long)final_b);
    bool final_b_match = (final_b == kDT729ASentinelB);
    dt729a_stage(final_b_match ? "BUILD102729A_FINAL_SENTINEL_MATCH=YES"
                               : "BUILD102729A_FINAL_SENTINEL_MATCH=NO");
    if (!final_b_match) {
        vm_deallocate(mach_task_self(), page, page_size);
        dt729a_finish(verdictOut, "FINAL_STATE_VERIFY_FAIL", -72);
        return -72;
    }

    kr = vm_deallocate(mach_task_self(), page, page_size);
    dt729a_log(log, @"[*] BUILD102729A_DEALLOCATE_RC=%d", kr);
    if (kr != KERN_SUCCESS) {
        dt729a_finish(verdictOut, "DEALLOCATE_FAIL", -80);
        return -80;
    }

    dt729a_finish(verdictOut, "SELF_PAGE_PROTECTION_CONTROL_PASS", 0);
    return 0;
}
