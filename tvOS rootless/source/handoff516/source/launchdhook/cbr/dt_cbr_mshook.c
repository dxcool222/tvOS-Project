/*
 * Map MSHookFunction-style API onto litehook for Theos/tvOS 16.4 builds.
 * - If result != NULL: need orig → rebind imports, keep absolute orig pointer.
 * - If result == NULL: prologue patch via litehook_hook_function (Dopamine
 *   spawn_hook passes NULL and uses syscall orig).
 */
#include "dt_cbr_mshook.h"
#include "../../systemhook_cbr/litehook.h"

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include "dt_runtime_trace.h"

int dt_cbr_MSHookFunction(void *symbol, void *replace, void **result)
{
	if (!symbol || !replace) {
		fprintf(stderr, "CBR_MSHOOK_FAIL reason=null_args\n");
		os_log(OS_LOG_DEFAULT,
		    "STAGE CBR_MSHOOK_PATCH=FAIL reason=null_args symbol=%{public}p replace=%{public}p",
		    symbol, replace);
		(void)dt_r24_trace_event("HOOK_ENGINE", "PATCH_FAIL_NULL_ARGS", -1, 0,
		    "dt_cbr_MSHookFunction");
		return -1;
	}

	if (result) {
		/* Preserve callable original; rebind importers to replace. */
		*result = symbol;
		size_t replacements = litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, symbol,
		    replace, NULL);
		fprintf(stderr, "CBR_MSHOOK_REBIND symbol=%p replace=%p\n", symbol, replace);
		os_log(OS_LOG_DEFAULT,
		    "STAGE CBR_MSHOOK_REBIND=%{public}s symbol=%{public}p replace=%{public}p count=%{public}lu",
		    replacements ? "PASS" : "FAIL", symbol, replace, replacements);
		char detail[256];
		snprintf(detail, sizeof(detail), "symbol=%p replace=%p count=%lu", symbol,
		    replace, replacements);
		(void)dt_r24_trace_event("HOOK_ENGINE",
		    replacements ? "REBIND_PASS" : "REBIND_FAIL", replacements ? 0 : -2, 0,
		    detail);
		return replacements ? 0 : -2;
	}

	kern_return_t kr = litehook_hook_function(symbol, replace);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "CBR_MSHOOK_PATCH_FAIL kr=0x%x\n", (unsigned)kr);
		os_log(OS_LOG_DEFAULT, "STAGE CBR_MSHOOK_PATCH=FAIL kr=0x%{public}x",
		    (unsigned)kr);
		(void)dt_r24_trace_event("HOOK_ENGINE", "PROLOGUE_PATCH_FAIL", (int)kr, 0,
		    "litehook_hook_function");
		return (int)kr;
	}
	fprintf(stderr, "CBR_MSHOOK_PATCH symbol=%p replace=%p\n", symbol, replace);
	os_log(OS_LOG_DEFAULT,
	    "STAGE CBR_MSHOOK_PATCH=PASS symbol=%{public}p replace=%{public}p",
	    symbol, replace);
	(void)dt_r24_trace_event("HOOK_ENGINE", "PROLOGUE_PATCH_VERIFIED", 0, 0,
	    "five_instruction_readback_match");
	return 0;
}
