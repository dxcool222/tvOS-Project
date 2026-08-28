#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <fcntl.h>
#include <libjailbreak/jbclient_mach.h>

#include "dyld.h"
#include "dyld_jbinfo.h"

__attribute__((section("__DATA,__jbinfo"))) static char jbinfoSection[0x4000];
#define jbInfo ((struct dyld_jbinfo *)&jbinfoSection[0])

extern ssize_t dt_dyldhook_raw_write(int, const void *, size_t);

static void dt_early_trace(const char *line)
{
	if (!line) return;
	(void)dt_dyldhook_raw_write(STDERR_FILENO, line, strlen(line));
	(void)dt_dyldhook_raw_write(STDERR_FILENO, "\n", 1);
}

bool gDyldhookInitDone = false;

bool jbinfo_is_checked_in(void) { return jbInfo->state == DYLD_STATE_CHECKED_IN; }
char *jbinfo_get_jbroot(void) { return jbInfo->jbRootPath; }

static void consume_tokenized_sandbox_extensions(char *extensions)
{
	if (!extensions || extensions[0] == '\0') return;
	char *it = extensions;
	char *last = extensions;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

static int dyldhook_perform_checkin(void)
{
	struct jbserver_mach_msg_checkin_reply *replyPtr;
	char *root = &jbInfo->data[0];
	char *boot = &jbInfo->data[sizeof(replyPtr->jbRootPath)];
	char *extensions = &jbInfo->data[sizeof(replyPtr->jbRootPath) + sizeof(replyPtr->bootUUID)];
	int rc = jbclient_mach_process_checkin(root, boot, extensions, &jbInfo->fullyDebugged);
	if (rc != 0) return rc;
	consume_tokenized_sandbox_extensions(extensions);
	jbInfo->jbRootPath = root;
	jbInfo->bootUUID = boot;
	jbInfo->sandboxExtensions = extensions;
	jbInfo->state = DYLD_STATE_CHECKED_IN;
	return 0;
}

void dyldhook_init(uintptr_t kernelParams)
{
	if (getpid() == 1) return;
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	char **envp = (char **)(kernelParams + sizeof(void *) + sizeof(argc)
	    + (sizeof(const char *) * argc) + sizeof(void *));
	const char *insert = _simple_getenv(envp, "DYLD_INSERT_LIBRARIES");
	if (!insert || !strstr(insert, "/systemhook.dylib")) return;

	dt_early_trace("R24_DYLDHOOK_CHECKIN_BEGIN");
	int rc = dyldhook_perform_checkin();
	if (rc == 0)
		dt_early_trace("R24_DYLDHOOK_CHECKIN_PASS");
	else
		dt_early_trace("R24_DYLDHOOK_CHECKIN_FAIL");
	gDyldhookInitDone = true;
}
