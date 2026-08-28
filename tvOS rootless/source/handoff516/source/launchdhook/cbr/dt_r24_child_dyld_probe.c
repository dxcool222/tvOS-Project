#include "dt_r24_child_dyld_probe.h"

#include "dt_runtime_trace.h"
#include "envbuf.h"

#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DT_R24_RUNTIME_PROBE_ENV "R24_RUNTIME_PROBE"
#define DT_R24_CONTROLLED_TRUE_PATH "/var/jb/usr/bin/true"
#define DT_R24_XPCPROXY_PATH "/usr/libexec/xpcproxy"

#define DT_R24_MERGED_DYLD_UUID_STR "444F5041-5456-3136-3500-0AF299CDDA68"
#define DT_R24_STOCK_DYLD_UUID_STR "7C25AD4D-2C32-3AE3-A52C-0AF299CDDA68"

static const uint8_t kMergedDyldUUID[16] = {
	0x44, 0x4f, 0x50, 0x41, 0x54, 0x56, 0x31, 0x36,
	0x35, 0x00, 0x0a, 0xf2, 0x99, 0xcd, 0xda, 0x68
};
static const uint8_t kStockDyldUUID[16] = {
	0x7c, 0x25, 0xad, 0x4d, 0x2c, 0x32, 0x3a, 0xe3,
	0xa5, 0x2c, 0x0a, 0xf2, 0x99, 0xcd, 0xda, 0x68
};

enum {
	kProbeMaxAttempts = 40,
	kProbeRetryUs = 5000,
	kProbeHeaderBufSize = 8192,
};

static void dt_r24_child_dyld_probe_emit(const char *stage, pid_t pid, const char *spawn_path,
                                         int rc, int error_number, const char *uuid_str)
{
	char detail[512];
	snprintf(detail, sizeof(detail), "pid=%d path=%s uuid=%s",
	    (int)pid, spawn_path ? spawn_path : "(null)", uuid_str ? uuid_str : "-");
	os_log(OS_LOG_DEFAULT, "STAGE %{public}s %{public}s", stage, detail);
	(void)dt_r24_trace_event("CHILD_DYLD_PROBE", stage, rc, error_number, detail);
}

static void dt_r24_uuid_to_string(const uint8_t uuid[16], char out[37])
{
	snprintf(out, 37,
	    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
	    uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
	    uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int dt_r24_extract_lc_uuid_from_header(const struct mach_header_64 *header,
					      size_t header_size, uint8_t uuid_out[16])
{
	if (!header || header_size < sizeof(*header))
		return -1;
	if (header->magic != MH_MAGIC_64)
		return -2;

	const uint8_t *cursor = (const uint8_t *)header + sizeof(*header);
	const uint8_t *end = (const uint8_t *)header + header_size;
	for (uint32_t i = 0; i < header->ncmds; i++) {
		if ((size_t)(end - cursor) < sizeof(struct load_command))
			return -3;
		const struct load_command *lc = (const struct load_command *)cursor;
		if (lc->cmdsize < sizeof(*lc) || (size_t)(end - cursor) < lc->cmdsize)
			return -4;
		if (lc->cmd == LC_UUID) {
			if (lc->cmdsize < sizeof(struct uuid_command))
				return -5;
			const struct uuid_command *uc = (const struct uuid_command *)lc;
			memcpy(uuid_out, uc->uuid, 16);
			return 0;
		}
		cursor += lc->cmdsize;
	}
	return -6;
}

static int dt_r24_read_remote_dyld_uuid(task_t task, uint8_t uuid_out[16])
{
	task_dyld_info_data_t dyld_info = {0};
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
	if (kr != KERN_SUCCESS)
		return -10;

	if (dyld_info.all_image_info_addr == 0)
		return -11;

	struct dyld_all_image_infos infos = {0};
	vm_size_t read_size = 0;
	kr = vm_read_overwrite(task, dyld_info.all_image_info_addr, sizeof(infos),
	    (vm_address_t)&infos, &read_size);
	if (kr != KERN_SUCCESS || read_size < sizeof(infos))
		return -12;

	vm_address_t dyld_load_address = (vm_address_t)(uintptr_t)infos.dyldImageLoadAddress;
	if (dyld_load_address == 0)
		return -13;

	uint8_t header_buf[kProbeHeaderBufSize];
	read_size = 0;
	kr = vm_read_overwrite(task, dyld_load_address, sizeof(header_buf),
	    (vm_address_t)header_buf, &read_size);
	if (kr != KERN_SUCCESS || read_size < sizeof(struct mach_header_64))
		return -14;

	return dt_r24_extract_lc_uuid_from_header((const struct mach_header_64 *)header_buf,
	    read_size, uuid_out);
}

static void dt_r24_child_dyld_probe_worker(pid_t pid, char *spawn_path)
{
	char uuid_str[37] = {0};
	uint8_t uuid[16] = {0};
	int last_not_ready = 0;

	for (int attempt = 0; attempt < kProbeMaxAttempts; attempt++) {
		task_t task = MACH_PORT_NULL;
		kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
		if (kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
			dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=TASK_ACCESS_FAILED",
			    pid, spawn_path, (int)kr, 0, NULL);
			free(spawn_path);
			return;
		}

		int read_rc = dt_r24_read_remote_dyld_uuid(task, uuid);
		mach_port_deallocate(mach_task_self(), task);

		if (read_rc == -11 || read_rc == -13) {
			last_not_ready = read_rc;
			usleep(kProbeRetryUs);
			continue;
		}
		if (read_rc != 0) {
			dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=REMOTE_READ_FAILED",
			    pid, spawn_path, read_rc, 0, NULL);
			free(spawn_path);
			return;
		}

		dt_r24_uuid_to_string(uuid, uuid_str);
		if (memcmp(uuid, kMergedDyldUUID, 16) == 0) {
			dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=MERGED_DYLD_CONFIRMED",
			    pid, spawn_path, 0, 0, uuid_str);
			free(spawn_path);
			return;
		}
		if (memcmp(uuid, kStockDyldUUID, 16) == 0) {
			dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=STOCK_DYLD_CONFIRMED",
			    pid, spawn_path, 0, 0, uuid_str);
			free(spawn_path);
			return;
		}

		dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=UNKNOWN_DYLD_UUID",
		    pid, spawn_path, 0, 0, uuid_str);
		free(spawn_path);
		return;
	}

	if (last_not_ready != 0) {
		dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=DYLD_INFO_NOT_READY",
		    pid, spawn_path, last_not_ready, 0, NULL);
	} else {
		dt_r24_child_dyld_probe_emit("R24_CHILD_DYLD_PROBE=REMOTE_READ_FAILED",
		    pid, spawn_path, -1, 0, NULL);
	}
	free(spawn_path);
}

static bool dt_r24_probe_target_spawn(const char *spawn_path, char *const envp[])
{
	if (!spawn_path)
		return false;

	if (!strcmp(spawn_path, DT_R24_XPCPROXY_PATH))
		return true;

	const char *probe_env = envbuf_getenv((const char **)envp, DT_R24_RUNTIME_PROBE_ENV);
	if (probe_env && !strcmp(probe_env, "1"))
		return true;

	char canonical_true[PATH_MAX];
	if (realpath(DT_R24_CONTROLLED_TRUE_PATH, canonical_true) == NULL)
		return false;
	return !strcmp(spawn_path, canonical_true);
}

void dt_r24_schedule_child_dyld_uuid_probe(pid_t child_pid, const char *spawn_path,
                                           char *const envp[])
{
	if (getpid() != 1)
		return;
	if (child_pid <= 1 || !spawn_path)
		return;
	if (!dt_r24_probe_target_spawn(spawn_path, envp))
		return;

	char *path_copy = strdup(spawn_path);
	if (!path_copy)
		return;

	pid_t pid_copy = child_pid;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
		dt_r24_child_dyld_probe_worker(pid_copy, path_copy);
	});
}
