/*
 * Extracted from Dopamine BaseBin/libjailbreak/src/util.c (proc_allow_all_syscalls, killall only).
 * REFERENCE_SOURCE: util.c — avoids linking full util.c (libarchive/IOKit deps).
 */
#include "util.h"
#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

static int kwrite1_bits(uint64_t startPtr, uint32_t bitCount)
{
	uint32_t byteSize = (uint32_t)ceil((float)bitCount / 8.0f);
	uint8_t buf[byteSize];

	for (uint32_t i = 0; i < bitCount; i += 8) {
		uint32_t rem = (bitCount - i);
		if (rem < 8) {
			for (int y = 0; y < (int)rem; y++) {
				buf[i / 8] |= (1 << y);
			}
		} else {
			buf[i / 8] = 0xff;
		}
	}

	return kwritebuf(startPtr, buf, byteSize);
}

void proc_allow_all_syscalls(uint64_t proc)
{
	if (!gSystemInfo.kernelStruct.proc_ro.exists) return;
	uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));

	uint64_t bsdFilter = kread_ptr(proc_ro + koffsetof(proc_ro, syscall_filter_mask));
	uint64_t machFilter = kread_ptr(proc_ro + koffsetof(proc_ro, mach_trap_filter_mask));
	uint64_t machKobjFilter = kread_ptr(proc_ro + koffsetof(proc_ro, mach_kobj_filter_mask));

	if (bsdFilter) {
		kwrite1_bits(bsdFilter, kconstant(nsysent));
	}
	if (machFilter) {
		kwrite1_bits(machFilter, kconstant(mach_trap_count));
	}
	if (machKobjFilter) {
		kwrite1_bits(machKobjFilter, kread64(ksymbol(mach_kobj_count)));
	}
}

void killall(const char *executablePath, int signal)
{
	static int maxArgumentSize = 0;
	if (maxArgumentSize == 0) {
		size_t size = sizeof(maxArgumentSize);
		if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
			maxArgumentSize = 4096;
		}
	}
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *info;
	size_t length;

	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
		return;
	if (!(info = malloc(length)))
		return;
	if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
		free(info);
		return;
	}
	int count = (int)(length / sizeof(struct kinfo_proc));
	for (int i = 0; i < count; i++) {
		pid_t pid = info[i].kp_proc.p_pid;
		if (pid == 0)
			continue;
		size_t size = (size_t)maxArgumentSize;
		char *buffer = (char *)malloc(size);
		if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
			char *cExecutablePath = buffer + sizeof(int);
			if (strcmp(cExecutablePath, executablePath) == 0) {
				kill(pid, signal);
			}
		}
		free(buffer);
	}
	free(info);
}

void proc_remove_msg_filter(uint64_t proc)
{
	if (__builtin_available(iOS 16.0, *)) {
		#define TFRO_FILTER_MSG 0x00004000

		if (koffsetof(proc_ro, t_flags_ro)) {
			uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
			uint32_t t_flags = kread32(proc_ro + koffsetof(proc_ro, t_flags_ro));
			kwrite32(proc_ro + koffsetof(proc_ro, t_flags_ro), t_flags & ~TFRO_FILTER_MSG);
		}
		else if (koffsetof(task, flags)) {
			uint64_t task = proc_task(proc);
			uint32_t t_flags = kread32(task + koffsetof(task, flags));
			kwrite32(task + koffsetof(task, flags), t_flags & ~TFRO_FILTER_MSG);
		}
	}
}
