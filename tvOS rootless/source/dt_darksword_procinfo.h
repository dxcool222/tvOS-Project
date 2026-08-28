#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

/*
 * proc_info / fileport socket oracle — XNU ABI (darwin-xnu bsd/sys/proc_info.h).
 * Layout verified by struct offsetof simulation for arm64:
 *   socket_fdinfo.pfi (24) + socket_info prefix (0xA0-0x18=0x88 from pfi end...)
 *   → psi.soi_proto.pri_in.insi_gencnt @ 0x110
 *
 * Kernel fill: bsd/kern/socket_info.c sets insi_gencnt = inp->inp_gencnt (PCB +0x78 on 20L563).
 */

#ifndef SYS_proc_info
#define SYS_proc_info 336
#endif

#define DT_DARKSWORD_PROC_INFO_CALL_PIDFILEPORTINFO 0x6
#define DT_DARKSWORD_PROC_PIDFILEPORTSOCKETINFO     3

#define DT_DARKSWORD_SOCKETINFO_INP_GENCNT_OFF 0x110

static inline uint64_t dt_darksword_socketinfo_inp_gencnt(const void *socketInfo)
{
    return *(const uint64_t *)((const uint8_t *)socketInfo + DT_DARKSWORD_SOCKETINFO_INP_GENCNT_OFF);
}
