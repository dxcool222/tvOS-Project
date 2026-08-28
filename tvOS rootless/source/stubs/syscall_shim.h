#ifndef KFD_SYSCALL_SHIM_H
#define KFD_SYSCALL_SHIM_H

#include <sys/syscall.h>

int kfd_syscall(int number, ...);

#define syscall(number, ...) kfd_syscall((number), ##__VA_ARGS__)

#endif
