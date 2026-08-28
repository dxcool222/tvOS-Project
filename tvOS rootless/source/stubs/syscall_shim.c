#include "syscall_shim.h"
#include <stdarg.h>
#include <stdint.h>

int kfd_syscall(int number, ...)
{
    va_list ap;
    va_start(ap, number);

    register int64_t x0 __asm__("x0") = va_arg(ap, int64_t);
    register int64_t x1 __asm__("x1") = va_arg(ap, int64_t);
    register int64_t x2 __asm__("x2") = va_arg(ap, int64_t);
    register int64_t x3 __asm__("x3") = va_arg(ap, int64_t);
    register int64_t x4 __asm__("x4") = va_arg(ap, int64_t);
    register int64_t x5 __asm__("x5") = va_arg(ap, int64_t);
    register int64_t x16 __asm__("x16") = number;

    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
                     : "memory", "cc");

    va_end(ap);
    return (int)x0;
}
