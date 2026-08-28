// BUILD102631 — minimal tvOS arm64 probe: exit(0) only, no libc, no dylibs.
    .globl _main
    .align 4
_main:
    mov     x0, #0
    mov     x16, #1          // SYS_exit
    svc     #0x80
