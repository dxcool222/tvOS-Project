.text
.align 4
.global _dt_dyldhook_raw_write
_dt_dyldhook_raw_write:
    mov x16, #4
    svc #0x80
    b.cc 1f
    mov x0, #-1
1:
    ret
