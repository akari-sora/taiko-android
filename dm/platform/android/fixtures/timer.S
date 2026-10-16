// void(uint64_t out[6]): destination-specific timer results, retains caller x19..24.
.text
.global fixture
fixture:
    sub sp, sp, #64
    stp x19, x20, [sp]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x29, x30, [sp, #48]
    mov x24, x0
    mrs x19, cntpct_el0
    mrs x20, cntpct_el0
    mrs x21, cntpct_el0
    mrs x22, cntpct_el0
    mrs x23, cntpct_el0
    mrs x18, cntpct_el0
    stp x19, x20, [x24]
    stp x21, x22, [x24, #16]
    str x23, [x24, #32]
    str x18, [x24, #40]
    ldp x19, x20, [sp]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x29, x30, [sp, #48]
    add sp, sp, #64
    ret
