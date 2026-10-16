// Existing full-frame harness seeds every GPR/SIMD register and status word.
// Allocate real guest storage before entering the SP-independent region.
.text
.global fixture
fixture:
    sub sp, sp, #64
    stp x0, x1, [sp]
    str x2, [sp, #16]
    add x0, sp, #32
    str x18, [x0]
    mov x2, #65535
retry:
    ldxr x18, [x0]
    stxr w1, x18, [x0]
    cbz w1, done
    sub x2, x2, #1
    cbnz x2, retry
done:
    ldp x0, x1, [sp]
    ldr x2, [sp, #16]
    add sp, sp, #64
    ret
