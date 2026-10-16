// Self-authored bounded SP-addressing contract. Every negative-offset store is
// observed immediately, before another helper can reuse inactive stack space.
// uint64_t receipt[...]: alternating architectural value and signed SP delta.
.text
.global fixture
.macro record reg
    str \reg, [x20], #8
    mov x9, sp
    sub x9, x9, x19
    str x9, [x20], #8
.endm
fixture:
    sub sp, sp, #1024
    str x19, [sp, #896]
    str x20, [sp, #904]
    str x30, [sp, #912]
    mov x19, sp
    mov x20, x0
    mov x10, #0x9988
    movk x10, #0xffaa, lsl #16
    movk x10, #0x6655, lsl #32
    movk x10, #0x8877, lsl #48
    mov x18, x10

    stur x18, [sp, #-8]
    ldur x11, [sp, #-8]
    record x11
    stur x18, [sp, #-256]
    ldur x11, [sp, #-256]
    record x11
    str x18, [sp, #-16]!
    ldr x11, [sp]
    record x11
    add sp, sp, #16
    str x18, [sp], #16
    ldur x11, [sp, #-16]
    record x11
    sub sp, sp, #16
    str x18, [sp, #240]!
    ldr x11, [sp]
    record x11
    sub sp, sp, #240

    stp x18, x16, [sp, #-512]!
    ldr x11, [sp]
    record x11
    ldr x11, [sp, #8]
    eor x11, x11, x16
    record x11
    add sp, sp, #512
    stp x30, x18, [sp, #496]!
    ldr x11, [sp, #8]
    record x11
    ldr x11, [sp]
    sub x11, x11, x30
    record x11
    sub sp, sp, #496

    // Load first and second pair lanes with live x16/LR in the other lane.
    stp x10, x16, [sp, #-512]
    ldp x18, x16, [sp, #-512]!
    mov x11, x18
    record x11
    add sp, sp, #512
    stp x30, x10, [sp]
    ldp x30, x18, [sp], #496
    mov x11, x18
    record x11
    sub sp, sp, #496
    str x10, [sp, #-256]
    ldr x18, [sp, #-256]!
    mov x11, x18
    record x11
    add sp, sp, #256
    str x10, [sp]
    ldr x18, [sp], #240
    mov x11, x18
    record x11
    sub sp, sp, #240

    mov w12, #0x8001
    movk w12, #0x8000, lsl #16
    stp w12, w12, [sp, #-256]
    ldpsw x18, x16, [sp, #-256]!
    mov x11, x18
    record x11
    add sp, sp, #256
    stp w12, w12, [sp]
    ldpsw x16, x18, [sp], #240
    mov x11, x18
    record x11
    sub sp, sp, #240

    // Signed byte/halfword extension and W-destination zero extension.
    str w12, [sp, #64]
    ldrsb w18, [sp, #65]
    mov x11, x18
    record x11
    ldrsb x18, [sp, #65]
    mov x11, x18
    record x11
    ldrsh w18, [sp, #64]
    mov x11, x18
    record x11
    ldrsh x18, [sp, #64]
    mov x11, x18
    record x11
    ldrsw x18, [sp, #64]
    mov x11, x18
    record x11
    mov x18, x10
    strb w18, [sp, #80]
    ldrb w11, [sp, #80]
    record x11
    strh w18, [sp, #80]
    ldrh w11, [sp, #80]
    record x11
    mov x11, x18
    record x11

    // SP reads/aliases, extended-register reads, and condition flag results.
    mov x18, sp
    sub x11, x18, x19
    record x11
    mov w18, wsp
    mov w11, w19
    sub x11, x18, x11
    record x11
    add x18, sp, #32
    sub x11, x18, x19
    record x11
    sub x18, sp, #16
    sub x11, x18, x19
    record x11
    mov x18, #24
    add x11, sp, x18
    sub x11, x11, x19
    record x11
    add x18, sp, x18
    sub x11, x18, x19
    record x11
    adds x18, sp, #0
    mrs x11, nzcv
    record x11
    cmp sp, x18
    mrs x11, nzcv
    record x11
    mov x11, sp
    record x11

    // Return receipt count, retaining virtual x18 as the last SP-derived value.
    sub x0, x20, x0
    ldr x19, [sp, #896]
    ldr x20, [sp, #904]
    ldr x30, [sp, #912]
    add sp, sp, #1024
    ret
