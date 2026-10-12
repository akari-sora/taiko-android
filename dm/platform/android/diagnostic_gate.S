// Synthetic ELF/AAPCS64 fixture, deliberately independent of the Apple dm_gate.
.text
.p2align 2
.global d2r_diagnostic_gate
.type d2r_diagnostic_gate, %function
d2r_diagnostic_gate:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x18, [sp, #16]
    bl d2r_diagnostic_host_call
    ldr x9, [sp, #16]
    cmp x9, x18
    b.eq 1f
    mov x0, #-1
1:  ldp x29, x30, [sp], #32
    ret
.size d2r_diagnostic_gate, .-d2r_diagnostic_gate

.p2align 2
.global d2r_diagnostic_illegal
.type d2r_diagnostic_illegal, %function
d2r_diagnostic_illegal:
    .inst 0x00000000
    ret
.size d2r_diagnostic_illegal, .-d2r_diagnostic_illegal
.section .note.GNU-stack,"",%progbits
