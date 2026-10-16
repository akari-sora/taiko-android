// Android AAPCS64 entry wrappers. x18 is platform reserved; x8 carries sret.
#if defined(__ANDROID__)
    .text
    .p2align 2
    .globl nvn_unimpl_entry
    .hidden nvn_unimpl_entry
    .type nvn_unimpl_entry,%function
nvn_unimpl_entry:
    stp x29,x30,[sp,#-16]!
    mov x29,sp
    mov x3,x2
    mov x2,x1
    mov x1,x0
    mov x0,x16
    bl nvn_unimpl_c
    ldp x29,x30,[sp],#16
    ret
    .size nvn_unimpl_entry,.-nvn_unimpl_entry

    .globl nvn_prof_entry
    .hidden nvn_prof_entry
    .type nvn_prof_entry,%function
    .hidden nvn_slot
    .hidden nvn_real
    .hidden nvn_prof_ticks
nvn_prof_entry:
    sub sp,sp,#240
    stp x29,x30,[sp]
    mov x29,sp
    stp x0,x1,[sp,#16]
    stp x2,x3,[sp,#32]
    stp x4,x5,[sp,#48]
    stp x6,x7,[sp,#64]
    stp q0,q1,[sp,#96]
    stp q2,q3,[sp,#128]
    stp q4,q5,[sp,#160]
    stp q6,q7,[sp,#192]
    stp x8,x18,[sp,#224]
    adrp x9,nvn_slot
    add x9,x9,:lo12:nvn_slot
    sub x16,x16,x9
    lsr x16,x16,#4
    str x16,[sp,#80]
    bl nvn_core_profile_clock
    str x0,[sp,#88]
    ldr x16,[sp,#80]
    adrp x9,nvn_real
    add x9,x9,:lo12:nvn_real
    ldr x17,[x9,x16,lsl #3]
    ldp x0,x1,[sp,#16]
    ldp x2,x3,[sp,#32]
    ldp x4,x5,[sp,#48]
    ldp x6,x7,[sp,#64]
    ldp q0,q1,[sp,#96]
    ldp q2,q3,[sp,#128]
    ldp q4,q5,[sp,#160]
    ldp q6,q7,[sp,#192]
    ldp x8,x18,[sp,#224]
    blr x17
    stp x0,x1,[sp,#16]
    stp q0,q1,[sp,#96]
    stp q2,q3,[sp,#128]
    bl nvn_core_profile_clock
    ldr x10,[sp,#88]
    sub x9,x0,x10
    ldr x16,[sp,#80]
    adrp x10,nvn_prof_ticks
    add x10,x10,:lo12:nvn_prof_ticks
    add x10,x10,x16,lsl #3
.Lprofile_add:
    ldxr x11,[x10]
    add x11,x11,x9
    stxr w17,x11,[x10]
    cbnz w17,.Lprofile_add
    ldp x0,x1,[sp,#16]
    ldp q0,q1,[sp,#96]
    ldp q2,q3,[sp,#128]
    ldr x18,[sp,#232]
    ldp x29,x30,[sp]
    add sp,sp,#240
    ret
    .size nvn_prof_entry,.-nvn_prof_entry
    .section .note.GNU-stack,"",%progbits
#endif
