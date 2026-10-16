// Run via dm_android_test_guest_frame. Preserve every architectural register,
// flag and SP while exercising rewritten SP forms with live x16 and LR.
.text
.global fixture
fixture:
    sub sp, sp, #1024
    str x9, [sp, #768]
    str x10, [sp, #776]
    str x18, [sp, #800]
    str x18, [sp, #-16]!
    ldr x18, [sp], #16
    stp x16, x18, [sp, #-512]!
    ldp x16, x18, [sp], #496
    add sp, sp, #16
    stp x18, x30, [sp, #496]!
    ldp x18, x30, [sp], #16
    sub sp, sp, #512
    mov x18, sp
    mov w18, wsp
    add x18, sp, #16
    sub x18, sp, #16
    mov x18, #8
    add x10, sp, x18
    ldr x18, [sp, #800]
    ldr x9, [sp, #768]
    ldr x10, [sp, #776]
    add sp, sp, #1024
    ret
