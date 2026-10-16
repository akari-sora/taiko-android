// ELF/AAPCS64 guest boundaries. Host x18 is never written by these helpers.
.text
.p2align 2

// All offsets match DmGuestRegisterFrame in guest_abi.h.
.macro save_frame
    sub sp, sp, #800
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    str x30, [sp, #792]
    add x9, sp, #800
    str x9, [sp, #248]
    stp q0, q1, [sp, #256]
    stp q2, q3, [sp, #288]
    stp q4, q5, [sp, #320]
    stp q6, q7, [sp, #352]
    stp q8, q9, [sp, #384]
    stp q10, q11, [sp, #416]
    stp q12, q13, [sp, #448]
    stp q14, q15, [sp, #480]
    stp q16, q17, [sp, #512]
    stp q18, q19, [sp, #544]
    stp q20, q21, [sp, #576]
    stp q22, q23, [sp, #608]
    stp q24, q25, [sp, #640]
    stp q26, q27, [sp, #672]
    stp q28, q29, [sp, #704]
    stp q30, q31, [sp, #736]
    mrs x9, nzcv
    str x9, [sp, #768]
    mrs x9, fpsr
    str x9, [sp, #776]
    mrs x9, fpcr
    str x9, [sp, #784]
.endm

.macro restore_frame
    ldr x9, [sp, #768]
    msr nzcv, x9
    ldr x9, [sp, #776]
    msr fpsr, x9
    ldr x9, [sp, #784]
    msr fpcr, x9
    ldp q0, q1, [sp, #256]
    ldp q2, q3, [sp, #288]
    ldp q4, q5, [sp, #320]
    ldp q6, q7, [sp, #352]
    ldp q8, q9, [sp, #384]
    ldp q10, q11, [sp, #416]
    ldp q12, q13, [sp, #448]
    ldp q14, q15, [sp, #480]
    ldp q16, q17, [sp, #512]
    ldp q18, q19, [sp, #544]
    ldp q20, q21, [sp, #576]
    ldp q22, q23, [sp, #608]
    ldp q24, q25, [sp, #640]
    ldp q26, q27, [sp, #672]
    ldp q28, q29, [sp, #704]
    ldp q30, q31, [sp, #736]
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldr x19, [sp, #152]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
.endm

.global dm_android_state_accessor
.type dm_android_state_accessor, %function
dm_android_state_accessor:
    save_frame
    bl dm_android_current_guest_state
    str x0, [sp, #128] // The documented x16 result replaces the incoming x16.
    restore_frame
    ldr x30, [sp, #240]
    add sp, sp, #800
    ret
.size dm_android_state_accessor, .-dm_android_state_accessor

.p2align 2
.global dm_android_dispatch_gate
.type dm_android_dispatch_gate, %function
dm_android_dispatch_gate:
    save_frame
    // The stub's outer frame holds guest x29/x30, before BLR x30.
    ldr x9, [sp, #800]
    ldr x10, [sp, #808]
    str x9, [sp, #232]
    str x10, [sp, #240]
    add x9, sp, #816
    str x9, [sp, #248]
    mov x0, sp
    bl dm_android_dispatch_frame
    // The stub will restore requested x29/x30 after our host return.
    ldr x9, [sp, #232]
    ldr x10, [sp, #240]
    str x9, [sp, #800]
    str x10, [sp, #808]
    restore_frame
    ldr x30, [sp, #792]
    add sp, sp, #800
    ret
.size dm_android_dispatch_gate, .-dm_android_dispatch_gate
// Full-frame snapshot fixture runner; entry must return without changing guest SP.
// void dm_android_test_guest_frame(void (*entry)(), Frame* before, Frame* after);
.p2align 2
.global dm_android_test_guest_frame
.type dm_android_test_guest_frame, %function
dm_android_test_guest_frame:
    save_frame
    sub sp, sp, #32
    stp x0, x1, [sp, #0]
    str x2, [sp, #16]
    mov x9, #256
    fmov d0, x9
    mov x9, #512
    ins v0.d[1], x9
    mov x9, #257
    fmov d1, x9
    mov x9, #513
    ins v1.d[1], x9
    mov x9, #258
    fmov d2, x9
    mov x9, #514
    ins v2.d[1], x9
    mov x9, #259
    fmov d3, x9
    mov x9, #515
    ins v3.d[1], x9
    mov x9, #260
    fmov d4, x9
    mov x9, #516
    ins v4.d[1], x9
    mov x9, #261
    fmov d5, x9
    mov x9, #517
    ins v5.d[1], x9
    mov x9, #262
    fmov d6, x9
    mov x9, #518
    ins v6.d[1], x9
    mov x9, #263
    fmov d7, x9
    mov x9, #519
    ins v7.d[1], x9
    mov x9, #264
    fmov d8, x9
    mov x9, #520
    ins v8.d[1], x9
    mov x9, #265
    fmov d9, x9
    mov x9, #521
    ins v9.d[1], x9
    mov x9, #266
    fmov d10, x9
    mov x9, #522
    ins v10.d[1], x9
    mov x9, #267
    fmov d11, x9
    mov x9, #523
    ins v11.d[1], x9
    mov x9, #268
    fmov d12, x9
    mov x9, #524
    ins v12.d[1], x9
    mov x9, #269
    fmov d13, x9
    mov x9, #525
    ins v13.d[1], x9
    mov x9, #270
    fmov d14, x9
    mov x9, #526
    ins v14.d[1], x9
    mov x9, #271
    fmov d15, x9
    mov x9, #527
    ins v15.d[1], x9
    mov x9, #272
    fmov d16, x9
    mov x9, #528
    ins v16.d[1], x9
    mov x9, #273
    fmov d17, x9
    mov x9, #529
    ins v17.d[1], x9
    mov x9, #274
    fmov d18, x9
    mov x9, #530
    ins v18.d[1], x9
    mov x9, #275
    fmov d19, x9
    mov x9, #531
    ins v19.d[1], x9
    mov x9, #276
    fmov d20, x9
    mov x9, #532
    ins v20.d[1], x9
    mov x9, #277
    fmov d21, x9
    mov x9, #533
    ins v21.d[1], x9
    mov x9, #278
    fmov d22, x9
    mov x9, #534
    ins v22.d[1], x9
    mov x9, #279
    fmov d23, x9
    mov x9, #535
    ins v23.d[1], x9
    mov x9, #280
    fmov d24, x9
    mov x9, #536
    ins v24.d[1], x9
    mov x9, #281
    fmov d25, x9
    mov x9, #537
    ins v25.d[1], x9
    mov x9, #282
    fmov d26, x9
    mov x9, #538
    ins v26.d[1], x9
    mov x9, #283
    fmov d27, x9
    mov x9, #539
    ins v27.d[1], x9
    mov x9, #284
    fmov d28, x9
    mov x9, #540
    ins v28.d[1], x9
    mov x9, #285
    fmov d29, x9
    mov x9, #541
    ins v29.d[1], x9
    mov x9, #286
    fmov d30, x9
    mov x9, #542
    ins v30.d[1], x9
    mov x9, #287
    fmov d31, x9
    mov x9, #543
    ins v31.d[1], x9
    mov x0, #4096
    mov x1, #4097
    mov x2, #4098
    mov x3, #4099
    mov x4, #4100
    mov x5, #4101
    mov x6, #4102
    mov x7, #4103
    mov x8, #4104
    mov x9, #4105
    mov x10, #4106
    mov x11, #4107
    mov x12, #4108
    mov x13, #4109
    mov x14, #4110
    mov x15, #4111
    mov x17, #4113
    mov x19, #4115
    mov x20, #4116
    mov x21, #4117
    mov x22, #4118
    mov x23, #4119
    mov x24, #4120
    mov x25, #4121
    mov x26, #4122
    mov x27, #4123
    mov x28, #4124
    mov x29, #4125
    ldr x16, [sp, #0]
    adr x30, .Lguest_frame_return
    mov x9, #0xa0000000
    msr nzcv, x9
    mov x9, #0x08000000
    movk x9, #0x9f
    msr fpsr, x9
    mov x9, #0x00400000
    msr fpcr, x9
    mov x9, #0x1009
    save_frame
    mov x0, sp
    ldr x1, [sp, #808]
    mov x2, #50
.Lcopy_before:
    ldp x4, x5, [x0], #16
    stp x4, x5, [x1], #16
    subs x2, x2, #1
    b.ne .Lcopy_before
    restore_frame
    ldr x30, [sp, #240]
    add sp, sp, #800
    br x16
.Lguest_frame_return:
    save_frame
    mov x0, sp
    ldr x1, [sp, #816]
    mov x2, #50
.Lcopy_after:
    ldp x4, x5, [x0], #16
    stp x4, x5, [x1], #16
    subs x2, x2, #1
    b.ne .Lcopy_after
    add sp, sp, #832
    restore_frame
    ldr x30, [sp, #240]
    add sp, sp, #800
    ret
.size dm_android_test_guest_frame, .-dm_android_test_guest_frame
// Typed entries capture genuine incoming guest LR/SP before any C call.
// Their target must match the one-shot typed guarded-transfer receipt.
.p2align 2
.global dm_android_swkbd_entry
.type dm_android_swkbd_entry, %function
dm_android_swkbd_entry:
    mov x2, x30
    mov x3, sp
    b dm_android_swkbd_show_from_guest
.size dm_android_swkbd_entry, .-dm_android_swkbd_entry
.p2align 2
.global dm_android_character_isalpha_entry
.type dm_android_character_isalpha_entry, %function
dm_android_character_isalpha_entry:
    mov x1, x30
    mov x2, sp
    b dm_android_character_isalpha_from_guest
.size dm_android_character_isalpha_entry, .-dm_android_character_isalpha_entry
.section .note.GNU-stack,"",%progbits
