// Production ELF guest call boundary; no hardware x18 or TPIDR writes.
// Host frame: x19..x30 [0,96), q0..q31 [96,608), NZCV/FPSR/FPCR
// [608,632), original SP at632, GuestCallContext* at640; 656 aligned bytes.
.text
.p2align 2
.global dm_android_guest_invoke
.type dm_android_guest_invoke, %function
dm_android_guest_invoke:
    sub sp, sp, #656
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp q0, q1, [sp, #96]
    stp q2, q3, [sp, #128]
    stp q4, q5, [sp, #160]
    stp q6, q7, [sp, #192]
    stp q8, q9, [sp, #224]
    stp q10, q11, [sp, #256]
    stp q12, q13, [sp, #288]
    stp q14, q15, [sp, #320]
    stp q16, q17, [sp, #352]
    stp q18, q19, [sp, #384]
    stp q20, q21, [sp, #416]
    stp q22, q23, [sp, #448]
    stp q24, q25, [sp, #480]
    stp q26, q27, [sp, #512]
    stp q28, q29, [sp, #544]
    stp q30, q31, [sp, #576]
    mrs x9, nzcv
    str x9, [sp, #608]
    mrs x9, fpsr
    str x9, [sp, #616]
    mrs x9, fpcr
    str x9, [sp, #624]
    add x9, sp, #656
    str x9, [sp, #632]
    str x3, [sp, #640]
    mov x9, sp
    str x9, [x3] // context.host_frame
    mov x16, x0
    mov x17, x1
    mov sp, x2
    ldp x0, x1, [x17, #0]
    ldp x2, x3, [x17, #16]
    ldp x4, x5, [x17, #32]
    ldp x6, x7, [x17, #48]
    blr x16
    // Do not depend on guest callee-saved GPR values for finding the host stack.
    // This compiler-TLS accessor runs on the guest stack and preserves x18/TLS.
    sub sp, sp, #16
    str x0, [sp]
    bl dm_android_guest_active_call
    ldr x1, [sp]
    ldr x9, [x0]
    mov sp, x9
    ldr x9, [x0, #8] // context.result
    str x1, [x9]
    strb wzr, [x9, #8] // result.exited=false
    b .Lrestore_host
.size dm_android_guest_invoke, .-dm_android_guest_invoke

.p2align 2
.global dm_android_guest_leave
.type dm_android_guest_leave, %function
dm_android_guest_leave:
    // x0 is a validated saved host frame, x1 is the ExitThread value.
    mov sp, x0
    ldr x9, [sp, #640]
    ldr x9, [x9, #8]
    str x1, [x9]
    mov w10, #1
    strb w10, [x9, #8]
.Lrestore_host:
    ldr x9, [sp, #608]
    msr nzcv, x9
    ldr x9, [sp, #616]
    msr fpsr, x9
    ldr x9, [sp, #624]
    msr fpcr, x9
    ldp q0, q1, [sp, #96]
    ldp q2, q3, [sp, #128]
    ldp q4, q5, [sp, #160]
    ldp q6, q7, [sp, #192]
    ldp q8, q9, [sp, #224]
    ldp q10, q11, [sp, #256]
    ldp q12, q13, [sp, #288]
    ldp q14, q15, [sp, #320]
    ldp q16, q17, [sp, #352]
    ldp q18, q19, [sp, #384]
    ldp q20, q21, [sp, #416]
    ldp q22, q23, [sp, #448]
    ldp q24, q25, [sp, #480]
    ldp q26, q27, [sp, #512]
    ldp q28, q29, [sp, #544]
    ldp q30, q31, [sp, #576]
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    ldr x9, [sp, #632]
    mov sp, x9
    ret
.size dm_android_guest_leave, .-dm_android_guest_leave
.section .note.GNU-stack,"",%progbits
