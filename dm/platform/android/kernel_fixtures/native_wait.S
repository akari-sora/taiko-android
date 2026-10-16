// Freely authored native busy-mutex and frame-preservation clients.
// No game program, SDK binary, or platform key is embedded here.
.text
.p2align 2
.global native_wait_mutex
.type native_wait_mutex,%function
native_wait_mutex:
    stp x22,x21,[sp,#-48]!
    stp x20,x19,[sp,#16]
    stp x29,x30,[sp,#32]
    add x29,sp,#32
    mrs x19,tpidrro_el0
    ldrh w8,[x19,#0x100]
    add x20,x0,#16
    prfm pstl1keep,[x20]
    add w21,w8,#1
    cbz w8,.Lzero_count
    mov w9,#1
    strh w21,[x19,#0x100]
.Lfirst_load:
    ldaxr w10,[x20]
    cbz w10,.Lfirst_store
.Lfirst_wait:
    strh w8,[x19,#0x100]
    wfe
    strh w21,[x19,#0x100]
    ldaxr w10,[x20]
    cbnz w10,.Lfirst_wait
.Lfirst_store:
    stxr w10,w9,[x20]
    cbz w10,.Lacquired
    strh w8,[x19,#0x100]
    strh w21,[x19,#0x100]
    ldaxr w10,[x20]
    cbnz w10,.Lfirst_wait
    b .Lfirst_store
.Lzero_count:
    mov w22,#1
    strh w21,[x19,#0x100]
    ldaxr w8,[x20]
    cbnz w8,.Lzero_check
    b .Lzero_store
.Lzero_wait:
    wfe
.Lzero_reload:
    strh w21,[x19,#0x100]
    ldaxr w8,[x20]
    cbz w8,.Lzero_store
.Lzero_check:
    strh wzr,[x19,#0x100]
    ldrh w8,[x19,#0x102]
    cbz w8,.Lzero_wait
    bl native_wait_svc36
    b .Lzero_wait
.Lzero_store:
    stxr w8,w22,[x20]
    cbz w8,.Lacquired
    strh wzr,[x19,#0x100]
    ldrh w8,[x19,#0x102]
    cbz w8,.Lzero_reload
    bl native_wait_svc36
    strh w21,[x19,#0x100]
    ldaxr w8,[x20]
    cbnz w8,.Lzero_check
    b .Lzero_store
.Lacquired:
    ldp x29,x30,[sp,#32]
    ldp x20,x19,[sp,#16]
    ldp x22,x21,[sp],#48
    ret
.size native_wait_mutex,.-native_wait_mutex

.global native_wait_svc36
.type native_wait_svc36,%function
native_wait_svc36:
    svc #0x36
    ret
.size native_wait_svc36,.-native_wait_svc36

.global native_wait_compact_mutex
.type native_wait_compact_mutex,%function
native_wait_compact_mutex:
    stp x22,x21,[sp,#-48]!
    stp x20,x19,[sp,#16]
    stp x29,x30,[sp,#32]
    add x29,sp,#32
    mrs x19,tpidrro_el0
    ldrh w8,[x19,#0x100]
    add x20,x0,#16
    prfm pstl1keep,[x20]
    add w21,w8,#1
    cbz w8,.Lc_zero_count
    mov w9,#1
    strh w21,[x19,#0x100]
.Lc_first_load:
    ldaxr w10,[x20]
    cbz w10,.Lc_first_store
.Lc_first_wait:
    strh w8,[x19,#0x100]
    wfe
    strh w21,[x19,#0x100]
    ldaxr w10,[x20]
    cbnz w10,.Lc_first_wait
.Lc_first_store:
    stxr w10,w9,[x20]
    cbz w10,.Lc_acquired
    strh w8,[x19,#0x100]
    strh w21,[x19,#0x100]
    ldaxr w10,[x20]
    cbnz w10,.Lc_first_wait
    b .Lc_first_store
.Lc_zero_count:
    mov w22,#1
    b .Lc_zero_reload
.Lc_zero_wait:
    wfe
.Lc_zero_reload:
    strh w21,[x19,#0x100]
    ldaxr w8,[x20]
    cbz w8,.Lc_zero_store
    strh wzr,[x19,#0x100]
    ldrh w8,[x19,#0x102]
    cbz w8,.Lc_zero_wait
    bl native_wait_svc36
    b .Lc_zero_wait
.Lc_zero_store:
    stxr w8,w22,[x20]
    cbz w8,.Lc_acquired
    strh wzr,[x19,#0x100]
    ldrh w8,[x19,#0x102]
    cbz w8,.Lc_zero_reload
    bl native_wait_svc36
    b .Lc_zero_reload
.Lc_acquired:
    ldp x29,x30,[sp,#32]
    ldp x20,x19,[sp,#16]
    ldp x22,x21,[sp],#48
    ret
.size native_wait_compact_mutex,.-native_wait_compact_mutex

.macro frame_begin frames
    stp x29,x30,[sp,#-224]!
    stp x19,x20,[sp,#16]
    stp x21,x22,[sp,#32]
    stp x23,x24,[sp,#48]
    stp x25,x26,[sp,#64]
    stp x27,x28,[sp,#80]
    stp q8,q9,[sp,#96]
    stp q10,q11,[sp,#128]
    stp q12,q13,[sp,#160]
    stp q14,q15,[sp,#192]
    mov x20,\frames
    add x21,x20,#800
    .irp reg,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,19,22,23,24,25,26,27,28,29,30
        mov x\reg,#(0x100+\reg)
    .endr
    movi v0.16b,#0
    movi v1.16b,#1
    movi v2.16b,#2
    movi v3.16b,#3
    movi v4.16b,#4
    movi v5.16b,#5
    movi v6.16b,#6
    movi v7.16b,#7
    movi v8.16b,#8
    movi v9.16b,#9
    movi v10.16b,#10
    movi v11.16b,#11
    movi v12.16b,#12
    movi v13.16b,#13
    movi v14.16b,#14
    movi v15.16b,#15
    movi v16.16b,#16
    movi v17.16b,#17
    movi v18.16b,#18
    movi v19.16b,#19
    movi v20.16b,#20
    movi v21.16b,#21
    movi v22.16b,#22
    movi v23.16b,#23
    movi v24.16b,#24
    movi v25.16b,#25
    movi v26.16b,#26
    movi v27.16b,#27
    movi v28.16b,#28
    movi v29.16b,#29
    movi v30.16b,#30
    movi v31.16b,#31
    mov x26,#0xb0000000
    msr nzcv,x26
.endm
.macro snapshot base
    stp x0,x1,[\base,#0]
    stp x2,x3,[\base,#16]
    stp x4,x5,[\base,#32]
    stp x6,x7,[\base,#48]
    stp x8,x9,[\base,#64]
    stp x10,x11,[\base,#80]
    stp x12,x13,[\base,#96]
    stp x14,x15,[\base,#112]
    stp x16,x17,[\base,#128]
    stp x18,x19,[\base,#144]
    stp x20,x21,[\base,#160]
    stp x22,x23,[\base,#176]
    stp x24,x25,[\base,#192]
    stp x26,x27,[\base,#208]
    stp x28,x29,[\base,#224]
    str x30,[\base,#240]
    mov x26,sp
    str x26,[\base,#248]
    stp q0,q1,[\base,#256]
    stp q2,q3,[\base,#288]
    stp q4,q5,[\base,#320]
    stp q6,q7,[\base,#352]
    stp q8,q9,[\base,#384]
    stp q10,q11,[\base,#416]
    stp q12,q13,[\base,#448]
    stp q14,q15,[\base,#480]
    stp q16,q17,[\base,#512]
    stp q18,q19,[\base,#544]
    stp q20,q21,[\base,#576]
    stp q22,q23,[\base,#608]
    stp q24,q25,[\base,#640]
    stp q26,q27,[\base,#672]
    stp q28,q29,[\base,#704]
    stp q30,q31,[\base,#736]
    mrs x26,nzcv
    str x26,[\base,#768]
    mrs x26,fpsr
    str x26,[\base,#776]
    mrs x26,fpcr
    str x26,[\base,#784]
    ldr x26,[\base,#208]
.endm
.macro frame_end
    ldp q8,q9,[sp,#96]
    ldp q10,q11,[sp,#128]
    ldp q12,q13,[sp,#160]
    ldp q14,q15,[sp,#192]
    ldp x19,x20,[sp,#16]
    ldp x21,x22,[sp,#32]
    ldp x23,x24,[sp,#48]
    ldp x25,x26,[sp,#64]
    ldp x27,x28,[sp,#80]
    ldp x29,x30,[sp],#224
    mov x0,#0
    ret
.endm

.global native_wait_entry
.type native_wait_entry,%function
native_wait_entry:
    // x0 points to the mutex, x1 to two owned 800-byte snapshots.
    frame_begin x1
    snapshot x20
    bl native_wait_mutex
    snapshot x21
    frame_end
.size native_wait_entry,.-native_wait_entry

.global native_wait_svc_frame_entry
.type native_wait_svc_frame_entry,%function
native_wait_svc_frame_entry:
    // Direct, normally lowered SVC36 with owned zero-flag TLR. No fake dispatcher.
    frame_begin x0
    mov x0,#0x100
    snapshot x20
    svc #0x36
    snapshot x21
    frame_end
.size native_wait_svc_frame_entry,.-native_wait_svc_frame_entry

.global native_wait_compact_entry
.type native_wait_compact_entry,%function
native_wait_compact_entry:
    // Same public snapshot ABI as native_wait_entry; compact 39-word source.
    frame_begin x1
    snapshot x20
    bl native_wait_compact_mutex
    snapshot x21
    frame_end
.size native_wait_compact_entry,.-native_wait_compact_entry
