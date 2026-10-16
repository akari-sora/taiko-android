// Self-authored public guest: all external calls use real ELF relocation slots.
.text
.macro IMPORT slot
    adrp x8,0x8000
    ldr x9,[x8,#(\slot * 8)]
    blr x9
.endm
.macro BEGIN name,bytes=16
.global \name
.type \name,%function
\name:
    stp x29,x30,[sp,#-\bytes]!
    mov x29,sp
.endm
.macro END name,bytes=16
    ldp x29,x30,[sp],#\bytes
    ret
.size \name,.-\name
.endm
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b applet_parameters
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40,0x9000-0x40,0xa000-0x40,0,0,0x8300-0x40

.org 0x100
// x0 op-enable, x1 perf-enable, x2 resume-enable, x3 focus-mode,
// x4 performance-mode, x5 performance-configuration. Bool high bits preserved.
BEGIN applet_setup,64
    stp x0,x1,[sp,#16]
    stp x2,x3,[sp,#32]
    stp x4,x5,[sp,#48]
    IMPORT 0
    IMPORT 1
    IMPORT 2
    IMPORT 3
    ldp x0,x1,[sp,#48]
    IMPORT 6
    ldr x0,[sp,#40]
    IMPORT 8
    ldr x0,[sp,#32]
    IMPORT 10
    ldr x0,[sp,#16]
    IMPORT 11
    ldr x0,[sp,#24]
    IMPORT 12
    mov x0,#0x1ff
END applet_setup,64

// Query results live in exported owned RW applet_query_result, not host storage.
BEGIN applet_query,48
    IMPORT 4
    str x0,[sp,#16]
    IMPORT 5
    str x0,[sp,#24]
    IMPORT 7
    str x0,[sp,#32]
    IMPORT 13
    adrp x8,0x8000
    str x0,[x8,#0x518]
    ldp x0,x1,[sp,#16]
    str x0,[x8,#0x500]
    str x1,[x8,#0x508]
    ldr x0,[sp,#32]
    str x0,[x8,#0x510]
    // Host output uses a local stack buffer; imported ABI never gets GOT data.
    sub sp,sp,#16
    mov x0,sp
    IMPORT 14
    ldp x0,x1,[sp]
    add sp,sp,#16
    adrp x8,0x8000
    str x0,[x8,#0x520]
    str x1,[x8,#0x528]
    mov x0,#0x3e00
    str x0,[x8,#0x530]
END applet_query,48

// Four cross-module calls exercise all existing canonical main PARAM sites.
BEGIN applet_parameters,48
    IMPORT 15
    str x0,[sp,#16]
    mov x0,#0
    IMPORT 16
    ldr x1,[sp,#16]
    sub x0,x0,x1
    sub x0,x0,#3
    str x0,[sp,#24]
    IMPORT 17
    str x0,[sp,#32]
    IMPORT 18
    adrp x8,0x8000
    str x0,[x8,#0x598]
    ldp x0,x1,[sp,#16]
    str x0,[x8,#0x580]
    str x1,[x8,#0x588]
    ldr x0,[sp,#32]
    str x0,[x8,#0x590]
    mov x0,#0
END applet_parameters,48

// x0 low32 poison. Read PARAM immediately after EACH pop, success or empty.
BEGIN applet_pop,32
    str w0,[sp,#20]
    add x0,sp,#20
    IMPORT 9
    str w0,[sp,#16]
    bl applet_parameters
    adrp x8,0x8000
    ldp w0,w1,[sp,#16]
    str w0,[x8,#0x540]
    str w1,[x8,#0x544]
    ldr x0,[x8,#0x580]
    ldr x1,[x8,#0x588]
    str x0,[x8,#0x548]
    str x1,[x8,#0x550]
    ldr x0,[x8,#0x590]
    ldr x1,[x8,#0x598]
    str x0,[x8,#0x558]
    str x1,[x8,#0x560]
    ldr w0,[sp,#16]
END applet_pop,32

// Actual kernel SVC wrappers. Create returns Result in x0 and handle in x1.
// x0=entry x1=argument x2=supplied kernel-owned stack top.
.global applet_sdk_create
.type applet_sdk_create,%function
applet_sdk_create:
    mov x3,x2
    mov x2,x1
    mov x1,x0
    mov w4,#32
    mov w5,#0
    svc #8
    adrp x8,0x8000
    str x0,[x8,#0x5c0]
    str x1,[x8,#0x5c8]
    ret
.size applet_sdk_create,.-applet_sdk_create
.global applet_sdk_start
.type applet_sdk_start,%function
applet_sdk_start:
    svc #9
    ret
.size applet_sdk_start,.-applet_sdk_start
BEGIN applet_sdk_wait,32
    str w0,[sp,#16]
    add x1,sp,#16
    mov w2,#1
    mov x3,#-1
    svc #0x18
END applet_sdk_wait,32
.global applet_sdk_close
.type applet_sdk_close,%function
applet_sdk_close:
    svc #0x16
    ret
.size applet_sdk_close,.-applet_sdk_close

// x0=context: >=80 writable owned bytes, event handle@64. Results staged on
// actual SDK local stack and copied by the checked-copy host ABI at slot19.
BEGIN applet_sdk_entry,112
    str x19,[sp,#16]
    mov x19,x0
    IMPORT 15
    str x0,[sp,#32]
    mov x0,#0
    IMPORT 16
    ldr x1,[sp,#32]
    sub x0,x0,x1
    sub x0,x0,#3
    str x0,[sp,#40]
    IMPORT 17
    str x0,[sp,#48]
    IMPORT 18
    str x0,[sp,#56]
    add x0,sp,#32
    str x0,[sp,#64]
    mov x0,#0xbeef
    movk x0,#0xfeed,lsl #16
    str x0,[sp,#72]
    str xzr,[sp,#80]
    mov x0,#1
    str x0,[sp,#88]
    add x0,sp,#32
    mov x1,x19
    mov x2,#64
    IMPORT 19
    // Wait exactly once using a real event. The orchestrator always releases it.
    ldr w0,[x19,#64]
    str w0,[sp,#96]
    add x1,sp,#96
    mov w2,#1
    mov x3,#-1
    svc #0x18
    str x0,[sp,#80]
    mov x0,#2
    str x0,[sp,#88]
    add x0,sp,#32
    mov x1,x19
    mov x2,#64
    IMPORT 19
    svc #0x0a
    // The kernel adapter rejects an entry that returns without explicit Exit.
    ldr x19,[sp,#16]
END applet_sdk_entry,112

.global fixture_init
.type fixture_init,%function
fixture_init:
    ret
.size fixture_init,.-fixture_init
.org 0xffc
.word 0
