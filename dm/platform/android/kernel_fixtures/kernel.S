// Freely authored Horizon ABI client. No original game bytes or SDK binaries.
.text
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b kernel_memory_entry
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40, 0x9000-0x40, 0xa000-0x40, 0, 0, 0x8300-0x40
.org 0x100
.global fixture_init
.type fixture_init,%function
fixture_init:
    ret
.size fixture_init,.-fixture_init

.macro begin
    stp x29,x30,[sp,#-64]!
    stp x19,x20,[sp,#16]
    stp x21,x22,[sp,#32]
    stp x23,x24,[sp,#48]
    mov x29,sp
    adrp x19,0x8000
.endm
.macro end
    ldp x23,x24,[sp,#48]
    ldp x21,x22,[sp,#32]
    ldp x19,x20,[sp,#16]
    ldp x29,x30,[sp],#64
    ret
.endm
.macro host slot
    adrp x19,0x8000
    ldr x9,[x19,#\slot]
    blr x9
.endm

.global kernel_memory_entry
.type kernel_memory_entry,%function
kernel_memory_entry:
    begin
    mov x1,#0x200000
    svc #1
    cbnz x0,1f
    adrp x19,0x8000
    str x1,[x19,#0x100]
    mov x1,#14
    mov x2,#0
    mov x3,#0
    svc #0x29
    cbnz x0,1f
    adrp x19,0x8000
    str x1,[x19,#0x108]
    mov x0,x1
    ldr x1,[x19,#0x100]
    mov x2,#0x20000
    svc #4
    cbnz x0,1f
    add x0,x19,#0x200
    mov x1,#0
    ldr x2,[x19,#0x108]
    svc #6
1:  end
.size kernel_memory_entry,.-kernel_memory_entry

.global kernel_network_entry
.type kernel_network_entry,%function
kernel_network_entry:
    begin
    mov x0,#73
    host 0
    host 8
    adrp x19,0x8000
    str x0,[x19,#0x110]
    // Real offline HLE must report -1 and FreeBSD ENETDOWN (50).
    mov x0,#2
    mov x1,#1
    mov x2,#0
    host 16
    adrp x19,0x8000
    str x0,[x19,#0x118]
    host 8
    adrp x19,0x8000
    str x0,[x19,#0x120]
    mov x0,#73
    host 0
    mov x0,#0
    end
.size kernel_network_entry,.-kernel_network_entry

.global kernel_thread_entry
.type kernel_thread_entry,%function
kernel_thread_entry:
    begin
    svc #0x45
    cbnz x0,9f
    adrp x19,0x8000
    str w1,[x19,#0x130]
    adrp x19,0x8000
    str w2,[x19,#0x134]
    adr x1,kernel_child_entry
    mov x2,#0
    ldr x3,[x19,#0x108]
    add x3,x3,#0x20000
    mov x4,#44
    mov x5,#0
    svc #8
    cbnz x0,8f
    mov x20,x1
    adrp x19,0x8000
    str w20,[x19,#0x138]
    // CreateThread already owns this stack: unmap must fail while parked.
    ldr x0,[x19,#0x108]
    ldr x1,[x19,#0x100]
    mov x2,#0x20000
    svc #5
    adrp x19,0x8000
    str x0,[x19,#0x140]
    mov x0,x20
    svc #9
    cbnz x0,7f
    add x1,x19,#0x134
    mov x2,#1
    mov x3,#0xca00
    movk x3,#0x3b9a,lsl #16 // 1 second, bounded real wait
    svc #0x18
    adrp x19,0x8000
    str x0,[x19,#0x148]
    add x1,x19,#0x138
    mov x2,#1
    mov x3,#0xca00
    movk x3,#0x3b9a,lsl #16
    svc #0x18
    adrp x19,0x8000
    str x0,[x19,#0x150]
7:  mov x0,x20
    svc #0x16
8:  ldr w0,[x19,#0x130]
    svc #0x16
    ldr w0,[x19,#0x134]
    svc #0x16
    host 8
    adrp x19,0x8000
    str x0,[x19,#0x158]
    ldr x0,[x19,#0x108]
    ldr x1,[x19,#0x100]
    mov x2,#0x20000
    svc #5
    adrp x19,0x8000
    str x0,[x19,#0x160]
9:  end
.size kernel_thread_entry,.-kernel_thread_entry

.global kernel_child_entry
.type kernel_child_entry,%function
kernel_child_entry:
    begin
    mov x0,sp
    adrp x19,0x8000
    str x0,[x19,#0x168]
    mov x0,#91
    host 0
    host 8
    adrp x19,0x8000
    str x0,[x19,#0x170]
    mrs x0,tpidr_el0
    adrp x19,0x8000
    str x0,[x19,#0x180]
    mrs x0,tpidrro_el0
    adrp x19,0x8000
    str x0,[x19,#0x188]
    mov x0,#1
    adrp x19,0x8000
    str x0,[x19,#0x178]
    ldr w0,[x19,#0x130]
    svc #0x11
    mov x0,#0
    svc #0x0a
    // Must never execute: explicit guest exit restores the host stack.
    mov x0,#0xbad
    adrp x19,0x8000
    str x0,[x19,#0x178]
    end
.size kernel_child_entry,.-kernel_child_entry

.global kernel_tick_entry
.type kernel_tick_entry,%function
kernel_tick_entry:
    stp x29,x30,[sp,#-16]!
    svc #0x1e
    mov x0,x1
    ldp x29,x30,[sp],#16
    ret
.size kernel_tick_entry,.-kernel_tick_entry
.global kernel_unknown_entry
.type kernel_unknown_entry,%function
kernel_unknown_entry:
    stp x29,x30,[sp,#-16]!
    svc #0x7f
    ldp x29,x30,[sp],#16
    ret
.size kernel_unknown_entry,.-kernel_unknown_entry
.org 0xffc
.word 0
