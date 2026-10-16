.section .entry,"ax",%progbits
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b nnMain
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x20400-0x40,0x21000-0x40,0x21000-0x40,0,0,0x20300-0x40
.org 0x100
.macro IMPORT name,slot
.global \name
.type \name,%function
\name:
    adrp x16,0x20000
    ldr x16,[x16,#(\slot * 8)]
    br x16
.size \name,.-\name
.endm
IMPORT graphics_bootstrap_import,0
IMPORT graphics_operation_mode_import,1
.global graphics_heap_allocate
.type graphics_heap_allocate,%function
graphics_heap_allocate:
    mov x0,#0
    mov x1,#0x200000
    svc #1
    cmp x0,#0
    csel x0,x1,xzr,eq
    ret
.size graphics_heap_allocate,.-graphics_heap_allocate
.section .imports,"aw",%progbits
.zero 16
