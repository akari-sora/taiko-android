// Freely authored NSO entry and relocatable cross-module computation.
.text
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b nnMain
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40, 0x9000-0x40, 0xa000-0x40, 0, 0, 0x8300-0x40
.org 0x100
.global fixture_main
.type fixture_main,%function
fixture_main:
    stp x29,x30,[sp,#-32]!
    mov x29,sp
    adrp x8,0x8000
    ldr x9,[x8,#0]
    blr x9
    mov x18,x0
    adrp x8,0x8000
    ldr x10,[x8,#8]
    ldr x10,[x10]
    add x18,x18,x10
    ldr x11,[x8,#16]
    ldr x11,[x11]
    add x18,x18,x11
    ldr x12,[x8,#24]
    ldr x12,[x12]
    add x18,x18,x12
    str x18,[sp,#16]
    ldr x18,[sp,#16]
    ldr x9,[x8,#32]
    blr x9
    add x0,x0,x18
    adrp x8,0x9000
    mov x9,#123
    str x9,[x8]
    ldp x29,x30,[sp],#32
    ret
.size fixture_main,.-fixture_main
.global fixture_init
.type fixture_init,%function
fixture_init:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    ldr x9,[x8,#64]
    mov x0,#1
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size fixture_init,.-fixture_init
.global nnMain
.type nnMain,%function
nnMain:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    ldr x9,[x8,#72]
    mov x0,#9
    blr x9
    bl fixture_main
    ldp x29,x30,[sp],#16
    ret
.size nnMain,.-nnMain
.org 0xffc
.word 0
