.text
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b extra_call
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40, 0x9000-0x40, 0xa000-0x40, 0, 0, 0x8300-0x40
.org 0x100
.global extra_call
.type extra_call,%function
extra_call:
    mov x0,#5
    ret
.size extra_call,.-extra_call
.global fixture_init
.type fixture_init,%function
fixture_init:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    ldr x9,[x8,#64]
    mov x0,#3
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size fixture_init,.-fixture_init
.org 0xffc
.word 0
