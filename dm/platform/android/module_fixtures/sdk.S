// Startup names match the production SDK sequence; implementation is our own.
.text
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b sdk_call
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40, 0x9000-0x40, 0xa000-0x40, 0, 0, 0x8300-0x40
.org 0x100
.global sdk_call
.type sdk_call,%function
sdk_call:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    ldr x9,[x8,#0]
    blr x9
    svc #0x77
    mov x0,#40
    ldp x29,x30,[sp],#16
    ret
.size sdk_call,.-sdk_call
.global force_override
.type force_override,%function
force_override:
    mov x0,#1
    ret
.size force_override,.-force_override
.global fixture_init
.type fixture_init,%function
fixture_init:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    ldr x9,[x8,#64]
    mov x0,#2
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size fixture_init,.-fixture_init
.macro boot name, step
.global \name
.type \name,%function
\name:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    ldr x9,[x8,#72]
    mov x0,#\step
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size \name,.-\name
.endm
boot _init_libc0,1
.global nnosInitialize
.type nnosInitialize,%function
nnosInitialize:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    str x0,[x8,#0x110]
    str x1,[x8,#0x118]
    ldr x9,[x8,#72]
    mov x0,#2
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size nnosInitialize,.-nnosInitialize
boot _init_libc1,3
boot nninitInitializeSdkModule,4
boot nninitStartup,5
boot _init_libc2,6
.global _ZN2nn2os11SetHostArgcEi
.type _ZN2nn2os11SetHostArgcEi,%function
_ZN2nn2os11SetHostArgcEi:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    str x0,[x8,#0x120]
    ldr x9,[x8,#72]
    mov x0,#7
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size _ZN2nn2os11SetHostArgcEi,.-_ZN2nn2os11SetHostArgcEi
.global _ZN2nn2os11SetHostArgvEPPc
.type _ZN2nn2os11SetHostArgvEPPc,%function
_ZN2nn2os11SetHostArgvEPPc:
    stp x29,x30,[sp,#-16]!
    adrp x8,0x8000
    str x0,[x8,#0x128]
    ldr x9,[x8,#72]
    mov x0,#8
    blr x9
    ldp x29,x30,[sp],#16
    ret
.size _ZN2nn2os11SetHostArgvEPPc,.-_ZN2nn2os11SetHostArgvEPPc
.org 0xffc
.word 0
