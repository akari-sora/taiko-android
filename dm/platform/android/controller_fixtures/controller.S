// Public SDK-shaped NSO. Every HID call goes through an ELF relocation, even
// though this SDK defines competing implementations which must never run.
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
.endm
.macro END name,bytes=16
    ldp x29,x30,[sp],#\bytes
    ret
.size \name,.-\name
.endm
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b nnMain
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40,0x9000-0x40,0xa000-0x40,0,0,0x8300-0x40
.org 0x100
BEGIN controller_setup,32
    IMPORT 0
    mov w8,#0
    str w8,[sp,#16]
    add x0,sp,#16
    mov x1,#1
    IMPORT 1
    mov w0,#3
    IMPORT 2
    mov w0,#0
    IMPORT 3
    adrp x8,0x8000
    ldr x9,[x8,#0x570]
    add x9,x9,#1
    str x9,[x8,#0x570]
END controller_setup,32

// x0 FullKey query ID; x1 Handheld query ID. Results remain in guest-owned RW.
BEGIN controller_sample,32
    stp w0,w1,[sp,#16]
    add x0,sp,#16
    IMPORT 4
    adrp x8,0x8000
    str w0,[x8,#0x500]
    add x0,sp,#20
    IMPORT 4
    adrp x8,0x8000
    str w0,[x8,#0x504]
    IMPORT 7
    adrp x8,0x8000
    str w0,[x8,#0x508]
    add x0,x8,#0x560
    mov x1,#1
    add x2,sp,#16
    mov w3,#3
    IMPORT 8
    adrp x8,0x8000
    str w0,[x8,#0x50c]
    add x0,x8,#0x560
    IMPORT 9
    adrp x8,0x8000
    add x0,x8,#0x560
    add x1,x8,#0x560
    IMPORT 10
    adrp x8,0x8000
    add x0,x8,#0x510
    add x1,sp,#16
    IMPORT 5
    adrp x8,0x8000
    add x0,x8,#0x538
    add x1,sp,#20
    IMPORT 6
    mov x0,#0xc011
END controller_sample,32

BEGIN nnMain
    bl controller_setup
    mov x0,#0
    mov x1,#0x20
    bl controller_sample
END nnMain

BEGIN fixture_init
    adrp x8,0x8000
    ldr x9,[x8,#0x580]
    add x9,x9,#1
    str x9,[x8,#0x580]
END fixture_init

BEGIN _init_libc0
    adrp x8,0x8000
    ldr x9,[x8,#0x578]
    add x9,x9,#1
    str x9,[x8,#0x578]
END _init_libc0
.macro NOOP name
BEGIN \name
END \name
.endm
NOOP nnosInitialize
NOOP _init_libc1
NOOP nninitInitializeSdkModule
NOOP nninitStartup
NOOP _init_libc2
NOOP _ZN2nn2os11SetHostArgcEi
NOOP _ZN2nn2os11SetHostArgvEPPc

// Deliberately conflicting SDK definitions: return poison and count any call.
.macro CONFLICT name
BEGIN \name
    adrp x8,0x8000
    ldr x9,[x8,#0x568]
    add x9,x9,#1
    str x9,[x8,#0x568]
    mov x0,#0xbad
END \name
.endm
CONFLICT _ZN2nn3hid14InitializeNpadEv
CONFLICT _ZN2nn3hid22SetSupportedNpadIdTypeEPKjm
CONFLICT _ZN2nn3hid24SetSupportedNpadStyleSetENS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE
CONFLICT _ZN2nn3hid29SetNpadHandheldActivationModeENS0_26NpadHandheldActivationModeE
CONFLICT _ZN2nn3hid15GetNpadStyleSetERKj
CONFLICT _ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj
CONFLICT _ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj
CONFLICT _ZN2nn3hid20IsVibrationPermittedEv
CONFLICT _ZN2nn3hid25GetVibrationDeviceHandlesEPNS0_21VibrationDeviceHandleEiRKjNS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE
CONFLICT _ZN2nn3hid25InitializeVibrationDeviceERKNS0_21VibrationDeviceHandleE
CONFLICT _ZN2nn3hid18SendVibrationValueERKNS0_21VibrationDeviceHandleERKNS0_14VibrationValueE
.org 0xffc
.word 0
