// Freely authored observations and parameter constants; no original game data.
.text
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    b fixture_plain
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x8400-0x40, 0x9000-0x40, 0xa000-0x40, 0, 0, 0x8300-0x40

.org 0x100
.global fixture_plain
.type fixture_plain,%function
fixture_plain:
    add x0,x0,#1
    ret
.size fixture_plain,.-fixture_plain

.org 0x120
.global fixture_ui
.type fixture_ui,%function
fixture_ui:
    add x0,x0,#1
    ret
.size fixture_ui,.-fixture_ui

.org 0x140
.global fixture_mid
.type fixture_mid,%function
fixture_mid:
    stp x29,x30,[sp,#-32]!
    mov x29,sp
    str x19,[sp,#16]
    add x0,x0,#1 // OBS6 PRE point; original FP/SP describe this exact frame.
    str x19,[x1]
    str s0,[x1,#8]
    ldr x19,[sp,#16]
    ldp x29,x30,[sp],#32
    ret
.size fixture_mid,.-fixture_mid

.org 0x180
.global fixture_nested
.type fixture_nested,%function
fixture_nested:
    add x0,x0,#7
    ret
.size fixture_nested,.-fixture_nested

.org 0x200
.global fixture_param_adjacent
.type fixture_param_adjacent,%function
fixture_param_adjacent:
    mov x8,#0x11
    movk x8,#0x22,lsl #16
    mov x0,x8
    ret
.size fixture_param_adjacent,.-fixture_param_adjacent

.org 0x240
.global fixture_param_interleaved
.type fixture_param_interleaved,%function
fixture_param_interleaved:
    mov x8,#0x11
    mov x9,#0x22
    add x0,x0,#3
    movk x8,#0x33,lsl #16
    movk x9,#0x44,lsl #16
    add x0,x0,x8
    add x0,x0,x9
    ret
.size fixture_param_interleaved,.-fixture_param_interleaved

.org 0x280
.global fixture_param_wide
.type fixture_param_wide,%function
fixture_param_wide:
    mov w8,#0x11
    movk w8,#0x22,lsl #16
    mov x0,x8
    ret
.size fixture_param_wide,.-fixture_param_wide

.org 0x2a0
.global fixture_param_ui
.type fixture_param_ui,%function
fixture_param_ui:
    mov w8,#0x33
    movk w8,#0x44,lsl #16
    mov x0,x8
    ret
.size fixture_param_ui,.-fixture_param_ui

.org 0x300
.global fixture_init
.type fixture_init,%function
fixture_init:
    ret
.size fixture_init,.-fixture_init
