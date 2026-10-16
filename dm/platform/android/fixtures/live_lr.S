// uint64_t(uint64_t input): return input+9; original unsaved LR survives helpers.
// x16 is a live operand during add; restores must precede the original operation.
.text
.global fixture
fixture:
    mov x16, #9
    mov x18, x0
    add x18, x18, x16
    mov x0, x18
    ret
