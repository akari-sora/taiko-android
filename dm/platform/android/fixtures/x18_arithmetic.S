// uint64_t(uint64_t input): return and virtual_x18 = input + 7.
.text
.global fixture
fixture:
    mov x18, x0
    add x18, x18, #7
    mov x0, x18
    ret
