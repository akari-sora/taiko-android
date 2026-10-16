// uint64_t(uint64_t input): return 11 if zero, otherwise 22; x18 = input.
.text
.global fixture
fixture:
    mov x18, x0
    cbz x18, zero
    mov x0, #22
    ret
zero:
    mov x0, #11
    ret
