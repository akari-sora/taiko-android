// uint64_t(uint64_t* memory): *memory, return and virtual_x18 = old + 5.
.text
.global fixture
fixture:
    ldr x18, [x0]
    add x18, x18, #5
    str x18, [x0]
    mov x0, x18
    ret
