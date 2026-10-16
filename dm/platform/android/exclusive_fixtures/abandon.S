.text
.global fixture
fixture:
    ldxr x18, [x0]
    cbz x1, abandon
    add x18, x18, #1
    stxr w2, x18, [x0]
    mov x0, x2
    ret
abandon:
    clrex
    stxr w2, x1, [x0]
    mov x0, x2
    ret
