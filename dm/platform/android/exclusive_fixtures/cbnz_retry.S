// A canonical status retry with a finite original attempt budget. The budget
// is decremented inside the reservation so the adjacent CBNZ remains direct.
.text
.global fixture
fixture:
    mov x2, #65535
retry:
    ldaxr x18, [x0]
    sub x2, x2, #1
    cbz x2, exhausted
    add x18, x18, #1
    stlxr w1, x18, [x0]
    cbnz w1, retry
    mov x0, x18
    ret
exhausted:
    clrex
    mov x0, #-1
    ret
