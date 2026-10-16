// Inverted status spelling, with virtual x18 retained as the memory base.
.text
.global fixture
fixture:
    mov x18, x0
    mov x2, #65535
retry:
    ldxr x16, [x18]
    sub x2, x2, #1
    cbz x2, exhausted
    add x16, x16, #1
    stxr w1, x16, [x18]
    cbz w1, done
    b retry
done:
    mov x0, x16
    ret
exhausted:
    clrex
    mov x0, #-1
    ret
