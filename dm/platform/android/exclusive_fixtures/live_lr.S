.text
.global fixture
fixture:
    mov x17, x30
    mov x2, #65535
retry:
    ldxr x30, [x0]
    add x30, x30, #1
    stxr w18, x30, [x0]
    cbz w18, done
    subs x2, x2, #1
    b.ne retry
    mov x0, #-1
    mov x30, x17
    ret
done:
    mov x0, x30
    mov x30, x17
    ret
