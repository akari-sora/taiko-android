.text
.global fixture
fixture:
    mov x2, #65535
retry:
    ldxr x16, [x0]
    add x16, x16, #1
    stxr w18, x16, [x0]
    cbz w18, done
    subs x2, x2, #1
    b.ne retry
    mov x0, #-1
    ret
done:
    mov x0, x16
    ret
