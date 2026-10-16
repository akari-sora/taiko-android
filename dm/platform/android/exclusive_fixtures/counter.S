.text
.global fixture
fixture:
    mov x2, #65535
retry:
    ldaxr x18, [x0]
    add x18, x18, #1
    stlxr w1, x18, [x0]
    cbz w1, done
    subs x2, x2, #1
    b.ne retry
    mov x0, #-1
    ret
done:
    mov x0, x18
    ret
