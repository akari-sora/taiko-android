.text
.global fixture
fixture:
    mov x2, #65535
    mov x3, x0
byte_retry:
    ldxrb w18, [x3]
    add w18, w18, #1
    stxrb w1, w18, [x3]
    cbz w1, next_byte
    subs x2, x2, #1
    b.ne byte_retry
    b fail
next_byte:
    mov x2, #65535
    add x3, x3, #8
half_retry:
    ldaxrh w18, [x3]
    add w18, w18, #1
    stlxrh w1, w18, [x3]
    cbz w1, next_half
    subs x2, x2, #1
    b.ne half_retry
    b fail
next_half:
    mov x2, #65535
    add x3, x3, #8
word_retry:
    ldxr w18, [x3]
    add w18, w18, #1
    stxr w1, w18, [x3]
    cbz w1, next_word
    subs x2, x2, #1
    b.ne word_retry
    b fail
next_word:
    mov x2, #65535
    add x3, x3, #8
double_retry:
    ldaxr x18, [x3]
    add x18, x18, #1
    stlxr w1, x18, [x3]
    cbz w1, next_double
    subs x2, x2, #1
    b.ne double_retry
    b fail
next_double:
    mov x2, #65535
    add x3, x3, #8
pair_retry:
    ldxp x18, x16, [x3]
    add x18, x18, #1
    add x16, x16, #1
    stxp w1, x18, x16, [x3]
    cbz w1, next_pair
    subs x2, x2, #1
    b.ne pair_retry
    b fail
next_pair:
    mov x2, #65535
    add x3, x3, #16
pair_word_retry:
    ldaxp w16, w18, [x3]
    add w18, w18, #1
    add w16, w16, #1
    stlxp w1, w16, w18, [x3]
    cbz w1, next_pair_word
    subs x2, x2, #1
    b.ne pair_word_retry
    b fail
next_pair_word:
    mov x2, #65535
    mov x0, x18
    ret
fail:
    mov x0, #-1
    ret
