// uint64_t(uint64_t input): SVC 0x42 dispatch may replace x0; LR must survive.
.text
.global fixture
fixture:
    svc #0x42
    ret
