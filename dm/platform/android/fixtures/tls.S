// uint64_t(uint64_t input): return input+3+initial TLR, TLS=input+3, x18=TLR.
.text
.global fixture
fixture:
    msr tpidr_el0, x0
    mrs x18, tpidr_el0
    add x18, x18, #3
    msr tpidr_el0, x18
    mrs x1, tpidr_el0
    mrs x18, tpidrro_el0
    add x0, x1, x18
    ret
