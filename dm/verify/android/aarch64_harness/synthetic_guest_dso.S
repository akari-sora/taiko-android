// Standalone synthetic AArch64 probes and DSO exports for Gate 3 / Gate 4.
// Hardware x18 and TPIDR_EL0 are never written by any instruction in this file.

    .text
    .p2align 4

    .globl dm_synthetic_dso_version
    .type dm_synthetic_dso_version, %function
dm_synthetic_dso_version:
    movz w0, #0x5331
    movk w0, #0x444d, lsl #16
    ret
    .size dm_synthetic_dso_version, . - dm_synthetic_dso_version

    .globl dm_synthetic_const42
    .type dm_synthetic_const42, %function
dm_synthetic_const42:
    mov w0, #42
    ret
    .size dm_synthetic_const42, . - dm_synthetic_const42

    .globl dm_synthetic_read_x18
    .type dm_synthetic_read_x18, %function
dm_synthetic_read_x18:
    mov x0, x18
    ret
    .size dm_synthetic_read_x18, . - dm_synthetic_read_x18

    .globl dm_synthetic_read_tpidr_el0
    .type dm_synthetic_read_tpidr_el0, %function
dm_synthetic_read_tpidr_el0:
    mrs x0, tpidr_el0
    ret
    .size dm_synthetic_read_tpidr_el0, . - dm_synthetic_read_tpidr_el0

    .globl dm_synthetic_read_sp
    .type dm_synthetic_read_sp, %function
dm_synthetic_read_sp:
    mov x0, sp
    ret
    .size dm_synthetic_read_sp, . - dm_synthetic_read_sp

    .globl dm_synthetic_exclusive_retry_ok
    .type dm_synthetic_exclusive_retry_ok, %function
dm_synthetic_exclusive_retry_ok:
    mov w1, #64
.Lretry_loop:
    ldxr x2, [x0]
    add x2, x2, #1
    stxr w3, x2, [x0]
    cbz w3, .Lretry_success
    sub w1, w1, #1
    cbnz w1, .Lretry_loop
    mov w0, #1
    ret
.Lretry_success:
    mov w0, #0
    ret
    .size dm_synthetic_exclusive_retry_ok, . - dm_synthetic_exclusive_retry_ok

    .globl dm_synthetic_exclusive_explicit_clrex
    .type dm_synthetic_exclusive_explicit_clrex, %function
dm_synthetic_exclusive_explicit_clrex:
    ldxr x2, [x0]
    add x2, x2, #1
    clrex
    stxr w3, x2, [x0]
    mov w0, w3
    ret
    .size dm_synthetic_exclusive_explicit_clrex, . - dm_synthetic_exclusive_explicit_clrex

    .hidden dm_synthetic_pure_ret_target
    .globl dm_synthetic_pure_ret_target
    .type dm_synthetic_pure_ret_target, %function
dm_synthetic_pure_ret_target:
    ret
    .size dm_synthetic_pure_ret_target, . - dm_synthetic_pure_ret_target

    .hidden dm_synthetic_private_clrex_stub
    .globl dm_synthetic_private_clrex_stub
    .type dm_synthetic_private_clrex_stub, %function
dm_synthetic_private_clrex_stub:
    clrex
    b dm_synthetic_pure_ret_target
    .size dm_synthetic_private_clrex_stub, . - dm_synthetic_private_clrex_stub

    .globl dm_synthetic_exclusive_bl_clrex_stub
    .type dm_synthetic_exclusive_bl_clrex_stub, %function
dm_synthetic_exclusive_bl_clrex_stub:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldxr x2, [x0]
    add x2, x2, #1
    bl dm_synthetic_private_clrex_stub
    stxr w3, x2, [x0]
    mov w0, w3
    ldp x29, x30, [sp], #16
    ret
    .size dm_synthetic_exclusive_bl_clrex_stub, . - dm_synthetic_exclusive_bl_clrex_stub

    .hidden dm_synthetic_long_diag_abort_target
    .weak dm_synthetic_long_diag_abort_target
    .type dm_synthetic_long_diag_abort_target, %function
dm_synthetic_long_diag_abort_target:
    mov w0, #42
    mov x8, #93
    svc #0
    brk #0
    .size dm_synthetic_long_diag_abort_target, . - dm_synthetic_long_diag_abort_target

    .globl dm_synthetic_long_diag_abort_entry
    .type dm_synthetic_long_diag_abort_entry, %function
dm_synthetic_long_diag_abort_entry:
    clrex
    mov x6, x30
    mov x7, sp
    b dm_synthetic_long_diag_abort_target
    .size dm_synthetic_long_diag_abort_entry, . - dm_synthetic_long_diag_abort_entry

    .section .rodata,"a",@progbits
    .p2align 4
    .globl dm_synthetic_dso_ident
dm_synthetic_dso_ident:
    .asciz "DM_AARCH64_SYNTHETIC_GUEST_DSO_V1"

    .section .note.GNU-stack,"",@progbits
