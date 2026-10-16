# Generated Android ABI v1 fixtures

All assembly is self-authored. `python dm/tools/gen_android_fixtures.py`
assembles it with installed NDK clang/llvm-objcopy, then sends the raw bytes
through `android_rewrite.rewrite`. `--check` repeats this and compares the
committed header without modifying it. No original game files are required.
`fixtures.h` includes `../guest_abi.h`; image objects have internal linkage.

| DmGuestImage object | C call signature | Expected result/state |
| --- | --- | --- |
| `dm_fixture_x18_arithmetic` | `uint64_t(uint64_t input)` | Return and `virtual_x18` equal input+7 modulo 2^64. |
| `dm_fixture_x18_memory` | `uint64_t(uint64_t* memory)` | Return, pointed value and `virtual_x18` equal original pointed value+5. |
| `dm_fixture_x18_conditional` | `uint64_t(uint64_t input)` | Return 11 for zero, 22 otherwise; `virtual_x18` equals input. Run both paths. |
| `dm_fixture_tls` | `uint64_t(uint64_t input)` | Return input+3+initial `guest_tpidrro_el0`; final `guest_tpidr_el0` equals input+3; final `virtual_x18` equals initial TLR. Exercises x18 TLS read destination and write source. |
| `dm_fixture_live_lr` | `uint64_t(uint64_t input)` | Return and `virtual_x18` equal input+9; tests unsaved live LR and x16 source operand. |
| `dm_fixture_svc` | `uint64_t(uint64_t input)` | Calls SVC kind 1, argument 0x42; callback owns returned x0. LR survives. Suggested callback sets x0=input+0x42. |
| `dm_fixture_timer` | `void(uint64_t out[6])` | Calls TIMER kind 2 with destinations 19,20,21,22,23,18 in that order; stores each callback-provided result in out; `virtual_x18` equals sixth result. Preserves caller x19..24, x29/x30. Suggested callback result = 0x1000+destination. |
| `dm_fixture_sp_memory` | `uint64_t(uint64_t receipt[66])` | Returns 512 bytes written: 32 alternating value/SP-delta pairs with two untouched trailing sentinels. Fixed expected values live in `sp_rewrite_probe()`. Checks bounded immediate pre/post/negative addresses, signed widths, partial stores, x16/LR, SP-source aliases/arithmetic and flags. |
| `dm_fixture_sp_preserve` | `void()` through full-frame harness | Preserves every GPR, full SIMD, NZCV/FPSR/FPCR, SP and virtual x18 while executing bounded SP-sensitive rewrites. |

Functions use the native ARM64 C ABI and assume an attached guest state and
loaded image association. Host x18/TLS must survive. Repeat the arithmetic or
TLS fixture in the runtime's signal-interrupted loop; each call traverses the
production state accessor. Timer and SVC use the production dispatch gate.
The header's helper pointer slots remain zero until loader fixups while RW.

Negative stores are observed before another unrelated rewritten instruction
can reuse inactive memory below SP. These cases do not establish a guest red
zone or arbitrary-memory equivalence below the active stack. Indexed SP memory,
unaligned writeback and dynamic pivots remain rejected. Separate exclusive
fixtures are specified in `../exclusive_fixtures/CONTRACT.md`.
