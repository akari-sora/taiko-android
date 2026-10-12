# Android port source audit

Audited upstream revision: `9f0c25768ac4b231c6f4cb0a9f182ded68d0e7cf`.
This audit precedes Phase 0 implementation. References below are upstream line
numbers at that revision. Source inspection does not verify iOS performance or
prove Android game execution. The existing Apple implementation is retained.

## Required files

| Source | Apple assumptions and Android implication |
| --- | --- |
| `dm/host/loader.c:6,11–12` | `TargetConditionals` and Mach-O headers prevent an unchanged Android build. |
| `dm/host/loader.c:42–48,178–186` | TLS assumes `(tpidrro_el0 & ~7) + pthread_key * 8`; key pages reject offset zero. Android pthread keys, including a valid key zero, are opaque. Replace this contract with explicit guest TLS rather than Bionic private offsets. |
| `dm/host/loader.c:127` | Forced HLE registration uses `getsectiondata(&_mh_execute_header, "__DATA", "swforce")`. ELF needs link-retained sections and explicit boundaries/registration. |
| `dm/host/loader.c:174,234,285–325` | Fixed 16 KiB layout, CommonCrypto hashing, Mach `vm_remap`, dyld enumeration and `Guest.framework` packaging require platform implementations. Signed Apple pages are not an Android memory strategy. |
| `dm/host/loader.c:343–351` | Desktop path copies anonymous RW pages then changes code to RX. A synthetic Android RW→RX probe can test one device policy, but cannot validate this loader, relocations or all devices. Page layout and instruction-cache handling require review. |
| `dm/host/entry.S:12,22,38,84,134–143` | Leading-underscore Mach-O symbols need ELF equivalents. The gate preserves GPR/SIMD state and FPSR/FPCR; preserve that behavior and the host x18. Thread entry switches directly to the guest stack and treats return as fatal. |
| `dm/host/hle.h:2–6,12,42` | ABI commentary is Apple-specific (small scalar extension and variadic argument placement). HLE and forced-HLE tables use `__DATA,swhle` / `__DATA,swforce`. Android ABI behavior and ELF discovery need tests. |
| `dm/host/hle_thread.c:27–28,175–178,210–214` | Mach thread ports and Darwin QoS calls require Android scheduling/diagnostic substitutes. |
| `dm/host/hle_thread.c:262–434,449–450` | Memory reads, thread suspension/register inspection and CPU accounting use Mach APIs. Guest threads are detached pthreads with an explicit guest stack; stack ownership, signals and exit need an Android contract. |
| `dm/host/hle_fs.c:22–23,94,116,228–229,418,427–428` | Save transactions use APFS `clonefile` and `renamex_np(RENAME_SWAP)`. xattr names and function signatures are Darwin-specific. Android needs a tested durable transaction/recovery protocol, including directory sync and process-kill recovery. |
| `dm/host/hle_audio.c:10–12,29–31,100–116,168–190,242–247` | CoreAudio AudioUnit and dispatch semaphores implement output/notifications/lifecycle. Keep PCM queue semantics while adding an Android audio backend. Phase 0 does not port audio. |
| `dm/gfx/nvn/nvn_mtl.m:3–7,25,27,38,49–88,337` | Metal/QuartzCore, CommonCrypto, dyld and os locks are pervasive. Metal 4 allocators, argument tables, residency, events and shared no-copy buffers require Vulkan designs; they are not direct API substitutions. Preserve NVN command recording. |
| `dm/gfx/tools/dmsh_build.py:27,38,321–353,389–403,446,458` | Ryujinx translation produces SPIR-V, but packaging compiles MSL with `spirv-cross`/`xcrun`; replay reflection is parsed from MSL. Add a separate Vulkan output/reflection path and validate emitted SPIR-V/pipelines. |

## Additional execution blockers

`dm/host/dm.h:42–45` defines the four guest TLS values (x18, TPIDR_EL0,
ThreadLocalRegion and HLE gate) as pthread keys. This is an Apple host contract,
not an Android implementation.

`dm/tools/patch_nso.py:280,335,346,362,395,404,420` emits TPIDRRO_EL0-based
slot lookup in rewritten x18, TLS and gate instructions. Android must leave the
host TLS register and x18 intact; portable C TLS probes do not exercise those
rewrites.

`dm/tools/patch_nso.py:335,346,362,372,395,404` saves temporary registers below
SP without allocating stack space (some paths reach SP−112). This borrows a
Darwin red zone. Android's AAPCS64 does not promise that region; signal delivery
may overwrite it. Rewritten scratch storage must be redesigned, then exercised
with asynchronous signals on guest stacks before approving game execution.
See [AAPCS64 stack rules](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).

The shader starting point is stronger than a generic format conversion:
`dm/gfx/tools/dmsh_xlate/Program.cs:122` already selects `TargetLanguage.Spirv`
and `TargetApi.Vulkan`; `:43–46,131–134` exposes set/binding and resource metadata.
This is reusable input, not evidence that the current shaders or bindings work
on Android GPUs.

## Phase 0 boundary and next decisions

Phase 0 adds an independent GameActivity diagnostic application, Kotlin/JNI,
CMake and ARM64 synthetic probes. It does not link the existing loader or replay
backend and does not import copyrighted game binaries, shaders, keys or assets.
Existing licenses/notices remain intact.

1. Build and install diagnostics; record device ABI, OS, page size and Vulkan.
2. Record synthetic W^X, explicit TLS, x18, ELF HLE gate, signal and thread checks.
3. Keep G1–G6 `NOT_RUN`; do not infer a playable game from probe success.
4. Before Phase 1, design platform TLS, ELF registration, red-zone-safe rewriting,
   guest stack/signal/exit behavior and page-size-aware loading.
5. Require an unrooted ARM64 physical device result before a feasibility GO.

Android references: [GameActivity](https://developer.android.com/games/agdk/game-activity),
[ARM64 ABI and reserved x18](https://developer.android.com/ndk/guides/abis),
[16 KiB page support](https://developer.android.com/guide/practices/page-sizes).
