# Public module corpus

These three modules are freely authored ARM64 assembly and ELF64-format
dynamic/symbol/RELA records in raw NSO0 containers. No game bytes, Apple
artifacts, or test-only native module loaders are used. `gen_android_modules.py`
assembles with the installed NDK, constructs NSOs, and invokes the same
`android_import.import_directory` entry point used for user-supplied ExeFS.
The SDK source uses LZ4 for all three sections; main/extra are uncompressed.
All section hashes and full 32-byte build IDs are deterministic.

Regenerate: `python dm/tools/gen_android_modules.py`
Verify reproducibility: `python dm/tools/gen_android_modules.py --check`
Production import: `python dm/tools/android_import.py INPUT OUTPUT --modules main sdk extra`
INPUT contains actual files named `main`, `sdk`, `extra`; OUTPUT must not
contain older `.dmag` packages. All modules validate before any package publishes.

## Native integration

Include `generated_modules.h`. Arrays and lengths are
`dm_module_main_bytes`, `dm_module_main_size`, `dm_module_sdk_bytes`,
`dm_module_sdk_size`, `dm_module_extra_bytes`, `dm_module_extra_size`.
Constants `dm_module_{main,sdk,extra}_package_sha256[32]` contain the trusted
whole-package hashes for compiled fixtures; supply the matching constant to the
production decoder. External packages require a separately trusted expected
package hash; the payload-only hash in the package header cannot authenticate
gate/provenance tables or the other header fields.
Each array is the complete `.dmag` package and must pass the production
`dm_android::decode_package` and `Process::load` path. Order is main, sdk, extra.
The files `main.dmag`, `sdk.dmag`, `extra.dmag` are identical package bytes.
`import.json` records every source hash, build ID, code range, rewrite/gate,
symbol inventory, section, relocation and constructor offset.

Provide host imports with normal AArch64 calling conventions:

* `extern "C" void record_init(uint64_t module_id)` records DT_INIT IDs 1,2,3.
* `extern "C" void record_boot(uint64_t step)` records SDK/main startup steps.
* Forced `extern "C" uint64_t force_override()` returns 90. SDK's definition
  returns 1; forced resolution must win over this real guest definition.

`uint64_t fixture_main(void)` is a guest export from main. It calls SDK's
`sdk_call`, reads `sdk_global` through GLOB_DAT, reads `extra_global + 8` through
ABS64 with addend, reads local initialized data through RELATIVE, and calls
`force_override` through JUMP_SLOT. Result is **161** with forced override,
**72** with SDK's definition. SDK calls extra's `extra_call` through JUMP_SLOT,
then SVC 0x77, then returns 40. The SVC belongs to SDK even though main invoked
the computation. Main also writes 123 into `main_bss`, proving writable BSS.
Its virtual guest x18 accumulates the cross-module subtotal.
Main's frame reserves 32 bytes and stores/loads virtual x18 at `[sp,#16]`
without writeback, providing native coverage of the Android emitter's SP form.
Unused main data slot 0x8030 has ABS64 `extra_global - 8`, so a runtime check
can verify signed negative addends independently of the computation.
Every module exports `duplicate_value` at data offset 0x8180 with values 1,2,3,
respectively. Resolving it must honor the explicitly supplied first-module order.

## SDK startup contract

SDK exports `_init_libc0`, `nnosInitialize`, `_init_libc1`,
`nninitInitializeSdkModule`, `nninitStartup`, `_init_libc2`,
`_ZN2nn2os11SetHostArgcEi`, `_ZN2nn2os11SetHostArgvEPPc`.
They record boot steps 1..8 in that order when the production bootstrap invokes
the real SDK sequence. `nnosInitialize` stores its x0/x1 arguments in the
uint64_t SDK globals `fixture_main_handle` and `fixture_argument_area`.
Argument setters store their x0 argument in `fixture_argc` and `fixture_argv`.
Main's `uint64_t nnMain(void)` records step 9 and calls `fixture_main`.
DT_INIT records 1,2,3 exactly once between boot steps 6 and 7.

These observations prove the production path on public inputs. Original game
startup and all graphics/audio/input/save parity gates remain **NOT_RUN** until
the actual supplied game corpus is tested.

## Import coverage and pointer assumptions

Code discovery also follows statically materialized text addresses that can
escape through callback arguments, stores or return values. A separate scan of
every original text word rejects uncovered x18/TLS/SVC/timer candidates and
unsupported system-register instructions. Validated metadata and bounded literal
loads can establish data ranges; an independently materialized address into a
literal range rejects as ambiguous. Unclassified nonzero text words also reject.
The inventory records address-taken roots, literal ranges and the candidate audit.

Relocation-backed indirect targets are initial pointer values, not immutable
storage. Any discovered store that overlaps a relocation slot, or whose alias
cannot be bounded, invalidates those pointer proofs. SP stores refer to the
separate guest stack; proven disjoint image stores do not invalidate slots.
Only aligned immediate SP adjustments of at most 4096 bytes and corresponding
bounded SP-relative load/store writeback are permitted. Arbitrary SP writes or
pivots reject before an SP store can acquire a stack exemption.
Known writable-image pointers passed to host imports invalidate slot proofs.
Host resolver implementations remain trusted to obey their ABI; this static
analysis does not sandbox arbitrary host writes or concurrent outside mutation.
