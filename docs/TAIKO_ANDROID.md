# Taiko Android

## Independent baseline

Worktree: `codex/taiko-android`. Git storage is the independent sibling `taiko-android.git`, cloned without shared objects from commit `6a7419fd25f66f641a93233f8bbf609abb22b62f`. No GitHub remote is configured. Original history and LICENSE are retained.

The requested APK014 archive (265 members) and tools001 archive (76 members) were rechecked against every frozen manifest entry. The newer APK021 (321 members, archive SHA256 `ac7c00dfec5812efbe8ae5b89359b7551d4306762d8edeb29af82fe47f9986e3`) and tools029 (112 members, `22eb25ed5664d04c55ec28c7592217bd97dd6862d02756603dfcdd38235c09fa`) form this baseline. Every member matched. Local records are `.local/source-provenance.json` and `.local/sources/`.

APK021 has scoped dual-device keyboard/helper/TLS evidence and unchanged graphics lineage; tools029 has independent reviews and 226 focused checks. Those are prior scoped results. This combined checkout built its own app/test APK and passed lint with source hashes unchanged; device parser validation is pending.

The Taiko target excludes D2R shader catalogs and the graphics fixture containing generated original game programs. Legacy original launch and unsupported graphics probes report unavailable. Generic NVN/Vulkan/Surface/AAudio implementations remain compiled. Application ID is `org.taikocompat.android`; test ID is `org.taikocompat.android.test`. The existing Kotlin/JNI namespace is retained to match actual exported JNI names.

## Verified original input

NACP/CNMT identifies **太鼓之達人 咚咚雷音祭**. The container includes base 1.0.0, Application `01002460135A4000` content version 0, and patch 1.1.1, `01002460135A4800` content version 131072. The current extracted ExeFS display version remains unknown until matched to a particular program NCA.

The NPDM ACI0 program ID is `01002460135A4000`. Full NSO source/build identities and real typed startup entries are recorded in `.local/identity/module-facts.json` and `startup-functions.json`. Input binaries and extracted metadata are local ignored data.

`main + subsdk0 + sdk` close all referenced strong imports across the three modules. `subsdk0` supplies multimedia functions; omitting it incorrectly creates 31 missing movie imports. The host supplies rtld's loader role. The constructor order is checked against its reverse module-list traversal; do not replay init arrays after also calling each DT_INIT. Actual original startup remains unexecuted.

This is Unity2020.3.26f1 IL2CPP output with metadata version27, not an Android Unity source project. No Assembly-CSharp.dll is present.

## Milestones

- A: Independent build and input/module identity. Build/lint, identity, S8 fixture combination and content/UI checks pass. Real strict module preparation is still being repaired; no original package/provider is admitted.
- B: Taiko-specific exact build authority/provider, actual SDK initialization, nnMain, first original frame. NOT_RUN. The inherited D2R original authority cannot authorize Taiko.
- C: Original menu, song selection, full performance, original judgments/results, save, restart/readback. NOT_RUN.
- D: Mobile drum input, physical drums/controllers, audio/video calibration and measured latency. NOT_RUN. Original judgment windows remain intact.

No source snapshot, diagnostic graphic, test audio or successful build constitutes original gameplay.

## Independent import and startup work

The Android folder importer now preserves every manifested RomFS file and its parent path, verifies SHA-256 before atomic publication, recovers abandoned staging, and keeps save data outside replacement. Empty directories without files are not represented. `dm/tools/taiko_content.py` prepares the folder only from the five exact ExeFS identities and a successful checked v2 import. `gen_taiko_pins.py` independently audits source/capsule/receipt/resource correspondence before emitting private compiled providers. No provider has been emitted while the real import is rejected.

On S8 `ce0317133a9ad0190c`, the content-free APK passed 11 content/lease tests and 4 UI/preflight tests, including a real JNI runner refusal before module loading/nnMain when the provider is absent. The same native build passed the two module/guest fixture tests. These are preparation and fixture results, not original Taiko execution.

Taiko has a separate stock authority and startup purpose. The pinned SDK prefix calls the original SDK/main entries and runs each DT_INIT in `sdk, subsdk0, main` order. This follows the actual rtld reverse list traversal combined with [the loader's contiguous module order](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/components/modules/loader.md#file-replacement). Its host loader-ready state is explicit; it does not claim execution of unmapped rtld. A normal nnMain return refuses unimplemented finalization. Original D2R hooks remain behind their original predicate.

The first real strict import rejected `main+0x150f588` (AND SP,X9,#-128). Exact Python/native support is covered by preserved-instruction and stack-reserve/bounds tests, and isolated commit `b0c6f87`. The mutable callback at `main+0xdbc7a4` now compares live virtual X18 with the source-verified `main+0xdb9050`, preserving all input registers and branching directly only on equality. Import003 subsequently reached the distinct function-pointer call at `main+0x292702c`. A separately audited immutable search forest now admits only 242334 positive indexed function entries cross-checked against complete CIE/FDE records; twelve zero-range indexed entries and unindexed records grant no target. Full ordinary-trampoline reach and complete preparation still require the next frozen-tool run.

Parallel SDK/subsdk0 prechecks use identical frozen tools and separate output folders. The SDK inline LR literal at `sdk+0x3807cc` now has a complete versioned saved-LR/stack/control-flow proof. The following SDK failure at `0x548d80` was traced to an unrelated earlier string being considered as another RO table candidate; the gapped local setup is covered by a bounded classifier. Four later audio dispatches share an earlier CMP through a finite CBZ graph; independent metadata/callback entries remain distinct from verified table CFG targets and invalidate this proof if they bypass the comparison. The subsdk0 cases at `0x44a84` and `0xe7078` are now covered by finite RO tables while preserving copied-index and suffix effects. The main signed32 relative table at `0x114b114` checks its actual RO base/full64 index before exactly one signed load, then admits only its six exact case targets.

Frozen toolset `taiko-006` used the same thirteen tool files for ordered import and both independent prechecks (manifest SHA256 `919ab21558bf3d41bcf8f181da4ba2416af1127be39199573a0d3406128da6ca`). Its ordered main check passed the signed32 dispatch and reached four uncovered X18 candidates near `0x2c26a8`. SDK and subsdk0 advanced to `0x19b024` and `0x1a89e8`, respectively. These two further failures were traced to an inline u16 table with virtual X18 as its loaded value, and a native-target u16 table with virtual X18 as its index. Both now have narrowly bounded classifiers and actual-value pre-read guards; independent CPU review covers aliasing x16, state restoration, all indices and refusal paths. Frozen `taiko-007` contains these changes and the corrected independent caller-FDE extent/policy (manifest SHA256 `8989051d6e558b21b44424529efda0578f2de7197798e04a3558c834f462bbd9`); new independent prechecks are running.

Available authored importer tests pass 344/344; the broader inherited suite separately errors on three missing binary fixture families and two observation cases, which are not counted as passing. Taiko tools pass 76 tests with four host-compiler skips, and the new EH parser passes 16 tests. These CPU/source checks do not establish original execution. No compiled provider is published until all three modules pass the same final frozen toolset. Original SDK/nnMain and first frame remain NOT_RUN/NOT_OBSERVED.

AAudio retains its current shared/performance-none baseline. Low-latency settings and actual acquired configurations need measurement. Compare the same phone/build/song/output, distinguish timestamp estimates from physical tap-to-sound measurement, and measure jitter/loss/duplication/full-song drift.

Upstream was checked on2026-10-16 at [the official repository](https://github.com/jhaizhou-ops/d2r-mobile): HEAD/main remains `17845634d71341cca1debf43ad79ac25c6a3a97a`; no migration was observed. Review b5c910e/e2a0c9a/9de307e by applicability without a blanket merge or Apple-performance claims.

Original D2R remains read-only for this lane. Shared fixes are separate reviewed patches. Device scheduling is coordinated with D2R thread `01a13ab7-5397-7452-b91b-2f450be60080`.
