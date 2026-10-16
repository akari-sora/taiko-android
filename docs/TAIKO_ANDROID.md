# Taiko Android

## Independent baseline

Worktree: `codex/taiko-android`. Git storage is the independent sibling `taiko-android.git`, cloned without shared objects from commit `6a7419fd25f66f641a93233f8bbf609abb22b62f`. No GitHub remote is configured. Original history and LICENSE are retained.

The requested APK014 archive (265 members) and tools001 archive (76 members) were rechecked against every frozen manifest entry. The newer APK021 (321 members, archive SHA256 `ac7c00dfec5812efbe8ae5b89359b7551d4306762d8edeb29af82fe47f9986e3`) and tools029 (112 members, `22eb25ed5664d04c55ec28c7592217bd97dd6862d02756603dfcdd38235c09fa`) form this baseline. Every member matched. Local records are `.local/source-provenance.json` and `.local/sources/`.

APK021 has scoped dual-device keyboard/helper/TLS evidence and unchanged graphics lineage; tools029 has independent reviews and 226 focused checks. Those are prior scoped results. This combined checkout built its own app/test APK and passed lint with source hashes unchanged; device parser validation is pending.

The Taiko target excludes D2R shader catalogs and the graphics fixture containing generated original game programs. Legacy original launch and unsupported graphics probes report unavailable. Generic NVN/Vulkan/Surface/AAudio implementations remain compiled. Application ID is `org.taikocompat.android`; test ID is `org.taikocompat.android.test`. The existing Kotlin/JNI namespace is retained to match actual exported JNI names.

## Verified original input

NACP/CNMT identifies **太鼓之達人 咚咚雷音祭**. The container includes base 1.0.0, Application `01002460135A4000` content version 0, and patch 1.1.1, `01002460135A4800` content version 131072. The current extracted ExeFS display version remains unknown until matched to a particular program NCA.

The NPDM ACI0 program ID is `01002460135A4000`. Full NSO source/build identities and real typed startup entries are recorded in `.local/identity/module-facts.json` and `startup-functions.json`. Input binaries and extracted metadata are local ignored data.

`main + subsdk0 + sdk` close all referenced strong imports across the three modules. `subsdk0` supplies multimedia functions; omitting it incorrectly creates 31 missing movie imports. The host supplies rtld's loader role. Cross-module constructor callback order still needs dedicated verification; do not replay init arrays after also calling each DT_INIT.

This is Unity2020.3.26f1 IL2CPP output with metadata version27, not an Android Unity source project. No Assembly-CSharp.dll is present.

## Milestones

- A: Independent build and input/module identity. Build/lint and identity checks pass; device parser combination checks remain.
- B: Taiko-specific exact build authority/provider, actual SDK initialization, nnMain, first original frame. NOT_RUN. The inherited D2R original authority cannot authorize Taiko.
- C: Original menu, song selection, full performance, original judgments/results, save, restart/readback. NOT_RUN.
- D: Mobile drum input, physical drums/controllers, audio/video calibration and measured latency. NOT_RUN. Original judgment windows remain intact.

No source snapshot, diagnostic graphic, test audio or successful build constitutes original gameplay.

AAudio retains its current shared/performance-none baseline. Low-latency settings and actual acquired configurations need measurement. Compare the same phone/build/song/output, distinguish timestamp estimates from physical tap-to-sound measurement, and measure jitter/loss/duplication/full-song drift.

Upstream was checked on2026-10-16 at [the official repository](https://github.com/jhaizhou-ops/d2r-mobile): HEAD/main remains `17845634d71341cca1debf43ad79ac25c6a3a97a`; no migration was observed. Review b5c910e/e2a0c9a/9de307e by applicability without a blanket merge or Apple-performance claims.

Original D2R remains read-only for this lane. Shared fixes are separate reviewed patches. Device scheduling is coordinated with D2R thread `01a13ab7-5397-7452-b91b-2f450be60080`.
