# Phase 0 evidence — 2026-10-12

Baseline: `9f0c25768ac4b231c6f4cb0a9f182ded68d0e7cf`.
Device: Samsung SM-S9280 (S24 Ultra), Android 16/API 36,
arm64-v8a, Adreno 750, 4096-byte pages. Installed as a regular Android
application using ADB; no root commands or permissions were used.

`assembleDebug lintDebug connectedDebugAndroidTest` completed successfully.
The one instrumented test invokes all eight probes twice and requires PASS
for every probe. Python evidence-contract tests: 4 passed. Android lint:
0 errors, 10 warnings (including diagnostic strings, icon and dependency
updates); no lint suppression or baseline was introduced.

| Evidence | Result |
| --- | --- |
| ARM64 pointer/ABI fixture | PASS |
| Anonymous RW → RX execution, return value 42 | PASS |
| x18 preservation across synthetic host call | PASS |
| ELF HLE section plus assembly gate | PASS |
| Alternate-stack signal delivery and SIGILL recovery | PASS |
| Isolated synthetic TLS, unchanged host TPIDR_EL0 | PASS |
| pthread entry, return and join | PASS |
| Vulkan graphics queue and logical device creation | PASS |
| G0: diagnostic APK build, install, launch | PASS |
| G1–G6: original runtime and game gates | NOT_RUN |

Raw report, build/install/launch logs, installed APK digest and validated
gate summary are in [evidence](evidence/gate-summary.json). The installed APK
SHA-256 was read from the device and checked against the local artifact.
The native report deliberately keeps G0 PENDING; only the external evidence
validator marks it PASS. `gamePlayable` remains false.

Reproduce from the repository root after collecting current evidence:

```sh
python -m unittest discover -s dm/verify/android/tests -v
python dm/verify/android/validate_report.py dm/verify/android/evidence/s24-ultra-report.json --out dm/verify/android/evidence/gate-summary.json --apk dm/android/app/build/outputs/apk/debug/app-debug.apk --build-log dm/verify/android/evidence/build.log --install-log dm/verify/android/evidence/install.log --install-metadata dm/verify/android/evidence/installation.json
```

This establishes a diagnostic starting point, not feasibility of the original
NSO loader. The next blocking work is replacing Apple TSD offsets and
TPIDRRO_EL0 rewrite rules, removing below-SP scratch use, and validating guest
stack/relocation/thread semantics. No copyrighted game data was used.
Vulkan NVN replay, release builds, 16 KB devices, Mali GPUs and long-duration
runtime testing were not performed. The CI workflow is supplied but has not
run on GitHub yet.
