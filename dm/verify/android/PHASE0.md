# Phase 0 diagnostic runbook

This is the first Android port increment, based on upstream
`9f0c25768ac4b231c6f4cb0a9f182ded68d0e7cf`. It provides a native diagnostic APK;
it does not execute Diablo II or implement NVN replay. See
[the source audit](PORTING_AUDIT.md) for the loader and rewriter blockers.

## Architecture and toolchain

Kotlin GameActivity 4.4.2 hosts JNI/C++ and ARM64 assembly; GameActivity's native
glue receives lifecycle/surface events. CMake links Android logging and Vulkan.
The app targets API 36, supports API 29+, and builds only `arm64-v8a`.
Use JDK 21, Android SDK 36 and NDK `28.2.13676358`; configure local SDK location
in `dm/android/local.properties` (do not commit machine paths).
GameActivity integration follows [Android's official guide](https://developer.android.com/games/agdk/game-activity).

The native contract lists `abi`, `wx`, `tls`, `x18`, `hle`, `signal`, `thread`,
and `vulkan`, with probe statuses `PASS`, `FAIL` or `SKIP`. Synthetic return values are 42; the ELF HLE registry contains one
test entry. No probe should write host TPIDR_EL0/x18 or create simultaneous RWX
memory. Signal handlers/alternate stacks and native resources must be restored.
Android reserves x18; see [the ABI guide](https://developer.android.com/ndk/guides/abis).

## Build, tests and installation

From `dm/android` in PowerShell, with one authorized ARM64 Android device attached:

```powershell
.\gradlew.bat assembleDebug lintDebug connectedDebugAndroidTest
adb devices -l
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`connectedDebugAndroidTest` needs a device; a missing device is `NOT_RUN`, not a
passing test. An x86 Android emulator cannot install this ARM64-only APK.
Use `adb -s SERIAL` for every command when multiple devices are connected.
Installation uses the normal package manager and requires no root.

Launch and export the app's private report (debug build permits `run-as`):

```powershell
$phase0Package = 'org.d2rmobile.diagnostics'
adb logcat -c
adb shell am force-stop $phase0Package
adb shell am start -W -n "$phase0Package/.MainActivity"
adb shell run-as $phase0Package cat files/phase0-report.json
adb shell run-as $phase0Package cat files/phase0-report.json | Set-Content -Encoding utf8 phase0-report.json
adb logcat -d -v threadtime | Set-Content -Encoding utf8 phase0-logcat.txt
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.build.fingerprint
adb shell getprop ro.kernel.qemu
```

Wait until the app reports completion before exporting. A missing report requires
inspection of logcat; do not synthesize one. Keep the report/logcat with build,
install and instrumentation logs, APK SHA-256, git revision, SDK/NDK versions and
device identity. Mark emulator evidence explicitly and retain physical-device
results separately. Review logs for personal paths/device identifiers before
publishing them.

The evidence validator `dm/verify/android/validate_report.py` generates
`gate-summary.json` from collected reports. Use its `--help` for the current
collector interface; preserve raw inputs and validator output together.
The report is authoritative only for the tested device/run, not a promise that
all Android devices permit the same executable-memory policy.

## Gate interpretation

| Gate | Required evidence / current scope |
| --- | --- |
| G0 | Clean APK assembly **and successful installation**; retain build/install logs and APK digest. Launch and diagnostic output provide additional evidence. Build alone cannot mark PASS. |
| G1 | `NOT_RUN`: the original host loader/runtime is not ported. Synthetic probe PASS must not upgrade this gate. |
| G2 | `NOT_RUN`: no original guest bootstrap milestone reached. |
| G3 | `NOT_RUN`: no Vulkan NVN replay or reference frame test. Vulkan device discovery is a diagnostic only. |
| G4 | `NOT_RUN`: no real game launch/input test. |
| G5 | `NOT_RUN`: no game audio/save/lifecycle/play test. |
| G6 | `NOT_RUN`: no game performance/stability measurement. |

No gate is PASS without matching evidence. The diagnostic UI, successful JNI
load or native process start cannot prove playability. `gamePlayable` remains
false. No physical-device results are claimed in this runbook; results belong
in collected evidence.

## Remaining GO / NO-GO work

A successful synthetic RW→RX function only proves that this instruction sequence
ran under this device's app policy. A feasibility GO also needs upstream NSO
rewriting/relocation, x18 virtualization, guest TLS, ELF HLE registration,
red-zone-safe scratch storage, guest stack signals and guest thread exit on
unrooted ARM64 hardware. Current portable TLS/HLE/thread probes cover the new
diagnostic implementation, not the Apple rewrite contract.

Stop at any failed required feasibility check. Preserve errno, signal metadata,
device identity and the failing report for investigation. The next reviewable
increment is the Android guest-state/rewriter contract, followed by loader tests;
Vulkan replay investment should follow those execution gates.

Keep all user-provided game files outside Git. Retain upstream and third-party
license notices. CI synthetic/build checks are useful regression protection;
they do not replace device or game evidence.
