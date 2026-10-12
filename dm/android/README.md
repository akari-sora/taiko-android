# Android Phase 0

Native ARM64 diagnostics for the Android port. This application runs only
self-authored fixtures and does not load game files.

Build from this directory with JDK 21 and Android SDK 36:

```sh
./gradlew assembleDebug lintDebug connectedDebugAndroidTest
```

The instrumented tests require a connected ARM64 device. CI builds and lints
the app; physical-device testing remains a separate gate.

See the [audit](../verify/android/PORTING_AUDIT.md),
[verification runbook](../verify/android/PHASE0.md), and
[recorded hardware results](../verify/android/RESULTS.md).

The original Apple host and renderer are intentionally unchanged. Android
diagnostics use their own JNI implementation and ELF assembly fixtures.
