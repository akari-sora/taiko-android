# D2R & Taiko Android Compatibility Layer Takeover + GitLab-Canonical Mirror Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Seal and adopt the remaining `task-4` work (`DMAMOD03` v3 guest contract foundation for Taiko and `0x1536e8` live adoption for D2R), establish GitLab (`aa22396584`) as the canonical source with zero-trigger GitHub mirrors (`akari-sora`), and execute the next implementation gates (AArch64 synthetic harness, Taiko `LONG_DIAG_ABORT_V1` / `RETURNING_RETIRE_V1` emitter, and production provider build pins).

**Architecture:** Both `d2r-mobile` (`android/phase0-diagnostics`) and `taiko-android` (`codex/taiko-android`) share the `dm/` AArch64 NSO-to-Android compatibility engine with strict fail-closed verification gates (`DMAMOD01`/`02`/`03` wire formats, `TrustedGuestContractAuditV1` private admission, `x18` preservation, and 16 KiB ELF alignment). Source control is canonical on GitLab (`aa22396584/d2r-mobile` and `aa22396584/taiko-android`) and pushed via SSH remote mirrors to pre-locked GitHub repositories (`akari-sora/d2r-mobile` and `akari-sora/taiko-android`) where GitHub Actions, Issues, Wiki, Projects, Discussions, Pages, and `.github/workflows` are completely disabled prior to first push.

**Tech Stack:** C11 / C++17 / ARM64 Assembly (`guest_entry.S`), Python 3.11 (`unittest`, Capstone, LZ4), Android NDK `28.2.13676358` (r28c, 16 KiB ELF default), CMake `3.22.1` + Ninja, Gradle `8.14` / AGP `8.13.1`, `glab` CLI, `gh` CLI.

---

### Task 1: Seal `taiko-dmamod03-candidate` and Adopt into `taiko-android` Live Worktree

**Files:**
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/android/native/CMakeLists.txt`
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/platform/android/guest_abi.h`
- Create: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/platform/android/guest_contract_abi.h`
- Create: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/platform/android/guest_contract_wire.h`
- Create: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/platform/android/guest_contract_wire.cpp`
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/platform/android/module_runtime.h`
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/platform/android/module_runtime.cpp`
- Create: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/tools/android_guest_contract.py`
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/tools/android_import.py`
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/tools/android_rewrite.py`
- Create: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/verify/android/fixtures/dmamod03_v1_golden.json`
- Test: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/verify/android/tests/test_android_guest_contract_v3.py`
- Test: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/verify/android/tests/test_android_guest_contract_v3_native.py`
- Test: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/verify/android/tests/test_android_guest_contract_v3_runtime.py`
- Test: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/dm/verify/android/tests/test_android_original_v3_boundary.py`

**Step 1: Verify the candidate regression tests against the overlay**

Run:
```powershell
C:\Python311\python.exe -B -m unittest discover -s C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android\dm\verify\android\tests -p "test_android_import.py" -v
C:\Python311\python.exe -B -m unittest discover -s C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android\dm\verify\android\tests -p "test_android_diag_abort_flags.py" -v
```
Expected: `Ran 35 tests ... OK` and `Ran 5 tests ... OK`.

**Step 2: Copy the 15 overlay files into `taiko-android` live worktree and seal `REPORT.md` + `FINAL-HASHES.json`**

Run:
```powershell
C:\Python311\python.exe -B -m unittest discover -s C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android\dm\verify\android\tests -p "test_android_guest_contract_v3.py" -v
```
Expected: `Ran 11 tests ... OK`.

**Step 3: Run the newly adopted native, runtime, and D2R-boundary v3 suites in `taiko-android`**

Run:
```powershell
C:\Python311\python.exe -B -m unittest discover -s C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android\dm\verify\android\tests -p "test_android_guest_contract_v3_*.py" -v
C:\Python311\python.exe -B -m unittest discover -s C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android\dm\verify\android\tests -p "test_android_original_v3_boundary.py" -v
```
Expected: All 6 native tests, 1 runtime test, and 2 boundary tests PASS.

---

### Task 2: Sanitize `.gitignore`, Remove `.github/workflows`, and Commit Clean Checkpoints

**Files:**
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/.gitignore`
- Delete: `C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android/.github/workflows/android-phase0.yml`
- Modify: `C:/Users/aa223/Documents/Codex/2026-10-12/10m-10s-jhaizhou-ops-d2r-mobile/.gitignore`
- Delete: `C:/Users/aa223/Documents/Codex/2026-10-12/10m-10s-jhaizhou-ops-d2r-mobile/.github/workflows/android-phase0.yml`

**Step 1: Harden `.gitignore` in both repositories to block keys, game dumps, local toolsets, and binary build artifacts**

Ensure `.gitignore` in both repos includes:
```gitignore
# Never commit keys, game dumps, extracted containers, or local toolsets
title.keys
*.keys
*.xci
*.nsp
*.nsz
*.nca
games/
dd-extract/
.local/
new.local/
**/.build/
dm/verify/android/evidence/
```

**Step 2: Remove `.github/workflows/android-phase0.yml` so GitHub Actions can never be triggered by workflow files**

Run:
```powershell
git -C "C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android" rm -f .github/workflows/android-phase0.yml
git -C "C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile" rm -f .github/workflows/android-phase0.yml
```
Expected: `.github/workflows/android-phase0.yml` staged for deletion in both repositories.

**Step 3: Audit staged files to ensure zero keys, game binaries, or >5MB compiled objects are staged**

Run:
```powershell
git -C "C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android" status -sb
git -C "C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile" status -sb
```
Expected: Only source, test, fixture header, and documentation files are tracked/staged; `title.keys`, `games/`, `dd-extract/`, `new.local/`, and `.build/` are ignored.

**Step 4: Commit clean checkpoints on `codex/taiko-android` and `android/phase0-diagnostics`**

Run:
```powershell
git -C "C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android" add -A
git -C "C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android" commit -m "feat(android): adopt DMAMOD03 v3 guest contract foundation and disable github workflows"

git -C "C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile" add -A
git -C "C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile" commit -m "feat(android): adopt 0x1536e8 live checkpoint and disable github workflows"
```
Expected: Clean working trees on both `codex/taiko-android` and `android/phase0-diagnostics`.

---

### Task 3: Provision GitLab Canonical Repos and Pre-Lock GitHub Mirrors (Zero-Trigger Protocol)

**Files:**
- Remote: `https://gitlab.com/aa22396584/d2r-mobile.git` (Canonical)
- Remote: `https://gitlab.com/aa22396584/taiko-android.git` (Canonical)
- Mirror: `ssh://git@github.com/akari-sora/d2r-mobile.git` (Read-only Mirror, all features off)
- Mirror: `ssh://git@github.com/akari-sora/taiko-android.git` (Read-only Mirror, all features off)

**Step 1: Create empty GitHub repositories under `akari-sora` WITHOUT pushing any code**

Run:
```powershell
gh api -X POST user/repos -f name="d2r-mobile" -f description="Mirror of gitlab.com/aa22396584/d2r-mobile (Canonical development on GitLab)" -F private=false -F has_issues=false -F has_projects=false -F has_wiki=false -F has_downloads=false -F has_discussions=false -F auto_init=false
gh api -X POST user/repos -f name="taiko-android" -f description="Mirror of gitlab.com/aa22396584/taiko-android (Canonical development on GitLab)" -F private=false -F has_issues=false -F has_projects=false -F has_wiki=false -F has_downloads=false -F has_discussions=false -F auto_init=false
```
Expected: Empty repositories created on GitHub with zero commits.

**Step 2: Disable GitHub Actions and all auxiliary GitHub features BEFORE any code is pushed**

Run:
```powershell
gh api -X PUT repos/akari-sora/d2r-mobile/actions/permissions -F enabled=false
gh api -X DELETE repos/akari-sora/d2r-mobile/vulnerability-alerts
gh api -X DELETE repos/akari-sora/d2r-mobile/automated-security-fixes

gh api -X PUT repos/akari-sora/taiko-android/actions/permissions -F enabled=false
gh api -X DELETE repos/akari-sora/taiko-android/vulnerability-alerts
gh api -X DELETE repos/akari-sora/taiko-android/automated-security-fixes
```
Expected: `gh api repos/akari-sora/d2r-mobile/actions/permissions` and `gh api repos/akari-sora/taiko-android/actions/permissions` both return `{"enabled":false,"sha_pinning_required":false}`.

**Step 3: Create canonical GitLab projects under `aa22396584` with shared runners disabled**

Run:
```powershell
glab api -X POST projects -f name="d2r-mobile" -f path="d2r-mobile" -f visibility="public" -f shared_runners_enabled="false" -f jobs_enabled="false" -f description="D2R Android ARM64 NSO compatibility layer (Canonical on GitLab)"
glab api -X POST projects -f name="taiko-android" -f path="taiko-android" -f visibility="public" -f shared_runners_enabled="false" -f jobs_enabled="false" -f description="Taiko Android ARM64 NSO compatibility layer (Canonical on GitLab)"
```
Expected: GitLab projects created with `shared_runners_enabled: false`.

**Step 4: Push local branches to GitLab and configure SSH push mirrors to GitHub**

Run:
```powershell
git -C "C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile" remote add gitlab https://gitlab.com/aa22396584/d2r-mobile.git
git -C "C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile" push -u gitlab main android/phase0-diagnostics

git -C "C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android" remote add gitlab https://gitlab.com/aa22396584/taiko-android.git
git -C "C:\Users\aa223\Documents\Codex\2026-10-16\taiko-android" push -u gitlab main codex/taiko-android
```
Then register `remote_mirrors` on GitLab (`auth_method=ssh_public_key`, `only_protected_branches=false`), attach each generated SSH public key to the corresponding GitHub repo's deploy keys (`read_only=false`), trigger `POST /projects/:id/remote_mirrors/:mirror_id/sync`, and verify `gh api repos/akari-sora/<repo>/actions/runs` returns `"total_count": 0`.

---

### Task 4: Implement Android AArch64 Synthetic Harness (`Gate 3` / `Gate 4`)

**Files:**
- Create: `dm/verify/android/aarch64_harness/CMakeLists.txt`
- Create: `dm/verify/android/aarch64_harness/harness_main.cpp`
- Create: `dm/verify/android/aarch64_harness/synthetic_guest_dso.S`
- Create: `dm/verify/android/aarch64_harness/tests/test_harness_contract.py`

**Step 1: Write the failing host contract test (`test_harness_contract.py`)**

```python
import unittest
from pathlib import Path

class HarnessContractTests(unittest.TestCase):
    def test_harness_cmake_and_sources_exist(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / "CMakeLists.txt").is_file())
        self.assertTrue((root / "harness_main.cpp").is_file())
        self.assertTrue((root / "synthetic_guest_dso.S").is_file())
```

**Step 2: Run test to verify it fails**

Run:
```powershell
C:\Python311\python.exe -B -m unittest discover -s dm/verify/android/aarch64_harness/tests -p "test_harness_contract.py" -v
```
Expected: FAIL (`AssertionError: False is not true`).

**Step 3: Implement `CMakeLists.txt`, `synthetic_guest_dso.S`, and `harness_main.cpp`**

Compile directly against `dm/platform/android/guest_loader.cpp` with `-ffixed-x18`, `-Wl,-z,relro,-z,now`, `-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON`, and `--wrap=mmap`/`--wrap=mprotect`/`--wrap=munmap` ledger verification.

**Step 4: Configure and build with pinned NDK `28.2.13676358` and run `llvm-readelf` 16 KiB PT_LOAD alignment check**

Run:
```powershell
& "C:\Users\aa223\AppData\Local\Android\Sdk\cmake\3.22.1\bin\cmake.exe" -S dm/verify/android/aarch64_harness -B build/aarch64_harness -G Ninja -DCMAKE_MAKE_PROGRAM="C:\Users\aa223\AppData\Local\Android\Sdk\cmake\3.22.1\bin\ninja.exe" -DCMAKE_TOOLCHAIN_FILE="C:\Users\aa223\AppData\Local\Android\Sdk\ndk\28.2.13676358\build\cmake\android.toolchain.cmake" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 -DANDROID_STL=c++_static -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON
& "C:\Users\aa223\AppData\Local\Android\Sdk\cmake\3.22.1\bin\ninja.exe" -C build/aarch64_harness
```
Expected: Produces `dm_aarch64_harness` PIE and `libsynthetic_guest_dso.so` with `p_align >= 0x4000` (16 KiB) and zero `R+W+X` segments.

**Step 5: Commit**

```powershell
git add dm/verify/android/aarch64_harness
git commit -m "feat(verify): add standalone Android AArch64 synthetic loader harness"
```

---

### Task 5: Implement Taiko `DMAMOD03` Selector/Emitter & Live Runtime Dispatch (`Gate 5` / `Gate 6`)

**Files:**
- Modify: `dm/tools/android_exclusive.py`
- Modify: `dm/tools/android_diag_abort.py`
- Modify: `dm/tools/android_rewrite.py`
- Modify: `dm/tools/android_import.py`
- Modify: `dm/platform/android/module_runtime.cpp`
- Modify: `dm/platform/android/guest_entry.S`
- Test: `dm/verify/android/tests/test_android_guest_contract_v3_dispatch.py`

**Step 1: Write failing tests for `RETURNING_RETIRE_V1` (`CLREX` first side-effect before `BL`) and `LONG_DIAG_ABORT_V1` (`0x569690` / `0x28c8f0` exact guest contracts)**

**Step 2: Run test to verify it fails**

Run:
```powershell
C:\Python311\python.exe -B -m unittest discover -s dm/verify/android/tests -p "test_android_guest_contract_v3_dispatch.py" -v
```
Expected: FAIL (`execution-not-implemented refusal`).

**Step 3: Implement selector, stub emitter (`CLREX` + exact `B`), and `module_runtime.cpp` kind-6 / retire admission**

**Step 4: Run tests to verify all positive and fail-closed negative cases pass**

Run:
```powershell
C:\Python311\python.exe -B -m unittest discover -s dm/verify/android/tests -p "test_android_guest_contract_v3*.py" -v
```
Expected: PASS.

**Step 5: Commit**

```powershell
git add dm/tools dm/platform/android dm/verify/android/tests
git commit -m "feat(taiko): wire DMAMOD03 returning-retire and exact-guest dispatch"
```

---

### Task 6: Generate Frozen Triple-Module Provider Build Pins & Run Dual-Device G0-G9 Matrix (`Gate 7` - `Gate 9`)

**Files:**
- Create: `dm/platform/android/original_build_pins.cpp` (D2R via `dm/tools/gen_android_original_pins.py`)
- Create: `.local/taiko_build_pins.cpp` (Taiko via `dm/tools/gen_taiko_pins.py`)
- Test: `dm/verify/android/tests/test_taiko_pins.py`

**Step 1: Run frozen triple-module (`main`, `sdk`, `subsdk0`) replay for D2R and Taiko**

**Step 2: Generate provider pin sources and run host pin verification**

**Step 3: Build provider-bearing APKs with Gradle/NDK and run static artifact gate audit (16 KiB `PT_LOAD`, zero `RWX`, `arm64-v8a` only)**

**Step 4: Execute G0 -> G9 acceptance lanes on Galaxy S24 Ultra (`SM-S9280`) first, then Galaxy S8 (`SM-G950F`)**
