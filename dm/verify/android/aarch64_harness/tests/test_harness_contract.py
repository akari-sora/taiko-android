"""Host contract and NDK 28.2.13676358 ELF verification tests for dm_aarch64_harness."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


HARNESS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = HARNESS_DIR.parents[3]
SDK_ROOT = Path(r"C:\Users\aa223\AppData\Local\Android\Sdk")
NDK_ROOT = SDK_ROOT / "ndk" / "28.2.13676358"
CMAKE_EXE = SDK_ROOT / "cmake" / "3.22.1" / "bin" / "cmake.exe"
NINJA_EXE = SDK_ROOT / "cmake" / "3.22.1" / "bin" / "ninja.exe"
LLVM_BIN = NDK_ROOT / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
LLVM_READELF = LLVM_BIN / "llvm-readelf.exe"
LLVM_OBJDUMP = LLVM_BIN / "llvm-objdump.exe"


def validate_readelf_output(readelf_text: str, *, expect_interp: bool) -> list[str]:
    """Validate llvm-readelf -hW -lW -nW output for an Android AArch64 artifact."""
    errors: list[str] = []

    if "Class:                             ELF64" not in readelf_text:
        errors.append("missing ELF64 class")
    if not (
        "Machine:                           AArch64" in readelf_text
        or "EM_AARCH64" in readelf_text
    ):
        errors.append("missing EM_AARCH64 / AArch64 machine")

    load_re = re.compile(
        r"^\s*LOAD\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"([RWE ]{3})\s+"
        r"(0x[0-9a-fA-F]+)",
        re.MULTILINE,
    )
    loads = load_re.findall(readelf_text)
    if not loads:
        errors.append("no PT_LOAD segments found")

    for idx, (offset_s, vaddr_s, _paddr_s, _filesz_s, _memsz_s, flags_s, align_s) in enumerate(loads):
        offset = int(offset_s, 16)
        vaddr = int(vaddr_s, 16)
        align = int(align_s, 16)
        flags = flags_s.strip()
        if align < 0x4000:
            errors.append(f"PT_LOAD[{idx}] p_align 0x{align:x} < 0x4000")
        if align > 0 and ((vaddr - offset) % align) != 0:
            errors.append(
                f"PT_LOAD[{idx}] non-congruent vaddr=0x{vaddr:x} offset=0x{offset:x} align=0x{align:x}"
            )
        if "W" in flags and ("E" in flags or "X" in flags):
            errors.append(f"PT_LOAD[{idx}] has forbidden W+X permissions ({flags})")

    phdr_perm_re = re.compile(
        r"^\s*\S+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+"
        r"0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+([RWE ]{3})\s+0x[0-9a-fA-F]+",
        re.MULTILINE,
    )
    for flags_s in phdr_perm_re.findall(readelf_text):
        flags = flags_s.strip()
        if "W" in flags and ("E" in flags or "X" in flags):
            errors.append(f"program header has forbidden W+X permissions ({flags})")

    has_interp = bool(re.search(r"^\s*INTERP\s+", readelf_text, re.MULTILINE))
    if expect_interp and not has_interp:
        errors.append("PIE executable missing PT_INTERP")
    if not expect_interp and has_interp:
        errors.append("shared library must not have PT_INTERP")

    if not re.search(r"^\s*GNU_RELRO\s+", readelf_text, re.MULTILINE):
        errors.append("missing GNU_RELRO segment")

    if "NT_GNU_BUILD_ID" not in readelf_text:
        errors.append("missing NT_GNU_BUILD_ID note")

    return errors


class HarnessContractTests(unittest.TestCase):
    def test_harness_cmake_and_sources_exist_and_configured(self):
        cmake_file = HARNESS_DIR / "CMakeLists.txt"
        main_file = HARNESS_DIR / "harness_main.cpp"
        dso_file = HARNESS_DIR / "synthetic_guest_dso.S"

        self.assertTrue(cmake_file.is_file(), f"Missing {cmake_file}")
        self.assertTrue(main_file.is_file(), f"Missing {main_file}")
        self.assertTrue(dso_file.is_file(), f"Missing {dso_file}")

        cmake_text = cmake_file.read_text(encoding="utf-8")
        self.assertIn("dm_aarch64_harness", cmake_text)
        self.assertIn("synthetic_guest_dso", cmake_text)
        self.assertIn("-ffixed-x18", cmake_text)
        self.assertIn("relro", cmake_text)
        self.assertIn("now", cmake_text)
        self.assertIn("--wrap=mmap", cmake_text)
        self.assertIn("--wrap=mprotect", cmake_text)
        self.assertIn("--wrap=munmap", cmake_text)
        self.assertIn("guest_loader.cpp", cmake_text)
        self.assertNotIn("module_runtime.cpp", cmake_text)
        self.assertNotIn("guest_entry.S", cmake_text)

        main_text = main_file.read_text(encoding="utf-8")
        self.assertIn("__wrap_mmap", main_text)
        self.assertIn("__wrap_mprotect", main_text)
        self.assertIn("__wrap_munmap", main_text)
        self.assertIn("dm_android_guest_prepare", main_text)
        self.assertIn("dm_android_guest_seal", main_text)
        self.assertIn("dm_android_guest_unload", main_text)

        dso_text = dso_file.read_text(encoding="utf-8")
        self.assertIn("clrex", dso_text.lower())

    def test_elf_contract_validator_rejects_mutations(self):
        valid_sample = """
ELF Header:
  Class:                             ELF64
  Machine:                           AArch64
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  INTERP         0x000270 0x0000000000000270 0x0000000000000270 0x000015 0x000015 R   0x1
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x001000 0x001000 R   0x4000
  LOAD           0x004000 0x0000000000004000 0x0000000000004000 0x002000 0x002000 R E 0x4000
  LOAD           0x008000 0x0000000000008000 0x0000000000008000 0x001000 0x001000 RW  0x4000
  GNU_RELRO      0x008000 0x0000000000008000 0x0000000000008000 0x000500 0x001000 R   0x1
Notes:
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
"""
        self.assertEqual(validate_readelf_output(valid_sample, expect_interp=True), [])

        bad_align = valid_sample.replace("R E 0x4000", "R E 0x1000")
        self.assertTrue(
            any("p_align" in e for e in validate_readelf_output(bad_align, expect_interp=True))
        )

        bad_rwx = valid_sample.replace("R E 0x4000", "RWE 0x4000")
        self.assertTrue(
            any("W+X" in e for e in validate_readelf_output(bad_rwx, expect_interp=True))
        )

        bad_build_id = valid_sample.replace("NT_GNU_BUILD_ID", "NT_OTHER")
        self.assertTrue(
            any("NT_GNU_BUILD_ID" in e for e in validate_readelf_output(bad_build_id, expect_interp=True))
        )

    def test_ndk_build_and_elf_contract(self):
        self.assertTrue(CMAKE_EXE.is_file(), f"Missing CMake at {CMAKE_EXE}")
        self.assertTrue(NINJA_EXE.is_file(), f"Missing Ninja at {NINJA_EXE}")
        self.assertTrue(NDK_ROOT.is_dir(), f"Missing NDK 28.2.13676358 at {NDK_ROOT}")
        self.assertTrue(LLVM_READELF.is_file(), f"Missing llvm-readelf at {LLVM_READELF}")
        self.assertTrue(LLVM_OBJDUMP.is_file(), f"Missing llvm-objdump at {LLVM_OBJDUMP}")

        toolchain_file = NDK_ROOT / "build" / "cmake" / "android.toolchain.cmake"
        self.assertTrue(toolchain_file.is_file(), f"Missing toolchain file at {toolchain_file}")

        with tempfile.TemporaryDirectory(prefix="dm_aarch64_harness_build_") as tmp_dir:
            build_dir = Path(tmp_dir) / "build"
            configure_cmd = [
                str(CMAKE_EXE),
                "-S",
                str(HARNESS_DIR),
                "-B",
                str(build_dir),
                "-G",
                "Ninja",
                f"-DCMAKE_MAKE_PROGRAM={NINJA_EXE}",
                f"-DCMAKE_TOOLCHAIN_FILE={toolchain_file}",
                "-DANDROID_ABI=arm64-v8a",
                "-DANDROID_PLATFORM=android-29",
                "-DANDROID_STL=c++_static",
                "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON",
                f"-DDM_REPO_ROOT={REPO_ROOT}",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ]
            cfg = subprocess.run(configure_cmd, capture_output=True, text=True)
            self.assertEqual(
                cfg.returncode,
                0,
                f"CMake configure failed:\nSTDOUT:\n{cfg.stdout}\nSTDERR:\n{cfg.stderr}",
            )

            build_cmd = [str(NINJA_EXE), "-C", str(build_dir)]
            bld = subprocess.run(build_cmd, capture_output=True, text=True)
            self.assertEqual(
                bld.returncode,
                0,
                f"Ninja build failed:\nSTDOUT:\n{bld.stdout}\nSTDERR:\n{bld.stderr}",
            )

            compile_commands_path = build_dir / "compile_commands.json"
            self.assertTrue(compile_commands_path.is_file(), "compile_commands.json not generated")
            compile_commands = json.loads(compile_commands_path.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(compile_commands), 3)
            for entry in compile_commands:
                cmd_str = entry.get("command", "")
                self.assertIn(
                    "-ffixed-x18",
                    cmd_str,
                    f"Translation unit {entry.get('file')} missing -ffixed-x18: {cmd_str}",
                )

            pie_path = build_dir / "dm_aarch64_harness"
            dso_path = build_dir / "libsynthetic_guest_dso.so"
            self.assertTrue(pie_path.is_file(), f"Missing PIE binary {pie_path}")
            self.assertTrue(dso_path.is_file(), f"Missing DSO binary {dso_path}")

            for artifact, expect_interp in ((pie_path, True), (dso_path, False)):
                readelf_lw = subprocess.run(
                    [str(LLVM_READELF), "-lW", str(artifact)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(readelf_lw.returncode, 0, readelf_lw.stderr)

                readelf_all = subprocess.run(
                    [str(LLVM_READELF), "-hW", "-lW", "-nW", "-dW", str(artifact)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(readelf_all.returncode, 0, readelf_all.stderr)
                errors = validate_readelf_output(readelf_all.stdout, expect_interp=expect_interp)
                self.assertEqual(
                    errors,
                    [],
                    f"ELF verification failed for {artifact.name}: {errors}\n{readelf_all.stdout}",
                )
                self.assertTrue(
                    "BIND_NOW" in readelf_all.stdout or "NOW" in readelf_all.stdout,
                    f"Missing BIND_NOW in {artifact.name}:\n{readelf_all.stdout}",
                )

                objdump = subprocess.run(
                    [str(LLVM_OBJDUMP), "-d", "--no-show-raw-insn", str(artifact)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(objdump.returncode, 0, objdump.stderr)
                self.assertIn("<dm_synthetic_private_clrex_stub>:", objdump.stdout)
                self.assertIn("<dm_synthetic_long_diag_abort_entry>:", objdump.stdout)
                self.assertRegex(
                    objdump.stdout,
                    r"<dm_synthetic_private_clrex_stub>:\s*\n\s*[0-9a-f]+:\s*clrex\s*\n\s*[0-9a-f]+:\s*b\s+",
                )
                self.assertRegex(
                    objdump.stdout,
                    r"<dm_synthetic_long_diag_abort_entry>:\s*\n"
                    r"\s*[0-9a-f]+:\s*clrex\s*\n"
                    r"\s*[0-9a-f]+:\s*mov\s+x6,\s*x30\s*\n"
                    r"\s*[0-9a-f]+:\s*mov\s+x7,\s*sp\s*\n"
                    r"\s*[0-9a-f]+:\s*b\s+",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
