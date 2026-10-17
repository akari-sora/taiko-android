"""D2R provider and compiled-graph boundaries remain exactly DMAMOD02."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[4]
LIVE = Path(os.environ.get("TAIKO_LIVE_REPO", ROOT))
EVIDENCE = Path(os.environ.get("DM_TEST_OUTPUT_ROOT", ROOT))
sys.path[:0] = [str(ROOT / "dm/tools"), str(LIVE / "dm/tools"), str(Path(__file__).parent)]

import android_import as importer
import gen_android_original_pins as original_pins
import test_android_guest_contract_v3 as fixture_module


def wsl_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if len(drive) != 1:
        raise AssertionError(f"cannot translate Windows path for WSL: {resolved}")
    return f"/mnt/{drive}{resolved.as_posix().split(':', 1)[1]}"


class OriginalV3BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_module.GuestContractImporterTests.setUpClass()
        helper = fixture_module.GuestContractImporterTests(methodName="runTest")
        cls.empty = importer.make_package("main", helper.nso, helper.metadata,
                                          helper.image(typed=False), 0x4000, 3)
        cls.full = importer.make_package("sdk", helper.nso, helper.metadata,
                                         helper.image(typed=True), 0x4000, 3)

    def test_pin_generator_rejects_empty_and_nonempty_v3_before_publication(self):
        run = EVIDENCE / "boundary-runs" / ("d2r-v3-pins-" + uuid.uuid4().hex)
        self.assertFalse(run.exists(), "boundary run directory must be unique")
        run.mkdir(parents=True)
        results = {}
        for name, package in (("empty", self.empty), ("nonempty", self.full)):
            path = run / f"{name}.dmag"
            path.write_bytes(package)
            with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, "must be checked-stack DMAMOD02") as rejected:
                original_pins.package_pin(path, {}, {}, None, None)
            results[name] = str(rejected.exception)
        (run / "result.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(set(run.iterdir()), {run / "empty.dmag", run / "nonempty.dmag", run / "result.json"})

    def test_compiled_original_graph_accepts_v2_identity_then_rejects_v3(self):
        run = EVIDENCE / "boundary-runs" / ("d2r-v3-graph-" + uuid.uuid4().hex)
        self.assertFalse(run.exists(), "boundary run directory must be unique")
        run.mkdir(parents=True)
        platform = LIVE / "dm/platform/android"
        source = r'''
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#define private public
#include "original_bringup.h"
#undef private
namespace dm_android {
struct ModuleDynamic {};
LoadedModule::LoadedModule()=default;LoadedModule::~LoadedModule()=default;Process::~Process()=default;
static const std::array<uint8_t,32> one{1};static const uint64_t roots[]{4};
static OriginalSourcePin sources[]={
 {"main",one,one,one,1},{"sdk",one,one,one,1},{"subsdk0",one,one,one,1}};
static OriginalModulePin pins_modules[]={
 {"main",one,one,4,4,{1,one,one,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1}},
 {"sdk",one,one,4,4,{1,one,one,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1}},
 {"subsdk0",one,one,4,4,{1,one,one,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1}}};
static OriginalBuildPins pins={1,"D2R/3.3.94012/OriginalBringup-stock-v1",sources,3,pins_modules,3,41,one,one};
const OriginalBuildPins* compiled_original_bringup_pins(){return &pins;}
bool Process::loaded_package_authority(size_t i,LoadedPackageAuthority* out)const{
 if(!out||i>=3)return false;
 out->capsule_sha256=pins_modules[i].package_sha256;out->capsule_bytes=4;
 out->checked_stack=true;out->callback_audited=true;return true;
}
}
int main(){using namespace dm_android;Process process;process.load_generation_=9;
 for(size_t i=0;i<3;++i){auto loaded=std::make_unique<LoadedModule>();loaded->package=std::make_unique<ModulePackage>();
  auto& p=*loaded->package;p.name=sources[i].name;p.wire_version=2;p.build_id=sources[i].build_id;
  p.source_sha256=sources[i].source_sha256;p.image_sha256=pins_modules[i].image_sha256;p.bytes.resize(4);
  process.modules_.push_back(std::move(loaded));}
 std::string error;assert(original_bringup_graph(process,&error));
 process.modules_[1]->package->wire_version=3;assert(!original_bringup_graph(process,&error));
 assert(error.find("frozen capsule/source/stack/callback identity mismatch")!=std::string::npos);
 process.modules_[1]->package->wire_version=2;assert(original_bringup_graph(process,&error));
 std::cout<<"D2R compiled original graph exact-v2 boundary PASS\n";return 0;}
'''
        cpp = run / "boundary.cpp"
        cpp.write_text(source, encoding="ascii")
        exe = run / "boundary"
        args = ["-std=c++17", "-Wall", "-Wextra", "-Werror", f"-I{platform}",
                str(cpp), str(platform / "original_bringup.cpp"), "-o", str(exe)]
        if os.name == "nt":
            linux_args = [("-I" + wsl_path(Path(arg[2:]))) if arg.startswith("-I") and len(arg)>3 and arg[3]==":"
                          else wsl_path(Path(arg)) if len(arg)>2 and arg[1]==":" else arg for arg in args]
            command = " ".join(map(shlex.quote, ["/usr/bin/c++", *linux_args]))
            compiled = subprocess.run(["wsl.exe", "-e", "sh", "-lc", command], capture_output=True)
            run_command = ["wsl.exe", "-e", wsl_path(exe)]
        else:
            compiler = next((value for name in ("c++", "g++", "clang++")
                             if (value := __import__("shutil").which(name))), None)
            self.assertIsNotNone(compiler, "host C++ compiler is mandatory; absence is not a boundary pass")
            compiled = subprocess.run([compiler, *args], capture_output=True)
            run_command = [str(exe)]
        cout = compiled.stdout.decode("utf-8", errors="replace")
        cerr = compiled.stderr.decode("utf-8", errors="replace")
        (run / "compile.stdout.log").write_text(cout, encoding="utf-8")
        (run / "compile.stderr.log").write_text(cerr, encoding="utf-8")
        self.assertEqual(compiled.returncode, 0, cout + cerr)
        executed = subprocess.run(run_command, capture_output=True)
        rout = executed.stdout.decode("utf-8", errors="replace")
        rerr = executed.stderr.decode("utf-8", errors="replace")
        (run / "run.stdout.log").write_text(rout, encoding="utf-8")
        (run / "run.stderr.log").write_text(rerr, encoding="utf-8")
        (run / "result.json").write_text(json.dumps({"compile_exit": compiled.returncode,
                                                       "run_exit": executed.returncode}, indent=2) + "\n")
        self.assertEqual(executed.returncode, 0, rout + rerr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
