"""POSIX host integration for DMAMOD03 admission and pre-map refusal."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[4]
LIVE = Path(os.environ.get("TAIKO_LIVE_REPO", ROOT))
EVIDENCE = Path(os.environ.get("DM_TEST_OUTPUT_ROOT", ROOT))
sys.path[:0] = [str(ROOT / "dm/tools"), str(LIVE / "dm/tools"), str(Path(__file__).parent)]

import android_guest_contract as contract
import android_import as importer
import test_android_guest_contract_v3 as fixture_module
from test_android_guest_contract_v3_native import cpp_bytes


def wsl_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if len(drive) != 1:
        raise AssertionError(f"cannot translate Windows path for WSL: {resolved}")
    tail = resolved.as_posix().split(":", 1)[1]
    return f"/mnt/{drive}{tail}"


class RuntimeGuestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_module.GuestContractImporterTests.setUpClass()
        helper = fixture_module.GuestContractImporterTests(methodName="runTest")
        cls.empty = importer.make_package("main", helper.nso, helper.metadata,
                                          helper.image(typed=False), 0x4000, 3)
        cls.full = importer.make_package("sdk", helper.nso, helper.metadata,
                                         helper.image(typed=True), 0x4000, 3)
        cls.golden = json.loads((ROOT / "dm/verify/android/fixtures/dmamod03_v1_golden.json")
                                .read_text(encoding="utf-8"))

    def test_admission_copy_move_identity_and_whole_graph_preflight(self):
        run = EVIDENCE / "native-runs" / ("dmamod03-runtime-" + uuid.uuid4().hex)
        self.assertFalse(run.exists(), "runtime run directory must be unique")
        stage = run / "src"
        stage.mkdir(parents=True)
        if not os.environ.get("DM_TEST_OUTPUT_ROOT"):
            self.addCleanup(shutil.rmtree, run, ignore_errors=True)
        overlay_platform = ROOT / "dm/platform/android"
        live_platform = LIVE / "dm/platform/android"
        for name in ("module_runtime.cpp", "module_runtime.h", "guest_abi.h",
                     "guest_contract_abi.h", "guest_contract_wire.h", "guest_contract_wire.cpp"):
            shutil.copy2(overlay_platform / name, stage / name)
        # These two local quote-includes must resolve beside the staged source,
        # otherwise the live guest_abi.h and candidate guest_abi.h would both
        # enter one translation unit under distinct canonical paths.
        for name in ("guest_loader_internal.h", "guest_stack_check.h"):
            shutil.copy2(live_platform / name, stage / name)

        package_sha = hashlib.sha256(self.full).digest()
        empty_sha = hashlib.sha256(self.empty).digest()
        body = copy.deepcopy(self.golden["audit"]["object_without_identity"])
        body.update(package_sha256=package_sha.hex(), source_sha256=self.full[216:248].hex(),
                    build_id=self.full[184:216].hex(),
                    exact_guest={"count": 1, "table_sha256": self.full[432:464].hex()},
                    returning_retire={"count": 1, "table_sha256": self.full[464:496].hex()},
                    final_independent_roots_sha256=self.golden["roots"]["sha256"],
                    whole_function_ownership_proof_sha256=self.golden["ownership"]["sha256"])
        audit_identity = contract.audit_identity_sha256(body)
        arrays = "".join((cpp_bytes("empty_package", self.empty), cpp_bytes("full_package", self.full),
                          cpp_bytes("empty_sha", empty_sha), cpp_bytes("package_sha", package_sha),
                          cpp_bytes("source_sha", self.full[216:248]),
                          cpp_bytes("build_id", self.full[184:216]),
                          cpp_bytes("recipe_sha", bytes.fromhex(body["toolset_recipe_sha256"])),
                          cpp_bytes("audit_sha", audit_identity),
                          cpp_bytes("roots_sha", bytes.fromhex(body["final_independent_roots_sha256"])),
                          cpp_bytes("proof_sha", bytes.fromhex(body["whole_function_ownership_proof_sha256"]))))
        harness = r'''
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#define private public
#include "module_runtime.h"
#undef private
using namespace dm_android;
''' + arrays + r'''
static unsigned map_calls=0,seal_calls=0,unload_calls=0,resolver_calls=0,profile_calls=0;
bool dm_android_guest_prepare_package_image(const DmGuestImage&,DmGuestLoadedImage* out,char*,size_t,bool,bool){++map_calls;if(out)*out={};return false;}
bool dm_android_guest_seal(DmGuestLoadedImage*,char*,size_t){++seal_calls;return false;}
void dm_android_guest_unload(DmGuestLoadedImage*){++unload_calls;}
extern "C" __attribute__((noreturn)) void dm_android_diag_abort_entry(uint64_t,uint64_t,uint64_t,uint64_t){std::abort();}
namespace dm_android {
bool validate_observation_profile(ModulePackage& p,const char** error){
 ++profile_calls;p.profile=nullptr;
 if(p.wire_version!=2){if(error)*error="compat validator did not receive v2";return false;}
 for(const auto& gate:p.gates)if(gate.kind==DM_GUEST_EXACT_GUEST){if(error)*error="kind6 leaked into compat validator";return false;}
 return true;
}
}
template<size_t N>void load32(std::array<uint8_t,32>& out,const uint8_t(&in)[N]){static_assert(N==32);std::copy_n(in,32,out.begin());}
TrustedGuestContractAuditV1 audit(){
 TrustedGuestContractAuditV1 value{};load32(value.package_sha256,package_sha);load32(value.source_sha256,source_sha);load32(value.build_id,build_id);
 load32(value.toolset_recipe_sha256,recipe_sha);load32(value.audit_identity_sha256,audit_sha);value.exact_guest_count=1;
 std::copy_n(full_package+432,32,value.exact_guest_table_sha256.begin());value.returning_retire_count=1;
 std::copy_n(full_package+464,32,value.returning_retire_table_sha256.begin());load32(value.final_independent_roots_sha256,roots_sha);
 load32(value.whole_function_ownership_proof_sha256,proof_sha);return value;
}
std::unique_ptr<ModulePackage> decode_full(bool admitted){
 std::unique_ptr<ModulePackage> out;std::string error;bool ok=false;
 if(admitted){auto a=audit();ok=decode_package_with_guest_contract_audit(full_package,sizeof(full_package),package_sha,a,&out,&error);}
 else ok=decode_package(full_package,sizeof(full_package),package_sha,&out,&error);
 if(!ok){std::cerr<<error<<"\n";std::abort();}return out;
}
std::unique_ptr<ModulePackage> decode_empty(){
 std::unique_ptr<ModulePackage> out;std::string error;
 if(!decode_package(empty_package,sizeof(empty_package),empty_sha,&out,&error)){std::cerr<<error<<"\n";std::abort();}return out;
}
bool resolver(const char*,bool,uintptr_t*,void*){++resolver_calls;return false;}
std::unique_ptr<ModulePackage> dummy_v2(const char* name){
 auto p=std::make_unique<ModulePackage>();p->name=name;p->wire_version=2;p->bytes={1,2,3,4};return p;
}
void expect_graph(std::vector<std::unique_ptr<ModulePackage>> graph,const char* fragment){
 Process process;process.load_generation_=73;
 auto old=std::make_unique<LoadedModule>();auto* old_address=old.get();process.modules_.push_back(std::move(old));
 map_calls=seal_calls=resolver_calls=0;const unsigned unload_before=unload_calls;std::string error;
 assert(!process.load(std::move(graph),resolver,nullptr,&error));
 assert(error.find(fragment)!=std::string::npos);
 assert(map_calls==0&&seal_calls==0&&resolver_calls==0&&unload_calls==unload_before);
 assert(process.load_generation()==73&&process.modules_.size()==1&&process.modules_[0].get()==old_address);
}
int main(){
 const unsigned before_profile=profile_calls;
 {auto raw=decode_full(false);assert(profile_calls==before_profile+1);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(raw));expect_graph(std::move(g),"require trusted guest-contract admission");}
 {auto admitted=decode_full(true);assert(admitted->guest_contract_admission_);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(admitted));expect_graph(std::move(g),"execution is unavailable");}
 {auto changed=decode_full(true);changed->exact_guest_records[0].symbol_index^=1;std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(changed));expect_graph(std::move(g),"stale or package data changed");}
 {auto source=decode_full(true);auto copied=std::make_unique<ModulePackage>(*source);assert(!copied->guest_contract_admission_);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(copied));expect_graph(std::move(g),"require trusted guest-contract admission");}
 {auto source=decode_full(true);auto moved=std::make_unique<ModulePackage>(std::move(*source));assert(!source->guest_contract_admission_&&moved->guest_contract_admission_);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(moved));expect_graph(std::move(g),"execution is unavailable");}
 {auto source=decode_full(true);*source=*source;assert(!source->guest_contract_admission_);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(source));expect_graph(std::move(g),"require trusted guest-contract admission");}
 {auto empty=decode_empty();std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(empty));expect_graph(std::move(g),"execution is unavailable");}
 {auto v3=decode_full(true);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(dummy_v2("legacy"));g.push_back(std::move(v3));expect_graph(std::move(g),"execution is unavailable");}
 {auto v3=decode_full(true);std::vector<std::unique_ptr<ModulePackage>> g;g.push_back(std::move(v3));g.push_back(dummy_v2("legacy"));expect_graph(std::move(g),"execution is unavailable");}
 {auto bad=audit();bad.audit_identity_sha256[0]^=1;std::unique_ptr<ModulePackage> out;std::string error;
  assert(!decode_package_with_guest_contract_audit(full_package,sizeof(full_package),package_sha,bad,&out,&error));assert(!out&&error.find("admission failed")!=std::string::npos);}
 std::cout<<"DMAMOD03 admission/lifecycle/pre-map refusal PASS\n";return 0;
}
'''
        cpp = stage / "runtime_test.cpp"
        cpp.write_text(harness, encoding="ascii")
        sources = [stage / "runtime_test.cpp", stage / "module_runtime.cpp",
                   stage / "guest_contract_wire.cpp", live_platform / "module_sha256.cpp"]
        exe = run / "runtime_test"
        arguments = ["-std=c++17", "-Wall", "-Wextra", "-Werror",
                     "-Wno-error=misleading-indentation", "-pthread",
                     f"-I{stage}", f"-I{live_platform}", *map(str, sources), "-o", str(exe)]
        if os.name == "nt":
            self.assertTrue(Path(r"C:\Windows\System32\wsl.exe").is_file(),
                            "WSL host compiler is mandatory; absence is not a runtime pass")
            compiler = "/usr/bin/c++"
            linux_args = [arg if not (len(arg) > 2 and arg[1] == ":") else wsl_path(Path(arg))
                          for arg in arguments]
            # Translate include arguments separately because they begin with -I.
            linux_args = [("-I" + wsl_path(Path(arg[2:]))) if arg.startswith("-I") and len(arg)>3 and arg[3]==":" else arg
                          for arg in linux_args]
            command = " ".join(map(shlex.quote, [compiler, *linux_args]))
            compiled = subprocess.run(["wsl.exe", "-e", "sh", "-lc", command], capture_output=True)
            run_command = ["wsl.exe", "-e", wsl_path(exe)]
        else:
            compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
            self.assertIsNotNone(compiler, "host C++ compiler is mandatory; absence is not a runtime pass")
            compiled = subprocess.run([compiler, *arguments], capture_output=True)
            run_command = [str(exe)]
        compile_stdout = compiled.stdout.decode("utf-8", errors="replace")
        compile_stderr = compiled.stderr.decode("utf-8", errors="replace")
        (run / "compile.stdout.log").write_text(compile_stdout, encoding="utf-8")
        (run / "compile.stderr.log").write_text(compile_stderr, encoding="utf-8")
        self.assertEqual(compiled.returncode, 0, compile_stdout + compile_stderr)
        executed = subprocess.run(run_command, capture_output=True)
        run_stdout = executed.stdout.decode("utf-8", errors="replace")
        run_stderr = executed.stderr.decode("utf-8", errors="replace")
        (run / "run.stdout.log").write_text(run_stdout, encoding="utf-8")
        (run / "run.stderr.log").write_text(run_stderr, encoding="utf-8")
        (run / "result.json").write_text(json.dumps({"compile_exit": compiled.returncode,
                                                       "run_exit": executed.returncode,
                                                       "package_sha256": package_sha.hex(),
                                                       "audit_identity_sha256": audit_identity.hex()}, indent=2) + "\n")
        self.assertEqual(executed.returncode, 0, run_stdout + run_stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
