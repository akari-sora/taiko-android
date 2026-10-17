"""Host tests of the real authority; synthetic capsules never execute guest code."""
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path[:0] = [
    str(ROOT / "dm/tools"),
    str(ROOT / ".local/test-env/Lib/site-packages"),
    str(pathlib.Path(__file__).parent),
]


def _wsl_path(path: pathlib.Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if len(drive) != 1:
        raise AssertionError(f"cannot translate Windows path for WSL: {resolved}")
    return f"/mnt/{drive}{resolved.as_posix().split(':', 1)[1]}"


class TaikoAuthorityTests(unittest.TestCase):
    def _compile_and_run(self, args: list[str], binary: pathlib.Path) -> subprocess.CompletedProcess:
        compiler = shutil.which("c++") or shutil.which("clang++")
        if compiler and os.name != "nt":
            compiled = subprocess.run([compiler, *args, "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            return executed
        if os.name == "nt":
            full_args = [*args, "-o", str(binary)]
            linux_args = [
                ("-I" + _wsl_path(pathlib.Path(arg[2:])))
                if arg.startswith("-I") and len(arg) > 3 and arg[3] == ":"
                else _wsl_path(pathlib.Path(arg))
                if len(arg) > 2 and arg[1] == ":"
                else arg
                for arg in full_args
            ]
            command = " ".join(map(shlex.quote, ["/usr/bin/c++", *linux_args]))
            compiled = subprocess.run(["wsl.exe", "-e", "sh", "-lc", command], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(["wsl.exe", "-e", _wsl_path(binary)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            return executed
        self.skipTest("host C++ compiler required")

    def test_real_loaded_callback_authority(self):
        harness = r'''
#include "module_runtime.cpp"
#include "controller_fixtures/generated_controllers.h"
#include <cassert>
#include <iostream>
void dm_android_state_accessor() {}
void dm_android_dispatch_gate() {}
using namespace dm_android;
bool resolve(const char*,bool forced,uintptr_t* address,void*){if(forced)return false;*address=reinterpret_cast<uintptr_t>(&dm_android_state_accessor);return true;}
int main(){std::string error;std::unique_ptr<ModulePackage> package;
 assert(decode_package(dm_controller_bytes,dm_controller_size,dm_controller_package_sha256,&package,&error));
 ModuleDynamic dynamic;assert(parse_dynamic(*package,&dynamic,&error));std::vector<uint64_t> roots;
 for(const auto& symbol:dynamic.symbols)if(symbol.st_shndx&&symbol.st_shndx!=SHN_ABS&&ELF64_ST_TYPE(symbol.st_info)==STT_FUNC)roots.push_back(symbol.st_value);
 std::sort(roots.begin(),roots.end());roots.erase(std::unique(roots.begin(),roots.end()),roots.end());assert(roots.size()>1);
 TrustedCallbackAudit audit;audit.source_sha256=package->source_sha256;std::copy_n(dm_controller_package_sha256,32,audit.package_sha256.begin());audit.indirect_policy=CallbackIndirectPolicy::GuardedHost;audit.roots=roots.data();audit.root_count=roots.size();
 if(!decode_package_with_callback_audit(dm_controller_bytes,dm_controller_size,dm_controller_package_sha256,audit,&package,&error)){std::cerr<<error;return 1;}
 Process process;std::vector<std::unique_ptr<ModulePackage>> packages;packages.push_back(std::move(package));
 if(!process.load(std::move(packages),resolve,nullptr,&error)){std::cerr<<error;return 1;}
 assert(process.loaded_callback_roots_match(0,audit));assert(!process.loaded_callback_roots_match(1,audit));
 auto altered=audit;altered.root_count--;assert(!process.loaded_callback_roots_match(0,altered));
 auto extra=roots;extra.push_back(0xffff);altered=audit;altered.roots=extra.data();altered.root_count=extra.size();assert(!process.loaded_callback_roots_match(0,altered));
 auto changed=roots;changed[0]^=4;altered=audit;altered.roots=changed.data();assert(!process.loaded_callback_roots_match(0,altered));
 altered=audit;altered.indirect_policy=CallbackIndirectPolicy::Strict;assert(!process.loaded_callback_roots_match(0,altered));
 altered=audit;altered.source_sha256[0]^=1;assert(!process.loaded_callback_roots_match(0,altered));
 altered=audit;altered.package_sha256[0]^=1;assert(!process.loaded_callback_roots_match(0,altered));
 process.modules()[0]->package->bytes[0]^=1;assert(!process.loaded_callback_roots_match(0,audit));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            (d / "callbacks.cpp").write_text(harness)
            args = [
                "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                f"-I{ROOT / 'dm/platform/android'}",
                str(d / "callbacks.cpp"),
                *(str(ROOT / "dm/platform/android" / name) for name in
                  ("guest_loader.cpp", "guest_contract_wire.cpp", "module_sha256.cpp", "observation_profile.cpp")),
            ]
            self._compile_and_run(args, d / "callbacks")

    def test_real_initializer_order_and_failure_guards(self):
        # Include the implementation to construct its private dynamic metadata
        # type, without adding any production authority or testing entry point.
        harness = r'''
#include "module_runtime.cpp"
#include <cassert>
void dm_android_guest_unload(DmGuestLoadedImage*) {}
using namespace dm_android;
struct Calls {Process* process;std::vector<uintptr_t> entries;bool fail=false;bool reenter=false;};
bool capture(uintptr_t entry,void* opaque,std::string* error){
 auto& c=*static_cast<Calls*>(opaque);c.entries.push_back(entry);
 if(c.reenter){c.reenter=false;assert(!c.process->run_initializers(capture,&c,error,InitializerOrder::Reverse));}
 return !c.fail;
}
void populate(Process& p){
 auto& modules=const_cast<std::vector<std::unique_ptr<LoadedModule>>&>(p.modules());
 for(size_t i=0;i<3;++i){auto m=std::make_unique<LoadedModule>();m->mapping.base=reinterpret_cast<void*>((i+1)*0x1000);m->dynamic=std::make_unique<ModuleDynamic>();m->dynamic->init=0x30;modules.push_back(std::move(m));}
}
int main(){std::string error;
 {Process p;populate(p);Calls c{&p,{},false,true};assert(p.run_initializers(capture,&c,&error,InitializerOrder::Reverse));assert((c.entries==std::vector<uintptr_t>{0x3030,0x2030,0x1030}));assert(p.run_initializers(capture,&c,&error));assert(c.entries.size()==3);}
 {Process p;populate(p);Calls c{&p,{}};assert(p.run_initializers(capture,&c,&error));assert((c.entries==std::vector<uintptr_t>{0x1030,0x2030,0x3030}));}
 {Process p;populate(p);Calls c{&p,{},true};assert(!p.run_initializers(capture,&c,&error,InitializerOrder::Reverse));assert((c.entries==std::vector<uintptr_t>{0x3030}));c.fail=false;assert(!p.run_initializers(capture,&c,&error));assert(c.entries.size()==1);}
 {Process p;populate(p);Calls c{&p,{}};assert(!p.run_initializers(capture,&c,&error,static_cast<InitializerOrder>(42)));assert(c.entries.empty());assert(p.run_initializers(capture,&c,&error));}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            (d / "initializers.cpp").write_text(harness)
            args = [
                "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                f"-I{ROOT / 'dm/platform/android'}",
                str(d / "initializers.cpp"),
            ]
            self._compile_and_run(args, d / "initializers")

    def test_native_contract(self):
        identity = json.loads((ROOT / "docs/TAIKO_CONTENT_IDENTITY.json").read_text(encoding="utf-8"))

        def digest(value):
            return "{" + ",".join("0x" + value[i:i+2] for i in range(0, 64, 2)) + "}"

        sources = []
        for name in ("main", "subsdk0", "sdk"):
            s = identity["sources"][name]
            sources.append('{"%s",%s,one,%s,%d}' % (name, digest(s["sha256"]), digest(s["build_id"]), s["file_bytes"]))
        rtld = identity["sources"]["rtld"]
        harness = r'''
#include "guest_bootstrap.h"
#include <cassert>
#include <iostream>
namespace dm_android {
struct ModuleDynamic {};
LoadedModule::LoadedModule() = default;
LoadedModule::~LoadedModule() = default;
Process::~Process() = default;
static const std::array<uint8_t,32> zero{};
static const std::array<uint8_t,32> one{1};
bool Process::load(std::vector<std::unique_ptr<ModulePackage>> p, HostResolver, void*, std::string*, const ModuleLimits&) {
  modules_.clear(); for(auto& item:p){auto m=std::make_unique<LoadedModule>();m->mapping.base=reinterpret_cast<void*>((modules_.size()+1)*0x10000000);m->package=std::move(item);modules_.push_back(std::move(m));} load_generation_=1;return true;
}
static bool wrong_entry=false,main_exits=false,roots_match=true,sdk_admitted=true;
static uint32_t frozen_flag_xor=0;
static uint64_t frozen_exact_xor=0,frozen_retire_xor=0;
static uint8_t frozen_audit_xor=0;
bool Process::loaded_package_authority(size_t index, LoadedPackageAuthority* f) const {
  if(index>=modules_.size()||!f)return false;
  const auto& p=*modules_[index]->package;
  f->checked_stack=p.checked_stack;
  f->callback_audited=true;
  f->capsule_sha256=one;
  f->capsule_bytes=4;
  f->required_flags=p.required_flags^frozen_flag_xor;
  f->guest_contract_admitted=(index==2)?sdk_admitted:false;
  f->exact_guest_count=p.exact_guest_records.size()^frozen_exact_xor;
  f->returning_retire_count=p.returning_retire_records.size()^frozen_retire_xor;
  f->exact_guest_table_sha256=p.exact_guest_table_sha256;
  f->returning_retire_table_sha256=p.returning_retire_table_sha256;
  f->final_independent_roots_sha256=p.final_independent_roots_sha256;
  f->whole_function_ownership_proof_sha256=p.whole_function_ownership_proof_sha256;
  f->guest_contract_audit_identity=(index==2)?one:zero;
  f->guest_contract_audit_identity[0]^=frozen_audit_xor;
  return true;
}
bool Process::loaded_callback_roots_match(size_t,const TrustedCallbackAudit&) const{return roots_match;}
static std::vector<std::string> calls;
bool Process::symbol(const char*,uintptr_t*) const{return false;}
bool Process::module_symbol(size_t index,const char* name,uintptr_t* address) const{
 for(const auto& step:taiko_startup_plan()) {
  if(step.kind==TaikoStartupKind::Guest&&step.module_index==index&&std::string(name)==step.name){*address=reinterpret_cast<uintptr_t>(modules_[index]->mapping.base)+step.offset+(wrong_entry?4:0);return true;}
 }return false;
}
bool Process::callback_root(uint64_t) const{return true;}
bool Process::checked_stack_entry(uintptr_t) const{return true;}
const DmGuestGate* Process::gate_resolver(void*,uint64_t){return nullptr;}
bool Process::run_initializers(InitRunner runner,void* context,std::string* error,InitializerOrder order){
 assert(order==InitializerOrder::Reverse);for(size_t i=3;i-->0;)if(!runner(reinterpret_cast<uintptr_t>(modules_[i]->mapping.base)+0x30,context,error))return false;return true;
}
bool DiagnosticAuthority::bind(const Process&,const BootstrapSession*,std::string*){return false;}
bool DiagnosticAuthority::validate(const Process&,const BootstrapSession*,std::string*)const{return false;}
bool OriginalBringupAuthority::bind(const Process&,const BootstrapSession*,std::string*){return false;}
bool OriginalBringupAuthority::validate(const Process&,const BootstrapSession*,std::string*)const{return false;}
GuestEnvironment::GuestEnvironment()=default;
GuestStack::GuestStack(size_t){mapping_=reinterpret_cast<void*>(1);}
GuestStack::~GuestStack()=default;
bool GuestStack::call(DmGuestThreadState&,uintptr_t entry,uint64_t arg,GuestCallResult* result,std::string*){
 result->value=reinterpret_cast<uint64_t(*)(uint64_t)>(entry)(arg);return true;
}
bool GuestStack::call(DmGuestThreadState&,uintptr_t entry,const uint64_t* args,size_t count,GuestCallResult* result,std::string*){
 for(const auto& step:taiko_startup_plan())if(step.kind==TaikoStartupKind::Guest&&entry==(step.module_index+1)*0x10000000+step.offset){
  calls.emplace_back(step.name);if(std::string(step.name)=="nnosInitialize"){assert(count==2&&args[0]==0x88&&args[1]==0x999);}
  if(std::string(step.name)=="nnMain")result->exited=main_exits;
  return true;
 }
 calls.emplace_back("DT_INIT:"+std::to_string(entry/0x10000000));return true;
}
static const uint64_t roots[]{0};
static TaikoSourcePin sources[]{SOURCES};
static const TrustedGuestContractAuditV1 zero_contract_audit{};
static const TrustedGuestContractAuditV1 sdk_contract_audit{
  1,0,one,sources[2].source_sha256,sources[2].build_id,one,one,5,one,2,one,one,one
};
static TaikoModulePin modules[]{
 {"main",one,one,4,4,{1,one,sources[0].source_sha256,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1},1u,0,zero,0,zero,zero_contract_audit},
 {"subsdk0",one,one,4,4,{1,one,sources[1].source_sha256,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1},1u,0,zero,0,zero,zero_contract_audit},
 {"sdk",one,one,4,4,{1,one,sources[2].source_sha256,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1},1u|DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1,5,one,2,one,sdk_contract_audit}};
[[maybe_unused]] static TaikoBuildPins pins{2,"Taiko/01002460135A4000/Stock-v1","01002460135A4000",NPDM,{"rtld",RTLDSHA,one,RTLDBUILD,RTLDBYTES},sources,3,modules,3,one,one};
#ifndef NO_PROVIDER
const TaikoBuildPins* compiled_taiko_bringup_pins(){return &pins;}
#endif
}
int main(){using namespace dm_android; std::string error; Process process;
#ifdef NO_PROVIDER
 assert(!taiko_bringup_build());assert(!taiko_bringup_graph(process,&error));std::cout<<"absent provider rejected\n";return 0;
#else
 assert(taiko_bringup_build());
 pins.schema=1;assert(!taiko_bringup_build());pins.schema=2;
 modules[0].exact_guest_count=1;assert(!taiko_bringup_build());modules[0].exact_guest_count=0;
 modules[1].returning_retire_count=1;assert(!taiko_bringup_build());modules[1].returning_retire_count=0;
 modules[0].required_flags|=DM_MODULE_REQUIRE_EXACT_GUEST_V1;assert(!taiko_bringup_build());modules[0].required_flags=1u;
 modules[2].exact_guest_count=4;assert(!taiko_bringup_build());modules[2].exact_guest_count=5;
 modules[2].returning_retire_count=1;assert(!taiko_bringup_build());modules[2].returning_retire_count=2;
 modules[2].required_flags=1u|DM_MODULE_REQUIRE_EXACT_GUEST_V1;assert(!taiko_bringup_build());
 modules[2].required_flags=1u|DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1;
 modules[2].guest_contract_audit.exact_guest_count=4;assert(!taiko_bringup_build());modules[2].guest_contract_audit.exact_guest_count=5;
 modules[2].guest_contract_audit.audit_identity_sha256=zero;assert(!taiko_bringup_build());modules[2].guest_contract_audit.audit_identity_sha256=one;
 std::vector<std::unique_ptr<ModulePackage>> packages;
 for(size_t i=0;i<3;++i){
  auto p=std::make_unique<ModulePackage>();
  p->name=sources[i].name;p->wire_version=3;p->checked_stack=true;
  p->build_id=sources[i].build_id;p->source_sha256=sources[i].source_sha256;
  p->image_sha256=one;p->bytes.resize(4);
  p->segments.push_back({0,0x1000000,DM_GUEST_READ|DM_GUEST_EXEC});
  if(i==2){
   p->required_flags=DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1;
   p->exact_guest_records.resize(5);
   for(size_t g=0;g<5;++g){
    p->exact_guest_records[g].gate_return_offset=0x4000+g*32;
    p->exact_guest_records[g].original_br_offset=0x1000+g*16;
    p->exact_guest_records[g].original_br_word=0xD61F0220;
    p->exact_guest_records[g].target_register=17;
    p->gates.push_back({0x4000+g*32,DM_GUEST_EXACT_GUEST,17});
   }
   p->returning_retire_records.resize(2);
   p->exact_guest_table_sha256=one;
   p->returning_retire_table_sha256=one;
   p->final_independent_roots_sha256=one;
   p->whole_function_ownership_proof_sha256=one;
  }
  packages.push_back(std::move(p));
 }
 assert(process.load(std::move(packages),nullptr,nullptr,&error));assert(taiko_bringup_graph(process,&error));
 pins.program_id="0100000000000000";assert(!taiko_bringup_build());pins.program_id="01002460135A4000";
 pins.rtld.source_sha256[0]^=1;assert(!taiko_bringup_build());pins.rtld.source_sha256[0]^=1;
 sources[0].source_sha256[0]^=1;assert(!taiko_bringup_build());sources[0].source_sha256[0]^=1;
 pins.npdm_sha256[0]^=1;assert(!taiko_bringup_build());pins.npdm_sha256[0]^=1;
 std::swap(modules[0],modules[1]);assert(!taiko_bringup_build());std::swap(modules[0],modules[1]);
 auto& p=*process.modules()[0]->package;
 p.source_sha256[0]^=1;assert(!taiko_bringup_graph(process,&error));p.source_sha256[0]^=1;
 p.name="sdk";assert(!taiko_bringup_graph(process,&error));p.name="main";
 p.wire_version=2;assert(!taiko_bringup_graph(process,&error));p.wire_version=3;
 p.profile_class=1;assert(!taiko_bringup_graph(process,&error));p.profile_class=0;
 p.profile_digest[0]=1;assert(!taiko_bringup_graph(process,&error));p.profile_digest[0]=0;
 roots_match=false;assert(!taiko_bringup_graph(process,&error));roots_match=true;
 p.gates.push_back({0,DM_GUEST_OBSERVATION,1});assert(!taiko_bringup_graph(process,&error));p.gates.clear();
 p.gates.push_back({0,DM_GUEST_SVC,0x80});assert(!taiko_bringup_graph(process,&error));p.gates.clear();
 p.gates.push_back({0x4000,DM_GUEST_EXACT_GUEST,17});assert(!taiko_bringup_graph(process,&error));p.gates.clear();
 sdk_admitted=false;assert(!taiko_bringup_graph(process,&error));sdk_admitted=true;
 frozen_flag_xor=DM_MODULE_REQUIRE_EXACT_GUEST_V1;assert(!taiko_bringup_graph(process,&error));frozen_flag_xor=0;
 frozen_exact_xor=1;assert(!taiko_bringup_graph(process,&error));frozen_exact_xor=0;
 frozen_retire_xor=1;assert(!taiko_bringup_graph(process,&error));frozen_retire_xor=0;
 frozen_audit_xor=1;assert(!taiko_bringup_graph(process,&error));frozen_audit_xor=0;
 assert(taiko_bringup_graph(process,&error));
 const auto& plan=taiko_startup_plan();
 assert(plan.size()==10);assert(std::string(plan[0].name)=="_init_libc0");
 assert(std::string(plan[1].name)=="nnosInitialize");assert(plan[1].module_index==2&&plan[1].offset==0x37f160);
 assert(plan[2].kind==TaikoStartupKind::HostLoaderReady);
 assert(std::string(plan[3].name)=="_init_libc1");assert(std::string(plan[4].name)=="nninitInitializeSdkModule");
 assert(plan[5].module_index==0&&plan[5].offset==0x300dc0);
 assert(plan[6].name==std::string("_init_libc2"));assert(plan[7].kind==TaikoStartupKind::ReverseModuleInitializers);
 assert(plan[8].kind==TaikoStartupKind::PlatformAttachment);assert(plan[9].module_index==0&&plan[9].offset==0x300e60);
 GuestEnvironment env;env.state.dispatch=+[](DmGuestThreadState*,DmGuestRegisterFrame*,const DmGuestGate*){};GuestStack stack(0x10000);BootstrapArguments arguments({"Taiko"});BootstrapHooks hooks;
 hooks.register_main_thread=+[](DmGuestThreadState&,uint64_t* handle,uint64_t* area,void*,std::string*){*handle=0x88;*area=0x999;return true;};
 hooks.before_main=+[](Process&,DmGuestThreadState&,void*,std::string*){calls.emplace_back("platform");return true;};
 BootstrapResult result;BootstrapSession session;assert(session.authorize_taiko_bringup(process,&error));
 wrong_entry=true;assert(!session.run(process,env,stack,arguments,hooks,&result,&error));assert(calls.empty());wrong_entry=false;
 p.source_sha256[0]^=1;assert(!session.run(process,env,stack,arguments,hooks,&result,&error));assert(calls.empty());p.source_sha256[0]^=1;
 assert(!session.run(process,env,stack,arguments,hooks,&result,&error));assert(error.find("teardown are unavailable")!=std::string::npos);
 assert((calls==std::vector<std::string>{"_init_libc0","nnosInitialize","_init_libc1","nninitInitializeSdkModule","nninitStartup","_init_libc2","DT_INIT:3","DT_INIT:2","DT_INIT:1","platform","nnMain"}));
 assert(result.completed_steps[3]=="taiko_host_loader_ready");assert(!session.run(process,env,stack,arguments,hooks,&result,&error));assert(error.find("already started")!=std::string::npos);
 calls.clear();main_exits=true;BootstrapSession exited;assert(exited.authorize_taiko_bringup(process,&error));assert(exited.run(process,env,stack,arguments,hooks,&result,&error));assert(result.main_result.exited);
 std::cout<<"strict identity, stock capsule, and startup plan checks passed\n";
#endif
}
'''
        for key, value in {"SOURCES": ",".join(sources), "NPDM": digest(identity["npdm_sha256"]),
                           "RTLDSHA": digest(rtld["sha256"]), "RTLDBUILD": digest(rtld["build_id"]),
                           "RTLDBYTES": str(rtld["file_bytes"])}.items():
            harness = harness.replace(key, value)
        with tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            (d / "contract.cpp").write_text(harness)
            for absent in (False, True):
                binary = d / ("absent" if absent else "contract")
                args = [
                    "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    f"-I{ROOT / 'dm/platform/android'}",
                    str(d / "contract.cpp"),
                    str(ROOT / "dm/platform/android/taiko_bringup.cpp"),
                    str(ROOT / "dm/platform/android/guest_bootstrap.cpp"),
                ]
                if absent:
                    args.insert(0, "-DNO_PROVIDER")
                result = self._compile_and_run(args, binary)
                self.assertIn("absent provider rejected" if absent else "startup plan checks passed", result.stdout)

    def test_real_loaded_v3_combined_callback_and_guest_contract_authority_and_diagnostic_equality(self):
        from unittest.mock import patch
        import android_guest_contract as contract
        import android_import as importer
        from test_android_guest_contract_v3_dispatch import build_synthetic_v3_sdk

        c_bytes = lambda data: '{' + ','.join(str(b) for b in data) + '}'
        c_arr32 = lambda hex_str: '{{' + ','.join(str(b) for b in bytes.fromhex(hex_str)) + '}}'

        sdk_source, spec = build_synthetic_v3_sdk()
        with patch.object(contract, "TAIKO_SDK_GUEST_CONTRACT_SPEC", spec):
            sdk_pkg, sdk_rep = importer.import_module(
                sdk_source, "sdk", package_version=3,
                indirect_policy="guarded-host", callback_audit=True, checked_stack=True,
            )
        cb = sdk_rep["callback_audit"]
        gca = sdk_rep["guest_contract_audit"]

        harness = f'''
#include "module_runtime.cpp"
#include "diagnostic_authority.cpp"
#include <cassert>
#include <iostream>
void dm_android_state_accessor() {{}}
void dm_android_dispatch_gate() {{}}
using namespace dm_android;
bool resolve(const char*,bool forced,uintptr_t* address,void*){{if(forced)return false;*address=reinterpret_cast<uintptr_t>(&dm_android_state_accessor);return true;}}
int main(){{
 static const uint8_t pkg_bytes[]={c_bytes(sdk_pkg)};
 static const std::array<uint8_t,32> pkg_sha={c_arr32(sdk_rep["package_sha256"])};
 static const std::array<uint8_t,32> src_sha={c_arr32(sdk_rep["source_sha256"])};
 static const std::array<uint8_t,32> build_id={c_arr32(sdk_rep["build_id"])};
 static const std::array<uint8_t,32> recipe_sha={c_arr32(gca["toolset_recipe_sha256"])};
 static const std::array<uint8_t,32> exact_sha={c_arr32(gca["exact_guest"]["table_sha256"])};
 static const std::array<uint8_t,32> retire_sha={c_arr32(gca["returning_retire"]["table_sha256"])};
 static const std::array<uint8_t,32> roots_sha={c_arr32(gca["final_independent_roots_sha256"])};
 static const std::array<uint8_t,32> proof_sha={c_arr32(gca["whole_function_ownership_proof_sha256"])};
 static const std::array<uint8_t,32> id_sha={c_arr32(gca["audit_identity_sha256"])};
 static const uint64_t cb_roots[]={{{",".join(f"0x{r:x}ULL" for r in cb["callback_roots"])}}};
 TrustedCallbackAudit cb_audit{{1,pkg_sha,src_sha,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,cb_roots,{len(cb["callback_roots"])}}};
 TrustedGuestContractAuditV1 gc_audit{{1,0,pkg_sha,src_sha,build_id,recipe_sha,id_sha,5,exact_sha,2,retire_sha,roots_sha,proof_sha}};
 std::string error; std::unique_ptr<ModulePackage> package;
 if(!decode_package_with_audits(pkg_bytes,sizeof(pkg_bytes),pkg_sha.data(),&cb_audit,&gc_audit,&package,&error)){{
  std::cerr<<"decode_package_with_audits failed: "<<error<<"\\n";return 1;
 }}
 Process process; std::vector<std::unique_ptr<ModulePackage>> packages; packages.push_back(std::move(package));
 if(!process.load(std::move(packages),resolve,nullptr,&error)){{
  std::cerr<<"Process::load failed: "<<error<<"\\n";return 1;
 }}
 LoadedPackageAuthority auth{{}};
 assert(process.loaded_package_authority(0,&auth));
 assert(auth.checked_stack&&auth.callback_audited&&auth.guest_contract_admitted);
 assert(auth.required_flags==(DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1));
 assert(auth.exact_guest_count==5&&auth.returning_retire_count==2);
 assert(auth.exact_guest_table_sha256==exact_sha&&auth.returning_retire_table_sha256==retire_sha);
 assert(auth.final_independent_roots_sha256==roots_sha&&auth.whole_function_ownership_proof_sha256==proof_sha);
 assert(auth.guest_contract_audit_identity==id_sha);
 assert(process.loaded_callback_roots_match(0,cb_audit));
 auto& live_pkg=*process.modules()[0]->package;
 ModulePackage copy_pkg=live_pkg;
 assert(equal_package(live_pkg,copy_pkg));
 copy_pkg.exact_guest_table_sha256[0]^=1;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 copy_pkg.returning_retire_table_sha256[0]^=1;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 copy_pkg.final_independent_roots_sha256[0]^=1;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 copy_pkg.whole_function_ownership_proof_sha256[0]^=1;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 copy_pkg.exact_guest_records[0].same_module_target_offset+=4;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 copy_pkg.returning_retire_records[0].reserved_stub_offset+=4;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 copy_pkg.required_flags^=DM_MODULE_REQUIRE_EXACT_GUEST_V1;assert(!equal_package(live_pkg,copy_pkg));copy_pkg=live_pkg;
 std::cout<<"v3 combined callback + guest contract authority + diagnostic equality PASS\\n";
 return 0;
}}
'''
        with tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            (d / "combined.cpp").write_text(harness)
            args = [
                "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                f"-I{ROOT / 'dm/platform/android'}",
                str(d / "combined.cpp"),
                *(str(ROOT / "dm/platform/android" / name) for name in
                  ("guest_loader.cpp", "guest_contract_wire.cpp", "module_sha256.cpp", "observation_profile.cpp")),
            ]
            result = self._compile_and_run(args, d / "combined")
            self.assertIn("v3 combined callback + guest contract authority + diagnostic equality PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()

