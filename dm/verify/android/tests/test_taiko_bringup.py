"""Host tests of the real authority; synthetic capsules never execute guest code."""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]


class TaikoAuthorityTests(unittest.TestCase):
    def test_real_loaded_callback_authority(self):
        compiler = shutil.which("c++") or shutil.which("clang++")
        if not compiler:
            self.skipTest("host C++ compiler required; run under WSL on Windows")
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
            cmd = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                   "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-I", str(ROOT / "dm/platform/android"),
                   str(d / "callbacks.cpp")]
            cmd += [str(ROOT / "dm/platform/android" / name) for name in
                    ("guest_loader.cpp", "module_sha256.cpp", "observation_profile.cpp")]
            cmd += ["-o", str(d / "callbacks")]
            compiled = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(d / "callbacks")], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)

    def test_real_initializer_order_and_failure_guards(self):
        compiler = shutil.which("c++") or shutil.which("clang++")
        if not compiler:
            self.skipTest("host C++ compiler required; run under WSL on Windows")
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
            cmd = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                   "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-I", str(ROOT / "dm/platform/android"),
                   str(d / "initializers.cpp"), "-o", str(d / "initializers")]
            compiled = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            subprocess.run([str(d / "initializers")], check=True, capture_output=True, text=True)

    def test_native_contract(self):
        compiler = shutil.which("c++") or shutil.which("clang++")
        if not compiler:
            self.skipTest("host C++ compiler required; run under WSL on Windows")
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
bool Process::load(std::vector<std::unique_ptr<ModulePackage>> p, HostResolver, void*, std::string*, const ModuleLimits&) {
  modules_.clear(); for(auto& item:p){auto m=std::make_unique<LoadedModule>();m->mapping.base=reinterpret_cast<void*>((modules_.size()+1)*0x10000000);m->package=std::move(item);modules_.push_back(std::move(m));} load_generation_=1;return true;
}
bool Process::loaded_package_authority(size_t, LoadedPackageAuthority* f) const {f->checked_stack=true;f->callback_audited=true;f->capsule_sha256=std::array<uint8_t,32>{1};f->capsule_bytes=4;return true;}
static bool wrong_entry=false,main_exits=false,roots_match=true;
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
static const std::array<uint8_t,32> one{1};
static const uint64_t roots[]{0};
static TaikoSourcePin sources[]{SOURCES};
static TaikoModulePin modules[]{
 {"main",one,one,4,4,{1,one,sources[0].source_sha256,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1}},
 {"subsdk0",one,one,4,4,{1,one,sources[1].source_sha256,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1}},
 {"sdk",one,one,4,4,{1,one,sources[2].source_sha256,CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,roots,1}}};
[[maybe_unused]] static TaikoBuildPins pins{1,"Taiko/01002460135A4000/Stock-v1","01002460135A4000",NPDM,{"rtld",RTLDSHA,one,RTLDBUILD,RTLDBYTES},sources,3,modules,3,one,one};
#ifndef NO_PROVIDER
const TaikoBuildPins* compiled_taiko_bringup_pins(){return &pins;}
#endif
}
int main(){using namespace dm_android; std::string error; Process process;
#ifdef NO_PROVIDER
 assert(!taiko_bringup_build());assert(!taiko_bringup_graph(process,&error));std::cout<<"absent provider rejected\n";return 0;
#else
 assert(taiko_bringup_build());
 std::vector<std::unique_ptr<ModulePackage>> packages;
 for(size_t i=0;i<3;++i){auto p=std::make_unique<ModulePackage>();p->name=sources[i].name;p->wire_version=2;p->build_id=sources[i].build_id;p->source_sha256=sources[i].source_sha256;p->image_sha256=one;p->bytes.resize(4);p->segments.push_back({0,0x1000000,DM_GUEST_READ|DM_GUEST_EXEC});packages.push_back(std::move(p));}
 assert(process.load(std::move(packages),nullptr,nullptr,&error));assert(taiko_bringup_graph(process,&error));
 pins.program_id="0100000000000000";assert(!taiko_bringup_build());pins.program_id="01002460135A4000";
 pins.rtld.source_sha256[0]^=1;assert(!taiko_bringup_build());pins.rtld.source_sha256[0]^=1;
 sources[0].source_sha256[0]^=1;assert(!taiko_bringup_build());sources[0].source_sha256[0]^=1;
 pins.npdm_sha256[0]^=1;assert(!taiko_bringup_build());pins.npdm_sha256[0]^=1;
 std::swap(modules[0],modules[1]);assert(!taiko_bringup_build());std::swap(modules[0],modules[1]);
 auto& p=*process.modules()[0]->package;
 p.source_sha256[0]^=1;assert(!taiko_bringup_graph(process,&error));p.source_sha256[0]^=1;
 p.name="sdk";assert(!taiko_bringup_graph(process,&error));p.name="main";
 p.wire_version=1;assert(!taiko_bringup_graph(process,&error));p.wire_version=2;
 p.profile_class=1;assert(!taiko_bringup_graph(process,&error));p.profile_class=0;
 p.profile_digest[0]=1;assert(!taiko_bringup_graph(process,&error));p.profile_digest[0]=0;
 roots_match=false;assert(!taiko_bringup_graph(process,&error));roots_match=true;
 p.gates.push_back({0,DM_GUEST_OBSERVATION,1});assert(!taiko_bringup_graph(process,&error));p.gates.clear();
 p.gates.push_back({0,DM_GUEST_SVC,0x80});assert(!taiko_bringup_graph(process,&error));p.gates.clear();
 assert(taiko_bringup_graph(process,&error));
 const auto& plan=taiko_startup_plan();
 assert(plan.size()==10);assert(std::string(plan[0].name)=="_init_libc0");
 assert(std::string(plan[1].name)=="nnosInitialize");assert(plan[1].module_index==2&&plan[1].offset==0x37f160);
 assert(plan[2].kind==TaikoStartupKind::HostLoaderReady);
 assert(std::string(plan[3].name)=="_init_libc1");assert(std::string(plan[4].name)=="nninitInitializeSdkModule");
 assert(plan[5].module_index==0&&plan[5].offset==0x300dc0);
 assert(std::string(plan[6].name)=="_init_libc2");assert(plan[7].kind==TaikoStartupKind::ReverseModuleInitializers);
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
                cmd = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "dm/platform/android"),
                       str(d / "contract.cpp"), str(ROOT / "dm/platform/android/taiko_bringup.cpp"),
                       str(ROOT / "dm/platform/android/guest_bootstrap.cpp"), "-o", str(binary)]
                if absent:
                    cmd.insert(1, "-DNO_PROVIDER")
                compiled = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
                self.assertIn("absent provider rejected" if absent else "startup plan checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
