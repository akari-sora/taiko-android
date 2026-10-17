
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
