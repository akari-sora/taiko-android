#include "original_name.h"
#include "original_bringup.h"
#include "keyboard_platform.h"
#include <cstring>
extern "C" void dm_android_character_isalpha_entry();
extern "C" {
#include "../../host/hle.h"
__attribute__((used,aligned(8),section("swforce"))) static const hle_force_ent character_isalpha = {
    "isalpha",reinterpret_cast<void*>(&dm_android_character_isalpha_entry),
    "Original offline character names: exact main BL/PLT origins and current source only"};
}
namespace dm_android {
namespace {
constexpr uint64_t config_offset=0x32137f0,filter_offset=0x3213dd8;
constexpr uint64_t filter_vtable=0x20b7758,filter_function=0xe09190;
constexpr std::array<uint8_t,32> main_source={
    0x55,0xfd,0x90,0x9b,0xb7,0x23,0x0b,0x00,0x23,0x57,0xe5,0xb0,0xd8,0x49,0x9c,0x11,
    0xf0,0x68,0x88,0xf3,0x45,0xc4,0x9e,0x69,0xeb,0x47,0x34,0xdf,0x44,0xa2,0x7d,0x0e};
bool source_current(const Process& process,uint64_t* base) {
    if(!base||!original_bringup_graph(process,nullptr))return false;
    const auto& module=*process.modules().front();
    if(module.package->source_sha256!=main_source)return false;
    *base=reinterpret_cast<uint64_t>(module.mapping.base);return true;
}
bool inline_name_filter(const std::array<uint8_t,0x28>& object,uint64_t base,uint64_t invoke) {
    uint64_t tag=0,function=0;std::memcpy(&tag,object.data(),8);std::memcpy(&function,object.data()+8,8);
    return base<=UINT64_MAX-filter_offset-object.size()&&tag==base+filter_vtable&&
        function==base+filter_function&&invoke==base+0xaa1eb4;
}
bool name_isalpha_callsite(uint64_t offset) {
    // All BL-to-isalpha sites in the five original validation functions.
    // Exact sites are narrower than iOS's function-interval return-PC check.
    constexpr uint64_t sites[]={
        0x7fe9f0,0x7fea0c,0x7fea64,0x7fea74,0x7fedbc,0x7fedd8,0x7feeb4,0x7feec4,
        0x8087d4,0x8087f0,0x8093b0,0x8093c0,0x6f0db4,0x6fe858,0x6fe874,0x6fe950,
        0x6fe968,0x6fe998,0x6fedf8,0x6fee14,0x6feef0,0x6fef04,0x6fef30,0x6fefd4,
        0x6feff0,0x6ff0cc,0x6ff0e4,0x6ff114,0x6ff1f4,0x6ff204,0x6ff64c,0x6ff65c,
        0x6ff778,0x6ff788};
    for(auto site:sites)if(site==offset)return true;return false;
}
}
OriginalNameRequest::Admission OriginalNameRequest::prepare(const Process& process,const GuestHleOrigin* origin,uint64_t config) {
    *this={};uint64_t base=0,site=0;
    if(!source_current(process,&base)||config!=base+config_offset)return Admission::Ordinary;
    if(base>UINT64_MAX-filter_offset-snapshot_.size()||
       !process.mapped_range(base+filter_offset,snapshot_.size(),DM_GUEST_READ|DM_GUEST_WRITE))return Admission::Refused;
    std::array<uint8_t,0x28> candidate{};
    uint64_t function=0,invoke=0;
    if(!process.copy_readable(base+filter_offset,candidate.data(),candidate.size()))return Admission::Refused;
    std::memcpy(&function,candidate.data()+8,8);
    if(function!=base+filter_function)return Admission::Ordinary;
    if(!origin||!origin->main_callsite(process,&site)||site!=0x1b665ec||
       !process.copy_readable(base+filter_vtable+0x10,&invoke,8)||
       !inline_name_filter(candidate,base,invoke))return Admission::Refused;
    origin_=*origin;process_=&process;state_=dm_android_peek_guest_state();generation_=process.load_generation();
    address_=base+filter_offset;snapshot_=candidate;return Admission::Ready;
}
bool OriginalNameRequest::unchanged() const {
    if(!process_||!state_||state_!=dm_android_peek_guest_state()||
       state_->runtime_generation!=generation_||process_->load_generation()!=generation_)return false;
    uint64_t base=0,site=0;std::array<uint8_t,0x28> current{};
    return origin_.main_callsite(*process_,&site)&&site==0x1b665ec&&
        source_current(*process_,&base)&&address_==base+filter_offset&&
        process_->mapped_range(address_,current.size(),DM_GUEST_READ|DM_GUEST_WRITE)&&
        process_->copy_readable(address_,current.data(),current.size())&&current==snapshot_;
}
bool OriginalNameRequest::disjoint(uint64_t address,size_t bytes) const {
    return !active() || (address&&bytes&&bytes<=UINT64_MAX-address&&
        (address+bytes<=address_||address>=address_+snapshot_.size()));
}
void OriginalNameRequest::commit_filter(std::string_view text) noexcept {
    if(!active())return;
    // English keeps the game's exact original filter. Rules have already
    // admitted only ASCII letters/Han and one interior separator before commit.
    for(unsigned char byte:text)if(byte>=0x80) {
        const uint64_t empty=1;std::memcpy(reinterpret_cast<void*>(address_),&empty,8);return;
    }
}
}
extern "C" int dm_android_character_isalpha_from_guest(int c,uint64_t lr,uintptr_t sp) {
    const int ascii=(((static_cast<unsigned>(c)|0x20u)-unsigned('a'))<26)?1:0;
    if(ascii)return 1;
    if(!((c>=128&&c<=255)||(c>=-128&&c<0)))return 0;
    try {
    dm_android::RuntimeReadLease lifetime;
    auto* runtime=lifetime.runtime();dm_android::GuestHleOrigin origin;
    const bool received=runtime&&runtime->keyboard_entry_origin(
        reinterpret_cast<uintptr_t>(&dm_android_character_isalpha_entry),lr,sp,&origin);
    if(!received)return 0;
    // entry_origin already checked the full current frozen graph. No guest
    // code executes between that proof and this source/version comparison.
    const auto* build=dm_android::original_bringup_build();uint64_t site=0;
    return build&&build->sources[0].source_sha256==dm_android::main_source&&
        origin.main_callsite(runtime->process(),&site)&&dm_android::name_isalpha_callsite(site)?1:0;
    }catch(...){return ascii;}
}
