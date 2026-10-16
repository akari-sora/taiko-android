#pragma once
#include "kernel_runtime.h"
#include <array>
#include <string_view>
namespace dm_android {
// Owned by the checked SDK request's RuntimeReadLease, never a guest pointer.
class OriginalNameRequest {
public:
    enum class Admission { Ordinary, Ready, Refused };
    Admission prepare(const Process&,const GuestHleOrigin*,uint64_t config);
    bool active() const {return process_!=nullptr;}
    bool unchanged() const;
    bool disjoint(uint64_t address,size_t bytes) const;
    // Call only after unchanged() and all SDK output checks in the same broker
    // publication transaction. No guest code, callbacks or allocations here.
    void commit_filter(std::string_view text) noexcept;
private:
    GuestHleOrigin origin_;
    const Process* process_=nullptr;
    const DmGuestThreadState* state_=nullptr;
    uint64_t generation_=0,address_=0;
    std::array<uint8_t,0x28> snapshot_{};
};
}
extern "C" uint32_t dm_android_swkbd_show_from_guest(void*,const void*,uint64_t,uintptr_t);
extern "C" int dm_android_character_isalpha_from_guest(int,uint64_t,uintptr_t);
