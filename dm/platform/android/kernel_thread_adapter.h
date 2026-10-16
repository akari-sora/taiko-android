#pragma once
#include "kernel_platform.h"

#ifdef __cplusplus
#include "guest_abi.h"
#include <cstring>

namespace dm_android {
// Captured only by the runtime's host-side configure operation. Guest-selectable
// TP values never grant ownership. The caller separately verifies the current
// live runtime/invocation before consulting this host-thread-local binding.
class NativeWaitState {
public:
    bool bind(const DmGuestThreadState& state,uint64_t generation) {
        state_=nullptr;tlr_=0;generation_=0;
        const auto& span=state.owned_memory[1];
        if(!generation || state.runtime_generation!=generation || !span.base ||
           span.size!=0x200 || (span.base&15) || span.base>UINTPTR_MAX-span.size ||
           state.guest_tpidrro_el0!=span.base)return false;
        state_=&state;tlr_=span.base;generation_=generation;return true;
    }
    bool synchronize(const DmGuestThreadState& state,uint64_t generation) const {
        if(state_!=&state || !generation_ || generation!=generation_ ||
           state.runtime_generation!=generation_ || state.owned_memory[1].base!=tlr_ ||
           state.owned_memory[1].size!=0x200 || state.guest_tpidrro_el0!=tlr_)return false;
        uint16_t interrupt_flag=0;
        std::memcpy(&interrupt_flag,reinterpret_cast<const void*>(tlr_+0x102),sizeof(interrupt_flag));
        // Android's guest threads are always preemptible and never pinned by
        // this adapter. A nonzero flag requires a pin model we do not provide.
        // Do not clear it, decrement disable_count, yield, or invent a Result.
        return interrupt_flag==0;
    }
private:
    const DmGuestThreadState* state_=nullptr;
    uintptr_t tlr_=0;
    uint64_t generation_=0;
};
// Linux arm64 HWCAP_EVTSTRM is bit 2. Pure predicate also tests the refusal
// path without pretending that a different host architecture has this ABI.
inline bool native_wait_event_stream_capable(unsigned long hwcap) {return (hwcap&(1ul<<2))!=0;}
bool native_wait_event_stream_available();
}
#endif

// Finish a main-thread attachment only AFTER GuestStack::call returned to its
// host frame. Worker attachments finish automatically after adapter cleanup.
#ifdef __cplusplus
extern "C" {
#endif
void dm_android_kernel_thread_finish_current(void);
#ifdef __cplusplus
}
#endif
