// Host contract only: real GuestEnvironment backing, no native WFE execution.
#include "../kernel_thread_adapter.h"
#include "../guest_thread.h"
#include <cassert>
#include <cstdio>
#include <cstring>

extern "C" void dm_android_guest_invoke(uintptr_t,const uint64_t*,uintptr_t,void*) { std::abort(); }
extern "C" [[noreturn]] void dm_android_guest_leave(uintptr_t,uint64_t) { std::abort(); }

int main() {
    using namespace dm_android;
    GuestEnvironment first,foreign;
    first.state.runtime_generation=7;foreign.state.runtime_generation=7;
    NativeWaitState binding;
    assert(!binding.synchronize(first.state,7));
    assert(binding.bind(first.state,7));
    auto* tlr=reinterpret_cast<uint8_t*>(first.state.owned_memory[1].base);
    // A nonzero disable count is owned guest state, not a request to yield or
    // decrement it. All bytes, including the thread-object pointer, survive.
    uint16_t count=31;
    std::memcpy(tlr+0x100,&count,sizeof(count));
    std::array<uint8_t,0x200> before{};
    std::memcpy(before.data(),tlr,before.size());
    assert(binding.synchronize(first.state,7));
    assert(!std::memcmp(before.data(),tlr,before.size()));
    // This adapter has no pinned-thread model. Never clear an unexplained flag.
    for(uint16_t flag:{uint16_t(1),uint16_t(0x8000),uint16_t(0xffff)}) {
        std::memcpy(tlr+0x102,&flag,sizeof(flag));
        std::memcpy(before.data(),tlr,before.size());
        assert(!binding.synchronize(first.state,7));
        assert(!std::memcmp(before.data(),tlr,before.size()));
    }
    std::memset(tlr+0x102,0,2);
    assert(!binding.synchronize(foreign.state,7));
    assert(!binding.synchronize(first.state,8));
    first.state.runtime_generation=8;
    assert(!binding.synchronize(first.state,7));
    first.state.runtime_generation=7;
    const auto base=first.state.owned_memory[1].base;
    first.state.owned_memory[1].base=foreign.state.owned_memory[1].base;
    assert(!binding.synchronize(first.state,7));
    first.state.owned_memory[1].base=base;
    first.state.guest_tpidrro_el0=base+2;
    assert(!binding.synchronize(first.state,7));
    first.state.guest_tpidrro_el0=base;
    first.state.owned_memory[1].size=0x1ff;
    assert(!binding.synchronize(first.state,7));
    assert(!binding.bind(first.state,7));
    first.state.owned_memory[1].size=0x200;
    assert(!binding.synchronize(first.state,7)); // failed bind revokes old view
    assert(binding.bind(first.state,7));
    assert(binding.synchronize(first.state,7));
    DmGuestThreadState missing{};
    missing.runtime_generation=7;
    assert(!binding.bind(missing,7));
    assert(!binding.synchronize(first.state,7));
    for(uintptr_t invalid:{uintptr_t(0),base+1,UINTPTR_MAX-15}) {
        first.state.owned_memory[1].base=invalid;
        first.state.guest_tpidrro_el0=invalid;
        assert(!binding.bind(first.state,7));
    }
    first.state.owned_memory[1].base=base;
    first.state.guest_tpidrro_el0=base;
    assert(binding.bind(first.state,7));
    assert(!binding.bind(first.state,0));
    assert(!binding.synchronize(first.state,7));
    assert(!native_wait_event_stream_capable(0));
    assert(!native_wait_event_stream_capable(~(1ul<<2)));
    assert(native_wait_event_stream_capable(1ul<<2));
    assert(native_wait_event_stream_capable(~0ul));
    std::puts("PASS owned TLR/no-pin validation, unchanged flag/count, stale/foreign/missing refusal and EVTSTRM mask; helper-only, no dispatch/frame/native WFE/SDK execution");
}
