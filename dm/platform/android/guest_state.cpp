#include "guest_abi.h"

#include <stdio.h>
#include <stdlib.h>
extern "C" bool dm_android_validate_stack_check(const DmGuestRegisterFrame*,uint32_t) __attribute__((weak));
extern "C" bool dm_android_stack_gate_authorized(const DmGuestThreadState*,uint64_t,const DmGuestGate*) __attribute__((weak));
extern "C" bool dm_android_stack_dispatch_context(const DmGuestThreadState*) __attribute__((weak));

namespace {
thread_local DmGuestThreadState* attached_state = nullptr;

[[noreturn]] void guest_failure(const char* reason) {
    fprintf(stderr, "Android guest ABI failure: %s\n", reason);
    abort();
}
}

extern "C" DmGuestThreadState* dm_android_attach_guest_state(DmGuestThreadState* state) {
    DmGuestThreadState* previous = attached_state;
    attached_state = state;
    return previous;
}

extern "C" DmGuestThreadState* dm_android_current_guest_state() {
    if (!attached_state) guest_failure("thread has no attached guest state");
    return attached_state;
}

extern "C" DmGuestThreadState* dm_android_peek_guest_state() { return attached_state; }

extern "C" void dm_android_dispatch_frame(DmGuestRegisterFrame* frame) {
    DmGuestThreadState* state = dm_android_current_guest_state();
    if (!frame) guest_failure("dispatch has no frame");
    if(dm_android_stack_dispatch_context && !dm_android_stack_dispatch_context(state)) __builtin_trap();
    const DmGuestGate* gate = nullptr;
    if (state->gate_resolver) {
        gate = state->gate_resolver(state->gate_context, frame->return_pc);
    } else {
        if (!state->image || !state->image->base || !state->image->source)
            guest_failure("dispatch has no image");
        const DmGuestImage& source = *state->image->source;
        const uintptr_t base = reinterpret_cast<uintptr_t>(state->image->base);
        if (frame->return_pc < base || frame->return_pc - base >= source.size)
            guest_failure("dispatch return PC is outside its image");
        const size_t offset = static_cast<size_t>(frame->return_pc - base);
        for (size_t i = 0; i < source.gate_count; ++i) {
            if (source.gates[i].return_offset == offset) {
                gate = &source.gates[i];
                break;
            }
        }
    }
    if (!gate) guest_failure("dispatch return PC has no validated gate");
    if(gate->kind==DM_GUEST_STACK_CHECK) {
        if(!dm_android_stack_gate_authorized || !dm_android_validate_stack_check ||
           !dm_android_validate_stack_check(frame,gate->argument) ||
           !dm_android_stack_gate_authorized(state,frame->return_pc,gate)) __builtin_trap();
        return; // Immutable preflight: no callback or register/SP mutation.
    }
    if(!state->dispatch) guest_failure("dispatch has no callback");
    frame->x[18] = state->virtual_x18;
    // The callback may select guest results, but cannot redirect the host return.
    const uint64_t return_pc = frame->return_pc;
    const uint64_t guest_sp = frame->guest_sp;
    state->dispatch(state, frame, gate);
    state->virtual_x18 = frame->x[18];
    frame->return_pc = return_pc;
    frame->guest_sp = guest_sp;
}
