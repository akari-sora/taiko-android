#include "guest_thread.h"
#include "guest_stack_check.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

// Headless legacy contracts do not link an observation registry. The APK's
// strong hook forbids nonlocal thread exit through a live OBS callback.
extern "C" int dm_android_observation_callback_active() __attribute__((weak));
extern "C" int dm_android_stack_entry_reserve(const DmGuestThreadState*,uintptr_t,size_t*) __attribute__((weak));

namespace {

// This context resides on the host stack and is reached through compiler TLS.
// Only its host_frame field is read by guest_call.S; result is reached through
// the context pointer saved at offset 640 in the bridge's host frame.
struct GuestCallContext {
    uintptr_t host_frame;
    dm_android::GuestCallResult* result;
    uintptr_t stack_bottom;
    size_t stack_size;
    bool owns_stack;
    bool checked_stack;
    const DmGuestThreadState* state;
    void* gate_context;
    DmGuestGateResolver resolver;
    uint64_t generation;
};
static_assert(offsetof(GuestCallContext, host_frame) == 0);
static_assert(offsetof(GuestCallContext, result) == 8);
static_assert(offsetof(dm_android::GuestCallResult, value) == 0);
static_assert(offsetof(dm_android::GuestCallResult, exited) == 8);
thread_local GuestCallContext* active_call = nullptr;

bool fail(std::string* error, const char* message) {
    if (error) *error = message;
    return false;
}

[[noreturn]] void invalid_exit() {
    std::fputs("Android guest exit without an active host call frame\n", stderr);
    std::abort();
}

} // namespace

extern "C" void dm_android_guest_invoke(uintptr_t entry, const uint64_t* arguments,
                                         uintptr_t guest_sp, GuestCallContext* context);
extern "C" [[noreturn]] void dm_android_guest_leave(uintptr_t host_frame, uint64_t value);
extern "C" GuestCallContext* dm_android_guest_active_call() {
    if (!active_call || !active_call->host_frame) invalid_exit();
    return active_call;
}

namespace dm_android {

GuestEnvironment::GuestEnvironment() {
    state.virtual_x18 = 0;
    state.guest_tpidr_el0 = reinterpret_cast<uintptr_t>(tls_.data());
    state.guest_tpidrro_el0 = reinterpret_cast<uintptr_t>(tlr_.data());
    const uintptr_t object = reinterpret_cast<uintptr_t>(thread_object_.data());
    std::memcpy(tlr_.data() + 0x1f8, &object, sizeof(object));
    state.owned_memory[0] = {reinterpret_cast<uintptr_t>(tls_.data()), tls_.size()};
    state.owned_memory[1] = {reinterpret_cast<uintptr_t>(tlr_.data()), tlr_.size()};
    state.owned_memory[2] = {object, thread_object_.size()};
}

GuestStack::GuestStack(size_t usable_size) {
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || !usable_size) {
        error_ = "invalid guest stack size or host page size";
        return;
    }
    page_size_ = static_cast<size_t>(page);
    const size_t remainder = usable_size % page_size_;
    const size_t extra = remainder ? page_size_ - remainder : 0;
    if (page_size_ > std::numeric_limits<size_t>::max() / 2 ||
        usable_size > std::numeric_limits<size_t>::max() - extra ||
        usable_size + extra > std::numeric_limits<size_t>::max() - page_size_ * 2) {
        error_ = "guest stack size overflows mapping bounds";
        return;
    }
    usable_size_ = usable_size + extra;
    mapping_size_ = usable_size_ + page_size_ * 2;
    void* region = mmap(nullptr, mapping_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        error_ = std::string("cannot reserve guest stack: ") + std::strerror(errno);
        return;
    }
    if (mprotect(static_cast<uint8_t*>(region) + page_size_, usable_size_, PROT_READ | PROT_WRITE)) {
        const int cause = errno;
        munmap(region, mapping_size_);
        error_ = std::string("cannot protect guest stack: ") + std::strerror(cause);
        return;
    }
    mapping_ = region;
}

GuestStack::GuestStack(void* bottom, size_t usable_size) : owns_mapping_(false) {
    const uintptr_t address = reinterpret_cast<uintptr_t>(bottom);
    if (!address || address % 16 || usable_size < 4096 || usable_size % 16 ||
        usable_size > std::numeric_limits<uintptr_t>::max() - address) {
        error_ = "invalid borrowed SDK stack span";
        return;
    }
    mapping_ = bottom;
    mapping_size_ = usable_size_ = usable_size;
}

GuestStack::~GuestStack() {
    // Unmapping an executing guest stack would invalidate its whole call chain.
    // Ownership requires callers to join before destruction; never force cancel.
    if (active_.load(std::memory_order_acquire)) std::abort();
    if (mapping_ && owns_mapping_) munmap(mapping_, mapping_size_);
}

uintptr_t GuestStack::top() const {
    return mapping_ ? reinterpret_cast<uintptr_t>(mapping_) + page_size_ + usable_size_ : 0;
}

bool GuestStack::call(DmGuestThreadState& state, uintptr_t entry, uint64_t arg,
                      GuestCallResult* result, std::string* error) {
    return call(state, entry, &arg, 1, result, error);
}

bool GuestStack::call(DmGuestThreadState& state, uintptr_t entry, const uint64_t* args,
                      size_t count, GuestCallResult* result, std::string* error) {
    if (error) error->clear();
    if (!valid()) return fail(error, error_.c_str());
    if (!entry || entry % 4 || !result || top() % 16)
        return fail(error, "invalid guest entry, result, or stack alignment");
    if (count > 8 || (count && !args)) return fail(error, "invalid guest call arguments");
    if (active_call) return fail(error, "nested guest stack calls are unsupported");
    const auto enter = state.invocation_enter;
    const auto leave = state.invocation_leave;
    void* const invocation_context = state.invocation_context;
    if ((enter == nullptr) != (leave == nullptr))
        return fail(error, "guest invocation lifetime callbacks must be paired");
    bool expected = false;
    if (!active_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return fail(error, "guest stack is already executing");
    if (enter && !enter(invocation_context)) {
        active_.store(false, std::memory_order_release);
        return fail(error, "guest runtime is closing");
    }
    size_t reserve=0;
    const int checked=dm_android_stack_entry_reserve?dm_android_stack_entry_reserve(&state,entry,&reserve):0;
    if(checked<0 || (checked && usable_size_<reserve)) {
        active_.store(false,std::memory_order_release);
        if(leave) leave(invocation_context);
        return fail(error,"invalid checked-stack context or insufficient guest stack headroom");
    }
    *result = {};
    uint64_t arguments[8]{};
    if (count) std::memcpy(arguments, args, count * sizeof(uint64_t));
    GuestCallContext context{0, result, reinterpret_cast<uintptr_t>(mapping_) + page_size_, usable_size_, owns_mapping_,checked!=0,&state,
                             state.gate_context,state.gate_resolver,state.runtime_generation};
    DmGuestThreadState* previous = dm_android_attach_guest_state(&state);
    active_call = &context;
    dm_android_guest_invoke(entry, arguments, top(), &context);
    // Both normal return and ExitThread restore this host stack before arriving
    // here, so ordinary host cleanup runs exactly once without guest unwinding.
    active_call = nullptr;
    dm_android_attach_guest_state(previous);
    active_.store(false, std::memory_order_release);
    if (leave) leave(invocation_context);
    return true;
}

[[noreturn]] void guest_exit(uint64_t value) {
    if (dm_android_observation_callback_active && dm_android_observation_callback_active()) {
        std::fputs("Android observation callbacks must return normally; ExitThread is unsupported\n", stderr);
        std::abort();
    }
    GuestCallContext* context = dm_android_guest_active_call();
    dm_android_guest_leave(context->host_frame, value);
}

bool active_guest_stack_bounds(uintptr_t address, uintptr_t* bottom, size_t* size) {
    if (!active_call || !bottom || !size || address < active_call->stack_bottom ||
        address - active_call->stack_bottom >= active_call->stack_size) return false;
    *bottom = active_call->stack_bottom;
    *size = active_call->stack_size;
    return true;
}

bool active_guest_stack_owned_bounds(uintptr_t address, uintptr_t* bottom, size_t* size) {
    return active_call && active_call->owns_stack && active_guest_stack_bounds(address, bottom, size);
}

} // namespace dm_android

extern "C" bool dm_android_validate_stack_check(const DmGuestRegisterFrame* frame,uint32_t word) {
    return frame && active_call && active_call->checked_stack &&
           active_call->state==dm_android_peek_guest_state() &&
           dm_android_stack_dispatch_context(active_call->state) &&
           dm_android_stack_candidate(*frame,word,active_call->stack_bottom,active_call->stack_size);
}
extern "C" bool dm_android_stack_dispatch_context(const DmGuestThreadState* state) {
    if(!active_call || !active_call->checked_stack) return true;
    return state==active_call->state && state->gate_context==active_call->gate_context &&
           state->gate_resolver==active_call->resolver && state->runtime_generation==active_call->generation;
}
