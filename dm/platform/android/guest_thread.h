// Owned guest TLS and stack invocation. Host TLS and hardware x18 stay Bionic-owned.
#pragma once
#include "guest_abi.h"
#include <array>
#include <atomic>
#include <string>

namespace dm_android {

class GuestEnvironment {
public:
    GuestEnvironment();
    GuestEnvironment(const GuestEnvironment&) = delete;
    GuestEnvironment& operator=(const GuestEnvironment&) = delete;
    GuestEnvironment(GuestEnvironment&&) = delete;
    GuestEnvironment& operator=(GuestEnvironment&&) = delete;

    DmGuestThreadState state{};

private:
    alignas(16) std::array<uint8_t, 8192> tls_{};
    alignas(16) std::array<uint8_t, 0x200> tlr_{};
    alignas(16) std::array<uint8_t, 0x400> thread_object_{};
};

struct GuestCallResult {
    uint64_t value = 0;
    bool exited = false;
};

class GuestStack {
public:
    explicit GuestStack(size_t usable_size);
    // Borrow an already validated and pinned writable SDK stack. The caller
    // retains its mapping/pin until call() has restored the host stack.
    GuestStack(void* bottom, size_t usable_size);
    ~GuestStack();
    GuestStack(const GuestStack&) = delete;
    GuestStack& operator=(const GuestStack&) = delete;
    GuestStack(GuestStack&&) = delete;
    GuestStack& operator=(GuestStack&&) = delete;

    bool valid() const { return mapping_ != nullptr; }
    const std::string& error() const { return error_; }
    size_t usable_size() const { return usable_size_; }
    uintptr_t top() const;

    // Entry is an aligned, executable C ABI guest address accepting x0=arg.
    // Only the calling host thread may attach state during this invocation.
    // Rejects concurrent stack reuse and nested guest calls. The caller must
    // keep state, its environment, executable modules, and this stack alive.
    bool call(DmGuestThreadState& state, uintptr_t entry, uint64_t arg,
              GuestCallResult* result, std::string* error);
    // Up to eight integer/pointer C ABI arguments; unused x0..x7 are zeroed.
    bool call(DmGuestThreadState& state, uintptr_t entry, const uint64_t* args,
              size_t count, GuestCallResult* result, std::string* error);

private:
    void* mapping_ = nullptr;
    size_t mapping_size_ = 0;
    size_t page_size_ = 0;
    size_t usable_size_ = 0;
    std::string error_;
    std::atomic<bool> active_{false};
    bool owns_mapping_ = true;
};

// ExitThread abandons the guest stack and returns to call's saved host frame.
// It does not unwind guest C++ frames. HLE exit handlers must not construct
// RAII objects needing destruction across this call. An exit without an active
// guest invocation aborts. It never terminates the host pthread.
[[noreturn]] void guest_exit(uint64_t value);

// Bounds of this host thread's active guest invocation, never host TLS/x18.
bool active_guest_stack_bounds(uintptr_t address, uintptr_t* bottom, size_t* size);
// Only guarded mappings owned by GuestStack qualify for immutable direct copy.
// Borrowed SDK/caller spans require their mapping owner's locked-copy path.
bool active_guest_stack_owned_bounds(uintptr_t address, uintptr_t* bottom, size_t* size);

} // namespace dm_android
