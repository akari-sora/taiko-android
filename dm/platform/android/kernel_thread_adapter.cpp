#include "kernel_thread_adapter.h"
#include "guest_thread.h"
#include <csignal>
#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>

namespace {
// A signal can arrive while running on a small SDK stack. Install a distinct
// guarded alternate stack and restore any embedding host's previous stack.
class SignalStack {
public:
    SignalStack() {
        const long page = sysconf(_SC_PAGESIZE);
        if (page <= 0) return;
        page_ = static_cast<size_t>(page);
        size_ = ((64 * 1024 + page_ - 1) / page_) * page_;
        mapping_ = mmap(nullptr, size_ + 2 * page_, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping_ == MAP_FAILED) { mapping_ = nullptr; return; }
        stack_t next{};
        next.ss_sp = static_cast<char*>(mapping_) + page_;
        next.ss_size = size_;
        if (mprotect(next.ss_sp, size_, PROT_READ | PROT_WRITE) ||
            sigaltstack(&next, &previous_)) return;
        valid_ = true;
    }
    ~SignalStack() {
        if (valid_ && sigaltstack(&previous_, nullptr)) std::abort();
        if (mapping_) munmap(mapping_, size_ + 2 * page_);
    }
    bool valid() const { return valid_; }
private:
    void* mapping_ = nullptr;
    size_t size_ = 0, page_ = 0;
    stack_t previous_{};
    bool valid_ = false;
};
}

extern "C" int dm_android_kernel_thread_run(uint64_t entry, uint64_t argument, uint64_t top) {
    uint64_t bottom = 0;
    size_t size = 0;
    if (!dm_android_kernel_stack_pin(top, &bottom, &size)) return 0;
    bool exited = false;
    {
        // Each worker has independent guest TLS/TLR and invocation state.
        dm_android::GuestEnvironment environment;
        dm_android_configure_kernel_state(&environment.state);
        // MapMemory may include reserved SDK data above the requested SP.
        // Preserve the exact supplied stack top rather than the mapping's end.
        dm_android::GuestStack stack(reinterpret_cast<void*>(bottom), static_cast<size_t>(top - bottom));
        SignalStack signals;
        dm_android::GuestCallResult result;
        std::string error;
        if (stack.valid() && signals.valid() && environment.state.dispatch &&
            stack.call(environment.state, entry, argument, &result, &error)) exited = result.exited;
    }
    // This runs on the restored HOST stack, before the C service publishes
    // exited/wakes handle waiters or frees its metadata.
    dm_android_kernel_stack_unpin(bottom);
    return exited;
}

extern "C" [[noreturn]] void dm_android_kernel_thread_exit(uint64_t value) {
    dm_android::guest_exit(value);
}
