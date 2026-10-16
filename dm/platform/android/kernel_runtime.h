#pragma once
#include "guest_thread.h"
#include "host_bridge.hpp"
#include <atomic>
#include <pthread.h>
#include <mutex>

namespace dm_android {
class RuntimeReadLease;
class RuntimeGpuLease;
// Candidate LR/SP come from the dedicated assembly entry before any C call.
// Only current exact original identity + live guest-stack/static PLT proof can
// construct this origin. No caller-provided offset or authority flag is used.
class GuestHleOrigin {
public:
    bool main_callsite(const Process&,uint64_t*) const;
private:
    friend class HleRuntime;
    const Process* process_=nullptr;
    const DmGuestThreadState* state_=nullptr;
    uint64_t generation_=0,callsite_=0,invocation_=0;
};
class GraphicsClosePermit {
public:
    GraphicsClosePermit(const GraphicsClosePermit&) = delete;
    GraphicsClosePermit& operator=(const GraphicsClosePermit&) = delete;
    uint64_t generation() const { return generation_; }
private:
    friend class HleRuntime;
    explicit GraphicsClosePermit(uint64_t generation) : generation_(generation) {}
    uint64_t generation_;
};
// The original C host is process-global. One runtime owns its publication and
// every common-host thread until shutdown has proven all workers quiescent.
class HleRuntime {
public:
    HleRuntime() = default;
    ~HleRuntime();
    HleRuntime(const HleRuntime&) = delete;
    HleRuntime& operator=(const HleRuntime&) = delete;
    bool load(std::vector<std::unique_ptr<ModulePackage>>, bool require_all_forces,
              HostResolver fixture_fallback, void* fixture_context, std::string* error);
    Process& process() { return process_; }
    HostRegistry& registry() { return registry_; }
    void configure(DmGuestThreadState&);
    uint32_t register_main();
    bool shutdown(std::string* error);
    uint64_t svc_count(unsigned number) const;
    uint64_t unavailable_host_calls() const { return unavailable_host_calls_.load(); }
    void count_svc(unsigned number);
    void count_unavailable_host_call();
    bool refresh_parameters(DmGuestThreadState&);
    uint64_t oe_epoch() const { return oe_epoch_; }
    uint64_t oe_refresh_successes() const { return oe_refresh_successes_.load(); }
    uint64_t oe_refresh_deferred() const { return oe_refresh_deferred_.load(); }
    bool observation_present(unsigned id) const;
    bool observation_set(unsigned id, void (*callback)(const uint64_t*));
    // Callback arrays retire only after invocation/read quiescence is proven.
    bool observation_set_frame(unsigned id, void (*callback)(DmGuestRegisterFrame*));
    // Pure guard; callers still transfer through the restored assembly frame.
    bool guarded_host_transfer(const DmGuestThreadState&, const DmGuestRegisterFrame&,
                               const DmGuestGate*) const;
    // Executes on the current retained guest invocation's stack. No nested
    // GuestStack::call and no lifecycle mutex spans the actual callback.
    bool graphics_guest_callback(uint64_t target, uint64_t command, uint64_t requested, uint64_t data);
    bool keyboard_entry_origin(uintptr_t target,uint64_t guest_lr,uintptr_t guest_sp,GuestHleOrigin*);
private:
    friend class RuntimeReadLease;
    friend class RuntimeGpuLease;
    static bool resolve(const char*, bool, uintptr_t*, void*);
    static void dispatch(DmGuestThreadState*, DmGuestRegisterFrame*, const DmGuestGate*);
    static bool invocation_enter(void*);
    static void invocation_leave(void*);
    static void oe_post_pop(void*, uint32_t);
    Process process_;
    HostRegistry registry_;
    HostBridge bridge_;
    HostResolver fixture_fallback_ = nullptr;
    void* fixture_context_ = nullptr;
    bool loaded_ = false, has_main_ = false;
    pthread_t main_owner_{};
    size_t active_invocations_ = 0; // protected by runtime_lifecycle
    size_t active_reads_ = 0;
    size_t active_gpu_ = 0;
    bool closing_ = false;
    bool needs_parameters_ = false;
    uint64_t parameter_seed_[4]{};
    uint64_t oe_epoch_ = 0;
    uint64_t vi_generation_ = 0;
    std::atomic<uint64_t> oe_refresh_successes_{0}, oe_refresh_deferred_{0};
    std::mutex observation_mutex_;
    void (*observers_[256])(const uint64_t*){};
    void (*frame_observers_[256])(DmGuestRegisterFrame*){};
    std::atomic<uint64_t> svc_counts_[256]{};
    std::atomic<uint64_t> unavailable_host_calls_{0};
};
// Pins immutable Process ownership; never invoke guest callbacks while held.
class RuntimeReadLease {
public:
    RuntimeReadLease();
    ~RuntimeReadLease();
    RuntimeReadLease(const RuntimeReadLease&) = delete;
    RuntimeReadLease& operator=(const RuntimeReadLease&) = delete;
    HleRuntime* runtime() const { return runtime_; }
private:
    HleRuntime* runtime_ = nullptr;
};
// Logical retention only: holds no lifecycle mutex across GPU waits/callbacks.
class RuntimeGpuLease {
public:
    RuntimeGpuLease();
    ~RuntimeGpuLease();
    RuntimeGpuLease(RuntimeGpuLease&&) noexcept;
    RuntimeGpuLease& operator=(RuntimeGpuLease&&) noexcept;
    RuntimeGpuLease(const RuntimeGpuLease&) = delete;
    RuntimeGpuLease& operator=(const RuntimeGpuLease&) = delete;
    HleRuntime* runtime() const { return runtime_; }
    uint64_t generation() const { return generation_; }
private:
    void release();
    HleRuntime* runtime_ = nullptr;
    uint64_t generation_ = 0;
};
} // namespace dm_android
extern "C" int dm_android_runtime_copy_guest(uint64_t, void*, size_t);
extern "C" int dm_android_observation_callback_active();
extern "C" int dm_android_refresh_guest_parameters();
extern "C" int dm_android_graphics_guest_callback(uint64_t target, uint64_t command,
                                                  uint64_t requested, uint64_t data);
