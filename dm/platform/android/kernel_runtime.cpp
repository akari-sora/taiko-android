#include "kernel_runtime.h"
#include "kernel_thread_adapter.h"
#include "kernel_platform.h"
#include "service_platform.h"
#include "fs_platform.h"
#include "app_platform.h"
#include "kernel_memory_android.h"
#include "guest_parameters.h"
#include "guest_stack_check.h"
#include "observation_platform.h"
#include "oe_platform.h"
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include "taiko_bringup.h"
#include "graphics_platform.h"
#include "vi_platform.h"
#include "audio_platform.h"
#include "audio_focus.h"
#include "../../gfx/nvn/include/nvn.h"
#include <cerrno>
#include <cstring>
extern "C" {
#include "../../host/dm.h"
#include "../../host/hle_hid_core.h"
#include "../../host/dm_gamepad_core.h"
uint32_t svc_thread_main_init(void);
uint64_t svc_dispatch(int, uint64_t*, uint64_t);
struct dm_flags g_flag{};
uint64_t g_t0_ns = 0;
}
#include <array>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <new>

extern "C" void dm_android_swkbd_entry() __attribute__((weak));
extern "C" void dm_android_character_isalpha_entry() __attribute__((weak));
namespace {
thread_local uint64_t keyboard_invocation=0;
std::atomic<dm_android::HleRuntime*> current_runtime{nullptr};
std::mutex runtime_lifecycle;
thread_local dm_android::HleRuntime* invoking_runtime=nullptr;
thread_local unsigned observation_depth=0;
thread_local unsigned oe_hook_depth=0;
thread_local unsigned graphics_callback_depth=0;
thread_local dm_android::NativeWaitState native_wait_state;
std::atomic<uint64_t> profile_ns[PROF_N]{}, profile_bytes[PROF_N]{};
std::atomic<uint64_t> frame_progress{0};
bool fail(std::string* error, const char* message) {
    if (error) *error = message;
    return false;
}
bool within(uint64_t address, size_t size, uint64_t base, size_t length) {
    return base && size && address >= base && size <= length && address - base <= length - size;
}
}

namespace dm_android {
RuntimeReadLease::RuntimeReadLease() {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    auto* candidate=current_runtime.load(std::memory_order_acquire);
    if(candidate && candidate->loaded_ && !candidate->closing_) { runtime_=candidate; ++runtime_->active_reads_; }
}
RuntimeReadLease::~RuntimeReadLease() {
    if(!runtime_) return;
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if(current_runtime.load()!=runtime_ || !runtime_->active_reads_) std::abort();
    --runtime_->active_reads_;
}
RuntimeGpuLease::RuntimeGpuLease() {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    auto* candidate=current_runtime.load(std::memory_order_acquire);
    if(candidate && candidate->loaded_ && !candidate->closing_) {
        runtime_=candidate;generation_=runtime_->process_.load_generation();++runtime_->active_gpu_;
    }
}
RuntimeGpuLease::~RuntimeGpuLease(){release();}
RuntimeGpuLease::RuntimeGpuLease(RuntimeGpuLease&& other) noexcept :runtime_(other.runtime_),generation_(other.generation_){other.runtime_=nullptr;}
RuntimeGpuLease& RuntimeGpuLease::operator=(RuntimeGpuLease&& other) noexcept {
    if(this!=&other){release();runtime_=other.runtime_;generation_=other.generation_;other.runtime_=nullptr;}return *this;
}
void RuntimeGpuLease::release() {
    if(!runtime_)return;
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if(current_runtime.load()!=runtime_ || !runtime_->active_gpu_ || runtime_->process_.load_generation()!=generation_)std::abort();
    --runtime_->active_gpu_;runtime_=nullptr;
}
bool HleRuntime::refresh_parameters(DmGuestThreadState& state) {
    uint64_t values[4];
    if(!dm_android_capture_guest_parameters(values)) return false;
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if(!loaded_ || current_runtime.load()!=this || invoking_runtime!=this ||
       dm_android_peek_guest_state()!=&state || state.user_data!=this || !needs_parameters_) return false;
    std::memcpy(parameter_seed_,values,sizeof(values));
    std::memcpy(state.parameters,values,sizeof(values));state.parameter_valid_mask=15;
    return true;
}
bool HleRuntime::observation_present(unsigned id) const {
    std::lock_guard<std::mutex> lifecycle(runtime_lifecycle);
    return loaded_ && current_runtime.load()==this && id<256 && process_.observation_present(id);
}
bool HleRuntime::observation_set(unsigned id,void (*callback)(const uint64_t*)) {
    std::lock_guard<std::mutex> lifecycle(runtime_lifecycle);
    if(!loaded_ || current_runtime.load()!=this || id>=256 || !process_.observation_present(id)) return false;
    std::lock_guard<std::mutex> lock(observation_mutex_);observers_[id]=callback;return true;
}
bool HleRuntime::observation_set_frame(unsigned id,void (*callback)(DmGuestRegisterFrame*)) {
    std::lock_guard<std::mutex> lifecycle(runtime_lifecycle);
    if(!loaded_ || current_runtime.load()!=this || id>=256 || !process_.observation_present(id)) return false;
    std::lock_guard<std::mutex> lock(observation_mutex_);frame_observers_[id]=callback;return true;
}
HleRuntime::~HleRuntime() {
    std::string error;
    if (!shutdown(&error)) {
        std::fprintf(stderr, "Android HLE runtime cannot unload: %s\n", error.c_str());
        std::abort();
    }
}
bool HleRuntime::resolve(const char* name, bool forced, uintptr_t* address, void* opaque) {
    auto& runtime = *static_cast<HleRuntime*>(opaque);
    if(name && !std::strcmp(name,DM_DIAG_ABORT_RESOLVER_V1) && forced) {
        uintptr_t registered=0;
        if(!address || !runtime.needs_diag_abort_ || !dm_android_diag_abort_entry ||
           !runtime.registry_.resolve(name,false,&registered) ||
           registered!=reinterpret_cast<uintptr_t>(dm_android_diag_abort_entry))return false;
        *address=registered;return true;
    }
    if (runtime.registry_.resolve(name, forced, address)) return true;
    return runtime.fixture_fallback_ && runtime.fixture_fallback_(name, forced, address, runtime.fixture_context_);
}
bool HleRuntime::load(std::vector<std::unique_ptr<ModulePackage>> packages, bool all_forces,
                      HostResolver fallback, void* context, std::string* error) {
    // No detached script worker is permitted to survive a runtime epoch.
    const char* script = std::getenv("DM_OE_SCRIPT");
    if (script && *script) return fail(error, "Android DM_OE_SCRIPT is unavailable; clear the nonempty script configuration");
    int operation_mode = 1;
    if (const char* mode = std::getenv("DM_OPMODE")) {
        char* end = nullptr; errno = 0;
        const long parsed = std::strtol(mode, &end, 10);
        if (errno || !*mode || !end || *end || (parsed != 0 && parsed != 1))
            return fail(error, "Android DM_OPMODE must be 0 or 1");
        operation_mode = static_cast<int>(parsed);
    }
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if (error) error->clear();
    if (loaded_ || current_runtime.load()) return fail(error, "another common-host runtime is active");
    bool process_owned=false,bridge_owned=false,observation_owned=false,hid_owned=false;
    const char* load_stage="host registry";
    // No guest has entered and the graphics binder publishes nothing on false
    // or exception. These are silent/nonblocking metadata retirements; they do
    // not call consumers or wait for GPU work while runtime_lifecycle is held.
    const auto rollback=[&]() noexcept {
        if(vi_generation_) {if(!vi_platform_reset(vi_generation_))std::abort();vi_generation_=0;}
        if(oe_epoch_) {if(!oe_platform_close(oe_epoch_))std::abort();oe_epoch_=0;}
        if(hid_owned && !dm_hid_close())std::abort();
        if(observation_owned)observation_platform_reset();
        if(bridge_owned)bridge_.unbind();
        if(process_owned)process_.unload();
        fixture_fallback_=nullptr;fixture_context_=nullptr;needs_parameters_=false;needs_diag_abort_=false;
        std::memset(parameter_seed_,0,sizeof(parameter_seed_));
    };
    try {
    if (!registry_.initialize(error)) return false;
    registry_.reset_force_hits();
    fixture_fallback_ = fallback;
    fixture_context_ = context;
    needs_parameters_=false;
    needs_diag_abort_=false;
    for(const auto& package:packages) if(package) {
        if(!package->parameters.empty())needs_parameters_=true;
        if(package->required_flags&DM_MODULE_REQUIRE_DIAG_ABORT_V1)needs_diag_abort_=true;
    }
    if(needs_parameters_ && !dm_android_capture_guest_parameters(parameter_seed_)) {
        rollback();
        return fail(error,"profile requires an available real guest parameter provider");
    }
    load_stage="process load";
    if (!process_.load(std::move(packages), resolve, this, error)) {rollback();return false;}
    process_owned=true;
    load_stage="original graph authority";
    const bool original_bringup=original_bringup_graph(process_,nullptr);
    const bool taiko_stock=taiko_bringup_graph(process_,nullptr);
    if((original_bringup || taiko_stock) && fallback) {
        rollback();return fail(error,"original bringup forbids a fixture import fallback");
    }
    if (all_forces && !registry_.require_all_forces(error)) {rollback();return false;}
    load_stage="common host publication";
    if (!bridge_.bind(process_, error)) {rollback();return false;}
    bridge_owned=true;
    dm_android_guest_clock_reset();
    g_t0_ns = now_ns();
    g_flag.bootprof = 1;
    for (auto& value : svc_counts_) value.store(0);
    unavailable_host_calls_.store(0);
    for (auto& value : profile_ns) value.store(0);
    for (auto& value : profile_bytes) value.store(0);
    frame_progress.store(0);
    // Configure uses this pinned, quiescent process directly; no recursive read lease.
    load_stage="observation publication";observation_owned=true;
    if(!observation_platform_configure(process_,error)) {rollback();return false;}
    // Exact public controller fixtures and the separately compiled original
    // stock graph may use actual basic input. Unknown graphs retain refusal;
    // neither route installs or claims a FullProduct gameplay adapter.
    if(controller_diagnostic_graph(process_,nullptr) || original_bringup || taiko_stock) {
        dm_hid_adapter input{};
        input.identity=taiko_stock?"android-taiko-stock-basic-input-v1":
            original_bringup?"android-original-bringup-basic-input-v1":"android-public-controller-sdk-v1";
        load_stage="basic input publication";
        if(!dm_hid_configure(DM_HID_DIAGNOSTIC_RAW,&input)) {
            rollback();
            return fail(error,"controller sampler is not quiescent");
        }
        hid_owned=true;
        dm_hid_reset_inputs();dm_gamepad_reset();
    }
    const DmOeOps ops{this, nullptr, oe_post_pop, nullptr};
    oe_refresh_successes_.store(0); oe_refresh_deferred_.store(0);
    load_stage="OE publication";
    oe_epoch_ = oe_platform_bind(ops, operation_mode);
    if (!oe_epoch_) {
        rollback();
        return fail(error, "Android OE channel already owns an active epoch");
    }
    load_stage="VI platform publication";
    if(!vi_platform_bind(process_,error,&vi_generation_)) {rollback();return false;}
    // This is the final throwing operation. Its candidate/catalog work precedes
    // NVN publication; a failed/throwing bind owns no GPU or global backend.
    // Once binding succeeds the following commit contains only noexcept stores.
    load_stage="graphics binding";
    if(!graphics_platform_bind(process_,error)) {rollback();return false;}
    loaded_ = true;
    current_runtime.store(this, std::memory_order_release);
    return true;
    } catch(const std::bad_alloc&) {
        rollback();
        if(error)try{*error="runtime load allocation failed at ";error->append(load_stage);}catch(...){}
        return false;
    } catch(...) {
        rollback();
        if(error)try{*error="runtime load exception at ";error->append(load_stage);}catch(...){}
        return false;
    }
}
void HleRuntime::oe_post_pop(void* opaque, uint32_t) {
    auto& runtime = *static_cast<HleRuntime*>(opaque);
    // The actual HLE call must retain its invocation while this unlocked hook
    // captures providers and updates current-thread state and the future seed.
    if (invoking_runtime != &runtime) std::abort();
    ++oe_hook_depth;
    try {
        if (dm_android_refresh_guest_parameters()) runtime.oe_refresh_successes_.fetch_add(1);
        else runtime.oe_refresh_deferred_.fetch_add(1);
    } catch (...) { std::fputs("Android OE callbacks must return normally\n", stderr); std::abort(); }
    --oe_hook_depth;
}
void HleRuntime::configure(DmGuestThreadState& state) {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if (!loaded_ || current_runtime.load(std::memory_order_acquire) != this) std::abort();
    state.dispatch = dispatch;
    state.user_data = this;
    state.gate_resolver = Process::gate_resolver;
    state.gate_context = &process_;
    state.invocation_enter = invocation_enter;
    state.invocation_leave = invocation_leave;
    state.invocation_context = this;
    state.runtime_generation = process_.load_generation();
    // A legacy diagnostic may not own a GuestEnvironment. It gains no SVC36
    // authority; bind failure revokes any previous view and dispatch refuses.
    native_wait_state.bind(state,state.runtime_generation);
    if(needs_parameters_) { std::memcpy(state.parameters,parameter_seed_,sizeof(parameter_seed_));state.parameter_valid_mask=15; }
    else { std::memset(state.parameters,0,sizeof(state.parameters));state.parameter_valid_mask=0; }
}
bool HleRuntime::invocation_enter(void* opaque) {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if (current_runtime.load() != opaque) return false;
    auto& runtime = *static_cast<HleRuntime*>(opaque);
    if (!runtime.loaded_ || runtime.closing_ || invoking_runtime) return false;
    if(keyboard_invocation==UINT64_MAX)return false;
    ++keyboard_invocation;
    invoking_runtime=&runtime;
    ++runtime.active_invocations_;
    return true;
}
void HleRuntime::invocation_leave(void* opaque) {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    auto& runtime = *static_cast<HleRuntime*>(opaque);
    if (current_runtime.load() != opaque || !runtime.active_invocations_) std::abort();
    --runtime.active_invocations_;
    if(invoking_runtime!=&runtime) std::abort();
    invoking_runtime=nullptr;
}
uint32_t HleRuntime::register_main() {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if (current_runtime.load() != this || !loaded_) return 0;
    if (has_main_ && !pthread_equal(main_owner_, pthread_self())) return 0;
    const uint32_t handle = svc_thread_main_init();
    if (handle) { has_main_ = true; main_owner_ = pthread_self(); }
    return handle;
}
bool HleRuntime::shutdown(std::string* error) {
    std::unique_lock<std::mutex> lock(runtime_lifecycle);
    if (!loaded_) return true;
    if (closing_) return fail(error,"runtime shutdown is already retiring graphics");
    if (error) error->clear();
    if (active_invocations_) return fail(error, "guest invocations are still executing");
    if (active_reads_) return fail(error,"guest memory reads are still executing");
    if (active_gpu_) return fail(error,"graphics work still retains guest memory");
    const auto* attached = dm_android_peek_guest_state();
    if (attached && attached->user_data == this) return fail(error, "guest invocation is still attached");
    if (has_main_ && !pthread_equal(main_owner_, pthread_self()))
        return fail(error, "runtime must shut down on its registered main host thread");
    if (dm_android_fs_has_open_handles()) return fail(error, "filesystem still owns open guest handles");
    // Parked threads also retain SDK stack pins. A caller must close or start
    // and finish them; shutdown never silently cancels guest work.
    if (!dm_android_kernel_threads_quiescent_except_current())
        return fail(error, "kernel still owns live guest threads");
    if (!dm_android_kernel_memory_quiescent()) return fail(error, "kernel memory still has live stack pins");
    if (!dm_hid_can_close()) return fail(error,"controller sampler is still executing");
    closing_=true;
    const GraphicsClosePermit graphics_close(process_.load_generation());
    lock.unlock();
    // Device retirement may wait. closing excludes new entries/leases while
    // the lifecycle mutex remains available to independent metadata queries.
    if(!graphics_platform_close(graphics_close,error)) {lock.lock();closing_=false;return false;}
    // Guest entry is now closed and all guest workers passed the quiescent
    // preflight. Join output/recovery/notification threads while SystemEvents
    // and the HostBridge still exist, with no runtime mutex held.
    dm_android_audio_focus_shutdown();
    dm_android_audio_shutdown();
    lock.lock();
    if(vi_generation_) {if(!vi_platform_reset(vi_generation_))std::abort();vi_generation_=0;}
    if (!oe_platform_close(oe_epoch_)) std::abort();
    if (!dm_hid_close()) std::abort();
    dm_gamepad_reset();
    oe_epoch_ = 0;
    oe_refresh_successes_.store(0); oe_refresh_deferred_.store(0);
    if (!dm_android_kernel_memory_reset()) std::abort();
    // These metadata resets cannot fail after the quiescent preflight while
    // lifecycle is locked. Do not resume a partially dismantled runtime.
    if (!dm_android_fs_reset()) std::abort();
    dm_android_kernel_thread_finish_current();
    if (!dm_android_kernel_threads_reset() || !dm_android_services_reset()) std::abort();
    observation_platform_reset();
    { std::lock_guard<std::mutex> observers(observation_mutex_);
      std::memset(observers_,0,sizeof(observers_)); std::memset(frame_observers_,0,sizeof(frame_observers_)); }
    dm_android_guest_clock_reset();
    dm_android_app_services_reset();
    current_runtime.store(nullptr, std::memory_order_release);
    bridge_.unbind();
    dm_android_host_objects_reset();
    process_.unload();
    needs_diag_abort_=false;
    loaded_ = has_main_ = closing_ = false;
    return true;
}
void HleRuntime::dispatch(DmGuestThreadState* state, DmGuestRegisterFrame* frame, const DmGuestGate* gate) {
    if (!state || !frame || !gate || state->user_data != current_runtime.load()) std::abort();
    if(gate->kind==DM_GUEST_INDIRECT_HOST) {
        auto& runtime=*static_cast<HleRuntime*>(state->user_data);
        if(!runtime.guarded_host_transfer(*state,*frame,gate)) {
            std::fputs("Android guarded host transfer lacks exact live authority\n",stderr);std::abort();
        }
    } else if(gate->kind==DM_GUEST_EXACT_GUEST) {
        auto& runtime=*static_cast<HleRuntime*>(state->user_data);
        if(!runtime.guarded_guest_transfer(*state,*frame,gate)) {
            std::fputs("Android exact guest transfer lacks exact live authority\n",stderr);std::abort();
        }
    } else if (gate->kind == DM_GUEST_SVC) {
        if(gate->argument==0x36) {
            auto* runtime=static_cast<HleRuntime*>(state->user_data);
            // The owned host invocation pins runtime and environment lifetime.
            // Full-frame preservation here is our adapter contract; SVC36 is
            // void and must never pass through the Result-writing fallback.
            if(!runtime || invoking_runtime!=runtime || dm_android_peek_guest_state()!=state ||
               !dm_android_stack_dispatch_context(state) ||
               state->runtime_generation!=runtime->process_.load_generation() ||
               !native_wait_state.synchronize(*state,runtime->process_.load_generation())) {
                std::fputs("Android SVC36 requires current owned unpinned TLR with zero interrupt flag\n",stderr);
                std::abort();
            }
            runtime->count_svc(0x36);
            return;
        }
        if((observation_depth || oe_hook_depth || graphics_callback_depth) && gate->argument==0x0a) {
            std::fputs("Android observers must return normally; ExitThread is refused\n",stderr);std::abort();
        }
        svc_dispatch(static_cast<int>(gate->argument), frame->x, frame->return_pc);
    } else if (gate->kind == DM_GUEST_TIMER && gate->argument < 31) {
        const uint64_t ns = guest_ns();
        frame->x[gate->argument] = (ns / 625) * 12 + (ns % 625) * 12 / 625;
    } else if(gate->kind==DM_GUEST_OBSERVATION) {
        auto& runtime=*static_cast<HleRuntime*>(state->user_data);
        if(invoking_runtime!=&runtime || !runtime.process_.observation_present(gate->argument) || gate->argument>=256) std::abort();
        void (*callback)(const uint64_t*)=nullptr;
        void (*full_callback)(DmGuestRegisterFrame*)=nullptr;
        { std::lock_guard<std::mutex> lock(runtime.observation_mutex_);
          callback=runtime.observers_[gate->argument];full_callback=runtime.frame_observers_[gate->argument]; }
        ++observation_depth;
        try { if(callback) callback(frame->x); if(full_callback) full_callback(frame); }
        catch(...) { std::fputs("Android observer attempted unsupported C++ unwind\n",stderr);std::abort(); }
        --observation_depth;
    } else std::abort();
}
bool GuestHleOrigin::main_callsite(const Process& process,uint64_t* out) const {
    if(out)*out=0;
    const auto* current=dm_android_peek_guest_state();
    if(!out||process_!=&process||!generation_||generation_!=process.load_generation()||
       state_!=current||!current||current->runtime_generation!=generation_||
       !invoking_runtime||invoking_runtime!=current->user_data||invocation_!=keyboard_invocation)return false;
    *out=callsite_;return true;
}
bool HleRuntime::keyboard_entry_origin(uintptr_t target,uint64_t guest_lr,uintptr_t guest_sp,GuestHleOrigin* out) {
    if(out)*out={};
    uintptr_t live_sp=0;
#if defined(__aarch64__)
    asm volatile("mov %0, sp":"=r"(live_sp));
#elif defined(__x86_64__)
    asm volatile("mov %%rsp, %0":"=r"(live_sp));
#else
    return false;
#endif
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    uintptr_t bottom=0;size_t bytes=0;
    const auto* state=dm_android_peek_guest_state();
    if(!out||!loaded_||closing_||current_runtime.load()!=this||invoking_runtime!=this||!active_invocations_||
       !state||state->user_data!=this||state->runtime_generation!=process_.load_generation()||
       state->gate_context!=&process_||state->gate_resolver!=Process::gate_resolver||
       (guest_sp&15)||guest_sp<live_sp||guest_sp-live_sp>DM_GUEST_STACK_RESERVE||
       !active_guest_stack_bounds(live_sp,&bottom,&bytes)||guest_sp-bottom>=bytes||
       !original_bringup_graph(process_,nullptr))return false;
    const char* symbol=nullptr;
    if(dm_android_swkbd_entry&&target==reinterpret_cast<uintptr_t>(&dm_android_swkbd_entry))
        symbol="_ZN2nn5swkbd12ShowKeyboardEPNS0_6StringERKNS0_15ShowKeyboardArgE";
    if(dm_android_character_isalpha_entry&&target==reinterpret_cast<uintptr_t>(&dm_android_character_isalpha_entry))symbol="isalpha";
    uint64_t site=0;
    if(!symbol||!registry_.contains_callable(target)||!process_.static_main_import_caller(guest_lr,target,symbol,&site))return false;
    out->process_=&process_;out->state_=state;out->generation_=state->runtime_generation;
    out->callsite_=site;out->invocation_=keyboard_invocation;return true;
}
bool HleRuntime::diag_abort_origin(uint64_t guest_lr,uintptr_t guest_sp,DiagAbortCaller* out) {
    if(out)*out={};
    uintptr_t live_sp=0;
#if defined(__aarch64__)
    asm volatile("mov %0, sp":"=r"(live_sp));
#elif defined(__x86_64__)
    asm volatile("mov %%rsp, %0":"=r"(live_sp));
#else
    return false;
#endif
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    const auto* state=dm_android_peek_guest_state();uintptr_t bottom=0;size_t bytes=0;
    if(!out || !loaded_ || closing_ || !needs_diag_abort_ || current_runtime.load()!=this ||
       invoking_runtime!=this || !active_invocations_ || !state || state->user_data!=this ||
       state->runtime_generation!=process_.load_generation() || state->gate_context!=&process_ ||
       state->gate_resolver!=Process::gate_resolver || !dm_android_stack_dispatch_context(state) ||
       (guest_sp&15) || guest_sp<live_sp || guest_sp-live_sp>DM_GUEST_STACK_RESERVE ||
       !active_guest_stack_bounds(live_sp,&bottom,&bytes) || guest_sp-bottom>bytes ||
       !dm_android_diag_abort_entry || !registry_.contains_callable(reinterpret_cast<uintptr_t>(dm_android_diag_abort_entry)))
        return false;
    return process_.diag_abort_import_caller(guest_lr,out);
}
bool HleRuntime::guarded_host_transfer(const DmGuestThreadState& state,
                                      const DmGuestRegisterFrame& frame,const DmGuestGate* gate) const {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if(!loaded_ || closing_ || current_runtime.load()!=this || invoking_runtime!=this ||
       !active_invocations_ || dm_android_peek_guest_state()!=&state || state.user_data!=this ||
       state.runtime_generation!=process_.load_generation() ||
       state.gate_context!=&process_ || state.gate_resolver!=Process::gate_resolver ||
       !process_.guarded_host_site(frame.return_pc,gate)) return false;
    const uintptr_t target=frame.x[gate->argument];
    uintptr_t required=0;
    if(process_.diag_abort_host_site(frame.return_pc,gate,&required)) {
        // This target was frozen from the flagged module's original import,
        // not read again from its writable GOT. No ordinary returning HLE may
        // satisfy the fatal ABI, even if it is otherwise registered/callable.
        return needs_diag_abort_ && gate->argument==17 && dm_android_diag_abort_entry &&
               required==reinterpret_cast<uintptr_t>(dm_android_diag_abort_entry) &&
               frame.x[17]==required;
    }
    return target && !(target&3) && (registry_.contains_callable(target) ||
                                  graphics_host_target(target,state.runtime_generation));
}
bool HleRuntime::guarded_guest_transfer(const DmGuestThreadState& state,
                                        const DmGuestRegisterFrame& frame,const DmGuestGate* gate) const {
    std::lock_guard<std::mutex> lock(runtime_lifecycle);
    if(!loaded_ || closing_ || current_runtime.load()!=this || invoking_runtime!=this ||
       !active_invocations_ || dm_android_peek_guest_state()!=&state || state.user_data!=this ||
       state.runtime_generation!=process_.load_generation() ||
       state.gate_context!=&process_ || state.gate_resolver!=Process::gate_resolver ||
       !dm_android_stack_dispatch_context(&state) || !gate ||
       gate->kind!=DM_GUEST_EXACT_GUEST || gate->argument!=17) return false;
    const uintptr_t target=frame.x[17];
    if(!target || (target&3) || registry_.contains_callable(target) ||
       graphics_host_target(target,state.runtime_generation)) return false;
    return process_.exact_guest_site(frame.return_pc,gate,target,state.runtime_generation);
}
bool HleRuntime::graphics_guest_callback(uint64_t target,uint64_t command,uint64_t requested,uint64_t data) {
    uintptr_t sp=0;
#if defined(__aarch64__)
    asm volatile("mov %0, sp":"=r"(sp));
#elif defined(__x86_64__)
    asm volatile("mov %%rsp, %0":"=r"(sp));
#else
    return false;
#endif
    auto* state=dm_android_peek_guest_state();
    {
        std::lock_guard<std::mutex> lock(runtime_lifecycle);
        if(!loaded_ || closing_ || current_runtime.load()!=this || invoking_runtime!=this ||
           !active_invocations_ || !state || state->user_data!=this ||
           state->runtime_generation!=process_.load_generation() ||
           state->gate_context!=&process_ || state->gate_resolver!=Process::gate_resolver ||
           !process_.callback_root(target) || !requested || requested>SIZE_MAX ||
           !command || (command&7)) return false;
    }
    uintptr_t bottom=0;size_t length=0;
    // This is the live hardware SP, not a guest-provided saved frame or a
    // pthread host-stack fallback. Borrowed SDK stacks are pinned by their
    // GuestStack invocation owner for this same retained call.
    if(!active_guest_stack_bounds(sp,&bottom,&length) || (sp&15)) return false;
    const auto readable=[&](uint64_t address,size_t size,bool write) {
        if(!address || !size || address>UINT64_MAX-size) return false;
        if(within(address,size,bottom,length)) return true;
        for(const auto& span:state->owned_memory)
            if(within(address,size,span.base,span.size)) return true;
        return process_.mapped_range(address,size,DM_GUEST_READ|(write?DM_GUEST_WRITE:0)) ||
               dm_android_current_guest_memory(address,size,write);
    };
    if(!readable(command,sizeof(NVNcommandBuffer),true) || (data && !readable(data,1,false))) return false;
    ++graphics_callback_depth;
    try {
        reinterpret_cast<PFNNVNCOMMANDBUFFERMEMORYCALLBACKPROC>(target)(
            reinterpret_cast<NVNcommandBuffer*>(command),
            NVN_COMMAND_BUFFER_MEMORY_EVENT_OUT_OF_COMMAND_MEMORY,
            static_cast<size_t>(requested),reinterpret_cast<void*>(data));
    } catch(...) {
        --graphics_callback_depth;
        return false;
    }
    --graphics_callback_depth;
    return true;
}
uint64_t HleRuntime::svc_count(unsigned number) const { return number < 256 ? svc_counts_[number].load() : 0; }
void HleRuntime::count_svc(unsigned number) { if (number < 256) svc_counts_[number].fetch_add(1); }
void HleRuntime::count_unavailable_host_call() { unavailable_host_calls_.fetch_add(1); }
} // namespace dm_android

extern "C" void dm_android_configure_kernel_state(DmGuestThreadState* state) {
    auto* runtime = current_runtime.load(std::memory_order_acquire);
    if (!runtime || !state) std::abort();
    runtime->configure(*state);
}
extern "C" int dm_android_current_stack_bounds(uint64_t address, uint64_t* bottom, size_t* size) {
    if (!bottom || !size) return 0;
    uintptr_t guest_bottom = 0;
    if (dm_android::active_guest_stack_bounds(address, &guest_bottom, size)) { *bottom = guest_bottom; return 1; }
    pthread_attr_t attributes;
    if (pthread_getattr_np(pthread_self(), &attributes)) return 0;
    void* host_bottom = nullptr;
    size_t host_size = 0;
    const int result = pthread_attr_getstack(&attributes, &host_bottom, &host_size);
    pthread_attr_destroy(&attributes);
    if (result || !within(address, 1, reinterpret_cast<uintptr_t>(host_bottom), host_size)) return 0;
    *bottom = reinterpret_cast<uintptr_t>(host_bottom); *size = host_size;
    return 1;
}
extern "C" int dm_android_current_guest_memory(uint64_t address, size_t size, int write) {
    uint64_t base = 0;
    size_t length = 0;
    unsigned flags = 0;
    return dm_android_current_guest_region(address, &base, &length, &flags) &&
        (flags & (write ? DM_GUEST_WRITE : DM_GUEST_READ)) && within(address, size, base, length);
}
extern "C" int dm_android_current_guest_range(uint64_t address, uint64_t* base, size_t* size) {
    unsigned flags = 0;
    return dm_android_current_guest_region(address, base, size, &flags);
}
extern "C" int dm_android_current_guest_region(uint64_t address, uint64_t* base, size_t* size, unsigned* flags) {
    const auto* state = dm_android_peek_guest_state();
    if (!state || !base || !size || !flags) return 0;
    for (const auto& span : state->owned_memory) if (within(address, 1, span.base, span.size)) {
        *base = span.base; *size = span.size; *flags = DM_GUEST_READ | DM_GUEST_WRITE; return 1;
    }
    return current_runtime.load() && dm_android_services_query_memory(address, base, size, flags);
}
extern "C" int dm_android_runtime_is_active() { return current_runtime.load() != nullptr; }
extern "C" int dm_android_observation_callback_active() { return observation_depth!=0 || oe_hook_depth!=0 || graphics_callback_depth!=0; }
extern "C" int dm_android_refresh_guest_parameters() {
    auto* state=dm_android_peek_guest_state();
    return state && invoking_runtime && invoking_runtime->refresh_parameters(*state);
}
extern "C" int dm_android_graphics_guest_callback(uint64_t target,uint64_t command,uint64_t requested,uint64_t data) {
    auto* runtime=invoking_runtime;
    return runtime && runtime->graphics_guest_callback(target,command,requested,data);
}
extern "C" int dm_android_runtime_copy_guest(uint64_t address,void* staging,size_t bytes) {
    if(!address || !staging || !bytes || bytes>65536 || address>UINT64_MAX-bytes) return 0;
    dm_android::RuntimeReadLease lease;
    auto* runtime=lease.runtime();
    if(!runtime) return 0;
    if(runtime->process().copy_readable(address,staging,bytes)) return 1;
    const auto* state=dm_android_peek_guest_state();
    if(invoking_runtime==runtime && state && state->user_data==runtime) {
        for(const auto& span:state->owned_memory) if(within(address,bytes,span.base,span.size)) {
            std::memcpy(staging,reinterpret_cast<const void*>(address),bytes);return 1;
        }
        uintptr_t bottom=0;size_t length=0;
        if(dm_android::active_guest_stack_owned_bounds(address,&bottom,&length) && within(address,bytes,bottom,length)) {
            // Only immutable guarded mappings owned by the current GuestStack.
            // Borrowed SDK stacks fall through to their kernel permission owner.
            std::memcpy(staging,reinterpret_cast<const void*>(address),bytes);return 1;
        }
    }
    return dm_android_kernel_memory_copy_readable(address,staging,bytes);
}
extern "C" int gate_obs_present(int id) {
    dm_android::RuntimeReadLease lease;
    return id>=0 && lease.runtime() && lease.runtime()->observation_present(static_cast<unsigned>(id));
}
extern "C" void gate_obs_set(int id,void (*callback)(const uint64_t*)) {
    dm_android::RuntimeReadLease lease;
    if(id<0 || !lease.runtime() || !lease.runtime()->observation_set(static_cast<unsigned>(id),callback)) {
        std::fputs("Android observation ID has no canonical loaded site\n",stderr);std::abort();
    }
}
extern "C" void hlecount_svc(int number) {
    if (auto* runtime = current_runtime.load()) runtime->count_svc(static_cast<unsigned>(number));
}
// Private gameplay cuts must be connected to their actual implementations.
// Until then the common SVC dispatcher returns ResultNotImplemented (0x4201).
extern "C" int svc_host_call(int, uint64_t*) {
    if (auto* runtime = current_runtime.load()) runtime->count_unavailable_host_call();
    return 0;
}
extern "C" void dm_prof_add(int id, uint64_t ns, uint64_t bytes) {
    if (id < 0 || id >= PROF_N) return;
    profile_ns[id].fetch_add(ns); profile_bytes[id].fetch_add(bytes);
}
extern "C" void crash_watch_frame() { frame_progress.fetch_add(1); }
extern "C" uint64_t crash_watch_progress_count() { return frame_progress.load(); }
