#include "kernel_probes.h"
#include "kernel_runtime.h"
#include "kernel_platform.h"
#include "kernel_thread_adapter.h"
#include "kernel_fixtures/generated_kernel.h"
#include <array>
#include <atomic>
#include <android/log.h>
#include <sys/auxv.h>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <time.h>
#include <unistd.h>

extern "C" {
uint64_t guest_ns(void);
void guest_clock_freeze_for(int reason, int on);
uint64_t svc_dispatch(int number, uint64_t* registers, uint64_t return_address);
}

namespace {
using namespace dm_android;
struct Check { const char* id; bool passed = false; std::string detail; };
std::string escape(const std::string& value) {
    std::string out;
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { out += '\\'; out += static_cast<char>(ch); }
        else if (ch < 32) { out += "\\u00"; out += digits[ch >> 4]; out += digits[ch & 15]; }
        else out += static_cast<char>(ch);
    }
    return out;
}
void pause_clock() {
    timespec remaining{0, 20000000};
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
}
std::string words(const std::array<uint64_t, 38>& values) {
    std::ostringstream text;
    text << std::hex;
    for (size_t i = 0; i < values.size(); ++i) text << (i ? "," : "") << values[i];
    return text.str();
}
extern "C" uint64_t kernel_owned_memory_entry(uint64_t) {
    const auto* state = dm_android_current_guest_state();
    for (const auto& span : state->owned_memory) {
        struct MemoryInfo { uint64_t base, size; uint32_t state, attributes, permissions, ipc, device, padding; } info{};
        uint64_t registers[31]{};
        registers[0] = reinterpret_cast<uintptr_t>(&info);
        registers[2] = span.base + span.size - 1;
        svc_dispatch(6, registers, 0);
        if (registers[0] || info.base != span.base || info.size != span.size || info.permissions != 3) return 0;
        if (!dm_android_kernel_memory_accessible(span.base, span.size, 1)) return 0;
    }
    return 1;
}
struct InvocationHold {
    explicit InvocationHold(HleRuntime& owner) : runtime(&owner) {}
    HleRuntime* runtime;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    bool ready = false, released = false, finished = false, passed = false;
    std::string error;
    ~InvocationHold() { pthread_cond_destroy(&condition); pthread_mutex_destroy(&mutex); }
};
extern "C" uint64_t kernel_hold_entry(uint64_t pointer) {
    auto& hold = *reinterpret_cast<InvocationHold*>(pointer);
    pthread_mutex_lock(&hold.mutex);
    hold.ready = true;
    pthread_cond_signal(&hold.condition);
    while (!hold.released) pthread_cond_wait(&hold.condition, &hold.mutex);
    pthread_mutex_unlock(&hold.mutex);
    return 0x51;
}
void* invocation_thread(void* pointer) {
    auto& hold = *static_cast<InvocationHold*>(pointer);
    auto environment = std::make_unique<GuestEnvironment>();
    GuestStack stack(128 * 1024);
    hold.runtime->configure(environment->state);
    GuestCallResult result;
    const bool passed = stack.call(environment->state, reinterpret_cast<uintptr_t>(&kernel_hold_entry),
                                    reinterpret_cast<uintptr_t>(&hold), &result, &hold.error) &&
                        !result.exited && result.value == 0x51 && !dm_android_peek_guest_state();
    pthread_mutex_lock(&hold.mutex);
    hold.passed = passed; hold.finished = true;
    pthread_cond_signal(&hold.condition);
    pthread_mutex_unlock(&hold.mutex);
    return nullptr;
}
bool concurrent_lifetime_probe(HleRuntime& runtime, std::string* error) {
    InvocationHold hold(runtime);
    pthread_t thread;
    if (pthread_create(&thread, nullptr, invocation_thread, &hold)) { *error = "cannot create invocation holder"; return false; }
    timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    pthread_mutex_lock(&hold.mutex);
    int wait = 0;
    while (!hold.ready && !hold.finished && !wait)
        wait = pthread_cond_timedwait(&hold.condition, &hold.mutex, &deadline);
    const bool ready = hold.ready;
    pthread_mutex_unlock(&hold.mutex);
    const bool rejected = ready && !runtime.shutdown(error) && !runtime.process().modules().empty();
    pthread_mutex_lock(&hold.mutex);
    hold.released = true;
    pthread_cond_signal(&hold.condition);
    pthread_mutex_unlock(&hold.mutex);
    const int joined = pthread_join(thread, nullptr);
    if (!ready) *error = "invocation did not enter: " + hold.error;
    else if (!rejected) *error = "shutdown failed to retain an unregistered active invocation";
    else if (joined || !hold.passed) *error = "invocation did not restore its host state: " + hold.error;
    return rejected && !joined && hold.passed;
}
struct RegistrationRace {
    explicit RegistrationRace(HleRuntime& owner) : runtime(owner) {}
    HleRuntime& runtime;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    bool start = false;
    unsigned expected = 0, attempted = 0, shutdown_successes = 0;
    uint32_t handles[2]{};
    std::string error;
    ~RegistrationRace() { pthread_cond_destroy(&condition); pthread_mutex_destroy(&mutex); }
};
struct RegistrationAttempt { RegistrationRace* race; size_t index; };
void* registration_thread(void* pointer) {
    const auto& attempt = *static_cast<RegistrationAttempt*>(pointer);
    auto& race = *attempt.race;
    pthread_mutex_lock(&race.mutex);
    while (!race.start) pthread_cond_wait(&race.condition, &race.mutex);
    pthread_mutex_unlock(&race.mutex);
    GuestEnvironment environment;
    race.runtime.configure(environment.state);
    const uint32_t handle = race.runtime.register_main();
    pthread_mutex_lock(&race.mutex);
    race.handles[attempt.index] = handle;
    ++race.attempted;
    pthread_cond_broadcast(&race.condition);
    if (handle) while (race.attempted < race.expected) pthread_cond_wait(&race.condition, &race.mutex);
    pthread_mutex_unlock(&race.mutex);
    // Shutdown must execute on the winning registered host pthread. Both
    // registration attempts have completed before it can unpublish anything.
    if (handle) {
        std::string error;
        const bool shutdown = race.runtime.shutdown(&error);
        pthread_mutex_lock(&race.mutex);
        if (shutdown) ++race.shutdown_successes;
        else race.error = error;
        pthread_mutex_unlock(&race.mutex);
    }
    return nullptr;
}
bool initial_registration_probe(std::string* error) {
    std::unique_ptr<ModulePackage> package;
    if (!decode_package(dm_kernel_bytes, dm_kernel_size, dm_kernel_package_sha256, &package, error)) return false;
    std::vector<std::unique_ptr<ModulePackage>> packages;
    packages.push_back(std::move(package));
    HleRuntime runtime;
    if (!runtime.load(std::move(packages), false, nullptr, nullptr, error)) return false;
    RegistrationRace race(runtime);
    RegistrationAttempt attempts[]{{&race, 0}, {&race, 1}};
    pthread_t threads[2]{};
    unsigned created = 0;
    for (; created < 2; ++created)
        if (pthread_create(&threads[created], nullptr, registration_thread, &attempts[created])) break;
    pthread_mutex_lock(&race.mutex);
    race.expected = created;
    race.start = true;
    pthread_cond_broadcast(&race.condition);
    pthread_mutex_unlock(&race.mutex);
    bool joined = true;
    for (unsigned i = 0; i < created; ++i) joined &= pthread_join(threads[i], nullptr) == 0;
    const unsigned winners = unsigned(race.handles[0] != 0) + unsigned(race.handles[1] != 0);
    // No winner means no thread affinity was established; clean up on this
    // host thread. In the success path only the winner performs shutdown.
    if (!winners && !runtime.shutdown(error)) return false;
    unsigned handles = 0, live = 0, objects = 0;
    dm_android_kernel_thread_stats(&handles, &live, &objects);
    const bool passed = created == 2 && joined && winners == 1 && race.shutdown_successes == 1 &&
        runtime.process().modules().empty() && !handles && !live && !objects;
    if (!passed) *error = "initial pthread registration race failed: " + race.error;
    return passed;
}
}

std::string dm_android_run_kernel_probes() {
    std::array<Check, 5> checks{{{"registry", false, "not reached"}, {"memory", false, "not reached"},
                                {"threads", false, "not reached"}, {"clock", false, "not reached"},
                                {"lifetime", false, "not reached"}}};
    HleRuntime runtime;
    GuestEnvironment environment;
    GuestStack stack(256 * 1024);
    std::string error;
    std::unique_ptr<ModulePackage> package;
    bool ready = stack.valid() && decode_package(dm_kernel_bytes, dm_kernel_size, dm_kernel_package_sha256,
                                                  &package, &error);
    if (ready) {
        std::vector<std::unique_ptr<ModulePackage>> packages;
        packages.push_back(std::move(package));
        ready = runtime.load(std::move(packages), false, nullptr, nullptr, &error);
    }
    uintptr_t results_address = 0;
    if (ready) {
        runtime.configure(environment.state);
        ready = runtime.register_main() != 0 && runtime.process().symbol("kernel_results", &results_address);
    }
    auto call = [&](const char* name, uint64_t* value) {
        uintptr_t address = 0;
        GuestCallResult result;
        if (!ready || !runtime.process().symbol(name, &address) ||
            !stack.call(environment.state, address, uint64_t{0}, &result, &error) || result.exited) return false;
        *value = result.value;
        return true;
    };
    std::array<uint64_t, 38> values{};
    auto read_results = [&] { if (results_address) std::memcpy(values.data(), reinterpret_cast<void*>(results_address), sizeof(values)); };
    uint64_t value = 0;
    if (ready) {
        const bool network = call("kernel_network_entry", &value) && value == 0;
        read_results();
        checks[0].passed = network && values[2] == 73 && static_cast<int32_t>(values[3]) == -1 && values[4] == 50 &&
            runtime.registry().force_hits("nnsocketSetLastErrno") > 0 &&
            runtime.registry().force_hits("nnsocketGetLastErrno") > 0 &&
            runtime.registry().force_hits("nnsocketSocket") > 0;
        checks[0].detail = checks[0].passed ? "Production NSO imports bind retained original C HLE; errno set/get and offline Socket=-1/ENETDOWN=50" : "Original C HLE failed: " + error + " words=" + words(values);
        const bool mapped = call("kernel_memory_entry", &value) && value == 0;
        read_results();
        // MemoryInfo at 0x8200: base,size,state/attr,permission/refcounts.
        checks[1].passed = mapped && values[0] && values[1] && values[32] == values[1] &&
            values[33] == 0x20000 && (values[34] & UINT32_MAX) == 0x0b && (values[35] & UINT32_MAX) == 3;
        uint64_t unknown = 0;
        checks[1].passed &= call("kernel_unknown_entry", &unknown) && unknown == 0x4201;
        auto heap_environment = std::make_unique<GuestEnvironment>();
        runtime.configure(heap_environment->state);
        GuestCallResult owned_result;
        checks[1].passed &= stack.call(heap_environment->state, reinterpret_cast<uintptr_t>(&kernel_owned_memory_entry),
            uint64_t{0}, &owned_result, &error) && !owned_result.exited && owned_result.value == 1;
        checks[1].detail = checks[1].passed ? "Rewritten SetHeapSize/GetInfo/MapMemory/QueryMemory expose SDK RW stack; heap-owned TLS/TLR/object exact spans remain RW; unknown SVC returns NotImplemented=0x4201" : "Memory/SVC failed: " + error + " words=" + words(values);
        if (mapped) {
            const bool joined = call("kernel_thread_entry", &value) && value == 0;
            read_results();
            const uint64_t child_sp = values[13];
            checks[2].passed = joined && values[8] == 0xfa01 && values[9] == 0 && values[10] == 0 && values[11] == 73 &&
                values[12] == 0 && child_sp >= values[1] && child_sp < values[1] + 0x20000 &&
                values[14] == 91 && values[15] == 1 && values[16] && values[17] &&
                values[16] != environment.state.guest_tpidr_el0 &&
                values[17] != environment.state.guest_tpidrro_el0 && runtime.svc_count(8) == 1 &&
                runtime.svc_count(9) == 1 && runtime.svc_count(0x0a) == 1;
            checks[2].detail = checks[2].passed ? "Real Create/Start/Exit on SDK mapped stack, Create-owned pin rejects early unmap, event and exited-thread waits, per-thread errno/TLS/TLR and final unmap" : "Thread/stack lifetime failed: " + error + " words=" + words(values);
        }
        uint64_t before = 0, after = 0, frozen = 0, overlap = 0, resumed = 0;
        bool clock = call("kernel_tick_entry", &before);
        pause_clock();
        clock &= call("kernel_tick_entry", &after) && after > before;
        guest_clock_freeze_for(1, 1);
        guest_clock_freeze_for(2, 1);
        clock &= call("kernel_tick_entry", &frozen);
        pause_clock();
        guest_clock_freeze_for(1, 0);
        clock &= call("kernel_tick_entry", &overlap) && overlap == frozen;
        guest_clock_freeze_for(2, 0);
        pause_clock();
        clock &= call("kernel_tick_entry", &resumed) && resumed > frozen;
        checks[3].passed = clock;
        checks[3].detail = clock ? "Original wall guest clock advances through rewritten GetSystemTick; overlapping background/keyboard freeze reasons hold until both release" : "Guest clock/freeze failed: " + error;
    } else {
        for (auto& check : checks) check.detail = "Kernel setup failed: " + (error.empty() ? stack.error() : error);
    }
    unsigned handles = 0, live = 0, objects = 0;
    const bool invocation_pin = ready && concurrent_lifetime_probe(runtime, &error);
    const std::string invocation_error = error;
    const bool shut_down = runtime.shutdown(&error);
    dm_android_kernel_thread_stats(&handles, &live, &objects);
    checks[4].passed = ready && invocation_pin && shut_down && !handles && !live && !objects &&
        dm_android_peek_guest_state() == nullptr && runtime.process().modules().empty();
    if (checks[4].passed) checks[4].passed = initial_registration_probe(&error);
    checks[4].detail = checks[4].passed ? "Active invocation rejects unload; after joined exit resources clear; racing initial pthread registrations select one owner, which alone shuts down safely" : "Kernel teardown failed: " + (invocation_pin ? error : invocation_error);
    std::ostringstream json;
    json << "{\"schemaVersion\":4,\"phase\":\"2\",\"syntheticOnly\":true,\"gamePlayable\":false,\"environment\":{\"pageSize\":"
         << sysconf(_SC_PAGESIZE) << ",\"abi\":\"arm64-v8a\"},\"checks\":[";
    for (size_t i = 0; i < checks.size(); ++i) {
        if (i) json << ',';
        json << "{\"id\":\"" << checks[i].id << "\",\"status\":\"" << (checks[i].passed ? "PASS" : "FAIL")
             << "\",\"detail\":\"" << escape(checks[i].detail) << "\"}";
    }
    json << "],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return json.str();
}

namespace {
struct alignas(16) NativeWaitFrames {
    uint64_t before_guard[2]{0x1122334455667788,0x8877665544332211};
    DmGuestRegisterFrame frames[2]{};
    uint64_t after_guard[2]{0xaabbccddeeff0011,0x1100ffeeddccbbaa};
    bool guards() const {
        return before_guard[0]==0x1122334455667788 && before_guard[1]==0x8877665544332211 &&
               after_guard[0]==0xaabbccddeeff0011 && after_guard[1]==0x1100ffeeddccbbaa;
    }
};
struct alignas(16) NativeWaitMutex {
    uint64_t before[2]{0x1020304050607080,0x8070605040302010};
    uint32_t cell=0;
    uint32_t adjacent=0xabcdef12;
    uint64_t after=0x8877665544332211;
    bool guards() const {
        return before[0]==0x1020304050607080 && before[1]==0x8070605040302010 &&
               adjacent==0xabcdef12 && after==0x8877665544332211;
    }
};
static_assert(offsetof(NativeWaitMutex,cell)==16);
struct HostWaitState {uint64_t x18,tp,sp;};
__attribute__((always_inline)) inline HostWaitState host_wait_state() {
    HostWaitState state{};
    asm volatile("mov %0,x18\n mrs %1,tpidr_el0\n mov %2,sp"
                 :"=r"(state.x18),"=r"(state.tp),"=r"(state.sp));
    return state;
}
bool same_host_wait_state(const HostWaitState& a,const HostWaitState& b) {
    return a.x18==b.x18 && a.tp==b.tp && a.sp==b.sp;
}
struct WaitRelease {
    uint16_t* count=nullptr;
    uint32_t* cell=nullptr;
    uint16_t old_count=0;
    std::atomic<bool> stop{false},saw_increment{false},saw_restore{false},released{false};
};
void* native_wait_release(void* opaque) {
    auto& watch=*static_cast<WaitRelease*>(opaque);
    const uint16_t incremented=static_cast<uint16_t>(watch.old_count+1);
    // Observe the real guest's busy path before the sole external release.
    // No SEV/SEVL, signal, sleep, yield, or periodic rescue manufactures a wake.
    while(!watch.stop.load(std::memory_order_acquire)) {
        const uint16_t value=__atomic_load_n(watch.count,__ATOMIC_ACQUIRE);
        if(value==incremented)watch.saw_increment.store(true,std::memory_order_release);
        if(watch.saw_increment.load(std::memory_order_acquire) && value==watch.old_count) {
            watch.saw_restore.store(true,std::memory_order_release);
            if(__atomic_load_n(watch.cell,__ATOMIC_ACQUIRE)!=1)return nullptr;
            __atomic_store_n(watch.cell,uint32_t{0},__ATOMIC_RELEASE);
            watch.released.store(true,std::memory_order_release);
            return nullptr;
        }
    }
    return nullptr;
}
bool native_wait_frames_equal(const NativeWaitFrames& snapshots,bool svc_only) {
    const auto& before=snapshots.frames[0];const auto& after=snapshots.frames[1];
    if(!snapshots.guards() || before.guest_sp!=after.guest_sp || before.nzcv!=after.nzcv ||
       before.fpsr!=after.fpsr || before.fpcr!=after.fpcr ||
       std::memcmp(before.q,after.q,sizeof(before.q)))return false;
    for(unsigned reg=0;reg<31;++reg) {
        // The busy-mutex ABI clobbers only these caller-saved registers. BL
        // changes x30; the complete callee-saved set and virtual x18 stay equal.
        if(!svc_only && (reg==8 || reg==9 || reg==10 || reg==30))continue;
        if(before.x[reg]!=after.x[reg])return false;
    }
    return before.nzcv==0xb0000000 && before.x[18]==0x1818181818181818;
}
}

std::string dm_android_run_native_wait_probe() {
    const unsigned long hwcap=getauxval(AT_HWCAP);
    const bool capable=dm_android::native_wait_event_stream_capable(hwcap) &&
                       dm_android::native_wait_event_stream_available();
    std::string error;
    bool passed=capable,ready=false;
    uint64_t svc_calls=0;
    unsigned cases=0,contentions=0;
    unsigned layout_cases[2]{},layout_contentions[2]{};
    HleRuntime runtime;
    GuestEnvironment environment;
    GuestStack stack(256*1024);
    uintptr_t wait_entries[2]{},svc_entry=0;
    constexpr const char* wait_symbols[]{"native_wait_entry","native_wait_compact_entry"};
    if(capable) {
        std::unique_ptr<ModulePackage> package;
        ready=stack.valid() && decode_package(dm_native_wait_bytes,dm_native_wait_size,
              dm_native_wait_package_sha256,&package,&error);
        if(ready) {
            std::vector<std::unique_ptr<ModulePackage>> packages;
            packages.push_back(std::move(package));
            ready=runtime.load(std::move(packages),false,nullptr,nullptr,&error);
        }
        if(ready) {
            runtime.configure(environment.state); // Same host pthread as every call below.
            environment.state.virtual_x18=0x1818181818181818;
            ready=runtime.register_main()!=0 && runtime.process().symbol(wait_symbols[0],&wait_entries[0]) &&
                  runtime.process().symbol(wait_symbols[1],&wait_entries[1]) &&
                  runtime.process().symbol("native_wait_svc_frame_entry",&svc_entry);
        }
        passed=ready;
    } else error="AT_HWCAP lacks supported EVTSTRM; native WFE execution was not attempted";
    auto* tlr=reinterpret_cast<uint8_t*>(environment.state.guest_tpidrro_el0);
    if(ready) {
        NativeWaitFrames snapshots;
        std::array<uint8_t,0x200> tlr_before{};
        std::memcpy(tlr_before.data(),tlr,tlr_before.size());
        GuestCallResult result;
        const auto host_before=host_wait_state();
        const bool called=stack.call(environment.state,svc_entry,reinterpret_cast<uintptr_t>(snapshots.frames),&result,&error);
        const auto host_after=host_wait_state();
        svc_calls=runtime.svc_count(0x36);
        passed=called && !result.exited && result.value==0 && svc_calls==1 &&
            native_wait_frames_equal(snapshots,true) && same_host_wait_state(host_before,host_after) &&
            !std::memcmp(tlr_before.data(),tlr,tlr_before.size()) && !dm_android_peek_guest_state();
        if(!passed && error.empty())error="owned SVC36 frame/TLR/host-state preservation failed";
    }
    for(unsigned layout=0;passed && layout<2;++layout) {
    for(unsigned index=0;passed && index<5;++index) {
        const uint16_t old_count=index==0 ? 0 : index==1 ? 7 : index==2 ? 0xffff : index==3 ? 0 : 7;
        const bool contended=index>=3;
        NativeWaitMutex mutex;
        NativeWaitFrames snapshots;
        mutex.cell=contended ? 1 : 0;
        std::memcpy(tlr+0x100,&old_count,sizeof(old_count));
        const uint16_t zero=0;std::memcpy(tlr+0x102,&zero,sizeof(zero));
        std::array<uint8_t,0x200> tlr_before{};
        std::memcpy(tlr_before.data(),tlr,tlr_before.size());
        WaitRelease watch;watch.count=reinterpret_cast<uint16_t*>(tlr+0x100);
        watch.cell=&mutex.cell;watch.old_count=old_count;
        pthread_t producer{};
        bool created=false;
        if(contended) {
            created=pthread_create(&producer,nullptr,native_wait_release,&watch)==0;
            if(!created){passed=false;error="cannot create external release producer";break;}
        }
        __android_log_print(ANDROID_LOG_INFO,"DmNativeWait","enter layout=%s case=%u old=%u contended=%u hwcap=%lx",
                            wait_symbols[layout],index,unsigned(old_count),unsigned(contended),hwcap);
        const uint64_t args[]{reinterpret_cast<uintptr_t>(&mutex),reinterpret_cast<uintptr_t>(snapshots.frames)};
        GuestCallResult result;
        const auto host_before=host_wait_state();
        const bool called=stack.call(environment.state,wait_entries[layout],args,2,&result,&error);
        const auto host_after=host_wait_state();
        watch.stop.store(true,std::memory_order_release);
        const bool joined=!created || pthread_join(producer,nullptr)==0;
        const uint16_t incremented=static_cast<uint16_t>(old_count+1);
        std::memcpy(tlr_before.data()+0x100,&incremented,sizeof(incremented));
        passed=called && !result.exited && result.value==0 && joined && mutex.guards() &&
            __atomic_load_n(&mutex.cell,__ATOMIC_ACQUIRE)==1 && native_wait_frames_equal(snapshots,false) &&
            same_host_wait_state(host_before,host_after) && !dm_android_peek_guest_state() &&
            !std::memcmp(tlr_before.data(),tlr,tlr_before.size()) && runtime.svc_count(0x36)==svc_calls;
        if(contended)passed=passed && watch.saw_increment.load() && watch.saw_restore.load() && watch.released.load();
        if(passed){++cases;++layout_cases[layout];if(contended){++contentions;++layout_contentions[layout];}}
        else if(error.empty())error="native wait acquisition/count/frame/guards or observed busy path failed at "+std::string(wait_symbols[layout])+" case "+std::to_string(index);
        __android_log_print(ANDROID_LOG_INFO,"DmNativeWait","leave layout=%s case=%u passed=%u",wait_symbols[layout],index,unsigned(passed));
    }
    }
    std::string close_error;
    const bool closed=runtime.shutdown(&close_error);
    if(!closed){passed=false;if(error.empty())error="native wait teardown failed: "+close_error;}
    unsigned handles=0,live=0,objects=0;
    dm_android_kernel_thread_stats(&handles,&live,&objects);
    if(handles || live || objects || !runtime.process().modules().empty() || dm_android_peek_guest_state()) {
        passed=false;if(error.empty())error="native wait resources did not retire";
    }
    std::ostringstream json;
    json<<"{\"schemaVersion\":2,\"syntheticOnly\":true,\"gamePlayable\":false,\"originalSdk\":\"NOT_RUN\","
        <<"\"status\":\""<<(passed?"PASS":capable?"FAIL":"UNSUPPORTED")<<"\",\"hwcap\":"<<hwcap
        <<",\"eventStream\":"<<(capable?"true":"false")<<",\"svc36Calls\":"<<svc_calls
        <<",\"mutexCases\":"<<cases<<",\"contendedCases\":"<<contentions
        <<",\"layouts\":[{\"symbol\":\"native_wait_entry\",\"nativeUnionWords\":45,\"mutexCases\":"<<layout_cases[0]
        <<",\"contendedCases\":"<<layout_contentions[0]<<"},{\"symbol\":\"native_wait_compact_entry\",\"nativeUnionWords\":39,\"mutexCases\":"<<layout_cases[1]
        <<",\"contendedCases\":"<<layout_contentions[1]<<"}]"
        <<",\"hardwareFailedStores\":\"NOT_MEASURED\",\"detail\":\""<<escape(error)<<"\"}";
    return json.str();
}
