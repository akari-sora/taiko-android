#include "kernel_probes.h"
#include "kernel_runtime.h"
#include "kernel_platform.h"
#include "kernel_fixtures/generated_kernel.h"
#include <array>
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
