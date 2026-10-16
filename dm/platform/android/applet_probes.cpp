#include "applet_probes.h"
#include "kernel_runtime.h"
#include "kernel_platform.h"
#include "kernel_memory_android.h"
#include "guest_memory.h"
#include "guest_parameters.h"
#include "oe_platform.h"
#include "observation_fixtures/generated_observations.h"
#include "applet_fixtures/generated_applets.h"
#include <array>
#include <algorithm>
#include <condition_variable>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <mutex>
#include <sstream>
#include <unistd.h>

extern "C" {
uint64_t svc_dispatch(int, uint64_t*, uint64_t);
void dm_set_opmode(int);
void dm_oe_ui_opmode(int);
void dm_focus_set(int);
}
namespace dm_android { void input_activity_restore_parameter_provider(); }

namespace {
using namespace dm_android;
constexpr uint32_t poison = 0xbadc0ffe;
struct SavedEnvironment {
    explicit SavedEnvironment(const char* name):key(name) {
        const char* old = std::getenv(key); present = old != nullptr; if (old) value = old;
    }
    ~SavedEnvironment() { if (present) setenv(key, value.c_str(), 1); else unsetenv(key); }
    const char* key; bool present = false; std::string value;
};
struct FixtureBasis {
    uint64_t values[4]{};
    bool available = true;
    static bool capture(uint64_t out[4], void* context) {
        const auto& self = *static_cast<FixtureBasis*>(context);
        if (!self.available) return false;
        std::memcpy(out, self.values, sizeof(self.values)); return true;
    }
    void install() { dm_android_set_parameter_provider(capture, this); }
    ~FixtureBasis() { input_activity_restore_parameter_provider(); }
};
std::string escape(const std::string& value) {
    std::string out; for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') out += '\\';
        out += ch < 32 ? ' ' : static_cast<char>(ch);
    } return out;
}
std::string hex(const uint8_t* bytes, size_t size) {
    constexpr char digits[]="0123456789abcdef";
    std::string result; result.reserve(size*2);
    for(size_t i=0;i<size;++i) {result+=digits[bytes[i]>>4];result+=digits[bytes[i]&15];}
    return result;
}
struct ModuleProof {
    std::string name, build_id, source_sha256, package_sha256, profile_digest;
    uint32_t profile_class=0;
};
struct CopyBridge {
    std::mutex mutex;
    std::condition_variable condition;
    uintptr_t targets[2]{};
    uint64_t receipts[2][8]{};
    unsigned phases[2]{};
    bool valid = true;
};
std::mutex loader_barrier_mutex;
std::condition_variable loader_barrier_condition;
AppLoadBarrier loader_barrier;
uint64_t loader_barrier_serial = 0;
bool pause_fixture_load() {
    std::unique_lock<std::mutex> lock(loader_barrier_mutex);
    if (!loader_barrier.armed) return true;
    // Only this exact diagnostic import can reach the pause. The resolver is
    // called synchronously by Process::load inside HleRuntime::load's lifecycle
    // scope, before OE bind/publication. No Process/context pointer is retained.
    loader_barrier.armed = false;
    loader_barrier.waiting = true;
    loader_barrier_condition.notify_all();
    const bool released = loader_barrier_condition.wait_for(lock, std::chrono::seconds(10), [] {
        return loader_barrier.released;
    });
    loader_barrier.waiting = false;
    if (!released) loader_barrier.timed_out = true;
    loader_barrier_condition.notify_all();
    // False leaves the import unresolved so the real transactional loader tears
    // down its candidate mappings; no active runtime or callback is published.
    return released;
}
// An explicit diagnostic ABI, not a generic guest-memory writer. Process lifetime
// is pinned by the caller's active invocation and the source is always staged.
std::atomic<CopyBridge*> copy_bridge{nullptr};
extern "C" int applet_checked_copy(uint64_t source, void* destination, size_t size) {
    auto* bridge = copy_bridge.load(std::memory_order_acquire);
    if (!bridge || size != 64) return 0;
    uint64_t stage[8]{};
    if (!dm_android_guest_copy(source, stage, sizeof(stage))) return 0;
    std::lock_guard<std::mutex> lock(bridge->mutex);
    const uintptr_t target = reinterpret_cast<uintptr_t>(destination);
    const int index = target == bridge->targets[0] ? 0 : target == bridge->targets[1] ? 1 : -1;
    if (index < 0 || !target) return 0;
    uintptr_t owned_bottom = 0; size_t owned_size = 0;
    // SDK local stacks are borrowed: only the kernel owner can authorize their
    // read. This additionally proves the generic owned-stack path did not apply.
    const bool borrowed = !active_guest_stack_owned_bounds(source, &owned_bottom, &owned_size);
    uint64_t kernel_stage[8]{};
    const bool kernel = dm_android_kernel_memory_copy_readable(source, kernel_stage, sizeof(kernel_stage));
    bridge->valid &= borrowed && kernel && !std::memcmp(stage, kernel_stage, sizeof(stage)) &&
        stage[4] == source && stage[5] == 0xfeedbeef &&
        stage[7] == bridge->phases[index] + 1 && stage[7] <= 2;
    std::memcpy(destination, stage, sizeof(stage));
    std::memcpy(bridge->receipts[index], stage, sizeof(stage));
    bridge->phases[index] = static_cast<unsigned>(stage[7]);
    bridge->condition.notify_all(); return 1;
}
bool resolver(const char* name, bool forced, uintptr_t* address, void*) {
    if (forced || std::strcmp(name, "dm_applet_checked_copy")) return false;
    if (!pause_fixture_load()) return false;
    *address = reinterpret_cast<uintptr_t>(applet_checked_copy); return true;
}
struct Query { uint64_t mode, performance, focus, language; uint8_t id[16]; uint64_t marker; };
struct Pop { uint32_t popped, message; uint64_t parameters[4]; };
static_assert(sizeof(Query) == 56 && sizeof(Pop) == 40, "public fixture records");
struct Probe {
    HleRuntime runtime;
    GuestEnvironment environment;
    GuestStack stack{256 * 1024};
    CopyBridge bridge;
    uintptr_t query_record = 0, pop_record = 0, parameter_record = 0, create_record = 0, sdk_entry = 0;
    bool opened = false;
    bool load(std::string* error) {
        std::unique_ptr<ModulePackage> main, applet;
        if (!stack.valid() || !decode_package(dm_observation_main_bytes, dm_observation_main_size,
              dm_observation_main_package_sha256, &main, error) ||
            !decode_package(dm_applet_bytes, dm_applet_size, dm_applet_package_sha256, &applet, error)) return false;
        if (main->profile_class != 1 || applet->profile_class || applet->profile || !applet->parameters.empty())
            return false;
        std::vector<std::unique_ptr<ModulePackage>> packages;
        packages.push_back(std::move(main)); packages.push_back(std::move(applet));
        if (!runtime.load(std::move(packages), false, resolver, nullptr, error)) return false;
        opened = true; runtime.configure(environment.state);
        const auto symbol = [&](const char* name, uintptr_t* address) { return runtime.process().symbol(name, address); };
        if (!symbol("applet_query_result", &query_record) || !symbol("applet_pop_result", &pop_record) ||
            !symbol("applet_parameter_result", &parameter_record) || !symbol("applet_create_result", &create_record) ||
            !symbol("applet_sdk_context_a", &bridge.targets[0]) || !symbol("applet_sdk_context_b", &bridge.targets[1]) ||
            !symbol("applet_sdk_entry", &sdk_entry)) return false;
        for (uintptr_t target : bridge.targets) {
            const auto& module = *runtime.process().modules()[1];
            const auto base = reinterpret_cast<uintptr_t>(module.mapping.base);
            if (target < base + module.package->data_offset || target + 80 >
                base + module.package->data_offset + module.package->data_bytes) return false;
        }
        return true;
    }
    bool call(const char* name, std::initializer_list<uint64_t> args, uint64_t* value, std::string* error) {
        uintptr_t address = 0; GuestCallResult result;
        if (!runtime.process().symbol(name, &address) || args.size() > 8 ||
            !stack.call(environment.state, address, args.begin(), args.size(), &result, error) || result.exited) return false;
        if (value) *value = result.value; return true;
    }
    bool setup(uint64_t op, uint64_t perf, std::string* error) {
        uint64_t result = 0;
        return call("applet_setup", {op, perf, 1, 1, 1, 0x1234}, &result, error) && result == 0x1ff;
    }
    bool query(Query* query, std::string* error) {
        uint64_t result = 0;
        return call("applet_query", {}, &result, error) && result == 0x3e00 &&
            dm_android_guest_copy(query_record, query, sizeof(*query)) && query->marker == 0x3e00;
    }
    bool pop(Pop* pop, std::string* error) {
        uint64_t result = 0;
        return call("applet_pop", {poison}, &result, error) &&
            dm_android_guest_copy(pop_record, pop, sizeof(*pop)) && pop->popped == result;
    }
    bool drain(std::string* error) {
        for (unsigned i = 0; i != 33; ++i) { Pop result{}; if (!pop(&result, error)) return false; if (!result.popped) return result.message == poison; }
        return false;
    }
    bool close(std::string* error) {
        if (!runtime.shutdown(error)) return false;
        opened = false; return true;
    }
};
std::vector<ModuleProof> capture_modules(HleRuntime& runtime) {
    std::vector<ModuleProof> result;
    // The decoder already checked these trusted whole-package identities. Copy
    // all loaded package metadata now; the report must not dereference mappings
    // or ModulePackage objects after runtime teardown.
    const uint8_t* package_hashes[]={dm_observation_main_package_sha256,dm_applet_package_sha256};
    const auto& modules=runtime.process().modules();
    for(size_t i=0;i<modules.size();++i) {
        const auto& package=*modules[i]->package;
        ModuleProof proof;
        proof.name=package.name;
        proof.build_id=hex(package.build_id.data(),package.build_id.size());
        proof.source_sha256=hex(package.source_sha256.data(),package.source_sha256.size());
        if(i<std::size(package_hashes)) proof.package_sha256=hex(package_hashes[i],32);
        proof.profile_class=package.profile_class;
        proof.profile_digest=hex(package.profile_digest.data(),package.profile_digest.size());
        result.push_back(std::move(proof));
    }
    return result;
}
struct SvcRequest { int number; uint64_t registers[8]{}; };
uint64_t svc_entry(uint64_t argument) {
    auto& request = *reinterpret_cast<SvcRequest*>(argument);
    svc_dispatch(request.number, request.registers, 0); return request.registers[0];
}
bool svc(Probe& probe, int number, std::initializer_list<uint64_t> args, SvcRequest* result, std::string* error) {
    *result = SvcRequest{number,{}}; std::copy(args.begin(), args.end(), result->registers);
    GuestCallResult returned;
    return probe.stack.call(probe.environment.state, reinterpret_cast<uintptr_t>(svc_entry),
        reinterpret_cast<uintptr_t>(result), &returned, error) && !returned.exited && !returned.value;
}
struct Consumer {
    Probe* probe;
    uint64_t parameters[4]{};
    bool passed = false;
};
void* consume_on_thread(void* opaque) {
    auto& consumer = *static_cast<Consumer*>(opaque);
    GuestEnvironment environment; GuestStack stack(128*1024);
    consumer.probe->runtime.configure(environment.state);
    uintptr_t entry=0; GuestCallResult result; std::string error; const uint64_t argument=poison;
    consumer.passed=consumer.probe->runtime.process().symbol("applet_pop",&entry) &&
        stack.call(environment.state,entry,argument,&result,&error) && !result.exited && result.value==1 &&
        environment.state.parameter_valid_mask==15;
    std::memcpy(consumer.parameters,environment.state.parameters,sizeof(consumer.parameters));
    return nullptr;
}
std::mutex persistent_mutex;
std::unique_ptr<Probe> persistent;
uint64_t persistent_serial = 0, persistent_handle = 0;
std::string receipt_json(Probe& probe, const Query& query, const std::vector<Pop>& pops) {
    const auto receipt = oe_platform_receipt();
    std::ostringstream out;
    out << "{\"schemaVersion\":7,\"phase\":\"5\",\"syntheticOnly\":true,\"gamePlayable\":false,"
        << "\"epoch\":" << receipt.epoch << ",\"generation\":" << receipt.platform.generation
        << ",\"revision\":" << receipt.platform.revision << ",\"open\":" << (receipt.open ? "true" : "false")
        << ",\"attached\":" << (receipt.platform.attached ? "true" : "false")
        << ",\"started\":" << (receipt.platform.started ? "true" : "false")
        << ",\"stopped\":" << (receipt.platform.stopped ? "true" : "false")
        << ",\"resumed\":" << (receipt.platform.resumed ? "true" : "false")
        << ",\"focused\":" << (receipt.platform.focused ? "true" : "false")
        << ",\"windowAvailable\":" << (receipt.platform.window_available ? "true" : "false")
        << ",\"nativeWidth\":" << receipt.platform.native_width << ",\"nativeHeight\":" << receipt.platform.native_height
        << ",\"adapterFocus\":" << receipt.core.focus << ",\"guestFocus\":" << query.focus
        << ",\"guestOperationMode\":" << query.mode << ",\"guestPerformanceMode\":" << query.performance
        << ",\"refreshSuccesses\":" << probe.runtime.oe_refresh_successes()
        << ",\"refreshDeferred\":" << probe.runtime.oe_refresh_deferred()
        << ",\"parameterValidMask\":" << probe.environment.state.parameter_valid_mask << ",\"parameters\":[";
    for (unsigned i=0;i<4;++i) { if(i) out << ','; out << probe.environment.state.parameters[i]; }
    out << "],\"pops\":[";
    for(size_t i=0;i<pops.size();++i) { if(i) out << ','; out << "{\"message\":" << pops[i].message << ",\"parameters\":[";
        for(unsigned j=0;j<4;++j) {if(j) out << ',';out << pops[i].parameters[j];} out << "]}"; }
    out << "],\"capabilities\":{\"prePop\":false,\"uiReread\":false,\"renderer\":false,\"save\":false,\"audio\":false,\"gpu\":false},"
        << "\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return out.str();
}
}

bool dm_android_applet_loader_arm(uint64_t* id) {
    std::lock_guard<std::mutex> lock(loader_barrier_mutex);
    if (!id || loader_barrier.armed || loader_barrier.waiting || loader_barrier_serial == UINT64_MAX) return false;
    loader_barrier = AppLoadBarrier{};
    loader_barrier.id = ++loader_barrier_serial;
    loader_barrier.armed = true;
    *id = loader_barrier.id;
    return true;
}
AppLoadBarrier dm_android_applet_loader_snapshot() {
    std::lock_guard<std::mutex> lock(loader_barrier_mutex);
    return loader_barrier;
}
bool dm_android_applet_loader_release(uint64_t id) {
    std::lock_guard<std::mutex> lock(loader_barrier_mutex);
    if (!id || id != loader_barrier.id || loader_barrier.released || loader_barrier.timed_out) return false;
    loader_barrier.armed = false;
    loader_barrier.released = true;
    loader_barrier_condition.notify_all();
    return true;
}

bool dm_android_applet_begin(uint64_t* handle, std::string* error) {
    std::lock_guard<std::mutex> lock(persistent_mutex);
    if (error) error->clear();
    if (!handle || persistent || persistent_serial == UINT64_MAX) {
        if(error) *error = "applet session already active or invalid output"; return false;
    }
    uint64_t values[4]{};
    if (!dm_android_capture_guest_parameters(values)) { if(error) *error = "real native-window parameter basis unavailable"; return false; }
    auto candidate = std::make_unique<Probe>();
    if (!candidate->load(error) || !candidate->setup(1, 1, error)) return false;
    persistent_handle = ++persistent_serial; *handle = persistent_handle; persistent = std::move(candidate); return true;
}
bool dm_android_applet_poll(uint64_t handle, std::string* report, std::string* error) {
    std::lock_guard<std::mutex> lock(persistent_mutex);
    if(error) error->clear();
    if(!persistent || !handle || handle != persistent_handle || !report) {if(error) *error = "stale applet session";return false;}
    std::vector<Pop> pops;
    for(unsigned i=0;i<33;++i) {
        Pop result{}; if(!persistent->pop(&result,error)) return false;
        if(!result.popped) {if(result.message != poison) return false;break;}
        pops.push_back(result); if(i==32) return false;
    }
    Query query{}; if(!persistent->query(&query,error)) return false;
    *report = receipt_json(*persistent,query,pops); return true;
}
bool dm_android_applet_end(uint64_t handle, std::string* error) {
    std::lock_guard<std::mutex> lock(persistent_mutex);
    if(error) error->clear();
    if(!persistent || !handle || handle != persistent_handle) {if(error) *error = "stale applet session";return false;}
    if(!persistent->close(error)) return false;
    persistent.reset(); persistent_handle = 0; return true;
}

std::string dm_android_run_applet_probes() {
    struct Check {const char* id; bool passed=false; std::string detail="not reached";};
    std::array<Check,6> checks{{{"exports"},{"notifications"},{"parameters"},{"sdk_copy"},{"preflight"},{"lifetime"}}};
    SavedEnvironment script("DM_OE_SCRIPT"), mode("DM_OPMODE"), language("DM_LANG");
    unsetenv("DM_OE_SCRIPT"); setenv("DM_OPMODE","1",1); unsetenv("DM_LANG");
    Probe probe; std::string error; bool ready=probe.load(&error);
    const auto modules=capture_modules(probe.runtime);
    const bool parameter_basis_available=ready && probe.environment.state.parameter_valid_mask==15;
    bool oe_core_available=false;
    if(ready) ready=probe.runtime.register_main()!=0;
    if(ready) {
        Query query{}; Pop popped{};
        const uint8_t expected_id[16]={0x78,0x62,0x6c,0x00,0x53,0x57,0x4e,0x41,0x54,0x49,0x56,0x45,0x31,0x30,0x30,0x31};
        uint64_t default_language=0; std::memcpy(&default_language,"zh-Hans",7);
        oe_core_available=probe.setup(0x101,0x101,&error);
        bool exports=oe_core_available && probe.query(&query,&error) && query.mode==1 && query.performance==1 &&
            query.language==default_language && !std::memcmp(query.id,expected_id,sizeof(expected_id));
        setenv("DM_LANG","abcdefghi",1); uint64_t truncated=0; std::memcpy(&truncated,"abcdefg",7);
        exports &= probe.query(&query,&error) && query.language==truncated;
        setenv("DM_LANG","ja",1); exports &= probe.query(&query,&error) && query.language==0x616a;
        exports &= probe.drain(&error) && probe.pop(&popped,&error) && !popped.popped && popped.message==poison;
        const auto capabilities=oe_platform_receipt().core;
        checks[0].passed=exports && capabilities.has_ops && capabilities.has_post_pop && !capabilities.has_pre_pop && !capabilities.has_ui_reread;
        checks[0].detail="15 real imported OE calls: nine setup, five query, pop; exact local UUID, dynamic default/truncated language, empty output poison; renderer/UI hooks unavailable";
        bool notifications=probe.setup(0x100,0x100,&error);
        dm_set_opmode(0); notifications &= probe.pop(&popped,&error) && !popped.popped;
        notifications &= probe.setup(0x101,0x101,&error);
        dm_set_opmode(1);
        notifications &= probe.pop(&popped,&error) && popped.popped && popped.message==30 &&
            probe.pop(&popped,&error) && popped.popped && popped.message==31;
        const auto before_ui=oe_platform_receipt().core.ui_reads;
        dm_oe_ui_opmode(0);
        notifications &= probe.query(&query,&error) && query.mode==0 && query.performance==1 &&
            probe.query(&query,&error) && oe_platform_receipt().core.ui_reads==before_ui+1;
        dm_oe_ui_opmode(-1);
        notifications &= probe.query(&query,&error) && query.mode==1 && query.performance==1 && probe.drain(&error);
        checks[1].passed=notifications;
        checks[1].detail="Low8 enables 0x100 disabled/0x101 enabled; actual mode FIFO30 then31; UI override keeps performance actual and acknowledges once per arm";
        FixtureBasis basis;
        bool parameters=dm_android_calculate_guest_parameters(2080,1080,basis.values);
        basis.install();
        uint64_t expected[4]{}; parameters &= dm_android_capture_guest_parameters(expected);
        for(auto& slot:probe.environment.state.parameters) slot=0xdecaf;
        probe.environment.state.parameter_valid_mask=7;
        dm_focus_set(oe_platform_receipt().core.focus==1?2:1); dm_set_opmode(0);
        parameters &= probe.pop(&popped,&error) && popped.popped && popped.message==15 &&
            !std::memcmp(popped.parameters,expected,sizeof(expected)) && probe.environment.state.parameter_valid_mask==15;
        const auto refresh_count=probe.runtime.oe_refresh_successes();
        parameters &= probe.pop(&popped,&error) && popped.popped && popped.message==30 &&
            probe.pop(&popped,&error) && popped.popped && popped.message==31 &&
            probe.runtime.oe_refresh_successes()==refresh_count+2;
        parameters &= probe.drain(&error);
        const auto empty_count=probe.runtime.oe_refresh_successes();
        parameters &= probe.pop(&popped,&error) && !popped.popped && probe.runtime.oe_refresh_successes()==empty_count;
        basis.available=false;
        const auto deferred=probe.runtime.oe_refresh_deferred();
        dm_focus_set(oe_platform_receipt().core.focus==1?2:1);
        parameters &= probe.pop(&popped,&error) && popped.popped && popped.message==15 &&
            !std::memcmp(popped.parameters,expected,sizeof(expected)) && probe.environment.state.parameter_valid_mask==15 &&
            probe.runtime.oe_refresh_deferred()==deferred+1;
        GuestEnvironment retained; probe.runtime.configure(retained.state);
        parameters &= retained.state.parameter_valid_mask==15 && !std::memcmp(retained.state.parameters,expected,sizeof(expected));
        basis.available=true;
        checks[2].passed=parameters;
        checks[2].detail="Native synthetic basis:15 precedes30/31 and all4 PARAM imports already refreshed; every success refreshes, empty does not; unavailable basis preserves slots/mask/future seed and increments deferred";
        const auto epoch=probe.runtime.oe_epoch(); const auto original=oe_platform_receipt();
        setenv("DM_OE_SCRIPT","wait_ingame",1);
        HleRuntime rejected; std::vector<std::unique_ptr<ModulePackage>> none;
        bool preflight=!rejected.load(std::move(none),false,nullptr,nullptr,&error) && error.find("DM_OE_SCRIPT")!=std::string::npos &&
            oe_platform_receipt().epoch==epoch && probe.query(&query,&error);
        unsetenv("DM_OE_SCRIPT");
        checks[4].passed=preflight && original.open;
        checks[4].detail="Nonempty Android script refused before mapping/publication; existing runtime epoch and actual guest OE calls stay usable; no script worker";

        // Actual SDK Create/Start/Wait/Close/Exit, with a real pinned MapMemory
        // supplied stack and checked-copy bridge as the only fixture fallback.
        SvcRequest request{}; uint64_t heap=0, map=0; uint32_t writes[2]{}, reads[2]{}, threads[2]{};
        bool sdk=svc(probe,1,{0,0x400000},&request,&error); heap=request.registers[1];
        sdk &= svc(probe,0x29,{0,14,0,0},&request,&error); map=request.registers[1];
        sdk &= heap && map && svc(probe,4,{map,heap,0x40000},&request,&error);
        copy_bridge.store(&probe.bridge,std::memory_order_release);
        uint64_t value=0;
        for(unsigned i=0;i<2 && sdk;++i) {
            sdk &= svc(probe,0x45,{},&request,&error); writes[i]=static_cast<uint32_t>(request.registers[1]); reads[i]=static_cast<uint32_t>(request.registers[2]);
            std::memcpy(reinterpret_cast<void*>(probe.bridge.targets[i]+64),&reads[i],sizeof(reads[i]));
            sdk &= probe.call("applet_sdk_create",{probe.sdk_entry,probe.bridge.targets[i],map+(i+1)*0x20000},&value,&error) && !value;
            uint64_t record[2]{}; sdk &= dm_android_guest_copy(probe.create_record,record,sizeof(record)) && !record[0];
            threads[i]=static_cast<uint32_t>(record[1]); sdk &= threads[i]!=0;
        }
        const bool parked_rejection=sdk && !probe.runtime.shutdown(&error) && !dm_android_kernel_memory_reset() &&
            oe_platform_receipt().epoch==epoch && probe.query(&query,&error);
        // Refresh AFTER Create but BEFORE Start; configured worker state inherits
        // this future seed, rather than a Create-time snapshot.
        sdk &= dm_android_calculate_guest_parameters(2560,1440,basis.values);
        dm_set_opmode(1); sdk &= probe.pop(&popped,&error) && popped.popped;
        uint64_t start_seed[2][4]{}; std::memcpy(start_seed[0],probe.environment.state.parameters,sizeof(start_seed[0]));
        bool started[2]{};
        if(threads[0]) {
            started[0]=probe.call("applet_sdk_start",{threads[0]},&value,&error) && !value;
            sdk &= started[0];
        }
        {
            std::unique_lock<std::mutex> lock(probe.bridge.mutex);
            sdk &= probe.bridge.condition.wait_for(lock,std::chrono::seconds(5),[&]{return probe.bridge.phases[0]>=1;}) && probe.bridge.valid;
        }
        // Another real guest consumer refreshes itself; the existing main thread
        // retains its configured slots while the future SDK seed changes.
        sdk &= dm_android_calculate_guest_parameters(2400,1080,basis.values);
        Consumer consumer{&probe}; pthread_t consumer_thread{};
        const bool consumer_created=pthread_create(&consumer_thread,nullptr,consume_on_thread,&consumer)==0;
        if(consumer_created && pthread_join(consumer_thread,nullptr)) std::abort();
        sdk &= consumer_created && consumer.passed && !std::memcmp(consumer.parameters,basis.values,sizeof(basis.values)) &&
            !std::memcmp(probe.environment.state.parameters,start_seed[0],sizeof(start_seed[0]));
        std::memcpy(start_seed[1],basis.values,sizeof(start_seed[1]));
        if(threads[1]) {
            started[1]=probe.call("applet_sdk_start",{threads[1]},&value,&error) && !value;
            sdk &= started[1];
        }
        {
            std::unique_lock<std::mutex> lock(probe.bridge.mutex);
            const bool received=probe.bridge.condition.wait_for(lock,std::chrono::seconds(5),[&]{return probe.bridge.phases[0]>=1 && probe.bridge.phases[1]>=1;});
            sdk &= received && probe.bridge.valid;
            for(unsigned i=0;i<2;++i) sdk &= !std::memcmp(probe.bridge.receipts[i],start_seed[i],sizeof(start_seed[i]));
        }
        const bool live_rejection=!probe.runtime.shutdown(&error) && !dm_android_kernel_memory_reset() && oe_platform_receipt().epoch==epoch;
        // Always release waits and close created handles, including failed proof
        // paths. Teardown never cancels an owned SDK worker.
        for(unsigned i=0;i<2;++i) if(writes[i]) sdk &= svc(probe,0x11,{writes[i]},&request,&error);
        for(unsigned i=0;i<2;++i) {
            if(threads[i]) {
                if(started[i] && (!probe.call("applet_sdk_wait",{threads[i]},&value,&error) || value)) std::abort();
                sdk &= probe.call("applet_sdk_close",{threads[i]},&value,&error) && !value;
            }
            for(uint32_t event:{writes[i],reads[i]}) if(event) sdk &= svc(probe,0x16,{event},&request,&error);
        }
        copy_bridge.store(nullptr,std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(probe.bridge.mutex);
            sdk &= probe.bridge.valid && probe.bridge.phases[0]==2 && probe.bridge.phases[1]==2;
            for(unsigned i=0;i<2;++i) sdk &= probe.bridge.receipts[i][6]==0;
        }
        uint64_t unowned=123,out=0xfeed;
        sdk &= !dm_android_guest_copy(reinterpret_cast<uintptr_t>(&unowned),&out,sizeof(out)) && out==0xfeed;
        checks[3].passed=sdk && parked_rejection && live_rejection && probe.runtime.svc_count(8)==2 &&
            probe.runtime.svc_count(9)==2 && probe.runtime.svc_count(0x0a)==2;
        checks[3].detail="Two actual SDK Create/Start/Wait/Close/Exit workers; pinned borrowed MapMemory stacks; staged checked-copy phase1/2 and PARAM seed at Start; parked/live unload and reset rejected";
    }
    const std::string execution_error=error;
    bool closed=probe.close(&error);
    // A cold PARAM-required runtime cannot invent a zero/fresh basis. This
    // isolated leaf is restored to the actual Activity provider before reload.
    bool cold_rejected=false;
    if(closed) {
        FixtureBasis unavailable; unavailable.available=false; unavailable.install();
        Probe cold;
        cold_rejected=!cold.load(&error) && cold.runtime.process().modules().empty() &&
            !oe_platform_receipt().open && error.find("parameter provider")!=std::string::npos;
    }
    checks[4].passed &= cold_rejected;
    checks[4].detail += "; cold PARAM load with unavailable synthetic provider fails before publication";
    checks[5].passed=ready && closed && !oe_platform_receipt().open && !oe_platform_receipt().core.has_ops &&
        oe_platform_receipt().core.pending_count==0 && probe.runtime.process().modules().empty();
    if(checks[5].passed) {
        setenv("DM_OE_SCRIPT","",1);
        Probe reload; Query query{};
        checks[5].passed=reload.load(&error) && reload.setup(1,1,&error) && reload.query(&query,&error) &&
            oe_platform_receipt().core.ui_reads==0 && reload.runtime.oe_refresh_successes()==0 &&
            reload.runtime.oe_refresh_deferred()==0 && reload.drain(&error) && reload.close(&error);
    }
    checks[5].detail="Quiescent close retires OE hooks/queue/UI counters and mappings; reload silently seeds latest Android facts without historical burst";
    std::ostringstream json;
    json << "{\"schemaVersion\":7,\"phase\":\"5\",\"syntheticOnly\":true,\"gamePlayable\":false,\"environment\":{\"pageSize\":"
        << sysconf(_SC_PAGESIZE) << ",\"abi\":\"arm64-v8a\"},\"modules\":[";
    for(size_t i=0;i<modules.size();++i) {
        if(i) json << ',';
        const auto& module=modules[i];
        json << "{\"name\":\"" << escape(module.name) << "\",\"buildId\":\"" << module.build_id
            << "\",\"sourceSha256\":\"" << module.source_sha256 << "\",\"packageSha256\":\"" << module.package_sha256
            << "\",\"profileClass\":" << module.profile_class << ",\"profileDigest\":\"" << module.profile_digest << "\"}";
    }
    json << "],\"capabilities\":{\"oeCore\":" << (oe_core_available?"true":"false")
        << ",\"parameterBasis\":" << (parameter_basis_available?"true":"false")
        << ",\"rendererResize\":false,\"uiCorrection\":false,\"saveSuspend\":false,\"audioSuspend\":false,\"gpuSuspend\":false},\"checks\":[";
    for(size_t i=0;i<checks.size();++i) {
        if(i) json << ',';
        json << "{\"id\":\"" << checks[i].id << "\",\"status\":\"" << (checks[i].passed?"PASS":"FAIL")
            << "\",\"detail\":\"" << escape(checks[i].detail + (checks[i].passed?"":"; " + execution_error + "; " + error)) << "\"}";
    }
    json << "],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return json.str();
}
