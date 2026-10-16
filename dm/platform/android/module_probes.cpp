#include "module_probes.h"
#include "module_runtime.h"
#include "module_sha256.h"
#include "guest_thread.h"
#include "guest_bootstrap.h"
#include "module_fixtures/generated_modules.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <unistd.h>

namespace {
using namespace dm_android;
uintptr_t host_tp() { uintptr_t value; asm volatile("mrs %0,tpidr_el0" : "=r"(value)); return value; }
uintptr_t host_x18() { uintptr_t value; asm volatile("mov %0,x18" : "=r"(value)); return value; }
std::string hex(const uint8_t* data, size_t size) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; ++i) { out += alphabet[data[i] >> 4]; out += alphabet[data[i] & 15]; }
    return out;
}
std::string escaped(const std::string& value) {
    std::string out;
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 32) { out += "\\u00"; out += hex(&c, 1); }
        else out += static_cast<char>(c);
    }
    return out;
}
struct Blob { const uint8_t* bytes; size_t size; const uint8_t* digest; };
const Blob blobs[]{{dm_module_main_bytes, dm_module_main_size, dm_module_main_package_sha256},
                   {dm_module_sdk_bytes, dm_module_sdk_size, dm_module_sdk_package_sha256},
                   {dm_module_extra_bytes, dm_module_extra_size, dm_module_extra_package_sha256}};
bool packages(std::vector<std::unique_ptr<ModulePackage>>* result, std::string* error) {
    result->clear();
    for (const auto& blob : blobs) {
        std::unique_ptr<ModulePackage> package;
        if (!decode_package(blob.bytes, blob.size, blob.digest, &package, error)) return false;
        result->push_back(std::move(package));
    }
    return true;
}

struct Context {
    Process process;
    GuestEnvironment environment;
    GuestStack stack{256 * 1024};
    bool forced = true, allow_imports = true, exit_requested = false, valid = true;
    bool on_guest_stack = false;
    size_t sdk_gates = 0;
    uintptr_t tp = host_tp(), x18 = host_x18();
    std::vector<uint64_t> events, init;
};
Context& context() { return *static_cast<Context*>(dm_android_current_guest_state()->user_data); }
extern "C" void module_record_init(uint64_t id) {
    auto& current = context();
    current.init.push_back(id); current.events.push_back(100 + id);
}
extern "C" void module_record_boot(uint64_t step) { context().events.push_back(step); }
extern "C" uint64_t module_force_override() { return 90; }
extern "C" uint64_t module_argument_probe(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                          uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    auto& current = context();
    volatile uint8_t local = 0;
    const uintptr_t address = reinterpret_cast<uintptr_t>(&local);
    current.on_guest_stack = address < current.stack.top() &&
        current.stack.top() - address <= current.stack.usable_size();
    uintptr_t owned_bottom = 0; size_t owned_size = 0;
    current.on_guest_stack &= active_guest_stack_owned_bounds(address, &owned_bottom, &owned_size) &&
        owned_bottom + owned_size == current.stack.top();
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h;
}
bool resolver(const char* name, bool forced_only, uintptr_t* address, void* opaque) {
    const auto& current = *static_cast<Context*>(opaque);
    if (std::strcmp(name, "force_override") == 0 && current.forced) {
        *address = reinterpret_cast<uintptr_t>(&module_force_override); return true;
    }
    if (forced_only || !current.allow_imports) return false;
    if (std::strcmp(name, "record_init") == 0) *address = reinterpret_cast<uintptr_t>(&module_record_init);
    else if (std::strcmp(name, "record_boot") == 0) *address = reinterpret_cast<uintptr_t>(&module_record_boot);
    else return false;
    return true;
}
void dispatch(DmGuestThreadState* state, DmGuestRegisterFrame* frame, const DmGuestGate* gate) {
    auto& current = *static_cast<Context*>(state->user_data);
    current.valid &= host_tp() == current.tp && host_x18() == current.x18 &&
        gate->kind == DM_GUEST_SVC && gate->argument == 0x77 &&
        frame->guest_sp <= current.stack.top() && current.stack.top() - frame->guest_sp <= current.stack.usable_size();
    bool sdk = false;
    for (const auto& module : current.process.modules()) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(module->mapping.base);
        sdk |= module->package->name == "sdk" && frame->return_pc >= base &&
            frame->return_pc - base < module->package->bytes.size();
    }
    current.valid &= sdk;
    ++current.sdk_gates;
    if (current.exit_requested) guest_exit(42);
}
bool load(Context& current, std::string* error, bool reverse = false) {
    std::vector<std::unique_ptr<ModulePackage>> prepared;
    if (!packages(&prepared, error)) return false;
    if (reverse) std::swap(prepared[0], prepared[1]);
    if (!current.process.load(std::move(prepared), resolver, &current, error)) return false;
    current.environment.state.dispatch = dispatch;
    current.environment.state.user_data = &current;
    current.environment.state.gate_resolver = Process::gate_resolver;
    current.environment.state.gate_context = &current.process;
    return true;
}
bool read_word(Context& current, const char* name, uint64_t* value) {
    uintptr_t address;
    if (!current.process.symbol(name, &address)) return false;
    std::memcpy(value, reinterpret_cast<const void*>(address), sizeof(*value));
    return true;
}
bool call(Context& current, const char* name, uint64_t* value, std::string* error) {
    uintptr_t address;
    if (!current.process.symbol(name, &address)) { *error = std::string("missing fixture symbol: ") + name; return false; }
    GuestCallResult result;
    if (!current.stack.call(current.environment.state, address, nullptr, 0, &result, error)) return false;
    *value = result.value;
    return !result.exited && current.valid && host_tp() == current.tp && host_x18() == current.x18;
}

bool module_probe(const std::string& cache, std::string& detail) {
    std::vector<std::unique_ptr<ModulePackage>> prepared;
    if (!packages(&prepared, &detail)) return false;
    bool ok = prepared.size() == 3;
    uint8_t digest[32];
    module_sha256(nullptr, 0, digest);
    ok &= hex(digest, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    module_sha256(reinterpret_cast<const uint8_t*>("abc"), 3, digest);
    ok &= hex(digest, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const char* padding = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    module_sha256(reinterpret_cast<const uint8_t*>(padding), std::strlen(padding), digest);
    ok &= hex(digest, 32) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    std::vector<char> path(cache.begin(), cache.end());
    constexpr char suffix[] = "/dm-module-XXXXXX";
    path.insert(path.end(), suffix, suffix + sizeof(suffix));
    const int fd = mkstemp(path.data());
    if (fd < 0) { detail = "Cannot create app-private module input file"; return false; }
    size_t written = 0;
    while (written < blobs[0].size) {
        const ssize_t count = write(fd, blobs[0].bytes + written, blobs[0].size - written);
        if (count <= 0) break;
        written += static_cast<size_t>(count);
    }
    std::unique_ptr<ModulePackage> from_file;
    ok &= written == blobs[0].size && lseek(fd, 7, SEEK_SET) == 7 &&
        read_package_fd(fd, blobs[0].digest, &from_file, &detail) && lseek(fd, 0, SEEK_CUR) == 7;
    ok &= from_file && from_file->name == prepared[0]->name && from_file->image_sha256 == prepared[0]->image_sha256;
    ok &= close(fd) == 0; ok &= unlink(path.data()) == 0;
    auto corrupted = std::vector<uint8_t>(blobs[0].bytes, blobs[0].bytes + blobs[0].size);
    corrupted.back() ^= 1;
    std::unique_ptr<ModulePackage> rejected;
    std::string rejection;
    ok &= !decode_package(corrupted.data(), corrupted.size(), blobs[0].digest, &rejected, &rejection) && !rejected;
    auto changed_metadata = std::vector<uint8_t>(blobs[1].bytes, blobs[1].bytes + blobs[1].size);
    uint64_t gate_table;
    std::memcpy(&gate_table, changed_metadata.data() + 136, 8);
    changed_metadata[gate_table + 12] ^= 1; // Structurally valid SVC metadata corruption.
    ok &= !decode_package(changed_metadata.data(), changed_metadata.size(), blobs[1].digest, &rejected, &rejection);
    changed_metadata.assign(blobs[1].bytes, blobs[1].bytes + blobs[1].size);
    changed_metadata[184] ^= 1; // Provenance is bound by the trusted package digest too.
    ok &= !decode_package(changed_metadata.data(), changed_metadata.size(), blobs[1].digest, &rejected, &rejection);
    ok &= !decode_package(blobs[0].bytes, blobs[0].size, nullptr, &rejected, &rejection);
    detail = "Three independently assembled NSOs use production decoder; trusted whole-package/payload SHA256, vectors, fd preservation and metadata/provenance corruption rejection";
    return ok;
}

bool relocation_probe(std::string& detail) {
    Context current;
    if (!load(current, &detail)) return false;
    uint64_t result = 0, bss = 0, duplicate = 0;
    bool ok = call(current, "fixture_main", &result, &detail) && result == 161 && current.sdk_gates == 1;
    ok &= read_word(current, "main_bss", &bss) && bss == 123;
    ok &= read_word(current, "duplicate_value", &duplicate) && duplicate == 1;
    uintptr_t extra;
    ok &= current.process.symbol("extra_global", &extra);
    const auto& main = current.process.modules()[0];
    uint64_t negative;
    std::memcpy(&negative, static_cast<const uint8_t*>(main->mapping.base) + 0x8030, 8);
    ok &= negative == extra - 8;
    Context unforced;
    unforced.forced = false;
    ok &= load(unforced, &detail) && call(unforced, "fixture_main", &result, &detail) && result == 72;
    Context reversed;
    ok &= load(reversed, &detail, true) && read_word(reversed, "duplicate_value", &duplicate) && duplicate == 2;
    detail = "Executed main->sdk->extra calls; RELATIVE/ABS64/GLOB_DAT/JUMP_SLOT, signed addends, forced override, ordered duplicate exports and writable BSS";
    return ok;
}

unsigned permissions(uintptr_t address) {
    FILE* maps = std::fopen("/proc/self/maps", "r");
    if (!maps) return 0xff;
    char line[512], mode[5];
    unsigned long long begin, end;
    unsigned result = 0xff;
    while (std::fgets(line, sizeof(line), maps)) {
        if (std::sscanf(line, "%llx-%llx %4s", &begin, &end, mode) == 3 && address >= begin && address < end) {
            result = (mode[0] == 'r' ? 1u : 0u) | (mode[1] == 'w' ? 2u : 0u) | (mode[2] == 'x' ? 4u : 0u);
            break;
        }
    }
    std::fclose(maps);
    return result;
}
bool permission_probe(std::string& detail) {
    Context current;
    if (!load(current, &detail)) return false;
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    bool ok = true;
    for (const auto& module : current.process.modules()) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(module->mapping.base);
        ok &= module->mapping.sealed && permissions(base - 1) == 0 &&
              permissions(base + module->mapping.mapping_size) == 0;
        for (const auto& segment : module->package->segments) if (segment.size)
            ok &= permissions(base + segment.offset) == segment.flags;
        for (size_t offset = 0; offset < module->mapping.mapping_size; offset += page) {
            const unsigned actual = permissions(base + offset);
            ok &= actual != 0xff && !((actual & DM_GUEST_WRITE) && (actual & DM_GUEST_EXEC));
        }
    }
    detail = "Actual process maps: text/patch RX, RO read-only, data/BSS RW, guarded holes; no W+X host page";
    return ok;
}

bool register_main(DmGuestThreadState&, uint64_t* handle, uint64_t* area, void* opaque, std::string*) {
    auto& current = *static_cast<Context*>(opaque);
    *handle = 0x1234; *area = 0;
    current.events.push_back(0);
    return true; // An explicit fixture kernel hook, not original-game HLE proof.
}
bool product_init(Process&, DmGuestThreadState& state, void* opaque, std::string* error) {
    volatile uint8_t local = 0;
    uintptr_t bottom = 0;
    size_t size = 0;
    if (!active_guest_stack_bounds(reinterpret_cast<uintptr_t>(&local), &bottom, &size) ||
        dm_android_current_guest_state() != &state) {
        if (error) *error = "product initialization requires the attached guest stack";
        return false;
    }
    static_cast<Context*>(opaque)->events.push_back(200);
    return true;
}
bool init_runner(uintptr_t address, void* opaque, std::string* error) {
    auto& current = *static_cast<Context*>(opaque);
    GuestCallResult called;
    return current.stack.call(current.environment.state, address, nullptr, 0, &called, error) && !called.exited;
}
bool initialization_probe(std::string& detail) {
    Context current;
    if (!load(current, &detail)) return false;
    BootstrapArguments arguments({"D2R", "--fixture"});
    BootstrapSession session;
    BootstrapResult result;
    const BootstrapHooks hooks{register_main, product_init, &current};
    bool ok = session.authorize(current.process, &detail) &&
        session.run(current.process, current.environment, current.stack, arguments, hooks, &result, &detail);
    const std::vector<uint64_t> expected{0,1,2,3,4,5,6,101,102,103,7,8,200,9};
    ok &= current.events == expected && current.init == std::vector<uint64_t>({1,2,3}) &&
        result.completed_steps.size() == 12 && result.main_result.value == 161 && !result.main_result.exited;
    uint64_t handle = 0, area = 1, argc = 0, argv = 0;
    ok &= read_word(current, "fixture_main_handle", &handle) && handle == 0x1234;
    ok &= read_word(current, "fixture_argument_area", &area) && area == 0;
    ok &= read_word(current, "fixture_argc", &argc) && argc == 2;
    ok &= read_word(current, "fixture_argv", &argv) && argv == reinterpret_cast<uintptr_t>(arguments.argv());
    const size_t events = current.events.size();
    ok &= current.process.run_initializers(init_runner, &current, &detail) && current.events.size() == events;
    BootstrapResult repeated;
    ok &= !session.run(current.process, current.environment, current.stack, arguments, hooks, &repeated, &detail) &&
        current.events.size() == events;
    detail = "Production SDK startup order, main-handle/x1/argc/argv, ordered exactly-once DT_INIT, required product hook and nnMain; repeat boot rejected";
    return ok;
}

bool import_probe(std::string& detail) {
    Context current;
    if (!load(current, &detail)) return false;
    uintptr_t before = 0, after = 0;
    bool ok = current.process.symbol("fixture_main", &before);
    Context missing;
    missing.allow_imports = false;
    std::vector<std::unique_ptr<ModulePackage>> candidate;
    ok &= packages(&candidate, &detail);
    ok &= !current.process.load(std::move(candidate), resolver, &missing, &detail) &&
        current.process.modules().size() == 3 && current.process.symbol("fixture_main", &after) && before == after;
    uint64_t value;
    ok &= call(current, "fixture_main", &value, &detail) && value == 161;
    BootstrapArguments arguments;
    BootstrapSession denied;
    BootstrapResult result;
    const size_t events = current.events.size();
    ok &= !denied.run(current.process, current.environment, current.stack, arguments, {}, &result, &detail) &&
        current.events.size() == events;
    detail = "Missing strong HLE imports reject transactionally and preserve prior process; absent kernel/product hooks reject before SDK side effects";
    return ok;
}

bool guest_stack_probe(std::string& detail) {
    Context current;
    if (!load(current, &detail)) return false;
    auto& state = current.environment.state;
    uint64_t object;
    std::memcpy(&object, reinterpret_cast<const void*>(state.guest_tpidrro_el0 + 0x1f8), sizeof(object));
    bool ok = state.virtual_x18 == 0 && object &&
        std::all_of(reinterpret_cast<const uint8_t*>(state.guest_tpidr_el0),
                    reinterpret_cast<const uint8_t*>(state.guest_tpidr_el0) + 8192, [](uint8_t v) { return v == 0; });
    GuestCallResult result;
    const uint64_t arguments[]{1,2,3,4,5,6,7,8};
    ok &= current.stack.call(state, reinterpret_cast<uintptr_t>(&module_argument_probe), arguments, 8, &result, &detail) &&
        result.value == 204 && !result.exited && current.on_guest_stack;
    ok &= current.stack.call(state, reinterpret_cast<uintptr_t>(&module_argument_probe), uint64_t{9}, &result, &detail) && result.value == 9;
    uintptr_t entry;
    ok &= current.process.symbol("sdk_call", &entry);
    current.exit_requested = true;
    ok &= current.stack.call(state, entry, uint64_t{0}, &result, &detail) && result.exited && result.value == 42;
    current.exit_requested = false;
    uint64_t value;
    ok &= call(current, "fixture_main", &value, &detail) && value == 161 &&
        host_tp() == current.tp && host_x18() == current.x18;
    detail = "Owned iOS-compatible TLS/TLR/object, actual guarded guest stack, eight/zero-filled arguments, SDK SVC ExitThread returns to host, stack reusable";
    return ok;
}
}

std::string dm_android_run_module_probes(const std::string& cache_directory) {
    std::ostringstream json;
    json << "{\"schemaVersion\":3,\"phase\":\"1B\",\"syntheticOnly\":true,\"gamePlayable\":false,\"environment\":{\"pageSize\":"
         << sysconf(_SC_PAGESIZE) << ",\"abi\":\"arm64-v8a\"},\"modules\":[";
    bool first = true;
    for (const auto& blob : blobs) {
        std::unique_ptr<ModulePackage> package;
        std::string error;
        if (!decode_package(blob.bytes, blob.size, blob.digest, &package, &error)) continue;
        if (!first) json << ',';
        first = false;
        json << "{\"name\":\"" << package->name << "\",\"buildId\":\"" << hex(package->build_id.data(),32)
             << "\",\"sourceSha256\":\"" << hex(package->source_sha256.data(),32)
             << "\",\"imageSha256\":\"" << hex(package->image_sha256.data(),32) << "\"}";
    }
    json << "],\"checks\":[";
    struct Probe { const char* id; bool (*call)(std::string&); };
    const Probe probes[]{{"relocations", relocation_probe}, {"permissions", permission_probe},
                         {"initializers", initialization_probe}, {"imports", import_probe}, {"guest_stack", guest_stack_probe}};
    std::string detail;
    const bool module_ok = module_probe(cache_directory, detail);
    json << "{\"id\":\"modules\",\"status\":\"" << (module_ok ? "PASS" : "FAIL")
         << "\",\"detail\":\"" << escaped(detail) << "\"}";
    for (const auto& probe : probes) {
        detail.clear();
        const bool passed = probe.call(detail);
        json << ",{\"id\":\"" << probe.id << "\",\"status\":\"" << (passed ? "PASS" : "FAIL")
             << "\",\"detail\":\"" << escaped(detail) << "\"}";
    }
    json << "],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return json.str();
}
