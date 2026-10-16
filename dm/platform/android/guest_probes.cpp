#include "guest_probes.h"
#include "exclusive_probes.h"
#include "guest_abi.h"
#include "fixtures/fixtures.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>

extern "C" void dm_android_test_guest_frame(void (*)(), DmGuestRegisterFrame*, DmGuestRegisterFrame*);

namespace {
uintptr_t host_tp() { uintptr_t v; asm volatile("mrs %0, tpidr_el0" : "=r"(v)); return v; }
uintptr_t host_x18() { uintptr_t v; asm volatile("mov %0, x18" : "=r"(v)); return v; }

class LoadedFixture {
public:
    DmGuestLoadedImage image{};
    char error[160]{};
    bool ok;
    explicit LoadedFixture(const DmGuestImage& source)
        : ok(dm_android_guest_load(source, &image, error, sizeof(error))) {}
    ~LoadedFixture() { dm_android_guest_unload(&image); }
    LoadedFixture(const LoadedFixture&) = delete;
    LoadedFixture& operator=(const LoadedFixture&) = delete;
    template<class Function> Function entry() const {
        return reinterpret_cast<Function>(static_cast<uint8_t*>(image.base) + image.source->entry_offset);
    }
};

class AttachedState {
    DmGuestThreadState* previous;
public:
    explicit AttachedState(DmGuestThreadState& state) : previous(dm_android_attach_guest_state(&state)) {}
    ~AttachedState() { dm_android_attach_guest_state(previous); }
};

struct DispatchData {
    uintptr_t tp = host_tp();
    uintptr_t x18 = host_x18();
    bool preserve = false;
    bool valid = true;
    size_t calls = 0;
    const DmGuestRegisterFrame* expected = nullptr;
};

// Deliberately clobber host-call volatile state. The compiler preserves the
// AAPCS64 callee-saved low halves; the guest gate must preserve all 128 bits.
__attribute__((noinline)) void clobber_host_state() {
    asm volatile(
        "mov x0, #0\n mov x1, #0\n mov x2, #0\n mov x3, #0\n"
        "mov x4, #0\n mov x5, #0\n mov x6, #0\n mov x7, #0\n"
        "mov x8, #0\n mov x9, #0\n mov x10, #0\n mov x11, #0\n"
        "mov x12, #0\n mov x13, #0\n mov x14, #0\n mov x15, #0\n"
        "mov x16, #0\n mov x17, #0\n"
        "movi v0.16b, #0\n movi v1.16b, #0\n movi v2.16b, #0\n movi v3.16b, #0\n"
        "movi v4.16b, #0\n movi v5.16b, #0\n movi v6.16b, #0\n movi v7.16b, #0\n"
        "movi v8.16b, #0\n movi v9.16b, #0\n movi v10.16b, #0\n movi v11.16b, #0\n"
        "movi v12.16b, #0\n movi v13.16b, #0\n movi v14.16b, #0\n movi v15.16b, #0\n"
        "movi v16.16b, #0\n movi v17.16b, #0\n movi v18.16b, #0\n movi v19.16b, #0\n"
        "movi v20.16b, #0\n movi v21.16b, #0\n movi v22.16b, #0\n movi v23.16b, #0\n"
        "movi v24.16b, #0\n movi v25.16b, #0\n movi v26.16b, #0\n movi v27.16b, #0\n"
        "movi v28.16b, #0\n movi v29.16b, #0\n movi v30.16b, #0\n movi v31.16b, #0\n"
        "msr nzcv, xzr\n msr fpsr, xzr\n msr fpcr, xzr\n"
        ::: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "x14", "x15", "x16", "x17", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17",
            "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28",
            "v29", "v30", "v31", "cc", "memory");
}

void dispatch(DmGuestThreadState* state, DmGuestRegisterFrame* frame, const DmGuestGate* gate) {
    auto& data = *static_cast<DispatchData*>(state->user_data);
    data.valid &= host_tp() == data.tp && host_x18() == data.x18 && frame->x[18] == state->virtual_x18;
    ++data.calls;
    if (data.expected) {
        data.valid &= frame->guest_sp == data.expected->guest_sp;
        for (size_t i = 0; i < 31; ++i)
            if (i != 18) data.valid &= frame->x[i] == data.expected->x[i];
        data.valid &= std::memcmp(frame->q, data.expected->q, sizeof(frame->q)) == 0;
        data.valid &= frame->nzcv == data.expected->nzcv && frame->fpsr == data.expected->fpsr &&
                      frame->fpcr == data.expected->fpcr;
    }
    if (!data.preserve) {
        if (gate->kind == DM_GUEST_SVC) {
            data.valid &= gate->argument == 0x42;
            frame->x[0] += gate->argument;
        } else if (gate->kind == DM_GUEST_TIMER && gate->argument < 31) {
            frame->x[gate->argument] = 0x1000 + gate->argument;
        }
    }
    clobber_host_state();
}

bool sp_rewrite_probe(std::string& detail) {
    LoadedFixture memory(dm_fixture_sp_memory), preserve(dm_fixture_sp_preserve);
    if (!memory.ok || !preserve.ok) {
        detail = "SP fixture could not be mapped RW then RX";
        return false;
    }
    const uintptr_t tp = host_tp(), x18 = host_x18();
    constexpr uint64_t pattern = UINT64_C(0x88776655ffaa9988);
    constexpr uint64_t signed_word = UINT64_C(0xffffffff80008001);
    struct Expected { uint64_t value; int64_t sp_delta; };
    // These constants describe architectural results, independently of the
    // emitter's trampoline layout. All writeback deltas are checked exactly.
    const Expected expected[] = {
        {pattern, 0}, {pattern, 0}, {pattern, -16}, {pattern, 16}, {pattern, 240},
        {pattern, -512}, {0, -512}, {pattern, 496}, {0, 496},
        {pattern, -512}, {pattern, 496}, {pattern, -256}, {pattern, 240},
        {signed_word, -256}, {signed_word, 240},
        {UINT64_C(0xffffff80), 0}, {UINT64_C(0xffffffffffffff80), 0},
        {UINT64_C(0xffff8001), 0}, {UINT64_C(0xffffffffffff8001), 0},
        {signed_word, 0}, {0x88, 0}, {0x9988, 0}, {pattern, 0},
        {0, 0}, {0, 0}, {32, 0}, {UINT64_MAX - 15, 0}, {24, 0}, {24, 0},
        {0, 0}, {0x60000000, 0},
    };
    constexpr size_t count = sizeof(expected) / sizeof(expected[0]);
    uint64_t receipt[(count + 1) * 2 + 2]{};
    receipt[(count + 1) * 2] = UINT64_C(0xbadc0ffee1234567);
    receipt[(count + 1) * 2 + 1] = UINT64_C(0xcafefeed12345678);
    DmGuestThreadState state{pattern, 0x111, 0x222, nullptr, nullptr, &memory.image};
    AttachedState attached(state);
    const uint64_t bytes = memory.entry<uint64_t (*)(uint64_t*)>()(receipt);
    bool ok = bytes == (count + 1) * 16;
    for (size_t i = 0; i < count; ++i) {
        if (receipt[2 * i] != expected[i].value ||
            receipt[2 * i + 1] != static_cast<uint64_t>(expected[i].sp_delta)) {
            std::ostringstream failure;
            failure << "SP receipt " << i << ": value=" << std::hex << receipt[2 * i]
                    << ", delta=" << receipt[2 * i + 1];
            detail = failure.str();
            return false;
        }
    }
    ok &= receipt[2 * count] != 0 && (receipt[2 * count] & 15) == 0 &&
          receipt[2 * count + 1] == 0 && state.virtual_x18 == receipt[2 * count];
    ok &= receipt[(count + 1) * 2] == UINT64_C(0xbadc0ffee1234567) &&
          receipt[(count + 1) * 2 + 1] == UINT64_C(0xcafefeed12345678);
    DmGuestRegisterFrame before{}, after{};
    state.image = &preserve.image;
    state.virtual_x18 = pattern;
    dm_android_test_guest_frame(preserve.entry<void (*)()>(), &before, &after);
    ok &= std::memcmp(before.x, after.x, sizeof(before.x)) == 0 &&
          std::memcmp(before.q, after.q, sizeof(before.q)) == 0 &&
          before.guest_sp == after.guest_sp && before.nzcv == after.nzcv &&
          before.fpsr == after.fpsr && before.fpcr == after.fpcr &&
          state.virtual_x18 == pattern && state.guest_tpidr_el0 == 0x111 &&
          state.guest_tpidrro_el0 == 0x222 && host_tp() == tp && host_x18() == x18;
    detail = "32 SP value/delta receipts; bounded negative/pre/post scalar/pair/LDPSW, signed loads, partial stores, SP aliases/arithmetic/flags; full frame preserved";
    return ok;
}

bool rewrite_probe(std::string& detail) {
    LoadedFixture arithmetic(dm_fixture_x18_arithmetic), memory(dm_fixture_x18_memory),
        conditional(dm_fixture_x18_conditional), tls(dm_fixture_tls), lr(dm_fixture_live_lr),
        svc(dm_fixture_svc), timer(dm_fixture_timer);
    if (!arithmetic.ok || !memory.ok || !conditional.ok || !tls.ok || !lr.ok || !svc.ok || !timer.ok) {
        detail = "A generated fixture could not be mapped RW then RX";
        return false;
    }
    DispatchData data;
    DmGuestThreadState state{0x700, 0x80, 0x200, dispatch, &data, &arithmetic.image};
    AttachedState attached(state);
    using Unary = uint64_t (*)(uint64_t);
    bool ok = arithmetic.entry<Unary>()(100) == 107 && state.virtual_x18 == 107;
    ok &= arithmetic.entry<Unary>()(UINT64_MAX) == 6 && state.virtual_x18 == 6;
    state.image = &memory.image;
    uint64_t value = 55;
    ok &= memory.entry<uint64_t (*)(uint64_t*)>()(&value) == 60 && value == 60 && state.virtual_x18 == 60;
    state.image = &conditional.image;
    ok &= conditional.entry<Unary>()(0) == 11 && state.virtual_x18 == 0;
    ok &= conditional.entry<Unary>()(41) == 22 && state.virtual_x18 == 41;
    state.image = &tls.image;
    ok &= tls.entry<Unary>()(64) == 579 && state.guest_tpidr_el0 == 67 && state.virtual_x18 == 512;
    state.image = &lr.image;
    ok &= lr.entry<Unary>()(100) == 109 && state.virtual_x18 == 109;
    state.image = &svc.image;
    ok &= svc.entry<Unary>()(100) == 166;
    state.image = &timer.image;
    uint64_t ticks[6]{};
    timer.entry<void (*)(uint64_t*)>()(ticks);
    for (size_t i = 0; i < 5; ++i) ok &= ticks[i] == 0x1000 + 19 + i;
    ok &= ticks[5] == 0x1012 && state.virtual_x18 == 0x1012;
    ok &= data.valid && data.calls == 7 && host_tp() == data.tp && host_x18() == data.x18;
    std::string sp_detail;
    if (!sp_rewrite_probe(sp_detail)) { detail = sp_detail; return false; }
    std::string exclusive_detail;
    if (!dm_android_exclusive_probe(exclusive_detail)) { detail = exclusive_detail; return false; }
    detail = "Generated ABI images; arithmetic wrap, memory, branches, virtual TLS/TLR, live LR, SVC, timers; " + sp_detail + "; " + exclusive_detail;
    return ok;
}

bool frame_probe(std::string& detail) {
    LoadedFixture svc(dm_fixture_svc);
    if (!svc.ok) { detail = svc.error; return false; }
    DmGuestRegisterFrame before{}, after{};
    DispatchData data;
    data.preserve = true;
    data.expected = &before;
    DmGuestThreadState state{0x88776655, 0, 0, dispatch, &data, &svc.image};
    AttachedState attached(state);
    dm_android_test_guest_frame(svc.entry<void (*)()>(), &before, &after);
    const bool ok = std::memcmp(before.x, after.x, sizeof(before.x)) == 0 &&
        std::memcmp(before.q, after.q, sizeof(before.q)) == 0 && before.guest_sp == after.guest_sp &&
        before.nzcv == after.nzcv && before.fpsr == after.fpsr && before.fpcr == after.fpcr &&
        data.valid && data.calls == 1 && state.virtual_x18 == 0x88776655;
    detail = "Real dispatch gate: x0-x30, all 32 full SIMD registers, NZCV/FPSR/FPCR and SP sentinels; clobbering host callback";
    return ok;
}

struct WorkerGroup { std::atomic<unsigned> ready{0}; std::atomic<bool> start{false}; };
struct Worker {
    const DmGuestLoadedImage* image;
    uint64_t seed;
    WorkerGroup* group;
    bool passed = false;
    uintptr_t tp = 0;
};
void* thread_worker(void* opaque) {
    auto& worker = *static_cast<Worker*>(opaque);
    const uintptr_t tp = host_tp(), x18 = host_x18();
    worker.tp = tp;
    DmGuestThreadState state{worker.seed, worker.seed + 1, worker.seed + 2, nullptr, nullptr, worker.image};
    AttachedState attached(state);
    auto entry = reinterpret_cast<uint64_t (*)(uint64_t)>(static_cast<uint8_t*>(worker.image->base) + worker.image->source->entry_offset);
    worker.group->ready.fetch_add(1, std::memory_order_release);
    while (!worker.group->start.load(std::memory_order_acquire)) sched_yield();
    bool ok = true;
    for (uint64_t i = 0; i < 10000; ++i) {
        const uint64_t input = worker.seed + i;
        ok &= entry(input) == input + 7 && state.virtual_x18 == input + 7 &&
              state.guest_tpidr_el0 == worker.seed + 1 && state.guest_tpidrro_el0 == worker.seed + 2;
    }
    worker.passed = ok && host_tp() == tp && host_x18() == x18;
    return nullptr;
}

bool thread_probe(std::string& detail) {
    LoadedFixture arithmetic(dm_fixture_x18_arithmetic);
    if (!arithmetic.ok) { detail = arithmetic.error; return false; }
    WorkerGroup group;
    Worker workers[2]{{&arithmetic.image, 0x10000, &group}, {&arithmetic.image, 0x20000, &group}};
    pthread_t threads[2]{};
    const int c0 = pthread_create(&threads[0], nullptr, thread_worker, &workers[0]);
    const int c1 = pthread_create(&threads[1], nullptr, thread_worker, &workers[1]);
    const unsigned created = static_cast<unsigned>(c0 == 0) + static_cast<unsigned>(c1 == 0);
    while (group.ready.load(std::memory_order_acquire) < created) sched_yield();
    group.start.store(true, std::memory_order_release);
    const int j0 = c0 == 0 ? pthread_join(threads[0], nullptr) : -1;
    const int j1 = c1 == 0 ? pthread_join(threads[1], nullptr) : -1;
    if ((c0 == 0 && j0 != 0) || (c1 == 0 && j1 != 0)) {
        std::fprintf(stderr, "Cannot join guest probe workers: %d/%d\n", j0, j1);
        std::abort(); // Continuing could release state still used by a worker.
    }
    detail = "Two pthreads, 10000 rewritten x18 fixture calls each, isolated TLS/TLR and unchanged host x18/TPIDR_EL0";
    return c0 == 0 && c1 == 0 && j0 == 0 && j1 == 0 && workers[0].passed && workers[1].passed && workers[0].tp != workers[1].tp;
}

struct SignalWorker {
    const DmGuestLoadedImage* image;
    std::atomic<bool> ready{false}, finish{false};
    volatile sig_atomic_t delivered = 0, interrupted = 0, invalid = 0;
    uintptr_t alternate_begin = 0, alternate_end = 0, tp = 0, x18 = 0;
    void* reservation = MAP_FAILED;
    size_t reservation_size = 0;
    bool passed = false;
    size_t calls = 0;
};
SignalWorker* active_signal_worker = nullptr; // Serialized by the JNI probe mutex.
void signal_handler(int, siginfo_t*, void* context) {
    auto* worker = active_signal_worker;
    volatile char marker;
    const auto address = reinterpret_cast<uintptr_t>(&marker);
    if (!worker) return;
    if (address < worker->alternate_begin || address >= worker->alternate_end ||
        host_tp() != worker->tp || host_x18() != worker->x18) worker->invalid = 1;
    const uintptr_t pc = static_cast<ucontext_t*>(context)->uc_mcontext.pc;
    const uintptr_t base = reinterpret_cast<uintptr_t>(worker->image->base);
    const uintptr_t accessor = reinterpret_cast<uintptr_t>(&dm_android_state_accessor);
    const uintptr_t dispatch_gate = reinterpret_cast<uintptr_t>(&dm_android_dispatch_gate);
    if ((pc >= base && pc - base < worker->image->source->size) ||
        (pc >= accessor && pc < dispatch_gate)) ++worker->interrupted;
    ++worker->delivered;
}
void* signal_worker(void* opaque) {
    auto& worker = *static_cast<SignalWorker*>(opaque);
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    constexpr size_t alternate_size = 64 * 1024;
    void* reservation = mmap(nullptr, alternate_size + 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    worker.reservation = reservation;
    worker.reservation_size = alternate_size + 2 * page;
    stack_t previous{};
    bool installed = false, mask_saved = false;
    sigset_t previous_mask;
    DmGuestThreadState state{0, 0x111, 0x222, nullptr, nullptr, worker.image};
    AttachedState attached(state);
    if (reservation != MAP_FAILED) {
        auto* alternate = static_cast<uint8_t*>(reservation) + page;
        if (mprotect(alternate, alternate_size, PROT_READ | PROT_WRITE) == 0) {
            stack_t stack{};
            stack.ss_sp = alternate; stack.ss_size = alternate_size;
            installed = sigaltstack(&stack, &previous) == 0;
            worker.alternate_begin = reinterpret_cast<uintptr_t>(alternate);
            worker.alternate_end = worker.alternate_begin + alternate_size;
        }
    }
    sigset_t unblocked;
    sigemptyset(&unblocked); sigaddset(&unblocked, SIGUSR2);
    if (installed) mask_saved = pthread_sigmask(SIG_UNBLOCK, &unblocked, &previous_mask) == 0;
    worker.tp = host_tp(); worker.x18 = host_x18();
    active_signal_worker = &worker;
    auto entry = reinterpret_cast<uint64_t (*)(uint64_t)>(static_cast<uint8_t*>(worker.image->base) + worker.image->source->entry_offset);
    bool ok = installed && mask_saved;
    if (ok) { ++worker.calls; ok = entry(worker.calls) == worker.calls + 7; }
    worker.ready.store(true, std::memory_order_release);
    while (!worker.finish.load(std::memory_order_acquire)) {
        if (ok) {
            const uint64_t input = ++worker.calls;
            ok &= entry(input) == input + 7 && state.virtual_x18 == input + 7;
        } else sched_yield(); // Sender must stop before any failure-path teardown.
    }
    // Stop delivery before removing the alternate stack. The sender has
    // stopped before publishing finish; drain any coalesced directed signal.
    bool restored = pthread_sigmask(SIG_BLOCK, &unblocked, nullptr) == 0;
    if (restored) {
        const timespec zero{};
        for (;;) {
            const int pending = sigtimedwait(&unblocked, nullptr, &zero);
            if (pending == SIGUSR2) continue;
            if (pending < 0 && errno == EINTR) continue;
            restored &= pending < 0 && errno == EAGAIN;
            break;
        }
    }
    if (installed) restored &= sigaltstack(&previous, nullptr) == 0;
    if (mask_saved) restored &= pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr) == 0;
    // The parent unmaps this storage after join, even if restoration failed.
    worker.passed = ok && restored && worker.delivered > 0 && worker.interrupted > 0 && !worker.invalid && worker.calls > 0 &&
                    host_tp() == worker.tp && host_x18() == worker.x18;
    return nullptr;
}

bool signal_probe(std::string& detail) {
    LoadedFixture arithmetic(dm_fixture_x18_arithmetic);
    if (!arithmetic.ok) { detail = arithmetic.error; return false; }
    struct sigaction action{}, previous{};
    action.sa_sigaction = signal_handler; action.sa_flags = SA_ONSTACK | SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR2, &action, &previous) != 0) { detail = "SIGUSR2 handler setup failed"; return false; }
    SignalWorker worker;
    worker.image = &arithmetic.image;
    pthread_t thread;
    const int created = pthread_create(&thread, nullptr, signal_worker, &worker);
    bool sent = created == 0;
    if (created == 0) {
        while (!worker.ready.load(std::memory_order_acquire)) sched_yield();
        for (int i = 0; i < 1000; ++i) { sent &= pthread_kill(thread, SIGUSR2) == 0; sched_yield(); }
        worker.finish.store(true, std::memory_order_release);
    }
    const int joined = created == 0 ? pthread_join(thread, nullptr) : -1;
    if (created == 0 && joined != 0) {
        std::fprintf(stderr, "Cannot join guest signal worker: %d\n", joined);
        std::abort(); // Leave its handler, state and stack alive until process exit.
    }
    active_signal_worker = nullptr;
    const bool restored = sigaction(SIGUSR2, &previous, nullptr) == 0;
    const bool released = worker.reservation == MAP_FAILED ||
        munmap(worker.reservation, worker.reservation_size) == 0;
    detail = "Async SIGUSR2 on guarded alternate stack during " + std::to_string(worker.calls) +
             " rewritten calls; delivered=" + std::to_string(worker.delivered) +
             "; native-code interruptions=" + std::to_string(worker.interrupted) + "; actions/masks/stack restored";
    return sent && joined == 0 && restored && released && worker.passed;
}

bool loader_probe(std::string& detail) {
    size_t rounded;
    bool ok = dm_android_guest_round_size(4097, 4096, &rounded) && rounded == 8192 &&
        dm_android_guest_round_size(4097, 16384, &rounded) && rounded == 16384 &&
        !dm_android_guest_round_size(SIZE_MAX, 4096, &rounded) &&
        !dm_android_guest_round_size(1, 123, &rounded);
    auto rejects = [](const DmGuestImage& image) {
        DmGuestLoadedImage loaded{};
        char error[160];
        const bool accepted = dm_android_guest_load(image, &loaded, error, sizeof(error));
        const bool rejected = !accepted && !loaded.base && error[0];
        if (accepted) dm_android_guest_unload(&loaded);
        return rejected;
    };
    DmGuestImage bad = dm_fixture_x18_arithmetic;
    bad.abi = 0; ok &= rejects(bad);
    bad = dm_fixture_x18_arithmetic; bad.entry_offset = bad.size; ok &= rejects(bad);
    bad = dm_fixture_x18_arithmetic; bad.size = 3; ok &= rejects(bad);
    DmGuestFixup fixups[2]{{1, DM_GUEST_STATE_HELPER}, {1, DM_GUEST_STATE_HELPER}};
    bad = dm_fixture_x18_arithmetic; bad.fixups = fixups; bad.fixup_count = 1; ok &= rejects(bad);
    fixups[0] = dm_fixture_x18_arithmetic.fixups[0]; fixups[0].helper = 99; ok &= rejects(bad);
    fixups[0] = dm_fixture_x18_arithmetic.fixups[0]; fixups[1] = fixups[0]; bad.fixup_count = 2; ok &= rejects(bad);
    DmGuestGate gate{4, DM_GUEST_TIMER, 32};
    bad = dm_fixture_svc; bad.gates = &gate; bad.gate_count = 1; ok &= rejects(bad);
    gate.argument = 1; ok &= rejects(bad); // Return must follow the real BLR x30.
    const uint32_t overlap_bytes[]{0xd65f03c0, 0xd503201f, 0xd503201f, 0xd63f03c0, 0, 0};
    const DmGuestFixup overlap_fixup{16, DM_GUEST_DISPATCH_HELPER};
    const DmGuestGate overlap_gate{16, DM_GUEST_SVC, 0};
    const DmGuestImage overlap{DM_ANDROID_GUEST_ABI, reinterpret_cast<const uint8_t*>(overlap_bytes),
        sizeof(overlap_bytes), 0, &overlap_fixup, 1, &overlap_gate, 1};
    ok &= rejects(overlap);
    LoadedFixture valid(dm_fixture_x18_arithmetic);
    ok &= valid.ok;
    detail = "Guarded W-to-X image loading; ABI/entry/fixup/gate rejection; overflow and 4KB/16KB rounding; cache synchronized";
    return ok;
}

std::string escape(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (c == '\\' || c == '"') out += '\\';
        if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}
}

std::string dm_android_run_guest_probes() {
    std::ostringstream json;
    json << "{\"schemaVersion\":2,\"phase\":\"1A\",\"syntheticOnly\":true,\"gamePlayable\":false,\"environment\":{\"pageSize\":"
         << sysconf(_SC_PAGESIZE) << ",\"abi\":\"arm64-v8a\",\"guestAbi\":" << DM_ANDROID_GUEST_ABI << "},\"checks\":[";
    struct Probe { const char* id; bool (*call)(std::string&); };
    const Probe probes[]{{"rewrite", rewrite_probe}, {"threads", thread_probe}, {"frame", frame_probe},
                         {"signal", signal_probe}, {"loader", loader_probe}};
    bool first = true;
    for (const auto& probe : probes) {
        std::string detail;
        const bool passed = probe.call(detail);
        if (!first) json << ',';
        first = false;
        json << "{\"id\":\"" << probe.id << "\",\"status\":\"" << (passed ? "PASS" : "FAIL")
             << "\",\"detail\":\"" << escape(detail) << "\"}";
    }
    json << "],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return json.str();
}
