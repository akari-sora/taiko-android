#include "exclusive_probes.h"
#include "exclusive_fixtures/fixtures.h"

#include <atomic>
#include <cstring>
#include <cstdlib>
#include <pthread.h>
#include <sched.h>

extern "C" void dm_android_test_guest_frame(void (*)(), DmGuestRegisterFrame*, DmGuestRegisterFrame*);

namespace {
uintptr_t host_tp() { uintptr_t value; asm volatile("mrs %0,tpidr_el0" : "=r"(value)); return value; }
uintptr_t host_x18() { uintptr_t value; asm volatile("mov %0,x18" : "=r"(value)); return value; }
using Increment = uint64_t (*)(uint64_t*);

class Fixture {
public:
    DmGuestLoadedImage loaded{};
    char error[160]{};
    bool valid;
    explicit Fixture(const DmGuestImage& source)
        : valid(dm_android_guest_load(source, &loaded, error, sizeof(error))) {}
    ~Fixture() { dm_android_guest_unload(&loaded); }
    template<class Function> Function entry() const {
        return reinterpret_cast<Function>(static_cast<uint8_t*>(loaded.base) + loaded.source->entry_offset);
    }
};

struct Worker {
    const Fixture* fixture;
    uint64_t* counter;
    std::atomic<bool>* start;
    std::atomic<unsigned>* ready;
    bool passed = false;
};

void* increment_worker(void* opaque) {
    auto& worker = *static_cast<Worker*>(opaque);
    const auto tp = host_tp(), x18 = host_x18();
    DmGuestThreadState state{};
    state.image = &worker.fixture->loaded;
    auto* previous = dm_android_attach_guest_state(&state);
    worker.ready->fetch_add(1, std::memory_order_release);
    while (!worker.start->load(std::memory_order_acquire)) sched_yield();
    bool passed = true;
    for (unsigned index = 0; index < 2000; ++index) {
        const auto result = worker.fixture->entry<Increment>()(worker.counter);
        passed &= result != UINT64_MAX && result == state.virtual_x18;
    }
    passed &= host_tp() == tp && host_x18() == x18;
    dm_android_attach_guest_state(previous);
    worker.passed = passed;
    return nullptr;
}
}

bool dm_android_exclusive_probe(std::string& detail) {
    Fixture counter(dm_fixture_exclusive_counter), status(dm_fixture_exclusive_status),
        lr(dm_fixture_exclusive_live_lr), abandon(dm_fixture_exclusive_abandon),
        preserve(dm_fixture_exclusive_preserve), widths(dm_fixture_exclusive_widths),
        cbnz(dm_fixture_exclusive_cbnz_retry), inverted(dm_fixture_exclusive_inverted_retry);
    if (!counter.valid || !status.valid || !lr.valid || !abandon.valid || !preserve.valid || !widths.valid ||
        !cbnz.valid || !inverted.valid) {
        detail = "exclusive fixture image loading failed";
        return false;
    }
    const auto tp = host_tp(), x18 = host_x18();
    DmGuestThreadState state{};
    auto* previous = dm_android_attach_guest_state(&state);
    bool passed = true;
    for (const Fixture* fixture : {&counter, &status, &lr, &cbnz, &inverted}) {
        uint64_t value = 41;
        state.virtual_x18 = UINT64_MAX;
        state.image = &fixture->loaded;
        passed &= fixture->entry<Increment>()(&value) == 42 && value == 42;
        const uint64_t expected_x18 = fixture == &inverted ? reinterpret_cast<uintptr_t>(&value) :
            (fixture == &counter || fixture == &cbnz ? 42u : 0u);
        passed &= state.virtual_x18 == expected_x18;
    }
    state.image = &abandon.loaded;
    uint64_t abandoned = 41;
    using Conditional = uint64_t (*)(uint64_t*, uint64_t);
    passed &= abandon.entry<Conditional>()(&abandoned, 0) == 1 && abandoned == 41 && state.virtual_x18 == 41;
    bool stored = false;
    for (unsigned index = 0; index < 65535 && !stored; ++index) {
        const auto result = abandon.entry<Conditional>()(&abandoned, 1);
        passed &= result <= 1 && abandoned == (result ? 41u : 42u);
        stored = result == 0;
    }
    passed &= stored;
    state.image = &widths.loaded;
    alignas(16) uint64_t values[]{0x11223344556677ffULL, 0x112233445566ffffULL,
        0x11223344ffffffffULL, UINT64_MAX, 40, 50, 0xffffffff00000010ULL, 0};
    passed &= widths.entry<Increment>()(values) == 0;
    const uint64_t expected[]{0x1122334455667700ULL, 0x1122334455660000ULL,
        0x1122334400000000ULL, 0, 41, 51, 0x11, 0};
    passed &= std::memcmp(values, expected, sizeof(values)) == 0 && state.virtual_x18 == 0;
    DmGuestRegisterFrame before{}, after{};
    state.image = &preserve.loaded;
    state.virtual_x18 = 0x8877665544332211ULL;
    dm_android_test_guest_frame(preserve.entry<void (*)()>(), &before, &after);
    passed &= std::memcmp(before.x, after.x, sizeof(before.x)) == 0 &&
        std::memcmp(before.q, after.q, sizeof(before.q)) == 0 &&
        before.guest_sp == after.guest_sp && before.nzcv == after.nzcv &&
        before.fpsr == after.fpsr && before.fpcr == after.fpcr && state.virtual_x18 == 0x8877665544332211ULL;
    passed &= host_tp() == tp && host_x18() == x18;
    dm_android_attach_guest_state(previous);

    alignas(16) uint64_t shared = 0;
    std::atomic<bool> start{false};
    std::atomic<unsigned> ready{0};
    Worker workers[]{{&counter, &shared, &start, &ready}, {&counter, &shared, &start, &ready}};
    pthread_t threads[2]{};
    unsigned created = 0;
    for (; created < 2; ++created)
        if (pthread_create(&threads[created], nullptr, increment_worker, &workers[created]) != 0) break;
    while (ready.load(std::memory_order_acquire) != created) sched_yield();
    start.store(true, std::memory_order_release);
    for (unsigned index = 0; index < created; ++index)
        if (pthread_join(threads[index], nullptr) != 0) std::abort();  // Never unload live guest code.
    passed &= created == 2 && workers[0].passed && workers[1].passed && shared == 4000;
    detail = "Native exclusive byte/half/word/double/pairs, acquire/release, CLREX, W18 status, live x16/LR, direct and inverted status retries, virtual x18 base; full GPR/SIMD/status/SP preservation; two pthreads perform 4000 contended increments; host x18/TLS unchanged";
    return passed;
}
