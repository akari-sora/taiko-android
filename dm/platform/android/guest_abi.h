// Android guest ABI v1. The compiler/Bionic own host TLS and x18.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "guest_parameter_layout.h"

#define DM_ANDROID_GUEST_ABI 0x444d4101u

struct alignas(16) DmGuestRegisterFrame {
    uint64_t x[31];
    uint64_t guest_sp;
    uint8_t q[32][16];
    uint64_t nzcv;
    uint64_t fpsr;
    uint64_t fpcr;
    uint64_t return_pc;
};
static_assert(offsetof(DmGuestRegisterFrame, guest_sp) == 248);
static_assert(offsetof(DmGuestRegisterFrame, q) == 256);
static_assert(offsetof(DmGuestRegisterFrame, nzcv) == 768);
static_assert(offsetof(DmGuestRegisterFrame, return_pc) == 792);
static_assert(sizeof(DmGuestRegisterFrame) == 800);

enum DmGuestHelper : uint32_t { DM_GUEST_STATE_HELPER = 1, DM_GUEST_DISPATCH_HELPER = 2 };
enum DmGuestGateKind : uint32_t { DM_GUEST_SVC = 1, DM_GUEST_TIMER = 2, DM_GUEST_OBSERVATION = 3, DM_GUEST_INDIRECT_HOST = 4, DM_GUEST_STACK_CHECK = 5, DM_GUEST_EXACT_GUEST = 6 };
struct DmGuestFixup { size_t offset; uint32_t helper; };
struct DmGuestGate { size_t return_offset; uint32_t kind; uint32_t argument; };
enum DmGuestSegmentFlags : uint32_t { DM_GUEST_READ = 1, DM_GUEST_WRITE = 2, DM_GUEST_EXEC = 4 };
struct DmGuestSegment { size_t offset; size_t size; uint32_t flags; };
struct DmGuestImage {
    uint32_t abi;
    const uint8_t* bytes;
    size_t size;
    size_t entry_offset;
    const DmGuestFixup* fixups;
    size_t fixup_count;
    const DmGuestGate* gates;
    size_t gate_count;
    const DmGuestSegment* segments = nullptr;
    size_t segment_count = 0;
};
struct DmGuestLoadedImage {
    void* base;
    size_t mapping_size;
    const DmGuestImage* source;
    void* reservation = nullptr;
    size_t reservation_size = 0;
    bool sealed = false;
};
struct DmGuestThreadState;
using DmGuestDispatch = void (*)(DmGuestThreadState*, DmGuestRegisterFrame*, const DmGuestGate*);
using DmGuestGateResolver = const DmGuestGate* (*)(void*, uint64_t);
struct DmGuestThreadState {
    uint64_t virtual_x18;
    uint64_t guest_tpidr_el0;
    uint64_t guest_tpidrro_el0;
    DmGuestDispatch dispatch;
    void* user_data;
    const DmGuestLoadedImage* image;
    DmGuestGateResolver gate_resolver = nullptr;
    void* gate_context = nullptr;
    // Exact environment backing spans; distinct from guest-selectable TP values.
    struct { uintptr_t base; size_t size; } owned_memory[3]{};
    bool (*invocation_enter)(void*) = nullptr;
    void (*invocation_leave)(void*) = nullptr;
    void* invocation_context = nullptr;
    uint64_t parameters[DM_GUEST_PARAMETER_COUNT]{};
    uint32_t parameter_valid_mask = 0;
    // Appended: assembly-visible parameter offsets above remain unchanged.
    uint64_t runtime_generation = 0;
};
static_assert(offsetof(DmGuestThreadState, virtual_x18) == 0);
static_assert(offsetof(DmGuestThreadState, guest_tpidr_el0) == 8);
static_assert(offsetof(DmGuestThreadState, guest_tpidrro_el0) == 16);
static_assert(offsetof(DmGuestThreadState, parameters) == DM_GUEST_PARAMETER_BASE);
static_assert(offsetof(DmGuestThreadState, parameter_valid_mask) == DM_GUEST_PARAMETER_VALID_MASK);
static_assert(sizeof(DmGuestGate) == 16);

extern "C" {
// Accessor assembly preserves every register/flag except x16 (state pointer).
// Callers must save x16 and their original LR in allocated stack storage.
void dm_android_state_accessor();
// Dispatch callers allocate 16 bytes and save original x29/x30 there.
// The gate exposes virtual guest x18; hardware x18 is never overwritten.
void dm_android_dispatch_gate();
DmGuestThreadState* dm_android_current_guest_state();
DmGuestThreadState* dm_android_peek_guest_state();
DmGuestThreadState* dm_android_attach_guest_state(DmGuestThreadState* state);
void dm_android_dispatch_frame(DmGuestRegisterFrame* frame);
// Derived from frozen Process/package mode and current generation, never a caller flag.
int dm_android_stack_entry_reserve(const DmGuestThreadState*, uintptr_t entry, size_t* reserve);
bool dm_android_stack_gate_authorized(const DmGuestThreadState*, uint64_t return_pc, const DmGuestGate*);
bool dm_android_validate_stack_check(const DmGuestRegisterFrame*, uint32_t word);
bool dm_android_stack_dispatch_context(const DmGuestThreadState*);
}

// Image bytes and metadata are borrowed, immutable, and must outlive the loaded
// image. prepare maps RW; seal applies final segment permissions. Without
// segments, the legacy raw fixture view is one RX segment through this mapper.
// Callers unload only after every attached guest thread has finished.
bool dm_android_guest_load(const DmGuestImage& image, DmGuestLoadedImage* out,
                           char* error, size_t error_size);
bool dm_android_guest_prepare(const DmGuestImage& image, DmGuestLoadedImage* out,
                             char* error, size_t error_size);
bool dm_android_guest_seal(DmGuestLoadedImage* image, char* error, size_t error_size);
void dm_android_guest_unload(DmGuestLoadedImage* image);
bool dm_android_guest_round_size(size_t size, size_t page_size, size_t* result);
