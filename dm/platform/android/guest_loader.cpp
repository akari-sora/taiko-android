#include "guest_abi.h"
#include "guest_loader_internal.h"
#include "guest_stack_check.h"

#include <errno.h>
#include <limits.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr size_t max_image_size = 256u * 1024u * 1024u;

bool fail(char* error, size_t error_size, const char* message) {
    if (error && error_size) snprintf(error, error_size, "%s", message);
    return false;
}

bool system_fail(char* error, size_t error_size, const char* operation) {
    const int saved_errno = errno;
    if (error && error_size)
        snprintf(error, error_size, "%s: %s", operation, strerror(saved_errno));
    return false;
}
bool permissions(const DmGuestImage& image, size_t page, size_t rounded,
                 std::vector<int>* pages, char* error, size_t error_size) {
    pages->assign(rounded / page, PROT_NONE);
    if (!image.segment_count) {
        if (image.segments) return fail(error, error_size, "segment pointer without segments");
        for (int& flags : *pages) flags = PROT_READ | PROT_EXEC;
        return true;
    }
    if (!image.segments || image.segment_count > 16)
        return fail(error, error_size, "invalid guest segments");
    for (size_t i = 0; i < image.segment_count; ++i) {
        const auto& s = image.segments[i];
        if (!s.size || s.offset >= image.size || s.size > image.size - s.offset ||
            !s.flags || (s.flags & ~7u) || !(s.flags & DM_GUEST_READ))
            return fail(error, error_size, "invalid guest segment bounds or flags");
        for (size_t j = 0; j < i; ++j) {
            const auto& t = image.segments[j];
            if (s.offset < t.offset + t.size && t.offset < s.offset + s.size)
                return fail(error, error_size, "overlapping guest segments");
        }
        const int flags = PROT_READ | ((s.flags & DM_GUEST_WRITE) ? PROT_WRITE : 0) |
                          ((s.flags & DM_GUEST_EXEC) ? PROT_EXEC : 0);
        for (size_t p = s.offset / page; p <= (s.offset + s.size - 1) / page; ++p) {
            (*pages)[p] |= flags;
            if (((*pages)[p] & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
                return fail(error, error_size, "guest writable/executable page conflict");
        }
    }
    const auto executable = [&](size_t off, size_t bytes) {
        for (size_t i = 0; i < image.segment_count; ++i) {
            const auto& s = image.segments[i];
            if ((s.flags & DM_GUEST_EXEC) && off >= s.offset && off - s.offset <= s.size &&
                bytes <= s.size - (off - s.offset)) return true;
        }
        return false;
    };
    if (!executable(image.entry_offset, 4))
        return fail(error, error_size, "guest entry outside executable segment");
    for (size_t i = 0; i < image.fixup_count; ++i)
        if (!executable(image.fixups[i].offset, 8))
            return fail(error, error_size, "helper outside executable segment");
    for (size_t i = 0; i < image.gate_count; ++i)
        if (!executable(image.gates[i].return_offset - 4, 8))
            return fail(error, error_size, "gate outside executable segment");
    return true;
}
}

bool dm_android_guest_round_size(size_t size, size_t page_size, size_t* result) {
    if (!result || !size || !page_size || (page_size & (page_size - 1))) return false;
    const size_t padding = page_size - 1;
    if (size > SIZE_MAX - padding) return false;
    *result = (size + padding) & ~padding;
    return true;
}

static bool prepare_image(const DmGuestImage& image, DmGuestLoadedImage* out,
                          char* error, size_t error_size, bool canonical_v2, bool profiled) {
    if (!out) return fail(error, error_size, "missing output image");
    *out = {};
    if (error && error_size) error[0] = '\0';
    if (image.abi != DM_ANDROID_GUEST_ABI)
        return fail(error, error_size, "unsupported Android guest ABI");
    if (!image.bytes || !image.size || image.size > max_image_size || (image.size & 3))
        return fail(error, error_size, "invalid guest image size");
    if ((image.entry_offset & 3) || image.entry_offset >= image.size)
        return fail(error, error_size, "invalid guest entry offset");
    if (image.fixup_count > image.size / 8 || (image.fixup_count && !image.fixups) ||
        image.gate_count > image.size / 4 || (image.gate_count && !image.gates))
        return fail(error, error_size, "invalid guest metadata bounds");
    // Two bits per instruction word: helper-data span and seen gate target.
    const size_t mark_size = (image.size / 4 + 3) / 4;
    std::unique_ptr<uint8_t, decltype(&free)> marks(
        static_cast<uint8_t*>(calloc(mark_size, 1)), &free);
    if (!marks) return fail(error, error_size, "cannot allocate guest metadata validation marks");
    const auto marked = [&](size_t offset, unsigned kind) {
        const size_t bit = offset / 4;
        const uint8_t mask = static_cast<uint8_t>(1u << ((bit & 3) * 2 + kind));
        return (marks.get()[bit / 4] & mask) != 0;
    };
    const auto duplicate = [&](size_t offset, unsigned kind) {
        const size_t bit = offset / 4;
        const uint8_t mask = static_cast<uint8_t>(1u << ((bit & 3) * 2 + kind));
        const bool present = (marks.get()[bit / 4] & mask) != 0;
        marks.get()[bit / 4] |= mask;
        return present;
    };
    for (size_t i = 0; i < image.fixup_count; ++i) {
        const DmGuestFixup& fixup = image.fixups[i];
        if ((fixup.offset & 7) || image.size < 8 || fixup.offset > image.size - 8)
            return fail(error, error_size, "unaligned or out-of-bounds helper fixup");
        if (fixup.helper != DM_GUEST_STATE_HELPER && fixup.helper != DM_GUEST_DISPATCH_HELPER)
            return fail(error, error_size, "unknown guest helper ID");
        uint64_t placeholder;
        memcpy(&placeholder, image.bytes + fixup.offset, sizeof(placeholder));
        if (placeholder) return fail(error, error_size, "helper fixup has nonzero placeholder");
        if (image.entry_offset >= fixup.offset && image.entry_offset < fixup.offset + 8)
            return fail(error, error_size, "guest entry points into helper data");
        if (duplicate(fixup.offset, 0))
            return fail(error, error_size, "duplicate guest helper fixup");
        duplicate(fixup.offset + 4, 0);
    }
    for (size_t i = 0; i < image.gate_count; ++i) {
        const DmGuestGate& gate = image.gates[i];
        if ((gate.return_offset & 3) || gate.return_offset < 4 || gate.return_offset >= image.size)
            return fail(error, error_size, "invalid dispatch return offset");
        if (marked(gate.return_offset, 0) || marked(gate.return_offset - 4, 0))
            return fail(error, error_size, "dispatch instructions overlap helper data");
        if ((gate.kind == DM_GUEST_SVC && gate.argument > 65535) ||
            (gate.kind == DM_GUEST_TIMER && gate.argument > 31) ||
            (gate.kind == DM_GUEST_INDIRECT_HOST && (gate.argument > 30 || gate.argument == 18)) ||
            (gate.kind == DM_GUEST_EXACT_GUEST && gate.argument != 17) ||
            (gate.kind == DM_GUEST_STACK_CHECK && !dm_android_decode_stack_check(gate.argument)) ||
            (gate.kind != DM_GUEST_SVC && gate.kind != DM_GUEST_TIMER &&
             !(profiled && gate.kind == DM_GUEST_OBSERVATION) &&
             !(canonical_v2 && (gate.kind == DM_GUEST_INDIRECT_HOST ||
                                gate.kind == DM_GUEST_STACK_CHECK ||
                                gate.kind == DM_GUEST_EXACT_GUEST))))
            return fail(error, error_size, "invalid dispatch kind or argument");
        uint32_t instruction;
        memcpy(&instruction, image.bytes + gate.return_offset - 4, sizeof(instruction));
        if (instruction != 0xd63f03c0u)
            return fail(error, error_size, "dispatch return offset does not follow BLR x30");
        if (duplicate(gate.return_offset, 1))
            return fail(error, error_size, "duplicate dispatch return offset");
    }
    const long page_query = sysconf(_SC_PAGESIZE);
    size_t rounded;
    if (page_query <= 0 || !dm_android_guest_round_size(image.size, static_cast<size_t>(page_query), &rounded))
        return fail(error, error_size, "invalid host page size or mapping overflow");
    const size_t page = static_cast<size_t>(page_query);
    std::vector<int> page_permissions;
    if (!permissions(image, page, rounded, &page_permissions, error, error_size)) return false;
    if (page > SIZE_MAX / 2 || rounded > SIZE_MAX - 2 * page)
        return fail(error, error_size, "guarded mapping size overflow");
    const size_t reservation_size = rounded + 2 * page;
    void* reservation = mmap(nullptr, reservation_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) return system_fail(error, error_size, "mmap guest image");
    auto* base = static_cast<uint8_t*>(reservation) + page;
    if (mprotect(base, rounded, PROT_READ | PROT_WRITE) != 0) {
        const bool result = system_fail(error, error_size, "mprotect guest image RW");
        munmap(reservation, reservation_size);
        return result;
    }
    memcpy(base, image.bytes, image.size);
    for (size_t i = 0; i < image.fixup_count; ++i) {
        const DmGuestFixup& fixup = image.fixups[i];
        const uintptr_t pointer = fixup.helper == DM_GUEST_STATE_HELPER
            ? reinterpret_cast<uintptr_t>(&dm_android_state_accessor)
            : reinterpret_cast<uintptr_t>(&dm_android_dispatch_gate);
        static_assert(sizeof(pointer) == 8, "Android guest requires ARM64 pointers");
        memcpy(base + fixup.offset, &pointer, sizeof(pointer));
    }
    // Source and metadata are immutable borrowed storage until this image unloads.
    *out = {base, rounded, &image, reservation, reservation_size, false};
    return true;
}

bool dm_android_guest_prepare(const DmGuestImage& image, DmGuestLoadedImage* out,
                             char* error, size_t error_size) {
    return prepare_image(image, out, error, error_size, false, false);
}

// Internal mapper implementation, intentionally absent from the public ABI
// header. Only the package-aware authority validator calls the extended path.
bool dm_android_guest_prepare_package_image(const DmGuestImage& image, DmGuestLoadedImage* out,
                                           char* error, size_t error_size, bool canonical_v2, bool profiled) {
    return prepare_image(image, out, error, error_size, canonical_v2, profiled);
}

bool dm_android_guest_seal(DmGuestLoadedImage* loaded, char* error, size_t error_size) {
    if (!loaded || !loaded->base || !loaded->source || loaded->sealed)
        return fail(error, error_size, "invalid or already sealed guest mapping");
    const long query = sysconf(_SC_PAGESIZE);
    if (query <= 0) return fail(error, error_size, "invalid host page size");
    std::vector<int> pages;
    if (!permissions(*loaded->source, static_cast<size_t>(query), loaded->mapping_size,
                     &pages, error, error_size)) return false;
    auto* base = static_cast<uint8_t*>(loaded->base);
    __builtin___clear_cache(reinterpret_cast<char*>(base),
                           reinterpret_cast<char*>(base + loaded->source->size));
    for (size_t i = 0; i < pages.size();) {
        size_t end = i + 1;
        while (end < pages.size() && pages[end] == pages[i]) ++end;
        if (mprotect(base + i * query, (end - i) * query, pages[i]) != 0)
            return system_fail(error, error_size, "mprotect guest final segments");
        i = end;
    }
    loaded->sealed = true;
    return true;
}

bool dm_android_guest_load(const DmGuestImage& image, DmGuestLoadedImage* out,
                           char* error, size_t error_size) {
    if (!dm_android_guest_prepare(image, out, error, error_size)) return false;
    if (dm_android_guest_seal(out, error, error_size)) return true;
    dm_android_guest_unload(out);
    return false;
}

void dm_android_guest_unload(DmGuestLoadedImage* image) {
    if (!image || !image->base) return;
    if (image->reservation) munmap(image->reservation, image->reservation_size);
    *image = {};
}
