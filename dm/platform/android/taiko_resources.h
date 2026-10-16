#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace dm_android {
struct TaikoResourcePin {
    const char* path; // Content-root relative, exact UTF-8 bytes: RomFS/...
    uint64_t bytes;
    std::array<uint8_t,32> sha256;
};
struct TaikoContentPins {
    uint32_t schema;
    const char* program_id;
    std::array<uint8_t,32> manifest_sha256;
    const TaikoResourcePin* files; // Strictly increasing bytewise path order.
    size_t file_count;
    uint64_t total_bytes; // Sum of resource files only.
};
const TaikoContentPins* taiko_content_pins();
// Does not parse caller JSON as authority. Verifies the compiled manifest hash
// and exact RomFS inventory, with no symlink traversal or whole-file allocation.
// Caller retains the content directory descriptor and its own lifecycle lock.
bool verify_taiko_content(int content_dir_fd,std::string* error);
}
