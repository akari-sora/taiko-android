#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
namespace dm_android {
class ModuleSha256 {
public:
    ModuleSha256();
    void update(const uint8_t* bytes, size_t size);
    void finish(uint8_t digest[32]) const;
private:
    uint32_t state_[8];
    uint8_t tail_[64]{};
    uint64_t bytes_ = 0;
    size_t tail_bytes_ = 0;
};
void module_sha256(const uint8_t* bytes, size_t size, uint8_t digest[32]);
// Offset-preserving streaming hash of one ordinary, stable file. Neither closes
// nor changes the caller's descriptor. expected_bytes and limit are trusted bounds.
bool module_sha256_fd(int fd, uint64_t expected_bytes, uint64_t limit,
                      uint8_t digest[32], std::string* error);
}
