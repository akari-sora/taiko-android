#pragma once
#include <stddef.h>
#include <stdint.h>
namespace dm_android {
void module_sha256(const uint8_t* bytes, size_t size, uint8_t digest[32]);
}
