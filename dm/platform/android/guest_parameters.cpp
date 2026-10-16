#include "guest_parameters.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <mutex>

namespace {
std::mutex provider_mutex;
DmGuestParameterProvider provider = nullptr;
void* provider_context = nullptr;
uint64_t pack(uint32_t width, uint32_t height) { return static_cast<uint64_t>(height) << 32 | width; }
uint32_t float_bits(float value) { uint32_t bits; std::memcpy(&bits, &value, sizeof bits); return bits; }
bool valid(const uint64_t values[4]) {
    for (unsigned i = 0; i < 2; ++i) {
        const uint32_t width = values[i], height = values[i] >> 32;
        if (!width || !height || width > 4096 || height > 4096) return false;
    }
    for (unsigned i = 2; i < 4; ++i) {
        if (values[i] >> 32) return false;
        const uint32_t bits = static_cast<uint32_t>(values[i]);
        float number; std::memcpy(&number, &bits, sizeof number);
        if (!std::isfinite(number) || number < 19.0f / 9.0f) return false;
    }
    return true;
}
}

extern "C" void dm_android_set_parameter_provider(DmGuestParameterProvider next, void* context) {
    std::lock_guard<std::mutex> lock(provider_mutex);
    provider = next; provider_context = context;
}
extern "C" bool dm_android_capture_guest_parameters(uint64_t values[4]) {
    if (!values) return false;
    std::lock_guard<std::mutex> lock(provider_mutex);
    uint64_t captured[4]{};
    if (!provider || !provider(captured, provider_context) || !valid(captured)) return false;
    std::memcpy(values, captured, sizeof captured);
    return true;
}
extern "C" bool dm_android_calculate_guest_parameters(uint32_t native_width, uint32_t native_height,
                                                       uint64_t values[4]) {
    if (!values || !native_width || !native_height || native_width > 4096 || native_height > 4096) return false;
    const uint32_t width = std::max(native_width, native_height);
    const uint32_t height = std::min(native_width, native_height);
    // Same nativeBounds orientation and nearest-eight handheld rounding as
    // front_ios.m; scene-specific UI layout/3D scale remains a separate owner.
    const double aspect = static_cast<double>(width) / height;
    const auto handheld_width = static_cast<uint64_t>(std::llround(720.0 * aspect / 8.0)) * 8;
    if (!handheld_width || handheld_width > 4096) return false;
    uint64_t result[4]{pack(static_cast<uint32_t>(handheld_width), 720), pack(width, height), 0, 0};
    float limit = 19.0f / 9.0f;
    bool wide = false;
    for (unsigned i = 0; i < 2; ++i) {
        const float ratio = static_cast<float>(static_cast<uint32_t>(result[i])) /
                            static_cast<float>(static_cast<uint32_t>(result[i] >> 32));
        if (ratio > limit) { limit = ratio; wide = true; }
    }
    result[2] = float_bits(limit);
    result[3] = float_bits(wide ? limit + 0.15f : limit);
    std::memcpy(values, result, sizeof result);
    return true;
}
