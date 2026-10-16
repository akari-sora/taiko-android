#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
enum {
    DM_PARAMETER_KRES0 = 0, DM_PARAMETER_KRES1 = 1,
    DM_PARAMETER_KASPECT = 2, DM_PARAMETER_KASPECT_UI = 3,
};
typedef bool (*DmGuestParameterProvider)(uint64_t values[4], void* context);
// Provider/context remain valid until replacement returns. Providers are pure
// leaf callbacks: no guest calls or recursive registration/capture.
void dm_android_set_parameter_provider(DmGuestParameterProvider, void* context);
// Capture all four values or leave caller output unchanged. No implicit size.
bool dm_android_capture_guest_parameters(uint64_t values[4]);
// Native display basis, oriented like iOS nativeBounds (long side first).
// This does not implement scene-specific UI/3D viewport scaling or OE refresh.
bool dm_android_calculate_guest_parameters(uint32_t native_width, uint32_t native_height,
                                           uint64_t values[4]);
#ifdef __cplusplus
}
#endif
