// These unchanged HID touch exports are shared by the Apple and Android hosts.
// Controller reads remain in hle_hid.c with their complete gameplay pump chain.
#include "hle.h"
#include "front.h"

HLE_FORCE("_ZN2nn3hid21InitializeTouchScreenEv", "连 hid 服务；触屏输入由前端另接", void, h_hid_InitTouch, void) {}

// nn::hid::TouchScreenState<16>: sampling, count, reserved, 16 x 0x28 touches.
// The game reads entry zero; return exactly one state, using the guest clock.
typedef struct { int64_t sampling; int32_t count, _r; uint8_t touches[16][0x28]; } TouchState16;
_Static_assert(sizeof(TouchState16) == 0x290, "TouchScreenState<16>");
int touch_fill(void *out, uint64_t now_ns);
HLE_FORCE("_ZN2nn3hid20GetTouchScreenStatesILm16EEEiPNS0_16TouchScreenStateIXT_EEEi", "触屏状态：前端触点（hle_touch.c）", int, h_hid_GetTouch, TouchState16 *out, int n) {
    if (n < 1) return 0;
    touch_fill(out, guest_ns());
    return 1;
}
