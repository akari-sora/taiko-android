#pragma once
#include "input_platform.h"
#include "../../ios/Sources/dm_touch_controls.h"

namespace dm_android {
struct TouchControlsSnapshot {
    TouchViewport viewport{};
    dm_tc_state state{};
    bool enabled = false;
};

// The current Activity owner serializes this model. The GameActivity collector
// remains the sole event source and the raw provider remains the sole publisher
// of dm_touch_set. This adapter publishes only the shared HID touch channel.
class TouchControlsPlatform {
public:
    bool set_viewport(const TouchViewport& viewport);
    void set_enabled(bool enabled);
    void cancel();
    // before/after are copied from the authoritative raw provider around an
    // accepted event. They supply slots; pointer-array order never supplies slots.
    void consume(const TouchMotion& event, const TouchSnapshot& before,
                 const TouchSnapshot& after, double monotonic_s);
    void consume_game_activity(const GameActivityMotionEvent& event,
                              const TouchSnapshot& before, const TouchSnapshot& after);
    void tick(double monotonic_s);
    int poll_timeout_ms() const;
    TouchControlsSnapshot snapshot() const;
private:
    void publish();
    void pulse_tick(double now_s);
    TouchViewport viewport_{};
    dm_tc_state state_{};
    bool valid_ = false, enabled_ = false, initialized_ = false;
    uint64_t pulse_epoch_ = 0, pulse_samples_ = 0, resume_samples_ = 0;
    double pulse_started_s_ = 0, pulse_seen_s_ = 0, resume_started_s_ = 0;
};
}

#ifdef __ANDROID__
#include <jni.h>
namespace dm_android {
// Implemented by the Activity owner. A retired Activity cannot enable, inspect
// or cancel a replacement Activity's controls. Snapshot is a read-only copy.
bool input_activity_touch_controls_visible(JNIEnv*, jobject activity, bool visible);
bool input_activity_touch_controls_snapshot(JNIEnv*, jobject activity, TouchControlsSnapshot*);
}
#endif
