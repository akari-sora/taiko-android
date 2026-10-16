#pragma once
#include <array>
#include <cstdint>
#include <mutex>

struct GameActivityMotionEvent;

namespace dm_android {
constexpr uint32_t kTouchCapacity = 16;
enum class TouchAction { Down, PointerDown, Move, PointerUp, Up, Cancel };
struct TouchPointer { int32_t pointer_id = -1; float x_px = 0, y_px = 0; };
struct TouchMotion {
    TouchAction action = TouchAction::Cancel;
    uint32_t action_index = 0, pointer_count = 0;
    int32_t device_id = 0;
    bool canceled = false; // A rejected Up/PointerUp is not a user release.
    std::array<TouchPointer, kTouchCapacity> pointers{};
};
struct TouchViewport {
    float left_px = 0, top_px = 0, width_px = 0, height_px = 0, density = 1;
};
struct TouchSample {
    uint32_t slot = 0;
    int32_t pointer_id = -1;
    float normalized_x = 0, normalized_y = 0;
    float logical_x = 0, logical_y = 0;
};
struct TouchSnapshot {
    uint32_t count = 0;
    float logical_width = 0, logical_height = 0;
    std::array<TouchSample, kTouchCapacity> points{};
};

// One active front-end provider owns the shared dm_touch_set publication.
// Methods are internally serialized; the guest's separate touch reader uses
// hle_touch.c's original mutex. This publishes raw touch points only, without
// claiming that the unported controls/game actions have run.
class TouchInputProvider {
public:
    bool set_viewport(const TouchViewport& viewport);
    void set_enabled(bool enabled);
    bool process(const TouchMotion& event);
    // Uses the actual GameActivity event layout and Android action constants.
    // Non-touch sources are left for their own mouse/controller providers.
    bool process_game_activity(const GameActivityMotionEvent& event);
    TouchSnapshot snapshot() const;
    void cancel();
    // Runtime teardown only: the guest must be quiescent. Keeps enabled/viewport.
    void reset();
private:
    struct Pointer {
        int32_t id = -1;
        int slot = -1; // A gesture starting outside the content stays excluded.
        float x_px = 0, y_px = 0;
    };
    void cancel_locked();
    void publish_locked();
    int find_locked(int32_t id) const;
    mutable std::mutex mutex_;
    TouchViewport viewport_{};
    std::array<Pointer, kTouchCapacity> pointers_{};
    uint32_t count_ = 0;
    int32_t device_id_ = 0;
    bool viewport_valid_ = false, enabled_ = false;
};
}
