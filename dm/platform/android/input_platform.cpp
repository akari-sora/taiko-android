#include "input_platform.h"
extern "C" {
#include "../../host/front.h"
}
#include <algorithm>
#include <cmath>
#if defined(__ANDROID__)
#include <game-activity/GameActivityEvents.h>
#endif

namespace dm_android {
namespace {
bool valid_viewport(const TouchViewport& v) {
    return std::isfinite(v.left_px) && std::isfinite(v.top_px) &&
           std::isfinite(v.width_px) && std::isfinite(v.height_px) &&
           std::isfinite(v.density) && v.width_px > 0 && v.height_px > 0 && v.density > 0 &&
           std::isfinite(v.left_px + v.width_px) && std::isfinite(v.top_px + v.height_px) &&
           std::isfinite(v.width_px / v.density) && std::isfinite(v.height_px / v.density);
}
bool same_viewport(const TouchViewport& a, const TouchViewport& b) {
    return a.left_px == b.left_px && a.top_px == b.top_px &&
           a.width_px == b.width_px && a.height_px == b.height_px && a.density == b.density;
}
float normalized(float p, float origin, float extent) {
    return std::min((std::clamp(p, origin, origin + extent) - origin) / extent, 0.99999f);
}
}

bool TouchInputProvider::set_viewport(const TouchViewport& viewport) {
    std::lock_guard<std::mutex> lock(mutex_);
    const bool valid = valid_viewport(viewport);
    if (!valid || !viewport_valid_ || !same_viewport(viewport_, viewport)) cancel_locked();
    viewport_ = viewport;
    viewport_valid_ = valid;
    return valid;
}
void TouchInputProvider::set_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!enabled) cancel_locked();
    enabled_ = enabled;
}
void TouchInputProvider::cancel_locked() {
    pointers_ = {};
    count_ = 0;
    dm_touch_cancel();
}
void TouchInputProvider::cancel() {
    std::lock_guard<std::mutex> lock(mutex_);
    cancel_locked();
}
void TouchInputProvider::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    cancel_locked();
    dm_touch_reset();
}
int TouchInputProvider::find_locked(int32_t id) const {
    for (uint32_t i = 0; i < count_; ++i) if (pointers_[i].id == id) return static_cast<int>(i);
    return -1;
}
void TouchInputProvider::publish_locked() {
    dm_touch points[kTouchCapacity];
    int count = 0;
    for (uint32_t slot = 0; slot < kTouchCapacity; ++slot) {
        for (uint32_t i = 0; i < count_; ++i) {
            const Pointer& p = pointers_[i];
            if (p.slot != static_cast<int>(slot)) continue;
            points[count++] = {slot, normalized(p.x_px, viewport_.left_px, viewport_.width_px),
                              normalized(p.y_px, viewport_.top_px, viewport_.height_px)};
        }
    }
    dm_touch_set(points, count);
}
bool TouchInputProvider::process(const TouchMotion& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!enabled_ || !viewport_valid_) return false;
    if (count_ && event.device_id != device_id_) return false;
    if (event.action == TouchAction::Cancel) { cancel_locked(); return true; }
    const auto invalid = [&] { cancel_locked(); return false; };
    const uint32_t n = event.pointer_count;
    if (!n || n > kTouchCapacity) return invalid();
    for (uint32_t i = 0; i < n; ++i) {
        const TouchPointer& p = event.pointers[i];
        if (p.pointer_id < 0 || !std::isfinite(p.x_px) || !std::isfinite(p.y_px)) return invalid();
        for (uint32_t j = 0; j < i; ++j)
            if (p.pointer_id == event.pointers[j].pointer_id) return invalid();
    }
    const bool down = event.action == TouchAction::Down;
    const bool add = event.action == TouchAction::PointerDown;
    const bool remove = event.action == TouchAction::PointerUp || event.action == TouchAction::Up;
    if (!down && !add && !remove && event.action != TouchAction::Move) return invalid();
    if (event.canceled && !remove) return invalid();
    if ((down || add || remove) && event.action_index >= n) return invalid();
    if (down) {
        if (n != 1 || event.action_index) return invalid();
        // A fresh down can recover a lost prior stream. An ordinary new gesture
        // after Up must retain hle_touch.c's pending End / re-press latch.
        if (count_) cancel_locked();
        device_id_ = event.device_id;
    } else {
        if (!count_ || n != count_ + (add ? 1u : 0u)) return invalid();
        if ((event.action == TouchAction::Up && (count_ != 1 || event.action_index)) ||
            (event.action == TouchAction::PointerUp && count_ < 2)) return invalid();
        for (uint32_t i = 0; i < n; ++i) {
            const bool known = find_locked(event.pointers[i].pointer_id) >= 0;
            if (add && i == event.action_index ? known : !known) return invalid();
        }
    }
    if (down || add) {
        const TouchPointer& p = event.pointers[event.action_index];
        int slot = -1;
        if (p.x_px >= viewport_.left_px && p.x_px < viewport_.left_px + viewport_.width_px &&
            p.y_px >= viewport_.top_px && p.y_px < viewport_.top_px + viewport_.height_px) {
            for (uint32_t candidate = 0; candidate < kTouchCapacity; ++candidate) {
                bool used = false;
                for (uint32_t i = 0; i < count_; ++i) used |= pointers_[i].slot == static_cast<int>(candidate);
                if (!used) { slot = static_cast<int>(candidate); break; }
            }
        }
        pointers_[count_++] = {p.pointer_id, slot, p.x_px, p.y_px};
    }
    for (uint32_t i = 0; i < n; ++i) {
        Pointer& p = pointers_[static_cast<size_t>(find_locked(event.pointers[i].pointer_id))];
        p.x_px = event.pointers[i].x_px; p.y_px = event.pointers[i].y_px;
    }
    // Publish final coordinates before removing the lifted pointer, so the
    // shared End record retains the position in this very MotionEvent.
    if (remove && event.canceled) {
        const Pointer& rejected = pointers_[static_cast<size_t>(find_locked(event.pointers[event.action_index].pointer_id))];
        if (rejected.slot >= 0) dm_touch_cancel_finger(static_cast<uint32_t>(rejected.slot));
    } else publish_locked();
    if (remove) {
        const int index = find_locked(event.pointers[event.action_index].pointer_id);
        for (uint32_t i = static_cast<uint32_t>(index); i + 1 < count_; ++i) pointers_[i] = pointers_[i + 1];
        --count_;
        pointers_[count_] = {};
        publish_locked();
    }
    return true;
}
TouchSnapshot TouchInputProvider::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    TouchSnapshot out{};
    if (!viewport_valid_) return out;
    out.logical_width = viewport_.width_px / viewport_.density;
    out.logical_height = viewport_.height_px / viewport_.density;
    for (uint32_t slot = 0; slot < kTouchCapacity; ++slot) {
        for (uint32_t i = 0; i < count_; ++i) {
            const Pointer& p = pointers_[i];
            if (p.slot != static_cast<int>(slot)) continue;
            const float nx = normalized(p.x_px, viewport_.left_px, viewport_.width_px);
            const float ny = normalized(p.y_px, viewport_.top_px, viewport_.height_px);
            out.points[out.count++] = {slot, p.id, nx, ny, nx * out.logical_width, ny * out.logical_height};
        }
    }
    return out;
}
#if defined(__ANDROID__)
bool TouchInputProvider::process_game_activity(const GameActivityMotionEvent& event) {
    if ((event.source & AINPUT_SOURCE_TOUCHSCREEN) != AINPUT_SOURCE_TOUCHSCREEN) return false;
    TouchMotion motion{};
    switch (event.action & AMOTION_EVENT_ACTION_MASK) {
        case AMOTION_EVENT_ACTION_DOWN: motion.action = TouchAction::Down; break;
        case AMOTION_EVENT_ACTION_POINTER_DOWN: motion.action = TouchAction::PointerDown; break;
        case AMOTION_EVENT_ACTION_MOVE: motion.action = TouchAction::Move; break;
        case AMOTION_EVENT_ACTION_POINTER_UP: motion.action = TouchAction::PointerUp; break;
        case AMOTION_EVENT_ACTION_UP: motion.action = TouchAction::Up; break;
        case AMOTION_EVENT_ACTION_CANCEL: motion.action = TouchAction::Cancel; break;
        default: return false;
    }
    motion.action_index = (event.action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK) >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
    motion.device_id = event.deviceId;
    motion.pointer_count = event.pointerCount;
    // MotionEvent.FLAG_CANCELED is part of the Java event ABI since API 33;
    // NDK input.h does not name it. On PointerUp this rejects only that finger.
    // https://developer.android.com/reference/android/view/MotionEvent#FLAG_CANCELED
    motion.canceled = (event.flags & 0x20) != 0;
    // process() rejects malformed counts before indexing its fixed array.
    if (event.pointerCount <= kTouchCapacity && event.pointerCount <= GAMEACTIVITY_MAX_NUM_POINTERS_IN_MOTION_EVENT) {
        for (uint32_t i = 0; i < event.pointerCount; ++i)
            motion.pointers[i] = {event.pointers[i].id, GameActivityPointerAxes_getX(&event.pointers[i]),
                                  GameActivityPointerAxes_getY(&event.pointers[i])};
    } else motion.pointer_count = kTouchCapacity + 1;
    return process(motion);
}
#endif
}
