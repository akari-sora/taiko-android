#include "input_activity.h"
#include "input_platform.h"
#include "touch_controls_platform.h"
#include "host_bridge.hpp"
#include "guest_parameters.h"
#include "oe_platform.h"
#include "controller_platform.h"
#include <game-activity/native_app_glue/android_native_app_glue.h>
#include <android/configuration.h>
#include <android/native_window.h>
#include <android/input.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <time.h>

extern "C" {
#include "../../host/front.h"
}

namespace {
struct Binding {
    android_app* app;
    dm_android::TouchInputProvider provider;
    dm_android::TouchControlsPlatform controls;
    bool controls_visible = false;
    dm_android::TouchViewport viewport{};
    uint32_t native_width = 0, native_height = 0;
    uint64_t generation, revision = 0, activation_ns = 0, controller_fence_ns = 0;
    uint64_t motions = 0, accepted = 0, cancellations = 0;
    bool started = false, stopped = false, focused = false, resumed = false;
    bool decor_focus_known = false;
    bool window_available = false;
    bool controller_ready = false;
    Binding(android_app* value, uint64_t serial) : app(value), generation(serial) {}
};
std::mutex binding_mutex;
std::unique_ptr<Binding> binding;
uint64_t next_generation = 0;
uint64_t monotonic_ns() {
    timespec now{};
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ?
        uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec) : 0;
}

bool native_parameter_basis(uint64_t values[4], void*) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    if (!binding) return false;
    // Only the native Activity thread reads app->window. Other guest threads
    // consume this mutex-protected pixel snapshot, not a potentially retired
    // native-window pointer or the IME's touch-content rectangle.
    return dm_android_calculate_guest_parameters(binding->native_width, binding->native_height, values);
}

void cancel(Binding& current) {
    current.provider.cancel();
    current.controls.cancel();
    ++current.cancellations;
    current.controller_fence_ns = std::max(current.controller_fence_ns, monotonic_ns());
}
void update_viewport(Binding& current) {
    auto* app = current.app;
    // TERM_WINDOW is delivered before native glue clears app->window. Once
    // retired, no later focus/config command may resurrect that old pointer.
    const int32_t width = current.window_available && app->window ? ANativeWindow_getWidth(app->window) : 0;
    const int32_t height = current.window_available && app->window ? ANativeWindow_getHeight(app->window) : 0;
    current.native_width = width > 0 ? static_cast<uint32_t>(width) : 0;
    current.native_height = height > 0 ? static_cast<uint32_t>(height) : 0;
    const int32_t density = app->config ? AConfiguration_getDensity(app->config) : 0;
    // The native window is the current content until a renderer supplies its
    // actual game viewport. Intersect the real content rect with that window.
    int left = 0, top = 0, right = width, bottom = height;
    if (app->contentRect.right > app->contentRect.left && app->contentRect.bottom > app->contentRect.top) {
        left = std::clamp(app->contentRect.left, 0, std::max(width, 0));
        top = std::clamp(app->contentRect.top, 0, std::max(height, 0));
        right = std::clamp(app->contentRect.right, left, std::max(width, 0));
        bottom = std::clamp(app->contentRect.bottom, top, std::max(height, 0));
    }
    current.viewport = {static_cast<float>(left), static_cast<float>(top),
        static_cast<float>(right - left), static_cast<float>(bottom - top),
        density > 0 && density < 0xfffe ? static_cast<float>(density) / 160.0f : 0.0f};
    current.provider.set_viewport(current.viewport);
    current.provider.set_enabled(current.focused && current.resumed && current.window_available);
    current.controls.set_viewport(current.viewport);
    current.controls.set_enabled(current.controls_visible && current.focused && current.resumed && current.window_available);
}

struct InputPublication {
    dm_android::OePlatformSnapshot oe;
    uint64_t controller_fence_ns;
    bool controller_ready;
};
InputPublication platform_snapshot(Binding& current, bool attached = true) {
    dm_android::OePlatformSnapshot value{};
    value.generation = current.generation;
    value.revision = ++current.revision;
    value.activation_ns = current.activation_ns;
    value.native_width = current.native_width; value.native_height = current.native_height;
    value.attached = attached; value.started = current.started; value.stopped = current.stopped;
    value.resumed = current.resumed; value.focused = current.focused;
    value.window_available = current.window_available;
    const bool ready = attached && current.resumed && current.focused && current.window_available;
    // A resumed focused Activity can lose/recreate its window without changing
    // OE focus. Fence both that re-enable and ordinary lifecycle cancellation.
    if (!current.controller_fence_ns || (!current.controller_ready && ready))
        current.controller_fence_ns = std::max(current.controller_fence_ns, monotonic_ns());
    current.controller_ready = ready;
    return {value, current.controller_fence_ns, ready};
}
void publish(const InputPublication& value) {
    // Neither downstream channel nor producer/gameplay consumers may execute
    // under binding_mutex. Both copies retain the same generation/revision.
    dm_android::oe_platform_publish(value.oe);
    dm_android::controller_platform_activity(value.oe.generation, value.oe.revision,
        value.controller_ready, value.controller_fence_ns);
}

int binding_focus(const Binding& current) {
    return current.stopped ? 3 : current.resumed && current.focused ? 1 : 2;
}
template<class T> T field(const uint8_t* bytes, size_t offset) {
    T value{}; std::memcpy(&value, bytes + offset, sizeof value); return value;
}
}

namespace dm_android {
void input_activity_restore_parameter_provider() {
    dm_android_set_parameter_provider(native_parameter_basis, nullptr);
}
void input_activity_attach(android_app* app) {
    // Provider callback locks binding_mutex, so registration occurs outside it.
    // The callback/context are static and remain valid after an Activity ends.
    input_activity_restore_parameter_provider();
    InputPublication snapshot;
    {
        std::lock_guard<std::mutex> lock(binding_mutex);
        if (binding) cancel(*binding);
        binding = std::make_unique<Binding>(app, ++next_generation);
        binding->window_available = app->window != nullptr;
        // Activity lifetime does not establish guest quiescence. Preserve the
        // HID sampling/time sequence across handover; only cancel contacts.
        dm_touch_cancel();
        update_viewport(*binding);
        snapshot = platform_snapshot(*binding);
    }
    publish(snapshot);
}
void input_activity_command(android_app* app, int32_t command) {
    InputPublication snapshot;
    {
        std::lock_guard<std::mutex> lock(binding_mutex);
        if (!binding || binding->app != app) return;
        auto& current = *binding;
        const int previous_focus = binding_focus(current);
        switch (command) {
        case APP_CMD_START: current.started = true; current.stopped = false; break;
        // Once the actual decor observer has published, queued GameActivity
        // focus commands may be stale and cannot override that newer OS fact.
        case APP_CMD_GAINED_FOCUS:
            if (!current.decor_focus_known) current.focused = true;
            break;
        case APP_CMD_RESUME: current.resumed = true; break;
        case APP_CMD_LOST_FOCUS:
            if (!current.decor_focus_known) { current.focused = false; cancel(current); }
            break;
        case APP_CMD_PAUSE: current.resumed = false; cancel(current); break;
        case APP_CMD_STOP:
            current.started = false; current.stopped = true;
            current.resumed = false; cancel(current); break;
        case APP_CMD_INIT_WINDOW: current.window_available = app->window != nullptr; break;
        case APP_CMD_TERM_WINDOW: case APP_CMD_DESTROY:
            current.window_available = false; cancel(current); break;
        default: break;
        }
        if (previous_focus != 1 && binding_focus(current) == 1) {
            timespec now{};
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
                current.activation_ns = uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec);
        }
        update_viewport(current);
        snapshot = platform_snapshot(current);
    }
    publish(snapshot);
}
bool input_activity_window_focus(JNIEnv* env, jobject activity, bool focused) {
    InputPublication snapshot;
    {
        std::lock_guard<std::mutex> lock(binding_mutex);
        if (!binding || !env->IsSameObject(activity, binding->app->activity->javaGameActivity))
            return false;
        auto& current = *binding;
        const int previous_focus = binding_focus(current);
        current.decor_focus_known = true;
        current.focused = focused;
        if (!focused) cancel(current);
        if (previous_focus != 1 && binding_focus(current) == 1) {
            timespec now{};
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
                current.activation_ns = uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec);
        }
        // This callback runs on the Java main thread. Only use cached geometry;
        // update_viewport() dereferences native-window/config pointers owned by
        // the native Activity thread and must not run here.
        current.provider.set_enabled(current.focused && current.resumed && current.window_available);
        current.controls.set_enabled(current.controls_visible && current.focused && current.resumed && current.window_available);
        snapshot = platform_snapshot(current);
    }
    publish(snapshot);
    return true;
}
uint64_t input_activity_controller_generation(JNIEnv* env, jobject activity) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    return binding && env->IsSameObject(activity, binding->app->activity->javaGameActivity) ?
        binding->generation : 0;
}
uint64_t input_activity_generation(android_app* app) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    return binding && binding->app == app ? binding->generation : 0;
}
void input_activity_motion(android_app* app, const GameActivityMotionEvent& event) {
    bool touched = false;
    {
        std::lock_guard<std::mutex> lock(binding_mutex);
        if (!binding || binding->app != app) return;
        ++binding->motions;
        const auto before = binding->provider.snapshot();
        if (binding->provider.process_game_activity(event)) {
            binding->controls.consume_game_activity(event, before, binding->provider.snapshot());
            ++binding->accepted;
            const int action = event.action & AMOTION_EVENT_ACTION_MASK;
            touched = (event.source & AINPUT_SOURCE_TOUCHSCREEN) == AINPUT_SOURCE_TOUCHSCREEN &&
                (action == AMOTION_EVENT_ACTION_DOWN || action == AMOTION_EVENT_ACTION_POINTER_DOWN);
        } else if (before.count && !binding->provider.snapshot().count) binding->controls.cancel();
    }
    if (touched) dm_gamepad_touched();
}
void input_activity_tick(android_app* app) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    if (binding && binding->app == app) binding->controls.tick(monotonic_ns()/1e9);
}
int input_activity_poll_timeout(android_app* app) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    return binding && binding->app == app ? binding->controls.poll_timeout_ms() : -1;
}
bool input_activity_touch_controls_visible(JNIEnv* env, jobject activity, bool visible) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    if (!binding || !env->IsSameObject(activity, binding->app->activity->javaGameActivity)) return false;
    auto& current=*binding;
    if (current.controls_visible != visible) {
        current.controls_visible=visible;
        current.controls.set_enabled(visible && current.focused && current.resumed && current.window_available);
        if (current.app->looper) ALooper_wake(current.app->looper);
    }
    return true;
}
bool input_activity_touch_controls_snapshot(JNIEnv* env, jobject activity, TouchControlsSnapshot* output) {
    std::lock_guard<std::mutex> lock(binding_mutex);
    if (!output || !binding || !env->IsSameObject(activity, binding->app->activity->javaGameActivity)) return false;
    *output=binding->controls.snapshot();
    return true;
}
void input_activity_detach(android_app* app) {
    InputPublication snapshot;
    {
        std::lock_guard<std::mutex> lock(binding_mutex);
        if (!binding || binding->app != app) return;
        cancel(*binding);
        binding->window_available = false;
        binding->native_width = binding->native_height = 0;
        snapshot = platform_snapshot(*binding, false);
        binding.reset();
    }
    publish(snapshot);
}
std::string input_activity_receipt(JNIEnv* env, jobject activity, bool read_touch_state) {
    struct Receipt {
        uint64_t generation, revision, motions, accepted, cancellations;
        uint32_t native_width, native_height;
        bool started, stopped, resumed, focused, window_available;
        int focus;
        TouchViewport viewport;
        TouchSnapshot sample;
    } current{};
    // Resolve the export before taking binding_mutex: registry setup allocates.
    // The final owner check, bounded metadata copy and real touch sample then
    // share one binding scope, so an old Activity cannot consume its successor's
    // global touch state between metadata capture and the HLE read.
    HostRegistry registry;
    std::string error;
    uintptr_t function = 0;
    constexpr const char* name = "_ZN2nn3hid20GetTouchScreenStatesILm16EEEiPNS0_16TouchScreenStateIXT_EEEi";
    const bool resolved = registry.initialize(&error) && registry.resolve(name, true, &function);
    alignas(8) uint8_t state[0x290]{};
    int written = 0;
    bool available = false;
    {
        std::lock_guard<std::mutex> lock(binding_mutex);
        available = binding && env->IsSameObject(activity, binding->app->activity->javaGameActivity);
        if (available) {
            const auto& value = *binding;
            current = {value.generation, value.revision, value.motions, value.accepted,
                value.cancellations, value.native_width, value.native_height,
                value.started, value.stopped, value.resumed, value.focused, value.window_available,
                binding_focus(value), value.viewport, value.provider.snapshot()};
            // This exact shared export only calls guest_ns() and touch_fill().
            // Neither path acquires runtime_lifecycle or calls guest code.
            if (resolved && read_touch_state)
                written = reinterpret_cast<int (*)(void*, int)>(function)(state, 1);
        }
    }
    if (!available) return "{\"available\":false,\"gamePlayable\":false}";
    const auto& sample = current.sample;
    const int count = field<int32_t>(state, 8);
    std::ostringstream out;
    out << "{\"available\":true,\"gamePlayable\":false,\"generation\":" << current.generation
        << ",\"motions\":" << current.motions << ",\"accepted\":" << current.accepted
        << ",\"cancellations\":" << current.cancellations << ",\"focused\":" << (current.focused ? "true" : "false")
        << ",\"resumed\":" << (current.resumed ? "true" : "false")
        << ",\"started\":" << (current.started ? "true" : "false")
        << ",\"stopped\":" << (current.stopped ? "true" : "false")
        << ",\"windowAvailable\":" << (current.window_available ? "true" : "false")
        << ",\"revision\":" << current.revision << ",\"oeFocus\":" << current.focus
        << ",\"nativeWidth\":" << current.native_width << ",\"nativeHeight\":" << current.native_height
        << ",\"viewport\":{\"left\":" << current.viewport.left_px << ",\"top\":" << current.viewport.top_px
        << ",\"width\":" << current.viewport.width_px << ",\"height\":" << current.viewport.height_px
        << ",\"density\":" << current.viewport.density << "},\"activePointers\":" << sample.count
        << ",\"logicalWidth\":" << sample.logical_width << ",\"logicalHeight\":" << sample.logical_height
        << ",\"hleResolved\":" << (resolved ? "true" : "false")
        << ",\"sampled\":" << (read_touch_state ? "true" : "false") << ",\"statesWritten\":" << written
        << ",\"sampling\":" << field<int64_t>(state, 0) << ",\"touches\":[";
    for (int i = 0; i < std::clamp(count, 0, 16); ++i) {
        const auto* touch = state + 0x10 + i * 0x28;
        if (i) out << ',';
        out << "{\"id\":" << field<int32_t>(touch, 12) << ",\"attributes\":" << field<uint32_t>(touch, 8)
            << ",\"x\":" << field<int32_t>(touch, 16) << ",\"y\":" << field<int32_t>(touch, 20) << '}';
    }
    out << "]}";
    return out.str();
}
}
extern "C" void dm_android_input_reset() {
    std::lock_guard<std::mutex> lock(binding_mutex);
    if (binding) { binding->provider.reset(); binding->controls.cancel(); ++binding->cancellations; }
    else dm_touch_reset();
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_nativeWindowFocusChanged(JNIEnv* env, jobject activity, jboolean focused) {
    return dm_android::input_activity_window_focus(env, activity, focused == JNI_TRUE) ? JNI_TRUE : JNI_FALSE;
}
