#pragma once
#include <jni.h>
#include <cstdint>
#include <string>

struct android_app;
struct GameActivityMotionEvent;

namespace dm_android {
void input_activity_attach(android_app* app);
void input_activity_command(android_app* app, int32_t command);
// Actual decor-window fact, delivered on the Java main thread. Rejects retired
// Activities and never reads the native thread's app/window/config pointers.
bool input_activity_window_focus(JNIEnv* env, jobject activity, bool focused);
// Read-only identity checks. Zero means that the caller is no longer bound.
uint64_t input_activity_controller_generation(JNIEnv* env, jobject activity);
uint64_t input_activity_generation(android_app* app);
void input_activity_motion(android_app* app, const GameActivityMotionEvent& event);
// The native input loop owns controller timers. Idle controls permit an
// indefinite poll; held fingers and release pulses request bounded 16ms ticks.
void input_activity_tick(android_app* app);
int input_activity_poll_timeout(android_app* app);
void input_activity_detach(android_app* app);
// Reinstall the static native-window snapshot provider after an owning test's
// temporary provider. Never call while holding binding_mutex.
void input_activity_restore_parameter_provider();
std::string input_activity_receipt(JNIEnv* env, jobject activity, bool read_touch_state);
}

// Optional frontend lifecycle hook used by common host-service teardown.
extern "C" void dm_android_input_reset();
