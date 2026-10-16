#pragma once
#include "../../host/dm_gamepad_core.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

struct android_app;
struct GameActivityKeyEvent;
struct GameActivityMotionEvent;

namespace dm_android {
// Android input constants are kept in the implementation. These copies contain
// no Java references or pointers into GameActivity's reusable input buffers.
struct ControllerRange {
    int32_t axis = 0, source = 0;
    float minimum = 0, maximum = 0, flat = 0, fuzz = 0;
};
struct ControllerDevice {
    int32_t id = 0, sources = 0, vendor = 0, product = 0;
    uint64_t notification = 0, fence_ns = 0;
    std::string name, descriptor;
    std::vector<ControllerRange> ranges;
    bool diagnostic_virtual = false;
};
struct ControllerEvent {
    enum class Kind { Key, Motion, Cancel } kind = Kind::Key;
    int32_t device = 0, source = 0, key = 0;
    uint64_t time_ns = 0;
    bool down = false;
    std::array<float, 48> axes{};
};

class ControllerCollector {
public:
    void activity(uint64_t generation, uint64_t revision, bool ready, uint64_t fence_ns);
    bool device(uint64_t generation, ControllerDevice metadata);
    bool remove(uint64_t generation, int32_t device, uint64_t notification, uint64_t fence_ns,
        bool require_virtual = false);
    void cancel(uint64_t generation, uint64_t fence_ns);
    // Events use CLOCK_MONOTONIC nanoseconds, including KeyEvent's converted
    // milliseconds and GameActivity motion history. Equal-time device updates
    // are committed together, then one union state is published.
    void consume(uint64_t generation, std::vector<ControllerEvent> events);
    std::string receipt() const;
private:
    struct Device {
        ControllerDevice metadata;
        dm_gamepad_source source{};
        uint64_t digital = 0, analog = 0, last_ns = 0;
        int32_t axes[4]{};
        int kind = 0;
    };
    struct Publication { dm_gamepad_source source; uint64_t buttons; std::array<int32_t, 4> axes; };
    void register_sources();
    void drain();
    mutable std::mutex mutex_;
    std::map<int32_t, Device> devices_;
    std::map<int32_t, uint64_t> notifications_;
    std::deque<Publication> pending_;
    uint64_t generation_ = 0, revision_ = 0, fence_ns_ = 0;
    uint64_t events_ = 0, accepted_ = 0, stale_ = 0, publications_ = 0, overflows_ = 0;
    bool ready_ = false, draining_ = false;
};

ControllerCollector& controller_platform();
void controller_platform_activity(uint64_t generation, uint64_t revision, bool ready, uint64_t fence_ns);
// Enable axes once before GameActivity can deliver events (call the Kotlin
// configureAxes() before super.onCreate). configure_game_activity installs only
// filters and is called when android_main receives its app.
void controller_platform_configure_axes();
void controller_platform_configure_game_activity(android_app* app);
void controller_platform_consume(uint64_t generation, const GameActivityKeyEvent* keys,
    size_t key_count, const GameActivityMotionEvent* motions, size_t motion_count);
}
