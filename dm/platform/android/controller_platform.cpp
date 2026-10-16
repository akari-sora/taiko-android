#include "controller_platform.h"
extern "C" {
#include "../../host/dm_padmap.h"
}
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <sstream>
#include <time.h>
#include <utility>
#if defined(__ANDROID__)
#include "input_activity.h"
#include "diagnostic_session.h"
#include <android/input.h>
#include <game-activity/GameActivityEvents.h>
#include <game-activity/native_app_glue/android_native_app_glue.h>
#include <jni.h>
#endif

namespace dm_android {
namespace {
// Stable public Android constants; static_asserts below check the pinned NDK.
constexpr int kGamepad = 0x401, kJoystick = 0x1000010, kDpad = 0x201;
constexpr int kX = 0, kY = 1, kZ = 11, kRx = 12, kRy = 13, kRz = 14;
constexpr int kHatX = 15, kHatY = 16, kLt = 17, kRt = 18, kGas = 22, kBrake = 23;
std::atomic<uint64_t> next_identity{0x414e440000000000ULL};
bool has_source(int value, int source) { return (value & source) == source; }
bool controller_source(int source) {
    return has_source(source, kGamepad) || has_source(source, kJoystick) || has_source(source, kDpad);
}
bool eligible(const ControllerDevice& d) {
    return has_source(d.sources, kGamepad) || has_source(d.sources, kJoystick);
}
bool valid(const ControllerRange& r) {
    return r.axis >= 0 && r.axis < 48 && std::isfinite(r.minimum) && std::isfinite(r.maximum) &&
        std::isfinite(r.flat) && std::isfinite(r.fuzz) && std::isfinite(r.maximum - r.minimum) &&
        r.maximum > r.minimum && r.flat >= 0 && r.fuzz >= 0;
}
const ControllerRange* range(const ControllerDevice& d, int axis, int source) {
    for (const auto& r : d.ranges) if (r.axis == axis && r.source == source && valid(r)) return &r;
    return nullptr;
}
float axis(const ControllerDevice& d, const ControllerEvent& e, int a, bool trigger = false) {
    const auto* r = range(d, a, e.source);
    const float value = e.axes[a];
    if (!r || !std::isfinite(value)) return 0;
    const float v = std::clamp(value, r->minimum, r->maximum);
    if (trigger) return std::clamp((v - r->minimum) / (r->maximum - r->minimum), 0.0f, 1.0f);
    const float center = r->minimum <= 0 && r->maximum >= 0 ? 0 : r->minimum + (r->maximum - r->minimum) * .5f;
    const float delta = v - center;
    if (std::abs(delta) <= r->flat) return 0;
    const float extent = delta > 0 ? r->maximum - center : center - r->minimum;
    return extent > 0 ? std::clamp(delta / extent, -1.0f, 1.0f) : 0;
}
int32_t stick(float v) { return static_cast<int32_t>(std::lround(v * DM_STICK_MAX)); }
uint64_t key_button(int key, int kind) {
    switch (key) {
    // Android A/B/X/Y are south/east/west/north. Apply the existing letter
    // policy exactly once; AOSP already normalized vendor key layouts.
    case 96: return dm_padmap_face(kind, 1, 0, 0, 0);
    case 97: return dm_padmap_face(kind, 0, 1, 0, 0);
    case 99: return dm_padmap_face(kind, 0, 0, 1, 0);
    case 100: return dm_padmap_face(kind, 0, 0, 0, 1);
    case 102: return DM_BTN_L; case 103: return DM_BTN_R;
    case 104: return DM_BTN_ZL; case 105: return DM_BTN_ZR;
    case 106: return DM_BTN_LS; case 107: return DM_BTN_RS;
    case 108: return DM_BTN_PLUS; case 109: return DM_BTN_MINUS;
    case 19: return DM_BTN_UP; case 20: return DM_BTN_DOWN;
    case 21: return DM_BTN_LEFT; case 22: return DM_BTN_RIGHT;
    default: return 0;
    }
}
void motion_state(const ControllerDevice& d, const ControllerEvent& e, uint64_t& buttons, int32_t out[4]) {
    out[0] = out[1] = out[2] = out[3] = 0;
    if (range(d, kX, e.source) && range(d, kY, e.source)) {
        out[0] = stick(axis(d, e, kX)); out[1] = stick(-axis(d, e, kY));
    }
    // RX/RY is an explicit compatibility fallback only when the complete
    // canonical pair is unavailable. It remains subject to physical testing.
    const int rx = range(d, kZ, e.source) && range(d, kRz, e.source) ? kZ : kRx;
    const int ry = rx == kZ ? kRz : kRy;
    if (range(d, rx, e.source) && range(d, ry, e.source)) {
        out[2] = stick(axis(d, e, rx)); out[3] = stick(-axis(d, e, ry));
    }
    const int lt = range(d, kLt, e.source) ? kLt : kBrake;
    const int rt = range(d, kRt, e.source) ? kRt : kGas;
    buttons = (axis(d, e, lt, true) > .5f ? DM_BTN_ZL : 0) |
        (axis(d, e, rt, true) > .5f ? DM_BTN_ZR : 0);
    const float hx = axis(d, e, kHatX), hy = axis(d, e, kHatY);
    if (hx < -.5f) buttons |= DM_BTN_LEFT;
    if (hx > .5f) buttons |= DM_BTN_RIGHT;
    if (hy < -.5f) buttons |= DM_BTN_UP;
    if (hy > .5f) buttons |= DM_BTN_DOWN;
}
}

void ControllerCollector::register_sources() {
    struct Request { int32_t id; uint64_t notification, epoch; };
    std::vector<Request> requests;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_) return;
        for (const auto& [id, d] : devices_) if (!d.source.generation)
            requests.push_back({id, d.metadata.notification, generation_});
    }
    for (const auto& r : requests) {
        auto source = dm_gamepad_source_register(++next_identity, r.epoch);
        bool keep = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto i = devices_.find(r.id);
            if (ready_ && generation_ == r.epoch && i != devices_.end() &&
                i->second.metadata.notification == r.notification && !i->second.source.generation) {
                i->second.source = source; keep = true;
            }
        }
        if (!keep && source.generation) dm_gamepad_source_remove(source);
    }
}
void ControllerCollector::activity(uint64_t generation, uint64_t revision, bool ready, uint64_t fence_ns) {
    std::vector<dm_gamepad_source> retired;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!generation || generation < generation_ || (generation == generation_ && revision <= revision_)) return;
        const bool replacement = generation != generation_;
        if (replacement || !ready || (!ready_ && ready)) {
            for (auto& [id, d] : devices_) {
                (void)id;
                if (d.source.generation) retired.push_back(d.source);
                d.source = {}; d.digital = d.analog = 0;
                std::fill(std::begin(d.axes), std::end(d.axes), 0);
                d.last_ns = std::max(d.last_ns, fence_ns);
            }
            pending_.clear();
        }
        if (replacement) { devices_.clear(); notifications_.clear(); }
        generation_ = generation; revision_ = revision; ready_ = ready;
        fence_ns_ = std::max(replacement ? uint64_t(0) : fence_ns_, fence_ns);
    }
    // Removal invalidates the old producer generation synchronously. A queued
    // or concurrent publication with that handle cannot revive pending edges.
    for (auto source : retired) dm_gamepad_source_remove(source);
    register_sources();
}
bool ControllerCollector::device(uint64_t generation, ControllerDevice metadata) {
    dm_gamepad_source retired{};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!generation || generation != generation_ || !eligible(metadata) ||
            metadata.ranges.size() > 96 || metadata.notification <= notifications_[metadata.id]) return false;
        const auto previous = devices_.find(metadata.id);
        if (metadata.diagnostic_virtual && previous != devices_.end() && !previous->second.metadata.diagnostic_virtual) return false;
        if (devices_.size() >= 32 && devices_.find(metadata.id) == devices_.end()) return false;
        for (const auto& r : metadata.ranges) if (!valid(r)) return false;
        notifications_[metadata.id] = metadata.notification;
        auto& d = devices_[metadata.id]; retired = d.source;
        d = {}; d.kind = metadata.vendor == 0x057e ? DM_PADKIND_NINTENDO : dm_padmap_kind(metadata.name.c_str(), "");
        d.last_ns = std::max(metadata.fence_ns, fence_ns_);
        d.metadata = std::move(metadata);
    }
    if (retired.generation) dm_gamepad_source_remove(retired);
    register_sources(); return true;
}
bool ControllerCollector::remove(uint64_t generation, int32_t id, uint64_t notification, uint64_t fence_ns, bool require_virtual) {
    dm_gamepad_source retired{};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!generation || generation != generation_ || notification <= notifications_[id]) return false;
        auto i = devices_.find(id);
        if (require_virtual && (i == devices_.end() || !i->second.metadata.diagnostic_virtual)) return false;
        notifications_[id] = notification;
        if (i != devices_.end()) { retired = i->second.source; devices_.erase(i); }
        (void)fence_ns; // Tombstone sequence fences delayed metadata; a new add supplies its time fence.
    }
    if (retired.generation) dm_gamepad_source_remove(retired);
    return true;
}
void ControllerCollector::cancel(uint64_t generation, uint64_t fence_ns) {
    std::vector<dm_gamepad_source> retired;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation != generation_) return;
        fence_ns_ = std::max(fence_ns_, fence_ns);
        for (auto& [id, d] : devices_) {
            (void)id;
            if (d.source.generation) retired.push_back(d.source);
            d.source = {}; d.digital = d.analog = 0;
            std::fill(std::begin(d.axes), std::end(d.axes), 0);
        }
        pending_.clear();
    }
    for (auto source : retired) dm_gamepad_source_remove(source);
    register_sources();
}
void ControllerCollector::drain() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (draining_) return;
        draining_ = true;
    }
    for (;;) {
        Publication p{};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (pending_.empty()) { draining_ = false; return; }
            p = pending_.front(); pending_.pop_front();
        }
        dm_gamepad_source_update(p.source, p.buttons, p.axes.data());
    }
}
void ControllerCollector::consume(uint64_t generation, std::vector<ControllerEvent> events) {
    if (events.size() > 8192) {
        uint64_t fence = 0;
        for (const auto& e : events) fence = std::max(fence, e.time_ns);
        cancel(generation, fence); return;
    }
    // Stable sort retains chronological order within each original stream.
    std::stable_sort(events.begin(), events.end(), [](const auto& a, const auto& b) {
        return a.time_ns != b.time_ns ? a.time_ns < b.time_ns : a.device < b.device;
    });
    std::vector<dm_gamepad_source> retired;
    const auto capability = dm_gamepad_core_capability();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_ += events.size();
        if (!ready_ || generation != generation_) { stale_ += events.size(); return; }
        if (pending_.size() + events.size() > 8192) {
            ++overflows_; stale_ += events.size();
            for (const auto& e : events) fence_ns_ = std::max(fence_ns_, e.time_ns);
            for (auto& [id, d] : devices_) {
                (void)id;
                if (d.source.generation) retired.push_back(d.source);
                d.source = {}; d.digital = d.analog = 0;
                std::fill(std::begin(d.axes), std::end(d.axes), 0);
            }
            pending_.clear(); events.clear();
        }
        for (size_t begin = 0; begin < events.size();) {
            size_t end = begin + 1;
            while (end < events.size() && events[end].device == events[begin].device && events[end].time_ns == events[begin].time_ns) ++end;
            auto i = devices_.find(events[begin].device);
            if (i == devices_.end() || !i->second.source.generation ||
                (i->second.metadata.diagnostic_virtual && capability != DM_GAMEPAD_DIAGNOSTIC_RAW) || !events[begin].time_ns ||
                events[begin].time_ns <= std::max(fence_ns_, i->second.metadata.fence_ns) ||
                events[begin].time_ns < i->second.last_ns) { stale_ += end - begin; begin = end; continue; }
            auto& d = i->second;
            bool changed = false, cancel = false;
            for (size_t n = begin; n < end; ++n) {
                const auto& e = events[n];
                if (!controller_source(e.source) || !has_source(d.metadata.sources, e.source)) continue;
                if (e.kind == ControllerEvent::Kind::Cancel) { cancel = true; break; }
                if (e.kind == ControllerEvent::Kind::Key) {
                    const uint64_t bit = key_button(e.key, d.kind);
                    if (!bit) continue;
                    if (e.down) d.digital |= bit; else d.digital &= ~bit;
                } else motion_state(d.metadata, e, d.analog, d.axes);
                changed = true; ++accepted_;
            }
            if (cancel) {
                retired.push_back(d.source); d.source = {}; d.digital = d.analog = 0;
                d.metadata.fence_ns = std::max(d.metadata.fence_ns, events[begin].time_ns);
                std::fill(std::begin(d.axes), std::end(d.axes), 0);
            } else if (changed) {
                pending_.push_back({d.source, d.digital | d.analog, {d.axes[0], d.axes[1], d.axes[2], d.axes[3]}});
                ++publications_;
            }
            d.last_ns = events[begin].time_ns;
            begin = end;
        }
    }
    for (auto source : retired) dm_gamepad_source_remove(source);
    register_sources(); drain();
}
std::string ControllerCollector::receipt() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t virtual_count = 0, registered = 0;
    for (const auto& [id, d] : devices_) { (void)id; virtual_count += d.metadata.diagnostic_virtual; registered += d.source.generation != 0; }
    std::ostringstream s;
    s << "{\"activityGeneration\":" << generation_ << ",\"activityRevision\":" << revision_
      << ",\"ready\":" << (ready_ ? "true" : "false") << ",\"metadataDevices\":" << devices_.size()
      << ",\"registeredSources\":" << registered << ",\"diagnosticVirtualDevices\":" << virtual_count
      << ",\"events\":" << events_ << ",\"accepted\":" << accepted_ << ",\"stale\":" << stale_
      << ",\"publications\":" << publications_ << ",\"overflows\":" << overflows_ << ",\"devices\":[";
    bool first = true;
    for (const auto& [id, d] : devices_) {
        if (!first) s << ',';
        first = false;
        s << "{\"id\":" << id << ",\"sourceGeneration\":" << d.source.generation
          << ",\"vendor\":" << d.metadata.vendor << ",\"product\":" << d.metadata.product
          << ",\"diagnosticVirtual\":" << (d.metadata.diagnostic_virtual ? "true" : "false")
          << ",\"lastEventNs\":" << d.last_ns << '}';
    }
    s << "]}";
    return s.str();
}
ControllerCollector& controller_platform() { static ControllerCollector collector; return collector; }
void controller_platform_activity(uint64_t generation, uint64_t revision, bool ready, uint64_t fence_ns) {
    controller_platform().activity(generation, revision, ready, fence_ns);
}

#if defined(__ANDROID__)
static_assert(kGamepad == AINPUT_SOURCE_GAMEPAD && kJoystick == AINPUT_SOURCE_JOYSTICK && kDpad == AINPUT_SOURCE_DPAD);
static_assert(kX == AMOTION_EVENT_AXIS_X && kY == AMOTION_EVENT_AXIS_Y && kZ == AMOTION_EVENT_AXIS_Z && kRz == AMOTION_EVENT_AXIS_RZ);
static_assert(kRx == AMOTION_EVENT_AXIS_RX && kRy == AMOTION_EVENT_AXIS_RY && kHatX == AMOTION_EVENT_AXIS_HAT_X && kHatY == AMOTION_EVENT_AXIS_HAT_Y);
static_assert(kLt == AMOTION_EVENT_AXIS_LTRIGGER && kRt == AMOTION_EVENT_AXIS_RTRIGGER && kGas == AMOTION_EVENT_AXIS_GAS && kBrake == AMOTION_EVENT_AXIS_BRAKE);
void controller_platform_configure_axes() {
    static std::once_flag once;
    std::call_once(once, [] {
        const dm_gamepad_ops diagnostic{DM_GAMEPAD_DIAGNOSTIC_RAW, nullptr, nullptr, nullptr, nullptr, nullptr};
        if (!dm_gamepad_core_configure(&diagnostic)) std::abort();
        for (const int a : {kX, kY, kZ, kRz, kRx, kRy, kHatX, kHatY, kLt, kRt, kGas, kBrake})
            GameActivityPointerAxes_enableAxis(a);
    });
}
void controller_platform_configure_game_activity(android_app* app) {
    android_app_set_motion_event_filter(app, [](const GameActivityMotionEvent* e) {
        return e && (has_source(e->source, AINPUT_SOURCE_TOUCHSCREEN) || controller_source(e->source));
    });
    android_app_set_key_event_filter(app, [](const GameActivityKeyEvent* e) {
        if (!e) return false;
        switch (e->keyCode) {
        case AKEYCODE_VOLUME_UP: case AKEYCODE_VOLUME_DOWN: case AKEYCODE_VOLUME_MUTE:
        case AKEYCODE_CAMERA: case AKEYCODE_ZOOM_IN: case AKEYCODE_ZOOM_OUT: return false;
        default: return true;
        }
    });
}
void controller_platform_consume(uint64_t generation, const GameActivityKeyEvent* keys, size_t key_count,
    const GameActivityMotionEvent* motions, size_t motion_count) {
    std::vector<ControllerEvent> events;
    bool overflow = key_count > 4096 || motion_count > 4096;
    for (size_t n = 0; keys && n < std::min(key_count, size_t(4096)); ++n) {
        const auto& k = keys[n];
        if (!controller_source(k.source) || k.eventTime <= 0 ||
            (k.action != AKEY_EVENT_ACTION_DOWN && k.action != AKEY_EVENT_ACTION_UP)) continue;
        ControllerEvent e{}; e.device = k.deviceId; e.source = k.source; e.time_ns = k.eventTime;
        if (k.flags & AKEY_EVENT_FLAG_CANCELED) e.kind = ControllerEvent::Kind::Cancel;
        e.key = k.keyCode; e.down = k.action == AKEY_EVENT_ACTION_DOWN; events.push_back(e);
    }
    for (size_t n = 0; motions && n < std::min(motion_count, size_t(4096)); ++n) {
        const auto& m = motions[n];
        if (!controller_source(m.source) || !m.pointerCount || m.pointerCount > GAMEACTIVITY_MAX_NUM_POINTERS_IN_MOTION_EVENT) continue;
        const int action = m.action & AMOTION_EVENT_ACTION_MASK;
        if (action != AMOTION_EVENT_ACTION_MOVE && action != AMOTION_EVENT_ACTION_CANCEL) continue;
        const auto append = [&](int history, int64_t time) {
            if (time <= 0) return;
            if (events.size() >= 8192) { overflow = true; return; }
            ControllerEvent e{}; e.kind = action == AMOTION_EVENT_ACTION_CANCEL ? ControllerEvent::Kind::Cancel : ControllerEvent::Kind::Motion;
            e.device = m.deviceId; e.source = m.source; e.time_ns = time;
            for (int a : {kX, kY, kZ, kRz, kRx, kRy, kHatX, kHatY, kLt, kRt, kGas, kBrake})
                e.axes[a] = history < 0 ? GameActivityPointerAxes_getAxisValue(&m.pointers[0], a) :
                    GameActivityMotionEvent_getHistoricalAxisValue(&m, a, 0, history);
            events.push_back(e);
        };
        if (m.historySize > 4096) overflow = true;
        if (m.historySize > 0 && m.historySize <= 4096 && m.historicalAxisValues) {
            for (int h = 0; h < m.historySize; ++h) {
                const int64_t ms = m.historicalEventTimesMillis ? m.historicalEventTimesMillis[h] : 0;
                const int64_t ns = m.historicalEventTimesNanos ? m.historicalEventTimesNanos[h] :
                    ms > 0 && ms <= INT64_MAX / 1000000LL ? ms * 1000000LL : 0;
                append(h, ns);
            }
        }
        // Pinned 4.4.2 Java passes MotionEvent.getEventTime() unchanged (ms),
        // whereas KeyEvent_fromJava and historicalEventTimesNanos are ns.
        append(-1, m.eventTime > 0 && m.eventTime <= INT64_MAX / 1000000LL ? m.eventTime * 1000000LL : 0);
    }
    if (overflow) {
        timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        controller_platform().cancel(generation, uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec));
        return;
    }
    controller_platform().consume(generation, std::move(events));
}
#endif
}

#if defined(__ANDROID__)
namespace dm_android {
// Root supplies the existing binding's live Java identity check. This function
// only takes the short binding mutex and never calls collector/producer code.
uint64_t input_activity_controller_generation(JNIEnv*, jobject);
}
namespace {
std::string owned_string(JNIEnv* env, jstring value) {
    if (!value || env->GetStringUTFLength(value) > 4096) return {};
    const char* bytes = env->GetStringUTFChars(value, nullptr);
    if (!bytes) return {};
    std::string result(bytes); env->ReleaseStringUTFChars(value, bytes); return result;
}
std::atomic<uint64_t> virtual_notification{uint64_t(1) << 62};
uint64_t monotonic_ns() {
    timespec time{};
    if (clock_gettime(CLOCK_MONOTONIC, &time)) return 0;
    return uint64_t(time.tv_sec) * 1000000000ULL + uint64_t(time.tv_nsec);
}
}
extern "C" JNIEXPORT void JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_configureAxesOnce(JNIEnv*, jclass) {
    dm_android::controller_platform_configure_axes();
}
extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_nativeGeneration(JNIEnv* env, jclass, jobject activity) {
    return static_cast<jlong>(dm_android::input_activity_controller_generation(env, activity));
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_nativeDevice(JNIEnv* env, jclass, jobject activity,
    jint id, jint sources, jint vendor, jint product, jstring name, jstring descriptor,
    jlong notification, jlong fence, jintArray axes, jintArray range_sources, jfloatArray calibration) {
    const auto generation = dm_android::input_activity_controller_generation(env, activity);
    if (!generation || notification <= 0 || fence <= 0 || !axes || !range_sources || !calibration) return JNI_FALSE;
    const jsize size = env->GetArrayLength(axes);
    if (size > 96 || env->GetArrayLength(range_sources) != size || env->GetArrayLength(calibration) != size * 4) return JNI_FALSE;
    std::vector<jint> owned_axes(size), owned_sources(size);
    std::vector<jfloat> owned_calibration(size * 4);
    env->GetIntArrayRegion(axes, 0, size, owned_axes.data());
    env->GetIntArrayRegion(range_sources, 0, size, owned_sources.data());
    env->GetFloatArrayRegion(calibration, 0, size * 4, owned_calibration.data());
    if (env->ExceptionCheck()) return JNI_FALSE;
    dm_android::ControllerDevice d{};
    d.id = id; d.sources = sources; d.vendor = vendor; d.product = product;
    d.notification = notification; d.fence_ns = fence;
    d.name = owned_string(env, name); d.descriptor = owned_string(env, descriptor);
    if (env->ExceptionCheck()) return JNI_FALSE;
    for (jsize n = 0; n < size; ++n) d.ranges.push_back({owned_axes[n], owned_sources[n],
        owned_calibration[n * 4], owned_calibration[n * 4 + 1], owned_calibration[n * 4 + 2], owned_calibration[n * 4 + 3]});
    return dm_android::controller_platform().device(generation, std::move(d)) ? JNI_TRUE : JNI_FALSE;
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_nativeRemove(JNIEnv* env, jclass, jobject activity,
    jint id, jlong notification, jlong fence) {
    const auto generation = dm_android::input_activity_controller_generation(env, activity);
    return generation && notification > 0 && fence > 0 && dm_android::controller_platform().remove(
        generation, id, notification, fence) ? JNI_TRUE : JNI_FALSE;
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_receipt(JNIEnv* env, jclass) {
    return env->NewStringUTF(dm_android::controller_platform().receipt().c_str());
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_registerDiagnosticVirtual(JNIEnv* env, jclass,
    jobject activity, jint id, jint sources, jlong owner) {
#if defined(NDEBUG)
    (void)env; (void)activity; (void)id; (void)sources; (void)owner; return JNI_FALSE;
#else
    const auto generation = dm_android::input_activity_controller_generation(env, activity);
    if (!generation || dm_gamepad_core_capability() != DM_GAMEPAD_DIAGNOSTIC_RAW) return JNI_FALSE;
    auto call = dm_android::diagnostic_call_enter(dm_android::DiagnosticGroup::InputSampling, owner);
    if (!call) return JNI_FALSE;
    dm_android::ControllerDevice d{};
    d.id = id; d.sources = sources; d.notification = ++virtual_notification;
    d.fence_ns = monotonic_ns(); d.name = "Diagnostic OS-injected virtual source"; d.diagnostic_virtual = true;
    for (int axis : {0, 1, 11, 14, 12, 13, 15, 16}) d.ranges.push_back({axis, 0x1000010, -1, 1, 0, 0});
    for (int axis : {17, 18, 22, 23}) d.ranges.push_back({axis, 0x1000010, 0, 1, 0, 0});
    const bool result = dm_android::controller_platform().device(generation, std::move(d));
    call.cleanup_complete(); return result ? JNI_TRUE : JNI_FALSE;
#endif
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_ControllerDevices_removeDiagnosticVirtual(JNIEnv* env, jclass,
    jobject activity, jint id, jlong owner) {
#if defined(NDEBUG)
    (void)env; (void)activity; (void)id; (void)owner; return JNI_FALSE;
#else
    const auto generation = dm_android::input_activity_controller_generation(env, activity);
    if (!generation || dm_gamepad_core_capability() != DM_GAMEPAD_DIAGNOSTIC_RAW) return JNI_FALSE;
    auto call = dm_android::diagnostic_call_enter(dm_android::DiagnosticGroup::InputSampling, owner);
    if (!call) return JNI_FALSE;
    const bool result = dm_android::controller_platform().remove(generation, id, ++virtual_notification, monotonic_ns(), true);
    call.cleanup_complete(); return result ? JNI_TRUE : JNI_FALSE;
#endif
}
#endif
