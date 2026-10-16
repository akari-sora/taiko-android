#include "oe_platform.h"
#include <mutex>

namespace {
std::mutex channel_mutex;
dm_android::OePlatformSnapshot latest;
uint64_t epoch_serial = 0, active_epoch = 0, publications = 0, rejected = 0;

bool valid_fact(const dm_android::OePlatformSnapshot& value) {
    if (!value.generation || !value.revision) return false;
    if (!value.window_available && (value.native_width || value.native_height)) return false;
    if (!value.attached && (value.window_available || value.native_width || value.native_height)) return false;
    if (value.generation < latest.generation) return false;
    if (value.generation == latest.generation &&
        (!latest.attached || value.revision <= latest.revision)) return false;
    return true;
}

bool publish_locked(const dm_android::OePlatformSnapshot& value) {
    if (!valid_fact(value)) { ++rejected; return false; }
    const bool dimensions_changed = latest.window_available != value.window_available ||
        latest.native_width != value.native_width || latest.native_height != value.native_height;
    latest = value;
    ++publications;
    if (active_epoch)
        dm_oe_core_publish_silent(dm_android::oe_platform_focus(value), value.activation_ns,
                                  dimensions_changed ? 1 : 0);
    return true;
}
}

namespace dm_android {
int oe_platform_focus(const OePlatformSnapshot& value) {
    return !value.attached ? 2 : value.stopped ? 3 : value.resumed && value.focused ? 1 : 2;
}
bool oe_platform_publish(const OePlatformSnapshot& value) {
    std::lock_guard<std::mutex> lock(channel_mutex);
    return publish_locked(value);
}
uint64_t oe_platform_bind(const DmOeOps& ops, int validated_opmode) {
    // Reject invalid requests before touching a valid subscription/core state.
    if (!ops.post_pop) return 0;
    std::lock_guard<std::mutex> lock(channel_mutex);
    if (active_epoch || epoch_serial == UINT64_MAX) return 0;
    dm_oe_core_reset_silent();
    dm_oe_core_install_ops_silent(&ops);
    dm_oe_core_seed_silent(validated_opmode, oe_platform_focus(latest), latest.activation_ns);
    active_epoch = ++epoch_serial;
    return active_epoch;
}
bool oe_platform_close(uint64_t epoch) {
    std::lock_guard<std::mutex> lock(channel_mutex);
    if (!epoch || epoch != active_epoch) return false;
    active_epoch = 0;
    dm_oe_core_reset_silent();
    return true;
}
bool oe_platform_publish_for_epoch(uint64_t epoch, const OePlatformSnapshot& value) {
    std::lock_guard<std::mutex> lock(channel_mutex);
    if (!epoch || epoch != active_epoch) { ++rejected; return false; }
    return publish_locked(value);
}
OePlatformReceipt oe_platform_receipt() {
    std::lock_guard<std::mutex> lock(channel_mutex);
    OePlatformReceipt result;
    result.platform = latest; result.epoch = active_epoch; result.open = active_epoch != 0;
    result.publications = publications; result.rejected = rejected;
    dm_oe_core_snapshot(&result.core);
    return result;
}
}
