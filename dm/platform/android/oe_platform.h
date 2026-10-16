#pragma once
#include <cstdint>
extern "C" {
#include "../../host/hle_oe_core.h"
}

namespace dm_android {
// A durable platform fact, not a runtime-targeted callback. The channel associates
// it with the current runtime at commit, after validating Activity ownership.
struct OePlatformSnapshot {
    uint64_t generation = 0, revision = 0, activation_ns = 0;
    uint32_t native_width = 0, native_height = 0;
    bool attached = false, started = false, stopped = false;
    bool resumed = false, focused = false, window_available = false;
};
struct OePlatformReceipt {
    OePlatformSnapshot platform{};
    DmOeSnapshot core{};
    uint64_t epoch = 0, publications = 0, rejected = 0;
    bool open = false;
};
int oe_platform_focus(const OePlatformSnapshot&);
bool oe_platform_publish(const OePlatformSnapshot&);
// These operations require the runtime owner's quiescent lifecycle scope. Ops
// contexts remain owned until close succeeds; no platform callback runs here.
uint64_t oe_platform_bind(const DmOeOps&, int validated_opmode);
bool oe_platform_close(uint64_t epoch);
// Explicitly targeted work must not migrate to a replacement runtime.
bool oe_platform_publish_for_epoch(uint64_t epoch, const OePlatformSnapshot&);
OePlatformReceipt oe_platform_receipt();
}
