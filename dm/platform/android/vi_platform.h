#pragma once
#include "graphics_surface.h"
#include <cstdint>
#include <string>

namespace dm_android {
class Process;
// Runtime-owner operations at a quiescent boundary, before graphics binding on
// load and before Process unload on rollback/shutdown. Metadata only: no Surface
// queries, native references, callbacks, allocations on reset, or GPU waits.
// owned_generation is trusted host storage, cleared on entry and assigned only
// by the successful publication commit. Inert success grants no reset ownership.
bool vi_platform_bind(const Process&, std::string* error,uint64_t* owned_generation=nullptr);
bool vi_platform_reset(uint64_t runtime_generation) noexcept;

struct ViPlatformSnapshot {
    uint64_t generation=0,binding=0,oe_epoch=0;
    SurfaceTicket surface{}; // last successful Initialize/handle query observation
    uintptr_t display=0,layer=0,native_window=0;
    bool initialized=false;
};
ViPlatformSnapshot vi_platform_snapshot();
struct ViNativeWindow {
    uint64_t generation=0,binding=0;
    SurfaceTicket surface{};
    uint32_t width=0,height=0;
};
// Checked observation for a future NVN backend, never an ANativeWindow pointer
// or a durable presentation permit. The existing presenter owns the window and
// revalidates SurfaceTicket at admission. Failure leaves *out untouched.
bool vi_platform_native_window(const void* token,uint64_t runtime_generation,ViNativeWindow* out);
}
