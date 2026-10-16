#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct android_app;
namespace dm_android {
// Linear, top-row-first GPU readback. The presenter only copies/scales these
// pixels; it does not rasterize or substitute a CPU rendering result.
struct SurfaceFrame {
    uint32_t width=0,height=0,row_stride_bytes=0;
    std::vector<uint8_t> rgba8;
};
struct SurfaceTicket {uint64_t owner=0,epoch=0;};
struct SurfaceCadence {
    SurfaceTicket ticket{};
    uint64_t serial=0;
    int64_t frame_time_ns=0;
};
struct SurfaceBuffer {int32_t width=0,height=0,stride=0,format=0;void* bits=nullptr;};
class SurfaceWindow {
public:
    virtual ~SurfaceWindow()=default;
    virtual int geometry_rgba8_default_size()=0;
    virtual int lock(SurfaceBuffer*)=0;
    virtual int unlock_and_post()=0;
};
struct SurfaceResult {
    bool accepted=false,locked=false,posted=false;
    uint32_t width=0,height=0;
    std::string error;
};
struct SurfaceSnapshot {
    uint64_t owner=0,epoch=0,posts=0,accepted=0,failures=0;
    uint32_t width=0,height=0;
    bool available=false,active=false;
};
// One bounded frame and one normal native worker. Lifecycle calls close
// admission and wait for an admitted lock/copy/post before returning. No external
// lifecycle/input/runtime mutex may span present(). The window reference is
// acquired by the caller during its valid surface callback, not in the worker.
class SurfacePresenter {
public:
    SurfacePresenter();
    ~SurfacePresenter();
    SurfacePresenter(const SurfacePresenter&)=delete;
    SurfacePresenter& operator=(const SurfacePresenter&)=delete;
    bool bind(uint64_t owner,std::shared_ptr<SurfaceWindow>,uint32_t width,uint32_t height,bool resumed);
    bool activity(uint64_t owner,bool resumed);
    bool detach(uint64_t owner);
    SurfaceTicket ticket() const;
    SurfaceSnapshot snapshot() const;
    SurfaceResult present(SurfaceTicket,SurfaceFrame);
    // Actual display callbacks pace acquisition; they do not prove scanout.
    // Waits release the internal mutex. No external lifecycle/runtime lock may
    // span a wait. Failure leaves out unchanged; timeout is bounded to 1 second.
    bool frame_tick(uint64_t owner,int64_t frame_time_ns);
    SurfaceCadence cadence() const;
    bool wait_cadence(SurfaceTicket,uint64_t after_serial,uint64_t timeout_ns,SurfaceCadence* out);
private:
    struct State;
    std::unique_ptr<State> state_;
};

void graphics_surface_attach(android_app*);
void graphics_surface_command(android_app*,int32_t);
void graphics_surface_detach(android_app*);
SurfaceTicket graphics_surface_ticket();
SurfaceSnapshot graphics_surface_snapshot();
bool graphics_surface_frame_tick(uint64_t owner,int64_t frame_time_ns);
SurfaceCadence graphics_surface_cadence();
bool graphics_surface_wait_cadence(SurfaceTicket,uint64_t after_serial,uint64_t timeout_ns,SurfaceCadence* out);
// Acquires a real RuntimeGpuLease and verifies the exact live generation before
// admitting a frame. The lease survives the normal worker's final post/ack.
SurfaceResult graphics_surface_present(SurfaceTicket,uint64_t runtime_generation,SurfaceFrame);
}
