#pragma once
#include "kernel_runtime.h"
#include "nvn_submit.h"
#include "program_resolver.h"
#include "graphics_surface.h"
#include "../../gfx/vulkan/nvn_vk.h"
#include <mutex>
namespace dm_android {
class GraphicsClosePermit;
class GraphicsLease {
public:
    GraphicsLease() = default;
    ~GraphicsLease();
    GraphicsLease(const GraphicsLease&)=delete;
    GraphicsLease& operator=(const GraphicsLease&)=delete;
    bool valid() const { return retention_.runtime()!=nullptr; }
    uint64_t generation() const { return retention_.generation(); }
    bool copy(uint64_t,void*,size_t);
    bool admit(uint64_t,size_t,unsigned);
    // Synchronous program storage may also use the current invocation's owned
    // read/write GuestStack. Async publication never uses this exception.
    bool admit_program_storage(uint64_t,size_t,unsigned);
    bool publish(const std::vector<SubmitWrite>&,const std::vector<SubmitEvent>&,std::string&);
private:
    RuntimeGpuLease retention_;
    struct Pin { uint64_t token,address; size_t size; unsigned permissions; };
    std::vector<Pin> pins_;
};
// Called only at a quiescent runtime boundary. Derives authority from the frozen
// Process identity; never initializes Vulkan or invokes guest/platform callbacks.
bool graphics_platform_bind(const Process&,std::string*);
bool graphics_platform_close(const GraphicsClosePermit&,std::string*);
bool graphics_host_target(uintptr_t address,uint64_t generation);
VkReplayStats graphics_platform_stats();
DrawDeviceContract graphics_platform_draw_device_contract(uint64_t generation);
uint64_t graphics_platform_last_fence();
uint64_t graphics_platform_last_fence(uint64_t generation);
uint64_t graphics_platform_completed_fence();
bool graphics_platform_publication_barrier(uint64_t generation,bool hold);
bool graphics_platform_publication_barrier_entered(uint64_t generation);
bool graphics_platform_inject_failure(NvnVkEngine::Failure);
// Requirement compatibility only. The program must belong to this bound
// generation; no initialization, NVN acceptance, submission or guest effect.
// Returned metadata is an observation, never a durable live-generation permit.
bool graphics_platform_shader_readiness(uint64_t generation,const ResolvedProgram&,
                                       ShaderDeviceContract* facts,std::string*);
struct GraphicsProgramStats {uint64_t live=0,retained=0,bytes=0,created=0,replaced=0,released=0;};
GraphicsProgramStats graphics_platform_program_stats();
// Observations only; neither object addresses nor durable resource permits.
struct GraphicsWindowStats {
    uint64_t generation=0,binding_epoch=0,revision=0,presents=0,last_acquire_fence=0,cadence_serial=0;
    SurfaceTicket surface{};
    uint32_t available=0,acquiring=0,acquired=0,pending=0;
    bool live=false,retired=false;
};
GraphicsWindowStats graphics_platform_window_stats();
} // namespace dm_android
