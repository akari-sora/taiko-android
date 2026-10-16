#pragma once
#include "../../platform/android/nvn_submit.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace dm_android {
struct ShaderDeviceContract;
class ResolvedProgram;
class VkComputeProgram;
class VkGraphicsProgram;
struct DrawDeviceContract;
enum class VkSubmitState { Pending, Completed, Failed };
enum class VkErrorKind { None, InvalidRequest, Device, Publication, UnprovenTermination };
struct VkSubmitResult {
    bool accepted = false;
    uint64_t fence = 0;
    std::string error;
    VkErrorKind error_kind=VkErrorKind::None;
};
struct VkWaitResult {
    VkSubmitState state = VkSubmitState::Pending;
    std::string error;
    VkErrorKind error_kind=VkErrorKind::None;
};
struct VkReplayStats {
    uint64_t submits = 0, completed = 0, failed = 0;
    uint64_t buffer_copies = 0, uniform_updates = 0;
    uint64_t image_uploads = 0, image_downloads = 0, render_passes = 0;
    uint64_t flushes = 0, invalidates = 0, validation_errors = 0;
    uint64_t compute_dispatches=0,compute_objects_created=0,compute_objects_destroyed=0;
    uint64_t compute_zero_workgroups=0;
    uint64_t graphics_draws=0,indexed_draws=0,zero_draws=0,graphics_objects_created=0,graphics_objects_destroyed=0;
    uint32_t api_version = 0, driver_version = 0, vendor_id = 0, device_id = 0;
    uint64_t noncoherent_atom_size = 0;
    bool validation_available = false, debug_utils_available = false;
    std::string device_name, validation_status;
};
using VkPublish = std::function<bool(const std::vector<SubmitWrite>&,
                                   const std::vector<SubmitEvent>&,std::string&)>;
// The callback runs after the actual VkFence succeeds, outside all backend
// locks. It must atomically admit every destination before its first write.
// Call drain BEFORE acquiring a runtime snapshot/read lease for the next submit.
class NvnVkEngine {
public:
    NvnVkEngine();
    ~NvnVkEngine();
    NvnVkEngine(const NvnVkEngine&) = delete;
    NvnVkEngine& operator=(const NvnVkEngine&) = delete;
    bool initialize(std::string* error);
    bool prepare_compute_program(std::shared_ptr<const ResolvedProgram>,
        std::shared_ptr<const VkComputeProgram>*,std::string* error);
    bool prepare_graphics_program(std::shared_ptr<const ResolvedProgram>,
        std::shared_ptr<const VkGraphicsProgram>*,std::string* error);
    DrawDeviceContract draw_device_contract() const;
    // Acceptance consumes the only plan owner and empties the publication
    // function. Caller preparation state cannot retain leases past terminal.
    VkSubmitResult submit(std::shared_ptr<const PreparedSubmit>&&, VkPublish&&);
    VkWaitResult wait(uint64_t fence, uint64_t timeout_ns);
    VkWaitResult drain();
    uint64_t last_fence() const;
    uint64_t completed_fence() const;
    bool retained_pool(uint64_t identity) const;
    bool retained_texture(uint64_t serial) const;
    std::string error() const;
    VkErrorKind error_kind() const;
    VkReplayStats stats() const;
    // Captured facts from the created device and selected queue. This performs
    // no initialization/submission and does not prove shader execution.
    ShaderDeviceContract shader_device_contract() const;
    // Controlled diagnostic boundaries; never replace a successful real GPU
    // fence. Allocation/submit refusal happens before acceptance; publication
    // failure/device-loss injection happens after real completion.
    enum class Failure { None, Allocation, Submit, DeviceLost, Publication,
        ShaderModule, DescriptorLayout, PipelineLayout, Pipeline,
        DescriptorPool, DescriptorSet, Command, Readback, UnprovenTermination };
    bool inject_failure(Failure);
    // Releases only the controlled wait/idle-error wrapper. Recovery still
    // requires a real successful fence/idle result or actual device loss.
    void release_termination_failure();
    void publication_barrier(bool hold);
    bool publication_barrier_entered() const;
private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
// Vulkan mapped ranges: finite size is atom-multiple unless it ends exactly at
// the allocation end. Mapping is always the complete dedicated allocation.
bool nvn_vk_atom_range(uint64_t offset, uint64_t size, uint64_t allocation,
                       uint64_t atom, uint64_t* begin, uint64_t* length);
} // namespace dm_android
