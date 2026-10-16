#pragma once
#include "../../gfx/nvn/nvn_obj.h"
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace dm_android {
class GraphicsLease;
class PreparedComputeDispatch;
class ResolvedProgram;
class VkComputeProgram;
class VkGraphicsProgram;
class PreparedDraw;
struct DrawState;
struct DrawCall;
// The adapter issues this only after a core live-program acquire. The lease
// owns that acquisition and the immutable backend entry, never a guest pointer.
struct SubmitProgram {
    prog_t snapshot{};
    uint64_t generation = 0;
    std::shared_ptr<const ResolvedProgram> resolved;
    std::shared_ptr<const VkComputeProgram> executable;
    std::shared_ptr<void> lease;
    std::shared_ptr<const VkGraphicsProgram> graphics_executable;
};
struct SubmitPool {
    uint64_t identity = 0, address = 0;
    std::vector<uint8_t> initial;
};
struct SubmitSampledResource {
    tex_t texture{};
    samp_par sampler{};
    uint64_t generation=0,binding_epoch=0;
    std::shared_ptr<void> lease;
};
struct SubmitOp {
    uint32_t opcode = 0;
    std::vector<uint8_t> payload;
    uint32_t compute_index = UINT32_MAX;
    uint32_t draw_index = UINT32_MAX;
};
struct SubmitEvent { uint64_t address = 0; uint32_t mode = 0, value = 0; };
struct SubmitWrite { uint64_t address = 0; std::vector<uint8_t> bytes; };
// Never mutate after preparation. Texture pointers embedded in payload refer
// only to separately owned snapshots, not guest objects or recorder storage.
struct PreparedSubmit {
    uint64_t generation = 0;
    std::vector<SubmitPool> pools;
    std::vector<SubmitOp> ops;
    std::vector<SubmitEvent> events;
    std::vector<std::shared_ptr<const PreparedComputeDispatch>> computes;
    std::vector<std::shared_ptr<const PreparedDraw>> draws;
    std::vector<SubmitProgram> programs;
    std::vector<std::unique_ptr<tex_t>> textures;
    std::vector<std::shared_ptr<void>> recorder_segments;
    std::shared_ptr<GraphicsLease> lease;
};
struct SubmitReader {
    std::function<bool(uint64_t, void*, size_t)> copy;
    // A recorder segment is accepted only through its actual registered owner.
    // This optional callback retains that owner before copying native memory.
    std::function<std::shared_ptr<void>(uint64_t,size_t)> retain_recorder;
    std::function<bool(uint64_t)> texture_live;
    std::function<bool(const dpool_t&,const dpool_t&,uint64_t,uint64_t,
        std::shared_ptr<const SubmitSampledResource>*,std::string*)> acquire_sampled;
    std::function<bool(const prog_t&, uint32_t, SubmitProgram*, std::string*)> acquire_program;
    std::function<bool(const SubmitProgram&, const std::vector<p_bind_buf>&,
        const std::vector<p_bind_buf>&, std::array<uint32_t,3>,
        const std::vector<SubmitPool>&, std::shared_ptr<const PreparedComputeDispatch>*,
        std::string*)> prepare_compute;
    std::function<bool(const SubmitProgram&,const DrawState&,const DrawCall&,
        const std::vector<SubmitPool>&,std::shared_ptr<const PreparedDraw>*,std::string*)> prepare_draw;
};
struct SubmitLimits {
    size_t handles = 256, depth = 32, operations = 131072;
    size_t bytes = 16u*1024u*1024u, pools_bytes = 128u*1024u*1024u;
};
bool prepare_submit(const uint64_t* handles, size_t count,
                    const SubmitReader&, std::vector<SubmitPool> pools,
                    std::shared_ptr<PreparedSubmit>* out, std::string* error,
                    const SubmitLimits& limits = {},
                    uint32_t* failure_operation = nullptr);
// failure_operation is cleared on success or when no current record header was
// readable. A fully read header identifies failures even if its size/payload is
// malformed. It is an NVN recorder opcode, never a hardware/backend operation.
} // namespace dm_android
