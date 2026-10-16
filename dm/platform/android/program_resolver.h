#pragma once
#include "shader_artifact.h"
namespace dm_android {
enum class ShaderFeature : uint64_t {
    Float64=1ull<<0,Int64=1ull<<1,Int16=1ull<<2,Geometry=1ull<<3,Tessellation=1ull<<4,
    FragmentStoresAndAtomics=1ull<<5,VertexStoresAndAtomics=1ull<<6,
    StorageImageExtendedFormats=1ull<<7,StorageImageReadWithoutFormat=1ull<<8,
    StorageImageWriteWithoutFormat=1ull<<9,UniformBufferArrayDynamicIndexing=1ull<<10,
    SampledImageArrayDynamicIndexing=1ull<<11,StorageBufferArrayDynamicIndexing=1ull<<12,
    StorageImageArrayDynamicIndexing=1ull<<13,SampleRateShading=1ull<<14,
    ClipDistance=1ull<<15,CullDistance=1ull<<16,ImageCubeArray=1ull<<17,
    ResourceMinLod=1ull<<18,StorageImageMultisample=1ull<<19
};
enum class ShaderDescriptorLimit : size_t {
    Samplers=0,UniformBuffers=1,StorageBuffers=2,SampledImages=3,StorageImages=4,InputAttachments=5
};
struct ShaderDeviceLimits {
    std::array<uint32_t,6> per_stage_descriptors{},aggregate_descriptors{};
    uint32_t per_stage_resources=0,max_bound_descriptor_sets=0;
    uint32_t max_color_attachments=0,max_fragment_output_attachments=0,
        max_fragment_combined_output_resources=0;
    std::array<uint32_t,3> compute_count{},compute_size{};
    uint32_t compute_invocations=0,compute_shared_bytes=0;
    uint64_t uniform_offset_alignment=0,storage_offset_alignment=0,
        uniform_buffer_range=0,storage_buffer_range=0;
};
struct ShaderDeviceContract {
    bool initialized=false;
    uint32_t effective_api_version=0,queue_stage_mask=0;
    uint64_t supported_features=0,enabled_features=0;
    std::vector<std::string> supported_extensions,enabled_extensions;
    // subgroup_stages uses NVN ordinals, NOT VkShaderStageFlags. C2 must convert.
    uint32_t subgroup_size=0,subgroup_stages=0,subgroup_operations=0;
    ShaderDeviceLimits limits;
};
struct ShaderSourceStage {
    ShaderTypedKey key;
    uint32_t locator_kind=0;
    uint64_t record_index=0,control_offset=0,record_address=0,record_bytes=0,
        record_control_offset=0,code_offset=0,code_bytes=0,c1_offset=0,c1_bytes=0;
    ShaderDigest record_sha256{};
};
struct ShaderStageSnapshot {
    ShaderSourceStage source;
    std::vector<uint8_t> record;
};
struct ProgramSnapshot {
    uint64_t generation=0,serial=0;
    uint32_t stage_mask=0;
    std::vector<ShaderStageSnapshot> stages;
};
// Owner-supplied identity consistency, not a core live-serial attestation.
struct ShaderResolveContext { uint64_t expected_generation=0,expected_serial=0; };
using ShaderSourceReader=bool (*)(uint64_t,void*,size_t,void*,std::string*);
using ShaderArtifactReader=bool (*)(const ShaderIndexEntry&,
    std::shared_ptr<const ShaderArtifact>*,void*,std::string*);
bool capture_program_snapshot(uint64_t,uint64_t,uint32_t,
    const std::vector<ShaderSourceStage>&,ShaderSourceReader,void*,ProgramSnapshot*,std::string*);
class ResolvedProgram {
public:
    uint64_t generation() const { return snapshot_.generation; }
    uint64_t serial() const { return snapshot_.serial; }
    uint32_t stage_mask() const { return snapshot_.stage_mask; }
    const std::vector<std::shared_ptr<const ShaderArtifact>>& stages() const { return stages_; }
    const ProgramSnapshot& snapshot() const { return snapshot_; }
private:
    ResolvedProgram()=default;
    ProgramSnapshot snapshot_;
    std::vector<std::shared_ptr<const ShaderArtifact>> stages_;
    friend bool resolve_program(const ProgramSnapshot&,const ShaderResolveContext&,
        const ShaderIndexEntry*,size_t,ShaderArtifactReader,void*,
        std::shared_ptr<const ResolvedProgram>*,std::string*);
};
bool resolve_program(const ProgramSnapshot&,const ShaderResolveContext&,
    const ShaderIndexEntry*,size_t,ShaderArtifactReader,void*,
    std::shared_ptr<const ResolvedProgram>*,std::string*);
// True means represented artifact/device requirement compatibility only. It
// proves no resource binding, offset/range, dispatch count, pipeline or NVN
// operation. FS conservatively reserves the device's maximum color attachments.
bool check_shader_program_device(const ResolvedProgram&,const ShaderDeviceContract&,std::string*);
}
