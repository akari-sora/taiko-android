#pragma once
#include "shader_index.h"
#include <memory>
namespace dm_android {
constexpr uint32_t kShaderNone=0xffffffffu;
struct ShaderArtifactLimits {
    size_t artifact_bytes=16u*1024u*1024u,spirv_bytes=1024u*1024u;
    size_t retained_bytes=256u*1024u*1024u;
    size_t preimage_bytes=32u*1024u*1024u,hash_work_bytes=64u*1024u*1024u;
    size_t context_work_bytes=32u*1024u*1024u;
};
enum class ShaderDescriptorType : uint32_t {
    Sampler=0,CombinedImageSampler=1,SampledImage=2,StorageImage=3,
    UniformTexelBuffer=4,StorageTexelBuffer=5,UniformBuffer=6,StorageBuffer=7
};
struct ShaderProfile {
    std::string name,binding_profile,entry,validation_target;
    uint32_t minimum_api=0,spirv_version=0,addressing_model=0,memory_model=0,execution_model=0;
    std::array<uint32_t,3> local_size{};
    uint32_t shared_bytes=0,stage_mask=0,subgroup_width=0,subgroup_operations=0,semantics_flags=0;
    uint64_t required_features=0;
    std::vector<std::string> required_extensions;
};
struct ShaderIdentity {
    uint32_t locator_kind=0,content_kind=0,control_size=0,code_size=0;
    uint64_t record_index=0,control_offset=0,record_size=0,code_offset=0,c1_offset=0;
    uint64_t record_control_offset=0;
    std::array<uint8_t,8> short_key{};
    ShaderDigest record_sha256{},c1_sha256{};
};
struct ShaderDescriptor {
    uint32_t variable_id=0,pointer_type_id=0,resource_type_id=0;
    ShaderDescriptorType type=ShaderDescriptorType::Sampler;
    uint32_t original_set=0,original_binding=0,set=0,binding=0,count=0,access=0,stage_mask=0;
    uint64_t minimum_buffer_bytes=0;
    uint32_t address_alignment=0,semantic_first=0,semantic_count=0,array_rank=0,minimum_runtime_elements=0;
    std::string name;
};
struct ShaderFill {
    uint64_t offset=0,size=0;
    std::string field;
    std::vector<uint8_t> bytes;
};
struct ShaderSemantic {
    uint32_t descriptor_index=0,kind=0,component=0,cb_slot=kShaderNone,nvn_slot=kShaderNone,encoding=0;
    uint64_t source_offset=0,source_size=0;
    uint32_t array_first=0,count=0,stride=0,driver_first=0,driver_count=0;
    std::string rule;
    uint64_t table_capacity=0;
    std::vector<ShaderFill> fill;
    // Canonical typed image/resource facts remain owned for the later binder.
    std::vector<uint8_t> resource_facts;
};
struct ShaderIo {
    uint32_t variable_id=0,type_id=0,member=kShaderNone,direction=0,location=kShaderNone,
        component=kShaderNone,builtin=kShaderNone,interpolation=0,index=kShaderNone,stage_mask=0,
        fragment_target=kShaderNone,stream=kShaderNone;
    std::string name,rule;
    uint64_t nvn_slot=UINT64_MAX;
};
struct ShaderType {
    uint32_t id=0,kind=0,width=0,element=0,count=0,stride=0,storage=kShaderNone,flags=0,
        member_first=0,member_count=0;
    std::array<uint32_t,6> image{};
};
struct ShaderMember {
    uint32_t owner=0,index=0,type=0,offset=kShaderNone,matrix_stride=0,flags=0,builtin=kShaderNone;
};
// Native supported-subset checks complement offline SPIRV-Tools validation;
// they are not a complete SPIR-V validator. Construction is decoder-only.
class ShaderArtifact {
public:
    const ShaderTypedKey& key() const;
    const ShaderDigest& file_sha256() const;
    const ShaderIdentity& identity() const;
    const ShaderProfile& profile() const;
    const std::vector<uint32_t>& words() const;
    const std::vector<uint8_t>& c1() const;
    const std::vector<ShaderDescriptor>& descriptors() const;
    const std::vector<ShaderSemantic>& semantics() const;
    const std::vector<ShaderIo>& io() const;
    const std::vector<ShaderType>& types() const;
    const std::vector<ShaderMember>& members() const;
    size_t file_bytes() const;
private:
    struct Storage;
    std::shared_ptr<const Storage> storage_;
    explicit ShaderArtifact(std::shared_ptr<const Storage>);
    friend struct ShaderArtifactDecoder;
};
bool decode_shader_artifact(const uint8_t*,size_t,const ShaderIndexEntry&,
    std::shared_ptr<const ShaderArtifact>*,std::string*,const ShaderArtifactLimits& = {});
// Caller retains FD ownership; reads offset0, never seeks, duplicates or closes.
bool read_shader_artifact_fd(int,const ShaderIndexEntry&,
    std::shared_ptr<const ShaderArtifact>*,std::string*,const ShaderArtifactLimits& = {});
}
