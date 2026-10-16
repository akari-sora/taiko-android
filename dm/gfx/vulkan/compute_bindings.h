#pragma once
#include "../../platform/android/nvn_submit.h"
#include "../../platform/android/program_resolver.h"

namespace dm_android {
class VkComputeProgram;
struct ComputeBinding { uint32_t nvn_slot=0; uint64_t address=0,size=0; };
struct ComputeSpan { size_t pool=0; uint64_t offset=0,size=0; };
struct ComputeDescriptor {
    uint32_t binding=0;
    ShaderDescriptorType type=ShaderDescriptorType::UniformBuffer;
    ComputeSpan span;
    // Static support storage has no guest address or pool. It is always copied
    // into a separate owned GPU buffer before recording.
    std::vector<uint8_t> initial;
};
// Construction is checked and produces only immutable owned values. An
// executable is engine-private authority; the binder never manufactures one.
class PreparedComputeDispatch {
public:
    const auto& program() const {return program_;}
    const auto& executable() const {return executable_;}
    const auto& ubos() const {return ubos_;}
    const auto& ssbos() const {return ssbos_;}
    const auto& groups() const {return groups_;}
    const auto& descriptors() const {return descriptors_;}
    const auto& reads() const {return reads_;}
    const auto& writes() const {return writes_;}
    uint64_t active() const {return active_;}
    const ComputeSpan& count_span() const {return count_span_;}
    uint64_t owned_bytes() const {
        uint64_t bytes=sizeof(*this)+ubos_.capacity()*sizeof(ComputeBinding)+ssbos_.capacity()*sizeof(ComputeBinding)+
            descriptors_.capacity()*sizeof(ComputeDescriptor)+reads_.capacity()*sizeof(ComputeSpan)+
            writes_.capacity()*sizeof(ComputeSpan)+driver_facts_.capacity();
        for(const auto& d:descriptors_)bytes+=d.initial.capacity();
        return bytes;
    }
private:
    PreparedComputeDispatch()=default;
    std::shared_ptr<const ResolvedProgram> program_;
    std::shared_ptr<const VkComputeProgram> executable_;
    std::vector<ComputeBinding> ubos_,ssbos_;
    std::array<uint32_t,3> groups_{};
    std::vector<ComputeDescriptor> descriptors_;
    std::vector<ComputeSpan> reads_,writes_;
    uint64_t active_=0;
    ComputeSpan count_span_;
    std::vector<uint8_t> driver_facts_;
    friend bool prepare_compute_dispatch(std::shared_ptr<const ResolvedProgram>,
        std::shared_ptr<const VkComputeProgram>,const std::vector<ComputeBinding>&,
        const std::vector<ComputeBinding>&,std::array<uint32_t,3>,
        const std::vector<SubmitPool>&,const ShaderDeviceContract&,
        std::shared_ptr<const PreparedComputeDispatch>*,std::string*);
};
// Exact four semantic and four independently extracted/translated original
// contracts. Every other original/authored input remains refused.
bool check_compute_access_program(const ResolvedProgram&,std::string*);
bool prepare_compute_dispatch(std::shared_ptr<const ResolvedProgram>,
    std::shared_ptr<const VkComputeProgram>,const std::vector<ComputeBinding>& ubos,
    const std::vector<ComputeBinding>& ssbos,std::array<uint32_t,3> groups,
    const std::vector<SubmitPool>&,const ShaderDeviceContract&,
    std::shared_ptr<const PreparedComputeDispatch>*,std::string*);
}
