#include "compute_bindings.h"
#include "../../platform/android/module_sha256.h"
#include <algorithm>
#include <cstring>

namespace dm_android {
namespace {
bool fail(std::string* e,const char* why){if(e)*e=why;return false;}
bool digest_is(const ShaderDigest& d,const char* hex) {
    auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};
    for(size_t i=0;i<d.size();++i)if(d[i]!=nibble(hex[i*2])*16+nibble(hex[i*2+1]))return false;
    return true;
}
int original_policy(const ResolvedProgram& p) {
    if(p.stage_mask()!=32||p.stages().size()!=1)return -1;
    const auto& a=*p.stages()[0];const auto& k=a.key();
    const auto* key=std::get_if<OriginalMaxwellKey>(&k.source);
    if(!key||k.stage!=ShaderStage::Compute||k.profile_name!="android-vulkan10-strict-v1"||
       !digest_is(k.profile_definition_sha256,"f88604a1812cf1dd27b3798384f93734968f7bb6af486e0548f1d667138bcb57")||
       key->content_kind!=2||key->content_name!="D2R/3.3.94012/Update/ExeFS/main.decoded-image"||
       !digest_is(key->trusted_content_sha256,"6843ab6909f96e1558b4b73b0fa807f3873409120cf3e1ef8a86dbebb275ee27"))return -1;
    static const char* const pins[4][3]={
        {"d0f769bb916bbba97e8d5907a2ab40349ed81e7b74383e870d78847114c28a7c","aaf657ee393245946601fb3e396dc093c1ce3fb09a3ae29ba4875a093d51f090","f60c6d61824645aebcbcfb273f5097732fc00f01dc405cc37c8185f62f9d4454"},
        {"16479cc6d75c2b2816eb113c33f96e3917ee172ca363d45de6a49dadf22127cc","b8dd773133250801475b34d541c8f8a5f1e349166aba3df81b1f4c86774950bc","ddbbb7c9b684640652ad17e9cc282979b3a05d22f7409e084a298e021e08195c"},
        {"0687e2ef9513357704103c9726f736575f958f0f314720b6315cff48cb07de5b","ddcb76a04571b0fedf35716c5fd17e4ba6a38c9309da8cf7a011444bd5b2c4be","81c7dbfe30dceecf89d3580ffb9b521fefbde6fcccb949138ca0e2fed5d7fe98"},
        {"4df5909e6dabee0515e1d53c9ae001f6af58d55f7346eb881c92b7c1642ea372","9d09120c2f3995ef1b61c2479b9c0b37061db403994914de2fafb760e0431fc1","78351336dda4881c368e12d759edc0bac426bb953fbab65579971301342e4eb6"}};
    ShaderDigest module{};module_sha256(reinterpret_cast<const uint8_t*>(a.words().data()),a.words().size()*4,module.data());
    for(int i=0;i<4;++i)if(digest_is(key->control_sha256,pins[i][0])&&digest_is(key->code_sha256,pins[i][1])&&digest_is(module,pins[i][2]))return i;
    return -1;
}
int policy(const ResolvedProgram& p) {
    if(p.stage_mask()!=32 || p.stages().size()!=1)return -1;
    const auto& a=*p.stages()[0];const auto& k=a.key();
    const auto* port=std::get_if<SemanticPortKey>(&k.source);
    if(!port || k.stage!=ShaderStage::Compute || k.profile_name!="android-vulkan10-strict-v1" ||
       !digest_is(k.profile_definition_sha256,"ac2721ac233c995cd801002f96ba316e0eeb17156cafabd45705349860c1f6df") ||
       !digest_is(port->semantic_source_sha256,"325b0b2003eb5f75d7c7fbb89a5660f7766dd0744cba93a6d615c98b56eeda5f"))return -1;
    static const char* const names[]={"builtin-q-val0","builtin-q-val8","builtin-q-dlt0","builtin-q-dlt8"};
    static const char* const sources[]={
        "71862bf0edfecb83ea7b8dd7a9d2b230a8bbdc1157f6d25028ebf89c479c641b",
        "3fa211119c13e4f35210edc78ac628747538c54f0c54642ad00a4f922850585b",
        "eafdcb911ed3802508c0378deb94f45f11fe2b62b117a01aa26700de2b7a3674",
        "945b8facae48b60b1ce11bc023a76a45c504ad5b7defdc15d55f3e5d2e193f9a"};
    static const char* const modules[]={
        "d2ce88826b6a417034b7b3465e498bb0f76280d4d31a06eda06621d0a751f7eb",
        "5c9f08004cb7a06591bbb36a3efcf87cf44209c497e170c05021edb8a729b029",
        "90d42b7cdc90f706df5f132d0daef122121ff7597f0d286c87ef14dfad80374f",
        "0d9e80f793e11f63e7d245aff5d8f0a7894d1e1486af2b981ea1bde22105de96"};
    ShaderDigest module{};module_sha256(reinterpret_cast<const uint8_t*>(a.words().data()),a.words().size()*4,module.data());
    for(int i=0;i<4;++i)if(port->builtin_name==names[i]&&digest_is(port->portable_source_sha256,sources[i])&&digest_is(module,modules[i]))return i;
    return -1;
}
bool intersects(const ComputeSpan& a,const ComputeSpan& b) {
    return a.pool==b.pool&&a.size&&b.size&&(a.offset<=b.offset?b.offset-a.offset<a.size:a.offset-b.offset<b.size);
}
}
bool check_compute_access_program(const ResolvedProgram& p,std::string* e) {
    const bool original=original_policy(p)>=0;
    if(!original&&policy(p)<0)return fail(e,"compute-unrecognized-exact-source-contract");
    const auto& a=*p.stages()[0];const auto& profile=a.profile();
    if(profile.minimum_api!=0x400000 || profile.spirv_version!=0x10000 || profile.execution_model!=5 ||
       profile.local_size!=std::array<uint32_t,3>{32,1,1} || profile.entry!="main" ||
       profile.required_features || !profile.required_extensions.empty() || profile.shared_bytes ||
       a.descriptors().size()!=(original?4u:3u) || a.semantics().size()!=(original?4u:3u))return fail(e,"compute-unsupported-profile-or-descriptors");
    if(original) {
        for(size_t i=0;i<4;++i) {
            const auto& d=a.descriptors()[i];const auto& semantic=a.semantics()[i];
            if(d.set||d.binding!=20480+i||d.original_set||d.original_binding!=i||d.count!=1||d.array_rank||d.stage_mask!=32||d.semantic_first!=i||d.semantic_count!=1||
               d.type!=((i==0||i==3)?ShaderDescriptorType::UniformBuffer:ShaderDescriptorType::StorageBuffer)||d.access!=((i==0||i==3)?1u:3u)||
               semantic.descriptor_index!=i||semantic.component||semantic.array_first||semantic.count!=1||semantic.stride)
                return fail(e,"compute-original-descriptor-mapping");
            if(i==0) {
                if(d.minimum_buffer_bytes!=1380||semantic.kind!=1||semantic.encoding||semantic.cb_slot!=kShaderNone||semantic.nvn_slot!=kShaderNone||semantic.source_offset||semantic.source_size!=1380||semantic.driver_count||
                   semantic.rule!="nvn-support-static-v1"||semantic.fill.size()!=1||semantic.fill[0].offset||semantic.fill[0].bytes.size()!=1380||
                   std::any_of(semantic.fill[0].bytes.begin(),semantic.fill[0].bytes.end(),[](uint8_t b){return b!=0;}))return fail(e,"compute-original-support-fill");
            }else if(i==3) {
                if(d.minimum_buffer_bytes!=65536||semantic.kind!=4||semantic.encoding!=3||semantic.cb_slot!=3||semantic.nvn_slot||semantic.source_offset||semantic.source_size!=65536||semantic.driver_count||!semantic.fill.empty()||semantic.rule!="nvn-ubo-slot-v1")return fail(e,"compute-original-count-mapping");
            }else {
                if(semantic.kind!=5||semantic.encoding!=1||semantic.cb_slot||semantic.nvn_slot!=i-1||semantic.source_offset!=0x310+16*(i-1)||semantic.source_size!=8||semantic.driver_count!=1||
                   semantic.rule!="nvn-ssbo-pointer-v1"||semantic.table_capacity!=16||semantic.fill.size()!=1||semantic.fill[0].offset!=semantic.source_offset||semantic.fill[0].size!=8||semantic.fill[0].field!="nvn-ssbo-address64"||!semantic.fill[0].bytes.empty())return fail(e,"compute-original-ssbo-pointer-mapping");
            }
        }
        return true;
    }
    static const char* const rules[]={"builtin-count-ubo-v1","builtin-source-ssbo-v1","builtin-destination-ssbo-v1"};
    for(size_t i=0;i<3;++i) {
        const auto& d=a.descriptors()[i];const auto& s=a.semantics()[i];
        if(d.set || d.binding!=20480+i || d.original_set || d.original_binding!=i || d.count!=1 || d.array_rank ||
           d.type!=(i?ShaderDescriptorType::StorageBuffer:ShaderDescriptorType::UniformBuffer) ||
           d.access!=(i==2?2u:1u) || d.stage_mask!=32 || d.semantic_first!=i || d.semantic_count!=1 ||
           s.descriptor_index!=i || s.kind!=(i?5u:4u) || s.component || s.encoding!=3 || s.nvn_slot!=(i==2?1u:0u) ||
           s.cb_slot!=(i?kShaderNone:3) || s.source_offset || s.source_size!=(i?0u:4u) ||
           s.array_first || s.count!=1 || s.stride || s.driver_count || !s.fill.empty() ||
           s.rule!=rules[i])return fail(e,"compute-unsupported-physical-semantic-mapping");
    }
    return true;
}
bool prepare_compute_dispatch(std::shared_ptr<const ResolvedProgram> program,
    std::shared_ptr<const VkComputeProgram> executable,const std::vector<ComputeBinding>& ubos,
    const std::vector<ComputeBinding>& ssbos,std::array<uint32_t,3> groups,
    const std::vector<SubmitPool>& pools,const ShaderDeviceContract& device,
    std::shared_ptr<const PreparedComputeDispatch>* out,std::string* e) {
    // Getter arguments may refer to the dispatch currently stored in *out.
    // Clear the result immediately while retaining that old input owner until
    // all referenced vectors have been validated/copied or failure returns.
    std::shared_ptr<const PreparedComputeDispatch> input_owner;
    if(out)input_owner.swap(*out);
    if(!out||!program)return fail(e,"compute-missing-owned-program-or-output");
    if(!check_compute_access_program(*program,e)||!check_shader_program_device(*program,device,e))return false;
    if(ubos.size()!=1||ssbos.size()!=2||ubos[0].nvn_slot||ssbos[0].nvn_slot||ssbos[1].nvn_slot!=1)
        return fail(e,"compute-missing-duplicate-extra-slot");
    for(size_t i=0;i<3;++i)if(groups[i]>device.limits.compute_count[i])return fail(e,"compute-workgroup-count-limit");
    const bool empty=!groups[0]||!groups[1]||!groups[2];
    if(!empty&&(groups[1]!=1||groups[2]!=1||uint64_t(groups[0])*32>UINT32_MAX))return fail(e,"compute-workgroup-shape-overflow");
    try {
        auto p=std::shared_ptr<PreparedComputeDispatch>(new PreparedComputeDispatch);
        p->program_=std::move(program);p->executable_=std::move(executable);p->ubos_=ubos;p->ssbos_=ssbos;p->groups_=groups;
        const auto& artifact=*p->program_->stages()[0];
        const bool original=original_policy(*p->program_)>=0;
        const ComputeBinding bindings[]={ubos[0],ssbos[0],ssbos[1],ubos[0]};
        for(size_t i=0;i<artifact.descriptors().size();++i) {
            const auto& b=bindings[i];const auto& d=artifact.descriptors()[i];
            const bool uniform=d.type==ShaderDescriptorType::UniformBuffer;
            if(original&&i==0) {
                if(d.minimum_buffer_bytes>device.limits.uniform_buffer_range)return fail(e,"compute-support-buffer-device-range");
                p->descriptors_.push_back({d.binding,d.type,{SIZE_MAX,0,d.minimum_buffer_bytes},artifact.semantics()[0].fill[0].bytes});continue;
            }
            const uint64_t alignment=uniform?device.limits.uniform_offset_alignment:device.limits.storage_offset_alignment;
            const uint64_t maximum=uniform?device.limits.uniform_buffer_range:device.limits.storage_buffer_range;
            if(!b.size||b.address>UINT64_MAX-b.size||!d.address_alignment||b.address%d.address_alignment||
               b.size<d.minimum_buffer_bytes||!alignment||b.size>maximum)return fail(e,"compute-descriptor-range-alignment-limit");
            size_t matches=0;ComputeSpan physical;
            for(size_t j=0;j<pools.size();++j) {
                const auto& pool=pools[j];
                if(!pool.identity||pool.initial.empty()||pool.address>UINT64_MAX-pool.initial.size())return fail(e,"compute-invalid-pool");
                if(b.address>=pool.address&&b.address-pool.address<pool.initial.size()&&b.size<=pool.initial.size()-(b.address-pool.address)) {
                    ++matches;physical={j,b.address-pool.address,b.size};
                }
            }
            if(matches!=1||physical.offset%alignment)return fail(e,"compute-pool-relative-descriptor-range-alignment");
            p->descriptors_.push_back({d.binding,d.type,physical,{}});
        }
        const auto& count=p->descriptors_[original?3:0].span;p->count_span_=count;uint32_t n=0;
        std::memcpy(&n,pools[count.pool].initial.data()+count.offset,4);
        p->active_=empty?0:std::min<uint64_t>(n,uint64_t(groups[0])*32);
        const int kernel=original?original_policy(*p->program_):policy(*p->program_);
        if(original) {
            // The physical storage descriptors are direct lowered bindings of
            // the measured c0 pointer slots. Preserve the complete initialized
            // driver fact bank rather than reinterpreting Pointer64LE as a slot.
            p->driver_facts_.resize(65536);
            for(size_t i=0;i<2;++i)for(size_t byte=0;byte<8;++byte)p->driver_facts_[0x310+16*i+byte]=uint8_t(ssbos[i].address>>(byte*8));
        }
        const uint64_t stride=kernel<2?16:32,tail=kernel==0?8:kernel==1?16:kernel==2?24:32;
        const uint64_t source_end=p->active_?(p->active_-1)*stride+tail:0;
        if(source_end>UINT32_MAX || source_end>p->descriptors_[1].span.size || p->active_*8>p->descriptors_[2].span.size)
            return fail(e,"compute-dynamic-access-outside-binding");
        p->reads_.push_back({count.pool,count.offset,4});
        if(p->active_) {
            auto src=p->descriptors_[1].span;src.size=source_end;p->reads_.push_back(src);
            auto dst=p->descriptors_[2].span;dst.size=p->active_*8;p->writes_.push_back(dst);
        }
        // A descriptor's declared destination extent must not alias a source or
        // uniform descriptor even when the current count happens to be zero.
        if(intersects(p->descriptors_[2].span,p->descriptors_[1].span)||intersects(p->descriptors_[2].span,count))return fail(e,"compute-writable-source-uniform-alias");
        *out=std::move(p);if(e)e->clear();return true;
    } catch(...) {return fail(e,"compute-binding-allocation");}
}
}
