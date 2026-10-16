#include "program_resolver.h"
#include "module_sha256.h"
#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <tuple>
namespace dm_android {
// Internal recipe check implemented next to the private immutable source catalog.
bool validate_original_builtin_snapshot(const ShaderTypedKey&,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,const uint8_t*,size_t,std::string*);
namespace {
bool fail(std::string* e,const std::string& detail){if(e)*e=detail.substr(0,512);return false;}
bool zero(const ShaderDigest& d){return std::all_of(d.begin(),d.end(),[](uint8_t b){return b==0;});}
bool range(uint64_t off,uint64_t n,uint64_t size){return off<=size && n<=size-off;}
ShaderDigest hash(const uint8_t* p,size_t n){ShaderDigest d;module_sha256(p,n,d.data());return d;}
bool key_valid(const ShaderTypedKey& key,std::string* error){ShaderIndexEntry diagnostic;diagnostic.key=key;diagnostic.expected_file_sha256.fill(1);return validate_compiled_shader_index(&diagnostic,1,error);}
bool source_valid(const ShaderStageSnapshot& stage,std::string* error) {
    const auto& x=stage.source;if(!key_valid(x.key,error))return false;
    if(x.record_address)return fail(error,"Snapshot: retained source must not borrow an address");
    if(shader_identity_kind(x.key)==ShaderIdentityKind::SemanticPort){
        if(x.locator_kind!=4 || x.record_index || x.control_offset || x.record_bytes || x.record_control_offset || x.code_offset || x.code_bytes || x.c1_offset || x.c1_bytes ||
           !zero(x.record_sha256) || !stage.record.empty())return fail(error,"Snapshot: semantic source cannot carry pretend original inputs");
        return true;
    }
    if(x.locator_kind<1 || x.locator_kind>3 || (shader_identity_kind(x.key)==ShaderIdentityKind::AuthoredTranslatorFixture?x.locator_kind!=3:x.locator_kind==3) ||
       !x.record_bytes || x.record_bytes>16777216 || stage.record.size()!=x.record_bytes || !x.code_bytes || x.code_bytes>16777216 || x.c1_bytes>4096 ||
       !range(x.record_control_offset,0x880,x.record_bytes) || !range(x.code_offset,x.code_bytes,x.record_bytes) || !range(x.c1_offset,x.c1_bytes,x.record_bytes) ||
       zero(x.record_sha256) || hash(stage.record.data(),stage.record.size())!=x.record_sha256)return fail(error,"Snapshot: source record/span/hash");
    ShaderDigest control,code;
    if(const auto* original=std::get_if<OriginalMaxwellKey>(&x.key.source)){control=original->control_sha256;code=original->code_sha256;
        if((x.locator_kind==1)!=(original->content_kind==1))return fail(error,"Snapshot: trusted content locator mismatch");}
    else {const auto& fixture=std::get<AuthoredTranslatorFixtureKey>(x.key.source);control=fixture.control_sha256;code=fixture.code_sha256;}
    if(hash(stage.record.data()+x.record_control_offset,0x880)!=control || hash(stage.record.data()+x.code_offset,static_cast<size_t>(x.code_bytes))!=code)return fail(error,"Snapshot: copied full control/code digest mismatch");
    if(!validate_original_builtin_snapshot(x.key,x.control_offset,x.record_index,x.record_control_offset,x.code_offset,x.code_bytes,x.c1_offset,x.c1_bytes,stage.record.data(),stage.record.size(),error))return false;
    return true;
}
bool snapshot_valid(const ProgramSnapshot& s,std::string* error){
    if(!s.generation || !s.serial || s.stages.empty() || s.stages.size()>6 || !s.stage_mask || (s.stage_mask&~63u))return fail(error,"Snapshot: generation/serial/stage count/mask");
    uint32_t mask=0;size_t bytes=0;
    for(const auto& stage:s.stages){if(!key_valid(stage.source.key,error))return false;uint32_t bit=1u<<static_cast<uint32_t>(stage.source.key.stage);
        if(mask&bit)return fail(error,"Snapshot: duplicate stage");mask|=bit;
        if(stage.record.size()>100663296-bytes)return fail(error,"Snapshot: owned source aggregate budget");bytes+=stage.record.size();
        if(!source_valid(stage,error))return false;}
    if(mask!=s.stage_mask || ((mask&32) && mask!=32))return fail(error,"Snapshot: mask disagreement or mixed compute/graphics");
    return true;
}
bool types_equal(const ShaderArtifact& a,uint32_t aid,const ShaderArtifact& b,uint32_t bid){
    std::map<std::pair<uint32_t,uint32_t>,uint8_t> visited;size_t work=0;
    auto find=[](const ShaderArtifact& artifact,uint32_t id)->const ShaderType*{
        auto t=std::lower_bound(artifact.types().begin(),artifact.types().end(),id,[](const ShaderType& type,uint32_t value){return type.id<value;});
        return t==artifact.types().end() || t->id!=id?nullptr:&*t;};
    std::function<bool(uint32_t,uint32_t,unsigned)> compare=[&](uint32_t x,uint32_t y,unsigned depth){
        if(depth>64 || ++work>65536)return false;auto key=std::make_pair(x,y);auto prior=visited.find(key);
        if(prior!=visited.end())return prior->second==2;if(visited.size()>=16384)return false;visited[key]=1;
        const ShaderType* left=find(a,x);const ShaderType* right=find(b,y);
        if(!left || !right || std::tie(left->kind,left->width,left->count,left->image,left->member_count)!=std::tie(right->kind,right->width,right->count,right->image,right->member_count) ||
           bool(left->element)!=bool(right->element))return false;
        if(left->element && !compare(left->element,right->element,depth+1))return false;
        for(size_t i=0;i<left->member_count;++i){if(!range(left->member_first+i,1,a.members().size()) || !range(right->member_first+i,1,b.members().size()) ||
            !compare(a.members()[left->member_first+i].type,b.members()[right->member_first+i].type,depth+1))return false;}
        visited[key]=2;return true;};
    return compare(aid,bid,0);
}
}
bool capture_program_snapshot(uint64_t generation,uint64_t serial,uint32_t mask,const std::vector<ShaderSourceStage>& sources,
    ShaderSourceReader reader,void* context,ProgramSnapshot* out,std::string* error) {
    if(error)error->clear();if(!out)return fail(error,"InvalidArgument: missing program snapshot output");*out={};
    if(!generation || !serial || sources.empty() || sources.size()>6)return fail(error,"Snapshot: source request identity/count");
    try{ProgramSnapshot candidate;candidate.generation=generation;candidate.serial=serial;candidate.stage_mask=mask;size_t total=0;
        for(const auto& source:sources){if(!key_valid(source.key,error))return false;ShaderStageSnapshot stage;stage.source=source;
            if(shader_identity_kind(source.key)==ShaderIdentityKind::SemanticPort){if(source.locator_kind!=0 && source.locator_kind!=4)return fail(error,"Snapshot: semantic locator kind");stage.source.locator_kind=4;}
            else {
                if(!reader || !source.record_address || !source.record_bytes || source.record_bytes>16777216 || source.record_bytes>UINT64_MAX-source.record_address ||
                   source.record_bytes>100663296-total)return fail(error,"Snapshot: missing/bounded source reader span");
                total+=static_cast<size_t>(source.record_bytes);
                stage.record.resize(static_cast<size_t>(source.record_bytes));if(!reader(source.record_address,stage.record.data(),stage.record.size(),context,error))return fail(error,"Snapshot: owned source reader refused");stage.source.record_address=0;
            }
            if(!source_valid(stage,error))return false;candidate.stages.push_back(std::move(stage));
        }
        if(!snapshot_valid(candidate,error))return false;*out=std::move(candidate);return true;
    }catch(const std::bad_alloc&){return fail(error,"Allocation: program source snapshot");}
}
bool resolve_program(const ProgramSnapshot& snapshot,const ShaderResolveContext& request,const ShaderIndexEntry* entries,size_t count,
    ShaderArtifactReader reader,void* context,std::shared_ptr<const ResolvedProgram>* out,std::string* error) {
    if(error)error->clear();if(!out)return fail(error,"InvalidArgument: missing resolved program output");
    const auto prior=*out;out->reset(); // snapshot may be borrowed from this owner
    try {
    if(!request.expected_generation || !request.expected_serial || request.expected_generation!=snapshot.generation || request.expected_serial!=snapshot.serial)return fail(error,"Snapshot: owner request generation/serial mismatch");
    if(!reader)return fail(error,"Index: artifact reader missing");
    if(!validate_compiled_shader_index(entries,count,error) || !snapshot_valid(snapshot,error))return false;
    std::shared_ptr<ResolvedProgram> candidate(new ResolvedProgram);std::set<std::pair<uint32_t,uint32_t>> bindings;size_t total=0;
        for(const auto& stage:snapshot.stages){const ShaderIndexEntry* entry=nullptr;
            for(size_t i=0;i<count;++i)if(shader_typed_key_equal(entries[i].key,stage.source.key)){entry=entries+i;break;}
            if(!entry)return fail(error,"Index: exact discriminated stage key absent");std::shared_ptr<const ShaderArtifact> artifact;
            if(!reader(*entry,&artifact,context,error) || !artifact)return fail(error,"Index: artifact reader refused stage");
            if(artifact->file_sha256()!=entry->expected_file_sha256 || !shader_typed_key_equal(artifact->key(),entry->key))return fail(error,"Identity: reader returned another compiled artifact");
            if(artifact->file_bytes()>268435456-total)return fail(error,"Budget: resolved artifact aggregate");total+=artifact->file_bytes();
            if(!candidate->stages_.empty() && (artifact->profile().name!=candidate->stages_[0]->profile().name || artifact->key().profile_definition_sha256!=candidate->stages_[0]->key().profile_definition_sha256))return fail(error,"Profile: linked stages use different profile definitions");
            const auto& x=stage.source;const auto& id=artifact->identity();
            if(shader_identity_kind(x.key)!=ShaderIdentityKind::SemanticPort){
                if(x.locator_kind!=id.locator_kind || x.record_index!=id.record_index || x.control_offset!=id.control_offset || x.record_bytes!=id.record_size ||
                   x.record_control_offset!=id.record_control_offset || x.code_offset!=id.code_offset || x.code_bytes!=id.code_size || x.c1_offset!=id.c1_offset || x.c1_bytes!=artifact->c1().size() ||
                   x.record_sha256!=id.record_sha256 || !std::equal(artifact->c1().begin(),artifact->c1().end(),stage.record.begin()+static_cast<ptrdiff_t>(x.c1_offset)))return fail(error,"Snapshot: full locator/record/control/code/c1 corroboration mismatch");
            }
            for(const auto& descriptor:artifact->descriptors())if(!bindings.emplace(descriptor.set,descriptor.binding).second)return fail(error,"Reflection: linked descriptor binding collision");
            candidate->stages_.push_back(std::move(artifact));
        }
        const ShaderArtifact *vertex=nullptr,*fragment=nullptr;
        for(const auto& stage:candidate->stages_){if(stage->key().stage==ShaderStage::Vertex)vertex=stage.get();if(stage->key().stage==ShaderStage::Fragment)fragment=stage.get();}
        if(fragment){if(!vertex)return fail(error,"Reflection: fragment stage requires linked vertex stage");
            for(const auto& input:fragment->io()){if(input.direction!=1 || input.builtin!=kShaderNone)continue;
                auto output=std::find_if(vertex->io().begin(),vertex->io().end(),[&](const ShaderIo& io){return io.direction==2 && io.builtin==kShaderNone && io.location==input.location && io.component==input.component;});
                if(output==vertex->io().end() || output->interpolation!=input.interpolation || !types_equal(*vertex,output->type_id,*fragment,input.type_id))return fail(error,"Reflection: complete linked IO disagreement or bounded comparison budget");}
        }
        candidate->snapshot_=snapshot;*out=std::move(candidate);return true;
    }catch(const std::bad_alloc&){return fail(error,"Allocation: immutable program transaction");}
}
bool check_shader_program_device(const ResolvedProgram& program,const ShaderDeviceContract& device,std::string* error) {
    if(error)error->clear();const auto& limits=device.limits;
    try {
    if(!device.initialized || !device.effective_api_version || program.stages().empty() || !program.generation() || !program.serial())return fail(error,"Device: initialized logical device and resolved program required");
    if((device.enabled_features&~device.supported_features) || (device.supported_features&~((1ull<<20)-1)) ||
       (program.stage_mask()&~device.queue_stage_mask))return fail(error,"Device: selected created queue or feature contract incompatible");
    if(!limits.max_bound_descriptor_sets || !limits.per_stage_resources)return fail(error,"Device: missing descriptor layout limits");
    std::array<uint64_t,6> aggregate{};
    for(const auto& artifact:program.stages()){const auto& p=artifact->profile();const uint32_t effective=device.effective_api_version&~4095u;
        if(p.minimum_api>effective || (p.spirv_version>0x10000 && effective<0x401000))return fail(error,"Device: effective API/SPIR-V version incompatible");
        if((p.required_features&device.supported_features)!=p.required_features || (p.required_features&device.enabled_features)!=p.required_features)return fail(error,"Device: required optional feature unsupported or disabled");
        for(const auto& ext:p.required_extensions)if(std::find(device.supported_extensions.begin(),device.supported_extensions.end(),ext)==device.supported_extensions.end() || std::find(device.enabled_extensions.begin(),device.enabled_extensions.end(),ext)==device.enabled_extensions.end())return fail(error,"Device: required extension unsupported or disabled");
        if(p.subgroup_width && (effective<0x401000 || p.subgroup_width!=device.subgroup_size || (device.subgroup_stages&p.stage_mask)!=p.stage_mask ||
            (device.subgroup_operations&p.subgroup_operations)!=p.subgroup_operations))return fail(error,"Device: exact subgroup width/stage/operations unavailable");
        std::array<uint64_t,6> per_stage{};uint64_t resources=0,storage_outputs=0;
        for(const auto& d:artifact->descriptors()){
            if(d.set>=limits.max_bound_descriptor_sets)return fail(error,"Device: descriptor set limit");
            auto add=[&](size_t kind){per_stage[kind]+=d.count;aggregate[kind]+=d.count;};
            switch(d.type){case ShaderDescriptorType::Sampler:add(0);break;case ShaderDescriptorType::CombinedImageSampler:add(0);add(3);break;
            case ShaderDescriptorType::SampledImage:case ShaderDescriptorType::UniformTexelBuffer:add(3);break;
            case ShaderDescriptorType::StorageImage:case ShaderDescriptorType::StorageTexelBuffer:add(4);storage_outputs+=d.count;break;
            case ShaderDescriptorType::UniformBuffer:add(1);break;case ShaderDescriptorType::StorageBuffer:add(2);storage_outputs+=d.count;break;}
            if(d.type!=ShaderDescriptorType::Sampler)resources+=d.count;
            if(d.type==ShaderDescriptorType::UniformBuffer && (!limits.uniform_buffer_range || !limits.uniform_offset_alignment || (limits.uniform_offset_alignment&(limits.uniform_offset_alignment-1)) || d.minimum_buffer_bytes>limits.uniform_buffer_range))return fail(error,"Device: uniform block/range/alignment facts incompatible");
            if(d.type==ShaderDescriptorType::StorageBuffer && (!limits.storage_buffer_range || !limits.storage_offset_alignment || (limits.storage_offset_alignment&(limits.storage_offset_alignment-1)) || d.minimum_buffer_bytes>limits.storage_buffer_range))return fail(error,"Device: storage block/range/alignment facts incompatible");
        }
        for(size_t i=0;i<6;++i)if(per_stage[i]>limits.per_stage_descriptors[i])return fail(error,"Device: per-stage descriptor category limit");
        if(artifact->key().stage==ShaderStage::Fragment){
            if(!limits.max_color_attachments || !limits.max_fragment_output_attachments || !limits.max_fragment_combined_output_resources)return fail(error,"Device: missing fragment output/attachment limits");
            std::set<uint32_t> locations;
            for(const auto& io:artifact->io())if(io.direction==2 && io.builtin==kShaderNone){auto type=std::find_if(artifact->types().begin(),artifact->types().end(),[&](const ShaderType& t){return t.id==io.type_id;});
                if(type==artifact->types().end() || type->kind<2 || type->kind>5 || io.location>=limits.max_fragment_output_attachments)return fail(error,"Device: unsupported/out-of-range fragment output location");locations.insert(io.location);}
            if(storage_outputs+locations.size()>limits.max_fragment_combined_output_resources)return fail(error,"Device: fragment combined storage/color output limit");
            if(resources+limits.max_color_attachments>limits.per_stage_resources)return fail(error,"Device: conditional fragment attachment budget needs exact C2 configuration");
        }else if(resources>limits.per_stage_resources)return fail(error,"Device: per-stage resource limit");
        if(artifact->key().stage==ShaderStage::Compute){uint64_t invocations=1;
            for(size_t i=0;i<3;++i){if(!limits.compute_size[i] || p.local_size[i]>limits.compute_size[i] || p.local_size[i]>UINT64_MAX/invocations)return fail(error,"Device: compute local size limit");invocations*=p.local_size[i];}
            if(!limits.compute_invocations || invocations>limits.compute_invocations || p.shared_bytes>limits.compute_shared_bytes)return fail(error,"Device: compute invocations/shared memory limit");}
    }
    for(size_t i=0;i<6;++i)if(aggregate[i]>limits.aggregate_descriptors[i])return fail(error,"Device: aggregate descriptor category limit");
    return true;
    }catch(const std::bad_alloc&){return fail(error,"Allocation: shader device compatibility");}
}
}
