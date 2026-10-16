#include "draw_bindings.h"
#include <algorithm>
#include <cmath>
#include <cstring>
namespace dm_android {
namespace {
bool fail(std::string* error,const char* why){if(error)*error=why;return false;}
bool digest_is(const ShaderDigest& bytes,const char* text){auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};for(size_t i=0;i<32;++i)if(bytes[i]!=nibble(text[2*i])*16+nibble(text[2*i+1]))return false;return true;}
bool resolve(const std::vector<SubmitPool>& pools,uint64_t address,uint64_t size,ComputeSpan* out,std::string* error){
    if(!size||address>UINT64_MAX-size)return fail(error,"draw-empty-overflowing-range");size_t matches=0;
    for(size_t i=0;i<pools.size();++i){const auto& pool=pools[i];if(!pool.identity||pool.initial.empty()||pool.address>UINT64_MAX-pool.initial.size())return fail(error,"draw-invalid-pool");if(address>=pool.address&&address-pool.address<pool.initial.size()&&size<=pool.initial.size()-(address-pool.address)){++matches;*out={i,address-pool.address,size};}}
    return matches==1||fail(error,"draw-range-not-unique-owned-pool");
}
bool overlap(const ComputeSpan& a,const ComputeSpan& b){return a.pool==b.pool&&a.size&&b.size&&(a.offset<=b.offset?b.offset-a.offset<a.size:a.offset-b.offset<b.size);}
}
uint64_t PreparedDraw::owned_bytes()const{uint64_t bytes=sizeof(*this)+state_.ubos.capacity()*sizeof(p_bind_buf)+descriptors_.capacity()*sizeof(DrawDescriptor)+reads_.capacity()*sizeof(ComputeSpan);for(const auto& d:descriptors_)bytes+=d.initial.capacity();return bytes;}
namespace {
bool original_program(const ResolvedProgram& program){
    const auto digest=[](const char* text){ShaderDigest out{};auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};for(size_t i=0;i<32;++i)out[i]=uint8_t(nibble(text[2*i])*16+nibble(text[2*i+1]));return out;};
    static const std::array<ShaderIndexEntry,2> entries={{
#include "../../platform/android/original_draw_shaders/catalog_entries.inc"
    }};
    return program.stages().size()==2&&std::all_of(program.stages().begin(),program.stages().end(),[&](const auto& stage){return stage&&std::any_of(entries.begin(),entries.end(),[&](const auto& entry){return shader_typed_key_equal(stage->key(),entry.key)&&stage->file_sha256()==entry.expected_file_sha256;});});
}
bool original_sampled_program(const ResolvedProgram& program){
    const auto digest=[](const char* text){ShaderDigest out{};auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};for(size_t i=0;i<32;++i)out[i]=uint8_t(nibble(text[2*i])*16+nibble(text[2*i+1]));return out;};
    static const std::array<ShaderIndexEntry,2> entries={{
#include "../../platform/android/original_sampled_shaders/catalog_entries.inc"
    }};
    return program.stages().size()==2&&std::all_of(program.stages().begin(),program.stages().end(),[&](const auto& stage){return stage&&std::any_of(entries.begin(),entries.end(),[&](const auto& entry){return shader_typed_key_equal(stage->key(),entry.key)&&stage->file_sha256()==entry.expected_file_sha256;});});
}
bool check_original_sampled_program(const ResolvedProgram& program,std::string* error){
    uint32_t seen=0;
    for(const auto& stage:program.stages()){
        const uint32_t ordinal=static_cast<uint32_t>(stage->key().stage);if(ordinal>1||(seen&(1u<<ordinal)))return fail(error,"original-sampled-stage-pair");seen|=1u<<ordinal;
        const auto& p=stage->profile();if(p.name!="android-vulkan10-original-embedded-texture-v1"||p.minimum_api!=0x400000||p.spirv_version!=0x10000||p.entry!="main"||p.required_features||!p.required_extensions.empty()||p.stage_mask!=(1u<<ordinal))return fail(error,"original-sampled-profile");
        if(stage->descriptors().size()!=(ordinal?3u:2u)||stage->semantics().size()!=(ordinal?4u:2u))return fail(error,"original-sampled-descriptor-coverage");
        for(size_t i=0;i<stage->descriptors().size();++i){const auto& d=stage->descriptors()[i];
            if(d.set||d.binding!=ordinal*4096+i||d.count!=1||d.array_rank||d.access!=1||d.stage_mask!=(1u<<ordinal))return fail(error,"original-sampled-physical-binding");
            if(ordinal&&i==1){if(d.type!=ShaderDescriptorType::CombinedImageSampler||d.semantic_first!=1||d.semantic_count!=2)return fail(error,"original-sampled-combined-binding");
                for(size_t n=1;n<=2;++n){const auto& r=stage->semantics()[n];const uint32_t kind=n+6,slot=n==1?10:0;const uint64_t offset=n==1?0x1b8:0x568;if(r.descriptor_index!=1||r.kind!=kind||r.component!=n||r.cb_slot!=2||r.nvn_slot!=slot||r.encoding!=2||r.source_offset!=offset||r.source_size!=8||r.count!=1||r.array_first||r.stride||r.table_capacity!=128||r.driver_count!=1)return fail(error,"original-sampled-slot-contract");}
                continue;}
            const size_t index=ordinal&&i==2?3:i;const auto& r=stage->semantics()[index];if(d.type!=ShaderDescriptorType::UniformBuffer||d.semantic_first!=index||d.semantic_count!=1||r.descriptor_index!=i||r.component||r.array_first||r.count!=1||r.stride||r.driver_count)return fail(error,"original-sampled-buffer-contract");
            if(!i){if(d.minimum_buffer_bytes!=1380||r.kind!=1||r.encoding||r.rule!="nvn-support-static-v1"||r.fill.size()!=1||r.fill[0].offset||r.fill[0].bytes.size()!=1380||std::any_of(r.fill[0].bytes.begin(),r.fill[0].bytes.end(),[](uint8_t b){return b!=0;}))return fail(error,"original-sampled-support-contract");}
            else if(d.minimum_buffer_bytes!=65536||r.kind!=4||r.cb_slot!=3||r.nvn_slot!=0||r.encoding!=3||r.source_offset||r.source_size!=65536||!r.fill.empty()||r.rule!="nvn-ubo-slot-v1")return fail(error,"original-sampled-ubo-contract");
        }
    }
    return seen==3;
}
bool check_original_program(const ResolvedProgram& program,std::string* error){
    uint32_t seen=0;
    for(const auto& stage:program.stages()){
        const uint32_t ordinal=static_cast<uint32_t>(stage->key().stage);if(ordinal>1||(seen&(1u<<ordinal)))return fail(error,"original-draw-stage-pair");seen|=1u<<ordinal;
        const auto& p=stage->profile();if(p.minimum_api!=0x400000||p.spirv_version!=0x10000||p.entry!="main"||p.required_features||!p.required_extensions.empty()||p.stage_mask!=(1u<<ordinal))return fail(error,"original-draw-profile");
        if(stage->descriptors().size()!=(ordinal?1u:2u)||stage->semantics().size()!=(ordinal?1u:2u))return fail(error,"original-draw-descriptor-coverage");
        for(size_t i=0;i<stage->descriptors().size();++i){const auto& d=stage->descriptors()[i];const auto& semantic=stage->semantics()[i];
            if(d.type!=ShaderDescriptorType::UniformBuffer||d.set||d.binding!=ordinal*4096+i||d.count!=1||d.array_rank||d.access!=1||d.stage_mask!=(1u<<ordinal)||d.semantic_first!=i||d.semantic_count!=1||semantic.descriptor_index!=i||semantic.component||semantic.array_first||semantic.count!=1||semantic.stride||semantic.driver_count)return fail(error,"original-draw-binding-contract");
            if(!i){if(d.minimum_buffer_bytes!=1380||semantic.kind!=1||semantic.encoding||semantic.rule!="nvn-support-static-v1"||semantic.fill.size()!=1||semantic.fill[0].offset||semantic.fill[0].bytes.size()!=1380||std::any_of(semantic.fill[0].bytes.begin(),semantic.fill[0].bytes.end(),[](uint8_t b){return b!=0;}))return fail(error,"original-draw-support-contract");}
            else if(d.minimum_buffer_bytes!=65536||semantic.kind!=4||semantic.cb_slot!=3||semantic.nvn_slot!=0||semantic.encoding!=3||semantic.source_offset||semantic.source_size!=65536||!semantic.fill.empty()||semantic.rule!="nvn-ubo-slot-v1")return fail(error,"original-draw-matrix-contract");
        }
    }
    return seen==3;
}
bool sampled_program(const ResolvedProgram& program){
    return program.stages().size()==2&&std::all_of(program.stages().begin(),program.stages().end(),[](const auto& stage){return stage&&digest_is(stage->key().profile_definition_sha256,"4415f7f1de064c453b16358c32c83d71f3a66b452da780f98aff44d476103a24");});
}
bool check_sampled_program(const ResolvedProgram& program,std::string* error){
    uint32_t seen=0;
    for(const auto& stage:program.stages()){
        if(!stage)return fail(error,"sampled-draw-null-stage");
        const auto ordinal=static_cast<uint32_t>(stage->key().stage);
        if(ordinal>1||(seen&(1u<<ordinal)))return fail(error,"sampled-draw-stage-pair");seen|=1u<<ordinal;
        const auto* key=std::get_if<AuthoredTranslatorFixtureKey>(&stage->key().source);
        const auto& profile=stage->profile();
        if(!key||key->fixture_name!=(ordinal?"authored_d2_fragcoord_clamp_fs":"authored_vs_position")||
           !digest_is(stage->file_sha256(),ordinal?"52bbbefebd0a2cc1e79cbcc27125859692532e87e143387a6346147360a0f115":"84ee0d54d9e50cf1fe2d749a0554e2568515bc93279026425b339c720c5d31a0")||
           profile.name!="android-vulkan10-authored-sampled2d-v1"||profile.minimum_api!=0x400000||profile.spirv_version!=0x10000||profile.entry!="main"||profile.required_features||!profile.required_extensions.empty()||profile.stage_mask!=(1u<<ordinal))return fail(error,"sampled-draw-unrecognized-exact-contract");
        if(stage->descriptors().size()!=(ordinal?2u:1u)||stage->semantics().size()!=(ordinal?3u:1u))return fail(error,"sampled-draw-descriptor-coverage");
        const auto& support=stage->descriptors()[0];const auto& fill=stage->semantics()[0];
        if(support.type!=ShaderDescriptorType::UniformBuffer||support.set||support.binding!=ordinal*4096||support.count!=1||support.array_rank||support.access!=1||support.stage_mask!=(1u<<ordinal)||support.minimum_buffer_bytes!=1380||support.semantic_first||support.semantic_count!=1||fill.descriptor_index||fill.kind!=1||fill.encoding||fill.fill.size()!=1||fill.fill[0].offset||fill.fill[0].bytes.size()!=1380)return fail(error,"sampled-draw-support-contract");
        for(size_t i=0;i<1380;++i){const bool one=ordinal&&i>=192&&i<=1347&&(i-192)%16==2;const bool exponent=ordinal&&i>=192&&i<=1347&&(i-192)%16==3;if(fill.fill[0].bytes[i]!=(one?0x80:exponent?0x3f:0))return fail(error,"sampled-draw-support-fill");}
        if(ordinal){const auto& d=stage->descriptors()[1];if(d.type!=ShaderDescriptorType::CombinedImageSampler||d.set||d.binding!=4097||d.count!=1||d.array_rank||d.access!=1||d.stage_mask!=2||d.semantic_first!=1||d.semantic_count!=2)return fail(error,"sampled-draw-image-contract");
            for(size_t i=1;i<3;++i){const auto& semantic=stage->semantics()[i];if(semantic.descriptor_index!=1||semantic.kind!=i+6||semantic.component!=i||semantic.cb_slot!=kShaderNone||semantic.nvn_slot||semantic.encoding!=3||semantic.source_offset||semantic.source_size||semantic.count!=1||semantic.array_first||semantic.stride||semantic.table_capacity!=1||!semantic.fill.empty()||semantic.rule!="authored-static-separate-or-word32-v1")return fail(error,"sampled-draw-slot-contract");}
        }
    }
    return seen==3;
}
bool check_sampled_resource(const SubmitSampledResource& sampled,const DrawDeviceContract& device,std::string* error){
    const auto& t=sampled.texture;const auto& d=t.d;const auto& p=sampled.sampler;
    if(!sampled.generation||!sampled.binding_epoch||!sampled.lease||t.pool||!t.serial||t.magic!=MAGIC('T','E','X',0)||d.target!=1||d.format!=NVN_FORMAT_RGBA8||d.samples!=1||d.levels!=1||d.depth!=1||!d.width||!d.height||d.width>device.sampled_extent[0]||d.height>device.sampled_extent[1]||d.flags!=0x10||d.pkg_block_h)return fail(error,"sampled-draw-unowned-or-unsupported-texture");
    if(p.minf!=NVN_MIN_FILTER_NEAREST||p.magf!=NVN_MAG_FILTER_NEAREST||p.ws!=NVN_WRAP_MODE_CLAMP_TO_EDGE||p.wt!=NVN_WRAP_MODE_CLAMP_TO_EDGE||p.wr!=NVN_WRAP_MODE_CLAMP_TO_EDGE||p.cmp_mode!=NVN_COMPARE_MODE_NONE||p.lod_min!=0||p.lod_max!=0||p.lod_bias!=0||p.aniso!=1)return fail(error,"sampled-draw-unsupported-sampler");
    nvn_texlayout layout{};nvn_tex_layout(&d,&layout);
    if(!layout.size||layout.size>64u*1024u*1024u||layout.size!=t.L.size||layout.layer_size!=t.L.layer_size||layout.align!=t.L.align||layout.layers!=t.L.layers||layout.bpb!=t.L.bpb||layout.tileH!=t.L.tileH||layout.tileD!=t.L.tileD)return fail(error,"sampled-draw-layout");
    return true;
}
}
bool check_draw_program(const ResolvedProgram& program,std::string* error){
    if(program.stage_mask()!=3||program.stages().size()!=2)return fail(error,"draw-requires-exact-vertex-fragment-pair");
    if(original_sampled_program(program))return check_original_sampled_program(program,error);
    if(original_program(program))return check_original_program(program,error);
    if(sampled_program(program))return check_sampled_program(program,error);
    uint32_t seen=0;
    for(const auto& stage:program.stages()){
        if(!stage)return fail(error,"draw-null-stage");const auto ordinal=static_cast<uint32_t>(stage->key().stage);
        if(ordinal>1||(seen&(1u<<ordinal)))return fail(error,"draw-duplicate-or-unsupported-stage");seen|=1u<<ordinal;
        const auto* key=std::get_if<AuthoredTranslatorFixtureKey>(&stage->key().source);
        const char* name=ordinal?"authored_collision_fs":"authored_vs_position";
        const char* pin=ordinal?"2749eda1f3c5d492b3859fb4ee5f6ff5a2d492d060405fc5252cb34b33153a38":"195a1f28ef3a38bfa113816781953a0c59fd504592245f84696f58586f0878e2";
        const auto& profile=stage->profile();
        if(!key||key->fixture_name!=name||!digest_is(stage->file_sha256(),pin)||
           !digest_is(stage->key().profile_definition_sha256,"6c8fa3cd302ee1eb94989728d22969dd8e49361a0c236844ec03a06b09dcabad")||
           profile.minimum_api!=0x400000||profile.spirv_version!=0x10000||profile.entry!="main"||profile.required_features||!profile.required_extensions.empty()||profile.stage_mask!=(1u<<ordinal))return fail(error,"draw-unrecognized-exact-authored-contract");
        if(stage->descriptors().size()!=(ordinal?2u:1u)||stage->semantics().size()!=(ordinal?2u:1u))return fail(error,"draw-descriptor-coverage");
        for(size_t i=0;i<stage->descriptors().size();++i){const auto& d=stage->descriptors()[i];const auto& semantic=stage->semantics()[i];
            if(d.type!=ShaderDescriptorType::UniformBuffer||d.set||d.binding!=ordinal*4096+i||d.count!=1||d.array_rank||d.access!=1||d.stage_mask!=(1u<<ordinal)||d.semantic_first!=i||d.semantic_count!=1||semantic.descriptor_index!=i||semantic.component||semantic.array_first||semantic.count!=1||semantic.stride||semantic.driver_count)return fail(error,"draw-unsupported-physical-binding");
            if(i==0){if(d.minimum_buffer_bytes!=1380||semantic.kind!=1||semantic.encoding||semantic.rule!="nvn-support-static-v1"||semantic.fill.size()!=1||semantic.fill[0].offset||semantic.fill[0].bytes.size()!=1380||std::any_of(semantic.fill[0].bytes.begin(),semantic.fill[0].bytes.end(),[](uint8_t byte){return byte!=0;}))return fail(error,"draw-support-fill-contract");}
            else if(d.minimum_buffer_bytes!=65536||semantic.kind!=4||semantic.cb_slot!=4||semantic.nvn_slot!=1||semantic.encoding!=3||semantic.source_offset||semantic.source_size!=65536||!semantic.fill.empty()||semantic.rule!="nvn-ubo-slot-v1")return fail(error,"draw-fragment-ubo-contract");
        }
    }
    return seen==3;
}
bool check_draw_raster_state(const DrawState& state,std::string* error){
    if(state.color.blend_en||state.color.logic_op!=NVN_LOGIC_OP_COPY||state.color.alpha_func!=NVN_ALPHA_FUNC_ALWAYS||(state.channels.mask&15)!=15||state.multisample.enable>1||state.multisample.a2c||state.multisample.a2c_dither||state.multisample.samples>1||state.multisample.raster_samples>1||state.multisample.cov_mod||state.multisample.cov2color_en||state.multisample.cov2color_out||state.multisample.sl_en||state.multisample.sl_grid||state.polygon.cull!=NVN_FACE_NONE||state.polygon.mode!=NVN_POLYGON_MODE_FILL||state.polygon.offset_en||state.depth.dt||state.depth.st)return fail(error,"draw-unsupported-fixed-function-state");
    return true;
}
bool prepare_draw(std::shared_ptr<const ResolvedProgram> program,std::shared_ptr<const VkGraphicsProgram> executable,
    const DrawState& state,const DrawCall& call,const std::vector<SubmitPool>& pools,const DrawDeviceContract& device,
    std::shared_ptr<const PreparedDraw>* out,std::string* error){
    std::shared_ptr<const PreparedDraw> prior;if(out)prior.swap(*out);
    if(!out||!program||!check_draw_program(*program,error)||!check_shader_program_device(*program,device.shader,error))return false;
    if(!device.rgba8_attachment||!device.float4_vertex||device.vertex_attributes<1||device.vertex_bindings<1||device.vertex_stride<16)return fail(error,"draw-device-format-or-vertex-limit");
    if(!state.target||!state.viewport_set||!state.scissor_set||state.target->d.target!=1||state.target->d.format!=NVN_FORMAT_RGBA8||state.target->d.samples>1||!state.target->d.width||!state.target->d.height||state.target->d.width>device.framebuffer[0]||state.target->d.height>device.framebuffer[1])return fail(error,"draw-invalid-render-target");
    const bool textured_original=original_sampled_program(*program);const bool original=original_program(*program)||textured_original;const uint32_t stride=textured_original?48:original?32:16;
    if(original&&(device.vertex_attributes<2||device.vertex_stride<32||device.vertex_attribute_offset<16))return fail(error,"original-draw-device-vertex-limits");
    va_st attribute{};std::memcpy(&attribute,&state.attribute,4);
    if(attribute.fmt!=NVN_FORMAT_RGBA32F||attribute.offset||attribute.stream||state.stream.stride!=stride||state.stream.divisor)return fail(error,"draw-unsupported-vertex-format-stride-divisor");
    if(original){va_st second{};std::memcpy(&second,&state.attribute1,4);if(!state.attribute1_set||second.fmt!=NVN_FORMAT_RGBA32F||second.offset!=16||second.stream)return fail(error,"original-draw-second-attribute");}
    else if(state.attribute1_set)return fail(error,"draw-unexpected-second-attribute");
    if(textured_original){va_st third{};std::memcpy(&third,&state.attribute2,4);if(device.vertex_attributes<3||device.vertex_stride<48||device.vertex_attribute_offset<32||!state.attribute2_set||third.fmt!=NVN_FORMAT_RGBA32F||third.offset!=32||third.stream)return fail(error,"original-sampled-third-attribute");}
    else if(state.attribute2_set)return fail(error,"draw-unexpected-third-attribute");
    if(!check_draw_raster_state(state,error))return false;
    const auto& vp=state.viewport;for(float value:vp)if(!std::isfinite(value))return fail(error,"draw-nonfinite-viewport");
    if(vp[0]<0||vp[1]<0||vp[2]<=0||vp[3]<=0||vp[2]>device.viewport[0]||vp[3]>device.viewport[1]||double(vp[0])+vp[2]>state.target->d.width||double(vp[1])+vp[3]>state.target->d.height||vp[0]<device.viewport_bounds[0]||vp[1]<device.viewport_bounds[0]||double(vp[0])+vp[2]>device.viewport_bounds[1]||double(vp[1])+vp[3]>device.viewport_bounds[1]||state.depth_near!=0||state.depth_far!=1)return fail(error,"draw-viewport-depth-range");
    const auto& sc=state.scissor;if(sc.x<0||sc.y<0||sc.w<0||sc.h<0||uint64_t(sc.x)+uint64_t(sc.w)>state.target->d.width||uint64_t(sc.y)+uint64_t(sc.h)>state.target->d.height)return fail(error,"draw-scissor-range");
    if(call.primitive!=NVN_DRAW_PRIMITIVE_TRIANGLES||call.count<0||call.first<0||call.instances!=1||call.base_instance<0||(call.indexed&&call.index_type!=NVN_INDEX_TYPE_UNSIGNED_SHORT)||(!call.indexed&&(call.base_vertex||call.base_instance||call.index_address)))return fail(error,"draw-unsupported-command-shape");
    const bool sampled=sampled_program(*program)||textured_original;
    if(sampled){if(!device.rgba8_sampled||!state.sampled||(!textured_original&&!state.ubos.empty())||!check_sampled_resource(*state.sampled,device,error))return fail(error,"draw-missing-or-invalid-sampled-binding");}
    auto stage_uniform=[&](uint32_t stage)->const p_bind_buf*{for(const auto& bound:state.ubos)if(bound.stage==int32_t(stage)&&bound.index==0)return &bound;return nullptr;};
    if(textured_original&&(state.ubos.size()!=2||!stage_uniform(0)||!stage_uniform(1)))return fail(error,"original-sampled-two-stage-ubos");
    else if(!sampled&&(state.sampled||state.ubos.size()!=1||state.ubos[0].stage!=(original?0:1)||state.ubos[0].index!=(original?0:1)))return fail(error,"draw-missing-or-extra-uniform-binding");
    try{
        auto prepared=std::shared_ptr<PreparedDraw>(new PreparedDraw);prepared->program_=std::move(program);prepared->executable_=std::move(executable);prepared->state_=state;prepared->call_=call;
        ComputeSpan target;if(!resolve(pools,reinterpret_cast<uint64_t>(state.target->mem),state.target->L.size,&target,error)||!resolve(pools,state.vertex.address,state.vertex.size,&prepared->vertex_,error))return false;
        if(state.vertex.size<stride||(state.vertex.address&3)||(prepared->vertex_.offset&3))return fail(error,"draw-vertex-buffer-alignment");
        uint64_t first=uint32_t(call.first),last=first;
        if(call.indexed){
            const uint64_t size=std::max<uint64_t>(2,uint64_t(uint32_t(call.count))*2);
            if(call.count>1048576||!resolve(pools,call.index_address,size,&prepared->indices_,error)||(call.index_address&1)||(prepared->indices_.offset&1))return fail(error,"draw-index-range-alignment-budget");
            first=UINT64_MAX;last=0;const auto* data=pools[prepared->indices_.pool].initial.data()+prepared->indices_.offset;
            for(int32_t i=0;i<call.count;++i){const int64_t index=int64_t(uint16_t(data[2*i])|uint16_t(data[2*i+1])<<8)+int64_t(call.base_vertex);if(index<0||uint64_t(index)>UINT32_MAX)return fail(error,"draw-negative-overflowing-effective-index");first=std::min(first,uint64_t(index));last=std::max(last,uint64_t(index));}
            auto indices=prepared->indices_;indices.size=uint64_t(uint32_t(call.count))*2;if(indices.size)prepared->reads_.push_back(indices);
        }else if(call.count)last=first+uint32_t(call.count)-1;
        if(call.count){if(last>UINT32_MAX||last>(UINT64_MAX-stride)/stride||last*stride+stride>state.vertex.size)return fail(error,"draw-vertex-fetch-outside-binding");auto read=prepared->vertex_;read.offset+=first*stride;read.size=(last-first)*stride+stride;prepared->reads_.push_back(read);}
        for(const auto& stage:prepared->program_->stages())for(size_t i=0;i<stage->descriptors().size();++i){const auto& descriptor=stage->descriptors()[i];const uint32_t ordinal=static_cast<uint32_t>(stage->key().stage);
            if(descriptor.type==ShaderDescriptorType::CombinedImageSampler)continue;
            if(i==0)prepared->descriptors_.push_back({descriptor.binding,ordinal,{SIZE_MAX,0,1380},stage->semantics()[i].fill[0].bytes});
            else{const auto& bound=textured_original?*stage_uniform(ordinal):state.ubos[0];ComputeSpan span;const auto& limits=device.shader.limits;
                if(!bound.size||bound.size<65536||bound.size>limits.uniform_buffer_range||!limits.uniform_offset_alignment||!descriptor.address_alignment||bound.addr%descriptor.address_alignment||!resolve(pools,bound.addr,bound.size,&span,error)||span.offset%limits.uniform_offset_alignment)return fail(error,"draw-ubo-range-alignment");
                prepared->descriptors_.push_back({descriptor.binding,ordinal,span,{}});auto read=span;read.size=textured_original?(ordinal?28:64):original?64:16;prepared->reads_.push_back(read);
            }
        }
        if(sampled){if(!resolve(pools,reinterpret_cast<uint64_t>(state.sampled->texture.mem),state.sampled->texture.L.size,&prepared->sampled_span_,error))return false;prepared->reads_.push_back(prepared->sampled_span_);}
        for(const auto& read:prepared->reads_)if(overlap(target,read))return fail(error,"draw-render-target-buffer-read-alias");
        *out=std::move(prepared);if(error)error->clear();return true;
    }catch(const std::bad_alloc&){return fail(error,"draw-preparation-allocation");}
}
}
