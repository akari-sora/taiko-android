#pragma once
#include "compute_bindings.h"
namespace dm_android {
class VkGraphicsProgram;
struct SubmitSampledResource;
struct DrawDeviceContract {
    ShaderDeviceContract shader;
    uint32_t vertex_attributes=0,vertex_bindings=0,vertex_stride=0,vertex_attribute_offset=0;
    std::array<uint32_t,2> framebuffer{},viewport{};
    std::array<float,2> viewport_bounds{};
    bool rgba8_attachment=false,float4_vertex=false,rgba8_sampled=false;
    std::array<uint32_t,2> sampled_extent{};
};
struct DrawState {
    const tex_t* target=nullptr;
    std::shared_ptr<const SubmitSampledResource> sampled;
    bool viewport_set=false,scissor_set=false;
    std::array<float,4> viewport{};
    p_scissor scissor{};
    float depth_near=0,depth_far=1;
    uint32_t attribute=0,attribute1=0,attribute2=0;
    bool attribute1_set=false,attribute2_set=false;
    vs_st stream{};
    NVNbufferRange vertex{};
    std::vector<p_bind_buf> ubos;
    color_st color{0,NVN_LOGIC_OP_COPY,NVN_ALPHA_FUNC_ALWAYS};
    chmask_st channels{0xffffffffu};
    blend_st blend{0,NVN_BLEND_FUNC_ONE,NVN_BLEND_FUNC_ZERO,NVN_BLEND_FUNC_ONE,NVN_BLEND_FUNC_ZERO,NVN_BLEND_EQUATION_ADD,NVN_BLEND_EQUATION_ADD};
    ms_st multisample{1,0,0,0,0,0,0,0,0,0};
    poly_st polygon{NVN_FACE_NONE,NVN_FRONT_FACE_CCW,NVN_POLYGON_MODE_FILL,0};
    ds_st depth{0,0,NVN_DEPTH_FUNC_LESS,0,NVN_STENCIL_FUNC_ALWAYS,NVN_STENCIL_FUNC_ALWAYS,NVN_STENCIL_OP_KEEP,NVN_STENCIL_OP_KEEP,NVN_STENCIL_OP_KEEP,NVN_STENCIL_OP_KEEP,NVN_STENCIL_OP_KEEP,NVN_STENCIL_OP_KEEP};
};
struct DrawCall {
    bool indexed=false;
    int32_t primitive=NVN_DRAW_PRIMITIVE_TRIANGLES,first=0,count=0;
    int32_t index_type=NVN_INDEX_TYPE_UNSIGNED_SHORT,base_vertex=0,base_instance=0,instances=1;
    uint64_t index_address=0;
};
struct DrawDescriptor {
    uint32_t binding=0,stage=0;
    ComputeSpan span;
    std::vector<uint8_t> initial;
};
class PreparedDraw {
public:
    const auto& program() const{return program_;}
    const auto& executable() const{return executable_;}
    const auto& state() const{return state_;}
    const auto& call() const{return call_;}
    const auto& descriptors() const{return descriptors_;}
    const auto& vertex() const{return vertex_;}
    const auto& indices() const{return indices_;}
    const auto& reads() const{return reads_;}
    const auto& sampled_span() const{return sampled_span_;}
    uint64_t owned_bytes() const;
private:
    PreparedDraw()=default;
    std::shared_ptr<const ResolvedProgram> program_;
    std::shared_ptr<const VkGraphicsProgram> executable_;
    DrawState state_;
    DrawCall call_;
    std::vector<DrawDescriptor> descriptors_;
    ComputeSpan vertex_,indices_,sampled_span_;
    std::vector<ComputeSpan> reads_;
    friend bool prepare_draw(std::shared_ptr<const ResolvedProgram>,std::shared_ptr<const VkGraphicsProgram>,const DrawState&,const DrawCall&,const std::vector<SubmitPool>&,const DrawDeviceContract&,std::shared_ptr<const PreparedDraw>*,std::string*);
};
bool check_draw_program(const ResolvedProgram&,std::string*);
bool check_draw_raster_state(const DrawState&,std::string*);
bool prepare_draw(std::shared_ptr<const ResolvedProgram>,std::shared_ptr<const VkGraphicsProgram>,
    const DrawState&,const DrawCall&,const std::vector<SubmitPool>&,const DrawDeviceContract&,
    std::shared_ptr<const PreparedDraw>*,std::string*);
}
