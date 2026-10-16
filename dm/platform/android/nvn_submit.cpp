#include "nvn_submit.h"
#include "../../gfx/vulkan/compute_bindings.h"
#include "../../gfx/vulkan/draw_bindings.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace dm_android {
namespace {
bool reject(std::string* e,const char* why) { if(e)*e=why;return false; }
size_t aligned(size_t n) { return (n+7)&~size_t(7); }
class Preparation {
public:
    const SubmitReader& reader;const SubmitLimits& limit;std::string* error;uint32_t* failure_operation;
    std::shared_ptr<PreparedSubmit> plan=std::make_shared<PreparedSubmit>();
    size_t bytes=0,operations=0;std::unordered_set<uint64_t> path;
    size_t bound_program=SIZE_MAX,bound_graphics=SIZE_MAX;
    DrawState draw_state{};
    dpool_t texture_pool{},sampler_pool{};
    std::array<uint64_t,128> texture_handles{};
    std::array<bool,128> texture_bound{};uint64_t sampler_handle=0;bool sampler_bound=false;
    std::vector<p_bind_buf> ubos{},ssbos{};
    // Transient preparation facts, bounded by pools_bytes. The GPU's initial
    // snapshot stays untouched. As in engine validation, only literal writes
    // establish new CPU-known bytes; copies and GPU writes make them unknown.
    std::vector<SubmitPool> facts{};
    std::vector<std::pair<uint64_t,uint64_t>> unknown{};
    const tex_t* render_target=nullptr;
    uint64_t copy_stride=0;
    void current(uint32_t opcode) {if(failure_operation)*failure_operation=opcode;}
    bool copy(uint64_t at,void* dst,size_t n) {
        if(!at || !n || at>UINT64_MAX-n)return reject(error,"invalid command range");
        if(reader.copy && reader.copy(at,dst,n))return true;
        if(reader.retain_recorder) {
            auto retained=reader.retain_recorder(at,n);
            if(retained) { std::memcpy(dst,reinterpret_cast<const void*>(at),n);plan->recorder_segments.push_back(std::move(retained));return true; }
        }
        return reject(error,"command/object range is not owned readable memory");
    }
    bool range(uint64_t a,uint64_t n) {
        if(!n || n>UINT64_MAX-a)return reject(error,"empty or overflowing buffer range");
        size_t matches=0;
        for(const auto& p:plan->pools)if(a>=p.address && a-p.address<=p.initial.size() && n<=p.initial.size()-(a-p.address))++matches;
        return matches==1 || reject(error,"buffer range has no unique live pool");
    }
    bool texture(const tex_t** pointer) {
        if(!*pointer)return reject(error,"missing texture");
        auto snapshot=std::make_unique<tex_t>();
        if(!copy(reinterpret_cast<uint64_t>(*pointer),snapshot.get(),sizeof(tex_t)))return false;
        if(snapshot->magic!=MAGIC('T','E','X',0) || !snapshot->serial ||
           !reader.texture_live || !reader.texture_live(snapshot->serial))
            return reject(error,"texture has invalid magic or retired serial");
        if(!range(reinterpret_cast<uint64_t>(snapshot->mem),snapshot->L.size))return false;
        // pool is not dereferenced by the backend; use immutable address/size
        // resolution. A by-value texture alias retains its original serial.
        snapshot->pool=nullptr;*pointer=snapshot.get();plan->textures.push_back(std::move(snapshot));return true;
    }
    template<class T> bool decode(SubmitOp& op,T* p) {
        if(op.payload.size()!=aligned(sizeof(T)))return reject(error,"record payload size mismatch");
        std::memcpy(p,op.payload.data(),sizeof(T));return true;
    }
    template<class T> void encode(SubmitOp& op,const T& p) {std::memcpy(op.payload.data(),&p,sizeof(T));}
    const std::vector<SubmitPool>& temporal_pools() {
        if(facts.empty())facts=plan->pools;
        return facts;
    }
    bool poison(uint64_t address,uint64_t size) {
        if(!reader.prepare_compute&&!reader.prepare_draw)return true;
        if(!range(address,size))return false;
        if(unknown.size()>=limit.operations)return reject(error,"temporal range budget exceeded");
        unknown.emplace_back(address,address+size);return true;
    }
    void literal(uint64_t address,const uint8_t* data,size_t size) {
        if(!reader.prepare_compute&&!reader.prepare_draw)return;
        temporal_pools();
        for(auto& pool:facts)if(address>=pool.address && address-pool.address<=pool.initial.size() && size<=pool.initial.size()-(address-pool.address))
            std::memcpy(pool.initial.data()+(address-pool.address),data,size);
        const uint64_t end=address+size;
        std::vector<std::pair<uint64_t,uint64_t>> remaining;
        for(const auto& r:unknown) {
            if(end<=r.first || r.second<=address){remaining.push_back(r);continue;}
            if(r.first<address)remaining.emplace_back(r.first,address);
            if(end<r.second)remaining.emplace_back(end,r.second);
        }
        unknown=std::move(remaining);
    }
    bool binding(SubmitOp& op,std::vector<p_bind_buf>& bindings) {
        p_bind_buf p{};if(!decode(op,&p))return false;
        if((p.stage!=0&&p.stage!=1&&p.stage!=5) || p.index<0 || p.index>=16)return reject(error,"compute binding stage or slot unsupported");
        if((!p.addr)!=(!p.size) || p.size>UINT64_MAX-p.addr)return reject(error,"invalid compute binding range");
        auto found=std::find_if(bindings.begin(),bindings.end(),[&](const auto& old){return old.stage==p.stage&&old.index==p.index;});
        if(found!=bindings.end())bindings.erase(found);
        if(p.size)bindings.push_back(p);
        std::sort(bindings.begin(),bindings.end(),[](const auto& a,const auto& b){return a.stage<b.stage||(a.stage==b.stage&&a.index<b.index);});
        return true;
    }
    bool operation(uint32_t code,std::vector<uint8_t> data,uint64_t payload_address) {
        SubmitOp op{code,std::move(data)};
        switch(code) {
        case OP_SET_TEX_POOL:case OP_SET_SAMP_POOL: {
            p_set_pool_owned value{};if(!decode(op,&value))return false;
            if(payload_address>UINT64_MAX- offsetof(p_set_pool_owned,snapshot) ||
               reinterpret_cast<uint64_t>(value.bind.pool)!=payload_address+offsetof(p_set_pool_owned,snapshot) ||
               !value.snapshot.pool||!value.snapshot.serial||value.snapshot.off<0||value.snapshot.n<1||value.snapshot.n>64)
                return reject(error,"descriptor pool record lacks owned identity");
            if(code==OP_SET_TEX_POOL)texture_pool=value.snapshot;else sampler_pool=value.snapshot;
            return true;
        }
        case OP_BIND_TEX:case OP_BIND_SAMP: {
            const size_t prefix=offsetof(p_bind_handles,h);
            if(op.payload.size()<prefix)return reject(error,"short sampled binding record");
            p_bind_handles value{};std::memcpy(&value,op.payload.data(),prefix);
            if(value.stage!=1||value.first<0||value.first>=(code==OP_BIND_TEX?128:1)||value.n!=1||op.payload.size()!=aligned(prefix+sizeof(uint64_t)))
                return reject(error,"sampled binding requires one bounded FS texture or sampler slot");
            std::memcpy(&value.h[0],op.payload.data()+prefix,sizeof(uint64_t));
            if(code==OP_BIND_TEX){if(value.h[0]&~uint64_t(0xfffff))return reject(error,"texture handle has unused bits");texture_handles[value.first]=value.h[0];texture_bound[value.first]=true;}
            else {if(value.h[0]&~uint64_t(0xfff00000))return reject(error,"sampler handle has unused bits");sampler_handle=value.h[0];sampler_bound=true;}
            return true;
        }
        case OP_BIND_PROGRAM: {
            if(op.payload.size()!=aligned(sizeof(p_bind_program)+sizeof(prog_t)))
                return reject(error,"program bind lacks recorded identity");
            p_bind_program p{};std::memcpy(&p,op.payload.data(),sizeof(p));
            if(p.stages!=32&&p.stages!=3)return reject(error,"program bind stage unsupported");
            if(payload_address>UINT64_MAX-sizeof(p_bind_program) ||
               reinterpret_cast<uint64_t>(p.prog)!=payload_address+sizeof(p_bind_program))
                return reject(error,"program snapshot address mismatches record");
            prog_t snapshot{};
            std::memcpy(&snapshot,op.payload.data()+sizeof(p),sizeof(snapshot));
            if(snapshot.magic!=MAGIC('P','R','O','G') || snapshot.nstage!=(p.stages==32?1u:2u) || !snapshot.serial)
                return reject(error,"program bind is empty or invalid");
            if(!reader.acquire_program)return reject(error,"compute program acquisition unavailable");
            SubmitProgram owned;
            if(!reader.acquire_program(snapshot,uint32_t(p.stages),&owned,error))return false;
            if(!owned.lease || !owned.resolved || (p.stages==32?!owned.executable:!owned.graphics_executable) || !owned.generation ||
               std::memcmp(&owned.snapshot,&snapshot,sizeof(snapshot)) ||
               owned.resolved->generation()!=owned.generation ||
               owned.resolved->serial()!=snapshot.serial || owned.resolved->stage_mask()!=uint32_t(p.stages))
                return reject(error,"acquired program identity mismatch");
            if(p.stages==32)bound_program=plan->programs.size();else bound_graphics=plan->programs.size();plan->programs.push_back(std::move(owned));return true;
        }
        case OP_VIEWPORTS: {
            p_viewports value{};if(!decode(op,&value)||value.first||value.n!=1)return reject(error,"draw requires one viewport at slot0");
            std::copy(value.v[0],value.v[0]+4,draw_state.viewport.begin());draw_state.viewport_set=true;return true;
        }
        case OP_SCISSOR: {p_scissor value{};if(!decode(op,&value)||value.x<0||value.y<0||value.w<0||value.h<0)return reject(error,"invalid draw scissor");draw_state.scissor=value;draw_state.scissor_set=true;return true;}
        case OP_DEPTH_RANGE: {p_depth_range value{};if(!decode(op,&value)||value.n!=0||value.f!=1)return reject(error,"unsupported draw depth range");draw_state.depth_near=value.n;draw_state.depth_far=value.f;return true;}
        case OP_BIND_STATE: {
            p_bind_state value{};if(!decode(op,&value))return false;
            switch(value.kind){case 0:std::memcpy(&draw_state.blend,value.bytes,sizeof(blend_st));break;case 1:std::memcpy(&draw_state.color,value.bytes,sizeof(color_st));break;case 2:std::memcpy(&draw_state.channels,value.bytes,sizeof(chmask_st));break;case 3:std::memcpy(&draw_state.multisample,value.bytes,sizeof(ms_st));break;case 4:std::memcpy(&draw_state.polygon,value.bytes,sizeof(poly_st));break;case 5:std::memcpy(&draw_state.depth,value.bytes,sizeof(ds_st));break;default:return reject(error,"unknown draw state kind");}
            return check_draw_raster_state(draw_state,error);
        }
        case OP_BIND_VATTR:case OP_BIND_VSTREAM:case OP_BIND_VBUF: {
            if(op.payload.size()<8)return reject(error,"short variable vertex record");int32_t first=0,n=0;std::memcpy(&first,op.payload.data(),4);std::memcpy(&n,op.payload.data()+4,4);
            const size_t item=code==OP_BIND_VATTR?4:code==OP_BIND_VSTREAM?sizeof(vs_st):sizeof(NVNbufferRange);
            if(code==OP_BIND_VATTR) {
                if(first<0||first>2||n<1||n>3-first||op.payload.size()!=aligned(8+item*size_t(n)))return reject(error,"unsupported or malformed vertex attributes");
                if(first==0)std::memcpy(&draw_state.attribute,op.payload.data()+8,4);
                if(first<=1&&first+n>=2){std::memcpy(&draw_state.attribute1,op.payload.data()+8+4*size_t(1-first),4);draw_state.attribute1_set=true;}
                if(first+n==3){std::memcpy(&draw_state.attribute2,op.payload.data()+8+4*size_t(2-first),4);draw_state.attribute2_set=true;}
            }
            else if(first!=0||n!=1||op.payload.size()!=aligned(8+item))return reject(error,"unsupported or malformed variable vertex record");
            else if(code==OP_BIND_VSTREAM)std::memcpy(&draw_state.stream,op.payload.data()+8,sizeof(vs_st));
            else std::memcpy(&draw_state.vertex,op.payload.data()+8,sizeof(NVNbufferRange));return true;
        }
        case OP_DRAW:case OP_DRAW_IDX: {
            // Bound owned support fills and immutable draws during preparation,
            // before another builder allocation. Match the engine graph cap.
            if(plan->draws.size()>=4096)return reject(error,"draw preparation count budget exceeded");
            if(bound_graphics>=plan->programs.size()||!reader.prepare_draw)return reject(error,"draw has no acquired graphics program or preparation callback");
            DrawCall call;
            if(code==OP_DRAW){p_draw value{};if(!decode(op,&value))return false;call.primitive=value.prim;call.first=value.first;call.count=value.count;}
            else {p_draw_idx value{};if(!decode(op,&value))return false;call.indexed=true;call.primitive=value.prim;call.index_type=value.itype;call.count=value.count;call.base_vertex=value.base_vertex;call.base_instance=value.base_instance;call.instances=value.instances;call.index_address=value.ibuf;}
            if(call.count<0)return reject(error,"negative draw count");
            if(call.indexed&&call.count){const uint64_t bytes=uint64_t(uint32_t(call.count))*2;if(bytes>UINT64_MAX-call.index_address)return reject(error,"draw index byte overflow");for(const auto& range:unknown)if(call.index_address<range.second&&range.first<call.index_address+bytes)return reject(error,"draw indices overwritten by unknown GPU write");}
            DrawState state=draw_state;state.target=render_target;for(const auto& uniform:ubos)if(uniform.stage==0||uniform.stage==1)state.ubos.push_back(uniform);
            const auto& program=plan->programs[bound_graphics];
            uint32_t required_texture_slot=0;size_t sampled_semantics=0;
            if(program.resolved)for(const auto& stage:program.resolved->stages())for(const auto& semantic:stage->semantics())if(semantic.kind==7){
                if(stage->key().stage!=ShaderStage::Fragment||semantic.count!=1||semantic.nvn_slot>=texture_bound.size())return reject(error,"draw sampled slot outside bounded FS domain");
                required_texture_slot=semantic.nvn_slot;++sampled_semantics;
            }
            if(sampled_semantics>1)return reject(error,"draw requires one exact sampled texture");
            if(std::any_of(texture_bound.begin(),texture_bound.end(),[](bool bound){return bound;})||sampler_bound||sampled_semantics) {
                if(!texture_bound[required_texture_slot]||!sampler_bound||!reader.acquire_sampled)return reject(error,"sampled image/sampler binding is incomplete");
                if(!reader.acquire_sampled(texture_pool,sampler_pool,texture_handles[required_texture_slot],sampler_handle,&state.sampled,error))return false;
                if(!state.sampled||!state.sampled->lease||!state.sampled->generation||!state.sampled->binding_epoch||state.sampled->texture.pool)
                    return reject(error,"sampled acquisition lacks immutable owner");
                const auto address=reinterpret_cast<uint64_t>(state.sampled->texture.mem),size=state.sampled->texture.L.size;
                if(!range(address,size))return false;
                if(render_target&&address<reinterpret_cast<uint64_t>(render_target->mem)+render_target->L.size&&reinterpret_cast<uint64_t>(render_target->mem)<address+size)
                    return reject(error,"sampled image aliases render target");
                for(const auto& written:unknown)if(address<written.second&&written.first<address+size)return reject(error,"sampled source follows an unknown GPU write");
                for(const auto& buffer:ssbos)if(buffer.size&&address<buffer.addr+buffer.size&&buffer.addr<address+size)return reject(error,"sampled image aliases a read/write buffer binding");
            }
            std::shared_ptr<const PreparedDraw> draw;
            if(state.sampled&&state.sampled->generation!=program.generation)return reject(error,"sampled resource generation differs from graphics program");
            if(!reader.prepare_draw(program,state,call,temporal_pools(),&draw,error))return false;
            if(!draw||draw->program()!=program.resolved||draw->executable()!=program.graphics_executable||draw->state().target!=state.target||draw->state().sampled!=state.sampled)return reject(error,"prepared draw identity mismatch");
            if(call.count&&render_target&&!poison(reinterpret_cast<uint64_t>(render_target->mem),render_target->L.size))return false;
            if(plan->draws.size()>=UINT32_MAX)return reject(error,"draw index overflow");op.draw_index=uint32_t(plan->draws.size());plan->draws.push_back(std::move(draw));op.payload.clear();break;
        }
        case OP_BIND_UBO:return binding(op,ubos);
        case OP_BIND_SSBO:return binding(op,ssbos);
        case OP_DISPATCH: {
            p_dispatch p{};if(!decode(op,&p))return false;
            if(bound_program>=plan->programs.size())return reject(error,"dispatch has no acquired compute program");
            if(p.x<0 || p.y<0 || p.z<0)return reject(error,"negative compute group count");
            if(!reader.prepare_compute)return reject(error,"compute preparation unavailable");
            const auto groups=std::array<uint32_t,3>{uint32_t(p.x),uint32_t(p.y),uint32_t(p.z)};
            const auto& program=plan->programs[bound_program];
            for(const auto& ubo:ubos)if(ubo.stage==5&&ubo.index==0 && ubo.size>=4)
                for(const auto& r:unknown)if(ubo.addr<r.second && r.first<ubo.addr+4)
                    return reject(error,"compute count overwritten by unknown GPU write");
            std::shared_ptr<const PreparedComputeDispatch> dispatch;
            std::vector<p_bind_buf> compute_ubos,compute_ssbos;for(const auto& binding:ubos)if(binding.stage==5)compute_ubos.push_back(binding);for(const auto& binding:ssbos)if(binding.stage==5)compute_ssbos.push_back(binding);
            if(!reader.prepare_compute(program,compute_ubos,compute_ssbos,groups,temporal_pools(),&dispatch,error))return false;
            if(!dispatch || dispatch->program()!=program.resolved || dispatch->executable()!=program.executable || dispatch->groups()!=groups)
                return reject(error,"prepared dispatch identity mismatch");
            for(const auto& write:dispatch->writes()) {
                if(write.pool>=plan->pools.size())return reject(error,"invalid compute write pool");
                const auto& pool=plan->pools[write.pool];
                if(write.offset>pool.initial.size() || write.size>pool.initial.size()-write.offset)
                    return reject(error,"invalid compute write range");
                if(!poison(pool.address+write.offset,write.size))return false;
            }
            if(plan->computes.size()>=UINT32_MAX)return reject(error,"compute index overflow");
            op.compute_index=uint32_t(plan->computes.size());plan->computes.push_back(std::move(dispatch));
            // Replay consumes only the checked immutable index. No caller PC,
            // raw program address or guest binding payload survives this point.
            op.payload.clear();break;
        }
        case OP_BARRIER: if(op.payload.size()!=8)return reject(error,"barrier size mismatch");break;
        case OP_COPY_STRIDE: {
            if(op.payload.size()!=8)return reject(error,"stride size mismatch");
            int32_t stride=0;std::memcpy(&stride,op.payload.data(),4);
            if(stride<0)return reject(error,"negative copy stride");
            copy_stride=uint64_t(stride);break;
        }
        case OP_COPY_B2B: {
            if(op.payload.size()!=24)return reject(error,"copy size mismatch");
            uint64_t p[3];std::memcpy(p,op.payload.data(),24);
            if(!range(p[0],p[2])||!range(p[1],p[2]))return false;
            if(!poison(p[1],p[2]))return false;
            break;
        }
        case OP_UPDATE_UB: {
            if(op.payload.size()<16)return reject(error,"short uniform update");
            uint64_t p[2];std::memcpy(p,op.payload.data(),16);
            if(p[1]>limit.bytes || p[1]>SIZE_MAX-23 || op.payload.size()!=aligned(16+size_t(p[1])))return reject(error,"uniform update size mismatch");
            if(!range(p[0],p[1]))return false;
            literal(p[0],op.payload.data()+16,size_t(p[1]));
            break;
        }
        case OP_SIGNAL_EVENT: {
            if(op.payload.size()!=16)return reject(error,"event size mismatch");
            SubmitEvent e;std::memcpy(&e.address,op.payload.data(),8);std::memcpy(&e.mode,op.payload.data()+8,4);std::memcpy(&e.value,op.payload.data()+12,4);
            if((e.address&3)||e.mode>1)return reject(error,"invalid event mode/alignment");
            uint32_t value;if(!copy(e.address,&value,sizeof(value)))return false;
            plan->events.push_back(e);return true;
        }
        case OP_SET_RT: {
            p_set_rt p{};if(!decode(op,&p))return false;
            if(p.n!=1 || p.depth || p.has_dview || p.has_cview[0])return reject(error,"render target/view unsupported");
            if(!texture(&p.color[0]))return false;
            render_target=p.color[0];
            encode(op,p);break;
        }
        case OP_CLEAR_COLOR: {p_clear_color p{};if(!decode(op,&p))return false;
            if(render_target && !poison(reinterpret_cast<uint64_t>(render_target->mem),render_target->L.size))return false;
            break;}
        case OP_COPY_B2T: {
            p_copy_b2t p{};if(!decode(op,&p)||!texture(&p.tex))return false;
            if(!poison(reinterpret_cast<uint64_t>(p.tex->mem),p.tex->L.size))return false;
            encode(op,p);break;
        }
        case OP_COPY_T2B: {
            p_copy_b2t p{};if(!decode(op,&p)||!texture(&p.tex))return false;
            if(reader.prepare_compute||reader.prepare_draw) {
                if(p.r.width<=0 || p.r.height<=0 || p.r.depth!=1)return reject(error,"invalid temporal texture region");
                const uint64_t width=uint64_t(p.r.width)*4,row=copy_stride?copy_stride:width;
                if(row<width || uint64_t(p.r.height)>limit.operations)return reject(error,"temporal texture range budget exceeded");
                for(int y=0;y<p.r.height;++y) {
                    if(uint64_t(y)>UINT64_MAX/row || uint64_t(y)*row>UINT64_MAX-p.src ||
                       !poison(p.src+uint64_t(y)*row,width))return false;
                }
            }
            encode(op,p);break;
        }
        default:return reject(error,"operation unsupported by the Android graphics capability set");
        }
        plan->ops.push_back(std::move(op));return true;
    }
    bool graph(uint64_t handle,size_t depth) {
        current(0);
        if(depth>=limit.depth || (handle&7))return reject(error,"command depth or handle alignment");
        const size_t marker=path.size();std::vector<uint64_t> entered;
        struct Cleanup {std::unordered_set<uint64_t>& path;std::vector<uint64_t>& entered;~Cleanup(){for(auto a:entered)path.erase(a);}} cleanup{path,entered};
        (void)marker;
        uint64_t at=handle;bool first=true;
        for(;;) {
            current(0);
            if(!path.insert(at).second)return reject(error,"recursive command cycle");
            entered.push_back(at);
            op_hdr header{};if(!copy(at,&header,sizeof(header)))return false;
            current(header.op);
            if(header.size<8 || (header.size&7) || header.size>limit.bytes || bytes>limit.bytes-header.size || ++operations>limit.operations)return reject(error,"record size or graph budget exceeded");
            bytes+=header.size;
            if(at>UINT64_MAX-header.size)return reject(error,"command pointer overflow");
            if(first) {if(header.op!=OP_BEGIN || header.size!=8)return reject(error,"graph must start with BEGIN");first=false;}
            else if(header.op==OP_BEGIN)return reject(error,"unexpected BEGIN");
            if(header.op==OP_END) return header.size==8 || reject(error,"END size mismatch");
            std::vector<uint8_t> payload(header.size-8);
            if(!payload.empty()&&!copy(at+8,payload.data(),payload.size()))return false;
            if(header.op==OP_CALL || header.op==OP_JUMP) {
                if(header.size!=16)return reject(error,"branch size mismatch");
                uint64_t target;std::memcpy(&target,payload.data(),8);
                if(target&7)return reject(error,"branch alignment");
                if(header.op==OP_CALL) {if(!graph(target,depth+1))return false;current(header.op);}
                else {at=target;continue;}
            } else if(header.op!=OP_BEGIN && !operation(header.op,std::move(payload),at+8))return false;
            at+=header.size;
        }
    }
};
}
bool prepare_submit(const uint64_t* handles,size_t count,const SubmitReader& reader,
                    std::vector<SubmitPool> pools,std::shared_ptr<PreparedSubmit>* out,
                    std::string* error,const SubmitLimits& limits,uint32_t* failure_operation) {
    if(out)out->reset();
    if(error)error->clear();
    if(failure_operation)*failure_operation=0;
    if(!out || !handles || !count || count>limits.handles || !reader.copy)return reject(error,"invalid submission input");
    try {
        Preparation p{reader,limits,error,failure_operation,std::make_shared<PreparedSubmit>(),0,0,{}};size_t total=0;
        if(count>SIZE_MAX/sizeof(uint64_t))return reject(error,"handle list size overflow");
        std::vector<uint64_t> owned_handles(count);
        if(!reader.copy(reinterpret_cast<uint64_t>(handles),owned_handles.data(),count*sizeof(uint64_t)))
            return reject(error,"handle list is not owned readable memory");
        for(auto& pool:pools) {
            if(!pool.identity || !pool.address || pool.initial.empty() || pool.initial.size()>UINT64_MAX-pool.address || pool.initial.size()>limits.pools_bytes-total)return reject(error,"invalid pool snapshot/budget");
            for(const auto& old:p.plan->pools)if(pool.address<old.address+old.initial.size() && old.address<pool.address+pool.initial.size())return reject(error,"overlapping distinct pools are unsupported");
            total+=pool.initial.size();
            if(!reader.copy(pool.address,pool.initial.data(),pool.initial.size()))return reject(error,"pool snapshot is not owned readable memory");
            p.plan->pools.push_back(std::move(pool));
        }
        for(auto handle:owned_handles)if(!p.graph(handle,0))return false;
        *out=std::move(p.plan);if(failure_operation)*failure_operation=0;return true;
    } catch(const std::bad_alloc&) {return reject(error,"submission snapshot allocation failed");}
}
} // namespace dm_android
