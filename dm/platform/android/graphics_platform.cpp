#include "graphics_platform.h"
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include "kernel_memory_android.h"
#include "shader_compute_catalog.h"
#include "shader_draw_catalog.h"
#include "vi_platform.h"
#include "../../gfx/vulkan/draw_bindings.h"
#include "../../gfx/vulkan/compute_bindings.h"
#include "../../gfx/nvn/nvn_backend.h"
#include "../../gfx/nvn/hle_nvn_core.h"
extern "C" {
#include "../../gfx/tex/nvn_deswizzle.h"
}
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <array>
#include <cstdio>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <tuple>
#include <cmath>

namespace dm_android {
GraphicsLease::~GraphicsLease(){for(auto pin:pins_)dm_android_kernel_gpu_unpin(pin.token);}
bool GraphicsLease::admit(uint64_t address,size_t size,unsigned permissions) {
    if(!valid() || !size || size>UINT64_MAX-address)return false;
    if(retention_.runtime()->process().mapped_range(address,size,permissions))return true;
    for(const auto& pin:pins_)if((pin.permissions&permissions)==permissions && address>=pin.address && address-pin.address<=pin.size && size<=pin.size-(address-pin.address))return true;
    // The owner validates every 4 KiB logical page. Covering page pins avoid a
    // token per tiny command read without broadening logical permissions.
    uint64_t pinned_address=address;size_t pinned_size=size;uint64_t token=0;
    const uint64_t end=address+size;
    if(end<=UINT64_MAX-4095) {
        const uint64_t begin=address&~uint64_t(4095),rounded=(end+4095)&~uint64_t(4095);
        if(rounded-begin<=SIZE_MAX) {
            token=dm_android_kernel_gpu_pin(begin,size_t(rounded-begin),permissions);
            if(token){pinned_address=begin;pinned_size=size_t(rounded-begin);}
        }
    }
    if(!token)token=dm_android_kernel_gpu_pin(address,size,permissions);
    if(!token)return false;
    try{pins_.push_back({token,pinned_address,pinned_size,permissions});}catch(...){dm_android_kernel_gpu_unpin(token);return false;}
    return true;
}
bool GraphicsLease::copy(uint64_t address,void* destination,size_t size) {
    if(!destination || !valid() || !size || size>UINT64_MAX-address)return false;
    if(!admit(address,size,DM_GUEST_READ)) {
        // Only synchronous input snapshots may read the currently executing
        // owned GuestStack. Async destinations still require admit()/retention.
        const auto* state=dm_android_peek_guest_state();
        uintptr_t bottom=0;size_t length=0;
        if(!state || state->user_data!=retention_.runtime() || state->runtime_generation!=generation() ||
           !active_guest_stack_owned_bounds(address,&bottom,&length) ||
           address<bottom || address-bottom>length || size>length-(address-bottom))return false;
    }
    // Mapping permissions/lifetime remain retained by the actual owners.
    std::memcpy(destination,reinterpret_cast<const void*>(address),size);return true;
}
bool GraphicsLease::admit_program_storage(uint64_t address,size_t size,unsigned permissions) {
    if(!valid()||!address||!size||size>UINT64_MAX-address||(permissions&~unsigned(DM_GUEST_READ|DM_GUEST_WRITE)))return false;
    if(admit(address,size,permissions))return true;
    const auto* state=dm_android_peek_guest_state();uintptr_t bottom=0;size_t length=0;
    return state&&state->user_data==retention_.runtime()&&state->runtime_generation==generation()&&
        active_guest_stack_owned_bounds(address,&bottom,&length)&&address>=bottom&&address-bottom<=length&&size<=length-(address-bottom);
}
bool GraphicsLease::publish(const std::vector<SubmitWrite>& writes,const std::vector<SubmitEvent>& events,std::string& error) {
    // Every allocation and destination check precedes the first guest byte.
    // Range pins prevent unmap/protect/shrink through the complete transaction.
    for(const auto& write:writes)if(!admit(write.address,write.bytes.size(),DM_GUEST_WRITE)){error="GPU publication destination is not writable owned memory";return false;}
    for(const auto& event:events)if((event.address&3) || event.mode>1 || !admit(event.address,4,DM_GUEST_READ|DM_GUEST_WRITE)){error="event publication destination is not readable/writable owned memory";return false;}
    for(const auto& write:writes)std::memcpy(reinterpret_cast<void*>(write.address),write.bytes.data(),write.bytes.size());
    // Metal defers event effects until after final GPU results. Overlaps and
    // repeated ADD operations deliberately observe prior publication bytes.
    for(const auto& event:events){uint32_t value=event.value;if(event.mode){uint32_t old;std::memcpy(&old,reinterpret_cast<const void*>(event.address),4);value+=old;}std::memcpy(reinterpret_cast<void*>(event.address),&value,4);}
    return true;
}
namespace {
struct BackendProgram {
    prog_t snapshot{};
    uint64_t generation=0,binding_epoch=0,bytes=0;
    uint32_t retained=0;
    std::shared_ptr<const ResolvedProgram> resolved;
    std::shared_ptr<const VkComputeProgram> executable;
    std::shared_ptr<const VkGraphicsProgram> graphics_executable;
};
struct BackendPool {
    NVNmemoryPool* object=nullptr;
    pool_t snapshot{};
    uint32_t textures=0,descriptors=0;
};
struct BackendTexture {
    NVNtexture* object=nullptr;
    tex_t snapshot{};
    uint64_t pool=0;
    uint32_t windows=0,descriptors=0,readers=0;
};
struct DescriptorSlot {uint64_t resource=0;uint32_t readers=0;};
struct BackendDescriptorPool {
    const void* object=nullptr;dpool_t snapshot{};uint64_t backing=0;bool sampler=false;
    uint32_t readers=0;std::map<int,DescriptorSlot> slots;
};
struct BackendSampler {NVNsampler* object=nullptr;samp_t snapshot{};uint32_t descriptors=0,readers=0;};
enum class WindowSlotState {Available,Acquiring,Acquired,PresentPending};
struct WindowSlot {WindowSlotState state=WindowSlotState::Available;SurfaceTicket surface{};uint64_t fence=0;bool abandoned=false;};
struct BackendWindow {
    NVNwindow* object=nullptr;
    NVNdevice* device=nullptr;
    win_t snapshot{};
    std::array<uint64_t,4> textures{};
    std::array<WindowSlot,4> slots{};
    uint64_t revision=0,cadence_serial=0,last_acquire_fence=0;
    SurfaceTicket surface{};
    bool live=false,retired=false;
};
struct Platform {
    NvnVkEngine engine;
    std::mutex admission;
    std::mutex registry;
    std::map<uint64_t,BackendPool> pools;
    std::map<uint64_t,BackendTexture> textures;
    std::map<uint64_t,BackendDescriptorPool> descriptor_pools;
    std::map<uint64_t,BackendSampler> samplers;
    BackendWindow window;
    uint64_t next_window=0,presents=0;
    uint64_t generation=0,next_pool=0;
    nvn_backend_ops ops{};
    std::mutex errors_mutex;
    std::array<std::array<char,512>,512> errors{};
    size_t error_count=0;
    std::mutex programs_mutex;
    std::map<uint64_t,std::shared_ptr<BackendProgram>> programs;
    uint64_t binding_epoch=0,program_bytes=0,program_created=0,program_replaced=0,program_released=0;
    ComputeSourceCatalog source_catalog;
    DrawSourceCatalog draw_catalog;
};
struct AcquiredProgram {Platform* owner=nullptr;std::shared_ptr<BackendProgram> entry;};
struct AcquiredSampled {
    std::shared_ptr<Platform> owner;std::shared_ptr<GraphicsLease> memory;
    uint64_t texture_pool=0,sampler_pool=0,texture=0,sampler=0;
    int texture_id=0,sampler_id=0;bool active=false;
    ~AcquiredSampled() {
        if(!active)return;
        std::lock_guard<std::mutex> lock(owner->registry);
        auto& tp=owner->descriptor_pools.at(texture_pool);auto& sp=owner->descriptor_pools.at(sampler_pool);
        auto& t=owner->textures.at(texture);auto& s=owner->samplers.at(sampler);
        if(!tp.readers||!sp.readers||!tp.slots.at(texture_id).readers||!sp.slots.at(sampler_id).readers||!t.readers||!s.readers)std::abort();
        --tp.readers;--sp.readers;--tp.slots.at(texture_id).readers;--sp.slots.at(sampler_id).readers;--t.readers;--s.readers;
    }
};
std::shared_ptr<Platform> platform;
nvn_result ok(){return {NVN_OK,0,nullptr};}
nvn_result error(Platform& p,nvn_error_code code,const char* reason,uint32_t operation=0){std::lock_guard<std::mutex> lock(p.errors_mutex);if(p.error_count==p.errors.size())return {code,operation,"graphics error storage exhausted"};auto& slot=p.errors[p.error_count++];std::snprintf(slot.data(),slot.size(),"%s",reason);return {code,operation,slot.data()};}
nvn_result unavailable(void* ctx){return error(*static_cast<Platform*>(ctx),NVN_UNSUPPORTED,"operation is outside the implemented Vulkan capability set");}
nvn_error_code vk_error(VkErrorKind kind){return kind==VkErrorKind::Publication?NVN_PUBLICATION_FAILED:kind==VkErrorKind::UnprovenTermination?NVN_RETAINED:kind==VkErrorKind::Device?NVN_DEVICE_FAILED:NVN_INVALID;}
bool same_pool(const pool_t& a,const pool_t& b){return a.magic==b.magic&&a.flags==b.flags&&a.mem==b.mem&&a.size==b.size;}
bool same_layout(const nvn_texlayout& a,const nvn_texlayout& b) {
    return std::tie(a.size,a.layer_size,a.align,a.layers,a.bpb,a.tileH,a.tileD)==std::tie(b.size,b.layer_size,b.align,b.layers,b.bpb,b.tileH,b.tileD);
}
bool same_texture(const tex_t& a,const tex_t& b) {
    const auto& x=a.d;const auto& y=b.d;
    return a.magic==b.magic&&a.serial==b.serial&&a.mem==b.mem&&a.pool==b.pool&&a.off==b.off&&
        a.has_layout==b.has_layout&&std::equal(std::begin(a.layout),std::end(a.layout),std::begin(b.layout))&&same_layout(a.L,b.L)&&
        std::tie(x.target,x.format,x.flags,x.samples,x.width,x.height,x.depth,x.levels,x.stride,x.pkg_block_h)==
        std::tie(y.target,y.format,y.flags,y.samples,y.width,y.height,y.depth,y.levels,y.stride,y.pkg_block_h);
}
bool same_window(const win_t& a,const win_t& b) {
    if(a.magic!=b.magic||a.native!=b.native||a.ntex!=b.ntex||a.interval!=b.interval||a.next!=b.next||a.presents!=b.presents||a.pace!=b.pace)return false;
    for(unsigned i=0;i<4;++i)if(a.crop[i]!=b.crop[i]||a.tex[i]!=b.tex[i]||a.avail[i]!=b.avail[i]||a.ticket[i]!=b.ticket[i])return false;
    return true;
}
bool overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&a<b+m&&b<a+n;}
enum class ResourceObjectKind {MemoryPool,Texture,Sampler,DescriptorPool,Window};
bool resource_object_alias(Platform& p,const void* object,size_t bytes,ResourceObjectKind kind) {
    const auto address=reinterpret_cast<uint64_t>(object);
    auto aliases=[&](const void* other,size_t size,ResourceObjectKind other_kind){
        return !(object==other&&kind==other_kind)&&overlap(address,bytes,reinterpret_cast<uint64_t>(other),size);
    };
    for(const auto& pair:p.pools)if(aliases(pair.second.object,sizeof(NVNmemoryPool),ResourceObjectKind::MemoryPool))return true;
    for(const auto& pair:p.textures)if(aliases(pair.second.object,sizeof(NVNtexture),ResourceObjectKind::Texture))return true;
    for(const auto& pair:p.samplers)if(aliases(pair.second.object,sizeof(NVNsampler),ResourceObjectKind::Sampler))return true;
    for(const auto& pair:p.descriptor_pools)if(aliases(pair.second.object,sizeof(NVNtexturePool),ResourceObjectKind::DescriptorPool))return true;
    return p.window.live&&overlap(address,bytes,reinterpret_cast<uint64_t>(p.window.object),sizeof(NVNwindow));
}
bool current_lease(Platform& p,const GraphicsLease& lease) {
    return lease.valid()&&lease.generation()==p.generation&&p.binding_epoch&&nvn_core_binding_epoch()==p.binding_epoch;
}
bool object_storage(Platform& p,GraphicsLease& lease,const void* object,size_t size,bool write) {
    return current_lease(p,lease)&&lease.admit_program_storage(reinterpret_cast<uint64_t>(object),size,DM_GUEST_READ|(write?DM_GUEST_WRITE:0));
}
bool window_current(Platform& p,const NVNwindow* object) {
    return p.window.live&&p.window.object==object&&same_window(*reinterpret_cast<const win_t*>(object),p.window.snapshot);
}
bool same_ticket(SurfaceTicket a,SurfaceTicket b){return a.owner==b.owner&&a.epoch==b.epoch;}
bool window_texture_shape(const tex_t& t) {
    const auto& d=t.d;nvn_texlayout layout{};
    if(t.magic!=MAGIC('T','E','X',0)||!t.serial||d.target!=NVN_TEXTURE_TARGET_2D||d.format!=NVN_FORMAT_RGBA8||
       d.samples<0||d.samples>1||d.levels!=1||d.depth!=1||!d.width||!d.height||d.width>16384||d.height>16384||
       (d.flags&~0x50)||d.pkg_block_h<0||d.pkg_block_h>5||uint64_t(d.width)*d.height*4>64u*1024u*1024u)return false;
    nvn_tex_layout(&d,&layout);
    return layout.size&&layout.size<=64u*1024u*1024u&&layout.layers==1&&same_layout(layout,t.L)&&
        (!(d.flags&0x10)||!d.stride||d.stride>=uint64_t(d.width)*4);
}
bool same_program(const prog_t& a,const prog_t& b) {
    if(a.magic!=b.magic||a.nstage!=b.nstage||a.serial!=b.serial||a.generation!=b.generation)return false;
    for(size_t i=0;i<6;++i)if(a.sd[i].data!=b.sd[i].data||a.sd[i].control!=b.sd[i].control)return false;
    return true;
}
bool source_copy(uint64_t address,void* out,size_t size,void* context,std::string* detail) {
    if(static_cast<GraphicsLease*>(context)->copy(address,out,size))return true;
    if(detail)*detail="original source record is not current owned readable memory";return false;
}
nvn_result prog_replace(void* ctx,const prog_t* old,const prog_t* next) {
    auto& p=*static_cast<Platform*>(ctx);
    if(!next||next->magic!=MAGIC('P','R','O','G')||!next->generation||next->nstage>2||
       (next->nstage&&!next->serial)||(old&&(old->generation!=next->generation||next->serial<=old->serial))||
       (!old&&(next->serial||next->nstage)))
        return error(p,NVN_INVALID,"invalid program candidate identity or stage count");
    const uint64_t epoch=nvn_core_binding_epoch();
    if(!epoch||epoch!=p.binding_epoch)return error(p,NVN_INVALID,"program binding epoch is stale");
    if(!p.engine.error().empty()) {const auto state=p.engine.drain();return error(p,vk_error(state.error_kind),state.error.c_str());}
    try {
        std::shared_ptr<BackendProgram> previous;
        {
            std::lock_guard<std::mutex> lock(p.programs_mutex);const auto found=p.programs.find(next->generation);
            if(old) {
                if(found==p.programs.end()||!same_program(found->second->snapshot,*old)||found->second->generation!=p.generation||found->second->binding_epoch!=epoch)
                    return error(p,NVN_INVALID,"old backend program revision is stale");
                if(found->second->retained)return error(p,NVN_RETAINED,"backend program revision is retained");
                previous=found->second;
            }else if(found!=p.programs.end()||p.programs.size()>=4096)return error(p,NVN_RETAINED,"program generation already live or registry capacity reached");
        }
        auto candidate=std::make_shared<BackendProgram>();candidate->snapshot=*next;candidate->generation=p.generation;candidate->binding_epoch=epoch;
        candidate->bytes=sizeof(BackendProgram)+128;
        if(next->nstage) {
            GraphicsLease lease;std::string detail;
            if(!lease.valid()||lease.generation()!=p.generation)return error(p,NVN_INVALID,"program source lease is not current");
            const bool resolved=next->nstage==1?
                resolve_catalog_compute(p.source_catalog,p.generation,next->serial,next->sd,next->nstage,source_copy,&lease,&candidate->resolved,&detail):
                resolve_catalog_draw(p.draw_catalog,p.generation,next->serial,next->sd,next->nstage,source_copy,&lease,&candidate->resolved,&detail);
            if(!resolved)return error(p,NVN_INVALID,detail.empty()?"program source capture unavailable":detail.c_str());
            if(candidate->resolved->stage_mask()==32){if(!p.engine.prepare_compute_program(candidate->resolved,&candidate->executable,&detail))return error(p,NVN_DEVICE_FAILED,detail.c_str());}
            else if(candidate->resolved->stage_mask()==3){if(!p.engine.prepare_graphics_program(candidate->resolved,&candidate->graphics_executable,&detail))return error(p,NVN_DEVICE_FAILED,detail.c_str());}
            else return error(p,NVN_UNSUPPORTED,"unsupported resolved program stage mask");
            for(const auto& artifact:candidate->resolved->stages())candidate->bytes+=8*artifact->file_bytes()+65536;
            for(const auto& stage:candidate->resolved->snapshot().stages)candidate->bytes+=stage.record.capacity();
        }
        // Preallocate the insertion node outside the registry lock. Existing
        // revisions commit with a shared_ptr swap; neither commit allocates.
        std::map<uint64_t,std::shared_ptr<BackendProgram>> staging;
        if(!old)staging.emplace(next->generation,candidate);
        auto node=old?decltype(staging)::node_type{}:staging.extract(next->generation);
        std::shared_ptr<BackendProgram> retired;
        {
            std::lock_guard<std::mutex> lock(p.programs_mutex);auto found=p.programs.find(next->generation);
            if(old) {
                if(found==p.programs.end()||found->second!=previous||!same_program(found->second->snapshot,*old))return error(p,NVN_INVALID,"program revision changed during candidate preparation");
                if(found->second->retained)return error(p,NVN_RETAINED,"program became retained during candidate preparation");
            }else if(found!=p.programs.end()||p.programs.size()>=4096)return error(p,NVN_RETAINED,"program registry changed during initialize");
            const uint64_t prior=old?previous->bytes:0;
            if(candidate->bytes>256u*1024u*1024u-(p.program_bytes-prior))return error(p,NVN_RETAINED,"program artifact/source budget exceeded");
            p.program_bytes=p.program_bytes-prior+candidate->bytes;
            if(old){retired=std::move(found->second);found->second.swap(candidate);++p.program_replaced;}
            else {p.programs.insert(std::move(node));++p.program_created;}
        }
        // Retired source/pipeline destructors run without backend/core locks.
        return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"program candidate allocation failed");}
}
nvn_result prog_release(void* ctx,const prog_t* program) {
    auto& p=*static_cast<Platform*>(ctx);if(!program)return error(p,NVN_INVALID,"missing backend program revision");
    std::shared_ptr<BackendProgram> retired;
    {std::lock_guard<std::mutex> lock(p.programs_mutex);const auto found=p.programs.find(program->generation);
     if(found==p.programs.end()||!same_program(found->second->snapshot,*program)||found->second->generation!=p.generation||found->second->binding_epoch!=p.binding_epoch)return error(p,NVN_INVALID,"backend program release is stale");
     if(found->second->retained)return error(p,NVN_RETAINED,"backend program is retained");
     retired=found->second;p.program_bytes-=retired->bytes;p.programs.erase(found);++p.program_released;}
    return ok();
}
nvn_result prog_acquire(void* ctx,const prog_t* program,uint32_t stages,void** token,uint32_t* actual) {
    if(token)*token=nullptr;if(actual)*actual=0;auto& p=*static_cast<Platform*>(ctx);
    if(!program||!token||!actual||(stages!=32&&stages!=3))return error(p,NVN_INVALID,"only a live compute or vertex/fragment program can be acquired");
    try {
        auto candidate=std::make_unique<AcquiredProgram>();candidate->owner=&p;
        {std::lock_guard<std::mutex> lock(p.programs_mutex);const auto found=p.programs.find(program->generation);
         if(found==p.programs.end()||!same_program(found->second->snapshot,*program)||found->second->generation!=p.generation||found->second->binding_epoch!=p.binding_epoch||!found->second->resolved||found->second->resolved->stage_mask()!=stages||(stages==32?!found->second->executable:!found->second->graphics_executable))
             return error(p,NVN_INVALID,"compute backend revision is empty, foreign or retired");
         if(found->second->retained==UINT32_MAX)return error(p,NVN_RETAINED,"backend reference count exhausted");
         candidate->entry=found->second;++candidate->entry->retained;}
        *actual=stages;*token=candidate.release();return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"program acquisition allocation failed");}
}
void prog_unacquire(void* ctx,void* opaque) {
    auto& p=*static_cast<Platform*>(ctx);std::unique_ptr<AcquiredProgram> token(static_cast<AcquiredProgram*>(opaque));
    if(!token||token->owner!=&p||!token->entry)std::abort();
    {std::lock_guard<std::mutex> lock(p.programs_mutex);if(!token->entry->retained)std::abort();--token->entry->retained;}
}
nvn_result initialize(void* ctx,const dev_t_*) {auto& p=*static_cast<Platform*>(ctx);std::string e;if(!p.engine.initialize(&e))return error(p,NVN_DEVICE_FAILED,e.c_str());return ok();}
nvn_result pool_add(void* ctx,NVNmemoryPool* object,const pool_t* pool) {
    auto& p=*static_cast<Platform*>(ctx);
    if(!pool||pool->magic!=MAGIC('P','O','O','L')||!pool->mem||!pool->size||pool->size>128u*1024u*1024u)return error(p,NVN_INVALID,"invalid memory pool candidate");
    try {
        GraphicsLease lease;if(!object_storage(p,lease,object,sizeof(*object),true)||!lease.admit(reinterpret_cast<uint64_t>(pool->mem),pool->size,DM_GUEST_READ|DM_GUEST_WRITE))return error(p,NVN_INVALID,"pool object or backing storage is not owned readable/writable memory");
        std::map<uint64_t,BackendPool> staging;staging.emplace(0,BackendPool{object,*pool,0});auto node=staging.extract(0);
        std::lock_guard<std::mutex> admission(p.admission);
        std::lock_guard<std::mutex> lock(p.registry);auto old=p.pools.end();uint64_t bytes=0;
        if(resource_object_alias(p,object,sizeof(*object),ResourceObjectKind::MemoryPool))return error(p,NVN_INVALID,"pool output aliases a live resource object");
        for(auto it=p.pools.begin();it!=p.pools.end();++it) {
            if(it->second.object==object){old=it;continue;}
            const auto& previous=it->second.snapshot;bytes+=previous.size;
            if(overlap(reinterpret_cast<uint64_t>(pool->mem),pool->size,reinterpret_cast<uint64_t>(previous.mem),previous.size))return error(p,NVN_INVALID,"distinct overlapping pools are unsupported");
        }
        pool_t old_public{};
        if(old!=p.pools.end()&&(!lease.copy(reinterpret_cast<uint64_t>(object),&old_public,sizeof(old_public))||!same_pool(old_public,old->second.snapshot)))return error(p,NVN_INVALID,"old pool public revision is altered");
        if(old!=p.pools.end()&&(old->second.textures||old->second.descriptors||p.engine.retained_pool(old->first)))return error(p,NVN_RETAINED,"registered textures or GPU work retain the old pool revision");
        if((old==p.pools.end()&&p.pools.size()>=4096)||p.next_pool==UINT64_MAX||bytes>128u*1024u*1024u-pool->size)return error(p,NVN_RETAINED,"pool registry identity or byte budget exhausted");
        if(old!=p.pools.end())p.pools.erase(old);
        node.key()=++p.next_pool;p.pools.insert(std::move(node));
        std::memcpy(object,pool,sizeof(*pool));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"pool registration allocation failed");}
}
nvn_result pool_del(void* ctx,NVNmemoryPool* object) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;
    if(!object_storage(p,lease,object,sizeof(*object),true))return error(p,NVN_INVALID,"pool finalization storage is not current owned memory");
    std::lock_guard<std::mutex> admission(p.admission);
    std::lock_guard<std::mutex> lock(p.registry);
    for(auto it=p.pools.begin();it!=p.pools.end();++it)if(it->second.object==object) {
        if(!same_pool(*reinterpret_cast<const pool_t*>(object),it->second.snapshot))return error(p,NVN_INVALID,"altered pool object");
        if(it->second.textures||it->second.descriptors||p.engine.retained_pool(it->first))return error(p,NVN_RETAINED,"registered textures or GPU work retain pool");
        p.pools.erase(it);reinterpret_cast<pool_t*>(object)->magic=0;return ok();
    }
    return error(p,NVN_INVALID,"pool is not registered");
}
nvn_result tex_register(void* ctx,NVNtexture* object,const tex_t* tex) {
    auto& p=*static_cast<Platform*>(ctx);
    if(!tex||!tex->serial||tex->magic!=MAGIC('T','E','X',0)||!tex->L.size||tex->L.size>128u*1024u*1024u||tex->off<0)return error(p,NVN_INVALID,"invalid texture registration candidate");
    try {
        GraphicsLease lease;
        if(!object_storage(p,lease,object,sizeof(*object),true)||!object_storage(p,lease,tex->pool,sizeof(NVNmemoryPool),false))return error(p,NVN_INVALID,"texture object or pool storage is not current owned memory");
        std::map<uint64_t,BackendTexture> staging;staging.emplace(tex->serial,BackendTexture{object,*tex,0,0});auto node=staging.extract(tex->serial);
        std::lock_guard<std::mutex> admission(p.admission);
        std::lock_guard<std::mutex> lock(p.registry);auto pool=p.pools.end();auto old=p.textures.end();
        if(resource_object_alias(p,object,sizeof(*object),ResourceObjectKind::Texture))return error(p,NVN_INVALID,"texture output aliases a live resource object");
        for(auto it=p.pools.begin();it!=p.pools.end();++it)if(reinterpret_cast<const void*>(it->second.object)==tex->pool){pool=it;break;}
        if(pool==p.pools.end()||!same_pool(*tex->pool,pool->second.snapshot)||uint64_t(tex->off)>pool->second.snapshot.size||
           tex->L.size>pool->second.snapshot.size-uint64_t(tex->off)||tex->mem!=pool->second.snapshot.mem+tex->off)return error(p,NVN_INVALID,"texture does not match exact registered pool span");
        for(auto it=p.textures.begin();it!=p.textures.end();++it)if(it->second.object==object){old=it;break;}
        tex_t old_public{};
        if(old!=p.textures.end()&&(!lease.copy(reinterpret_cast<uint64_t>(object),&old_public,sizeof(old_public))||!same_texture(old_public,old->second.snapshot)))return error(p,NVN_INVALID,"old texture public revision is altered");
        if(old!=p.textures.end()&&(old->second.windows||old->second.descriptors||old->second.readers||p.engine.retained_texture(old->first)))return error(p,NVN_RETAINED,"window or GPU work retains the old texture revision");
        if(p.textures.count(tex->serial)||(old==p.textures.end()&&p.textures.size()>=4096)||pool->second.textures==UINT32_MAX)return error(p,NVN_RETAINED,"texture serial or registry budget exhausted");
        if(old!=p.textures.end()){auto old_pool=p.pools.find(old->second.pool);if(old_pool==p.pools.end()||!old_pool->second.textures)std::abort();--old_pool->second.textures;p.textures.erase(old);}
        node.mapped().pool=pool->first;++pool->second.textures;p.textures.insert(std::move(node));std::memcpy(object,tex,sizeof(*tex));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"texture registration allocation failed");}
}
nvn_result tex_release(void* ctx,NVNtexture* object) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;
    if(!object_storage(p,lease,object,sizeof(*object),true))return error(p,NVN_INVALID,"texture finalization storage is not current owned memory");
    std::lock_guard<std::mutex> admission(p.admission);
    std::lock_guard<std::mutex> lock(p.registry);
    for(auto it=p.textures.begin();it!=p.textures.end();++it)if(it->second.object==object) {
        if(!same_texture(*reinterpret_cast<const tex_t*>(object),it->second.snapshot))return error(p,NVN_INVALID,"altered texture revision");
        if(it->second.windows||it->second.descriptors||it->second.readers||p.engine.retained_texture(it->first))return error(p,NVN_RETAINED,"window or GPU work retains texture");
        auto pool=p.pools.find(it->second.pool);if(pool==p.pools.end()||!pool->second.textures)std::abort();--pool->second.textures;
        p.textures.erase(it);reinterpret_cast<tex_t*>(object)->magic=0;return ok();
    }
    return error(p,NVN_INVALID,"texture is not registered");
}
bool acquire_sampled(Platform&,const std::shared_ptr<GraphicsLease>&,const dpool_t&,const dpool_t&,uint64_t,uint64_t,
                     std::shared_ptr<const SubmitSampledResource>*,std::string*);
nvn_result submit(void* ctx,queue_t*,int count,const uint64_t* handles) {
    auto& p=*static_cast<Platform*>(ctx);
    if(count<=0 || size_t(count)>SubmitLimits{}.handles || !handles)return error(p,NVN_INVALID,"invalid command handle count/list");
    try {
    // Serialize the complete coherence transaction across guest submitters. A
    // second caller must retire the first caller's accepted writes before it
    // snapshots memory. This admission mutex is independent of the resource
    // registry/lifecycle locks; publication and barrier release never take it.
    std::lock_guard<std::mutex> admission(p.admission);
    // Conservative cross-submit coherence: complete prior GPU writes and their
    // publication before taking any new host snapshot. No lifecycle/read lock.
    auto prior=p.engine.drain();if(prior.state!=VkSubmitState::Completed)return error(p,vk_error(prior.error_kind),prior.error.c_str());
    std::shared_ptr<PreparedSubmit> prepared;VkPublish publish;
    {
    auto lease=std::make_shared<GraphicsLease>();if(!lease->valid()||lease->generation()!=p.generation)return error(p,NVN_INVALID,"stale runtime generation");
    nvn_error_code preparation_code=NVN_INVALID;
    std::vector<SubmitPool> pools;std::unordered_set<uint64_t> textures;
    {std::lock_guard<std::mutex> lock(p.registry);
        size_t total=0;const size_t budget=SubmitLimits{}.pools_bytes;
        for(const auto& pair:p.pools) {
            if(pair.second.snapshot.size>budget-total)return error(p,NVN_INVALID,"pool snapshot budget exceeded");
            total+=size_t(pair.second.snapshot.size);
        }
        for(const auto& pair:p.pools)pools.push_back({pair.first,reinterpret_cast<uint64_t>(pair.second.snapshot.mem),std::vector<uint8_t>(pair.second.snapshot.size)});
        for(const auto& pair:p.textures)textures.insert(pair.first);
    }
    SubmitReader reader;reader.copy=[lease](uint64_t a,void* d,size_t n){return lease->copy(a,d,n);};
    reader.texture_live=[textures=std::move(textures)](uint64_t serial){return textures.count(serial)!=0;};
    reader.acquire_sampled=[&p,lease](const dpool_t& texture_pool,const dpool_t& sampler_pool,uint64_t texture,uint64_t sampler,
        std::shared_ptr<const SubmitSampledResource>* out,std::string* detail){return acquire_sampled(p,lease,texture_pool,sampler_pool,texture,sampler,out,detail);};
    reader.retain_recorder=[](uint64_t a,size_t n)->std::shared_ptr<void>{
        auto pin=new nvn_host_segment_lease{};if(!nvn_core_host_segment_retain(a,n,pin)){delete pin;return {};}
        return std::shared_ptr<void>(pin,[](void* opaque){auto* value=static_cast<nvn_host_segment_lease*>(opaque);nvn_core_host_segment_release(*value);delete value;});
    };
    reader.acquire_program=[&p,&preparation_code](const prog_t& snapshot,uint32_t stages,SubmitProgram* out,std::string* detail) {
        if(!out)return false;const prog_t copied=snapshot;*out={};nvn_program_ref* raw=nullptr;
        const auto result=nvn_core_program_acquire(&copied,stages,&raw);
        if(result.code!=NVN_OK){preparation_code=result.code;if(detail)*detail=result.reason?result.reason:"live program acquire refused";return false;}
        std::unique_ptr<nvn_program_ref,decltype(&nvn_core_program_release)> retained(raw,nvn_core_program_release);
        auto* token=static_cast<AcquiredProgram*>(nvn_core_program_backend_token(raw));
        if(!token||token->owner!=&p||!token->entry||token->entry->generation!=p.generation||token->entry->binding_epoch!=p.binding_epoch||
           nvn_core_program_binding_epoch(raw)!=p.binding_epoch||nvn_core_program_stage_mask(raw)!=stages||!same_program(*nvn_core_program_snapshot(raw),copied)) {
            if(detail)*detail="core/backend/runtime program acquisition identity mismatch";return false;
        }
        SubmitProgram candidate;candidate.snapshot=copied;candidate.generation=p.generation;
        candidate.resolved=token->entry->resolved;candidate.executable=token->entry->executable;candidate.graphics_executable=token->entry->graphics_executable;
        candidate.lease=std::shared_ptr<void>(retained.release(),[](void* value){nvn_core_program_release(static_cast<nvn_program_ref*>(value));});
        *out=std::move(candidate);return true;
    };
    reader.prepare_compute=[&p](const SubmitProgram& program,const std::vector<p_bind_buf>& ubos,const std::vector<p_bind_buf>& ssbos,
        std::array<uint32_t,3> groups,const std::vector<SubmitPool>& pools,std::shared_ptr<const PreparedComputeDispatch>* out,std::string* detail) {
        std::vector<ComputeBinding> u,s;
        auto copy=[&](const auto& from,auto& to){for(const auto& binding:from){if(binding.stage!=5||binding.index<0||binding.index>=16)return false;to.push_back({uint32_t(binding.index),binding.addr,binding.size});}std::sort(to.begin(),to.end(),[](const auto& a,const auto& b){return a.nvn_slot<b.nvn_slot;});return true;};
        if(program.generation!=p.generation||!program.lease||!copy(ubos,u)||!copy(ssbos,s)){if(out)out->reset();if(detail)*detail="invalid current compute program or binding stage/slot";return false;}
        return prepare_compute_dispatch(program.resolved,program.executable,u,s,groups,pools,p.engine.shader_device_contract(),out,detail);
    };
    reader.prepare_draw=[&p](const SubmitProgram& program,const DrawState& state,const DrawCall& call,
        const std::vector<SubmitPool>& pools,std::shared_ptr<const PreparedDraw>* out,std::string* detail){
        if(program.generation!=p.generation||!program.lease||!program.graphics_executable||!program.resolved||program.resolved->stage_mask()!=3){if(out)out->reset();if(detail)*detail="invalid current graphics program";return false;}
        return prepare_draw(program.resolved,program.graphics_executable,state,call,pools,p.engine.draw_device_contract(),out,detail);
    };
    for(const auto& pool:pools)if(!lease->admit(pool.address,pool.initial.size(),DM_GUEST_READ|DM_GUEST_WRITE))return error(p,NVN_INVALID,"pool permissions changed before snapshot");
    std::string e;uint32_t failure_operation=0;
    if(!prepare_submit(handles,size_t(count),reader,std::move(pools),&prepared,&e,{},&failure_operation))return error(p,preparation_code,e.c_str(),failure_operation);
    for(const auto& event:prepared->events)if(!lease->admit(event.address,4,DM_GUEST_READ|DM_GUEST_WRITE))return error(p,NVN_INVALID,"event is not owned readable/writable memory",OP_SIGNAL_EVENT);
    prepared->generation=p.generation;prepared->lease=lease;
    publish=[lease=std::move(lease)](const std::vector<SubmitWrite>& writes,const std::vector<SubmitEvent>& events,std::string& detail){return lease->publish(writes,events,detail);};
    } // Reader captures and all preparation owners retire before acceptance.
    auto accepted=p.engine.submit(std::move(prepared),std::move(publish));
    if(!accepted.accepted)return error(p,vk_error(accepted.error_kind),accepted.error.c_str());return ok();
    } catch(const std::bad_alloc&) {return error(p,NVN_INVALID,"graphics submission allocation failed");}
}
uint64_t last_fence(void* ctx){return static_cast<Platform*>(ctx)->engine.last_fence();}
nvn_wait_result wait(void* ctx,uint64_t fence,uint64_t timeout){auto& p=*static_cast<Platform*>(ctx);auto r=p.engine.wait(fence,timeout);return {r.state==VkSubmitState::Completed?NVN_COMPLETED:r.state==VkSubmitState::Pending?NVN_PENDING:NVN_FAILED,r.error_kind!=VkErrorKind::None?error(p,vk_error(r.error_kind),r.error.c_str()):ok()};}
nvn_result drain(void* ctx){auto& p=*static_cast<Platform*>(ctx);auto r=p.engine.drain();return r.state!=VkSubmitState::Completed?error(p,vk_error(r.error_kind),r.error.c_str()):ok();}
nvn_result queue_error(void* ctx,const queue_t*){auto& p=*static_cast<Platform*>(ctx);auto e=p.engine.error();return e.empty()?ok():error(p,vk_error(p.engine.error_kind()),e.c_str());}
nvn_result callback(void* ctx,cmd_t* command,size_t requested){auto& p=*static_cast<Platform*>(ctx);return command&&command->cb&&dm_android_graphics_guest_callback(reinterpret_cast<uint64_t>(command->cb),reinterpret_cast<uint64_t>(command),requested,reinterpret_cast<uint64_t>(command->cb_data))?ok():error(p,NVN_INVALID,"command callback target/state/owned stack validation failed");}
uint64_t frame_count(void* ctx){auto& p=*static_cast<Platform*>(ctx);std::lock_guard<std::mutex> lock(p.registry);return p.presents;}
nvn_result prog_copy_shaders(void* ctx,const NVNshaderData* source,uint32_t count,NVNshaderData* out){auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;if(!source||!out||!count||count>6||!lease.valid()||lease.generation()!=p.generation||!lease.copy(reinterpret_cast<uint64_t>(source),out,size_t(count)*sizeof(*out)))return error(p,NVN_INVALID,"shaderData array is not current owned readable memory");return ok();}
nvn_result prog_storage_acquire(void* ctx,const NVNprogram* object,uint32_t writable,void** out) {
    if(out)*out=nullptr;auto& p=*static_cast<Platform*>(ctx);if(!out||writable>1)return error(p,NVN_INVALID,"invalid program storage lease request");
    try{auto lease=std::make_unique<GraphicsLease>();if(!lease->valid()||lease->generation()!=p.generation||!lease->admit_program_storage(reinterpret_cast<uint64_t>(object),sizeof(NVNprogram),DM_GUEST_READ|(writable?DM_GUEST_WRITE:0)))return error(p,NVN_INVALID,"program storage is not current owned readable/writable memory");*out=lease.release();return ok();}
    catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"program storage lease allocation failed");}
}
void prog_storage_release(void*,void* token){delete static_cast<GraphicsLease*>(token);}
bool same_descriptor_pool(const dpool_t& a,const dpool_t& b) {
    return a.pool==b.pool&&a.off==b.off&&a.n==b.n&&a.serial==b.serial;
}
bool same_sampler(const samp_t& a,const samp_t& b) {
    const auto& x=a.p;const auto& y=b.p;
    return a.magic==b.magic&&a.serial==b.serial&&
        std::tie(x.minf,x.magf,x.ws,x.wt,x.wr,x.cmp_mode,x.cmp_func,x.lod_min,x.lod_max,x.lod_bias,x.aniso)==
        std::tie(y.minf,y.magf,y.ws,y.wt,y.wr,y.cmp_mode,y.cmp_func,y.lod_min,y.lod_max,y.lod_bias,y.aniso)&&
        std::equal(std::begin(x.border),std::end(x.border),std::begin(y.border));
}
bool sampled_sampler(const samp_par& p) {
    return p.minf==NVN_MIN_FILTER_NEAREST&&p.magf==NVN_MAG_FILTER_NEAREST&&
        p.ws==NVN_WRAP_MODE_CLAMP_TO_EDGE&&p.wt==NVN_WRAP_MODE_CLAMP_TO_EDGE&&p.wr==NVN_WRAP_MODE_CLAMP_TO_EDGE&&
        p.cmp_mode==NVN_COMPARE_MODE_NONE&&p.lod_min==0&&p.lod_max==0&&p.lod_bias==0&&p.aniso==1&&
        std::all_of(std::begin(p.border),std::end(p.border),[](float v){return std::isfinite(v);});
}
void retire_descriptor_pool(Platform& p,const BackendDescriptorPool& pool) {
    for(const auto& slot:pool.slots) {
        if(slot.second.readers)std::abort();
        if(pool.sampler){auto& resource=p.samplers.at(slot.second.resource);if(!resource.descriptors)std::abort();--resource.descriptors;}
        else {auto& resource=p.textures.at(slot.second.resource);if(!resource.descriptors)std::abort();--resource.descriptors;}
    }
    auto& backing=p.pools.at(pool.backing);if(!backing.descriptors)std::abort();--backing.descriptors;
}
nvn_result descriptor_pool_init(void* ctx,void* object,const dpool_t* candidate,bool sampler) {
    auto& p=*static_cast<Platform*>(ctx);
    if(!candidate||!candidate->serial||!candidate->pool||candidate->off<0||(candidate->off&31)||candidate->n<1||candidate->n>64)
        return error(p,NVN_INVALID,"descriptor pool candidate has invalid identity/range/alignment");
    try {
        GraphicsLease lease;pool_t backing{};
        if(!object_storage(p,lease,object,sizeof(NVNtexturePool),true)||
           !object_storage(p,lease,candidate->pool,sizeof(NVNmemoryPool),false)||
           !lease.copy(reinterpret_cast<uint64_t>(candidate->pool),&backing,sizeof(backing)))
            return error(p,NVN_INVALID,"descriptor pool object/backing is not owned memory");
        const uint64_t bytes=uint64_t(candidate->n)*32;
        if(uint64_t(candidate->off)>backing.size||bytes>backing.size-uint64_t(candidate->off))
            return error(p,NVN_INVALID,"descriptor pool exceeds backing span");
        std::map<uint64_t,BackendDescriptorPool> staging;
        BackendDescriptorPool value;value.object=object;value.snapshot=*candidate;value.sampler=sampler;
        staging.emplace(candidate->serial,std::move(value));auto node=staging.extract(candidate->serial);
        std::lock_guard<std::mutex> admission(p.admission);std::lock_guard<std::mutex> lock(p.registry);
        if(resource_object_alias(p,object,sizeof(NVNtexturePool),ResourceObjectKind::DescriptorPool))return error(p,NVN_INVALID,"descriptor pool output aliases a live resource object");
        auto pool=std::find_if(p.pools.begin(),p.pools.end(),[&](const auto& pair){return reinterpret_cast<const void*>(pair.second.object)==candidate->pool;});
        if(pool==p.pools.end()||!same_pool(backing,pool->second.snapshot)||pool->second.descriptors==UINT32_MAX)
            return error(p,NVN_INVALID,"descriptor backing is not the exact registered memory pool");
        auto old=std::find_if(p.descriptor_pools.begin(),p.descriptor_pools.end(),[&](const auto& pair){return pair.second.object==object;});
        dpool_t old_public{};
        if(old!=p.descriptor_pools.end()&&(!lease.copy(reinterpret_cast<uint64_t>(object),&old_public,sizeof(old_public))||!same_descriptor_pool(old_public,old->second.snapshot)))return error(p,NVN_INVALID,"old descriptor pool public revision is altered");
        if(old!=p.descriptor_pools.end()&&(old->second.readers||old->second.sampler!=sampler))return error(p,NVN_RETAINED,"descriptor pool is retained or changes kind");
        if(p.descriptor_pools.count(candidate->serial)||(old==p.descriptor_pools.end()&&p.descriptor_pools.size()>=4096))return error(p,NVN_RETAINED,"descriptor pool identity/capacity exhausted");
        if(old!=p.descriptor_pools.end()){retire_descriptor_pool(p,old->second);p.descriptor_pools.erase(old);}
        node.mapped().backing=pool->first;++pool->second.descriptors;p.descriptor_pools.insert(std::move(node));
        std::memcpy(object,candidate,sizeof(*candidate));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"descriptor pool allocation failed");}
}
nvn_result descriptor_pool_release(void* ctx,void* object,bool sampler) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;dpool_t snapshot{};
    if(!object_storage(p,lease,object,sizeof(NVNtexturePool),true)||!lease.copy(reinterpret_cast<uint64_t>(object),&snapshot,sizeof(snapshot)))return error(p,NVN_INVALID,"descriptor pool release is not owned memory");
    std::lock_guard<std::mutex> admission(p.admission);std::lock_guard<std::mutex> lock(p.registry);
    auto pool=p.descriptor_pools.find(snapshot.serial);
    if(pool==p.descriptor_pools.end()||pool->second.object!=object||pool->second.sampler!=sampler||!same_descriptor_pool(snapshot,pool->second.snapshot))return error(p,NVN_INVALID,"descriptor pool release is stale or altered");
    if(pool->second.readers)return error(p,NVN_RETAINED,"accepted draw retains descriptor pool");
    retire_descriptor_pool(p,pool->second);p.descriptor_pools.erase(pool);std::memset(object,0,sizeof(dpool_t));return ok();
}
nvn_result tex_pool_init(void* ctx,NVNtexturePool* object,const dpool_t* candidate){return descriptor_pool_init(ctx,object,candidate,false);}
nvn_result samp_pool_init(void* ctx,NVNsamplerPool* object,const dpool_t* candidate){return descriptor_pool_init(ctx,object,candidate,true);}
nvn_result tex_pool_release(void* ctx,NVNtexturePool* object){return descriptor_pool_release(ctx,object,false);}
nvn_result samp_pool_release(void* ctx,NVNsamplerPool* object){return descriptor_pool_release(ctx,object,true);}
nvn_result sampler_init(void* ctx,NVNsampler* object,const samp_t* candidate) {
    auto& p=*static_cast<Platform*>(ctx);
    if(!candidate||candidate->magic!=MAGIC('S','M','P',0)||!candidate->serial||!sampled_sampler(candidate->p))return error(p,NVN_UNSUPPORTED,"sampler requires nearest/clamp/LOD0 without comparison");
    try {
        GraphicsLease lease;if(!object_storage(p,lease,object,sizeof(*object),true))return error(p,NVN_INVALID,"sampler object is not owned memory");
        std::map<uint64_t,BackendSampler> staging;staging.emplace(candidate->serial,BackendSampler{object,*candidate,0,0});auto node=staging.extract(candidate->serial);
        std::lock_guard<std::mutex> admission(p.admission);std::lock_guard<std::mutex> lock(p.registry);
        if(resource_object_alias(p,object,sizeof(*object),ResourceObjectKind::Sampler))return error(p,NVN_INVALID,"sampler output aliases a live resource object");
        auto old=std::find_if(p.samplers.begin(),p.samplers.end(),[&](const auto& pair){return pair.second.object==object;});
        samp_t old_public{};
        if(old!=p.samplers.end()&&(!lease.copy(reinterpret_cast<uint64_t>(object),&old_public,sizeof(old_public))||!same_sampler(old_public,old->second.snapshot)))return error(p,NVN_INVALID,"old sampler public revision is altered");
        if(old!=p.samplers.end()&&(old->second.descriptors||old->second.readers))return error(p,NVN_RETAINED,"descriptor or draw retains sampler");
        if(p.samplers.count(candidate->serial)||(old==p.samplers.end()&&p.samplers.size()>=4096))return error(p,NVN_RETAINED,"sampler identity/capacity exhausted");
        if(old!=p.samplers.end())p.samplers.erase(old);
        p.samplers.insert(std::move(node));std::memcpy(object,candidate,sizeof(*candidate));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"sampler registration allocation failed");}
}
nvn_result sampler_release(void* ctx,NVNsampler* object) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;samp_t snapshot{};
    if(!object_storage(p,lease,object,sizeof(*object),true)||!lease.copy(reinterpret_cast<uint64_t>(object),&snapshot,sizeof(snapshot)))return error(p,NVN_INVALID,"sampler release storage is unowned");
    std::lock_guard<std::mutex> admission(p.admission);std::lock_guard<std::mutex> lock(p.registry);
    auto sampler=p.samplers.find(snapshot.serial);
    if(sampler==p.samplers.end()||sampler->second.object!=object||!same_sampler(snapshot,sampler->second.snapshot))return error(p,NVN_INVALID,"sampler release is stale or altered");
    if(sampler->second.descriptors||sampler->second.readers)return error(p,NVN_RETAINED,"descriptor or draw retains sampler");
    p.samplers.erase(sampler);reinterpret_cast<samp_t*>(object)->magic=0;return ok();
}
nvn_result reg_tex(void* ctx,const NVNtexturePool* object,int id,const NVNtexture* texture,const NVNtextureView* view) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;dpool_t pool{};tex_t snapshot{};
    if(view)return error(p,NVN_UNSUPPORTED,"sampled texture views are not implemented");
    if(!object_storage(p,lease,object,sizeof(*object),false)||!object_storage(p,lease,texture,sizeof(*texture),false)||
       !lease.copy(reinterpret_cast<uint64_t>(object),&pool,sizeof(pool))||!lease.copy(reinterpret_cast<uint64_t>(texture),&snapshot,sizeof(snapshot)))return error(p,NVN_INVALID,"sampled registration storage is unowned");
    if(!window_texture_shape(snapshot))return error(p,NVN_UNSUPPORTED,"sampled texture requires single-mip RGBA8 2D storage");
    try {
        std::map<int,DescriptorSlot> staging;staging.emplace(id,DescriptorSlot{snapshot.serial,0});auto node=staging.extract(id);
        std::lock_guard<std::mutex> admission(p.admission);std::lock_guard<std::mutex> lock(p.registry);
        auto parent=p.descriptor_pools.find(pool.serial);auto source=p.textures.find(snapshot.serial);
        if(parent==p.descriptor_pools.end()||parent->second.sampler||parent->second.object!=object||!same_descriptor_pool(pool,parent->second.snapshot)||id<0||id>=pool.n||
           source==p.textures.end()||source->second.object!=texture||!same_texture(snapshot,source->second.snapshot)||source->second.descriptors==UINT32_MAX)return error(p,NVN_INVALID,"texture registration has stale pool/texture or invalid ID");
        auto previous=parent->second.slots.find(id);if(previous!=parent->second.slots.end()&&previous->second.readers)return error(p,NVN_RETAINED,"accepted draw retains texture descriptor");
        if(previous!=parent->second.slots.end()){--p.textures.at(previous->second.resource).descriptors;parent->second.slots.erase(previous);}
        ++source->second.descriptors;parent->second.slots.insert(std::move(node));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"texture descriptor allocation failed");}
}
nvn_result reg_samp(void* ctx,const NVNsamplerPool* object,int id,const NVNsampler* sampler_object) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;dpool_t pool{};samp_t snapshot{};
    if(!object_storage(p,lease,object,sizeof(*object),false)||!object_storage(p,lease,sampler_object,sizeof(*sampler_object),false)||
       !lease.copy(reinterpret_cast<uint64_t>(object),&pool,sizeof(pool))||!lease.copy(reinterpret_cast<uint64_t>(sampler_object),&snapshot,sizeof(snapshot)))return error(p,NVN_INVALID,"sampler descriptor storage is unowned");
    try {
        std::map<int,DescriptorSlot> staging;staging.emplace(id,DescriptorSlot{snapshot.serial,0});auto node=staging.extract(id);
        std::lock_guard<std::mutex> admission(p.admission);std::lock_guard<std::mutex> lock(p.registry);
        auto parent=p.descriptor_pools.find(pool.serial);auto source=p.samplers.find(snapshot.serial);
        if(parent==p.descriptor_pools.end()||!parent->second.sampler||parent->second.object!=object||!same_descriptor_pool(pool,parent->second.snapshot)||id<0||id>=pool.n||
           source==p.samplers.end()||source->second.object!=sampler_object||!same_sampler(snapshot,source->second.snapshot)||source->second.descriptors==UINT32_MAX)return error(p,NVN_INVALID,"sampler registration has stale pool/resource or invalid ID");
        auto previous=parent->second.slots.find(id);if(previous!=parent->second.slots.end()&&previous->second.readers)return error(p,NVN_RETAINED,"accepted draw retains sampler descriptor");
        if(previous!=parent->second.slots.end()){--p.samplers.at(previous->second.resource).descriptors;parent->second.slots.erase(previous);}
        ++source->second.descriptors;parent->second.slots.insert(std::move(node));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"sampler descriptor allocation failed");}
}
bool acquire_sampled(Platform& p,const std::shared_ptr<GraphicsLease>& lease,const dpool_t& texture_pool,const dpool_t& sampler_pool,
    uint64_t texture_handle,uint64_t sampler_handle,std::shared_ptr<const SubmitSampledResource>* out,std::string* detail) {
    if(out)out->reset();
    auto refuse=[&](const char* why){if(detail)*detail=why;return false;};
    if(!out||!lease||!current_lease(p,*lease)||(texture_handle&~uint64_t(0xfffff))||(sampler_handle&~uint64_t(0xfff00000)))return refuse("invalid sampled acquisition generation or handle bits");
    try {
        auto retained=std::make_shared<AcquiredSampled>();retained->owner=std::atomic_load(&platform);retained->memory=lease;
        if(retained->owner.get()!=&p)return refuse("sampled owner binding retired");
        auto result=std::make_shared<SubmitSampledResource>();result->lease=retained;
        const int texture_id=int(texture_handle),sampler_id=int(sampler_handle>>20);
        std::lock_guard<std::mutex> lock(p.registry);
        auto tp=p.descriptor_pools.find(texture_pool.serial),sp=p.descriptor_pools.find(sampler_pool.serial);
        if(tp==p.descriptor_pools.end()||sp==p.descriptor_pools.end()||tp->second.sampler||!sp->second.sampler||
           !same_descriptor_pool(tp->second.snapshot,texture_pool)||!same_descriptor_pool(sp->second.snapshot,sampler_pool)||
           texture_id>=texture_pool.n||sampler_id>=sampler_pool.n)return refuse("sampled descriptor pools/IDs are stale or invalid");
        auto ts=tp->second.slots.find(texture_id),ss=sp->second.slots.find(sampler_id);
        if(ts==tp->second.slots.end()||ss==sp->second.slots.end())return refuse("sampled descriptor ID is not registered");
        auto tex=p.textures.find(ts->second.resource);auto sampler=p.samplers.find(ss->second.resource);
        if(tex==p.textures.end()||sampler==p.samplers.end())return refuse("sampled descriptor resource retired");
        auto descriptor_current=[&](const BackendDescriptorPool& pool) {
            dpool_t object{};pool_t backing{};auto live=p.pools.find(pool.backing);
            return live!=p.pools.end()&&object_storage(p,*lease,pool.object,sizeof(NVNtexturePool),false)&&
                lease->copy(reinterpret_cast<uint64_t>(pool.object),&object,sizeof(object))&&same_descriptor_pool(object,pool.snapshot)&&
                reinterpret_cast<const void*>(live->second.object)==pool.snapshot.pool&&object_storage(p,*lease,pool.snapshot.pool,sizeof(NVNmemoryPool),false)&&
                lease->copy(reinterpret_cast<uint64_t>(pool.snapshot.pool),&backing,sizeof(backing))&&same_pool(backing,live->second.snapshot);
        };
        tex_t texture{};samp_t sampler_value{};pool_t source_backing{};auto source_pool=p.pools.find(tex->second.pool);
        if(!descriptor_current(tp->second)||!descriptor_current(sp->second)||source_pool==p.pools.end()||
           !object_storage(p,*lease,tex->second.object,sizeof(NVNtexture),false)||!lease->copy(reinterpret_cast<uint64_t>(tex->second.object),&texture,sizeof(texture))||
           !same_texture(texture,tex->second.snapshot)||!window_texture_shape(texture)||reinterpret_cast<const void*>(source_pool->second.object)!=texture.pool||
           !object_storage(p,*lease,texture.pool,sizeof(NVNmemoryPool),false)||!lease->copy(reinterpret_cast<uint64_t>(texture.pool),&source_backing,sizeof(source_backing))||
           !same_pool(source_backing,source_pool->second.snapshot)||!lease->admit(reinterpret_cast<uint64_t>(texture.mem),texture.L.size,DM_GUEST_READ)||
           !object_storage(p,*lease,sampler->second.object,sizeof(NVNsampler),false)||!lease->copy(reinterpret_cast<uint64_t>(sampler->second.object),&sampler_value,sizeof(sampler_value))||
           !same_sampler(sampler_value,sampler->second.snapshot)||!sampled_sampler(sampler_value.p))return refuse("sampled registration public object/backing revision changed");
        if(tp->second.readers==UINT32_MAX||sp->second.readers==UINT32_MAX||ts->second.readers==UINT32_MAX||ss->second.readers==UINT32_MAX||
           tex->second.readers==UINT32_MAX||sampler->second.readers==UINT32_MAX)return refuse("sampled reference count exhausted");
        result->texture=texture;result->texture.pool=nullptr;result->sampler=sampler_value.p;result->generation=p.generation;result->binding_epoch=p.binding_epoch;
        retained->texture_pool=tp->first;retained->sampler_pool=sp->first;retained->texture_id=texture_id;retained->sampler_id=sampler_id;
        retained->texture=tex->first;retained->sampler=sampler->first;
        ++tp->second.readers;++sp->second.readers;++ts->second.readers;++ss->second.readers;++tex->second.readers;++sampler->second.readers;retained->active=true;
        *out=std::move(result);return true;
    }catch(const std::bad_alloc&){return refuse("sampled owner allocation failed");}
}
nvn_result read_texels(void* ctx,const tex_t*,int,int,const NVNcopyRegion*,void*,size_t,size_t){return unavailable(ctx);}
nvn_result window_storage_acquire(void* ctx,const void* object,size_t bytes,uint32_t access,void** out) {
    auto& p=*static_cast<Platform*>(ctx);if(out)*out=nullptr;
    if(!out||!bytes||bytes>32768||!access||(access&~uint32_t(NVN_STORAGE_READ|NVN_STORAGE_WRITE)))return error(p,NVN_INVALID,"invalid W0 storage request");
    try {
        auto lease=std::make_unique<GraphicsLease>();
        if(!current_lease(p,*lease)||!lease->admit_program_storage(reinterpret_cast<uint64_t>(object),bytes,access))return error(p,NVN_INVALID,"W0 storage is not current owned memory with the required permissions");
        *out=lease.release();return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"W0 storage lease allocation failed");}
}
void window_storage_release(void*,void* token){delete static_cast<GraphicsLease*>(token);}
nvn_result window_init(void* ctx,NVNwindow* object,const NVNwindowBuilder* builder) {
    auto& p=*static_cast<Platform*>(ctx);
    try {
        GraphicsLease lease;win_builder_t input{};
        if(!object_storage(p,lease,object,sizeof(*object),true)||!object_storage(p,lease,builder,sizeof(*builder),false)||
           !lease.copy(reinterpret_cast<uint64_t>(builder),&input,sizeof(input)))return error(p,NVN_INVALID,"window/builder storage is not owned");
        if(input.ntex<1||input.ntex>4||(input.interval!=0&&input.interval!=1))return error(p,NVN_UNSUPPORTED,"window requires 1..4 textures and interval 0 or 1");
        dev_t_ device{};ViNativeWindow native{};
        if(!object_storage(p,lease,input.dev,sizeof(NVNdevice),false)||!lease.copy(reinterpret_cast<uint64_t>(input.dev),&device,sizeof(device))||
           device.magic!=MAGIC('D','E','V',0)||!p.engine.shader_device_contract().initialized||
           !vi_platform_native_window(input.native,p.generation,&native))return error(p,NVN_INVALID,"window device or current VI native token is unavailable");
        std::array<tex_t,4> textures{};std::array<pool_t,4> pools{};uint64_t bytes=0;
        for(int i=0;i<input.ntex;++i) {
            if(!object_storage(p,lease,input.tex[i],sizeof(NVNtexture),false)||!lease.copy(reinterpret_cast<uint64_t>(input.tex[i]),&textures[i],sizeof(tex_t))||
               !window_texture_shape(textures[i])||!object_storage(p,lease,textures[i].pool,sizeof(NVNmemoryPool),false)||
               !lease.copy(reinterpret_cast<uint64_t>(textures[i].pool),&pools[i],sizeof(pool_t)))return error(p,NVN_INVALID,"unsupported or unowned window texture/pool");
            if(textures[i].L.size>64u*1024u*1024u-bytes)return error(p,NVN_RETAINED,"window texture storage budget exceeded");bytes+=textures[i].L.size;
            for(int j=0;j<i;++j)if(input.tex[j]==input.tex[i]||textures[j].serial==textures[i].serial||
                textures[j].d.width!=textures[i].d.width||textures[j].d.height!=textures[i].d.height||
                overlap(reinterpret_cast<uint64_t>(textures[i].mem),textures[i].L.size,reinterpret_cast<uint64_t>(textures[j].mem),textures[j].L.size))return error(p,NVN_INVALID,"window textures overlap, repeat, or have different extents");
        }
        std::lock_guard<std::mutex> lock(p.registry);
        if(p.window.object||p.window.live||p.window.retired||p.next_window==UINT64_MAX)return error(p,NVN_RETAINED,"one window lifecycle per runtime binding; replacement/reuse refused");
        if(resource_object_alias(p,object,sizeof(*object),ResourceObjectKind::Window))return error(p,NVN_INVALID,"window output aliases a live resource object");
        BackendWindow candidate;candidate.object=object;candidate.device=input.dev;candidate.revision=p.next_window+1;candidate.live=true;
        candidate.snapshot.magic=MAGIC('W','I','N','D');candidate.snapshot.native=input.native;candidate.snapshot.ntex=input.ntex;candidate.snapshot.interval=input.interval;
        for(int i=0;i<input.ntex;++i) {
            auto tex=p.textures.find(textures[i].serial);
            if(tex==p.textures.end()||tex->second.object!=input.tex[i]||!same_texture(textures[i],tex->second.snapshot)||tex->second.windows==UINT32_MAX)return error(p,NVN_INVALID,"window texture is not the authoritative registered revision");
            auto pool=p.pools.find(tex->second.pool);
            if(pool==p.pools.end()||reinterpret_cast<const void*>(pool->second.object)!=textures[i].pool||!same_pool(pools[i],pool->second.snapshot))return error(p,NVN_INVALID,"window texture backing pool revision mismatch");
            candidate.textures[i]=tex->first;candidate.snapshot.tex[i]=input.tex[i];
        }
        for(int i=0;i<input.ntex;++i)++p.textures.at(candidate.textures[i]).windows;
        ++p.next_window;p.window=candidate;std::memcpy(object,&candidate.snapshot,sizeof(candidate.snapshot));return ok();
    }catch(const std::bad_alloc&){return error(p,NVN_UNAVAILABLE,"window preparation allocation failed");}
}
void reap_abandoned_acquires(Platform& p) {
    for(auto& slot:p.window.slots)if(slot.abandoned&&slot.fence&&p.engine.wait(slot.fence,0).state!=VkSubmitState::Pending)slot={};
}
bool window_busy(Platform& p) {
    reap_abandoned_acquires(p);
    for(const auto& slot:p.window.slots)if(slot.state==WindowSlotState::Acquiring||slot.state==WindowSlotState::PresentPending||
        (slot.fence&&p.engine.wait(slot.fence,0).state==VkSubmitState::Pending))return true;
    return false;
}
nvn_result acquire_resources(Platform& p,GraphicsLease& lease,NVNwindow* object,NVNsync* sync,int* index) {
    std::array<BackendTexture,4> textures{};std::array<BackendPool,4> pools{};int count=0;NVNdevice* device=nullptr;
    {
        std::lock_guard<std::mutex> lock(p.registry);
        if(!window_current(p,object))return error(p,NVN_INVALID,"acquire resource window is not current");
        count=p.window.snapshot.ntex;device=p.window.device;
        for(int i=0;i<count;++i){auto texture=p.textures.find(p.window.textures[i]);
            if(texture==p.textures.end()||!texture->second.windows)return error(p,NVN_INVALID,"acquire texture ownership retired");
            auto pool=p.pools.find(texture->second.pool);if(pool==p.pools.end()||!pool->second.textures)return error(p,NVN_INVALID,"acquire pool ownership retired");
            textures[i]=texture->second;pools[i]=pool->second;
        }
    }
    const auto aliases_output=[&](const void* address,size_t bytes){return overlap(reinterpret_cast<uint64_t>(index),sizeof(*index),reinterpret_cast<uint64_t>(address),bytes)||
        (sync&&overlap(reinterpret_cast<uint64_t>(sync),sizeof(*sync),reinterpret_cast<uint64_t>(address),bytes));};
    if(aliases_output(device,sizeof(*device))||!object_storage(p,lease,device,sizeof(*device),false))return error(p,NVN_INVALID,"acquire output overlaps device or its storage is not owned");
    for(int i=0;i<count;++i) {
        const auto& texture=textures[i];const auto& pool=pools[i];
        if(aliases_output(texture.object,sizeof(NVNtexture))||aliases_output(pool.object,sizeof(NVNmemoryPool)))return error(p,NVN_INVALID,"acquire output overlaps a registered texture or pool object");
        if(!object_storage(p,lease,texture.object,sizeof(NVNtexture),false)||!object_storage(p,lease,pool.object,sizeof(NVNmemoryPool),false)||
           !lease.admit(reinterpret_cast<uint64_t>(texture.snapshot.mem),size_t(texture.snapshot.L.size),DM_GUEST_READ))return error(p,NVN_INVALID,"acquire texture/pool/backing span is not current owned memory");
    }
    std::lock_guard<std::mutex> lock(p.registry);
    if(!window_current(p,object)||reinterpret_cast<const dev_t_*>(device)->magic!=MAGIC('D','E','V',0))return error(p,NVN_INVALID,"acquire device/window revision changed");
    for(int i=0;i<count;++i) {
        const auto& texture=textures[i];const auto& pool=pools[i];auto registered=p.textures.find(texture.snapshot.serial);
        if(registered==p.textures.end()||registered->second.object!=texture.object||registered->second.pool!=texture.pool||
           !same_texture(registered->second.snapshot,texture.snapshot)||!same_texture(*reinterpret_cast<const tex_t*>(texture.object),texture.snapshot)||
           !same_pool(*reinterpret_cast<const pool_t*>(pool.object),pool.snapshot))return error(p,NVN_INVALID,"acquire authoritative texture or pool snapshot changed");
    }
    return ok();
}
void retire_window(Platform& p) {
    auto& window=p.window;
    if(window.live)for(int i=0;i<window.snapshot.ntex;++i){auto tex=p.textures.find(window.textures[i]);if(tex==p.textures.end()||!tex->second.windows)std::abort();--tex->second.windows;}
    window.live=false;window.retired=true;window.slots={};
}
nvn_result window_finalize(void* ctx,NVNwindow* object) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;
    if(!object_storage(p,lease,object,sizeof(*object),true))return error(p,NVN_INVALID,"window finalization storage is not owned");
    std::lock_guard<std::mutex> lock(p.registry);
    if(!window_current(p,object))return error(p,NVN_INVALID,"window is altered, foreign or retired");
    if(window_busy(p))return error(p,NVN_RETAINED,"window call or dependency remains pending");
    retire_window(p);reinterpret_cast<win_t*>(object)->magic=0;return ok();
}
nvn_result window_set_present_interval(void* ctx,NVNwindow* object,int interval) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;
    if(!object_storage(p,lease,object,sizeof(*object),true))return error(p,NVN_INVALID,"window interval storage is not owned");
    if(interval!=0&&interval!=1)return error(p,NVN_UNSUPPORTED,"only actual cadence intervals 0 and 1 are supported");
    std::lock_guard<std::mutex> lock(p.registry);
    if(!window_current(p,object))return error(p,NVN_INVALID,"window interval revision is not current");
    if(window_busy(p))return error(p,NVN_RETAINED,"window operation is in flight");
    p.window.snapshot.interval=interval;reinterpret_cast<win_t*>(object)->interval=interval;return ok();
}
nvn_result window_set_crop(void* ctx,NVNwindow* object,int x,int y,int width,int height) {
    auto& p=*static_cast<Platform*>(ctx);GraphicsLease lease;
    if(!object_storage(p,lease,object,sizeof(*object),true))return error(p,NVN_INVALID,"window crop storage is not owned");
    std::lock_guard<std::mutex> lock(p.registry);
    if(!window_current(p,object))return error(p,NVN_INVALID,"window crop revision is not current");
    if(window_busy(p))return error(p,NVN_RETAINED,"window operation is in flight");
    const auto tex=p.textures.find(p.window.textures[0]);if(tex==p.textures.end())return error(p,NVN_INVALID,"window texture retired");
    const auto& desc=tex->second.snapshot.d;
    if((x||y||width||height)&&(x<0||y<0||width<=0||height<=0||uint64_t(x)+uint64_t(width)>desc.width||uint64_t(y)+uint64_t(height)>desc.height))return error(p,NVN_INVALID,"crop is not full-extent zero or an in-bounds positive rectangle");
    const int crop[4]={x,y,width,height};std::memcpy(p.window.snapshot.crop,crop,sizeof(crop));std::memcpy(reinterpret_cast<win_t*>(object)->crop,crop,sizeof(crop));return ok();
}
NVNwindowAcquireTextureResult window_acquire(void* ctx,NVNwindow* object,NVNsync* sync,int* index) {
    auto& p=*static_cast<Platform*>(ctx);int selected=-1;uint64_t revision=0;
    auto refuse=[&](nvn_error_code code,const char* reason) {
        if(selected>=0){std::lock_guard<std::mutex> lock(p.registry);if(p.window.revision==revision&&p.window.slots[selected].state==WindowSlotState::Acquiring){
            auto& slot=p.window.slots[selected];
            if(slot.fence&&p.engine.wait(slot.fence,0).state==VkSubmitState::Pending)slot.abandoned=true;
            else slot={};
        }}
        nvn_core_record_error(error(p,code,reason));return NVN_WINDOW_ACQUIRE_TEXTURE_RESULT_NATIVE_ERROR;
    };
    try {
        auto lease=std::make_shared<GraphicsLease>();
        if(!object_storage(p,*lease,object,sizeof(*object),true)||!object_storage(p,*lease,index,sizeof(*index),true)||
           (sync&&!object_storage(p,*lease,sync,sizeof(*sync),true)))return refuse(NVN_INVALID,"acquire object/output storage is not owned");
        if(overlap(reinterpret_cast<uint64_t>(object),sizeof(*object),reinterpret_cast<uint64_t>(index),sizeof(*index))||
           (sync&&(overlap(reinterpret_cast<uint64_t>(sync),sizeof(*sync),reinterpret_cast<uint64_t>(index),sizeof(*index))||
                   overlap(reinterpret_cast<uint64_t>(sync),sizeof(*sync),reinterpret_cast<uint64_t>(object),sizeof(*object)))))return refuse(NVN_INVALID,"acquire outputs overlap window or one another");
        if(sync&&reinterpret_cast<const sync_t*>(sync)->magic!=MAGIC('S','Y','N','C'))return refuse(NVN_INVALID,"acquire sync is not initialized");
        const auto resources=acquire_resources(p,*lease,object,sync,index);if(resources.code)return refuse(resources.code,resources.reason);
        void* native_token=nullptr;int interval=0;uint64_t cadence_serial=0;
        {
            std::lock_guard<std::mutex> lock(p.registry);
            if(!window_current(p,object))return refuse(NVN_INVALID,"acquire window revision is not current");
            native_token=p.window.snapshot.native;interval=p.window.snapshot.interval;cadence_serial=p.window.cadence_serial;revision=p.window.revision;
        }
        ViNativeWindow native{};if(!vi_platform_native_window(native_token,p.generation,&native))return refuse(NVN_UNAVAILABLE,"acquire has no current VI Surface");
        {
            std::lock_guard<std::mutex> lock(p.registry);
            if(!window_current(p,object)||p.window.revision!=revision)return refuse(NVN_INVALID,"window changed during Surface capture");
            reap_abandoned_acquires(p);
            for(const auto& slot:p.window.slots)if(slot.state==WindowSlotState::Acquiring)return refuse(NVN_RETAINED,"another window acquire or abandoned dependency is pending");
            // Serialize reservations and capture the latest committed cursor at
            // that boundary. Earlier Surface queries may overlap another call.
            interval=p.window.snapshot.interval;cadence_serial=p.window.cadence_serial;
            for(int i=0;i<p.window.snapshot.ntex;++i)if(p.window.slots[i].state==WindowSlotState::Acquired&&!same_ticket(p.window.slots[i].surface,native.surface))p.window.slots[i].state=WindowSlotState::Available;
            for(int n=0;n<p.window.snapshot.ntex;++n){int i=(p.window.snapshot.next+n)%p.window.snapshot.ntex;if(p.window.slots[i].state==WindowSlotState::Available){selected=i;break;}}
            if(selected<0)return refuse(NVN_RETAINED,"all window texture slots are acquired or pending");
            p.window.slots[selected].state=WindowSlotState::Acquiring;
        }
        SurfaceCadence cadence{};
        if(interval&&!graphics_surface_wait_cadence(native.surface,cadence_serial,1000000000ull,&cadence))return refuse(NVN_UNAVAILABLE,"actual Surface cadence unavailable or retired");
        uint64_t fence=0;
        {
            std::lock_guard<std::mutex> admission(p.admission);auto drained=p.engine.drain();
            if(drained.state!=VkSubmitState::Completed)return refuse(vk_error(drained.error_kind),drained.error.c_str());
            if(sync){auto plan=std::make_shared<PreparedSubmit>();plan->generation=p.generation;plan->lease=lease;
                VkPublish publish=[lease](const auto& writes,const auto& events,std::string& detail){return lease->publish(writes,events,detail);};
                auto accepted=p.engine.submit(std::move(plan),std::move(publish));
                if(!accepted.accepted)return refuse(vk_error(accepted.error_kind),accepted.error.c_str());fence=accepted.fence;
                // Publish ownership before any later Surface/commit refusal.
                // The engine retains its actual lease; the slot keeps its
                // fence until real terminal completion can retire the reserve.
                {std::lock_guard<std::mutex> lock(p.registry);if(p.window.revision!=revision||p.window.slots[selected].state!=WindowSlotState::Acquiring)std::abort();p.window.slots[selected].fence=fence;}
            }
        }
        ViNativeWindow latest{};if(!vi_platform_native_window(native_token,p.generation,&latest)||!same_ticket(native.surface,latest.surface))return refuse(NVN_UNAVAILABLE,"Surface changed before acquire commit");
        {
            std::unique_lock<std::mutex> lock(p.registry);
            if(!window_current(p,object)||p.window.revision!=revision||p.window.slots[selected].state!=WindowSlotState::Acquiring){lock.unlock();return refuse(NVN_INVALID,"acquire reservation changed");}
            if(interval&&cadence.serial<=p.window.cadence_serial){lock.unlock();return refuse(NVN_RETAINED,"cadence tick was already committed by another acquire");}
            auto& w=p.window;w.slots[selected]={WindowSlotState::Acquired,native.surface,fence};w.surface=native.surface;w.last_acquire_fence=fence;
            if(interval)w.cadence_serial=cadence.serial;
            w.snapshot.next=(selected+1)%w.snapshot.ntex;w.snapshot.pace=w.cadence_serial;w.snapshot.ticket[selected]=native.surface.epoch;
            std::memcpy(object,&w.snapshot,sizeof(w.snapshot));if(sync){auto* s=reinterpret_cast<sync_t*>(sync);s->fenced=1;s->fence=fence;}*index=selected;
        }
        return NVN_WINDOW_ACQUIRE_TEXTURE_RESULT_SUCCESS;
    }catch(const std::bad_alloc&){return refuse(NVN_UNAVAILABLE,"acquire allocation failed");}
}
nvn_result window_present(void* ctx,NVNqueue* queue,NVNwindow* object,int index) {
    auto& p=*static_cast<Platform*>(ctx);bool reserved=false;uint64_t revision=0;
    auto finish=[&](nvn_error_code code,const char* reason,bool pending=false) {
        if(reserved&&!pending){std::lock_guard<std::mutex> lock(p.registry);if(p.window.revision==revision&&p.window.slots[index].state==WindowSlotState::PresentPending)p.window.slots[index].state=WindowSlotState::Available;}
        return code==NVN_OK?ok():error(p,code,reason);
    };
    try {
        auto lease=std::make_shared<GraphicsLease>();
        if(!object_storage(p,*lease,object,sizeof(*object),true)||!object_storage(p,*lease,queue,sizeof(*queue),true))return finish(NVN_INVALID,"present queue/window storage is not owned");
        BackendTexture texture;BackendPool pool;SurfaceTicket ticket{};std::array<int,4> crop{};
        {
            std::lock_guard<std::mutex> lock(p.registry);const auto* q=reinterpret_cast<const queue_t*>(queue);
            if(!window_current(p,object)||q->magic!=MAGIC('Q','U','E','U')||q->dev!=p.window.device||index<0||index>=p.window.snapshot.ntex)return finish(NVN_INVALID,"present queue/window/index is not current");
            if(p.window.slots[index].state!=WindowSlotState::Acquired)return finish(NVN_INVALID,"present slot is not acquired");
            auto tex=p.textures.find(p.window.textures[index]);if(tex==p.textures.end())return finish(NVN_INVALID,"window texture revision retired");
            auto backing=p.pools.find(tex->second.pool);if(backing==p.pools.end())return finish(NVN_INVALID,"window pool revision retired");
            texture=tex->second;pool=backing->second;ticket=p.window.slots[index].surface;revision=p.window.revision;
            std::copy(std::begin(p.window.snapshot.crop),std::end(p.window.snapshot.crop),crop.begin());
        }
        if(!object_storage(p,*lease,texture.object,sizeof(NVNtexture),false)||!object_storage(p,*lease,pool.object,sizeof(NVNmemoryPool),false)||
           !lease->admit(reinterpret_cast<uint64_t>(texture.snapshot.mem),size_t(texture.snapshot.L.size),DM_GUEST_READ))return finish(NVN_INVALID,"present texture/pool/backing memory is not owned");
        {
            std::lock_guard<std::mutex> lock(p.registry);
            if(!window_current(p,object)||p.window.revision!=revision||p.window.slots[index].state!=WindowSlotState::Acquired||
               !same_texture(*reinterpret_cast<const tex_t*>(texture.object),texture.snapshot)||!same_pool(*reinterpret_cast<const pool_t*>(pool.object),pool.snapshot))return finish(NVN_INVALID,"present resource revision changed");
            p.window.slots[index].state=WindowSlotState::PresentPending;reserved=true;
        }
        std::vector<uint8_t> storage(size_t(texture.snapshot.L.size));
        {
            std::lock_guard<std::mutex> admission(p.admission);const auto drained=p.engine.drain();
            if(drained.state!=VkSubmitState::Completed)return finish(vk_error(drained.error_kind),drained.error.c_str(),drained.error_kind==VkErrorKind::UnprovenTermination);
            if(!lease->copy(reinterpret_cast<uint64_t>(texture.snapshot.mem),storage.data(),storage.size()))return finish(NVN_INVALID,"present storage snapshot refused");
        }
        const auto& d=texture.snapshot.d;SurfaceFrame frame;frame.width=d.width;frame.height=d.height;frame.row_stride_bytes=d.width*4;frame.rgba8.resize(size_t(d.width)*d.height*4);
        if(storage.capacity()>128u*1024u*1024u-frame.rgba8.capacity())return finish(NVN_RETAINED,"present transient byte budget exceeded");
        if(d.flags&0x10){const uint64_t stride=d.stride?d.stride:uint64_t(d.width)*4;
            if(uint64_t(d.height-1)*stride+uint64_t(d.width)*4>storage.size())return finish(NVN_INVALID,"linear present rows exceed storage");
            for(uint32_t y=0;y<d.height;++y)std::memcpy(frame.rgba8.data()+uint64_t(y)*frame.row_stride_bytes,storage.data()+uint64_t(y)*stride,frame.row_stride_bytes);
        }else if(nvn_deswizzle(&d,0,0,storage.data(),frame.rgba8.data(),frame.row_stride_bytes)!=0)return finish(NVN_INVALID,"present deswizzle refused");
        if(crop[2]){const auto width=uint32_t(crop[2]),height=uint32_t(crop[3]);
            for(uint32_t y=0;y<height;++y)std::memmove(frame.rgba8.data()+uint64_t(y)*width*4,frame.rgba8.data()+uint64_t(y+crop[1])*frame.row_stride_bytes+uint64_t(crop[0])*4,uint64_t(width)*4);
            frame.width=width;frame.height=height;frame.row_stride_bytes=width*4;frame.rgba8.resize(uint64_t(width)*height*4);
        }
        const auto result=graphics_surface_present(ticket,p.generation,std::move(frame));
        if(!result.accepted||!result.posted)return finish(NVN_PUBLICATION_FAILED,result.error.empty()?"Surface did not accept and post the frame":result.error.c_str());
        {
            std::lock_guard<std::mutex> lock(p.registry);
            if(p.window.revision!=revision||p.window.slots[index].state!=WindowSlotState::PresentPending)std::abort();
            ++p.window.snapshot.presents;++p.presents;std::memcpy(object,&p.window.snapshot,sizeof(p.window.snapshot));p.window.slots[index].state=WindowSlotState::Available;
        }
        return ok();
    }catch(const std::bad_alloc&){return finish(NVN_UNAVAILABLE,"present frame allocation failed");}
}
}
bool graphics_platform_bind(const Process& process,std::string* detail) {
    if(std::atomic_load(&platform)){if(detail)*detail="graphics platform already bound";return false;}
    // Unrelated existing fixtures retain their previous behavior and need no
    // graphics binding. Full product capability remains a separate future gate.
    const bool fixture=graphics_diagnostic_graph(process,nullptr);
    const bool original=!fixture && original_bringup_graph(process,nullptr);
    if(!fixture && !original)return true;
    auto candidate=std::make_shared<Platform>();candidate->generation=process.load_generation();
    std::string catalog_error;
    if(!create_compute_source_catalog(process,&candidate->source_catalog,&catalog_error) && original){
        if(detail)*detail=catalog_error.empty()?"original compute source catalog unavailable":catalog_error;
        return false;
    }
    // Draw source admission independently verifies its complete current graph
    // and shader provenance; compute admission grants no draw authority.
    if(!create_draw_source_catalog(process,&candidate->draw_catalog,&catalog_error)&&original){if(detail)*detail=catalog_error.empty()?"original draw source catalog unavailable":catalog_error;return false;}
    auto& ops=candidate->ops;ops.abi_version=NVN_BACKEND_ABI_VERSION;ops.capabilities=NVN_CAP_OFFSCREEN;
    ops.device_initialize=initialize;ops.device_finalize=[](void* ctx,const dev_t_*){return drain(ctx);};ops.pool_add=pool_add;ops.pool_del=pool_del;ops.tex_register=tex_register;ops.tex_release=tex_release;ops.prog_release=prog_release;ops.tex_pool_init=tex_pool_init;ops.tex_pool_release=tex_pool_release;ops.samp_pool_init=samp_pool_init;ops.samp_pool_release=samp_pool_release;ops.sampler_init=sampler_init;ops.sampler_release=sampler_release;ops.reg_tex=reg_tex;ops.reg_samp=reg_samp;ops.read_texels=read_texels;ops.submit=submit;ops.last_fence=last_fence;ops.wait=wait;ops.finish=drain;ops.drain=drain;ops.queue_error=queue_error;ops.command_callback=callback;ops.frame_count=frame_count;ops.window_init=window_init;ops.window_acquire=window_acquire;ops.window_present=window_present;
    ops.prog_replace=prog_replace;ops.prog_acquire=prog_acquire;ops.prog_unacquire=prog_unacquire;
    ops.prog_copy_shaders=prog_copy_shaders;
    ops.prog_storage_acquire=prog_storage_acquire;ops.prog_storage_release=prog_storage_release;
    ops.window_storage_acquire=window_storage_acquire;ops.window_storage_release=window_storage_release;
    ops.window_finalize=window_finalize;ops.window_set_present_interval=window_set_present_interval;ops.window_set_crop=window_set_crop;
    auto bound=nvn_core_bind(&ops,candidate.get());if(bound.code!=NVN_OK){if(detail)*detail=bound.reason?bound.reason:"NVN binding refused";return false;}
    candidate->binding_epoch=nvn_core_binding_epoch();
    std::atomic_store(&platform,std::move(candidate));return true;
}
bool graphics_platform_close(const GraphicsClosePermit& permit,std::string* detail) {
    auto current=std::atomic_load(&platform);
    if(!current)return true;
    if(!permit.generation() || permit.generation()!=current->generation){if(detail)*detail="graphics close generation mismatch";return false;}
    auto result=current->engine.drain();if(result.state==VkSubmitState::Pending){if(detail)*detail="graphics work remains pending";return false;}
    auto unbound=nvn_core_unbind();
    if(unbound.code!=NVN_OK){if(detail)*detail=unbound.reason?unbound.reason:"NVN unbind refused";return false;}
    {std::lock_guard<std::mutex> lock(current->registry);retire_window(*current);}
    std::atomic_store(&platform,std::shared_ptr<Platform>{});return true;
}
bool graphics_host_target(uintptr_t address,uint64_t generation) {
    auto current=std::atomic_load(&platform);
    if(!current || !generation || generation!=current->generation || !address)return false;
    for(size_t i=0;i<NVN_NFUNC;++i)if(address==reinterpret_cast<uintptr_t>(nvn_thunk[i]))return true;
    return false;
}
DrawDeviceContract graphics_platform_draw_device_contract(uint64_t generation){auto current=std::atomic_load(&platform);return current&&generation&&current->generation==generation?current->engine.draw_device_contract():DrawDeviceContract{};}
VkReplayStats graphics_platform_stats(){auto current=std::atomic_load(&platform);return current?current->engine.stats():VkReplayStats{};}
GraphicsProgramStats graphics_platform_program_stats(){auto current=std::atomic_load(&platform);GraphicsProgramStats out;if(!current)return out;std::lock_guard<std::mutex> lock(current->programs_mutex);out.live=current->programs.size();out.bytes=current->program_bytes;out.created=current->program_created;out.replaced=current->program_replaced;out.released=current->program_released;for(const auto& entry:current->programs)out.retained+=entry.second->retained;return out;}
GraphicsWindowStats graphics_platform_window_stats() {
    auto current=std::atomic_load(&platform);GraphicsWindowStats out;if(!current)return out;
    std::lock_guard<std::mutex> lock(current->registry);const auto& window=current->window;
    out.generation=current->generation;out.binding_epoch=current->binding_epoch;out.revision=window.revision;
    out.presents=window.snapshot.presents;out.last_acquire_fence=window.last_acquire_fence;out.cadence_serial=window.cadence_serial;
    out.surface=window.surface;out.live=window.live;out.retired=window.retired;
    for(int i=0;i<window.snapshot.ntex;++i)switch(window.slots[i].state){case WindowSlotState::Available:++out.available;break;case WindowSlotState::Acquiring:++out.acquiring;break;case WindowSlotState::Acquired:++out.acquired;break;case WindowSlotState::PresentPending:++out.pending;break;}
    return out;
}
uint64_t graphics_platform_last_fence(){auto current=std::atomic_load(&platform);return current?current->engine.last_fence():0;}
uint64_t graphics_platform_last_fence(uint64_t generation){auto current=std::atomic_load(&platform);return current&&generation&&current->generation==generation?current->engine.last_fence():0;}
uint64_t graphics_platform_completed_fence(){auto current=std::atomic_load(&platform);return current?current->engine.completed_fence():0;}
bool graphics_platform_publication_barrier(uint64_t generation,bool hold){auto current=std::atomic_load(&platform);if(!current || !generation || current->generation!=generation)return false;current->engine.publication_barrier(hold);return true;}
bool graphics_platform_publication_barrier_entered(uint64_t generation){auto current=std::atomic_load(&platform);return current&&generation&&current->generation==generation&&current->engine.publication_barrier_entered();}
bool graphics_platform_inject_failure(NvnVkEngine::Failure failure){auto current=std::atomic_load(&platform);return current&&current->engine.inject_failure(failure);}
bool graphics_platform_shader_readiness(uint64_t generation,const ResolvedProgram& program,
                                       ShaderDeviceContract* facts,std::string* detail) {
    if(facts)*facts={};
    try {
        auto current=std::atomic_load(&platform);
        if(!current || !generation || current->generation!=generation || program.generation()!=generation) {
            if(detail)*detail="shader readiness generation is not current";
            return false;
        }
        auto contract=current->engine.shader_device_contract();
        const bool compatible=check_shader_program_device(program,contract,detail);
        if(std::atomic_load(&platform)!=current) {
            if(detail)*detail="shader readiness binding retired during inspection";
            return false;
        }
        if(facts)*facts=std::move(contract);
        return compatible;
    } catch(const std::bad_alloc&) {
        if(detail)*detail="shader readiness metadata allocation failed";
        return false;
    }
}
} // namespace dm_android
