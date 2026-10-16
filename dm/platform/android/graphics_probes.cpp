#include "graphics_probes.h"
#include "diagnostic_authority.h"
#include "graphics_platform.h"
#include "vi_platform.h"
#include "shader_compute_catalog.h"
#include "guest_bootstrap.h"
#include "kernel_memory_android.h"
#include "kernel_platform.h"
#include "../../gfx/nvn/hle_nvn_core.h"
#include "../../gfx/nvn/nvn_protos.h"
#include "graphics_fixtures/generated_graphics.h"
#include "graphics_fixtures/record.h"
#include "graphics_fixtures/draw_probe_record.h"
#include "module_sha256.h"
#include "observation_fixtures/generated_observations.h"
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <algorithm>
#include <condition_variable>

namespace {
using namespace dm_android;
bool fail(std::string* error,const char* message){if(error)*error=message;return false;}
std::string escaped(const std::string& s){std::string r;for(unsigned char c:s){if(c=='"'||c=='\\')r+='\\';r+=c<32?' ':c;}return r;}
std::string hex(const uint8_t* b,size_t n){static const char d[]="0123456789abcdef";std::string r;for(size_t i=0;i<n;++i){r+=d[b[i]>>4];r+=d[b[i]&15];}return r;}

// Metadata controls deliberately never acquire probe_mutex. A waiter may own
// that mutex and a guest invocation while the completion worker waits here.
std::mutex metadata_mutex;
DmGraphicsPublicationBarrier barrier;
uint64_t next_barrier=0;
bool owner_active=false;
// Screenshot handshakes are observation-only. They do not admit a graph,
// program, descriptor or Surface ticket and never take the probe/runtime lock.
std::mutex sampled_observation_mutex;
std::condition_variable sampled_observation_changed;
uint64_t next_sampled_observation=0,sampled_observation=0;
unsigned sampled_observation_frame=0,sampled_observation_ack=0;
bool sampled_observation_active=false;
bool sampled_observe(uint64_t id,unsigned frame){
    std::unique_lock<std::mutex> lock(sampled_observation_mutex);
    if(!sampled_observation_active||sampled_observation!=id)return false;
    sampled_observation_frame=frame;sampled_observation_changed.notify_all();
    return sampled_observation_changed.wait_for(lock,std::chrono::seconds(30),[&]{
        return !sampled_observation_active||sampled_observation!=id||sampled_observation_ack>=frame;
    })&&sampled_observation_active&&sampled_observation==id&&sampled_observation_ack>=frame;
}
void release_bound_barrier(uint64_t generation){
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if(barrier.load_generation==generation&&!barrier.released){
        graphics_platform_publication_barrier(generation,false);barrier.released=true;
    }
}
struct Probe {
    HleRuntime runtime;
    GuestEnvironment environment;
    GuestStack stack{256*1024};
    uintptr_t output=0,poll=0,wait=0,finalize=0;
    bool opened=false,main_started=false;
    unsigned authority_checks=0,denied_registrations=0;
    DmGraphicsGuestRecord last{};
    static bool registration(DmGuestThreadState&,uint64_t* handle,uint64_t* area,void* context,std::string* error){
        auto& self=*static_cast<Probe*>(context);*handle=self.runtime.register_main();*area=0;
        return *handle||fail(error,"graphics main registration failed");
    }
    static bool denied_registration(DmGuestThreadState&,uint64_t*,uint64_t*,void* context,std::string*){
        ++static_cast<Probe*>(context)->denied_registrations;return false;
    }
    static bool initialized(Process& process,DmGuestThreadState&,void* context,std::string* error){
        auto& self=*static_cast<Probe*>(context);
        if(!graphics_diagnostic_graph(process,error))return false;
        std::lock_guard<std::mutex> lock(metadata_mutex);
        if(barrier.armed&&!barrier.released){
            if(barrier.load_generation)return fail(error,"publication barrier already bound");
            const auto generation=process.load_generation();
            if(!graphics_platform_publication_barrier(generation,true))return fail(error,"graphics barrier binding refused");
            barrier.load_generation=generation;
        }
        self.main_started=true;return true;
    }
    bool copy(DmGraphicsGuestRecord* record,std::string* error){
        if(!runtime.process().copy_readable(output,record,sizeof(*record)))return fail(error,"graphics checked result read failed");
        return true;
    }
    bool untouched(){DmGraphicsGuestRecord r{};return !denied_registrations&&copy(&r,nullptr)&&
        !r.sdk_init&&!r.module_init&&!r.setup_calls&&!r.fallback_calls;}
    bool begin(std::string* error){
        std::unique_ptr<ModulePackage> main,sdk;
        if(!stack.valid()||!decode_package(dm_observation_main_bytes,dm_observation_main_size,dm_observation_main_package_sha256,&main,error)||
           !decode_package_with_callback_audit(dm_graphics_bytes,dm_graphics_size,dm_graphics_package_sha256,dm_graphics_callback_audit,&sdk,error))return false;
        std::vector<std::unique_ptr<ModulePackage>> packages;packages.push_back(std::move(main));packages.push_back(std::move(sdk));
        if(!runtime.load(std::move(packages),false,nullptr,nullptr,error))return false;
        opened=true;runtime.configure(environment.state);
        if(!runtime.process().symbol("graphics_result",&output)||!runtime.process().symbol("graphics_poll",&poll)||
           !runtime.process().symbol("graphics_wait",&wait)||!runtime.process().symbol("graphics_end",&finalize))
            return fail(error,"graphics guest exports missing");
        BootstrapSession session;BootstrapArguments args({"D2R","--graphics-sdk-fixture"});BootstrapResult result;
        const BootstrapHooks denied{denied_registration,initialized,this};
        if(session.run(runtime.process(),environment,stack,args,denied,&result,error)||!untouched())
            return fail(error,"missing graphics authority reached initialization");
        ++authority_checks;
        for(size_t index=0;index<2;++index){
            BootstrapSession altered;if(!altered.authorize(runtime.process(),error))return false;
            auto& identity=index?runtime.process().modules()[index]->package->source_sha256:
                                 runtime.process().modules()[index]->package->build_id;
            identity[31]^=1;
            const bool refused=!altered.run(runtime.process(),environment,stack,args,denied,&result,error)&&untouched();
            identity[31]^=1;
            if(!refused)return fail(error,"mutated graphics graph reached initialization");
            ++authority_checks;
        }
        if(!session.authorize(runtime.process(),error)||!session.run(runtime.process(),environment,stack,args,{registration,initialized,this},&result,error))return false;
        if(result.completed_steps.size()!=12||result.main_result.exited||result.main_result.value!=0x612)
            return fail(error,"graphics bootstrap did not return normally");
        return copy(&last,error);
    }
    bool invoke(uintptr_t target,uint64_t timeout,bool use_argument,std::string* error){
        GuestCallResult result;
        if(!stack.call(environment.state,target,use_argument?&timeout:nullptr,use_argument?1:0,&result,error)||result.exited||result.value!=0x612)
            return fail(error,"graphics actual guest call failed");
        return copy(&last,error);
    }
    bool end(bool force,std::string* error){
        if(!opened)return true;
        if(force)release_bound_barrier(runtime.process().load_generation());
        if(main_started&&graphics_platform_last_fence()){
            if(force&&!invoke(wait,std::numeric_limits<uint64_t>::max(),true,error))return false;
            if(last.wait_result==2)return fail(error,"graphics work remains pending");
            if(last.phase!=3&&!invoke(finalize,0,false,error))return false;
        }
        if(!runtime.shutdown(error))return false;opened=false;return true;
    }
    ~Probe(){if(opened){std::string error;if(!end(true,&error))std::abort();}}
};
// Authored, compiled host leaf on Probe's actual owned GuestStack. These are
// resolved host exports, not original ARM game imports or relocation evidence.
struct ViProbeCall {
    void (*initialize)()=nullptr;
    uint32_t (*open)(void**)=nullptr;
    uint32_t (*create)(void**,void*)=nullptr;
    uint32_t (*native)(void**,void*)=nullptr;
    void* host_output=reinterpret_cast<void*>(uintptr_t{0x6b17});
    uintptr_t display=0,layer=0,native_window=0;
    bool owned_outputs=false,host_outputs_refused=false,forged_parents_refused=false;
    bool created=false,capacity_preserved=false,repeated=false;
};
__attribute__((noinline)) uint64_t vi_probe_leaf(uint64_t argument){
    auto& call=*reinterpret_cast<ViProbeCall*>(argument);
    void* const sentinel=reinterpret_cast<void*>(uintptr_t{0x6b17});
    void* display=sentinel;void* layer=sentinel;void* native=sentinel;
    uintptr_t bottom=0;size_t length=0;
    call.owned_outputs=active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(&display),&bottom,&length)&&
        active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(&layer),&bottom,&length)&&
        active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(&native),&bottom,&length);
    call.initialize();
    const bool opened=call.open(&display)==0&&display&&display!=sentinel;
    void* repeated_display=sentinel;
    const bool repeat_display=call.open(&repeated_display)==0&&repeated_display==display;
    const bool host_open=call.open(&call.host_output)!=0&&call.host_output==sentinel;
    void* rejected=sentinel;
    const bool forged_display=call.create(&rejected,sentinel)!=0&&rejected==sentinel;
    const bool host_create=call.create(&call.host_output,display)!=0&&call.host_output==sentinel;
    const bool created=call.create(&layer,display)==0&&layer&&layer!=sentinel;
    void* second=sentinel;
    const bool capacity=call.create(&second,display)!=0&&second==sentinel;
    const bool forged_layer=call.native(&rejected,sentinel)!=0&&rejected==sentinel;
    const bool host_native=call.native(&call.host_output,layer)!=0&&call.host_output==sentinel;
    const bool queried=call.native(&native,layer)==0&&native&&native!=sentinel;
    void* repeated_native=sentinel;
    const bool repeat_native=call.native(&repeated_native,layer)==0&&repeated_native==native;
    call.display=reinterpret_cast<uintptr_t>(display);call.layer=reinterpret_cast<uintptr_t>(layer);
    call.native_window=reinterpret_cast<uintptr_t>(native);
    call.host_outputs_refused=host_open&&host_create&&host_native;
    call.forged_parents_refused=forged_display&&forged_layer;
    call.created=opened&&created&&queried;
    call.capacity_preserved=capacity&&queried&&repeat_native;
    call.repeated=repeat_display&&repeat_native;
    return 0x7169;
}
// W0 has a separate pool in the unused tail of the carrier's real 2 MiB heap.
// Baseline occupies [0,0x40000), C2b ends at 0x60000, and D1 ends at
// 0x80000+DM_DRAW_POOL_BYTES==0x120000. No fixture bytes or graph change.
constexpr size_t window_heap_offset=0x140000,window_pool_bytes=0xc0000;
constexpr unsigned window_width=64,window_height=48,window_pixel_bytes=64*48*4;
#define WINDOW_PROCS(X) \
    X(nvnDeviceBuilderSetDefaults) X(nvnDeviceInitialize) X(nvnDeviceFinalize) \
    X(nvnMemoryPoolBuilderSetDefaults) X(nvnMemoryPoolBuilderSetDevice) X(nvnMemoryPoolBuilderSetStorage) \
    X(nvnMemoryPoolBuilderSetFlags) X(nvnMemoryPoolInitialize) X(nvnMemoryPoolFinalize) \
    X(nvnTextureBuilderSetDefaults) X(nvnTextureBuilderSetDevice) X(nvnTextureBuilderSetFlags) \
    X(nvnTextureBuilderSetTarget) X(nvnTextureBuilderSetWidth) X(nvnTextureBuilderSetHeight) \
    X(nvnTextureBuilderSetLevels) X(nvnTextureBuilderSetSamples) X(nvnTextureBuilderSetFormat) \
    X(nvnTextureBuilderSetStride) X(nvnTextureBuilderSetStorage) X(nvnTextureBuilderGetStorageSize) \
    X(nvnTextureInitialize) X(nvnTextureFinalize) \
    X(nvnQueueBuilderSetDefaults) X(nvnQueueBuilderSetDevice) X(nvnQueueBuilderGetQueueMemorySize) \
    X(nvnQueueBuilderSetQueueMemory) X(nvnQueueInitialize) X(nvnQueueFinalize) X(nvnQueueGetError) \
    X(nvnQueueSubmitCommands) X(nvnQueueFenceSync) X(nvnQueueFinish) X(nvnQueuePresentTexture) \
    X(nvnWindowBuilderSetDefaults) X(nvnWindowBuilderSetDevice) X(nvnWindowBuilderSetNativeWindow) \
    X(nvnWindowBuilderSetTextures) X(nvnWindowBuilderSetPresentInterval) X(nvnWindowInitialize) \
    X(nvnWindowFinalize) X(nvnWindowAcquireTexture) X(nvnWindowSetPresentInterval) X(nvnWindowSetCrop) \
    X(nvnWindowGetPresentInterval) X(nvnWindowGetCrop) \
    X(nvnSyncInitialize) X(nvnSyncFinalize) X(nvnSyncWait) \
    X(nvnCommandBufferInitialize) X(nvnCommandBufferFinalize) X(nvnCommandBufferAddCommandMemory) \
    X(nvnCommandBufferBeginRecording) X(nvnCommandBufferEndRecording) X(nvnCommandBufferSetRenderTargets) \
    X(nvnCommandBufferClearColor) X(nvnCommandBufferSetCopyRowStride) \
    X(nvnCommandBufferCopyBufferToTexture) X(nvnCommandBufferCopyTextureToBuffer)
struct WindowProbeFrame {
    int index=-1,interval=0,crop_x=0,crop_y=0,crop_width=0,crop_height=0;
    int observed_interval=-1,observed_crop[4]{};
    uint64_t dependency_fence=0,render_fence=0,completed_fence=0;
    GraphicsWindowStats acquired{},presented{};
    SurfaceSnapshot surface_before{},surface_after{};
    bool configured=false,acquired_ok=false,dependency_wait=false,pixels=false,clear_pixels=false,posted=false;
    uint8_t corners[16]{},rgba_sha256[32]{};
};
struct WindowProbeCall {
    ViProbeCall vi;
#define WINDOW_PROC_FIELD(name) NVNT_##name name=nullptr;
    WINDOW_PROCS(WINDOW_PROC_FIELD)
#undef WINDOW_PROC_FIELD
    uint8_t* memory=nullptr;
    WindowProbeFrame frames[4];
    uint64_t texture_bytes[2]{};
    bool device=false,pool=false,textures=false,window=false,cleaned=false;
    uint32_t queue_error=0;unsigned completed=0;
    int failed_frame=-1;const char* failure_stage="initialization";
    std::string failure;
    GraphicsWindowStats retired{};
};
__attribute__((noinline)) uint64_t window_probe_leaf(uint64_t argument){
    auto& c=*reinterpret_cast<WindowProbeCall*>(argument);
    // All opaque NVN objects and pointer arrays remain live on this owned stack
    // until real GPU/publication/Surface acknowledgement and finalization finish.
    NVNdevice device{};NVNdeviceBuilder db{};NVNmemoryPool pool{};NVNmemoryPoolBuilder pb{};
    NVNtexture textures[2]{};NVNtextureBuilder tb{};NVNqueue queue{};NVNqueueBuilder qb{};
    NVNwindow window{};NVNwindowBuilder wb{};NVNsync sync{},acquire_sync{};NVNcommandBuffer command{};
    bool queue_ready=false,command_ready=false,sync_ready=false,acquire_ready=false;
    unsigned texture_count=0;
    vi_probe_leaf(reinterpret_cast<uint64_t>(&c.vi));
    if(!c.vi.created||!c.vi.owned_outputs){c.failure="W0 VI host leaf did not create owned-stack outputs";return 0;}
    do {
        c.nvnDeviceBuilderSetDefaults(&db);c.device=c.nvnDeviceInitialize(&device,&db)!=0;if(!c.device)break;
        c.nvnMemoryPoolBuilderSetDefaults(&pb);c.nvnMemoryPoolBuilderSetDevice(&pb,&device);
        c.nvnMemoryPoolBuilderSetStorage(&pb,c.memory,window_pool_bytes);c.nvnMemoryPoolBuilderSetFlags(&pb,0x24);
        c.pool=c.nvnMemoryPoolInitialize(&pool,&pb)!=0;if(!c.pool)break;
        for(unsigned i=0;i<2;++i){
            c.nvnTextureBuilderSetDefaults(&tb);c.nvnTextureBuilderSetDevice(&tb,&device);
            c.nvnTextureBuilderSetTarget(&tb,NVN_TEXTURE_TARGET_2D);c.nvnTextureBuilderSetWidth(&tb,window_width);
            c.nvnTextureBuilderSetHeight(&tb,window_height);c.nvnTextureBuilderSetLevels(&tb,1);c.nvnTextureBuilderSetSamples(&tb,1);
            c.nvnTextureBuilderSetFormat(&tb,NVN_FORMAT_RGBA8);
            c.nvnTextureBuilderSetFlags(&tb,i?0:NVN_TEXTURE_FLAGS_LINEAR|NVN_TEXTURE_FLAGS_LINEAR_RENDER_TARGET);
            c.nvnTextureBuilderSetStride(&tb,i?0:window_width*4);c.nvnTextureBuilderSetStorage(&tb,&pool,i*0x10000);
            c.texture_bytes[i]=c.nvnTextureBuilderGetStorageSize(&tb);
            if(!c.texture_bytes[i]||c.texture_bytes[i]>0x10000||!c.nvnTextureInitialize(&textures[i],&tb))break;
            ++texture_count;
        }
        c.textures=texture_count==2;if(!c.textures)break;
        c.nvnQueueBuilderSetDefaults(&qb);c.nvnQueueBuilderSetDevice(&qb,&device);
        const size_t queue_bytes=c.nvnQueueBuilderGetQueueMemorySize(&qb);if(queue_bytes>0x80000)break;
        c.nvnQueueBuilderSetQueueMemory(&qb,c.memory+0x40000,queue_bytes);
        queue_ready=c.nvnQueueInitialize(&queue,&qb)!=0;if(!queue_ready)break;
        sync_ready=c.nvnSyncInitialize(&sync,&device)!=0;acquire_ready=c.nvnSyncInitialize(&acquire_sync,&device)!=0;
        command_ready=c.nvnCommandBufferInitialize(&command,&device)!=0;if(!sync_ready||!acquire_ready||!command_ready)break;
        c.nvnCommandBufferAddCommandMemory(&command,&pool,0x30000,0x10000);
        c.nvnWindowBuilderSetDefaults(&wb);c.nvnWindowBuilderSetDevice(&wb,&device);
        c.nvnWindowBuilderSetNativeWindow(&wb,reinterpret_cast<NVNnativeWindow>(c.vi.native_window));
        NVNtexture* slots[]={&textures[0],&textures[1]};c.nvnWindowBuilderSetTextures(&wb,2,slots);
        c.nvnWindowBuilderSetPresentInterval(&wb,0);c.window=c.nvnWindowInitialize(&window,&wb)!=0;if(!c.window)break;
        for(unsigned frame=0;frame<4;++frame){
            c.failed_frame=static_cast<int>(frame);c.failure_stage="configure";
            auto& f=c.frames[frame];f.interval=(frame==1||frame==2)?1:0;
            if(frame==2){f.crop_x=8;f.crop_y=6;f.crop_width=40;f.crop_height=30;}
            c.nvnWindowSetPresentInterval(&window,f.interval);
            c.nvnWindowSetCrop(&window,f.crop_x,f.crop_y,f.crop_width,f.crop_height);
            NVNrectangle crop{};c.nvnWindowGetCrop(&window,&crop);
            f.observed_interval=c.nvnWindowGetPresentInterval(&window);
            f.observed_crop[0]=crop.x;f.observed_crop[1]=crop.y;f.observed_crop[2]=crop.width;f.observed_crop[3]=crop.height;
            f.configured=f.observed_interval==f.interval&&f.observed_crop[0]==f.crop_x&&f.observed_crop[1]==f.crop_y&&
                f.observed_crop[2]==f.crop_width&&f.observed_crop[3]==f.crop_height;
            if(!f.configured){const auto failure=nvn_core_last_error();std::ostringstream detail;detail<<"W0 frame "<<frame<<" configure getter mismatch: interval "
                <<f.observed_interval<<" expected "<<f.interval<<"; crop ["<<f.observed_crop[0]<<','<<f.observed_crop[1]<<','
                <<f.observed_crop[2]<<','<<f.observed_crop[3]<<"] expected ["<<f.crop_x<<','<<f.crop_y<<','<<f.crop_width<<','<<f.crop_height
                <<"]; NVN code="<<failure.code<<" operation="<<failure.operation<<" reason="<<(failure.reason&&*failure.reason?failure.reason:"no backend error recorded");
                c.failure=detail.str();break;}
            c.failure_stage="acquire";
            f.surface_before=graphics_surface_snapshot();
            int index=-1;
            f.acquired_ok=c.nvnWindowAcquireTexture(&window,frame==0?&acquire_sync:nullptr,&index)==NVN_WINDOW_ACQUIRE_TEXTURE_RESULT_SUCCESS;
            f.index=index;
            f.acquired=graphics_platform_window_stats();
            if(!f.acquired_ok||f.index<0||f.index>1)break;
            f.dependency_fence=frame==0?reinterpret_cast<const sync_t*>(&acquire_sync)->fence:0;
            c.failure_stage="acquire-dependency-wait";
            f.dependency_wait=frame!=0||c.nvnSyncWait(&acquire_sync,UINT64_MAX)<2;
            if(!f.dependency_wait)break;
            uint8_t* source=c.memory+0x20000;
            for(unsigned y=0;y<window_height;++y)for(unsigned x=0;x<window_width;++x){
                const bool left=x<23,top=y<17,marker=x>=5&&x<11&&y>=7&&y<13;
                uint8_t* pixel=source+(y*window_width+x)*4;
                pixel[0]=marker?0:(left?(top?255:0):(top?0:255));
                pixel[1]=marker?255:(left?0:255);pixel[2]=marker?255:(!top&&left?255:0);pixel[3]=255;
            }
            std::memset(c.memory+0x24000,0xa7,window_pixel_bytes);std::memset(c.memory+0x28000,0xa8,window_pixel_bytes);
            c.nvnCommandBufferBeginRecording(&command);const NVNtexture* colors[]={&textures[f.index]};
            c.nvnCommandBufferSetRenderTargets(&command,1,colors,nullptr,nullptr,nullptr);
            const float magenta[]={1,0,1,1};c.nvnCommandBufferClearColor(&command,0,magenta,15);
            const NVNcopyRegion all={0,0,0,window_width,window_height,1};
            c.nvnCommandBufferSetCopyRowStride(&command,window_width*4);
            c.nvnCommandBufferCopyTextureToBuffer(&command,&textures[f.index],nullptr,&all,reinterpret_cast<uint64_t>(c.memory+0x28000),0);
            c.nvnCommandBufferCopyBufferToTexture(&command,reinterpret_cast<uint64_t>(source),&textures[f.index],nullptr,&all,0);
            c.nvnCommandBufferCopyTextureToBuffer(&command,&textures[f.index],nullptr,&all,reinterpret_cast<uint64_t>(c.memory+0x24000),0);
            const NVNcommandHandle handle=c.nvnCommandBufferEndRecording(&command);
            c.nvnQueueSubmitCommands(&queue,1,&handle);c.nvnQueueFenceSync(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);
            f.render_fence=reinterpret_cast<const sync_t*>(&sync)->fence;
            c.failure_stage="render-fence-publication-wait";
            if(c.nvnSyncWait(&sync,UINT64_MAX)>=2)break;f.completed_fence=graphics_platform_completed_fence();
            f.pixels=std::memcmp(source,c.memory+0x24000,window_pixel_bytes)==0;
            module_sha256(c.memory+0x24000,window_pixel_bytes,f.rgba_sha256);
            f.clear_pixels=true;for(unsigned i=0;i<window_pixel_bytes;i+=4){const uint8_t* pixel=c.memory+0x28000+i;
                f.clear_pixels&=pixel[0]==255&&pixel[1]==0&&pixel[2]==255&&pixel[3]==255;}
            const unsigned corners[]={0,window_width-1,(window_height-1)*window_width,window_width*window_height-1};
            for(unsigned i=0;i<4;++i)std::memcpy(f.corners+i*4,c.memory+0x24000+corners[i]*4,4);
            c.failure_stage="present-and-pixel-oracles";
            c.nvnQueuePresentTexture(&queue,&window,f.index);c.queue_error=c.nvnQueueGetError(&queue,nullptr);
            f.presented=graphics_platform_window_stats();f.surface_after=graphics_surface_snapshot();
            f.posted=!c.queue_error&&f.presented.presents==frame+1&&f.surface_after.posts==f.surface_before.posts+1&&
                f.surface_after.accepted==f.surface_before.accepted+1;
            if(!f.pixels||!f.clear_pixels||!f.posted)break;++c.completed;
        }
    }while(false);
    if(c.completed!=4&&c.failure.empty()){const auto failure=nvn_core_last_error();std::ostringstream detail;
        detail<<"W0 frame "<<c.failed_frame<<" stopped at "<<c.failure_stage<<"; NVN code="<<failure.code<<" operation="<<failure.operation
            <<" reason="<<(failure.reason&&*failure.reason?failure.reason:"no backend error recorded");c.failure=detail.str();}
    if(c.completed==4){c.failed_frame=-1;c.failure_stage="completed";}
    if(queue_ready)c.nvnQueueFinish(&queue);
    if(c.window){c.nvnWindowFinalize(&window);c.retired=graphics_platform_window_stats();}
    if(command_ready)c.nvnCommandBufferFinalize(&command);
    if(sync_ready)c.nvnSyncFinalize(&sync);if(acquire_ready)c.nvnSyncFinalize(&acquire_sync);
    for(unsigned i=0;i<texture_count;++i)c.nvnTextureFinalize(&textures[i]);
    if(queue_ready)c.nvnQueueFinalize(&queue);if(c.pool)c.nvnMemoryPoolFinalize(&pool);if(c.device)c.nvnDeviceFinalize(&device);
    c.cleaned=c.window&&c.retired.retired&&!c.retired.live&&reinterpret_cast<const pool_t*>(&pool)->magic==0;
    return 0x7730;
}
bool bytes(Probe& p,uint64_t address,const std::vector<uint8_t>& expected){
    std::vector<uint8_t> actual(expected.size());return
        (p.runtime.process().copy_readable(address,actual.data(),actual.size())||
         dm_android_kernel_memory_copy_readable(address,actual.data(),actual.size()))&&actual==expected;
}
bool data_oracle(Probe& p){
    const auto& r=p.last;
    std::vector<uint8_t> uniform(0x1000,0xcc);
    for(unsigned k=0;k<20;++k)for(unsigned i=0;i<16;++i){uint32_t value=k*100+i;std::memcpy(uniform.data()+k*64+i*4,&value,4);}
    std::vector<uint8_t> copy(0x100,0xcd),clear(0x100,0xce),roundtrip(0x100,0xcf),large(65536);
    for(unsigned i=0;i<64;++i)copy[i]=uint8_t(i*3+1);
    for(unsigned y=0;y<3;++y)for(unsigned x=0;x<5;++x){auto i=y*32+x*4;clear[i]=0;clear[i+1]=255;clear[i+2]=0;clear[i+3]=255;}
    for(unsigned y=0;y<2;++y)for(unsigned x=0;x<3;++x){auto i=y*24+x*4;roundtrip[i]=uint8_t((x+1)*16+y+1);roundtrip[i+1]=uint8_t((y+1)*16+x+1);roundtrip[i+2]=0x55;roundtrip[i+3]=0xaa;}
    for(unsigned i=0;i<16384;++i){uint32_t value=0x51000000u+i;std::memcpy(large.data()+i*4,&value,4);}
    uint32_t event=0;
    return bytes(p,r.uniform_address,uniform)&&bytes(p,r.copy_address,copy)&&bytes(p,r.clear_address,clear)&&
        bytes(p,r.roundtrip_address,roundtrip)&&bytes(p,r.host_update_address,large)&&
        dm_android_kernel_memory_copy_readable(r.event_address,&event,sizeof(event))&&event==12;
}
bool untouched_data_oracle(Probe& p){
    const auto& r=p.last;uint32_t event=1;
    return bytes(p,r.uniform_address,std::vector<uint8_t>(0x1000,0xcc))&&
        bytes(p,r.copy_address,std::vector<uint8_t>(0x100,0xcd))&&
        bytes(p,r.clear_address,std::vector<uint8_t>(0x100,0xce))&&
        bytes(p,r.roundtrip_address,std::vector<uint8_t>(0x100,0xcf))&&
        bytes(p,r.host_update_address,std::vector<uint8_t>(65536,0))&&
        dm_android_kernel_memory_copy_readable(r.event_address,&event,sizeof(event))&&!event;
}
bool shape(const Probe& p){const auto& r=p.last;return r.sdk_init==1&&r.module_init==1&&r.setup_calls==1&&
    !r.fallback_calls&&!r.guest_failures&&!r.unknown_lookup&&r.lookup_count&&r.callback_calls>2&&r.callback_hle_calls==r.callback_calls&&
    r.callback_sp&&!(r.callback_sp&15)&&r.callback_tls==r.callback_expected_tls&&r.callback_current==p.output&&
    r.callback_bytes>256&&r.host_callback_calls>=2&&r.host_callback_bytes&&r.host_fallback_handle&&
    r.wait_unfenced==2&&r.submit_calls==1&&r.recording_handle&&r.repeat_handle;}
bool forced(Probe& p){return p.runtime.registry().force_hits("nvnBootstrapLoader")&&
    p.runtime.registry().force_hits("_ZN2nn2oe16GetOperationModeEv");}
std::string report(Probe& p){
    const auto& r=p.last;const auto stats=graphics_platform_stats();
    const bool completed=r.wait_result<2,failed=r.wait_result==3;
    const bool data=completed&&data_oracle(p);
    bool publication_held=false,pending_untouched=false;
    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        publication_held=barrier.armed&&!barrier.released&&barrier.load_generation==p.runtime.process().load_generation()&&
            graphics_platform_publication_barrier_entered(barrier.load_generation);
        // Holding metadata prevents release while this independent old-value
        // oracle runs. Without a hold, timeout and subsequent completion may race.
        if(publication_held)pending_untouched=untouched_data_oracle(p);
    }
    const bool forced_exports=forced(p);
    const bool gpu=stats.submits==1&&stats.completed==1&&stats.uniform_updates>=60&&stats.buffer_copies>=1&&
        stats.image_uploads>=1&&stats.image_downloads>=2&&stats.render_passes>=1;
    const bool passed=completed&&shape(p)&&data&&forced_exports&&!r.queue_error&&stats.submits==1&&stats.completed==1&&
        stats.uniform_updates>=60&&stats.buffer_copies>=1&&stats.image_uploads>=1&&stats.image_downloads>=2&&stats.render_passes>=1&&
        !stats.validation_errors&&!p.runtime.unavailable_host_calls();
    std::ostringstream o;o<<"{\"schemaVersion\":1,\"suite\":\"android-graphics-sdk\",\"status\":\""<<(completed?(passed?"PASS":"FAIL"):failed?"FAIL":"PENDING")
      <<"\",\"outcome\":\""<<(completed?"Completed":failed?"Failed":"Pending")<<"\",\"gamePlayable\":false,\"syntheticOnly\":true,\"originalGame\":\"NOT_RUN\",\"capability\":\"offscreen-diagnostic\","
      <<"\"loadGeneration\":"<<p.runtime.process().load_generation()<<",\"fence\":"<<graphics_platform_last_fence()<<",\"completedFence\":"<<graphics_platform_completed_fence()
      <<",\"authorityChecks\":"<<p.authority_checks<<",\"dataOraclePassed\":"<<(data?"true":"false")<<",\"shapePassed\":"<<(shape(p)?"true":"false")
      <<",\"forceBootstrapMatched\":"<<(forced_exports?"true":"false")<<",\"retentionReceipts\":\"NOT_RUN\",\"verifiedDataBytes\":"<<(data?70404:0)
      <<",\"publicationHeld\":"<<(publication_held?"true":"false")<<",\"pendingDataUntouched\":"<<(pending_untouched?"true":"false")
      <<",\"checks\":[{\"id\":\"exact-graph-bootstrap\",\"passed\":"<<(p.authority_checks==3?"true":"false")
      <<"},{\"id\":\"forced-bootstrap-exports\",\"passed\":"<<(forced_exports?"true":"false")
      <<"},{\"id\":\"guest-callback-growth\",\"passed\":"<<(shape(p)?"true":"false")
      <<"},{\"id\":\"full-byte-data-oracle\",\"passed\":"<<(data?"true":"false")
      <<"},{\"id\":\"actual-vulkan-operations\",\"passed\":"<<(gpu?"true":"false")
      <<"},{\"id\":\"no-unavailable-host-or-validation-errors\",\"passed\":"<<(!stats.validation_errors&&!p.runtime.unavailable_host_calls()?"true":"false")<<"}]"
      <<",\"addresses\":{\"pool\":"<<r.pool_address<<",\"command\":"<<r.command_address<<",\"uniform\":"<<r.uniform_address<<",\"copy\":"<<r.copy_address
      <<",\"clear\":"<<r.clear_address<<",\"roundtrip\":"<<r.roundtrip_address<<",\"event\":"<<r.event_address<<",\"hostUpdate\":"<<r.host_update_address<<"}"
      <<",\"guest\":{\"sdkInit\":"<<r.sdk_init<<",\"moduleInit\":"<<r.module_init<<",\"fallbackCalls\":"<<r.fallback_calls<<",\"lookupCount\":"<<r.lookup_count
      <<",\"callbackCalls\":"<<r.callback_calls<<",\"callbackBytes\":"<<r.callback_bytes<<",\"callbackSp\":"<<r.callback_sp<<",\"callbackTls\":"<<r.callback_tls
      <<",\"callbackExpectedTls\":"<<r.callback_expected_tls<<",\"hostCallbackCalls\":"<<r.host_callback_calls<<",\"waitUnfenced\":"<<r.wait_unfenced<<",\"waitInitial\":"<<r.wait_initial
      <<",\"waitResult\":"<<r.wait_result<<",\"queueError\":"<<r.queue_error<<",\"phase\":"<<r.phase<<",\"failures\":"<<r.guest_failures<<"},"
      <<"\"gpu\":{\"device\":\""<<escaped(stats.device_name)<<"\",\"vendorId\":"<<stats.vendor_id<<",\"deviceId\":"<<stats.device_id<<",\"apiVersion\":"<<stats.api_version
      <<",\"driverVersion\":"<<stats.driver_version<<",\"submits\":"<<stats.submits<<",\"completed\":"<<stats.completed<<",\"failed\":"<<stats.failed
      <<",\"uniformUpdates\":"<<stats.uniform_updates<<",\"bufferCopies\":"<<stats.buffer_copies<<",\"imageUploads\":"<<stats.image_uploads<<",\"imageDownloads\":"<<stats.image_downloads
      <<",\"renderPasses\":"<<stats.render_passes<<",\"flushes\":"<<stats.flushes<<",\"invalidates\":"<<stats.invalidates<<",\"noncoherentAtomSize\":"<<stats.noncoherent_atom_size
      <<",\"validationAvailable\":"<<(stats.validation_available?"true":"false")<<",\"validationErrors\":"<<stats.validation_errors<<",\"validationStatus\":\""<<escaped(stats.validation_status)<<"\"},"
      <<"\"sdkPackageSha256\":\""<<hex(dm_graphics_package_sha256,32)<<"\",\"unsupported\":[\"draw\",\"compute\",\"shaders\",\"presentation\",\"full-product\"]}";
    return o.str();
}
std::mutex probe_mutex;
std::unique_ptr<Probe> persistent;
uint64_t next_handle=0,current_handle=0;
void owner(bool active){std::lock_guard<std::mutex> lock(metadata_mutex);owner_active=active;}
} // namespace

bool dm_android_graphics_begin(uint64_t* handle,std::string* error){
    std::lock_guard<std::mutex> lock(probe_mutex);if(error)error->clear();
    if(!handle||persistent||next_handle==std::numeric_limits<uint64_t>::max())return fail(error,"graphics diagnostic already retained or invalid handle output");
    owner(true);auto candidate=std::make_unique<Probe>();
    if(!candidate->begin(error)){std::string cleanup;if(!candidate->end(true,&cleanup))std::abort();owner(false);return false;}
    current_handle=++next_handle;*handle=current_handle;persistent=std::move(candidate);return true;
}
bool dm_android_graphics_wait(uint64_t handle,uint64_t timeout,std::string* output,std::string* error){
    std::lock_guard<std::mutex> lock(probe_mutex);if(error)error->clear();
    if(!output||!persistent||!handle||handle!=current_handle)return fail(error,"stale graphics diagnostic handle");
    if(!persistent->invoke(persistent->wait,timeout,true,error))return false;*output=report(*persistent);return true;
}
bool dm_android_graphics_poll(uint64_t handle,std::string* output,std::string* error){return dm_android_graphics_wait(handle,0,output,error);}
bool dm_android_graphics_end(uint64_t handle,std::string* error){
    std::lock_guard<std::mutex> lock(probe_mutex);if(error)error->clear();
    if(!persistent||!handle||handle!=current_handle)return fail(error,"stale graphics diagnostic handle");
    const auto generation=persistent->runtime.process().load_generation();
    if(!persistent->end(false,error))return false;release_bound_barrier(generation);
    persistent.reset();current_handle=0;owner(false);return true;
}
bool dm_android_graphics_arm_publication_barrier(uint64_t* id,std::string* error){
    std::lock_guard<std::mutex> lock(metadata_mutex);if(error)error->clear();
    if(!id||owner_active||(barrier.armed&&!barrier.released)||next_barrier==std::numeric_limits<uint64_t>::max())return fail(error,"graphics barrier requires idle ownership");
    barrier={};barrier.id=++next_barrier;barrier.armed=true;*id=barrier.id;return true;
}
bool dm_android_graphics_publication_barrier_snapshot(uint64_t id,DmGraphicsPublicationBarrier* out,std::string* error){
    std::lock_guard<std::mutex> lock(metadata_mutex);if(error)error->clear();
    if(!out||!id||id!=barrier.id)return fail(error,"stale graphics publication barrier");
    if(barrier.load_generation){
        barrier.entered=barrier.entered||graphics_platform_publication_barrier_entered(barrier.load_generation);
        const auto fence=graphics_platform_last_fence(barrier.load_generation);if(fence)barrier.fence=fence;
    }
    *out=barrier;return true;
}
bool dm_android_graphics_release_publication_barrier(uint64_t id,std::string* error){
    std::lock_guard<std::mutex> lock(metadata_mutex);if(error)error->clear();
    if(!id||id!=barrier.id||!barrier.armed)return fail(error,"stale graphics publication barrier");
    if(barrier.released)return true;
    if(barrier.load_generation&&!graphics_platform_publication_barrier(barrier.load_generation,false))return fail(error,"graphics barrier generation retired");
    barrier.released=true;return true;
}
bool dm_android_graphics_retention_snapshot(uint64_t id,std::string* output,std::string* error){
    // This lock keeps the real worker's original GPU retention alive through
    // every refusal below. In particular no diagnostic GPU/read pin is added.
    std::lock_guard<std::mutex> lock(metadata_mutex);if(error)error->clear();
    if(!output||!id||id!=barrier.id||!barrier.armed||barrier.released||!barrier.load_generation||
       !graphics_platform_publication_barrier_entered(barrier.load_generation))
        return fail(error,"retention snapshot requires entered unreleased exact-generation publication barrier");
    HleRuntime* runtime=nullptr;uint64_t epoch=0;DmGraphicsExtendedRecord r{};
    NVNmemoryPool pool_before{};NVNtexture texture_before{};
    {
        RuntimeReadLease read;runtime=read.runtime();uintptr_t record=0,pool_symbol=0,texture_symbol=0;
        if(!runtime||runtime->process().load_generation()!=barrier.load_generation||
           !runtime->process().symbol("graphics_extended_result",&record)||
           !runtime->process().copy_readable(record,&r,sizeof(r))||
           !runtime->process().symbol("pool",&pool_symbol)||!runtime->process().symbol("texture",&texture_symbol)||
           r.pool_object!=pool_symbol||r.texture_object!=texture_symbol||r.heap_size!=0x200000||!r.heap_address||
           !runtime->process().mapped_range(r.pool_object,sizeof(pool_before),DM_GUEST_READ|DM_GUEST_WRITE)||
           !runtime->process().mapped_range(r.texture_object,sizeof(texture_before),DM_GUEST_READ|DM_GUEST_WRITE)||
           !runtime->process().copy_readable(r.pool_object,&pool_before,sizeof(pool_before))||
           !runtime->process().copy_readable(r.texture_object,&texture_before,sizeof(texture_before)))
            return fail(error,"retention snapshot runtime/object identity mismatch");
        epoch=runtime->oe_epoch();
    } // Drop active_reads before shutdown: only the original work retains it.
    const auto* pool_view=reinterpret_cast<const pool_t*>(&pool_before);
    if(reinterpret_cast<uint64_t>(pool_view->mem)!=r.heap_address||pool_view->size!=0x40000)
        return fail(error,"retention snapshot primary pool is not the guest SVC heap");
    std::vector<uint8_t> before(size_t(r.heap_size)),after(before.size());
    if(!dm_android_kernel_memory_copy_readable(r.heap_address,before.data(),before.size()))
        return fail(error,"retention snapshot checked heap read refused");
    auto pool_finalize=reinterpret_cast<NVNT_nvnMemoryPoolFinalize>(nvn_core_lookup("nvnMemoryPoolFinalize"));
    auto texture_finalize=reinterpret_cast<NVNT_nvnTextureFinalize>(nvn_core_lookup("nvnTextureFinalize"));
    if(!pool_finalize||!texture_finalize)return fail(error,"retention finalization thunks unavailable");
    pool_finalize(reinterpret_cast<NVNmemoryPool*>(r.pool_object));
    const bool pool_retained=nvn_core_last_error().code==NVN_RETAINED;
    texture_finalize(reinterpret_cast<NVNtexture*>(r.texture_object));
    const bool texture_retained=nvn_core_last_error().code==NVN_RETAINED;
    const bool nonquiescent=!dm_android_kernel_memory_quiescent();
    if(!pool_retained||!texture_retained||!nonquiescent)
        return fail(error,"held publication did not retain actual pool/texture/kernel mapping; mutation probes skipped");
    // Exact STATE_IN_USE is distinguishable from an invalid parameter refusal.
    auto svc=[](unsigned number,uint64_t a,uint64_t b,uint64_t c,uint64_t* value=nullptr){
        uint64_t registers[32]={a,b,c};
        if(!dm_android_memory_svc(int(number),registers))return uint64_t(-1);
        if(value)*value=registers[1];return registers[0];
    };
    uint64_t alias=0;const bool alias_found=svc(0x29,0,14,0,&alias)==0&&alias;
    if(!alias_found)return fail(error,"retention snapshot alias metadata unavailable; mutation probes skipped");
    const uint64_t permission=svc(2,r.heap_address,0x1000,1);
    if(permission!=0xfa01){
        // A missing heap pin is a failed receipt. Restore the reversible test
        // permission and skip shrink/map/reset, which would otherwise be unsafe.
        if(!permission)(void)svc(2,r.heap_address,0x1000,3);
        return fail(error,"held GPU heap did not refuse permission change; destructive probes skipped");
    }
    const uint64_t shrink=svc(1,0,0,0);
    if(shrink!=0xfa01)return fail(error,"held GPU heap did not refuse shrink; later mutation probes skipped");
    const uint64_t map=svc(4,alias,r.heap_address,0x1000);
    if(map!=0xfa01)return fail(error,"held GPU heap did not refuse map; later mutation probes skipped");
    const uint64_t unmap=svc(5,alias,r.heap_address,0x1000);
    if(unmap!=0xfa01)return fail(error,"held GPU heap did not refuse unmap; later mutation probes skipped");
    // Never attempt reset unless the exact held job's pool and mapping both
    // proved retention. A missing pin must become a failed receipt, not unmap.
    const bool reset_guard=pool_retained&&texture_retained&&nonquiescent&&permission==0xfa01&&shrink==0xfa01&&map==0xfa01&&unmap==0xfa01;
    const bool reset_refused=reset_guard&&!dm_android_kernel_memory_reset();
    if(!reset_refused)return fail(error,"held GPU heap did not refuse reset; later mutation probes skipped");
    std::string shutdown_error;
    const bool shutdown_refused=!runtime->shutdown(&shutdown_error);
    NVNmemoryPool pool_after{};NVNtexture texture_after{};
    const bool unchanged=shutdown_refused&&runtime->process().load_generation()==barrier.load_generation&&runtime->oe_epoch()==epoch&&
        runtime->process().copy_readable(r.pool_object,&pool_after,sizeof(pool_after))&&
        runtime->process().copy_readable(r.texture_object,&texture_after,sizeof(texture_after))&&
        !std::memcmp(&pool_before,&pool_after,sizeof(pool_before))&&!std::memcmp(&texture_before,&texture_after,sizeof(texture_before))&&
        dm_android_kernel_memory_copy_readable(r.heap_address,after.data(),after.size())&&before==after;
    const bool passed=pool_retained&&texture_retained&&permission==0xfa01&&shrink==0xfa01&&map==0xfa01&&unmap==0xfa01&&
        nonquiescent&&reset_refused&&shutdown_refused&&unchanged;
    std::ostringstream o;o<<"{\"schemaVersion\":1,\"suite\":\"android-graphics-retention\",\"status\":\""<<(passed?"PASS":"FAIL")
      <<"\",\"barrierId\":"<<id<<",\"loadGeneration\":"<<barrier.load_generation<<",\"fence\":"<<graphics_platform_last_fence(barrier.load_generation)
      <<",\"completedFence\":"<<graphics_platform_completed_fence()<<",\"heapAddress\":"<<r.heap_address
      <<",\"heapSize\":"<<r.heap_size<<",\"poolBytes\":262144,\"verifiedUnchangedBytes\":"<<(unchanged?r.heap_size:0)
      <<",\"poolFinalizeRetained\":"<<(pool_retained?"true":"false")<<",\"textureFinalizeRetained\":"<<(texture_retained?"true":"false")
      <<",\"protectResult\":"<<permission<<",\"shrinkResult\":"<<shrink<<",\"mapResult\":"<<map<<",\"unmapPinnedSourceResult\":"<<unmap
      <<",\"nonquiescent\":"<<(nonquiescent?"true":"false")<<",\"resetRefused\":"<<(reset_refused?"true":"false")
      <<",\"shutdownRefused\":"<<(shutdown_refused?"true":"false")<<",\"shutdownReason\":\""<<escaped(shutdown_error)
      <<"\",\"objectsAndHeapUnchanged\":"<<(unchanged?"true":"false")<<",\"readLeaseHeldForShutdown\":false,\"gamePlayable\":false}";
    *output=o.str();return true;
}
std::string dm_android_run_graphics_probes(){
    uint64_t handle=0;std::string error,result;
    if(!dm_android_graphics_begin(&handle,&error))return "{\"schemaVersion\":1,\"suite\":\"android-graphics-sdk\",\"status\":\"FAIL\",\"gamePlayable\":false,\"error\":\""+escaped(error)+"\"}";
    const bool waited=dm_android_graphics_wait(handle,10000000000ull,&result,&error);
    if(!dm_android_graphics_end(handle,&error)){
        // A one-shot batch cannot leave an unadvertised persistent owner behind.
        // Release its diagnostic hold and retire real accepted work before exit.
        std::lock_guard<std::mutex> lock(probe_mutex);std::string cleanup;
        if(!persistent||!persistent->end(true,&cleanup))std::abort();
        persistent.reset();current_handle=0;owner(false);
        return "{\"schemaVersion\":1,\"suite\":\"android-graphics-sdk\",\"status\":\"FAIL\",\"gamePlayable\":false,\"error\":\""+escaped(error)+"\"}";
    }
    return waited?result:"{\"schemaVersion\":1,\"suite\":\"android-graphics-sdk\",\"status\":\"FAIL\",\"gamePlayable\":false,\"error\":\""+escaped(error)+"\"}";
}

namespace {
bool extended_call(Probe& p,const char* name,uint64_t argument,DmGraphicsExtendedRecord* result,std::string* error){
    uintptr_t entry=0,record=0;
    return (p.runtime.process().symbol(name,&entry)&&p.runtime.process().symbol("graphics_extended_result",&record)&&
        p.invoke(entry,argument,true,error)&&p.runtime.process().copy_readable(record,result,sizeof(*result)))||
        fail(error,"extended actual guest export/call/result failed");
}
std::vector<uint8_t> extended_seed(unsigned scenario){
    std::vector<uint8_t> expected(0x10000,0xa1);
    for(unsigned i=0;i<64;++i)expected[0x100+i]=uint8_t(17+i*7);
    if(scenario==3)for(unsigned y=0;y<3;++y)for(unsigned x=0;x<5;++x)for(unsigned c=0;c<4;++c)
        expected[0x100+y*32+x*4+c]=uint8_t(31+y*47+x*5+c);
    return expected;
}
std::vector<uint8_t> extended_expected(unsigned scenario){
    auto expected=extended_seed(scenario);
    if(scenario==2){
        for(unsigned i=0;i<16;++i){uint32_t v=0x62510000u+i*13;
            std::memcpy(expected.data()+0x300+i*4,&v,4);std::memcpy(expected.data()+0x500+i*4,&v,4);}
    } else if(scenario==3){
        for(unsigned y=0;y<3;++y)for(unsigned x=0;x<5;++x)for(unsigned c=0;c<4;++c)
            expected[0x500+y*32+x*4+c]=uint8_t(31+y*47+x*5+c);
    } else if(scenario==5){
        for(unsigned i=0;i<64;++i){expected[0x110+i]=uint8_t(17+i*7);expected[0x500+i]=uint8_t(17+i*7);}
    } else {
        for(unsigned i=0;i<64;++i){expected[0x300+i]=uint8_t(17+i*7);
            expected[0x500+i]=uint8_t(scenario==4?203-i*3:17+i*7);
            if(scenario==4)expected[0x100+i]=uint8_t(203-i*3);}
    }
    return expected;
}
bool ready(Probe& p,std::string* error){
    return p.begin(error)&&p.invoke(p.wait,10000000000ull,true,error)&&p.last.wait_result<2&&shape(p)&&data_oracle(p)&&forced(p);
}
bool hold_loaded(Probe& p,uint64_t* id,std::string* error){
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if((barrier.armed&&!barrier.released)||next_barrier==UINT64_MAX)return fail(error,"extended barrier already held/exhausted");
    barrier={};barrier.id=++next_barrier;barrier.armed=true;barrier.load_generation=p.runtime.process().load_generation();
    if(!graphics_platform_publication_barrier(barrier.load_generation,true)){barrier.released=true;return fail(error,"extended exact-generation hold refused");}
    *id=barrier.id;return true;
}
bool entered_hold(uint64_t id){
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    do {DmGraphicsPublicationBarrier state;std::string error;
        if(!dm_android_graphics_publication_barrier_snapshot(id,&state,&error))return false;
        if(state.entered)return true;
        std::this_thread::yield();
    } while(std::chrono::steady_clock::now()<deadline);
    return false;
}
bool retired_heap_roundtrip(uint64_t heap){
    auto svc=[](unsigned number,uint64_t a,uint64_t b,uint64_t c,uint64_t* value=nullptr){
        uint64_t registers[32]={a,b,c};if(!dm_android_memory_svc(int(number),registers))return uint64_t(-1);
        if(value)*value=registers[1];return registers[0];
    };
    if(!dm_android_kernel_memory_quiescent())return false;
    std::vector<uint8_t> before(0x1000),after(before.size());
    if(!dm_android_kernel_memory_copy_readable(heap,before.data(),before.size()))return false;
    const bool read_only=svc(2,heap,0x1000,1)==0;
    const bool writable=svc(2,heap,0x1000,3)==0;
    uint64_t alias=0;const bool alias_found=svc(0x29,0,14,0,&alias)==0&&alias;
    const bool mapped=read_only&&writable&&alias_found&&svc(4,alias,heap,0x1000)==0;
    const bool unmapped=mapped&&svc(5,alias,heap,0x1000)==0;
    return read_only&&writable&&mapped&&unmapped&&dm_android_kernel_memory_quiescent()&&
        dm_android_kernel_memory_copy_readable(heap,after.data(),after.size())&&before==after;
}
struct ExtendedCheck {
    explicit ExtendedCheck(const char* name):id(name){}
    const char* id;bool passed=false;uint64_t bytes=0;
    uint64_t first_fence=0,last_fence=0,completed_fence=0,submits=0,completed=0,failed=0;
    uint64_t guest_waits=0,wait_result=UINT64_MAX,queue_error=0;
    uint64_t error_code=0,error_operation=0;
    uint64_t generation=0;
    bool first_pending=false,closed=false,baseline_passed=false;
    bool suffix_rejected=false,suffix_unchanged=false;
    uint64_t suffix_wait_result=UINT64_MAX;
    std::string detail,retention;
};
}
std::string dm_android_run_graphics_extended_probes(){
    std::lock_guard<std::mutex> lock(probe_mutex);
    if(persistent)return "{\"schemaVersion\":1,\"suite\":\"android-graphics-extended\",\"status\":\"FAIL\",\"gamePlayable\":false,\"error\":\"persistent graphics diagnostic already active\"}";
    {std::lock_guard<std::mutex> metadata(metadata_mutex);
        if(owner_active||(barrier.armed&&!barrier.released))return "{\"schemaVersion\":1,\"suite\":\"android-graphics-extended\",\"status\":\"FAIL\",\"gamePlayable\":false,\"error\":\"graphics ownership/barrier already retained\"}";
        owner_active=true;
    }
    struct OwnerReset{~OwnerReset(){owner(false);}} owner_reset;
    std::vector<ExtendedCheck> checks;
    const char* ids[]={"cross-submit-buffer-copy","cross-submit-uniform-copy","cross-submit-image-by-value-alias","cpu-edit-after-successful-wait","same-pool-overlapping-copy"};
    VkReplayStats identity;
    for(unsigned scenario=1;scenario<=5;++scenario){
        ExtendedCheck c{ids[scenario-1]};Probe p;std::string error;DmGraphicsExtendedRecord r{};uint64_t id=0;
        bool ok=ready(p,&error);identity=graphics_platform_stats();c.baseline_passed=ok;c.generation=p.runtime.process().load_generation();
        if(ok){c.first_fence=graphics_platform_last_fence()+1;ok=hold_loaded(p,&id,&error);}
        if(ok)ok=extended_call(p,"graphics_extended_first",scenario,&r,&error)&&entered_hold(id);
        if(ok){const auto stats=graphics_platform_stats();
            c.first_pending=r.first_wait==UINT64_MAX&&r.guest_waits==0&&stats.submits==2&&stats.completed==1&&
                graphics_platform_last_fence()==c.first_fence&&graphics_platform_completed_fence()==1;
            ok=c.first_pending;
        }
        if(id){std::string release;ok=dm_android_graphics_release_publication_barrier(id,&release)&&ok;if(!release.empty())error=release;}
        if(ok&&scenario==4)ok=extended_call(p,"graphics_extended_wait",10000000000ull,&r,&error)&&r.wait_result<2&&r.guest_waits==1;
        if(ok)ok=extended_call(p,"graphics_extended_next",scenario,&r,&error)&&
            extended_call(p,"graphics_extended_wait",10000000000ull,&r,&error)&&r.wait_result<2;
        if(ok){c.bytes=bytes(p,r.window_address,extended_expected(scenario))?65536:0;
            ok=c.bytes==65536&&data_oracle(p)&&r.submits==2&&r.guest_waits==(scenario==4?2u:1u)&&
                !r.queue_error_first&&!r.queue_error_second&&!p.runtime.unavailable_host_calls();}
        const auto stats=graphics_platform_stats();c.submits=stats.submits;c.completed=stats.completed;c.failed=stats.failed;
        c.last_fence=graphics_platform_last_fence();c.completed_fence=graphics_platform_completed_fence();c.guest_waits=r.guest_waits;c.wait_result=r.wait_result;
        ok=ok&&stats.submits==3&&stats.completed==3&&!stats.failed&&!stats.validation_errors&&c.last_fence==3&&c.completed_fence==3;
        c.closed=p.end(true,&error);c.passed=ok&&c.closed;c.detail=error;checks.push_back(std::move(c));
    }
    // Every controlled boundary gets a new runtime and a successful real GPU
    // baseline before injection. No engine initializer can clear the injection.
    const char* failure_ids[]={"late-unsupported-whole-submit","preaccept-allocation-refusal","preaccept-submit-refusal","accepted-device-loss","accepted-publication-refusal"};
    const NvnVkEngine::Failure injections[]={NvnVkEngine::Failure::None,NvnVkEngine::Failure::Allocation,NvnVkEngine::Failure::Submit,NvnVkEngine::Failure::DeviceLost,NvnVkEngine::Failure::Publication};
    for(unsigned index=0;index<5;++index){
        ExtendedCheck c{failure_ids[index]};Probe p;std::string error;DmGraphicsExtendedRecord r{};uint64_t prior_guest_waits=0;
        bool ok=ready(p,&error);identity=graphics_platform_stats();c.baseline_passed=ok;c.generation=p.runtime.process().load_generation();
        std::vector<uint8_t> expected(0x40000);
        if(ok)ok=dm_android_kernel_memory_copy_readable(p.last.pool_address,expected.data(),expected.size());
        if(ok){const auto seed=extended_seed(10);std::memcpy(expected.data()+0x20000,seed.data(),seed.size());
            c.first_fence=graphics_platform_last_fence();
            if(index)ok=graphics_platform_inject_failure(injections[index]);}
        if(ok)ok=extended_call(p,"graphics_extended_first",index?20:10,&r,&error);
        const bool accepted=index>=3;
        if(ok&&accepted){ok=extended_call(p,"graphics_extended_wait",10000000000ull,&r,&error)&&r.wait_result==3&&
                extended_call(p,"graphics_extended_wait",0,&r,&error)&&r.wait_result==3;}
        if(ok&&accepted){
            const auto before=graphics_platform_stats();const uint64_t fence=graphics_platform_last_fence(),completed_fence=graphics_platform_completed_fence();
            const uint64_t sticky=r.queue_error_second;prior_guest_waits=r.guest_waits;
            const bool unchanged_before=bytes(p,p.last.pool_address,expected);
            // Reuse the actual guest recorder export. Its CPU setup writes the
            // same independently expected seed; the valid GPU prefix must be
            // refused by this terminal runtime before a new fence is allocated.
            const bool prior_failed=sticky&&r.queue_error_first==sticky&&prior_guest_waits==2;
            const bool suffix_ran=prior_failed&&extended_call(p,"graphics_extended_first",20,&r,&error);
            ok=suffix_ran&&r.submits==1&&r.guest_waits==0&&r.queue_error_first==sticky&&r.queue_error_second==sticky;
            if(ok)ok=extended_call(p,"graphics_extended_wait",0,&r,&error);
            c.suffix_wait_result=r.wait_result;
            const auto after=graphics_platform_stats();
            const bool counters_unchanged=before.submits==after.submits&&before.completed==after.completed&&before.failed==after.failed&&
                before.buffer_copies==after.buffer_copies&&before.uniform_updates==after.uniform_updates&&before.image_uploads==after.image_uploads&&
                before.image_downloads==after.image_downloads&&before.render_passes==after.render_passes&&before.flushes==after.flushes&&
                before.invalidates==after.invalidates&&before.validation_errors==after.validation_errors;
            c.suffix_rejected=suffix_ran&&r.submits==1&&counters_unchanged&&graphics_platform_last_fence()==fence&&graphics_platform_completed_fence()==completed_fence;
            c.suffix_unchanged=suffix_ran&&unchanged_before&&bytes(p,p.last.pool_address,expected)&&counters_unchanged;
            ok=ok&&c.suffix_rejected&&c.suffix_unchanged&&r.wait_result==3&&r.guest_waits==1&&
                r.queue_error_first==sticky&&r.queue_error_second==sticky;
        }
        if(ok){c.bytes=bytes(p,p.last.pool_address,expected)?262144:0;
            ok=c.bytes==262144&&r.queue_error_first&&r.queue_error_first==r.queue_error_second;
            uintptr_t queue_address=0;queue_t queue{};
            if(!p.runtime.process().symbol("queue",&queue_address)||!p.runtime.process().copy_readable(queue_address,&queue,sizeof(queue)))ok=false;
            else {c.detail=queue.error_reason;c.error_code=queue.error_code;c.error_operation=queue.error_operation;
                // Accepted backend errors are surfaced by repeated QueueGetError;
                // rejected commands additionally carry the owned queue reason.
                if(!accepted)ok=ok&&queue.error_code==NVN_INVALID&&!c.detail.empty();
                if(index==0)ok=ok&&queue.error_operation==OP_DISPATCH;}
        }
        const auto stats=graphics_platform_stats();c.submits=stats.submits;c.completed=stats.completed;c.failed=stats.failed;
        c.last_fence=graphics_platform_last_fence();c.completed_fence=graphics_platform_completed_fence();c.guest_waits=prior_guest_waits+r.guest_waits;c.wait_result=r.wait_result;c.queue_error=r.queue_error_second;
        ok=ok&&stats.submits==(accepted?2u:1u)&&stats.completed==1&&stats.failed==(accepted?1u:0u)&&
            c.last_fence==(accepted?2u:1u)&&c.completed_fence==1&&!stats.validation_errors&&
            !p.runtime.unavailable_host_calls()&&dm_android_kernel_memory_quiescent();
        c.closed=p.end(true,&error);c.passed=ok&&c.closed;if(!error.empty())c.detail=error;checks.push_back(std::move(c));
    }
    {
        ExtendedCheck c{"held-gpu-retention-and-retirement"};Probe p;std::string error;uint64_t id=0;
        bool ok=false;
        {std::lock_guard<std::mutex> metadata(metadata_mutex);
            if((!barrier.armed||barrier.released)&&next_barrier!=UINT64_MAX){barrier={};barrier.id=++next_barrier;barrier.armed=true;id=barrier.id;ok=true;}}
        if(ok)ok=p.begin(&error)&&entered_hold(id);
        if(ok){c.first_pending=p.last.wait_result==2&&untouched_data_oracle(p);
            ok=c.first_pending&&dm_android_graphics_retention_snapshot(id,&c.retention,&error)&&c.retention.find("\"status\":\"PASS\"")!=std::string::npos&&
                c.retention.find("graphics work still retains guest memory")!=std::string::npos;}
        if(id){std::string release;ok=dm_android_graphics_release_publication_barrier(id,&release)&&ok;if(!release.empty())error=release;}
        if(ok)ok=p.invoke(p.wait,10000000000ull,true,&error)&&p.last.wait_result<2&&data_oracle(p)&&
            retired_heap_roundtrip(p.last.pool_address)&&data_oracle(p);
        c.baseline_passed=ok;c.generation=p.runtime.process().load_generation();c.wait_result=p.last.wait_result;
        c.bytes=ok?70404:0;const auto stats=graphics_platform_stats();c.submits=stats.submits;c.completed=stats.completed;c.failed=stats.failed;
        c.last_fence=graphics_platform_last_fence();c.completed_fence=graphics_platform_completed_fence();
        ok=ok&&stats.submits==1&&stats.completed==1&&!stats.failed&&!stats.validation_errors;
        c.closed=p.end(true,&error);c.passed=ok&&c.closed;c.detail=error;checks.push_back(std::move(c));
    }
    {
        ExtendedCheck c{"clean-reload-after-terminal-cases"};Probe p;std::string error;
        const bool ok=ready(p,&error)&&dm_android_kernel_memory_quiescent();identity=graphics_platform_stats();
        c.baseline_passed=ok;c.generation=p.runtime.process().load_generation();c.wait_result=p.last.wait_result;
        c.bytes=ok?70404:0;c.closed=p.end(true,&error);c.passed=ok&&c.closed;c.detail=error;checks.push_back(std::move(c));
    }
    bool passed=true;uint64_t total_bytes=0;for(const auto& c:checks){passed=passed&&c.passed;total_bytes+=c.bytes;}
    std::ostringstream o;o<<"{\"schemaVersion\":1,\"suite\":\"android-graphics-extended\",\"status\":\""<<(passed?"PASS":"FAIL")
      <<"\",\"gamePlayable\":false,\"syntheticOnly\":true,\"originalGame\":\"NOT_RUN\",\"capability\":\"offscreen-diagnostic\",\"verifiedDataBytes\":"<<total_bytes
      <<",\"checkCount\":"<<checks.size()<<",\"checks\":[";
    for(size_t i=0;i<checks.size();++i){const auto& c=checks[i];if(i)o<<',';
        o<<"{\"id\":\""<<c.id<<"\",\"passed\":"<<(c.passed?"true":"false")<<",\"baselinePassed\":"<<(c.baseline_passed?"true":"false")
         <<",\"loadGeneration\":"<<c.generation<<",\"verifiedDataBytes\":"<<c.bytes
         <<",\"firstFence\":"<<c.first_fence<<",\"lastFence\":"<<c.last_fence<<",\"completedFence\":"<<c.completed_fence
         <<",\"submits\":"<<c.submits<<",\"completed\":"<<c.completed<<",\"failed\":"<<c.failed<<",\"guestWaits\":"<<c.guest_waits
         <<",\"waitResult\":"<<(c.wait_result==UINT64_MAX?"null":std::to_string(c.wait_result))<<",\"queueError\":"<<c.queue_error<<",\"firstPending\":"<<(c.first_pending?"true":"false")
         <<",\"queueErrorCode\":"<<c.error_code<<",\"queueErrorOperation\":"<<c.error_operation
         <<",\"suffixRejected\":"<<(c.suffix_rejected?"true":"false")<<",\"suffixWaitResult\":"<<(c.suffix_wait_result==UINT64_MAX?"null":std::to_string(c.suffix_wait_result))
         <<",\"suffixUnchanged\":"<<(c.suffix_unchanged?"true":"false")
         <<",\"closed\":"<<(c.closed?"true":"false")<<",\"detail\":\""<<escaped(c.detail)<<'"';
        if(!c.retention.empty())o<<",\"retention\":"<<c.retention;o<<'}';}
    o<<"],\"gpu\":{\"device\":\""<<escaped(identity.device_name)<<"\",\"vendorId\":"<<identity.vendor_id<<",\"deviceId\":"<<identity.device_id
     <<",\"apiVersion\":"<<identity.api_version<<",\"driverVersion\":"<<identity.driver_version<<",\"validationAvailable\":"<<(identity.validation_available?"true":"false")
     <<",\"validationErrors\":"<<identity.validation_errors<<"},\"sdkPackageSha256\":\""<<hex(dm_graphics_package_sha256,32)<<"\",\"unsupported\":[\"draw\",\"compute\",\"shaders\",\"presentation\",\"full-product\"]}";
    return o.str();
}

std::string dm_android_run_window_probes(){
    std::lock_guard<std::mutex> lock(probe_mutex);owner(true);
    Probe p;WindowProbeCall calls;std::string error;
    std::vector<std::pair<std::string,bool>> checks;
    uint64_t generation=0,binding=0,pin=0,heap=0;ViPlatformSnapshot vi{};
    const auto before=graphics_surface_snapshot();SurfaceSnapshot after{};SurfaceCadence tick{};
    VkReplayStats gpu_before{},gpu_after{};GraphicsWindowStats final_window{};
    auto check=[&](const char* id,bool value){checks.emplace_back(id,value);return value;};
    try {
        if(!p.begin(&error)||!p.invoke(p.wait,UINT64_MAX,true,&error))throw std::runtime_error(error);
        if(!check("unchanged-carrier-bootstrap",shape(p)&&data_oracle(p)&&forced(p)&&p.authority_checks==3))throw std::runtime_error("W0 baseline failed");
        generation=p.runtime.process().load_generation();binding=nvn_core_binding_epoch();heap=p.last.pool_address;
        uintptr_t record_address=0;DmGraphicsExtendedRecord record{};
        if(!p.runtime.process().symbol("graphics_extended_result",&record_address)||
           !p.runtime.process().copy_readable(record_address,&record,sizeof(record))||record.heap_address!=heap||record.heap_size!=0x200000||
           heap>UINTPTR_MAX-window_heap_offset-window_pool_bytes)throw std::runtime_error("W0 carrier heap receipt invalid");
        const uint64_t address=heap+window_heap_offset;
        pin=dm_android_kernel_gpu_pin(address,window_pool_bytes,DM_GUEST_READ|DM_GUEST_WRITE);
        std::vector<uint8_t> initial(window_pool_bytes);
        const bool owned=pin&&dm_android_kernel_gpu_copy(pin,address,initial.data(),initial.size())&&
            std::all_of(initial.begin(),initial.end(),[](uint8_t b){return b==0;})&&window_heap_offset>=0x80000+DM_DRAW_POOL_BYTES;
        if(!check("dedicated-owned-heap-tail-no-pool-alias",owned))throw std::runtime_error("W0 heap tail ownership or unused-byte check refused");
        calls.memory=reinterpret_cast<uint8_t*>(address);
        const char* names[]={"_ZN2nn2vi10InitializeEv","_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE",
            "_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE","_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE"};
        uintptr_t functions[4]{};
        for(size_t i=0;i<4;++i)if(!p.runtime.registry().resolve(names[i],true,&functions[i])||!functions[i]||
            !p.runtime.registry().contains_callable(functions[i]))throw std::runtime_error("W0 forced VI export missing");
        calls.vi.initialize=reinterpret_cast<void (*)()>(functions[0]);calls.vi.open=reinterpret_cast<uint32_t (*)(void**)>(functions[1]);
        calls.vi.create=reinterpret_cast<uint32_t (*)(void**,void*)>(functions[2]);calls.vi.native=reinterpret_cast<uint32_t (*)(void**,void*)>(functions[3]);
#define WINDOW_PROC_RESOLVE(name) calls.name=reinterpret_cast<NVNT_##name>(nvn_core_lookup(#name));if(!calls.name)throw std::runtime_error("W0 procedure missing: " #name);
        WINDOW_PROCS(WINDOW_PROC_RESOLVE)
#undef WINDOW_PROC_RESOLVE
        gpu_before=graphics_platform_stats();GuestCallResult result;
        const bool invoked=p.stack.call(p.environment.state,reinterpret_cast<uintptr_t>(&window_probe_leaf),reinterpret_cast<uint64_t>(&calls),&result,&error)&&
            !result.exited&&result.value==0x7730;
        check("authored-host-leaf-on-owned-guest-stack",invoked&&calls.vi.owned_outputs&&calls.vi.created);
        vi=vi_platform_snapshot();tick=graphics_surface_cadence();gpu_after=graphics_platform_stats();final_window=graphics_platform_window_stats();
        check("actual-vi-device-pool-two-textures-window",calls.device&&calls.pool&&calls.textures&&calls.window&&
            vi.initialized&&vi.generation==generation&&vi.native_window==calls.vi.native_window);
        bool frames=calls.completed==4,epochs=true,cadence=true,slots=true;uint64_t last_tick=0,last_render=0;
        for(unsigned i=0;i<4;++i){const auto& f=calls.frames[i];
            frames&=f.configured&&f.acquired_ok&&f.dependency_wait&&f.pixels&&f.clear_pixels&&f.posted&&!calls.queue_error&&
                f.render_fence>last_render&&f.completed_fence>=f.render_fence;
            epochs&=f.acquired.generation==generation&&f.acquired.binding_epoch==binding&&f.acquired.revision&&
                f.acquired.surface.owner==before.owner&&f.acquired.surface.epoch==before.epoch&&
                f.surface_after.owner==before.owner&&f.surface_after.epoch==before.epoch;
            if(f.interval==1){cadence&=f.acquired.cadence_serial>last_tick;last_tick=f.acquired.cadence_serial;}
            slots&=f.index==static_cast<int>(i%2);last_render=f.render_fence;
        }
        check("four-gpu-clear-copy-publications-and-posts",frames);
        check("initial-acquire-real-empty-fence",calls.frames[0].dependency_fence>gpu_before.completed&&
            calls.frames[0].acquired.last_acquire_fence==calls.frames[0].dependency_fence&&
            calls.frames[0].render_fence>calls.frames[0].dependency_fence);
        check("two-slots-round-robin-repeat",slots);
        check("actual-choreographer-interval-one",cadence&&last_tick&&tick.serial>=last_tick&&tick.frame_time_ns>0&&
            tick.ticket.owner==before.owner&&tick.ticket.epoch==before.epoch);
        check("same-runtime-window-vi-surface-epoch",epochs&&vi.surface.owner==before.owner&&vi.surface.epoch==before.epoch);
        check("crop-and-interval-zero-one",calls.frames[2].crop_width==40&&calls.frames[2].crop_height==30&&
            calls.frames[0].interval==0&&calls.frames[1].interval==1&&calls.frames[2].interval==1&&calls.frames[3].interval==0&&frames);
        check("only-successful-posts-counted",final_window.presents==4&&final_window.retired&&!final_window.live);
        check("actual-vulkan-operations",gpu_after.submits==gpu_before.submits+5&&gpu_after.completed==gpu_before.completed+5&&
            gpu_after.render_passes>=gpu_before.render_passes+4&&gpu_after.image_downloads>=gpu_before.image_downloads+8&&
            gpu_after.image_uploads>=gpu_before.image_uploads+4&&!gpu_after.validation_errors&&!p.runtime.unavailable_host_calls());
        check("window-resources-finalized-carrier-unchanged",calls.cleaned&&data_oracle(p));
        dm_android_kernel_gpu_unpin(pin);pin=0;
        std::string shutdown_error;if(!p.end(false,&shutdown_error))throw std::runtime_error(shutdown_error);
        if(!frames&&!calls.failure.empty())error=calls.failure;
        check("runtime-and-kernel-retired",!p.opened&&dm_android_kernel_memory_quiescent()&&!vi_platform_snapshot().generation);
    }catch(const std::exception& failure){error=failure.what();check("execution-completed",false);}
    if(pin)dm_android_kernel_gpu_unpin(pin);
    if(p.opened){std::string cleanup;if(!p.end(true,&cleanup))std::abort();}
    after=graphics_surface_snapshot();check("four-accepted-and-posted-surface-acks",after.posts==before.posts+4&&after.accepted==before.accepted+4&&after.failures==before.failures);
    owner(false);bool passed=!checks.empty();for(const auto& c:checks)passed&=c.second;
    std::ostringstream out;out<<"{\"schemaVersion\":1,\"suite\":\"AndroidNVNWindow\",\"status\":\""<<(passed?"PASS":"FAIL")
        <<"\",\"sourcekind\":\"AuthoredHostLeaf\",\"scope\":\"actual-owned-GuestStack-VI-NVN-window-Vulkan-publication-Surface-post\""
        <<",\"gamePlayable\":false,\"originalGame\":\"NOT_RUN\",\"originalArmGameEntry\":\"NOT_RUN\",\"originalImportRelocations\":\"NOT_RUN\",\"scanout\":\"NOT_PROVEN\""
        <<",\"loadGeneration\":"<<generation<<",\"bindingEpoch\":"<<binding<<",\"viBinding\":"<<vi.binding<<",\"oeEpoch\":"<<vi.oe_epoch
        <<",\"displayToken\":"<<calls.vi.display<<",\"layerToken\":"<<calls.vi.layer<<",\"nativeWindowToken\":"<<calls.vi.native_window
        <<",\"ownedGuestStackOutputs\":"<<(calls.vi.owned_outputs?"true":"false")<<",\"heapAddress\":"<<heap
        <<",\"poolOffset\":"<<window_heap_offset<<",\"poolBytes\":"<<window_pool_bytes<<",\"textureWidth\":"<<window_width<<",\"textureHeight\":"<<window_height
        <<",\"successfulPresents\":"<<final_window.presents<<",\"surfaceOwner\":"<<before.owner<<",\"surfaceEpoch\":"<<before.epoch
        <<",\"surfacePostsBefore\":"<<before.posts<<",\"surfacePostsAfter\":"<<after.posts<<",\"surfaceAcceptedBefore\":"<<before.accepted<<",\"surfaceAcceptedAfter\":"<<after.accepted
        <<",\"cadenceSerial\":"<<tick.serial<<",\"frameTimeNs\":"<<tick.frame_time_ns<<",\"gpuSubmits\":"<<(gpu_after.submits-gpu_before.submits)
        <<",\"gpuCompleted\":"<<(gpu_after.completed-gpu_before.completed)<<",\"validationErrors\":"<<gpu_after.validation_errors
        <<",\"pixelPattern\":\"top-left red,top-right green,bottom-left blue,bottom-right yellow; split x23 y17; cyan marker x5..10 y7..12; RGBA8 top-row-first\""
        <<",\"failedFrame\":"<<calls.failed_frame<<",\"failureStage\":\""<<calls.failure_stage
        <<"\",\"error\":\""<<escaped(error)<<"\",\"frames\":[";
    for(unsigned i=0;i<4;++i){if(i)out<<',';const auto& f=calls.frames[i];out<<"{\"slot\":"<<f.index<<",\"interval\":"<<f.interval
        <<",\"layout\":\""<<(f.index==0?"linear":"block-linear")<<"\",\"windowRevision\":"<<f.acquired.revision
        <<",\"surfaceOwner\":"<<f.acquired.surface.owner<<",\"surfaceEpoch\":"<<f.acquired.surface.epoch
        <<",\"cadenceSerial\":"<<f.acquired.cadence_serial<<",\"dependencyFence\":"<<f.dependency_fence<<",\"renderFence\":"<<f.render_fence<<",\"completedFence\":"<<f.completed_fence
        <<",\"crop\":["<<f.crop_x<<','<<f.crop_y<<','<<f.crop_width<<','<<f.crop_height<<"],\"configured\":"<<(f.configured?"true":"false")
        <<",\"observedInterval\":"<<f.observed_interval<<",\"observedCrop\":["<<f.observed_crop[0]<<','<<f.observed_crop[1]<<','<<f.observed_crop[2]<<','<<f.observed_crop[3]
        <<"],\"pixelsPassed\":"<<(f.pixels?"true":"false")
        <<",\"clearPixelsPassed\":"<<(f.clear_pixels?"true":"false")<<",\"acceptedAndPosted\":"<<(f.posted?"true":"false")
        <<",\"successfulPresents\":"<<f.presented.presents<<",\"cornerRgbaHex\":\""<<hex(f.corners,16)<<"\",\"publishedRgbaSha256\":\""<<hex(f.rgba_sha256,32)<<"\"}";}
    out<<"],\"checks\":[";for(size_t i=0;i<checks.size();++i){if(i)out<<',';out<<"{\"id\":\""<<checks[i].first<<"\",\"status\":\""<<(checks[i].second?"PASS":"FAIL")<<"\"}";}
    out<<"]}";return out.str();
}
#define SAMPLED_EXTRA_PROCS(X) \
    X(nvnProgramInitialize) X(nvnProgramSetShaders) X(nvnProgramFinalize) \
    X(nvnTexturePoolInitialize) X(nvnTexturePoolFinalize) X(nvnTexturePoolRegisterTexture) \
    X(nvnSamplerPoolInitialize) X(nvnSamplerPoolFinalize) X(nvnSamplerPoolRegisterSampler) \
    X(nvnSamplerBuilderSetDefaults) X(nvnSamplerBuilderSetDevice) X(nvnSamplerBuilderSetMinMagFilter) \
    X(nvnSamplerBuilderSetWrapMode) X(nvnSamplerBuilderSetLodClamp) X(nvnSamplerInitialize) X(nvnSamplerFinalize) \
    X(nvnDeviceGetSeparateTextureHandle) X(nvnDeviceGetSeparateSamplerHandle) \
    X(nvnCommandBufferSetTexturePool) X(nvnCommandBufferSetSamplerPool) \
    X(nvnCommandBufferBindSeparateTextures) X(nvnCommandBufferBindSeparateSamplers) \
    X(nvnVertexAttribStateSetDefaults) X(nvnVertexAttribStateSetFormat) X(nvnVertexAttribStateSetStreamIndex) \
    X(nvnVertexStreamStateSetDefaults) X(nvnVertexStreamStateSetStride) X(nvnVertexStreamStateSetDivisor) \
    X(nvnColorStateSetDefaults) X(nvnColorStateSetBlendEnable) X(nvnBlendStateSetDefaults) X(nvnChannelMaskStateSetDefaults) \
    X(nvnPolygonStateSetDefaults) X(nvnPolygonStateSetCullFace) X(nvnPolygonStateSetPolygonMode) \
    X(nvnDepthStencilStateSetDefaults) X(nvnDepthStencilStateSetDepthTestEnable) X(nvnDepthStencilStateSetDepthWriteEnable) X(nvnDepthStencilStateSetStencilTestEnable) \
    X(nvnMultisampleStateSetDefaults) X(nvnMultisampleStateSetSamples) X(nvnMultisampleStateSetAlphaToCoverageEnable) X(nvnMultisampleStateSetSampleLocationsEnable) \
    X(nvnCommandBufferBindProgram) X(nvnCommandBufferBindUniformBuffer) X(nvnCommandBufferBindVertexAttribState) X(nvnCommandBufferBindVertexStreamState) X(nvnCommandBufferBindVertexBuffers) \
    X(nvnCommandBufferBindColorState) X(nvnCommandBufferBindBlendState) X(nvnCommandBufferBindChannelMaskState) X(nvnCommandBufferBindPolygonState) X(nvnCommandBufferBindDepthStencilState) X(nvnCommandBufferBindMultisampleState) \
    X(nvnCommandBufferSetViewports) X(nvnCommandBufferSetScissor) X(nvnCommandBufferSetDepthRange) X(nvnCommandBufferDrawArrays)
namespace {
constexpr unsigned sampled_pixel_bytes=64*64*4;
constexpr size_t sampled_readback=0x24000,sampled_pixels=sampled_readback+0x100;
struct SampledFrame {
    uint64_t upload_fence=0,draw_fence=0,completed_fence=0;
    bool source_updated=false,held=false,retained=false,pixels=false,guards=false,posted=false,observed=false;
    GraphicsWindowStats window{};
    SurfaceSnapshot surface{};
    uint8_t digest[32]{};
};
struct SampledProbeCall {
    ViProbeCall vi;
#define SAMPLED_PROC_FIELD(name) NVNT_##name name=nullptr;
    WINDOW_PROCS(SAMPLED_PROC_FIELD)
    SAMPLED_EXTRA_PROCS(SAMPLED_PROC_FIELD)
#undef SAMPLED_PROC_FIELD
    uint8_t* memory=nullptr;uint64_t generation=0,observation=0;
    uintptr_t records[2]{};SampledFrame frames[2];
    bool initialized=false,owned_arrays=false,cleaned=false;
    bool surface_replaced=false,stale_ticket_refused=false;
    unsigned completed=0;const char* stage="initialization";std::string failure;
};
bool sampled_pixel_oracle(const uint8_t* actual,unsigned frame){
    // Expected bytes only: no CPU-produced framebuffer is submitted/presented.
    static constexpr uint8_t palette[2][16]={{255,0,0,255,0,255,0,255,0,0,255,255,255,255,0,255},
        {0,255,255,255,255,0,255,255,255,255,255,255,0,0,0,255}};
    for(unsigned y=0;y<64;++y)for(unsigned x=0;x<64;++x){
        const uint8_t black[]={0,0,0,255};
        const uint8_t* expected=x>=8&&x<56&&y>=8&&y<56?palette[frame]+((y>=32?2:0)+(x>=32?1:0))*4:black;
        if(std::memcmp(actual+(y*64+x)*4,expected,4))return false;
    }
    return true;
}
__attribute__((noinline)) uint64_t sampled_probe_leaf(uint64_t argument){
    auto& c=*reinterpret_cast<SampledProbeCall*>(argument);
    NVNdevice device{};NVNdeviceBuilder db{};NVNmemoryPool pool{};NVNmemoryPoolBuilder pb{};
    NVNtexture target{},source{};NVNtextureBuilder tb{};NVNqueue queue{};NVNqueueBuilder qb{};
    NVNwindow window{};NVNwindowBuilder wb{};NVNsync sync{},acquire_sync{};NVNcommandBuffer command{};
    NVNprogram program{};NVNtexturePool texture_pool{};NVNsamplerPool sampler_pool{};
    NVNsampler sampler{};NVNsamplerBuilder sb{};
    bool device_ready=false,pool_ready=false,target_ready=false,source_ready=false,queue_ready=false;
    bool window_ready=false,sync_ready=false,acquire_ready=false,command_ready=false,program_ready=false;
    bool texture_pool_ready=false,sampler_pool_ready=false,sampler_ready=false,publication_held=false;
    const uint8_t palettes[2][16]={{255,0,0,255,0,255,0,255,0,0,255,255,255,255,0,255},
        {0,255,255,255,255,0,255,255,255,255,255,255,0,0,0,255}};
    vi_probe_leaf(reinterpret_cast<uint64_t>(&c.vi));
    if(!c.vi.created||!c.vi.owned_outputs){c.failure="sampled VI owned-stack outputs refused";return 0;}
    do {
        c.nvnDeviceBuilderSetDefaults(&db);device_ready=c.nvnDeviceInitialize(&device,&db)!=0;if(!device_ready)break;
        c.nvnMemoryPoolBuilderSetDefaults(&pb);c.nvnMemoryPoolBuilderSetDevice(&pb,&device);
        c.nvnMemoryPoolBuilderSetStorage(&pb,c.memory,window_pool_bytes);c.nvnMemoryPoolBuilderSetFlags(&pb,0x24);
        pool_ready=c.nvnMemoryPoolInitialize(&pool,&pb)!=0;if(!pool_ready)break;
        for(unsigned i=0;i<2;++i){
            c.nvnTextureBuilderSetDefaults(&tb);c.nvnTextureBuilderSetDevice(&tb,&device);
            c.nvnTextureBuilderSetTarget(&tb,NVN_TEXTURE_TARGET_2D);c.nvnTextureBuilderSetWidth(&tb,i?2:64);
            c.nvnTextureBuilderSetHeight(&tb,i?2:64);c.nvnTextureBuilderSetLevels(&tb,1);c.nvnTextureBuilderSetSamples(&tb,1);
            c.nvnTextureBuilderSetFormat(&tb,NVN_FORMAT_RGBA8);c.nvnTextureBuilderSetFlags(&tb,NVN_TEXTURE_FLAGS_LINEAR);
            c.nvnTextureBuilderSetStride(&tb,i?8:256);c.nvnTextureBuilderSetStorage(&tb,&pool,i?0x10000:0);
            const size_t bytes=c.nvnTextureBuilderGetStorageSize(&tb);if(!bytes||bytes>0x10000)break;
            if(i)source_ready=c.nvnTextureInitialize(&source,&tb)!=0;
            else target_ready=c.nvnTextureInitialize(&target,&tb)!=0;
        }
        if(!target_ready||!source_ready)break;
        texture_pool_ready=c.nvnTexturePoolInitialize(&texture_pool,&pool,0x18000,4)!=0;
        sampler_pool_ready=c.nvnSamplerPoolInitialize(&sampler_pool,&pool,0x19000,4)!=0;
        c.nvnSamplerBuilderSetDefaults(&sb);c.nvnSamplerBuilderSetDevice(&sb,&device);
        c.nvnSamplerBuilderSetMinMagFilter(&sb,NVN_MIN_FILTER_NEAREST,NVN_MAG_FILTER_NEAREST);
        c.nvnSamplerBuilderSetWrapMode(&sb,NVN_WRAP_MODE_CLAMP_TO_EDGE,NVN_WRAP_MODE_CLAMP_TO_EDGE,NVN_WRAP_MODE_CLAMP_TO_EDGE);
        c.nvnSamplerBuilderSetLodClamp(&sb,0,0);sampler_ready=c.nvnSamplerInitialize(&sampler,&sb)!=0;
        if(!texture_pool_ready||!sampler_pool_ready||!sampler_ready)break;
        c.nvnTexturePoolRegisterTexture(&texture_pool,2,&source,nullptr);c.nvnSamplerPoolRegisterSampler(&sampler_pool,3,&sampler);
        program_ready=c.nvnProgramInitialize(&program,&device)!=0;
        const NVNshaderData shaders[]={{c.records[0],reinterpret_cast<void*>(c.records[0]+144)},
            {c.records[1],reinterpret_cast<void*>(c.records[1]+208)}};
        if(!program_ready||!c.nvnProgramSetShaders(&program,2,shaders))break;
        c.nvnQueueBuilderSetDefaults(&qb);c.nvnQueueBuilderSetDevice(&qb,&device);
        const size_t qbytes=c.nvnQueueBuilderGetQueueMemorySize(&qb);if(qbytes>0x80000)break;
        c.nvnQueueBuilderSetQueueMemory(&qb,c.memory+0x40000,qbytes);queue_ready=c.nvnQueueInitialize(&queue,&qb)!=0;
        sync_ready=c.nvnSyncInitialize(&sync,&device)!=0;acquire_ready=c.nvnSyncInitialize(&acquire_sync,&device)!=0;
        command_ready=c.nvnCommandBufferInitialize(&command,&device)!=0;if(!queue_ready||!sync_ready||!acquire_ready||!command_ready)break;
        c.nvnCommandBufferAddCommandMemory(&command,&pool,0x30000,0x10000);
        c.nvnWindowBuilderSetDefaults(&wb);c.nvnWindowBuilderSetDevice(&wb,&device);
        c.nvnWindowBuilderSetNativeWindow(&wb,reinterpret_cast<NVNnativeWindow>(c.vi.native_window));
        NVNtexture* slots[]={&target};c.nvnWindowBuilderSetTextures(&wb,1,slots);c.nvnWindowBuilderSetPresentInterval(&wb,0);
        window_ready=c.nvnWindowInitialize(&window,&wb)!=0;if(!window_ready)break;
        std::memset(c.memory+0x20000,0x6d,0x2000);
        std::memset(c.memory+0x20000,0,1380);std::memset(c.memory+0x21000,0,1380);
        const float one=1;for(unsigned i=0;i<=72;++i)std::memcpy(c.memory+0x21000+192+i*16,&one,4);
        const float vertices[]={1,-.75f,.5f,1,-1,-.75f,.5f,1,1,.75f,.5f,1,1,-.75f,.5f,1,1,.75f,.5f,1,-1,.75f,.5f,1};
        std::memset(c.memory+0x22000,0x72,0x1000);std::memcpy(c.memory+0x22100,vertices,sizeof(vertices));
        c.initialized=true;
        for(unsigned frame=0;frame<2;++frame){
            auto& f=c.frames[frame];c.stage="window acquire";int index=-1;
            if(frame){
                const auto previous=c.frames[0].window.surface;
                const auto current=graphics_surface_ticket();
                c.surface_replaced=previous.owner!=current.owner||previous.epoch!=current.epoch;
                if(c.surface_replaced){
                    // Reuse the first real GPU readback, never an authored CPU
                    // framebuffer. A retired Activity ticket must not reach the
                    // replacement Surface, even while this runtime stays live.
                    SurfaceFrame stale;stale.width=stale.height=64;stale.row_stride_bytes=256;
                    stale.rgba8.assign(c.memory+sampled_pixels,c.memory+sampled_pixels+sampled_pixel_bytes);
                    const auto before=graphics_surface_snapshot();
                    const auto refused=graphics_surface_present(previous,c.generation,std::move(stale));
                    const auto after=graphics_surface_snapshot();
                    c.stale_ticket_refused=!refused.accepted&&!refused.locked&&!refused.posted&&
                        before.posts==after.posts&&before.accepted==after.accepted&&before.failures==after.failures;
                    if(!c.stale_ticket_refused){c.stage="retired Surface ticket refusal";break;}
                }
            }
            if(c.nvnWindowAcquireTexture(&window,frame?nullptr:&acquire_sync,&index)!=NVN_WINDOW_ACQUIRE_TEXTURE_RESULT_SUCCESS||index!=0||
                (!frame&&c.nvnSyncWait(&acquire_sync,UINT64_MAX)>=2))break;
            f.window=graphics_platform_window_stats();
            c.stage="source GPU update";std::memcpy(c.memory+0x23000,palettes[frame],16);std::memset(c.memory+0x23100,0xa9,16);
            const NVNcopyRegion source_region={0,0,0,2,2,1};
            c.nvnCommandBufferBeginRecording(&command);c.nvnCommandBufferSetCopyRowStride(&command,8);
            c.nvnCommandBufferCopyBufferToTexture(&command,reinterpret_cast<uint64_t>(c.memory+0x23000),&source,nullptr,&source_region,0);
            c.nvnCommandBufferCopyTextureToBuffer(&command,&source,nullptr,&source_region,reinterpret_cast<uint64_t>(c.memory+0x23100),0);
            NVNcommandHandle handle=c.nvnCommandBufferEndRecording(&command);c.nvnQueueSubmitCommands(&queue,1,&handle);
            c.nvnQueueFenceSync(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);f.upload_fence=reinterpret_cast<sync_t*>(&sync)->fence;
            if(c.nvnSyncWait(&sync,UINT64_MAX)>=2||c.nvnQueueGetError(&queue,nullptr))break;
            f.source_updated=std::memcmp(c.memory+0x10000,palettes[frame],16)==0&&std::memcmp(c.memory+0x23100,palettes[frame],16)==0;
            if(!f.source_updated)break;
            c.stage="sampled draw recording";std::memset(c.memory+sampled_readback,0xa7,0x5000);
            NVNvertexAttribState attr{};NVNvertexStreamState stream{};NVNcolorState color{};NVNblendState blend{};
            NVNchannelMaskState channels{};NVNpolygonState polygon{};NVNdepthStencilState depth{};NVNmultisampleState samples{};
            c.nvnVertexAttribStateSetDefaults(&attr);c.nvnVertexAttribStateSetFormat(&attr,NVN_FORMAT_RGBA32F,0);c.nvnVertexAttribStateSetStreamIndex(&attr,0);
            c.nvnVertexStreamStateSetDefaults(&stream);c.nvnVertexStreamStateSetStride(&stream,16);c.nvnVertexStreamStateSetDivisor(&stream,0);
            c.nvnColorStateSetDefaults(&color);c.nvnColorStateSetBlendEnable(&color,0,0);c.nvnBlendStateSetDefaults(&blend);c.nvnChannelMaskStateSetDefaults(&channels);
            c.nvnPolygonStateSetDefaults(&polygon);c.nvnPolygonStateSetCullFace(&polygon,NVN_FACE_NONE);c.nvnPolygonStateSetPolygonMode(&polygon,NVN_POLYGON_MODE_FILL);
            c.nvnDepthStencilStateSetDefaults(&depth);c.nvnDepthStencilStateSetDepthTestEnable(&depth,0);c.nvnDepthStencilStateSetDepthWriteEnable(&depth,0);c.nvnDepthStencilStateSetStencilTestEnable(&depth,0);
            c.nvnMultisampleStateSetDefaults(&samples);c.nvnMultisampleStateSetSamples(&samples,1);c.nvnMultisampleStateSetAlphaToCoverageEnable(&samples,0);c.nvnMultisampleStateSetSampleLocationsEnable(&samples,0);
            const NVNtexture* targets[]={&target};const float viewport[]={0,0,64,64},black[]={0,0,0,1};
            const NVNbufferRange vertex={reinterpret_cast<uint64_t>(c.memory+0x22100),sizeof(vertices)};
            const NVNseparateTextureHandle th[]={c.nvnDeviceGetSeparateTextureHandle(&device,2)};
            const NVNseparateSamplerHandle sh[]={c.nvnDeviceGetSeparateSamplerHandle(&device,3)};
            uintptr_t bottom=0;size_t length=0;c.owned_arrays=active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(th),&bottom,&length)&&
                active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(sh),&bottom,&length)&&active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(shaders),&bottom,&length);
            c.nvnCommandBufferBeginRecording(&command);c.nvnCommandBufferSetRenderTargets(&command,1,targets,nullptr,nullptr,nullptr);
            c.nvnCommandBufferBindProgram(&command,&program,NVN_SHADER_STAGE_VERTEX_BIT|NVN_SHADER_STAGE_FRAGMENT_BIT);
            // Both support descriptors are generated from the pinned artifact
            // fills by prepare_draw; this shader has no guest UBO semantics.
            c.nvnCommandBufferSetTexturePool(&command,&texture_pool);c.nvnCommandBufferSetSamplerPool(&command,&sampler_pool);
            c.nvnCommandBufferBindSeparateTextures(&command,NVN_SHADER_STAGE_FRAGMENT,0,1,th);c.nvnCommandBufferBindSeparateSamplers(&command,NVN_SHADER_STAGE_FRAGMENT,0,1,sh);
            c.nvnCommandBufferBindVertexAttribState(&command,1,&attr);c.nvnCommandBufferBindVertexStreamState(&command,1,&stream);c.nvnCommandBufferBindVertexBuffers(&command,0,1,&vertex);
            c.nvnCommandBufferBindColorState(&command,&color);c.nvnCommandBufferBindBlendState(&command,&blend);c.nvnCommandBufferBindChannelMaskState(&command,&channels);
            c.nvnCommandBufferBindPolygonState(&command,&polygon);c.nvnCommandBufferBindDepthStencilState(&command,&depth);c.nvnCommandBufferBindMultisampleState(&command,&samples);
            c.nvnCommandBufferSetViewports(&command,0,1,viewport);c.nvnCommandBufferSetScissor(&command,0,0,64,64);c.nvnCommandBufferSetDepthRange(&command,0,1);
            c.nvnCommandBufferClearColor(&command,0,black,15);c.nvnCommandBufferDrawArrays(&command,NVN_DRAW_PRIMITIVE_TRIANGLES,0,6);
            const NVNcopyRegion all={0,0,0,64,64,1};c.nvnCommandBufferSetCopyRowStride(&command,256);
            c.nvnCommandBufferCopyTextureToBuffer(&command,&target,nullptr,&all,reinterpret_cast<uint64_t>(c.memory+sampled_pixels),0);
            handle=c.nvnCommandBufferEndRecording(&command);
            c.stage="accepted draw publication retention";
            publication_held=graphics_platform_publication_barrier(c.generation,true);if(!publication_held)break;
            c.nvnQueueSubmitCommands(&queue,1,&handle);c.nvnQueueFenceSync(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);
            f.draw_fence=reinterpret_cast<sync_t*>(&sync)->fence;
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
            while(!graphics_platform_publication_barrier_entered(c.generation)&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
            f.held=graphics_platform_publication_barrier_entered(c.generation);
            if(f.held){
                const auto tp=texture_pool;const auto sp=sampler_pool;const auto sm=sampler;const auto tx=source;const auto mp=pool;const auto pg=program;
                c.nvnTexturePoolRegisterTexture(&texture_pool,2,&source,nullptr);c.nvnSamplerPoolRegisterSampler(&sampler_pool,3,&sampler);
                c.nvnTexturePoolFinalize(&texture_pool);c.nvnSamplerPoolFinalize(&sampler_pool);c.nvnSamplerFinalize(&sampler);
                c.nvnTextureFinalize(&source);c.nvnMemoryPoolFinalize(&pool);c.nvnProgramFinalize(&program);
                f.retained=std::memcmp(&tp,&texture_pool,sizeof(tp))==0&&std::memcmp(&sp,&sampler_pool,sizeof(sp))==0&&
                    std::memcmp(&sm,&sampler,sizeof(sm))==0&&std::memcmp(&tx,&source,sizeof(tx))==0&&std::memcmp(&mp,&pool,sizeof(mp))==0&&
                    std::memcmp(&pg,&program,sizeof(pg))==0&&graphics_platform_program_stats().retained>0&&nvn_core_last_error().code==NVN_RETAINED;
            }
            graphics_platform_publication_barrier(c.generation,false);publication_held=false;
            c.stage="draw fence and exact GPU pixels";
            if(c.nvnSyncWait(&sync,UINT64_MAX)>=2||c.nvnQueueGetError(&queue,nullptr))break;
            f.completed_fence=graphics_platform_completed_fence();f.pixels=sampled_pixel_oracle(c.memory+sampled_pixels,frame);
            module_sha256(c.memory+sampled_pixels,sampled_pixel_bytes,f.digest);
            f.guards=std::all_of(c.memory+sampled_readback,c.memory+sampled_pixels,[](uint8_t v){return v==0xa7;})&&
                std::all_of(c.memory+sampled_pixels+sampled_pixel_bytes,c.memory+sampled_readback+0x5000,[](uint8_t v){return v==0xa7;})&&
                std::all_of(c.memory+0x22000,c.memory+0x22100,[](uint8_t v){return v==0x72;})&&
                std::memcmp(c.memory+0x22100,vertices,sizeof(vertices))==0&&
                std::all_of(c.memory+0x22100+sizeof(vertices),c.memory+0x23000,[](uint8_t v){return v==0x72;});
            c.stage="W0 accepted Surface post";const auto before=graphics_surface_snapshot();
            c.nvnQueuePresentTexture(&queue,&window,index);const auto after=graphics_surface_snapshot();
            f.surface=after;
            f.posted=!c.nvnQueueGetError(&queue,nullptr)&&graphics_platform_window_stats().presents==frame+1&&after.posts==before.posts+1&&after.accepted==before.accepted+1;
            if(!c.owned_arrays||!f.held||!f.retained||!f.pixels||!f.guards||!f.posted)break;
            c.stage="compositor observation acknowledgement";f.observed=sampled_observe(c.observation,frame+1);if(!f.observed)break;
            ++c.completed;
        }
    }while(false);
    if(publication_held)graphics_platform_publication_barrier(c.generation,false);
    if(c.completed!=2){const auto e=nvn_core_last_error();std::ostringstream detail;
        detail<<"sampled frame "<<c.completed<<" stopped at "<<c.stage<<"; NVN code="<<e.code<<" operation="<<e.operation<<" reason="<<(e.reason?e.reason:"");c.failure=detail.str();}
    if(queue_ready)c.nvnQueueFinish(&queue);
    if(window_ready)c.nvnWindowFinalize(&window);
    if(command_ready)c.nvnCommandBufferFinalize(&command);
    if(sync_ready)c.nvnSyncFinalize(&sync);if(acquire_ready)c.nvnSyncFinalize(&acquire_sync);
    if(texture_pool_ready)c.nvnTexturePoolFinalize(&texture_pool);if(sampler_pool_ready)c.nvnSamplerPoolFinalize(&sampler_pool);
    if(sampler_ready)c.nvnSamplerFinalize(&sampler);if(program_ready)c.nvnProgramFinalize(&program);
    if(source_ready)c.nvnTextureFinalize(&source);if(target_ready)c.nvnTextureFinalize(&target);
    if(queue_ready)c.nvnQueueFinalize(&queue);if(pool_ready)c.nvnMemoryPoolFinalize(&pool);if(device_ready)c.nvnDeviceFinalize(&device);
    c.cleaned=c.initialized&&reinterpret_cast<pool_t*>(&pool)->magic==0&&reinterpret_cast<samp_t*>(&sampler)->magic==0&&
        reinterpret_cast<tex_t*>(&source)->magic==0&&graphics_platform_program_stats().live==0&&graphics_platform_window_stats().retired;
    return 0x7364;
}
}
std::string dm_android_sampled_frame_snapshot(){
    std::lock_guard<std::mutex> lock(sampled_observation_mutex);std::ostringstream out;
    out<<"{\"id\":"<<sampled_observation<<",\"active\":"<<(sampled_observation_active?"true":"false")<<",\"frame\":"<<sampled_observation_frame<<"}";return out.str();
}
bool dm_android_sampled_frame_ack(uint64_t id,unsigned frame){
    std::lock_guard<std::mutex> lock(sampled_observation_mutex);
    if(!sampled_observation_active||id!=sampled_observation||!frame||frame!=sampled_observation_frame)return false;
    sampled_observation_ack=frame;sampled_observation_changed.notify_all();return true;
}
std::string dm_android_run_sampled_draw_probes(){
    std::lock_guard<std::mutex> lock(probe_mutex);owner(true);Probe p;SampledProbeCall calls;std::string error;
    std::vector<std::pair<std::string,bool>> checks;uint64_t pin=0,binding=0;VkReplayStats before{},after{};
    const auto surface_before=graphics_surface_snapshot();SurfaceSnapshot surface_after{};
    auto check=[&](const char* id,bool ok){checks.emplace_back(id,ok);return ok;};
    try{
        {std::lock_guard<std::mutex> observation_lock(sampled_observation_mutex);
            if(next_sampled_observation==INT64_MAX)throw std::runtime_error("sampled observation ID exhausted");
            sampled_observation=++next_sampled_observation;sampled_observation_frame=sampled_observation_ack=0;sampled_observation_active=true;calls.observation=sampled_observation;}
        if(!p.begin(&error)||!p.invoke(p.wait,UINT64_MAX,true,&error))throw std::runtime_error(error);
        if(!check("carrier-bootstrap-and-existing-GPU-path",shape(p)&&data_oracle(p)&&forced(p)&&p.authority_checks==3))throw std::runtime_error("sampled carrier baseline failed");
        calls.generation=p.runtime.process().load_generation();binding=nvn_core_binding_epoch();
        const uint64_t heap=p.last.pool_address;if(heap>UINTPTR_MAX-window_heap_offset-window_pool_bytes)throw std::runtime_error("sampled heap address overflow");
        const uint64_t address=heap+window_heap_offset;pin=dm_android_kernel_gpu_pin(address,window_pool_bytes,DM_GUEST_READ|DM_GUEST_WRITE);
        std::vector<uint8_t> initial(window_pool_bytes);const bool owned=pin&&dm_android_kernel_gpu_copy(pin,address,initial.data(),initial.size())&&
            std::all_of(initial.begin(),initial.end(),[](uint8_t b){return b==0;})&&window_heap_offset>=0x80000+DM_DRAW_POOL_BYTES;
        if(!check("separate-owned-unused-heap-tail",owned))throw std::runtime_error("sampled unused owned heap refused");calls.memory=reinterpret_cast<uint8_t*>(address);
        if(!p.runtime.process().module_symbol(1,"sampled_draw_shader_vs_record",&calls.records[0])||
           !p.runtime.process().module_symbol(1,"sampled_draw_shader_fs_record",&calls.records[1]))throw std::runtime_error("exact sampled carrier record exports absent");
        const char* names[]={"_ZN2nn2vi10InitializeEv","_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE","_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE","_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE"};
        uintptr_t functions[4]{};for(unsigned i=0;i<4;++i)if(!p.runtime.registry().resolve(names[i],true,&functions[i])||!p.runtime.registry().contains_callable(functions[i]))throw std::runtime_error("sampled forced VI export missing");
        calls.vi.initialize=reinterpret_cast<void (*)()>(functions[0]);calls.vi.open=reinterpret_cast<uint32_t (*)(void**)>(functions[1]);
        calls.vi.create=reinterpret_cast<uint32_t (*)(void**,void*)>(functions[2]);calls.vi.native=reinterpret_cast<uint32_t (*)(void**,void*)>(functions[3]);
#define SAMPLED_PROC_RESOLVE(name) calls.name=reinterpret_cast<NVNT_##name>(nvn_core_lookup(#name));if(!calls.name)throw std::runtime_error("sampled procedure missing: " #name);
        WINDOW_PROCS(SAMPLED_PROC_RESOLVE) SAMPLED_EXTRA_PROCS(SAMPLED_PROC_RESOLVE)
#undef SAMPLED_PROC_RESOLVE
        before=graphics_platform_stats();GuestCallResult result;
        const bool invoked=p.stack.call(p.environment.state,reinterpret_cast<uintptr_t>(&sampled_probe_leaf),reinterpret_cast<uint64_t>(&calls),&result,&error)&&!result.exited&&result.value==0x7364;
        after=graphics_platform_stats();check("actual-owned-GuestStack-and-NVN-arrays",invoked&&calls.vi.owned_outputs&&calls.owned_arrays);
        check("NVN-live-program-descriptor-pool-sampler-window",calls.initialized);
        for(unsigned i=0;i<2;++i){const auto& f=calls.frames[i];check(i?"second-source-update-real-GPU-and-pixels":"first-source-real-GPU-and-pixels",
            f.source_updated&&f.draw_fence>f.upload_fence&&f.completed_fence>=f.draw_fence&&f.pixels&&f.guards&&f.posted&&f.observed);
            check(i?"second-accepted-retention":"first-accepted-retention",f.held&&f.retained);}
        check("same-live-descriptors-see-updated-source",calls.completed==2&&std::memcmp(calls.frames[0].digest,calls.frames[1].digest,32)!=0);
        check("same-window-runtime-and-binding-between-draws",calls.completed==2&&calls.frames[0].window.revision&&
            calls.frames[0].window.revision==calls.frames[1].window.revision&&
            calls.frames[0].window.generation==calls.generation&&calls.frames[1].window.generation==calls.generation&&
            calls.frames[0].window.binding_epoch==binding&&calls.frames[1].window.binding_epoch==binding);
        if(calls.surface_replaced)check("retired-Activity-ticket-never-posts",calls.stale_ticket_refused);
        check("real-Vulkan-draws-and-completions",after.submits==before.submits+5&&after.completed==before.completed+5&&after.graphics_draws==before.graphics_draws+2&&!after.validation_errors&&!p.runtime.unavailable_host_calls());
        check("resources-retire-after-real-fences",calls.cleaned&&data_oracle(p));
        dm_android_kernel_gpu_unpin(pin);pin=0;std::string cleanup;if(!p.end(false,&cleanup))throw std::runtime_error(cleanup);
        check("runtime-kernel-and-VI-retired",!p.opened&&dm_android_kernel_memory_quiescent()&&!vi_platform_snapshot().generation);
        if(calls.completed!=2)error=calls.failure;
    }catch(const std::exception& e){error=e.what();check("execution-completed",false);}
    {std::lock_guard<std::mutex> observation_lock(sampled_observation_mutex);sampled_observation_active=false;sampled_observation_changed.notify_all();}
    if(pin)dm_android_kernel_gpu_unpin(pin);if(p.opened){std::string cleanup;if(!p.end(true,&cleanup))std::abort();}
    surface_after=graphics_surface_snapshot();check("two-accepted-Surface-posts",surface_after.posts==surface_before.posts+2&&surface_after.accepted==surface_before.accepted+2&&surface_after.failures==surface_before.failures);
    owner(false);bool passed=!checks.empty();for(const auto& item:checks)passed&=item.second;
    std::ostringstream out;out<<"{\"schemaVersion\":1,\"suite\":\"AndroidNVNSampledDraw\",\"status\":\""<<(passed?"PASS":"FAIL")
        <<"\",\"sourcekind\":\"AuthoredHostLeaf+AuthoredTranslatorFixture\",\"originalGame\":\"NOT_RUN\",\"originalArmGameEntry\":\"NOT_RUN\",\"gamePlayable\":false,\"scanout\":\"NOT_PROVEN\""
        <<",\"loadGeneration\":"<<calls.generation<<",\"bindingEpoch\":"<<binding<<",\"poolOffset\":"<<window_heap_offset<<",\"poolBytes\":"<<window_pool_bytes
        <<",\"ownedGuestStackOutputs\":"<<(calls.vi.owned_outputs&&calls.owned_arrays?"true":"false")<<",\"successfulPresents\":"<<calls.completed
        <<",\"gpuSubmits\":"<<after.submits-before.submits<<",\"gpuCompleted\":"<<after.completed-before.completed<<",\"gpuDraws\":"<<after.graphics_draws-before.graphics_draws
        <<",\"surfaceReplaced\":"<<(calls.surface_replaced?"true":"false")<<",\"staleTicketRefused\":"<<(calls.stale_ticket_refused?"true":"false")
        <<",\"validationErrors\":"<<after.validation_errors<<",\"failedStage\":\""<<calls.stage<<"\",\"error\":\""<<escaped(error)<<"\",\"frames\":[";
    for(unsigned i=0;i<2;++i){if(i)out<<',';const auto& f=calls.frames[i];out<<"{\"index\":"<<i<<",\"uploadFence\":"<<f.upload_fence<<",\"drawFence\":"<<f.draw_fence
        <<",\"windowRevision\":"<<f.window.revision<<",\"loadGeneration\":"<<f.window.generation<<",\"bindingEpoch\":"<<f.window.binding_epoch
        <<",\"surfaceOwner\":"<<f.window.surface.owner<<",\"surfaceEpoch\":"<<f.window.surface.epoch
        <<",\"surfacePosts\":"<<f.surface.posts<<",\"surfaceAccepted\":"<<f.surface.accepted
        <<",\"completedFence\":"<<f.completed_fence<<",\"sourceUpdated\":"<<(f.source_updated?"true":"false")<<",\"publicationHeld\":"<<(f.held?"true":"false")
        <<",\"retentionPassed\":"<<(f.retained?"true":"false")<<",\"pixelsPassed\":"<<(f.pixels?"true":"false")<<",\"guardsPassed\":"<<(f.guards?"true":"false")
        <<",\"acceptedAndPosted\":"<<(f.posted?"true":"false")<<",\"compositorAcknowledged\":"<<(f.observed?"true":"false")<<",\"rgbaSha256\":\""<<hex(f.digest,32)<<"\"}";}
    out<<"],\"checks\":[";for(size_t i=0;i<checks.size();++i){if(i)out<<',';out<<"{\"id\":\""<<checks[i].first<<"\",\"status\":\""<<(checks[i].second?"PASS":"FAIL")<<"\"}";}out<<"]}";return out.str();
}
#undef SAMPLED_EXTRA_PROCS
#undef WINDOW_PROCS

std::string dm_android_run_vi_probes(){
    std::lock_guard<std::mutex> lock(probe_mutex);owner(true);
    Probe p;ViProbeCall calls;std::string error;
    std::vector<std::pair<std::string,bool>> checks;
    const auto before=graphics_surface_snapshot();
    SurfaceSnapshot after_calls{},after{};ViPlatformSnapshot live{};ViNativeWindow window{};
    uint64_t generation=0,runtime_generation=0;size_t forced_exports=0;
    auto check=[&](const char* id,bool value){checks.emplace_back(id,value);return value;};
    auto same=[](const ViNativeWindow& a,const ViNativeWindow& b){return a.generation==b.generation&&a.binding==b.binding&&
        a.surface.owner==b.surface.owner&&a.surface.epoch==b.surface.epoch&&a.width==b.width&&a.height==b.height;};
    try {
        if(!p.begin(&error)||!p.invoke(p.wait,UINT64_MAX,true,&error))throw std::runtime_error(error);
        if(!check("unchanged-authored-graphics-bootstrap",shape(p)&&data_oracle(p)&&forced(p)&&p.authority_checks==3))
            throw std::runtime_error("VI authored graphics bootstrap failed");
        generation=p.runtime.process().load_generation();runtime_generation=p.environment.state.runtime_generation;
        // Registry lookup and C++ host storage remain on the normal host stack.
        const char* names[]={"_ZN2nn2vi10InitializeEv","_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE",
            "_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE","_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE"};
        uintptr_t functions[4]{};
        for(size_t i=0;i<4;++i){
            if(!p.runtime.registry().resolve(names[i],true,&functions[i])||!functions[i]||
               !p.runtime.registry().contains_callable(functions[i]))throw std::runtime_error("forced Android VI export missing");
            if(p.runtime.registry().force_hits(names[i]))++forced_exports;
        }
        check("four-actual-forced-exports",forced_exports==4);
        calls.initialize=reinterpret_cast<void (*)()>(functions[0]);
        calls.open=reinterpret_cast<uint32_t (*)(void**)>(functions[1]);
        calls.create=reinterpret_cast<uint32_t (*)(void**,void*)>(functions[2]);
        calls.native=reinterpret_cast<uint32_t (*)(void**,void*)>(functions[3]);
        GuestCallResult result;
        const bool invoked=p.stack.call(p.environment.state,reinterpret_cast<uintptr_t>(&vi_probe_leaf),
            reinterpret_cast<uint64_t>(&calls),&result,&error)&&!result.exited&&result.value==0x7169;
        if(!check("trusted-host-leaf-on-owned-guest-stack",invoked&&calls.owned_outputs))
            throw std::runtime_error(error.empty()?"VI actual guest stack call failed":error);
        live=vi_platform_snapshot();
        check("actual-vi-initialize-open-create-query",calls.created&&live.initialized&&live.generation==generation&&
            runtime_generation==generation&&live.oe_epoch==p.runtime.oe_epoch()&&live.display==calls.display&&
            live.layer==calls.layer&&live.native_window==calls.native_window);
        check("host-context-output-slots-refused",calls.host_outputs_refused);
        check("forged-parent-output-unchanged",calls.forged_parents_refused);
        check("second-layer-refused-first-preserved",calls.capacity_preserved&&live.layer==calls.layer);
        check("repeated-display-native-queries",calls.repeated);
        after_calls=graphics_surface_snapshot();const auto ticket=graphics_surface_ticket();
        const bool queried=vi_platform_native_window(reinterpret_cast<void*>(calls.native_window),runtime_generation,&window);
        check("native-token-matches-live-surface",queried&&window.generation==generation&&window.binding==live.binding&&
            window.surface.owner==ticket.owner&&window.surface.epoch==ticket.epoch&&window.surface.owner==after_calls.owner&&
            window.surface.epoch==after_calls.epoch&&window.width==after_calls.width&&window.height==after_calls.height&&
            window.width&&window.height&&after_calls.available&&!after_calls.active);
        ViNativeWindow rejected=window;
        const auto stale=generation==UINT64_MAX?generation-1:generation+1;
        check("stale-generation-output-unchanged",!vi_platform_native_window(reinterpret_cast<void*>(calls.native_window),stale,&rejected)&&same(rejected,window));
        check("no-unavailable-host-calls",p.runtime.unavailable_host_calls()==0);
        if(!p.end(false,&error))throw std::runtime_error(error);
        rejected=window;
        const auto retired=vi_platform_snapshot();
        check("shutdown-retires-vi-and-refuses-token",!vi_platform_native_window(reinterpret_cast<void*>(calls.native_window),runtime_generation,&rejected)&&
            same(rejected,window)&&!retired.generation&&!retired.binding&&!retired.initialized&&!retired.display&&!retired.layer&&!retired.native_window);
        check("runtime-resources-retired",!p.opened&&dm_android_kernel_memory_quiescent());
    }catch(const std::exception& failure){error=failure.what();check("execution-completed",false);}
    if(p.opened){std::string cleanup;if(!p.end(true,&cleanup))std::abort();}
    after=graphics_surface_snapshot();check("vi-does-not-post-surface",before.posts==after_calls.posts&&before.posts==after.posts);
    owner(false);bool passed=!checks.empty();for(const auto& c:checks)passed&=c.second;
    std::ostringstream out;out<<"{\"schemaVersion\":1,\"suite\":\"AndroidVI\",\"status\":\""<<(passed?"PASS":"FAIL")
       <<"\",\"scope\":\"authored-host-leaf-to-real-VI-HLE-in-actual-GuestStack\",\"originalGame\":\"NOT_RUN\",\"gamePlayable\":false"
       <<",\"originalArmGameEntry\":\"NOT_RUN\",\"originalImportRelocations\":\"NOT_RUN\",\"presentation\":\"NOT_RUN\""
       <<",\"loadGeneration\":"<<generation<<",\"runtimeGeneration\":"<<runtime_generation<<",\"viBinding\":"<<live.binding
       <<",\"oeEpoch\":"<<live.oe_epoch<<",\"forcedExports\":"<<forced_exports<<",\"authorityChecks\":"<<p.authority_checks
       <<",\"ownedGuestStackOutputs\":"<<(calls.owned_outputs?"true":"false")
       <<",\"displayToken\":"<<calls.display<<",\"layerToken\":"<<calls.layer<<",\"nativeWindowToken\":"<<calls.native_window
       <<",\"surfaceOwner\":"<<window.surface.owner<<",\"surfaceEpoch\":"<<window.surface.epoch
       <<",\"surfaceWidth\":"<<window.width<<",\"surfaceHeight\":"<<window.height
       <<",\"surfacePostsBefore\":"<<before.posts<<",\"surfacePostsAfterCalls\":"<<after_calls.posts<<",\"surfacePostsAfter\":"<<after.posts
       <<",\"error\":\""<<escaped(error)<<"\",\"checks\":[";
    for(size_t i=0;i<checks.size();++i){if(i)out<<',';out<<"{\"id\":\""<<checks[i].first<<"\",\"status\":\""<<(checks[i].second?"PASS":"FAIL")<<"\"}";}
    out<<"]}";return out.str();
}

std::string dm_android_run_shader_compute_probes(){
    std::lock_guard<std::mutex> lock(probe_mutex);owner(true);
    Probe p;std::string error;DmGraphicsComputeRecord record{};bool held=false;
    std::vector<std::pair<std::string,bool>> checks;std::array<std::vector<uint8_t>,4> outputs;
    uint64_t generation=0,epoch=0,held_fence=0;VkReplayStats identity;GraphicsProgramStats retained{},terminal{},finalized{};
    auto check=[&](const char* id,bool value){checks.emplace_back(id,value);return value;};
    auto call=[&](const char* name,uint64_t argument=0,bool use_argument=true){uintptr_t entry=0,address=0;return
        (p.runtime.process().symbol(name,&entry)&&p.runtime.process().symbol("graphics_compute_result",&address)&&
         p.invoke(entry,argument,use_argument,&error)&&p.runtime.process().copy_readable(address,&record,sizeof(record)))||
        fail(&error,"actual compute guest entry/result copy refused");};
    auto read=[&](uint64_t address,size_t size,std::vector<uint8_t>* out){out->resize(size);return
        p.runtime.process().copy_readable(address,out->data(),size)||dm_android_kernel_memory_copy_readable(address,out->data(),size);};
    auto load64=[](const uint8_t* bytes){uint64_t out=0;for(unsigned i=0;i<8;++i)out|=uint64_t(bytes[i])<<(i*8);return out;};
    auto store64=[](uint8_t* bytes,uint64_t value){for(unsigned i=0;i<8;++i)bytes[i]=uint8_t(value>>(i*8));};
    std::vector<uint8_t> source(0x1000,0x72),count(65536,0x66);uint32_t n=37;std::memcpy(count.data(),&n,4);
    for(size_t i=0;i<256;++i)store64(source.data()+256+i*8,(0xd831a97b1234abcdull+uint64_t(i)*0x789b1234feca0123ull)^(uint64_t(i)<<41));
    const uint64_t special[]={0,UINT64_MAX,0x100000000ull,0xffffffffull,0x7777777700000001ull,0x7777777700000000ull,UINT64_MAX,0,0x00000001ffffffffull,0x0000000100000000ull,0,UINT64_MAX};
    for(size_t i=0;i<sizeof(special)/sizeof(*special);++i)store64(source.data()+256+i*8,special[i]);
    std::array<std::vector<uint8_t>,4> expected;
    for(size_t k=0;k<4;++k){expected[k].assign(0x1000,0x73);std::fill(expected[k].begin()+256,expected[k].begin()+768,0xaa);
        for(size_t i=0;i<37;++i){const auto* src=source.data()+256;uint64_t value;
            if(k==0)value=load64(src+16*i);else if(k==1)value=load64(src+16*i+8);
            else if(k==2)value=load64(src+32*i+16)-load64(src+32*i);else value=load64(src+32*i+24)-load64(src+32*i+8);
            store64(expected[k].data()+256+8*i,value);}}
    try {
        if(!p.begin(&error)||!p.invoke(p.wait,UINT64_MAX,true,&error))throw std::runtime_error(error);
        check("unchanged-transfer-bootstrap",shape(p)&&data_oracle(p)&&forced(p));
        generation=p.runtime.process().load_generation();epoch=nvn_core_binding_epoch();identity=graphics_platform_stats();
        if(!graphics_platform_publication_barrier(generation,true))throw std::runtime_error("compute publication hold refused");held=true;
        if(!call("graphics_compute_begin",0,false))throw std::runtime_error(error);
        if(!check("original-program-transactions",record.initialized==4&&record.shaders==4&&record.submits==1&&!record.queue_error))throw std::runtime_error("guest original program transactions or submit refused");
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
        while(!graphics_platform_publication_barrier_entered(generation)&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if(!check("actual-fence-publication-held",graphics_platform_publication_barrier_entered(generation)))throw std::runtime_error("actual compute fence did not reach publication hold");held_fence=graphics_platform_last_fence(generation);
        retained=graphics_platform_program_stats();
        bool untouched=true;for(size_t k=0;k<4;++k){std::vector<uint8_t> initial(0x1000,0x73);std::fill(initial.begin()+256,initial.begin()+768,0xaa);untouched&=bytes(p,record.destination[k],initial)&&bytes(p,record.echo[k],std::vector<uint8_t>(0x1000,0x84));}
        uint32_t event=1,initial_count=0;untouched&=dm_android_kernel_memory_copy_readable(record.event_address,&event,4)&&!event&&dm_android_kernel_memory_copy_readable(record.count_address,&initial_count,4)&&initial_count==UINT32_MAX;
        check("no-guest-publication-before-release",untouched);
        if(!call("graphics_compute_retained"))throw std::runtime_error(error);
        const bool core_retained=nvn_core_last_error().code==NVN_RETAINED;
        check("actual-core-and-backend-retention",record.retained_finalize&&record.retained_replace&&core_retained&&retained.live==4&&retained.retained==4);
        std::string shutdown_error;const bool blocked=!p.runtime.shutdown(&shutdown_error);
        check("actual-process-mapping-retention",blocked&&p.runtime.process().load_generation()==generation&&!dm_android_kernel_memory_quiescent());
        graphics_platform_publication_barrier(generation,false);held=false;
        if(!call("graphics_compute_wait",UINT64_MAX))throw std::runtime_error(error);
        terminal=graphics_platform_program_stats();
        check("real-guest-wait-and-program-retirement",record.wait_result<2&&!record.queue_error&&terminal.live==4&&terminal.retained==0&&graphics_platform_completed_fence()==held_fence);
        bool data=bytes(p,record.source_address,source)&&bytes(p,record.source_echo,source)&&bytes(p,record.count_address,count)&&bytes(p,record.count_echo,count);
        for(size_t k=0;k<4;++k){std::vector<uint8_t> echo;data&=read(record.echo[k],0x1000,&echo)&&echo==expected[k]&&bytes(p,record.destination[k],expected[k]);if(echo.size()==0x1000)outputs[k].assign(echo.begin()+256,echo.begin()+768);}
        event=0;data&=dm_android_kernel_memory_copy_readable(record.event_address,&event,4)&&event==0xc2b;
        check("four-original-gpu-results-full-guards-events",data);
        bool matrix=true;for(size_t k=0;k<4;++k)for(size_t j=0;j<4;++j){std::vector<uint8_t> want(expected[j].begin()+256,expected[j].begin()+768);matrix&=(outputs[k]==want)==(k==j);}
        check("independent-original-four-by-four",matrix);
        const auto before_rollback=graphics_platform_program_stats();
        if(!graphics_platform_inject_failure(NvnVkEngine::Failure::Pipeline)||!call("graphics_compute_pipeline_rollback")||!call("graphics_compute_wait",UINT64_MAX))throw std::runtime_error("actual pipeline rollback probe failed");
        const auto after_rollback=graphics_platform_program_stats();
        check("actual-pipeline-failure-preserves-usable-old-program",record.pipeline_rollback&&record.wait_result<2&&!record.queue_error&&
            bytes(p,record.destination[1],expected[1])&&bytes(p,record.echo[1],expected[1])&&after_rollback.live==4&&!after_rollback.retained&&after_rollback.replaced==before_rollback.replaced&&after_rollback.bytes==before_rollback.bytes);
        const auto before=graphics_platform_stats();
        std::vector<std::vector<uint8_t>> before_bytes(6);for(size_t k=0;k<4;++k)if(!read(record.echo[k],0x1000,&before_bytes[k]))throw std::runtime_error("negative before readback");
        if(!read(record.count_address,65536,&before_bytes[4])||!read(record.event_address,4,&before_bytes[5]))throw std::runtime_error("negative count/event snapshot");
        if(!call("graphics_compute_negatives"))throw std::runtime_error(error);
        bool no_effect=graphics_platform_stats().submits==before.submits;
        for(size_t k=0;k<4;++k)no_effect&=bytes(p,record.echo[k],before_bytes[k]);no_effect&=bytes(p,record.count_address,before_bytes[4])&&bytes(p,record.event_address,before_bytes[5]);
        check("source-array-and-control-rollback",record.rollback);
        check("bad-object-storage-and-owned-stack",record.bad_object&&record.stack_object);
        check("stale-alias-replace-finalize-rejected",record.stale_replace&&record.stale_finalize&&graphics_platform_program_stats().live==4);
        check("late-stale-bind-and-unknown-count-no-effects",record.stale_submit_error&&record.unknown_count_error&&no_effect);
        if(!call("graphics_compute_end"))throw std::runtime_error(error);
        finalized=graphics_platform_program_stats();check("real-program-finalization",record.programs_finalized==4&&!finalized.live&&!finalized.retained&&!finalized.bytes&&finalized.created==5&&finalized.released==5);
        identity=graphics_platform_stats();check("actual-original-dispatch-and-validation",identity.compute_dispatches==5&&identity.completed>=3&&!identity.validation_errors);
        if(!p.end(false,&error))throw std::runtime_error(error);check("runtime-unload-after-retirement",true);
    }catch(const std::exception& failure){error=failure.what();check("execution-completed",false);}
    if(held)graphics_platform_publication_barrier(generation,false);
    if(p.opened){std::string cleanup;if(!p.end(true,&cleanup))std::abort();}
    owner(false);bool passed=!checks.empty();for(const auto& c:checks)passed&=c.second;
    std::ostringstream out;out<<"{\"schemaVersion\":1,\"suite\":\"android-original-compute\",\"status\":\""<<(passed?"PASS":"FAIL")<<"\",\"gamePlayable\":false,\"originalGame\":\"NOT_RUN\",\"route\":\"ARM64-guest-shared-NVN-Vulkan-checked-guest-publication\",\"verifiedOriginalKernels\":"<<(passed?4:0)<<",\"gpuDispatches\":"<<identity.compute_dispatches<<",\"dataOraclePassed\":"<<(passed?"true":"false")<<",\"loadGeneration\":"<<generation<<",\"bindingEpoch\":"<<epoch<<",\"fence\":"<<held_fence<<",\"error\":\""<<escaped(error)<<"\",\"checks\":[";
    for(size_t i=0;i<checks.size();++i){if(i)out<<',';out<<"{\"id\":\""<<checks[i].first<<"\",\"status\":\""<<(checks[i].second?"PASS":"FAIL")<<"\"}";}
    out<<"],\"sourcekind\":\"OriginalMaxwell\",\"kernels\":[";
    const auto& catalog=compiled_compute_catalog();
    for(size_t k=0;k<4;++k){if(k)out<<',';const auto& source_key=std::get<OriginalMaxwellKey>(catalog[k].key.source);out<<"{\"kernel\":"<<k<<",\"n\":37,\"groups\":[2,1,1],\"objectGeneration\":"<<record.generation[k]<<",\"serial\":"<<record.serial[k]<<",\"artifactSha256\":\""<<hex(catalog[k].expected_file_sha256.data(),32)<<"\",\"controlSha256\":\""<<hex(source_key.control_sha256.data(),32)<<"\",\"codeSha256\":\""<<hex(source_key.code_sha256.data(),32)<<"\",\"readbackHex\":\""<<hex(outputs[k].data(),outputs[k].size())<<"\"}";}
    out<<"],\"gpu\":{\"device\":\""<<escaped(identity.device_name)<<"\",\"physicalApi\":"<<identity.api_version<<",\"effectiveApi\":4194304,\"validationErrors\":"<<identity.validation_errors<<"},\"programs\":{\"held\":"<<retained.retained<<",\"afterFence\":"<<terminal.retained<<",\"afterFinalize\":"<<finalized.live<<"},\"sdkPackageSha256\":\""<<hex(dm_graphics_package_sha256,32)<<"\",\"trustedOriginalImageSha256\":\""<<hex(std::get<OriginalMaxwellKey>(catalog[0].key.source).trusted_content_sha256.data(),32)<<"\"}";
    return out.str();
}

std::string dm_android_run_shader_draw_probes(DmGraphicsDrawReadback* image,
    const std::function<bool(const DmGraphicsDrawReadback&,std::string*)>& present){
    if(image)*image={};
    std::lock_guard<std::mutex> lock(probe_mutex);owner(true);
    Probe p;std::string error;DmGraphicsDrawRecord record{};bool held=false;
    std::vector<std::pair<std::string,bool>> checks;
    uint64_t generation=0,runtime_generation=0,epoch=0,held_fence=0;
    VkReplayStats identity;GraphicsProgramStats retained{},terminal{},finalized{};
    bool arrays=false,indexed=false,rollback=false,late=false,retention=false,data=false,consumer_invoked=false,consumed=false;
    DmGraphicsDrawReadback frame;
    std::array<std::vector<uint8_t>,4> expected;
    auto check=[&](const char* id,bool value){checks.emplace_back(id,value);if(!value)throw std::runtime_error(id);};
    auto call=[&](const char* name,uint64_t argument=0,bool use_argument=true){
        uintptr_t entry=0,address=0;
        if(!p.runtime.process().symbol(name,&entry)||!p.runtime.process().symbol("graphics_draw_result",&address)||
           !p.invoke(entry,argument,use_argument,&error)||!p.runtime.process().copy_readable(address,&record,sizeof(record)))
            throw std::runtime_error(error.empty()?"actual draw guest entry/result copy refused":error);
    };
    auto read=[&](uint64_t address,size_t size,std::vector<uint8_t>* out){
        out->resize(size);
        if(p.runtime.process().copy_readable(address,out->data(),size))return true;
        GraphicsLease lease;
        return lease.valid()&&lease.generation()==generation&&lease.copy(address,out->data(),size);
    };
    auto equal=[&](uint64_t address,const std::vector<uint8_t>& want){
        std::vector<uint8_t> actual;return read(address,want.size(),&actual)&&actual==want;
    };
    auto event_is=[&](uint32_t want){std::vector<uint8_t> bytes;
        return read(record.event_address,4,&bytes)&&bytes[0]==uint8_t(want)&&bytes[1]==uint8_t(want>>8)&&bytes[2]==uint8_t(want>>16)&&bytes[3]==uint8_t(want>>24);};
    auto uniform=[&](bool blue){std::vector<uint8_t> bytes(65536,0x6d);float color[]={0,blue?0.f:1.f,blue?1.f:0.f,1};std::memcpy(bytes.data(),color,sizeof(color));return bytes;};
    auto inputs=[&](){
        std::vector<uint8_t> vertex(0x1000,0x72),index(0x100,0x73);
        const float points[]={-.75f,-.75f,.5f,1,-.75f,.75f,.5f,1,.75f,.75f,.5f,1};
        const uint16_t order[]={2,0,1};std::memcpy(vertex.data()+0x100,points,sizeof(points));std::memcpy(index.data()+0x100-sizeof(order),order,sizeof(order));
        return equal(record.vertex_guard,vertex)&&equal(record.index_guard,index);
    };
    // At64x64 no pixel center meets any edge exactly. Integer clip-space
    // inequalities avoid both a GPU-derived oracle and rounding/tie guesses.
    for(size_t k=0;k<expected.size();++k){expected[k].assign(DM_DRAW_WINDOW_BYTES,uint8_t(0xa9+k));
        for(int y=0;y<DM_DRAW_HEIGHT;++y)for(int x=0;x<DM_DRAW_WIDTH;++x){
            const int nx=2*x+1-DM_DRAW_WIDTH,ny=2*y+1-DM_DRAW_HEIGHT;
            const bool inside=nx<36&&ny<48&&4*nx+3*ny>0;
            const uint8_t color[]={uint8_t(inside?0:255),uint8_t(inside&&k==0?255:0),uint8_t(inside&&k!=0?255:0),255};
            std::memcpy(expected[k].data()+DM_DRAW_PIXEL_OFFSET+y*DM_DRAW_ROW_STRIDE+x*4,color,4);
        }}
    auto pixels=[&](unsigned k){return equal(record.readback_window[k],expected[k])&&equal(record.readback_echo[k],expected[k]);};
    try{
        if(!p.begin(&error)||!p.invoke(p.wait,UINT64_MAX,true,&error))throw std::runtime_error(error);
        check("unchanged-transfer-bootstrap",shape(p)&&data_oracle(p)&&forced(p));
        generation=p.runtime.process().load_generation();runtime_generation=p.environment.state.runtime_generation;epoch=nvn_core_binding_epoch();
        const auto baseline=graphics_platform_stats();
        if(!graphics_platform_publication_barrier(generation,true))throw std::runtime_error("draw publication hold refused");held=true;
        call("graphics_draw_begin",0,false);
        check("authored-pair-real-program-and-submit",record.initialized==3&&record.shaders==1&&record.submits==1&&!record.queue_error&&!p.last.guest_failures);
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
        while(!graphics_platform_publication_barrier_entered(generation)&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
        check("actual-draw-fence-publication-held",graphics_platform_publication_barrier_entered(generation));
        held_fence=graphics_platform_last_fence(generation);retained=graphics_platform_program_stats();
        bool untouched=true;
        for(size_t k=0;k<4;++k)untouched&=equal(record.readback_window[k],std::vector<uint8_t>(DM_DRAW_WINDOW_BYTES,uint8_t(0xa9+k)))&&
            equal(record.readback_echo[k],std::vector<uint8_t>(DM_DRAW_WINDOW_BYTES,uint8_t(0xb9+k)));
        check("no-draw-publication-before-release",untouched&&equal(record.uniform_address,std::vector<uint8_t>(65536,0x6d))&&event_is(0));
        call("graphics_draw_retained");
        std::string shutdown_error;const bool shutdown_refused=!p.runtime.shutdown(&shutdown_error);
        retention=record.retained_finalize&&record.retained_replace&&record.retained_pool&&record.retained_texture&&
            retained.live==1&&retained.retained==1&&shutdown_refused&&p.runtime.process().load_generation()==generation&&!dm_android_kernel_memory_quiescent();
        check("actual-program-pool-image-process-retention",retention);
        if(!graphics_platform_publication_barrier(generation,false))throw std::runtime_error("draw publication release refused");held=false;
        call("graphics_draw_wait",UINT64_MAX);terminal=graphics_platform_program_stats();
        check("draw-fence-wait-and-program-retirement",record.wait_result<2&&!record.queue_error&&terminal.live==1&&!terminal.retained&&graphics_platform_completed_fence()==held_fence);
        arrays=pixels(0)&&equal(record.uniform_address,uniform(false))&&inputs()&&event_is(0xd11);
        check("arrays-full-pixels-and-gpu-padding-canaries",arrays);
        frame.width=DM_DRAW_WIDTH;frame.height=DM_DRAW_HEIGHT;frame.row_stride_bytes=DM_DRAW_WIDTH*4;
        frame.load_generation=generation;frame.runtime_generation=runtime_generation;frame.binding_epoch=epoch;
        frame.rgba8.resize(size_t(DM_DRAW_WIDTH)*DM_DRAW_HEIGHT*4);
        std::vector<uint8_t> checked_echo;
        if(!read(record.readback_echo[0],DM_DRAW_WINDOW_BYTES,&checked_echo)||checked_echo!=expected[0])throw std::runtime_error("owned arrays readback changed after oracle");
        for(size_t y=0;y<DM_DRAW_HEIGHT;++y)std::memcpy(frame.rgba8.data()+y*frame.row_stride_bytes,checked_echo.data()+DM_DRAW_PIXEL_OFFSET+y*DM_DRAW_ROW_STRIDE,frame.row_stride_bytes);
        call("graphics_draw_indexed");call("graphics_draw_wait",UINT64_MAX);
        indexed=record.wait_result<2&&!record.queue_error&&pixels(1)&&pixels(0)&&inputs()&&equal(record.uniform_address,uniform(true))&&event_is(0xd12);
        check("uint16-indexed-full-pixels-and-gpu-padding-canaries",indexed);
        const auto before_rollback=graphics_platform_program_stats();
        if(!graphics_platform_inject_failure(NvnVkEngine::Failure::Pipeline))throw std::runtime_error("draw pipeline failure injection refused");
        call("graphics_draw_pipeline_rollback");call("graphics_draw_wait",UINT64_MAX);
        const auto after_rollback=graphics_platform_program_stats();
        rollback=record.pipeline_rollback&&record.wait_result<2&&!record.queue_error&&pixels(2)&&after_rollback.live==1&&!after_rollback.retained&&
            after_rollback.replaced==before_rollback.replaced&&after_rollback.bytes==before_rollback.bytes;
        check("pipeline-failure-preserves-usable-old-program",rollback);
        const auto before_invalid=graphics_platform_stats();
        call("graphics_draw_late_invalid");
        late=record.late_invalid_error&&graphics_platform_stats().submits==before_invalid.submits&&pixels(0)&&pixels(1)&&pixels(2)&&
            equal(record.readback_window[3],std::vector<uint8_t>(DM_DRAW_WINDOW_BYTES,0xac))&&equal(record.readback_echo[3],std::vector<uint8_t>(DM_DRAW_WINDOW_BYTES,0xbc))&&
            equal(record.uniform_address,uniform(true))&&equal(record.negative_address,std::vector<uint8_t>(0x1000,0xa7))&&event_is(0xd12)&&inputs();
        check("late-invalid-draw-prefix-has-no-effects",late);
        call("graphics_draw_after_invalid");call("graphics_draw_wait",UINT64_MAX);
        late=late&&record.wait_result<2&&!record.queue_error&&pixels(3)&&equal(record.uniform_address,uniform(true))&&event_is(0xd12);
        check("late-invalid-preserves-actual-gpu-target",late);
        data=arrays&&indexed&&rollback&&late&&inputs();
        for(unsigned k=0;k<4;++k)data=data&&pixels(k);
        check("full-readback-guards-and-input-preservation",data);
        call("graphics_draw_end");finalized=graphics_platform_program_stats();
        check("draw-resources-finalize-after-fence",record.programs_finalized&&!finalized.live&&!finalized.retained&&!finalized.bytes);
        identity=graphics_platform_stats();
        check("ordinary-guest-draw-validation",identity.submits==baseline.submits+4&&identity.completed==baseline.completed+4&&
            identity.render_passes>=baseline.render_passes+3&&identity.image_downloads>=baseline.image_downloads+4&&!identity.validation_errors&&!p.runtime.unavailable_host_calls()&&!p.last.guest_failures);
        if(present){std::string present_error;consumer_invoked=true;consumed=present(frame,&present_error);
            checks.emplace_back("live-runtime-owned-image-consumer",consumed);
            if(!consumed)throw std::runtime_error(present_error.empty()?"live image consumer refused":present_error);}
        if(!p.end(false,&error))throw std::runtime_error(error);check("runtime-unload-after-draw-retirement",true);
    }catch(const std::exception& failure){error=failure.what();checks.emplace_back("execution-completed",false);}
    if(held)graphics_platform_publication_barrier(generation,false);
    if(p.opened){std::string cleanup;if(!p.end(true,&cleanup))std::abort();}
    owner(false);bool passed=!checks.empty();for(const auto& c:checks)passed&=c.second;
    ShaderDigest image_digest{};if(passed)module_sha256(frame.rgba8.data(),frame.rgba8.size(),image_digest.data());
    if(passed&&image)*image=std::move(frame);
    std::ostringstream out;out<<"{\"schemaVersion\":1,\"suite\":\"android-authored-draw\",\"status\":\""<<(passed?"PASS":"FAIL")
      <<"\",\"gamePlayable\":false,\"syntheticOnly\":true,\"originalGame\":\"NOT_RUN\",\"sourcekind\":\"AuthoredTranslatorFixture\",\"route\":\"ARM64-guest-shared-NVN-Vulkan-checked-guest-publication\""
      <<",\"dataOraclePassed\":"<<(passed&&data?"true":"false")<<",\"arraysPassed\":"<<(arrays?"true":"false")<<",\"indexedPassed\":"<<(indexed?"true":"false")
      <<",\"pipelineRollbackPassed\":"<<(rollback?"true":"false")<<",\"lateInvalidNoEffects\":"<<(late?"true":"false")<<",\"retentionPassed\":"<<(retention?"true":"false")
      <<",\"imageWidth\":64,\"imageHeight\":64,\"rowStrideBytes\":256,\"topRowFirst\":true,\"imageSource\":\"draw-arrays-green-on-red\",\"imageSha256\":\""<<hex(image_digest.data(),32)
      <<"\",\"liveImageConsumerInvoked\":"<<(consumer_invoked?"true":"false")<<",\"liveImageConsumerPassed\":"<<(consumed?"true":"false")
      <<",\"loadGeneration\":"<<generation<<",\"runtimeGeneration\":"<<runtime_generation<<",\"bindingEpoch\":"<<epoch<<",\"fence\":"<<held_fence
      <<",\"verifiedDataBytes\":"<<(passed?237828:0)<<",\"error\":\""<<escaped(error)<<"\",\"checks\":[";
    for(size_t i=0;i<checks.size();++i){if(i)out<<',';out<<"{\"id\":\""<<checks[i].first<<"\",\"status\":\""<<(checks[i].second?"PASS":"FAIL")<<"\"}";}
    out<<"],\"gpu\":{\"device\":\""<<escaped(identity.device_name)<<"\",\"physicalApi\":"<<identity.api_version<<",\"effectiveApi\":4194304,\"submits\":"<<identity.submits
      <<",\"completed\":"<<identity.completed<<",\"validationErrors\":"<<identity.validation_errors<<"},\"programs\":{\"held\":"<<retained.retained<<",\"afterFence\":"<<terminal.retained
      <<",\"afterFinalize\":"<<finalized.live<<"},\"sdkPackageSha256\":\""<<hex(dm_graphics_package_sha256,32)<<"\",\"unsupported\":[\"textures\",\"original-game-draw\",\"full-product\"]}";
    return out.str();
}
