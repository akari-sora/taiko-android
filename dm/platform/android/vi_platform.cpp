#include "vi_platform.h"
#include "kernel_runtime.h"
#include "kernel_memory_android.h"
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include "oe_platform.h"
extern "C" {
#include "../../host/hle.h"
}
#include <cstring>
#include <limits>
#include <mutex>

namespace dm_android {
namespace {
std::mutex metadata_mutex;
ViPlatformSnapshot state;
const Process* bound_process=nullptr;
uint64_t binding_serial=0;
// Opaque identities are values, never dereferenceable host object addresses.
// Runtime retirement never recycles one. Refuse before overflow.
uintptr_t token_serial=0;
constexpr uintptr_t max_token_serial=std::numeric_limits<uintptr_t>::max()>>2;
enum class Kind:uintptr_t {Display=1,Layer=2,NativeWindow=3};
bool same(SurfaceTicket a,SurfaceTicket b){return a.owner==b.owner&&a.epoch==b.epoch;}
struct AvailableSurface {
    SurfaceTicket ticket;
    uint64_t oe_epoch;
    uint32_t width,height;
};
bool available_surface(HleRuntime& runtime,AvailableSurface* out) {
    // RuntimeReadLease pins ownership without retaining runtime_lifecycle.
    // Cross-check independent platform observations; these queries never own a
    // native window. Surface epochs are monotonic across pause/replacement.
    const auto ticket=graphics_surface_ticket();
    const auto surface=graphics_surface_snapshot();
    const auto oe=oe_platform_receipt();
    const auto latest=graphics_surface_ticket();
    if(!ticket.owner||!ticket.epoch||!same(ticket,latest)||!surface.available||
       surface.owner!=ticket.owner||surface.epoch!=ticket.epoch||!surface.width||!surface.height||
       !oe.open||!oe.epoch||oe.epoch!=runtime.oe_epoch()||
       oe.platform.generation!=ticket.owner||!oe.platform.attached||!oe.platform.resumed||
       oe.platform.stopped||!oe.platform.window_available||
       oe.platform.native_width!=surface.width||oe.platform.native_height!=surface.height)return false;
    // Focus is not display existence: a resumed Activity can temporarily lose
    // focus while retaining its window. Foreground SDK entry is gated by the
    // bootstrap owner independently of this display metadata query.
    *out={ticket,oe.epoch,surface.width,surface.height};return true;
}
bool bound(HleRuntime& runtime) {
    return bound_process==&runtime.process()&&state.generation&&state.binding&&
           state.generation==runtime.process().load_generation();
}
bool current(HleRuntime& runtime,const AvailableSurface& surface) {
    return bound(runtime)&&state.initialized&&state.oe_epoch==surface.oe_epoch;
}
// Process spans are immutable under RuntimeReadLease; mutable kernel mappings
// are pinned through the write. Only the current invocation's owned GuestStack
// has the direct stack exception; no pthread-stack/TLS/host-query fallback.
class OutputSlot {
public:
    explicit OutputSlot(HleRuntime& runtime,void** destination):destination_(destination) {
        const auto address=reinterpret_cast<uintptr_t>(destination);
        if(!address||sizeof(void*)>UINTPTR_MAX-address)return;
        if(runtime.process().mapped_range(address,sizeof(void*),DM_GUEST_WRITE)){valid_=true;return;}
        pin_=dm_android_kernel_gpu_pin(address,sizeof(void*),DM_GUEST_WRITE);
        if(pin_){valid_=true;return;}
        const auto* guest=dm_android_peek_guest_state();uintptr_t bottom=0;size_t length=0;
        valid_=guest&&guest->user_data==&runtime&&guest->runtime_generation==runtime.process().load_generation()&&
            active_guest_stack_owned_bounds(address,&bottom,&length)&&address>=bottom&&
            address-bottom<=length&&sizeof(void*)<=length-(address-bottom);
    }
    ~OutputSlot(){if(pin_)dm_android_kernel_gpu_unpin(pin_);}
    OutputSlot(const OutputSlot&)=delete;
    OutputSlot& operator=(const OutputSlot&)=delete;
    bool valid()const{return valid_;}
    void write(uintptr_t identity){void* token=reinterpret_cast<void*>(identity);std::memcpy(destination_,&token,sizeof(token));}
private:
    void** destination_;uint64_t pin_=0;bool valid_=false;
};
uintptr_t issue(Kind kind) {
    if(token_serial==max_token_serial)return 0;
    return (++token_serial<<2)|static_cast<uintptr_t>(kind);
}
void initialize() {
    RuntimeReadLease lease;if(!lease.runtime())return;
    auto& runtime=*lease.runtime();AvailableSurface surface{};
    // The SDK signature has no Result. Failure leaves initialized false; every
    // Result operation below then refuses explicitly, with no output mutation.
    if(!available_surface(runtime,&surface))return;
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if(!bound(runtime)||current(runtime,surface))return;
    state.oe_epoch=surface.oe_epoch;state.surface=surface.ticket;
    state.initialized=true;
}
Result handle(void** destination,const void* parent,Kind kind) {
    RuntimeReadLease lease;if(!lease.runtime())return RES_FAIL;
    auto& runtime=*lease.runtime();OutputSlot output(runtime,destination);
    if(!output.valid())return RES_FAIL;
    AvailableSurface surface{};if(!available_surface(runtime,&surface))return RES_FAIL;
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if(!current(runtime,surface))return RES_FAIL;
    const auto identity=reinterpret_cast<uintptr_t>(parent);
    uintptr_t* slot=nullptr;
    if(kind==Kind::Display)slot=&state.display;
    else if(kind==Kind::Layer) {
        // CreateLayer creates a resource, unlike the repeatable display/native
        // queries. The bounded service owns one layer per runtime binding.
        if(!identity||identity!=state.display||state.layer)return RES_FAIL;
        slot=&state.layer;
    } else {
        if(!identity||identity!=state.layer)return RES_FAIL;
        slot=&state.native_window;
    }
    // All ownership, parent and Surface checks precede either state or output.
    if(!*slot){const auto candidate=issue(kind);if(!candidate)return RES_FAIL;*slot=candidate;}
    state.surface=surface.ticket;
    output.write(*slot);return RES_OK;
}
}
bool vi_platform_bind(const Process& process,std::string* error,uint64_t* owned_generation) {
    if(owned_generation)*owned_generation=0;
    if(!graphics_diagnostic_graph(process,nullptr)&&!original_bringup_graph(process,nullptr))return true;
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if(bound_process||!process.load_generation()||binding_serial==UINT64_MAX) {
        if(error)*error="VI platform binding is occupied or its identity is exhausted";
        return false;
    }
    state={};state.generation=process.load_generation();state.binding=++binding_serial;
    bound_process=&process;
    if(owned_generation)*owned_generation=state.generation;
    return true;
}
bool vi_platform_reset(uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if(!bound_process)return true;
    if(!generation||state.generation!=generation)return false;
    state={};bound_process=nullptr;return true;
}
ViPlatformSnapshot vi_platform_snapshot(){std::lock_guard<std::mutex> lock(metadata_mutex);return state;}
bool vi_platform_native_window(const void* token,uint64_t generation,ViNativeWindow* out) {
    if(!token||!generation||!out)return false;
    RuntimeReadLease lease;if(!lease.runtime())return false;
    auto& runtime=*lease.runtime();if(runtime.process().load_generation()!=generation)return false;
    AvailableSurface surface{};if(!available_surface(runtime,&surface))return false;
    std::lock_guard<std::mutex> lock(metadata_mutex);
    if(!current(runtime,surface)||reinterpret_cast<uintptr_t>(token)!=state.native_window)return false;
    *out={generation,state.binding,surface.ticket,surface.width,surface.height};return true;
}
}

HLE_FORCE("_ZN2nn2vi10InitializeEv", "Android VI context from the live runtime, OE and real Surface epoch", void, h_vi_Init, void) {
    dm_android::initialize();
}
HLE_FORCE("_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE", "Android VI runtime-owned opaque default display", Result, h_vi_OpenDisp, void** out) {
    return dm_android::handle(out,nullptr,dm_android::Kind::Display);
}
HLE_FORCE("_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE", "Android VI layer owned by the exact live display; current Surface checked", Result, h_vi_CreateLayer, void** out, void* display) {
    return dm_android::handle(out,display,dm_android::Kind::Layer);
}
HLE_FORCE("_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE", "Android VI checked native token; the presenter retains native window ownership", Result, h_vi_GetNative, void** out, void* layer) {
    return dm_android::handle(out,layer,dm_android::Kind::NativeWindow);
}
