#include "controller_probes.h"
#include "diagnostic_authority.h"
#include "guest_bootstrap.h"
#include "guest_memory.h"
#include "kernel_runtime.h"
#include "controller_fixtures/generated_controllers.h"
#include "observation_fixtures/generated_observations.h"
#include "../../host/hle_hid_core.h"
#include "../../host/dm_gamepad_core.h"
extern "C" {
#include "../../host/dm_input.h"
int dm_opmode(void);
void dm_set_opmode(int);
}
#include <array>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>

namespace {
using namespace dm_android;
constexpr const char* names[]{
    "_ZN2nn3hid14InitializeNpadEv",
    "_ZN2nn3hid22SetSupportedNpadIdTypeEPKjm",
    "_ZN2nn3hid24SetSupportedNpadStyleSetENS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE",
    "_ZN2nn3hid29SetNpadHandheldActivationModeENS0_26NpadHandheldActivationModeE",
    "_ZN2nn3hid15GetNpadStyleSetERKj",
    "_ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj",
    "_ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj",
    "_ZN2nn3hid20IsVibrationPermittedEv",
    "_ZN2nn3hid25GetVibrationDeviceHandlesEPNS0_21VibrationDeviceHandleEiRKjNS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE",
    "_ZN2nn3hid25InitializeVibrationDeviceERKNS0_21VibrationDeviceHandleE",
    "_ZN2nn3hid18SendVibrationValueERKNS0_21VibrationDeviceHandleERKNS0_14VibrationValueE"};
struct Record {
    uint32_t full_style,handheld_style,vibration_permitted,vibration_count;
    dm_hid_npad_state full,handheld;
    uint64_t vibration_handle,fallback_calls,setup_calls,sdk_init,module_init;
};
static_assert(sizeof(Record)==136 && offsetof(Record,full)==16 &&
              offsetof(Record,handheld)==56 && offsetof(Record,sdk_init)==120,"guest record ABI");
bool fail(std::string* error,const char* message) {if(error)*error=message;return false;}
std::string escaped(const std::string& s) {std::string r;for(unsigned char c:s){if(c=='"'||c=='\\')r+='\\';r+=c<32?' ':c;}return r;}
std::string hex(const uint8_t* b,size_t n) {static constexpr char d[]="0123456789abcdef";std::string r;for(size_t i=0;i<n;++i){r+=d[b[i]>>4];r+=d[b[i]&15];}return r;}
bool packages(std::vector<std::unique_ptr<ModulePackage>>* out,std::string* error) {
    std::unique_ptr<ModulePackage> main,sdk;
    if(!decode_package(dm_observation_main_bytes,dm_observation_main_size,dm_observation_main_package_sha256,&main,error)||
       !decode_package(dm_controller_bytes,dm_controller_size,dm_controller_package_sha256,&sdk,error))return false;
    out->push_back(std::move(main));out->push_back(std::move(sdk));return true;
}
struct Probe {
    HleRuntime runtime;
    GuestEnvironment environment;
    GuestStack stack{256*1024};
    uintptr_t output=0,sample=0;
    unsigned authority_checks=0, denied_registrations=0;
    bool opened=false;
    static bool registration(DmGuestThreadState&,uint64_t* handle,uint64_t* area,void* context,std::string* error) {
        auto& self=*static_cast<Probe*>(context);*handle=self.runtime.register_main();*area=0;
        return *handle || fail(error,"controller main registration failed");
    }
    static bool initialized(Process& process,DmGuestThreadState&,void*,std::string* error) {
        return controller_diagnostic_graph(process,error) &&
            (dm_hid_configured_mode()==DM_HID_DIAGNOSTIC_RAW || fail(error,"controller raw adapter was not selected by exact graph authority"));
    }
    static bool denied_registration(DmGuestThreadState&,uint64_t*,uint64_t*,void* context,std::string*) {
        ++static_cast<Probe*>(context)->denied_registrations;return false;
    }
    bool no_initialization() {
        Record record{};
        return !denied_registrations && runtime.process().copy_readable(output,&record,sizeof(record)) &&
            !record.sdk_init && !record.module_init && !record.setup_calls && !record.fallback_calls;
    }
    bool begin(std::string* error) {
        std::vector<std::unique_ptr<ModulePackage>> prepared;
        if(!stack.valid()||!packages(&prepared,error)||!runtime.load(std::move(prepared),false,nullptr,nullptr,error))return false;
        opened=true;runtime.configure(environment.state);
        if(!runtime.process().symbol("controller_result",&output)||!runtime.process().symbol("controller_sample",&sample))
            return fail(error,"controller public guest symbols missing");
        BootstrapSession session;BootstrapArguments args({"D2R","--controller-sdk-fixture"});BootstrapResult result;
        const BootstrapHooks denied_hooks{denied_registration,initialized,this};
        // These are actual mapped guest sentinels in the first SDK initializer
        // and DT_INIT, observed before the successful bootstrap runs either one.
        if(session.run(runtime.process(),environment,stack,args,denied_hooks,&result,error)||!no_initialization())
            return fail(error,"missing authority reached an initialization side effect");
        ++authority_checks;
        for(size_t index=0;index<2;++index) {
            BootstrapSession altered;
            if(!altered.authorize(runtime.process(),error))return false;
            auto& identity=index?runtime.process().modules()[index]->package->source_sha256:
                                 runtime.process().modules()[index]->package->build_id;
            identity[31]^=1;
            const bool denied=!altered.run(runtime.process(),environment,stack,args,denied_hooks,&result,error)&&no_initialization();
            identity[31]^=1;
            if(!denied)return fail(error,"altered graph reached an initialization side effect");
            ++authority_checks;
        }
        if(!session.authorize(runtime.process(),error)||
           !session.run(runtime.process(),environment,stack,args,{registration,initialized,this},&result,error))return false;
        return result.completed_steps.size()==12 && result.main_result.value==0xc011 && !result.main_result.exited;
    }
    bool read(Record* record,std::string* error) {
        const uint64_t args[]{0,0x20};GuestCallResult value;
        if(!stack.call(environment.state,sample,args,2,&value,error)||value.exited||value.value!=0xc011)
            return fail(error,"controller actual guest sample failed");
        // The guest wrote its complete result into its owned mapped RW section.
        const auto& module=*runtime.process().modules()[1];
        const uintptr_t base=reinterpret_cast<uintptr_t>(module.mapping.base);
        if(output<base+module.package->data_offset || output+sizeof(*record)>
           base+module.package->data_offset+module.package->data_bytes ||
           !dm_android_guest_copy(output,record,sizeof(*record)))return fail(error,"controller checked result copy failed");
        return true;
    }
    bool end(std::string* error) {if(!opened)return true;if(!runtime.shutdown(error))return false;opened=false;return true;}
    ~Probe(){if(opened){std::string error;if(!end(&error))std::abort();}}
};
void state_json(std::ostream& out,const dm_hid_npad_state& s) {
    out<<"{\"sampling\":"<<s.sampling<<",\"buttons\":"<<s.buttons<<",\"axes\":["<<s.lx<<','<<s.ly<<','<<s.rx<<','<<s.ry
       <<"],\"attributes\":"<<s.attributes<<",\"padding\":"<<s._pad<<'}';
}
bool shape(const Record& r) {
    const bool handheld=dm_opmode()==0;
    return r.full_style==(handheld?0u:1u) && r.handheld_style==(handheld?2u:0u) &&
        !r.vibration_permitted && !r.vibration_count && !r.vibration_handle && !r.fallback_calls &&
        r.setup_calls==1 && r.sdk_init==1 && r.module_init==1 &&
        r.full.sampling>0 && r.handheld.sampling>r.full.sampling &&
        r.full.attributes==(handheld?0u:1u) && r.handheld.attributes==(handheld?1u:0u) &&
        !r.full._pad && !r.handheld._pad;
}
std::string report(Probe& probe,const Record& r,bool passed,const char* kind,const std::string& detail) {
    std::ostringstream out;
    out<<"{\"schemaVersion\":1,\"suite\":\"android-controller-sdk\",\"kind\":\""<<kind<<"\",\"status\":\""<<(passed?"PASS":"FAIL")
       <<"\",\"gamePlayable\":false,\"originalGameBoot\":\"NOT_RUN\",\"physicalControllerVerified\":false,\"adapter\":{\"mode\":\""
       <<(dm_hid_configured_mode()==DM_HID_DIAGNOSTIC_RAW?"DIAGNOSTIC_RAW":"UNAVAILABLE")<<"\",\"identity\":\""<<escaped(dm_hid_adapter_identity()?dm_hid_adapter_identity():"")
       <<"\",\"productComplete\":"<<(dm_hid_product_complete()?"true":"false")<<"},\"operationMode\":"<<dm_opmode()<<",\"fullStyle\":"<<r.full_style
       <<",\"handheldStyle\":"<<r.handheld_style<<",\"full\":";state_json(out,r.full);out<<",\"handheld\":";state_json(out,r.handheld);
    out<<",\"vibration\":{\"permitted\":"<<r.vibration_permitted<<",\"count\":"<<r.vibration_count<<",\"handle\":"<<r.vibration_handle
       <<"},\"sdkFallbackCalls\":"<<r.fallback_calls<<",\"setupCalls\":"<<r.setup_calls<<",\"sdkInitializers\":"<<r.sdk_init
       <<",\"moduleInitializers\":"<<r.module_init<<",\"authorityChecks\":"<<probe.authority_checks
       <<",\"deniedRegistrations\":"<<probe.denied_registrations<<",\"loadGeneration\":"<<probe.runtime.process().load_generation()<<",\"forceHits\":[";
    for(size_t i=0;i<std::size(names);++i){if(i)out<<',';out<<"{\"name\":\""<<names[i]<<"\",\"hits\":"<<probe.runtime.registry().force_hits(names[i])<<'}';}
    out<<"],\"modules\":[";
    for(size_t i=0;i<probe.runtime.process().modules().size();++i){if(i)out<<',';const auto& p=*probe.runtime.process().modules()[i]->package;
        out<<"{\"name\":\""<<p.name<<"\",\"profileClass\":"<<p.profile_class<<",\"buildId\":\""<<hex(p.build_id.data(),32)
           <<"\",\"sourceSha256\":\""<<hex(p.source_sha256.data(),32)<<"\",\"packageSha256\":\""
           <<hex(i?dm_controller_package_sha256:dm_observation_main_package_sha256,32)<<"\"}";}
    out<<"],\"checks\":[{\"id\":\"actual-guest-npad\",\"status\":\""<<(passed?"PASS":"FAIL")<<"\",\"detail\":\""<<escaped(detail)
       <<"\"}],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return out.str();
}
bool forces(Probe& p){for(const char* name:names)if(!p.runtime.registry().force_hits(name))return false;return true;}
std::mutex persistent_mutex;
std::unique_ptr<Probe> persistent;
uint64_t next_handle=0,current_handle=0;
} // namespace

bool dm_android_controller_begin(uint64_t* handle,std::string* error) {
    std::lock_guard<std::mutex> lock(persistent_mutex);if(error)error->clear();
    if(!handle||persistent)return fail(error,"controller diagnostic already retained or missing handle output");
    auto candidate=std::make_unique<Probe>();if(!candidate->begin(error))return false;
    current_handle=++next_handle;*handle=current_handle;persistent=std::move(candidate);return true;
}
bool dm_android_controller_poll(uint64_t handle,std::string* output,std::string* error) {
    std::lock_guard<std::mutex> lock(persistent_mutex);if(error)error->clear();
    if(!output||!persistent||!handle||handle!=current_handle)return fail(error,"stale controller diagnostic handle");
    Record record{};if(!persistent->read(&record,error))return false;
    const bool passed=shape(record)&&forces(*persistent)&&!dm_hid_product_complete();
    *output=report(*persistent,record,passed,"persistent-poll","Actual ARM64 SDK guest calls all 11 forced HID exports; each poll samples current producer input; diagnostic raw only");
    return passed;
}
bool dm_android_controller_end(uint64_t handle,std::string* error) {
    std::lock_guard<std::mutex> lock(persistent_mutex);if(error)error->clear();
    if(!persistent||!handle||handle!=current_handle)return fail(error,"stale controller diagnostic handle");
    if(!persistent->end(error))return false;persistent.reset();current_handle=0;return true;
}
std::string dm_android_run_controller_probes() {
    std::lock_guard<std::mutex> lock(persistent_mutex);
    std::string error;if(persistent)return "{\"schemaVersion\":1,\"suite\":\"android-controller-sdk\",\"status\":\"FAIL\",\"error\":\"persistent controller owner active\",\"gamePlayable\":false}";
    Probe probe;Record first{},tap{},neutral{},handheld{};
    if(!probe.begin(&error))return "{\"schemaVersion\":1,\"suite\":\"android-controller-sdk\",\"status\":\"FAIL\",\"error\":\""+escaped(error)+"\",\"gamePlayable\":false}";
    const int original_mode=dm_opmode();dm_set_opmode(1);dm_hid_reset_inputs();
    bool passed=probe.read(&first,&error)&&shape(first)&&forces(probe);
    dm_pad_set(DM_BTN_A,0,0,0,0);dm_pad_set(0,0,0,0,0);
    passed=probe.read(&tap,&error)&&passed&&tap.full.buttons==DM_BTN_A;
    passed=probe.read(&neutral,&error)&&passed&&!neutral.full.buttons;
    dm_set_opmode(0);dm_pad_set(DM_BTN_B,12000,-13000,14000,-15000);
    passed=probe.read(&handheld,&error)&&passed&&shape(handheld)&&!handheld.full.buttons&&
        handheld.handheld.buttons==DM_BTN_B&&handheld.handheld.lx==12000&&handheld.handheld.ly==-13000&&
        handheld.handheld.rx==14000&&handheld.handheld.ry==-15000;
    dm_hid_reset_inputs();dm_set_opmode(original_mode);
    Record final{};passed=probe.read(&final,&error)&&passed&&shape(final)&&!dm_hid_product_complete();
    const std::string result=report(probe,final,passed,"suite","Real bootstrap SDK/module sentinels each once; 11 forced exports defeat defined SDK conflicts; short tap once; docked/handheld style and exact axes; vibration original no-output");
    if(!probe.end(&error))return "{\"schemaVersion\":1,\"suite\":\"android-controller-sdk\",\"status\":\"FAIL\",\"error\":\""+escaped(error)+"\",\"gamePlayable\":false}";
    return result;
}
