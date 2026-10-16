#include "taiko_bringup.h"
#include <cstring>

namespace dm_android {
const TaikoBuildPins* compiled_taiko_bringup_pins() __attribute__((weak));
namespace {
bool fail(std::string* error,const char* message){if(error)*error=message;return false;}
bool named(const char* a,const char* b){return a && b && !std::strcmp(a,b);}
bool nonzero(const std::array<uint8_t,32>& value){for(auto byte:value)if(byte)return true;return false;}
bool digest(const std::array<uint8_t,32>& actual,const char* expected){
    static constexpr char hex[]="0123456789abcdef";
    for(size_t i=0;i<actual.size();++i)
        if(expected[2*i]!=hex[actual[i]>>4] || expected[2*i+1]!=hex[actual[i]&15])return false;
    return expected[64]=='\0';
}
struct SourceIdentity {const char* name;uint64_t bytes;const char* sha256;const char* build_id;};
constexpr SourceIdentity rtld_identity{"rtld",7132,
    "8e08c8cf2e4d6b39d69643af10ce765d39c06860878224c68f8cafc45a2636aa",
    "567cdd4c5251494c5cd70822e3ccc740c190c2b2000000000000000000000000"};
constexpr SourceIdentity identities[]{
    {"main",38127530,"f1313fe0d6cd4a024e53d8a283434448bacea453b02f37b75b18bfe281d0fcff",
     "4541b79257635ce79105b3ba59e4808500000000000000000000000000000000"},
    {"subsdk0",3385425,"f38d30e8241ee208cbf3090f44613e328af517ad199eb5985619416bb2cbcb55",
     "a8cb97803f7f442a3b6cce1c7cd4ee4a78b7def3000000000000000000000000"},
    {"sdk",5989236,"2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28",
     "357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000"}};
bool source_matches(const TaikoSourcePin& pin,const SourceIdentity& expected){
    return named(pin.name,expected.name) && pin.source_bytes==expected.bytes &&
        digest(pin.source_sha256,expected.sha256) && digest(pin.build_id,expected.build_id) && nonzero(pin.decoded_sha256);
}
bool valid_pins(const TaikoBuildPins* pins){
    if(!pins || pins->schema!=1 || !named(pins->build,"Taiko/01002460135A4000/Stock-v1") ||
       !named(pins->program_id,"01002460135A4000") ||
       !digest(pins->npdm_sha256,"afd3aade95cbcc607759eb677b67082193719a701a5b0cc8ed78ac33b5c65150") ||
       !source_matches(pins->rtld,rtld_identity) || !pins->sources || pins->source_count!=3 ||
       !pins->modules || pins->module_count!=3 || !nonzero(pins->source_audit_sha256) ||
       !nonzero(pins->import_manifest_sha256))return false;
    for(size_t i=0;i<3;++i){
        const auto& source=pins->sources[i];const auto& module=pins->modules[i];const auto& audit=module.callback_audit;
        if(!source_matches(source,identities[i]) || !named(module.name,identities[i].name) ||
           !module.package_bytes || !module.image_bytes || !nonzero(module.package_sha256) ||
           !nonzero(module.image_sha256) || audit.version!=1 || audit.package_sha256!=module.package_sha256 ||
           audit.source_sha256!=source.source_sha256 || audit.root_kind!=CallbackRootKind::DefinedSttFunc ||
           audit.indirect_policy!=CallbackIndirectPolicy::GuardedHost || !audit.roots || !audit.root_count ||
           audit.root_count>(1u<<20))return false;
        for(size_t root=1;root<audit.root_count;++root)
            if(audit.roots[root-1]>=audit.roots[root])return false;
    }
    return true;
}
}
const TaikoBuildPins* taiko_bringup_build(){
    const auto* pins=compiled_taiko_bringup_pins?compiled_taiko_bringup_pins():nullptr;
    return valid_pins(pins)?pins:nullptr;
}
bool taiko_bringup_graph(const Process& process,std::string* error){
    if(error)error->clear();
    const auto* pins=taiko_bringup_build();
    if(!pins)return fail(error,"Taiko stock startup has no complete trusted compiled build pins");
    if(!process.load_generation() || process.modules().size()!=3)
        return fail(error,"Taiko stock startup requires main/subsdk0/sdk in pinned loader order");
    for(size_t i=0;i<3;++i){
        if(!process.modules()[i] || !process.modules()[i]->package)
            return fail(error,"Taiko stock startup mapped module is missing");
        const auto& package=*process.modules()[i]->package;const auto& pin=pins->modules[i];
        const auto& source=pins->sources[i];LoadedPackageAuthority frozen{};
        if(!process.loaded_package_authority(i,&frozen) || !frozen.checked_stack || !frozen.callback_audited ||
           frozen.capsule_sha256!=pin.package_sha256 || frozen.capsule_bytes!=pin.package_bytes ||
           package.name!=pin.name || package.wire_version!=2 || package.profile_class || package.profile ||
           package.build_id!=source.build_id || package.source_sha256!=source.source_sha256 ||
           package.image_sha256!=pin.image_sha256 || package.bytes.size()!=pin.image_bytes ||
           !package.parameters.empty() || !process.loaded_callback_roots_match(i,pin.callback_audit) ||
           nonzero(package.profile_digest))return fail(error,"Taiko stock capsule/source/stack/callback identity mismatch");
        for(const auto& gate:package.gates)
            if(gate.kind==DM_GUEST_OBSERVATION || (gate.kind==DM_GUEST_SVC && gate.argument>=0x80))
                return fail(error,"Taiko stock startup rejects observation profiles and private CUTS");
    }
    return true;
}
const std::array<TaikoStartupStep,10>& taiko_startup_plan(){
    // Pinned sdk Start 0x2dbb80..0x2dbbf0. rtld callback A sets only its
    // exception-ready flag; host semantics replace that store while rtld is
    // absent. Callback B traverses loader nodes backwards and calls DT_INIT.
    static constexpr std::array<TaikoStartupStep,10> plan{{
        {TaikoStartupKind::Guest,"_init_libc0",2,0x5691f0},
        {TaikoStartupKind::Guest,"nnosInitialize",2,0x37f160},
        {TaikoStartupKind::HostLoaderReady,"taiko_host_loader_ready",0,0},
        {TaikoStartupKind::Guest,"_init_libc1",2,0x5691f8},
        {TaikoStartupKind::Guest,"nninitInitializeSdkModule",2,0x2dbaf0},
        {TaikoStartupKind::Guest,"nninitStartup",0,0x300dc0},
        {TaikoStartupKind::Guest,"_init_libc2",2,0x569210},
        {TaikoStartupKind::ReverseModuleInitializers,"taiko_reverse_module_initializers",0,0},
        {TaikoStartupKind::PlatformAttachment,"taiko_platform_attachment",0,0},
        {TaikoStartupKind::Guest,"nnMain",0,0x300e60}}};
    return plan;
}
bool TaikoBringupAuthority::bind(const Process& process,const BootstrapSession* session,std::string* error){
    if(error)error->clear();
    if(process_ || !session)return fail(error,"Taiko stock authority already bound or missing session");
    if(!taiko_bringup_graph(process,error))return false;
    process_=&process;session_=session;generation_=process.load_generation();return true;
}
bool TaikoBringupAuthority::validate(const Process& process,const BootstrapSession* session,std::string* error) const{
    if(process_!=&process || session_!=session || !generation_ || generation_!=process.load_generation())
        return fail(error,"missing, foreign or stale Taiko stock authority");
    return taiko_bringup_graph(process,error);
}
}
