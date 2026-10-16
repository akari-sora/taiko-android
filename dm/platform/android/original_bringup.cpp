#include "original_bringup.h"
#include <cstring>

namespace dm_android {
// Only a trusted generated translation unit defines this provider in production.
// Until a successful original import exists, its absence refuses original entry.
const OriginalBuildPins* compiled_original_bringup_pins() __attribute__((weak));
namespace {
bool fail(std::string* error,const char* text){if(error)*error=text;return false;}
bool nonzero(const std::array<uint8_t,32>& value){for(auto b:value)if(b)return true;return false;}
bool named(const char* a,const char* b){return a && b && !std::strcmp(a,b);}
bool valid_pins(const OriginalBuildPins* p){
    if(!p || p->schema!=1 || !named(p->build,"D2R/3.3.94012/OriginalBringup-stock-v1") ||
       !p->sources || p->source_count!=3 || !p->modules || p->module_count!=3 ||
       p->original_word_checks!=41 || !nonzero(p->source_audit_sha256) || !nonzero(p->import_manifest_sha256))return false;
    const char* names[]={"main","sdk","subsdk0"};
    for(size_t i=0;i<3;++i) {
        const auto& s=p->sources[i];
        if(!named(s.name,names[i]) || !s.source_bytes || !nonzero(s.source_sha256) ||
           !nonzero(s.decoded_sha256) || !nonzero(s.build_id))return false;
    }
    for(size_t i=0;i<p->module_count;++i) {
        const auto& m=p->modules[i];const auto& a=m.callback_audit;
        if(!named(m.name,names[i]) || !m.package_bytes || !m.image_bytes || !nonzero(m.package_sha256) ||
           !nonzero(m.image_sha256) || a.version!=1 || a.package_sha256!=m.package_sha256 ||
           a.source_sha256!=p->sources[i].source_sha256 || a.root_kind!=CallbackRootKind::DefinedSttFunc ||
           a.indirect_policy!=CallbackIndirectPolicy::GuardedHost || !a.roots || !a.root_count || a.root_count>(1u<<20))return false;
    }
    return true;
}
}
const OriginalBuildPins* original_bringup_build(){
    const auto* pins=compiled_original_bringup_pins?compiled_original_bringup_pins():nullptr;
    return valid_pins(pins)?pins:nullptr;
}
bool original_bringup_graph(const Process& process,std::string* error){
    if(error)error->clear();
    const auto* pins=original_bringup_build();
    if(!pins)return fail(error,"original bringup has no complete trusted compiled build pins");
    if(!process.load_generation() || process.modules().size()!=pins->module_count)
        return fail(error,"original bringup module order/count differs from compiled build");
    for(size_t i=0;i<pins->module_count;++i){
        if(!process.modules()[i] || !process.modules()[i]->package)
            return fail(error,"original bringup mapped module descriptor is missing");
        const auto& m=*process.modules()[i];const auto& p=*m.package;
        const auto& pin=pins->modules[i];const auto& source=pins->sources[i];
        LoadedPackageAuthority facts{};
        if(!process.loaded_package_authority(i,&facts) || !facts.checked_stack || !facts.callback_audited ||
           facts.capsule_sha256!=pin.package_sha256 || facts.capsule_bytes!=pin.package_bytes ||
           p.name!=pin.name || p.wire_version!=2 || p.profile_class || p.profile ||
           p.build_id!=source.build_id || p.source_sha256!=source.source_sha256 ||
           p.image_sha256!=pin.image_sha256 || p.bytes.size()!=pin.image_bytes ||
           !p.parameters.empty())return fail(error,"original bringup frozen capsule/source/stack/callback identity mismatch");
        for(const auto& g:p.gates)
            if(g.kind==DM_GUEST_OBSERVATION || (g.kind==DM_GUEST_SVC && g.argument>=0x80))
                return fail(error,"stock original bringup cannot carry product OBS or private CUTS");
    }
    return true;
}
bool OriginalBringupAuthority::bind(const Process& process,const BootstrapSession* session,std::string* error){
    if(error)error->clear();
    if(process_ || !session)return fail(error,"original bringup authority already bound or missing session");
    if(!original_bringup_graph(process,error))return false;
    process_=&process;session_=session;generation_=process.load_generation();return true;
}
bool OriginalBringupAuthority::validate(const Process& process,const BootstrapSession* session,std::string* error) const{
    if(process_!=&process || session_!=session || !generation_ || generation_!=process.load_generation())
        return fail(error,"missing, foreign or stale original bringup authority");
    return original_bringup_graph(process,error);
}
}
