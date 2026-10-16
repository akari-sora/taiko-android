#include "diagnostic_authority.h"
#include "module_fixtures/generated_modules.h"
#include "observation_fixtures/generated_observations.h"
#include "controller_fixtures/generated_controllers.h"
#if !defined(DM_TARGET_TAIKO) || !DM_TARGET_TAIKO
#include "graphics_fixtures/generated_graphics.h"
#endif
#include <cstring>
#include <initializer_list>

namespace dm_android {
namespace {
bool fail(std::string* error, const char* message) { if(error) *error=message; return false; }
struct Blob { const uint8_t* bytes; size_t size; const uint8_t* digest; };
template<class T, class Equal>
bool equal_vector(const std::vector<T>& a,const std::vector<T>& b,Equal equal) {
    if(a.size()!=b.size()) return false;
    for(size_t i=0;i<a.size();++i) if(!equal(a[i],b[i])) return false;
    return true;
}
// Compare semantic fields, never padding or self-asserted hashes alone. The
// expected package is freshly decoded from the independent compiled byte pin.
bool equal_package(const ModulePackage& a,const ModulePackage& b) {
    if(a.name!=b.name || a.build_id!=b.build_id || a.source_sha256!=b.source_sha256 ||
       a.image_sha256!=b.image_sha256 || a.original_size!=b.original_size ||
       a.symbol_count!=b.symbol_count || a.string_bytes!=b.string_bytes ||
       a.data_offset!=b.data_offset || a.data_bytes!=b.data_bytes || a.bss_bytes!=b.bss_bytes ||
       a.bytes!=b.bytes || a.wire_version!=b.wire_version || a.profile_class!=b.profile_class ||
       a.profile_digest!=b.profile_digest || a.profile!=b.profile) return false;
    return equal_vector(a.fixups,b.fixups,[](auto& x,auto& y){return x.offset==y.offset&&x.helper==y.helper;}) &&
      equal_vector(a.gates,b.gates,[](auto& x,auto& y){return x.return_offset==y.return_offset&&x.kind==y.kind&&x.argument==y.argument;}) &&
      equal_vector(a.gate_provenance,b.gate_provenance,[](auto& x,auto& y){return x.return_offset==y.return_offset&&x.original_offset==y.original_offset&&x.kind==y.kind&&x.argument==y.argument&&x.original_word==y.original_word&&x.flags==y.flags;}) &&
      equal_vector(a.parameters,b.parameters,[](auto& x,auto& y){return x.a==y.a&&x.b==y.b&&x.word_a==y.word_a&&x.word_b==y.word_b&&x.destination==y.destination&&x.slot==y.slot&&x.flags==y.flags;}) &&
      equal_vector(a.sites,b.sites,[](auto& x,auto& y){return x.original_offset==y.original_offset&&x.trampoline_offset==y.trampoline_offset;}) &&
      equal_vector(a.segments,b.segments,[](auto& x,auto& y){return x.offset==y.offset&&x.size==y.size&&x.flags==y.flags;}) &&
      a.image.abi==DM_ANDROID_GUEST_ABI && a.image.bytes==a.bytes.data() && a.image.size==a.bytes.size() &&
      a.image.entry_offset==b.image.entry_offset && a.image.fixups==a.fixups.data() &&
      a.image.fixup_count==a.fixups.size() && a.image.gates==a.gates.data() &&
      a.image.gate_count==a.gates.size() && a.image.segments==a.segments.data() &&
      a.image.segment_count==a.segments.size();
}
bool graph(const Process& process,std::initializer_list<Blob> expected) {
    if(!process.load_generation() || process.modules().size()!=expected.size()) return false;
    size_t index=0;
    for(const auto& blob:expected) {
        std::unique_ptr<ModulePackage> canonical; std::string error;
        if(!decode_package(blob.bytes,blob.size,blob.digest,&canonical,&error)) return false;
        const auto& module=process.modules()[index];
        if(!module || !module->package || !module->mapping.sealed || !module->mapping.base ||
           !process.loaded_package_matches(index,*canonical) ||
           !equal_package(*module->package,*canonical)) return false;
        ++index;
    }
    return true;
}
bool bootstrap_graph(const Process& process) {
    return graph(process,{{dm_module_main_bytes,dm_module_main_size,dm_module_main_package_sha256},
                          {dm_module_sdk_bytes,dm_module_sdk_size,dm_module_sdk_package_sha256},
                          {dm_module_extra_bytes,dm_module_extra_size,dm_module_extra_package_sha256}}) ||
           controller_diagnostic_graph(process,nullptr) || graphics_diagnostic_graph(process,nullptr);
}
constexpr const char* missing = "startup capability refused: sampler.receipt_prepare, sampler.ui_taps, sampler.frontend, sampler.textinput, sampler.update, sampler.actions, sampler.world, sampler.ui_mouse, sampler.aim_cone, sampler.script_keys, sampler.auto_release, sampler.auto_buttons, sampler.alone_take, sampler.input_gate, sampler.runeword_filter, sampler.page_filter, sampler.swap_filter, sampler.right_test, sampler.cursor, sampler.receipt, producer.mode, producer.navigation, producer.free_portal, producer.portal_request";
}
bool controller_diagnostic_graph(const Process& process,std::string* error) {
    if(error) error->clear();
    if(graph(process,{{dm_observation_main_bytes,dm_observation_main_size,dm_observation_main_package_sha256},
                      {dm_controller_bytes,dm_controller_size,dm_controller_package_sha256}})) return true;
    return fail(error,"controller diagnostic graph identity mismatch");
}
bool graphics_diagnostic_graph(const Process& process,std::string* error) {
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
    (void)process;
    return fail(error,"legacy graphics diagnostic carrier unavailable for Taiko: contains D2R original compute records");
#else
    if(error) error->clear();
    if(graph(process,{{dm_observation_main_bytes,dm_observation_main_size,dm_observation_main_package_sha256},
                      {dm_graphics_bytes,dm_graphics_size,dm_graphics_package_sha256}})) return true;
    return fail(error,"graphics diagnostic graph identity mismatch");
#endif
}
bool DiagnosticAuthority::bind(const Process& process,const BootstrapSession* session,std::string* error) {
    if(error) error->clear();
    if(process_ || !session) return fail(error,"bootstrap authority already bound or missing session");
    if(!bootstrap_graph(process)) return fail(error,missing);
    process_=&process; session_=session; generation_=process.load_generation(); return true;
}
bool DiagnosticAuthority::validate(const Process& process,const BootstrapSession* session,std::string* error) const {
    if(!process_ || process_!=&process || session_!=session || generation_!=process.load_generation())
        return fail(error,"missing, foreign or stale bootstrap authority");
    if(!bootstrap_graph(process)) return fail(error,missing);
    return true;
}
} // namespace dm_android
