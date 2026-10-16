#include "shader_draw_catalog.h"
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
namespace dm_android {
namespace {
ShaderDigest digest(const char* text){ShaderDigest out{};auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};for(size_t i=0;i<32;++i)out[i]=uint8_t(nibble(text[i*2])*16+nibble(text[i*2+1]));return out;}
}
// These authored diagnostic identities grant no original game shader authority.
const std::array<ShaderIndexEntry,2>& compiled_draw_catalog(){
    static const std::array<ShaderIndexEntry,2> value={{
#include "graphics_fixtures/draw_shaders/catalog_entries.inc"
    }};return value;
}
const std::array<ShaderIndexEntry,2>& compiled_sampled_draw_catalog(){
    static const std::array<ShaderIndexEntry,2> value={{
#include "graphics_fixtures/draw_texture_shaders/catalog_entries.inc"
    }};return value;
}
const std::array<ShaderIndexEntry,kCompiledOriginalDrawCount>& compiled_original_draw_catalog(){
    static const std::array<ShaderIndexEntry,kCompiledOriginalDrawCount> empty{};return empty;
}
const std::array<ShaderIndexEntry,kCompiledOriginalDrawCount>& compiled_original_sampled_draw_catalog(){
    return compiled_original_draw_catalog();
}
bool create_draw_source_catalog(const Process&,DrawSourceCatalog* out,std::string* error){
    if(out)*out={};if(error)*error="Taiko draw shaders are unsupported: no actual Taiko shader catalog; legacy graphics carrier unavailable";return false;
}
bool resolve_catalog_draw(const DrawSourceCatalog&,uint64_t,uint64_t,const NVNshaderData*,size_t,
    ShaderSourceReader,void*,std::shared_ptr<const ResolvedProgram>* out,std::string* error){
    if(out)out->reset();if(error)*error="Taiko draw shaders are unsupported: no actual Taiko shader catalog";return false;
}
}
#else
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include <cstring>
namespace dm_android {
namespace {
ShaderDigest digest(const char* text){ShaderDigest out{};auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};for(size_t i=0;i<32;++i)out[i]=uint8_t(nibble(text[i*2])*16+nibble(text[i*2+1]));return out;}
const std::array<ShaderIndexEntry,2>& entries(){static const std::array<ShaderIndexEntry,2> value={{
#include "graphics_fixtures/draw_shaders/catalog_entries.inc"
}};return value;}
const std::array<ShaderIndexEntry,2>& sampled_entries(){static const std::array<ShaderIndexEntry,2> value={{
#include "graphics_fixtures/draw_texture_shaders/catalog_entries.inc"
}};return value;}
const std::array<ShaderIndexEntry,2>& original_entries(){static const std::array<ShaderIndexEntry,2> value={{
#include "original_draw_shaders/catalog_entries.inc"
}};return value;}
const std::array<ShaderIndexEntry,2>& original_sampled_entries(){static const std::array<ShaderIndexEntry,2> value={{
#include "original_sampled_shaders/catalog_entries.inc"
}};return value;}
struct ArtifactView{const uint8_t* data;size_t size;};
ArtifactView artifact(size_t index){static constexpr uint8_t vertex[]={
#include "graphics_fixtures/draw_shaders/authored_vs_position.dmsv.inc"
},fragment[]={
#include "graphics_fixtures/draw_shaders/authored_collision_fs.dmsv.inc"
},sampled_vertex[]={
#include "graphics_fixtures/draw_texture_shaders/authored_vs_position.dmsv.inc"
},sampled_fragment[]={
#include "graphics_fixtures/draw_texture_shaders/authored_d2_fragcoord_clamp_fs.dmsv.inc"
},original_vertex[]={
#include "original_draw_shaders/original_embedded_vs.dmsv.inc"
},original_fragment[]={
#include "original_draw_shaders/original_embedded_fs.dmsv.inc"
},original_sampled_vertex[]={
#include "original_sampled_shaders/original_embedded_vs.dmsv.inc"
},original_sampled_fragment[]={
#include "original_sampled_shaders/original_embedded_fs.dmsv.inc"
};switch(index){case 0:return {vertex,sizeof(vertex)};case 1:return {fragment,sizeof(fragment)};case 2:return {sampled_vertex,sizeof(sampled_vertex)};case 3:return {sampled_fragment,sizeof(sampled_fragment)};case 4:return {original_vertex,sizeof(original_vertex)};case 5:return {original_fragment,sizeof(original_fragment)};case 6:return {original_sampled_vertex,sizeof(original_sampled_vertex)};default:return {original_sampled_fragment,sizeof(original_sampled_fragment)};}}
bool read_artifact(const ShaderIndexEntry& entry,std::shared_ptr<const ShaderArtifact>* out,void*,std::string* error){
    const std::array<ShaderIndexEntry,2>* groups[]={&entries(),&sampled_entries(),&original_entries(),&original_sampled_entries()};
    for(size_t group=0;group<4;++group)for(size_t i=0;i<2;++i){const auto& known=(*groups[group])[i];if(shader_typed_key_equal(entry.key,known.key)&&entry.expected_file_sha256==known.expected_file_sha256){const auto view=artifact(group*2+i);return decode_shader_artifact(view.data,view.size,known,out,error);}}
    if(out)out->reset();if(error)*error="draw compiled artifact absent";return false;
}
struct SourceRead {const DrawSourceCatalog* catalog;ShaderSourceReader reader;void* context;};
bool read_source(uint64_t at,void* bytes,size_t size,void* context,std::string* error){
    const auto& read=*static_cast<const SourceRead*>(context);
    if(!read.catalog->original)return read.reader(at,bytes,size,read.context,error);
    for(const auto& source:read.catalog->sources)if(at==source.record_address&&size==source.record_bytes&&size>=0x38){
        // The publisher's existing image-main-rec-v1 recipe has a synthetic
        // zero prefix. Never copy or grant authority to the preceding image
        // bytes: only the complete pinned code-area/control body is borrowed.
        std::memset(bytes,0,0x38);
        return read.reader(at+0x38,static_cast<uint8_t*>(bytes)+0x38,size-0x38,read.context,error);
    }
    if(error)*error="original draw source is outside exact compiled record spans";return false;
}
bool fixture_sources(const Process& process,DrawSourceCatalog* candidate,std::string* error){
    const char* names[]={"draw_shader_vs_record","draw_shader_fs_record","sampled_draw_shader_vs_record","sampled_draw_shader_fs_record"};
    uintptr_t addresses[4]{};
    for(size_t i=0;i<4;++i)(void)process.module_symbol(1,names[i],&addresses[i]);
    if(!addresses[0]||!addresses[1]){if(error)*error="current exact carrier lacks authored draw records";return false;}
    if(bool(addresses[2])!=bool(addresses[3])){if(error)*error="current exact carrier has incomplete sampled draw records";return false;}
    for(size_t i=0;i<(addresses[2]?4u:2u);++i){ShaderSourceStage source;source.key=(i<2?entries():sampled_entries())[i%2].key;source.locator_kind=3;source.record_address=addresses[i];
        auto& out=source;switch(i){
#include "graphics_fixtures/draw_shaders/source_spans.inc"
        case 2:case 3:{switch(i-2){
#include "graphics_fixtures/draw_texture_shaders/source_spans.inc"
        default:return false;}break;}
        default:return false;}
        if(!process.mapped_range(source.record_address,source.record_bytes,DM_GUEST_READ)){if(error)*error="authored draw record is not owned readable storage";return false;}candidate->sources.push_back(std::move(source));
    }return true;
}
}
const std::array<ShaderIndexEntry,2>& compiled_draw_catalog(){return entries();}
const std::array<ShaderIndexEntry,2>& compiled_original_draw_catalog(){return original_entries();}
const std::array<ShaderIndexEntry,2>& compiled_original_sampled_draw_catalog(){return original_sampled_entries();}
const std::array<ShaderIndexEntry,2>& compiled_sampled_draw_catalog(){return sampled_entries();}
bool create_draw_source_catalog(const Process& process,DrawSourceCatalog* out,std::string* error){
    if(out)*out={};if(!out)return false;
    const bool fixture=graphics_diagnostic_graph(process,nullptr);
    const bool original=!fixture&&original_bringup_graph(process,error);
    if(!fixture&&!original)return false;
    DrawSourceCatalog candidate;candidate.generation=process.load_generation();candidate.original=original;
    if(fixture){if(!fixture_sources(process,&candidate,error))return false;*out=std::move(candidate);return true;}
    const auto* pins=original_bringup_build();
    if(!pins||!pins->sources||!pins->source_count||process.modules().empty()||!process.modules()[0]->mapping.base||process.modules()[0]->package->original_size!=52510720||
       pins->sources[0].decoded_sha256!=std::get<OriginalMaxwellKey>(original_entries()[0].key.source).trusted_content_sha256){if(error)*error="original main decoded source identity does not match draw catalog";return false;}
    const uint64_t base=reinterpret_cast<uintptr_t>(process.modules()[0]->mapping.base);
    for(size_t i=0;i<4;++i){ShaderSourceStage source;source.key=(i<2?original_entries():original_sampled_entries())[i%2].key;source.locator_kind=2;switch(i){
#include "original_draw_shaders/source_spans.inc"
        case 2:case 3:{switch(i-2){
#include "original_sampled_shaders/source_spans.inc"
        default:return false;}break;}
        default:return false;}
        if(source.control_offset<source.record_control_offset||source.control_offset>52510720-0x880||base>UINT64_MAX-(source.control_offset-source.record_control_offset)||source.record_bytes<0x38){if(error)*error="original draw source image window out of bounds";return false;}
        source.record_address=base+source.control_offset-source.record_control_offset;
        if(source.record_bytes>UINT64_MAX-source.record_address){if(error)*error="original draw record address overflows";return false;}
        const uint64_t body=source.record_address+0x38,bytes=source.record_bytes-0x38;
        if(!process.mapped_range(body,bytes,DM_GUEST_READ)||process.mapped_range(body,bytes,DM_GUEST_READ|DM_GUEST_WRITE)||process.mapped_range(body,bytes,DM_GUEST_READ|DM_GUEST_EXEC)){if(error)*error="original draw source is not a complete owned read-only span";return false;}
        candidate.sources.push_back(std::move(source));
    }
    auto copy=[](uint64_t at,void* bytes,size_t size,void* context,std::string* detail){if(static_cast<const Process*>(context)->copy_readable(at,bytes,size))return true;if(detail)*detail="original draw source copy refused";return false;};
    SourceRead read{&candidate,copy,const_cast<Process*>(&process)};ProgramSnapshot checked;
    for(size_t i=0;i<4;i+=2){std::vector<ShaderSourceStage> pair{candidate.sources[i],candidate.sources[i+1]};if(!capture_program_snapshot(candidate.generation,1,3,pair,read_source,&read,&checked,error))return false;}
    *out=std::move(candidate);return true;
}
bool resolve_catalog_draw(const DrawSourceCatalog& catalog,uint64_t generation,uint64_t serial,const NVNshaderData* shaders,size_t count,ShaderSourceReader reader,void* context,std::shared_ptr<const ResolvedProgram>* out,std::string* error){
    if(out)out->reset();if(!out||!shaders||count!=2||!generation||generation!=catalog.generation||!serial||!reader){if(error)*error="missing current owned draw request";return false;}
    std::vector<ShaderSourceStage> selected;uint32_t seen=0;
    for(size_t i=0;i<count;++i){bool found=false;for(const auto& source:catalog.sources)if(source.record_address&&shaders[i].data==source.record_address+source.code_offset&&reinterpret_cast<uint64_t>(shaders[i].control)==source.record_address+source.record_control_offset){uint32_t bit=1u<<static_cast<uint32_t>(source.key.stage);if(seen&bit){if(error)*error="duplicate draw stage";return false;}seen|=bit;selected.push_back(source);found=true;break;}if(!found){if(error)*error="draw pointers do not identify exact current catalog spans";return false;}}
    const auto& compiled=catalog.original?(selected[0].key.profile_name==original_sampled_entries()[0].key.profile_name?original_sampled_entries():original_entries()):(selected[0].key.profile_name==sampled_entries()[0].key.profile_name?sampled_entries():entries());
    SourceRead read{&catalog,reader,context};ProgramSnapshot snapshot;
    return seen==3&&capture_program_snapshot(generation,serial,3,selected,read_source,&read,&snapshot,error)&&resolve_program(snapshot,{generation,serial},compiled.data(),compiled.size(),read_artifact,nullptr,out,error);
}
}
#endif
