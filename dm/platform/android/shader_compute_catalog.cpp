#include "shader_compute_catalog.h"
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include <cstring>
namespace dm_android {
namespace {
ShaderDigest digest(const char* text) {
    ShaderDigest out{};auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};
    for(size_t i=0;i<32;++i)out[i]=uint8_t(nibble(text[i*2])*16+nibble(text[i*2+1]));return out;
}
const std::array<ShaderIndexEntry,4>& entries() {
    static const std::array<ShaderIndexEntry,4> value={{
#include "graphics_fixtures/shaders/catalog_entries.inc"
    }};return value;
}
struct Source {uint64_t control_offset;ShaderDigest record;};
const std::array<Source,4>& sources() {
    static const std::array<Source,4> value={{
#include "graphics_fixtures/shaders/catalog_sources.inc"
    }};return value;
}
struct ArtifactView {const uint8_t* data;size_t size;};
ArtifactView artifact(size_t index) {
    // Literal backing arrays remain in read-only storage. A vector's local
    // initializer_list generated a 1.2 MiB temporary stack frame in Debug,
    // overflowing the actual guest invocation stack before decoder admission.
    static constexpr uint8_t bytes0[]={
#include "graphics_fixtures/shaders/q_val0.dmsv.inc"
    },bytes1[]={
#include "graphics_fixtures/shaders/q_val8.dmsv.inc"
    },bytes2[]={
#include "graphics_fixtures/shaders/q_dlt0.dmsv.inc"
    },bytes3[]={
#include "graphics_fixtures/shaders/q_dlt8.dmsv.inc"
    };
    switch(index){case 0:return {bytes0,sizeof(bytes0)};case 1:return {bytes1,sizeof(bytes1)};case 2:return {bytes2,sizeof(bytes2)};default:return {bytes3,sizeof(bytes3)};}
}
bool read_artifact(const ShaderIndexEntry& entry,std::shared_ptr<const ShaderArtifact>* out,void*,std::string* error) {
    for(size_t i=0;i<4;++i)if(shader_typed_key_equal(entry.key,entries()[i].key)&&entry.expected_file_sha256==entries()[i].expected_file_sha256) {
        const auto bytes=artifact(i);return decode_shader_artifact(bytes.data,bytes.size,entries()[i],out,error);
    }
    if(out)out->reset();if(error)*error="original compiled artifact absent";return false;
}
}
const std::array<ShaderIndexEntry,4>& compiled_compute_catalog(){return entries();}
bool create_compute_source_catalog(const Process& process,ComputeSourceCatalog* out,std::string* error) {
    if(out)*out={};if(!out)return false;
    const bool fixture=graphics_diagnostic_graph(process,nullptr);
    const bool original=!fixture && original_bringup_graph(process,error);
    if(!fixture && !original)return false;
    uintptr_t address=0;
    if(fixture && (!process.module_symbol(1,"graphics_original_records",&address)||!address||
       !process.mapped_range(address,4*2452,DM_GUEST_READ))) {
        if(error)*error="current exact carrier has no owned original compute records";return false;
    }
    const auto* pins=original?original_bringup_build():nullptr;
    if(original && (!pins || !pins->sources || !pins->source_count || process.modules().empty() ||
       process.modules()[0]->package->original_size!=52510720 || !process.modules()[0]->mapping.base ||
       pins->sources[0].decoded_sha256!=std::get<OriginalMaxwellKey>(entries()[0].key.source).trusted_content_sha256)) {
        if(error)*error="original main decoded source identity does not match Original4 catalog";return false;
    }
    ComputeSourceCatalog candidate;candidate.generation=process.load_generation();
    for(size_t i=0;i<4;++i) {
        auto& source=candidate.sources[i];source.key=entries()[i].key;source.locator_kind=2;
        source.control_offset=sources()[i].control_offset;source.record_sha256=sources()[i].record;
        source.record_bytes=2452;source.record_control_offset=276;
        source.code_offset=20;source.code_bytes=256;source.c1_offset=276;
        if(fixture)source.record_address=address+i*2452;
        else {
            const auto& key=std::get<OriginalMaxwellKey>(source.key.source);
            const uint64_t base=reinterpret_cast<uintptr_t>(process.modules()[0]->mapping.base);
            if(key.trusted_content_sha256!=pins->sources[0].decoded_sha256 || source.control_offset<276 ||
               source.control_offset>52510720-0x880 || base>UINT64_MAX-(source.control_offset-276)) {
                if(error)*error="original compute catalog image source window is out of bounds";return false;
            }
            source.record_address=base+source.control_offset-276;
            if(!process.mapped_range(source.record_address,2452,DM_GUEST_READ) ||
               process.mapped_range(source.record_address,2452,DM_GUEST_READ|DM_GUEST_WRITE) ||
               process.mapped_range(source.record_address,2452,DM_GUEST_READ|DM_GUEST_EXEC)) {
                if(error)*error="original compute source is not a complete owned read-only span";return false;
            }
            // The rewritten capsule has a distinct image hash. Verify these
            // exact original source windows after mapping/relocation instead of
            // treating the capsule hash or a diagnostic export as source bytes.
            ProgramSnapshot checked;
            auto read=[](uint64_t at,void* bytes,size_t size,void* context,std::string* detail){
                if(static_cast<const Process*>(context)->copy_readable(at,bytes,size))return true;
                if(detail)*detail="original compute source copy refused";return false;
            };
            if(!capture_program_snapshot(candidate.generation,1,32,{source},read,
               const_cast<Process*>(&process),&checked,error))return false;
        }
    }
    *out=std::move(candidate);return true;
}
bool resolve_catalog_compute(const ComputeSourceCatalog& catalog,uint64_t generation,uint64_t serial,
    const NVNshaderData* shaders,size_t count,ShaderSourceReader reader,void* context,
    std::shared_ptr<const ResolvedProgram>* out,std::string* error) {
    if(out)out->reset();
    if(!out||!shaders||count!=1||!generation||generation!=catalog.generation||!serial||!reader) {
        if(error)*error="missing current owned original shader request";return false;
    }
    for(const auto& source:catalog.sources)if(source.record_address&&
        shaders[0].data==source.record_address+source.code_offset&&
        reinterpret_cast<uint64_t>(shaders[0].control)==source.record_address+source.record_control_offset) {
        ProgramSnapshot snapshot;
        return capture_program_snapshot(generation,serial,32,{source},reader,context,&snapshot,error)&&
            resolve_program(snapshot,{generation,serial},entries().data(),entries().size(),read_artifact,nullptr,out,error);
    }
    if(error)*error="shader pointers do not identify exact current catalog spans";return false;
}
}
