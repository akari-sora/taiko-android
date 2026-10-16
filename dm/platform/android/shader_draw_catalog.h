#pragma once
#include "shader_compute_catalog.h"
namespace dm_android {
struct DrawSourceCatalog {uint64_t generation=0;bool original=false;std::vector<ShaderSourceStage> sources;};
const std::array<ShaderIndexEntry,2>& compiled_draw_catalog();
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
constexpr size_t kCompiledOriginalDrawCount=0;
#else
constexpr size_t kCompiledOriginalDrawCount=2;
#endif
const std::array<ShaderIndexEntry,kCompiledOriginalDrawCount>& compiled_original_draw_catalog();
const std::array<ShaderIndexEntry,2>& compiled_sampled_draw_catalog();
const std::array<ShaderIndexEntry,kCompiledOriginalDrawCount>& compiled_original_sampled_draw_catalog();
bool create_draw_source_catalog(const Process&,DrawSourceCatalog*,std::string*);
bool resolve_catalog_draw(const DrawSourceCatalog&,uint64_t,uint64_t,const NVNshaderData*,size_t,
    ShaderSourceReader,void*,std::shared_ptr<const ResolvedProgram>*,std::string*);
}
