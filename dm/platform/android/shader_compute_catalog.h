#pragma once
#include "module_runtime.h"
#include "program_resolver.h"
#include "../../gfx/nvn/nvn_obj.h"
namespace dm_android {
// Per-load addresses derive from the exact compiled diagnostic carrier or the
// separately authorized original main read-only mapping. Artifacts retain their
// full OriginalMaxwell identity in both paths; carrier addresses grant no authority.
struct ComputeSourceCatalog {
    uint64_t generation=0;
    std::array<ShaderSourceStage,4> sources{};
};
const std::array<ShaderIndexEntry,4>& compiled_compute_catalog();
bool create_compute_source_catalog(const Process&,ComputeSourceCatalog*,std::string*);
bool resolve_catalog_compute(const ComputeSourceCatalog&,uint64_t generation,uint64_t serial,
    const NVNshaderData*,size_t,ShaderSourceReader,void*,
    std::shared_ptr<const ResolvedProgram>*,std::string*);
}
