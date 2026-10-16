#include "nvn_vk.h"
#include "compute_bindings.h"
#include "draw_bindings.h"
#include "../../platform/android/program_resolver.h"
#include <vulkan/vulkan.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
extern "C" {
#include "../tex/nvn_deswizzle.h"
}

namespace dm_android {
bool nvn_vk_atom_range(uint64_t off,uint64_t size,uint64_t alloc,uint64_t atom,
                       uint64_t* begin,uint64_t* length) {
    if (!begin || !length || !atom || !size || off>alloc || size>alloc-off) return false;
    const uint64_t b=off-off%atom, end=off+size;
    uint64_t e=end;
    if (e%atom) {
        const uint64_t add=atom-e%atom;
        e=add>alloc-e ? alloc : e+add;
    }
    *begin=b; *length=e-b; return *length!=0;
}
namespace {
constexpr VkImageUsageFlags kImageUsage=VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT |
    VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
constexpr VkImageUsageFlags kSampledImageUsage=kImageUsage|VK_IMAGE_USAGE_SAMPLED_BIT;
bool span(uint64_t a,uint64_t n,uint64_t base,uint64_t size,uint64_t* offset=nullptr) {
    if (!n || a<base || a-base>size || n>size-(a-base)) return false;
    if (offset) *offset=a-base;
    return true;
}
bool overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return a<=b ? b-a<n : a-b<m;
}
template<class T> bool decode(const SubmitOp& op,T* dst) {
    if (op.payload.size()<sizeof(T)) return false;
    std::memcpy(dst,op.payload.data(),sizeof(T)); return true;
}
struct Range { uint64_t off=0,size=0; };
struct Buffer {
    VkBuffer buffer=VK_NULL_HANDLE;
    VkDeviceMemory memory=VK_NULL_HANDLE;
    VkDeviceSize allocation=0,size=0;
    void* mapped=nullptr;
    bool coherent=false;
};
struct Image {
    const tex_t* texture=nullptr;
    size_t pool=0; uint64_t offset=0;
    VkImage image=VK_NULL_HANDLE;
    VkDeviceMemory memory=VK_NULL_HANDLE;
    VkImageView view=VK_NULL_HANDLE;
    VkFramebuffer framebuffer=VK_NULL_HANDLE;
    VkImageLayout layout=VK_IMAGE_LAYOUT_UNDEFINED;
    Buffer staging;
    bool written=false,sampled=false;
};
struct DeviceContext {
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    VkRenderPass render_pass=VK_NULL_HANDLE;
    VkDebugUtilsMessengerEXT messenger=VK_NULL_HANDLE;
    PFN_vkDestroyDebugUtilsMessengerEXT destroy_messenger=nullptr;
    std::atomic<uint32_t> samplers{0};
    std::atomic<uint64_t> validation_errors{0},created{0},destroyed{0},graphics_created{0},graphics_destroyed{0};
    ~DeviceContext() {
        if(render_pass)vkDestroyRenderPass(device,render_pass,nullptr);
        if(device)vkDestroyDevice(device,nullptr);
        if(messenger&&destroy_messenger)destroy_messenger(instance,messenger,nullptr);
        if(instance)vkDestroyInstance(instance,nullptr);
    }
    static VKAPI_ATTR VkBool32 VKAPI_CALL debug(VkDebugUtilsMessageSeverityFlagBitsEXT severity,
          VkDebugUtilsMessageTypeFlagsEXT,const VkDebugUtilsMessengerCallbackDataEXT*,void* user) {
        if(severity&VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT)
            static_cast<DeviceContext*>(user)->validation_errors.fetch_add(1,std::memory_order_relaxed);
        return VK_FALSE;
    }
};
struct ComputeObjects { VkDescriptorPool pool=VK_NULL_HANDLE;VkDescriptorSet set=VK_NULL_HANDLE;std::vector<Buffer> support; VkSampler sampler=VK_NULL_HANDLE; };
struct Job {
    uint64_t id=0;
    std::shared_ptr<const PreparedSubmit> plan;
    VkPublish publish;
    VkCommandPool command_pool=VK_NULL_HANDLE;
    VkCommandBuffer command=VK_NULL_HANDLE;
    VkFence fence=VK_NULL_HANDLE;
    std::vector<Buffer> pools,temporaries;
    std::vector<VkBufferUsageFlags> usages;
    std::vector<std::shared_ptr<const PreparedComputeDispatch>> computes;
    std::vector<ComputeObjects> compute_objects,draw_objects;
    std::vector<std::shared_ptr<const PreparedDraw>> draws;
    uint64_t ownership_bytes=0;
    std::vector<Image> images;
    std::vector<std::vector<Range>> writes;
    std::vector<std::vector<Range>> reads;
    std::vector<SubmitWrite> outputs;
    // Immutable retention metadata remains readable while the worker releases
    // the plan outside backend locks (its lease destructor may lock the runtime).
    std::vector<uint64_t> pool_identities,texture_serials;
    NvnVkEngine::Failure failure=NvnVkEngine::Failure::None;
    VkReplayStats counters;
};
struct Outcome { VkSubmitState state=VkSubmitState::Pending; std::string error; VkErrorKind kind=VkErrorKind::None; };
uint64_t shader_feature_mask(const VkPhysicalDeviceFeatures& f) {
    uint64_t mask=0;
    auto add=[&](VkBool32 value,ShaderFeature bit) { if(value)mask|=static_cast<uint64_t>(bit); };
    add(f.shaderFloat64,ShaderFeature::Float64);
    add(f.shaderInt64,ShaderFeature::Int64);
    add(f.shaderInt16,ShaderFeature::Int16);
    add(f.geometryShader,ShaderFeature::Geometry);
    add(f.tessellationShader,ShaderFeature::Tessellation);
    add(f.fragmentStoresAndAtomics,ShaderFeature::FragmentStoresAndAtomics);
    add(f.vertexPipelineStoresAndAtomics,ShaderFeature::VertexStoresAndAtomics);
    add(f.shaderStorageImageExtendedFormats,ShaderFeature::StorageImageExtendedFormats);
    add(f.shaderStorageImageReadWithoutFormat,ShaderFeature::StorageImageReadWithoutFormat);
    add(f.shaderStorageImageWriteWithoutFormat,ShaderFeature::StorageImageWriteWithoutFormat);
    add(f.shaderUniformBufferArrayDynamicIndexing,ShaderFeature::UniformBufferArrayDynamicIndexing);
    add(f.shaderSampledImageArrayDynamicIndexing,ShaderFeature::SampledImageArrayDynamicIndexing);
    add(f.shaderStorageBufferArrayDynamicIndexing,ShaderFeature::StorageBufferArrayDynamicIndexing);
    add(f.shaderStorageImageArrayDynamicIndexing,ShaderFeature::StorageImageArrayDynamicIndexing);
    add(f.sampleRateShading,ShaderFeature::SampleRateShading);
    add(f.shaderClipDistance,ShaderFeature::ClipDistance);
    add(f.shaderCullDistance,ShaderFeature::CullDistance);
    add(f.imageCubeArray,ShaderFeature::ImageCubeArray);
    add(f.shaderResourceMinLod,ShaderFeature::ResourceMinLod);
    add(f.shaderStorageImageMultisample,ShaderFeature::StorageImageMultisample);
    return mask;
}
}

class VkComputeProgram {
public:
    std::shared_ptr<DeviceContext> context;
    std::shared_ptr<const ResolvedProgram> program;
    VkDescriptorSetLayout descriptor_layout=VK_NULL_HANDLE;
    VkPipelineLayout pipeline_layout=VK_NULL_HANDLE;
    VkShaderModule module=VK_NULL_HANDLE;
    VkPipeline pipeline=VK_NULL_HANDLE;
    ~VkComputeProgram() {
        auto destroy=[&](auto handle,auto function){if(handle){function(context->device,handle,nullptr);context->destroyed.fetch_add(1,std::memory_order_relaxed);}};
        destroy(pipeline,vkDestroyPipeline);destroy(module,vkDestroyShaderModule);
        destroy(pipeline_layout,vkDestroyPipelineLayout);destroy(descriptor_layout,vkDestroyDescriptorSetLayout);
    }
};

class VkGraphicsProgram {
public:
    std::shared_ptr<DeviceContext> context;
    std::shared_ptr<const ResolvedProgram> program;
    VkDescriptorSetLayout descriptor_layout=VK_NULL_HANDLE;
    VkPipelineLayout pipeline_layout=VK_NULL_HANDLE;
    std::array<VkShaderModule,2> modules{};
    VkPipeline pipeline=VK_NULL_HANDLE;
    ~VkGraphicsProgram(){
        auto destroy=[&](auto handle,auto function){if(handle){function(context->device,handle,nullptr);context->graphics_destroyed.fetch_add(1,std::memory_order_relaxed);}};
        destroy(pipeline,vkDestroyPipeline);for(auto module:modules)destroy(module,vkDestroyShaderModule);
        destroy(pipeline_layout,vkDestroyPipelineLayout);destroy(descriptor_layout,vkDestroyDescriptorSetLayout);
    }
};

struct NvnVkEngine::Impl {
    std::shared_ptr<DeviceContext> context=std::make_shared<DeviceContext>();
    VkInstance& instance=context->instance;
    VkPhysicalDevice physical=VK_NULL_HANDLE;
    VkDevice& device=context->device;
    VkQueue queue=VK_NULL_HANDLE;
    uint32_t family=0;
    VkRenderPass& render_pass=context->render_pass;
    VkPhysicalDeviceProperties properties{};
    VkPhysicalDeviceFeatures supported_features{},created_features{};
    bool float4_vertex_supported=false,rgba8_sampled_supported=false;
    VkImageFormatProperties sampled_image_properties{};
    uint32_t requested_api=0,queue_flags=0;
    std::vector<std::string> supported_extensions,created_extensions;
    VkPhysicalDeviceMemoryProperties memory_properties{};
    VkImageFormatProperties image_properties{};
    VkDebugUtilsMessengerEXT& messenger=context->messenger;
    PFN_vkDestroyDebugUtilsMessengerEXT& destroy_messenger=context->destroy_messenger;
    mutable std::mutex mutex;
    std::mutex submit_mutex;
    std::condition_variable cv;
    std::thread worker;
    std::deque<std::shared_ptr<Job>> jobs;
    std::map<uint64_t,Outcome> outcomes;
    std::vector<std::shared_ptr<Job>> retained;
    bool initialized=false,stop=false,lost=false,hold=false,entered=false;
    uint64_t last=0,completed=0,first_failure=0,retained_bytes=0;
    bool quarantined=false,termination_wrapper=false;
    VkErrorKind sticky_kind=VkErrorKind::None;
    std::string sticky;
    VkReplayStats totals;
    Failure injection=Failure::None;
    ShaderDeviceContract contract() const {
    ShaderDeviceContract out;
    if(!initialized)return out;
    out.initialized=true;
    out.effective_api_version=std::min(requested_api,properties.apiVersion);
    if(queue_flags&VK_QUEUE_GRAPHICS_BIT)out.queue_stage_mask|=0x1fu;
    if(queue_flags&VK_QUEUE_COMPUTE_BIT)out.queue_stage_mask|=1u<<5;
    out.supported_features=shader_feature_mask(supported_features);
    out.enabled_features=shader_feature_mask(created_features);
    out.supported_extensions=supported_extensions;
    out.enabled_extensions=created_extensions;
    // No subgroup properties were queried under the existing1.0 instance.
    const auto& limits=properties.limits;
    out.limits.per_stage_descriptors={limits.maxPerStageDescriptorSamplers,
        limits.maxPerStageDescriptorUniformBuffers,limits.maxPerStageDescriptorStorageBuffers,
        limits.maxPerStageDescriptorSampledImages,limits.maxPerStageDescriptorStorageImages,
        limits.maxPerStageDescriptorInputAttachments};
    out.limits.aggregate_descriptors={limits.maxDescriptorSetSamplers,
        limits.maxDescriptorSetUniformBuffers,limits.maxDescriptorSetStorageBuffers,
        limits.maxDescriptorSetSampledImages,limits.maxDescriptorSetStorageImages,
        limits.maxDescriptorSetInputAttachments};
    out.limits.per_stage_resources=limits.maxPerStageResources;
    out.limits.max_bound_descriptor_sets=limits.maxBoundDescriptorSets;
    out.limits.max_color_attachments=limits.maxColorAttachments;
    out.limits.max_fragment_output_attachments=limits.maxFragmentOutputAttachments;
    out.limits.max_fragment_combined_output_resources=limits.maxFragmentCombinedOutputResources;
    for(size_t i=0;i<3;++i) {
        out.limits.compute_count[i]=limits.maxComputeWorkGroupCount[i];
        out.limits.compute_size[i]=limits.maxComputeWorkGroupSize[i];
    }
    out.limits.compute_invocations=limits.maxComputeWorkGroupInvocations;
    out.limits.compute_shared_bytes=limits.maxComputeSharedMemorySize;
    out.limits.uniform_offset_alignment=limits.minUniformBufferOffsetAlignment;
    out.limits.storage_offset_alignment=limits.minStorageBufferOffsetAlignment;
    out.limits.uniform_buffer_range=limits.maxUniformBufferRange;
    out.limits.storage_buffer_range=limits.maxStorageBufferRange;
    return out;
    }
    DrawDeviceContract draw_contract() const {
        DrawDeviceContract out;out.shader=contract();if(!out.shader.initialized)return out;
        const auto& limits=properties.limits;
        out.vertex_attributes=limits.maxVertexInputAttributes;out.vertex_bindings=limits.maxVertexInputBindings;
        out.vertex_stride=limits.maxVertexInputBindingStride;out.vertex_attribute_offset=limits.maxVertexInputAttributeOffset;
        out.framebuffer={limits.maxFramebufferWidth,limits.maxFramebufferHeight};
        out.viewport={limits.maxViewportDimensions[0],limits.maxViewportDimensions[1]};
        out.viewport_bounds={limits.viewportBoundsRange[0],limits.viewportBoundsRange[1]};
        out.rgba8_attachment=physical!=VK_NULL_HANDLE;out.float4_vertex=float4_vertex_supported;
        out.rgba8_sampled=rgba8_sampled_supported;out.sampled_extent={sampled_image_properties.maxExtent.width,sampled_image_properties.maxExtent.height};return out;
    }
    bool fail(std::string* err,const char* text,VkResult result=VK_SUCCESS) {
        if (err) *err=std::string(text)+(result==VK_SUCCESS?"":":"+std::to_string(result));
        return false;
    }
    uint32_t memory_type(uint32_t mask,VkMemoryPropertyFlags required,bool* coherent=nullptr) {
        uint32_t fallback=UINT32_MAX;
        for (uint32_t i=0;i<memory_properties.memoryTypeCount;i++) {
            auto flags=memory_properties.memoryTypes[i].propertyFlags;
            if (!(mask&(1u<<i)) || (flags&required)!=required) continue;
            if (fallback==UINT32_MAX) fallback=i;
            if (flags&VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) { fallback=i; break; }
        }
        if (coherent && fallback!=UINT32_MAX)
            *coherent=(memory_properties.memoryTypes[fallback].propertyFlags&VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)!=0;
        return fallback;
    }
    bool charge(Job& job,uint64_t bytes,std::string* err) {
        if(bytes>256u*1024u*1024u-job.ownership_bytes)return fail(err,"accepted-ownership-byte-budget");
        job.ownership_bytes+=bytes;return true;
    }
    bool buffer(Buffer& out,uint64_t size,Job& job,std::string* err,VkBufferUsageFlags usage=0) {
        if (!size) return fail(err,"empty-buffer");
        VkBufferCreateInfo info{}; info.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        info.size=size; info.usage=VK_BUFFER_USAGE_TRANSFER_SRC_BIT|VK_BUFFER_USAGE_TRANSFER_DST_BIT|usage;
        info.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
        VkResult result=vkCreateBuffer(device,&info,nullptr,&out.buffer);
        if (result!=VK_SUCCESS) return fail(err,"create-buffer",result);
        VkMemoryRequirements req{}; vkGetBufferMemoryRequirements(device,out.buffer,&req);
        if(!charge(job,req.size,err))return false;
        uint32_t type=memory_type(req.memoryTypeBits,VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,&out.coherent);
        if (type==UINT32_MAX) return fail(err,"no-host-visible-buffer-memory");
        VkMemoryAllocateInfo alloc{}; alloc.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc.allocationSize=req.size; alloc.memoryTypeIndex=type;
        result=vkAllocateMemory(device,&alloc,nullptr,&out.memory);
        if (result!=VK_SUCCESS) return fail(err,"allocate-buffer",result);
        out.allocation=req.size; out.size=size;
        result=vkBindBufferMemory(device,out.buffer,out.memory,0);
        if (result!=VK_SUCCESS) return fail(err,"bind-buffer",result);
        result=vkMapMemory(device,out.memory,0,req.size,0,&out.mapped);
        if (result!=VK_SUCCESS) return fail(err,"map-buffer",result);
        return true;
    }
    bool cache(Buffer& b,bool invalidate,Job& job,std::string* err) {
        if (b.coherent) return true;
        uint64_t off=0,len=0;
        if (!nvn_vk_atom_range(0,b.size,b.allocation,properties.limits.nonCoherentAtomSize,&off,&len))
            return fail(err,"noncoherent-atom-range");
        VkMappedMemoryRange range{}; range.sType=VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        range.memory=b.memory; range.offset=off; range.size=len;
        VkResult result=invalidate?vkInvalidateMappedMemoryRanges(device,1,&range):vkFlushMappedMemoryRanges(device,1,&range);
        if (result!=VK_SUCCESS) return fail(err,invalidate?"invalidate":"flush",result);
        if (invalidate) job.counters.invalidates++; else job.counters.flushes++;
        return true;
    }
    void destroy_buffer(Buffer& b) {
        if (b.mapped) vkUnmapMemory(device,b.memory);
        if (b.buffer) vkDestroyBuffer(device,b.buffer,nullptr);
        if (b.memory) vkFreeMemory(device,b.memory,nullptr);
        b=Buffer{};
    }
    void cleanup(Job& job) {
        for(auto& objects:job.draw_objects){
            if(objects.sampler){vkDestroySampler(device,objects.sampler,nullptr);context->samplers.fetch_sub(1,std::memory_order_relaxed);context->graphics_destroyed.fetch_add(1,std::memory_order_relaxed);}
            if(objects.pool){vkDestroyDescriptorPool(device,objects.pool,nullptr);context->graphics_destroyed.fetch_add(objects.set?2:1,std::memory_order_relaxed);}
            for(auto& b:objects.support)destroy_buffer(b);objects={};
        }
        for(auto& objects:job.compute_objects) {
            if(objects.pool){vkDestroyDescriptorPool(device,objects.pool,nullptr);context->destroyed.fetch_add(objects.set?2:1,std::memory_order_relaxed);}
            for(auto& b:objects.support)destroy_buffer(b);
            objects={};
        }
        for (auto& image:job.images) {
            if (image.framebuffer) vkDestroyFramebuffer(device,image.framebuffer,nullptr);
            if (image.view) vkDestroyImageView(device,image.view,nullptr);
            if (image.image) vkDestroyImage(device,image.image,nullptr);
            if (image.memory) vkFreeMemory(device,image.memory,nullptr);
            destroy_buffer(image.staging);
        }
        for (auto& b:job.pools) destroy_buffer(b);
        for (auto& b:job.temporaries) destroy_buffer(b);
        if (job.fence) vkDestroyFence(device,job.fence,nullptr);
        if (job.command_pool) vkDestroyCommandPool(device,job.command_pool,nullptr);
    }
    bool resolve(const PreparedSubmit& p,uint64_t address,uint64_t size,size_t* index,uint64_t* offset,
                 std::string* err) {
        bool found=false;
        for (size_t i=0;i<p.pools.size();i++) if (span(address,size,p.pools[i].address,p.pools[i].initial.size(),offset)) {
            if (found) return fail(err,"ambiguous-pool-address");
            *index=i; found=true;
        }
        return found || fail(err,"buffer-range-outside-pool");
    }
    bool tex_validate(const PreparedSubmit& plan,const tex_t* tex,const view_t* view,
                      size_t* pool,uint64_t* offset,std::string* err) {
        const bool retained_sample=tex&&std::any_of(plan.draws.begin(),plan.draws.end(),[&](const auto& draw){return draw&&draw->state().sampled&&draw->state().sampled->lease&&draw->state().sampled->generation==plan.generation&& &draw->state().sampled->texture==tex;});
        if (!tex || (!retained_sample&&std::none_of(plan.textures.begin(),plan.textures.end(),[tex](const auto& t){return t.get()==tex;})))
            return fail(err,"unowned-texture-snapshot");
        const auto& d=tex->d;
        if (!tex->serial || tex->magic!=MAGIC('T','E','X',0) || d.target!=1 || d.format!=0x25 ||
            d.samples>1 || d.samples<0 || d.levels>1 || d.depth>1 || !d.width || !d.height ||
            d.width>image_properties.maxExtent.width || d.height>image_properties.maxExtent.height ||
            (d.flags&~0x50) || d.pkg_block_h<0 || d.pkg_block_h>5)
            return fail(err,"unsupported-texture-shape-format-flags");
        if (view && ((view->set_levels && (view->base_level!=0 || view->nlevels!=1)) ||
            (view->set_layers && (view->min_layer!=0 || view->nlayers!=1)) ||
            (view->set_format && view->format!=d.format) || (view->set_target && view->target!=d.target)))
            return fail(err,"unsupported-texture-view");
        nvn_texlayout layout{}; nvn_tex_layout(&d,&layout);
        if (!layout.size || layout.size!=tex->L.size || layout.layers!=1 || layout.size>128u*1024u*1024u ||
            layout.layer_size!=tex->L.layer_size || layout.align!=tex->L.align ||
            layout.layers!=tex->L.layers || layout.bpb!=tex->L.bpb ||
            layout.tileH!=tex->L.tileH || layout.tileD!=tex->L.tileD)
            return fail(err,"texture-storage-layout-mismatch");
        if ((d.flags&0x10) && (d.stride && (d.stride<static_cast<uint64_t>(d.width)*4)))
            return fail(err,"texture-linear-stride");
        return resolve(plan,reinterpret_cast<uint64_t>(tex->mem),layout.size,pool,offset,err);
    }
    Image* find_image(Job& job,const tex_t* tex) {
        if(!tex)return nullptr;
        auto it=std::find_if(job.images.begin(),job.images.end(),[tex](const Image& i){return i.texture->serial==tex->serial;});
        return it==job.images.end()?nullptr:&*it;
    }
    bool add_image(Job& job,const tex_t* tex,const view_t* view,std::string* err) {
        size_t pool=0; uint64_t off=0;
        if (!tex_validate(*job.plan,tex,view,&pool,&off,err)) return false;
        if (auto* existing=find_image(job,tex)) {
            if (existing->pool!=pool || existing->offset!=off || std::memcmp(&existing->texture->d,&tex->d,sizeof(tex->d)))
                return fail(err,"texture-serial-alias-mismatch");
            return true;
        }
        for (const auto& existing:job.images)
            if (existing.pool==pool && overlap(existing.offset,existing.texture->L.size,off,tex->L.size))
                return fail(err,"distinct-overlapping-texture-storage");
        Image image; image.texture=tex; image.pool=pool; image.offset=off;
        job.images.push_back(image); return true;
    }
    bool region(const p_copy_b2t& c,int64_t stride,uint64_t* row,uint64_t* bytes,std::string* err) {
        const auto& r=c.r; const auto& d=c.tex->d;
        if (c.flags || r.xoffset<0 || r.yoffset<0 || r.zoffset || r.width<=0 || r.height<=0 ||
            (r.depth!=0 && r.depth!=1) || static_cast<uint64_t>(r.xoffset)+r.width>d.width ||
            static_cast<uint64_t>(r.yoffset)+r.height>d.height || stride<0)
            return fail(err,"unsupported-copy-region-flags");
        *row=stride?static_cast<uint64_t>(stride):static_cast<uint64_t>(r.width)*4;
        if (*row<static_cast<uint64_t>(r.width)*4 || *row%4 || *row/4>UINT32_MAX)
            return fail(err,"copy-row-stride");
        if (static_cast<uint64_t>(r.height-1)>(UINT64_MAX-static_cast<uint64_t>(r.width)*4)/ *row)
            return fail(err,"copy-row-overflow");
        *bytes=static_cast<uint64_t>(r.height-1)* *row+static_cast<uint64_t>(r.width)*4;
        return true;
    }
    bool validate(Job& job,std::string* err) {
        const auto& p=*job.plan;
        if (p.pools.size()>256 || p.computes.size()>4096 || p.draws.size()>4096 || p.programs.size()>4096 || p.ops.size()>131072) return fail(err,"submit-count-budget");
        for (const auto& pool:p.pools) job.pool_identities.push_back(pool.identity);
        for (const auto& texture:p.textures) {
            if (!texture) return fail(err,"null-owned-texture");
            job.texture_serials.push_back(texture->serial);
        }
        uint64_t total=0;
        for (size_t i=0;i<p.pools.size();i++) {
            const auto& a=p.pools[i];
            if (!a.identity || a.initial.empty() || a.address>UINT64_MAX-a.initial.size() ||
                a.initial.capacity()>128u*1024u*1024u-total) return fail(err,"pool-snapshot-budget-range");
            total+=a.initial.capacity();
            for (size_t j=0;j<i;j++) if (a.identity==p.pools[j].identity || overlap(a.address,a.initial.size(),p.pools[j].address,p.pools[j].initial.size()))
                return fail(err,"distinct-overlapping-pools-unsupported");
        }
        job.ownership_bytes=total;
        if(!charge(job,sizeof(Job)+sizeof(PreparedSubmit)+p.pools.capacity()*sizeof(SubmitPool)+
            p.ops.capacity()*sizeof(SubmitOp)+p.events.capacity()*sizeof(SubmitEvent)+p.textures.size()*sizeof(tex_t)+
            p.textures.capacity()*sizeof(std::unique_ptr<tex_t>)+p.programs.capacity()*sizeof(SubmitProgram)+
            (p.computes.capacity()+p.draws.capacity()+p.recorder_segments.capacity())*sizeof(std::shared_ptr<void>)+
            p.pools.size()*(sizeof(Buffer)+2*sizeof(std::vector<Range>)+2*sizeof(uint64_t))+
            p.textures.size()*(2*sizeof(Image)+2*sizeof(uint64_t))+
            p.computes.size()*(sizeof(ComputeObjects)+sizeof(std::shared_ptr<const PreparedComputeDispatch>))+
            p.draws.size()*(sizeof(ComputeObjects)+sizeof(std::shared_ptr<const PreparedDraw>)),err))return false;
        for(const auto& op:p.ops)if(!charge(job,op.payload.capacity(),err))return false;
        auto charge_program=[&](const ResolvedProgram& program) {
            // Only the exact eight pinned modules are executable here. Reserve
            // conservatively for file bytes AND decoded vectors/strings/words,
            // plus source snapshots. Sharing is deliberately overcharged.
            for(const auto& artifact:program.stages())if(!charge(job,8*artifact->file_bytes()+65536,err))return false;
            const auto& snapshot=program.snapshot();
            if(!charge(job,snapshot.stages.capacity()*sizeof(ShaderStageSnapshot),err))return false;
            for(const auto& stage:snapshot.stages)if(!charge(job,stage.record.capacity(),err))return false;
            return true;
        };
        for(const auto& program:p.programs)if(program.resolved&&!charge_program(*program.resolved))return false;
        job.usages.resize(p.pools.size());
        job.computes.resize(p.computes.size());
        job.draws.resize(p.draws.size());
        std::vector<bool> referenced_draws(p.draws.size());
        std::vector<bool> referenced(p.computes.size());
        // Temporal CPU facts contain only exact initial bytes and literal
        // updates. GPU writes/copies poison count facts before any submission.
        auto facts=p.pools;
        std::vector<std::vector<Range>> unknown(p.pools.size());
        job.writes.resize(p.pools.size());
        job.reads.resize(p.pools.size());
        const tex_t* rt=nullptr; int64_t stride=0;
        for (const auto& op:p.ops) {
            if(op.opcode!=OP_DRAW&&op.opcode!=OP_DRAW_IDX&&op.draw_index!=UINT32_MAX)return fail(err,"draw-index-on-nondraw");
            if(op.opcode!=OP_DISPATCH&&op.compute_index!=UINT32_MAX)return fail(err,"compute-index-on-nondispatch");
            size_t pi=0,pj=0; uint64_t off=0,other=0;
            switch (op.opcode) {
            case OP_UPDATE_UB: {
                uint64_t a=0,n=0;
                if (op.payload.size()<16) return fail(err,"short-update");
                std::memcpy(&a,op.payload.data(),8); std::memcpy(&n,op.payload.data()+8,8);
                if (!n || n%4 || a%4 || n>op.payload.size()-16 || n>65536 ||
                    !resolve(p,a,n,&pi,&off,err) || off%4) return fail(err,"update-range-size-alignment");
                job.writes[pi].push_back({off,n});
                std::memcpy(facts[pi].initial.data()+off,op.payload.data()+16,n);
                std::vector<Range> remaining;
                for(auto r:unknown[pi]) {
                    if(!overlap(off,n,r.off,r.size)){remaining.push_back(r);continue;}
                    if(r.off<off)remaining.push_back({r.off,off-r.off});
                    if(r.off+r.size>off+n)remaining.push_back({off+n,r.off+r.size-off-n});
                }
                unknown[pi]=std::move(remaining);break;
            }
            case OP_COPY_B2B: {
                uint64_t values[3]{};
                if (!decode(op,&values)) return fail(err,"short-buffer-copy");
                if (!values[2] || ((values[0]|values[1]|values[2])&3) ||
                    !resolve(p,values[0],values[2],&pi,&off,err) ||
                    !resolve(p,values[1],values[2],&pj,&other,err) || ((off|other)&3)) return fail(err,"buffer-copy-range-alignment");
                job.writes[pj].push_back({other,values[2]});
                unknown[pj].push_back({other,values[2]});
                job.reads[pi].push_back({off,values[2]}); break;
            }
            case OP_SET_RT: {
                p_set_rt r{};
                if (!decode(op,&r) || r.n!=1 || r.depth || !r.color[0]) return fail(err,"unsupported-render-targets");
                if (!add_image(job,r.color[0],r.has_cview[0]?&r.cview[0]:nullptr,err)) return false;
                rt=r.color[0]; break;
            }
            case OP_CLEAR_COLOR: {
                p_clear_color c{};
                if (!decode(op,&c) || !rt || c.index || c.mask!=15) return fail(err,"unsupported-clear-mask-target");
                find_image(job,rt)->written=true;{const auto* image=find_image(job,rt);unknown[image->pool].push_back({image->offset,image->texture->L.size});} break;
            }
            case OP_COPY_B2T: case OP_COPY_T2B: {
                p_copy_b2t c{}; uint64_t row=0,n=0;
                if (!decode(op,&c)) return fail(err,"short-texture-copy");
                if (c.src%4) return fail(err,"texture-copy-buffer-alignment");
                if (!add_image(job,c.tex,c.has_view?&c.view:nullptr,err) ||
                    !region(c,stride,&row,&n,err) || !resolve(p,c.src,n,&pi,&off,err)) return false;
                if (off%4) return fail(err,"texture-copy-buffer-offset-alignment");
                if (op.opcode==OP_COPY_B2T) {
                    find_image(job,c.tex)->written=true;{const auto* image=find_image(job,c.tex);unknown[image->pool].push_back({image->offset,image->texture->L.size});}
                    job.reads[pi].push_back({off,n});
                }
                else for (int y=0;y<c.r.height;y++) {
                    Range r{off+static_cast<uint64_t>(y)*row,static_cast<uint64_t>(c.r.width)*4};
                    job.writes[pi].push_back(r);unknown[pi].push_back(r);
                }
                break;
            }
            case OP_COPY_STRIDE: {
                p_copy_stride c{}; if (!decode(op,&c) || c.stride<0) return fail(err,"invalid-copy-stride");
                stride=c.stride; break;
            }
            case OP_DRAW:case OP_DRAW_IDX: {
                if(!op.payload.empty()||op.draw_index>=p.draws.size()||referenced_draws[op.draw_index]||!p.draws[op.draw_index])return fail(err,"missing-duplicate-invalid-draw-index");
                referenced_draws[op.draw_index]=true;const auto& request=*p.draws[op.draw_index];const auto& executable=request.executable();
                if(!executable||executable->context!=context||!executable->program||!request.program()||request.program()->stages().size()!=2||executable->program->stages().size()!=2)return fail(err,"foreign-or-invalid-graphics-executable");
                for(size_t i=0;i<2;++i)if(request.program()->stages()[i]->file_sha256()!=executable->program->stages()[i]->file_sha256()||!shader_typed_key_equal(request.program()->stages()[i]->key(),executable->program->stages()[i]->key()))return fail(err,"mismatched-graphics-program-identity");
                if(!rt||request.state().target!=rt||(op.opcode==OP_DRAW_IDX)!=request.call().indexed)return fail(err,"draw-target-or-command-mismatch");
                if(!add_image(job,rt,nullptr,err))return false;
                std::shared_ptr<const PreparedDraw> checked;
                if(!prepare_draw(request.program(),executable,request.state(),request.call(),facts,draw_contract(),&checked,err))return false;
                if(checked->state().sampled){
                    const auto& sampled=*checked->state().sampled;
                    if(sampled.generation!=p.generation||!add_image(job,&sampled.texture,nullptr,err))return fail(err,"sampled-draw-generation-or-image");
                    const auto& read=checked->sampled_span();
                    for(const auto& r:unknown[read.pool])if(overlap(read.offset,read.size,r.off,r.size))return fail(err,"sampled-source-overwritten-in-submit");
                    find_image(job,&sampled.texture)->sampled=true;job.texture_serials.push_back(sampled.texture.serial);
                }
                if(checked->call().indexed&&checked->call().count){const auto& indices=checked->indices();const uint64_t count=uint64_t(uint32_t(checked->call().count))*2;for(const auto& r:unknown[indices.pool])if(overlap(indices.offset,count,r.off,r.size))return fail(err,"draw-index-bytes-overwritten-by-unknown-gpu-write");}
                for(const auto& descriptor:checked->descriptors())if(descriptor.initial.empty())job.usages[descriptor.span.pool]|=VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;
                job.usages[checked->vertex().pool]|=VK_BUFFER_USAGE_VERTEX_BUFFER_BIT;
                if(checked->call().indexed)job.usages[checked->indices().pool]|=VK_BUFFER_USAGE_INDEX_BUFFER_BIT;
                if(!charge(job,request.owned_bytes()+checked->owned_bytes(),err)||!charge_program(*checked->program()))return false;
                for(const auto& read:checked->reads())job.reads[read.pool].push_back({read.offset,read.size});
                if(checked->call().count){auto* image=find_image(job,rt);image->written=true;unknown[image->pool].push_back({image->offset,image->texture->L.size});}
                job.draws[op.draw_index]=std::move(checked);break;
            }
            case OP_DISPATCH: {
                if(!op.payload.empty()||op.compute_index>=p.computes.size()||referenced[op.compute_index]||!p.computes[op.compute_index])return fail(err,"missing-duplicate-invalid-compute-index");
                referenced[op.compute_index]=true;
                const auto& request=*p.computes[op.compute_index];
                const auto& executable=request.executable();
                if(!executable||executable->context!=context||!executable->program||!request.program()||
                   executable->program->stages().size()!=1||request.program()->stages().size()!=1||
                   executable->program->stages()[0]->file_sha256()!=request.program()->stages()[0]->file_sha256()||
                   !shader_typed_key_equal(executable->program->stages()[0]->key(),request.program()->stages()[0]->key()))return fail(err,"foreign-or-mismatched-compute-executable");
                std::shared_ptr<const PreparedComputeDispatch> checked;
                if(!prepare_compute_dispatch(request.program(),executable,request.ubos(),request.ssbos(),request.groups(),facts,contract(),&checked,err))return false;
                const auto& count=checked->count_span();
                for(const auto& r:unknown[count.pool])if(overlap(count.offset,4,r.off,r.size))return fail(err,"compute-count-overwritten-by-unknown-gpu-write");
                for(const auto& d:checked->descriptors()) {
                    if(d.initial.empty())job.usages[d.span.pool]|=d.type==ShaderDescriptorType::UniformBuffer?VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT:VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
                }
                // Both caller and rebuilt dispatches remain owned until
                // retirement, including their separate driver/support facts.
                if(!charge(job,request.owned_bytes()+checked->owned_bytes(),err)||!charge_program(*checked->program()))return false;
                for(const auto& r:checked->reads())job.reads[r.pool].push_back({r.offset,r.size});
                for(const auto& r:checked->writes()){job.writes[r.pool].push_back({r.offset,r.size});unknown[r.pool].push_back({r.offset,r.size});}
                job.computes[op.compute_index]=std::move(checked);break;
            }
            case OP_BARRIER: break;
            case OP_SIGNAL_EVENT: break; // Already deep-copied into ordered post-effects by the runtime.
            default: return fail(err,("unsupported-nvn-opcode-"+std::to_string(op.opcode)).c_str());
            }
        }
        if(std::find(referenced_draws.begin(),referenced_draws.end(),false)!=referenced_draws.end())return fail(err,"orphaned-draw-request");
        if(std::find(referenced.begin(),referenced.end(),false)!=referenced.end())return fail(err,"orphaned-compute-request");
        // Buffers and textures alias the same NVN storage but have different
        // Vulkan representations. Reject cross-representation writes until an
        // explicit per-range transition/canonical representation is implemented.
        for (const auto& image:job.images) {
            for (const auto& r:job.writes[image.pool])
                if (overlap(image.offset,image.texture->L.size,r.off,r.size)) return fail(err,"buffer-image-storage-write-alias-unsupported");
            if (image.written) for (const auto& r:job.reads[image.pool]) {
                if (overlap(r.off,r.size,image.offset,image.texture->L.size))
                    return fail(err,"buffer-read-of-device-image-storage-unsupported");
            }
        }
        for (auto& ranges:job.writes) {
            std::sort(ranges.begin(),ranges.end(),[](Range a,Range b){return a.off<b.off;});
            std::vector<Range> merged;
            for (auto r:ranges) {
                if (!merged.empty() && r.off<=merged.back().off+merged.back().size)
                    merged.back().size=std::max(merged.back().size,r.off+r.size-merged.back().off);
                else merged.push_back(r);
            }
            ranges=std::move(merged);
        }
        // Reserve the CPU readback copies before acceptance as well as the
        // actual dedicated GPU allocations charged while recording below.
        size_t output_count=0;
        for(const auto& ranges:job.writes)for(const auto& r:ranges) {
            ++output_count;
            if(!charge(job,r.size+sizeof(SubmitWrite)+2*sizeof(Range),err))return false;
        }
        for(const auto& ranges:job.reads)if(!charge(job,2*ranges.size()*sizeof(Range),err))return false;
        for(const auto& image:job.images)if(image.written) {
            const uint64_t bytes=uint64_t(image.texture->d.width)*image.texture->d.height*4;
            const uint64_t rows=uint64_t(image.texture->d.height)*((uint64_t(image.texture->d.width)*4+15)/16);
            if(!charge(job,bytes+rows*sizeof(SubmitWrite),err))return false;
            output_count+=static_cast<size_t>(rows);
        }
        job.outputs.reserve(output_count);
        return true;
    }
    bool create_image(Image& out,Job& job,std::string* err) {
        const auto& t=*out.texture; const uint64_t bytes=static_cast<uint64_t>(t.d.width)*t.d.height*4;
        VkImageCreateInfo info{}; info.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
        info.imageType=VK_IMAGE_TYPE_2D; info.format=VK_FORMAT_R8G8B8A8_UNORM;
        info.extent={t.d.width,t.d.height,1}; info.mipLevels=1; info.arrayLayers=1;
        info.samples=VK_SAMPLE_COUNT_1_BIT; info.tiling=VK_IMAGE_TILING_OPTIMAL;
        info.usage=out.sampled?kSampledImageUsage:kImageUsage; info.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
        VkResult r=vkCreateImage(device,&info,nullptr,&out.image);
        if (r!=VK_SUCCESS) return fail(err,"create-image",r);
        VkMemoryRequirements req{}; vkGetImageMemoryRequirements(device,out.image,&req);
        if(!charge(job,req.size,err))return false;
        uint32_t type=memory_type(req.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
        if (type==UINT32_MAX) type=memory_type(req.memoryTypeBits,0);
        if (type==UINT32_MAX) return fail(err,"image-memory-type");
        VkMemoryAllocateInfo alloc{}; alloc.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc.allocationSize=req.size; alloc.memoryTypeIndex=type;
        r=vkAllocateMemory(device,&alloc,nullptr,&out.memory);
        if (r!=VK_SUCCESS) return fail(err,"allocate-image",r);
        r=vkBindImageMemory(device,out.image,out.memory,0);
        if (r!=VK_SUCCESS) return fail(err,"bind-image",r);
        VkImageViewCreateInfo view{}; view.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        view.image=out.image; view.viewType=VK_IMAGE_VIEW_TYPE_2D; view.format=info.format;
        view.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
        r=vkCreateImageView(device,&view,nullptr,&out.view);
        if (r!=VK_SUCCESS) return fail(err,"image-view",r);
        VkFramebufferCreateInfo fb{}; fb.sType=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fb.renderPass=render_pass; fb.attachmentCount=1; fb.pAttachments=&out.view;
        fb.width=t.d.width; fb.height=t.d.height; fb.layers=1;
        r=vkCreateFramebuffer(device,&fb,nullptr,&out.framebuffer);
        if (r!=VK_SUCCESS) return fail(err,"framebuffer",r);
        if (!buffer(out.staging,bytes,job,err)) return false;
        const uint8_t* src=job.plan->pools[out.pool].initial.data()+out.offset;
        if (t.d.flags&0x10) {
            uint64_t row=t.d.stride?t.d.stride:(static_cast<uint64_t>(t.d.width)*4+t.L.align-1)/t.L.align*t.L.align;
            for (uint32_t y=0;y<t.d.height;y++) std::memcpy(static_cast<uint8_t*>(out.staging.mapped)+static_cast<uint64_t>(y)*t.d.width*4,src+y*row,t.d.width*4);
        } else if (nvn_deswizzle(&t.d,0,0,src,out.staging.mapped,t.d.width*4)) return fail(err,"texture-deswizzle");
        return cache(out.staging,false,job,err);
    }
    void barrier(VkCommandBuffer cmd) {
        VkMemoryBarrier b{}; b.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        b.srcAccessMask=VK_ACCESS_MEMORY_READ_BIT|VK_ACCESS_MEMORY_WRITE_BIT;
        b.dstAccessMask=VK_ACCESS_MEMORY_READ_BIT|VK_ACCESS_MEMORY_WRITE_BIT;
        vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,0,1,&b,0,nullptr,0,nullptr);
    }
    void transition(VkCommandBuffer cmd,Image& image,VkImageLayout layout) {
        VkImageMemoryBarrier b{}; b.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        b.oldLayout=image.layout; b.newLayout=layout; b.image=image.image;
        b.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED; b.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
        b.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
        const bool initial=image.layout==VK_IMAGE_LAYOUT_UNDEFINED;
        b.srcAccessMask=initial?0:VK_ACCESS_MEMORY_READ_BIT|VK_ACCESS_MEMORY_WRITE_BIT;
        b.dstAccessMask=layout==VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL?VK_ACCESS_COLOR_ATTACHMENT_READ_BIT|VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT:
            layout==VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL?VK_ACCESS_SHADER_READ_BIT:
            layout==VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL?VK_ACCESS_TRANSFER_READ_BIT:VK_ACCESS_TRANSFER_WRITE_BIT;
        VkPipelineStageFlags dst=layout==VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL?VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT:layout==VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL?VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT:VK_PIPELINE_STAGE_TRANSFER_BIT;
        vkCmdPipelineBarrier(cmd,initial?VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT:VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,dst,0,0,nullptr,0,nullptr,1,&b);
        image.layout=layout;
    }
    bool record(Job& job,std::string* err) {
        const auto& p=*job.plan;
        job.pools.resize(p.pools.size());
        for (size_t i=0;i<p.pools.size();i++) {
            if (!buffer(job.pools[i],p.pools[i].initial.size(),job,err,job.usages[i])) return false;
            std::memcpy(job.pools[i].mapped,p.pools[i].initial.data(),p.pools[i].initial.size());
            if (!cache(job.pools[i],false,job,err)) return false;
        }
        for (auto& image:job.images) if (!create_image(image,job,err)) return false;
        job.compute_objects.resize(job.computes.size());
        for(size_t i=0;i<job.computes.size();++i) {
            const auto& dispatch=*job.computes[i];auto& objects=job.compute_objects[i];
            uint32_t uniforms=0,storage=0;
            for(const auto& d:dispatch.descriptors())if(d.type==ShaderDescriptorType::UniformBuffer)++uniforms;else ++storage;
            const VkDescriptorPoolSize sizes[]={{VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,uniforms},{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,storage}};
            VkDescriptorPoolCreateInfo pool{};pool.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;pool.maxSets=1;pool.poolSizeCount=2;pool.pPoolSizes=sizes;
            if(job.failure==Failure::DescriptorPool)return fail(err,"injected-descriptor-pool");
            VkResult r=vkCreateDescriptorPool(device,&pool,nullptr,&objects.pool);
            if(r!=VK_SUCCESS)return fail(err,"compute-descriptor-pool",r);
            context->created.fetch_add(1,std::memory_order_relaxed);
            VkDescriptorSetAllocateInfo allocate{};allocate.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;allocate.descriptorPool=objects.pool;allocate.descriptorSetCount=1;allocate.pSetLayouts=&dispatch.executable()->descriptor_layout;
            if(job.failure==Failure::DescriptorSet)return fail(err,"injected-descriptor-set");
            r=vkAllocateDescriptorSets(device,&allocate,&objects.set);
            if(r!=VK_SUCCESS)return fail(err,"compute-descriptor-set",r);
            context->created.fetch_add(1,std::memory_order_relaxed);
            std::vector<VkDescriptorBufferInfo> infos;std::vector<VkWriteDescriptorSet> writes;
            infos.reserve(dispatch.descriptors().size());writes.reserve(dispatch.descriptors().size());
            for(const auto& d:dispatch.descriptors()) {
                VkBuffer descriptor_buffer=VK_NULL_HANDLE;
                if(d.initial.empty())descriptor_buffer=job.pools[d.span.pool].buffer;
                else {
                    if(!charge(job,sizeof(Buffer),err))return false;
                    objects.support.emplace_back();auto& b=objects.support.back();
                    if(!buffer(b,d.initial.size(),job,err,VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT))return false;
                    std::memcpy(b.mapped,d.initial.data(),d.initial.size());if(!cache(b,false,job,err))return false;descriptor_buffer=b.buffer;
                }
                infos.push_back({descriptor_buffer,d.span.offset,d.span.size});
                VkWriteDescriptorSet write{};write.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;write.dstSet=objects.set;write.dstBinding=d.binding;write.descriptorCount=1;
                write.descriptorType=d.type==ShaderDescriptorType::UniformBuffer?VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;write.pBufferInfo=&infos.back();writes.push_back(write);
            }
            vkUpdateDescriptorSets(device,static_cast<uint32_t>(writes.size()),writes.data(),0,nullptr);
        }
        job.draw_objects.resize(job.draws.size());
        for(size_t i=0;i<job.draws.size();++i){
            const auto& draw=*job.draws[i];auto& objects=job.draw_objects[i];
            const VkDescriptorPoolSize sizes[]={{VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,static_cast<uint32_t>(draw.descriptors().size())},{VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,1}};
            VkDescriptorPoolCreateInfo pool{};pool.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;pool.maxSets=1;pool.poolSizeCount=draw.state().sampled?2:1;pool.pPoolSizes=sizes;
            if(job.failure==Failure::DescriptorPool)return fail(err,"injected-draw-descriptor-pool");
            VkResult result=vkCreateDescriptorPool(device,&pool,nullptr,&objects.pool);if(result!=VK_SUCCESS)return fail(err,"draw-descriptor-pool",result);context->graphics_created.fetch_add(1,std::memory_order_relaxed);
            VkDescriptorSetAllocateInfo allocate{};allocate.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;allocate.descriptorPool=objects.pool;allocate.descriptorSetCount=1;allocate.pSetLayouts=&draw.executable()->descriptor_layout;
            if(job.failure==Failure::DescriptorSet)return fail(err,"injected-draw-descriptor-set");
            result=vkAllocateDescriptorSets(device,&allocate,&objects.set);if(result!=VK_SUCCESS)return fail(err,"draw-descriptor-set",result);context->graphics_created.fetch_add(1,std::memory_order_relaxed);
            std::vector<VkDescriptorBufferInfo> infos;std::vector<VkWriteDescriptorSet> writes;infos.reserve(draw.descriptors().size());writes.reserve(draw.descriptors().size());
            for(const auto& descriptor:draw.descriptors()){
                VkBuffer buffer_handle=VK_NULL_HANDLE;
                if(descriptor.initial.empty())buffer_handle=job.pools[descriptor.span.pool].buffer;
                else{if(!charge(job,2*sizeof(Buffer),err))return false;objects.support.emplace_back();auto& support=objects.support.back();if(!buffer(support,descriptor.initial.size(),job,err,VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT))return false;std::memcpy(support.mapped,descriptor.initial.data(),descriptor.initial.size());if(!cache(support,false,job,err))return false;buffer_handle=support.buffer;}
                infos.push_back({buffer_handle,descriptor.span.offset,descriptor.span.size});VkWriteDescriptorSet write{};write.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;write.dstSet=objects.set;write.dstBinding=descriptor.binding;write.descriptorCount=1;write.descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;write.pBufferInfo=&infos.back();writes.push_back(write);
            }
            VkDescriptorImageInfo image_info{};
            if(draw.state().sampled){
                VkSamplerCreateInfo sampler{};sampler.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
                sampler.minFilter=sampler.magFilter=VK_FILTER_NEAREST;sampler.mipmapMode=VK_SAMPLER_MIPMAP_MODE_NEAREST;
                sampler.addressModeU=sampler.addressModeV=sampler.addressModeW=VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
                sampler.maxAnisotropy=1;sampler.minLod=sampler.maxLod=0;sampler.compareOp=VK_COMPARE_OP_ALWAYS;
                if(context->samplers.load(std::memory_order_relaxed)>=properties.limits.maxSamplerAllocationCount)return fail(err,"draw-sampler-device-allocation-limit");
                result=vkCreateSampler(device,&sampler,nullptr,&objects.sampler);if(result!=VK_SUCCESS)return fail(err,"draw-sampler",result);context->samplers.fetch_add(1,std::memory_order_relaxed);context->graphics_created.fetch_add(1,std::memory_order_relaxed);
                auto* image=find_image(job,&draw.state().sampled->texture);if(!image||!image->sampled)return fail(err,"draw-missing-sampled-image");
                image_info={objects.sampler,image->view,VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
                VkWriteDescriptorSet write{};write.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;write.dstSet=objects.set;write.dstBinding=4097;write.descriptorCount=1;write.descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;write.pImageInfo=&image_info;writes.push_back(write);
            }
            vkUpdateDescriptorSets(device,static_cast<uint32_t>(writes.size()),writes.data(),0,nullptr);
        }
        if(job.failure==Failure::Command)return fail(err,"injected-command-setup");
        VkCommandPoolCreateInfo cp{}; cp.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO; cp.queueFamilyIndex=family;
        VkResult result=vkCreateCommandPool(device,&cp,nullptr,&job.command_pool);
        if (result!=VK_SUCCESS) return fail(err,"command-pool",result);
        VkCommandBufferAllocateInfo ca{}; ca.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ca.commandPool=job.command_pool; ca.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY; ca.commandBufferCount=1;
        result=vkAllocateCommandBuffers(device,&ca,&job.command);
        if (result!=VK_SUCCESS) return fail(err,"command-buffer",result);
        VkCommandBufferBeginInfo bi{}; bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO; bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        result=vkBeginCommandBuffer(job.command,&bi);
        if (result!=VK_SUCCESS) return fail(err,"begin-command",result);
        for (auto& image:job.images) {
            transition(job.command,image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
            VkBufferImageCopy copy{}; copy.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1};
            copy.imageExtent={image.texture->d.width,image.texture->d.height,1};
            vkCmdCopyBufferToImage(job.command,image.staging.buffer,image.image,image.layout,1,&copy);
            job.counters.image_uploads++;
        }
        Image* rt=nullptr; int64_t stride=0;
        for (const auto& op:p.ops) {
            barrier(job.command);
            switch (op.opcode) {
            case OP_UPDATE_UB: {
                uint64_t a=0,n=0,off=0; size_t pool=0;
                std::memcpy(&a,op.payload.data(),8); std::memcpy(&n,op.payload.data()+8,8);
                if (!resolve(p,a,n,&pool,&off,err)) return false;
                vkCmdUpdateBuffer(job.command,job.pools[pool].buffer,off,n,op.payload.data()+16);
                job.counters.uniform_updates++; break;
            }
            case OP_COPY_B2B: {
                uint64_t a[3]{},so=0,dest=0; size_t sp=0,dp=0; decode(op,&a);
                if (!resolve(p,a[0],a[2],&sp,&so,err) || !resolve(p,a[1],a[2],&dp,&dest,err)) return false;
                VkBufferCopy copy{so,dest,a[2]};
                if (sp==dp && overlap(so,a[2],dest,a[2])) {
                    if(!charge(job,2*sizeof(Buffer),err))return false;
                    job.temporaries.emplace_back();
                    if (!buffer(job.temporaries.back(),a[2],job,err)) return false;
                    VkBufferCopy first{so,0,a[2]},second{0,dest,a[2]};
                    vkCmdCopyBuffer(job.command,job.pools[sp].buffer,job.temporaries.back().buffer,1,&first);
                    barrier(job.command);
                    vkCmdCopyBuffer(job.command,job.temporaries.back().buffer,job.pools[dp].buffer,1,&second);
                } else vkCmdCopyBuffer(job.command,job.pools[sp].buffer,job.pools[dp].buffer,1,&copy);
                job.counters.buffer_copies++; break;
            }
            case OP_SET_RT: { p_set_rt r{}; decode(op,&r); rt=find_image(job,r.color[0]); break; }
            case OP_CLEAR_COLOR: {
                p_clear_color c{}; decode(op,&c);
                if(!rt)return fail(err,"record-missing-validated-render-target");
                transition(job.command,*rt,VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);
                VkRenderPassBeginInfo begin{}; begin.sType=VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
                begin.renderPass=render_pass; begin.framebuffer=rt->framebuffer;
                begin.renderArea.extent={rt->texture->d.width,rt->texture->d.height};
                vkCmdBeginRenderPass(job.command,&begin,VK_SUBPASS_CONTENTS_INLINE);
                VkClearAttachment clear{}; clear.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
                std::memcpy(clear.clearValue.color.float32,c.rgba,sizeof(c.rgba));
                VkClearRect rect{}; rect.rect.extent=begin.renderArea.extent; rect.layerCount=1;
                vkCmdClearAttachments(job.command,1,&clear,1,&rect);
                vkCmdEndRenderPass(job.command); job.counters.render_passes++; break;
            }
            case OP_COPY_B2T: case OP_COPY_T2B: {
                p_copy_b2t c{}; decode(op,&c); auto* image=find_image(job,c.tex);
                if(!image)return fail(err,"record-missing-validated-image");
                uint64_t row=0,n=0,off=0; size_t pool=0;
                if (!region(c,stride,&row,&n,err) || !resolve(p,c.src,n,&pool,&off,err)) return false;
                VkBufferImageCopy copy{}; copy.bufferOffset=off; copy.bufferRowLength=static_cast<uint32_t>(row/4);
                copy.bufferImageHeight=static_cast<uint32_t>(c.r.height);
                copy.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1};
                copy.imageOffset={c.r.xoffset,c.r.yoffset,0};
                copy.imageExtent={static_cast<uint32_t>(c.r.width),static_cast<uint32_t>(c.r.height),1};
                if (op.opcode==OP_COPY_B2T) {
                    transition(job.command,*image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
                    vkCmdCopyBufferToImage(job.command,job.pools[pool].buffer,image->image,image->layout,1,&copy);
                    job.counters.image_uploads++;
                } else {
                    transition(job.command,*image,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
                    vkCmdCopyImageToBuffer(job.command,image->image,image->layout,job.pools[pool].buffer,1,&copy);
                    job.counters.image_downloads++;
                }
                break;
            }
            case OP_DRAW:case OP_DRAW_IDX: {
                const auto& draw=*job.draws[op.draw_index];const auto& executable=*draw.executable();auto* target=find_image(job,draw.state().target);
                if(!target)return fail(err,"record-missing-validated-draw-target");
                if(!draw.call().count){++job.counters.zero_draws;break;}
                if(draw.state().sampled){auto* source=find_image(job,&draw.state().sampled->texture);if(!source||!source->sampled)return fail(err,"record-missing-sampled-image");transition(job.command,*source,VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);}
                transition(job.command,*target,VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);
                VkRenderPassBeginInfo begin{};begin.sType=VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;begin.renderPass=render_pass;begin.framebuffer=target->framebuffer;begin.renderArea.extent={target->texture->d.width,target->texture->d.height};
                vkCmdBeginRenderPass(job.command,&begin,VK_SUBPASS_CONTENTS_INLINE);
                vkCmdBindPipeline(job.command,VK_PIPELINE_BIND_POINT_GRAPHICS,executable.pipeline);
                vkCmdBindDescriptorSets(job.command,VK_PIPELINE_BIND_POINT_GRAPHICS,executable.pipeline_layout,0,1,&job.draw_objects[op.draw_index].set,0,nullptr);
                const auto& values=draw.state().viewport;VkViewport viewport{values[0],values[1],values[2],values[3],draw.state().depth_near,draw.state().depth_far};vkCmdSetViewport(job.command,0,1,&viewport);
                const auto& scissor=draw.state().scissor;VkRect2D rectangle{{scissor.x,scissor.y},{uint32_t(scissor.w),uint32_t(scissor.h)}};vkCmdSetScissor(job.command,0,1,&rectangle);
                const auto& vertex=draw.vertex();const VkDeviceSize offset=vertex.offset;vkCmdBindVertexBuffers(job.command,0,1,&job.pools[vertex.pool].buffer,&offset);
                const auto& call=draw.call();
                if(call.indexed){const auto& indices=draw.indices();vkCmdBindIndexBuffer(job.command,job.pools[indices.pool].buffer,indices.offset,VK_INDEX_TYPE_UINT16);vkCmdDrawIndexed(job.command,uint32_t(call.count),1,0,call.base_vertex,uint32_t(call.base_instance));++job.counters.indexed_draws;}
                else vkCmdDraw(job.command,uint32_t(call.count),1,uint32_t(call.first),0);
                ++job.counters.graphics_draws;vkCmdEndRenderPass(job.command);++job.counters.render_passes;break;
            }
            case OP_DISPATCH: {
                const auto& dispatch=*job.computes[op.compute_index];const auto& executable=*dispatch.executable();
                vkCmdBindPipeline(job.command,VK_PIPELINE_BIND_POINT_COMPUTE,executable.pipeline);
                vkCmdBindDescriptorSets(job.command,VK_PIPELINE_BIND_POINT_COMPUTE,executable.pipeline_layout,0,1,&job.compute_objects[op.compute_index].set,0,nullptr);
                const auto& groups=dispatch.groups();
                // The S8 Mali1.0 driver loses the device on a zero workgroup
                // count. The command has zero invocations in every dimension;
                // omit only that no-op after all bindings/pipeline checks. All
                // surrounding barriers, transfers and real fence remain live.
                // Vulkan1.0 global workgroups are X*Y*Z:
                // https://docs.vulkan.org/refpages/latest/refpages/source/vkCmdDispatch.html
                if(groups[0]&&groups[1]&&groups[2]){vkCmdDispatch(job.command,groups[0],groups[1],groups[2]);job.counters.compute_dispatches++;}
                else job.counters.compute_zero_workgroups++;
                break;
            }
            case OP_COPY_STRIDE: { p_copy_stride c{}; decode(op,&c); stride=c.stride; break; }
            default: break; // All operations were exhaustively admitted above.
            }
        }
        for (auto& image:job.images) if (image.written) {
            transition(job.command,image,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
            VkBufferImageCopy copy{}; copy.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1};
            copy.imageExtent={image.texture->d.width,image.texture->d.height,1};
            vkCmdCopyImageToBuffer(job.command,image.image,image.layout,image.staging.buffer,1,&copy);
            job.counters.image_downloads++;
        }
        VkMemoryBarrier host{}; host.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        host.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT|VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT|VK_ACCESS_SHADER_WRITE_BIT;
        host.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
        vkCmdPipelineBarrier(job.command,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,VK_PIPELINE_STAGE_HOST_BIT,0,1,&host,0,nullptr,0,nullptr);
        result=vkEndCommandBuffer(job.command);
        if (result!=VK_SUCCESS) return fail(err,"end-command",result);
        VkFenceCreateInfo fi{}; fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        result=vkCreateFence(device,&fi,nullptr,&job.fence);
        return result==VK_SUCCESS || fail(err,"create-fence",result);
    }
    bool readbacks(Job& job,std::string* err) {
        for (size_t i=0;i<job.pools.size();i++) if (!job.writes[i].empty()) {
            if (!cache(job.pools[i],true,job,err)) return false;
            for (const auto& range:job.writes[i]) {
                SubmitWrite write; write.address=job.plan->pools[i].address+range.off;
                const auto* data=static_cast<const uint8_t*>(job.pools[i].mapped)+range.off;
                write.bytes.assign(data,data+range.size); job.outputs.push_back(std::move(write));
            }
        }
        for (auto& image:job.images) if (image.written) {
            if (!cache(image.staging,true,job,err)) return false;
            const auto& t=*image.texture; const auto* linear=static_cast<const uint8_t*>(image.staging.mapped);
            const uint64_t row=static_cast<uint64_t>(t.d.width)*4;
            // Publish only real texel bytes, preserving NVN padding and holes.
            for (uint32_t y=0;y<t.d.height;y++) for (uint64_t x=0;x<row;x+=16) {
                const uint64_t count=std::min<uint64_t>(16,row-x);
                uint64_t offset=0;
                if (t.d.flags&0x10) {
                    uint64_t pitch=t.d.stride?t.d.stride:(row+t.L.align-1)/t.L.align*t.L.align;
                    offset=y*pitch+x;
                } else {
                    unsigned th=0,td=0; nvn_tex_level_tiles(&t.d,0,&th,&td);
                    offset=nvn_bl_offset(static_cast<uint32_t>(x),y,0,static_cast<uint32_t>(row),t.d.height,th,td);
                }
                if (offset>t.L.size || count>t.L.size-offset) return fail(err,"texture-readback-layout-bounds");
                SubmitWrite write; write.address=reinterpret_cast<uint64_t>(t.mem)+offset;
                write.bytes.assign(linear+y*row+x,linear+y*row+x+count);
                job.outputs.push_back(std::move(write));
            }
        }
        return true;
    }
    void run() {
        for (;;) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock,[this]{return stop||!jobs.empty();});
                if(jobs.empty()){if(stop)return;continue;}
                job=jobs.front();jobs.pop_front();
            }
            auto wrapped=[&] {std::lock_guard<std::mutex> lock(mutex);return job->failure==Failure::UnprovenTermination&&termination_wrapper;};
            // The wrapper returns an error without reporting a successful real
            // fence. It never fabricates completion or authorizes destruction.
            VkResult result=wrapped()?VK_ERROR_UNKNOWN:vkWaitForFences(device,1,&job->fence,VK_TRUE,UINT64_MAX);
            bool terminal=result==VK_SUCCESS||result==VK_ERROR_DEVICE_LOST;
            bool poisoned=result!=VK_SUCCESS;
            std::string error=poisoned?"gpu-fence:"+std::to_string(result):std::string{};
            VkErrorKind kind=poisoned?VkErrorKind::Device:VkErrorKind::None;
            if(!terminal) {
                // Finish any already-entered submit, then close admission before
                // device-idle touches the queue. The actual wait holds neither
                // lock; Vulkan's queue external synchronization is still met.
                {
                    std::lock_guard<std::mutex> serial(submit_mutex);
                    std::lock_guard<std::mutex> lock(mutex);
                    quarantined=true;if(!first_failure)first_failure=job->id;
                    sticky="unproven-termination:fence="+std::to_string(result);
                    sticky_kind=VkErrorKind::UnprovenTermination;
                    outcomes.at(job->id).error=sticky;outcomes.at(job->id).kind=sticky_kind;cv.notify_all();
                }
                const VkResult idle=wrapped()?VK_ERROR_UNKNOWN:vkDeviceWaitIdle(device);
                terminal=idle==VK_SUCCESS||idle==VK_ERROR_DEVICE_LOST;
                if(idle==VK_ERROR_DEVICE_LOST)result=idle;
                if(!terminal) {
                    std::lock_guard<std::mutex> lock(mutex);
                    quarantined=true;if(!first_failure)first_failure=job->id;
                    sticky="unproven-termination:fence="+std::to_string(result)+";idle="+std::to_string(idle);
                    sticky_kind=VkErrorKind::UnprovenTermination;
                    outcomes.at(job->id).error=sticky;outcomes.at(job->id).kind=sticky_kind;cv.notify_all();
                }
            }
            while(!terminal) {
                {std::unique_lock<std::mutex> lock(mutex);cv.wait_for(lock,std::chrono::milliseconds(100));}
                if(wrapped())continue;
                // No engine/core/resource lock is held during recovery. A
                // timeout is not terminal; unsuccessful idle retains the graph.
                result=vkGetFenceStatus(device,job->fence);
                terminal=result==VK_SUCCESS||result==VK_ERROR_DEVICE_LOST;
                if(!terminal) {
                    const VkResult idle=vkDeviceWaitIdle(device);
                    terminal=idle==VK_SUCCESS||idle==VK_ERROR_DEVICE_LOST;
                    if(idle==VK_ERROR_DEVICE_LOST)result=idle;
                }
            }
            bool ok=!poisoned;
            {
                std::lock_guard<std::mutex> lock(mutex);
                if(ok&&(lost||first_failure)){ok=false;error="failed-submission-prefix";kind=VkErrorKind::Device;}
            }
            if(ok&&job->failure==Failure::DeviceLost){ok=false;error="injected-device-lost-after-gpu-fence";kind=VkErrorKind::Device;}
            if(ok) {
                try {
                    if(job->failure==Failure::Readback){ok=false;error="injected-readback-failure";}
                    else ok=readbacks(*job,&error);
                }catch(...){ok=false;error="readback-metadata-allocation";}
                if(!ok)kind=VkErrorKind::Device;
            }
            if(ok) {
                std::unique_lock<std::mutex> lock(mutex);entered=true;cv.notify_all();
                cv.wait(lock,[this]{return !hold||stop;});entered=false;
            }
            if(ok&&job->failure==Failure::Publication){ok=false;error="injected-publication-refusal";kind=VkErrorKind::Publication;}
            if(ok) {
                try{ok=job->publish(job->outputs,job->plan->events,error);}
                catch(...){ok=false;error="publication-exception";}
                if(!ok){kind=VkErrorKind::Publication;if(error.empty())error="publication-refused";}
            }
            cleanup(*job);job->compute_objects.clear();job->computes.clear();job->draw_objects.clear();job->draws.clear();
            job->outputs.clear();job->publish={};job->plan.reset();
            {
                std::lock_guard<std::mutex> lock(mutex);
                if(result==VK_ERROR_DEVICE_LOST||job->failure==Failure::DeviceLost)lost=true;
                quarantined=false;
                auto& outcome=outcomes.at(job->id);outcome.state=ok?VkSubmitState::Completed:VkSubmitState::Failed;
                outcome.error=error;outcome.kind=kind;
                if(ok)totals.completed++;
                else {totals.failed++;if(!first_failure)first_failure=job->id;if(sticky.empty()||sticky_kind==VkErrorKind::UnprovenTermination){sticky=error;sticky_kind=kind;}}
                while(completed<last){auto next=outcomes.find(completed+1);if(next==outcomes.end()||next->second.state!=VkSubmitState::Completed)break;++completed;}
                totals.flushes+=job->counters.flushes;totals.invalidates+=job->counters.invalidates;
                retained_bytes-=job->ownership_bytes;
                retained.erase(std::remove(retained.begin(),retained.end(),job),retained.end());cv.notify_all();
            }
        }
    }
};

NvnVkEngine::NvnVkEngine():p_(std::make_shared<Impl>()) {}
NvnVkEngine::~NvnVkEngine() {
    if (!p_) return;
    {
        std::lock_guard<std::mutex> lock(p_->mutex); p_->hold=false; p_->stop=true; p_->cv.notify_all();
    }
    const auto terminal=drain();
    if(p_->worker.joinable()) {
        if(terminal.state==VkSubmitState::Pending)p_->worker.detach();
        else p_->worker.join();
    }
}
bool NvnVkEngine::initialize(std::string* error) {
    std::lock_guard<std::mutex> serial(p_->submit_mutex);
    if (p_->initialized) return true;
    uint32_t count=0; VkResult result=vkEnumerateInstanceLayerProperties(&count,nullptr);
    if (result!=VK_SUCCESS) return p_->fail(error,"enumerate-layers",result);
    std::vector<VkLayerProperties> layers(count);
    result=vkEnumerateInstanceLayerProperties(&count,layers.data());
    if (result!=VK_SUCCESS) return p_->fail(error,"enumerate-layers",result);
    p_->totals.validation_available=std::any_of(layers.begin(),layers.end(),[](const auto& l){return std::strcmp(l.layerName,"VK_LAYER_KHRONOS_validation")==0;});
    std::vector<VkExtensionProperties> extensions;
    auto get_extensions=[&](const char* layer) {
        uint32_t n=0;
        if (vkEnumerateInstanceExtensionProperties(layer,&n,nullptr)!=VK_SUCCESS) return;
        std::vector<VkExtensionProperties> found(n);
        if (vkEnumerateInstanceExtensionProperties(layer,&n,found.data())==VK_SUCCESS)
            extensions.insert(extensions.end(),found.begin(),found.end());
    };
    get_extensions(nullptr);
    if (p_->totals.validation_available) get_extensions("VK_LAYER_KHRONOS_validation");
    p_->totals.debug_utils_available=std::any_of(extensions.begin(),extensions.end(),[](const auto& e){return std::strcmp(e.extensionName,VK_EXT_DEBUG_UTILS_EXTENSION_NAME)==0;});
    const char* layer="VK_LAYER_KHRONOS_validation"; const char* extension=VK_EXT_DEBUG_UTILS_EXTENSION_NAME;
    VkApplicationInfo app{}; app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO; app.pApplicationName="D2R NVN Vulkan"; app.apiVersion=VK_API_VERSION_1_0;
    VkInstanceCreateInfo create{}; create.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO; create.pApplicationInfo=&app;
    if (p_->totals.validation_available) { create.enabledLayerCount=1; create.ppEnabledLayerNames=&layer; }
    if (p_->totals.debug_utils_available) { create.enabledExtensionCount=1; create.ppEnabledExtensionNames=&extension; }
    result=vkCreateInstance(&create,nullptr,&p_->instance);
    if (result!=VK_SUCCESS) return p_->fail(error,"create-instance",result);
    if (p_->totals.debug_utils_available) {
        auto make=reinterpret_cast<PFN_vkCreateDebugUtilsMessengerEXT>(vkGetInstanceProcAddr(p_->instance,"vkCreateDebugUtilsMessengerEXT"));
        p_->destroy_messenger=reinterpret_cast<PFN_vkDestroyDebugUtilsMessengerEXT>(vkGetInstanceProcAddr(p_->instance,"vkDestroyDebugUtilsMessengerEXT"));
        VkDebugUtilsMessengerCreateInfoEXT debug{}; debug.sType=VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
        debug.messageSeverity=VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT|VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT;
        debug.messageType=VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT|VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT|VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;
        debug.pfnUserCallback=DeviceContext::debug; debug.pUserData=p_->context.get();
        if (!make || !p_->destroy_messenger || make(p_->instance,&debug,nullptr,&p_->messenger)!=VK_SUCCESS)
            return p_->fail(error,"debug-utils-messenger");
    }
    p_->totals.validation_status=p_->totals.validation_available?
        (p_->messenger?"ENABLED":"ENABLED_NO_MESSAGE_CAPTURE"):"UNAVAILABLE";
    result=vkEnumeratePhysicalDevices(p_->instance,&count,nullptr);
    if (result!=VK_SUCCESS || !count) return p_->fail(error,"enumerate-devices",result);
    std::vector<VkPhysicalDevice> devices(count);
    result=vkEnumeratePhysicalDevices(p_->instance,&count,devices.data());
    if (result!=VK_SUCCESS) return p_->fail(error,"enumerate-devices",result);
    for (auto physical:devices) {
        uint32_t n=0; vkGetPhysicalDeviceQueueFamilyProperties(physical,&n,nullptr);
        std::vector<VkQueueFamilyProperties> queues(n); vkGetPhysicalDeviceQueueFamilyProperties(physical,&n,queues.data());
        for (uint32_t i=0;i<n;i++) if (queues[i].queueCount && (queues[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)) {
            VkImageFormatProperties image{};
            if (vkGetPhysicalDeviceImageFormatProperties(physical,VK_FORMAT_R8G8B8A8_UNORM,VK_IMAGE_TYPE_2D,VK_IMAGE_TILING_OPTIMAL,kImageUsage,0,&image)!=VK_SUCCESS || !(image.sampleCounts&VK_SAMPLE_COUNT_1_BIT)) continue;
            VkFormatProperties format{}; vkGetPhysicalDeviceFormatProperties(physical,VK_FORMAT_R8G8B8A8_UNORM,&format);
            if (!(format.optimalTilingFeatures&VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT)) continue;
            p_->physical=physical; p_->family=i; p_->queue_flags=queues[i].queueFlags;
            p_->image_properties=image; break;
        }
        if (p_->physical) break;
    }
    if (!p_->physical) return p_->fail(error,"no-graphics-queue-rgba8-combination");
    VkFormatProperties sampled_format{};vkGetPhysicalDeviceFormatProperties(p_->physical,VK_FORMAT_R8G8B8A8_UNORM,&sampled_format);
    p_->rgba8_sampled_supported=(sampled_format.optimalTilingFeatures&VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT)&&
        vkGetPhysicalDeviceImageFormatProperties(p_->physical,VK_FORMAT_R8G8B8A8_UNORM,VK_IMAGE_TYPE_2D,VK_IMAGE_TILING_OPTIMAL,kSampledImageUsage,0,&p_->sampled_image_properties)==VK_SUCCESS&&
        (p_->sampled_image_properties.sampleCounts&VK_SAMPLE_COUNT_1_BIT);
    vkGetPhysicalDeviceProperties(p_->physical,&p_->properties);
    vkGetPhysicalDeviceFeatures(p_->physical,&p_->supported_features);
    vkGetPhysicalDeviceMemoryProperties(p_->physical,&p_->memory_properties);
    VkFormatProperties vertex_format{};vkGetPhysicalDeviceFormatProperties(p_->physical,VK_FORMAT_R32G32B32A32_SFLOAT,&vertex_format);p_->float4_vertex_supported=(vertex_format.bufferFeatures&VK_FORMAT_FEATURE_VERTEX_BUFFER_BIT)!=0;
    // Extension support is an inventory; it never enables an extension. A
    // failed/incomplete enumeration leaves a conservative empty known subset.
    uint32_t extension_count=0;
    if(vkEnumerateDeviceExtensionProperties(p_->physical,nullptr,&extension_count,nullptr)==VK_SUCCESS && extension_count<=4096) {
        std::vector<VkExtensionProperties> found(extension_count);
        if(vkEnumerateDeviceExtensionProperties(p_->physical,nullptr,&extension_count,found.data())==VK_SUCCESS && extension_count<=found.size()) {
            for(uint32_t i=0;i<extension_count;++i)p_->supported_extensions.emplace_back(found[i].extensionName);
            std::sort(p_->supported_extensions.begin(),p_->supported_extensions.end());
            p_->supported_extensions.erase(std::unique(p_->supported_extensions.begin(),p_->supported_extensions.end()),p_->supported_extensions.end());
        }
    }
    float priority=1; VkDeviceQueueCreateInfo qi{}; qi.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qi.queueFamilyIndex=p_->family; qi.queueCount=1; qi.pQueuePriorities=&priority;
    VkDeviceCreateInfo di{}; di.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO; di.queueCreateInfoCount=1; di.pQueueCreateInfos=&qi;
    result=vkCreateDevice(p_->physical,&di,nullptr,&p_->device);
    if (result!=VK_SUCCESS) return p_->fail(error,"create-device",result);
    p_->requested_api=app.apiVersion;
    // These facts mirror the actual creation inputs. C2 must extend this capture
    // when introducing Features2 chains, extension features or subgroup queries.
    p_->created_features=di.pEnabledFeatures?*di.pEnabledFeatures:VkPhysicalDeviceFeatures{};
    for(uint32_t i=0;i<di.enabledExtensionCount;++i)p_->created_extensions.emplace_back(di.ppEnabledExtensionNames[i]);
    vkGetDeviceQueue(p_->device,p_->family,0,&p_->queue);
    VkAttachmentDescription attachment{}; attachment.format=VK_FORMAT_R8G8B8A8_UNORM;
    attachment.samples=VK_SAMPLE_COUNT_1_BIT; attachment.loadOp=VK_ATTACHMENT_LOAD_OP_LOAD;
    attachment.storeOp=VK_ATTACHMENT_STORE_OP_STORE; attachment.stencilLoadOp=VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    attachment.stencilStoreOp=VK_ATTACHMENT_STORE_OP_DONT_CARE;
    attachment.initialLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL; attachment.finalLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    VkAttachmentReference reference{0,VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkSubpassDescription subpass{}; subpass.pipelineBindPoint=VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount=1; subpass.pColorAttachments=&reference;
    VkRenderPassCreateInfo rp{}; rp.sType=VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rp.attachmentCount=1; rp.pAttachments=&attachment; rp.subpassCount=1; rp.pSubpasses=&subpass;
    result=vkCreateRenderPass(p_->device,&rp,nullptr,&p_->render_pass);
    if (result!=VK_SUCCESS) return p_->fail(error,"render-pass",result);
    p_->totals.api_version=p_->properties.apiVersion; p_->totals.driver_version=p_->properties.driverVersion;
    p_->totals.vendor_id=p_->properties.vendorID; p_->totals.device_id=p_->properties.deviceID;
    p_->totals.device_name=p_->properties.deviceName; p_->totals.noncoherent_atom_size=p_->properties.limits.nonCoherentAtomSize;
    p_->initialized=true; p_->worker=std::thread([owner=p_]{owner->run();}); return true;
}
ShaderDeviceContract NvnVkEngine::shader_device_contract() const {
    // Initialization uses submit_mutex. Worker terminal state uses mutex. Keep
    // the same lock order as submit and never wait for GPU work under either.
    std::lock_guard<std::mutex> serial(p_->submit_mutex);
    std::lock_guard<std::mutex> lock(p_->mutex);
    if(p_->stop||p_->lost||p_->first_failure||p_->quarantined)return {};
    return p_->contract();
}
DrawDeviceContract NvnVkEngine::draw_device_contract() const {
    std::lock_guard<std::mutex> serial(p_->submit_mutex);std::lock_guard<std::mutex> lock(p_->mutex);
    if(p_->stop||p_->lost||p_->first_failure||p_->quarantined)return {};return p_->draw_contract();
}
bool NvnVkEngine::prepare_compute_program(std::shared_ptr<const ResolvedProgram> program,
    std::shared_ptr<const VkComputeProgram>* out,std::string* error) {
    if(out)out->reset();
    if(!out||!program)return p_->fail(error,"compute-missing-program-output");
    std::lock_guard<std::mutex> serial(p_->submit_mutex);
    Failure injection=Failure::None;
    {std::lock_guard<std::mutex> lock(p_->mutex);
     if(!p_->initialized||p_->stop||p_->lost||p_->first_failure||p_->quarantined)return p_->fail(error,"engine-not-ready-or-terminal-failure");
     if(p_->injection>=Failure::ShaderModule&&p_->injection<=Failure::Pipeline){injection=p_->injection;p_->injection=Failure::None;}}
    if(!check_compute_access_program(*program,error)||!check_shader_program_device(*program,p_->contract(),error))return false;
    try {
        auto candidate=std::make_shared<VkComputeProgram>();candidate->context=p_->context;candidate->program=std::move(program);
        const auto& artifact=*candidate->program->stages()[0];
        std::vector<VkDescriptorSetLayoutBinding> bindings;
        for(const auto& d:artifact.descriptors())bindings.push_back({d.binding,
            d.type==ShaderDescriptorType::UniformBuffer?VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
            1,VK_SHADER_STAGE_COMPUTE_BIT,nullptr});
        VkDescriptorSetLayoutCreateInfo layout{};layout.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
        layout.bindingCount=static_cast<uint32_t>(bindings.size());layout.pBindings=bindings.data();
        if(injection==Failure::DescriptorLayout)return p_->fail(error,"injected-compute-descriptor-layout");
        VkResult r=vkCreateDescriptorSetLayout(p_->device,&layout,nullptr,&candidate->descriptor_layout);
        if(r!=VK_SUCCESS)return p_->fail(error,"compute-descriptor-layout",r);
        p_->context->created.fetch_add(1,std::memory_order_relaxed);
        VkPipelineLayoutCreateInfo pipeline_layout{};pipeline_layout.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
        pipeline_layout.setLayoutCount=1;pipeline_layout.pSetLayouts=&candidate->descriptor_layout;
        if(injection==Failure::PipelineLayout)return p_->fail(error,"injected-compute-pipeline-layout");
        r=vkCreatePipelineLayout(p_->device,&pipeline_layout,nullptr,&candidate->pipeline_layout);
        if(r!=VK_SUCCESS)return p_->fail(error,"compute-pipeline-layout",r);
        p_->context->created.fetch_add(1,std::memory_order_relaxed);
        VkShaderModuleCreateInfo module{};module.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        module.codeSize=artifact.words().size()*4;module.pCode=artifact.words().data();
        if(injection==Failure::ShaderModule)return p_->fail(error,"injected-compute-shader-module");
        r=vkCreateShaderModule(p_->device,&module,nullptr,&candidate->module);
        if(r!=VK_SUCCESS)return p_->fail(error,"compute-shader-module",r);
        p_->context->created.fetch_add(1,std::memory_order_relaxed);
        VkComputePipelineCreateInfo pipeline{};pipeline.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
        pipeline.stage.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;pipeline.stage.stage=VK_SHADER_STAGE_COMPUTE_BIT;
        pipeline.stage.module=candidate->module;pipeline.stage.pName=artifact.profile().entry.c_str();pipeline.layout=candidate->pipeline_layout;
        if(injection==Failure::Pipeline)return p_->fail(error,"injected-compute-pipeline");
        r=vkCreateComputePipelines(p_->device,VK_NULL_HANDLE,1,&pipeline,nullptr,&candidate->pipeline);
        if(candidate->pipeline)p_->context->created.fetch_add(1,std::memory_order_relaxed);
        if(r!=VK_SUCCESS)return p_->fail(error,"compute-pipeline",r);
        *out=std::move(candidate);if(error)error->clear();return true;
    }catch(...){return p_->fail(error,"compute-program-allocation");}
}
bool NvnVkEngine::prepare_graphics_program(std::shared_ptr<const ResolvedProgram> program,
    std::shared_ptr<const VkGraphicsProgram>* out,std::string* error){
    if(out)out->reset();if(!out||!program)return p_->fail(error,"draw-missing-program-output");
    std::lock_guard<std::mutex> serial(p_->submit_mutex);Failure injection=Failure::None;
    {std::lock_guard<std::mutex> lock(p_->mutex);if(!p_->initialized||p_->stop||p_->lost||p_->first_failure||p_->quarantined)return p_->fail(error,"engine-not-ready-or-terminal-failure");if(p_->injection>=Failure::ShaderModule&&p_->injection<=Failure::Pipeline){injection=p_->injection;p_->injection=Failure::None;}}
    const auto facts=p_->draw_contract();
    if(!check_draw_program(*program,error)||!check_shader_program_device(*program,facts.shader,error))return false;
    if(!facts.rgba8_attachment||!facts.float4_vertex||facts.vertex_attributes<1||facts.vertex_bindings<1||facts.vertex_stride<16)return p_->fail(error,"draw-device-format-vertex-limits");
    try{
        auto candidate=std::make_shared<VkGraphicsProgram>();candidate->context=p_->context;candidate->program=std::move(program);
        std::vector<VkDescriptorSetLayoutBinding> bindings;
        for(const auto& stage:candidate->program->stages()){const auto ordinal=static_cast<uint32_t>(stage->key().stage);const VkShaderStageFlags flag=ordinal==0?VK_SHADER_STAGE_VERTEX_BIT:VK_SHADER_STAGE_FRAGMENT_BIT;for(const auto& descriptor:stage->descriptors())bindings.push_back({descriptor.binding,descriptor.type==ShaderDescriptorType::CombinedImageSampler?VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,1,flag,nullptr});}
        VkDescriptorSetLayoutCreateInfo layout{};layout.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;layout.bindingCount=static_cast<uint32_t>(bindings.size());layout.pBindings=bindings.data();
        if(injection==Failure::DescriptorLayout)return p_->fail(error,"injected-graphics-descriptor-layout");
        VkResult result=vkCreateDescriptorSetLayout(p_->device,&layout,nullptr,&candidate->descriptor_layout);if(result!=VK_SUCCESS)return p_->fail(error,"graphics-descriptor-layout",result);p_->context->graphics_created.fetch_add(1,std::memory_order_relaxed);
        VkPipelineLayoutCreateInfo pipeline_layout{};pipeline_layout.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;pipeline_layout.setLayoutCount=1;pipeline_layout.pSetLayouts=&candidate->descriptor_layout;
        if(injection==Failure::PipelineLayout)return p_->fail(error,"injected-graphics-pipeline-layout");
        result=vkCreatePipelineLayout(p_->device,&pipeline_layout,nullptr,&candidate->pipeline_layout);if(result!=VK_SUCCESS)return p_->fail(error,"graphics-pipeline-layout",result);p_->context->graphics_created.fetch_add(1,std::memory_order_relaxed);
        std::array<VkPipelineShaderStageCreateInfo,2> stages{};
        for(const auto& stage:candidate->program->stages()){const auto ordinal=static_cast<uint32_t>(stage->key().stage);VkShaderModuleCreateInfo module{};module.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;module.codeSize=stage->words().size()*4;module.pCode=stage->words().data();
            if(injection==Failure::ShaderModule)return p_->fail(error,"injected-graphics-shader-module");
            result=vkCreateShaderModule(p_->device,&module,nullptr,&candidate->modules[ordinal]);if(result!=VK_SUCCESS)return p_->fail(error,"graphics-shader-module",result);p_->context->graphics_created.fetch_add(1,std::memory_order_relaxed);
            auto& shader=stages[ordinal];shader.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;shader.stage=ordinal==0?VK_SHADER_STAGE_VERTEX_BIT:VK_SHADER_STAGE_FRAGMENT_BIT;shader.module=candidate->modules[ordinal];shader.pName=stage->profile().entry.c_str();
        }
        const bool original=shader_identity_kind(candidate->program->stages()[0]->key())==ShaderIdentityKind::OriginalMaxwell;
        const bool textured_original=candidate->program->stages()[0]->profile().name=="android-vulkan10-original-embedded-texture-v1";
        if(textured_original&&(facts.vertex_attributes<3||facts.vertex_stride<48||facts.vertex_attribute_offset<32))return p_->fail(error,"original-sampled-device-vertex-limits");
        if(original&&(facts.vertex_attributes<2||facts.vertex_stride<32||facts.vertex_attribute_offset<16))return p_->fail(error,"original-draw-device-vertex-limits");
        VkVertexInputBindingDescription binding{0,textured_original?48u:original?32u:16u,VK_VERTEX_INPUT_RATE_VERTEX};const VkVertexInputAttributeDescription attributes[]={{0,0,VK_FORMAT_R32G32B32A32_SFLOAT,0},{1,0,VK_FORMAT_R32G32B32A32_SFLOAT,16},{2,0,VK_FORMAT_R32G32B32A32_SFLOAT,32}};
        VkPipelineVertexInputStateCreateInfo vertex{};vertex.sType=VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;vertex.vertexBindingDescriptionCount=1;vertex.pVertexBindingDescriptions=&binding;vertex.vertexAttributeDescriptionCount=textured_original?3:original?2:1;vertex.pVertexAttributeDescriptions=attributes;
        VkPipelineInputAssemblyStateCreateInfo assembly{};assembly.sType=VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;assembly.topology=VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
        VkPipelineViewportStateCreateInfo viewport{};viewport.sType=VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;viewport.viewportCount=1;viewport.scissorCount=1;
        VkPipelineRasterizationStateCreateInfo raster{};raster.sType=VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;raster.polygonMode=VK_POLYGON_MODE_FILL;raster.cullMode=VK_CULL_MODE_NONE;raster.frontFace=VK_FRONT_FACE_COUNTER_CLOCKWISE;raster.lineWidth=1;
        VkPipelineMultisampleStateCreateInfo sample{};sample.sType=VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;sample.rasterizationSamples=VK_SAMPLE_COUNT_1_BIT;
        VkPipelineDepthStencilStateCreateInfo depth{};depth.sType=VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO;
        VkPipelineColorBlendAttachmentState attachment{};attachment.colorWriteMask=VK_COLOR_COMPONENT_R_BIT|VK_COLOR_COMPONENT_G_BIT|VK_COLOR_COMPONENT_B_BIT|VK_COLOR_COMPONENT_A_BIT;
        VkPipelineColorBlendStateCreateInfo blend{};blend.sType=VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;blend.attachmentCount=1;blend.pAttachments=&attachment;
        const VkDynamicState dynamic_states[]={VK_DYNAMIC_STATE_VIEWPORT,VK_DYNAMIC_STATE_SCISSOR};VkPipelineDynamicStateCreateInfo dynamic{};dynamic.sType=VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;dynamic.dynamicStateCount=2;dynamic.pDynamicStates=dynamic_states;
        VkGraphicsPipelineCreateInfo create{};create.sType=VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;create.stageCount=2;create.pStages=stages.data();create.pVertexInputState=&vertex;create.pInputAssemblyState=&assembly;create.pViewportState=&viewport;create.pRasterizationState=&raster;create.pMultisampleState=&sample;create.pDepthStencilState=&depth;create.pColorBlendState=&blend;create.pDynamicState=&dynamic;create.layout=candidate->pipeline_layout;create.renderPass=p_->render_pass;create.basePipelineIndex=-1;
        if(injection==Failure::Pipeline)return p_->fail(error,"injected-graphics-pipeline");
        result=vkCreateGraphicsPipelines(p_->device,VK_NULL_HANDLE,1,&create,nullptr,&candidate->pipeline);if(candidate->pipeline)p_->context->graphics_created.fetch_add(1,std::memory_order_relaxed);if(result!=VK_SUCCESS)return p_->fail(error,"graphics-pipeline",result);
        *out=std::move(candidate);if(error)error->clear();return true;
    }catch(const std::bad_alloc&){return p_->fail(error,"graphics-program-allocation");}
}
VkSubmitResult NvnVkEngine::submit(std::shared_ptr<const PreparedSubmit>&& plan,VkPublish&& publish) {
    std::lock_guard<std::mutex> serial(p_->submit_mutex);
    VkSubmitResult output;
    output.error_kind=VkErrorKind::InvalidRequest;
    {
        std::lock_guard<std::mutex> lock(p_->mutex);
        if (!p_->initialized || p_->stop || p_->lost || p_->first_failure || p_->quarantined) {
            output.error="engine-not-ready-or-terminal-failure";
            output.error_kind=p_->quarantined?VkErrorKind::UnprovenTermination:VkErrorKind::Device;return output;
        }
    }
    if (!plan || !publish) { output.error="missing-owned-plan-or-publication"; return output; }
    if (plan.use_count()!=1) { output.error="shared-submit-plan"; return output; }
    auto job=std::make_shared<Job>(); job->plan=std::move(plan);
    // swap guarantees the caller's function is empty, including for callable
    // types whose move constructor leaves ownership in the moved-from object.
    job->publish.swap(publish);
    {
        std::lock_guard<std::mutex> lock(p_->mutex); job->failure=p_->injection; p_->injection=Failure::None;
    }
    try {
        if (!p_->validate(*job,&output.error)) return output;
        {std::lock_guard<std::mutex> lock(p_->mutex);
         if(p_->retained.size()>=32||job->ownership_bytes>256u*1024u*1024u-p_->retained_bytes){output.error="accepted-ownership-budget";return output;}}
        output.error_kind=VkErrorKind::Device;
        if (job->failure==Failure::Allocation) { output.error="injected-allocation-refusal"; return output; }
        if (!p_->record(*job,&output.error)) { p_->cleanup(*job); return output; }
    } catch (...) { p_->cleanup(*job); output.error="submission-metadata-allocation";output.error_kind=VkErrorKind::Device; return output; }
    if (job->failure==Failure::Submit) { p_->cleanup(*job); output.error="injected-submit-refusal"; return output; }
    // Reserve every bookkeeping allocation BEFORE the external submit. Workers
    // cannot observe the job until vkQueueSubmit succeeds and the lock releases.
    std::unique_lock<std::mutex> lock(p_->mutex);
    if(p_->stop||p_->lost||p_->first_failure||p_->quarantined) {
        lock.unlock();p_->cleanup(*job);output.error="engine-became-terminal-before-submit";output.error_kind=VkErrorKind::Device;return output;
    }
    // Recording queries the driver's real allocation sizes, including padding,
    // support/staging/temporary buffers and images. Recheck the aggregate with
    // those costs before this job can become visible to the queue/worker.
    if(p_->retained.size()>=32||job->ownership_bytes>256u*1024u*1024u-p_->retained_bytes) {
        lock.unlock();p_->cleanup(*job);output.error="accepted-ownership-budget";return output;
    }
    if(p_->last==UINT64_MAX){lock.unlock();p_->cleanup(*job);output.error="fence-exhaustion";return output;}
    job->id=p_->last+1;
    try {
        p_->outcomes.emplace(job->id,Outcome{}); p_->retained.push_back(job); p_->jobs.push_back(job);
    } catch (...) {
        p_->outcomes.erase(job->id); p_->retained.erase(std::remove(p_->retained.begin(),p_->retained.end(),job),p_->retained.end());
        if (!p_->jobs.empty() && p_->jobs.back()==job) p_->jobs.pop_back();
        lock.unlock(); p_->cleanup(*job); output.error="submission-bookkeeping-allocation"; return output;
    }
    VkSubmitInfo si{}; si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO; si.commandBufferCount=1; si.pCommandBuffers=&job->command;
    VkResult result=vkQueueSubmit(p_->queue,1,&si,job->fence);
    if (result!=VK_SUCCESS) {
        p_->jobs.pop_back(); p_->retained.pop_back(); p_->outcomes.erase(job->id);
        if (result==VK_ERROR_DEVICE_LOST) p_->lost=true;
        lock.unlock(); p_->cleanup(*job); output.error="queue-submit:"+std::to_string(result); return output;
    }
    p_->retained_bytes+=job->ownership_bytes;
    if(job->failure==Failure::UnprovenTermination)p_->termination_wrapper=true;
    p_->last=job->id; p_->totals.submits++;
    p_->totals.buffer_copies+=job->counters.buffer_copies; p_->totals.uniform_updates+=job->counters.uniform_updates;
    p_->totals.image_uploads+=job->counters.image_uploads; p_->totals.image_downloads+=job->counters.image_downloads;
    p_->totals.render_passes+=job->counters.render_passes;
    p_->totals.compute_dispatches+=job->counters.compute_dispatches;
    p_->totals.compute_zero_workgroups+=job->counters.compute_zero_workgroups;
    p_->totals.graphics_draws+=job->counters.graphics_draws;p_->totals.indexed_draws+=job->counters.indexed_draws;p_->totals.zero_draws+=job->counters.zero_draws;
    output.accepted=true; output.fence=job->id;output.error_kind=VkErrorKind::None; p_->cv.notify_all(); return output;
}
VkWaitResult NvnVkEngine::wait(uint64_t fence,uint64_t timeout) {
    std::unique_lock<std::mutex> lock(p_->mutex);
    if (!fence || fence>p_->last) return {VkSubmitState::Failed,"unknown-fence",VkErrorKind::InvalidRequest};
    auto done=[&] {
        const auto it=p_->outcomes.find(fence);
        return it!=p_->outcomes.end() && (it->second.state!=VkSubmitState::Pending || p_->quarantined);
    };
    if (!done()) {
        if (timeout==UINT64_MAX) p_->cv.wait(lock,done);
        else if (timeout) p_->cv.wait_for(lock,std::chrono::nanoseconds(std::min<uint64_t>(timeout,INT64_MAX)),done);
    }
    // A failed earlier fence dooms this suffix, but is not proof that this
    // accepted job's GPU resources and process leases have retired yet.
    const auto& out=p_->outcomes.at(fence);
    if(out.state==VkSubmitState::Pending&&p_->quarantined)return {VkSubmitState::Pending,p_->sticky,VkErrorKind::UnprovenTermination};
    return {out.state,out.error,out.kind};
}
VkWaitResult NvnVkEngine::drain() {
    std::unique_lock<std::mutex> lock(p_->mutex);
    p_->cv.wait(lock,[this]{return p_->retained.empty()||p_->quarantined;});
    if(p_->quarantined)return {VkSubmitState::Pending,p_->sticky,VkErrorKind::UnprovenTermination};
    return p_->first_failure?VkWaitResult{VkSubmitState::Failed,p_->sticky,p_->sticky_kind}:VkWaitResult{VkSubmitState::Completed,{}};
}
uint64_t NvnVkEngine::last_fence() const { std::lock_guard<std::mutex> lock(p_->mutex); return p_->last; }
uint64_t NvnVkEngine::completed_fence() const { std::lock_guard<std::mutex> lock(p_->mutex); return p_->completed; }
bool NvnVkEngine::retained_pool(uint64_t identity) const {
    std::lock_guard<std::mutex> lock(p_->mutex);
    for (const auto& job:p_->retained)
        if (std::find(job->pool_identities.begin(),job->pool_identities.end(),identity)!=job->pool_identities.end()) return true;
    return false;
}
bool NvnVkEngine::retained_texture(uint64_t serial) const {
    std::lock_guard<std::mutex> lock(p_->mutex);
    for (const auto& job:p_->retained)
        if (std::find(job->texture_serials.begin(),job->texture_serials.end(),serial)!=job->texture_serials.end()) return true;
    return false;
}
std::string NvnVkEngine::error() const { std::lock_guard<std::mutex> lock(p_->mutex); return p_->sticky; }
VkErrorKind NvnVkEngine::error_kind() const {std::lock_guard<std::mutex> lock(p_->mutex);return p_->sticky_kind;}
VkReplayStats NvnVkEngine::stats() const {
    std::lock_guard<std::mutex> lock(p_->mutex); auto out=p_->totals;
    out.validation_errors=p_->context->validation_errors.load(std::memory_order_relaxed);
    out.compute_objects_created=p_->context->created.load(std::memory_order_relaxed);
    out.compute_objects_destroyed=p_->context->destroyed.load(std::memory_order_relaxed);
    out.graphics_objects_created=p_->context->graphics_created.load(std::memory_order_relaxed);out.graphics_objects_destroyed=p_->context->graphics_destroyed.load(std::memory_order_relaxed);return out;
}
bool NvnVkEngine::inject_failure(Failure failure) {
    std::lock_guard<std::mutex> lock(p_->mutex);
    if (!p_->retained.empty() || p_->injection!=Failure::None) return false;
    p_->injection=failure; return true;
}
void NvnVkEngine::release_termination_failure() {std::lock_guard<std::mutex> lock(p_->mutex);p_->termination_wrapper=false;p_->cv.notify_all();}
void NvnVkEngine::publication_barrier(bool hold) { std::lock_guard<std::mutex> lock(p_->mutex); p_->hold=hold; p_->cv.notify_all(); }
bool NvnVkEngine::publication_barrier_entered() const { std::lock_guard<std::mutex> lock(p_->mutex); return p_->entered; }
} // namespace dm_android
