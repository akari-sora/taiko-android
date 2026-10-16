#include "host_bridge.hpp"
#include "guest_abi.h"
extern "C" {
#include "../../host/hle.h"
// Undefined weak boundaries deliberately represent an empty registration
// section. Consumers must retain nonempty sections as documented in .hpp.
extern const hle_ent __start_swhle[] __attribute__((weak));
extern const hle_ent __stop_swhle[] __attribute__((weak));
extern const hle_force_ent __start_swforce[] __attribute__((weak));
extern const hle_force_ent __stop_swforce[] __attribute__((weak));
module_t g_mod[MAX_MOD]{};
int g_nmod=0;
}
#include <climits>
#include <cstring>
#include <algorithm>
#include <limits>
#include <new>

namespace {
dm_android::Process* published=nullptr;
std::mutex publication_mutex;
bool fail(std::string* error,const std::string& reason) {
    if(error) *error=reason;
    return false;
}
template<class T> bool count_section(const T* begin,const T* end,size_t* count,std::string* error) {
    const uintptr_t b=reinterpret_cast<uintptr_t>(begin),e=reinterpret_cast<uintptr_t>(end);
    if(!b && !e) { *count=0;return true; }
    if(!b || !e || e<b || (b&7) || (e-b)%sizeof(T))
        return fail(error,"invalid ELF HLE section boundaries/alignment");
    *count=(e-b)/sizeof(T);
    return true;
}
}

namespace dm_android {
bool HostRegistry::initialize(std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if(error) error->clear();
    if(ready_) return true;
    size_t normals=0,forces=0;
    if(!count_section(__start_swhle,__stop_swhle,&normals,error) ||
       !count_section(__start_swforce,__stop_swforce,&forces,error)) return false;
    try {
        std::unordered_map<std::string,Entry> ordinary,forced;
        for(size_t i=0;i<normals;++i) {
            const auto& entry=__start_swhle[i];
            if(!entry.name || !*entry.name || !entry.fn ||
               !ordinary.emplace(entry.name,Entry{reinterpret_cast<uintptr_t>(entry.fn),0}).second)
                return fail(error,"invalid or duplicate ordinary HLE registration");
        }
        for(size_t i=0;i<forces;++i) {
            const auto& entry=__start_swforce[i];
            if(!entry.name || !*entry.name || !entry.fn || !entry.why || !*entry.why ||
               !forced.emplace(entry.name,Entry{reinterpret_cast<uintptr_t>(entry.fn),0}).second)
                return fail(error,"invalid or duplicate forced HLE registration");
            if(ordinary.count(entry.name)) return fail(error,"ordinary/forced HLE registration conflict: "+std::string(entry.name));
        }
        ordinary_.swap(ordinary);forced_.swap(forced);ready_=true;
        return true;
    } catch(const std::bad_alloc&) { return fail(error,"HLE registry allocation failed"); }
}
bool HostRegistry::resolve(const char* name,bool forced_only,uintptr_t* address) {
    if(!name || !address) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if(!ready_) return false;
    const auto force=forced_.find(name);
    if(force!=forced_.end()) {
        *address=force->second.address;
        // The forced-only pass is the loader's actual takeover decision. Its
        // ordinary fallback never increments a second time.
        if(forced_only && force->second.hits!=std::numeric_limits<size_t>::max()) ++force->second.hits;
        return true;
    }
    if(forced_only) return false;
    const auto ordinary=ordinary_.find(name);
    if(ordinary==ordinary_.end()) return false;
    *address=ordinary->second.address;
    return true;
}
bool HostRegistry::resolver(const char* name,bool forced_only,uintptr_t* address,void* context) {
    return context && static_cast<HostRegistry*>(context)->resolve(name,forced_only,address);
}
bool HostRegistry::contains_callable(uintptr_t address) const {
    if(!address || (address&3)) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if(!ready_) return false;
    for(const auto& item:ordinary_) if(item.second.address==address) return true;
    for(const auto& item:forced_) if(item.second.address==address) return true;
    return false;
}
void HostRegistry::reset_force_hits() {
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto& item:forced_) item.second.hits=0;
}
size_t HostRegistry::force_hits(const char* name) const {
    if(!name) return 0;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found=forced_.find(name);
    return found==forced_.end()?0:found->second.hits;
}
bool HostRegistry::require_all_forces(std::string* error) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if(error) error->clear();
    if(!ready_) return fail(error,"HLE registry has not been validated");
    for(const auto& item:forced_)
        if(!item.second.hits) return fail(error,"unreferenced forced HLE registration: "+item.first);
    return true;
}
HostBridge::~HostBridge() { unbind(); }
bool HostBridge::bind(Process& process,std::string* error) {
    std::lock_guard<std::mutex> lock(publication_mutex);
    if(error) error->clear();
    if(process_ || published) return fail(error,"common host already has a published process");
    if(process.modules().empty() || process.modules().size()>MAX_MOD)
        return fail(error,"common host requires one to eight validated modules");
    module_t candidate[MAX_MOD]{};
    for(size_t i=0;i<process.modules().size();++i) {
        const auto& m=*process.modules()[i]; HostModuleView view;
        if(!m.mapping.base || !m.mapping.sealed || !process.borrowed_module(i,&view) ||
           view.symbol_count>UINT_MAX || m.package->name.size()>=sizeof(candidate[i].name))
            return fail(error,"module cannot be published to common host");
        auto& out=candidate[i];
        std::memcpy(out.name,m.package->name.c_str(),m.package->name.size()+1);
        out.base=static_cast<uint8_t*>(m.mapping.base);out.size=m.package->bytes.size();
        out.data_off=m.package->data_offset;
        for(const auto& segment:m.package->segments) {
            if(segment.flags==(DM_GUEST_READ|DM_GUEST_EXEC) && segment.offset<m.package->original_size)
                out.text_end=segment.offset+segment.size;
            if(segment.flags==DM_GUEST_READ) out.ro_off=segment.offset;
            if(segment.offset>=m.package->original_size) out.patch_off=segment.offset;
        }
        out.dyn=static_cast<const Elf64_Dyn*>(view.dynamic);
        out.symtab=static_cast<const Elf64_Sym*>(view.symbols);out.strtab=view.strings;
        out.nsym=static_cast<unsigned>(view.symbol_count);
        out.init=view.init;out.init_array=view.init_array;out.init_arraysz=view.init_array_bytes;
    }
    if(!process.pin_host_binding(error)) return false;
    std::memcpy(g_mod,candidate,sizeof(g_mod));
    g_nmod=static_cast<int>(process.modules().size());published=&process;process_=&process;
    return true;
}
void HostBridge::unbind() {
    std::lock_guard<std::mutex> lock(publication_mutex);
    if(!process_) return;
    g_nmod=0;std::memset(g_mod,0,sizeof(g_mod));published=nullptr;
    process_->unpin_host_binding();process_=nullptr;
}
}
extern "C" void* module_sym(module_t* module,const char* name) {
    std::lock_guard<std::mutex> lock(publication_mutex);
    if(!published || !module || !name) return nullptr;
    // Compare numeric addresses; relational comparison of unrelated C pointers
    // (a caller may supply any module_t*) would be undefined behavior.
    const uintptr_t value=reinterpret_cast<uintptr_t>(module),base=reinterpret_cast<uintptr_t>(g_mod);
    if(value<base || value-base>=static_cast<size_t>(g_nmod)*sizeof(module_t) || (value-base)%sizeof(module_t)) return nullptr;
    uintptr_t result=0;
    return published->module_symbol((value-base)/sizeof(module_t),name,&result)?reinterpret_cast<void*>(result):nullptr;
}
extern "C" void* guest_sym(const char* name) {
    std::lock_guard<std::mutex> lock(publication_mutex);
    if(!published || !name) return nullptr;
    uintptr_t result;
    for(int i=0;i<g_nmod;++i)
        if(published->module_symbol(static_cast<size_t>(i),name,&result)) return reinterpret_cast<void*>(result);
    return nullptr;
}
extern "C" module_t* module_of(const void* pointer) {
    std::lock_guard<std::mutex> lock(publication_mutex);
    const uintptr_t address=reinterpret_cast<uintptr_t>(pointer);
    for(int i=0;i<g_nmod;++i) {
        const uintptr_t base=reinterpret_cast<uintptr_t>(g_mod[i].base);
        if(address>=base && address-base<g_mod[i].size) return &g_mod[i];
    }
    return nullptr;
}
extern "C" int dm_android_host_query_memory(uint64_t address,uint64_t* base,uint64_t* size,unsigned* flags) {
    if(!base || !size || !flags) return 0;
    std::lock_guard<std::mutex> lock(publication_mutex);
    if(!published) return 0;
    for(const auto& module:published->modules()) {
        const uint64_t start=reinterpret_cast<uintptr_t>(module->mapping.base);
        if(address<start || address-start>=module->package->bytes.size()) continue;
        const uint64_t offset=address-start;
        uint64_t hole_begin=0,hole_end=module->package->bytes.size();
        for(const auto& segment:module->package->segments) {
            if(offset>=segment.offset && offset-segment.offset<segment.size) {
                *base=start+segment.offset;*size=segment.size;*flags=segment.flags;return 1;
            }
            if(segment.offset+segment.size<=offset) hole_begin=std::max(hole_begin,uint64_t(segment.offset+segment.size));
            if(segment.offset>offset) hole_end=std::min(hole_end,uint64_t(segment.offset));
        }
        *base=start+hole_begin;*size=hole_end-hole_begin;*flags=0;return 1;
    }
    return 0;
}
extern "C" uint64_t dm_android_get_guest_x18() { return dm_android_current_guest_state()->virtual_x18; }
extern "C" uint64_t dm_android_get_guest_tls() { return dm_android_current_guest_state()->guest_tpidr_el0; }
extern "C" uint64_t dm_android_get_guest_tlr() { return dm_android_current_guest_state()->guest_tpidrro_el0; }
extern "C" void dm_android_set_guest_x18(uint64_t v) { dm_android_current_guest_state()->virtual_x18=v; }
extern "C" void dm_android_set_guest_tls(uint64_t v) { dm_android_current_guest_state()->guest_tpidr_el0=v; }
extern "C" void dm_android_set_guest_tlr(uint64_t v) { dm_android_current_guest_state()->guest_tpidrro_el0=v; }
