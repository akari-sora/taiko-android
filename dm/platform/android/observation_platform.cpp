#include "observation_platform.h"
#include "kernel_runtime.h"
#include "guest_memory.h"
extern "C" {
#include "../../host/dm_uimsg.h"
int gate_obs_present(int);
void gate_obs_set(int,void (*)(const uint64_t*));
}
#include <cstdio>
#include <cstdlib>

namespace {
// Configure owns the runtime lifecycle lock, so its scan must use that existing
// pin instead of recursively acquiring a read lease. Never survives configure.
thread_local dm_android::Process* scanning_process=nullptr;
size_t read_guest(void*,uint64_t address,void* output,size_t bytes) {
    if(scanning_process) return scanning_process->copy_readable(address,output,bytes)?bytes:0;
    if(dm_android_guest_copy(address,output,bytes)) return bytes;
    // Legacy ASCII arguments may end at the final readable byte. Preserve a
    // checked readable prefix for the bus's NUL test; message objects still
    // require their exact 24 bytes. Every byte uses the same owned-copy backend.
    if(bytes>64) return 0;
    size_t copied=0;
    while(copied<bytes && address<=UINT64_MAX-copied &&
          dm_android_guest_copy(address+copied,static_cast<uint8_t*>(output)+copied,1)) ++copied;
    return copied;
}
struct SpanSearch {size_t wanted,index=0;uint64_t base=0;size_t bytes=0;};
bool find_span(uint64_t base,size_t bytes,void* opaque) {
    auto& search=*static_cast<SpanSearch*>(opaque);
    if(search.index++==search.wanted) {search.base=base;search.bytes=bytes;}
    return true;
}
int read_only(void*,size_t index,uint64_t* address,size_t* bytes) {
    if(!address || !bytes) return -1;
    SpanSearch search{index};
    if(scanning_process) {
        if(!scanning_process->visit_readonly(find_span,&search)) return -1;
    } else {
        dm_android::RuntimeReadLease lease;
        if(!lease.runtime() || !lease.runtime()->process().visit_readonly(find_span,&search)) return -1;
    }
    if(!search.bytes) return 0;
    *address=search.base;*bytes=search.bytes;return 1;
}
int present(void*) {return gate_obs_present(1);}
void set(void*,void (*callback)(const uint64_t*)) {gate_obs_set(1,callback);}
void failure(void*,const char* text) {
    std::fprintf(stderr,"Android UI observation refused: %s\n",text);std::abort();
}
}
namespace dm_android {
bool observation_platform_configure(Process& process,std::string* error) {
    dm_uimsg_config config{};
    config.read=read_guest;config.ro_span=read_only;config.gate_present=present;
    config.gate_set=set;config.failure=failure;
    scanning_process=&process;
    const int result=dm_uimsg_configure(&config);
    scanning_process=nullptr;
    if(result && error) *error="UI observation RO cache could not be built";
    return result==0;
}
void observation_platform_reset() {dm_uimsg_reset();}
}
