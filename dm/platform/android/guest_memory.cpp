#include "guest_memory.h"
#include <cstdlib>
#include <cstring>

// Runtime pins its Process generation and dispatches only to owned mappings.
// This private staging pointer must never be a caller's published output.
extern "C" int dm_android_runtime_copy_guest(uint64_t source, void* staging, size_t bytes);

extern "C" int dm_android_guest_copy(uint64_t source, void* out, size_t bytes) {
    if(!source || !out || !bytes || bytes>DM_ANDROID_GUEST_COPY_MAX_BYTES ||
       bytes>UINT64_MAX-source)return 0;
    // Guest callbacks may run on small SDK stacks; never place this bounded
    // scratch allocation on that stack. No guest calls occur while it is live.
    void* staging=std::malloc(bytes);
    if(!staging)return 0;
    const int complete=dm_android_runtime_copy_guest(source,staging,bytes);
    if(complete==1)std::memcpy(out,staging,bytes);
    std::free(staging);
    return complete==1;
}
