#include "../../../platform/android/guest_stack_check.h"
#include <cstdio>

// Host-side arithmetic test: no original program or guest instruction executes.
int main() {
    constexpr uint32_t word=0x9279e13f; // AND SP, X9, #-128
    DmGuestStackOperation operation{};
    if(!dm_android_decode_stack_check(word,&operation) || operation.source!=9 ||
       operation.alignment_mask!=UINT64_C(0xffffffffffffff80) || operation.delta ||
       operation.access_bytes || operation.post_index) {
        std::fputs("128-byte SP alignment decode mismatch\n",stderr);return 1;
    }
    const unsigned unsupported_sources[]{18u,31u};
    for(unsigned source:unsupported_sources)
        if(dm_android_decode_stack_check((word&~(31u<<5))|(source<<5)))return 2;
    constexpr uintptr_t bottom=0x100000,bytes=0x10000,top=bottom+bytes;
    DmGuestRegisterFrame frame{};frame.guest_sp=top-0x100;
    frame.x[9]=top+127;
    if(!dm_android_stack_candidate(frame,word,bottom,bytes))return 3;
    frame.x[9]=top+128;
    if(dm_android_stack_candidate(frame,word,bottom,bytes))return 4;
    frame.x[9]=bottom+DM_GUEST_STACK_RESERVE-1;
    if(dm_android_stack_candidate(frame,word,bottom,bytes))return 5;
    frame.x[9]=bottom+DM_GUEST_STACK_RESERVE+127;
    if(!dm_android_stack_candidate(frame,word,bottom,bytes))return 6;
    frame.x[9]=UINT64_MAX;
    if(dm_android_stack_candidate(frame,word,bottom,bytes))return 7;
    frame.x[9]=top;frame.guest_sp=top+16;
    if(dm_android_stack_candidate(frame,word,bottom,bytes))return 8;
    std::puts("SP alignment decode and guard/reserve bounds PASS");return 0;
}
