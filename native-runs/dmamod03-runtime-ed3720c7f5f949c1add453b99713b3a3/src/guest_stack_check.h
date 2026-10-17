#pragma once
#include "guest_abi.h"
#include <cstdint>

// Audited reserve covers the 816-byte gate snapshot and native checker chain.
constexpr size_t DM_GUEST_STACK_RESERVE = 16384;
struct DmGuestStackOperation {
    unsigned source;
    int64_t delta;
    unsigned access_bytes;
    bool post_index;
    uint64_t alignment_mask=UINT64_MAX;
};
inline bool dm_android_decode_stack_check(uint32_t w,DmGuestStackOperation* out=nullptr) {
    const unsigned rn=(w>>5)&31,rt=w&31,rt2=(w>>10)&31;
    DmGuestStackOperation op{rn,0,0,false};
    const uint32_t alignment=w&0xfffffc1fu;
    if(alignment==0x9274cc1fu || alignment==0x927be81fu || alignment==0x927ae41fu || alignment==0x9279e01fu) {
        if(rn==18 || rn==31) return false;
        op.alignment_mask=UINT64_MAX-(alignment==0x9274cc1fu?4095:alignment==0x927be81fu?31:alignment==0x927ae41fu?63:127);
    } else if((w&0xbf80001fu)==0x9100001fu) {
        const uint32_t amount=((w>>10)&4095)<<((w&(1u<<22))?12:0);
        if(rn==18 || amount>1048576 || (rn==31 && (amount&15))) return false;
        op.delta=(w&(1u<<30))?-static_cast<int64_t>(amount):amount;
    } else if(w==0xa9bf4ff2u || w==0xa8c14ff2u) {
        // Only the SDK's exact 64-bit x18/x19 save and restore are admitted.
        // The canonical trampoline virtualizes x18 after this pure preflight;
        // the original word is never executed against Android's hardware x18.
        op.delta=w==0xa9bf4ff2u?-16:16;
        op.access_bytes=16;op.post_index=w==0xa8c14ff2u;
    } else if(w==0x4cdf27e0u || w==0x4cdf27e4u || w==0x4cdf27e8u || w==0x4cdf27ecu ||
              w==0x4cdfa7e0u || w==0x4cdfa7e4u || w==0x4cdfa7e8u || w==0x4cdfa7ecu) {
        // Exact SDK LD1 .8h, SP immediate post-index forms only. Every byte
        // read and the final SP must fit before the unchanged instruction runs.
        op.access_bytes=(w&0x8000u)?32:64;
        op.delta=op.access_bytes;op.post_index=true;
    } else if(rn==31 && (w&0x3a000000u)==0x28000000u && (((w>>23)&3)==1 || ((w>>23)&3)==3)) {
        const bool vector=w&(1u<<26),load=w&(1u<<22);
        const unsigned opc=w>>30;
        if(opc==3 || (!vector && (rt==18 || rt2==18 || (opc==1 && !load))) || (load && rt==rt2)) return false;
        const unsigned width=vector?(4u<<opc):(opc==2?8:4);
        int64_t imm=(w>>15)&127;if(imm&64) imm-=128;
        op.delta=imm*width;op.access_bytes=width*2;op.post_index=((w>>23)&3)==1;
        if(op.delta%16) return false;
    } else if(rn==31 && (w&0x3b200000u)==0x38000000u && (((w>>10)&3)==1 || ((w>>10)&3)==3)) {
        const bool vector=w&(1u<<26);const unsigned size=w>>30,opc=(w>>22)&3;
        if((!vector && (opc>1 || rt==18)) || (vector && opc>1 && size)) return false;
        int64_t imm=(w>>12)&511;if(imm&256) imm-=512;
        op.delta=imm;op.access_bytes=vector && opc>1?16:1u<<size;op.post_index=((w>>10)&3)==1;
        if(op.delta%16) return false;
    } else return false;
    if(out) *out=op;
    return true;
}

inline bool dm_android_stack_candidate(const DmGuestRegisterFrame& frame,uint32_t word,
                                        uintptr_t bottom,size_t size) {
    DmGuestStackOperation op;
    if(!dm_android_decode_stack_check(word,&op) || size<DM_GUEST_STACK_RESERVE ||
       size>UINTPTR_MAX-bottom || bottom>UINTPTR_MAX-DM_GUEST_STACK_RESERVE) return false;
    const uintptr_t top=bottom+size,floor=bottom+DM_GUEST_STACK_RESERVE,old=frame.guest_sp;
    if((old&15) || old<floor || old>top) return false;
    const uint64_t base=(op.source==31?old:frame.x[op.source])&op.alignment_mask;
    uint64_t candidate;
    if(op.delta<0) {
        const uint64_t amount=static_cast<uint64_t>(-op.delta);
        if(base<amount) return false;
        candidate=base-amount;
    } else {
        const uint64_t amount=static_cast<uint64_t>(op.delta);
        if(base>UINTPTR_MAX-amount) return false;
        candidate=base+amount;
    }
    if((candidate&15) || candidate<floor || candidate>top) return false;
    const uint64_t address=op.post_index?old:candidate;
    return !op.access_bytes || (address>=bottom && address<=top && op.access_bytes<=top-address);
}
