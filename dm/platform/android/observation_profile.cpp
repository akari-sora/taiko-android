#include "observation_profile.h"
#include "module_runtime.h"
#include "guest_stack_check.h"
#include <cstring>

namespace dm_android {
// Generated from the independent declarative authority, never package data.
#include "observation_fixtures/generated_catalog.inc"
namespace {
bool reject(const char** error, const char* text) { if(error) *error=text; return false; }
bool bounds(const ModulePackage& p,uint64_t off,size_t n) {
    return off<=p.bytes.size() && n<=p.bytes.size()-off;
}
uint32_t word(const ModulePackage& p,uint64_t off) {
    uint32_t result=0; if(bounds(p,off,4)) std::memcpy(&result,p.bytes.data()+off,4); return result;
}
bool branch_to(const ModulePackage& p,uint64_t at,uint64_t to) {
    const uint32_t w=word(p,at);
    const int64_t displacement=static_cast<int64_t>(static_cast<int32_t>(w<<6)>>6)*4;
    return bounds(p,at,4) && (w&0xfc000000u)==0x14000000u &&
           static_cast<int64_t>(at)+displacement==static_cast<int64_t>(to);
}
const RewriteSite* site(const ModulePackage& p,uint64_t at) {
    for(const auto& s:p.sites) if(s.original_offset==at) return &s;
    return nullptr;
}
bool helper_at(const ModulePackage& p,uint64_t at,unsigned reg,unsigned helper) {
    const uint32_t w=word(p,at);
    if((w&0xff00001fu)!=(0x58000000u|reg)) return false;
    const int64_t displacement=static_cast<int64_t>(static_cast<int32_t>(w<<8)>>13)*4;
    const int64_t target=static_cast<int64_t>(at)+displacement;
    for(const auto& f:p.fixups) if(target>=0 && f.offset>=p.original_size &&
        f.offset==static_cast<uint64_t>(target) && f.helper==helper) return true;
    return false;
}
uint32_t pair(bool load,unsigned a,unsigned b,unsigned offset) {
    return (load?0xa9400000u:0xa9000000u)|((offset/8)<<15)|(b<<10)|(31u<<5)|a;
}
bool stack_tail(const ModulePackage& p,uint64_t t,const GateProvenance& v) {
    if(v.original_word!=0xa9bf4ff2u && v.original_word!=0xa8c14ff2u)
        return bounds(p,t,32) && word(p,t+24)==v.original_word && branch_to(p,t+28,v.original_offset+4);
    const bool load=v.original_word==0xa8c14ff2u;
    const unsigned frame=load?48:64,cleanup=load?64:48;
    // Exact Emitter.x18 composition: save scratch/state/SP-base, obtain the
    // private thread state, operate on virtual x18 through X0, then restore.
    // No arbitrary suffix, helper, register tuple or original x18 word passes.
    return bounds(p,t,88) && word(p,t+24)==(0xd10003ffu|(frame<<10)) &&
        word(p,t+28)==pair(false,16,30,0) && word(p,t+32)==pair(false,0,1,16) &&
        word(p,t+36)==pair(false,2,31,32) && helper_at(p,t+40,16,DM_GUEST_STATE_HELPER) &&
        word(p,t+44)==0xd63f0200u && word(p,t+48)==0xaa1003e1u &&
        word(p,t+52)==pair(true,16,30,0) && word(p,t+56)==(0x910003e2u|(frame<<10)) &&
        word(p,t+60)==0xf9400020u && word(p,t+64)==(load?0xa8c14c40u:0xa9bf4c40u) &&
        word(p,t+68)==0xf9000020u && word(p,t+72)==pair(true,2,31,32) &&
        word(p,t+76)==pair(true,0,1,16) && word(p,t+80)==(0x910003ffu|(cleanup<<10)) &&
        branch_to(p,t+84,v.original_offset+4);
}
bool untouched(const ModulePackage& p,uint64_t pc,unsigned reg) {
    uint32_t w=word(p,pc);
    for(const auto& q:p.parameters) {
        if(pc==q.b) w=q.word_b;
        if(pc==q.a) return q.destination!=reg; // canonical setter has no guest reads
    }
    if(w==0xd503201fu) return true;
    // Independently bounded non-control ALU subset. Unknown instructions are
    // refused rather than guessing register effects inside a parameter pair.
    if((w&0x1f000000u)==0x11000000u) // ADD/SUB immediate
        return (w&31)!=reg && ((w>>5)&31)!=reg;
    if((w&0x1f800000u)==0x12800000u) // MOVN/Z/K (K reads its destination)
        return (w&31)!=reg;
    if((w&0x1f000000u)==0x0a000000u || (w&0x1f000000u)==0x0b000000u)
        return (w&31)!=reg && ((w>>5)&31)!=reg && ((w>>16)&31)!=reg;
    return false;
}
bool direct_target(uint32_t w,uint64_t pc,uint64_t* target) {
    int64_t delta=0;
    if((w&0x7c000000u)==0x14000000u)
        delta=static_cast<int64_t>(static_cast<int32_t>(w<<6)>>6)*4;
    else if((w&0xff000010u)==0x54000000u || (w&0x7e000000u)==0x34000000u)
        delta=static_cast<int64_t>(static_cast<int32_t>(w<<8)>>13)*4;
    else if((w&0x7e000000u)==0x36000000u)
        delta=static_cast<int64_t>(static_cast<int32_t>(w<<13)>>18)*4;
    else return false;
    const int64_t destination=static_cast<int64_t>(pc)+delta;
    if(destination<0) return false;
    *target=static_cast<uint64_t>(destination);return true;
}
}

bool validate_observation_profile(ModulePackage& p,const char** error) {
    p.profile=nullptr;
    bool have_obs=false;
    for(const auto& g:p.gates) have_obs|=g.kind==DM_GUEST_OBSERVATION;
    bool have_indirect=false;
    for(const auto& g:p.gates) have_indirect|=g.kind==DM_GUEST_INDIRECT_HOST;
    bool have_stack=false;
    for(const auto& g:p.gates) have_stack|=g.kind==DM_GUEST_STACK_CHECK;
    const std::array<uint8_t,32> zeros{};
    if(p.wire_version==1) {
        if(have_obs || have_indirect || have_stack || p.checked_stack || !p.parameters.empty() || p.profile_class || p.profile_digest!=zeros || !p.gate_provenance.empty())
            return reject(error,"legacy image cannot carry extended authority");
        return true;
    }
    if(p.wire_version!=2 || p.gate_provenance.size()!=p.gates.size())
        return reject(error,"extended gate provenance is missing");
    if(!p.profile_class) {
        if(p.profile_digest!=zeros || have_obs || !p.parameters.empty())
            return reject(error,"NONE profile cannot authorize OBS or PARAM");
    } else {
        for(size_t i=0;i<kObservationProfileCount;++i) {
            const auto& c=kObservationProfiles[i];
            if(c.identity_class==p.profile_class && p.name==c.module && c.digest==p.profile_digest &&
               c.build_id==p.build_id && c.source_sha256==p.source_sha256) {
                if(p.profile) return reject(error,"ambiguous compiled profile identity");
                p.profile=&c;
            }
        }
        if(!p.profile) return reject(error,"package lacks independent canonical profile authority");
    }
    size_t observation_count=0;
    for(size_t i=0;i<p.gates.size();++i) {
        const auto& g=p.gates[i]; const auto& v=p.gate_provenance[i];
        if(v.return_offset!=g.return_offset || v.kind!=g.kind || v.argument!=g.argument || v.flags ||
           v.original_offset>=p.original_size || !bounds(p,v.original_offset,4))
            return reject(error,"gate provenance disagrees with runtime gate");
        const RewriteSite* s=site(p,v.original_offset);
        if(!s || !branch_to(p,v.original_offset,s->trampoline_offset))
            return reject(error,"gate site has no actual canonical branch");
        if(g.kind==DM_GUEST_SVC) {
            if(v.original_word!=(0xd4000001u|(g.argument<<5))) return reject(error,"SVC original word mismatch");
        } else if(g.kind==DM_GUEST_TIMER) {
            if((v.original_word&0xffffffe0u)!=0xd53be040u && (v.original_word&0xffffffe0u)!=0xd53be020u)
                return reject(error,"timer original word mismatch");
            if((v.original_word&31)!=g.argument) return reject(error,"timer destination mismatch");
        } else if(g.kind==DM_GUEST_OBSERVATION) {
            if(!p.profile || observation_count>=p.profile->observation_count)
                return reject(error,"unexpected observation record");
            const auto& c=p.profile->observations[observation_count++];
            if(c.offset!=v.original_offset || c.id!=g.argument || c.word!=v.original_word)
                return reject(error,"observation differs from canonical source record");
            const uint64_t t=s->trampoline_offset;
            if(!bounds(p,t,32) || g.return_offset!=t+16 || word(p,t)!=0xd10043ffu ||
               word(p,t+4)!=pair(false,29,30,0) || !helper_at(p,t+8,30,DM_GUEST_DISPATCH_HELPER) ||
               word(p,t+12)!=0xd63f03c0u || word(p,t+16)!=pair(true,29,30,0) ||
               word(p,t+20)!=0x910043ffu || word(p,t+24)!=c.word || !branch_to(p,t+28,c.offset+4))
                return reject(error,"observation PRE stub differs from canonical shape");
        } else if(g.kind==DM_GUEST_INDIRECT_HOST) {
            const bool link=(v.original_word&0xfffffc1fu)==0xd63f0000u;
            if((!link && (v.original_word&0xfffffc1fu)!=0xd61f0000u) ||
               g.argument>30 || g.argument==18 || (link && g.argument==30) ||
               ((v.original_word>>5)&31)!=g.argument)
                return reject(error,"guarded host original branch/register mismatch");
            const uint64_t t=s->trampoline_offset;
            if(!bounds(p,t,link?36:28) || g.return_offset!=t+16 || word(p,t)!=0xd10043ffu ||
               word(p,t+4)!=pair(false,29,30,0) || !helper_at(p,t+8,30,DM_GUEST_DISPATCH_HELPER) ||
               word(p,t+12)!=0xd63f03c0u || word(p,t+16)!=pair(true,29,30,0) ||
               word(p,t+20)!=0x910043ffu)
                return reject(error,"guarded host prefix differs from canonical shape");
            if(link) {
                const uint64_t destination=v.original_offset+4;
                const int64_t pages=(static_cast<int64_t>(destination&~uint64_t(4095))-
                                     static_cast<int64_t>((t+24)&~uint64_t(4095)))/4096;
                if(pages<-(1<<20) || pages>=(1<<20)) return reject(error,"guarded host LR page outside ADRP range");
                const uint32_t immediate=static_cast<uint32_t>(pages)&0x1fffffu;
                const uint32_t adrp=0x9000001eu|((immediate&3)<<29)|((immediate>>2)<<5);
                const uint32_t add=0x910003deu|(static_cast<uint32_t>(destination&4095)<<10);
                if(word(p,t+24)!=adrp || word(p,t+28)!=add || word(p,t+32)!=(0xd61f0000u|(g.argument<<5)))
                    return reject(error,"guarded host call continuation differs from original LR");
            } else if(word(p,t+24)!=v.original_word)
                return reject(error,"guarded host tail branch differs from original");
        } else if(g.kind==DM_GUEST_STACK_CHECK) {
            const uint64_t t=s->trampoline_offset;
            if(!p.checked_stack || g.argument!=v.original_word || !dm_android_decode_stack_check(g.argument) ||
               !bounds(p,t,32) || g.return_offset!=t+16 || word(p,t)!=0xd10043ffu ||
               word(p,t+4)!=pair(false,29,30,0) || !helper_at(p,t+8,30,DM_GUEST_DISPATCH_HELPER) ||
               word(p,t+12)!=0xd63f03c0u || word(p,t+16)!=pair(true,29,30,0) ||
               word(p,t+20)!=0x910043ffu || !stack_tail(p,t,v))
                return reject(error,"checked-stack preflight differs from canonical instruction/stub");
        } else return reject(error,"unknown extended gate kind");
        if(g.kind!=DM_GUEST_OBSERVATION && g.kind!=DM_GUEST_INDIRECT_HOST && g.kind!=DM_GUEST_STACK_CHECK) {
            const uint64_t t=s->trampoline_offset;
            if(!bounds(p,t,28) || g.return_offset!=t+16 || word(p,t)!=0xd10043ffu ||
               word(p,t+4)!=pair(false,29,30,0) || !helper_at(p,t+8,30,DM_GUEST_DISPATCH_HELPER) ||
               word(p,t+12)!=0xd63f03c0u || word(p,t+16)!=pair(true,29,30,0) ||
               word(p,t+20)!=0x910043ffu || !branch_to(p,t+24,v.original_offset+4))
                return reject(error,"extended SVC/timer stub differs from canonical shape");
        }
    }
    if(p.profile && (observation_count!=p.profile->observation_count || p.parameters.size()!=p.profile->parameter_count))
        return reject(error,"canonical profile record counts disagree");
    for(size_t i=0;i<p.parameters.size();++i) {
        const auto& q=p.parameters[i]; const auto& c=p.profile->parameters[i];
        if(q.a!=c.a || q.b!=c.b || q.word_a!=c.word_a || q.word_b!=c.word_b ||
           q.destination!=c.destination || q.slot!=c.slot || q.flags!=c.flags ||
           q.flags>1 || q.destination>30 || q.destination==18 || q.slot>=DM_GUEST_PARAMETER_COUNT ||
           (q.a&3) || (q.b&3) || q.b<=q.a || q.b>=p.original_size || !bounds(p,q.b,4))
            return reject(error,"parameter differs from canonical source record");
        for(size_t j=0;j<i;++j) {
            const auto& other=p.parameters[j];
            if(q.a==other.a || q.a==other.b || q.b==other.a || q.b==other.b)
                return reject(error,"parameter physical endpoints overlap");
        }
        if(word(p,q.b)!=0xd503201fu || site(p,q.b)) return reject(error,"parameter B is not an unrewritten NOP");
        const RewriteSite* s=site(p,q.a);
        if(!s || !branch_to(p,q.a,s->trampoline_offset)) return reject(error,"parameter A is not an actual site branch");
        // Original A reads determine the scratch choice in the offline emitter.
        unsigned scratch=31,state=31;
        if((q.word_a&0x7f800000u)!=0x52800000u || (q.word_b&0x7f800000u)!=0x72800000u ||
           (q.word_a&31)!=q.destination || (q.word_b&31)!=q.destination ||
           ((q.word_a>>31)==0)!=static_cast<bool>(q.flags) || ((q.word_b>>31)==0)!=static_cast<bool>(q.flags))
            return reject(error,"parameter endpoints are not canonical MOVZ/MOVK constants");
        for(unsigned r=0;r<16;++r) {
            if(r==q.destination) continue;
            if(scratch==31) scratch=r; else {state=r;break;}
        }
        const uint64_t t=s->trampoline_offset;
        const uint32_t load=(q.flags?0xb9400000u:0xf9400000u)|
            ((DM_GUEST_PARAMETER_BASE+q.slot*8)/(q.flags?4:8)<<10)|(state<<5)|q.destination;
        if(state==31 || !bounds(p,t,44) || word(p,t)!=0xd10083ffu || word(p,t+4)!=pair(false,16,30,0) ||
           word(p,t+8)!=pair(false,scratch,state,16) || !helper_at(p,t+12,16,DM_GUEST_STATE_HELPER) ||
           word(p,t+16)!=0xd63f0200u || word(p,t+20)!=(0xaa1003e0u|state) ||
           word(p,t+24)!=pair(true,16,30,0) || word(p,t+28)!=load ||
           word(p,t+32)!=pair(true,scratch,state,16) || word(p,t+36)!=0x910083ffu || !branch_to(p,t+40,q.a+4))
            return reject(error,"parameter canonical stub mismatch");
        for(uint64_t pc=q.a+4;pc<q.b;pc+=4)
            if(!untouched(p,pc,q.destination)) return reject(error,"parameter interval has register/control hazard");
        for(const auto& segment:p.segments) {
            if(!(segment.flags&DM_GUEST_EXEC) || segment.offset>=p.original_size) continue;
            const uint64_t end=segment.offset+segment.size;
            for(uint64_t pc=segment.offset;pc<end;pc+=4) {
                uint64_t target=0;
                if(direct_target(word(p,pc),pc,&target) && target>q.a && target<=q.b)
                    return reject(error,"parameter interval has a direct control-flow entry");
            }
        }
    }
    return true;
}
}
