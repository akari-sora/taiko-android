#include "guest_contract_wire.h"
#include "guest_abi.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <string>

namespace dm_android {
namespace {

constexpr uint64_t kHeader = 512;
constexpr uint64_t kExactStride = 288;
constexpr uint64_t kRetireStride = 192;
constexpr uint32_t kCheckedStack = 1u;
constexpr uint32_t kDiagAbort = 2u;

uint32_t u32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
uint64_t u64(const uint8_t* p) { return u32(p) | uint64_t(u32(p + 4)) << 32; }
int64_t i64(const uint8_t* p) { return static_cast<int64_t>(u64(p)); }

bool zeros(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return false;
    return true;
}
bool digest_zero(const std::array<uint8_t,32>& d) { return zeros(d.data(), d.size()); }
bool aligned(uint64_t value, uint64_t by) { return (value & (by - 1)) == 0; }
bool add_mul(uint64_t base, uint64_t count, uint64_t stride, uint64_t limit, uint64_t* end) {
    if (count && stride > (std::numeric_limits<uint64_t>::max() - base) / count) return false;
    const uint64_t value = base + count * stride;
    if (value > limit) return false;
    *end = value;
    return true;
}
bool reject(GuestContractWireError* out, GuestContractWireError value) {
    if (out) *out = value;
    return false;
}
void copy32(std::array<uint8_t,32>* out, const uint8_t* in) { std::copy_n(in, 32, out->begin()); }
bool digest_matches(const uint8_t* bytes, size_t size, const std::array<uint8_t,32>& expected,
                    GuestContractDigest digest, void* context) {
    if (!digest) return false;
    uint8_t actual[32]{};
    return digest(bytes, size, actual, context) && !std::memcmp(actual, expected.data(), 32);
}
bool nonzero_digest(const std::array<uint8_t,32>& d) { return !digest_zero(d); }

bool decode_exact(const uint8_t* p, ExactGuestRecordV1* out) {
    ExactGuestRecordV1 r{};
    r.schema=u32(p);r.flags=u32(p+4);r.gate_return_offset=u64(p+8);r.original_br_offset=u64(p+16);
    r.original_br_word=u32(p+24);r.target_register=u32(p+28);r.got_offset=u64(p+32);
    r.relocation_index=u32(p+40);r.relocation_type=u32(p+44);r.symbol_index=u32(p+48);
    r.symbol_type=p[52];r.symbol_binding=p[53];r.symbol_visibility=p[54];r.reserved_zero=p[55];
    r.relocation_addend=i64(p+56);r.symbol_name_offset=u32(p+64);r.symbol_name_length=u32(p+68);
    r.symbol_section_index=u32(p+72);r.eh_identity_kind=u32(p+76);r.symbol_value=u64(p+80);
    r.symbol_size=u64(p+88);r.same_module_target_offset=u64(p+96);r.function_start=u64(p+104);
    r.function_end=u64(p+112);r.fde_offset=u64(p+120);r.cie_offset=u64(p+128);
    r.independent_root_offset=u64(p+136);copy32(&r.symbol_name_sha256,p+144);
    copy32(&r.function_sha256,p+176);copy32(&r.eh_identity_sha256,p+208);
    copy32(&r.final_independent_roots_sha256,p+240);std::copy_n(p+272,16,r.reserved_tail.begin());
    if(r.schema!=1 || r.flags || r.reserved_zero || !zeros(r.reserved_tail.data(),16) ||
       !aligned(r.gate_return_offset,4) || !aligned(r.original_br_offset,4) ||
       r.original_br_word!=0xd61f0220u || r.target_register!=17 || !aligned(r.got_offset,8) ||
       !r.symbol_name_length || uint64_t(r.symbol_name_offset)+r.symbol_name_length>(uint64_t(1)<<32) ||
       !aligned(r.same_module_target_offset,4) || !aligned(r.function_start,4) ||
       !aligned(r.function_end,4) || r.function_start>=r.function_end ||
       r.same_module_target_offset<r.function_start || r.same_module_target_offset>=r.function_end ||
       !aligned(r.fde_offset,4) || !aligned(r.cie_offset,4) || !aligned(r.independent_root_offset,4) ||
       !nonzero_digest(r.symbol_name_sha256) || !nonzero_digest(r.function_sha256) ||
       !nonzero_digest(r.final_independent_roots_sha256)) return false;
    if(r.eh_identity_kind==0) {
        if(!r.symbol_size || r.function_start!=r.symbol_value ||
           r.symbol_size>std::numeric_limits<uint64_t>::max()-r.symbol_value ||
           r.function_end!=r.symbol_value+r.symbol_size || r.fde_offset || r.cie_offset ||
           !digest_zero(r.eh_identity_sha256)) return false;
    } else if(r.eh_identity_kind==1) {
        if(!r.fde_offset || !r.cie_offset || !nonzero_digest(r.eh_identity_sha256)) return false;
    } else return false;
    *out=r;return true;
}

bool decode_retire(const uint8_t* p, ReturningRetireRecordV1* out) {
    ReturningRetireRecordV1 r{};
    r.schema=u32(p);r.flags=u32(p+4);r.source_callsite=u64(p+8);r.original_bl_word=u32(p+16);
    r.stub_extent=u32(p+20);r.original_target=u64(p+24);r.normal_return=u64(p+32);
    r.reserved_stub_offset=u64(p+40);r.exclusive_head=u64(p+48);r.matching_store=u64(p+56);
    r.function_start=u64(p+64);r.function_end=u64(p+72);r.fde_offset=u64(p+80);r.cie_offset=u64(p+88);
    copy32(&r.function_sha256,p+96);copy32(&r.final_independent_roots_sha256,p+128);
    copy32(&r.whole_function_ownership_proof_sha256,p+160);
    if(r.schema!=1 || r.flags || !aligned(r.source_callsite,4) ||
       (r.original_bl_word&0xfc000000u)!=0x94000000u || r.stub_extent!=8 ||
       !aligned(r.original_target,4) || !aligned(r.normal_return,4) ||
       r.source_callsite==std::numeric_limits<uint64_t>::max() || r.normal_return!=r.source_callsite+4 ||
       !aligned(r.reserved_stub_offset,4) || !aligned(r.exclusive_head,4) ||
       !aligned(r.matching_store,4) || !aligned(r.function_start,4) || !aligned(r.function_end,4) ||
       r.function_start>=r.function_end || r.source_callsite<r.function_start ||
       r.source_callsite>=r.function_end || r.exclusive_head<r.function_start ||
       r.exclusive_head>=r.function_end || r.matching_store<r.function_start ||
       r.matching_store>=r.function_end || !r.fde_offset || !r.cie_offset ||
       !aligned(r.fde_offset,4) || !aligned(r.cie_offset,4) ||
       !nonzero_digest(r.function_sha256) || !nonzero_digest(r.final_independent_roots_sha256) ||
       !nonzero_digest(r.whole_function_ownership_proof_sha256)) return false;
    *out=r;return true;
}

std::string hex(const uint8_t* p,size_t n) {
    static constexpr char digits[]="0123456789abcdef";
    std::string out;out.resize(n*2);
    for(size_t i=0;i<n;++i){out[i*2]=digits[p[i]>>4];out[i*2+1]=digits[p[i]&15];}
    return out;
}
void append_count(std::string* out,uint64_t value) {
    char digits[32];size_t n=0;do{digits[n++]=char('0'+value%10);value/=10;}while(value);
    while(n)*out+=digits[--n];
}
bool same(const std::array<uint8_t,32>& a,const uint8_t* b){return !std::memcmp(a.data(),b,32);}

} // namespace

bool decode_guest_contract_v3(const uint8_t* blob,size_t size,GuestContractDigest digest,
                              void* context,DecodedGuestContractV1* out,GuestContractWireError* error) {
    if(error)*error=GuestContractWireError::Ok;
    if(!blob || !out || size<kHeader)return reject(error,GuestContractWireError::MissingInput);
    *out={};
    if(std::memcmp(blob,"DMAMOD03",8) || u32(blob+8)!=3 || u32(blob+12)!=DM_ANDROID_GUEST_ABI ||
       u32(blob+16)!=kHeader || !zeros(blob+296,24) || u32(blob+356)!=32 ||
       u32(blob+376)!=40 || u32(blob+380) || !zeros(blob+496,16))
        return reject(error,GuestContractWireError::UnsupportedHeader);
    const uint32_t flags=u32(blob+20),allowed=kCheckedStack|kDiagAbort|
        DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1;
    if((flags&~allowed) || ((flags&kDiagAbort)&&!(flags&kCheckedStack)) ||
       ((flags&(DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1))&&!(flags&kCheckedStack)))
        return reject(error,GuestContractWireError::InvalidFlags);
    const uint64_t payload=u64(blob+112),image_size=u64(blob+24);
    if(!aligned(payload,16) || payload<kHeader || payload>size || image_size>size-payload ||
       payload+image_size!=size)return reject(error,GuestContractWireError::InvalidGeometry);
    const uint64_t offsets[6]={u64(blob+120),u64(blob+136),u64(blob+152),u64(blob+360),u64(blob+384),u64(blob+408)};
    const uint64_t counts[6]={u64(blob+128),u64(blob+144),u64(blob+160),u64(blob+368),u64(blob+392),u64(blob+416)};
    const uint64_t strides[6]={16,32,16,40,kExactStride,kRetireStride};
    if(u32(blob+400)!=kExactStride || u32(blob+404)!=1 || u32(blob+424)!=kRetireStride || u32(blob+428)!=1)
        return reject(error,GuestContractWireError::InvalidGeometry);
    uint64_t cursor=kHeader;
    for(unsigned i=0;i<6;++i) {
        if(offsets[i]!=cursor || !aligned(offsets[i],8) || !add_mul(cursor,counts[i],strides[i],payload,&cursor))
            return reject(error,GuestContractWireError::InvalidGeometry);
    }
    if(cursor>std::numeric_limits<uint64_t>::max()-15 || payload!=((cursor+15)&~uint64_t(15)))
        return reject(error,GuestContractWireError::InvalidGeometry);
    if(!zeros(blob+cursor,static_cast<size_t>(payload-cursor)))
        return reject(error,GuestContractWireError::InvalidPadding);
    out->required_flags=flags;out->exact_guest_offset=offsets[4];out->returning_retire_offset=offsets[5];
    out->payload_offset=payload;copy32(&out->exact_guest_table_sha256,blob+432);
    copy32(&out->returning_retire_table_sha256,blob+464);
    const bool exact_nonempty=counts[4]!=0,retire_nonempty=counts[5]!=0;
    if(exact_nonempty!=((flags&DM_MODULE_REQUIRE_EXACT_GUEST_V1)!=0) ||
       retire_nonempty!=((flags&DM_MODULE_REQUIRE_RETURNING_RETIRE_V1)!=0) ||
       exact_nonempty!=nonzero_digest(out->exact_guest_table_sha256) ||
       retire_nonempty!=nonzero_digest(out->returning_retire_table_sha256))
        return reject(error,GuestContractWireError::InvalidFlags);
    if((exact_nonempty && !digest_matches(blob+offsets[4],static_cast<size_t>(counts[4]*kExactStride),out->exact_guest_table_sha256,digest,context)) ||
       (retire_nonempty && !digest_matches(blob+offsets[5],static_cast<size_t>(counts[5]*kRetireStride),out->returning_retire_table_sha256,digest,context)))
        return reject(error,GuestContractWireError::InvalidDigest);
    try {
        out->exact_guest.reserve(static_cast<size_t>(counts[4]));
        for(uint64_t i=0;i<counts[4];++i) {
            ExactGuestRecordV1 r{};if(!decode_exact(blob+offsets[4]+i*kExactStride,&r) ||
               (i&&out->exact_guest.back().original_br_offset>=r.original_br_offset))
                return reject(error,GuestContractWireError::InvalidExactRecord);
            out->exact_guest.push_back(r);
        }
        out->returning_retire.reserve(static_cast<size_t>(counts[5]));
        for(uint64_t i=0;i<counts[5];++i) {
            ReturningRetireRecordV1 r{};if(!decode_retire(blob+offsets[5]+i*kRetireStride,&r) ||
               (i&&out->returning_retire.back().source_callsite>=r.source_callsite))
                return reject(error,GuestContractWireError::InvalidRetireRecord);
            out->returning_retire.push_back(r);
        }
    } catch(...) {return reject(error,GuestContractWireError::InvalidGeometry);}
    size_t kind6=0;
    for(uint64_t i=0;i<counts[1];++i) {
        const uint8_t* gate=blob+offsets[1]+i*32;
        if(u32(gate+16)!=DM_GUEST_EXACT_GUEST)continue;
        ++kind6;
        if(u32(gate+20)!=17 || u32(gate+28))return reject(error,GuestContractWireError::InvalidGateAssociation);
        size_t matches=0;
        for(const auto& r:out->exact_guest)if(r.gate_return_offset==u64(gate) &&
            r.original_br_offset==u64(gate+8) && r.original_br_word==u32(gate+24))++matches;
        if(matches!=1)return reject(error,GuestContractWireError::InvalidGateAssociation);
    }
    if(kind6!=out->exact_guest.size())return reject(error,GuestContractWireError::InvalidGateAssociation);
    bool have_roots=false;
    for(const auto& r:out->exact_guest) {
        if(!have_roots){out->final_independent_roots_sha256=r.final_independent_roots_sha256;have_roots=true;}
        else if(out->final_independent_roots_sha256!=r.final_independent_roots_sha256)
            return reject(error,GuestContractWireError::InvalidExactRecord);
    }
    bool have_proof=false;
    for(const auto& r:out->returning_retire) {
        if(!have_roots){out->final_independent_roots_sha256=r.final_independent_roots_sha256;have_roots=true;}
        else if(out->final_independent_roots_sha256!=r.final_independent_roots_sha256)
            return reject(error,GuestContractWireError::InvalidRetireRecord);
        if(!have_proof){out->whole_function_ownership_proof_sha256=r.whole_function_ownership_proof_sha256;have_proof=true;}
        else if(out->whole_function_ownership_proof_sha256!=r.whole_function_ownership_proof_sha256)
            return reject(error,GuestContractWireError::InvalidRetireRecord);
    }
    return true;
}

bool validate_guest_contract_audit_v1(const DecodedGuestContractV1& decoded,
                                      const TrustedGuestContractAuditV1& audit,
                                      const uint8_t package_sha256[32],const uint8_t source_sha256[32],
                                      const uint8_t build_id[32],GuestContractDigest digest,void* context,
                                      GuestContractWireError* error) {
    if(error)*error=GuestContractWireError::Ok;
    if(!package_sha256||!source_sha256||!build_id||!digest || audit.schema!=1 || audit.flags ||
       !same(audit.package_sha256,package_sha256) || !same(audit.source_sha256,source_sha256) ||
       !same(audit.build_id,build_id) || digest_zero(audit.toolset_recipe_sha256) ||
       audit.exact_guest_count!=decoded.exact_guest.size() ||
       audit.returning_retire_count!=decoded.returning_retire.size() ||
       audit.exact_guest_table_sha256!=decoded.exact_guest_table_sha256 ||
       audit.returning_retire_table_sha256!=decoded.returning_retire_table_sha256 ||
       audit.final_independent_roots_sha256!=decoded.final_independent_roots_sha256 ||
       audit.whole_function_ownership_proof_sha256!=decoded.whole_function_ownership_proof_sha256)
        return reject(error,GuestContractWireError::InvalidAudit);
    std::string canonical="{\"build_id\":\""+hex(audit.build_id.data(),32)+
        "\",\"exact_guest\":{\"count\":";
    append_count(&canonical,audit.exact_guest_count);
    canonical+=",\"table_sha256\":\""+hex(audit.exact_guest_table_sha256.data(),32)+
        "\"},\"final_independent_roots_sha256\":\""+hex(audit.final_independent_roots_sha256.data(),32)+
        "\",\"flags\":0,\"package_sha256\":\""+hex(audit.package_sha256.data(),32)+
        "\",\"returning_retire\":{\"count\":";
    append_count(&canonical,audit.returning_retire_count);
    canonical+=",\"table_sha256\":\""+hex(audit.returning_retire_table_sha256.data(),32)+
        "\"},\"schema\":1,\"source_sha256\":\""+hex(audit.source_sha256.data(),32)+
        "\",\"toolset_recipe_sha256\":\""+hex(audit.toolset_recipe_sha256.data(),32)+
        "\",\"whole_function_ownership_proof_sha256\":\""+
        hex(audit.whole_function_ownership_proof_sha256.data(),32)+"\"}";
    uint8_t identity[32]{};
    if(!digest(reinterpret_cast<const uint8_t*>(canonical.data()),canonical.size(),identity,context) ||
       std::memcmp(identity,audit.audit_identity_sha256.data(),32))
        return reject(error,GuestContractWireError::InvalidAudit);
    return true;
}

} // namespace dm_android

