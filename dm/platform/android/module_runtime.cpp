#include "module_runtime.h"
#include "module_sha256.h"
#include "guest_loader_internal.h"
#include "guest_stack_check.h"
#include "guest_contract_wire.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <elf.h>
#include <limits>
#include <new>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

namespace dm_android {
namespace {
std::atomic<uint64_t> process_generation{0};
struct StackEntryAuthority {
    const Process* process;
    uint64_t generation;
    uintptr_t base;
    size_t size;
    bool checked;
};
std::mutex stack_entry_mutex; // Host-side entry preflight only, never the gate path.
std::vector<StackEntryAuthority> stack_entries;
std::array<uint8_t,32> package_identity(const ModulePackage& p) {
    std::vector<uint8_t> encoded;
    const auto scalar=[&](uint64_t n){for(unsigned i=0;i<8;++i)encoded.push_back(static_cast<uint8_t>(n>>(i*8)));};
    const auto raw=[&](const uint8_t* b,size_t n){scalar(n);if(n)encoded.insert(encoded.end(),b,b+n);};
    raw(reinterpret_cast<const uint8_t*>(p.name.data()),p.name.size());
    raw(p.build_id.data(),32);raw(p.source_sha256.data(),32);raw(p.image_sha256.data(),32);
    scalar(p.original_size);scalar(p.symbol_count);scalar(p.string_bytes);
    scalar(p.data_offset);scalar(p.data_bytes);scalar(p.bss_bytes);scalar(p.wire_version);
    scalar(p.profile_class);raw(p.profile_digest.data(),32);scalar(p.checked_stack);scalar(p.required_flags);
    std::array<uint8_t,32> image_hash{};module_sha256(p.bytes.data(),p.bytes.size(),image_hash.data());
    scalar(p.bytes.size());raw(image_hash.data(),32);
    scalar(p.fixups.size());for(const auto& x:p.fixups){scalar(x.offset);scalar(x.helper);}
    scalar(p.gates.size());for(const auto& x:p.gates){scalar(x.return_offset);scalar(x.kind);scalar(x.argument);}
    scalar(p.gate_provenance.size());for(const auto& x:p.gate_provenance){scalar(x.return_offset);scalar(x.original_offset);scalar(x.kind);scalar(x.argument);scalar(x.original_word);scalar(x.flags);}
    scalar(p.parameters.size());for(const auto& x:p.parameters){scalar(x.a);scalar(x.b);scalar(x.word_a);scalar(x.word_b);scalar(x.destination);scalar(x.slot);scalar(x.flags);}
    scalar(p.exact_guest_records.size());for(const auto& x:p.exact_guest_records){
        scalar(x.schema);scalar(x.flags);scalar(x.gate_return_offset);scalar(x.original_br_offset);
        scalar(x.original_br_word);scalar(x.target_register);scalar(x.got_offset);scalar(x.relocation_index);
        scalar(x.relocation_type);scalar(x.symbol_index);scalar(x.symbol_type);scalar(x.symbol_binding);
        scalar(x.symbol_visibility);scalar(static_cast<uint64_t>(x.relocation_addend));
        scalar(x.symbol_name_offset);scalar(x.symbol_name_length);scalar(x.symbol_section_index);
        scalar(x.eh_identity_kind);scalar(x.symbol_value);scalar(x.symbol_size);
        scalar(x.same_module_target_offset);scalar(x.function_start);scalar(x.function_end);
        scalar(x.fde_offset);scalar(x.cie_offset);scalar(x.independent_root_offset);
        raw(x.symbol_name_sha256.data(),32);raw(x.function_sha256.data(),32);
        raw(x.eh_identity_sha256.data(),32);raw(x.final_independent_roots_sha256.data(),32);
    }
    scalar(p.returning_retire_records.size());for(const auto& x:p.returning_retire_records){
        scalar(x.schema);scalar(x.flags);scalar(x.source_callsite);scalar(x.original_bl_word);
        scalar(x.stub_extent);scalar(x.original_target);scalar(x.normal_return);scalar(x.reserved_stub_offset);
        scalar(x.exclusive_head);scalar(x.matching_store);scalar(x.function_start);scalar(x.function_end);
        scalar(x.fde_offset);scalar(x.cie_offset);raw(x.function_sha256.data(),32);
        raw(x.final_independent_roots_sha256.data(),32);raw(x.whole_function_ownership_proof_sha256.data(),32);
    }
    raw(p.exact_guest_table_sha256.data(),32);raw(p.returning_retire_table_sha256.data(),32);
    raw(p.final_independent_roots_sha256.data(),32);raw(p.whole_function_ownership_proof_sha256.data(),32);
    scalar(p.sites.size());for(const auto& x:p.sites){scalar(x.original_offset);scalar(x.trampoline_offset);}
    scalar(p.segments.size());for(const auto& x:p.segments){scalar(x.offset);scalar(x.size);scalar(x.flags);}
    scalar(p.image.abi);scalar(p.image.size);scalar(p.image.entry_offset);
    scalar(reinterpret_cast<uintptr_t>(p.profile));
    scalar(p.image.bytes==p.bytes.data());
    scalar(p.image.fixups==p.fixups.data());scalar(p.image.fixup_count);
    scalar(p.image.gates==p.gates.data());scalar(p.image.gate_count);
    scalar(p.image.segments==p.segments.data());scalar(p.image.segment_count);
    std::array<uint8_t,32> result{};module_sha256(encoded.data(),encoded.size(),result.data());return result;
}
bool fail(std::string* error, const std::string& message) {
    if (error) *error = message;
    return false;
}
uint32_t u32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
uint64_t u64(const uint8_t* p) { return u32(p) | (uint64_t(u32(p + 4)) << 32); }
bool range(uint64_t offset, uint64_t size, uint64_t bound) {
    return offset <= bound && size <= bound - offset;
}
struct Span { uint64_t offset, size; };
bool overlaps(Span a, Span b) {
    return a.size && b.size && a.offset < b.offset + b.size && b.offset < a.offset + a.size;
}
bool zero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return false;
    return true;
}
bool guest_contract_digest(const uint8_t* bytes,size_t size,uint8_t digest[32],void*) {
    if(!digest || (size && !bytes))return false;
    module_sha256(bytes,size,digest);return true;
}
const char* guest_contract_error(GuestContractWireError error) {
    switch(error) {
    case GuestContractWireError::Ok:return "ok";
    case GuestContractWireError::MissingInput:return "missing input";
    case GuestContractWireError::UnsupportedHeader:return "unsupported header";
    case GuestContractWireError::InvalidFlags:return "invalid flags";
    case GuestContractWireError::InvalidGeometry:return "invalid geometry";
    case GuestContractWireError::InvalidPadding:return "invalid padding";
    case GuestContractWireError::InvalidDigest:return "invalid digest";
    case GuestContractWireError::InvalidExactRecord:return "invalid exact-guest record";
    case GuestContractWireError::InvalidRetireRecord:return "invalid returning-retire record";
    case GuestContractWireError::InvalidGateAssociation:return "invalid kind-6 gate association";
    case GuestContractWireError::InvalidAudit:return "invalid trusted guest-contract audit";
    }
    return "unknown guest-contract error";
}
bool limits_valid(const ModuleLimits& limits) {
    return limits.image_bytes && limits.image_bytes <= 256u * 1024u * 1024u &&
           limits.package_bytes && limits.package_bytes <= 512u * 1024u * 1024u &&
           limits.module_count && limits.module_count <= 32 &&
           limits.callback_roots && limits.callback_roots <= (1u << 20);
}
bool in_segment(const ModulePackage& p, uint64_t off, uint64_t size, uint32_t flags) {
    for (const auto& s : p.segments)
        if ((s.flags & flags) == flags && off >= s.offset && range(off - s.offset, size, s.size)) return true;
    return false;
}
bool in_original(const ModulePackage& p, uint64_t off, uint64_t size) {
    return range(off, size, p.original_size) && in_segment(p, off, size, DM_GUEST_READ);
}
template<class T> T read(const ModulePackage& p, size_t off) {
    T value;
    memcpy(&value, p.bytes.data() + off, sizeof(value));
    return value;
}
bool validate_callback_symbols(const ModulePackage&,const TrustedCallbackAudit&,std::string*);
// The first three immutable instructions identify a standard PLT/GOT pair.
// The fourth must separately be the admitted typed BR x17 gate.
bool static_plt_got(const ModulePackage& p,uint64_t plt,uint64_t* got) {
    if(!got || !range(plt,16,p.original_size) || !range(plt,16,p.bytes.size()) ||
       !in_segment(p,plt,16,DM_GUEST_READ|DM_GUEST_EXEC))return false;
    const uint32_t a=read<uint32_t>(p,plt),b=read<uint32_t>(p,plt+4),c=read<uint32_t>(p,plt+8);
    if((a&0x9f00001fu)!=0x90000010u || (b&0xffc003ffu)!=0xf9400211u ||
       (c&0xffc003ffu)!=0x91000210u || ((b>>10)&4095)*8!=((c>>10)&4095))return false;
    int64_t pages=((a>>5)&0x7ffff)*4+((a>>29)&3);
    if(pages&(1<<20))pages-=1<<21;
    const int64_t value=static_cast<int64_t>(plt&~uint64_t(4095))+pages*4096+((b>>10)&4095)*8;
    if(value<0 || !range(static_cast<uint64_t>(value),8,p.original_size) ||
       !in_segment(p,static_cast<uint64_t>(value),8,DM_GUEST_READ|DM_GUEST_WRITE))return false;
    *got=static_cast<uint64_t>(value);return true;
}
const DmGuestGate* plt_kind_gate(const ModulePackage& p,uint64_t plt,uint32_t expected_kind) {
    if((p.wire_version!=2 && p.wire_version!=3) || p.gate_provenance.size()!=p.gates.size() ||
       !range(plt,16,p.original_size) || !range(plt,16,p.bytes.size()) ||
       !in_segment(p,plt,16,DM_GUEST_READ|DM_GUEST_EXEC))return nullptr;
    for(size_t i=0;i<p.gates.size();++i) {
        const auto& gate=p.gates[i];const auto& provenance=p.gate_provenance[i];
        if(provenance.original_offset!=plt+12)continue;
        if(gate.kind!=expected_kind || gate.argument!=17 ||
           provenance.kind!=gate.kind || provenance.argument!=gate.argument ||
           provenance.return_offset!=gate.return_offset || provenance.flags ||
           provenance.original_word!=0xd61f0220u)return nullptr;
        for(const auto& site:p.sites)if(site.original_offset==plt+12) {
            const uint64_t t=site.trampoline_offset;
            if(t<p.original_size || (t&3) || !range(t,28,p.bytes.size()) ||
               !in_segment(p,t,28,DM_GUEST_READ|DM_GUEST_EXEC) || gate.return_offset!=t+16)return nullptr;
            const uint32_t branch=read<uint32_t>(p,plt+12);
            const int64_t distance=static_cast<int64_t>(static_cast<int32_t>(branch<<6)>>6)*4;
            if((branch&0xfc000000u)!=0x14000000u ||
               static_cast<int64_t>(plt+12)+distance!=static_cast<int64_t>(t) ||
               read<uint32_t>(p,t)!=0xd10043ffu || read<uint32_t>(p,t+4)!=0xa9007bfdu ||
               read<uint32_t>(p,t+12)!=0xd63f03c0u || read<uint32_t>(p,t+16)!=0xa9407bfdu ||
               read<uint32_t>(p,t+20)!=0x910043ffu || read<uint32_t>(p,t+24)!=0xd61f0220u)return nullptr;
            const uint32_t literal=read<uint32_t>(p,t+8);
            if((literal&0xff00001fu)!=0x5800001eu)return nullptr;
            const int64_t displacement=static_cast<int64_t>(static_cast<int32_t>(literal<<8)>>13)*4;
            const int64_t target=static_cast<int64_t>(t+8)+displacement;
            if(target<0)return nullptr;
            const uint64_t helper=static_cast<uint64_t>(target);
            if(helper<p.original_size || (helper&7) || !range(helper,8,p.bytes.size()) ||
               !in_segment(p,helper,8,DM_GUEST_READ|DM_GUEST_EXEC) || read<uint64_t>(p,helper))return nullptr;
            size_t matches=0;
            for(const auto& fixup:p.fixups)if(fixup.offset==helper) {
                if(fixup.helper!=DM_GUEST_DISPATCH_HELPER)return nullptr;
                ++matches;
            }
            return matches==1?&gate:nullptr;
        }
        return nullptr;
    }
    return nullptr;
}
const DmGuestGate* diag_plt_gate(const ModulePackage& p,uint64_t plt) {
    return plt_kind_gate(p,plt,DM_GUEST_INDIRECT_HOST);
}
const DmGuestGate* exact_plt_gate(const ModulePackage& p,uint64_t plt) {
    return (p.wire_version==3 && p.checked_stack)?plt_kind_gate(p,plt,DM_GUEST_EXACT_GUEST):nullptr;
}
bool validate_v3_lowered_premap(const ModulePackage& p) {
    if(p.wire_version!=3 || !p.checked_stack ||
       p.exact_guest_records.size()!=5 || p.returning_retire_records.size()!=2)return false;
    for(size_t i=0;i<p.returning_retire_records.size();++i) {
        const auto& r=p.returning_retire_records[i];
        if(r.stub_extent!=8 || !range(r.source_callsite,4,p.original_size) ||
           !range(r.original_target,4,p.original_size) ||
           !in_segment(p,r.source_callsite,4,DM_GUEST_READ|DM_GUEST_EXEC) ||
           !in_segment(p,r.original_target,4,DM_GUEST_READ|DM_GUEST_EXEC) ||
           r.reserved_stub_offset<p.original_size || !range(r.reserved_stub_offset,8,p.bytes.size()) ||
           !in_segment(p,r.reserved_stub_offset,8,DM_GUEST_READ|DM_GUEST_EXEC))return false;
        for(size_t j=0;j<i;++j)
            if(overlaps({r.reserved_stub_offset,8},{p.returning_retire_records[j].reserved_stub_offset,8}))
                return false;
        const uint32_t bl=read<uint32_t>(p,r.source_callsite);
        const int64_t bl_dist=static_cast<int64_t>(static_cast<int32_t>(bl<<6)>>6)*4;
        if((bl&0xfc000000u)!=0x94000000u ||
           static_cast<int64_t>(r.source_callsite)+bl_dist!=static_cast<int64_t>(r.reserved_stub_offset))
            return false;
        const uint32_t clrex=read<uint32_t>(p,r.reserved_stub_offset);
        const uint32_t b=read<uint32_t>(p,r.reserved_stub_offset+4);
        const int64_t b_dist=static_cast<int64_t>(static_cast<int32_t>(b<<6)>>6)*4;
        if(clrex!=0xd5033f5fu || (b&0xfc000000u)!=0x14000000u ||
           static_cast<int64_t>(r.reserved_stub_offset+4)+b_dist!=static_cast<int64_t>(r.original_target))
            return false;
    }
    size_t kind6_count=0;
    for(const auto& g:p.gates)if(g.kind==DM_GUEST_EXACT_GUEST)++kind6_count;
    if(kind6_count!=p.exact_guest_records.size())return false;
    for(size_t i=0;i<p.exact_guest_records.size();++i) {
        const auto& x=p.exact_guest_records[i];
        if(x.original_br_offset<12 || !range(x.function_start,x.function_end-x.function_start,p.original_size) ||
           !in_segment(p,x.function_start,x.function_end-x.function_start,DM_GUEST_READ|DM_GUEST_EXEC))
            return false;
        uint64_t got=0;
        if(!static_plt_got(p,x.original_br_offset-12,&got) || got!=x.got_offset)return false;
        const DmGuestGate* gate=exact_plt_gate(p,x.original_br_offset-12);
        if(!gate || gate->return_offset!=x.gate_return_offset)return false;
        for(size_t j=0;j<i;++j)
            if(p.exact_guest_records[j].got_offset==x.got_offset ||
               p.exact_guest_records[j].gate_return_offset==x.gate_return_offset)
                return false;
    }
    return true;
}
}

ModulePackage::ModulePackage(const ModulePackage& other) { *this=other; }
ModulePackage& ModulePackage::operator=(const ModulePackage& p) {
    if(this==&p) { guest_contract_admission_.reset(); return *this; }
    // Revoke before copying, including if a later allocation throws.
    callback_admitted_=false;callback_identity_={};callback_roots_.clear();callback_indirect_policy_=CallbackIndirectPolicy::Strict;
    stack_admitted_=false;stack_identity_={};
    capsule_verified_=false;capsule_bytes_=0;capsule_sha256_={};
    guest_contract_admission_.reset();
    name=p.name;build_id=p.build_id;source_sha256=p.source_sha256;image_sha256=p.image_sha256;
    original_size=p.original_size;symbol_count=p.symbol_count;string_bytes=p.string_bytes;
    data_offset=p.data_offset;data_bytes=p.data_bytes;bss_bytes=p.bss_bytes;
    bytes=p.bytes;fixups=p.fixups;gates=p.gates;wire_version=p.wire_version;
    checked_stack=p.checked_stack;
    required_flags=p.required_flags;
    profile_class=p.profile_class;profile_digest=p.profile_digest;profile=p.profile;
    gate_provenance=p.gate_provenance;parameters=p.parameters;sites=p.sites;segments=p.segments;
    exact_guest_records=p.exact_guest_records;returning_retire_records=p.returning_retire_records;
    exact_guest_table_sha256=p.exact_guest_table_sha256;
    returning_retire_table_sha256=p.returning_retire_table_sha256;
    final_independent_roots_sha256=p.final_independent_roots_sha256;
    whole_function_ownership_proof_sha256=p.whole_function_ownership_proof_sha256;
    image=p.image;
    image.bytes=bytes.data();image.fixups=fixups.data();image.gates=gates.data();image.segments=segments.data();
    return *this;
}

void ModulePackage::refresh_view() {
    image = {DM_ANDROID_GUEST_ABI, bytes.data(), bytes.size(),
             segments.empty() ? 0 : segments.front().offset,
             fixups.data(), fixups.size(), gates.data(), gates.size(),
             segments.data(), segments.size()};
}

bool decode_package_with_callback_audit(const uint8_t* blob,size_t size,const uint8_t* expected_digest,
                    const TrustedCallbackAudit& audit,std::unique_ptr<ModulePackage>* out,
                    std::string* error,const ModuleLimits& limits) {
    return decode_package_with_audits(blob,size,expected_digest,&audit,nullptr,out,error,limits);
}

bool decode_package_with_guest_contract_audit(const uint8_t* blob,size_t size,const uint8_t* expected_digest,
                    const TrustedGuestContractAuditV1& audit,std::unique_ptr<ModulePackage>* out,
                    std::string* error,const ModuleLimits& limits) {
    return decode_package_with_audits(blob,size,expected_digest,nullptr,&audit,out,error,limits);
}
namespace {
// Called by Process only after its private admission/identity checks, or by
// the public wrapper for legacy packages. Checked mappings need the Process
// entry registry before any instruction, including a leaf without gates.
bool prepare_validated_package(ModulePackage& package,DmGuestLoadedImage* out,char* error,size_t error_size) {
    const char* detail=nullptr;
    if(package.wire_version==3) {
        if(!validate_v3_lowered_premap(package)) {
            if(error && error_size) std::snprintf(error,error_size,"DMAMOD03 execution is unavailable in the host-only foundation");
            if(out) *out={};
            return false;
        }
        ModulePackage compatible=package;
        compatible.wire_version=2;
        compatible.required_flags&=DM_MODULE_REQUIRE_DIAG_ABORT_V1;
        compatible.exact_guest_records.clear();compatible.returning_retire_records.clear();
        compatible.exact_guest_table_sha256={};compatible.returning_retire_table_sha256={};
        compatible.final_independent_roots_sha256={};compatible.whole_function_ownership_proof_sha256={};
        compatible.gates.clear();compatible.gate_provenance.clear();
        for(size_t i=0;i<package.gates.size();++i)if(package.gates[i].kind!=DM_GUEST_EXACT_GUEST) {
            compatible.gates.push_back(package.gates[i]);
            compatible.gate_provenance.push_back(package.gate_provenance[i]);
        }
        if(!validate_observation_profile(compatible,&detail)) {
            if(error && error_size) std::snprintf(error,error_size,"%s",detail?detail:"invalid canonical profile");
            if(out) *out={};
            return false;
        }
        package.profile=compatible.profile;
    } else if(!validate_observation_profile(package,&detail)) {
        if(error && error_size) std::snprintf(error,error_size,"%s",detail?detail:"invalid canonical profile");
        if(out) *out={};
        return false;
    }
    package.refresh_view();
    return dm_android_guest_prepare_package_image(package.image,out,error,error_size,
                                                   package.wire_version>=2,package.profile!=nullptr);
}
}
bool prepare_package(ModulePackage& package,DmGuestLoadedImage* out,char* error,size_t error_size) {
    if(package.checked_stack || package.stack_admitted_) {
        if(error && error_size) snprintf(error,error_size,"checked-stack mapping requires Process ownership");
        if(out) *out={};
        return false;
    }
    return prepare_validated_package(package,out,error,error_size);
}

bool decode_package(const uint8_t* blob, size_t size, const uint8_t* expected_digest,
                    std::unique_ptr<ModulePackage>* out, std::string* error,
                    const ModuleLimits& limits) {
    if (error) error->clear();
    if (!out) return fail(error, "missing package output");
    out->reset();
    if (!limits_valid(limits)) return fail(error, "invalid module allocation limits");
    if (!blob || size < 320 || size > limits.package_bytes)
        return fail(error, "invalid package size");
    if (!expected_digest || zero(expected_digest,32))
        return fail(error,"trusted whole-package SHA256 is required");
    uint8_t package_digest[32];
    module_sha256(blob,size,package_digest);
    if (memcmp(package_digest,expected_digest,32))
        return fail(error,"whole-package SHA256 mismatch");
    const uint32_t version = u32(blob + 8);
    const size_t header = version == 1 ? 320 : version == 2 ? 384 : version == 3 ? 512 : 0;
    const char* magic = version == 1 ? "DMAMOD01" : version == 2 ? "DMAMOD02" : "DMAMOD03";
    const uint32_t allowed_flags = version == 1 ? 0u : version == 2 ?
        (1u|DM_MODULE_REQUIRE_DIAG_ABORT_V1) :
        (1u|DM_MODULE_REQUIRE_DIAG_ABORT_V1|DM_MODULE_REQUIRE_EXACT_GUEST_V1|
            DM_MODULE_REQUIRE_RETURNING_RETIRE_V1);
    if (!header || size < header || memcmp(blob,magic,8) ||
        u32(blob + 12) != DM_ANDROID_GUEST_ABI || u32(blob + 16) != header ||
        (u32(blob + 20)&~allowed_flags) ||
        ((u32(blob+20)&DM_MODULE_REQUIRE_DIAG_ABORT_V1) && !(u32(blob+20)&1u)) ||
        ((u32(blob+20)&(DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1)) &&
         (version!=3 || !(u32(blob+20)&1u))) ||
        !zero(blob + 296, 24))
        return fail(error, "invalid module format, ABI, flags or reserved header");
    if (version >= 2 && (u32(blob+356) != 32 || u32(blob+376) != 40 || u32(blob+380)))
        return fail(error, "invalid extended metadata strides or reserved word");
    DecodedGuestContractV1 decoded_contract{};
    if(version==3) {
        GuestContractWireError wire_error=GuestContractWireError::Ok;
        if(!decode_guest_contract_v3(blob,size,guest_contract_digest,nullptr,&decoded_contract,&wire_error))
            return fail(error,std::string("invalid DMAMOD03 guest contract: ")+guest_contract_error(wire_error));
    }
    const uint64_t image_size = u64(blob + 24), original_size = u64(blob + 32);
    Span sections[4] = {{u64(blob+40),u64(blob+48)}, {u64(blob+56),u64(blob+64)},
                        {u64(blob+72),u64(blob+80)}, {u64(blob+96),u64(blob+104)}};
    const uint64_t bss = u64(blob + 88);
    if (!image_size || image_size > limits.image_bytes || (image_size & 3) ||
        !original_size || original_size > image_size || !sections[0].size ||
        (sections[0].offset & 3) || (sections[0].size & 3) ||
        !range(sections[2].offset, sections[2].size, original_size) ||
        bss > original_size - sections[2].offset - sections[2].size ||
        (sections[3].offset & 0x3fff) || sections[3].offset < original_size ||
        !range(sections[3].offset, sections[3].size, image_size) ||
        sections[3].offset + sections[3].size != image_size)
        return fail(error, "invalid module section layout");
    sections[2].size += bss;
    uint64_t end = 0;
    for (unsigned i = 0; i < 3; ++i) {
        if (!range(sections[i].offset, sections[i].size, original_size))
            return fail(error, "original section exceeds image");
        end = std::max(end, sections[i].offset + sections[i].size);
        for (unsigned j = 0; j < i; ++j)
            if (overlaps(sections[i], sections[j])) return fail(error, "overlapping original sections");
    }
    if (end != original_size) return fail(error, "original image size does not match sections and BSS");
    const uint64_t payload = u64(blob + 112);
    if ((payload & 15) || payload < header || !range(payload,image_size,size) || payload+image_size != size)
        return fail(error, "invalid payload placement or trailing package bytes");
    Span tables[4];
    uint64_t counts[4]{};
    const uint64_t strides[4] = {16, version == 1 ? 16u : 32u, 16, 40};
    const unsigned table_count = version == 1 ? 3 : 4;
    for (unsigned i = 0; i < table_count; ++i) {
        tables[i].offset = u64(blob + (i == 3 ? 360 : 120 + 16*i));
        counts[i] = u64(blob + (i == 3 ? 368 : 128 + 16*i));
        if (counts[i] > image_size / 4 || counts[i] > (size - header) / strides[i] ||
            (tables[i].offset & 7) || tables[i].offset < header)
            return fail(error, "invalid package metadata table");
        tables[i].size = counts[i] * strides[i];
        if (!range(tables[i].offset,tables[i].size,payload))
            return fail(error, "table exceeds package metadata region");
        for (unsigned j = 0; j < i; ++j)
            if (overlaps(tables[i],tables[j])) return fail(error, "overlapping package tables");
    }
    size_t name_size = 0;
    while (name_size < 16 && blob[168+name_size]) {
        const uint8_t c = blob[168+name_size];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return fail(error, "invalid module name");
        ++name_size;
    }
    if (!name_size || name_size == 16 || !zero(blob+168+name_size,16-name_size))
        return fail(error, "module name is not terminated or has nonzero padding");
    uint8_t digest[32];
    module_sha256(blob + payload, static_cast<size_t>(image_size), digest);
    if (memcmp(digest,blob+248,32)) return fail(error, "rewritten image SHA256 mismatch");
    const uint64_t nsym = u64(blob+280), strbytes = u64(blob+288);
    if (!nsym || nsym > original_size / sizeof(Elf64_Sym) || !strbytes || strbytes > original_size)
        return fail(error, "invalid validated symbol/string counts");
    try {
        auto package = std::make_unique<ModulePackage>();
        package->wire_version = version;
        package->checked_stack = (u32(blob+20)&1)!=0;
        package->required_flags = u32(blob+20)&(DM_MODULE_REQUIRE_DIAG_ABORT_V1|
            DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1);
        if (version >= 2) {
            package->profile_class = u32(blob+352);
            memcpy(package->profile_digest.data(),blob+320,32);
        }
        package->name.assign(reinterpret_cast<const char*>(blob+168),name_size);
        memcpy(package->build_id.data(),blob+184,32);
        memcpy(package->source_sha256.data(),blob+216,32);
        memcpy(package->image_sha256.data(),digest,32);
        package->original_size = static_cast<size_t>(original_size);
        package->data_offset = static_cast<size_t>(u64(blob+72));
        package->data_bytes = static_cast<size_t>(u64(blob+80));
        package->bss_bytes = static_cast<size_t>(bss);
        package->symbol_count = static_cast<size_t>(nsym);
        package->string_bytes = static_cast<size_t>(strbytes);
        package->bytes.assign(blob+payload,blob+size);
        const uint32_t flags[4] = {DM_GUEST_READ|DM_GUEST_EXEC,DM_GUEST_READ,
                                  DM_GUEST_READ|DM_GUEST_WRITE,DM_GUEST_READ|DM_GUEST_EXEC};
        for (unsigned i=0;i<4;++i)
            if (sections[i].size) package->segments.push_back({static_cast<size_t>(sections[i].offset),
                                                              static_cast<size_t>(sections[i].size),flags[i]});
        if (bss && !zero(package->bytes.data()+u64(blob+72)+u64(blob+80),static_cast<size_t>(bss)))
            return fail(error,"nonzero BSS bytes");
        std::unordered_set<size_t> helper_offsets, gate_offsets, site_offsets, tramp_offsets;
        for (uint64_t i=0;i<counts[0];++i) {
            const uint8_t* record=blob+tables[0].offset+i*16;
            const uint64_t off=u64(record); const uint32_t helper=u32(record+8);
            if ((off&7) || !range(off,8,image_size) || u32(record+12) ||
                (helper!=DM_GUEST_STATE_HELPER && helper!=DM_GUEST_DISPATCH_HELPER) ||
                !in_segment(*package,off,8,DM_GUEST_EXEC) || !zero(package->bytes.data()+off,8) ||
                !helper_offsets.insert(static_cast<size_t>(off)).second)
                return fail(error,"invalid helper record");
            package->fixups.push_back({static_cast<size_t>(off),helper});
        }
        for (uint64_t i=0;i<counts[1];++i) {
            const uint8_t* record=blob+tables[1].offset+i*strides[1];
            const uint64_t off=u64(record), original=version >= 2 ? u64(record+8) : 0;
            const uint32_t kind=u32(record+(version >= 2 ? 16 : 8)),
                           arg=u32(record+(version >= 2 ? 20 : 12));
            if ((off&3) || off<4 || !range(off,4,image_size) ||
                !in_segment(*package,off-4,8,DM_GUEST_EXEC) ||
                ((kind==DM_GUEST_SVC && arg>65535) || (kind==DM_GUEST_TIMER && arg>31) ||
                 (kind==DM_GUEST_OBSERVATION && (!arg || arg>=256)) ||
                 (kind==DM_GUEST_INDIRECT_HOST && (arg>30 || arg==18)) ||
                  (kind!=DM_GUEST_SVC && kind!=DM_GUEST_TIMER &&
                   !(version >= 2 && (kind==DM_GUEST_OBSERVATION || kind==DM_GUEST_INDIRECT_HOST ||
                                     (package->checked_stack && kind==DM_GUEST_STACK_CHECK) ||
                                     (version==3 && package->checked_stack &&
                                      kind==DM_GUEST_EXACT_GUEST && arg==17))))) ||
                (version >= 2 && (u32(record+28) || (original&3) ||
                    !in_segment(*package,original,4,DM_GUEST_EXEC) || original >= original_size)) ||
                u32(package->bytes.data()+off-4)!=0xd63f03c0u ||
                !gate_offsets.insert(static_cast<size_t>(off)).second)
                return fail(error,"invalid gate record");
            package->gates.push_back({static_cast<size_t>(off),kind,arg});
            if (version >= 2) package->gate_provenance.push_back({off,original,kind,arg,u32(record+24),u32(record+28)});
        }
        for (uint64_t i=0;i<counts[2];++i) {
            const uint8_t* record=blob+tables[2].offset+i*16;
            const uint64_t orig=u64(record),tramp=u64(record+8);
            if ((orig&3) || (tramp&3) || orig<sections[0].offset ||
                !range(orig-sections[0].offset,4,sections[0].size) || tramp<sections[3].offset ||
                !range(tramp-sections[3].offset,4,sections[3].size) ||
                !site_offsets.insert(static_cast<size_t>(orig)).second ||
                !tramp_offsets.insert(static_cast<size_t>(tramp)).second)
                return fail(error,"invalid rewrite-site record");
            package->sites.push_back({static_cast<size_t>(orig),static_cast<size_t>(tramp)});
        }
        for (uint64_t i=0;i<counts[3];++i) {
            const uint8_t* r=blob+tables[3].offset+i*40;
            if (u32(r+36)) return fail(error,"nonzero parameter reserved word");
            package->parameters.push_back({u64(r),u64(r+8),u32(r+16),u32(r+20),u32(r+24),u32(r+28),u32(r+32)});
        }
        const char* profile_error=nullptr;
        if(version==3) {
            package->exact_guest_records=std::move(decoded_contract.exact_guest);
            package->returning_retire_records=std::move(decoded_contract.returning_retire);
            package->exact_guest_table_sha256=decoded_contract.exact_guest_table_sha256;
            package->returning_retire_table_sha256=decoded_contract.returning_retire_table_sha256;
            package->final_independent_roots_sha256=decoded_contract.final_independent_roots_sha256;
            package->whole_function_ownership_proof_sha256=decoded_contract.whole_function_ownership_proof_sha256;
            ModulePackage compatible=*package;
            compatible.wire_version=2;
            compatible.required_flags&=DM_MODULE_REQUIRE_DIAG_ABORT_V1;
            compatible.exact_guest_records.clear();compatible.returning_retire_records.clear();
            compatible.exact_guest_table_sha256={};compatible.returning_retire_table_sha256={};
            compatible.final_independent_roots_sha256={};compatible.whole_function_ownership_proof_sha256={};
            compatible.gates.clear();compatible.gate_provenance.clear();
            for(size_t i=0;i<package->gates.size();++i)if(package->gates[i].kind!=DM_GUEST_EXACT_GUEST) {
                compatible.gates.push_back(package->gates[i]);
                compatible.gate_provenance.push_back(package->gate_provenance[i]);
            }
            if(!validate_observation_profile(compatible,&profile_error))return fail(error,profile_error);
            package->profile=compatible.profile;
        } else if (!validate_observation_profile(*package,&profile_error)) return fail(error,profile_error);
        package->refresh_view();
        if(package->checked_stack) {
            package->stack_identity_=package_identity(*package);
            package->stack_admitted_=true;
        }
        package->capsule_verified_=true;package->capsule_bytes_=size;
        memcpy(package->capsule_sha256_.data(),package_digest,32);
        *out=std::move(package);
        return true;
    } catch (const std::bad_alloc&) { return fail(error,"module package allocation failed"); }
}

bool decode_package_with_audits(const uint8_t* blob,size_t size,const uint8_t* expected_digest,
                    const TrustedCallbackAudit* callback_audit,
                    const TrustedGuestContractAuditV1* contract_audit,
                    std::unique_ptr<ModulePackage>* out,std::string* error,
                    const ModuleLimits& limits) {
    if(error)error->clear();
    if(!out)return fail(error,"missing package output");
    out->reset();
    if(callback_audit && contract_audit)
        return fail(error,"callback and guest-contract audits target different package versions");
    if(callback_audit) {
        const auto& audit=*callback_audit;
        // Bound caller-supplied counts before decoding or allocating a root list.
        if(!limits_valid(limits) || !blob || size<384 || size>limits.package_bytes ||
           audit.version!=1 || audit.root_kind!=CallbackRootKind::DefinedSttFunc ||
           (audit.indirect_policy!=CallbackIndirectPolicy::Strict &&
            audit.indirect_policy!=CallbackIndirectPolicy::GuardedHost) ||
           audit.root_count>limits.callback_roots || (audit.root_count && !audit.roots) ||
           memcmp(blob,"DMAMOD02",8) || u32(blob+8)!=2 ||
           audit.root_count>u64(blob+48)/4)
            return fail(error,"invalid or unsupported trusted callback audit");
        if(!expected_digest || memcmp(audit.package_sha256.data(),expected_digest,32) ||
           memcmp(audit.source_sha256.data(),blob+216,32))
            return fail(error,"callback audit package/source identity mismatch");
        for(size_t i=0;i<audit.root_count;++i) {
            const uint64_t root=audit.roots[i],text=u64(blob+40),text_size=u64(blob+48);
            if((root&3) || root<text || !range(root-text,4,text_size) ||
               (i && audit.roots[i-1]>=root))
                return fail(error,"callback audit roots must be sorted unique original-text entries");
        }
    }
    if(contract_audit) {
        const auto& audit=*contract_audit;
        if(!limits_valid(limits) || !blob || size<512 || size>limits.package_bytes ||
           memcmp(blob,"DMAMOD03",8) || u32(blob+8)!=3 ||
           audit.schema!=1 || audit.flags)
            return fail(error,"invalid or unsupported trusted guest-contract audit");
        if(!expected_digest || memcmp(audit.package_sha256.data(),expected_digest,32) ||
           memcmp(audit.source_sha256.data(),blob+216,32) ||
           memcmp(audit.build_id.data(),blob+184,32))
            return fail(error,"guest-contract audit package/source/build identity mismatch");
    }
    std::unique_ptr<ModulePackage> package;
    if(!decode_package(blob,size,expected_digest,&package,error,limits))return false;
    try {
        if(callback_audit) {
            const auto& audit=*callback_audit;
            const bool guarded=std::any_of(package->gates.begin(),package->gates.end(),
                [](const DmGuestGate& gate){return gate.kind==DM_GUEST_INDIRECT_HOST;});
            if(guarded && audit.indirect_policy==CallbackIndirectPolicy::Strict)
                return fail(error,"strict callback audit contains guarded-host gates");
            if(!validate_callback_symbols(*package,audit,error))return false;
            if(audit.root_count)package->callback_roots_.assign(audit.roots,audit.roots+audit.root_count);
            package->callback_indirect_policy_=audit.indirect_policy;
            package->callback_identity_=package_identity(*package);package->callback_admitted_=true;
        }
        if(contract_audit) {
            DecodedGuestContractV1 decoded{};
            decoded.required_flags=(package->checked_stack?1u:0u)|package->required_flags;
            decoded.exact_guest=package->exact_guest_records;
            decoded.returning_retire=package->returning_retire_records;
            decoded.exact_guest_table_sha256=package->exact_guest_table_sha256;
            decoded.returning_retire_table_sha256=package->returning_retire_table_sha256;
            decoded.final_independent_roots_sha256=package->final_independent_roots_sha256;
            decoded.whole_function_ownership_proof_sha256=package->whole_function_ownership_proof_sha256;
            GuestContractWireError audit_error=GuestContractWireError::Ok;
            if(!validate_guest_contract_audit_v1(decoded,*contract_audit,
                   package->capsule_sha256_.data(),package->source_sha256.data(),package->build_id.data(),
                   guest_contract_digest,nullptr,&audit_error))
                return fail(error,std::string("guest-contract admission failed: ")+guest_contract_error(audit_error));
            auto token=std::make_unique<ModulePackage::GuestContractAdmissionTokenV1>();
            token->package_identity=package_identity(*package);
            token->audit_identity=contract_audit->audit_identity_sha256;
            package->guest_contract_admission_=std::move(token);
        }
        *out=std::move(package);return true;
    } catch(const std::bad_alloc&) {return fail(error,"trusted package audit allocation failed");}
}

bool read_package_fd(int fd, const uint8_t* expected_digest, std::unique_ptr<ModulePackage>* out,
                     std::string* error, const ModuleLimits& limits) {
    if (!out) return fail(error,"missing package output");
    out->reset();
    if (!expected_digest || zero(expected_digest,32))
        return fail(error,"trusted whole-package SHA256 is required");
    struct stat st{};
    if (!limits_valid(limits) || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<320 ||
        static_cast<uint64_t>(st.st_size)>limits.package_bytes)
        return fail(error,"invalid package descriptor, size or allocation limits");
    try {
        std::vector<uint8_t> bytes(static_cast<size_t>(st.st_size));
        size_t done=0;
        while(done<bytes.size()) {
            ssize_t n=pread(fd,bytes.data()+done,bytes.size()-done,static_cast<off_t>(done));
            if(n<0 && errno==EINTR) continue;
            if(n<=0) return fail(error,"cannot read complete module package");
            done+=static_cast<size_t>(n);
        }
        return decode_package(bytes.data(),bytes.size(),expected_digest,out,error,limits);
    } catch (const std::bad_alloc&) { return fail(error,"module file allocation failed"); }
}

struct ModuleDynamic {
    std::vector<Elf64_Sym> symbols;
    std::vector<Elf64_Rela> relocations;
    std::unordered_map<std::string,size_t> exports;
    std::unordered_map<std::string,size_t> definitions;
    size_t dynamic=0, symtab=0, strings=0, string_bytes=0, init=0, init_array=0, init_array_bytes=0;
    size_t jmprel_offset_index=0, jmprel_count=0;
};

namespace {
bool parse_dynamic(const ModulePackage& p, ModuleDynamic* out, std::string* error) {
    if (!out || !in_original(p,0,8)) return fail(error,"missing original MOD0 pointer");
    const uint64_t mod=u32(p.bytes.data()+4);
    if ((mod&3) || !in_original(p,mod,28) || memcmp(p.bytes.data()+mod,"MOD0",4))
        return fail(error,"invalid MOD0 header");
    const int64_t relative=static_cast<int32_t>(u32(p.bytes.data()+mod+4));
    const auto mod_relative = [&](unsigned field) {
        return static_cast<int64_t>(mod) + static_cast<int32_t>(u32(p.bytes.data()+mod+field));
    };
    // NSO BSS sizes describe the allocated zero tail. MOD0 describes logical
    // BSS inside it; linker padding may precede/follow that logical range.
    if(!range(p.data_offset,p.data_bytes,p.original_size) ||
       !range(p.data_offset+p.data_bytes,p.bss_bytes,p.original_size))
        return fail(error,"MOD0 BSS allocation exceeds original image");
    const uint64_t data_end=p.data_offset+p.data_bytes, allocation_end=data_end+p.bss_bytes;
    const int64_t bss_begin=mod_relative(8),bss_end=mod_relative(12);
    if(bss_begin<0 || bss_end<bss_begin || static_cast<uint64_t>(bss_begin)<data_end ||
       static_cast<uint64_t>(bss_end)>allocation_end)
        return fail(error,"MOD0 BSS geometry exceeds package allocation");
    const int64_t eh_begin=mod_relative(16),eh_end=mod_relative(20),object=mod_relative(24);
    if(eh_begin<0 || eh_end<eh_begin ||
       (eh_begin!=eh_end && !in_original(p,static_cast<uint64_t>(eh_begin),static_cast<uint64_t>(eh_end-eh_begin))) ||
       (object!=static_cast<int64_t>(mod) && (object<0 || !in_segment(p,static_cast<uint64_t>(object),1,DM_GUEST_WRITE))))
        return fail(error,"invalid MOD0 EH-frame or module-object range");
    const int64_t dynamic=static_cast<int64_t>(mod)+relative;
    if (dynamic<0 || (dynamic&7) || !in_original(p,static_cast<uint64_t>(dynamic),16))
        return fail(error,"invalid MOD0 dynamic offset");
    std::unordered_map<int64_t,uint64_t> tags;
    bool terminated=false;
    uint64_t dynamic_bytes=0;
    // A bounded dynamic table can never consume the appended executable patch.
    for(uint64_t off=static_cast<uint64_t>(dynamic), count=0;count<65536;++count,off+=16) {
        if(!in_original(p,off,16)) return fail(error,"unterminated or out-of-range dynamic table");
        const auto d=read<Elf64_Dyn>(p,static_cast<size_t>(off));
        if(d.d_tag==DT_NULL) { terminated=true;dynamic_bytes=off+16-static_cast<uint64_t>(dynamic);break; }
        // DT_NEEDED may repeat; singleton structural tags must not.
        if (d.d_tag!=DT_NEEDED && !tags.emplace(d.d_tag,d.d_un.d_val).second)
            return fail(error,"duplicate dynamic tag");
    }
    if(!terminated || !in_original(p,static_cast<uint64_t>(dynamic),dynamic_bytes))
        return fail(error,"dynamic entry limit exceeded or table crosses sections");
    auto get=[&](int64_t t) { auto i=tags.find(t);return i==tags.end()?uint64_t(0):i->second; };
    const uint64_t sym=get(DT_SYMTAB),str=get(DT_STRTAB),strsz=get(DT_STRSZ);
    if(!tags.count(DT_SYMTAB) || !tags.count(DT_STRTAB) || get(DT_SYMENT)!=sizeof(Elf64_Sym) ||
       !strsz || strsz!=p.string_bytes || (sym&7) ||
       !in_original(p,sym,p.symbol_count*sizeof(Elf64_Sym)) || !in_original(p,str,strsz))
        return fail(error,"invalid dynamic symbol/string tables");
    if(overlaps({sym,p.symbol_count*sizeof(Elf64_Sym)},{str,strsz}))
        return fail(error,"overlapping symbol and string tables");
    size_t hash_count=0;
    if(tags.count(DT_HASH)) {
        uint64_t h=get(DT_HASH);
        if((h&3) || !in_original(p,h,8)) return fail(error,"invalid ELF hash header");
        uint64_t buckets=u32(p.bytes.data()+h),chains=u32(p.bytes.data()+h+4);
        if(!buckets || !chains || chains!=p.symbol_count ||
           !in_original(p,h,8+4*(buckets+chains))) return fail(error,"invalid ELF hash counts or bounds");
        for(uint64_t i=0;i<buckets+chains;++i)
            if(u32(p.bytes.data()+h+8+i*4)>=chains) return fail(error,"ELF hash index exceeds symbol count");
        // Check every chain, including unreachable ones, in linear time.
        std::vector<uint8_t> marks(static_cast<size_t>(chains),0);
        const uint8_t* chain=p.bytes.data()+h+8+buckets*4;
        for(uint64_t start=1;start<chains;++start) {
            uint32_t index=static_cast<uint32_t>(start);
            while(index && !marks[index]) { marks[index]=1; index=u32(chain+index*4); }
            if(index && marks[index]==1) return fail(error,"cyclic ELF hash chain");
            index=static_cast<uint32_t>(start);
            while(index && marks[index]==1) { marks[index]=2; index=u32(chain+index*4); }
        }
        hash_count=static_cast<size_t>(chains);
    }
    if(tags.count(DT_GNU_HASH)) {
        const uint64_t h=get(DT_GNU_HASH);
        if((h&7) || !in_original(p,h,16)) return fail(error,"invalid GNU hash header");
        const uint64_t buckets=u32(p.bytes.data()+h),first=u32(p.bytes.data()+h+4),
                       bloom=u32(p.bytes.data()+h+8),shift=u32(p.bytes.data()+h+12);
        if(!buckets || !first || !bloom || (bloom&(bloom-1)) || shift>=64 || first>p.symbol_count ||
           !in_original(p,h,16+bloom*8+buckets*4+(p.symbol_count-first)*4))
            return fail(error,"invalid GNU hash counts or bounds");
        const uint8_t* bucket=p.bytes.data()+h+16+bloom*8;
        const uint8_t* chain=bucket+buckets*4;
        size_t derived=static_cast<size_t>(first);
        // Bound total chain walking as well as every individual read.
        uint64_t walked=0;
        for(uint64_t i=0;i<buckets;++i) {
            uint64_t index=u32(bucket+i*4);
            if(!index) continue;
            if(index<first || index>=p.symbol_count) return fail(error,"GNU hash bucket outside symbols");
            for(;;++index) {
                if(index>=p.symbol_count || ++walked>p.symbol_count+buckets)
                    return fail(error,"unterminated or overlapping GNU hash chain");
                derived=std::max(derived,static_cast<size_t>(index+1));
                if(u32(chain+(index-first)*4)&1) break;
            }
        }
        if(derived!=p.symbol_count || (hash_count && hash_count!=derived))
            return fail(error,"GNU hash count differs from validated header");
        hash_count=derived;
    }
    // Hashless NSOs are accepted only when the supplied count is independently
    // established by the exact adjacent SYMTAB/STRTAB extent and DT_STRSZ.
    if(!hash_count && (sym>str || str-sym!=p.symbol_count*sizeof(Elf64_Sym)))
        return fail(error,"unverifiable hashless dynamic symbol count");
    if(!zero(p.bytes.data()+sym,sizeof(Elf64_Sym)) || p.bytes[str] || p.bytes[str+strsz-1])
        return fail(error,"invalid null dynamic symbol or string");
    out->dynamic=static_cast<size_t>(dynamic);out->symtab=static_cast<size_t>(sym);
    out->strings=static_cast<size_t>(str);out->string_bytes=static_cast<size_t>(strsz);
    out->symbols.reserve(p.symbol_count);
    for(size_t i=0;i<p.symbol_count;++i) {
        auto s=read<Elf64_Sym>(p,static_cast<size_t>(sym)+i*sizeof(Elf64_Sym));
        if(s.st_name>=strsz || !memchr(p.bytes.data()+str+s.st_name,0,static_cast<size_t>(strsz-s.st_name)))
            return fail(error,"unterminated dynamic symbol name");
        const unsigned binding=ELF64_ST_BIND(s.st_info),type=ELF64_ST_TYPE(s.st_info);
        if(binding!=STB_LOCAL && binding!=STB_GLOBAL && binding!=STB_WEAK)
            return fail(error,"unsupported dynamic symbol binding");
        if(type>STT_FUNC || (s.st_other&~3u) || (!s.st_shndx && (s.st_value || s.st_size)))
            return fail(error,"unsupported dynamic symbol attributes or undefined value");
        // GNU ld linker markers carry an address without storage. This exact
        // one-past value grants neither a readable byte nor a function entry.
        const bool end_marker=type!=STT_FUNC && !s.st_size && s.st_value==p.original_size;
        if(s.st_shndx && s.st_shndx!=SHN_ABS &&
           ((!end_marker && !in_original(p,s.st_value,s.st_size?s.st_size:1)) || s.st_shndx>=SHN_LORESERVE))
            return fail(error,"invalid defined symbol range or section");
        if(s.st_shndx && s.st_shndx!=SHN_ABS && type==STT_FUNC &&
           ((s.st_value&3) || (s.st_size&3) || !in_segment(p,s.st_value,s.st_size?s.st_size:4,DM_GUEST_EXEC)))
            return fail(error,"function symbol outside executable section or unaligned");
        out->symbols.push_back(s);
        if(s.st_shndx) out->definitions.emplace(reinterpret_cast<const char*>(p.bytes.data()+str+s.st_name),i);
        if(s.st_shndx && binding!=STB_LOCAL && (s.st_other&3)!=STV_HIDDEN && (s.st_other&3)!=STV_INTERNAL)
            out->exports.emplace(reinterpret_cast<const char*>(p.bytes.data()+str+s.st_name),i);
    }
    if(tags.count(DT_REL) || tags.count(DT_RELSZ) || tags.count(DT_RELR) || tags.count(DT_RELRSZ))
        return fail(error,"unsupported REL/RELR relocation format");
    Span rela[2]={{get(DT_RELA),get(DT_RELASZ)},{get(DT_JMPREL),get(DT_PLTRELSZ)}};
    if((tags.count(DT_RELA)!=tags.count(DT_RELASZ)) ||
       (tags.count(DT_JMPREL)!=tags.count(DT_PLTRELSZ)) ||
       (rela[0].size && get(DT_RELAENT)!=sizeof(Elf64_Rela)) ||
       (rela[1].size && get(DT_PLTREL)!=DT_RELA) || overlaps(rela[0],rela[1]))
        return fail(error,"invalid RELA dynamic tags or overlapping tables");
    std::unordered_set<size_t> targets;
    for(unsigned table_idx=0;table_idx<2;++table_idx) {
        const Span table=rela[table_idx];
        if(table_idx==1) out->jmprel_offset_index=out->relocations.size();
        if(table.size && ((table.offset&7) || table.size%sizeof(Elf64_Rela) ||
                          !in_original(p,table.offset,table.size)))
            return fail(error,"invalid RELA table bounds");
        for(uint64_t at=0;at<table.size;at+=sizeof(Elf64_Rela)) {
            auto r=read<Elf64_Rela>(p,static_cast<size_t>(table.offset+at));
            uint32_t type=ELF64_R_TYPE(r.r_info);uint64_t index=ELF64_R_SYM(r.r_info);
            // Packed NSO RELATIVE fields can be four-aligned; publication below
            // uses memcpy for the complete eight bytes. Keep all other places
            // eight-aligned and reject partial as well as exact write aliases.
            const uint64_t alignment_mask=type==1027?3:7;
            if((r.r_offset&alignment_mask) || !in_segment(p,r.r_offset,8,DM_GUEST_WRITE) ||
               index>=p.symbol_count ||
               (r.r_offset>=4 && targets.count(static_cast<size_t>(r.r_offset-4))) ||
               targets.count(static_cast<size_t>(r.r_offset+4)) ||
               !targets.insert(static_cast<size_t>(r.r_offset)).second ||
               (type!=1027 && type!=257 && type!=1025 && type!=1026))
                return fail(error,"unsupported relocation or invalid relocation target/symbol");
            if(type==1027 && (index || r.r_addend<0 ||
                             (static_cast<uint64_t>(r.r_addend)!=p.original_size &&
                              !in_original(p,static_cast<uint64_t>(r.r_addend),1))))
                return fail(error,"invalid RELATIVE relocation symbol or addend");
            out->relocations.push_back(r);
        }
        if(table_idx==1) out->jmprel_count=out->relocations.size()-out->jmprel_offset_index;
    }
    if(tags.count(DT_INIT)) {
        const uint64_t init=get(DT_INIT);
        if(init && ((init&3) || !in_segment(p,init,4,DM_GUEST_EXEC) || init>=p.original_size))
            return fail(error,"invalid DT_INIT executable offset");
        out->init=static_cast<size_t>(init);
    }
    if(tags.count(DT_INIT_ARRAY)!=tags.count(DT_INIT_ARRAYSZ) ||
       (get(DT_INIT_ARRAYSZ) && ((get(DT_INIT_ARRAY)&7) || (get(DT_INIT_ARRAYSZ)&7) ||
                               !in_original(p,get(DT_INIT_ARRAY),get(DT_INIT_ARRAYSZ)))))
        return fail(error,"invalid DT_INIT_ARRAY bounds");
    out->init_array=static_cast<size_t>(get(DT_INIT_ARRAY));
    out->init_array_bytes=static_cast<size_t>(get(DT_INIT_ARRAYSZ));
    return true;
}
bool validate_callback_symbols(const ModulePackage& p,const TrustedCallbackAudit& audit,std::string* error) {
    ModuleDynamic dynamic;
    if(!parse_dynamic(p,&dynamic,error)) return false;
    std::unordered_set<uint64_t> eligible;
    for(const auto& s:dynamic.symbols) {
        if(!s.st_shndx || s.st_shndx==SHN_ABS || ELF64_ST_TYPE(s.st_info)!=STT_FUNC) continue;
        // Original text is the first segment. Appended trampoline RX, other
        // readable sections, ABS and undefined functions cannot grant roots.
        const auto& text=p.segments.front();
        if((s.st_value&3) || s.st_value<text.offset ||
           !range(s.st_value-text.offset,s.st_size?s.st_size:4,text.size))
            return fail(error,"callback function exceeds original executable text");
        if(!eligible.count(s.st_value)) {
            if(eligible.size()>=audit.root_count) return fail(error,"callback audit omits defined function entry");
            eligible.insert(s.st_value);
        }
    }
    if(eligible.size()!=audit.root_count) return fail(error,"callback audit differs from defined function entries");
    for(size_t i=0;i<audit.root_count;++i)
        if(!eligible.count(audit.roots[i])) return fail(error,"callback audit contains non-function entry");
    return true;
}
const char* symbol_name(const LoadedModule& m,const Elf64_Sym& s) {
    return reinterpret_cast<const char*>(m.package->bytes.data()+m.dynamic->strings+s.st_name);
}
uintptr_t definition(const LoadedModule& m,const Elf64_Sym& s) {
    return s.st_shndx==SHN_ABS ? static_cast<uintptr_t>(s.st_value) :
           reinterpret_cast<uintptr_t>(m.mapping.base)+static_cast<uintptr_t>(s.st_value);
}
bool lookup(const std::vector<std::unique_ptr<LoadedModule>>& modules,const char* name,uintptr_t* address) {
    for(const auto& m:modules) {
        const auto found=m->dynamic->exports.find(name);
        if(found!=m->dynamic->exports.end()) {
            *address=definition(*m,m->dynamic->symbols[found->second]);return true;
        }
    }
    return false;
}
bool addend(uintptr_t address,int64_t value,uintptr_t* out) {
    if(value>=0) {
        if(static_cast<uint64_t>(value)>UINTPTR_MAX-address) return false;
        *out=address+static_cast<uintptr_t>(value);
    } else {
        uint64_t magnitude=uint64_t(-(value+1))+1;
        if(magnitude>address) return false;
        *out=address-static_cast<uintptr_t>(magnitude);
    }
    return true;
}
}

LoadedModule::LoadedModule() = default;
LoadedModule::~LoadedModule() { dm_android_guest_unload(&mapping); }
Process::~Process() { unload(); }
void Process::unload() {
    if(host_bound_) std::abort(); // cached common-C module pointers remain borrowed
    {
        std::lock_guard<std::mutex> lock(stack_entry_mutex);
        stack_entries.erase(std::remove_if(stack_entries.begin(),stack_entries.end(),
            [&](const StackEntryAuthority& a){return a.process==this;}),stack_entries.end());
    }
    callback_roots_.clear();gates_.clear();modules_.clear();initializing_=false;initializer_failed_=false;checked_stack_=false;
    load_generation_=++process_generation;
}

bool Process::load(std::vector<std::unique_ptr<ModulePackage>> packages,
                   HostResolver resolver,void* context,std::string* error,const ModuleLimits& limits) {
    if(error) error->clear();
    if(host_bound_) return fail(error,"cannot replace process while common host borrows module views");
    if(initializing_) return fail(error,"cannot replace process during initialization");
    if(!limits_valid(limits) || packages.empty() || packages.size()>limits.module_count)
        return fail(error,"invalid process module count or limits");
    try {
        // Scan the complete input graph before parsing, resolving, mapping or
        // publishing any member.  A later v3 module therefore cannot leave an
        // earlier v2 module transiently mapped.  Typed v3 authority must first
        // match its private post-decode admission, even though this foundation
        // deliberately has no v3 execution path.
        bool contains_v3=false;
        for(const auto& package:packages)if(package && package->wire_version==3) {
            contains_v3=true;
            const uint32_t typed=package->required_flags&
                (DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1);
            const std::array<uint8_t,32> empty{};
            const bool exact=!package->exact_guest_records.empty();
            const bool retire=!package->returning_retire_records.empty();
            if((package->required_flags&~(DM_MODULE_REQUIRE_DIAG_ABORT_V1|
                    DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1)) ||
               ((package->required_flags&DM_MODULE_REQUIRE_DIAG_ABORT_V1) && !package->checked_stack) ||
               ((typed!=0) && !package->checked_stack) ||
               exact!=bool(typed&DM_MODULE_REQUIRE_EXACT_GUEST_V1) ||
               retire!=bool(typed&DM_MODULE_REQUIRE_RETURNING_RETIRE_V1) ||
               exact!=(package->exact_guest_table_sha256!=empty) ||
               retire!=(package->returning_retire_table_sha256!=empty))
                return fail(error,"invalid or altered DMAMOD03 public contract metadata");
            if(typed) {
                if(!package->guest_contract_admission_)
                    return fail(error,"DMAMOD03 typed records require trusted guest-contract admission");
                if(package->guest_contract_admission_->package_identity!=package_identity(*package))
                    return fail(error,"DMAMOD03 guest-contract admission is stale or package data changed");
            }
            if(!validate_v3_lowered_premap(*package))
                return fail(error,"DMAMOD03 execution is unavailable in the host-only foundation");
        }
        if(contains_v3) {
            for(const auto& package:packages)
                if(!package || !package->checked_stack || !package->stack_admitted_)
                    return fail(error,"DMAMOD03 execution is unavailable in the host-only foundation");
        }
        std::vector<std::unique_ptr<LoadedModule>> candidate;
        std::unordered_set<std::string> names;
        size_t total=0;
        const bool checked=packages.front() && packages.front()->checked_stack;
        for(auto& package:packages) {
            if(!package || !names.insert(package->name).second || package->bytes.size()>limits.image_bytes ||
               !package->bytes.size() || package->bytes.size()>1024u*1024u*1024u-total)
                return fail(error,"invalid, duplicate or excessive process modules (aggregate 1 GiB limit)");
            total+=package->bytes.size();
            const uint32_t allowed_required=package->wire_version==2 ? DM_MODULE_REQUIRE_DIAG_ABORT_V1 :
                package->wire_version==3 ? (DM_MODULE_REQUIRE_DIAG_ABORT_V1|
                    DM_MODULE_REQUIRE_EXACT_GUEST_V1|DM_MODULE_REQUIRE_RETURNING_RETIRE_V1) : 0u;
            if((package->required_flags&~allowed_required) ||
               (package->required_flags && !package->checked_stack))
                return fail(error,"invalid required diagnostic ABI flags");
            if(package->checked_stack!=checked || (package->checked_stack &&
               (!package->stack_admitted_ || package->stack_identity_!=package_identity(*package))))
                return fail(error,"mixed or altered checked-stack module graph");
            if(package->stack_admitted_ && package->stack_identity_!=package_identity(*package))
                return fail(error,"checked-stack property changed after admission");
            if(package->callback_admitted_ && package->callback_identity_!=package_identity(*package))
                return fail(error,"receipt-backed module changed after callback admission");
            uint8_t hash[32]; module_sha256(package->bytes.data(),package->bytes.size(),hash);
            if(memcmp(hash,package->image_sha256.data(),32)) return fail(error,"module payload changed after decode");
            package->refresh_view();
            auto m=std::make_unique<LoadedModule>(); m->package=std::move(package);
            m->load_identity_=package_identity(*m->package);
            m->mapped_segments_=m->package->segments;
            m->checked_stack_=m->package->checked_stack;
            m->required_flags_=m->package->required_flags;
            m->capsule_verified_=m->package->capsule_verified_;
            m->capsule_bytes_=m->package->capsule_bytes_;
            m->capsule_sha256_=m->package->capsule_sha256_;
            m->guest_contract_admitted_=m->package->guest_contract_admission_!=nullptr &&
                m->package->guest_contract_admission_->package_identity==m->load_identity_;
            if(m->guest_contract_admitted_)
                m->guest_contract_audit_identity_=m->package->guest_contract_admission_->audit_identity;
            m->dynamic=std::make_unique<ModuleDynamic>();
            if(!parse_dynamic(*m->package,m->dynamic.get(),error)) return false;
            if(m->package->wire_version==3) {
                for(const auto& x:m->package->exact_guest_records) {
                    if(x.relocation_index>=m->dynamic->jmprel_count || x.relocation_type!=1026 ||
                       x.relocation_addend!=0 || !x.symbol_index || x.symbol_index>=m->dynamic->symbols.size())
                        return fail(error,m->package->name+": exact-guest relocation index or type mismatch");
                    const auto& rel=m->dynamic->relocations[m->dynamic->jmprel_offset_index+x.relocation_index];
                    if(rel.r_offset!=x.got_offset || ELF64_R_TYPE(rel.r_info)!=x.relocation_type ||
                       ELF64_R_SYM(rel.r_info)!=x.symbol_index || rel.r_addend!=x.relocation_addend)
                        return fail(error,m->package->name+": exact-guest JMPREL entry disagrees with record");
                    const auto& sym=m->dynamic->symbols[x.symbol_index];
                    const char* sname=reinterpret_cast<const char*>(m->package->bytes.data()+m->dynamic->strings+sym.st_name);
                    uint8_t sname_sha[32]{};
                    module_sha256(reinterpret_cast<const uint8_t*>(sname),std::strlen(sname),sname_sha);
                    if(sym.st_name!=x.symbol_name_offset || std::strlen(sname)!=x.symbol_name_length ||
                       std::memcmp(sname_sha,x.symbol_name_sha256.data(),32) ||
                       ELF64_ST_TYPE(sym.st_info)!=x.symbol_type || x.symbol_type!=STT_FUNC ||
                       ELF64_ST_BIND(sym.st_info)!=x.symbol_binding ||
                       (sym.st_other&3u)!=x.symbol_visibility ||
                       sym.st_shndx!=x.symbol_section_index || !sym.st_shndx || sym.st_shndx==SHN_ABS ||
                       sym.st_value!=x.symbol_value || sym.st_size!=x.symbol_size ||
                       x.same_module_target_offset!=sym.st_value)
                        return fail(error,m->package->name+": exact-guest dynamic symbol disagrees with record");
                }
            }
            char detail[256];
            if(!prepare_validated_package(*m->package,&m->mapping,detail,sizeof(detail)))
                return fail(error,m->package->name+": "+detail);
            candidate.push_back(std::move(m));
        }
        for(const auto& m:candidate) {
            size_t required_bindings=0;
            size_t exact_bindings=0;
            for(size_t rel_pos=0;rel_pos<m->dynamic->relocations.size();++rel_pos) {
                const auto& r=m->dynamic->relocations[rel_pos];
                const auto& s=m->dynamic->symbols[ELF64_R_SYM(r.r_info)];
                const char* name=symbol_name(*m,s); uintptr_t address=0,value=0;
                const ExactGuestRecordV1* exact_rec=nullptr;
                if(m->package->wire_version==3) {
                    for(const auto& x:m->package->exact_guest_records)
                        if(x.got_offset==r.r_offset) { exact_rec=&x; break; }
                }
                if(exact_rec) {
                    if(rel_pos<m->dynamic->jmprel_offset_index ||
                       rel_pos-m->dynamic->jmprel_offset_index!=exact_rec->relocation_index ||
                       ELF64_R_TYPE(r.r_info)!=1026 || r.r_addend!=0 || !s.st_shndx || s.st_shndx==SHN_ABS)
                        return fail(error,m->package->name+": invalid exact-guest relocation binding");
                    uintptr_t forced_addr=0;
                    if(resolver && resolver(name,true,&forced_addr,context))
                        return fail(error,m->package->name+": forced host override is forbidden for exact-guest symbol "+name);
                    address=definition(*m,s);
                    const uintptr_t expected=reinterpret_cast<uintptr_t>(m->mapping.base)+exact_rec->same_module_target_offset;
                    if(address!=expected)
                        return fail(error,m->package->name+": exact-guest definition disagrees with target offset");
                    ++exact_bindings;
                }
                else if((m->required_flags_&DM_MODULE_REQUIRE_DIAG_ABORT_V1) &&
                   !std::strcmp(name,DM_DIAG_ABORT_IMPL_SYMBOL)) {
                    const uintptr_t canonical=reinterpret_cast<uintptr_t>(&dm_android_diag_abort_entry);
                    if(ELF64_R_TYPE(r.r_info)!=1026 || r.r_addend || !canonical || !resolver ||
                       !resolver(DM_DIAG_ABORT_RESOLVER_V1,true,&address,context) || address!=canonical)
                        return fail(error,m->package->name+": required diagnostic abort ABI binding unavailable or invalid");
                    ++required_bindings;
                    size_t plt_count=0;
                    // This scan only rejects incomplete contract coverage; it
                    // grants no code, callback, or arbitrary target authority.
                    for(const auto& segment:m->package->segments) {
                        if(!(segment.flags&DM_GUEST_EXEC))continue;
                        for(uint64_t plt=segment.offset;range(plt,16,m->package->original_size) &&
                            range(plt-segment.offset,16,segment.size);plt+=4) {
                            uint64_t got=0;
                            if(!static_plt_got(*m->package,plt,&got) || got!=r.r_offset)continue;
                            if(!diag_plt_gate(*m->package,plt))
                                return fail(error,m->package->name+": required diagnostic PLT lacks canonical guarded BR x17");
                            ++plt_count;
                        }
                    }
                    if(!plt_count)return fail(error,m->package->name+": required diagnostic relocation has no guarded static PLT");
                }
                else if(ELF64_R_TYPE(r.r_info)==1027) address=reinterpret_cast<uintptr_t>(m->mapping.base);
                else if(!ELF64_R_SYM(r.r_info)) address=0; // ELF null symbol has value zero.
                else {
                    bool found=resolver && resolver(name,true,&address,context);
                    if(!found && s.st_shndx) { address=definition(*m,s);found=true; }
                    if(!found && ELF64_ST_BIND(s.st_info)!=STB_LOCAL &&
                       (s.st_other&3)!=STV_HIDDEN && (s.st_other&3)!=STV_INTERNAL)
                        found=lookup(candidate,name,&address);
                    if(!found && resolver) found=resolver(name,false,&address,context);
                    if(!found && ELF64_ST_BIND(s.st_info)!=STB_WEAK)
                        return fail(error,m->package->name+": missing strong import "+name);
                    if(!found) address=0;
                }
                if(!addend(address,r.r_addend,&value)) return fail(error,"relocation address/addend overflow");
                memcpy(static_cast<uint8_t*>(m->mapping.base)+r.r_offset,&value,8);
            }
            if((m->required_flags_&DM_MODULE_REQUIRE_DIAG_ABORT_V1) && !required_bindings)
                return fail(error,m->package->name+": required diagnostic abort ABI has no relocation");
            if(m->package->wire_version==3 && exact_bindings!=m->package->exact_guest_records.size())
                return fail(error,m->package->name+": incomplete exact-guest relocation bindings");
        }
        std::unordered_map<uint64_t,FrozenGate> candidate_gates;
        std::unordered_set<uint64_t> candidate_callback_roots;
        std::unordered_set<uint32_t> observation_ids;
        for(size_t mod_idx=0;mod_idx<candidate.size();++mod_idx) {
            const auto& m=candidate[mod_idx];
            const uint64_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
            if(m->package->callback_admitted_) for(uint64_t root:m->package->callback_roots_) {
                if(root>UINT64_MAX-base || !candidate_callback_roots.insert(base+root).second)
                    return fail(error,"duplicate or overflowing absolute callback root");
            }
            for(size_t i=0;i<m->package->gates.size();++i) {
                const auto& gate=m->package->gates[i];
                if(gate.kind == DM_GUEST_OBSERVATION &&
                   (!m->package->profile || strcmp(m->package->profile->module,"main") ||
                    !observation_ids.insert(gate.argument).second))
                    return fail(error,"ambiguous observation namespace or duplicate ID");
                const bool v2=m->package->wire_version>=2;
                const GateProvenance provenance=v2?m->package->gate_provenance[i]:GateProvenance{};
                uintptr_t required_target=0;
                uint64_t exact_guest_target=0;
                if(gate.kind==DM_GUEST_EXACT_GUEST) {
                    if(m->package->wire_version!=3 || !m->checked_stack_ || !m->guest_contract_admitted_)
                        return fail(error,"exact-guest gate requires admitted checked v3 module");
                    const ExactGuestRecordV1* match=nullptr;
                    for(const auto& x:m->package->exact_guest_records)
                        if(x.gate_return_offset==gate.return_offset) { match=&x; break; }
                    if(!match || match->same_module_target_offset>UINT64_MAX-base)
                        return fail(error,"exact-guest gate has no matching contract record");
                    exact_guest_target=base+match->same_module_target_offset;
                    uint64_t got_value=0;
                    std::memcpy(&got_value,static_cast<const uint8_t*>(m->mapping.base)+match->got_offset,8);
                    if(got_value!=exact_guest_target)
                        return fail(error,"exact-guest GOT slot does not match frozen target");
                }
                if((m->required_flags_&DM_MODULE_REQUIRE_DIAG_ABORT_V1) && provenance.original_offset>=12) {
                    uint64_t got=0;
                    if(static_plt_got(*m->package,provenance.original_offset-12,&got))
                        for(const auto& relocation:m->dynamic->relocations)
                            if(relocation.r_offset==got && ELF64_R_TYPE(relocation.r_info)==1026 && !relocation.r_addend &&
                               !std::strcmp(symbol_name(*m,m->dynamic->symbols[ELF64_R_SYM(relocation.r_info)]),DM_DIAG_ABORT_IMPL_SYMBOL))
                                required_target=reinterpret_cast<uintptr_t>(&dm_android_diag_abort_entry);
                }
                if(!candidate_gates.emplace(base+gate.return_offset,
                    FrozenGate{gate,provenance,v2,m->checked_stack_,required_target,exact_guest_target,mod_idx,m->load_identity_}).second)
                    return fail(error,"duplicate absolute process gate");
            }
        }
        // Register absolute gates before sealing, and publish only after every
        // mapping has received its final permissions.
        for(const auto& m:candidate) {
            char detail[256];
            if(!dm_android_guest_seal(&m->mapping,detail,sizeof(detail)))
                return fail(error,m->package->name+": "+detail);
        }
        {
            std::lock_guard<std::mutex> lock(stack_entry_mutex);
            auto entries=stack_entries;
            entries.erase(std::remove_if(entries.begin(),entries.end(),
                [&](const StackEntryAuthority& a){return a.process==this;}),entries.end());
            const uint64_t generation=++process_generation;
            for(const auto& m:candidate) for(const auto& s:m->mapped_segments_) if(s.flags&DM_GUEST_EXEC) {
                const uintptr_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
                if(s.offset>UINTPTR_MAX-base || s.size>UINTPTR_MAX-base-s.offset)
                    return fail(error,"checked entry span overflow");
                entries.push_back({this,generation,base+s.offset,s.size,m->checked_stack_});
            }
            modules_.swap(candidate);
            gates_.swap(candidate_gates);
            callback_roots_.swap(candidate_callback_roots);
            checked_stack_=checked;
            initializer_failed_=false;
            load_generation_=generation;
            stack_entries.swap(entries);
        }
        return true;
    } catch(const std::bad_alloc&) { return fail(error,"process module allocation failed"); }
}

bool Process::symbol(const char* name,uintptr_t* address) const {
    return name && address && lookup(modules_,name,address);
}
bool Process::loaded_package_matches(size_t index,const ModulePackage& canonical) const {
    return index<modules_.size() && modules_[index]->load_identity_==package_identity(canonical);
}
bool Process::loaded_package_authority(size_t index,LoadedPackageAuthority* out) const {
    if(out)*out={};
    if(!out || index>=modules_.size() || !modules_[index] || !modules_[index]->package)return false;
    const auto& m=*modules_[index];const auto& p=*m.package;
    if(!m.mapping.base || !m.mapping.sealed || !m.capsule_verified_ || !p.capsule_verified_ ||
       !m.capsule_bytes_ || m.capsule_bytes_!=p.capsule_bytes_ ||
       m.capsule_sha256_!=p.capsule_sha256_ || m.load_identity_!=package_identity(p))return false;
    out->capsule_sha256=m.capsule_sha256_;out->capsule_bytes=m.capsule_bytes_;
    out->checked_stack=m.checked_stack_ && p.stack_admitted_ && p.stack_identity_==m.load_identity_;
    out->callback_audited=p.callback_admitted_ && p.callback_identity_==m.load_identity_;
    return true;
}
bool Process::loaded_callback_roots_match(size_t index,const TrustedCallbackAudit& audit) const {
    LoadedPackageAuthority frozen{};
    if(!loaded_package_authority(index,&frozen) || !frozen.callback_audited ||
       audit.version!=1 || audit.root_kind!=CallbackRootKind::DefinedSttFunc ||
       audit.package_sha256!=frozen.capsule_sha256 || !audit.roots || !audit.root_count)return false;
    const auto& package=*modules_[index]->package;
    if(audit.source_sha256!=package.source_sha256 || audit.indirect_policy!=package.callback_indirect_policy_ ||
       audit.root_count!=package.callback_roots_.size())return false;
    return std::equal(package.callback_roots_.begin(),package.callback_roots_.end(),audit.roots);
}
bool Process::observation_present(uint32_t id) const {
    for(const auto& entry:gates_) {
        const auto& gate=entry.second.gate;
        if(gate.kind==DM_GUEST_OBSERVATION && gate.argument==id) return true;
    }
    return false;
}
bool Process::copy_readable(uint64_t address,void* staging,size_t bytes) const {
    if(!staging || !bytes) return false;
    for(const auto& m:modules_) {
        if(!m->mapping.sealed) continue;
        const uint64_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
        if(address<base) continue;
        const uint64_t off=address-base;
        for(const auto& span:m->mapped_segments_) {
            if((span.flags&DM_GUEST_READ) && off>=span.offset &&
               off-span.offset<=span.size && bytes<=span.size-(off-span.offset)) {
                memcpy(staging,reinterpret_cast<const void*>(address),bytes);
                return true;
            }
        }
    }
    return false;
}
bool Process::mapped_range(uint64_t address,size_t bytes,unsigned permissions) const {
    if(!address || !bytes || bytes>UINT64_MAX-address || !permissions || (permissions&~7u))return false;
    for(const auto& m:modules_) {
        if(!m->mapping.sealed)continue;
        uint64_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
        if(address<base)continue;const uint64_t off=address-base;
        for(const auto& s:m->mapped_segments_)if((s.flags&permissions)==permissions && off>=s.offset && off-s.offset<=s.size && bytes<=s.size-(off-s.offset))return true;
    }
    return false;
}
bool Process::callback_root(uint64_t address) const {
    return callback_roots_.count(address)!=0;
}
bool Process::visit_readonly(ReadOnlyVisitor visitor,void* context) const {
    if(!visitor) return false;
    for(const auto& m:modules_) for(const auto& s:m->package->segments) {
        if(s.flags==DM_GUEST_READ &&
           !visitor(reinterpret_cast<uintptr_t>(m->mapping.base)+s.offset,s.size,context)) return false;
    }
    return true;
}
bool Process::module_symbol(size_t index,const char* name,uintptr_t* address) const {
    if(index>=modules_.size() || !name || !address) return false;
    const auto& module=*modules_[index];
    const auto found=module.dynamic->definitions.find(name);
    if(found==module.dynamic->definitions.end()) return false;
    *address=definition(module,module.dynamic->symbols[found->second]);
    return true;
}
bool Process::borrowed_module(size_t index,HostModuleView* view) const {
    if(index>=modules_.size() || !view) return false;
    const auto& m=*modules_[index];
    const auto* base=static_cast<const uint8_t*>(m.mapping.base);
    *view={base+m.dynamic->dynamic, m.dynamic->symbols.data(),
           reinterpret_cast<const char*>(base+m.dynamic->strings),m.dynamic->symbols.size(),
           m.dynamic->init,m.dynamic->init_array,m.dynamic->init_array_bytes};
    return true;
}
bool Process::pin_host_binding(std::string* error) {
    if(host_bound_ || modules_.empty() || initializing_ || initializer_failed_)
        return fail(error,"process is empty, initializing, failed or already bound to common host");
    host_bound_=true;
    return true;
}
void Process::unpin_host_binding() { host_bound_=false; }
bool Process::run_initializers(InitRunner runner,void* context,std::string* error,InitializerOrder order) {
    if(error) error->clear();
    if(!runner || modules_.empty()) return fail(error,"initializer runner or loaded process missing");
    if(order!=InitializerOrder::Forward && order!=InitializerOrder::Reverse)
        return fail(error,"unknown module initializer order");
    if(initializing_ || initializer_failed_)
        return fail(error,"reentrant or previously failed process initialization");
    initializing_=true;
    for(size_t position=0;position<modules_.size();++position) {
        auto& m=modules_[order==InitializerOrder::Reverse?modules_.size()-1-position:position];
        if(m->init_started) continue;
        // Mark before invoking: reentrant/retried calls never repeat DT_INIT.
        m->init_started=true;
        if(m->dynamic->init && !runner(reinterpret_cast<uintptr_t>(m->mapping.base)+m->dynamic->init,context,error)) {
            initializing_=false;initializer_failed_=true;
            return false;
        }
    }
    initializing_=false;
    return true;
}
const DmGuestGate* Process::gate_resolver(void* context,uint64_t return_pc) {
    if(!context) return nullptr;
    auto* process=static_cast<Process*>(context);
    const auto found=process->gates_.find(return_pc);
    return found==process->gates_.end()?nullptr:&found->second.gate;
}
bool Process::guarded_host_site(uint64_t return_pc,const DmGuestGate* gate) const {
    const auto found=gates_.find(return_pc);
    if(found==gates_.end() || gate!=&found->second.gate || !found->second.canonical_v2) return false;
    const auto& g=found->second.gate;const auto& p=found->second.provenance;
    return g.kind==DM_GUEST_INDIRECT_HOST && g.argument<31 && g.argument!=18 &&
           p.kind==g.kind && p.argument==g.argument && p.return_offset==g.return_offset && !p.flags;
}
bool Process::exact_guest_site(uint64_t return_pc,const DmGuestGate* gate,uint64_t live_x17,uint64_t generation) const {
    if(!gate || !generation || generation!=load_generation_ || !checked_stack_)return false;
    const auto found=gates_.find(return_pc);
    if(found==gates_.end() || gate!=&found->second.gate)return false;
    const auto& f=found->second;
    if(!f.canonical_v2 || !f.checked_stack || f.gate.kind!=DM_GUEST_EXACT_GUEST || f.gate.argument!=17)return false;
    if(f.provenance.kind!=f.gate.kind || f.provenance.argument!=f.gate.argument ||
       f.provenance.return_offset!=f.gate.return_offset || f.provenance.flags ||
       f.provenance.original_word!=0xd61f0220u)return false;
    if(!live_x17 || (live_x17&3) || !f.exact_guest_target || live_x17!=f.exact_guest_target)return false;
    if(f.module_index>=modules_.size() || !modules_[f.module_index] || !modules_[f.module_index]->package)return false;
    const auto& m=*modules_[f.module_index];const auto& p=*m.package;
    if(!m.mapping.base || !m.mapping.sealed || !m.checked_stack_ || !p.checked_stack || p.wire_version!=3)return false;
    if(!m.guest_contract_admitted_ || !p.guest_contract_admission_ ||
       m.load_identity_!=f.package_identity ||
       p.guest_contract_admission_->package_identity!=m.load_identity_ ||
       p.guest_contract_admission_->audit_identity!=m.guest_contract_audit_identity_ ||
       package_identity(p)!=m.load_identity_)return false;
    const uint64_t base=reinterpret_cast<uintptr_t>(m.mapping.base);
    if(live_x17<base || live_x17-base>=p.original_size)return false;
    return in_segment(p,live_x17-base,4,DM_GUEST_READ|DM_GUEST_EXEC);
}
bool Process::static_main_import_caller(uint64_t lr,uintptr_t target,const char* symbol,uint64_t* callsite) const {
    if(callsite)*callsite=0;
    if(!callsite||!symbol||!target||(target&3)||lr<4||(lr&3))return false;
    for(const auto& m:modules_) {
        if(m->package->name!="main")continue;
        const uint64_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
        if(lr<base+4||!mapped_range(lr-4,4,DM_GUEST_EXEC))return false;
        uint32_t bl=0;
        if(!copy_readable(lr-4,&bl,4)||(bl&0xfc000000u)!=0x94000000u)return false;
        const int64_t distance=static_cast<int64_t>(static_cast<int32_t>(bl<<6)>>6)*4;
        const int64_t plt_signed=static_cast<int64_t>(lr-4)+distance;
        if(plt_signed<0)return false;const uint64_t plt=uint64_t(plt_signed);
        uint32_t words[4]{};
        if(plt<base||!mapped_range(plt,sizeof(words),DM_GUEST_EXEC)||!copy_readable(plt,words,sizeof(words))||
           (words[0]&0x9f00001fu)!=0x90000010u||(words[1]&0xffc003ffu)!=0xf9400211u||
           (words[2]&0xffc003ffu)!=0x91000210u||words[3]!=0xd61f0220u||
           ((words[1]>>10)&4095)*8!=((words[2]>>10)&4095))return false;
        int64_t pages=((words[0]>>5)&0x7ffff)*4+((words[0]>>29)&3);
        if(pages&(1<<20))pages-=1<<21;
        const int64_t got_signed=static_cast<int64_t>(plt&~uint64_t(4095))+pages*4096+
            ((words[1]>>10)&4095)*8;
        if(got_signed<0)return false;const uint64_t got=uint64_t(got_signed);
        uint64_t current=0;
        if(got<base||!copy_readable(got,&current,8)||current!=target)return false;
        for(const auto& rel:m->dynamic->relocations) {
            if(ELF64_R_TYPE(rel.r_info)!=1026||rel.r_addend||rel.r_offset!=got-base)continue;
            const auto& entry=m->dynamic->symbols[ELF64_R_SYM(rel.r_info)];
            const char* name=symbol_name(*m,entry);
            if(name&&!std::strcmp(name,symbol)){*callsite=lr-base-4;return true;}
        }
        return false;
    }
    return false;
}
bool Process::diag_abort_import_caller(uintptr_t lr,DiagAbortCaller* out) const {
    if(out)*out={};
    const uintptr_t canonical=reinterpret_cast<uintptr_t>(&dm_android_diag_abort_entry);
    if(!out || !canonical || lr<4 || (lr&3))return false;
    for(const auto& m:modules_) {
        const auto& p=*m->package;
        const uintptr_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
        if(lr<base+4 || lr-base>p.original_size)continue;
        if(!(m->required_flags_&DM_MODULE_REQUIRE_DIAG_ABORT_V1) ||
           p.required_flags!=m->required_flags_ || !m->checked_stack_ || !p.checked_stack ||
           !m->mapping.sealed || m->load_identity_!=package_identity(p))return false;
        const uint64_t call=lr-base-4;
        if(!in_segment(p,call,4,DM_GUEST_READ|DM_GUEST_EXEC))return false;
        const uint32_t bl=read<uint32_t>(p,call);
        uint32_t mapped_bl=0;
        std::memcpy(&mapped_bl,static_cast<const uint8_t*>(m->mapping.base)+call,4);
        if(bl!=mapped_bl || (bl&0xfc000000u)!=0x94000000u)return false;
        const int64_t distance=static_cast<int64_t>(static_cast<int32_t>(bl<<6)>>6)*4;
        const int64_t plt_signed=static_cast<int64_t>(call)+distance;
        if(plt_signed<0)return false;
        const uint64_t plt=static_cast<uint64_t>(plt_signed);
        if(!range(plt,16,p.original_size) || !in_segment(p,plt,16,DM_GUEST_READ|DM_GUEST_EXEC))return false;
        uint32_t words[4]{};
        std::memcpy(words,p.bytes.data()+plt,sizeof(words));
        if(std::memcmp(words,static_cast<const uint8_t*>(m->mapping.base)+plt,sizeof(words)) ||
           (words[0]&0x9f00001fu)!=0x90000010u || (words[1]&0xffc003ffu)!=0xf9400211u ||
           (words[2]&0xffc003ffu)!=0x91000210u ||
           ((words[1]>>10)&4095)*8!=((words[2]>>10)&4095))return false;
        const DmGuestGate* contract_gate=diag_plt_gate(p,plt);
        uintptr_t required=0;
        if(!contract_gate || !diag_abort_host_site(base+contract_gate->return_offset,
             gate_resolver(const_cast<Process*>(this),base+contract_gate->return_offset),&required) || required!=canonical)return false;
        const uint64_t trampoline=contract_gate->return_offset-16;
        if(std::memcmp(p.bytes.data()+trampoline,static_cast<const uint8_t*>(m->mapping.base)+trampoline,28))return false;
        // Only the fourth PLT word has the mandatory canonical typed rewrite.
        for(const auto& site:p.sites)
            if(site.original_offset==call || (site.original_offset>=plt && site.original_offset<plt+12))return false;
        int64_t pages=((words[0]>>5)&0x7ffff)*4+((words[0]>>29)&3);
        if(pages&(1<<20))pages-=1<<21;
        const int64_t got_signed=static_cast<int64_t>((base+plt)&~uintptr_t(4095))+pages*4096+
            ((words[1]>>10)&4095)*8;
        if(got_signed<0 || static_cast<uint64_t>(got_signed)<base)return false;
        const uint64_t got=static_cast<uint64_t>(got_signed)-base;
        if(!in_segment(p,got,8,DM_GUEST_READ|DM_GUEST_WRITE) || !range(got,8,p.original_size))return false;
        uint64_t current=0;
        std::memcpy(&current,static_cast<const uint8_t*>(m->mapping.base)+got,8);
        if(current!=canonical)return false;
        size_t matches=0;
        for(const auto& rel:m->dynamic->relocations) {
            if(rel.r_offset!=got)continue;
            const auto& entry=m->dynamic->symbols[ELF64_R_SYM(rel.r_info)];
            const char* name=symbol_name(*m,entry);
            if(ELF64_R_TYPE(rel.r_info)!=1026 || rel.r_addend ||
               !name || std::strcmp(name,DM_DIAG_ABORT_IMPL_SYMBOL))return false;
            ++matches;
        }
        if(matches!=1)return false;
        out->module=p.name.c_str();out->callsite=call;return true;
    }
    return false;
}
bool Process::diag_abort_host_site(uint64_t return_pc,const DmGuestGate* gate,uintptr_t* required) const {
    if(required)*required=0;
    if(!required)return false;
    const auto found=gates_.find(return_pc);
    if(found==gates_.end() || gate!=&found->second.gate || !found->second.required_target)return false;
    *required=found->second.required_target;return true;
}
bool Process::stack_check_site(uint64_t return_pc,const DmGuestGate* gate) const {
    const auto found=gates_.find(return_pc);
    if(found==gates_.end() || gate!=&found->second.gate || !found->second.canonical_v2 || !found->second.checked_stack) return false;
    const auto& g=found->second.gate;const auto& p=found->second.provenance;
    return checked_stack_ && g.kind==DM_GUEST_STACK_CHECK && p.kind==g.kind && p.argument==g.argument &&
           p.original_word==g.argument && p.return_offset==g.return_offset && !p.flags;
}
bool Process::checked_stack_entry(uintptr_t entry) const {
    if(!checked_stack_) return false;
    for(const auto& m:modules_) {
        const uintptr_t base=reinterpret_cast<uintptr_t>(m->mapping.base);
        if(entry>=base && entry-base<m->mapping.mapping_size) return m->checked_stack_;
    }
    // Trusted host product/callback helpers execute on this same guest stack.
    // Requiring reserve grants no additional entry or callback authority.
    return true;
}
} // namespace dm_android

extern "C" int dm_android_stack_entry_reserve(const DmGuestThreadState* state,uintptr_t entry,size_t* reserve) {
    if(!state || !reserve) return -1;
    *reserve=0;
    std::lock_guard<std::mutex> lock(dm_android::stack_entry_mutex);
    const dm_android::StackEntryAuthority* target=nullptr;
    const dm_android::StackEntryAuthority* context=nullptr;
    for(const auto& a:dm_android::stack_entries) {
        if(entry>=a.base && entry-a.base<a.size) target=&a;
        if(state->gate_context==a.process) context=&a;
    }
    if(target && target->checked) {
        if(state->gate_resolver!=dm_android::Process::gate_resolver || state->gate_context!=target->process ||
           state->runtime_generation!=target->generation) return -1;
        *reserve=DM_GUEST_STACK_RESERVE;return 1;
    }
    if(context && context->checked) {
        if(target || state->gate_resolver!=dm_android::Process::gate_resolver ||
           state->runtime_generation!=context->generation) return -1;
        // Trusted native helpers in a checked Process use the same stack.
        *reserve=DM_GUEST_STACK_RESERVE;return 1;
    }
    if(state->gate_resolver==dm_android::Process::gate_resolver && !context) return -1;
    return 0;
}
extern "C" bool dm_android_stack_gate_authorized(const DmGuestThreadState* state,uint64_t pc,const DmGuestGate* gate) {
    if(!state || state->gate_resolver!=dm_android::Process::gate_resolver || !state->gate_context) return false;
    const auto* process=static_cast<const dm_android::Process*>(state->gate_context);
    return state->runtime_generation && state->runtime_generation==process->load_generation() && process->stack_check_site(pc,gate);
}
