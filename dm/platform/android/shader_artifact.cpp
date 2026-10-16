#include "shader_artifact.h"
#include "module_sha256.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <sys/stat.h>
#include <unistd.h>
namespace dm_android {
namespace {
std::atomic<size_t> retained_bytes{0};
bool fail(std::string* e,const std::string& s) { if(e)*e=s.substr(0,512);return false; }
uint32_t u32(const uint8_t* p) { return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24; }
uint64_t u64(const uint8_t* p) { return u32(p)|uint64_t(u32(p+4))<<32; }
bool zero(const uint8_t* p,size_t n) { for(size_t i=0;i<n;++i)if(p[i])return false;return true; }
bool present(const ShaderDigest& d) { return !zero(d.data(),d.size()); }
bool range(uint64_t off,uint64_t n,uint64_t size) { return off<=size && n<=size-off; }
bool utf8(const uint8_t* p,size_t n) {
    for(size_t i=0;i<n;) {
        uint32_t c=p[i++]; if(!c)return false;if(c<128)continue;
        unsigned more=0;uint32_t min=0;
        if(c>=0xc2 && c<=0xdf){more=1;c&=31;min=128;}
        else if(c>=0xe0 && c<=0xef){more=2;c&=15;min=2048;}
        else if(c>=0xf0 && c<=0xf4){more=3;c&=7;min=65536;}else return false;
        if(more>n-i)return false;
        while(more--){uint32_t a=p[i++];if((a&192)!=128)return false;c=(c<<6)|(a&63);}
        if(c<min || c>0x10ffff || (c>=0xd800 && c<=0xdfff))return false;
    }return true;
}
bool text_ok(const std::string& s,size_t maximum) {
    return !s.empty() && s.size()<=maximum && utf8(reinterpret_cast<const uint8_t*>(s.data()),s.size());
}
constexpr const char* original_texture_profile="android-vulkan10-original-embedded-texture-v1";
constexpr const char* sampled_profile="android-vulkan10-authored-sampled2d-v1";
constexpr const char* sampled_rule="authored-static-separate-or-word32-v1";
bool profile_name(const std::string& n) { return n=="android-vulkan10-strict-v1" || n==sampled_profile || n==original_texture_profile || n=="android-vulkan11-warp32-v1"; }
bool builtin_name(const std::string& n) {
    return n=="builtin-q-val0" || n=="builtin-q-val8" || n=="builtin-q-dlt0" || n=="builtin-q-dlt8";
}
bool hex_digest(const uint8_t* value,const char* hex) {
    auto nibble=[](char c){return unsigned(c>='a'?c-'a'+10:c-'0');};
    for(size_t i=0;i<32;++i)if(value[i]!=nibble(hex[i*2])*16+nibble(hex[i*2+1]))return false;
    return true;
}
constexpr const char* builtin_image_sha="6843ab6909f96e1558b4b73b0fa807f3873409120cf3e1ef8a86dbebb275ee27";
constexpr const char* builtin_image_name="D2R/3.3.94012/Update/ExeFS/main.decoded-image";
struct OriginalBuiltinSource {uint64_t offset;const char* control;const char* code;const char* record;uint32_t used;};
// Independently measured original bytes from the reviewed materialized image.
// This is a private immutable catalog, not a runtime registration surface.
constexpr OriginalBuiltinSource original_builtins[]={
    {0x1df10e8,"d0f769bb916bbba97e8d5907a2ab40349ed81e7b74383e870d78847114c28a7c","aaf657ee393245946601fb3e396dc093c1ce3fb09a3ae29ba4875a093d51f090","201efc863bca70745c83f54430b5036d537ab8c9f50c3071451d2a992925362a",192},
    {0x1df1a94,"16479cc6d75c2b2816eb113c33f96e3917ee172ca363d45de6a49dadf22127cc","b8dd773133250801475b34d541c8f8a5f1e349166aba3df81b1f4c86774950bc","bd1fc047280417bc42449f7907f53cffa899a0c2a72febfc8d87d2d3f13f0190",192},
    {0x1df2440,"0687e2ef9513357704103c9726f736575f958f0f314720b6315cff48cb07de5b","ddcb76a04571b0fedf35716c5fd17e4ba6a38c9309da8cf7a011444bd5b2c4be","c7388e8cbac3ded0546d2a1301090999b240d07a9fd3a950a45d0fa9ede33217",256},
    {0x1df2dec,"4df5909e6dabee0515e1d53c9ae001f6af58d55f7346eb881c92b7c1642ea372","9d09120c2f3995ef1b61c2479b9c0b37061db403994914de2fafb760e0431fc1","df7abb0b7c8fdc77cbe9aa8365aea246e27d4f277616a1b20dc90e1755ef30f3",256}
};
const OriginalBuiltinSource* original_builtin(const ShaderTypedKey& key,uint64_t offset) {
    const auto* original=std::get_if<OriginalMaxwellKey>(&key.source);
    if(!original || key.stage!=ShaderStage::Compute || original->content_kind!=2 || original->content_name!=builtin_image_name ||
       !hex_digest(original->trusted_content_sha256.data(),builtin_image_sha))return nullptr;
    for(const auto& source:original_builtins)if(source.offset==offset && hex_digest(original->control_sha256.data(),source.control) && hex_digest(original->code_sha256.data(),source.code))return &source;
    return nullptr;
}
bool valid_key(const ShaderTypedKey& k) {
    uint32_t stage=static_cast<uint32_t>(k.stage);
    if((stage!=0 && stage!=1 && stage!=5) || !profile_name(k.profile_name) || !present(k.profile_definition_sha256))return false;
    if(const auto* x=std::get_if<OriginalMaxwellKey>(&k.source))
        return (x->content_kind==1 || x->content_kind==2) && text_ok(x->content_name,1024) &&
            present(x->trusted_content_sha256) && present(x->control_sha256) && present(x->code_sha256);
    if(const auto* x=std::get_if<SemanticPortKey>(&k.source))
        return stage==5 && builtin_name(x->builtin_name) && present(x->semantic_source_sha256) && present(x->portable_source_sha256);
    const auto* x=std::get_if<AuthoredTranslatorFixtureKey>(&k.source);
    return x && text_ok(x->fixture_name,256) && present(x->control_sha256) && present(x->code_sha256);
}
void put32(std::vector<uint8_t>& b,uint32_t v){for(unsigned i=0;i<4;++i)b.push_back(uint8_t(v>>(8*i)));}
void put64(std::vector<uint8_t>& b,uint64_t v){for(unsigned i=0;i<8;++i)b.push_back(uint8_t(v>>(8*i)));}
void append(std::vector<uint8_t>& b,const uint8_t* p,size_t n){if(n)b.insert(b.end(),p,p+n);}
void lp(std::vector<uint8_t>& b,const uint8_t* p,size_t n){put32(b,static_cast<uint32_t>(n));append(b,p,n);}
void lp(std::vector<uint8_t>& b,const std::string& s){lp(b,reinterpret_cast<const uint8_t*>(s.data()),s.size());}
void digest_append(std::vector<uint8_t>& b,const ShaderDigest& d){append(b,d.data(),d.size());}
std::vector<uint8_t> key_bytes(const ShaderTypedKey& k) {
    const char domain[]="DMSV1-KEY";std::vector<uint8_t>b;append(b,reinterpret_cast<const uint8_t*>(domain),sizeof(domain));
    put32(b,static_cast<uint32_t>(shader_identity_kind(k)));put32(b,static_cast<uint32_t>(k.stage));
    lp(b,k.profile_name);digest_append(b,k.profile_definition_sha256);
    if(const auto* x=std::get_if<OriginalMaxwellKey>(&k.source)) {
        put32(b,x->content_kind);lp(b,x->content_name);digest_append(b,x->trusted_content_sha256);
        digest_append(b,x->control_sha256);digest_append(b,x->code_sha256);
    } else if(const auto* x=std::get_if<SemanticPortKey>(&k.source)) {
        lp(b,x->builtin_name);digest_append(b,x->semantic_source_sha256);digest_append(b,x->portable_source_sha256);
    } else {const auto& authored=std::get<AuthoredTranslatorFixtureKey>(k.source);lp(b,authored.fixture_name);digest_append(b,authored.control_sha256);digest_append(b,authored.code_sha256);}
    return b;
}
struct View { const uint8_t* p=nullptr;size_t n=0; };
bool same(View a,View b){return a.n==b.n && (!a.n || !memcmp(a.p,b.p,a.n));}
ShaderDigest sha(View v){ShaderDigest d;module_sha256(v.p,v.n,d.data());return d;}
struct Section {size_t off=0,bytes=0;uint32_t count=0,stride=0;};
constexpr uint32_t strides[16]={576,128,32,96,96,64,32,64,32,48,32,96,1,1,1,1};
constexpr uint32_t counts[16]={1,1,1024,4096,8192,4096,8192,16384,16384,8192,1024,8192,65536,4096,1048576,12582912};
const std::vector<std::pair<size_t,bool>>& refs(size_t section) {
    static const std::vector<std::pair<size_t,bool>> fields[16]={
        {{24,false},{32,false}},{{0,false},{8,false},{16,false},{24,false},{88,true}},
        {{16,false},{24,true}},{{72,false}},{{56,true},{64,false}},{{48,false},{56,true}},{{24,true}},
        {},{},{{0,false},{8,true},{16,true},{40,false}},{{8,false},{24,false}},
        {{8,false},{56,true},{64,true}},{},{},{},{}};
    return fields[section];
}
bool limits_ok(const ShaderArtifactLimits& l) {
    return l.artifact_bytes>=1401 && l.artifact_bytes<=16777216 && l.spirv_bytes>=20 && l.spirv_bytes<=1048576 &&
        l.retained_bytes && l.retained_bytes<=268435456 && l.preimage_bytes && l.preimage_bytes<=33554432 &&
        l.hash_work_bytes && l.hash_work_bytes<=67108864 && l.context_work_bytes && l.context_work_bytes<=33554432;
}
bool canonical_float(View v) {
    size_t at=0;
    auto text_value=[&](const char* expected)->bool{size_t n=strlen(expected);if(!range(at,5+n,v.n) || v.p[at]!=6 || u32(v.p+at+1)!=n || memcmp(v.p+at+5,expected,n))return false;at+=5+n;return true;};
    if(v.n<5 || v.p[0]!=8 || u32(v.p+1)!=2)return false;at=5;
    if(!text_value("bits") || !range(at,5,v.n) || v.p[at]!=5)return false;uint32_t n=u32(v.p+at+1);at+=5;
    if((n!=4 && n!=8) || !range(at,n,v.n))return false;const uint8_t* bits=v.p+at;at+=n;
    if(!text_value("format") || !text_value(n==4?"binary32":"binary64") || at!=v.n)return false;
    return n==4?(u32(bits)&0x7f800000u)!=0x7f800000u:(u64(bits)&0x7ff0000000000000ull)!=0x7ff0000000000000ull;
}
}
ShaderIdentityKind shader_identity_kind(const ShaderTypedKey& k) {return static_cast<ShaderIdentityKind>(k.source.index()+1);}
bool shader_typed_key_equal(const ShaderTypedKey& a,const ShaderTypedKey& b) {
    if(a.stage!=b.stage || a.profile_name!=b.profile_name || a.profile_definition_sha256!=b.profile_definition_sha256 || a.source.index()!=b.source.index())return false;
    if(const auto* x=std::get_if<OriginalMaxwellKey>(&a.source)){const auto* y=std::get_if<OriginalMaxwellKey>(&b.source);return y &&
        std::tie(x->content_kind,x->content_name,x->trusted_content_sha256,x->control_sha256,x->code_sha256)==std::tie(y->content_kind,y->content_name,y->trusted_content_sha256,y->control_sha256,y->code_sha256);}
    if(const auto* x=std::get_if<SemanticPortKey>(&a.source)){const auto* y=std::get_if<SemanticPortKey>(&b.source);return y &&
        std::tie(x->builtin_name,x->semantic_source_sha256,x->portable_source_sha256)==std::tie(y->builtin_name,y->semantic_source_sha256,y->portable_source_sha256);}
    const auto* x=std::get_if<AuthoredTranslatorFixtureKey>(&a.source);const auto* y=std::get_if<AuthoredTranslatorFixtureKey>(&b.source);
    return x && y && std::tie(x->fixture_name,x->control_sha256,x->code_sha256)==std::tie(y->fixture_name,y->control_sha256,y->code_sha256);
}
// Internal cross-translation-unit check; no public header/API or authority is
// added. Other reviewed recipes keep their previous source-span semantics.
bool validate_original_builtin_snapshot(const ShaderTypedKey& key,uint64_t offset,uint64_t record_index,
    uint64_t control_offset,uint64_t code_offset,uint64_t code_size,uint64_t c1_offset,uint64_t c1_size,
    const uint8_t* record,size_t size,std::string* error) {
    const auto* original=std::get_if<OriginalMaxwellKey>(&key.source);
    if(!original || original->content_kind!=2 || !hex_digest(original->trusted_content_sha256.data(),builtin_image_sha))return true;
    bool selected=false;for(const auto& source:original_builtins)selected|=source.offset==offset || hex_digest(original->control_sha256.data(),source.control);
    if(!selected)return true;
    const auto* source=original_builtin(key,offset);
    if(!source || record_index || control_offset!=276 || code_offset!=20 || code_size!=256 || c1_offset!=276 || c1_size || size!=2452 || !record)
        return fail(error,"Snapshot: original builtin catalog/record geometry");
    const uint32_t header[]={5,0x898,0x10c,0x100,4};
    for(size_t i=0;i<5;++i)if(u32(record+i*4)!=header[i])return fail(error,"Snapshot: original builtin serialized header");
    const uint8_t* control=record+276;
    if(u32(control+0x6f8)!=source->used || u32(control+0x700)!=256 || u32(control+0x704)!=256 ||
       u32(control+0x748)!=32 || u32(control+0x74c)!=1 || u32(control+0x750)!=1)return fail(error,"Snapshot: original builtin control fields");
    ShaderDigest digest;module_sha256(record,size,digest.data());if(!hex_digest(digest.data(),source->record))return fail(error,"Snapshot: original builtin full record hash");
    return true;
}
bool validate_compiled_shader_index(const ShaderIndexEntry* entries,size_t count,std::string* error) {
    if(error)error->clear();
    if(!entries || !count || count>65536)return fail(error,"Index: missing or excessive compiled table");
    try {std::set<std::vector<uint8_t>> keys;
        for(size_t i=0;i<count;++i) {
            if(!valid_key(entries[i].key))return fail(error,"Index: invalid discriminated typed key");
            if(!present(entries[i].expected_file_sha256))return fail(error,"ExpectedDigestMissing: compiled pin is required");
            if(!keys.insert(key_bytes(entries[i].key)).second)return fail(error,"Index: duplicate exact compiled key");
        }return true;
    }catch(const std::bad_alloc&){return fail(error,"Allocation: compiled index validation");}
}
struct ShaderArtifact::Storage {
    ShaderTypedKey key;ShaderDigest file_sha256{};ShaderIdentity identity;ShaderProfile profile;
    std::vector<uint8_t> bytes,c1;std::vector<uint32_t> words;
    std::vector<ShaderDescriptor> descriptors;std::vector<ShaderSemantic> semantics;
    std::vector<ShaderIo> io;std::vector<ShaderType> types;std::vector<ShaderMember> members;
    size_t lease=0;
    ~Storage(){if(lease)retained_bytes.fetch_sub(lease,std::memory_order_acq_rel);}
};
ShaderArtifact::ShaderArtifact(std::shared_ptr<const Storage> s):storage_(std::move(s)){}
const ShaderTypedKey& ShaderArtifact::key()const{return storage_->key;}
const ShaderDigest& ShaderArtifact::file_sha256()const{return storage_->file_sha256;}
const ShaderIdentity& ShaderArtifact::identity()const{return storage_->identity;}
const ShaderProfile& ShaderArtifact::profile()const{return storage_->profile;}
const std::vector<uint32_t>& ShaderArtifact::words()const{return storage_->words;}
const std::vector<uint8_t>& ShaderArtifact::c1()const{return storage_->c1;}
const std::vector<ShaderDescriptor>& ShaderArtifact::descriptors()const{return storage_->descriptors;}
const std::vector<ShaderSemantic>& ShaderArtifact::semantics()const{return storage_->semantics;}
const std::vector<ShaderIo>& ShaderArtifact::io()const{return storage_->io;}
const std::vector<ShaderType>& ShaderArtifact::types()const{return storage_->types;}
const std::vector<ShaderMember>& ShaderArtifact::members()const{return storage_->members;}
size_t ShaderArtifact::file_bytes()const{return storage_->bytes.size();}

struct ShaderArtifactDecoder {
    std::shared_ptr<ShaderArtifact::Storage> s=std::make_shared<ShaderArtifact::Storage>();
    std::array<Section,16> sections{};
    ShaderArtifactLimits limits;std::string* error;
    size_t hash_work=0,context_work=0,cbo_nodes=0;
    std::map<size_t,size_t> string_refs,blob_refs;
    std::set<std::pair<size_t,size_t>> canonical_checked;
    std::map<std::pair<size_t,size_t>,ShaderDigest> direct_hashes;
    struct Requirement {uint32_t domain=0,flags=0,value=0;std::string name;View details;};
    std::vector<Requirement> requirements;
    std::set<std::string> closure_ids;
    std::map<std::string,uint32_t> host_queries;
    std::set<std::string> profile_source_rules;
    explicit ShaderArtifactDecoder(const ShaderArtifactLimits& l,std::string* e):limits(l),error(e){}
    bool bad(const char* category,const std::string& detail){return fail(error,std::string(category)+": "+detail);}
    const uint8_t* row(size_t sec,size_t index=0)const{return s->bytes.data()+sections[sec].off+index*sections[sec].stride;}
    View data(size_t sec)const{return {row(sec),sections[sec].bytes};}
    bool charge(size_t n,size_t& used,size_t limit,const char* detail) {
        if(n>limit-used)return bad("Budget",detail);used+=n;return true;
    }
    bool hash(View v,ShaderDigest* out) {
        const auto key=std::make_pair(static_cast<size_t>(v.p-s->bytes.data()),v.n);
        auto found=direct_hashes.find(key);if(found!=direct_hashes.end()){*out=found->second;return true;}
        if(!charge(v.n,hash_work,limits.hash_work_bytes,"direct hash work"))return false;
        *out=sha(v);direct_hashes.emplace(key,*out);return true;
    }
    bool hash_matches(View v,const uint8_t* expected) {ShaderDigest d;return hash(v,&d) && (!memcmp(d.data(),expected,32) || bad("Closure","direct payload digest mismatch"));}
    bool get_ref(const uint8_t* p,bool blob,View* out) {
        size_t off=u32(p),n=u32(p+4);const auto& sec=sections[blob?15:12];
        if(!n){if(off)return bad("Canonical","empty reference offset");*out={s->bytes.data()+sec.off,0};return true;}
        if(!range(off,n,sec.bytes) || (!blob && n>4096))return bad("Bounds","interned reference");
        auto& table=blob?blob_refs:string_refs;auto inserted=table.emplace(off,n);
        if(!inserted.second && inserted.first->second!=n)return bad("Canonical","substring/overlap reference");
        *out={s->bytes.data()+sec.off+off,n};return true;
    }
    bool str(const uint8_t* p,std::string* out) {View v;if(!get_ref(p,false,&v))return false;out->assign(reinterpret_cast<const char*>(v.p),v.n);return true;}
    bool blob(const uint8_t* p,View* out,bool canonical=false) {
        if(!get_ref(p,true,out))return false;return !canonical || validate_cbo(*out);
    }
    bool skip(View v,size_t* at,unsigned depth,size_t* nodes) {
        if(depth>32 || ++*nodes>65536)return bad("Budget","canonical object depth/nodes");
        if(*at>=v.n)return bad("Canonical","truncated value");uint8_t tag=v.p[(*at)++];
        if(tag<=2)return true;
        if(tag==3 || tag==4){if(!range(*at,8,v.n))return bad("Canonical","integer bounds");
            if(tag==4 && !(v.p[*at+7]&128))return bad("Canonical","negative integer sign");*at+=8;return true;}
        if(tag<5 || tag>8 || !range(*at,4,v.n))return bad("Canonical","tag or count");
        uint32_t n=u32(v.p+*at);*at+=4;
        if(tag==5 || tag==6){if(!range(*at,n,v.n) || (tag==6 && (n>4096 || !utf8(v.p+*at,n))))return bad("Canonical","bytes/text bounds or UTF8");*at+=n;return true;}
        if(n>65536)return bad("Budget","canonical collection count");
        std::string previous;
        for(uint32_t i=0;i<n;++i){bool is_float=false;
            if(tag==8){if(!range(*at,5,v.n) || v.p[*at]!=6)return bad("Canonical","map key type");size_t len=u32(v.p+*at+1);
                if(!range(*at+5,len,v.n))return bad("Canonical","map key bounds");
                std::string key(reinterpret_cast<const char*>(v.p+*at+5),len);
                if(i && !(previous<key))return bad("Canonical","map key order/duplicate");is_float=key=="$float";previous=std::move(key);
                if(is_float && n!=1)return bad("Canonical","typed float outer map shape");
                if(!skip(v,at,depth+1,nodes))return false;}
            size_t value_start=*at;if(!skip(v,at,depth+1,nodes))return false;
            if(is_float && !canonical_float({v.p+value_start,*at-value_start}))return bad("Canonical","typed float shape or nonfinite bits");
        }return true;
    }
    bool validate_cbo(View v) {
        if(!v.n || v.n>1048576)return bad("Budget","canonical object size");
        auto key=std::make_pair(static_cast<size_t>(v.p-s->bytes.data()),v.n);
        if(canonical_checked.count(key))return true;
        size_t at=0,nodes=0;if(!skip(v,&at,0,&nodes) || at!=v.n)return bad("Canonical","incomplete or trailing object");
        if(!charge(nodes,cbo_nodes,1048576,"aggregate canonical nodes"))return false;
        canonical_checked.insert(key);return true;
    }
    bool context(View v){return charge(v.n,context_work,limits.context_work_bytes,"contextual canonical traversal");}
    bool map(View v,std::map<std::string,View>* out,std::initializer_list<const char*> keys={}) {
        if(!context(v) || v.n<5 || v.p[0]!=8)return bad("Canonical","expected map");
        out->clear();size_t at=5;uint32_t count=u32(v.p+1);
        for(uint32_t i=0;i<count;++i){
            size_t len=u32(v.p+at+1);std::string key(reinterpret_cast<const char*>(v.p+at+5),len);at+=5+len;
            size_t start=at,nodes=0;if(!skip(v,&at,0,&nodes))return false;out->emplace(std::move(key),View{v.p+start,at-start});
        }
        if(keys.size()){if(out->size()!=keys.size())return bad("Canonical","map field set");for(auto key:keys)if(!out->count(key))return bad("Canonical","map field missing");}
        return true;
    }
    bool list(View v,std::vector<View>* out) {
        if(!context(v) || v.n<5 || v.p[0]!=7)return bad("Canonical","expected list");out->clear();size_t at=5;
        for(uint32_t i=0;i<u32(v.p+1);++i){size_t start=at,nodes=0;if(!skip(v,&at,0,&nodes))return false;out->push_back({v.p+start,at-start});}return true;
    }
    bool integer(View v,uint64_t* out){if(v.n!=9 || v.p[0]!=3)return bad("Canonical","expected unsigned integer");*out=u64(v.p+1);return true;}
    bool boolean(View v,bool* out){if(v.n!=1 || (v.p[0]!=1 && v.p[0]!=2))return bad("Canonical","expected boolean");*out=v.p[0]==2;return true;}
    bool text(View v,std::string* out){if(v.n<5 || v.p[0]!=6)return bad("Canonical","expected text");out->assign(reinterpret_cast<const char*>(v.p+5),u32(v.p+1));return true;}
    bool bytes(View v,View* out){if(v.n<5 || v.p[0]!=5)return bad("Canonical","expected byte string");*out={v.p+5,u32(v.p+1)};return true;}
    bool exact_string(View v,const std::string& expected){std::string value;return text(v,&value) && (value==expected || bad("Canonical","text value mismatch"));}
    bool directory();bool preflight();bool identities();bool tables();bool closures();bool digests();bool spirv();bool semantics();bool interned();
    bool reserve_file(size_t size);
    bool decode_owned(const ShaderIndexEntry&,std::shared_ptr<const ShaderArtifact>*);
    bool finish(const uint8_t* bytes,size_t size,const ShaderIndexEntry& entry,std::shared_ptr<const ShaderArtifact>* out);
};

bool ShaderArtifactDecoder::directory() {
    const auto& b=s->bytes;const uint8_t magic[8]={0x44,0x4d,0x53,0x56,0x31,13,10,26};
    if(b.size()<576 || memcmp(b.data(),magic,8) || u32(b.data()+8)!=1 || u32(b.data()+12)!=64 ||
       u64(b.data()+16)!=b.size() || u32(b.data()+24)!=64 || u32(b.data()+28)!=16 ||
       u32(b.data()+32)!=32 || u32(b.data()+36) || u32(b.data()+40)!=0x01020304 || !zero(b.data()+44,20))
        return bad("Header","magic/version/size/flags/reserved");
    uint64_t next=576;
    for(size_t i=0;i<16;++i) {
        const uint8_t* p=b.data()+64+i*32;const uint64_t off=u64(p+8),n=u64(p+16);
        const uint32_t count=u32(p+24),stride=u32(p+28);
        if(u32(p)!=i+1 || u32(p+4) || stride!=strides[i] || count>counts[i] ||
           n!=uint64_t(count)*stride || off!=next || !range(off,n,b.size()))return bad("Directory","section order/offset/count/stride/size");
        if((i<2 && count!=1) || (i==11 && !count) || (i>=14 && !count))return bad("Directory","required section count");
        sections[i]={static_cast<size_t>(off),static_cast<size_t>(n),count,stride};
        const uint64_t end=off+n;next=(end+7)&~uint64_t(7);
        if(i==15){if(end!=b.size())return bad("Directory","trailing bytes");}
        else if(!range(end,next-end,b.size()) || !zero(b.data()+end,static_cast<size_t>(next-end)))return bad("Reserved","section padding");
    }
    if(sections[14].bytes<20 || sections[14].bytes>limits.spirv_bytes || (sections[14].bytes&3))return bad("Budget","SPIR-V byte size");
    // Register every reference before any expanded digest allocation.
    for(size_t i=0;i<12;++i)for(size_t j=0;j<sections[i].count;++j)
        for(auto ref:refs(i)){View ignored;if(!get_ref(row(i,j)+ref.first,ref.second,&ignored))return false;}
    return true;
}
bool ShaderArtifactDecoder::interned() {
    for(bool blob:{false,true}) {
        const auto& table=blob?blob_refs:string_refs;const auto sec=data(blob?15:12);size_t end=0;
        View previous{};
        for(auto item:table){
            if(item.first!=end)return bad("Canonical","intern table gap/overlap/unreferenced bytes");
            View now{sec.p+item.first,item.second};
            if(!blob && !utf8(now.p,now.n))return bad("String","invalid UTF8 or NUL");
            if(previous.n){
                const int compare=memcmp(previous.p,now.p,std::min(previous.n,now.n));
                bool ordered=blob?(previous.n<now.n || (previous.n==now.n && compare<0)):
                    (compare<0 || (compare==0 && previous.n<now.n));
                if(!ordered)return bad("Canonical","intern table ordering/duplicate values");
            }previous=now;end=item.first+item.second;
        }if(end!=sec.n)return bad("Canonical","unreferenced intern table tail");
    }return true;
}
bool ShaderArtifactDecoder::preflight() {
    if(limits.preimage_bytes<64)return bad("Budget","derived preimage minimum");
    size_t content=sizeof("DMSV1-CONTENT")+4;
    for(size_t section=0;section<16;++section){size_t total=20;
        if(section>=12){if(sections[section].bytes>limits.preimage_bytes-total)return bad("Budget","byte section expanded preimage");total+=sections[section].bytes;}
        else for(size_t index=0;index<sections[section].count;++index){size_t start=0;const uint8_t* p=row(section,index);
            for(auto field:refs(section)){View value;if(!get_ref(p+field.first,field.second,&value))return false;size_t scalar=field.first-start;
                if(scalar>limits.preimage_bytes-total || value.n>limits.preimage_bytes-total-scalar || 4>limits.preimage_bytes-total-scalar-value.n)return bad("Budget","repeated interned reference expansion");
                total+=scalar+4+value.n;start=field.first+8;}
            size_t tail=sections[section].stride-start;if(tail>limits.preimage_bytes-total)return bad("Budget","record expansion");total+=tail;}
        if(total>limits.preimage_bytes-content)return bad("Budget","content expanded preimage");content+=total;
    }return true;
}
bool ShaderArtifactDecoder::identities() {
    const uint8_t* id=row(0);auto& key=s->key;auto& identity=s->identity;
    const uint32_t kind=u32(id),stage=u32(id+4),presence=u32(id+20);
    std::string name,content;
    if(kind<1 || kind>3 || (stage!=0 && stage!=1 && stage!=5) || u32(id+8)!=1 || u32(id+16) ||
       u32(id+44) || !zero(id+88,8) || !zero(id+560,16) || !str(id+24,&name) || !str(id+32,&content))return bad("Identity","kind/stage/backend/reserved");
    key.stage=static_cast<ShaderStage>(stage);identity.locator_kind=u32(id+12);identity.content_kind=u32(id+40);
    identity.record_index=u64(id+48);identity.control_offset=u64(id+56);identity.control_size=u32(id+64);
    identity.code_size=u32(id+68);identity.record_size=u64(id+72);identity.code_offset=u64(id+544);identity.c1_offset=u64(id+552);
    memcpy(identity.short_key.data(),id+80,8);memcpy(identity.record_sha256.data(),id+192,32);memcpy(identity.c1_sha256.data(),id+288,32);
    memcpy(key.profile_definition_sha256.data(),id+320,32);
    auto copy_digest=[](const uint8_t* p){ShaderDigest d;memcpy(d.data(),p,32);return d;};
    if(kind==1){
        if(presence!=0x27 || !name.empty() || !text_ok(content,1024) ||
           !((identity.locator_kind==1 && identity.content_kind==1) || (identity.locator_kind==2 && identity.content_kind==2)) ||
           !zero(id+224,64))return bad("Identity","OriginalMaxwell discriminant fields");
        key.source=OriginalMaxwellKey{identity.content_kind,content,copy_digest(id+96),copy_digest(id+128),copy_digest(id+160)};
    }else if(kind==2){
        if(presence!=0x18 || identity.locator_kind!=4 || stage!=5 || identity.content_kind || !content.empty() ||
           identity.record_index || identity.control_size || identity.code_size || identity.record_size || identity.code_offset || identity.c1_offset ||
           !zero(id+96,128) || sections[13].bytes || !builtin_name(name))return bad("Identity","SemanticPort absence fields");
        const char* names[]={"builtin-q-val0","builtin-q-val8","builtin-q-dlt0","builtin-q-dlt8"};
        const uint8_t short_keys[4][8]={{0xd0,0xf7,0x69,0xbb,0x91,0x6b,0xbb,0xa9},{0x16,0x47,0x9c,0xc6,0xd7,0x5c,0x2b,0x28},
            {0x06,0x87,0xe2,0xef,0x95,0x13,0x35,0x77},{0x4d,0xf5,0x90,0x9e,0x6d,0xab,0xee,0x05}};
        const uint64_t offsets[]={0x1df10e8,0x1df1a94,0x1df2440,0x1df2dec};
        size_t index=0;while(index<4 && name!=names[index])++index;
        if(index==4 || memcmp(id+80,short_keys[index],8) || identity.control_offset!=offsets[index])return bad("Identity","semantic descriptive original metadata");
        key.source=SemanticPortKey{name,copy_digest(id+224),copy_digest(id+256)};
    }else{
        if(presence!=7 || identity.locator_kind!=3 || !text_ok(name,256) || identity.content_kind || !content.empty() ||
           identity.record_index || !zero(id+96,32) || !zero(id+224,64))return bad("Identity","authored discriminant fields");
        key.source=AuthoredTranslatorFixtureKey{name,copy_digest(id+128),copy_digest(id+160)};
    }
    if(kind!=2 && (identity.control_size!=0x880 || !identity.code_size || identity.code_size>16777216 ||
       !identity.record_size || identity.record_size>16777216 || memcmp(id+80,id+128,8) ||
       !present(identity.record_sha256) || !range(identity.code_offset,identity.code_size,identity.record_size) ||
       !range(identity.c1_offset,sections[13].bytes,identity.record_size)))return bad("Identity","source sizes/spans/hashes");
    const uint8_t* p=row(1);auto& profile=s->profile;
    if(!str(p,&profile.name) || !str(p+8,&profile.binding_profile) || !str(p+16,&profile.entry) || !str(p+24,&profile.validation_target))return false;
    key.profile_name=profile.name;
    profile.minimum_api=u32(p+32);profile.spirv_version=u32(p+36);profile.addressing_model=u32(p+40);
    profile.memory_model=u32(p+44);profile.execution_model=u32(p+48);
    for(size_t i=0;i<3;++i)profile.local_size[i]=u32(p+52+i*4);
    profile.shared_bytes=u32(p+64);profile.stage_mask=u32(p+68);profile.subgroup_width=u32(p+72);
    profile.subgroup_operations=u32(p+76);profile.semantics_flags=u32(p+80);
    const bool sampled=profile.name==sampled_profile;
    const bool strict=profile.name=="android-vulkan10-strict-v1" || sampled || profile.name==original_texture_profile;
    if(profile.name==original_texture_profile && (kind!=1 || stage>1 || !hex_digest(id+96,builtin_image_sha) || data(13).n || !(profile.semantics_flags&1) ||
       (stage==0 && (!hex_digest(id+128,"96757bb36a024b91e6f161b424af3cc3db2f035f059842e5151ba7fb1ff89cc4") || !hex_digest(id+160,"a964063ef317618d70bfba606028442d0d353ab167cbe2524644e30db4ad7f00") || !hex_digest(id+192,"404af01f74cc32288864a03baca67bd68a953b1e80868eec7f2084f36980ab04"))) ||
       (stage==1 && (!hex_digest(id+128,"a7672f1d3bfeb7d0312812c8e98eea92565d5934bad06bbb5f345e5a684f92e5") || !hex_digest(id+160,"4dfa1dadaac17a24407e0c559f636e9bac1dd88566c8b4944552c33956e76cba") || !hex_digest(id+192,"6e7687e92d74f328d5ebe11f7918edef5a49ea542103f5816199e28c27cbf834")))))return bad("Profile","exact original sampled full source admission");
    if(sampled && (kind!=3 || (stage!=0 && stage!=1) || s->identity.code_size!=(stage==0?144u:208u) ||
       !hex_digest(id+160,stage==0?"9c12a4b816bf322a48e913ab6fb4ab3f2729e86735f5d15b8ffea2adfe04eaf3":"84cf2ffa64562957d5c1e2dd022702e8ce19287125a2bdffff0904d7c1a0dd6a") ||
       !hex_digest(id+512,stage==0?"0512d8f5b742bd2478b82b9b6048b0095fb6de18642077678c67ac95b68ab92f":"7dc34669e45d815d379355bd7f96da0b79af6179bdb2b3e0342fdcb493b720d6") ||
       data(14).n!=(stage==0?1744u:2516u) || data(13).n || !(profile.semantics_flags&1)))return bad("Profile","exact authored sampled source/module admission");
    if(!valid_key(key) || profile.binding_profile!="nvn-stage4096-set0-v1" || profile.entry!="main" ||
       profile.validation_target!=(strict?"vulkan1.0":"vulkan1.1") || profile.minimum_api!=(strict?0x400000u:0x401000u) ||
       profile.spirv_version!=(strict?0x10000u:0x10300u) || profile.addressing_model || profile.memory_model!=1 ||
       profile.execution_model!=(stage==0?0u:stage==1?4u:5u) || profile.stage_mask!=(1u<<stage) || u32(p+84) ||
       (profile.semantics_flags&~63u) || (profile.semantics_flags&12)!=12 || (profile.semantics_flags&50) ||
       (profile.subgroup_operations&~255u) || (profile.subgroup_width && profile.subgroup_width!=32) ||
       (strict && (profile.subgroup_width || profile.subgroup_operations)) ||
       ((profile.subgroup_operations!=0)!=(profile.subgroup_width!=0)) ||
       (profile.subgroup_operations && !(profile.subgroup_operations&1)) ||
       (stage==5?(!profile.local_size[0] || !profile.local_size[1] || !profile.local_size[2]):
          (profile.local_size[0] || profile.local_size[1] || profile.local_size[2] || profile.shared_bytes)))return bad("Profile","fixed profile/entry/model/assumptions");
    if((kind==2)!=zero(p+96,32))return bad("Profile","BufferUsageFlags enum contract presence");
    View definition;if(!blob(p+88,&definition,true) || !hash_matches(definition,id+320) || !hash_matches(data(13),id+288) ||
       !hash_matches(data(14),id+512))return false;
    std::map<std::string,View> fields;
    if(!map(definition,&fields,{"backend","binding_profile","entry","host_queries","id","policy","source_requirement_rules","supported_stages","target_env","vulkan_api","spirv_version"}) ||
       !exact_string(fields["backend"],"vulkan") || !exact_string(fields["binding_profile"],profile.binding_profile) ||
       !exact_string(fields["entry"],profile.entry) || !exact_string(fields["id"],profile.name) ||
       !exact_string(fields["target_env"],profile.validation_target))return false;
    uint64_t number;if(!integer(fields["vulkan_api"],&number) || number!=profile.minimum_api ||
       !integer(fields["spirv_version"],&number) || number!=profile.spirv_version)return bad("Profile","definition versions");
    std::map<std::string,View> policy;if(!map(fields["policy"],&policy))return false;
    std::vector<View> queries,stages,rules;if(!list(fields["host_queries"],&queries) || !list(fields["supported_stages"],&stages) || !list(fields["source_requirement_rules"],&rules))return false;
    bool found_stage=false;uint64_t previous=0;bool first=true;
    for(auto value:stages){if(!integer(value,&number) || (number!=0 && number!=1 && number!=5) || (!first && number<=previous))return bad("Profile","supported stage list");first=false;previous=number;found_stage|=number==stage;}
    if((sampled || profile.name==original_texture_profile) && (stages.size()!=2 || previous!=1))return bad("Profile","sampled profile VS/FS stage list");
    if(!found_stage || (kind!=2 && queries.empty()))return bad("Profile","query coverage/stage absence");
    std::vector<uint8_t> previous_query_definition;
    for(auto q:queries){std::map<std::string,View> f;std::string method,rule;uint64_t classification;
        if(!map(q,&f,{"classification","method","rule"}) || !integer(f["classification"],&classification) || classification<1 || classification>3 ||
           !text(f["method"],&method) || !text(f["rule"],&rule) || method.empty() ||
           rule!=(classification==1?"profile-query-v1":classification==2?"measured-query-v1":"derived-query-v1"))return bad("Profile","host query classification/order");
        std::vector<uint8_t> encoded(q.p,q.p+q.n);
        if((!previous_query_definition.empty() && encoded<=previous_query_definition) || !host_queries.emplace(method,static_cast<uint32_t>(classification)).second)return bad("Profile","host query canonical ordering/duplicate method");
        previous_query_definition=std::move(encoded);}
    std::vector<uint8_t> previous_source_rule;
    for(auto value:rules){std::string rule;if(!text(value,&rule) || rule.empty())return bad("Profile","source rule token");std::vector<uint8_t> encoded(value.p,value.p+value.n);
        if((!previous_source_rule.empty() && encoded<=previous_source_rule) || !profile_source_rules.insert(rule).second)return bad("Profile","source rule canonical order/duplicate");previous_source_rule=std::move(encoded);}
    s->c1.assign(data(13).p,data(13).p+data(13).n);
    return true;
}

bool ShaderArtifactDecoder::tables() {
    const uint32_t stage_mask=s->profile.stage_mask;const uint32_t stage=static_cast<uint32_t>(s->key.stage);
    static const char* features[]={"shaderFloat64","shaderInt64","shaderInt16","geometryShader","tessellationShader",
        "fragmentStoresAndAtomics","vertexPipelineStoresAndAtomics","shaderStorageImageExtendedFormats",
        "shaderStorageImageReadWithoutFormat","shaderStorageImageWriteWithoutFormat","shaderUniformBufferArrayDynamicIndexing",
        "shaderSampledImageArrayDynamicIndexing","shaderStorageBufferArrayDynamicIndexing","shaderStorageImageArrayDynamicIndexing",
        "sampleRateShading","shaderClipDistance","shaderCullDistance","imageCubeArray","shaderResourceMinLod","shaderStorageImageMultisample"};
    static const std::set<std::string> source_rules={"core32","storage-read","storage-write","sampled-image","storage-image-read",
        "storage-image-write","texel-buffer","derivative","discard","c1-read","driver-read","semantic-port-pair-u32",
        "subgroup-basic","subgroup-vote","subgroup-arithmetic","subgroup-ballot","subgroup-shuffle","subgroup-shuffle-relative","subgroup-clustered","subgroup-quad"};
    std::tuple<uint32_t,uint32_t,std::string,std::vector<uint8_t>> previous_requirement;
    for(size_t i=0;i<sections[2].count;++i){const uint8_t* p=row(2,i);Requirement r;
        r.domain=u32(p);r.flags=u32(p+4);r.value=u32(p+8);
        if(u32(p+12) || !str(p+16,&r.name) || !blob(p+24,&r.details,true))return bad("Reserved","requirement record");
        std::map<std::string,View> detail;if(!map(r.details,&detail))return false;
        auto order=std::make_tuple(r.domain,r.value,r.name,std::vector<uint8_t>(r.details.p,r.details.p+r.details.n));
        if(i && !(previous_requirement<order))return bad("Canonical","requirements sort/duplicate");previous_requirement=std::move(order);
        if(r.name.empty() || r.domain<1 || r.domain>6 || r.flags!=(r.domain==3 || r.domain==4?4u:r.domain==5?2u:1u))return bad("Enum","requirement flags/domain/name");
        if(r.domain==3){if(!r.value || r.value>20 || r.name!=features[r.value-1] || r.value<=5)return bad("Profile","forbidden/unknown optional feature");s->profile.required_features|=uint64_t(1)<<(r.value-1);}
        if(r.domain==4){if(r.value || r.name.rfind("VK_",0)!=0)return bad("Enum","Vulkan extension");s->profile.required_extensions.push_back(r.name);}
        if(r.domain==2 && r.value)return bad("Enum","SPIR-V extension value");
        if(r.domain==5 && (r.value || !source_rules.count(r.name) || !profile_source_rules.count(r.name) ||
            (r.name=="semantic-port-pair-u32" && shader_identity_kind(s->key)!=ShaderIdentityKind::SemanticPort) ||
            (r.name.rfind("subgroup-",0)==0 && !s->profile.subgroup_operations)))return bad("Profile","unknown/forbidden source rule");
        if(r.domain!=6 && !detail.empty())return bad("Canonical","unexpected requirement operands");
        if(r.domain==6){std::vector<View> args;if(detail.size()!=1 || !detail.count("operands") || !list(detail["operands"],&args))return bad("Canonical","execution mode details");
            for(auto arg:args){uint64_t n;if(!integer(arg,&n) || n>UINT32_MAX)return bad("Canonical","mode operand");}}
        requirements.push_back(std::move(r));
    }
    std::pair<uint32_t,uint32_t> previous_pair{};uint32_t previous_variable=0;
    for(size_t i=0;i<sections[3].count;++i){const uint8_t* p=row(3,i);ShaderDescriptor d;
        d.variable_id=u32(p);d.pointer_type_id=u32(p+4);d.resource_type_id=u32(p+8);d.type=static_cast<ShaderDescriptorType>(u32(p+12));
        d.original_set=u32(p+16);d.original_binding=u32(p+20);d.set=u32(p+24);d.binding=u32(p+28);d.count=u32(p+32);d.access=u32(p+36);d.stage_mask=u32(p+40);
        d.minimum_buffer_bytes=u64(p+48);d.address_alignment=u32(p+56);d.semantic_first=u32(p+60);d.semantic_count=u32(p+64);d.array_rank=u32(p+68);d.minimum_runtime_elements=u32(p+80);
        if(u32(p+12)>7 || !d.variable_id || !d.pointer_type_id || !d.resource_type_id || d.original_set || d.set || d.original_binding>=4096 ||
           d.binding!=stage*4096+d.original_binding || !d.count || d.count>4096 || !d.access || (d.access&~7u) ||
           ((d.access&4) && (d.access&3)!=3) || d.stage_mask!=stage_mask || u32(p+44) || !zero(p+84,12) ||
           !d.address_alignment || d.address_alignment>4096 || (d.address_alignment&(d.address_alignment-1)) ||
           !d.semantic_count || !range(d.semantic_first,d.semantic_count,sections[4].count) || !str(p+72,&d.name))return bad("Reflection","descriptor record fields");
        const auto pair=std::make_pair(d.set,d.binding);
        if(i && (pair<=previous_pair || (pair==previous_pair && d.variable_id<=previous_variable)))return bad("Reflection","duplicate/sorted binding");
        previous_pair=pair;previous_variable=d.variable_id;
        if(u32(p+12)<6 && (d.minimum_buffer_bytes || d.minimum_runtime_elements))return bad("Reflection","nonbuffer extent");
        s->descriptors.push_back(std::move(d));
    }
    uint32_t previous_type=0;
    for(size_t i=0;i<sections[7].count;++i){const uint8_t* p=row(7,i);ShaderType t;
        t.id=u32(p);t.kind=u32(p+4);t.width=u32(p+8);t.element=u32(p+12);t.count=u32(p+16);t.stride=u32(p+20);
        t.storage=u32(p+24);t.flags=u32(p+28);t.member_first=u32(p+32);t.member_count=u32(p+36);
        for(size_t j=0;j<6;++j)t.image[j]=u32(p+40+4*j);
        if(!t.id || t.id<=previous_type || !t.kind || t.kind>13 || (t.flags&~7u) || ((t.flags&6)==6) ||
           ((t.flags&1)!=0)!=(t.stride!=0) || !range(t.member_first,t.member_count,sections[8].count))return bad("Reflection","type record");
        if((t.kind==1 && t.width!=1) || (t.kind>=2 && t.kind<=4 && t.width!=32))return bad("Profile","unsupported reflected scalar width");
        previous_type=t.id;s->types.push_back(t);
    }
    std::pair<uint32_t,uint32_t> previous_member{};
    for(size_t i=0;i<sections[8].count;++i){const uint8_t* p=row(8,i);ShaderMember m;
        m.owner=u32(p);m.index=u32(p+4);m.type=u32(p+8);m.offset=u32(p+12);m.matrix_stride=u32(p+16);m.flags=u32(p+20);m.builtin=u32(p+24);
        auto order=std::make_pair(m.owner,m.index);
        if(!m.owner || !m.type || (i && order<=previous_member) || u32(p+28) || (m.flags&~127u) ||
           (!(m.flags&1) && m.offset!=kShaderNone) || (!(m.flags&2) && m.matrix_stride) ||
           ((m.flags&2) && (!m.matrix_stride || ((m.flags&12)!=4 && (m.flags&12)!=8))) ||
           (!(m.flags&2) && (m.flags&12)))return bad("Reflection","member record");
        previous_member=order;s->members.push_back(m);
    }
    std::tuple<uint32_t,uint32_t,uint32_t> previous_io{};
    for(size_t i=0;i<sections[5].count;++i){const uint8_t* p=row(5,i);ShaderIo io;
        uint32_t* fields[]={&io.variable_id,&io.type_id,&io.member,&io.direction,&io.location,&io.component,&io.builtin,&io.interpolation,&io.index,&io.stage_mask,&io.fragment_target,&io.stream};
        for(size_t j=0;j<12;++j)*fields[j]=u32(p+j*4);
        View facts;std::map<std::string,View> map_facts;
        if(!io.variable_id || !io.type_id || (io.direction!=1 && io.direction!=2) ||
           ((io.location==kShaderNone)==(io.builtin==kShaderNone)) || (io.component!=kShaderNone && io.component>3) ||
           (io.index!=kShaderNone && io.index>1) || (io.interpolation&~127u) || ((io.interpolation&3)==3) ||
           (io.interpolation&16) || io.stage_mask!=stage_mask || io.stream!=kShaderNone ||
           !str(p+48,&io.name) || !blob(p+56,&facts,true) || !map(facts,&map_facts,{"evidence","nvn_slot","rule"}) || !text(map_facts["rule"],&io.rule))return bad("Reflection","IO record/facts");
        if(map_facts["nvn_slot"].n==1 && map_facts["nvn_slot"].p[0]==0)io.nvn_slot=UINT64_MAX;
        else if(!integer(map_facts["nvn_slot"],&io.nvn_slot))return false;
        std::vector<View> evidence;if(!list(map_facts["evidence"],&evidence))return false;
        if(io.builtin!=kShaderNone){if(io.rule!="spirv-builtin-v1" || io.nvn_slot!=UINT64_MAX || io.fragment_target!=kShaderNone)return bad("Semantic","builtin IO mapping");}
        else if(stage==1 && io.direction==2){if((io.rule!="nvn-fragment-target-v1" && io.rule!="authored-io-v1") || io.fragment_target!=io.location || io.nvn_slot!=io.fragment_target)return bad("Semantic","fragment target mapping");}
        else if(stage==0 && io.direction==1){if((io.rule!="nvn-vertex-attribute-v1" && io.rule!="authored-io-v1") || io.nvn_slot==UINT64_MAX)return bad("Semantic","vertex attribute mapping");}
        else if(io.rule!="stage-location-v1" && io.rule!="authored-io-v1")return bad("Semantic","stage location rule");
        if(io.rule=="authored-io-v1" && shader_identity_kind(s->key)!=ShaderIdentityKind::AuthoredTranslatorFixture)return bad("Semantic","authored IO kind");
        auto order=std::make_tuple(io.direction,io.variable_id,io.member);if(i && order<=previous_io)return bad("Canonical","IO order/duplicate");previous_io=order;s->io.push_back(std::move(io));
    }
    // Canonical query/audit payloads are exact data, never runtime behavior.
    std::tuple<std::string,std::vector<uint8_t>,uint64_t> previous_query;
    std::vector<uint8_t> previous_answer;
    std::tuple<std::string,std::vector<uint8_t>,uint64_t,std::vector<uint8_t>,uint32_t,std::string> previous_full_query;
    for(size_t i=0;i<sections[9].count;++i){const uint8_t* p=row(9,i);std::string method,evidence;View args,answer;
        if(!str(p,&method) || method.empty() || !str(p+40,&evidence) || evidence.empty() || !blob(p+8,&args,true) || !blob(p+16,&answer,true) ||
           u32(p+24)<1 || u32(p+24)>3 || u32(p+28)!=1 || (u64(p+32)!=UINT64_MAX && u64(p+32)>=s->identity.code_size))return bad("Canonical","query record");
        std::vector<View> args_list;if(!list(args,&args_list))return false;
        auto order=std::make_tuple(method,std::vector<uint8_t>(args.p,args.p+args.n),u64(p+32));
        const std::vector<uint8_t> a(answer.p,answer.p+answer.n);
        auto classified=host_queries.find(method);
        if(classified==host_queries.end() || classified->second!=u32(p+24))return bad("Profile","query method/classification absent from definition");
        auto full=std::make_tuple(method,std::vector<uint8_t>(args.p,args.p+args.n),u64(p+32),a,u32(p+24),evidence);
        if(i && full<=previous_full_query)return bad("Canonical","query order/duplicate exact row");previous_full_query=std::move(full);
        if(i && (order<previous_query || (order==previous_query && a!=previous_answer)))return bad("Canonical","query order/conflicting answer");
        previous_query=std::move(order);previous_answer=a;
    }
    if(shader_identity_kind(s->key)!=ShaderIdentityKind::SemanticPort && !sections[9].count)return bad("Profile","missing translator query log");
    std::tuple<uint32_t,std::string,uint64_t,std::string> previous_diagnostic;
    for(size_t i=0;i<sections[10].count;++i){const uint8_t* p=row(10,i);std::string kind,message;
        if(u32(p)!=1 || u32(p+4)!=1 || !str(p+8,&kind) || kind.empty() || !str(p+24,&message))return bad("Profile","unresolved/warning diagnostic");
        auto order=std::make_tuple(u32(p),kind,u64(p+16),message);if(i && order<=previous_diagnostic)return bad("Canonical","diagnostic order/duplicate");previous_diagnostic=std::move(order);
    }
    return true;
}

bool ShaderArtifactDecoder::closures() {
    const uint32_t identity_kind=static_cast<uint32_t>(shader_identity_kind(s->key));
    std::map<std::pair<uint32_t,uint32_t>,size_t> roles;
    std::map<std::string,std::pair<uint64_t,ShaderDigest>> logical_bytes;
    std::tuple<uint32_t,uint32_t,std::string> previous;
    std::set<std::string> input_kinds;bool validator=false,compiler=false,builtin_recipe=false,builtin_recipe_pinned=false;uint64_t portable_source_size=0;
    std::map<std::string,std::vector<std::string>> tool_arguments;std::map<std::string,std::string> tool_runtimes;std::set<std::string> runtimes;
    for(size_t i=0;i<sections[11].count;++i){const uint8_t* p=row(11,i);const uint32_t group=u32(p),role=u32(p+4),flags=u32(p+72);
        std::string id;View payload,metadata;std::map<std::string,View> meta;
        if(!str(p+8,&id) || !text_ok(id,1024) || id[0]=='/' || id.find('\\')!=std::string::npos || id.find(':')!=std::string::npos ||
           id.back()=='/' || id.find("//")!=std::string::npos || !zero(p+76,20) || (flags&~3u) || ((flags&2) && !(flags&1)) ||
           !blob(p+56,&payload,(flags&2)!=0) || !blob(p+64,&metadata,true) || !map(metadata,&meta))return bad("Closure","record/id/flags/metadata");
        size_t begin=0;while(begin<id.size()){size_t end=id.find('/',begin);if(end==std::string::npos)end=id.size();auto part=id.substr(begin,end-begin);
            if(part=="." || part=="..")return bad("Closure","dot path segment");begin=end+1;}
        auto order=std::make_tuple(group,role,id);if(i && order<=previous)return bad("Canonical","closure order/duplicate");previous=order;
        closure_ids.insert(id);ShaderDigest named_digest;memcpy(named_digest.data(),p+24,32);
        const auto named=std::make_pair(u64(p+16),named_digest);auto named_before=logical_bytes.emplace(id,named);
        if(!named_before.second && named_before.first->second!=named)return bad("Closure","conflicting bytes for logical identity");
        if(!((group==1 && role>=1 && role<=5) || (group==2 && (role==16 || role==17)) || (group==3 && role>=32 && role<=42)))return bad("Enum","closure group/role");
        ++roles[{group,role}];
        if(zero(p+24,32) || ((flags&1) && (u64(p+16)!=payload.n || !hash_matches(payload,p+24))) ||
           (!(flags&1) && (payload.n || u32(p+56))))return bad("Closure","payload size/hash/presence");
        if(group==1 && !meta.empty())return bad("Closure","source metadata field set");
        if(group==1 && role==2 && id=="dm/gfx/shader/recipes/image-nvn-builtin-v1.md"){
            if(u64(p+16)!=3801 || !hex_digest(p+24,"65625e8af6daf0bc4c0608b7b626df418a65be0c15319ce51dc39e160b26b164"))return bad("Closure","original builtin recipe supplement pin");
            builtin_recipe_pinned=true;
        }
        if(group==2 && role==16){
            if(!map(metadata,&meta,{"arguments","build_source_root","runtime"}))return false;
            std::vector<View> args;std::string runtime;if(!list(meta["arguments"],&args) || !text(meta["runtime"],&runtime) || runtime.empty())return bad("Closure","tool invocation/runtime");
            std::vector<std::string> tokens;for(auto arg:args){std::string token;if(!text(arg,&token))return false;tokens.push_back(token);}tool_arguments.emplace(id,std::move(tokens));tool_runtimes.emplace(id,runtime);
            View root=meta["build_source_root"];if(!(root.n==1 && root.p[0]==0)){View digest;if(!bytes(root,&digest) || digest.n!=32 || zero(digest.p,32))return bad("Closure","tool build root");}
            validator|=id=="tools/spirv-val";compiler|=id=="tools/glslc";
        }else if(group==2){if(!meta.empty() || flags!=3)return bad("Closure","runtime identity metadata/payload");runtimes.insert(id);}
        if(group==3){
            if(role>=33 && role<=35){bool applicable;
                if(!(flags&1) || !map(metadata,&meta,{"applicable"}) || !boolean(meta["applicable"],&applicable) || (!applicable && payload.n))return bad("Closure","row applicability");
            }else if(role==41 || role==42){
                std::string input;if(flags || !map(metadata,&meta,{"kind"}) || !text(meta["kind"],&input) || !input_kinds.insert(input).second ||
                   (role==41?identity_kind!=1:identity_kind!=3))return bad("Closure","kind-specific original/authored input");
                const uint8_t* expected=nullptr;uint64_t expected_size=0;
                if(input=="content" && role==41){expected=row(0)+96;if(builtin_recipe)expected_size=52510720;}
                else if(input=="control"){expected=row(0)+128;expected_size=s->identity.control_size;}
                else if(input=="code"){expected=row(0)+160;expected_size=s->identity.code_size;}
                else if(input=="record"){expected=row(0)+192;expected_size=s->identity.record_size;}
                if(!expected || memcmp(expected,p+24,32) || (expected_size && u64(p+16)!=expected_size))return bad("Closure","source input correspondence");
            }else if(!meta.empty() || !(flags&1))return bad("Closure","request metadata/embedded presence");
            if(role==38 && !hash_matches(payload,row(0)+448))return false;
            if(role==39){View definition;if(flags!=3 || !blob(row(1)+88,&definition,true) || !same(payload,definition))return bad("Closure","profile definition payload");}
            if(role==40){std::map<std::string,View> provenance;uint64_t kind;std::vector<View> evidence;
                if(flags!=3 || !map(payload,&provenance,{"identity_kind","label","evidence"}) || !integer(provenance["identity_kind"],&kind) || kind!=identity_kind ||
                   !exact_string(provenance["label"],identity_kind==1?"original-maxwell":identity_kind==2?"existing-disassembly-equivalent":"authored-translator-fixture") || !list(provenance["evidence"],&evidence))return bad("Identity","provenance label/kind");}
            if(role==36){std::map<std::string,View> extraction,locator;uint64_t control,code,c1,code_size,c1_size,record_size;View prefix;std::string recipe;
                if(flags!=3 || !map(payload,&extraction,{"recipe","source_locator","record_control_offset","record_code_offset","record_c1_offset","code_size","c1_size","record_size","synthetic_prefix"}) ||
                   !text(extraction["recipe"],&recipe) || !integer(extraction["record_control_offset"],&control) || !integer(extraction["record_code_offset"],&code) ||
                   !integer(extraction["record_c1_offset"],&c1) || !integer(extraction["code_size"],&code_size) || !integer(extraction["c1_size"],&c1_size) ||
                   !integer(extraction["record_size"],&record_size) || !bytes(extraction["synthetic_prefix"],&prefix) || !map(extraction["source_locator"],&locator))return false;
                builtin_recipe=recipe=="image-nvn-builtin-v1";
                const char* expected_recipe=s->identity.locator_kind==1?"package-record-v1":s->identity.locator_kind==2?(builtin_recipe?"image-nvn-builtin-v1":"image-main-rec-v1"):s->identity.locator_kind==3?"authored-record-v1":"semantic-builtin-v1";
                if(recipe!=expected_recipe || code!=s->identity.code_offset || c1!=s->identity.c1_offset || code_size!=s->identity.code_size ||
                   c1_size!=sections[13].bytes || record_size!=s->identity.record_size ||
                   !range(control,s->identity.control_size,record_size) || (identity_kind==2 && (control || prefix.n)))return bad("Identity","extraction source spans");
                s->identity.record_control_offset=control;
                if(builtin_recipe){const auto* source=original_builtin(s->key,s->identity.control_offset);
                    if(identity_kind!=1 || s->identity.locator_kind!=2 || !source || !builtin_recipe_pinned || s->identity.record_index ||
                       control!=276 || code!=20 || c1!=276 || code_size!=256 || c1_size || record_size!=2452 || prefix.n ||
                       s->identity.control_size!=0x880 || !hex_digest(s->identity.record_sha256.data(),source->record) ||
                       s->profile.local_size!=std::array<uint32_t,3>{32,1,1})return bad("Identity","original builtin recipe catalog/geometry/supplement");}
                if(identity_kind==2){if(locator.size()!=1 || !locator.count("builtin") || !exact_string(locator["builtin"],std::get<SemanticPortKey>(s->key.source).builtin_name))return bad("Identity","semantic locator");}
                else if(identity_kind==3){if(locator.size()!=1 || !locator.count("fixture") || !exact_string(locator["fixture"],std::get<AuthoredTranslatorFixtureKey>(s->key.source).fixture_name) || prefix.n || s->identity.control_offset!=control)return bad("Identity","authored locator");}
                else {const auto& key=std::get<OriginalMaxwellKey>(s->key.source);uint64_t content_kind,offset;View digest;
                    if(locator.size()!=4 || !locator.count("content_kind") || !locator.count("content_name") || !locator.count("content_sha256") ||
                       !integer(locator["content_kind"],&content_kind) || content_kind!=key.content_kind || !exact_string(locator["content_name"],key.content_name) ||
                       !bytes(locator["content_sha256"],&digest) || digest.n!=32 || memcmp(digest.p,key.trusted_content_sha256.data(),32))return bad("Identity","trusted content locator");
                    const char* field=key.content_kind==1?"record_index":"control_offset";
                    if(!locator.count(field) || !integer(locator[field],&offset) || offset!=(key.content_kind==1?s->identity.record_index:s->identity.control_offset) ||
                       (key.content_kind==1 && (prefix.n || s->identity.control_offset!=control)) ||
                       (key.content_kind==2 && (builtin_recipe?prefix.n!=0:(prefix.n!=0x38 || !zero(prefix.p,prefix.n)))))return bad("Identity","record/image extraction locator");
                }
            }
            if(role==32){if(flags!=3)return bad("Closure","canonical effective Job required");std::map<std::string,View> job,code;
                if(!map(payload,&job,{"actual_stage","attr","c1","code","debug","fout","identity_kind","img","key","local","local_memory","pc_missing","reduced","requested_stage","shared","tex"}))return bad("Closure","Job exact field set");
                uint64_t kind,stage,shared,memory,code_size;bool debug,reduced,missing;std::string key;View c1,digest;std::vector<View> local;
                if(!integer(job["identity_kind"],&kind) || kind!=identity_kind || !integer(job["actual_stage"],&stage) || stage!=static_cast<uint32_t>(s->key.stage) ||
                   !exact_string(job["requested_stage"],stage==0?"vs":stage==1?"ps":"cs") || !boolean(job["debug"],&debug) || debug!=bool(s->profile.semantics_flags&1) ||
                   !boolean(job["reduced"],&reduced) || reduced || !boolean(job["pc_missing"],&missing) || missing || !bytes(job["c1"],&c1) || !same(c1,data(13)) ||
                   !text(job["key"],&key) || key.empty() || !integer(job["shared"],&shared) || shared!=s->profile.shared_bytes || !integer(job["local_memory"],&memory) || memory>16777216 ||
                   !list(job["local"],&local) || local.size()!=3 || !map(job["code"],&code,{"sha256","size"}) || !bytes(code["sha256"],&digest) || digest.n!=32 || !integer(code["size"],&code_size))return bad("Closure","Job effective identity/stage/options");
                for(size_t axis=0;axis<3;++axis){uint64_t n;if(!integer(local[axis],&n) || n!=s->profile.local_size[axis])return bad("Closure","Job local size");}
                const uint8_t* expected=identity_kind==2?row(0)+256:row(0)+160;
                if(memcmp(digest.p,expected,32) || code_size!=(identity_kind==2?portable_source_size:s->identity.code_size))return bad("Closure","Job exact code size/digest");
                if(identity_kind==2 && (key!=std::get<SemanticPortKey>(s->key.source).builtin_name || debug || memory || shared || c1.n))return bad("Closure","Job semantic compiler contract");
                if(identity_kind==3 && key!=std::get<AuthoredTranslatorFixtureKey>(s->key.source).fixture_name)return bad("Closure","Job authored fixture name");
                const std::set<std::string> scalar_types={"float","sint","uint"};
                const std::set<std::string> image_types={"1d","1darray","2d","2darray","2dms","2dmsarray","3d","cube","cubearray","buffer"};
                const bool sampled=s->profile.name==sampled_profile;
                for(const char* name:{"attr","fout","tex","img"}){std::map<std::string,View> entries;if(!map(job[name],&entries) || (identity_kind==2 && !entries.empty()))return bad("Closure","Job explicit source fact maps");
                    if(sampled && ((std::string(name)=="tex" && entries.size()!=(stage==1?1u:0u)) || (std::string(name)=="img" && !entries.empty())))return bad("Closure","sampled singleton texture facts");
                    for(const auto& entry:entries){const auto& slot=entry.first;if(slot.empty() || (slot.size()>1 && slot[0]=='0') || slot.size()>10 || !std::all_of(slot.begin(),slot.end(),[](char c){return c>='0' && c<='9';}))return bad("Closure","Job canonical decimal slot");
                        if(std::string(name)=="img"){std::map<std::string,View> image;std::string format,type;if(!map(entry.second,&image,{"fmt","type"}) || !text(image["fmt"],&format) || format!="R32Uint" || !text(image["type"],&type) || type!="2d")return bad("Closure","Job image type/format outside proved R32Uint subset");}
                        else if(sampled && std::string(name)=="tex"){std::map<std::string,View> texture;bool normalized;
                            if(slot!="0" || !map(entry.second,&texture,{"normalized","type"}) || !exact_string(texture["type"],"2d") || !boolean(texture["normalized"],&normalized) || !normalized)return bad("Closure","sampled typed normalization");}
                        else {std::string type;if(!text(entry.second,&type) || !(std::string(name)=="tex"?image_types:scalar_types).count(type))return bad("Closure","Job source scalar/texture type");}}
                }
            }
            if(role==37){std::map<std::string,View> options;
                if(flags!=3 || !map(payload,&options,{"binding_profile","compiler","profile","support_policy","translator","validator"}) ||
                   !exact_string(options["binding_profile"],s->profile.binding_profile) || !exact_string(options["profile"],s->profile.name))return bad("Closure","effective Options");
                for(const char* field:{"compiler","translator","validator"}){View tool=options[field];bool unused=tool.n==1 && tool.p[0]==0;
                    const bool expected_unused=std::string(field)=="compiler"?identity_kind!=2:std::string(field)=="translator"?identity_kind==2:false;
                    if(unused!=expected_unused)return bad("Closure","Options tool usage versus identity kind");if(unused)continue;
                    std::map<std::string,View> invocation;std::vector<View> args;std::string id_tool;
                    if(!map(tool,&invocation,{"arguments","tool"}) || !text(invocation["tool"],&id_tool) || !list(invocation["arguments"],&args) || !tool_arguments.count(id_tool))return bad("Closure","option tool invocation");
                    std::vector<std::string> tokens;for(View arg:args){std::string token;if(!text(arg,&token))return false;tokens.push_back(token);}
                    if(tokens!=tool_arguments[id_tool])return bad("Closure","Options arguments versus actual ToolBinary invocation");}
                std::vector<View> support;if(!list(options["support_policy"],&support))return false;
                // Support's no-access and initializer are checked with SPIR-V below.
            }
        }
        if(group==1 && (role==3 || role==4)){
            if(identity_kind!=2 || memcmp(p+24,row(0)+(role==3?224:256),32))return bad("Identity","semantic source closure");
            if(role==4)portable_source_size=u64(p+16);
        }
    }
    for(uint32_t role=32;role<=40;++role)if(roles[{3,role}]!=1)return bad("Closure","missing/duplicate required request row");
    for(const auto& tool:tool_runtimes)if(!runtimes.count(tool.second))return bad("Closure","ToolBinary runtime reference missing");
    if(!roles[{1,2}] || !roles[{1,5}] || !roles[{2,17}] || !validator)return bad("Closure","missing publisher/build/runtime/validator closure");
    if(identity_kind==2){if(roles[{1,3}]!=1 || roles[{1,4}]!=1 || roles[{1,1}] || !compiler || !input_kinds.empty())return bad("Closure","semantic provenance closure");}
    else if(!roles[{1,1}] || input_kinds.size()!=(identity_kind==1?4u:3u))return bad("Closure","translator/original input closure");
    for(size_t i=0;i<sections[9].count;++i){std::string id;if(!str(row(9,i)+40,&id) || !closure_ids.count(id))return bad("Closure","query evidence identity");}
    if(s->profile.name==sampled_profile){size_t normalized=0;
        for(size_t i=0;i<sections[9].count;++i){const uint8_t* p=row(9,i);std::string method;if(!str(p,&method))return false;
            if(method.find(".QueryTextureCoordNormalized(")==std::string::npos)continue;
            ++normalized;View arguments,answer;std::vector<View> args;uint64_t handle,bank;bool value;
            if(!blob(p+8,&arguments,true) || !list(arguments,&args) || args.size()!=2 || !integer(args[0],&handle) || handle!=0x1056805a ||
               !integer(args[1],&bank) || bank!=0x30002 || !blob(p+16,&answer,true) || !boolean(answer,&value) || !value || u32(p+24)!=2)return bad("Closure","sampled normalized query proof");}
        if(normalized!=(s->key.stage==ShaderStage::Fragment?1u:0u))return bad("Closure","sampled normalized query count");
    }
    return true;
}

bool ShaderArtifactDecoder::digests() {
    std::array<size_t,16> sizes{};
    for(size_t section=0;section<16;++section){size_t total=20;
        if(section>=12){if(sections[section].bytes>limits.preimage_bytes-total)return bad("Budget","byte section preimage");total+=sections[section].bytes;}
        else for(size_t index=0;index<sections[section].count;++index){size_t start=0;const uint8_t* p=row(section,index);
            for(auto field:refs(section)){View v;if(!get_ref(p+field.first,field.second,&v))return false;
                size_t scalar=field.first-start;
                if(scalar>limits.preimage_bytes-total || v.n>limits.preimage_bytes-total-scalar || 4>limits.preimage_bytes-total-scalar-v.n)return bad("Budget","expanded reference preimage");
                total+=scalar+4+v.n;start=field.first+8;}
            size_t tail=sections[section].stride-start;if(tail>limits.preimage_bytes-total)return bad("Budget","expanded record preimage");total+=tail;}
        sizes[section]=total;
    }
    auto expand=[&](std::vector<uint8_t>& out,size_t section){put32(out,static_cast<uint32_t>(section+1));put32(out,sections[section].count);put32(out,sections[section].stride);put64(out,sizes[section]-20);
        if(section>=12){auto v=data(section);append(out,v.p,v.n);return;}
        for(size_t index=0;index<sections[section].count;++index){size_t start=0;const uint8_t* p=row(section,index);
            for(auto field:refs(section)){View v;get_ref(p+field.first,field.second,&v);append(out,p+start,field.first-start);lp(out,v.p,v.n);start=field.first+8;}append(out,p+start,sections[section].stride-start);}};
    std::array<size_t,4> group_sizes{};std::array<uint32_t,4> group_counts{};
    for(size_t i=0;i<sections[11].count;++i){const uint8_t* p=row(11,i);uint32_t group=u32(p);View id,payload,meta;
        if(!get_ref(p+8,false,&id) || !blob(p+56,&payload) || !blob(p+64,&meta))return false;
        const size_t n=4+4+4+id.n+8+32+4+4+payload.n+4+meta.n;
        if(n>limits.preimage_bytes-group_sizes[group])return bad("Budget","closure repeated-reference preimage");group_sizes[group]+=n;++group_counts[group];
    }
    auto closure=[&](std::vector<uint8_t>& out,uint32_t group,bool translator_only){
        for(size_t i=0;i<sections[11].count;++i){const uint8_t* p=row(11,i);if(u32(p)!=group)continue;
            View id,payload,meta;get_ref(p+8,false,&id);blob(p+56,&payload);blob(p+64,&meta);
            const std::string name(reinterpret_cast<const char*>(id.p),id.n);
            if(translator_only && u32(p+4)!=1 && !(u32(p+4)==5 && name.rfind("build/translator/",0)==0))continue;
            put32(out,group);put32(out,u32(p+4));lp(out,id.p,id.n);put64(out,u64(p+16));append(out,p+24,32);put32(out,u32(p+72));lp(out,payload.p,payload.n);lp(out,meta.p,meta.n);}};
    struct Task{const char* domain;size_t size;const uint8_t* expected;uint32_t group;std::vector<size_t> sections;};
    std::vector<Task> tasks={{"DMSV1-SOURCES",sizeof("DMSV1-SOURCES")+4+group_sizes[1],row(0)+352,1,{}},
        {"DMSV1-TOOLS",sizeof("DMSV1-TOOLS")+4+group_sizes[2],row(0)+384,2,{}},
        {"DMSV1-REQUEST",sizeof("DMSV1-REQUEST")+4+group_sizes[3]+sizes[9]+sizes[10],row(0)+416,3,{9,10}}};
    size_t reflection=sizeof("DMSV1-REFLECTION")+4,content=sizeof("DMSV1-CONTENT")+4;
    for(size_t i=1;i<=8;++i){if(sizes[i]>limits.preimage_bytes-reflection)return bad("Budget","reflection preimage");reflection+=sizes[i];}
    for(size_t n:sizes){if(n>limits.preimage_bytes-content)return bad("Budget","content preimage repeated references");content+=n;}
    tasks.push_back({"DMSV1-REFLECTION",reflection,row(0)+480,0,{1,2,3,4,5,6,7,8}});
    tasks.push_back({"DMSV1-CONTENT",content,nullptr,0,{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}});
    size_t all=hash_work;for(const auto& task:tasks)if(task.size>limits.preimage_bytes || !charge(task.size,all,limits.hash_work_bytes,"cumulative derived hash work"))return bad("Budget","digest preimage work");
    // Preflight all roots before constructing even the first expanded buffer.
    for(const auto& task:tasks){std::vector<uint8_t> preimage;preimage.reserve(task.size);append(preimage,reinterpret_cast<const uint8_t*>(task.domain),strlen(task.domain)+1);
        put32(preimage,task.group?group_counts[task.group]:static_cast<uint32_t>(task.sections.size()));
        if(task.group)closure(preimage,task.group,false);for(auto section:task.sections)expand(preimage,section);
        if(preimage.size()!=task.size)return bad("Canonical","digest size accounting");ShaderDigest digest=sha({preimage.data(),preimage.size()});
        if(task.expected && memcmp(digest.data(),task.expected,32))return bad("Closure","derived closure/reflection digest mismatch");
    }hash_work=all;
    // A translator build attests only its own sources/build definitions.
    if(shader_identity_kind(s->key)!=ShaderIdentityKind::SemanticPort){
        std::vector<uint8_t> rows;closure(rows,1,true);uint32_t selected=0;
        for(size_t i=0;i<sections[11].count;++i){const uint8_t* p=row(11,i);std::string id;if(!str(p+8,&id))return false;
            selected+=u32(p)==1 && (u32(p+4)==1 || (u32(p+4)==5 && id.rfind("build/translator/",0)==0));}
        const size_t length=sizeof("DMSV1-XLATE-SOURCES")+4+rows.size();if(length>limits.preimage_bytes || !charge(length,hash_work,limits.hash_work_bytes,"translator source root"))return false;
        std::vector<uint8_t> preimage;append(preimage,reinterpret_cast<const uint8_t*>("DMSV1-XLATE-SOURCES"),sizeof("DMSV1-XLATE-SOURCES"));put32(preimage,selected);append(preimage,rows.data(),rows.size());auto digest=sha({preimage.data(),preimage.size()});
        bool attested=false;
        for(size_t i=0;i<sections[11].count;++i){const uint8_t* p=row(11,i);if(u32(p)!=2 || u32(p+4)!=16)continue;View metadata;if(!blob(p+64,&metadata,true))return false;std::map<std::string,View> f;if(!map(metadata,&f))return false;
            View root=f["build_source_root"];if(root.n==1 && root.p[0]==0)continue;View value;if(!bytes(root,&value) || value.n!=32 || memcmp(value.p,digest.data(),32))return bad("Closure","translator build source attestation");attested=true;}
        if(!attested)return bad("Closure","translator build attestation missing");
    }
    return true;
}

namespace {
struct SpvType {uint32_t op=0;std::vector<uint32_t> args;};
struct SpvVar {uint32_t type=0,storage=0;};
using Decorations=std::map<uint32_t,std::vector<uint32_t>>;
struct SpvFacts {
    std::map<uint32_t,SpvType> types;
    std::map<uint32_t,SpvVar> vars;
    std::map<uint32_t,uint32_t> constants;
    std::map<uint32_t,uint32_t> constant_types;
    std::map<uint32_t,Decorations> dec;
    std::map<std::pair<uint32_t,uint32_t>,Decorations> member_dec;
    std::map<uint32_t,std::string> names;
    std::map<std::pair<uint32_t,uint32_t>,std::string> member_names;
    std::map<uint32_t,std::vector<uint32_t>> modes;
    std::set<uint32_t> capabilities,interface_ids;
    std::set<uint32_t> accessed,stored;
    std::map<uint32_t,uint32_t> pointer_roots;
    std::set<uint32_t> unknown_pointer_roots;
};
uint32_t decoration(const Decorations& d,uint32_t key,uint32_t otherwise=kShaderNone){auto it=d.find(key);return it==d.end() || it->second.empty()?otherwise:it->second[0];}
bool has_dec(const Decorations& d,uint32_t key){return d.count(key)!=0;}
uint32_t interpolation(const Decorations& d) {
    uint32_t flags=0;const uint32_t keys[]={14,13,16,17,15,18,0};
    for(unsigned i=0;i<7;++i)if(has_dec(d,keys[i]))flags|=1u<<i;return flags;
}
bool spv_string(const std::vector<uint32_t>& words,size_t start,size_t end,std::string* out,size_t* after) {
    if(start>=end)return false;out->clear();bool nul=false;
    for(size_t i=start;i<end;++i){for(unsigned byte=0;byte<4;++byte){uint8_t value=uint8_t(words[i]>>(8*byte));
        if(nul){if(value)return false;continue;}if(!value){nul=true;*after=i+1;}else out->push_back(static_cast<char>(value));}
        if(nul)return utf8(reinterpret_cast<const uint8_t*>(out->data()),out->size());}
    return false;
}
const char* capability_name(uint32_t v) {
    switch(v){case 0:return "Matrix";case 1:return "Shader";case 27:return "StorageImageMultisample";
    case 32:return "ClipDistance";case 33:return "CullDistance";case 34:return "ImageCubeArray";case 35:return "SampleRateShading";
    case 42:return "MinLod";case 43:return "Sampled1D";case 44:return "Image1D";case 46:return "SampledBuffer";
    case 47:return "ImageBuffer";case 48:return "ImageMSArray";case 49:return "StorageImageExtendedFormats";
    case 50:return "ImageQuery";case 51:return "DerivativeControl";case 52:return "InterpolationFunction";
    case 55:return "StorageImageReadWithoutFormat";case 56:return "StorageImageWriteWithoutFormat";default:return nullptr;}
}
const char* mode_name(uint32_t v) {switch(v){case 7:return "OriginUpperLeft";case 9:return "EarlyFragmentTests";
    case 12:return "DepthReplacing";case 14:return "DepthGreater";case 15:return "DepthLess";case 16:return "DepthUnchanged";case 17:return "LocalSize";default:return nullptr;}}
// Core instruction grammar admitted by this reflector. Types/variables and all
// resource-affecting instructions are handled separately; barriers, atomics,
// group operations, unknown/newer opcodes and decoration groups refuse.
bool plain_instruction(uint32_t op,size_t wc) {
    switch(op){case 0:return wc==1;case 3:return wc>=3;case 4:return wc>=2;case 8:return wc==4;
    case 10:return false;case 11:return wc>=3;case 12:return wc>=5;
    case 41:case 42:case 46:return wc==3;case 43:return wc==4;case 44:return wc>=4;
    case 54:return wc==5;case 55:return wc==3;case 56:return wc==1;case 57:return wc>=4;
    case 61:return wc>=4;case 62:return wc>=3;case 63:return wc>=3;case 64:return wc>=4;
    case 65:case 66:return wc>=5;case 68:return wc==5;
    case 79:return wc>=6;case 80:return wc>=4;case 81:return wc>=5;case 82:return wc>=6;case 83:return wc==4;
    case 86:return wc==5;case 87:case 88:case 89:case 90:case 91:case 92:case 93:case 94:case 95:case 96:case 97:case 98:return wc>=5;
    case 99:return wc>=4;case 100:return wc==4;case 101:case 102:case 103:case 104:case 105:case 106:case 107:return wc>=4;
    case 245:return wc>=5 && (wc&1)==1;case 246:return wc>=4;case 247:return wc==3;case 248:return wc==2;
    case 249:return wc==2;case 250:return wc>=4;case 251:return wc>=3 && (wc&1)==1;
    case 252:case 253:case 255:return wc==1;case 254:return wc==2;case 317:return wc==1;
    default:break;}
    // Dense core scalar/vector arithmetic/conversion ranges; gaps are excluded.
    if((op>=109 && op<=124) || (op>=126 && op<=152) || (op>=154 && op<=191) ||
       (op>=194 && op<=205) || (op>=207 && op<=215))return wc>=4 && wc<=8;
    return false;
}
}

bool ShaderArtifactDecoder::spirv() {
    const auto bytes_spv=data(14);s->words.resize(bytes_spv.n/4);
    for(size_t i=0;i<s->words.size();++i)s->words[i]=u32(bytes_spv.p+4*i);
    const auto& w=s->words;
    if(w[0]!=0x07230203 || w[1]!=s->profile.spirv_version || !w[3] || w[3]>262144 || w[4])return bad("Spirv","header/version/bound");
    const uint32_t bound=w[3];SpvFacts facts;bool memory=false,entry=false;uint32_t entry_function=0;
    std::set<uint32_t> declared_ids;std::vector<uint32_t> result_types;
    auto id_ok=[&](uint32_t id){return id && id<bound;};
    auto define=[&](uint32_t id){return id_ok(id) && declared_ids.insert(id).second;};
    auto decorations=[&](Decorations& d,size_t operand,size_t end)->bool{
        uint32_t key=w[operand];size_t args=end-operand-1;
        const bool flag=key==0 || key==2 || key==3 || key==4 || key==5 || key==13 || key==14 || key==15 || key==16 || key==17 || key==18 || key==24 || key==25 || key==42;
        const bool scalar=key==6 || key==7 || key==11 || key==30 || key==31 || key==32 || key==33 || key==34 || key==35;
        if((!flag && !scalar) || args!=(flag?0u:1u) || d.count(key))return false;
        d.emplace(key,std::vector<uint32_t>(w.begin()+static_cast<ptrdiff_t>(operand+1),w.begin()+static_cast<ptrdiff_t>(end)));return true;};
    struct Instruction {size_t at;uint32_t op,wc;};std::vector<Instruction> instructions;
    for(size_t at=5;at<w.size();){uint32_t wc=w[at]>>16,op=w[at]&65535;
        if(!wc || wc>w.size()-at)return bad("Spirv","zero/truncated instruction");size_t end=at+wc;instructions.push_back({at,op,wc});
        if(op==5 || op==6){const size_t string_at=at+(op==5?2:3);std::string name;size_t after=0;
            if(wc<(op==5?3u:4u) || !id_ok(w[at+1]) || !spv_string(w,string_at,end,&name,&after) || after!=end)return bad("Spirv","debug name string");
            if(op==5){if(!facts.names.emplace(w[at+1],name).second)return bad("Spirv","duplicate name");}
            else if(!facts.member_names.emplace(std::make_pair(w[at+1],w[at+2]),name).second)return bad("Spirv","duplicate member name");
        }else if(op==14){if(wc!=3 || memory || w[at+1]!=s->profile.addressing_model || w[at+2]!=s->profile.memory_model)return bad("Spirv","memory model");memory=true;}
        else if(op==15){std::string name;size_t after=0;
            if(wc<4 || entry || w[at+1]!=s->profile.execution_model || !id_ok(w[at+2]) || !spv_string(w,at+3,end,&name,&after) || name!=s->profile.entry)return bad("Spirv","entry/model");
            entry=true;entry_function=w[at+2];for(size_t i=after;i<end;++i)if(!id_ok(w[i]) || !facts.interface_ids.insert(w[i]).second)return bad("Spirv","entry interface ID");
        }else if(op==16){if(wc<3 || !id_ok(w[at+1]) || !mode_name(w[at+2]) || !facts.modes.emplace(w[at+2],std::vector<uint32_t>(w.begin()+static_cast<ptrdiff_t>(at+3),w.begin()+static_cast<ptrdiff_t>(end))).second)return bad("Spirv","execution mode");
            if(entry_function && w[at+1]!=entry_function)return bad("Spirv","execution mode entry");}
        else if(op==17){if(wc!=2 || !capability_name(w[at+1]) || !facts.capabilities.insert(w[at+1]).second)return bad("Spirv","unsupported/duplicate capability");}
        else if(op>=19 && op<=33){
            if(wc<2)return bad("Spirv","type operands");
            if(!define(w[at+1]))return bad("Spirv","type ID bound/duplicate");
            facts.types.emplace(w[at+1],SpvType{op,std::vector<uint32_t>(w.begin()+static_cast<ptrdiff_t>(at+2),w.begin()+static_cast<ptrdiff_t>(end))});
        }else if(op==59){if((wc!=4 && wc!=5) || !id_ok(w[at+1]) || !define(w[at+2]))return bad("Spirv","variable/type ID");
            facts.vars.emplace(w[at+2],SpvVar{w[at+1],w[at+3]});facts.pointer_roots[w[at+2]]=w[at+2];}
        else if(op==71){if(wc<3 || !id_ok(w[at+1]) || !decorations(facts.dec[w[at+1]],at+2,end))return bad("Spirv","duplicate/unsupported decoration");}
        else if(op==72){if(wc<4 || !id_ok(w[at+1]) || !decorations(facts.member_dec[{w[at+1],w[at+2]}],at+3,end))return bad("Spirv","duplicate/unsupported member decoration");}
        else {
            if(!plain_instruction(op,wc))return bad("Spirv","unsupported opcode "+std::to_string(op));
            if(op==11){std::string name;size_t after;if(!define(w[at+1]) || !spv_string(w,at+2,end,&name,&after) || after!=end || name!="GLSL.std.450")return bad("Spirv","extended instruction import");}
            const bool typed=op==12 || (op>=41 && op<=46) || op==54 || op==55 || op==57 || op==61 || op==65 || op==66 || op==68 ||
                (op>=79 && op<=98) || (op>=100 && op<=215) || op==245;
            if(typed){if(wc<3 || !id_ok(w[at+1]) || !define(w[at+2]))return bad("Spirv","typed result ID bound/duplicate");result_types.push_back(w[at+1]);}
            if(op==248 && !define(w[at+1]))return bad("Spirv","label ID bound/duplicate");
            if(op==43){facts.constants[w[at+2]]=w[at+3];facts.constant_types[w[at+2]]=w[at+1];}
        }
        at=end;
    }
    if(!memory || !entry || !facts.capabilities.count(1))return bad("Spirv","missing memory/entry/Shader capability");
    for(uint32_t type:result_types)if(!facts.types.count(type))return bad("Spirv","typed instruction references missing type");
    // Independently compare every declared capability and execution mode.
    std::set<uint32_t> reflected_caps,reflected_modes;
    for(const auto& r:requirements){if(r.domain==1){if(!facts.capabilities.count(r.value) || !capability_name(r.value) || r.name!=capability_name(r.value) || !reflected_caps.insert(r.value).second)return bad("Reflection","capability declaration disagreement");}
        if(r.domain==2)return bad("Spirv","extensions outside native admitted subset");
        if(r.domain==6){auto found=facts.modes.find(r.value);if(found==facts.modes.end() || !mode_name(r.value) || r.name!=mode_name(r.value) || !reflected_modes.insert(r.value).second)return bad("Reflection","mode declaration disagreement");
            std::map<std::string,View> detail;std::vector<View> args;if(!map(r.details,&detail,{"operands"}) || !list(detail["operands"],&args) || args.size()!=found->second.size())return bad("Reflection","mode operands");
            for(size_t i=0;i<args.size();++i){uint64_t value;if(!integer(args[i],&value) || value!=found->second[i])return bad("Reflection","mode operand mismatch");}}
    }
    if(reflected_caps!=facts.capabilities || reflected_modes.size()!=facts.modes.size())return bad("Reflection","missing capability/mode record");
    if(s->key.stage==ShaderStage::Compute){auto mode=facts.modes.find(17);if(mode==facts.modes.end() || mode->second.size()!=3 || !std::equal(mode->second.begin(),mode->second.end(),s->profile.local_size.begin()))return bad("Reflection","compute local size");}
    else if(s->key.stage==ShaderStage::Fragment && !facts.modes.count(7))return bad("Reflection","fragment upper-left origin");
    // Reject unsupported widths/types even when they are unrelated local types.
    for(const auto& pair:facts.types){const auto& t=pair.second;const auto& a=t.args;bool valid=false;
        switch(t.op){case 19:case 20:case 26:valid=a.empty();break;case 21:valid=a.size()==2 && a[0]==32 && a[1]<=1;break;
        case 22:valid=a.size()==1 && a[0]==32;break;case 23:case 24:valid=a.size()==2 && id_ok(a[0]) && a[1]>=2 && a[1]<=4;break;
        case 25:valid=a.size()==7 && id_ok(a[0]) && a[1]<=5 && a[2]<=2 && a[3]<=1 && a[4]<=1 && (a[5]==1 || a[5]==2) && a[6]<=41;break;
        case 27:case 29:valid=a.size()==1 && id_ok(a[0]);break;case 28:valid=a.size()==2 && id_ok(a[0]) && facts.constants.count(a[1]) && facts.constants[a[1]]>0;break;
        case 30:valid=a.size()<=16384;break;case 32:valid=a.size()==2 && id_ok(a[1]) && a[0]<=7;break;case 33:valid=!a.empty();break;default:break;}
        if(!valid)return bad("Spirv","unsupported/malformed type "+std::to_string(pair.first));
    }
    for(const auto& pair:facts.types){const auto& t=pair.second;const auto& a=t.args;
        auto child=[&](uint32_t id)->const SpvType*{auto found=facts.types.find(id);return found==facts.types.end()?nullptr:&found->second;};
        if(t.op==23){const auto* element=child(a[0]);if(!element || (element->op!=20 && element->op!=21 && element->op!=22))return bad("Spirv","vector scalar type");}
        if(t.op==24){const auto* vector=child(a[0]);if(!vector || vector->op!=23 || !child(vector->args[0]) || child(vector->args[0])->op!=22)return bad("Spirv","matrix vector type");}
        if(t.op==25){const auto* element=child(a[0]);if(!element || (element->op!=21 && element->op!=22))return bad("Spirv","image sampled scalar type");}
        if(t.op==27){const auto* element=child(a[0]);if(!element || element->op!=25)return bad("Spirv","sampled image element");}
        if(t.op==28 || t.op==29){const auto* element=child(a[0]);if(!element || element->op==19 || element->op==33 || element->op==32 || element->op==29)return bad("Spirv","array element type");
            if(t.op==28){auto constant=facts.constant_types.find(a[1]);if(constant==facts.constant_types.end() || !child(constant->second) || child(constant->second)->op!=21 ||
                (child(constant->second)->args[1] && (facts.constants[a[1]]&0x80000000u)))return bad("Spirv","array length integer type/sign");}}
        if(t.op==30 || t.op==33){for(uint32_t id:a)if(!child(id))return bad("Spirv","struct/function missing member type");}
        if(t.op==32){const auto* element=child(a[1]);if(!element || element->op==19 || element->op==33 || element->op==32)return bad("Spirv","pointer pointee type");}
    }
    // Known pointer traces provide access/unused checks; unsupported aliases of
    // resource pointers fail instead of granting an unused-support exemption.
    bool in_function=false;
    for(const auto& ins:instructions){size_t at=ins.at;uint32_t op=ins.op;
        if(op==54)in_function=true;
        if(op==65 || op==66 || op==83){uint32_t root=0;auto found=facts.pointer_roots.find(w[at+3]);if(found!=facts.pointer_roots.end())root=found->second;
            if(root)facts.pointer_roots[w[at+2]]=root;}
        if(op==61){auto type=facts.types.find(w[at+1]);
            if(type!=facts.types.end() && (type->second.op==25 || type->second.op==26 || type->second.op==27)){
                auto source=facts.pointer_roots.find(w[at+3]);if(source!=facts.pointer_roots.end())facts.pointer_roots[w[at+2]]=source->second;}}
        if(op==61 || op==62 || op==99){uint32_t pointer=op==61?w[at+3]:w[at+1];auto found=facts.pointer_roots.find(pointer);
            if(found!=facts.pointer_roots.end()){facts.accessed.insert(found->second);if(op!=61)facts.stored.insert(found->second);}}
        if(in_function){for(size_t i=at+1;i<at+ins.wc;++i){auto found=facts.pointer_roots.find(w[i]);if(found==facts.pointer_roots.end())continue;
            auto variable=facts.vars.find(found->second);if(variable==facts.vars.end() || (variable->second.storage!=0 && variable->second.storage!=2))continue;
            bool known=((op==65 || op==66 || op==83) && (i==at+2 || i==at+3)) || (op==61 && i==at+3) || (op==62 && i==at+1);
            if(!known)facts.unknown_pointer_roots.insert(found->second);}}
        if(op==56)in_function=false;
    }
    std::set<uint32_t> needed;std::map<uint32_t,uint8_t> visits;
    std::function<bool(uint32_t,unsigned)> visit=[&](uint32_t id,unsigned depth){
        if(depth>64)return bad("Budget","SPIR-V type dependency depth");auto found=facts.types.find(id);if(found==facts.types.end())return bad("Spirv","missing referenced type");
        uint8_t& state=visits[id];if(state==1)return bad("Spirv","recursive type graph");if(state==2)return true;state=1;needed.insert(id);
        const auto& t=found->second;const auto& a=t.args;
        if(t.op==23 || t.op==24 || t.op==25 || t.op==27 || t.op==28 || t.op==29){if(!visit(a[0],depth+1))return false;}
        else if(t.op==32){if(!visit(a[1],depth+1))return false;}
        else if(t.op==30){for(uint32_t child:a)if(!visit(child,depth+1))return false;}
        state=2;return true;};
    std::vector<ShaderDescriptor> reflected;
    struct Layout {uint64_t size=0;uint32_t alignment=1;bool runtime=false;};
    std::map<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t>,Layout> layout_cache;
    std::function<bool(uint32_t,uint32_t,const Decorations*,Layout*,unsigned)> layout;
    layout=[&](uint32_t id,uint32_t minimum,const Decorations* member,Layout* out,unsigned depth)->bool{
        if(depth>64)return bad("Budget","layout depth");
        const auto cache_key=std::make_tuple(id,minimum,member?decoration(*member,7,0):0u,member?uint32_t(has_dec(*member,4)):0u);
        auto cached=layout_cache.find(cache_key);if(cached!=layout_cache.end()){*out=cached->second;return true;}
        const auto it=facts.types.find(id);if(it==facts.types.end())return bad("Spirv","layout missing type");const auto& t=it->second;const auto& a=t.args;Layout result;
        if(t.op==20 || t.op==21 || t.op==22){result={t.op==20?4u:uint64_t(a[0]/8),4,false};}
        else if(t.op==23){Layout child;if(!layout(a[0],0,nullptr,&child,depth+1))return false;result={child.size*a[1],child.alignment*(a[1]==3?4:a[1]),false};}
        else if(t.op==24){if(!member || !has_dec(*member,7) || (has_dec(*member,4)==has_dec(*member,5)))return bad("Spirv","matrix layout decorations");
            Layout vector;if(!layout(a[0],0,nullptr,&vector,depth+1))return false;uint32_t stride=decoration(*member,7),count=a[1];
            if(has_dec(*member,4)){const auto& vector_type=facts.types.at(a[0]);count=vector_type.args[1];vector.size=uint64_t(a[1])*4;}
            if(stride<vector.size)return bad("Spirv","matrix stride overlap");result={uint64_t(stride)*(count-1)+vector.size,vector.alignment,false};}
        else if(t.op==28 || t.op==29){Layout child;if(!layout(a[0],0,member,&child,depth+1))return false;uint32_t stride=decoration(facts.dec[id],6,0);uint64_t count=t.op==28?facts.constants[a[1]]:minimum;
            if(!stride || child.runtime || stride<child.size || (count && count-1>(UINT64_MAX-child.size)/stride))return bad("Spirv","array stride/extent");
            result={count?uint64_t(stride)*(count-1)+child.size:0,child.alignment,t.op==29};}
        else if(t.op==30){uint64_t end=0;uint32_t alignment=1;bool runtime=false;
            for(size_t i=0;i<a.size();++i){const auto& d=facts.member_dec[{id,static_cast<uint32_t>(i)}];uint32_t offset=decoration(d,35);Layout child;
                if(offset==kShaderNone || !layout(a[i],minimum,&d,&child,depth+1) || offset<end || child.size>UINT64_MAX-offset || (child.runtime && i+1!=a.size()))return bad("Spirv","block member offset/runtime tail");
                end=uint64_t(offset)+child.size;alignment=std::max(alignment,child.alignment);runtime=child.runtime;}
            result={end,alignment,runtime};
        }else return bad("Spirv","nondata type in buffer/workgroup layout");layout_cache.emplace(cache_key,result);*out=result;return true;
    };
    uint64_t shared=0;
    for(const auto& item:facts.vars){const uint32_t id=item.first;const auto& v=item.second;auto pointer=facts.types.find(v.type);
        if(pointer==facts.types.end() || pointer->second.op!=32 || pointer->second.args[0]!=v.storage)return bad("Spirv","variable pointer/storage mismatch");
        uint32_t base=pointer->second.args[1];
        if(v.storage==4){Layout l;if(!layout(base,0,nullptr,&l,0) || l.runtime || l.size>UINT32_MAX-shared)return bad("Spirv","shared-memory extent");shared+=l.size;}
        const auto& decorations=facts.dec[id];bool descriptor=v.storage==0 || v.storage==2;
        if(!descriptor)continue;
        if(!has_dec(decorations,33) || decoration(decorations,34)!=0)return bad("Spirv","descriptor set/binding absent");
        ShaderDescriptor d;d.variable_id=id;d.pointer_type_id=v.type;d.set=0;d.binding=decoration(decorations,33);d.stage_mask=s->profile.stage_mask;d.count=1;d.access=3;d.address_alignment=1;d.name=facts.names[id];
        if(!visit(v.type,0))return false;
        auto resource=facts.types.find(base);while(resource!=facts.types.end() && resource->second.op==28){
            uint32_t n=facts.constants[resource->second.args[1]];if(n>4096/d.count)return bad("Budget","descriptor array count");d.count*=n;++d.array_rank;base=resource->second.args[0];resource=facts.types.find(base);}
        if(resource==facts.types.end() || resource->second.op==29)return bad("Spirv","runtime/missing descriptor resource");d.resource_type_id=base;
        const auto& t=resource->second;
        if(v.storage==2 && t.op==30){const auto& td=facts.dec[base];if(has_dec(td,2)==has_dec(td,3))return bad("Spirv","block/BufferBlock descriptor");d.type=has_dec(td,2)?ShaderDescriptorType::UniformBuffer:ShaderDescriptorType::StorageBuffer;
            auto original=std::find_if(s->descriptors.begin(),s->descriptors.end(),[&](const ShaderDescriptor& x){return x.variable_id==id;});if(original==s->descriptors.end())return bad("Reflection","unreflected descriptor");
            d.minimum_runtime_elements=original->minimum_runtime_elements;Layout l;if(!layout(base,d.minimum_runtime_elements,nullptr,&l,0))return false;d.minimum_buffer_bytes=l.size;d.address_alignment=l.alignment;
            bool readable=!has_dec(decorations,25),writable=!has_dec(decorations,24);
            if(!t.args.empty()){bool all_no_read=true,all_no_write=true;for(size_t index=0;index<t.args.size();++index){const auto& md=facts.member_dec[{base,static_cast<uint32_t>(index)}];all_no_read&=has_dec(md,25);all_no_write&=has_dec(md,24);}readable&=!all_no_read;writable&=!all_no_write;}
            if(d.type==ShaderDescriptorType::UniformBuffer)writable=false;d.access=(readable?1u:0u)|(writable?2u:0u);
            if(facts.stored.count(id) && !writable)return bad("Spirv","store to nonwritable descriptor");
        }else if(v.storage==0){d.access=1;
            if(t.op==26)d.type=ShaderDescriptorType::Sampler;
            else {const SpvType* image=&t;
                if(t.op==27){auto found=facts.types.find(t.args[0]);if(found==facts.types.end() || found->second.op!=25)return bad("Spirv","sampled-image type");image=&found->second;d.type=ShaderDescriptorType::CombinedImageSampler;}
                else if(t.op==25)d.type=t.args[5]==1?ShaderDescriptorType::SampledImage:ShaderDescriptorType::StorageImage;
                else return bad("Spirv","unsupported UniformConstant resource");
                if(image->args[1]==5){if(t.op==27)return bad("Spirv","combined texel-buffer unsupported");d.type=image->args[5]==1?ShaderDescriptorType::UniformTexelBuffer:ShaderDescriptorType::StorageTexelBuffer;}
                if(d.type==ShaderDescriptorType::StorageImage || d.type==ShaderDescriptorType::StorageTexelBuffer)d.access=(has_dec(decorations,25)?0u:1u)|(has_dec(decorations,24)?0u:2u);
            }
        }else return bad("Spirv","unsupported descriptor storage/type");
        reflected.push_back(std::move(d));
    }
    if(shared!=s->profile.shared_bytes)return bad("Reflection","shared-memory mismatch");
    std::sort(reflected.begin(),reflected.end(),[](const ShaderDescriptor& a,const ShaderDescriptor& b){return std::tie(a.set,a.binding,a.variable_id)<std::tie(b.set,b.binding,b.variable_id);});
    if(reflected.size()!=s->descriptors.size())return bad("Reflection","descriptor count disagreement");
    for(size_t i=0;i<reflected.size();++i){const auto& a=reflected[i];const auto& b=s->descriptors[i];
        if(a.variable_id!=b.variable_id || a.pointer_type_id!=b.pointer_type_id || a.resource_type_id!=b.resource_type_id || a.type!=b.type || a.set!=b.set || a.binding!=b.binding ||
           a.count!=b.count || a.access!=b.access || a.minimum_buffer_bytes!=b.minimum_buffer_bytes || a.address_alignment!=b.address_alignment || a.array_rank!=b.array_rank || a.name!=b.name)return bad("Reflection","independent descriptor/type/layout disagreement");
    }
    // Independently expand the selected entry's complete IO, including members.
    std::vector<ShaderIo> io;
    for(uint32_t id:facts.interface_ids){auto found=facts.vars.find(id);if(found==facts.vars.end() || (found->second.storage!=1 && found->second.storage!=3))return bad("Spirv","entry interface variable");
        uint32_t value=facts.types.at(found->second.type).args[1];const auto& type=facts.types.at(value);const auto& d=facts.dec[id];
        auto add_io=[&](uint32_t member,uint32_t value_type,const Decorations& decorations,const std::string& name){ShaderIo item;
            item.variable_id=id;item.member=member;item.type_id=value_type;item.direction=found->second.storage==1?1u:2u;
            item.location=decoration(decorations,30);item.component=decoration(decorations,31);item.builtin=decoration(decorations,11);
            item.index=decoration(decorations,32);item.interpolation=interpolation(decorations);item.stage_mask=s->profile.stage_mask;item.name=name;io.push_back(item);};
        if(type.op==30){if(!visit(value,0))return false;for(size_t index=0;index<type.args.size();++index){uint32_t m=static_cast<uint32_t>(index);add_io(m,type.args[index],facts.member_dec[{value,m}],facts.member_names[{value,m}]);}}
        else{add_io(kShaderNone,value,d,facts.names[id]);if(!visit(value,0))return false;}
    }
    std::sort(io.begin(),io.end(),[](const ShaderIo& a,const ShaderIo& b){return std::tie(a.direction,a.variable_id,a.member)<std::tie(b.direction,b.variable_id,b.member);});
    if(io.size()!=s->io.size())return bad("Reflection","IO count disagreement");
    for(size_t i=0;i<io.size();++i){const auto& a=io[i];const auto& b=s->io[i];if(a.variable_id!=b.variable_id || a.type_id!=b.type_id || a.member!=b.member || a.direction!=b.direction ||
        a.location!=b.location || a.component!=b.component || a.builtin!=b.builtin || a.index!=b.index || a.interpolation!=b.interpolation || a.name!=b.name)return bad("Reflection","independent IO disagreement");}
    std::vector<ShaderType> types;std::vector<ShaderMember> members;
    for(uint32_t id:needed){const auto& t=facts.types.at(id);const auto& a=t.args;const auto& d=facts.dec[id];ShaderType result;result.id=id;
        if(t.op==20){result.kind=1;result.width=1;}else if(t.op==21){result.kind=a[1]?2:3;result.width=a[0];}
        else if(t.op==22){result.kind=4;result.width=a[0];}else if(t.op==23 || t.op==24){result.kind=t.op==23?5:6;result.element=a[0];result.count=a[1];}
        else if(t.op==28 || t.op==29){result.kind=t.op==28?7:8;result.element=a[0];result.count=t.op==28?facts.constants[a[1]]:0;result.stride=decoration(d,6,0);if(result.stride)result.flags|=1;}
        else if(t.op==30){result.kind=9;result.member_first=static_cast<uint32_t>(members.size());result.member_count=static_cast<uint32_t>(a.size());if(has_dec(d,2))result.flags|=2;if(has_dec(d,3))result.flags|=4;
            for(size_t index=0;index<a.size();++index){const auto& md=facts.member_dec[{id,static_cast<uint32_t>(index)}];ShaderMember m;m.owner=id;m.index=static_cast<uint32_t>(index);m.type=a[index];m.offset=decoration(md,35);m.matrix_stride=decoration(md,7,0);m.builtin=decoration(md,11);
                const uint32_t flags[]={35,7,4,5,24,25,0};for(unsigned bit=0;bit<7;++bit)if(has_dec(md,flags[bit]))m.flags|=1u<<bit;members.push_back(m);}}
        else if(t.op==32){result.kind=10;result.storage=a[0];result.element=a[1];}else if(t.op==25){result.kind=11;result.element=a[0];for(size_t j=0;j<6;++j)result.image[j]=a[j+1];}
        else if(t.op==26)result.kind=12;else if(t.op==27){result.kind=13;result.element=a[0];}else return bad("Spirv","unreflectable resource/IO type");types.push_back(result);
    }
    if(types.size()!=s->types.size() || members.size()!=s->members.size())return bad("Reflection","type/member dependency closure size");
    for(size_t i=0;i<types.size();++i){const auto& a=types[i];const auto& b=s->types[i];if(std::tie(a.id,a.kind,a.width,a.element,a.count,a.stride,a.storage,a.flags,a.member_first,a.member_count,a.image)!=
        std::tie(b.id,b.kind,b.width,b.element,b.count,b.stride,b.storage,b.flags,b.member_first,b.member_count,b.image))return bad("Reflection","independent type closure disagreement");}
    for(size_t i=0;i<members.size();++i){const auto& a=members[i];const auto& b=s->members[i];if(std::tie(a.owner,a.index,a.type,a.offset,a.matrix_stride,a.flags,a.builtin)!=
        std::tie(b.owner,b.index,b.type,b.offset,b.matrix_stride,b.flags,b.builtin))return bad("Reflection","independent member layout disagreement");}
    // Declared optional facts are still required even when a declaration is unused.
    uint64_t required_features=0;for(uint32_t cap:facts.capabilities){uint32_t feature=0;switch(cap){case 27:feature=20;break;case 32:feature=16;break;case 33:feature=17;break;case 34:feature=18;break;case 35:feature=15;break;case 42:feature=19;break;case 49:feature=8;break;case 55:feature=9;break;case 56:feature=10;break;default:break;}if(feature)required_features|=uint64_t(1)<<(feature-1);}
    if(s->key.stage!=ShaderStage::Compute)for(const auto& d:reflected)if(d.access&2)required_features|=uint64_t(1)<<(s->key.stage==ShaderStage::Fragment?5:6);
    if((s->profile.required_features&required_features)!=required_features)return bad("Reflection","missing induced optional feature requirement");
    // Unused support is the sole allowed synthetic static initializer. Any trace
    // uncertainty or actual read/store refuses the unused claim.
    for(const auto& semantic:s->semantics)if(semantic.kind>=1 && semantic.kind<=3){const auto& d=s->descriptors[semantic.descriptor_index];
        if(facts.unknown_pointer_roots.count(d.variable_id))return bad("Semantic","unknown support pointer trace");
        if(semantic.kind==3 && !semantic.source_size && !semantic.driver_count && facts.accessed.count(d.variable_id))return bad("Semantic","accessed empty driver requires source-proven finite reads");}
    // The translated RenderScale helper passes scalar Function pointers. Prove
    // constants from every store and every call; global resource pointer calls,
    // pointer escapes, conflicting values and unknown indices stay unsupported.
    std::map<uint32_t,std::vector<uint32_t>> parameters,stores,arguments;
    std::map<uint32_t,uint32_t> local_pointers;
    uint32_t current_function=0,current_block=0;
    std::map<uint32_t,uint32_t> entry_blocks;
    std::map<uint32_t,size_t> dominating_initialization;
    for(const auto& variable:facts.vars)if(variable.second.storage==7)local_pointers[variable.first]=variable.second.type;
    for(const auto& ins:instructions){size_t at=ins.at;if(ins.op==54){current_function=w[at+2];current_block=0;}
        if(ins.op==248){current_block=w[at+1];if(!entry_blocks[current_function])entry_blocks[current_function]=current_block;}
        if(ins.op==55){parameters[current_function].push_back(w[at+2]);local_pointers[w[at+2]]=w[at+1];}
        if(ins.op==62){stores[w[at+1]].push_back(w[at+2]);
            if(current_block && current_block==entry_blocks[current_function])dominating_initialization.emplace(w[at+1],at);}
        if(ins.op==59 && ins.wc==5 && w[at+3]==7){stores[w[at+2]].push_back(w[at+4]);dominating_initialization.emplace(w[at+2],at);}}
    std::set<uint32_t> unproved_locals;
    for(const auto& ins:instructions){size_t at=ins.at;
        if(ins.op==57){const auto found=parameters.find(w[at+3]);if(found==parameters.end() || found->second.size()!=ins.wc-4)return bad("Spirv","unclassified function call signature");
            for(size_t index=0;index<found->second.size();++index){uint32_t parameter=found->second[index],argument=w[at+4+index];
                auto p=local_pointers.find(parameter),q=local_pointers.find(argument);
                if(p==local_pointers.end() || q==local_pointers.end()){unproved_locals.insert(parameter);continue;}
                const auto& pt=facts.types.at(p->second);const auto& qt=facts.types.at(q->second);
                if(pt.op!=32 || qt.op!=32 || pt.args[0]!=7 || qt.args[0]!=7 || pt.args[1]!=qt.args[1]){unproved_locals.insert(parameter);continue;}
                arguments[parameter].push_back(argument);}
        }
        for(size_t pos=at+1;pos<at+ins.wc;++pos){auto local=local_pointers.find(w[pos]);if(local==local_pointers.end())continue;
            bool known=(ins.op==59 && pos==at+2) || (ins.op==55 && pos==at+2) || (ins.op==61 && pos==at+3) || (ins.op==62 && pos==at+1) || (ins.op==57 && pos>=at+4);
            if(!known)unproved_locals.insert(local->first);}
    }
    for(const auto& function:parameters)for(uint32_t parameter:function.second)if(stores.count(parameter))unproved_locals.insert(parameter);
    for(const auto& ins:instructions){size_t at=ins.at;
        for(size_t pos=at+1;pos<at+ins.wc;++pos){uint32_t id=w[pos];auto variable=facts.vars.find(id);
            if(variable==facts.vars.end() || variable->second.storage!=7 || !((ins.op==61 && pos==at+3) || (ins.op==57 && pos>=at+4)))continue;
            auto initialization=dominating_initialization.find(id);
            if(initialization==dominating_initialization.end() || initialization->second>=at)unproved_locals.insert(id);
        }
    }
    for(unsigned iteration=0;iteration<64;++iteration){bool changed=false;for(const auto& call:arguments)if(unproved_locals.count(call.first))for(uint32_t argument:call.second)changed|=unproved_locals.insert(argument).second;
        if(!changed)break;if(iteration==63)return bad("Budget","function-pointer unknown propagation did not converge");}
    std::map<uint32_t,uint32_t> proven_constants=facts.constants,memory_constants;
    for(unsigned iteration=0;iteration<64;++iteration){bool changed=false;
        for(const auto& pointer:local_pointers){if(unproved_locals.count(pointer.first) || memory_constants.count(pointer.first))continue;
            auto param=arguments.find(pointer.first);const auto& values=param!=arguments.end()?param->second:stores[pointer.first];if(values.empty())continue;
            bool complete=true,first=true;uint32_t common=0;
            for(uint32_t value:values){const auto& known=param!=arguments.end()?memory_constants:proven_constants;auto found=known.find(value);
                if(found==known.end() || (!first && found->second!=common)){complete=false;break;}first=false;common=found->second;}
            if(complete){memory_constants.emplace(pointer.first,common);changed=true;}}
        for(const auto& ins:instructions){size_t at=ins.at;uint32_t value=0;bool known=false;
            if(ins.op==61){auto found=memory_constants.find(w[at+3]);if(found!=memory_constants.end()){value=found->second;known=true;}}
            else if(ins.op==128 || ins.op==130 || ins.op==132){auto left=proven_constants.find(w[at+3]),right=proven_constants.find(w[at+4]);
                if(left!=proven_constants.end() && right!=proven_constants.end()){value=ins.op==128?left->second+right->second:ins.op==130?left->second-right->second:left->second*right->second;known=true;}}
            else if(ins.op==83 || ins.op==124 || ins.op==113 || ins.op==114){auto found=proven_constants.find(w[at+3]);if(found!=proven_constants.end()){value=found->second;known=true;}}
            if(known && proven_constants.emplace(w[at+2],value).second)changed=true;
        }if(!changed)break;
    }
    // C1/driver reads need a finite source byte proof. Unknown pointer arithmetic
    // or an escape is refused; ordinary runtime SSBO indexing is a C2 binding
    // obligation and is deliberately not interpreted as a driver-bank read.
    struct PointerTrace {uint32_t root=0,type=0;uint64_t offset=0;bool finite=true;};
    std::map<uint32_t,PointerTrace> traces;
    std::map<uint32_t,std::set<uint64_t>> support_reads;
    for(const auto& variable:facts.vars){const auto& t=facts.types.at(variable.second.type);traces[variable.first]={variable.first,t.args[1],0,true};}
    for(const auto& ins:instructions){const size_t at=ins.at;const uint32_t op=ins.op;
        if(op==65 || op==66 || op==83){auto base=traces.find(w[at+3]);if(base!=traces.end()){PointerTrace trace=base->second;
            if(op!=83)for(size_t i=at+4;i<at+ins.wc;++i){auto t=facts.types.find(trace.type);auto index=proven_constants.find(w[i]);
                if(t==facts.types.end() || index==proven_constants.end()){trace.finite=false;break;}uint64_t add=0;uint32_t value=index->second;
                if(t->second.op==30){if(value>=t->second.args.size()){trace.finite=false;break;}add=decoration(facts.member_dec[{trace.type,value}],35);trace.type=t->second.args[value];if(add==kShaderNone){trace.finite=false;break;}}
                else if(t->second.op==28 || t->second.op==29){uint32_t stride=decoration(facts.dec[trace.type],6,0);if(!stride){trace.finite=false;break;}add=uint64_t(value)*stride;trace.type=t->second.args[0];}
                else if(t->second.op==23){if(value>=t->second.args[1]){trace.finite=false;break;}add=uint64_t(value)*4;trace.type=t->second.args[0];}
                else {trace.finite=false;break;}
                if(add>UINT64_MAX-trace.offset){trace.finite=false;break;}trace.offset+=add;}
            traces[w[at+2]]=trace;}}
        if(op==61 || op==62){uint32_t pointer=op==61?w[at+3]:w[at+1];auto found=traces.find(pointer);if(found==traces.end())continue;
            const auto& trace=found->second;
            for(const auto& semantic:s->semantics){const auto& descriptor=s->descriptors[semantic.descriptor_index];
                if(descriptor.variable_id!=trace.root || (semantic.kind!=1 && semantic.kind!=2 && semantic.kind!=3))continue;
                Layout read;if(op!=61 || !trace.finite || facts.unknown_pointer_roots.count(trace.root) || !layout(trace.type,0,nullptr,&read,0) || read.runtime ||
                    trace.offset<semantic.source_offset || !range(trace.offset-semantic.source_offset,read.size,semantic.source_size))return bad("Semantic","unproved c1/driver read bounds");
                if(semantic.kind==1){auto type=facts.types.find(trace.type);
                    if(type==facts.types.end() || type->second.op!=22 || read.size!=4 || trace.offset<192 || (trace.offset-192)%16 || (trace.offset-192)/16>=73)
                        return bad("Semantic","support field outside proved RenderScale scalar reads");
                    support_reads[trace.root].insert(trace.offset);}
                if(semantic.kind==3){bool covered=false;
                    for(size_t i=semantic.driver_first;i<semantic.driver_first+semantic.driver_count;++i){const uint8_t* r=row(6,i);uint64_t start=u32(r+8),length=u32(r+12);
                        if(trace.offset>=start && range(trace.offset-start,read.size,length))covered=true;}
                    if(!covered)return bad("Semantic","actual driver load missing finite evidence range");}
            }
        }
    }
    for(size_t i=0;i<sections[11].count;++i){const uint8_t* record=row(11,i);if(u32(record)!=3 || u32(record+4)!=37)continue;
        View payload;if(!blob(record+56,&payload,true))return false;std::map<std::string,View> options;if(!map(payload,&options))return false;
        std::vector<View> policies;if(!list(options["support_policy"],&policies))return false;std::set<uint32_t> supplied;uint64_t previous=0;bool first=true;
        for(View policy:policies){std::map<std::string,View> fields;uint64_t id;bool unused;View initialized;
            if(!map(policy,&fields,{"bytes","unused","variable_id"}) || !integer(fields["variable_id"],&id) || id>UINT32_MAX || !boolean(fields["unused"],&unused) || !bytes(fields["bytes"],&initialized) ||
               (!first && id<=previous) || !supplied.insert(static_cast<uint32_t>(id)).second)return bad("Semantic","support policy fields/order");
            first=false;previous=id;
            auto descriptor=std::find_if(s->descriptors.begin(),s->descriptors.end(),[&](const ShaderDescriptor& d){return d.variable_id==id;});
            if(descriptor==s->descriptors.end() || initialized.n!=descriptor->minimum_buffer_bytes || (unused && (facts.accessed.count(static_cast<uint32_t>(id)) || facts.unknown_pointer_roots.count(static_cast<uint32_t>(id)))))return bad("Semantic","support initializer extent/unused claim");
            if(!unused && facts.accessed.count(static_cast<uint32_t>(id))){
                if(initialized.n!=1380 || support_reads[static_cast<uint32_t>(id)].empty())return bad("Semantic","accessed support missing finite RenderScale proof");
                for(size_t byte=0;byte<initialized.n;++byte){uint8_t expected=0;
                    if(byte>=192 && byte<192+73*16 && (byte-192)%16<4){unsigned lane=static_cast<unsigned>((byte-192)%16);expected=uint8_t(0x3f800000u>>(lane*8));}
                    if(initialized.p[byte]!=expected)return bad("Semantic","RenderScale support initializer value");}
            }
            bool support=false;for(const auto& semantic:s->semantics)if(semantic.descriptor_index==static_cast<size_t>(descriptor-s->descriptors.begin()) && semantic.kind==1){support=true;
                for(const auto& fill:semantic.fill)if(!range(fill.offset,fill.bytes.size(),initialized.n) || memcmp(initialized.p+fill.offset,fill.bytes.data(),fill.bytes.size()))return bad("Semantic","support policy/static fill disagreement");}
            if(!support)return bad("Semantic","support policy names another semantic");
        }
        for(const auto& semantic:s->semantics)if(semantic.kind==1 && !supplied.count(s->descriptors[semantic.descriptor_index].variable_id))return bad("Semantic","missing support initializer policy");
    }
    return true;
}

bool ShaderArtifactDecoder::semantics() {
    std::tuple<uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint64_t> previous;
    const bool port=shader_identity_kind(s->key)==ShaderIdentityKind::SemanticPort;
    const bool sampled=s->profile.name==sampled_profile;
    const uint32_t stage=static_cast<uint32_t>(s->key.stage);
    auto evidence=[&](View v,bool require)->bool{std::vector<View> ids;if(!list(v,&ids) || (require && ids.empty()))return bad("Semantic","missing evidence");std::vector<uint8_t> previous_id;
        for(View id:ids){std::string name;std::vector<uint8_t> encoded(id.p,id.p+id.n);if(!text(id,&name) || !closure_ids.count(name) || (!previous_id.empty() && encoded<=previous_id))return bad("Semantic","unknown/unsorted evidence");previous_id=std::move(encoded);}return true;};
    for(size_t i=0;i<sections[4].count;++i){const uint8_t* p=row(4,i);ShaderSemantic r;
        r.descriptor_index=u32(p);r.kind=u32(p+4);r.component=u32(p+8);r.cb_slot=u32(p+12);r.source_offset=u64(p+16);r.source_size=u64(p+24);
        r.nvn_slot=u32(p+32);r.encoding=u32(p+36);r.array_first=u32(p+40);r.count=u32(p+44);r.stride=u32(p+48);r.driver_first=u32(p+72);r.driver_count=u32(p+76);
        if(r.descriptor_index>=s->descriptors.size() || !r.kind || r.kind>9 || r.component>2 || r.encoding>3 || !r.count ||
           u32(p+52) || !zero(p+80,16) || !str(p+64,&r.rule))return bad("Semantic","record fields");
        const auto& d=s->descriptors[r.descriptor_index];
        const bool historical=r.rule==sampled_rule;
        if(historical){if(!sampled || port || stage!=1 || (r.kind!=7 && r.kind!=8) || r.component!=r.kind-6 || r.encoding!=3 ||
            r.cb_slot!=kShaderNone || r.source_offset || r.source_size || r.nvn_slot || r.array_first || r.count!=1 || r.stride || r.driver_count!=1 ||
            d.type!=ShaderDescriptorType::CombinedImageSampler || d.count!=1 || d.access!=1 || d.binding!=4097)return bad("Semantic","authored static separate DirectSlot fields");}
        else if(sampled && r.kind!=1)return bad("Semantic","sampled profile resource rule");
        if(i<d.semantic_first || i-d.semantic_first>=d.semantic_count || !range(r.array_first,r.count,d.count) ||
           !range(r.driver_first,r.driver_count,sections[6].count) || (r.count==1 && r.stride))return bad("Semantic","descriptor/driver/array span");
        if((r.kind<=4 && d.type!=ShaderDescriptorType::UniformBuffer) || ((r.kind==5 || r.kind==6) && d.type!=ShaderDescriptorType::StorageBuffer) ||
           (r.kind==7 && d.type!=ShaderDescriptorType::SampledImage && d.type!=ShaderDescriptorType::CombinedImageSampler && d.type!=ShaderDescriptorType::UniformTexelBuffer) ||
           (r.kind==8 && d.type!=ShaderDescriptorType::Sampler && d.type!=ShaderDescriptorType::CombinedImageSampler) ||
           (r.kind==9 && d.type!=ShaderDescriptorType::StorageImage && d.type!=ShaderDescriptorType::StorageTexelBuffer))return bad("Semantic","source kind versus physical descriptor type");
        auto order=std::make_tuple(r.descriptor_index,r.component,r.array_first,r.kind,r.nvn_slot,r.source_offset);
        if(i && order<=previous)return bad("Canonical","semantic order/duplicate");previous=order;
        View facts;std::map<std::string,View> f;
        if(!blob(p+56,&facts,true) || !map(facts,&f,{"evidence","fill","resource","table_capacity"}) ||
           !evidence(f["evidence"],true) || !integer(f["table_capacity"],&r.table_capacity))return false;
        std::vector<View> fills;if(!list(f["fill"],&fills))return false;uint64_t fill_end=0;
        for(View fill:fills){std::map<std::string,View> value;ShaderFill item;
            if(!map(fill,&value) || !value.count("offset") || !integer(value["offset"],&item.offset))return bad("Semantic","fill shape/offset");
            if(value.count("bytes")){View bytes_fill;if(value.size()!=2 || !bytes(value["bytes"],&bytes_fill))return bad("Semantic","static fill shape");item.bytes.assign(bytes_fill.p,bytes_fill.p+bytes_fill.n);item.size=bytes_fill.n;}
            else {if(value.size()!=3 || !value.count("field") || !value.count("size") || !text(value["field"],&item.field) || !integer(value["size"],&item.size) || item.size!=8)return bad("Semantic","runtime fill shape");
                const char* expected=r.kind==5?"nvn-ssbo-address64":r.kind==6?"nvn-ubo-address64":r.kind==7?"nvn-texture-handle64":r.kind==8?"nvn-sampler-handle64":r.kind==9?"nvn-image-handle64":"";
                if(item.field!=expected)return bad("Semantic","unknown/contextually invalid runtime fill");}
            if(!item.size || item.offset<fill_end || !range(item.offset,item.size,65536))return bad("Semantic","fill range/overlap");fill_end=item.offset+item.size;r.fill.push_back(std::move(item));
        }
        std::map<std::string,View> resource;if(!map(f["resource"],&resource))return false;
        r.resource_facts.assign(f["resource"].p,f["resource"].p+f["resource"].n);
        if(r.kind<7 && !resource.empty())return bad("Semantic","buffer resource facts must be empty");
        if(r.kind>=7){
            if(!map(f["resource"],&resource,{"arrayed","dim","format","multisampled","sampled_type","shadow","source_format"}))return false;
            bool arrayed,multisampled,shadow;uint64_t dim,format;std::string sampled,source;
            if(!boolean(resource["arrayed"],&arrayed) || !boolean(resource["multisampled"],&multisampled) || !boolean(resource["shadow"],&shadow) ||
               !integer(resource["dim"],&dim) || dim>5 || !integer(resource["format"],&format) || format>41 ||
               !text(resource["sampled_type"],&sampled) || (sampled!="float32" && sampled!="sint32" && sampled!="uint32") ||
               !text(resource["source_format"],&source) ||
               !(historical || (s->profile.name==original_texture_profile && r.kind!=9)?(source=="R8G8B8A8Unorm" && sampled=="float32" && dim==1 && !arrayed && !multisampled && !shadow && format==0):
                 (source=="R32Uint" && sampled=="uint32" && dim==1 && !arrayed && !multisampled && !shadow && (format==33 || (r.kind!=9 && format==0)))))return bad("Semantic","image facts outside proved R32Uint subset");
            auto type=std::find_if(s->types.begin(),s->types.end(),[&](const ShaderType& x){return x.id==d.resource_type_id;});
            if(type==s->types.end())return bad("Semantic","physical resource type missing");
            if(type->kind==13)type=std::find_if(s->types.begin(),s->types.end(),[&](const ShaderType& x){return x.id==type->element;});
            if(type==s->types.end() || (type->kind!=12 && (type->kind!=11 || type->image[0]!=dim || type->image[2]!=uint32_t(arrayed) ||
               type->image[3]!=uint32_t(multisampled) || type->image[5]!=format || (type->image[1]==1)!=shadow)))return bad("Semantic","image facts disagree with final type");
            if(type->kind==11){auto scalar=std::find_if(s->types.begin(),s->types.end(),[&](const ShaderType& x){return x.id==type->element;});
                if(scalar==s->types.end() || sampled!=(scalar->kind==4?"float32":scalar->kind==2?"sint32":"uint32"))return bad("Semantic","sampled scalar disagreement");}
        }
        if(r.encoding==1 || r.encoding==2){
            if(r.source_offset>65536 || !range(r.source_offset,r.source_size,65536) ||
               (r.count>1 && (!r.stride || r.stride>65536)) ||
               r.source_size!=uint64_t(r.count-1)*r.stride+8)return bad("Semantic","pointer/handle finite span");
        }
        if(r.kind==1){if(r.rule!="nvn-support-static-v1" || r.cb_slot!=kShaderNone || r.nvn_slot!=kShaderNone || r.encoding || r.source_offset || r.source_size<d.minimum_buffer_bytes || r.driver_count)return bad("Semantic","support fields");}
        else if(r.kind==2){if(r.rule!="nvn-c1-exact-v1" || r.cb_slot!=1 || r.nvn_slot!=kShaderNone || r.encoding || !range(r.source_offset,r.source_size,s->c1.size()) || r.driver_count)return bad("Semantic","c1 bounds/fields");}
        else if(r.kind==3){if(r.rule!="nvn-driver-static-v1" || (r.cb_slot!=0 && r.cb_slot!=2) || r.nvn_slot!=kShaderNone || r.encoding || !range(r.source_offset,r.source_size,65536) ||
            (!r.driver_count && (r.source_offset || r.source_size || r.array_first || r.count!=1 || r.stride || r.driver_first || !r.fill.empty() || r.table_capacity)))return bad("Semantic","driver fields");}
        else if(r.kind==4){if((r.rule!="nvn-ubo-slot-v1" && !(port && r.rule=="builtin-count-ubo-v1")) || r.cb_slot<3 || r.cb_slot>16 || r.nvn_slot!=r.cb_slot-3 || r.encoding!=3 || r.source_offset ||
            r.source_size<d.minimum_buffer_bytes || r.driver_count || r.count>14-r.nvn_slot || (r.count>1 && r.stride!=1) ||
            (r.rule=="builtin-count-ubo-v1" && (r.cb_slot!=3 || r.source_size!=4 || d.type!=ShaderDescriptorType::UniformBuffer || d.minimum_buffer_bytes!=4)))return bad("Semantic","NVN UBO mapping");}
        else if(r.kind==5){
            if(port){bool source=r.rule=="builtin-source-ssbo-v1",destination=r.rule=="builtin-destination-ssbo-v1";
                if((!source && !destination) || r.encoding!=3 || r.cb_slot!=kShaderNone || r.source_offset || r.source_size!=d.minimum_buffer_bytes || r.nvn_slot!=(source?0u:1u) || r.count!=1 ||
                   r.driver_count || !r.fill.empty() || d.type!=ShaderDescriptorType::StorageBuffer || d.access!=(source?1u:2u))return bad("Semantic","semantic port direct storage slot");
            }else {uint32_t base=stage==0?0x110:stage==1?0x510:stage==5?0x310:0;
                if(r.rule!="nvn-ssbo-pointer-v1" || !base || r.cb_slot || r.encoding!=1 || !r.table_capacity || r.table_capacity>(65536-base)/16 || r.nvn_slot>=r.table_capacity || r.count>r.table_capacity-r.nvn_slot ||
                   r.source_offset!=uint64_t(base)+uint64_t(r.nvn_slot)*16 || (r.count>1 && r.stride!=16))return bad("Semantic","measured SSBO pointer mapping");}
        }else if(r.kind==6){if(r.rule!="nvn-compute-ubo-pointer-v1" || stage!=5 || r.cb_slot || r.encoding!=1 || r.nvn_slot>15 || r.count>16-r.nvn_slot ||
            r.source_offset!=0x210+uint64_t(r.nvn_slot)*16 || r.source_offset+r.source_size>0x310 || (r.count>1 && r.stride!=16))return bad("Semantic","compute UBO pointer mapping");}
        else {const char* rule=r.kind==7?"nvn-texture-handle-v1":r.kind==8?"nvn-sampler-handle-v1":"nvn-image-handle-v1";
            if((r.rule!=rule && !historical) || (r.encoding!=2 && r.encoding!=3))return bad("Semantic","image source rule/encoding");
            if(r.encoding==2){uint64_t base=r.kind==7?0x168:r.kind==8?0x568:0x120,capacity=r.kind==7?128:r.kind==9?9:r.table_capacity;
                if(r.cb_slot!=2 || !capacity || capacity>(65536-base)/8 || r.table_capacity!=capacity || r.nvn_slot>=capacity || r.count>capacity-r.nvn_slot ||
                   r.source_offset!=base+uint64_t(r.nvn_slot)*8 || (r.count>1 && r.stride!=8))return bad("Semantic","image/texture/sampler table bounds");}
            else if(r.cb_slot!=kShaderNone || r.source_offset || r.source_size || !r.table_capacity || r.nvn_slot>=r.table_capacity || r.count>r.table_capacity-r.nvn_slot ||
                (r.count>1 && r.stride!=1))return bad("Semantic","direct image slot fields");
        }
        if(r.encoding==1 || r.encoding==2){if(r.fill.size()!=r.count)return bad("Semantic","pointer/handle fill count");
            for(size_t element=0;element<r.fill.size();++element)if(r.fill[element].offset!=r.source_offset+element*r.stride || r.fill[element].size!=8)return bad("Semantic","pointer/handle fill exact element offset");}
        if(historical && (r.table_capacity!=1 || !r.fill.empty()))return bad("Semantic","sampled singleton resource facts");
        if(r.encoding==3 && !r.fill.empty())return bad("Semantic","DirectSlot fill must be empty");
        if(r.kind==2 && !r.fill.empty())return bad("Semantic","c1 must use exact owned bytes without fill");
        if(r.kind==1 || r.kind==3){uint64_t covered=r.source_offset;
            for(const auto& fill:r.fill){if(!fill.field.empty() || fill.offset!=covered)return bad("Semantic","unfillable support/driver byte");covered+=fill.size;}
            if(covered!=r.source_offset+r.source_size)return bad("Semantic","incomplete static fill");
        }
        s->semantics.push_back(std::move(r));
    }
    for(const auto& d:s->descriptors){
        const bool combined=d.type==ShaderDescriptorType::CombinedImageSampler;
        for(uint32_t component:combined?std::vector<uint32_t>{1,2}:std::vector<uint32_t>{0}){uint32_t end=0;
            for(size_t i=d.semantic_first;i<d.semantic_first+d.semantic_count;++i){const auto& r=s->semantics[i];if(r.component!=component)continue;
                if(r.array_first!=end)return bad("Semantic","descriptor array semantic gap/overlap");end+=r.count;}
            if(end!=d.count)return bad("Semantic","incomplete descriptor component coverage");}
        for(size_t i=d.semantic_first;i<d.semantic_first+d.semantic_count;++i){const auto& r=s->semantics[i];if(combined?(r.component!=1 && r.component!=2):r.component!=0)return bad("Semantic","invalid descriptor component");
            if(combined && ((r.component==1 && r.kind!=7) || (r.component==2 && r.kind!=8)))return bad("Semantic","combined image/sampler conflation");}
    }
    for(size_t i=0;i<sections[5].count;++i){View facts;std::map<std::string,View> f;if(!blob(row(5,i)+56,&facts,true) || !map(facts,&f) || !evidence(f["evidence"],true))return bad("Semantic","IO evidence identity/order");}
    std::tuple<uint32_t,uint32_t,uint32_t> previous_driver;uint32_t previous_end=0;
    for(size_t i=0;i<sections[6].count;++i){const uint8_t* p=row(6,i);uint32_t semantic=u32(p),bank=u32(p+4),start=u32(p+8),length=u32(p+12);View sites;
        if(semantic>=s->semantics.size() || (bank!=0 && bank!=2) || !length || !range(start,length,65536) || u32(p+16)!=1 || u32(p+20) || !blob(p+24,&sites,true))return bad("Semantic","driver range record");
        const auto& r=s->semantics[semantic];const bool historical=sampled && r.rule==sampled_rule;
        if(i<r.driver_first || i-r.driver_first>=r.driver_count || (historical?(bank!=2 || start!=(r.kind==7?0x168u:0x568u) || length!=4):
           (bank!=r.cb_slot || start<r.source_offset || !range(start-r.source_offset,length,r.source_size))))return bad("Semantic","driver range ownership/span");
        auto order=std::make_tuple(semantic,bank,start);
        if(i && (order<=previous_driver || (std::get<0>(previous_driver)==semantic && std::get<1>(previous_driver)==bank && start<=previous_end)))return bad("Semantic","driver range overlap/adjacency/order");
        previous_driver=order;previous_end=start+length;std::vector<View> reads;if(!list(sites,&reads) || reads.empty() || (historical && reads.size()!=1))return bad("Semantic","driver read evidence empty");
        for(View read:reads){std::map<std::string,View> f;uint64_t offset,size;std::string rule;
            if(!map(read,&f,{"code_offset","rule","size"}) || !integer(f["code_offset"],&offset) || !integer(f["size"],&size) || !size || size>length || !text(f["rule"],&rule) || rule!=r.rule ||
               (historical && (offset!=(r.kind==7?0x98u:0xa0u) || size!=4)) ||
               (port?offset!=UINT64_MAX:(offset==UINT64_MAX || offset>=s->identity.code_size)))return bad("Semantic","driver read site");}
    }
    return true;
}

bool ShaderArtifactDecoder::reserve_file(size_t size) {
    size_t current=retained_bytes.load(std::memory_order_acquire);
    do{if(size>limits.retained_bytes || current>limits.retained_bytes-size)return bad("Budget","global retained artifact file bytes");}
    while(!retained_bytes.compare_exchange_weak(current,current+size,std::memory_order_acq_rel));s->lease=size;
    return true;
}
bool ShaderArtifactDecoder::decode_owned(const ShaderIndexEntry& entry,std::shared_ptr<const ShaderArtifact>* out) {
    s->file_sha256=sha({s->bytes.data(),s->bytes.size()});hash_work=s->bytes.size();
    if(s->file_sha256!=entry.expected_file_sha256)return bad("DigestMismatch","independent whole-file pin against captured owned bytes");
    if(!directory() || !preflight() || !identities() || !tables() || !closures() || !semantics() || !spirv() || !interned() || !digests())return false;
    if(!shader_typed_key_equal(s->key,entry.key))return bad("Identity","artifact differs from compiled exact typed key");
    *out=std::shared_ptr<const ShaderArtifact>(new ShaderArtifact(s));return true;
}
bool ShaderArtifactDecoder::finish(const uint8_t* bytes,size_t size,const ShaderIndexEntry& entry,std::shared_ptr<const ShaderArtifact>* out) {
    if(!reserve_file(size))return false;s->bytes.assign(bytes,bytes+size);return decode_owned(entry,out);
}
bool decode_shader_artifact(const uint8_t* bytes,size_t size,const ShaderIndexEntry& entry,
    std::shared_ptr<const ShaderArtifact>* out,std::string* error,const ShaderArtifactLimits& limits) {
    if(error)error->clear();if(!out)return fail(error,"InvalidArgument: missing artifact output");
    const auto prior=*out;out->reset(); // input span may belong to the old artifact
    if(!validate_compiled_shader_index(&entry,1,error))return false;
    if(!bytes || !limits_ok(limits) || size<1401 || size>limits.artifact_bytes)return fail(error,"FileSize: invalid shader byte span or limits");
    if(size>limits.hash_work_bytes)return fail(error,"Budget: whole-file hash work");
    try{ShaderArtifactDecoder decoder(limits,error);return decoder.finish(bytes,size,entry,out);}
    catch(const std::bad_alloc&){return fail(error,"Allocation: shader artifact decode");}
}
bool read_shader_artifact_fd(int fd,const ShaderIndexEntry& entry,std::shared_ptr<const ShaderArtifact>* out,
    std::string* error,const ShaderArtifactLimits& limits) {
    if(error)error->clear();if(!out)return fail(error,"InvalidArgument: missing artifact output");
    const auto prior=*out;out->reset();
    if(!validate_compiled_shader_index(&entry,1,error))return false;
    if(!limits_ok(limits))return fail(error,"Budget: invalid shader limits");
    struct stat st{};if(fstat(fd,&st))return fail(error,"FileType: fstat errno="+std::to_string(errno));
    if(!S_ISREG(st.st_mode))return fail(error,"FileType: regular shader file required");
    if(st.st_size<1401 || static_cast<uint64_t>(st.st_size)>limits.artifact_bytes)return fail(error,"FileSize: shader file size bounds");
    if(static_cast<uint64_t>(st.st_size)>limits.hash_work_bytes)return fail(error,"Budget: whole-file hash work");
    try{ShaderArtifactDecoder decoder(limits,error);if(!decoder.reserve_file(static_cast<size_t>(st.st_size)))return false;
        auto& captured=decoder.s->bytes;captured.resize(static_cast<size_t>(st.st_size));size_t done=0;
        while(done<captured.size()){ssize_t n=pread(fd,captured.data()+done,captured.size()-done,static_cast<off_t>(done));
            if(n<0 && errno==EINTR)continue;if(n<=0 || static_cast<size_t>(n)>captured.size()-done)return fail(error,"FileRead: incomplete shader file errno="+std::to_string(n<0?errno:0));done+=static_cast<size_t>(n);}
        if(captured.size()>limits.hash_work_bytes)return fail(error,"Budget: whole-file hash work");
        return decoder.decode_owned(entry,out);
    }catch(const std::bad_alloc&){return fail(error,"Allocation: shader file copy");}
}
}
