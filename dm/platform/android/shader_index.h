#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>
namespace dm_android {
using ShaderDigest = std::array<uint8_t,32>;
enum class ShaderStage : uint32_t { Vertex=0,Fragment=1,Geometry=2,
    TessellationControl=3,TessellationEvaluation=4,Compute=5 };
enum class ShaderIdentityKind : uint32_t {
    OriginalMaxwell=1,SemanticPort=2,AuthoredTranslatorFixture=3
};
struct OriginalMaxwellKey {
    uint32_t content_kind=0;
    std::string content_name;
    ShaderDigest trusted_content_sha256{},control_sha256{},code_sha256{};
};
struct SemanticPortKey {
    std::string builtin_name;
    ShaderDigest semantic_source_sha256{},portable_source_sha256{};
};
struct AuthoredTranslatorFixtureKey {
    std::string fixture_name;
    ShaderDigest control_sha256{},code_sha256{};
};
struct ShaderTypedKey {
    ShaderStage stage=ShaderStage::Vertex;
    std::string profile_name;
    ShaderDigest profile_definition_sha256{};
    std::variant<OriginalMaxwellKey,SemanticPortKey,AuthoredTranslatorFixtureKey> source;
};
// Entries are compiled const values. No external index or runtime registration
// exists. Their pins check correspondence, not an arbitrary producer's authority.
struct ShaderIndexEntry {
    ShaderTypedKey key;
    ShaderDigest expected_file_sha256{};
};
ShaderIdentityKind shader_identity_kind(const ShaderTypedKey&);
bool shader_typed_key_equal(const ShaderTypedKey&,const ShaderTypedKey&);
bool validate_compiled_shader_index(const ShaderIndexEntry*,size_t,std::string*);
}
