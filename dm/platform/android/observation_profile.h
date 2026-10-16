#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
namespace dm_android {
struct ObservationRecord { uint64_t offset; uint32_t id, word; };
struct ParameterRecord {
    uint64_t a, b;
    uint32_t word_a, word_b, destination, slot, flags;
};
struct ObservationProfile {
    const char *target, *module, *variant, *ruleset;
    std::array<uint8_t,32> build_id, source_sha256, digest;
    uint32_t identity_class;
    const ObservationRecord* observations;
    size_t observation_count;
    const ParameterRecord* parameters;
    size_t parameter_count;
};
extern const ObservationProfile kObservationProfiles[];
extern const size_t kObservationProfileCount;
struct ModulePackage;
// Exact independent compiled authority, never a package's self-asserted digest.
bool validate_observation_profile(ModulePackage&, const char** error);
}
