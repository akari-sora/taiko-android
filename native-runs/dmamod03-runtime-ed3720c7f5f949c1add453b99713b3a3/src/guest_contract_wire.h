#pragma once
#include "guest_contract_abi.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace dm_android {

enum class GuestContractWireError : uint32_t {
    Ok = 0,
    MissingInput,
    UnsupportedHeader,
    InvalidFlags,
    InvalidGeometry,
    InvalidPadding,
    InvalidDigest,
    InvalidExactRecord,
    InvalidRetireRecord,
    InvalidGateAssociation,
    InvalidAudit,
};

using GuestContractDigest = bool (*)(const uint8_t*, size_t, uint8_t[32], void*);

struct DecodedGuestContractV1 {
    uint32_t required_flags = 0;
    uint64_t exact_guest_offset = 0, returning_retire_offset = 0, payload_offset = 0;
    std::array<uint8_t,32> exact_guest_table_sha256{}, returning_retire_table_sha256{};
    std::array<uint8_t,32> final_independent_roots_sha256{};
    std::array<uint8_t,32> whole_function_ownership_proof_sha256{};
    std::vector<ExactGuestRecordV1> exact_guest;
    std::vector<ReturningRetireRecordV1> returning_retire;
};

bool decode_guest_contract_v3(const uint8_t* blob, size_t size,
                              GuestContractDigest digest, void* digest_context,
                              DecodedGuestContractV1* out,
                              GuestContractWireError* error);

bool validate_guest_contract_audit_v1(const DecodedGuestContractV1& decoded,
                                      const TrustedGuestContractAuditV1& audit,
                                      const uint8_t package_sha256[32],
                                      const uint8_t source_sha256[32],
                                      const uint8_t build_id[32],
                                      GuestContractDigest digest, void* digest_context,
                                      GuestContractWireError* error);

} // namespace dm_android

