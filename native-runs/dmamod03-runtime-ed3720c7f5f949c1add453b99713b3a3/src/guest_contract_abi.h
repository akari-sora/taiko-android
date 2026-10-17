#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace dm_android {

constexpr uint32_t DM_MODULE_REQUIRE_EXACT_GUEST_V1 = 1u << 2;
constexpr uint32_t DM_MODULE_REQUIRE_RETURNING_RETIRE_V1 = 1u << 3;

struct ExactGuestRecordV1 {
    uint32_t schema = 0, flags = 0;
    uint64_t gate_return_offset = 0, original_br_offset = 0;
    uint32_t original_br_word = 0, target_register = 0;
    uint64_t got_offset = 0;
    uint32_t relocation_index = 0, relocation_type = 0, symbol_index = 0;
    uint8_t symbol_type = 0, symbol_binding = 0, symbol_visibility = 0, reserved_zero = 0;
    int64_t relocation_addend = 0;
    uint32_t symbol_name_offset = 0, symbol_name_length = 0;
    uint32_t symbol_section_index = 0, eh_identity_kind = 0;
    uint64_t symbol_value = 0, symbol_size = 0, same_module_target_offset = 0;
    uint64_t function_start = 0, function_end = 0, fde_offset = 0, cie_offset = 0;
    uint64_t independent_root_offset = 0;
    std::array<uint8_t,32> symbol_name_sha256{}, function_sha256{}, eh_identity_sha256{};
    std::array<uint8_t,32> final_independent_roots_sha256{};
    std::array<uint8_t,16> reserved_tail{};
};
static_assert(std::is_standard_layout_v<ExactGuestRecordV1>);
static_assert(sizeof(ExactGuestRecordV1) == 288);
static_assert(offsetof(ExactGuestRecordV1, gate_return_offset) == 8);
static_assert(offsetof(ExactGuestRecordV1, original_br_offset) == 16);
static_assert(offsetof(ExactGuestRecordV1, got_offset) == 32);
static_assert(offsetof(ExactGuestRecordV1, relocation_addend) == 56);
static_assert(offsetof(ExactGuestRecordV1, symbol_value) == 80);
static_assert(offsetof(ExactGuestRecordV1, independent_root_offset) == 136);
static_assert(offsetof(ExactGuestRecordV1, symbol_name_sha256) == 144);
static_assert(offsetof(ExactGuestRecordV1, reserved_tail) == 272);

struct ReturningRetireRecordV1 {
    uint32_t schema = 0, flags = 0;
    uint64_t source_callsite = 0;
    uint32_t original_bl_word = 0, stub_extent = 0;
    uint64_t original_target = 0, normal_return = 0, reserved_stub_offset = 0;
    uint64_t exclusive_head = 0, matching_store = 0;
    uint64_t function_start = 0, function_end = 0, fde_offset = 0, cie_offset = 0;
    std::array<uint8_t,32> function_sha256{}, final_independent_roots_sha256{};
    std::array<uint8_t,32> whole_function_ownership_proof_sha256{};
};
static_assert(std::is_standard_layout_v<ReturningRetireRecordV1>);
static_assert(sizeof(ReturningRetireRecordV1) == 192);
static_assert(offsetof(ReturningRetireRecordV1, source_callsite) == 8);
static_assert(offsetof(ReturningRetireRecordV1, original_target) == 24);
static_assert(offsetof(ReturningRetireRecordV1, exclusive_head) == 48);
static_assert(offsetof(ReturningRetireRecordV1, function_start) == 64);
static_assert(offsetof(ReturningRetireRecordV1, function_sha256) == 96);
static_assert(offsetof(ReturningRetireRecordV1, whole_function_ownership_proof_sha256) == 160);

struct TrustedGuestContractAuditV1 {
    uint32_t schema = 1, flags = 0;
    std::array<uint8_t,32> package_sha256{}, source_sha256{}, build_id{};
    std::array<uint8_t,32> toolset_recipe_sha256{}, audit_identity_sha256{};
    uint64_t exact_guest_count = 0;
    std::array<uint8_t,32> exact_guest_table_sha256{};
    uint64_t returning_retire_count = 0;
    std::array<uint8_t,32> returning_retire_table_sha256{};
    std::array<uint8_t,32> final_independent_roots_sha256{};
    std::array<uint8_t,32> whole_function_ownership_proof_sha256{};
};

} // namespace dm_android

