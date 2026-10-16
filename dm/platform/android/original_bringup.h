#pragma once
#include "module_runtime.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace dm_android {
struct OriginalSourcePin {
    const char* name;
    std::array<uint8_t,32> source_sha256, decoded_sha256, build_id;
    uint64_t source_bytes;
};
struct OriginalModulePin {
    const char* name;
    std::array<uint8_t,32> package_sha256, image_sha256;
    uint64_t package_bytes, image_bytes;
    TrustedCallbackAudit callback_audit;
};
struct OriginalBuildPins {
    uint32_t schema;
    const char* build;
    const OriginalSourcePin* sources;
    size_t source_count;
    const OriginalModulePin* modules;
    size_t module_count;
    uint32_t original_word_checks;
    std::array<uint8_t,32> source_audit_sha256, import_manifest_sha256;
};
// Read-only facts from the trusted PC-generated, compiled provider. An absent
// provider returns nullptr and cannot authorize startup. External JSON, class
// labels and caller-supplied pin objects never enter these authority functions.
const OriginalBuildPins* original_bringup_build();
bool original_bringup_graph(const Process&, std::string* error);

class BootstrapSession;
class OriginalBringupAuthority {
    friend class BootstrapSession;
    bool bind(const Process&, const BootstrapSession*, std::string*);
    bool validate(const Process&, const BootstrapSession*, std::string*) const;
    const Process* process_ = nullptr;
    const BootstrapSession* session_ = nullptr;
    uint64_t generation_ = 0;
};
}
