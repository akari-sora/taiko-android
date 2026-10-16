#pragma once
#include "module_runtime.h"
#include <array>

namespace dm_android {
struct TaikoSourcePin {
    const char* name;
    std::array<uint8_t,32> source_sha256, decoded_sha256, build_id;
    uint64_t source_bytes;
};
struct TaikoModulePin {
    const char* name;
    std::array<uint8_t,32> package_sha256, image_sha256;
    uint64_t package_bytes, image_bytes;
    TrustedCallbackAudit callback_audit;
};
struct TaikoBuildPins {
    uint32_t schema;
    const char* build;
    const char* program_id;
    std::array<uint8_t,32> npdm_sha256;
    TaikoSourcePin rtld;
    const TaikoSourcePin* sources;
    size_t source_count;
    const TaikoModulePin* modules;
    size_t module_count;
    std::array<uint8_t,32> source_audit_sha256, import_manifest_sha256;
};
// Only a compiled provider produced after the complete import/audit can supply
// these facts. Caller JSON and caller-created pins never grant startup authority.
const TaikoBuildPins* taiko_bringup_build();
bool taiko_bringup_graph(const Process&, std::string* error);

enum class TaikoStartupKind { Guest, HostLoaderReady, ReverseModuleInitializers, PlatformAttachment };
struct TaikoStartupStep {
    TaikoStartupKind kind;
    const char* name;
    size_t module_index;
    uint64_t offset;
};
// Pinned SDK Start prefix through nnMain, with host loader semantics explicit.
// It does not assert execution of rtld, SDK Start itself, or post-main teardown.
const std::array<TaikoStartupStep,10>& taiko_startup_plan();

class BootstrapSession;
class TaikoBringupAuthority {
    friend class BootstrapSession;
    bool bind(const Process&, const BootstrapSession*, std::string*);
    bool validate(const Process&, const BootstrapSession*, std::string*) const;
    const Process* process_ = nullptr;
    const BootstrapSession* session_ = nullptr;
    uint64_t generation_ = 0;
};
}
