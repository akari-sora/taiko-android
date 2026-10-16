#pragma once
#include "guest_abi.h"
#include "observation_profile.h"
#include "diag_abort_abi.h"
#include <array>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace dm_android {
// Hard bounds apply before allocation. Defaults are configured limits, not
// evidence of original game coverage. Callers may permit up to 256 MiB per image
// and 512 MiB per package; process aggregate image allocation is capped at 1 GiB.
struct ModuleLimits {
    size_t image_bytes = 128u * 1024u * 1024u;
    size_t package_bytes = 256u * 1024u * 1024u;
    size_t module_count = 16;
    size_t callback_roots = 1u << 20;
};
enum class CallbackIndirectPolicy : uint32_t { Strict = 1, GuardedHost = 2 };
enum class CallbackRootKind : uint32_t { DefinedSttFunc = 1 };
// An opt-in attestation supplied by the trusted PC importer, independently of
// the package bytes. This is corruption/structure checking, not authentication
// or independent native revalidation of a malicious importer's CFG audit.
struct TrustedCallbackAudit {
    uint32_t version = 1;
    std::array<uint8_t,32> package_sha256{}, source_sha256{};
    CallbackIndirectPolicy indirect_policy = CallbackIndirectPolicy::Strict;
    CallbackRootKind root_kind = CallbackRootKind::DefinedSttFunc;
    const uint64_t* roots = nullptr;
    size_t root_count = 0;
};
struct RewriteSite { size_t original_offset; size_t trampoline_offset; };
struct GateProvenance { uint64_t return_offset, original_offset; uint32_t kind, argument, original_word, flags; };
struct ModulePackage {
    ModulePackage() = default;
    // Copies contain public data only; authority never propagates by copying.
    ModulePackage(const ModulePackage&);
    ModulePackage& operator=(const ModulePackage&);
    ModulePackage(ModulePackage&&) noexcept = default;
    ModulePackage& operator=(ModulePackage&&) noexcept = default;
    std::string name;
    std::array<uint8_t, 32> build_id{}, source_sha256{}, image_sha256{};
    size_t original_size = 0, symbol_count = 0, string_bytes = 0;
    size_t data_offset = 0, data_bytes = 0, bss_bytes = 0;
    std::vector<uint8_t> bytes;
    std::vector<DmGuestFixup> fixups;
    std::vector<DmGuestGate> gates;
    uint32_t wire_version = 1, profile_class = 0;
    bool checked_stack = false;
    uint32_t required_flags = 0;
    std::array<uint8_t,32> profile_digest{};
    const ObservationProfile* profile = nullptr;
    std::vector<GateProvenance> gate_provenance;
    std::vector<ParameterRecord> parameters;
    std::vector<RewriteSite> sites;
    std::vector<DmGuestSegment> segments;
    DmGuestImage image{};
    void refresh_view();
private:
    friend class Process;
    friend bool prepare_package(ModulePackage&,DmGuestLoadedImage*,char*,size_t);
    friend bool decode_package(const uint8_t*,size_t,const uint8_t*,std::unique_ptr<ModulePackage>*,std::string*,const ModuleLimits&);
    friend bool decode_package_with_callback_audit(const uint8_t*, size_t, const uint8_t*,
        const TrustedCallbackAudit&, std::unique_ptr<ModulePackage>*, std::string*, const ModuleLimits&);
    bool callback_admitted_ = false;
    CallbackIndirectPolicy callback_indirect_policy_ = CallbackIndirectPolicy::Strict;
    std::array<uint8_t,32> callback_identity_{};
    std::vector<uint64_t> callback_roots_;
    bool stack_admitted_ = false;
    std::array<uint8_t,32> stack_identity_{};
    // Actual whole capsule bytes verified by decode, never a public header
    // assertion. Copies revoke this provenance together with other admissions.
    bool capsule_verified_ = false;
    uint64_t capsule_bytes_ = 0;
    std::array<uint8_t,32> capsule_sha256_{};
};
// Standalone preparation is legacy-only. Checked packages require Process
// ownership so their executable spans participate in entry preflight.
bool prepare_package(ModulePackage&, DmGuestLoadedImage*, char*, size_t);
// Both compiled fixture blobs and external files use this same decoder. A
// nonzero expected whole-package SHA256 must come from a trusted PC import
// manifest or compiled fixture constant, never from the package being decoded.
// This detects corruption against that manifest; it does not authenticate
// arbitrary native code or establish that its producer is trustworthy.
bool decode_package(const uint8_t* blob, size_t size, const uint8_t* expected_digest,
                    std::unique_ptr<ModulePackage>* out, std::string* error,
                    const ModuleLimits& limits = {});
bool decode_package_with_callback_audit(const uint8_t* blob, size_t size,
                    const uint8_t* expected_digest, const TrustedCallbackAudit& audit,
                    std::unique_ptr<ModulePackage>* out, std::string* error,
                    const ModuleLimits& limits = {});
// Reads from offset zero with pread; does not close/change caller's descriptor.
bool read_package_fd(int fd, const uint8_t* expected_digest, std::unique_ptr<ModulePackage>* out,
                     std::string* error, const ModuleLimits& limits = {});
using HostResolver = bool (*)(const char* name, bool forced_only,
                              uintptr_t* address, void* context);
// Runner owns attaching thread state / invocation ABI. No NSO entry execution
// occurs during load; DT_INIT execution requires an explicit caller.
using InitRunner = bool (*)(uintptr_t address, void* context, std::string* error);
enum class InitializerOrder { Forward, Reverse };
struct ModuleDynamic;
struct HostModuleView {
    const void *dynamic=nullptr, *symbols=nullptr;
    const char* strings=nullptr;
    size_t symbol_count=0, init=0, init_array=0, init_array_bytes=0;
};
struct LoadedModule {
    std::unique_ptr<ModulePackage> package;
    DmGuestLoadedImage mapping{};
    std::unique_ptr<ModuleDynamic> dynamic;
    bool init_started = false;
    LoadedModule();
    ~LoadedModule();
private:
    friend class Process;
    std::array<uint8_t,32> load_identity_{};
    std::vector<DmGuestSegment> mapped_segments_;
    bool checked_stack_ = false;
    uint32_t required_flags_ = 0;
    bool capsule_verified_ = false;
    uint64_t capsule_bytes_ = 0;
    std::array<uint8_t,32> capsule_sha256_{};
};
struct LoadedPackageAuthority {
    std::array<uint8_t,32> capsule_sha256{};
    uint64_t capsule_bytes = 0;
    bool checked_stack = false, callback_audited = false;
};
class Process {
public:
    Process() = default;
    ~Process();
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    // Supplied order is preserved (default game order main, sdk). Transactional:
    // failure destroys all candidate mappings; an existing process is unchanged.
    bool load(std::vector<std::unique_ptr<ModulePackage>> packages,
              HostResolver resolver, void* context, std::string* error,
              const ModuleLimits& limits = {});
    bool symbol(const char* name, uintptr_t* address) const;
    // Common-C host lookup intentionally includes local/hidden definitions and
    // preserves first defined symbol order. It never re-parses guest MOD0.
    bool module_symbol(size_t index, const char* name, uintptr_t* address) const;
    bool borrowed_module(size_t index, HostModuleView* view) const;
    bool pin_host_binding(std::string* error);
    void unpin_host_binding();
    bool run_initializers(InitRunner runner, void* context, std::string* error,
                          InitializerOrder order = InitializerOrder::Forward);
    static const DmGuestGate* gate_resolver(void* context, uint64_t return_pc);
    bool guarded_host_site(uint64_t return_pc, const DmGuestGate* gate) const;
    bool stack_check_site(uint64_t return_pc,const DmGuestGate* gate) const;
    // Structural source/relocation proof, not original-game authority. Only a
    // direct original BL through the same module's standard static PLT passes.
    bool static_main_import_caller(uint64_t lr,uintptr_t target,const char* symbol,uint64_t* callsite) const;
    bool diag_abort_import_caller(uintptr_t lr,DiagAbortCaller* out) const;
    // Query only after guarded_host_site succeeds. A nonzero requirement is
    // frozen during load and cannot be removed by mutating package metadata.
    bool diag_abort_host_site(uint64_t return_pc,const DmGuestGate*,uintptr_t* required) const;
    bool checked_stack_entry(uintptr_t entry) const;
    bool observation_present(uint32_t id) const;
    bool copy_readable(uint64_t address, void* staging, size_t bytes) const;
    bool mapped_range(uint64_t address, size_t bytes, unsigned permissions) const;
    bool callback_root(uint64_t address) const;
    // Caller pins process lifetime with a runtime read lease.
    using ReadOnlyVisitor = bool (*)(uint64_t base, size_t size, void* context);
    bool visit_readonly(ReadOnlyVisitor visitor, void* context) const;
    // Caller must finish/detach all guest threads before unload or replacement.
    void unload();
    const std::vector<std::unique_ptr<LoadedModule>>& modules() const { return modules_; }
    // Globally unique successful-load/unload epoch. Failed replacement retains it.
    uint64_t load_generation() const { return load_generation_; }
    // Frozen before relocation/sealing. Rewriting the exposed package after a
    // successful load cannot grant authority to different mapped native code.
    bool loaded_package_matches(size_t index, const ModulePackage& canonical) const;
    // Returns only verified, frozen provenance while the complete public
    // descriptor still matches its pre-relocation load identity.
    bool loaded_package_authority(size_t index, LoadedPackageAuthority* out) const;
    // Exact private admitted audit roots/policy against a compiled authority.
    // Public descriptor or caller-created subset/superset roots cannot match.
    bool loaded_callback_roots_match(size_t index, const TrustedCallbackAudit&) const;
private:
    std::vector<std::unique_ptr<LoadedModule>> modules_;
    struct FrozenGate { DmGuestGate gate; GateProvenance provenance; bool canonical_v2; bool checked_stack; uintptr_t required_target=0; };
    std::unordered_map<uint64_t,FrozenGate> gates_;
    std::unordered_set<uint64_t> callback_roots_;
    bool initializing_ = false, initializer_failed_ = false;
    bool host_bound_ = false;
    uint64_t load_generation_ = 0;
    bool checked_stack_ = false;
};
using DmGuestProcess = Process;
} // namespace dm_android
