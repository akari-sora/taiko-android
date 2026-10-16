#pragma once
#include "guest_thread.h"
#include "module_runtime.h"
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include "taiko_bringup.h"
#include <string>
#include <vector>

namespace dm_android {
// Arguments stay alive and immutable through the whole guest process lifetime.
class BootstrapArguments {
public:
    explicit BootstrapArguments(std::vector<std::string> values = {"D2R"});
    BootstrapArguments(const BootstrapArguments&) = delete;
    BootstrapArguments& operator=(const BootstrapArguments&) = delete;
    bool valid() const { return error_.empty(); }
    const std::string& error() const { return error_; }
    size_t argc() const { return values_.size(); }
    char* const* argv() const { return pointers_.data(); }
private:
    std::vector<std::string> values_;
    std::vector<char*> pointers_;
    std::string error_;
};

struct BootstrapHooks {
    // The Horizon handle must be supplied by the actual kernel/HLE registry.
    bool (*register_main_thread)(DmGuestThreadState&, uint64_t* handle,
                                 uint64_t* argument_area, void*, std::string*) = nullptr;
    // Runs on the attached guest stack; may call guest functions directly.
    // Performs the selected purpose's real platform/product attachment.
    // OriginalBringup does not require later FullProduct feature hooks.
    bool (*before_main)(Process&, DmGuestThreadState&, void*, std::string*) = nullptr;
    void* context = nullptr;
    // Host-stack journal callback. false means ATTEMPT immediately before the
    // operation; true means the operation actually returned successfully.
    // In particular ATTEMPT nnMain does not claim execution or a first frame.
    void (*observer)(const char* step, bool completed, void*) = nullptr;
    void* observer_context = nullptr;
};
struct BootstrapResult {
    std::vector<std::string> completed_steps;
    GuestCallResult main_result{};
};
class BootstrapSession {
public:
    // Explicitly bind this session to an exact compiled diagnostic Process graph.
    // There is deliberately no product-enable flag while real consumers are absent.
    bool authorize(Process& process, std::string* error);
    bool authorize_original_bringup(Process& process, std::string* error);
    bool authorize_taiko_bringup(Process& process, std::string* error);
    // Matches host/main.c guest_main. It never jumps to NSO offset zero and
    // never runs DT_INIT_ARRAY separately from each module's own DT_INIT.
    // A failed/finished session cannot be retried against initialized state.
    bool run(Process&, GuestEnvironment&, GuestStack&, const BootstrapArguments&,
             const BootstrapHooks&, BootstrapResult*, std::string*);
private:
    bool started_ = false;
    DiagnosticAuthority authority_;
    OriginalBringupAuthority original_authority_;
    TaikoBringupAuthority taiko_authority_;
    // Semantic replacement for pinned rtld callback A's exception-ready store.
    // It is session/generation bound and never claims guest rtld execution.
    bool taiko_host_loader_ready_ = false;
    enum class Purpose { None, Diagnostic, OriginalBringup, TaikoStock } purpose_ = Purpose::None;
};
} // namespace dm_android
