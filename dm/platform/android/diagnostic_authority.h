#pragma once
#include "module_runtime.h"
#include <string>
namespace dm_android {
// Exact graph checks against independently compiled public packages. No class,
// environment setting, external manifest or caller flag grants this authority.
bool controller_diagnostic_graph(const Process&, std::string* error);
bool graphics_diagnostic_graph(const Process&, std::string* error);
class BootstrapSession;
class DiagnosticAuthority {
    friend class BootstrapSession;
public:
    DiagnosticAuthority() = default;
    DiagnosticAuthority(const DiagnosticAuthority&) = delete;
    DiagnosticAuthority& operator=(const DiagnosticAuthority&) = delete;
private:
    bool bind(const Process&, const BootstrapSession*, std::string*);
    bool validate(const Process&, const BootstrapSession*, std::string*) const;
    const Process* process_ = nullptr;
    const BootstrapSession* session_ = nullptr;
    uint64_t generation_ = 0;
};
} // namespace dm_android
