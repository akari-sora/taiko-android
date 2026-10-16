#pragma once
#include "host_bridge.h"
#include "module_runtime.h"
#include <mutex>
#include <unordered_map>

namespace dm_android {
// Populated from retained ELF swhle/swforce sections; absent weak sections are
// intentionally empty. Direct-link registration object files or whole-archive
// their library. For section GC use KEEP(*(swhle)) / KEEP(*(swforce)), or root
// __start_swhle/__start_swforce and -z nostart-stop-gc. used alone is insufficient.
class HostRegistry {
public:
    bool initialize(std::string* error);
    bool resolve(const char* name, bool forced_only, uintptr_t* address);
    bool contains_callable(uintptr_t address) const;
    static bool resolver(const char* name, bool forced_only, uintptr_t* address, void* context);
    void reset_force_hits();
    bool require_all_forces(std::string* error) const;
    size_t normal_count() const { return ordinary_.size(); }
    size_t force_count() const { return forced_.size(); }
    size_t force_hits(const char* name) const;
private:
    struct Entry { uintptr_t address; size_t hits; };
    std::unordered_map<std::string,Entry> ordinary_, forced_;
    bool ready_=false;
    mutable std::mutex mutex_;
};
class HostBridge {
public:
    ~HostBridge();
    HostBridge() = default;
    HostBridge(const HostBridge&) = delete;
    HostBridge& operator=(const HostBridge&) = delete;
    bool bind(Process& process, std::string* error);
    // All common-host guest threads must have joined before unbind. The caller
    // owns that lifecycle; unpublishing does not stop or detach guest threads.
    void unbind();
private:
    Process* process_=nullptr;
};
}
