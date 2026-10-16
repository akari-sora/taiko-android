#include "diagnostic_session.h"
#include <cstdlib>
#include <limits>
#include <mutex>
#include <utility>

namespace {
std::mutex session_mutex;
dm_android::DiagnosticSessionSnapshot owner;
uint64_t next_id=1;
uint64_t allocate_id() {
    if(next_id==std::numeric_limits<uint64_t>::max()) return 0;
    return next_id++;
}
bool control_group(dm_android::DiagnosticGroup group) {
    using dm_android::DiagnosticGroup;
    return group==DiagnosticGroup::AppletControl || group==DiagnosticGroup::ControllerControl ||
        group==DiagnosticGroup::GraphicsControl;
}
bool allowed(dm_android::DiagnosticRole role,dm_android::DiagnosticGroup group) {
    using dm_android::DiagnosticGroup;
    using dm_android::DiagnosticRole;
    if(group==DiagnosticGroup::None) return false;
    if(role==DiagnosticRole::PersistentApplet)
        return group==DiagnosticGroup::AppletControl || group==DiagnosticGroup::InputSampling;
    if(role==DiagnosticRole::PersistentController)
        return group==DiagnosticGroup::ControllerControl || group==DiagnosticGroup::InputSampling;
    if(role==DiagnosticRole::PersistentGraphics)
        return group==DiagnosticGroup::GraphicsControl || group==DiagnosticGroup::InputSampling;
    return role==DiagnosticRole::AutomaticBatch && !control_group(group);
}
}

namespace dm_android {
bool diagnostic_session_open(DiagnosticRole role,uint64_t* token) {
    if(!token || (role!=DiagnosticRole::AutomaticBatch && role!=DiagnosticRole::PersistentApplet &&
                  role!=DiagnosticRole::PersistentController && role!=DiagnosticRole::PersistentGraphics)) return false;
    std::lock_guard<std::mutex> lock(session_mutex);
    if(owner.id) return false;
    const uint64_t id=allocate_id();if(!id) return false;
    owner={};owner.id=id;owner.role=role;*token=id;return true;
}
DiagnosticSessionSnapshot diagnostic_session_snapshot() {
    std::lock_guard<std::mutex> lock(session_mutex);return owner;
}
bool diagnostic_session_begin_close(uint64_t token) {
    std::lock_guard<std::mutex> lock(session_mutex);
    if(!token || owner.id!=token || owner.group_active || owner.closing || owner.retained) return false;
    owner.closing=true;return true;
}
bool diagnostic_session_begin_recovery(uint64_t token) {
    std::lock_guard<std::mutex> lock(session_mutex);
    if(!token || owner.id!=token || owner.group_active || owner.closing || !owner.retained) return false;
    owner.closing=true;return true;
}
bool diagnostic_session_cancel_close(uint64_t token) {
    std::lock_guard<std::mutex> lock(session_mutex);
    if(!token || owner.id!=token || !owner.closing) return false;
    owner.closing=false;return true;
}
bool diagnostic_session_finish_close(uint64_t token) {
    std::lock_guard<std::mutex> lock(session_mutex);
    if(!token || owner.id!=token || !owner.closing || owner.group_active) return false;
    owner={};return true;
}
DiagnosticCall diagnostic_call_enter(DiagnosticGroup group,uint64_t parent) {
    std::lock_guard<std::mutex> lock(session_mutex);
    if(group==DiagnosticGroup::None || (parent==0 && control_group(group)))
        return {0,false,DiagnosticRefusal::WrongRole};
    if(parent) {
        if(owner.id!=parent) return {0,false,DiagnosticRefusal::StaleToken};
        if(owner.closing) return {0,false,DiagnosticRefusal::Closing};
        if(owner.retained) return {0,false,DiagnosticRefusal::CleanupRetained};
        if(!allowed(owner.role,group)) return {0,false,DiagnosticRefusal::WrongRole};
        if(owner.group_active) return {0,false,DiagnosticRefusal::Busy};
        owner.group_active=true;owner.group=group;
        return {parent,false,DiagnosticRefusal::None};
    }
    if(owner.id) return {0,false,DiagnosticRefusal::Busy};
    const uint64_t token=allocate_id();
    if(!token) return {0,false,DiagnosticRefusal::Exhausted};
    owner={};owner.id=token;owner.role=DiagnosticRole::SingleGroup;
    owner.group_active=true;owner.group=group;
    return {token,true,DiagnosticRefusal::None};
}
DiagnosticCall::DiagnosticCall(DiagnosticCall&& previous) noexcept
    :token_(std::exchange(previous.token_,0)),ephemeral_(previous.ephemeral_),
     completed_(previous.completed_),refusal_(previous.refusal_) {}
DiagnosticCall::~DiagnosticCall() {
    if(!token_) return;
    std::lock_guard<std::mutex> lock(session_mutex);
    if(owner.id!=token_ || !owner.group_active || owner.closing) std::abort();
    owner.group_active=false;owner.group=DiagnosticGroup::None;
    if(!completed_) owner.retained=true;
    else if(ephemeral_) owner={};
}
} // namespace dm_android
