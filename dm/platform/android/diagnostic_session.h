// Process ownership for diagnostic preparation, execution and cleanup.
#pragma once
#include <cstdint>

namespace dm_android {
enum class DiagnosticRole { None, AutomaticBatch, SingleGroup, PersistentApplet, PersistentController, PersistentGraphics };
enum class DiagnosticGroup { None, Phase0, Guest, Module, Kernel, Services, Observation,
                             InputSampling, Applet, AppletControl, Controller, ControllerControl,
                             Graphics, GraphicsControl, OriginalEntry };
enum class DiagnosticRefusal { None, Busy, StaleToken, WrongRole, Closing, CleanupRetained, Exhausted };
struct DiagnosticSessionSnapshot {
    uint64_t id=0;
    DiagnosticRole role=DiagnosticRole::None;
    DiagnosticGroup group=DiagnosticGroup::None;
    bool group_active=false, closing=false, retained=false;
};

// These operations only hold a short metadata mutex. They never call runtime,
// platform, Java, environment or cleanup code. A long session owns a token, not
// that mutex. Metadata-only Activity/channel observations need no session.
bool diagnostic_session_open(DiagnosticRole role,uint64_t* token);
DiagnosticSessionSnapshot diagnostic_session_snapshot();
// Close is a two-phase protocol: reserve retirement with no active borrower,
// perform actual cleanup unlocked, then finish. Refused cleanup cancels close
// while retaining the owner. No new borrowers enter during retirement.
bool diagnostic_session_begin_close(uint64_t token);
// Explicit recovery after missing cleanup confirmation; ordinary close must
// reject retained state atomically, even if a caller's prior snapshot was clean.
bool diagnostic_session_begin_recovery(uint64_t token);
bool diagnostic_session_cancel_close(uint64_t token);
bool diagnostic_session_finish_close(uint64_t token);

class DiagnosticCall {
public:
    DiagnosticCall()=default;
    ~DiagnosticCall();
    DiagnosticCall(const DiagnosticCall&)=delete;
    DiagnosticCall& operator=(const DiagnosticCall&)=delete;
    DiagnosticCall(DiagnosticCall&&) noexcept;
    DiagnosticCall& operator=(DiagnosticCall&&)=delete;
    explicit operator bool() const {return token_!=0;}
    uint64_t token() const {return token_;}
    DiagnosticRefusal refusal() const {return refusal_;}
    // Invoke only after this call's actual preparation/destructors/restoration
    // have completed. Forgetting confirmation retains ownership visibly.
    void cleanup_complete() {completed_=true;}
private:
    friend DiagnosticCall diagnostic_call_enter(DiagnosticGroup,uint64_t);
    DiagnosticCall(uint64_t token,bool ephemeral,DiagnosticRefusal refusal)
        :token_(token),ephemeral_(ephemeral),refusal_(refusal) {}
    uint64_t token_=0;
    bool ephemeral_=false,completed_=false;
    DiagnosticRefusal refusal_=DiagnosticRefusal::None;
};
// Parent 0 creates a temporary single-group owner if idle. A batch borrow pins
// its parent and serializes groups. Persistent tokens admit only their controls
// and explicit HID sampling, never another full diagnostic suite.
DiagnosticCall diagnostic_call_enter(DiagnosticGroup group,uint64_t parent=0);
} // namespace dm_android
