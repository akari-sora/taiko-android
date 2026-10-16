#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// A successful real playback Start owns one lease. Never waits on the UI thread.
int dm_android_audio_focus_acquire(void);
void dm_android_audio_focus_release(void);
// Prevent new Starts first. Cancels guest waits without waiting for Java/main;
// quiesce the guest and close old outputs before allowing a new runtime to Start.
void dm_android_audio_focus_shutdown(void);
#ifdef __cplusplus
}

#include <functional>
#include <memory>
namespace dm_android {
class AudioFocusClient {
public:
    virtual ~AudioFocusClient()=default;
    virtual bool post_request(uint64_t generation,uint64_t request)=0;
    virtual void post_abandon(uint64_t generation)=0;
};
// Platform callbacks update this broker; only its normal control worker calls
// the Java client and the potentially blocking audio suspension adapter. Guest
// callers never enter ART on their foreign GuestStack.
class AudioFocusBroker {
public:
    using Suspend=std::function<void(unsigned,int)>;
    explicit AudioFocusBroker(Suspend);
    ~AudioFocusBroker();
    uint64_t attach(std::shared_ptr<AudioFocusClient>);
    void activity(uint64_t generation,bool resumed);
    void detach(uint64_t generation);
    bool pending(uint64_t generation,uint64_t request) const;
    bool should_abandon(uint64_t generation) const;
    void result(uint64_t generation,uint64_t request,bool granted);
    void focus_changed(uint64_t generation,bool has_focus);
    int acquire();
    void release();
    void shutdown();
#ifndef NDEBUG
    bool debug_has_focus() const;
#endif
private:
    struct State;
    std::unique_ptr<State> state_;
};
}
#endif
