#pragma once
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace dm_android {
struct KeyboardRequest {
    uint64_t generation = 0, id = 0;
    std::string title, subtitle, guide, initial;
    int min_units = 0, max_units = 1002, max_utf8_bytes = 3006;
    int numeric_max = -1;
    bool character_name = false;
};

// Limits count UTF-16 code units, matching swkbd_show, rather than UTF-8 bytes.
// Invalid UTF-8, embedded NULs and unpaired UTF-16 surrogates are refused.
bool keyboard_utf8_to_utf16(std::string_view value, std::u16string* out);
bool keyboard_utf16_to_utf8(std::u16string_view value, std::string* out);
bool keyboard_text_valid(const KeyboardRequest& request, std::string_view text);

// One foreground Activity owns one keyboard. UI dispatch is asynchronous;
// request() blocks only its calling guest thread. Java dispatch/cancel callbacks
// run unlocked on the normal native control worker, never on a foreign guest SP.
struct KeyboardReceipt { uint64_t generation=0, id=0, epoch=0; };
class KeyboardBroker {
public:
    using Dispatch = std::function<bool(const KeyboardRequest&)>;
    using Cancel = std::function<void(uint64_t,uint64_t)>;
    ~KeyboardBroker();
    bool attach(uint64_t generation, Dispatch dispatch,
                std::thread::id ui_thread = std::this_thread::get_id(), Cancel cancel = {});
    bool active(uint64_t generation, bool value);
    bool detach(uint64_t generation);
    std::pair<uint64_t, uint64_t> cancel(); // Cancelled generation/request, or {0,0}.
    int request(KeyboardRequest request, std::string* result, KeyboardReceipt* receipt = nullptr);
    // SDK publication runs under the same owner lock as Activity cancellation.
    // The callback only checks/copies pinned native memory; never Java/guest code.
    bool commit(KeyboardReceipt receipt, const std::function<bool()>& publish);
    bool complete(uint64_t generation, uint64_t id, bool confirmed, std::string text);
    bool pending(uint64_t generation, uint64_t id) const;
private:
    struct Pending { uint64_t epoch=0; KeyboardRequest request; bool done = false; int result = 0; std::string text; };
    struct Post { Dispatch dispatch; Cancel cancel; std::shared_ptr<Pending> pending; bool cancellation=false; };
    void cancel_locked();
    bool post_locked(bool cancellation,const std::shared_ptr<Pending>& pending);
    void control();
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    uint64_t generation_ = 0, next_id_ = 0, epoch_ = 0;
    bool active_ = false;
    bool closing_ = false, fault_ = false;
    std::thread::id ui_thread_;
    Dispatch dispatch_;
    Cancel cancel_;
    std::shared_ptr<Pending> pending_;
    std::deque<Post> posts_;
    std::thread worker_;
};
}

#if defined(__ANDROID__) || defined(DM_KEYBOARD_SDK_HOST_TEST)
extern "C" {
// Android ShowKeyboard adapter: exact original/fixture runtime and owned spans;
// writes the real SDK String only after confirmed UI and before-write rechecks.
uint32_t dm_android_swkbd_show(void* out, const void* arg);
// Product startup registers the actual frontend consumer after it is attached.
// Remove it before teardown. Original SDK String output needs no frontend hook.
void dm_android_keyboard_set_text_consumer(void (*consumer)(const char*));
// Call before waiting for guest shutdown; it wakes the wait and dismisses UI.
void dm_android_keyboard_cancel();
bool dm_android_keyboard_has_text_consumer();
void dm_android_keyboard_text_entered(const char* text);
int front_text_input(const char* title, const char* sub, const char* guide,
                     const char* initial, int max_chars, char* out, int out_cap);
}
#endif
