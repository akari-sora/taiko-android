#include "keyboard_platform.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace dm_android {
bool keyboard_utf8_to_utf16(std::string_view value, std::u16string* out) {
    if (!out) return false;
    std::u16string result;
    for (size_t i = 0; i < value.size();) {
        const auto lead = static_cast<uint8_t>(value[i++]);
        uint32_t c = lead;
        size_t continuation = 0;
        uint32_t minimum = 0;
        if (lead >= 0xc2 && lead <= 0xdf) { c &= 31; continuation = 1; minimum = 0x80; }
        else if (lead >= 0xe0 && lead <= 0xef) { c &= 15; continuation = 2; minimum = 0x800; }
        else if (lead >= 0xf0 && lead <= 0xf4) { c &= 7; continuation = 3; minimum = 0x10000; }
        else if (lead >= 0x80 || !lead) return false;
        if (continuation > value.size() - i) return false;
        for (size_t n = 0; n < continuation; ++n) {
            const auto next = static_cast<uint8_t>(value[i++]);
            if ((next & 0xc0) != 0x80) return false;
            c = (c << 6) | (next & 63);
        }
        if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return false;
        if (c < 0x10000) result.push_back(static_cast<char16_t>(c));
        else {
            c -= 0x10000;
            result.push_back(static_cast<char16_t>(0xd800 | (c >> 10)));
            result.push_back(static_cast<char16_t>(0xdc00 | (c & 1023)));
        }
    }
    *out = std::move(result);
    return true;
}
bool keyboard_utf16_to_utf8(std::u16string_view value, std::string* out) {
    if (!out) return false;
    std::string result;
    for (size_t i = 0; i < value.size(); ++i) {
        uint32_t c = value[i];
        if (!c) return false;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (i + 1 == value.size() || value[i + 1] < 0xdc00 || value[i + 1] > 0xdfff) return false;
            c = 0x10000 + ((c - 0xd800) << 10) + (value[++i] - 0xdc00);
        } else if (c >= 0xdc00 && c <= 0xdfff) return false;
        if (c < 0x80) result.push_back(static_cast<char>(c));
        else {
            if (c < 0x800) result.push_back(static_cast<char>(0xc0 | (c >> 6)));
            else {
                if (c < 0x10000) result.push_back(static_cast<char>(0xe0 | (c >> 12)));
                else {
                    result.push_back(static_cast<char>(0xf0 | (c >> 18)));
                    result.push_back(static_cast<char>(0x80 | ((c >> 12) & 63)));
                }
                result.push_back(static_cast<char>(0x80 | ((c >> 6) & 63)));
            }
            result.push_back(static_cast<char>(0x80 | (c & 63)));
        }
    }
    *out = std::move(result);
    return true;
}
bool keyboard_text_valid(const KeyboardRequest& request, std::string_view text) {
    if (request.min_units < 0 || request.max_units < request.min_units || request.max_units > 1002 ||
        request.max_utf8_bytes < 0 || request.max_utf8_bytes > 3006 ||
        text.size() > static_cast<size_t>(request.max_utf8_bytes)) return false;
    std::u16string units;
    if (!keyboard_utf8_to_utf16(text, &units) || units.size() < static_cast<size_t>(request.min_units) ||
        units.size() > static_cast<size_t>(request.max_units)) return false;
    if (request.character_name) {
        if (text.size() < 2 || text.size() > 15 || units.empty()) return false;
        unsigned separators = 0;
        for (const auto c : units) {
            if ((c >= u'A' && c <= u'Z') || (c >= u'a' && c <= u'z') ||
                (c >= 0x3400 && c <= 0x4dbf) || (c >= 0x4e00 && c <= 0x9fff)) continue;
            if ((c == u'-' || c == u'_') && ++separators <= 1) continue;
            return false;
        }
        if (units.front() == u'-' || units.front() == u'_' || units.back() == u'-' || units.back() == u'_') return false;
    }
    if (request.numeric_max >= 0) {
        if (text.empty()) return false;
        uint64_t value = 0;
        for (const auto c : text) {
            if (c < '0' || c > '9' || value > static_cast<uint64_t>(request.numeric_max) / 10) return false;
            value = value * 10 + static_cast<unsigned>(c - '0');
            if (value > static_cast<uint64_t>(request.numeric_max)) return false;
        }
    }
    return true;
}

void KeyboardBroker::cancel_locked() {
    if(epoch_==UINT64_MAX){fault_=true;active_=false;}else ++epoch_;
    if (pending_) {
        if (!pending_->done) { pending_->done = true; pending_->result = 0; post_locked(true,pending_); }
        pending_.reset(); changed_.notify_all();
    }
}
bool KeyboardBroker::post_locked(bool cancellation,const std::shared_ptr<Pending>& pending) {
    if(cancellation&&!cancel_)return true;
    try {
        if(posts_.size()>=64)throw std::bad_alloc();
        posts_.push_back({cancellation?Dispatch{}:dispatch_,cancellation?cancel_:Cancel{},pending,cancellation});
        changed_.notify_all();return true;
    }catch(...){
        fault_=true;active_=false;
        if(pending_){pending_->done=true;pending_->result=0;pending_.reset();}
        changed_.notify_all();return false;
    }
}
void KeyboardBroker::control() {
    std::unique_lock<std::mutex> lock(mutex_);
    for(;;){
        changed_.wait(lock,[&]{return closing_||!posts_.empty();});
        if(posts_.empty()){if(closing_)return;continue;}
        Post post=std::move(posts_.front());posts_.pop_front();
        const bool execute=post.cancellation||(!closing_&&!fault_&&active_&&pending_==post.pending&&
            generation_==post.pending->request.generation&&!post.pending->done);
        lock.unlock();
        bool accepted=false;
        try {
            if(execute){if(post.cancellation)post.cancel(post.pending->request.generation,post.pending->request.id);
                        else accepted=post.dispatch(post.pending->request);}
        }catch(...){ /* A failed Java post cancels its exact pending request. */ }
        if(!post.cancellation&&execute&&!accepted)
            complete(post.pending->request.generation,post.pending->request.id,false,{});
        post={}; // Retired Java callback references are released on this host stack.
        lock.lock();
    }
}
KeyboardBroker::~KeyboardBroker() {
    Dispatch retired;Cancel retired_cancel;
    {std::lock_guard<std::mutex> lock(mutex_);cancel_locked();closing_=true;
     retired=std::move(dispatch_);retired_cancel=std::move(cancel_);changed_.notify_all();}
    if(worker_.joinable())worker_.join();
}
bool KeyboardBroker::attach(uint64_t generation, Dispatch dispatch, std::thread::id ui_thread, Cancel cancel) {
    Dispatch retired;
    Cancel retired_cancel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closing_ || fault_ || !generation || generation <= generation_ || !dispatch) return false;
        if(!worker_.joinable())try{worker_=std::thread([this]{control();});}catch(...){return false;}
        cancel_locked();
        retired = std::move(dispatch_);
        retired_cancel = std::move(cancel_);
        generation_ = generation; dispatch_ = std::move(dispatch);cancel_=std::move(cancel); ui_thread_ = ui_thread; active_ = false;
    }
    return true;
}
bool KeyboardBroker::active(uint64_t generation, bool value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_ || !dispatch_) return false;
    active_ = value;
    if (!value) cancel_locked();
    return true;
}
bool KeyboardBroker::detach(uint64_t generation) {
    Dispatch retired;
    Cancel retired_cancel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation != generation_ || !dispatch_) return false;
        cancel_locked(); active_ = false; retired = std::move(dispatch_);retired_cancel=std::move(cancel_);
    }
    return true;
}
std::pair<uint64_t, uint64_t> KeyboardBroker::cancel() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto cancelled = pending_ && !pending_->done ?
        std::make_pair(pending_->request.generation, pending_->request.id) : std::make_pair(uint64_t{0}, uint64_t{0});
    cancel_locked();
    return cancelled;
}
int KeyboardBroker::request(KeyboardRequest request, std::string* result, KeyboardReceipt* receipt) {
    if(receipt)*receipt={};
    std::u16string decoded;
    if (!result || request.min_units < 0 || request.max_units < request.min_units || request.max_units > 1002 ||
        request.max_utf8_bytes < 0 || request.max_utf8_bytes > 3006) return 0;
    for (const auto* value : {&request.title, &request.subtitle, &request.guide, &request.initial}) {
        if (value->size() > 3006 || !keyboard_utf8_to_utf16(*value, &decoded)) return 0;
    }
    auto pending = std::make_shared<Pending>();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closing_ || fault_ || !active_ || !dispatch_ || std::this_thread::get_id() == ui_thread_) return -1;
        if (pending_ || next_id_ == std::numeric_limits<uint64_t>::max()) return 0;
        request.generation = generation_; request.id = ++next_id_;
        pending->request = std::move(request); pending->epoch=epoch_; pending_ = pending;
        if(!post_locked(false,pending))return 0;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    changed_.wait(lock, [&] { return pending->done; });
    if (pending_ == pending) pending_.reset();
    if (pending->result == 1) {
        *result = std::move(pending->text);
        if(receipt)*receipt={pending->request.generation,pending->request.id,pending->epoch};
    }
    return pending->result;
}
bool KeyboardBroker::commit(KeyboardReceipt receipt,const std::function<bool()>& publish) {
    std::lock_guard<std::mutex> lock(mutex_);
    if(!receipt.generation||!receipt.id||closing_||fault_||!active_||!dispatch_||
       generation_!=receipt.generation||next_id_!=receipt.id||epoch_!=receipt.epoch||pending_||!publish)return false;
    return publish();
}
bool KeyboardBroker::complete(uint64_t generation, uint64_t id, bool confirmed, std::string text) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_ || !active_ || !pending_ || pending_->request.id != id || pending_->done) return false;
    if (confirmed && !keyboard_text_valid(pending_->request, text)) return false;
    pending_->text = confirmed ? std::move(text) : std::string();
    pending_->result = confirmed ? 1 : 0; pending_->done = true; changed_.notify_all();
    return true;
}
bool KeyboardBroker::pending(uint64_t generation, uint64_t id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return generation == generation_ && active_ && pending_ && pending_->request.id == id && !pending_->done;
}
}

#if defined(__ANDROID__) || defined(DM_KEYBOARD_SDK_HOST_TEST)
#include <atomic>
#include <array>
#include <cstring>
#include "guest_thread.h"
#include "kernel_runtime.h"
#include "kernel_memory_android.h"
#include "diagnostic_authority.h"
#include "original_bringup.h"
#include "original_name.h"
#ifdef __ANDROID__
#include <jni.h>
#include "graphics_probes.h"
#include <sstream>
#endif

namespace {
dm_android::KeyboardBroker broker;
std::mutex consumer_mutex;
void (*text_consumer)(const char*)=nullptr;
uint64_t consumer_revision=0;
thread_local bool original_name_request = false;
thread_local int minimum_units = 0;
thread_local int maximum_bytes = 3006;
thread_local int maximum_units = 1002;
thread_local dm_android::KeyboardReceipt keyboard_receipt;
#ifdef __ANDROID__
std::atomic<uint64_t> next_generation{0};
struct JavaEnv {
    JavaVM* vm; JNIEnv* env = nullptr; bool attached = false;
    explicit JavaEnv(JavaVM* value) : vm(value) {
        if (!vm) return;
        const int status = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            attached = vm->AttachCurrentThread(&env, nullptr) == JNI_OK;
            if (!attached) env = nullptr;
        }
        else if (status != JNI_OK) env = nullptr;
    }
    ~JavaEnv() { if (attached) vm->DetachCurrentThread(); }
};
struct JavaDialog {
    JavaVM* vm = nullptr; jobject object = nullptr; jmethodID post = nullptr, dismiss = nullptr;
    uint64_t generation = 0;
    ~JavaDialog() { JavaEnv java(vm); if (java.env && object) java.env->DeleteGlobalRef(object); }
    bool dispatch(const dm_android::KeyboardRequest& request) {
        JavaEnv java(vm); auto* env = java.env;
        if (!env || env->PushLocalFrame(8) != JNI_OK) return false;
        jstring strings[4]{};
        const std::string* values[] = {&request.title, &request.subtitle, &request.guide, &request.initial};
        bool valid = true;
        for (unsigned i = 0; i < 4; ++i) {
            std::u16string value;
            valid = valid && dm_android::keyboard_utf8_to_utf16(*values[i], &value);
            if (valid) strings[i] = env->NewString(reinterpret_cast<const jchar*>(value.data()), static_cast<jsize>(value.size()));
            if (!strings[i]) valid = false;
        }
        jboolean accepted = JNI_FALSE;
        if (valid) accepted = env->CallBooleanMethod(object, post, static_cast<jlong>(request.generation),
            static_cast<jlong>(request.id), strings[0], strings[1], strings[2], strings[3],
            request.min_units, request.max_units, request.max_utf8_bytes, request.numeric_max,
            static_cast<jboolean>(request.character_name));
        if (env->ExceptionCheck()) { env->ExceptionClear(); accepted = JNI_FALSE; }
        env->PopLocalFrame(nullptr);
        return accepted == JNI_TRUE;
    }
    void cancel(uint64_t owner, uint64_t id) {
        JavaEnv java(vm);
        if (!java.env) return;
        java.env->CallVoidMethod(object, dismiss, static_cast<jlong>(owner), static_cast<jlong>(id));
        if (java.env->ExceptionCheck()) java.env->ExceptionClear();
    }
};
bool string_from_java(JNIEnv* env, jstring value, std::string* out) {
    if (!value || env->GetStringLength(value) > 3006) return false;
    const jchar* data = env->GetStringChars(value, nullptr);
    if (!data) return false;
    const bool valid = dm_android::keyboard_utf16_to_utf8(
        std::u16string_view(reinterpret_cast<const char16_t*>(data), static_cast<size_t>(env->GetStringLength(value))), out);
    env->ReleaseStringChars(value, data);
    return valid;
}
#ifndef NDEBUG
struct GuestKeyboardCall {
    dm_android::KeyboardRequest request;
    std::string output;
    int result=0;
    bool owned_stack=false;
};
uint64_t keyboard_guest_entry(uint64_t opaque) {
    auto& call=*reinterpret_cast<GuestKeyboardCall*>(opaque);
    uint8_t marker=0;uintptr_t bottom=0;size_t bytes=0;
    call.owned_stack=dm_android::active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(&marker),&bottom,&bytes);
    if(!call.owned_stack)return 0;
    call.result=broker.request(std::move(call.request),&call.output);
    return static_cast<uint64_t>(call.result);
}
struct SdkKeyboardProbe {
    using Show=uint32_t(*)(void*,const void*);
    Show show=nullptr;int mode=0;uint32_t result=~0u;
    bool owned=false,guards=false,unchanged=false;
    std::string text;
};
__attribute__((noinline)) uint64_t keyboard_sdk_guest_entry(uint64_t opaque) {
    auto& call=*reinterpret_cast<SdkKeyboardProbe*>(opaque);
    alignas(8) std::array<uint8_t,0x500> config{};
    alignas(8) std::array<uint8_t,0x1000> work{};
    alignas(8) std::array<uint8_t,0x7d4+32> output{};output.fill(0xa5);
    struct {uint64_t address,capacity;} string{reinterpret_cast<uint64_t>(output.data()+16),0x7d4};
    const uint64_t work_address=reinterpret_cast<uint64_t>(work.data()),work_size=work.size();
    const int32_t minimum=2,maximum=8,offset=0x14,length=4;
    std::memcpy(config.data()+0x24,u"原版 SDK 文字回寫",sizeof(u"原版 SDK 文字回寫"));
    std::memcpy(config.data()+0x3b0,&minimum,4);std::memcpy(config.data()+0x3ac,&maximum,4);
    config[0x3bd]=call.mode==1?0:1;
    std::memcpy(config.data()+0x3c0,&offset,4);std::memcpy(config.data()+0x3c4,&length,4);
    std::memcpy(config.data()+0x4d0,&work_address,8);std::memcpy(config.data()+0x4d8,&work_size,8);
    std::memcpy(work.data()+offset,u"初始Ab",8);
    uintptr_t bottom=0;size_t bytes=0;
    call.owned=dm_android::active_guest_stack_owned_bounds(reinterpret_cast<uintptr_t>(&string),&bottom,&bytes)&&
        reinterpret_cast<uintptr_t>(&string)>=bottom&&sizeof(string)<=bytes-(reinterpret_cast<uintptr_t>(&string)-bottom);
    if(!call.owned)return 0;
    if(call.mode==2)string.address=bottom+bytes-8; // Full SDK span must be rejected before any write.
    auto* state=dm_android_peek_guest_state();if(call.mode==3)++state->runtime_generation;
    call.result=call.show(&string,config.data());
    if(call.mode==3)--state->runtime_generation;
    call.guards=std::all_of(output.begin(),output.begin()+16,[](uint8_t v){return v==0xa5;})&&
        std::all_of(output.end()-16,output.end(),[](uint8_t v){return v==0xa5;});
    call.unchanged=std::all_of(output.begin(),output.end(),[](uint8_t v){return v==0xa5;});
    if(call.result==0){
        if(call.mode==1){std::u16string units;for(size_t i=16;i<output.size()-16;i+=2){uint16_t c=0;std::memcpy(&c,output.data()+i,2);if(!c)break;units.push_back(char16_t(c));}dm_android::keyboard_utf16_to_utf8(units,&call.text);}
        else call.text.assign(reinterpret_cast<const char*>(output.data()+16));
    }
    return call.result;
}

#endif
#endif // Android JNI and authored direct broker caller
}
extern "C" {
uint32_t swkbd_show(void*, const void*, int (*)(const char*, const char*, const char*, const char*, int, char*, int));
extern int g_swkbd_name_panel, g_swkbd_numeric_max;
extern int (*g_swkbd_unfilter)(void);

void dm_android_keyboard_set_text_consumer(void (*consumer)(const char*)) {
    // Wake pending input before waiting for a retired callback to finish.
    broker.cancel();
    std::lock_guard<std::mutex> lock(consumer_mutex);
    if(consumer_revision==UINT64_MAX)return;
    text_consumer=consumer;++consumer_revision;
}
void dm_android_keyboard_cancel() { broker.cancel(); }
bool dm_android_keyboard_has_text_consumer() {
    std::lock_guard<std::mutex> lock(consumer_mutex);return text_consumer!=nullptr;
}
void dm_android_keyboard_text_entered(const char* text) {
    std::lock_guard<std::mutex> lock(consumer_mutex);
    if(text_consumer)text_consumer(text);
}
}
namespace {
constexpr size_t keyboard_arg_bytes=0x500, maximum_work_bytes=64u*1024u*1024u;
struct SdkString { uint64_t address,capacity; };
class KeyboardSpan {
public:
    ~KeyboardSpan(){if(pin_)dm_android_kernel_gpu_unpin(pin_);}
    bool admit(dm_android::HleRuntime& runtime,uint64_t address,size_t bytes,unsigned permissions) {
        if(!address||!bytes||bytes>UINT64_MAX-address)return false;
        if(runtime.process().mapped_range(address,bytes,permissions))return true;
        pin_=dm_android_kernel_gpu_pin(address,bytes,permissions);if(pin_)return true;
        const auto* guest=dm_android_peek_guest_state();uintptr_t bottom=0;size_t size=0;
        return guest&&guest->user_data==&runtime&&guest->runtime_generation==runtime.process().load_generation()&&
            dm_android::active_guest_stack_owned_bounds(address,&bottom,&size)&&address>=bottom&&
            address-bottom<=size&&bytes<=size-(address-bottom);
    }
private:
    uint64_t pin_=0;
};
bool overlaps(uint64_t a,size_t n,uint64_t b,size_t m){return a<b+m&&b<a+n;}
bool current_keyboard_guest(dm_android::HleRuntime& runtime,uint64_t generation) {
    const auto* guest=dm_android_peek_guest_state();
    return guest&&guest->user_data==&runtime&&guest->runtime_generation==generation&&
        runtime.process().load_generation()==generation;
}
uint32_t checked_sdk_show(void* out,const void* arg,const dm_android::GuestHleOrigin* origin=nullptr) {
    dm_android::RuntimeReadLease lifetime;
    auto* runtime=lifetime.runtime();
    if(!runtime)return 0x29f;
    const auto generation=runtime->process().load_generation();
    if(!generation||!current_keyboard_guest(*runtime,generation)||
       (!dm_android::original_bringup_graph(runtime->process(),nullptr)&&
        !dm_android::graphics_diagnostic_graph(runtime->process(),nullptr)))return 0x29f;
    // Android has no admitted character-name filter callback yet. A raw function
    // pointer must not become a new callback root merely because text was typed.
    if(g_swkbd_unfilter||std::getenv("DM_KBD"))return 0x29f;
    KeyboardSpan config_span,string_span,work_span,output_span;
    const auto config_address=reinterpret_cast<uint64_t>(arg),string_address=reinterpret_cast<uint64_t>(out);
    if(!config_span.admit(*runtime,config_address,keyboard_arg_bytes,DM_GUEST_READ)||
       !string_span.admit(*runtime,string_address,sizeof(SdkString),DM_GUEST_READ|DM_GUEST_WRITE))return 0x29f;
    dm_android::OriginalNameRequest name_request;
    const auto name_admission=name_request.prepare(runtime->process(),origin,config_address);
    if(name_admission==dm_android::OriginalNameRequest::Admission::Refused)return 0x29f;
    // Keep the codec's existing sizeable frame within the checked HLE reserve.
    struct Staging {
        std::array<uint8_t,keyboard_arg_bytes> config{},staging_config{};
        std::array<uint16_t,501> initial{};
        std::array<uint8_t,0x7d4> output{};
    };
    auto storage=std::make_unique<Staging>();
    auto& config=storage->config;auto& initial=storage->initial;
    auto& staging_config=storage->staging_config;auto& staging=storage->output;
    SdkString string{};
    std::memcpy(config.data(),arg,config.size());std::memcpy(&string,out,sizeof(string));
    // Original SDK 3a7650 stores text-check enable at 3d0 and callback at 3d8;
    // 3a632c uses the separate 4e0 scratch. No checked callback adapter exists.
    // ShowKeyboard 3a6a00 also consumes optional dictionary storage at 4f0/4f8.
    uint64_t dictionary=0,dictionary_bytes=0;
    std::memcpy(&dictionary,config.data()+0x4f0,8);std::memcpy(&dictionary_bytes,config.data()+0x4f8,8);
    if(config[0x3d0]||(config[0x4c0]&&dictionary&&dictionary_bytes)||
       (name_request.active()&&!config[0x3bd]))return 0x29f;
    int32_t minimum=0,maximum=0,offset=0,length=0;uint64_t work=0,work_bytes=0;
    std::memcpy(&minimum,config.data()+0x3b0,4);std::memcpy(&maximum,config.data()+0x3ac,4);
    std::memcpy(&offset,config.data()+0x3c0,4);std::memcpy(&length,config.data()+0x3c4,4);
    std::memcpy(&work,config.data()+0x4d0,8);std::memcpy(&work_bytes,config.data()+0x4d8,8);
    if(minimum<0||maximum<0||maximum>1002||minimum>(maximum?maximum:1002)||
       offset<0||(offset&1)||length<0||length>500||config[0x3bd]>1||
       !work_bytes||work_bytes>maximum_work_bytes||!work_span.admit(*runtime,work,size_t(work_bytes),DM_GUEST_READ|DM_GUEST_WRITE)||
       uint64_t(offset)>work_bytes||uint64_t(length)*2>work_bytes-uint64_t(offset)||
       !string.capacity||string.capacity>0x7d4||(!config[0x3bd]&&(string.capacity<2||(string.address&1)||(string.capacity&1)))||
       !output_span.admit(*runtime,string.address,size_t(string.capacity),DM_GUEST_READ|DM_GUEST_WRITE)||
       overlaps(string.address,size_t(string.capacity),config_address,config.size())||
       overlaps(string.address,size_t(string.capacity),string_address,sizeof(string))||
       overlaps(string.address,size_t(string.capacity),work,size_t(work_bytes))||
       !name_request.disjoint(string.address,size_t(string.capacity))||
       !name_request.disjoint(string_address,sizeof(string))||
       !name_request.disjoint(work,size_t(work_bytes)))return 0x29f;
    // Validate fixed UTF-16 metadata before handing it to the common codec.
    for(const auto& field:std::array<std::pair<size_t,size_t>,3>{{{0x24,65},{0xa6,129},{0x1a8,257}}}) {
        std::u16string value;
        for(size_t i=0;i<field.second;++i){uint16_t unit=0;std::memcpy(&unit,config.data()+field.first+i*2,2);if(!unit)break;value.push_back(char16_t(unit));}
        std::string decoded;if(!dm_android::keyboard_utf16_to_utf8(value,&decoded))return 0x29f;
    }
    if(length)std::memcpy(initial.data(),reinterpret_cast<const void*>(work+uint64_t(offset)),size_t(length)*2);
    std::u16string initial_units;initial_units.reserve(size_t(length));
    for(int32_t i=0;i<length;++i)initial_units.push_back(char16_t(initial[size_t(i)]));
    std::string initial_text;
    if(!dm_android::keyboard_utf16_to_utf8(initial_units,&initial_text))return 0x29f;
    staging_config=config;const uint64_t initial_address=reinterpret_cast<uint64_t>(initial.data());const int32_t zero=0;
    std::memcpy(staging_config.data()+0x4d0,&initial_address,8);std::memcpy(staging_config.data()+0x3c0,&zero,4);
    SdkString staging_string{reinterpret_cast<uint64_t>(staging.data()),string.capacity};
    uint64_t consumer_identity=0;
    {std::lock_guard<std::mutex> lock(consumer_mutex);consumer_identity=consumer_revision;}
    const auto previous_minimum=minimum_units,previous_bytes=maximum_bytes,previous_units=maximum_units;
    const bool previous_name=original_name_request;
    original_name_request=name_request.active();
    const auto previous_receipt=keyboard_receipt;
    // Original name validation counts UTF-8 bytes: a single Han character is
    // three bytes and valid, so do not apply a two-UTF16-unit ASCII minimum.
    minimum_units=name_request.active()?1:minimum;
    maximum_bytes=config[0x3bd]?int(string.capacity-1):3006;
    if(name_request.active())maximum_bytes=std::min(maximum_bytes,15);
    maximum_units=config[0x3bd]?1002:int(string.capacity/2-1);
    keyboard_receipt={};
    uint32_t result=0x29f;
    try{result=swkbd_show(&staging_string,staging_config.data(),front_text_input);}
    catch(...){original_name_request=previous_name;minimum_units=previous_minimum;maximum_bytes=previous_bytes;maximum_units=previous_units;keyboard_receipt=previous_receipt;throw;}
    const auto receipt=keyboard_receipt;
    original_name_request=previous_name;minimum_units=previous_minimum;maximum_bytes=previous_bytes;maximum_units=previous_units;keyboard_receipt=previous_receipt;
    if(result)return result;
    std::lock_guard<std::mutex> consumer_lock(consumer_mutex);
    if(consumer_identity!=consumer_revision)return 0x29f;
    std::string notification;
    if(text_consumer||name_request.active()){
        if(config[0x3bd])notification.assign(reinterpret_cast<const char*>(staging.data()));
        else {std::u16string units;for(size_t i=0;i<string.capacity/2;++i){uint16_t c=0;std::memcpy(&c,staging.data()+i*2,2);if(!c)break;units.push_back(char16_t(c));}if(!dm_android::keyboard_utf16_to_utf8(units,&notification))return 0x29f;}
    }
    if(name_request.active()) {
        dm_android::KeyboardRequest rules;rules.character_name=true;rules.max_utf8_bytes=15;
        if(!config[0x3bd]||!dm_android::keyboard_text_valid(rules,notification))return 0x29f;
    }
    const bool published=broker.commit(receipt,[&]{
        if(!current_keyboard_guest(*runtime,generation)||g_swkbd_unfilter||
           std::memcmp(arg,config.data(),config.size())||std::memcmp(out,&string,sizeof(string))||
           (length&&std::memcmp(reinterpret_cast<const void*>(work+uint64_t(offset)),initial.data(),size_t(length)*2)))return false;
        if(name_request.active()&&!name_request.unchanged())return false;
        std::memcpy(reinterpret_cast<void*>(string.address),staging.data(),size_t(string.capacity));
        if(name_request.active())name_request.commit_filter(notification);
        return true;
    });
    if(!published)return 0x29f;
    // Legacy frontend hook is optional and runs only after actual SDK output.
    // It is never installed on behalf of OriginalBringup.
    if(text_consumer)try{text_consumer(notification.empty()?nullptr:notification.c_str());}
        catch(...){/* Optional notification cannot undo committed SDK output. */}
    return 0;
}
}
extern "C" {
void dm_android_swkbd_entry();
uint32_t dm_android_swkbd_show_from_guest(void* out,const void* arg,uint64_t lr,uintptr_t sp) {
    try {
        dm_android::RuntimeReadLease lifetime;auto* runtime=lifetime.runtime();dm_android::GuestHleOrigin origin;
        const bool received=runtime&&runtime->keyboard_entry_origin(reinterpret_cast<uintptr_t>(&dm_android_swkbd_entry),lr,sp,&origin);
        return checked_sdk_show(out,arg,received?&origin:nullptr);
    }catch(...){return 0x29f;}
}
uint32_t dm_android_swkbd_show(void* out,const void* arg) {
    try{return checked_sdk_show(out,arg);}catch(...){return 0x29f;}
}
int front_text_input(const char* title, const char* sub, const char* guide, const char* initial,
                     int max_chars, char* out, int out_cap) {
    try {
    if (!out || out_cap <= 0) return 0;
    dm_android::KeyboardRequest request;
    request.title = title ? title : ""; request.subtitle = sub ? sub : "";
    request.guide = guide ? guide : ""; request.initial = initial ? initial : "";
    request.min_units = minimum_units; request.max_units = std::min(max_chars > 0 ? std::min(max_chars, 1002) : 1002,maximum_units);
    request.max_utf8_bytes = std::min({out_cap - 1, maximum_bytes, 3006});
    request.character_name = original_name_request || g_swkbd_name_panel != 0; request.numeric_max = g_swkbd_numeric_max;
    std::string text;
    const int result = broker.request(std::move(request), &text, &keyboard_receipt);
    if (result == 1) std::memcpy(out, text.c_str(), text.size() + 1);
    return result;
    }catch(...){return 0;}
}

#ifdef __ANDROID__
JNIEXPORT jlong JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_nativeAttach(JNIEnv* env, jclass, jobject object) {
    auto dialog = std::make_shared<JavaDialog>();
    if (env->GetJavaVM(&dialog->vm) != JNI_OK) return 0;
    const jclass cls = env->GetObjectClass(object);
    dialog->post = env->GetMethodID(cls, "postRequest", "(JJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIIZ)Z");
    dialog->dismiss = env->GetMethodID(cls, "dismissRequest", "(JJ)V");
    env->DeleteLocalRef(cls);
    if (!dialog->post || !dialog->dismiss) return 0;
    dialog->object = env->NewGlobalRef(object);
    if (!dialog->object) return 0;
    const uint64_t generation = ++next_generation;
    dialog->generation = generation;
    if (!broker.attach(generation, [dialog](const auto& request) { return dialog->dispatch(request); },
        std::this_thread::get_id(),[dialog](uint64_t owner,uint64_t id){dialog->cancel(owner,id);})) return 0;
    return static_cast<jlong>(generation);
}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_nativeActive(JNIEnv*, jclass, jlong generation, jboolean active) {
    broker.active(static_cast<uint64_t>(generation), active == JNI_TRUE);
}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_nativeDetach(JNIEnv*, jclass, jlong generation) {
    broker.detach(static_cast<uint64_t>(generation));
}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_cancelPending(JNIEnv*, jclass) {
    dm_android_keyboard_cancel();
}
JNIEXPORT jboolean JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_nativePending(JNIEnv*, jclass, jlong generation, jlong id) {
    return broker.pending(static_cast<uint64_t>(generation), static_cast<uint64_t>(id)) ? JNI_TRUE : JNI_FALSE;
}
JNIEXPORT jboolean JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_nativeComplete(JNIEnv* env, jclass, jlong generation,
                                                                                          jlong id, jboolean confirmed, jstring value) {
    std::string text;
    if (confirmed == JNI_TRUE && !string_from_java(env, value, &text)) return JNI_FALSE;
    return broker.complete(static_cast<uint64_t>(generation), static_cast<uint64_t>(id), confirmed == JNI_TRUE, std::move(text)) ? JNI_TRUE : JNI_FALSE;
}
// A generic frontend entry used by host/UI clients and instrumentation. It
// exercises the actual broker/dialog without impersonating a product callback.
JNIEXPORT jstring JNICALL Java_org_d2rmobile_diagnostics_KeyboardCoordinator_enterText(JNIEnv* env, jclass, jstring title, jstring sub,
                                                                                   jstring guide, jstring initial, jint minimum, jint maximum) {
    dm_android::KeyboardRequest request;
    if (!string_from_java(env, title, &request.title) || !string_from_java(env, sub, &request.subtitle) ||
        !string_from_java(env, guide, &request.guide) || !string_from_java(env, initial, &request.initial)) return nullptr;
    request.min_units = minimum; request.max_units = maximum;
    std::string result;
    if (broker.request(std::move(request), &result) != 1) return nullptr;
    std::u16string units;
    if (!dm_android::keyboard_utf8_to_utf16(result, &units)) return nullptr;
    return env->NewString(reinterpret_cast<const jchar*>(units.data()), static_cast<jsize>(units.size()));
}
#ifndef NDEBUG
// Fixed compiled graphics graph, real registered SDK HLE, real owned GuestStack.
// It never grants original authority or pretends to execute original ARM imports.
JNIEXPORT jstring JNICALL Java_org_d2rmobile_diagnostics_NativeKeyboardTest_sdkStringOnGuestStack(JNIEnv* env,jobject,jint mode) {
    if(mode<0||mode>3)return nullptr;
    SdkKeyboardProbe call;call.mode=mode;uint64_t handle=0;std::string error;
    bool opened=false,invoked=false,closed=false;
    try{
        opened=dm_android_graphics_begin(&handle,&error);
        if(opened){
            // begin() submits the existing graphics fixture's initial GPU job.
            // Honor its real wait/publication contract before opening the SDK
            // dialog; end() correctly refuses a still-pending fixture runtime.
            std::string fixture_report;
            const bool ready=dm_android_graphics_wait(handle,10000000000ull,&fixture_report,&error);
            if(ready){
                dm_android::RuntimeReadLease lifetime;
                if(auto* runtime=lifetime.runtime()){
                    uintptr_t show=0;
                    if(dm_android::graphics_diagnostic_graph(runtime->process(),&error)&&
                       runtime->registry().resolve("_ZN2nn5swkbd12ShowKeyboardEPNS0_6StringERKNS0_15ShowKeyboardArgE",true,&show)){
                        call.show=reinterpret_cast<SdkKeyboardProbe::Show>(show);
                        dm_android::GuestEnvironment guest;dm_android::GuestStack stack(256u*1024u);
                        dm_android::GuestCallResult returned;runtime->configure(guest.state);
                        invoked=stack.call(guest.state,reinterpret_cast<uintptr_t>(&keyboard_sdk_guest_entry),reinterpret_cast<uint64_t>(&call),&returned,&error)&&!returned.exited;
                    }
                }
            }
            std::string cleanup_error;closed=dm_android_graphics_end(handle,&cleanup_error);
            if(!closed&&error.empty())error=cleanup_error;
        }
    }catch(...){
        if(opened){std::string cleanup,fixture_report;
            dm_android_graphics_wait(handle,10000000000ull,&fixture_report,&cleanup);
            closed=dm_android_graphics_end(handle,&cleanup);}
        error="SDK keyboard probe raised an exception";
    }
    std::ostringstream json;
    json<<"{\"schemaVersion\":1,\"scope\":\"authored-fixed-graph-real-SDK-HLE-owned-GuestStack-Dialog-String\",\"originalGame\":\"NOT_RUN\",\"mode\":"<<mode
        <<",\"invoked\":"<<(invoked?"true":"false")<<",\"closed\":"<<(closed?"true":"false")
        <<",\"owned\":"<<(call.owned?"true":"false")<<",\"guards\":"<<(call.guards?"true":"false")
        <<",\"unchanged\":"<<(call.unchanged?"true":"false")<<",\"sdkResult\":"<<call.result<<",\"utf8Hex\":\"";
    static const char digits[]="0123456789abcdef";
    for(unsigned char c:call.text)json<<digits[c>>4]<<digits[c&15];
    json<<"\",\"error\":\"";for(unsigned char c:error)json<<char(c=='"'||c=='\\'||c<32?' ':c);json<<"\"}";
    std::u16string units;if(!dm_android::keyboard_utf8_to_utf16(json.str(),&units))return nullptr;
    return env->NewString(reinterpret_cast<const jchar*>(units.data()),static_cast<jsize>(units.size()));
}
// Generic frontend caller retained for the existing broker UI regression.
// All Java string access happens before/after the real owned stack.
JNIEXPORT jstring JNICALL Java_org_d2rmobile_diagnostics_NativeKeyboardTest_enterTextOnGuestStack(JNIEnv* env,jobject,
    jstring title,jstring sub,jstring guide,jstring initial,jint minimum,jint maximum) {
    GuestKeyboardCall call;
    if(!string_from_java(env,title,&call.request.title)||!string_from_java(env,sub,&call.request.subtitle)||
       !string_from_java(env,guide,&call.request.guide)||!string_from_java(env,initial,&call.request.initial))return nullptr;
    call.request.min_units=minimum;call.request.max_units=maximum;
    dm_android::GuestEnvironment guest;dm_android::GuestStack stack(256u*1024u);
    dm_android::GuestCallResult result;std::string error;
    if(!stack.call(guest.state,reinterpret_cast<uintptr_t>(&keyboard_guest_entry),reinterpret_cast<uint64_t>(&call),&result,&error)||
       result.exited||!call.owned_stack||call.result!=1)return nullptr;
    std::u16string units;
    if(!dm_android::keyboard_utf8_to_utf16(call.output,&units))return nullptr;
    return env->NewString(reinterpret_cast<const jchar*>(units.data()),static_cast<jsize>(units.size()));
}
#endif
#endif // Android JNI
}
#endif
