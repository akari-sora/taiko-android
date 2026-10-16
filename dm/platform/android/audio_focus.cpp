#include "audio_focus.h"
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

namespace dm_android {
struct AudioFocusBroker::State {
    explicit State(Suspend fn):suspend(std::move(fn)){}
    mutable std::mutex mutex;
    std::condition_variable changed;
    Suspend suspend;
    std::thread worker;
    std::thread::id ui_thread;
    std::shared_ptr<AudioFocusClient> client;
    struct Post {std::shared_ptr<AudioFocusClient> client;uint64_t generation,request;};
    std::deque<Post> posts;
    uint64_t generation=0,next_generation=0,next_request=0,request=0;
    uint64_t epoch=1,version=0,applied=0,leases=0,waiters=0;
    bool resumed=false,focused=false,session=false,requesting=false,closing=false,fault=false;

    void cancel_locked() {++epoch;waiters=0;requesting=false;request=0;}
    void update_locked(){++version;changed.notify_all();}
    bool post_locked(const std::shared_ptr<AudioFocusClient>& target,uint64_t owner,uint64_t id=0){
        if(!target)return true;
        try {
            if(posts.size()>=64)throw std::bad_alloc();
            posts.push_back({target,owner,id});changed.notify_all();return true;
        }catch(...){fault=true;focused=false;cancel_locked();update_locked();return false;}
    }
    uint64_t request_locked(){
        if(requesting)return 0;
        if(next_request==static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))return 0;
        request=++next_request;requesting=true;
        if(!post_locked(client,generation,request))return 0;
        update_locked();return request;
    }
    void control() {
        std::unique_lock<std::mutex> lock(mutex);
        uint64_t observed=0;
        bool fault_abandoned=false;
        for(;;){
            changed.wait(lock,[&]{return closing||version!=observed||!posts.empty()||(fault&&!fault_abandoned);});
            if(!posts.empty()||(fault&&!fault_abandoned&&client)){
                Post post;
                if(!posts.empty()){post=std::move(posts.front());posts.pop_front();}
                else {post={client,generation,0};fault_abandoned=true;}
                const bool execute=!post.request||(!closing&&!fault&&resumed&&client==post.client&&
                    generation==post.generation&&requesting&&request==post.request);
                lock.unlock();
                bool accepted=true;
                try {
                    if(execute){if(post.request)accepted=post.client->post_request(post.generation,post.request);
                                else post.client->post_abandon(post.generation);}
                }catch(...){accepted=false;}
                // A retired Java client's final reference is dropped on this
                // normal host stack, never on the guest caller's foreign SP.
                post.client.reset();
                lock.lock();
                if(post.request&&execute&&!accepted&&generation==post.generation&&requesting&&request==post.request){
                    focused=false;session=false;cancel_locked();post_locked(client,generation);update_locked();
                }
                continue;
            }
            if(fault)fault_abandoned=true;
            if(closing)break;
            const uint64_t revision=version;const bool active=resumed,has_focus=focused;
            lock.unlock();
            try {suspend(1,active?0:1);suspend(2,has_focus?0:1);}
            catch(...){lock.lock();fault=true;focused=false;cancel_locked();changed.notify_all();return;}
            lock.lock();observed=revision;
            if(version==revision){applied=revision;changed.notify_all();}
        }
    }
};

AudioFocusBroker::AudioFocusBroker(Suspend fn):state_(std::make_unique<State>(std::move(fn))){}
AudioFocusBroker::~AudioFocusBroker(){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);s.post_locked(s.client,s.generation);s.client.reset();s.closing=true;s.cancel_locked();s.changed.notify_all();}
    if(s.worker.joinable())s.worker.join();
}
uint64_t AudioFocusBroker::attach(std::shared_ptr<AudioFocusClient> client){
    if(!client)return 0;
    auto& s=*state_;uint64_t generation=0;
    {std::lock_guard<std::mutex> lock(s.mutex);
        if(s.closing||s.fault||s.next_generation==static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))return 0;
        if(!s.worker.joinable())try{s.worker=std::thread([&s]{s.control();});}catch(...){return 0;}
        if(!s.post_locked(s.client,s.generation))return 0;
        s.cancel_locked();
        s.client=std::move(client);s.generation=++s.next_generation;generation=s.generation;
        s.ui_thread=std::this_thread::get_id();s.resumed=false;s.focused=false;s.session=false;s.update_locked();
    }
    return generation;
}
void AudioFocusBroker::activity(uint64_t generation,bool resumed){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);if(!generation||generation!=s.generation||!s.client)return;
        const bool became_active=resumed&&!s.resumed;s.resumed=resumed;
        if(!resumed){s.cancel_locked();s.focused=false;s.session=false;s.post_locked(s.client,generation);}
        else if(became_active&&s.leases&&!s.focused){s.request_locked();}
        s.update_locked();
    }
}
void AudioFocusBroker::detach(uint64_t generation){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);if(!generation||generation!=s.generation)return;
        s.post_locked(s.client,generation);s.client.reset();s.cancel_locked();s.resumed=false;s.focused=false;s.session=false;s.generation=0;s.update_locked();
    }
}
bool AudioFocusBroker::pending(uint64_t generation,uint64_t request) const{
    const auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    return !s.closing&&!s.fault&&s.client&&s.resumed&&s.generation==generation&&s.requesting&&request&&s.request==request;
}
bool AudioFocusBroker::should_abandon(uint64_t generation) const{
    const auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    return s.closing||s.fault||generation!=s.generation||!s.resumed||(!s.requesting&&(!s.session||(!s.leases&&!s.waiters)));
}
void AudioFocusBroker::result(uint64_t generation,uint64_t request,bool granted){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);
        if(s.closing||s.fault||!generation||generation!=s.generation||!s.client||!s.resumed||!s.requesting||!request||s.request!=request)return;
        if(granted){s.focused=true;s.session=true;s.requesting=false;s.request=0;}
        else{s.focused=false;s.session=false;s.cancel_locked();s.post_locked(s.client,generation);}
        s.update_locked();
    }
}
void AudioFocusBroker::focus_changed(uint64_t generation,bool focused){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);
        if(!generation||generation!=s.generation||!s.client)return;
        if(focused){if(s.closing||s.fault||!s.resumed||!s.session||(!s.leases&&!s.waiters))return;s.focused=true;}
        else{s.focused=false;s.cancel_locked();if(!s.leases){s.session=false;s.post_locked(s.client,generation);}}
        s.update_locked();
    }
}
int AudioFocusBroker::acquire(){
    auto& s=*state_;uint64_t generation,epoch;
    {std::lock_guard<std::mutex> lock(s.mutex);
        if(s.closing||s.fault||!s.client||!s.resumed||s.ui_thread==std::this_thread::get_id()||s.leases==std::numeric_limits<uint64_t>::max())return 0;
        generation=s.generation;epoch=s.epoch;++s.waiters;
        if(!s.focused&&!s.requesting&&!s.request_locked()){if(s.waiters)--s.waiters;return 0;}
    }
    int granted=0;
    {std::unique_lock<std::mutex> lock(s.mutex);
        s.changed.wait(lock,[&]{return s.closing||s.fault||s.epoch!=epoch||s.generation!=generation||!s.resumed||(s.focused&&s.applied==s.version);});
        if(!s.closing&&!s.fault&&s.epoch==epoch&&s.generation==generation&&s.resumed&&s.focused&&s.applied==s.version){++s.leases;granted=1;}
        if(s.epoch==epoch&&s.waiters)--s.waiters;
        if(!s.leases&&!s.waiters&&s.generation==generation){s.focused=false;s.session=false;s.cancel_locked();s.post_locked(s.client,generation);s.update_locked();}
    }
    return granted;
}
void AudioFocusBroker::release(){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);if(!s.leases)return;--s.leases;
        if(!s.leases&&!s.waiters){s.focused=false;s.session=false;s.cancel_locked();s.post_locked(s.client,s.generation);s.update_locked();}
    }
}
void AudioFocusBroker::shutdown(){
    auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);s.leases=0;s.focused=false;s.session=false;s.cancel_locked();s.post_locked(s.client,s.generation);s.update_locked();}
}
#ifndef NDEBUG
bool AudioFocusBroker::debug_has_focus() const{
    const auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    return s.client&&s.resumed&&s.focused&&s.applied==s.version;
}
#endif
}

#ifdef __ANDROID__
#include "audio_platform.h"
#include <jni.h>
namespace {
struct JavaEnv {
    JavaVM* vm;JNIEnv* env=nullptr;bool attached=false;
    explicit JavaEnv(JavaVM* value):vm(value){
        if(!vm)return;const int status=vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_6);
        if(status==JNI_EDETACHED){attached=vm->AttachCurrentThread(&env,nullptr)==JNI_OK;if(!attached)env=nullptr;}
        else if(status!=JNI_OK)env=nullptr;
    }
    ~JavaEnv(){if(attached)vm->DetachCurrentThread();}
};
struct JavaFocus final:dm_android::AudioFocusClient {
    JavaVM* vm=nullptr;jobject object=nullptr;jmethodID request=nullptr,abandon=nullptr;
    ~JavaFocus() override{JavaEnv java(vm);if(java.env&&object)java.env->DeleteGlobalRef(object);}
    bool post_request(uint64_t generation,uint64_t id) override{
        JavaEnv java(vm);if(!java.env)return false;
        const auto accepted=java.env->CallBooleanMethod(object,request,static_cast<jlong>(generation),static_cast<jlong>(id));
        if(java.env->ExceptionCheck()){java.env->ExceptionClear();return false;}return accepted==JNI_TRUE;
    }
    void post_abandon(uint64_t generation) override{
        JavaEnv java(vm);if(!java.env)return;
        java.env->CallVoidMethod(object,abandon,static_cast<jlong>(generation));
        if(java.env->ExceptionCheck())java.env->ExceptionClear();
    }
};
dm_android::AudioFocusBroker broker([](unsigned reason,int on){dm_android_audio_set_suspended(reason,on);});
}
extern "C" {
int dm_android_audio_focus_acquire(){return broker.acquire();}
void dm_android_audio_focus_release(){broker.release();}
void dm_android_audio_focus_shutdown(){broker.shutdown();}
JNIEXPORT jlong JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativeAttach(JNIEnv* env,jclass,jobject object){
    try{
        auto client=std::make_shared<JavaFocus>();if(env->GetJavaVM(&client->vm)!=JNI_OK)return 0;
        const auto cls=env->GetObjectClass(object);if(!cls)return 0;
        client->request=env->GetMethodID(cls,"postRequestFocus","(JJ)Z");
        client->abandon=env->GetMethodID(cls,"postAbandonFocus","(J)V");env->DeleteLocalRef(cls);
        if(env->ExceptionCheck()){env->ExceptionClear();return 0;}
        if(!client->request||!client->abandon)return 0;
        client->object=env->NewGlobalRef(object);if(!client->object){if(env->ExceptionCheck())env->ExceptionClear();return 0;}
        return static_cast<jlong>(broker.attach(std::move(client)));
    }catch(...){return 0;}
}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativeActivity(JNIEnv*,jclass,jlong generation,jboolean active){broker.activity(static_cast<uint64_t>(generation),active==JNI_TRUE);}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativeDetach(JNIEnv*,jclass,jlong generation){broker.detach(static_cast<uint64_t>(generation));}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativeFocusResult(JNIEnv*,jclass,jlong generation,jlong request,jboolean granted){broker.result(static_cast<uint64_t>(generation),static_cast<uint64_t>(request),granted==JNI_TRUE);}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativeFocusChanged(JNIEnv*,jclass,jlong generation,jboolean focused){broker.focus_changed(static_cast<uint64_t>(generation),focused==JNI_TRUE);}
JNIEXPORT jboolean JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativePending(JNIEnv*,jclass,jlong generation,jlong request){return broker.pending(static_cast<uint64_t>(generation),static_cast<uint64_t>(request))?JNI_TRUE:JNI_FALSE;}
JNIEXPORT jboolean JNICALL Java_org_d2rmobile_diagnostics_AudioCoordinator_nativeShouldAbandon(JNIEnv*,jclass,jlong generation){return broker.should_abandon(static_cast<uint64_t>(generation))?JNI_TRUE:JNI_FALSE;}
#ifndef NDEBUG
// The instrumentation client exercises these same playback lease entries. It
// cannot grant focus; only the current Activity's AudioManager result can.
JNIEXPORT jint JNICALL Java_org_d2rmobile_diagnostics_NativeAudioFocusTest_nativeAcquire(JNIEnv*,jobject){return dm_android_audio_focus_acquire();}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_NativeAudioFocusTest_nativeRelease(JNIEnv*,jobject){dm_android_audio_focus_release();}
JNIEXPORT void JNICALL Java_org_d2rmobile_diagnostics_NativeAudioFocusTest_nativeCancel(JNIEnv*,jobject){dm_android_audio_focus_shutdown();}
JNIEXPORT jboolean JNICALL Java_org_d2rmobile_diagnostics_NativeAudioFocusTest_nativeHasFocus(JNIEnv*,jobject){return broker.debug_has_focus()?JNI_TRUE:JNI_FALSE;}
#endif
}
#endif
