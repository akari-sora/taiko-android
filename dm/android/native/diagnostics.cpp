#include <jni.h>
#include <android/log.h>
#include <game-activity/native_app_glue/android_native_app_glue.h>
#include <vulkan/vulkan.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include "../../platform/android/guest_probes.h"
#include "../../platform/android/input_activity.h"
#include "../../platform/android/module_probes.h"
#include "../../platform/android/kernel_probes.h"
#include "../../platform/android/service_probes.h"
#include "../../platform/android/observation_probes.h"
#include "../../platform/android/applet_probes.h"
#include "../../platform/android/controller_probes.h"
#include "../../platform/android/controller_platform.h"
#include "../../platform/android/graphics_probes.h"
#include "../../platform/android/graphics_surface.h"
#if !defined(DM_TARGET_TAIKO) || !DM_TARGET_TAIKO
#include "../../platform/android/original_runner.h"
#endif
#include "../../platform/android/diagnostic_session.h"
#include "../../platform/android/oe_platform.h"
extern "C" {
#include "../../host/romfs_validate.h"
int dm_android_runtime_is_active();
}

extern "C" int d2r_diagnostic_gate();
extern "C" void d2r_diagnostic_illegal();
extern "C" int d2r_diagnostic_host_call() { return 42; }
struct HleEntry { const char* name; int (*call)(); };
__attribute__((used, section("sw_hle"), aligned(8)))
static const HleEntry fixture = {"synthetic_host_call", d2r_diagnostic_host_call};
extern "C" const HleEntry __start_sw_hle[], __stop_sw_hle[];
static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
namespace {
using namespace dm_android;
uint64_t applet_owner=0, applet_handle=0; // protected by probe_lock
uint64_t controller_owner=0, controller_handle=0; // protected by probe_lock
uint64_t graphics_owner=0, graphics_handle=0; // protected by probe_lock
class ProbeLock {
public:
    ProbeLock() {if(pthread_mutex_lock(&probe_lock)) std::abort();}
    ~ProbeLock() {if(pthread_mutex_unlock(&probe_lock)) std::abort();}
};
const char* role_name(DiagnosticRole role) {
    switch(role) {
    case DiagnosticRole::AutomaticBatch: return "AutomaticBatch";
    case DiagnosticRole::SingleGroup: return "SingleGroup";
    case DiagnosticRole::PersistentApplet: return "PersistentApplet";
    case DiagnosticRole::PersistentController: return "PersistentController";
    case DiagnosticRole::PersistentGraphics: return "PersistentGraphics";
    default: return "None";
    }
}
void ownership_error(JNIEnv* env,DiagnosticRefusal refusal) {
    const std::string message="Diagnostic ownership unavailable (reason="+
        std::to_string(static_cast<int>(refusal))+"); preparation was not started";
    env->ThrowNew(env->FindClass("org/d2rmobile/diagnostics/DiagnosticOwnershipException"),message.c_str());
}
DiagnosticCall enter_group(JNIEnv* env,DiagnosticGroup group,jlong parent) {
    auto call=diagnostic_call_enter(group,static_cast<uint64_t>(parent));
    if(!call) ownership_error(env,call.refusal());
    return call;
}
bool complete_group(JNIEnv* env,DiagnosticCall& call) {
    if(dm_android_runtime_is_active()) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),"Diagnostic cleanup retained an active runtime");
        return false; // call destructor keeps process ownership
    }
    call.cleanup_complete();return true;
}
}
static thread_local sigjmp_buf recovery;
static thread_local volatile sig_atomic_t armed = 0;
static thread_local volatile sig_atomic_t delivered = 0;
static thread_local volatile sig_atomic_t recovered_signal = 0;
static thread_local int guest_tls = 7;
static const int signals[] = {SIGILL, SIGSEGV, SIGBUS, SIGUSR1};
static struct sigaction old_actions[4];

static void handler(int number, siginfo_t* info, void* context) {
    if (number == SIGUSR1 && armed) { delivered = 1; return; }
    if (armed && (number == SIGILL || number == SIGSEGV || number == SIGBUS)) {
        recovered_signal = number;
        siglongjmp(recovery, 1);
    }
    for (size_t i = 0; i < 4; ++i) {
        if (signals[i] != number) continue;
        const struct sigaction& previous = old_actions[i];
        if (previous.sa_handler == SIG_IGN) return;
        if (previous.sa_handler == SIG_DFL) {
            sigaction(number, &previous, nullptr);
            raise(number);
        } else if (previous.sa_flags & SA_SIGINFO) previous.sa_sigaction(number, info, context);
        else previous.sa_handler(number);
        return;
    }
}

class SignalScope {
    stack_t previous{};
    sigset_t previous_mask{};
    void* memory = nullptr;
    size_t count = 0;
    bool stack_installed = false;
    bool mask_saved = false;
public:
    bool ready = false;
    SignalScope() {
        memory = std::malloc(64 * 1024);
        if (!memory) return;
        stack_t alternate{};
        alternate.ss_sp = memory;
        alternate.ss_size = 64 * 1024;
        if (sigaltstack(&alternate, &previous) != 0) return;
        stack_installed = true;
        struct sigaction action{};
        action.sa_sigaction = handler;
        action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&action.sa_mask);
        for (; count < 4; ++count)
            if (sigaction(signals[count], &action, &old_actions[count]) != 0) return;
        sigset_t unblocked;
        sigemptyset(&unblocked);
        for (int number : signals) sigaddset(&unblocked, number);
        if (pthread_sigmask(SIG_UNBLOCK, &unblocked, &previous_mask) != 0) return;
        mask_saved = true;
        ready = true;
    }
    ~SignalScope() {
        armed = 0;
        if (mask_saved) pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
        while (count) { --count; sigaction(signals[count], &old_actions[count], nullptr); }
        if (stack_installed) sigaltstack(&previous, nullptr);
        std::free(memory);
    }
};

static bool safe_call(int (*function)(), int* value) {
    recovered_signal = 0;
    if (sigsetjmp(recovery, 1)) { armed = 0; return false; }
    armed = 1;
    *value = function();
    armed = 0;
    return true;
}

static uintptr_t read_tp() {
    uintptr_t value;
    asm volatile("mrs %0, tpidr_el0" : "=r"(value));
    return value;
}
static uintptr_t read_x18() {
    uintptr_t value;
    asm volatile("mov %0, x18" : "=r"(value));
    return value;
}
struct ThreadResult { uintptr_t tp = 0; uintptr_t tls_address = 0; int value = 0; };
static void* guest_thread(void* opaque) {
    auto* result = static_cast<ThreadResult*>(opaque);
    guest_tls = 42;
    result->tp = read_tp();
    result->tls_address = reinterpret_cast<uintptr_t>(&guest_tls);
    result->value = guest_tls;
    return reinterpret_cast<void*>(static_cast<uintptr_t>(42));
}
static std::string quote(const std::string& input) {
    std::string output = "\"";
    for (unsigned char c : input) {
        if (c == '\\' || c == '"') { output += '\\'; output += static_cast<char>(c); }
        else if (c >= 32) output += static_cast<char>(c);
        else output += ' ';
    }
    return output + "\"";
}
static void record(std::ostringstream& json, bool& first, const char* id,
                   const char* status, const std::string& detail) {
    if (!first) json << ',';
    first = false;
    json << "{\"id\":" << quote(id) << ",\"status\":" << quote(status)
         << ",\"detail\":" << quote(detail) << '}';
}

static bool vulkan_probe(std::string& detail) {
    VkApplicationInfo application{};
    application.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    application.pApplicationName = "D2R Phase 0 diagnostics";
    application.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo create{};
    create.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create.pApplicationInfo = &application;
    VkInstance instance = VK_NULL_HANDLE;
    VkResult status = vkCreateInstance(&create, nullptr, &instance);
    if (status != VK_SUCCESS) { detail = "vkCreateInstance result=" + std::to_string(status); return false; }
    uint32_t count = 0;
    status = vkEnumeratePhysicalDevices(instance, &count, nullptr);
    bool success = false;
    detail = "No usable graphics queue / logical device; enumeration result=" + std::to_string(status);
    if (status == VK_SUCCESS && count) {
        std::vector<VkPhysicalDevice> devices(count);
        status = vkEnumeratePhysicalDevices(instance, &count, devices.data());
        if (status == VK_SUCCESS) for (uint32_t i = 0; i < count && !success; ++i) {
            uint32_t queues = 0;
            vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queues, nullptr);
            std::vector<VkQueueFamilyProperties> properties(queues);
            vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queues, properties.data());
            for (uint32_t q = 0; q < queues; ++q) {
                if (!(properties[q].queueFlags & VK_QUEUE_GRAPHICS_BIT) || !properties[q].queueCount) continue;
                float priority = 1.0f;
                VkDeviceQueueCreateInfo queue{};
                queue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
                queue.queueFamilyIndex = q;
                queue.queueCount = 1;
                queue.pQueuePriorities = &priority;
                VkDeviceCreateInfo device_create{};
                device_create.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
                device_create.queueCreateInfoCount = 1;
                device_create.pQueueCreateInfos = &queue;
                VkDevice device = VK_NULL_HANDLE;
                status = vkCreateDevice(devices[i], &device_create, nullptr, &device);
                if (status == VK_SUCCESS) {
                    VkPhysicalDeviceProperties info{};
                    vkGetPhysicalDeviceProperties(devices[i], &info);
                    detail = std::string(info.deviceName) + "; graphics queue=" + std::to_string(q)
                        + "; API=" + std::to_string(info.apiVersion) + "; logical device created; no replay/present tested";
                    vkDestroyDevice(device, nullptr);
                    success = true;
                    break;
                }
                detail = "vkCreateDevice result=" + std::to_string(status);
            }
        }
    }
    vkDestroyInstance(instance, nullptr);
    return success;
}

static std::string diagnostics() {
    std::ostringstream json;
    bool first = true;
    json << "{\"schemaVersion\":1,\"checks\":[";
    record(json, first, "abi", sizeof(void*) == 8 ? "PASS" : "FAIL", "Compiled for AArch64/AAPCS64; pointer bytes=" + std::to_string(sizeof(void*)) + "; original NSO ABI not validated");
    {
        SignalScope signals_scope;
        if (signals_scope.ready) {
            const long page_size = sysconf(_SC_PAGESIZE);
            void* page = page_size > 0 ? mmap(nullptr, static_cast<size_t>(page_size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) : MAP_FAILED;
            bool passed = false;
            std::string detail;
            if (page == MAP_FAILED) detail = "RW mmap failed; errno=" + std::to_string(errno);
            else {
                const uint32_t instructions[] = {0x52800540, 0xd65f03c0}; // mov w0,#42; ret
                std::memcpy(page, instructions, sizeof(instructions));
                __builtin___clear_cache(static_cast<char*>(page), static_cast<char*>(page) + sizeof(instructions));
                if (mprotect(page, static_cast<size_t>(page_size), PROT_READ | PROT_EXEC) != 0)
                    detail = "RW-to-RX mprotect denied; errno=" + std::to_string(errno);
                else {
                    int result = 0;
                    passed = safe_call(reinterpret_cast<int (*)()>(page), &result) && result == 42;
                    detail = "Synthetic RW-to-RX return=" + std::to_string(result) + "; recovered signal=" + std::to_string(recovered_signal) + "; no RWX requested; page size=" + std::to_string(page_size);
                }
                munmap(page, static_cast<size_t>(page_size));
            }
            record(json, first, "wx", passed ? "PASS" : "FAIL", detail);
            int gate_result = 0;
            const uintptr_t before = read_x18();
            const bool gate_ok = safe_call(d2r_diagnostic_gate, &gate_result);
            record(json, first, "x18", gate_ok && before == read_x18() && gate_result == 42 ? "PASS" : "FAIL", "Synthetic assembly host call preserves x18; compiled -ffixed-x18; upstream rewriter not executed");
            const auto entries = __stop_sw_hle - __start_sw_hle;
            const bool hle_ok = entries == 1 && __start_sw_hle[0].call() == 42 && gate_ok && gate_result == 42;
            record(json, first, "hle", hle_ok ? "PASS" : "FAIL", "ELF sw_hle entries=" + std::to_string(entries) + "; synthetic AAPCS64 gate allocates stack; not original dm_gate");
            delivered = 0;
            armed = 1;
            const int delivery_result = raise(SIGUSR1);
            armed = 0;
            bool illegal_recovered = false;
            if (sigsetjmp(recovery, 1) == 0) {
                armed = 1;
                d2r_diagnostic_illegal();
                armed = 0;
            } else { armed = 0; illegal_recovered = recovered_signal == SIGILL; }
            record(json, first, "signal", delivery_result == 0 && delivered && illegal_recovered ? "PASS" : "FAIL", "Scoped alternate-stack SIGUSR1 delivery and synchronous synthetic SIGILL recovery; handlers restored after probes");
        } else {
            for (const char* id : {"wx", "x18", "hle", "signal"})
                record(json, first, id, "FAIL", "Could not install scoped signal handlers / alternate stack");
        }
    }
    guest_tls = 7;
    const uintptr_t host_tp = read_tp();
    ThreadResult thread_result;
    pthread_t thread;
    void* return_value = nullptr;
    const int created = pthread_create(&thread, nullptr, guest_thread, &thread_result);
    const int joined = created == 0 ? pthread_join(thread, &return_value) : -1;
    const bool thread_ok = created == 0 && joined == 0 && thread_result.value == 42 && reinterpret_cast<uintptr_t>(return_value) == 42;
    const bool tls_ok = thread_ok && guest_tls == 7 && host_tp == read_tp() && thread_result.tp != host_tp && thread_result.tls_address != reinterpret_cast<uintptr_t>(&guest_tls);
    record(json, first, "tls", tls_ok ? "PASS" : "FAIL", "pthread-local synthetic guest TLS is isolated; TPIDR_EL0 observed, never written; upstream TPIDRRO_EL0 rewriting not validated");
    record(json, first, "thread", thread_ok ? "PASS" : "FAIL", "Synthetic pthread entry/exit return=42; create=" + std::to_string(created) + "; join=" + std::to_string(joined) + "; original guest thread startup not tested");
    std::string vulkan_detail;
    const bool vulkan_ok = vulkan_probe(vulkan_detail);
    record(json, first, "vulkan", vulkan_ok ? "PASS" : "FAIL", vulkan_detail);
    json << "],\"gates\":{\"G0\":\"PENDING\",\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"},\"gamePlayable\":false}";
    return json.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runDiagnostics(JNIEnv* env, jobject, jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Phase0,owner);if(!call) return nullptr;
    pthread_mutex_lock(&probe_lock);
    const std::string result = diagnostics();
    pthread_mutex_unlock(&probe_lock);
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO, "D2RDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runGuestDiagnostics(JNIEnv* env, jobject, jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Guest,owner);if(!call) return nullptr;
    pthread_mutex_lock(&probe_lock);
    const std::string result = dm_android_run_guest_probes();
    pthread_mutex_unlock(&probe_lock);
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO, "D2RGuestDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runModuleDiagnostics(JNIEnv* env, jobject activity, jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Module,owner);if(!call) return nullptr;
    jclass activity_class = env->GetObjectClass(activity);
    jmethodID get_cache = env->GetMethodID(activity_class, "getCacheDir", "()Ljava/io/File;");
    jobject cache_file = env->CallObjectMethod(activity, get_cache);
    jclass file_class = env->FindClass("java/io/File");
    jmethodID get_path = env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
    auto path = static_cast<jstring>(env->CallObjectMethod(cache_file, get_path));
    const char* characters = env->GetStringUTFChars(path, nullptr);
    const std::string cache_directory(characters);
    env->ReleaseStringUTFChars(path, characters);
    env->DeleteLocalRef(path); env->DeleteLocalRef(file_class);
    env->DeleteLocalRef(cache_file); env->DeleteLocalRef(activity_class);
    pthread_mutex_lock(&probe_lock);
    const std::string result = dm_android_run_module_probes(cache_directory);
    pthread_mutex_unlock(&probe_lock);
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO, "D2RModuleDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runKernelDiagnostics(JNIEnv* env, jobject, jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Kernel,owner);if(!call) return nullptr;
    pthread_mutex_lock(&probe_lock);
    const std::string result = dm_android_run_kernel_probes();
    pthread_mutex_unlock(&probe_lock);
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO, "D2RKernelDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runServiceDiagnostics(JNIEnv* env, jobject activity, jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Services,owner);if(!call) return nullptr;
    jclass activity_class = env->GetObjectClass(activity);
    jclass file_class = env->FindClass("java/io/File");
    jmethodID get_path = env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
    auto directory = [&](const char* method) {
        jmethodID get_directory = env->GetMethodID(activity_class, method, "()Ljava/io/File;");
        jobject file = env->CallObjectMethod(activity, get_directory);
        auto path = static_cast<jstring>(env->CallObjectMethod(file, get_path));
        const char* text = env->GetStringUTFChars(path, nullptr);
        std::string result(text);
        env->ReleaseStringUTFChars(path, text);
        env->DeleteLocalRef(path); env->DeleteLocalRef(file);
        return result;
    };
    const std::string files = directory("getFilesDir"), cache = directory("getCacheDir");
    jclass locale_class = env->FindClass("java/util/Locale");
    jmethodID get_default = env->GetStaticMethodID(locale_class, "getDefault", "()Ljava/util/Locale;");
    jobject locale_object = env->CallStaticObjectMethod(locale_class, get_default);
    jmethodID language_tag = env->GetMethodID(locale_class, "toLanguageTag", "()Ljava/lang/String;");
    auto locale_string = static_cast<jstring>(env->CallObjectMethod(locale_object, language_tag));
    const char* locale_chars = env->GetStringUTFChars(locale_string, nullptr);
    const std::string locale(locale_chars);
    env->ReleaseStringUTFChars(locale_string, locale_chars);
    env->DeleteLocalRef(locale_string); env->DeleteLocalRef(locale_object);
    env->DeleteLocalRef(locale_class); env->DeleteLocalRef(file_class); env->DeleteLocalRef(activity_class);
    pthread_mutex_lock(&probe_lock);
    const std::string result = dm_android_run_service_probes(files, cache, locale);
    pthread_mutex_unlock(&probe_lock);
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO, "D2RServiceDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeResources_validateRomFs(JNIEnv* env, jobject, jstring path) {
    if (!path) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "Resource directory is required");
        return nullptr;
    }
    const char* characters = env->GetStringUTFChars(path, nullptr);
    if (!characters) return nullptr;
    const std::string directory(characters);
    env->ReleaseStringUTFChars(path, characters);
    char details[4096]{};
    char validation_reason[4096]{};
    pthread_mutex_lock(&probe_lock);
    const bool ready = dm_romfs_validate(directory.c_str(), validation_reason, sizeof validation_reason) != 0;
    const int incomplete = dm_romfs_report(directory.c_str(), details, sizeof details);
    if (!ready && !incomplete) std::snprintf(details, sizeof details, "%s", validation_reason);
    pthread_mutex_unlock(&probe_lock);
    std::string quoted;
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char byte : std::string(details)) {
        if (byte == '"' || byte == '\\') { quoted += '\\'; quoted += static_cast<char>(byte); }
        else if (byte < 32) { quoted += "\\u00"; quoted += digits[byte >> 4]; quoted += digits[byte & 15]; }
        else quoted += static_cast<char>(byte);
    }
    const std::string result = std::string("{\"ready\":") + (ready ? "true" : "false") +
        ",\"details\":\"" + quoted + "\",\"integrity\":\"sizes-and-extents\",\"gamePlayable\":false}";
    return env->NewStringUTF(result.c_str());
}

extern "C" void android_main(struct android_app* app) {
    dm_android::controller_platform_configure_game_activity(app);
    dm_android::input_activity_attach(app);
    dm_android::graphics_surface_attach(app);
    app->onAppCmd = [](android_app* current,int32_t command) {
        dm_android::input_activity_command(current,command);
        dm_android::graphics_surface_command(current,command);
    };
    while (!app->destroyRequested) {
        dm_android::input_activity_tick(app);
        android_poll_source* source = nullptr;
        const int event = ALooper_pollOnce(dm_android::input_activity_poll_timeout(app), nullptr, nullptr, reinterpret_cast<void**>(&source));
        if (event >= 0 && source) source->process(app, source);
        if (event == ALOOPER_POLL_ERROR) break;
        android_input_buffer* input = android_app_swap_input_buffers(app);
        if (input) {
            dm_android::controller_platform_consume(dm_android::input_activity_generation(app),
                input->keyEvents, input->keyEventsCount, input->motionEvents, input->motionEventsCount);
            for (uint32_t i = 0; i < input->motionEventsCount; ++i)
                dm_android::input_activity_motion(app, input->motionEvents[i]);
            android_app_clear_motion_events(input);
            android_app_clear_key_events(input);
        }
    }
    dm_android::graphics_surface_detach(app);
    dm_android::input_activity_detach(app);
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runInputDiagnostics(JNIEnv* env, jobject activity, jboolean readTouchState, jlong owner) {
    if(readTouchState==JNI_FALSE) {
        const auto receipt=dm_android::input_activity_receipt(env,activity,false);
        return env->NewStringUTF(receipt.c_str());
    }
    auto call=enter_group(env,DiagnosticGroup::InputSampling,owner);if(!call) return nullptr;
    ProbeLock lock;
    const auto receipt = dm_android::input_activity_receipt(env, activity, readTouchState != JNI_FALSE);
    call.cleanup_complete();
    return env->NewStringUTF(receipt.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runObservationDiagnostics(JNIEnv* env, jobject, jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Observation,owner);if(!call) return nullptr;
    pthread_mutex_lock(&probe_lock);
    const std::string result = dm_android_run_observation_probes();
    pthread_mutex_unlock(&probe_lock);
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO, "D2RObservationDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runAppletDiagnostics(JNIEnv* env,jobject,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Applet,owner);if(!call) return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_applet_probes();}
    if(!complete_group(env,call)) return nullptr;
    __android_log_print(ANDROID_LOG_INFO,"D2RAppletDiagnostics","%s",result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_NativeDiagnosticOwner_beginAutomaticBatch(JNIEnv*,jclass) {
    uint64_t token=0;
    if(dm_android_runtime_is_active() || !diagnostic_session_open(DiagnosticRole::AutomaticBatch,&token)) return 0;
    return static_cast<jlong>(token);
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeDiagnosticOwner_endAutomaticBatch(JNIEnv*,jclass,jlong value) {
    const uint64_t token=static_cast<uint64_t>(value);
    const auto state=diagnostic_session_snapshot();
    if(state.id!=token || state.role!=DiagnosticRole::AutomaticBatch || state.retained ||
       !diagnostic_session_begin_close(token)) return JNI_FALSE;
    if(dm_android_runtime_is_active()) {diagnostic_session_cancel_close(token);return JNI_FALSE;}
    return diagnostic_session_finish_close(token)?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeDiagnosticOwner_sessionStatus(JNIEnv* env,jclass) {
    const auto state=diagnostic_session_snapshot();
    std::ostringstream json;
    json<<"{\"id\":"<<state.id<<",\"role\":\""<<role_name(state.role)
        <<"\",\"groupActive\":"<<(state.group_active?"true":"false")
        <<",\"closing\":"<<(state.closing?"true":"false")<<",\"retained\":"<<(state.retained?"true":"false")<<'}';
    return env->NewStringUTF(json.str().c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_NativeApplet_begin(JNIEnv* env,jclass) {
    uint64_t owner=0;
    if(dm_android_runtime_is_active() || !diagnostic_session_open(DiagnosticRole::PersistentApplet,&owner)) return 0;
    bool ready=false;std::string error;
    {
        auto call=enter_group(env,DiagnosticGroup::AppletControl,static_cast<jlong>(owner));
        if(!call) return 0;
        ProbeLock lock;uint64_t handle=0;
        ready=dm_android_applet_begin(&handle,&error);
        if(ready) {applet_owner=owner;applet_handle=handle;}
        call.cleanup_complete();
    }
    if(!ready) {
        if(!dm_android_runtime_is_active() && diagnostic_session_begin_close(owner)) diagnostic_session_finish_close(owner);
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.c_str());return 0;
    }
    return static_cast<jlong>(owner);
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeApplet_poll(JNIEnv* env,jclass,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::AppletControl,owner);if(!call) return nullptr;
    std::string result,error;bool ok=false;
    {
        ProbeLock lock;
        if(applet_owner==static_cast<uint64_t>(owner)) ok=dm_android_applet_poll(applet_handle,&result,&error);
    }
    call.cleanup_complete();
    if(!ok) {env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.empty()?"Stale applet session":error.c_str());return nullptr;}
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeApplet_nativeEnd(JNIEnv*,jclass,jlong value) {
    const uint64_t owner=static_cast<uint64_t>(value);
    const auto state=diagnostic_session_snapshot();
    if(state.id!=owner || state.role!=DiagnosticRole::PersistentApplet || state.retained ||
       !diagnostic_session_begin_close(owner)) return JNI_FALSE;
    bool closed=false;std::string error;
    {
        ProbeLock lock;
        if(applet_owner==owner) closed=dm_android_applet_end(applet_handle,&error);
        if(closed) applet_owner=applet_handle=0;
    }
    if(!closed) {diagnostic_session_cancel_close(owner);return JNI_FALSE;}
    return diagnostic_session_finish_close(owner)?JNI_TRUE:JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runControllerDiagnostics(JNIEnv* env,jobject,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Controller,owner);if(!call) return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_controller_probes();}
    if(!complete_group(env,call)) return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_NativeController_begin(JNIEnv* env,jclass) {
    uint64_t owner=0;
    if(dm_android_runtime_is_active() || !diagnostic_session_open(DiagnosticRole::PersistentController,&owner)) return 0;
    bool ready=false;std::string error;
    {
        auto call=enter_group(env,DiagnosticGroup::ControllerControl,static_cast<jlong>(owner));
        if(!call) return 0;
        ProbeLock lock;uint64_t handle=0;
        ready=dm_android_controller_begin(&handle,&error);
        if(ready) {controller_owner=owner;controller_handle=handle;}
        call.cleanup_complete();
    }
    if(!ready) {
        if(!dm_android_runtime_is_active() && diagnostic_session_begin_close(owner)) diagnostic_session_finish_close(owner);
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.c_str());return 0;
    }
    return static_cast<jlong>(owner);
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeController_poll(JNIEnv* env,jclass,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::ControllerControl,owner);if(!call) return nullptr;
    std::string result,error;bool ok=false;
    {
        ProbeLock lock;
        if(controller_owner==static_cast<uint64_t>(owner)) ok=dm_android_controller_poll(controller_handle,&result,&error);
    }
    call.cleanup_complete();
    if(!ok) {env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.empty()?"Stale controller session":error.c_str());return nullptr;}
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeController_nativeEnd(JNIEnv*,jclass,jlong value) {
    const uint64_t owner=static_cast<uint64_t>(value);
    const auto state=diagnostic_session_snapshot();
    if(state.id!=owner || state.role!=DiagnosticRole::PersistentController || state.retained ||
       !diagnostic_session_begin_close(owner)) return JNI_FALSE;
    bool closed=false;std::string error;
    {
        ProbeLock lock;
        if(controller_owner==owner) closed=dm_android_controller_end(controller_handle,&error);
        if(closed) controller_owner=controller_handle=0;
    }
    if(!closed) {diagnostic_session_cancel_close(owner);return JNI_FALSE;}
    return diagnostic_session_finish_close(owner)?JNI_TRUE:JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runGraphicsDiagnostics(JNIEnv* env,jobject,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_graphics_probes();}
    if(!complete_group(env,call))return nullptr;
    __android_log_print(ANDROID_LOG_INFO,"D2RGraphicsDiagnostics","%s",result.c_str());
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runGraphicsExtendedDiagnostics(JNIEnv* env,jobject,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_graphics_extended_probes();}
    if(!complete_group(env,call))return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_runWindowDiagnostics(JNIEnv* env,jclass,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_window_probes();}
    if(!complete_group(env,call))return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_runSampledDiagnostics(JNIEnv* env,jclass,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    std::string result;{ProbeLock lock;result=dm_android_run_sampled_draw_probes();}
    if(!complete_group(env,call))return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_sampledFrameSnapshot(JNIEnv* env,jclass) {
    const auto result=dm_android_sampled_frame_snapshot();return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_acknowledgeSampledFrame(JNIEnv*,jclass,jlong id,jint frame) {
    return id>0&&frame>0&&dm_android_sampled_frame_ack(static_cast<uint64_t>(id),static_cast<unsigned>(frame))?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_runViDiagnostics(JNIEnv* env,jclass,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_vi_probes();}
    if(!complete_group(env,call))return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_runComputeDiagnostics(JNIEnv* env,jclass,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_shader_compute_probes();}
    if(!complete_group(env,call))return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeOriginal_run(JNIEnv* env,jclass,jobject activity) {
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
    (void)activity;
    return env->NewStringUTF("{\"schemaVersion\":1,\"suite\":\"taiko-original-entry\",\"status\":\"UNAVAILABLE\",\"gamePlayable\":false,\"originalGame\":\"NOT_RUN\",\"error\":\"Taiko original startup has no admitted build or shader catalog\"}");
#else
    auto call=enter_group(env,DiagnosticGroup::OriginalEntry,0);if(!call)return nullptr;
    // All ART access happens on the ordinary host stack before the first guest
    // call. The native runner receives owned values and never captures JNIEnv.
    try {
        auto require=[&](bool ok){if(!ok||env->ExceptionCheck())throw std::runtime_error("original-entry Android context lookup failed");};
        require(activity!=nullptr);
        jclass activity_class=env->GetObjectClass(activity);require(activity_class!=nullptr);
        jclass file_class=env->FindClass("java/io/File");require(file_class!=nullptr);
        jmethodID get_files=env->GetMethodID(activity_class,"getFilesDir","()Ljava/io/File;");require(get_files!=nullptr);
        jmethodID get_path=env->GetMethodID(file_class,"getAbsolutePath","()Ljava/lang/String;");require(get_path!=nullptr);
        jobject file=env->CallObjectMethod(activity,get_files);require(file!=nullptr);
        auto path=static_cast<jstring>(env->CallObjectMethod(file,get_path));require(path!=nullptr);
        struct Utf {
            JNIEnv* env;jstring value;const char* chars;
            ~Utf(){if(chars)env->ReleaseStringUTFChars(value,chars);}
        };
        auto string_value=[&](jstring value){Utf utf{env,value,env->GetStringUTFChars(value,nullptr)};require(utf.chars!=nullptr);return std::string(utf.chars);};
        const std::string directory=string_value(path);
        jclass locale_class=env->FindClass("java/util/Locale");require(locale_class!=nullptr);
        jmethodID get_default=env->GetStaticMethodID(locale_class,"getDefault","()Ljava/util/Locale;");require(get_default!=nullptr);
        jobject locale_object=env->CallStaticObjectMethod(locale_class,get_default);require(locale_object!=nullptr);
        jmethodID language_tag=env->GetMethodID(locale_class,"toLanguageTag","()Ljava/lang/String;");require(language_tag!=nullptr);
        auto locale_tag=static_cast<jstring>(env->CallObjectMethod(locale_object,language_tag));require(locale_tag!=nullptr);
        const std::string locale=string_value(locale_tag);
        const uint64_t owner=dm_android::input_activity_controller_generation(env,activity);require(!env->ExceptionCheck());
        // Release Java local references before the potentially long guest call.
        env->DeleteLocalRef(path);env->DeleteLocalRef(file);env->DeleteLocalRef(file_class);env->DeleteLocalRef(activity_class);
        env->DeleteLocalRef(locale_tag);env->DeleteLocalRef(locale_object);env->DeleteLocalRef(locale_class);
        std::string result;
        {ProbeLock lock;result=dm_android::run_original_entry(directory,locale,owner);}
        // Retained resources retain process ownership as well.
        if(!dm_android_runtime_is_active())call.cleanup_complete();
        __android_log_print(ANDROID_LOG_INFO,"D2ROriginalEntry","%s",result.c_str());
        return env->NewStringUTF(result.c_str());
    } catch(...) {
        if(!dm_android_runtime_is_active())call.cleanup_complete();
        if(!env->ExceptionCheck()) {
            jclass error=env->FindClass("java/lang/IllegalStateException");
            if(error)env->ThrowNew(error,"Original entry stopped during native preparation or reporting; inspect its attempt journal");
        }
        return nullptr;
    }
#endif
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_surfaceSnapshot(JNIEnv* env,jclass,jobject activity) {
    const auto owner=dm_android::input_activity_controller_generation(env,activity);
    const auto surface=dm_android::graphics_surface_snapshot();
    const auto cadence=dm_android::graphics_surface_cadence();
    const bool current_cadence=owner&&owner==surface.owner&&cadence.ticket.owner==owner&&cadence.ticket.epoch==surface.epoch;
    std::ostringstream out;out<<"{\"owner\":"<<surface.owner<<",\"epoch\":"<<surface.epoch
        <<",\"receiverMatches\":"<<(owner&&owner==surface.owner?"true":"false")
        <<",\"available\":"<<(owner&&owner==surface.owner&&surface.available?"true":"false")
        <<",\"active\":"<<(surface.active?"true":"false")<<",\"width\":"<<surface.width
        <<",\"height\":"<<surface.height<<",\"posts\":"<<surface.posts<<",\"accepted\":"<<surface.accepted
        <<",\"failures\":"<<surface.failures
        <<",\"cadenceSerial\":"<<(current_cadence?cadence.serial:0)
        <<",\"frameTimeNs\":"<<(current_cadence?cadence.frame_time_ns:0)<<"}";
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_nativeDisplayFrame(JNIEnv* env,jobject activity,jlong frame_time_ns) {
    const auto owner=dm_android::input_activity_controller_generation(env,activity);
    if(env->ExceptionCheck()||frame_time_ns<=0)return JNI_FALSE;
    return dm_android::graphics_surface_frame_tick(owner,frame_time_ns)?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_runDrawDiagnostics(JNIEnv* env,jclass,jobject activity,jboolean present,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Graphics,owner);if(!call)return nullptr;
    const auto receiver=dm_android::input_activity_controller_generation(env,activity);
    const auto ticket=dm_android::graphics_surface_ticket();
    const bool requested=present!=JNI_FALSE;
    if(requested&&(!receiver||ticket.owner!=receiver)) {
        call.cleanup_complete();
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),"No current resumed presentation surface");return nullptr;
    }
    std::string result;dm_android::SurfaceResult posted;DmGraphicsDrawReadback image;
    {
        ProbeLock lock;
        std::function<bool(const DmGraphicsDrawReadback&,std::string*)> consumer;
        if(requested)consumer=[&](const DmGraphicsDrawReadback& readback,std::string* error) {
            if(!readback.top_row_first) {if(error)*error="draw readback orientation is unsupported";return false;}
            dm_android::SurfaceFrame frame{readback.width,readback.height,readback.row_stride_bytes,readback.rgba8};
            posted=dm_android::graphics_surface_present(ticket,readback.runtime_generation,std::move(frame));
            if(!posted.accepted&&error)*error=posted.error;return posted.accepted;
        };
        result=dm_android_run_shader_draw_probes(&image,consumer);
    }
    if(!complete_group(env,call))return nullptr;
    const auto surface=dm_android::graphics_surface_snapshot();
    if(!result.empty()&&result.back()=='}') {
        result.pop_back();std::ostringstream extra;
        extra<<",\"presentation\":{\"requested\":"<<(requested?"true":"false")
            <<",\"route\":\"GPU-readback-native-window-copy\",\"accepted\":"<<(posted.accepted?"true":"false")
            <<",\"locked\":"<<(posted.locked?"true":"false")<<",\"postSucceeded\":"<<(posted.posted?"true":"false")
            <<",\"owner\":"<<ticket.owner<<",\"epoch\":"<<ticket.epoch<<",\"currentEpoch\":"<<surface.epoch
            <<",\"width\":"<<posted.width<<",\"height\":"<<posted.height<<",\"error\":"<<quote(posted.error)
            <<",\"displayObservation\":\"NOT_RUN\"}}";result+=extra.str();
    }
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_MainActivity_runAudioDiagnostics(JNIEnv* env,jobject,jlong owner) {
    auto call=enter_group(env,DiagnosticGroup::Services,owner);if(!call)return nullptr;
    std::string result;
    {ProbeLock lock;result=dm_android_run_audio_probes();}
    if(!complete_group(env,call))return nullptr;
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jint JNICALL
Java_org_d2rmobile_diagnostics_NativeAudioTest_nativePhase(JNIEnv*,jobject) {
    return static_cast<jint>(dm_android_audio_probe_phase());
}
extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_begin(JNIEnv* env,jclass) {
    uint64_t owner=0;
    if(dm_android_runtime_is_active() || !diagnostic_session_open(DiagnosticRole::PersistentGraphics,&owner))return 0;
    bool ready=false;std::string error;
    {
        auto call=enter_group(env,DiagnosticGroup::GraphicsControl,static_cast<jlong>(owner));
        if(!call)return 0;
        ProbeLock lock;uint64_t handle=0;
        ready=dm_android_graphics_begin(&handle,&error);
        if(ready){graphics_owner=owner;graphics_handle=handle;}
        // A failed preparation must have rolled back its actual runtime before
        // ownership can be released. Otherwise retain the visible owner.
        if(ready || !dm_android_runtime_is_active())call.cleanup_complete();
    }
    if(!ready){
        if(!dm_android_runtime_is_active() && diagnostic_session_begin_close(owner))diagnostic_session_finish_close(owner);
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.empty()?"Graphics preparation failed":error.c_str());return 0;
    }
    return static_cast<jlong>(owner);
}
namespace {
jstring graphics_report(JNIEnv* env,jlong owner,bool wait,jlong timeout) {
    if(timeout<0){env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"),"GPU timeout must be nonnegative");return nullptr;}
    auto call=enter_group(env,DiagnosticGroup::GraphicsControl,owner);if(!call)return nullptr;
    std::string result,error;bool ok=false;
    {
        ProbeLock lock;
        if(graphics_owner==static_cast<uint64_t>(owner)){
            ok=wait?dm_android_graphics_wait(graphics_handle,static_cast<uint64_t>(timeout),&result,&error)
                   :dm_android_graphics_poll(graphics_handle,&result,&error);
        }
    }
    call.cleanup_complete();
    if(!ok){env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.empty()?"Stale graphics session":error.c_str());return nullptr;}
    return env->NewStringUTF(result.c_str());
}
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_poll(JNIEnv* env,jclass,jlong owner) {
    return graphics_report(env,owner,false,0);
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_waitForCompletion(JNIEnv* env,jclass,jlong owner,jlong timeout) {
    return graphics_report(env,owner,true,timeout);
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_nativeEnd(JNIEnv*,jclass,jlong value) {
    const uint64_t owner=static_cast<uint64_t>(value);
    const auto state=diagnostic_session_snapshot();
    if(state.id!=owner || state.role!=DiagnosticRole::PersistentGraphics || state.retained ||
       !diagnostic_session_begin_close(owner))return JNI_FALSE;
    bool closed=false;std::string error;
    {
        ProbeLock lock;
        if(graphics_owner==owner)closed=dm_android_graphics_end(graphics_handle,&error);
        if(closed)graphics_owner=graphics_handle=0;
    }
    if(!closed){diagnostic_session_cancel_close(owner);return JNI_FALSE;}
    return diagnostic_session_finish_close(owner)?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_armPublicationBarrier(JNIEnv* env,jclass) {
#if defined(NDEBUG)
    (void)env;return 0;
#else
    auto call=enter_group(env,DiagnosticGroup::Graphics,0);if(!call)return 0;
    uint64_t id=0;std::string error;
    const bool armed=!dm_android_runtime_is_active() && dm_android_graphics_arm_publication_barrier(&id,&error);
    call.cleanup_complete();return armed?static_cast<jlong>(id):0;
#endif
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_publicationBarrierSnapshot(JNIEnv* env,jclass,jlong id) {
    DmGraphicsPublicationBarrier state;std::string error;
    if(!dm_android_graphics_publication_barrier_snapshot(static_cast<uint64_t>(id),&state,&error)){
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.empty()?"Stale graphics barrier":error.c_str());return nullptr;
    }
    std::ostringstream json;
    json<<"{\"id\":"<<state.id<<",\"loadGeneration\":"<<state.load_generation
        <<",\"fence\":"<<state.fence<<",\"armed\":"<<(state.armed?"true":"false")
        <<",\"entered\":"<<(state.entered?"true":"false")<<",\"released\":"<<(state.released?"true":"false")<<'}';
    return env->NewStringUTF(json.str().c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_retentionSnapshot(JNIEnv* env,jclass,jlong id) {
#if defined(NDEBUG)
    (void)id;env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),"Graphics retention controls require a debug build");return nullptr;
#else
    std::string report,error;
    if(!dm_android_graphics_retention_snapshot(static_cast<uint64_t>(id),&report,&error)){
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),error.empty()?"Graphics retention snapshot refused":error.c_str());return nullptr;
    }
    return env->NewStringUTF(report.c_str());
#endif
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeGraphics_releasePublicationBarrier(JNIEnv*,jclass,jlong id) {
#if defined(NDEBUG)
    (void)id;return JNI_FALSE;
#else
    std::string error;return dm_android_graphics_release_publication_barrier(static_cast<uint64_t>(id),&error)?JNI_TRUE:JNI_FALSE;
#endif
}

extern "C" JNIEXPORT jlong JNICALL
Java_org_d2rmobile_diagnostics_NativeApplet_armLoadBarrier(JNIEnv* env,jclass) {
#if defined(NDEBUG)
    (void)env;return 0;
#else
    auto call=enter_group(env,DiagnosticGroup::Applet,0);if(!call) return 0;
    uint64_t id=0;
    const bool armed=!dm_android_runtime_is_active() && dm_android_applet_loader_arm(&id);
    call.cleanup_complete();return armed?static_cast<jlong>(id):0;
#endif
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_d2rmobile_diagnostics_NativeApplet_loaderSnapshot(JNIEnv* env,jclass) {
    const auto barrier=dm_android_applet_loader_snapshot();
    const auto receipt=oe_platform_receipt();
    const auto& platform=receipt.platform;
    std::ostringstream json;
    json<<"{\"id\":"<<barrier.id<<",\"armed\":"<<(barrier.armed?"true":"false")
        <<",\"waiting\":"<<(barrier.waiting?"true":"false")<<",\"released\":"<<(barrier.released?"true":"false")
        <<",\"timedOut\":"<<(barrier.timed_out?"true":"false")<<",\"epoch\":"<<receipt.epoch
        <<",\"open\":"<<(receipt.open?"true":"false")<<",\"generation\":"<<platform.generation
        <<",\"revision\":"<<platform.revision<<",\"adapterFocus\":"<<oe_platform_focus(platform)
        <<",\"attached\":"<<(platform.attached?"true":"false")<<",\"resumed\":"<<(platform.resumed?"true":"false")
        <<",\"focused\":"<<(platform.focused?"true":"false")<<",\"stopped\":"<<(platform.stopped?"true":"false")<<'}';
    return env->NewStringUTF(json.str().c_str());
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_NativeApplet_releaseLoadBarrier(JNIEnv*,jclass,jlong id) {
    return dm_android_applet_loader_release(static_cast<uint64_t>(id))?JNI_TRUE:JNI_FALSE;
}
