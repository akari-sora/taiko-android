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

extern "C" int d2r_diagnostic_gate();
extern "C" void d2r_diagnostic_illegal();
extern "C" int d2r_diagnostic_host_call() { return 42; }
struct HleEntry { const char* name; int (*call)(); };
__attribute__((used, section("sw_hle"), aligned(8)))
static const HleEntry fixture = {"synthetic_host_call", d2r_diagnostic_host_call};
extern "C" const HleEntry __start_sw_hle[], __stop_sw_hle[];
static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
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
Java_org_d2rmobile_diagnostics_MainActivity_runDiagnostics(JNIEnv* env, jobject) {
    pthread_mutex_lock(&probe_lock);
    const std::string result = diagnostics();
    pthread_mutex_unlock(&probe_lock);
    __android_log_print(ANDROID_LOG_INFO, "D2RDiagnostics", "%s", result.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" void android_main(struct android_app* app) {
    while (!app->destroyRequested) {
        android_poll_source* source = nullptr;
        const int event = ALooper_pollOnce(-1, nullptr, nullptr, reinterpret_cast<void**>(&source));
        if (event >= 0 && source) source->process(app, source);
        if (event == ALOOPER_POLL_ERROR) break;
        android_input_buffer* input = android_app_swap_input_buffers(app);
        if (input) {
            android_app_clear_motion_events(input);
            android_app_clear_key_events(input);
        }
    }
}
