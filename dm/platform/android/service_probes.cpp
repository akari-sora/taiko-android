#include "service_probes.h"
#include "kernel_runtime.h"
#include "kernel_platform.h"
#include "fs_platform.h"
#include "app_platform.h"
#include "audio_platform.h"
#include "service_fixtures/generated_services.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <initializer_list>
#include <sstream>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern "C" {
void dm_fs_save_poison(int);
void hle_signal_system_event(void*);
void dm_guest_write_prep_register(void (*)(void*, size_t));
uint64_t dm_audio_render_calls(void);
}

namespace {
using namespace dm_android;
constexpr uint64_t failed = 0x2a2, timeout = 0xea01;
std::atomic<uint64_t> prepared_writes{0};
std::atomic<unsigned> audio_phase{0};
void prepare_write(void* address, size_t size) { if (address && size) prepared_writes.fetch_add(1); }
struct Check {
    explicit Check(const char* value) : id(value) {}
    const char* id; bool passed = false; std::string detail;
};
struct Event { uint32_t writable = 0, readable = 0; };
struct User { uint64_t word[3]{}; };
struct Calendar { int16_t year; int8_t month, day, hour, minute, second, pad; };
struct Additional { uint32_t weekday, yearday; char zone[8]; uint32_t dst; int32_t offset; };
struct MemoryInfo { uint64_t base, size; uint32_t state, attributes, permissions, ipc, device, padding; };
struct DirectoryEntry { char name[0x301]; uint8_t pad0[3]; int8_t type; uint8_t pad1[3]; int64_t size; };
static_assert(sizeof(DirectoryEntry) == 0x310, "public directory ABI");
template<class T> uint64_t ptr(T* value) { return reinterpret_cast<uintptr_t>(value); }
std::string escape(const std::string& value) {
    std::string out;
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { out += '\\'; out += static_cast<char>(ch); }
        else if (ch < 32) { out += "\\u00"; out += digits[ch >> 4]; out += digits[ch & 15]; }
        else out += static_cast<char>(ch);
    }
    return out;
}
bool write_bytes(const std::string& path, const char* bytes, size_t size) {
    const int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t done = 0;
    while (done < size) {
        const ssize_t count = write(fd, bytes + done, size - done);
        if (count > 0) done += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
    return close(fd) == 0 && done == size;
}
bool read_bytes(const std::string& path, const char* expected, size_t size) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    std::array<char, 64> data{};
    const ssize_t count = read(fd, data.data(), data.size());
    const int closed = close(fd);
    return !closed && count == static_cast<ssize_t>(size) && !std::memcmp(data.data(), expected, size);
}
bool remove_tree(const std::string& path) {
    struct stat info{};
    if (lstat(path.c_str(), &info)) return errno == ENOENT;
    if (!S_ISDIR(info.st_mode)) return unlink(path.c_str()) == 0;
    DIR* directory = opendir(path.c_str());
    if (!directory) return false;
    bool ok = true;
    while (auto* entry = readdir(directory)) {
        if (!std::strcmp(entry->d_name, ".") || !std::strcmp(entry->d_name, "..")) continue;
        ok &= remove_tree(path + "/" + entry->d_name);
    }
    ok &= closedir(directory) == 0;
    return rmdir(path.c_str()) == 0 && ok;
}
class Environment {
public:
    void set(const char* key, const std::string& value) {
        const char* old = getenv(key);
        saved_.push_back({key, old ? old : "", old != nullptr});
        if (setenv(key, value.c_str(), 1)) valid_ = false;
    }
    bool valid() const { return valid_; }
    ~Environment() {
        for (auto it = saved_.rbegin(); it != saved_.rend(); ++it)
            if (it->present) setenv(it->key.c_str(), it->value.c_str(), 1);
            else unsetenv(it->key.c_str());
        tzset();
    }
private:
    struct Saved { std::string key, value; bool present; };
    std::vector<Saved> saved_;
    bool valid_ = true;
};
struct Suite {
    Suite(HleRuntime& owner, std::array<Check, 6>& results, const std::string& directory)
        : runtime(owner), checks(results), root(directory) {}
    HleRuntime& runtime;
    std::array<Check, 6>& checks;
    const std::string& root;
    bool calls_valid = true;
    std::string missing;
    uint64_t held_file = UINT64_MAX;
    unsigned save_notifications = 0;
    int save_error = 0;
    uint64_t invoke(const char* key, std::initializer_list<uint64_t> arguments = {}) {
        uintptr_t address = 0;
        const std::string name = std::string("service_") + key;
        if (!runtime.process().symbol(name.c_str(), &address) || arguments.size() > 8) {
            calls_valid = false; missing = name; return UINT64_MAX;
        }
        std::array<uint64_t, 8> slots{};
        std::copy(arguments.begin(), arguments.end(), slots.begin());
        return reinterpret_cast<uint64_t (*)(const uint64_t*)>(address)(slots.data());
    }
    bool wait(const Event& event, uint64_t duration = 0) {
        const uint32_t handle = event.readable;
        return invoke("wait", {0, ptr(&handle), 1, duration}) == 0;
    }
    bool quiet(const Event& event) {
        const uint32_t handle = event.readable;
        return event.writable && handle && invoke("wait", {0, ptr(&handle), 1, 0}) == timeout;
    }
    bool file(const char* path, const char* expected, size_t size) {
        uint64_t handle = UINT64_MAX;
        if (invoke("open_file", {ptr(&handle), ptr(path), 1})) return false;
        size_t got = 0;
        std::array<char, 64> bytes{};
        int64_t length = -1;
        const bool ok = invoke("file_mode", {handle}) == 1 &&
            invoke("get_size", {ptr(&length), handle}) == 0 && length == static_cast<int64_t>(size) &&
            invoke("read_file", {ptr(&got), handle, 0, ptr(bytes.data()), bytes.size()}) == 0 &&
            got == size && !std::memcmp(bytes.data(), expected, size);
        invoke("close_file", {handle});
        return ok;
    }
    bool replace(const char* data) {
        uint64_t handle = UINT64_MAX;
        if (invoke("open_file", {ptr(&handle), ptr("save:/hero.d2s"), 2})) return false;
        const uint64_t option = 0;
        bool ok = invoke("set_size", {handle, 3}) == 0;
        ok &= invoke("write_file", {handle, 0, ptr(data), 3, ptr(&option)}) == 0;
        ok &= invoke("flush_file", {handle}) == 0;
        invoke("close_file", {handle});
        return ok;
    }
};
void save_failure(int error, void* context) {
    auto& suite = *static_cast<Suite*>(context);
    ++suite.save_notifications;
    suite.save_error = error;
}
void* signal_event(void* event) {
    timespec remaining{0, 20000000};
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    hle_signal_system_event(event);
    return nullptr;
}
extern "C" uint64_t service_suite_entry(uint64_t pointer) {
    auto& suite = *reinterpret_cast<Suite*>(pointer);
    auto& c = suite.checks;
    User user{};
    uint64_t uid[2]{}, listed[2]{};
    int count = -1;
    char nickname[33]{};
    size_t token_size = 99;
    char token[16] = "unchanged";
    c[0].passed = suite.invoke("list_users", {ptr(&count), ptr(listed), 1}) == 0 && count == 1 &&
        suite.invoke("open_user", {ptr(&user)}) == 1 &&
        suite.invoke("user_id", {ptr(uid), ptr(&user)}) == 0 &&
        uid[0] == 0x78626c0000000001ull && uid[1] == 0x53574e4154495645ull &&
        !std::memcmp(uid, listed, sizeof uid) && user.word[2] == 0x55534552484e444cull &&
        suite.invoke("nickname", {ptr(nickname), ptr(uid)}) == 0 && !std::strcmp(nickname, "Android Probe") &&
        suite.invoke("ensure_network", {ptr(&user)}) == failed &&
        suite.invoke("token", {ptr(&token_size), ptr(token), sizeof token, ptr(&user)}) == failed &&
        token_size == 0 && !std::strcmp(token, "unchanged");
    int aoc = -1;
    uint32_t masks[2]{0xffffffff, 0xffffffff};
    const char* words[] = {"Player", "self-authored"};
    c[0].passed &= suite.invoke("aoc_count") == 1 && suite.invoke("aoc_list", {ptr(&aoc), 0, 1}) == 1 && aoc == 1 &&
        suite.invoke("aoc_list", {ptr(&aoc), 1, 1}) == 0 &&
        suite.invoke("profanity", {ptr(&user), ptr(masks), 0, ptr(words), 2}) == 0 && !masks[0] && !masks[1];
    c[0].detail = "Imported original shared C: one fixed local user/handle/nickname, offline token failure, Warlock entitlement 1 and empty profanity masks";

    Event account, authorization, friends, dlc;
    bool events = suite.invoke("account_event", {ptr(&user), ptr(&account)}) == 0 && suite.wait(account) &&
        suite.invoke("account_result", {ptr(&user)}) == failed &&
        suite.invoke("auth_event", {ptr(&user), ptr(&authorization)}) == 0 && suite.wait(authorization) &&
        suite.invoke("auth_result", {ptr(&user)}) == failed &&
        suite.invoke("friends_event", {ptr(&user), ptr(&friends)}) == 0 && suite.wait(friends) &&
        suite.invoke("friends_result", {ptr(&user)}) == failed;
    token_size = 99;
    events &= suite.invoke("auth_token", {ptr(&user), ptr(&token_size), ptr(token), sizeof token}) == failed && token_size == 0;
    suite.invoke("aoc_event", {ptr(&dlc)});
    auto* notify = reinterpret_cast<Event*>(suite.invoke("friends_notify", {ptr(&user)}));
    auto* invite = reinterpret_cast<Event*>(suite.invoke("friends_invite"));
    events &= notify && invite && notify != invite && suite.quiet(dlc);
    if (notify && invite) events &= suite.quiet(*notify) && suite.quiet(*invite);
    unsigned before = 0, live = 0, objects = 0, after = 0;
    dm_android_kernel_thread_stats(&before, &live, &objects);
    for (unsigned i = 0; i < 4; ++i) {
        events &= suite.invoke("account_event", {ptr(&user), ptr(&account)}) == 0;
        suite.invoke("aoc_event", {ptr(&dlc)});
        events &= suite.invoke("friends_notify", {ptr(&user)}) == ptr(notify) && suite.invoke("friends_invite") == ptr(invite);
    }
    dm_android_kernel_thread_stats(&after, &live, &objects);
    events &= before == after && suite.quiet(dlc);
    pthread_t thread{};
    const bool created = pthread_create(&thread, nullptr, signal_event, &dlc) == 0;
    events &= created;
    if (created) { events &= suite.wait(dlc, 1000000000); events &= pthread_join(thread, nullptr) == 0; }
    events &= suite.runtime.svc_count(0x45) == 6;
    c[1].passed = events;
    c[1].detail = "Real rewritten SDK CreateEvent: three failed async completions signal, DLC/notification/invitation remain independently quiet, repeat binding reuses handles, host signal satisfies kernel wait";

    int64_t sdk = -1, now = -1;
    Calendar calendar{};
    Additional additional{};
    c[2].passed = suite.invoke("sdk_time", {ptr(&sdk)}) == 0x3456 && sdk == 0x3456 &&
        suite.invoke("user_time", {ptr(&now)}) == 0 && now == 1700000000 &&
        suite.invoke("time_now") == 1700000000 &&
        suite.invoke("calendar", {ptr(&calendar), ptr(&additional), ptr(&now)}) == 0 &&
        calendar.year == 2023 && calendar.month == 11 && calendar.day == 14 && calendar.hour == 22 &&
        calendar.minute == 13 && calendar.second == 20 && additional.offset == 0 && additional.dst == 0;
    const auto* local = reinterpret_cast<const tm*>(suite.invoke("localtime", {ptr(&now)}));
    bool zone = local && local->tm_zone && !std::strcmp(local->tm_zone, "UTC");
    if (zone) {
        MemoryInfo information{};
        const uint64_t address = ptr(local->tm_zone);
        const size_t bytes = std::strlen(local->tm_zone) + 1;
        zone = dm_android_kernel_memory_accessible(address, bytes, 0) &&
            !dm_android_kernel_memory_accessible(address, bytes, 1) &&
            suite.invoke("query_memory", {ptr(&information), 0, address}) == 0 &&
            information.base == address && information.size == bytes && information.permissions == 1;
    }
    c[2].passed &= zone;
    c[2].detail = "Forced time forwards to current SDK; fixed clock converts to 2023-11-14 22:13:20 UTC; original localtime timezone span is readable, refuses writes and QueryMemory reports permission 1";

    const uint64_t writes_before = prepared_writes.load();
    size_t cache_size = 0;
    bool filesystem = suite.invoke("rom_cache_size", {ptr(&cache_size)}) == 0 && cache_size == 0x1000 &&
        suite.invoke("mount_rom", {ptr("rom"), 0, 0}) == 0 &&
        suite.invoke("mount_temp", {ptr("temp")}) == 0 &&
        suite.invoke("ensure_save", {ptr(uid)}) == 0 &&
        suite.invoke("mount_save", {ptr("save"), ptr(uid)}) == 0;
    filesystem &= suite.file("rom:/asset.data", "OVERLAY", 7) && suite.file("rom:/sparse.data", "AB\0\0EF\0\0", 8);
    uint64_t handle = UINT64_MAX;
    filesystem &= suite.invoke("open_file", {ptr(&handle), ptr("rom:/case.data"), 1}) == 0x202 &&
        suite.invoke("create_file", {ptr("rom:/forbidden"), 1}) != 0 &&
        suite.invoke("open_file", {ptr(&handle), ptr("rom:/Case.data"), 2}) != 0;
    filesystem &= suite.invoke("create_dir", {ptr("temp:/directory")}) == 0 &&
        suite.invoke("create_file", {ptr("temp:/directory/a"), 0}) == 0 &&
        suite.invoke("rename_file", {ptr("temp:/directory/a"), ptr("temp:/directory/A")}) == 0;
    int32_t type = -1;
    filesystem &= suite.invoke("entry_type", {ptr(&type), ptr("temp:/directory/A")}) == 0 && type == 1;
    uint64_t directory = 0;
    const bool opened = suite.invoke("open_dir", {ptr(&directory), ptr("temp:/directory"), 3}) == 0;
    filesystem &= opened;
    if (opened) {
        DirectoryEntry entry[2]{}; int64_t entries = -1;
        filesystem &= suite.invoke("read_dir", {ptr(&entries), ptr(entry), directory, 2}) == 0 && entries == 1 &&
            !std::strcmp(entry[0].name, "A") && entry[0].type == 1;
        suite.invoke("close_dir", {directory});
    }
    filesystem &= suite.invoke("delete_file", {ptr("temp:/directory/A")}) == 0 &&
        suite.invoke("delete_dir", {ptr("temp:/directory")}) == 0;
    c[3].passed = filesystem && prepared_writes.load() > writes_before;
    c[3].detail = "Imported filesystem operations preserve overlay precedence, sparse logical bytes/size, exact case, ROM read-only, file/directory operations and real guest-write preparation callbacks";

    for (size_t i = 0; i < 4; ++i) {
        c[i].passed &= suite.calls_valid;
        if (!c[i].passed) c[i].detail = std::string("Service assertion failed: ") + c[i].detail +
            (suite.missing.empty() ? "" : "; missing=" + suite.missing);
    }
    return suite.calls_valid ? 1 : 0;
}
extern "C" uint64_t service_save_entry(uint64_t pointer) {
    auto& suite = *reinterpret_cast<Suite*>(pointer);
    bool save = suite.file("save:/hero.d2s", "OLD", 3) && suite.replace("NEW") &&
        suite.invoke("commit", {ptr("save")}) == 0 && read_bytes(suite.root + "/save/hero.d2s", "NEW", 3);
    save &= suite.replace("BAD");
    dm_fs_save_poison(EIO);
    save &= suite.invoke("commit", {ptr("save")}) != 0 && suite.save_notifications == 1 &&
        suite.save_error == EIO && dm_android_save_failure_count() == 1 && dm_android_last_save_error() == EIO &&
        read_bytes(suite.root + "/save/hero.d2s", "NEW", 3) && suite.file("save:/hero.d2s", "NEW", 3);
    save &= suite.replace("LOS"); // Uncommitted bytes must be discarded at remount.
    suite.checks[4].passed = save && suite.calls_valid;
    suite.invoke("unmount", {ptr("save")}); // Original SDK host contract: intentional no-op.
    suite.checks[4].detail = "On a 32KiB guest stack, actual save copy/exchange publishes NEW; poisoned BAD refuses commit and restores NEW; reset/remount discards uncommitted work";
    if (!suite.checks[4].passed) suite.checks[4].detail = "Service assertion failed: " + suite.checks[4].detail;
    return suite.calls_valid ? 1 : 0;
}
extern "C" uint64_t service_remount_entry(uint64_t pointer) {
    auto& suite = *reinterpret_cast<Suite*>(pointer);
    const uint64_t uid[2]{0x78626c0000000001ull, 0x53574e4154495645ull};
    const bool remounted = suite.invoke("mount_save", {ptr("save"), ptr(uid)}) == 0 &&
        suite.file("save:/hero.d2s", "NEW", 3);
    suite.checks[4].passed &= remounted;
    if (!remounted) suite.checks[4].detail += "; remount did not restore committed NEW";
    if (suite.invoke("open_file", {ptr(&suite.held_file), ptr("save:/hero.d2s"), 1}) != 0) suite.held_file = UINT64_MAX;
    return remounted && suite.calls_valid ? 1 : 0;
}
extern "C" uint64_t service_close_entry(uint64_t pointer) {
    auto& suite = *reinterpret_cast<Suite*>(pointer);
    std::array<char, 4> bytes{};
    size_t size = 0;
    const bool ok = suite.held_file != UINT64_MAX && suite.invoke("read_file",
        {ptr(&size), suite.held_file, 0, ptr(bytes.data()), 3}) == 0 && size == 3 && !std::memcmp(bytes.data(), "NEW", 3);
    if (suite.held_file != UINT64_MAX) suite.invoke("close_file", {suite.held_file});
    suite.held_file = UINT64_MAX;
    return ok ? 1 : 0;
}
uint64_t audio_now() {
    timespec value{}; clock_gettime(CLOCK_MONOTONIC, &value);
    return static_cast<uint64_t>(value.tv_sec) * 1000000000ULL + static_cast<uint64_t>(value.tv_nsec);
}
void audio_pause() {
    timespec remaining{0, 5000000};
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
}
struct AudioBuffer { uint64_t pointer = 0, capacity = 0, bytes = 0; };
static_assert(sizeof(AudioBuffer) == 24, "original AudioOutBuffer prefix");
struct AudioSuite {
    AudioSuite(HleRuntime& runtime, std::array<Check, 6>& checks) : calls(runtime, checks, empty) {}
    std::string empty, failure;
    Suite calls;
    const void* final_output = nullptr;
    uint64_t released = 0, background_released = 0, event_waits = 0;
    uint64_t start_result = UINT64_MAX;
    int refused_suspended = 0, refused_backend_error = 0;
    int diagnostic_guest_focus_grant = -1;
    bool copied = false;
    dm_android_audio_status playing{}, background{}, resumed{}, final_status{};
    uint64_t fail(const char* message) { failure = message; return 0; }
    template<class Predicate> bool status(const void* object, dm_android_audio_status* out, Predicate accept,
                                        uint64_t duration = 10000000000ULL,
                                        const std::function<bool()>& pump = {}) {
        const uint64_t deadline = audio_now() + duration;
        do {
            if (pump && !pump()) return false;
            int suspended = 0;
            if (!dm_android_audio_out_status(object, out, &suspended)) return false;
            if (accept(*out, suspended)) return true;
            audio_pause();
        } while (audio_now() < deadline);
        return false;
    }
};
extern "C" uint64_t service_audio_entry(uint64_t pointer) {
    auto& audio = *reinterpret_cast<AudioSuite*>(pointer);
    auto& suite = audio.calls;
    auto& checks = suite.checks;
    constexpr unsigned channels = 6, frames = 4800, count = 6;
    constexpr size_t payload = frames * channels * sizeof(int16_t);
    std::array<uint8_t, 64> output{}, final_output{};
    std::array<uint8_t, 8> parameters{};
    Event event{}, final_event{};
    std::array<AudioBuffer, count> buffers{};
    // This is actual guarded guest-stack memory. Each submitted block fits the
    // checked-copy owner limit; no host-owned or unregistered PCM pointer is used.
    std::array<std::array<int16_t, frames * channels>, count> pcm{};
    auto append = [&](unsigned index) {
        for (unsigned frame = 0; frame < frames; ++frame)
            for (unsigned channel = 0; channel < channels; ++channel)
                pcm[index][frame * channels + channel] = frame % 96 < 48 ? 768 : -768;
        suite.invoke("audio_set_buffer", {ptr(&buffers[index]), ptr(pcm[index].data()), payload, payload});
        const bool valid = suite.invoke("audio_buffer_pointer", {ptr(&buffers[index])}) == ptr(pcm[index].data()) &&
            suite.invoke("audio_buffer_size", {ptr(&buffers[index])}) == payload &&
            suite.invoke("audio_append", {ptr(output.data()), ptr(&buffers[index])}) == 1;
        // The callback must use the accepted owned snapshot, even when the
        // guest immediately changes both descriptor and original PCM bytes.
        pcm[index].fill(0);
        buffers[index] = {1, 0, UINT64_MAX};
        return valid;
    };
    auto drain = [&]() {
        unsigned got = 0;
        while (got < 64) {
            const uint64_t value = suite.invoke("audio_released", {ptr(output.data())});
            if (!value) return static_cast<int>(got);
            const unsigned index = static_cast<unsigned>(audio.released % count);
            if (value != ptr(&buffers[index]) || !append(index)) return -1;
            ++audio.released; ++got;
        }
        return -1;
    };
    auto released_event = [&]() {
        const uint64_t deadline = audio_now() + 3000000000ULL;
        do {
            if (!suite.wait(event, 1000000000ULL)) return false;
            ++audio.event_waits;
            if (suite.invoke("clear_event", {event.writable}) != 0) return false;
            const int got = drain();
            if (got < 0) return false;
            if (got) return true;
        } while (audio_now() < deadline);
        return false;
    };
    suite.invoke("audio_init", {ptr(parameters.data())});
    const uint16_t requested_channels = channels;
    std::memcpy(parameters.data() + 4, &requested_channels, sizeof requested_channels);
    if (suite.invoke("audio_open", {ptr(output.data()), ptr(&event), 0, ptr(parameters.data())}) != 0)
        return audio.fail("original imported OpenAudioOut refused");
    checks[0].passed = suite.invoke("audio_state", {ptr(output.data())}) == 1 &&
        suite.invoke("audio_rate", {ptr(output.data())}) == 48000 &&
        suite.invoke("audio_channels", {ptr(output.data())}) == channels &&
        suite.invoke("audio_format", {ptr(output.data())}) == 2 && event.writable && event.readable;
    checks[0].detail = "Rewritten guest imports resolve original AudioOut; authored SDK executes actual CreateEvent SVC and returns real readable/writable handles";
    if (!checks[0].passed) return audio.fail("AudioOut parameter/event ABI mismatch");
    for (unsigned i = 0; i < count; ++i) if (!append(i)) return audio.fail("owned guest PCM Append refused");
    audio.copied = true;
    audio.start_result = suite.invoke("audio_start", {ptr(output.data())});
    if (audio.start_result != 0) {
        dm_android_audio_status refused{};
        dm_android_audio_out_status(output.data(), &refused, &audio.refused_suspended);
        audio.refused_backend_error = refused.last_error;
        audio.diagnostic_guest_focus_grant = dm_android_audio_focus_acquire();
        if (audio.diagnostic_guest_focus_grant) dm_android_audio_focus_release();
        return audio.fail("original imported StartAudioOut refused before event wait");
    }
    if (!released_event()) return audio.fail("released-buffer SystemEvent wait failed");
    if (!audio.status(output.data(), &audio.playing, [](const auto& value, int suspended) {
            return !suspended && value.callbacks && value.nonzero_samples && value.timestamp_valid && value.presented_frames > 0;
        }, 3000000000ULL, [&] { return drain() >= 0; })) return audio.fail("HLE output did not reach real nonzero PCM presentation");
    checks[1].passed = audio.copied && audio.released && audio.event_waits;
    checks[1].detail = "Original Append copied guarded guest PCM; changing source/descriptors afterward preserved nonzero AAudio output, ordered original handles and real SystemEvent wakeups";

    audio_phase.store(2, std::memory_order_release);
    if (!audio.status(output.data(), &audio.background, [](const auto&, int suspended) { return suspended != 0; },
                      10000000000ULL, [&] { return drain() >= 0; }))
        return audio.fail("Activity did not suspend its actual HLE output");
    const uint64_t callbacks = audio.background.callbacks;
    const int stale = drain();
    if (stale < 0 || suite.invoke("clear_event", {event.writable}) != 0) return audio.fail("background release drain failed");
    const uint64_t before_background = audio.released;
    if (!released_event())
        return audio.fail("background pacing did not release through the actual SystemEvent");
    int background_state = 0;
    if (!dm_android_audio_out_status(output.data(), &audio.background, &background_state)) return audio.fail("background HLE output disappeared");
    audio.background_released = audio.released - before_background;
    checks[2].passed = background_state && audio.background_released && audio.background.callbacks == callbacks && !audio.background.running;
    checks[2].detail = "Actual Activity pause quiesced AAudio; original explicit background pacing still released copied buffers and signaled the SDK-created kernel event";
    if (!checks[2].passed) return audio.fail("background callbacks or queue pacing violated ownership");
    audio_phase.store(3, std::memory_order_release);
    if (!audio.status(output.data(), &audio.resumed, [&](const auto& value, int suspended) {
            return !suspended && value.callbacks > callbacks && value.nonzero_samples > audio.background.nonzero_samples &&
                value.timestamp_valid && value.presented_frames > 0;
        }, 15000000000ULL, [&] { return drain() >= 0; })) return audio.fail("foreground replacement did not resume actual HLE PCM");
    checks[3].passed = released_event();
    checks[3].detail = "Current Activity reacquired real focus; the registered HLE output resumed nonzero AAudio callbacks/presentation and ordered released handles";
    if (!checks[3].passed) return audio.fail("resumed SystemEvent/buffer retrieval failed");
    audio_phase.store(4, std::memory_order_release);

    suite.invoke("audio_stop", {ptr(output.data())});
    dm_android_audio_status stopped{}, stable{}; int suspended = 0;
    if (!dm_android_audio_out_status(output.data(), &stopped, &suspended)) return audio.fail("stopped output missing");
    const uint64_t deadline = audio_now() + 100000000ULL;
    while (audio_now() < deadline) audio_pause();
    checks[4].passed = suite.invoke("audio_state", {ptr(output.data())}) == 1 &&
        dm_android_audio_out_status(output.data(), &stable, &suspended) && !stable.running && stable.callbacks == stopped.callbacks;
    suite.invoke("audio_close", {ptr(output.data())});
    checks[4].passed &= !dm_android_audio_out_status(output.data(), &stable, &suspended);
    checks[4].detail = "Original imported Stop quiesced callbacks; Close joined device/notifier workers and removed the actual output";
    if (!checks[4].passed) return audio.fail("Stop/Close left an output or callbacks alive");

    if (suite.invoke("audio_open", {ptr(final_output.data()), ptr(&final_event), 0, ptr(parameters.data())}) != 0)
        return audio.fail("shutdown fixture output open failed");
    for (unsigned frame = 0; frame < frames; ++frame) for (unsigned channel = 0; channel < channels; ++channel)
        pcm[0][frame * channels + channel] = frame % 96 < 48 ? 768 : -768;
    suite.invoke("audio_set_buffer", {ptr(&buffers[0]), ptr(pcm[0].data()), payload, payload});
    if (suite.invoke("audio_append", {ptr(final_output.data()), ptr(&buffers[0])}) != 1 ||
        suite.invoke("audio_start", {ptr(final_output.data())}) != 0) return audio.fail("active shutdown fixture failed to start");
    pcm[0].fill(0); buffers[0] = {1, 0, UINT64_MAX};
    if (!audio.status(final_output.data(), &audio.final_status, [](const auto& value, int suspended_state) {
            return !suspended_state && value.callbacks && value.nonzero_samples;
        }, 3000000000ULL)) return audio.fail("shutdown output never produced actual PCM");
    audio.final_output = final_output.data();
    return suite.calls_valid ? 1 : 0;
}
bool load(HleRuntime& runtime, std::string* error) {
    std::vector<std::unique_ptr<ModulePackage>> packages;
    struct Blob { const uint8_t* bytes; size_t size; const uint8_t* digest; };
    for (const Blob& blob : {Blob{dm_service_main_bytes, dm_service_main_size, dm_service_main_package_sha256},
                             Blob{dm_service_sdk_bytes, dm_service_sdk_size, dm_service_sdk_package_sha256}}) {
        std::unique_ptr<ModulePackage> package;
        if (!decode_package(blob.bytes, blob.size, blob.digest, &package, error)) return false;
        packages.push_back(std::move(package));
    }
    return runtime.load(std::move(packages), false, nullptr, nullptr, error);
}
} // namespace

std::string dm_android_run_service_probes(const std::string& files, const std::string& cache,
                                        const std::string& locale) {
    (void)cache;
    std::array<Check, 6> checks{{Check("account"), Check("events"), Check("time"), Check("filesystem"), Check("save_transactions"), Check("lifetime")}};
    std::vector<char> pattern(files.begin(), files.end());
    constexpr char suffix[] = "/dm-services-XXXXXX";
    pattern.insert(pattern.end(), suffix, suffix + sizeof suffix);
    const char* created = mkdtemp(pattern.data());
    const std::string root = created ? created : "";
    bool prepared = !root.empty();
    std::string preparation_error = prepared ? "" : "mkdtemp failed errno=" + std::to_string(errno);
    for (const char* directory : {"rom", "overlay", "save", "temp"})
        if (prepared && mkdir((root + "/" + directory).c_str(), 0700)) {
            prepared = false; preparation_error = std::string("mkdir ") + directory + " errno=" + std::to_string(errno);
        }
    if (prepared) prepared = write_bytes(root + "/rom/asset.data", "BASE", 4) &&
        write_bytes(root + "/overlay/asset.data", "OVERLAY", 7) &&
        write_bytes(root + "/rom/Case.data", "case", 4) &&
        write_bytes(root + "/rom/sparse.data", "ABEF", 4) &&
        write_bytes(root + "/rom/sparse.data.holes", "size 8\n2 2\n6 2\n", 15) &&
        write_bytes(root + "/save/hero.d2s", "OLD", 3);
    if (!prepared && preparation_error.empty()) preparation_error = "fixture file creation failed errno=" + std::to_string(errno);
    std::string error;
    bool teardown = false;
    {
        Environment environment;
        environment.set("DM_ROMFS", root + "/rom"); environment.set("DM_ROMFS_OVERLAY", root + "/overlay");
        environment.set("DM_SAVE", root + "/save"); environment.set("DM_TEMP", root + "/temp");
        environment.set("DM_NICK", "Android Probe"); environment.set("DM_AOC_OWNED", "1");
        environment.set("DM_FIXED_TIME", "1700000000"); environment.set("DM_TOUCH_DEFAULTS", "0");
        environment.set("DM_LANG", locale.empty() ? "en-US" : locale); environment.set("TZ", "UTC"); tzset();
        HleRuntime runtime;
        GuestEnvironment guest;
        GuestStack stack(512 * 1024);
        GuestStack small_stack(32 * 1024);
        Suite suite{runtime, checks, root};
        bool ready = false;
        if (!prepared) error = preparation_error;
        else if (!environment.valid()) error = "environment setenv failed errno=" + std::to_string(errno);
        else if (!stack.valid()) error = "guest stack: " + stack.error();
        else if (!small_stack.valid()) error = "32KiB guest stack: " + small_stack.error();
        else if (!dm_android_app_services_prepare(locale.c_str(), root.c_str()))
            error = "app services prepare failed errno=" + std::to_string(errno) + " locale=" + locale;
        else if (load(runtime, &error)) ready = true;
        else if (error.empty()) error = "service module load failed without diagnostic";
        bool ran = false;
        if (ready) {
            dm_guest_write_prep_register(prepare_write);
            dm_android_save_failure_listener(save_failure, &suite);
            runtime.configure(guest.state);
            GuestCallResult result;
            if (!runtime.register_main()) error = "main thread registration failed";
            else if (stack.call(guest.state, reinterpret_cast<uintptr_t>(&service_suite_entry), ptr(&suite), &result, &error)) {
                ran = !result.exited && result.value == 1;
                if (!ran) error = "service suite returned value=" + std::to_string(result.value) +
                    " exited=" + std::to_string(result.exited) + " missing=" + suite.missing;
            }
        }
        const bool suite_ran = ran;
        if (ran) {
            GuestCallResult result;
            ran = small_stack.call(guest.state, reinterpret_cast<uintptr_t>(&service_save_entry),
                ptr(&suite), &result, &error) && !result.exited && result.value == 1;
            if (!ran && error.empty()) error = "32KiB save invocation failed";
        }
        // Reset only while no guest invocation executes; all service-suite
        // handles are closed. Keep the runtime/module bridge alive for remount.
        if (ran) {
            const bool reset = dm_android_fs_reset() == 1;
            GuestCallResult result;
            ran = reset && small_stack.call(guest.state, reinterpret_cast<uintptr_t>(&service_remount_entry),
                ptr(&suite), &result, &error) && !result.exited && result.value == 1;
            if (!ran && error.empty()) error = reset ? "remount did not expose committed NEW" :
                "FS reset refused errno=" + std::to_string(errno);
        }
        const std::string execution_error = error;
        const bool busy = ran && suite.held_file != UINT64_MAX && !runtime.shutdown(&error) &&
            !runtime.process().modules().empty() && dm_android_fs_has_open_handles();
        bool survived = false;
        if (ready && suite.held_file != UINT64_MAX) {
            GuestCallResult result;
            survived = small_stack.call(guest.state, reinterpret_cast<uintptr_t>(&service_close_entry),
                ptr(&suite), &result, &error) && !result.exited && result.value == 1;
        }
        teardown = runtime.shutdown(&error);
        if (!ready) dm_android_app_services_reset();
        unsigned handles = 0, live = 0, objects = 0;
        dm_android_kernel_thread_stats(&handles, &live, &objects);
        checks[5].passed = ran && busy && survived && teardown && !handles && !live && !objects &&
            runtime.process().modules().empty() && !dm_android_peek_guest_state() && !dm_android_fs_has_open_handles();
        checks[5].detail = checks[5].passed ? "Live FS handle rejects shutdown without unpublishing; resumed read/close succeeds, then modules/kernel/service/FS state release" : "Runtime lifetime failed: " + error;
        if (!suite_ran) for (size_t i = 0; i < 5; ++i) {
            checks[i].passed = false;
            checks[i].detail = "Service setup/call failed: " + execution_error + "; " + checks[i].detail;
        }
    }
    const bool cleaned = !root.empty() && remove_tree(root) && remove_tree(root + ".work") && remove_tree(root + ".new");
    checks[5].passed &= cleaned && teardown;
    if (!cleaned) checks[5].detail += "; private fixture cleanup failed";
    std::ostringstream json;
    json << "{\"schemaVersion\":5,\"phase\":\"3\",\"syntheticOnly\":true,\"gamePlayable\":false,\"environment\":{\"pageSize\":"
         << sysconf(_SC_PAGESIZE) << ",\"abi\":\"arm64-v8a\"},\"checks\":[";
    for (size_t i = 0; i < checks.size(); ++i) {
        if (i) json << ',';
        json << "{\"id\":\"" << checks[i].id << "\",\"status\":\"" << (checks[i].passed ? "PASS" : "FAIL")
             << "\",\"detail\":\"" << escape(checks[i].detail) << "\"}";
    }
    json << "],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return json.str();
}

unsigned dm_android_audio_probe_phase() { return audio_phase.load(std::memory_order_acquire); }

std::string dm_android_run_audio_probes() {
    audio_phase.store(1, std::memory_order_release);
    std::array<Check, 6> checks{{Check("imports"), Check("pcm_release_event"), Check("background_pacing"),
        Check("resume"), Check("stop_close"), Check("shutdown")}};
    HleRuntime runtime;
    GuestEnvironment guest;
    GuestStack stack(1024 * 1024);
    AudioSuite audio(runtime, checks);
    std::string error;
    bool ran = false;
    if (!stack.valid()) error = "audio guest stack: " + stack.error();
    else if (load(runtime, &error)) {
        runtime.configure(guest.state);
        GuestCallResult result;
        if (!runtime.register_main()) error = "audio main registration failed";
        else if (stack.call(guest.state, reinterpret_cast<uintptr_t>(&service_audio_entry), ptr(&audio), &result, &error)) {
            ran = !result.exited && result.value == 1 && audio.calls.calls_valid;
            if (!ran) error = "audio guest returned value=" + std::to_string(result.value) +
                " exited=" + std::to_string(result.exited) + "; " + audio.failure + "; missing=" + audio.calls.missing;
        }
    }
    unsigned bindings = 0;
    for (const char* name : dm_service_audio_imports) bindings += runtime.registry().force_hits(name) != 0;
    checks[0].passed &= bindings == sizeof(dm_service_audio_imports) / sizeof(dm_service_audio_imports[0]);
    const uint64_t create_events = runtime.svc_count(0x45), waits = runtime.svc_count(0x18);
    // Failure-only comparison, never a passing workaround: distinguish a JNI
    // dispatch made on the guest stack from the same current Activity's normal
    // host-stack focus path. Successful probe execution does not take this lease.
    int diagnostic_host_focus_grant = -1;
    if (!ran && audio.start_result != UINT64_MAX && audio.start_result != 0) {
        diagnostic_host_focus_grant = dm_android_audio_focus_acquire();
        if (diagnostic_host_focus_grant) dm_android_audio_focus_release();
    }
    const std::string execution_error = error;
    const bool teardown = runtime.shutdown(&error);
    const uint64_t callbacks_at_shutdown = dm_audio_render_calls();
    const uint64_t until = audio_now() + 100000000ULL;
    while (audio_now() < until) audio_pause();
    dm_android_audio_status removed{}; int suspended = 0;
    unsigned handles = 0, live = 0, objects = 0;
    dm_android_kernel_thread_stats(&handles, &live, &objects);
    checks[5].passed = ran && teardown && audio.final_output &&
        !dm_android_audio_out_status(audio.final_output, &removed, &suspended) &&
        dm_audio_render_calls() == callbacks_at_shutdown && runtime.process().modules().empty() &&
        !dm_android_peek_guest_state() && !handles && !live && !objects && create_events == 2;
    checks[5].detail = checks[5].passed ?
        "Quiescent runtime shutdown closed an active HLE output, joined audio/recovery/notifier workers before resetting both SDK-created events, and left zero modules/kernel objects or later callbacks" :
        "Audio runtime shutdown failed: " + error;
    if (!ran) for (auto& check : checks) if (!check.passed)
        check.detail = "Audio probe failed: " + execution_error + "; " + check.detail;
    bool passed = true;
    for (const auto& check : checks) passed &= check.passed;
    audio_phase.store(passed ? 5u : 6u, std::memory_order_release);
    std::ostringstream json;
    json << "{\"schemaVersion\":1,\"phase\":\"audio-hle\",\"syntheticOnly\":true,\"gamePlayable\":false,\"originalGameAudio\":false,\"checks\":[";
    for (size_t i = 0; i < checks.size(); ++i) {
        if (i) json << ',';
        json << "{\"id\":\"" << checks[i].id << "\",\"status\":\"" << (checks[i].passed ? "PASS" : "FAIL")
             << "\",\"detail\":\"" << escape(checks[i].detail) << "\"}";
    }
    json << "],\"audio\":{\"channels\":6,\"sampleRate\":48000,\"payloadBytes\":57600,\"importBindings\":" << bindings
         << ",\"startResult\":" << audio.start_result << ",\"refusedSuspended\":" << audio.refused_suspended
         << ",\"refusedBackendError\":" << audio.refused_backend_error << ",\"diagnosticHostFocusGrant\":" << diagnostic_host_focus_grant
         << ",\"diagnosticGuestFocusGrant\":" << audio.diagnostic_guest_focus_grant
         << ",\"createEventSvcCalls\":" << create_events << ",\"waitSvcCalls\":" << waits
         << ",\"releasedBuffers\":" << audio.released << ",\"eventWaits\":" << audio.event_waits
         << ",\"copiedGuestPcm\":" << (audio.copied ? "true" : "false")
         << ",\"playingCallbacks\":" << audio.playing.callbacks << ",\"playingNonzeroSamples\":" << audio.playing.nonzero_samples
         << ",\"playingPresentedFrames\":" << audio.playing.presented_frames
         << ",\"backgroundCallbacks\":" << audio.background.callbacks << ",\"backgroundReleasedBuffers\":" << audio.background_released
         << ",\"resumedCallbacks\":" << audio.resumed.callbacks << ",\"resumedNonzeroSamples\":" << audio.resumed.nonzero_samples
         << ",\"resumedPresentedFrames\":" << audio.resumed.presented_frames
         << ",\"callbacksAtShutdown\":" << callbacks_at_shutdown << ",\"teardownComplete\":" << (teardown ? "true" : "false") << "}}";
    return json.str();
}
