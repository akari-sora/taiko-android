#include "audio_platform.h"
#include <aaudio/AAudio.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <mutex>
#include <new>
#include <semaphore.h>
#include <thread>
#include <time.h>

static thread_local int32_t open_error = AAUDIO_OK;

struct DmAndroidAudioDevice {
    std::mutex control;
    AAudioStream* stream = nullptr;
    const int guest_channels;
    const int output_channels;
    const dm_android_audio_pull_fn pull;
    void* const context;
    sem_t wake{};
    std::thread recovery;
    bool wanted = false;
    std::atomic<bool> closing{false}, failed{false};
    std::atomic<int32_t> last_error{AAUDIO_OK};
    std::atomic<uint64_t> callbacks{0}, frames{0}, nonzero{0}, recoveries{0};
    // AAudio callback counts may vary. Allocate bounded staging with the device,
    // then consume every requested frame in chunks without callback allocation.
    static constexpr size_t mix_frames = 1024;
    int16_t mix_pcm[mix_frames * 6]{};

    DmAndroidAudioDevice(int count, dm_android_audio_pull_fn fn, void* ctx)
        : guest_channels(count), output_channels(count == 6 ? 2 : count), pull(fn), context(ctx) {}
    static int16_t mix_sample(int16_t front, int16_t center, int16_t rear) {
        // Same Q15 Lo/Ro gains as upstream: headroom on fronts, centre/rears
        // audible in both appropriate outputs, LFE omitted. Worst sum fits int32.
        const int32_t value = (23170 * front + 16384 * center + 16384 * rear) >> 15;
        return static_cast<int16_t>(value > 32767 ? 32767 : value < -32768 ? -32768 : value);
    }
    static aaudio_data_callback_result_t render(AAudioStream*, void* opaque, void* pcm, int32_t count) {
        auto* device = static_cast<DmAndroidAudioDevice*>(opaque);
        if (count <= 0) return AAUDIO_CALLBACK_RESULT_CONTINUE;
        const size_t samples = static_cast<size_t>(count) * static_cast<size_t>(device->output_channels);
        if (device->guest_channels != 6) device->pull(device->context, pcm, samples * sizeof(int16_t));
        else {
            auto* output = static_cast<int16_t*>(pcm);
            size_t remaining = static_cast<size_t>(count);
            while (remaining) {
                const size_t frames = remaining < mix_frames ? remaining : mix_frames;
                device->pull(device->context, device->mix_pcm, frames * 6 * sizeof(int16_t));
                for (size_t i = 0; i < frames; ++i) {
                    const int16_t* input = device->mix_pcm + i * 6;
                    output[i * 2] = mix_sample(input[0], input[2], input[4]);
                    output[i * 2 + 1] = mix_sample(input[1], input[2], input[5]);
                }
                output += frames * 2;
                remaining -= frames;
            }
        }
        uint64_t audible = 0;
        const auto* values = static_cast<const int16_t*>(pcm);
        for (size_t i = 0; i < samples; ++i) audible += values[i] != 0;
        device->callbacks.fetch_add(1, std::memory_order_relaxed);
        device->frames.fetch_add(static_cast<uint64_t>(count), std::memory_order_relaxed);
        device->nonzero.fetch_add(audible, std::memory_order_relaxed);
        return AAUDIO_CALLBACK_RESULT_CONTINUE;
    }
    static void error(AAudioStream*, void* opaque, aaudio_result_t value) {
        auto* device = static_cast<DmAndroidAudioDevice*>(opaque);
        device->last_error.store(value, std::memory_order_relaxed);
        device->failed.store(true, std::memory_order_release);
        // Never close, wait or allocate on AAudio's error callback thread.
        sem_post(&device->wake);
    }
    bool open_locked() {
        AAudioStreamBuilder* builder = nullptr;
        aaudio_result_t result = AAudio_createStreamBuilder(&builder);
        if (result != AAUDIO_OK) { last_error.store(result); return false; }
        AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_OUTPUT);
        AAudioStreamBuilder_setSharingMode(builder, AAUDIO_SHARING_MODE_SHARED);
        AAudioStreamBuilder_setPerformanceMode(builder, AAUDIO_PERFORMANCE_MODE_NONE);
        AAudioStreamBuilder_setUsage(builder, AAUDIO_USAGE_GAME);
        AAudioStreamBuilder_setContentType(builder, AAUDIO_CONTENT_TYPE_MUSIC);
        AAudioStreamBuilder_setSampleRate(builder, 48000);
        AAudioStreamBuilder_setChannelCount(builder, output_channels);
        AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16);
        AAudioStreamBuilder_setDataCallback(builder, render, this);
        AAudioStreamBuilder_setErrorCallback(builder, error, this);
        result = AAudioStreamBuilder_openStream(builder, &stream);
        AAudioStreamBuilder_delete(builder);
        if (result != AAUDIO_OK) { stream = nullptr; last_error.store(result); return false; }
        if (AAudioStream_getSampleRate(stream) != 48000 || AAudioStream_getChannelCount(stream) != output_channels ||
            AAudioStream_getFormat(stream) != AAUDIO_FORMAT_PCM_I16) {
            last_error.store(AAUDIO_ERROR_INVALID_FORMAT); close_locked(); return false;
        }
        return true;
    }
    void close_locked() {
        if (!stream) return;
        AAudioStream_requestStop(stream);
        // close is serialized with all other stream API access. It stops and
        // joins callbacks before the HLE changes consumers or frees context.
        AAudioStream_close(stream);
        stream = nullptr;
    }
    bool start_locked() {
        if (!stream && !open_locked()) return false;
        aaudio_result_t result = AAudioStream_requestStart(stream);
        if (result == AAUDIO_OK) {
            aaudio_stream_state_t state = AAudioStream_getState(stream);
            for (unsigned attempt = 0; state == AAUDIO_STREAM_STATE_STARTING && attempt < 10; ++attempt) {
                result = AAudioStream_waitForStateChange(stream, state, &state, 100000000);
                // A single wait timeout does not mean asynchronous start
                // failed. Recheck the actual state through the bounded budget.
                state = AAudioStream_getState(stream);
                if (result != AAUDIO_OK && result != AAUDIO_ERROR_TIMEOUT) break;
                if (state == AAUDIO_STREAM_STATE_STARTED) result = AAUDIO_OK;
            }
            if (result == AAUDIO_OK && state == AAUDIO_STREAM_STATE_STARTED) return true;
            if (result == AAUDIO_OK) result = AAUDIO_ERROR_INVALID_STATE;
        }
        last_error.store(result);
        close_locked();
        return false;
    }
    void recover() {
        while (!closing.load(std::memory_order_acquire)) {
            timespec until{}; clock_gettime(CLOCK_REALTIME, &until);
            until.tv_nsec += 250000000;
            if (until.tv_nsec >= 1000000000) { ++until.tv_sec; until.tv_nsec -= 1000000000; }
            while (sem_timedwait(&wake, &until) && errno == EINTR) {}
            if (closing.load(std::memory_order_acquire)) break;
            std::lock_guard<std::mutex> lock(control);
            if (failed.exchange(false, std::memory_order_acq_rel)) close_locked();
            if (wanted && !stream && start_locked()) recoveries.fetch_add(1, std::memory_order_relaxed);
        }
    }
};

extern "C" DmAndroidAudioDevice* dm_android_audio_device_open(int channels, dm_android_audio_pull_fn pull, void* context) {
    open_error = AAUDIO_OK;
    if (channels < 1 || channels > 8 || !pull) { open_error = AAUDIO_ERROR_ILLEGAL_ARGUMENT; return nullptr; }
    auto* device = new (std::nothrow) DmAndroidAudioDevice(channels, pull, context);
    if (!device) { open_error = AAUDIO_ERROR_NO_MEMORY; return nullptr; }
    if (sem_init(&device->wake, 0, 0)) { open_error = AAUDIO_ERROR_INTERNAL; delete device; return nullptr; }
    if (!device->open_locked()) { open_error = device->last_error.load(); sem_destroy(&device->wake); delete device; return nullptr; }
    try { device->recovery = std::thread([device] { device->recover(); }); }
    catch (...) { open_error = AAUDIO_ERROR_NO_MEMORY; device->close_locked(); sem_destroy(&device->wake); delete device; return nullptr; }
    return device;
}
extern "C" int32_t dm_android_audio_open_error() { return open_error; }
extern "C" int dm_android_audio_device_start(DmAndroidAudioDevice* device) {
    if (!device) return 0;
    std::lock_guard<std::mutex> lock(device->control);
    if (device->closing.load()) return 0;
    device->failed.store(false);
    device->wanted = true;
    const bool started = device->start_locked();
    if (!started) device->wanted = false;
    return started;
}
extern "C" void dm_android_audio_device_stop(DmAndroidAudioDevice* device) {
    if (!device) return;
    std::lock_guard<std::mutex> lock(device->control);
    device->wanted = false;
    device->close_locked();
}
extern "C" void dm_android_audio_device_close(DmAndroidAudioDevice* device) {
    if (!device) return;
    device->closing.store(true, std::memory_order_release);
    sem_post(&device->wake);
    device->recovery.join();
    dm_android_audio_device_stop(device);
    sem_destroy(&device->wake);
    delete device;
}
extern "C" int dm_android_audio_device_status(DmAndroidAudioDevice* device, dm_android_audio_status* status) {
    if (!device || !status) return 0;
    std::lock_guard<std::mutex> lock(device->control);
    *status = {};
    status->callbacks = device->callbacks.load(); status->frames = device->frames.load();
    status->nonzero_samples = device->nonzero.load(); status->recoveries = device->recoveries.load();
    status->last_error = device->last_error.load(); status->running = device->wanted && device->stream;
    if (device->stream) {
        status->stream_state = AAudioStream_getState(device->stream);
        status->device_id = AAudioStream_getDeviceId(device->stream);
        status->sample_rate = AAudioStream_getSampleRate(device->stream);
        status->channels = AAudioStream_getChannelCount(device->stream);
        status->format = AAudioStream_getFormat(device->stream);
        status->timestamp_valid = AAudioStream_getTimestamp(device->stream, CLOCK_MONOTONIC,
            &status->presented_frames, &status->presentation_time_ns) == AAUDIO_OK;
    }
    return 1;
}
