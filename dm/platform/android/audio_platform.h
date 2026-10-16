#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct DmAndroidAudioDevice DmAndroidAudioDevice;
typedef void (*dm_android_audio_pull_fn)(void* context, void* pcm, size_t bytes);
typedef struct {
    uint64_t callbacks, frames, nonzero_samples, recoveries;
    // channels is the actual AAudio stream format, not the guest AudioOut ABI.
    int32_t stream_state, device_id, sample_rate, channels, format, last_error;
    int64_t presented_frames, presentation_time_ns;
    int32_t timestamp_valid, running;
} dm_android_audio_status;

// Guest interleaved signed PCM16, 48kHz, channel count (1..8). Six-channel
// FL/FR/C/LFE/RL/RR is explicitly downmixed to stereo before actual AAudio
// output; pull still consumes all six guest samples per frame. Others pass through.
// No fallback sink: open/start return failure when the device refuses it.
DmAndroidAudioDevice* dm_android_audio_device_open(int channels, dm_android_audio_pull_fn pull, void* context);
// Exact error from this caller thread's latest open attempt (AAudio result).
int32_t dm_android_audio_open_error(void);
int dm_android_audio_device_start(DmAndroidAudioDevice* device);
// Stop returns after callbacks are quiescent; context may then be reclaimed.
void dm_android_audio_device_stop(DmAndroidAudioDevice* device);
void dm_android_audio_device_close(DmAndroidAudioDevice* device);
int dm_android_audio_device_status(DmAndroidAudioDevice* device, dm_android_audio_status* status);

// HLE lifecycle adapter. Call from ordinary control threads, never UI/AAudio
// callbacks. Reasons combine:1=Activity background,2=AudioManager interruption.
void dm_android_audio_set_suspended(unsigned reason, int on);
// Guest threads must be quiescent; invoke before retiring SystemEvents/runtime.
void dm_android_audio_shutdown(void);
// Read-only status of an actual registered HLE output, identified by its guest
// object address. Returns zero after Close/shutdown or for an unknown object.
int dm_android_audio_out_status(const void* guest_out, dm_android_audio_status* status, int* suspended);

// Supplied by the frontend focus owner. Acquire is requested only on Start;
// missing/denied focus is failure. Release balances each successful acquire.
int dm_android_audio_focus_acquire(void);
void dm_android_audio_focus_release(void);
#ifdef __cplusplus
}
#endif
