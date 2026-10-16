#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { DM_GAMEPAD_SOURCES = 6 };
typedef enum {
    DM_GAMEPAD_UNAVAILABLE = 0,
    DM_GAMEPAD_FULL_PRODUCT = 1,
    DM_GAMEPAD_DIAGNOSTIC_RAW = 2
} dm_gamepad_capability;
typedef struct {
    dm_gamepad_capability capability;
    void *context;
    void (*mode_request)(void *, int);
    int (*navigation)(void *);
    int (*zr_free)(void *, int zl);
    void (*portal_request)(void *);
} dm_gamepad_ops;
typedef struct { uint64_t identity, generation; } dm_gamepad_source;
typedef struct {
    uint64_t buttons, pending_buttons, cancellation_generation;
    int32_t axes[4];
    struct { uint64_t generation, pending_sequence[64]; } source[DM_GAMEPAD_SOURCES];
} dm_gamepad_sample;

/* Quiescent session initialization. FULL_PRODUCT requires every real consumer;
 * DIAGNOSTIC_RAW explicitly lacks gameplay capability and performs no callbacks. */
int dm_gamepad_core_configure(const dm_gamepad_ops *ops);
dm_gamepad_capability dm_gamepad_core_capability(void);
dm_gamepad_source dm_gamepad_source_register(uint64_t identity, uint64_t epoch);
int dm_gamepad_source_update(dm_gamepad_source source, uint64_t buttons,
                           const int32_t axes[4]);
int dm_gamepad_source_remove(dm_gamepad_source source);
void dm_gamepad_cancel_epoch(uint64_t epoch);
void dm_gamepad_sample_capture(dm_gamepad_sample *sample);
/* Joint sampler -> producer snapshot: prepare must run BEFORE acquiring the
 * sampler lock. Claimed capture/ack never drain, allocate or call consumers. */
void dm_gamepad_sample_prepare(void);
void dm_gamepad_sample_capture_claimed(dm_gamepad_sample *sample);
void dm_gamepad_sample_ack_claimed(const dm_gamepad_sample *sample);
void dm_gamepad_sample_ack(const dm_gamepad_sample *sample);
int dm_gamepad_sample_validate(const dm_gamepad_sample *sample);
/* Sampling linearization: validate cancellation and optionally acknowledge all
 * captured edge generations atomically, before externally visible filters.
 * Once claimed, later cancellation cannot roll back dispatched gameplay work. */
int dm_gamepad_sample_claim(const dm_gamepad_sample *sample, int consume);

/* Existing front-end entry points, now shared by platform adapters. Reset clears
 * current AND pending input, including already-neutral sources, retaining mode. */
int dm_gamepad_mode(void);
void dm_gamepad_touched(void);
void dm_gamepad_reset(void);
void dm_gamepad_inject_n(int n, uint64_t buttons, int32_t lx, int32_t ly,
                        int32_t rx, int32_t ry);
void dm_gamepad_drop_n(int n);
void dm_gamepad_inject(uint64_t buttons, int32_t lx, int32_t ly,
                      int32_t rx, int32_t ry);
#ifdef __cplusplus
}
#endif
