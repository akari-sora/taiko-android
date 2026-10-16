// Shared Npad sampler. Platform callbacks are immutable for a quiescent session.
#pragma once
#define DM_HID_CORE_INCLUDED 1
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    int64_t sampling;
    uint64_t buttons;
    int32_t lx, ly, rx, ry;
    uint32_t attributes, _pad;
} dm_hid_npad_state;
enum { DM_HID_STYLE_FULLKEY = 1, DM_HID_STYLE_HANDHELD = 2 };
enum { PK_LSL = 1u << 24, PK_LSR = 1u << 25, PK_LSU = 1u << 26,
       PK_LSD = 1u << 27, PK_MASK = 0xFu << 24, PK_TOUCH = 1u << 28,
       PK_MSG = 1u << 29, PK_CLICK = 1u << 30 };
typedef enum { DM_HID_UNCONFIGURED, DM_HID_FULL_PRODUCT, DM_HID_DIAGNOSTIC_RAW } dm_hid_mode;
typedef struct {
    const char *identity;
    void (*receipt_prepare)(void);
    void (*ui_taps)(void);
    void (*frontend)(void);
    void (*textinput)(void);
    void (*update)(void);
    void (*actions)(void);
    void (*world)(void);
    void (*ui_mouse)(void);
    void (*aim_cone)(void);
    uint64_t (*read_start)(void);
    uint64_t (*script_keys)(void);
    uint64_t (*auto_release)(void);
    uint64_t (*auto_buttons)(void);
    uint64_t (*alone_take)(uint64_t);
    int (*input_gate)(uint64_t *);
    uint64_t (*runeword_filter)(uint64_t);
    uint64_t (*page_filter)(uint64_t);
    uint64_t (*swap_filter)(uint64_t);
    void (*right_test)(dm_hid_npad_state *);
    void (*cursor)(uint64_t *, int32_t *, int32_t *);
    void (*receipt)(const dm_hid_npad_state *, uint32_t, uint32_t, uint64_t, uint64_t);
} dm_hid_adapter;
// No running sample may overlap configuration. FULL_PRODUCT refuses any absent callback.
int dm_hid_configure(dm_hid_mode mode, const dm_hid_adapter *adapter);
dm_hid_mode dm_hid_configured_mode(void);
const char *dm_hid_adapter_identity(void);
int dm_hid_product_complete(void);
const char *dm_hid_missing_consumer(void);
// Runtime epoch teardown only. Both checks are nonblocking; close refuses all
// mutation while a current or queued invocation exists. This resets core state,
// not state owned by the Apple script/receipt adapter or the physical producer.
int dm_hid_can_close(void);
int dm_hid_close(void);
// GetNpadState invocations are serialized without holding input locks during
// callbacks. Recursive GetNpadState on the same thread is unsupported and returns
// a neutral disconnected state; ordinary read-only and publication reentry works.
uint64_t dm_hid_reentrant_rejections(void);
void dm_hid_sample(dm_hid_npad_state *, uint32_t id, uint32_t style);
uint32_t dm_hid_style(uint32_t id);
// Unlike an ordinary neutral publication, cancellation retires pending short taps.
void dm_hid_cancel_touch(void);
void dm_hid_cancel_compat_pad(void);
void dm_hid_reset_inputs(void);
#ifdef __cplusplus
}
#endif
