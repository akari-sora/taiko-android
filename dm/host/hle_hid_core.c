// One original Npad sampling algorithm, with explicit platform augmentation.
#include "hle_hid_core.h"
#include "hle.h"
#include "dm_input.h"
#include "dm_gamepad_core.h"
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

_Static_assert(sizeof(dm_hid_npad_state) == 0x28, "NpadState");
_Static_assert(offsetof(dm_hid_npad_state, attributes) == 32, "Npad attributes");
_Atomic int g_dm_l_presses;
static _Atomic int64_t g_sampling;
static _Atomic uint64_t g_sampled_right, g_stick_ns;
void (*dm_pad_hook)(uint64_t, uint64_t *, int32_t *, int32_t *, int32_t *, int32_t *);

// Current tuples and pending edges are captured together. Acknowledgment of a
// captured sequence must not erase a newer press of the same button.
typedef struct {
    uint64_t buttons, pending, sequence[64], cancellation;
    int32_t axes[4];
} input_channel;
static pthread_mutex_t g_hid_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hid_cv = PTHREAD_COND_INITIALIZER;
static input_channel g_touch_channel, g_compat_channel;
static dm_hid_adapter g_adapter;
static dm_hid_mode g_mode;
static unsigned g_active_samples, g_waiting_samples;
static pthread_t g_sample_owner;
static int g_sample_busy;
static _Atomic uint64_t g_reentrant_rejections;
static _Atomic int g_old_arbitration=-1;
static _Atomic uint64_t g_previous_buttons;
static int g_stall_ms = -1, g_stall_due;
static const char *missing(const dm_hid_adapter *a) {
    if (!a || !a->identity || !*a->identity) return "adapter.identity";
#define REQUIRED(field) if (!a->field) return #field
    REQUIRED(receipt_prepare); REQUIRED(ui_taps); REQUIRED(frontend);
    REQUIRED(textinput); REQUIRED(update); REQUIRED(actions); REQUIRED(world);
    REQUIRED(ui_mouse); REQUIRED(aim_cone); REQUIRED(read_start);
    REQUIRED(script_keys); REQUIRED(auto_release); REQUIRED(auto_buttons);
    REQUIRED(alone_take); REQUIRED(input_gate); REQUIRED(runeword_filter);
    REQUIRED(page_filter); REQUIRED(swap_filter); REQUIRED(right_test);
    REQUIRED(cursor); REQUIRED(receipt);
#undef REQUIRED
    return NULL;
}
int dm_hid_configure(dm_hid_mode mode, const dm_hid_adapter *a) {
    if (mode != DM_HID_FULL_PRODUCT && mode != DM_HID_DIAGNOSTIC_RAW) return 0;
    if (!a || !a->identity || !*a->identity || (mode == DM_HID_FULL_PRODUCT && missing(a))) return 0;
    pthread_mutex_lock(&g_hid_lock);
    int ok = g_active_samples == 0 && g_waiting_samples == 0;
    if (ok) { g_adapter = *a; g_mode = mode; }
    pthread_mutex_unlock(&g_hid_lock);
    return ok;
}
dm_hid_mode dm_hid_configured_mode(void) {
    pthread_mutex_lock(&g_hid_lock); dm_hid_mode m = g_mode;
    pthread_mutex_unlock(&g_hid_lock); return m;
}
const char *dm_hid_adapter_identity(void) {
    pthread_mutex_lock(&g_hid_lock); const char *s = g_adapter.identity;
    pthread_mutex_unlock(&g_hid_lock); return s ? s : "unconfigured";
}
const char *dm_hid_missing_consumer(void) {
    pthread_mutex_lock(&g_hid_lock);
    const char *s = g_mode == DM_HID_FULL_PRODUCT ? missing(&g_adapter) : "full_product_adapter";
    pthread_mutex_unlock(&g_hid_lock); return s;
}
int dm_hid_product_complete(void) { return dm_hid_missing_consumer() == NULL; }
uint64_t dm_hid_reentrant_rejections(void) { return atomic_load(&g_reentrant_rejections); }
int dm_hid_can_close(void) {
    pthread_mutex_lock(&g_hid_lock); int ok=!g_active_samples&&!g_waiting_samples;
    pthread_mutex_unlock(&g_hid_lock); return ok;
}
int dm_hid_close(void) {
    pthread_mutex_lock(&g_hid_lock);
    int ok=!g_active_samples&&!g_waiting_samples;
    if (ok) {
        memset(&g_touch_channel,0,sizeof g_touch_channel);
        memset(&g_compat_channel,0,sizeof g_compat_channel);
        memset(&g_adapter,0,sizeof g_adapter); g_mode=DM_HID_UNCONFIGURED;
        g_stall_ms=-1;g_stall_due=0;dm_pad_hook=NULL;
        atomic_store(&g_sampling,0);atomic_store(&g_sampled_right,0);atomic_store(&g_stick_ns,0);
        atomic_store(&g_dm_l_presses,0);atomic_store(&g_reentrant_rejections,0);
        atomic_store(&g_old_arbitration,-1);atomic_store(&g_previous_buttons,0);
    }
    pthread_mutex_unlock(&g_hid_lock); return ok;
}
static void publish(input_channel *c, uint64_t buttons, const int32_t axes[4]) {
    uint64_t rise = buttons & ~c->buttons;
    c->pending |= rise;
    for (unsigned i = 0; i < 64; ++i) if (rise & (UINT64_C(1) << i)) ++c->sequence[i];
    c->buttons = buttons; memcpy(c->axes, axes, sizeof c->axes);
}
void dm_input_set(uint64_t buttons, int32_t lx, int32_t ly, int32_t rx, int32_t ry) {
    int32_t axes[] = {lx,ly,rx,ry}; int log_stall=0;
    pthread_mutex_lock(&g_hid_lock);
    if (g_stall_ms < 0) { const char *e = getenv("DM_TEST_HID_STALL_MS"); g_stall_ms = e ? atoi(e) : 0; log_stall=g_stall_ms; }
    if (g_stall_ms > 0 && (buttons & DM_BTN_A) && !(g_touch_channel.buttons & DM_BTN_A)) g_stall_due = 1;
    publish(&g_touch_channel,buttons,axes);
    pthread_mutex_unlock(&g_hid_lock);
    if (log_stall) LOG("DM_TEST_HID_STALL_MS：A 每次按下沿后游戏取手柄先睡 %d ms",log_stall);
}
void dm_pad_set(uint64_t buttons, int32_t lx, int32_t ly, int32_t rx, int32_t ry) {
    // Preserve the original signed-16-bit physical axis ABI.
    int32_t axes[] = {(int16_t)lx,(int16_t)ly,(int16_t)rx,(int16_t)ry};
    pthread_mutex_lock(&g_hid_lock); publish(&g_compat_channel,buttons,axes);
    pthread_mutex_unlock(&g_hid_lock);
}
static void cancel(input_channel *c) {
    c->buttons = c->pending = 0; memset(c->axes,0,sizeof c->axes); ++c->cancellation;
}
void dm_hid_cancel_touch(void) {
    pthread_mutex_lock(&g_hid_lock); cancel(&g_touch_channel); g_stall_due = 0;
    pthread_mutex_unlock(&g_hid_lock);
}
void dm_hid_cancel_compat_pad(void) {
    pthread_mutex_lock(&g_hid_lock); cancel(&g_compat_channel);
    pthread_mutex_unlock(&g_hid_lock);
}
void dm_hid_reset_inputs(void) {
    pthread_mutex_lock(&g_hid_lock); cancel(&g_touch_channel); cancel(&g_compat_channel); g_stall_due=0;
    pthread_mutex_unlock(&g_hid_lock);
}
static void acknowledge(input_channel *live, const input_channel *sample) {
    if (live->cancellation != sample->cancellation) return;
    for (unsigned i=0;i<64;++i)
        if (live->sequence[i] == sample->sequence[i]) live->pending &= ~(sample->pending & (UINT64_C(1)<<i));
}
void dm_input_sampled_right(int32_t *rx, int32_t *ry) {
    uint64_t v=atomic_load_explicit(&g_sampled_right,memory_order_acquire);
    *rx=(int32_t)(uint32_t)v; *ry=(int32_t)(uint32_t)(v>>32);
}
uint64_t dm_stick_last_ns(void) { return atomic_load(&g_stick_ns); }
uint64_t dm_input_samples(void) { return (uint64_t)atomic_load(&g_sampling); }
uint32_t dm_hid_style(uint32_t id) {
    uint32_t connected = dm_opmode() == 0 ? 0x20 : 0;
    return id == connected ? (id == 0x20 ? DM_HID_STYLE_HANDHELD : DM_HID_STYLE_FULLKEY) : 0;
}
static uint64_t query(uint64_t (*f)(void)) { return f ? f() : 0; }
#define PUMP(field) do { if (a.field) a.field(); } while (0)
void dm_hid_sample(dm_hid_npad_state *s, uint32_t id, uint32_t style) {
    dm_hid_adapter a; dm_hid_mode mode;
    pthread_mutex_lock(&g_hid_lock);
    if (g_sample_busy && pthread_equal(g_sample_owner,pthread_self())) {
        atomic_fetch_add(&g_reentrant_rejections,1);
        memset(s,0,sizeof *s); s->sampling=atomic_fetch_add(&g_sampling,1)+1;
        pthread_mutex_unlock(&g_hid_lock); return;
    }
    ++g_waiting_samples; pthread_cond_broadcast(&g_hid_cv);
    while (g_sample_busy) pthread_cond_wait(&g_hid_cv,&g_hid_lock);
    --g_waiting_samples; g_sample_busy=1; g_sample_owner=pthread_self();
    ++g_active_samples; a=g_adapter; mode=g_mode;
    pthread_mutex_unlock(&g_hid_lock);
    PUMP(receipt_prepare); PUMP(ui_taps); PUMP(frontend); PUMP(textinput);
    PUMP(update); PUMP(actions); PUMP(world); PUMP(ui_mouse); PUMP(aim_cone);
    pthread_mutex_lock(&g_hid_lock); int stall=g_stall_due ? g_stall_ms : 0; g_stall_due=0;
    pthread_mutex_unlock(&g_hid_lock);
    if (stall > 0) usleep((useconds_t)stall*1000);
    uint64_t read_start_ns=query(a.read_start), km=0;
    memset(s,0,sizeof *s); s->sampling=atomic_fetch_add(&g_sampling,1)+1;
    if (mode == DM_HID_UNCONFIGURED || !(dm_hid_style(id)&style)) goto done;
    km=query(a.script_keys);
    input_channel touch, compat;
    dm_gamepad_sample physical;
    // Drain policy queries and external actions first. The joint claim itself
    // is bounded: sampler -> producer, with no callbacks, drains or allocation.
    dm_gamepad_sample_prepare();
    pthread_mutex_lock(&g_hid_lock); touch=g_touch_channel; compat=g_compat_channel;
    dm_gamepad_sample_capture_claimed(&physical);
    pthread_mutex_unlock(&g_hid_lock);
    uint64_t tb=((touch.buttons|touch.pending)&~query(a.auto_release)) | (km&~(uint64_t)PK_MASK) | query(a.auto_buttons);
    uint64_t pb=compat.buttons|compat.pending|physical.buttons|physical.pending_buttons;
    int legacy=atomic_load(&g_old_arbitration);
    if (legacy<0) {
        int expected=-1, candidate=getenv("DM_TEST_ALONE_NOPAD")!=NULL;
        atomic_compare_exchange_strong(&g_old_arbitration,&expected,candidate);
        legacy=atomic_load(&g_old_arbitration);
    }
    uint64_t alone=a.alone_take ? a.alone_take(legacy?tb:tb|pb) : 0;
    uint64_t release=0, automatic=0;
    if (!alone) { release=query(a.auto_release); automatic=query(a.auto_buttons); }
    // The coherent claim above precedes even stateful exclusive arbitration.
    // Acknowledgment follows that decision; callbacks can publish or cancel
    // meanwhile, but an already-claimed invocation cannot be rolled back.
    int consume_physical=!alone||legacy;
    pthread_mutex_lock(&g_hid_lock);
    if (!alone) acknowledge(&g_touch_channel,&touch);
    if (consume_physical) acknowledge(&g_compat_channel,&compat);
    pthread_mutex_unlock(&g_hid_lock);
    if (consume_physical) dm_gamepad_sample_ack_claimed(&physical);
    pb=compat.buttons|compat.pending|physical.buttons|physical.pending_buttons;
    if (alone) s->buttons=legacy ? alone|pb : alone;
    else s->buttons=((touch.buttons|touch.pending)&~release) |
        (km&~(uint64_t)PK_MASK) | automatic | pb;
    s->lx=touch.axes[0];s->ly=touch.axes[1];s->rx=touch.axes[2];s->ry=touch.axes[3];
    int32_t pad[4]; memcpy(pad,compat.axes,sizeof pad);
    // Compatibility source and physical producer remain separate latch owners.
    // Stronger producer pairs win; ties retain the compatibility source.
    for (int j=0;j<4;j+=2) {
        int64_t p=(int64_t)physical.axes[j]*physical.axes[j]+(int64_t)physical.axes[j+1]*physical.axes[j+1];
        int64_t c=(int64_t)pad[j]*pad[j]+(int64_t)pad[j+1]*pad[j+1];
        if(p>c){pad[j]=physical.axes[j];pad[j+1]=physical.axes[j+1];}
    }
    if (!(s->lx||s->ly)) {s->lx=pad[0];s->ly=pad[1];}
    if (!(s->rx||s->ry)) {s->rx=pad[2];s->ry=pad[3];}
    if (a.input_gate && a.input_gate(&s->buttons)) s->lx=s->ly=s->rx=s->ry=0;
    if (dm_pad_hook) dm_pad_hook(guest_ns(),&s->buttons,&s->lx,&s->ly,&s->rx,&s->ry);
    if (a.runeword_filter) s->buttons=a.runeword_filter(s->buttons);
    if (a.page_filter) s->buttons=a.page_filter(s->buttons);
    if (a.swap_filter) s->buttons=a.swap_filter(s->buttons);
    if (a.right_test) a.right_test(s);
    if (s->lx||s->ly||(km&PK_MASK&~(uint64_t)PK_TOUCH)) atomic_store(&g_stick_ns,now_ns());
    if (a.cursor) a.cursor(&s->buttons,&s->lx,&s->ly);
    { uint64_t before=atomic_exchange(&g_previous_buttons,s->buttons);
      if ((s->buttons&DM_BTN_L)&&!(before&DM_BTN_L)) {
        int n=atomic_fetch_add(&g_dm_l_presses,1)+1;
        if(n<=3) LOG("取手柄处：「显示物品」键（L）交给了游戏，本进程第 %d 次",n);
      } }
    if(km&PK_LSL)s->lx=-32767; if(km&PK_LSR)s->lx=32767;
    if(km&PK_LSU)s->ly=32767; if(km&PK_LSD)s->ly=-32767;
    s->attributes=1;
    atomic_store_explicit(&g_sampled_right,(uint32_t)s->rx|((uint64_t)(uint32_t)s->ry<<32),memory_order_release);
done:
    if (a.receipt) a.receipt(s,id,style,km,read_start_ns);
    pthread_mutex_lock(&g_hid_lock); --g_active_samples; g_sample_busy=0;
    pthread_cond_broadcast(&g_hid_cv); pthread_mutex_unlock(&g_hid_lock);
}
#undef PUMP

HLE_FORCE("_ZN2nn3hid14InitializeNpadEv", "连 hid 服务；宿主从 dm_input 取输入", void, h_hid_InitNpad, void) {}
HLE_FORCE("_ZN2nn3hid22SetSupportedNpadIdTypeEPKjm", "支持的手柄号；宿主固定", void, h_hid_SetIds, const uint32_t *ids, uint64_t n) { (void)ids;(void)n; }
HLE_FORCE("_ZN2nn3hid24SetSupportedNpadStyleSetENS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE", "支持的手柄样式；宿主固定", void, h_hid_SetStyles, uint32_t styles) { (void)styles; }
HLE_FORCE("_ZN2nn3hid29SetNpadHandheldActivationModeENS0_26NpadHandheldActivationModeE", "掌机手柄激活方式；宿主固定", void, h_hid_SetHhMode, int m) { (void)m; }
HLE_FORCE("_ZN2nn3hid15GetNpadStyleSetERKj", "手柄样式查询；跟 DM_OPMODE 走", uint32_t, h_hid_GetStyle, const uint32_t *id) { return dm_hid_style(*id); }
HLE_FORCE("_ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj", "全键手柄状态；取 dm_input", void, h_hid_GetFullKey, dm_hid_npad_state *s, const uint32_t *id) { dm_hid_sample(s,*id,DM_HID_STYLE_FULLKEY); }
HLE_FORCE("_ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj", "掌机手柄状态；取 dm_input", void, h_hid_GetHandheld, dm_hid_npad_state *s, const uint32_t *id) { dm_hid_sample(s,*id,DM_HID_STYLE_HANDHELD); }
HLE_FORCE("_ZN2nn3hid20IsVibrationPermittedEv", "震动许可；宿主不支持（返回 bool）", unsigned, h_hid_VibPermit, void) { return 0; }
HLE_FORCE("_ZN2nn3hid25GetVibrationDeviceHandlesEPNS0_21VibrationDeviceHandleEiRKjNS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE", "震动设备；宿主 0 个", int, h_hid_GetVibHandles, void *out,int max,const uint32_t *id,uint32_t style) {(void)out;(void)max;(void)id;(void)style;return 0;}
HLE_FORCE("_ZN2nn3hid25InitializeVibrationDeviceERKNS0_21VibrationDeviceHandleE", "震动；宿主不支持", void, h_hid_InitVib,const void *h) {(void)h;}
HLE_FORCE("_ZN2nn3hid18SendVibrationValueERKNS0_21VibrationDeviceHandleERKNS0_14VibrationValueE", "震动；宿主不支持", void, h_hid_SendVib,const void *h,const void *v) {(void)h;(void)v;}
