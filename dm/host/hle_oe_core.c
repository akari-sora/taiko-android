// nn::oe（应用运行环境）：真机上经 am/oe 服务查询主机状态；宿主直接给固定状态。
// oe::Initialize 在 hle_sdkinit.c，不在这里。
// 环境开关：DM_OPMODE=0 掌机 / 1 主机（默认 1，对应主机模式的渲染档）；DM_LANG=语言码（默认 zh-Hans）。
// nn::oe (application operating environment): on the real device the console state is queried through the am/oe services; the host gives fixed state directly.
// oe::Initialize is in hle_sdkinit.c, not here.
// Environment switches: DM_OPMODE=0 handheld / 1 console (default 1, corresponding to the console-mode render profile); DM_LANG=language code (default zh-Hans).
#include "hle.h"
#include "hle_oe_core.h"

// 运行模式是运行时状态（前端可改：iOS 过热降级切掌机）：唯一来源在此，启动时从 DM_OPMODE 取一次，之后不再读环境变量
// The operation mode is runtime state (the front end can change it: iOS overheat downgrade switches to handheld): the single source is here, taken once from DM_OPMODE at startup, the environment variable is not read again afterwards
#include <stdatomic.h>
static _Atomic int g_opmode = -1;
int dm_opmode(void) {
    int m = g_opmode;
    if (m < 0) { const char *e = getenv("DM_OPMODE"); int v = e ? atoi(e) : 1; int exp = -1; atomic_compare_exchange_strong(&g_opmode, &exp, v); m = g_opmode; }
    return m;
}
// ---------- 系统通知队列（AppletMessage）：前端状态变化 → 游戏每帧 TryPopNotificationMessage 取 ----------
// 消息号（游戏 main 0xe10d30 实际处理的）：15 焦点变化、30 运行模式变化、31 性能模式变化
// ---------- System notification queue (AppletMessage): front end state changes → fetched by the game every frame with TryPopNotificationMessage ----------
// Message numbers (those actually handled by the game at main 0xe10d30): 15 focus change, 30 operation mode change, 31 performance mode change
enum { MSG_FOCUS = 15, MSG_OPMODE = 30, MSG_PERFMODE = 31 };
#define MQ 32
static pthread_mutex_t g_mq_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_mq[MQ]; static int g_mqh, g_mqn;
static _Atomic int g_ntf_opmode, g_ntf_perfmode;          // 游戏用 Set*NotificationEnabled 打开后才推 | only pushed after the game turns it on with Set*NotificationEnabled
static int mq_push_locked(uint32_t m) {
    // 15/30/31 是「查询当前状态」的失效通知，不是携带历史值的事件。
    // 同类型尚未取走时保留首次排位：D2R 消费循环只读最新状态，重复通知的写回相同，尺寸相同不再 resize。
    // 只合并这三种状态通知；未来的逐次事件（如 Resume/Exit）不能套这个规则。
    // 合法生产者只发这三种，因此待取最多三项，任意多次失焦/恢复不再撞 32 槽上限；弹出后新变化照常入队。
    // 15/30/31 are invalidation notifications meaning "query the current state", not events carrying historical values.
    // While one of the same type has not been taken yet, the first queue position is kept: the D2R consumer loop only reads the latest state, repeated notifications write back the same thing, and with the same size there is no further resize.
    // Only these three state notifications are merged; future per-occurrence events (such as Resume/Exit) must not use this rule.
    // Legitimate producers only send these three, so at most three items are pending, and any number of focus losses/restores no longer hits the 32-slot limit; after a pop, new changes are enqueued as usual.
    if (m == MSG_FOCUS || m == MSG_OPMODE || m == MSG_PERFMODE)
        for (int i = 0; i < g_mqn; i++)
            if (g_mq[(g_mqh + i) % MQ] == m) return 1;
    if (g_mqn == MQ) return 0;
    g_mq[(g_mqh + g_mqn++) % MQ] = m;
    return 1;
}
static void mq_push(uint32_t m) { pthread_mutex_lock(&g_mq_lock); int ok = mq_push_locked(m); pthread_mutex_unlock(&g_mq_lock); if (!ok) die("oe 通知队列溢出（游戏没在取？）"); }
void dm_oe_res_changed(void) { if (getenv("DM_TEST_OE_FOCUS_FIRST")) mq_push(MSG_FOCUS);   /* 测试：让 31 排在一条焦点通知后面（iOS 包启动时的顺序） | Test: queue 31 behind a focus notification (the order at iOS app startup) */
    if (g_ntf_perfmode) mq_push(MSG_PERFMODE); else LOG("【红】分辨率要切，但游戏没打开性能模式变化通知"); }   // 出图分辨率该变了（dm_uiscreen.c）：让游戏重读参数位 | the render resolution should change (dm_uiscreen.c): make the game re-read the parameter bits
// 只对 GetOperationMode 报的运行模式（手柄 / 触屏布局切换让游戏重载布局用，dm_padmode.c）：m ≥ 0 报 m 并推一次运行模式通知，m < 0 报回真值再推一次。
// 手柄样式（hle_hid.c connected_id）与性能模式照真值，所以不弹「重新连接控制器」、出图分辨率不变
// Operation mode reported to GetOperationMode only (used to make the game reload layouts when switching between controller / touch layouts, dm_padmode.c):
// m ≥ 0 reports m and pushes one operation-mode notification; m < 0 reports the true value again and pushes one more.
// The controller style (hle_hid.c connected_id) and performance mode keep their true values, so no "Reconnect controller" prompt appears and the render
// resolution does not change
static _Atomic int g_ui_opmode = -1;
static _Atomic int g_ui_armed; static _Atomic uint32_t g_ui_reads;   // 推过通知后游戏第一次来读运行模式记一次：切换事务拿它回读「游戏收到了」 | Counts once when the game first comes to read the operation mode after a notification has been pushed: the switch transaction uses it to read back "the game received it"
uint32_t dm_oe_ui_opmode_reads(void) { return atomic_load(&g_ui_reads); }
void dm_oe_ui_opmode(int m) {
    pthread_mutex_lock(&g_mq_lock);
    g_ui_opmode = m < 0 ? -1 : m; atomic_store(&g_ui_armed, 1);
    int ok = !g_ntf_opmode || mq_push_locked(MSG_OPMODE);
    pthread_mutex_unlock(&g_mq_lock);
    if (!ok) die("oe 通知队列溢出（游戏没在取？）");
}
void dm_set_opmode(int m) {
    (void)dm_opmode();
    pthread_mutex_lock(&g_mq_lock);
    int old = g_opmode, ok = 1;
    if (old != m) {
        g_opmode = m;
        if (g_ntf_opmode) ok &= mq_push_locked(MSG_OPMODE);
        if (g_ntf_perfmode) ok &= mq_push_locked(MSG_PERFMODE);
    }
    pthread_mutex_unlock(&g_mq_lock);
    if (!ok) die("oe 通知队列溢出（游戏没在取？）");
    if (old != m) LOG("oe 运行模式 %d → %d", old, m);
}
// FocusState：1 InFocus、2 OutOfFocus、3 Background。前端调 dm_focus_set（iOS 生命周期 / Mac 窗口失焦）
// FocusState: 1 InFocus, 2 OutOfFocus, 3 Background. The front end calls dm_focus_set (iOS lifecycle / Mac window losing focus)
static _Atomic int g_focus = 1; static _Atomic uint64_t g_focus_in_ns;   // 最近一次进入 InFocus 的时刻 | time of the most recent entry into InFocus
int dm_focus_now(void) { return atomic_load(&g_focus); }
uint64_t dm_focus_in_since(void) { return atomic_load(&g_focus_in_ns); }   // 图形层显示节拍看门狗：只在激活时算停顿，从激活起算（nvn_mtl.m mtl_present_wait） | graphics layer display link watchdog: stalls are only computed while active, counted from activation (nvn_mtl.m mtl_present_wait)
void dm_focus_set(int st) {
    if (st < 1 || st > 3) die("dm_focus_set 非法状态 %d", st);
    uint64_t entered = st == 1 ? now_ns() : 0;
    pthread_mutex_lock(&g_mq_lock);
    if (st == 1) atomic_store(&g_focus_in_ns, entered);
    int changed = atomic_exchange(&g_focus, st) != st;
    int ok = !changed || mq_push_locked(MSG_FOCUS);
    pthread_mutex_unlock(&g_mq_lock);
    if (!ok) die("oe 通知队列溢出（游戏没在取？）");
    if (changed) LOG("oe 焦点状态 → %d", st);
}
static int opmode(void) { return dm_opmode(); }

// 截图 / 录像开关：宿主无系统截图服务，空操作
// Screenshot / video recording switches: the host has no system screenshot service, no-op
HLE_FORCE("_ZN2nn2oe15EnableRecordingEv", "录像开关；宿主无系统录像", void, h_oe_EnableRec, void) {}
HLE_FORCE("_ZN2nn2oe16DisableRecordingEv", "录像开关；宿主无系统录像", void, h_oe_DisableRec, void) {}
HLE_FORCE("_ZN2nn2oe16EnableScreenShotEv", "截图开关；宿主无系统截图", void, h_oe_EnableShot, void) {}
HLE_FORCE("_ZN2nn2oe17DisableScreenShotEv", "截图开关；宿主无系统截图", void, h_oe_DisableShot, void) {}

// OperationMode：0 Handheld、1 Console；PerformanceMode：0 Normal、1 Boost（与运行模式一一对应）
// OperationMode: 0 Handheld, 1 Console; PerformanceMode: 0 Normal, 1 Boost (one-to-one with the operation mode)
HLE_FORCE("_ZN2nn2oe16GetOperationModeEv", "运行模式查询；按 DM_OPMODE 给固定值", int, h_oe_GetOpMode, void) { (void)dm_opmode(); pthread_mutex_lock(&g_mq_lock); int u = g_ui_opmode; if (atomic_exchange(&g_ui_armed, 0)) atomic_fetch_add(&g_ui_reads, 1); int result = u >= 0 ? u : g_opmode; pthread_mutex_unlock(&g_mq_lock); return result; }
HLE_FORCE("_ZN2nn2oe18GetPerformanceModeEv", "性能模式查询；与运行模式一致", int, h_oe_GetPerfMode, void) { return opmode(); }
HLE_FORCE("_ZN2nn2oe27SetPerformanceConfigurationENS0_15PerformanceModeEi", "设 CPU/GPU 频率档；宿主不调频", void, h_oe_SetPerfCfg, int mode, int cfg) {
    LOG("oe::SetPerformanceConfiguration mode=%d cfg=%#x（忽略）", mode, cfg);
}

HLE_FORCE("_ZN2nn2oe20GetCurrentFocusStateEv", "前后台状态；由前端 dm_focus_set 驱动", int, h_oe_GetFocus, void) { return g_focus; }
HLE_FORCE("_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE", "前后台切换策略；游戏设 1（收焦点通知），宿主按通知语义实现", void, h_oe_SetFocusMode, int m) { LOG("oe::SetFocusHandlingMode %d", m); }


static DmOeOps g_oe_ops;
int dm_oe_core_install_ops_silent(const DmOeOps *ops) {
    if (!ops || !ops->post_pop) return 0;
    pthread_mutex_lock(&g_mq_lock); g_oe_ops = *ops; pthread_mutex_unlock(&g_mq_lock);
    return 1;
}
void dm_oe_core_reset_silent(void) {
    pthread_mutex_lock(&g_mq_lock);
    memset(g_mq, 0, sizeof g_mq); g_mqh = g_mqn = 0;
    g_opmode = -1; g_focus = 1; g_focus_in_ns = 0;
    g_ntf_opmode = g_ntf_perfmode = 0;
    g_ui_opmode = -1; g_ui_armed = 0; g_ui_reads = 0;
    memset(&g_oe_ops, 0, sizeof g_oe_ops);
    pthread_mutex_unlock(&g_mq_lock);
}
int dm_oe_core_seed_silent(int mode, int focus, uint64_t focus_ns) {
    if (focus < 1 || focus > 3) return 0;
    pthread_mutex_lock(&g_mq_lock);
    g_opmode = mode; g_focus = focus; g_focus_in_ns = focus_ns;
    pthread_mutex_unlock(&g_mq_lock); return 1;
}
int dm_oe_core_publish_silent(int focus, uint64_t focus_ns, int dimensions_changed) {
    if (focus < 1 || focus > 3) return 0;
    pthread_mutex_lock(&g_mq_lock);
    int add_focus = g_focus != focus, add_perf = dimensions_changed && g_ntf_perfmode;
    for (int i = 0; i < g_mqn; ++i) {
        uint32_t pending = g_mq[(g_mqh + i) % MQ];
        if (pending == MSG_FOCUS) add_focus = 0;
        if (pending == MSG_PERFMODE) add_perf = 0;
    }
    if (g_mqn + add_focus + add_perf > MQ) { pthread_mutex_unlock(&g_mq_lock); return 0; }
    if (focus == 1) g_focus_in_ns = focus_ns;
    if (atomic_exchange(&g_focus, focus) != focus) mq_push_locked(MSG_FOCUS);
    if (dimensions_changed && g_ntf_perfmode) mq_push_locked(MSG_PERFMODE);
    pthread_mutex_unlock(&g_mq_lock); return 1;
}
void dm_oe_core_snapshot(DmOeSnapshot *out) {
    if (!out) return;
    pthread_mutex_lock(&g_mq_lock);
    memset(out, 0, sizeof *out);
    out->opmode = g_opmode; out->focus = g_focus; out->focus_in_ns = g_focus_in_ns;
    out->ui_opmode = g_ui_opmode; out->ui_armed = g_ui_armed; out->ui_reads = g_ui_reads;
    out->notify_opmode = g_ntf_opmode; out->notify_perfmode = g_ntf_perfmode;
    out->pending_count = (uint32_t)g_mqn;
    for (int i = 0; i < g_mqn; ++i) out->pending[i] = g_mq[(g_mqh + i) % MQ];
    out->has_ops = g_oe_ops.post_pop != NULL;
    out->has_pre_pop = g_oe_ops.pre_pop != NULL;
    out->has_post_pop = g_oe_ops.post_pop != NULL;
    out->has_ui_reread = g_oe_ops.ui_reread != NULL;
    pthread_mutex_unlock(&g_mq_lock);
}
#if (!defined(__ANDROID__) && !defined(DM_OE_TEST_PORTABLE)) || defined(DM_OE_TEST_APPLE)
/* Always linked from hle_oe.c on Apple. This is deliberately not a constructor. */
const DmOeOps *dm_oe_apple_ops(void);
#endif
HLE_FORCE("_ZN2nn2oe25TryPopNotificationMessageEPj", "系统通知队列；前端状态变化入队", unsigned, h_oe_TryPopMsg, uint32_t *msg) {
    DmOeOps ops;
#if (!defined(__ANDROID__) && !defined(DM_OE_TEST_PORTABLE)) || defined(DM_OE_TEST_APPLE)
    ops = *dm_oe_apple_ops();
#else
    pthread_mutex_lock(&g_mq_lock); ops = g_oe_ops; pthread_mutex_unlock(&g_mq_lock);
    if (!ops.post_pop) die("Android OE hooks not installed before guest entry");
#endif
    if (ops.pre_pop) ops.pre_pop(ops.context);
    pthread_mutex_lock(&g_mq_lock);
    int ok = g_mqn > 0; uint32_t popped = 0;
    if (ok) { popped = g_mq[g_mqh]; *msg = popped; g_mqh = (g_mqh + 1) % MQ; g_mqn--; }
    pthread_mutex_unlock(&g_mq_lock);
    /* Every successful pop refreshes the CURRENT guest thread, including 15/30
     * before a queued 31. No provider or guest callback runs under the state lock. */
    if (ok && ops.post_pop) ops.post_pop(ops.context, popped);
    if (ok && popped == MSG_PERFMODE && ops.ui_reread) ops.ui_reread(ops.context);
    if (ok) LOG("oe 通知被游戏取走：%u", popped);
    return (unsigned)ok;
}
// bool 参数：Switch 调用方不扩展，声明成 unsigned 只看低 8 位
// bool arguments: Switch callers do not extend them, declared as unsigned and only the low 8 bits are looked at
HLE_FORCE("_ZN2nn2oe28SetResumeNotificationEnabledEb", "恢复通知开关；宿主的恢复以焦点通知 15 表达", void, h_oe_SetResumeNtf, unsigned on) { (void)on; }
HLE_FORCE("_ZN2nn2oe42SetOperationModeChangedNotificationEnabledEb", "运行模式变化通知开关", void, h_oe_SetOpModeNtf, unsigned on) { pthread_mutex_lock(&g_mq_lock); g_ntf_opmode = on & 0xff; pthread_mutex_unlock(&g_mq_lock); }
HLE_FORCE("_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb", "性能模式变化通知开关", void, h_oe_SetPerfModeNtf, unsigned on) { pthread_mutex_lock(&g_mq_lock); g_ntf_perfmode = on & 0xff; pthread_mutex_unlock(&g_mq_lock); }

// nn::settings::LanguageCode = struct { char string[8]; }，8 字节按值返回在 x0
// nn::settings::LanguageCode = struct { char string[8]; }, 8 bytes returned by value in x0
HLE_FORCE("_ZN2nn2oe18GetDesiredLanguageEv", "系统语言查询；按 DM_LANG 给值", uint64_t, h_oe_GetLang, void) {
    const char *e = getenv("DM_LANG");
    char code[8] = {0};
    strncpy(code, e ? e : "zh-Hans", sizeof code - 1);
    uint64_t v; memcpy(&v, code, 8);
    return v;
}

// nn::util::Uuid 16 字节：本机固定值（只用于本地区分设备，联网已剪）
// nn::util::Uuid 16 bytes: a fixed local value (only used to tell devices apart locally, networking is cut)
HLE_FORCE("_ZN2nn2oe17GetPseudoDeviceIdEPNS_4util4UuidE", "伪设备号；宿主固定值", void, h_oe_GetDevId, uint8_t *uuid) {
    static const uint8_t k[16] = {0x78, 0x62, 0x6c, 0x00, 0x53, 0x57, 0x4e, 0x41, 0x54, 0x49, 0x56, 0x45, 0x31, 0x30, 0x30, 0x31};
    memcpy(uuid, k, 16);
}
