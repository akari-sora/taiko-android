#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Install/retire only while consumers are quiescent. Context remains owned by
 * the runtime until all consumers return. Hooks execute outside the core lock;
 * callbacks must return normally and must not retire their own context. */
typedef struct DmOeOps {
    void *context;
    void (*pre_pop)(void *context); /* optional capability; NULL = unavailable */
    void (*post_pop)(void *context, uint32_t message); /* required on Android */
    void (*ui_reread)(void *context); /* optional capability; NULL = unavailable */
} DmOeOps;
typedef struct DmOeSnapshot {
    int opmode, focus, ui_opmode, ui_armed;
    uint64_t focus_in_ns;
    uint32_t ui_reads, notify_opmode, notify_perfmode;
    uint32_t pending[32], pending_count;
    uint32_t has_ops, has_pre_pop, has_post_pop, has_ui_reread;
} DmOeSnapshot;
/* Bounded value operations: no log, clock, environment, provider, allocation or
 * guest calls. The caller serializes its channel publication around each call.
 * install returns 1 on acceptance, 0 for NULL/missing required post_pop.
 * seed/publish return 0 for invalid focus (1..3), without changing anything.
 * publish also returns 0 unchanged if the bounded FIFO cannot hold new entries
 * (the normal three coalescible notification types cannot exhaust its 32 slots).
 * seed sets initial actual values without enqueueing historical notifications.
 * reset clears ALL state and installed ops; only a closed/quiescent epoch may reset. */
int dm_oe_core_install_ops_silent(const DmOeOps *ops);
void dm_oe_core_reset_silent(void);
int dm_oe_core_seed_silent(int opmode, int focus, uint64_t focus_ns);
int dm_oe_core_publish_silent(int focus, uint64_t focus_ns, int dimensions_changed);
void dm_oe_core_snapshot(DmOeSnapshot *out);
#ifdef __cplusplus
}
#endif
