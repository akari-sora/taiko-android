#include "dm_gamepad_core.h"
#include "dm_input.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t identity, generation, epoch, cancel;
    uint64_t raw, published, pending[64];
    int script;
    int32_t axes[4], published_axes[4];
} source_state;
typedef struct event {
    struct event *next;
    dm_gamepad_source source;
    uint64_t cancel, buttons;
    int32_t axes[4];
    int touched;
} event;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static source_state sources[DM_GAMEPAD_SOURCES];
static dm_gamepad_ops consumers;
static uint64_t next_generation, sequence, revision, cancelled, previous;
static int mode, notified_mode, need_center, on[2], zr_claimed, running, dirty;
static event *head, *tail;

static int find(dm_gamepad_source h) {
    if (!h.identity || !h.generation) return -1;
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i)
        if (sources[i].identity == h.identity && sources[i].generation == h.generation)
            return i;
    return -1;
}
static int32_t clamp(int32_t x) {
    return x > DM_STICK_MAX ? DM_STICK_MAX : x < -DM_STICK_MAX ? -DM_STICK_MAX : x;
}
static uint64_t magnitude(const int32_t *a) {
    return (uint64_t)((int64_t)a[0] * a[0] + (int64_t)a[1] * a[1]);
}
static void aggregate(source_state *s, int published, uint64_t *buttons, int32_t *a) {
    uint64_t best[2] = {0, 0};
    *buttons = 0; memset(a, 0, 4 * sizeof *a);
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i) {
        if (!s[i].identity) continue;
        *buttons |= published ? s[i].published : s[i].raw;
        const int32_t *v = published ? s[i].published_axes : s[i].axes;
        for (int k = 0; k < 2; ++k) {
            uint64_t m = magnitude(v + 2 * k);
            if (m > best[k]) { best[k] = m; a[2*k] = v[2*k]; a[2*k+1] = v[2*k+1]; }
        }
    }
}
static void clear_source(source_state *s) {
    s->raw = s->published = 0;
    memset(s->axes, 0, sizeof s->axes);
    memset(s->published_axes, 0, sizeof s->published_axes);
    memset(s->pending, 0, sizeof s->pending);
    ++s->cancel;
}

/* Exactly one dispatcher runs. Queries and externally visible actions never
 * hold lock; reentrant publication appends work rather than recursing. */
static void drain(void) {
    pthread_mutex_lock(&lock);
    if (running) { pthread_mutex_unlock(&lock); return; }
    running = 1;
    int conflicts = 0;
    for (;;) {
        event *e = dirty ? NULL : head;
        if (e) {
            head = e->next; if (!head) tail = NULL;
            if (e->touched) {
                if (mode) { need_center = 1; mode = 0; dirty = 1; }
            } else {
                int i = find(e->source);
                if (i >= 0 && sources[i].cancel == e->cancel) {
                    sources[i].raw = e->buttons;
                    memcpy(sources[i].axes, e->axes, sizeof e->axes);
                    dirty = 1;
                }
            }
            free(e);
        }
        if (!dirty) {
            if (head) continue;
            running = 0; pthread_mutex_unlock(&lock); return;
        }
        source_state snap[DM_GAMEPAD_SOURCES];
        memcpy(snap, sources, sizeof snap);
        uint64_t r = revision, b; int32_t a[4];
        aggregate(snap, 0, &b, a);
        int next_on[2];
        for (int k = 0; k < 2; ++k) {
            /* Squared integer comparison preserves the original hypot thresholds. */
            int threshold = on[k] ? 15 : 25;
            next_on[k] = magnitude(a + 2*k) * 10000 >=
                (uint64_t)DM_STICK_MAX * DM_STICK_MAX * threshold * threshold;
        }
        int center = need_center;
        if (!next_on[0] && !next_on[1]) center = 0;
        int next_mode = mode;
        if ((b & ~previous) || ((next_on[0] || next_on[1]) && !center)) next_mode = 1;
        int any = 0; for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i) any |= snap[i].identity != 0;
        if (!any) next_mode = 0;
        int query = (b & DM_BTN_ZR) && !(previous & DM_BTN_ZR);
        dm_gamepad_ops ops = consumers;
        int mode_action = notified_mode != next_mode, mode_value = next_mode;
        mode = next_mode; need_center = center; on[0] = next_on[0]; on[1] = next_on[1];
        notified_mode = next_mode;
        pthread_mutex_unlock(&lock);
        /* Original apply() changes the layout before querying ZR policy. Real
         * mode callbacks may change navigation/skill state, so keep that order. */
        if (mode_action && ops.capability == DM_GAMEPAD_FULL_PRODUCT)
            ops.mode_request(ops.context, mode_value);
        pthread_mutex_lock(&lock);
        if (r != revision) {
            dirty = 1;
            if (++conflicts == 32) { running = 0; pthread_mutex_unlock(&lock); return; }
            continue;
        }
        pthread_mutex_unlock(&lock);
        int claim = 0;
        if (query && ops.capability == DM_GAMEPAD_FULL_PRODUCT)
            claim = !ops.navigation(ops.context) && ops.zr_free(ops.context, (b & DM_BTN_ZL) != 0);
        pthread_mutex_lock(&lock);
        if (r != revision) {
            dirty = 1;
            /* No action was claimed. A subsequent publication/read retries the
             * latest state without spinning indefinitely against cancellation. */
            if (++conflicts == 32) { running = 0; pthread_mutex_unlock(&lock); return; }
            continue;
        }
        conflicts = 0;
        if (query) zr_claimed = claim;
        if (!(b & DM_BTN_ZR)) zr_claimed = 0;
        previous = b;
        for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i) {
            uint64_t delivered = snap[i].raw;
            if (zr_claimed) delivered &= ~(uint64_t)DM_BTN_ZR;
            uint64_t rise = delivered & ~sources[i].published;
            for (int bit = 0; bit < 64; ++bit)
                if (rise & (UINT64_C(1) << bit)) sources[i].pending[bit] = ++sequence;
            sources[i].published = delivered;
            for (int k = 0; k < 2; ++k) {
                int enabled = mode && next_on[k];
                sources[i].published_axes[2*k] = enabled ? snap[i].axes[2*k] : 0;
                sources[i].published_axes[2*k+1] = enabled ? snap[i].axes[2*k+1] : 0;
            }
        }
        dirty = 0;
        int portal_action = query && claim;
        pthread_mutex_unlock(&lock);
        if (ops.capability == DM_GAMEPAD_FULL_PRODUCT) {
            if (portal_action) ops.portal_request(ops.context);
        }
        pthread_mutex_lock(&lock);
    }
}

int dm_gamepad_core_configure(const dm_gamepad_ops *ops) {
    if (!ops || (ops->capability != DM_GAMEPAD_FULL_PRODUCT &&
                 ops->capability != DM_GAMEPAD_DIAGNOSTIC_RAW)) return 0;
    if (ops->capability == DM_GAMEPAD_FULL_PRODUCT &&
        (!ops->mode_request || !ops->navigation || !ops->zr_free || !ops->portal_request)) return 0;
    pthread_mutex_lock(&lock);
    if (running || head) { pthread_mutex_unlock(&lock); return 0; }
    consumers = *ops;
    memset(sources, 0, sizeof sources);
    previous = 0; mode = notified_mode = need_center = on[0] = on[1] = zr_claimed = dirty = 0;
    ++revision; ++cancelled;
    pthread_mutex_unlock(&lock); return 1;
}
dm_gamepad_capability dm_gamepad_core_capability(void) {
    pthread_mutex_lock(&lock); dm_gamepad_capability c = consumers.capability;
    pthread_mutex_unlock(&lock); return c;
}
static dm_gamepad_source register_source(uint64_t identity, uint64_t epoch, int script) {
    dm_gamepad_source out = {0, 0};
    if (!identity) return out;
    pthread_mutex_lock(&lock);
    if (!consumers.capability) { pthread_mutex_unlock(&lock); return out; }
    int free_slot = -1;
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i) {
        source_state *s = &sources[i];
        if (s->identity == identity && s->script == script) {
            if (s->epoch == epoch) { out.identity = identity; out.generation = s->generation;
                pthread_mutex_unlock(&lock); return out; }
            clear_source(s); memset(s, 0, sizeof *s); ++cancelled; free_slot = i; break;
        }
        if (!s->identity && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        source_state *s = &sources[free_slot];
        s->identity = identity; s->generation = ++next_generation; s->epoch = epoch; s->script = script;
        out.identity = identity; out.generation = s->generation; ++revision; dirty = 1;
    }
    pthread_mutex_unlock(&lock); drain(); return out;
}
dm_gamepad_source dm_gamepad_source_register(uint64_t identity, uint64_t epoch) {
    return register_source(identity, epoch, 0);
}
int dm_gamepad_source_update(dm_gamepad_source h, uint64_t b, const int32_t a[4]) {
    if (!a) return 0;
    event *e = calloc(1, sizeof *e); if (!e) return 0;
    pthread_mutex_lock(&lock);
    int i = find(h);
    if (i < 0) { pthread_mutex_unlock(&lock); free(e); return 0; }
    e->source = h; e->cancel = sources[i].cancel; e->buttons = b;
    for (int k = 0; k < 4; ++k) e->axes[k] = clamp(a[k]);
    if (tail) tail->next = e; else head = e; tail = e;
    pthread_mutex_unlock(&lock); drain(); return 1;
}
int dm_gamepad_source_remove(dm_gamepad_source h) {
    pthread_mutex_lock(&lock); int i = find(h);
    if (i < 0) { pthread_mutex_unlock(&lock); return 0; }
    memset(&sources[i], 0, sizeof sources[i]); ++revision; ++cancelled; dirty = 1;
    pthread_mutex_unlock(&lock); drain(); return 1;
}
static void cancel_sources(uint64_t epoch, int all) {
    pthread_mutex_lock(&lock); int matched = 0;
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i)
        if (sources[i].identity && (all || sources[i].epoch == epoch)) {
            clear_source(&sources[i]); matched = 1;
        }
    if (matched) { ++revision; ++cancelled; dirty = 1; }
    pthread_mutex_unlock(&lock); drain();
}
void dm_gamepad_cancel_epoch(uint64_t epoch) { cancel_sources(epoch, 0); }
void dm_gamepad_reset(void) { cancel_sources(0, 1); }
int dm_gamepad_mode(void) {
    pthread_mutex_lock(&lock); int result = mode; pthread_mutex_unlock(&lock); return result;
}
void dm_gamepad_touched(void) {
    event *e = calloc(1, sizeof *e); if (!e) return;
    e->touched = 1;
    pthread_mutex_lock(&lock);
    if (tail) tail->next = e; else head = e; tail = e;
    pthread_mutex_unlock(&lock); drain();
}
void dm_gamepad_sample_capture(dm_gamepad_sample *out) {
    dm_gamepad_sample_prepare(); dm_gamepad_sample_capture_claimed(out);
}
void dm_gamepad_sample_prepare(void) { drain(); }
void dm_gamepad_sample_capture_claimed(dm_gamepad_sample *out) {
    if (!out) return;
    pthread_mutex_lock(&lock); memset(out, 0, sizeof *out);
    aggregate(sources, 1, &out->buttons, out->axes); out->cancellation_generation = cancelled;
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i) {
        out->source[i].generation = sources[i].generation;
        for (int bit = 0; bit < 64; ++bit) {
            uint64_t value = sources[i].pending[bit];
            out->source[i].pending_sequence[bit] = value;
            if (value) out->pending_buttons |= UINT64_C(1) << bit;
        }
    }
    pthread_mutex_unlock(&lock);
}
void dm_gamepad_sample_ack(const dm_gamepad_sample *sample) {
    (void)dm_gamepad_sample_claim(sample, 1);
}
static void acknowledge_locked(const dm_gamepad_sample *sample) {
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i)
        if (sources[i].generation == sample->source[i].generation)
            for (int bit = 0; bit < 64; ++bit)
                if (sources[i].pending[bit] == sample->source[i].pending_sequence[bit])
                    sources[i].pending[bit] = 0;
}
void dm_gamepad_sample_ack_claimed(const dm_gamepad_sample *sample) {
    if (!sample) return;
    pthread_mutex_lock(&lock); acknowledge_locked(sample); pthread_mutex_unlock(&lock);
}
int dm_gamepad_sample_claim(const dm_gamepad_sample *sample, int consume) {
    if (!sample) return 0;
    pthread_mutex_lock(&lock);
    if (cancelled != sample->cancellation_generation) {
        pthread_mutex_unlock(&lock); return 0;
    }
    if (consume) acknowledge_locked(sample);
    pthread_mutex_unlock(&lock); return 1;
}
int dm_gamepad_sample_validate(const dm_gamepad_sample *sample) {
    if (!sample) return 0;
    pthread_mutex_lock(&lock); int result = cancelled == sample->cancellation_generation;
    pthread_mutex_unlock(&lock); return result;
}
void dm_gamepad_inject_n(int n, uint64_t b, int32_t lx, int32_t ly, int32_t rx, int32_t ry) {
    dm_gamepad_source h = register_source(n == 2 ? 2 : 1, 0, 1);
    int32_t a[4] = {lx, ly, rx, ry}; dm_gamepad_source_update(h, b, a);
}
void dm_gamepad_drop_n(int n) {
    pthread_mutex_lock(&lock); dm_gamepad_source h = {0,0};
    for (int i = 0; i < DM_GAMEPAD_SOURCES; ++i)
        if (sources[i].script && sources[i].identity == (uint64_t)(n == 2 ? 2 : 1)) {
            h.identity = sources[i].identity; h.generation = sources[i].generation; break;
        }
    pthread_mutex_unlock(&lock); dm_gamepad_source_remove(h);
}
void dm_gamepad_inject(uint64_t b, int32_t lx, int32_t ly, int32_t rx, int32_t ry) {
    dm_gamepad_inject_n(1, b, lx, ly, rx, ry);
}
