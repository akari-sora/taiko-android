#ifndef DM_UIMSG_H
#define DM_UIMSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DM_UIMSG_NAME_MAX 1024
#define DM_UIMSG_SUBSCRIBERS 8
typedef void (*dm_uimsg_subscriber)(const char *, const char *, const char *);
typedef struct dm_uimsg_message {
    uint64_t fields[3];
    char category[DM_UIMSG_NAME_MAX + 1];
    char action[DM_UIMSG_NAME_MAX + 1];
    char argument[65];
    int category_known, action_known, have_argument;
} dm_uimsg_message;

typedef struct dm_uimsg_config {
    void *context;
    /* Copy under the mapping owner's protection. Never query then memcpy. */
    size_t (*read)(void *, uint64_t address, void *output, size_t size);
    /* Enumerate actual readable RO spans, excluding alignment holes. */
    int (*ro_span)(void *, size_t index, uint64_t *address, size_t *size);
    int (*gate_present)(void *);
    void (*gate_set)(void *, void (*callback)(const uint64_t *));
    void (*failure)(void *, const char *reason);
    /* Optional legacy diagnostics/features, before (0) and after (1) dispatch. */
    void (*on_message)(void *, const uint64_t *, const dm_uimsg_message *, int);
} dm_uimsg_config;

/* Configure/reset require process quiescence. Configure owns copied names and
 * publishes only after a complete bounded scan; errors leave the old config.
 * Reset retires all subscribers. Neither function unmaps caller-owned memory. */
int dm_uimsg_configure(const dm_uimsg_config *);
void dm_uimsg_reset(void);
uint64_t dm_uimsg_hash(const char *, size_t);
int dm_uimsg_decode(const uint64_t *registers, dm_uimsg_message *);
void dm_uimsg_observe(const uint64_t *registers);
/* Snapshot eight plain function pointers, invoke unlocked. Changes during a
 * dispatch affect its next snapshot, including a nested dispatch. Callbacks
 * must return normally; process teardown must wait for active dispatches. */
void uimsg_emit(const char *, const char *, const char *);
void uimsg_subscribe(dm_uimsg_subscriber);

#ifdef __cplusplus
}
#endif
#endif
