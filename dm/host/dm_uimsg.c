#include "dm_uimsg.h"
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The old table had 2^18 slots and retained guest pointers indefinitely. Copy
 * names before callbacks, bound both allocation and probing, and never scan
 * padding between the declared RO spans. Overlong names retain hex fallback. */
#define HASH_BITS 18
#define HASH_SIZE (1u << HASH_BITS)
#define STRING_BUDGET (32u * 1024u * 1024u)
#define SCAN_BUDGET (512u * 1024u * 1024u)
#define SPAN_LIMIT 4096
typedef struct name_entry { uint64_t hash; char *name; } name_entry;
static pthread_mutex_t bus_lock = PTHREAD_MUTEX_INITIALIZER;
static dm_uimsg_config current;
static name_entry *names;
static dm_uimsg_subscriber subscribers[DM_UIMSG_SUBSCRIBERS];
static size_t subscriber_count;

uint64_t dm_uimsg_hash(const char *p, size_t size) {
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    for (size_t i = 0; i < size; i++) hash = (hash ^ (unsigned char)p[i]) * UINT64_C(0x100000001b3);
    return hash;
}
static void free_names(name_entry *table) {
    if (!table) return;
    for (size_t i = 0; i < HASH_SIZE; i++) free(table[i].name);
    free(table);
}
static int add_name(name_entry *table, const char *name, size_t length,
                    size_t *count, size_t *bytes) {
    uint64_t hash = dm_uimsg_hash(name, length);
    size_t index = hash >> (64 - HASH_BITS);
    while (table[index].name && table[index].hash != hash) index = (index + 1) & (HASH_SIZE - 1);
    size_t old = table[index].name ? strlen(table[index].name) + 1 : 0;
    if ((!old && *count >= HASH_SIZE * 3 / 4) || length + 1 > STRING_BUDGET - (*bytes - old)) return -E2BIG;
    char *copy = malloc(length + 1);
    if (!copy) return -ENOMEM;
    memcpy(copy, name, length); copy[length] = 0;
    free(table[index].name); table[index].name = copy; table[index].hash = hash;
    *bytes = *bytes - old + length + 1;
    if (!old) (*count)++;
    return 0;
}
static int build_names(const dm_uimsg_config *config, name_entry **output) {
    name_entry *table = calloc(HASH_SIZE, sizeof *table);
    if (!table) return -ENOMEM;
    size_t total = 0, count = 0, bytes = 0;
    int error = 0;
    for (size_t i = 0;; i++) {
        uint64_t address = 0; size_t size = 0;
        int found = config->ro_span(config->context, i, &address, &size);
        if (found == 0) break;
        if (found != 1 || i == SPAN_LIMIT || size > SCAN_BUDGET - total || address > UINT64_MAX - size) { error = -E2BIG; break; }
        total += size;
        char candidate[DM_UIMSG_NAME_MAX + 1]; size_t length = 0;
        unsigned char chunk[4096];
        for (size_t offset = 0; offset < size && !error;) {
            size_t n = size - offset; if (n > sizeof chunk) n = sizeof chunk;
            if (config->read(config->context, address + offset, chunk, n) != n) { error = -EFAULT; break; }
            for (size_t j = 0; j < n; j++) {
                unsigned char ch = chunk[j];
                if (ch >= 0x20 && ch < 0x7f) {
                    if (length < DM_UIMSG_NAME_MAX) candidate[length] = (char)ch;
                    if (length <= DM_UIMSG_NAME_MAX) length++;
                } else {
                    if (ch == 0 && length >= 3 && length <= DM_UIMSG_NAME_MAX)
                        error = add_name(table, candidate, length, &count, &bytes);
                    length = 0;
                    if (error) break;
                }
            }
            offset += n;
        }
        if (error) break;
    }
    if (error) { free_names(table); return error; }
    *output = table; return 0;
}
int dm_uimsg_configure(const dm_uimsg_config *config) {
    if (!config || !config->read || !config->ro_span || !config->gate_present || !config->gate_set || !config->failure) return -EINVAL;
    name_entry *table = NULL;
    int error = build_names(config, &table);
    if (error) return error;
    pthread_mutex_lock(&bus_lock);
    name_entry *old = names; names = table; current = *config;
    pthread_mutex_unlock(&bus_lock);
    free_names(old);
    return 0;
}
void dm_uimsg_reset(void) {
    pthread_mutex_lock(&bus_lock);
    name_entry *old = names; names = NULL;
    memset(&current, 0, sizeof current);
    memset(subscribers, 0, sizeof subscribers); subscriber_count = 0;
    pthread_mutex_unlock(&bus_lock);
    free_names(old);
}
static int lookup(uint64_t hash, char output[DM_UIMSG_NAME_MAX + 1]) {
    if (names) {
        size_t index = hash >> (64 - HASH_BITS);
        while (names[index].name) {
            if (names[index].hash == hash) { strcpy(output, names[index].name); return 1; }
            index = (index + 1) & (HASH_SIZE - 1);
        }
    }
    snprintf(output, DM_UIMSG_NAME_MAX + 1, "%#" PRIx64, hash); return 0;
}
int dm_uimsg_decode(const uint64_t *registers, dm_uimsg_message *message) {
    if (!registers || !message) return 0;
    pthread_mutex_lock(&bus_lock); dm_uimsg_config config = current; pthread_mutex_unlock(&bus_lock);
    if (!config.read) return 0;
    dm_uimsg_message decoded = {0};
    if (config.read(config.context, registers[1], decoded.fields, sizeof decoded.fields) != sizeof decoded.fields) return 0;
    if (decoded.fields[2]) {
        size_t got = config.read(config.context, decoded.fields[2], decoded.argument, 64);
        if (got <= 64 && got) {
            for (size_t i = 0; i < got; i++) {
                unsigned char ch = (unsigned char)decoded.argument[i];
                if (!ch) { decoded.have_argument = 1; break; }
                if (ch < 0x20 || ch >= 0x7f) break;
            }
        }
    }
    if (!decoded.have_argument) decoded.argument[0] = 0;
    pthread_mutex_lock(&bus_lock);
    decoded.category_known = lookup(decoded.fields[0], decoded.category);
    decoded.action_known = lookup(decoded.fields[1], decoded.action);
    pthread_mutex_unlock(&bus_lock);
    *message = decoded; return 1;
}
void uimsg_emit(const char *category, const char *action, const char *argument) {
    dm_uimsg_subscriber snapshot[DM_UIMSG_SUBSCRIBERS];
    pthread_mutex_lock(&bus_lock);
    size_t count = subscriber_count; memcpy(snapshot, subscribers, count * sizeof *snapshot);
    pthread_mutex_unlock(&bus_lock);
    for (size_t i = 0; i < count; i++) snapshot[i](category, action, argument);
}
void uimsg_subscribe(dm_uimsg_subscriber callback) {
    pthread_mutex_lock(&bus_lock); dm_uimsg_config config = current; pthread_mutex_unlock(&bus_lock);
    const char *error = NULL;
    if (!callback) error = "null UI message subscriber";
    else if (!config.gate_present || !config.gate_present(config.context)) error = "missing UI observation gate OBS_UIMSG";
    else {
        pthread_mutex_lock(&bus_lock);
        if (subscriber_count == DM_UIMSG_SUBSCRIBERS) error = "more than 8 UI message subscribers";
        else subscribers[subscriber_count++] = callback;
        pthread_mutex_unlock(&bus_lock);
    }
    if (error) {
        if (config.failure) config.failure(config.context, error);
        else { fprintf(stderr, "[dm] FATAL %s\n", error); abort(); }
        return;
    }
    config.gate_set(config.context, dm_uimsg_observe);
}
void dm_uimsg_observe(const uint64_t *registers) {
    dm_uimsg_message message;
    if (!dm_uimsg_decode(registers, &message)) return;
    pthread_mutex_lock(&bus_lock); dm_uimsg_config config = current; pthread_mutex_unlock(&bus_lock);
    if (config.on_message) config.on_message(config.context, registers, &message, 0);
    uimsg_emit(message.category, message.action, message.argument);
    if (config.on_message) config.on_message(config.context, registers, &message, 1);
}
