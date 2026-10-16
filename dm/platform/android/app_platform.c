#include "app_platform.h"
#include "../../host/dm.h"
#include "../../host/dm_custom.h"
#include <stdatomic.h>
#include <sys/stat.h>
#include <time.h>

static pthread_mutex_t g_callbacks_lock = PTHREAD_MUTEX_INITIALIZER;
static void (*g_write_callbacks[4])(void*, size_t);
static unsigned g_write_callback_count;
static void (*g_save_callback)(int, void*);
static void* g_save_context;
static _Atomic uint64_t g_save_failures;
static _Atomic int g_last_save_error;
static char* g_previous_timezone;
static int g_timezone_overridden;
static void restore_timezone(void) {
    if (!g_timezone_overridden) return;
    const int error = g_previous_timezone ? setenv("TZ", g_previous_timezone, 1) : unsetenv("TZ");
    if (error) die("cannot restore Android service timezone");
    free(g_previous_timezone); g_previous_timezone = NULL;
    g_timezone_overridden = 0;
    tzset();
}

int dm_android_app_services_prepare(const char* locale, const char* directory) {
    struct stat status;
    if (dm_android_runtime_is_active() || !locale || strlen(locale) >= 64 || !directory ||
        strlen(directory) >= 1024 || stat(directory, &status) || !S_ISDIR(status.st_mode)) return 0;
    dm_android_custom_reset();
    if (!dm_android_i18n_prepare(locale)) return 0;
    dm_custom_init(directory);
    restore_timezone();
    // Matches original main.c: fixed-time comparison pins calendar time to UTC.
    if (getenv("DM_FIXED_TIME")) {
        const char* previous = getenv("TZ");
        if (previous && !(g_previous_timezone = strdup(previous))) return 0;
        if (setenv("TZ", "UTC", 1)) { free(g_previous_timezone); g_previous_timezone = NULL; return 0; }
        g_timezone_overridden = 1;
    }
    tzset();
    return 1;
}
void dm_android_app_services_reset(void) {
    restore_timezone();
    pthread_mutex_lock(&g_callbacks_lock);
    memset(g_write_callbacks, 0, sizeof g_write_callbacks);
    g_write_callback_count = 0;
    g_save_callback = NULL; g_save_context = NULL;
    pthread_mutex_unlock(&g_callbacks_lock);
    atomic_store(&g_save_failures, 0);
    atomic_store(&g_last_save_error, 0);
    dm_android_custom_reset();
    (void)dm_android_i18n_prepare("");
}
void dm_guest_write_prep_register(void (*callback)(void*, size_t)) {
    if (!callback) die("null guest write-preparation hook");
    pthread_mutex_lock(&g_callbacks_lock);
    if (g_write_callback_count == 4) die("too many guest write-preparation hooks");
    g_write_callbacks[g_write_callback_count++] = callback;
    pthread_mutex_unlock(&g_callbacks_lock);
}
void dm_guest_write_prepare(void* address, size_t size) {
    void (*callbacks[4])(void*, size_t);
    pthread_mutex_lock(&g_callbacks_lock);
    const unsigned count = g_write_callback_count;
    memcpy(callbacks, g_write_callbacks, count * sizeof *callbacks);
    pthread_mutex_unlock(&g_callbacks_lock);
    for (unsigned i = 0; i < count; ++i) callbacks[i](address, size);
}
void dm_android_save_failure_listener(void (*callback)(int, void*), void* context) {
    pthread_mutex_lock(&g_callbacks_lock);
    g_save_callback = callback; g_save_context = context;
    pthread_mutex_unlock(&g_callbacks_lock);
}
void front_save_failed(int error) {
    atomic_store(&g_last_save_error, error);
    atomic_fetch_add(&g_save_failures, 1);
    pthread_mutex_lock(&g_callbacks_lock);
    void (*callback)(int, void*) = g_save_callback;
    void* context = g_save_context;
    pthread_mutex_unlock(&g_callbacks_lock);
    if (callback) callback(error, context);
    else LOG("Android save transaction rejected: errno=%d (no front-end listener)", error);
}
uint64_t dm_android_save_failure_count(void) { return atomic_load(&g_save_failures); }
int dm_android_last_save_error(void) { return atomic_load(&g_last_save_error); }
