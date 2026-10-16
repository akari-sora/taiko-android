#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Prepare only before publishing a runtime; paths belong to app-private storage.
int dm_android_app_services_prepare(const char* locale, const char* custom_directory);
void dm_android_app_services_reset(void);
int dm_android_i18n_prepare(const char* locale);
void dm_android_custom_reset(void);
int dm_android_runtime_is_active(void);
// Listener and write hooks remain valid until quiescent service reset.
void dm_android_save_failure_listener(void (*callback)(int, void*), void* context);
uint64_t dm_android_save_failure_count(void);
int dm_android_last_save_error(void);
#ifdef __cplusplus
}
#endif
