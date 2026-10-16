#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Call only after worker completion and kernel SystemEvent bindings reset,
// while the old module bridge is still published. Returns zero if workers live.
int dm_android_services_reset(void);
// Only actual owned service buffers are exposed, never a Bionic TLS page.
int dm_android_services_query_memory(uint64_t address, uint64_t* base, size_t* size, unsigned* flags);

// Common-C implementation hooks; lifecycle belongs to services_reset above.
void dm_android_time_services_reset(void);
int dm_android_time_services_query_memory(uint64_t address, uint64_t* base, size_t* size, unsigned* flags);
void dm_android_friends_services_reset(void);
int dm_android_friends_services_query_memory(uint64_t address, uint64_t* base, size_t* size, unsigned* flags);
void dm_android_misc_services_reset(void);
#ifdef __cplusplus
}
#endif
