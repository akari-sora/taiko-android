#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// These are virtual guest values. No host TLS or reserved x18 is modified.
uint64_t dm_android_get_guest_x18(void);
uint64_t dm_android_get_guest_tls(void);
uint64_t dm_android_get_guest_tlr(void);
void dm_android_set_guest_x18(uint64_t value);
void dm_android_set_guest_tls(uint64_t value);
void dm_android_set_guest_tlr(uint64_t value);
int dm_android_host_query_memory(uint64_t address, uint64_t* base, uint64_t* size, unsigned* flags);
#ifdef __cplusplus
}
#endif
