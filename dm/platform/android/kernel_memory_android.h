#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Returns one only for memory SVCs implemented by the Android adapter. */
int dm_android_memory_svc(int number, uint64_t* registers);
/* Nonmutating shutdown preflight. Runtime lifecycle serialization prevents new
 * guest entries/pins between this check and actual reset. */
int dm_android_kernel_memory_quiescent(void);
int dm_android_heap_readable(uint64_t address, size_t size);
/* Internal checked-copy backend. Output is private trusted staging, not guest
 * memory. Holds the mapping-owner mutex through logical 4 KiB permission and
 * coverage validation AND memcpy, including on 16 KiB host pages. No host-query
 * or generic pthread-stack fallback; only this adapter's owned address space.
 * Mapping mutations must go through this adapter's owner APIs. */
int dm_android_kernel_memory_copy_readable(uint64_t source, void* staging, size_t size);
/* General asynchronous GPU range retention. Pins exact logical permissions and
 * coverage; unrelated mappings remain mutable. No host stack/query fallback. */
uint64_t dm_android_kernel_gpu_pin(uint64_t address, size_t size, unsigned permissions);
void dm_android_kernel_gpu_unpin(uint64_t token);
int dm_android_kernel_gpu_copy(uint64_t token, uint64_t source, void* staging, size_t size);
void dm_android_memory_range(uint8_t** base, size_t* size);
#ifdef __cplusplus
}
#endif
