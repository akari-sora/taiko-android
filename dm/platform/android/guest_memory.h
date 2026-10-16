#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DM_ANDROID_GUEST_COPY_MAX_BYTES ((size_t)65536)

/* Copies only recognized guest-owned readable memory. The caller owns a valid,
 * trusted output buffer. Failure leaves it unchanged, including when an owner
 * refuses a span after partial internal staging. Zero length is refused.
 * Owners serialize mapping lifetime/permissions with the copy; this does not
 * make a snapshot of guest data concurrently modified by guest instructions.
 * Arbitrary native munmap/mprotect outside those owner APIs is not supported. */
int dm_android_guest_copy(uint64_t source, void* out, size_t bytes);

#ifdef __cplusplus
}
#endif
