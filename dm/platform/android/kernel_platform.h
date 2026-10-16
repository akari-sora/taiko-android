#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Memory adapter: a live SDK MapMemory stack is pinned until host-side exit.
int dm_android_kernel_stack_pin(uint64_t top, uint64_t* bottom, size_t* size);
void dm_android_kernel_stack_unpin(uint64_t bottom);
int dm_android_kernel_memory_accessible(uint64_t address, size_t size, int write);
int dm_android_kernel_memory_reset(void);
int dm_android_kernel_memory_quiescent(void);

// Runtime: returns actual guest invocation or pthread stack bounds.
int dm_android_current_stack_bounds(uint64_t address, uint64_t* bottom, size_t* size);
int dm_android_current_guest_memory(uint64_t address, size_t size, int write);
int dm_android_current_guest_range(uint64_t address, uint64_t* base, size_t* size);
int dm_android_current_guest_region(uint64_t address, uint64_t* base, size_t* size, unsigned* flags);
struct DmGuestThreadState;
void dm_android_configure_kernel_state(struct DmGuestThreadState* state);

// Thread adapter: returns only after restoring host SP and releasing guest
// invocation resources. One means an explicit ExitThread; zero means invalid
// setup or an unexpected guest entry return. Never pthread_exit on guest SP.
int dm_android_kernel_thread_run(uint64_t entry, uint64_t argument, uint64_t stack_top);
#if defined(__cplusplus)
[[noreturn]]
#else
_Noreturn
#endif
void dm_android_kernel_thread_exit(uint64_t value);

// Shared original thread service lifetime; shutdown must reject live workers.
int dm_android_kernel_threads_reset(void);
int dm_android_kernel_threads_quiescent_except_current(void);
void dm_android_kernel_thread_stats(unsigned* handles, unsigned* live, unsigned* objects);
void dm_android_kernel_thread_finish_current(void);
void dm_android_guest_clock_reset(void);
void dm_android_host_objects_reset(void);

// Shared host bridge: logical validated module segment or hole at address.
// flags use DM_GUEST_READ/WRITE/EXEC; zero means a reserved image hole.
int dm_android_host_query_memory(uint64_t address, uint64_t* base, size_t* size, unsigned* flags);

#ifdef __cplusplus
}
#endif
