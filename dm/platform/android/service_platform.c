#include "service_platform.h"
#include "kernel_platform.h"

// Headless service-contract binaries have no frontend. The APK links this
// strong hook so quiescent teardown also clears provider slots/pending touches.
extern void dm_android_input_reset(void) __attribute__((weak));

int dm_android_services_reset(void) {
    if (!dm_android_kernel_threads_quiescent_except_current()) return 0;
    dm_android_time_services_reset();
    dm_android_friends_services_reset();
    dm_android_misc_services_reset();
    if (dm_android_input_reset) dm_android_input_reset();
    return 1;
}
int dm_android_services_query_memory(uint64_t address, uint64_t* base, size_t* size, unsigned* flags) {
    if (!base || !size || !flags) return 0;
    return dm_android_friends_services_query_memory(address, base, size, flags) ||
           dm_android_time_services_query_memory(address, base, size, flags);
}
