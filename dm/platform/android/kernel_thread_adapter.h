#pragma once
#include "kernel_platform.h"

// Finish a main-thread attachment only AFTER GuestStack::call returned to its
// host frame. Worker attachments finish automatically after adapter cleanup.
#ifdef __cplusplus
extern "C" {
#endif
void dm_android_kernel_thread_finish_current(void);
#ifdef __cplusplus
}
#endif
