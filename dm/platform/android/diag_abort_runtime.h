#pragma once
#include "diag_abort_abi.h"

// Only guest_entry.S supplies the last two arguments, before any C prologue.
extern "C" [[noreturn]] void dm_android_diag_abort_from_guest(
    uint64_t arg0,uint64_t arg1,uint64_t arg2,uint64_t line,
    uint64_t guest_lr,uintptr_t guest_sp) noexcept __attribute__((visibility("hidden")));
