#pragma once
#include <stdint.h>

// DMAMOD02 retains its layout. Older decoders reject this required-contract bit.
#define DM_MODULE_REQUIRE_DIAG_ABORT_V1 (1u << 1)
#define DM_DIAG_ABORT_IMPL_SYMBOL "_ZN2nn4diag6detail9AbortImplEPKcS3_S3_i"
#define DM_DIAG_ABORT_RESOLVER_V1 "__dm_android_diag_abort_v1"

#ifdef __cplusplus
extern "C" {
#endif
// Only the canonical hidden ASM entry implements this contract. It clears the
// monitor before touching memory, captures guest LR/SP, and never returns.
void dm_android_diag_abort_entry(uint64_t arg0, uint64_t arg1,
                                uint64_t arg2, uint64_t line)
    __attribute__((weak, visibility("hidden"), noreturn));
#ifdef __cplusplus
}

namespace dm_android {
struct DiagAbortCaller {
    const char* module = nullptr; // Borrowed from the live, immutable Process.
    uint64_t callsite = 0;
};
}
#endif
