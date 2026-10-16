#pragma once
#include "nvn_backend.h"
#include "nvn_count.h"
#ifdef __cplusplus
extern "C" {
#endif
#ifndef __cplusplus
#include <stdatomic.h>
typedef struct { _Atomic uint64_t cnt; void *fn; } nvn_slot_t;
extern nvn_slot_t nvn_slot[NVN_NFUNC];
extern _Atomic uint64_t nvn_prof_ticks[NVN_NFUNC];
#endif
extern void *nvn_real[NVN_NFUNC];
extern void *nvn_thunk[NVN_NFUNC];
extern const char *nvn_names[NVN_NFUNC];
#ifdef __cplusplus
}
#endif
