// Apple host forced-import registration; semantics live in the shared core.
#include "../../host/hle.h"
#include "hle_nvn_core.h"
HLE_FORCE("nvnBootstrapLoader", "NVN shared interface with the selected real graphics backend", void *, h_nvnBootstrapLoader, const char *name) { return nvn_core_lookup(name); }
