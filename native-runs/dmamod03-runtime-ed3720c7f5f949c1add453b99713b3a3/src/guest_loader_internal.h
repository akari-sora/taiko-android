#pragma once
#include "guest_abi.h"
// Implementation-only bridge. All extended authority validation must finish in
// prepare_package before entering the mapper. Public raw APIs never use true.
bool dm_android_guest_prepare_package_image(const DmGuestImage&, DmGuestLoadedImage*,
                                           char*, size_t, bool canonical_v2_validated,
                                           bool canonical_profile_validated);
