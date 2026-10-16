#pragma once
#include <string>
namespace dm_android {
class Process;
// Called with runtime lifecycle serialized and no attached invocations/readers.
bool observation_platform_configure(Process&, std::string* error);
void observation_platform_reset();
}
