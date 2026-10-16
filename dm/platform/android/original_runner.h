#pragma once
#include <cstdint>
#include <string>

namespace dm_android {
// Blocking owner-thread operation. The caller holds the process's exclusive
// diagnostic/runtime ownership through preparation, guest execution and cleanup.
// Paths are derived from Android Context.filesDir, never a document-provider URI.
// No Java/JNI calls occur while the guest stack is attached.
std::string run_original_entry(const std::string& files_directory,
                               const std::string& locale, uint64_t activity_owner);
}
