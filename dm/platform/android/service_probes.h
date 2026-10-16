#pragma once
#include <string>
// Public, self-authored clients exercising the shared host service bodies.
std::string dm_android_run_service_probes(const std::string& files,
                                        const std::string& cache,
                                        const std::string& locale);
// Optional authored AudioOut integration suite. Runs only on a current resumed
// Activity with real focus. UI test backgrounds at phase2 and restores at phase3.
std::string dm_android_run_audio_probes();
// Metadata only:0=idle,1=preparing,2=await-background,3=await-foreground,
// 4=resumed,5=completed,6=failed. It cannot grant or drive a lifecycle state.
unsigned dm_android_audio_probe_phase();
