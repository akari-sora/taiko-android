#pragma once
#include <cstdint>
#include <string>
// Caller retains a process diagnostic ownership scope for the whole operation.
// This layer never acquires/releases the session coordinator. A failed end keeps
// the opaque handle, runtime and environment alive for an orderly retry.
std::string dm_android_run_applet_probes();
bool dm_android_applet_begin(uint64_t* handle, std::string* error);
bool dm_android_applet_poll(uint64_t handle, std::string* report, std::string* error);
bool dm_android_applet_end(uint64_t handle, std::string* error);

// Diagnostic-only one-shot pause at the self-authored fixture's import resolver.
// HleRuntime::load owns its actual lifecycle lock at that point. Arm requires an
// idle Applet diagnostic scope; snapshot/release are metadata-only controls and
// must remain callable while begin owns its normal diagnostic scope.
struct AppLoadBarrier {
    uint64_t id = 0;
    bool armed = false, waiting = false, released = false, timed_out = false;
};
bool dm_android_applet_loader_arm(uint64_t* id);
AppLoadBarrier dm_android_applet_loader_snapshot();
// Valid ID release cancels an armed pause even before the resolver reaches it.
// Stale, repeated and expired releases fail without changing the current pause.
bool dm_android_applet_loader_release(uint64_t id);
