#pragma once
#include <cstdint>
#include <string>
// The caller retains its process diagnostic ownership scope. Poll executes the
// actual guest against current input; it does not synthesize controller state.
std::string dm_android_run_controller_probes();
bool dm_android_controller_begin(uint64_t* handle,std::string* error);
bool dm_android_controller_poll(uint64_t handle,std::string* report,std::string* error);
bool dm_android_controller_end(uint64_t handle,std::string* error);
