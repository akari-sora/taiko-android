cmake_minimum_required(VERSION 3.22.1)
project(dm_aarch64_harness LANGUAGES C CXX ASM)

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
  message(FATAL_ERROR "dm_aarch64_harness requires Android arm64-v8a")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

get_filename_component(DM_DEFAULT_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(DM_REPO_ROOT "${DM_DEFAULT_REPO_ROOT}" CACHE PATH "Selected DM repository root")

set(DM_GUEST_LOADER_CPP "${DM_REPO_ROOT}/dm/platform/android/guest_loader.cpp")
if(NOT EXISTS "${DM_GUEST_LOADER_CPP}")
  message(FATAL_ERROR "Missing guest_loader.cpp at ${DM_GUEST_LOADER_CPP}")
endif()
file(SHA256 "${DM_GUEST_LOADER_CPP}" DM_GUEST_LOADER_SHA256)

set(DM_HARNESS_COMMON_COMPILE_OPTIONS
  -Wall
  -Wextra
  -Werror
  -ffixed-x18
  -fasynchronous-unwind-tables
)

set(DM_HARNESS_COMMON_LINK_OPTIONS
  "-Wl,-z,max-page-size=16384"
  "-Wl,-z,common-page-size=16384"
  "-Wl,-z,relro,-z,now"
  "-Wl,--build-id=sha1"
)

add_library(synthetic_guest_dso SHARED
  synthetic_guest_dso.S
)
set_target_properties(synthetic_guest_dso PROPERTIES
  LINKER_LANGUAGE C
  PREFIX "lib"
  OUTPUT_NAME "synthetic_guest_dso"
  SUFFIX ".so"
)
target_compile_options(synthetic_guest_dso PRIVATE ${DM_HARNESS_COMMON_COMPILE_OPTIONS})
target_link_options(synthetic_guest_dso PRIVATE
  ${DM_HARNESS_COMMON_LINK_OPTIONS}
  "-Wl,--no-undefined"
)

add_executable(dm_aarch64_harness
  harness_main.cpp
  synthetic_guest_dso.S
  "${DM_GUEST_LOADER_CPP}"
)
target_include_directories(dm_aarch64_harness PRIVATE
  "${DM_REPO_ROOT}/dm/platform/android"
)
target_compile_definitions(dm_aarch64_harness PRIVATE
  DM_GUEST_LOADER_SHA256="${DM_GUEST_LOADER_SHA256}"
)
target_compile_features(dm_aarch64_harness PRIVATE cxx_std_17)
target_compile_options(dm_aarch64_harness PRIVATE ${DM_HARNESS_COMMON_COMPILE_OPTIONS})
target_link_options(dm_aarch64_harness PRIVATE
  -pie
  ${DM_HARNESS_COMMON_LINK_OPTIONS}
  "-Wl,--wrap=mmap"
  "-Wl,--wrap=mprotect"
  "-Wl,--wrap=munmap"
)
target_link_libraries(dm_aarch64_harness PRIVATE dl)
