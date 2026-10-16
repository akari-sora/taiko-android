cmake_minimum_required(VERSION 3.22.1)
project(d2r_diagnostics LANGUAGES C CXX ASM)
option(DM_TARGET_TAIKO "Build the independent Taiko target without D2R program authority" ON)
if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
  message(FATAL_ERROR "Phase 0 requires Android arm64-v8a")
endif()
find_package(game-activity REQUIRED CONFIG)
add_library(d2r_diagnostics SHARED diagnostics.cpp
  ../../platform/android/diagnostic_gate.S
  ../../platform/android/guest_state.cpp
  ../../platform/android/guest_parameters.cpp
  ../../platform/android/guest_memory.cpp
  ../../platform/android/observation_profile.cpp
  ../../platform/android/observation_platform.cpp
  ../../platform/android/observation_probes.cpp
  ../../platform/android/oe_platform.cpp
  ../../platform/android/diagnostic_session.cpp
  ../../platform/android/applet_probes.cpp
  ../../platform/android/controller_platform.cpp
  ../../platform/android/controller_probes.cpp
  ../../platform/android/graphics_probes.cpp
  ../../platform/android/graphics_platform.cpp
  ../../platform/android/graphics_surface.cpp
  ../../platform/android/vi_platform.cpp
  ../../platform/android/nvn_submit.cpp
  ../../platform/android/shader_artifact.cpp
  ../../platform/android/program_resolver.cpp
  ../../platform/android/shader_compute_catalog.cpp
  ../../platform/android/shader_draw_catalog.cpp
  ../../platform/android/original_name.cpp
  ../../platform/android/keyboard_platform.cpp
  ../../platform/android/audio_platform.cpp
  ../../platform/android/audio_focus.cpp
  ../../platform/android/diagnostic_authority.cpp
  ../../platform/android/original_bringup.cpp
  ../../platform/android/original_runner.cpp
  ../../platform/android/guest_loader.cpp
  ../../platform/android/guest_entry.S
  ../../platform/android/guest_probes.cpp
  ../../platform/android/exclusive_probes.cpp
  ../../platform/android/input_platform.cpp
  ../../platform/android/touch_controls_platform.cpp
  ../../platform/android/input_activity.cpp
  ../../platform/android/module_runtime.cpp
  ../../platform/android/module_sha256.cpp
  ../../platform/android/module_probes.cpp
  ../../platform/android/guest_thread.cpp
  ../../platform/android/guest_call.S
  ../../platform/android/guest_bootstrap.cpp
  ../../platform/android/host_bridge.cpp
  ../../platform/android/kernel_runtime.cpp
  ../../platform/android/kernel_probes.cpp
  ../../platform/android/service_probes.cpp
  ../../platform/android/kernel_memory_android.c
  ../../platform/android/kernel_thread_adapter.cpp
  ../../platform/android/app_platform.c
  ../../platform/android/service_platform.c
  ../../platform/android/fs_platform.c
  ../../host/hle_sdkinit.c
  ../../host/hle_net.c
  ../../host/hle_os.c
  ../../host/hle_oe_core.c
  ../../host/hle_hid_core.c
  ../../host/dm_gamepad_core.c
  ../../host/hle_svc.c
  ../../host/hle_thread.c
  ../../host/hle_account.c
  ../../host/hle_friends.c
  ../../host/hle_misc.c
  ../../host/hle_time.c
  ../../host/hle_fs.c
  ../../host/hle_touch.c
  ../../host/hle_touch_exports.c
  ../../host/hle_swkbd.c
  ../../host/hle_audio.c
  ../../host/extent_map.c
  ../../host/romfs_validate.c
  ../../host/dm_i18n.c
  ../../host/dm_uimsg.c
  ../../ios/Sources/dm_touch_game_identity.c
  ../../ios/Sources/dm_touch_controls.c
  ../../host/dm_custom.c
  ../../gfx/nvn/hle_nvn_core.c
  ../../gfx/nvn/hle_nvn.c
  ../../gfx/nvn/nvn_tex.c
  ../../gfx/nvn/nvn_thunks_android.S
  ../../gfx/nvn/nvn_entry_android.S
  ../../gfx/tex/nvn_deswizzle.c
  ../../gfx/vulkan/nvn_vk.cpp
  ../../gfx/vulkan/compute_bindings.cpp
  ../../gfx/vulkan/draw_bindings.cpp)
# A provider is emitted only after all actual retail capsules and independent
# source/callback audits succeed. Its absence keeps original startup unavailable.
# Track this exact generated file appearing/disappearing too: a cached absent
# provider must not leave a later successful import out of the next binary.
file(GLOB DM_ORIGINAL_PINS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/android/original_build_pins.cpp")
if(DM_ORIGINAL_PINS AND NOT DM_TARGET_TAIKO)
  target_sources(d2r_diagnostics PRIVATE ${DM_ORIGINAL_PINS})
endif()
if(DM_TARGET_TAIKO)
  target_compile_definitions(d2r_diagnostics PRIVATE DM_TARGET_TAIKO=1)
endif()
target_include_directories(d2r_diagnostics PRIVATE ../../gfx/nvn/include)
set_source_files_properties(../../host/dm_custom.c PROPERTIES COMPILE_DEFINITIONS DM_ANDROID_CONFIG_ONLY=1)
target_compile_features(d2r_diagnostics PRIVATE c_std_11 cxx_std_17)
target_compile_options(d2r_diagnostics PRIVATE -Wall -Wextra -Werror -ffixed-x18)
target_link_options(d2r_diagnostics PRIVATE "-Wl,-u,GameActivity_onCreate" "-Wl,-u,JNI_OnLoad")
target_link_options(d2r_diagnostics PRIVATE "-Wl,-z,nostart-stop-gc"
  "-Wl,--undefined=__start_swhle" "-Wl,--undefined=__start_swforce"
  "-Wl,--undefined=__start_swnvn")
target_link_libraries(d2r_diagnostics PRIVATE game-activity::game-activity_static android log vulkan aaudio)
