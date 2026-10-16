#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
// The caller retains process diagnostic ownership. Ordinary Pending/Failed GPU
// outcomes are reports; false denotes invalid API/handle or guest/control error.
std::string dm_android_run_graphics_probes();
// Separate schema/suite for guest cross-submit and controlled failure cases.
std::string dm_android_run_graphics_extended_probes();
std::string dm_android_run_shader_compute_probes();
std::string dm_android_run_vi_probes();
std::string dm_android_run_window_probes();
std::string dm_android_run_sampled_draw_probes();
// Debug compositor observation only; metadata never grants graphics authority.
std::string dm_android_sampled_frame_snapshot();
bool dm_android_sampled_frame_ack(uint64_t id,unsigned frame);
// Owned, tightly packed RGBA8 after checked guest publication and fence retirement.
// Row0 is the upper framebuffer row. Observed generations are receipts, not permits.
struct DmGraphicsDrawReadback {
    uint32_t width=0,height=0,row_stride_bytes=0;
    bool top_row_first=true;
    uint64_t load_generation=0,runtime_generation=0,binding_epoch=0;
    std::vector<uint8_t> rgba8;
};
// Optional synchronous consumer runs after checked readback while the same Process
// remains live, before runtime shutdown. False fails the probe and still cleans up.
std::string dm_android_run_shader_draw_probes(DmGraphicsDrawReadback* image=nullptr,
    const std::function<bool(const DmGraphicsDrawReadback&,std::string*)>& present={});
bool dm_android_graphics_begin(uint64_t* handle,std::string* error);
bool dm_android_graphics_poll(uint64_t handle,std::string* report,std::string* error);
bool dm_android_graphics_wait(uint64_t handle,uint64_t timeout_ns,std::string* report,std::string* error);
bool dm_android_graphics_end(uint64_t handle,std::string* error);
struct DmGraphicsPublicationBarrier {
    uint64_t id=0,load_generation=0,fence=0;
    bool armed=false,entered=false,released=false;
};
// Metadata controls never take the persistent probe mutex and remain usable
// while an ordinary wait retains its diagnostic borrower and actual guest call.
bool dm_android_graphics_arm_publication_barrier(uint64_t* id,std::string* error);
bool dm_android_graphics_publication_barrier_snapshot(uint64_t id,DmGraphicsPublicationBarrier* out,std::string* error);
bool dm_android_graphics_release_publication_barrier(uint64_t id,std::string* error);
// Requires this exact generation's real completion worker to be inside its
// unreleased publication barrier. Does not take the persistent probe mutex.
bool dm_android_graphics_retention_snapshot(uint64_t barrier_id,std::string* report,std::string* error);
