// Shared NVN backend contract. A binding is immutable while guest work is live.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "nvn_obj.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum { NVN_OK = 0, NVN_UNSUPPORTED, NVN_INVALID, NVN_RETAINED,
               NVN_DEVICE_FAILED, NVN_PUBLICATION_FAILED, NVN_UNAVAILABLE } nvn_error_code;
typedef struct { nvn_error_code code; uint32_t operation; const char *reason; } nvn_result;
typedef enum { NVN_PENDING, NVN_COMPLETED, NVN_FAILED } nvn_wait_status;
typedef struct { nvn_wait_status status; nvn_result error; } nvn_wait_result;
enum { NVN_STORAGE_READ = 1u, NVN_STORAGE_WRITE = 2u };
enum { NVN_CAP_OFFSCREEN = 1, NVN_CAP_FULL_PRODUCT = 2 };
typedef struct nvn_backend_ops {
    uint32_t abi_version, capabilities;
    nvn_result (*device_initialize)(void *, const dev_t_ *);
    nvn_result (*device_finalize)(void *, const dev_t_ *);
    nvn_result (*pool_add)(void *, NVNmemoryPool *, const pool_t *);
    nvn_result (*pool_del)(void *, NVNmemoryPool *);
    nvn_result (*tex_register)(void *, NVNtexture *, const tex_t *);
    nvn_result (*tex_release)(void *, NVNtexture *);
    nvn_result (*prog_release)(void *, const prog_t *);
    // Replacement is transactional. Failure preserves the complete old backend
    // revision. All staging allocations and source copies precede its commit.
    nvn_result (*prog_replace)(void *, const prog_t *old_or_null, const prog_t *candidate);
    nvn_result (*prog_copy_shaders)(void *, const NVNshaderData *source, uint32_t count,
                                  NVNshaderData *owned_array);
    // Establish full sizeof(NVNprogram) readable storage before any core access;
    // writable==1 also establishes no-fail writes through the synchronous call.
    nvn_result (*prog_storage_acquire)(void *, const NVNprogram *, uint32_t writable, void **owned_token);
    void (*prog_storage_release)(void *, void *owned_token);
    nvn_result (*prog_acquire)(void *, const prog_t *, uint32_t requested_stages,
                              void **owned_token, uint32_t *actual_stages);
    void (*prog_unacquire)(void *, void *owned_token);
    nvn_result (*tex_pool_init)(void *, NVNtexturePool *, const dpool_t *);
    nvn_result (*tex_pool_release)(void *, NVNtexturePool *);
    nvn_result (*samp_pool_init)(void *, NVNsamplerPool *, const dpool_t *);
    nvn_result (*samp_pool_release)(void *, NVNsamplerPool *);
    nvn_result (*reg_tex)(void *, const NVNtexturePool *, int, const NVNtexture *, const NVNtextureView *);
    nvn_result (*reg_samp)(void *, const NVNsamplerPool *, int, const NVNsampler *);
    nvn_result (*sampler_init)(void *, NVNsampler *, const samp_t *);
    nvn_result (*sampler_release)(void *, NVNsampler *);
    nvn_result (*read_texels)(void *, const tex_t *, int, int, const NVNcopyRegion *, void *, size_t, size_t);
    // Submit must validate the entire graph before acceptance. Runtime ownership,
    // prior GPU-write retirement and checked snapshot/publication live in adapter.
    nvn_result (*submit)(void *, queue_t *, int, const uint64_t *);
    uint64_t (*last_fence)(void *);
    nvn_wait_result (*wait)(void *, uint64_t, uint64_t);
    nvn_result (*finish)(void *);
    nvn_result (*drain)(void *);
    nvn_result (*queue_error)(void *, const queue_t *);
    // Called without core locks, under the current validated guest invocation.
    nvn_result (*command_callback)(void *, cmd_t *, size_t);
    uint64_t (*frame_count)(void *);
    // Complete range/permission owners, held through the synchronous W0 call.
    nvn_result (*window_storage_acquire)(void *, const void *, size_t, uint32_t, void **);
    void (*window_storage_release)(void *, void *);
    nvn_result (*window_finalize)(void *, NVNwindow *);
    nvn_result (*window_set_present_interval)(void *, NVNwindow *, int);
    nvn_result (*window_set_crop)(void *, NVNwindow *, int, int, int, int);
    nvn_result (*window_init)(void *, NVNwindow *, const NVNwindowBuilder *);
    NVNwindowAcquireTextureResult (*window_acquire)(void *, NVNwindow *, NVNsync *, int *);
    nvn_result (*window_present)(void *, NVNqueue *, NVNwindow *, int);
} nvn_backend_ops;
#define NVN_BACKEND_ABI_VERSION 4u
#if defined(__APPLE__)
nvn_result nvn_apple_descriptor_pool(const dpool_t *, int sampler, int apply);
#endif
nvn_result nvn_core_bind(const nvn_backend_ops *, void *context);
// Caller first stops guest entry and retires backend work. Refuses without
// mutation while any recorder segment is retained; success invalidates the old
// recorder epoch, allowing a new load without fabricating presented frames.
nvn_result nvn_core_unbind(void);
// Returned reason is an owned thread-local snapshot, valid until the next
// last_error call on this thread (including across quiescent unbind/rebind).
nvn_result nvn_core_last_error(void);
const nvn_backend_ops *nvn_core_backend(void **context);
void nvn_core_record_error(nvn_result);
void *nvn_core_lookup(const char *);
uint64_t nvn_core_profile_clock(void);
// A successful acquire retains both the authoritative core revision and its
// backend resources. The copied snapshot is never a guest object address.
typedef struct nvn_program_ref nvn_program_ref;
nvn_result nvn_core_program_acquire(const prog_t *copied_snapshot, uint32_t requested_stages,
                                    nvn_program_ref **out);
const prog_t *nvn_core_program_snapshot(const nvn_program_ref *);
void *nvn_core_program_backend_token(const nvn_program_ref *);
uint32_t nvn_core_program_stage_mask(const nvn_program_ref *);
uint64_t nvn_core_program_binding_epoch(const nvn_program_ref *);
void nvn_core_program_release(nvn_program_ref *);
uint64_t nvn_core_binding_epoch(void);
// Only live recorder-owned host segments can be retained; arbitrary pointers are
// never admitted. Retention prevents frame-age reuse until the final release.
typedef struct { uint32_t slot; uint64_t generation; } nvn_host_segment_lease;
int nvn_core_host_segment_retain(uint64_t address, size_t size, nvn_host_segment_lease *);
int nvn_core_host_segment_copy(nvn_host_segment_lease, uint64_t address, size_t size, void *);
void nvn_core_host_segment_release(nvn_host_segment_lease);
void nvn_core_command_stats_frame(void);
#ifdef __cplusplus
}
#endif
