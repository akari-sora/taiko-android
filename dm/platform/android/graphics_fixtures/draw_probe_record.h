#pragma once
#include <stdint.h>
/* Separate D1 wire ABI; the existing baseline/compute records stay unchanged. */
enum {
    DM_DRAW_WIDTH=64, DM_DRAW_HEIGHT=64, DM_DRAW_ROW_STRIDE=272,
    DM_DRAW_WINDOW_BYTES=0x5000, DM_DRAW_PIXEL_OFFSET=0x100,
    DM_DRAW_POOL_BYTES=0xa0000
};
typedef struct {
    uint64_t phase,initialized,shaders,submits,wait_result,queue_error;
    uint64_t pool_address,pool_object,texture_object,program,serial,generation;
    uint64_t readback_window[4],readback_echo[4],vertex_guard,index_guard,uniform_address,event_address,negative_address;
    uint64_t vertex_address,index_address;
    uint64_t retained_finalize,retained_replace,retained_pool,retained_texture;
    uint64_t pipeline_rollback,late_invalid_error,programs_finalized;
} DmGraphicsDrawRecord;
