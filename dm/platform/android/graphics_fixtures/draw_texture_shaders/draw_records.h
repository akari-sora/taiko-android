#pragma once
#include <stdint.h>
/* Authored Maxwell diagnostics; no original-game authority. */
static const uint8_t sampled_draw_shader_vs_record[] __attribute__((aligned(16))) = {
#include "authored_vs_position.record.inc"
};
static const uint8_t sampled_draw_shader_fs_record[] __attribute__((aligned(16))) = {
#include "authored_d2_fragcoord_clamp_fs.record.inc"
};
