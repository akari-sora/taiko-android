#ifndef DM_EXTENT_MAP_H
#define DM_EXTENT_MAP_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DM_EXTENT_MAX_TEXT (8u * 1024u * 1024u)
#define DM_EXTENT_MAX_HOLES 131072u
typedef struct { int64_t logical, length, physical; } dm_extent;
typedef struct {
    int64_t logical_size, physical_size;
    size_t count;
    dm_extent *kept;
} dm_extent_map;
enum { DM_EXTENT_SIZE_MISMATCH = -2, DM_EXTENT_INVALID = -1, DM_EXTENT_ABSENT = 0, DM_EXTENT_VALID = 1 };
/* ABSENT means ENOENT only. INVALID leaves *out NULL and a bounded diagnostic.
 * physical_size is obtained from the archive fd (or a checked stat), not the sidecar. */
int dm_extent_map_load(const char *hostpath, int64_t physical_size, dm_extent_map **out, char *why, size_t why_n);
/* Readiness needs to distinguish a valid table paired with an incomplete copy.
 * This variant returns SIZE_MISMATCH and its expected physical byte count, but
 * still publishes no usable map on failure. The ordinary loader returns INVALID. */
int dm_extent_map_load_detail(const char *hostpath, int64_t physical_size, dm_extent_map **out, char *why, size_t why_n, int64_t *expected_physical, int64_t *expected_logical);
void dm_extent_map_free(dm_extent_map *map);
ssize_t dm_extent_map_pread(const dm_extent_map *map, int fd, void *buf, size_t n, off_t off);
#ifdef __cplusplus
}
#endif
#endif
