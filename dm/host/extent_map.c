#define _POSIX_C_SOURCE 200809L
#include "extent_map.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int invalid(char *why, size_t n, const char *message) {
    if (why && n) snprintf(why, n, "%s", message);
    errno = EINVAL; return DM_EXTENT_INVALID;
}
static int horizontal(unsigned char c) { return c == ' ' || c == '\t' || c == '\r'; }
static void spaces(const char **p, const char *end) { while (*p < end && horizontal((unsigned char)**p)) ++*p; }
static int number(const char **p, const char *end, int64_t *value) {
    spaces(p, end); if (*p == end || **p < '0' || **p > '9') return 0;
    uint64_t v = 0;
    while (*p < end && **p >= '0' && **p <= '9') {
        unsigned d = (unsigned)(**p - '0');
        if (v > ((uint64_t)INT64_MAX - d) / 10) return 0;
        v = v * 10 + d; ++*p;
    }
    *value = (int64_t)v; return 1;
}
static int append(dm_extent_map *m, size_t *capacity, int64_t logical, int64_t length) {
    if (!length) return 1;
    if (m->count == *capacity) {
        size_t cap = *capacity ? *capacity * 2 : 16;
        if (cap > DM_EXTENT_MAX_HOLES + 1u) cap = DM_EXTENT_MAX_HOLES + 1u;
        if (cap <= m->count || cap > SIZE_MAX / sizeof(dm_extent)) return 0;
        dm_extent *next = realloc(m->kept, cap * sizeof *next);
        if (!next) return 0;
        m->kept = next; *capacity = cap;
    }
    m->kept[m->count++] = (dm_extent){ logical, length, m->physical_size };
    m->physical_size += length; return 1;
}
void dm_extent_map_free(dm_extent_map *m) { if (m) { free(m->kept); free(m); } }
int dm_extent_map_load_detail(const char *hostpath, int64_t physical_size, dm_extent_map **out, char *why, size_t why_n, int64_t *expected_physical, int64_t *expected_logical) {
    if (out) *out = NULL;
    if (expected_physical) *expected_physical = -1;
    if (expected_logical) *expected_logical = -1;
    if (why && why_n) *why = 0;
    if (!hostpath || !out || physical_size < 0) return invalid(why, why_n, "invalid archive size or arguments");
    size_t path_n = strlen(hostpath);
    if (path_n > SIZE_MAX - 7 || path_n > 65536) return invalid(why, why_n, "archive path too long");
    char *path = malloc(path_n + 7);
    if (!path) return invalid(why, why_n, "extent path allocation failed");
    memcpy(path, hostpath, path_n); memcpy(path + path_n, ".holes", 7);
    int flags = O_RDONLY | O_NONBLOCK;
#if defined(__ANDROID__)
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags); int open_error = errno; free(path);
    if (fd < 0) { if (open_error == ENOENT) return DM_EXTENT_ABSENT; return invalid(why, why_n, "cannot open extent sidecar (or symlink)"); }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > DM_EXTENT_MAX_TEXT) {
        close(fd); return invalid(why, why_n, "extent sidecar is not a bounded regular file");
    }
    size_t length = (size_t)st.st_size;
    char *text = malloc(length + 1);
    if (!text) { close(fd); return invalid(why, why_n, "extent text allocation failed"); }
    size_t got = 0; int ok = 1;
    while (got < length) {
        ssize_t n = read(fd, text + got, length - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = 0; break; }
        got += (size_t)n;
    }
    char extra; ssize_t tail;
    do { tail = read(fd, &extra, 1); } while (tail < 0 && errno == EINTR);
    close(fd);
    if (!ok || tail != 0 || memchr(text, 0, length)) { free(text); return invalid(why, why_n, "extent sidecar changed, truncated, or contains NUL"); }
    text[length] = 0;
    dm_extent_map *m = calloc(1, sizeof *m);
    if (!m) { free(text); return invalid(why, why_n, "extent map allocation failed"); }
    const char *p = text, *end = text + length; size_t capacity = 0, holes = 0; int header = 0; int64_t pos = 0;
    const char *error = NULL;
    while (p < end) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p)); if (!line_end) line_end = end;
        const char *q = p; spaces(&q, line_end);
        if (q != line_end) {
            if (!header) {
                if (line_end - q < 5 || memcmp(q, "size", 4) || !horizontal((unsigned char)q[4])) { error = "expected size header"; break; }
                q += 4;
                if (!number(&q, line_end, &m->logical_size)) { error = "invalid logical size"; break; }
                header = 1;
            } else {
                int64_t offset, span;
                if (++holes > DM_EXTENT_MAX_HOLES) { error = "too many hole extents"; break; }
                if (!number(&q, line_end, &offset) || q == line_end || !horizontal((unsigned char)*q) || !number(&q, line_end, &span)) { error = "expected hole offset and length"; break; }
                if (offset < pos || span <= 0 || span > m->logical_size || offset > m->logical_size - span) { error = "hole overlap, ordering, or bounds invalid"; break; }
                if (!append(m, &capacity, pos, offset - pos)) { error = "extent allocation failed"; break; }
                pos = offset + span;
            }
            spaces(&q, line_end); if (q != line_end) { error = "unexpected trailing extent text"; break; }
        }
        p = line_end < end ? line_end + 1 : end;
    }
    if (!error && !header) error = "missing size header";
    if (!error && !append(m, &capacity, pos, m->logical_size - pos)) error = "extent allocation failed";
    int mismatch = !error && m->physical_size != physical_size;
    if (!error && expected_physical) *expected_physical = m->physical_size;
    if (!error && expected_logical) *expected_logical = m->logical_size;
    if (mismatch) error = "archive physical byte count does not match extent map";
    free(text);
    if (error) { dm_extent_map_free(m); invalid(why, why_n, error); return mismatch ? DM_EXTENT_SIZE_MISMATCH : DM_EXTENT_INVALID; }
    *out = m; return DM_EXTENT_VALID;
}
int dm_extent_map_load(const char *hostpath, int64_t physical_size, dm_extent_map **out, char *why, size_t why_n) {
    int result = dm_extent_map_load_detail(hostpath, physical_size, out, why, why_n, NULL, NULL);
    return result == DM_EXTENT_SIZE_MISMATCH ? DM_EXTENT_INVALID : result;
}
ssize_t dm_extent_map_pread(const dm_extent_map *m, int fd, void *buf, size_t n, off_t off) {
    if (off < 0 || n > (size_t)SSIZE_MAX || (uint64_t)off > (uint64_t)INT64_MAX - n) { errno = EINVAL; return -1; }
    if (!n) {
        if (m) return 0;
        char unused;
        return pread(fd, &unused, 0, off);
    }
    if (!buf) { errno = EINVAL; return -1; }
    if (!m) return pread(fd, buf, n, off);
    if (off >= m->logical_size) return 0;
    if ((int64_t)n > m->logical_size - off) n = (size_t)(m->logical_size - off);
    size_t lo = 0, hi = m->count;
    while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (m->kept[mid].logical + m->kept[mid].length <= off) lo = mid + 1; else hi = mid; }
    size_t done = 0;
    while (done < n) {
        int64_t cur = off + (int64_t)done;
        if (lo < m->count && cur >= m->kept[lo].logical) {
            const dm_extent *e = &m->kept[lo]; int64_t in = cur - e->logical;
            size_t want = n - done; if ((int64_t)want > e->length - in) want = (size_t)(e->length - in);
            ssize_t r = pread(fd, (unsigned char *)buf + done, want, (off_t)(e->physical + in));
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) return -1;
            if (!r) return (ssize_t)done;
            done += (size_t)r;
            if (in + r == e->length) lo++;
        } else {
            int64_t stop = lo < m->count ? m->kept[lo].logical : m->logical_size;
            size_t z = n - done; if ((int64_t)z > stop - cur) z = (size_t)(stop - cur);
            memset((unsigned char *)buf + done, 0, z); done += z;
        }
    }
    return (ssize_t)done;
}
