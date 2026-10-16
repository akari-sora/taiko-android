#define _GNU_SOURCE 1
#include "fs_platform.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#define GUEST_NAME "user.org.d2rmobile.guest-name"
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE 2
#endif

ssize_t dm_android_fs_get_guest_name(const char *p, void *out, size_t n) { return lgetxattr(p, GUEST_NAME, out, n); }
int dm_android_fs_set_guest_name(const char *p, const void *v, size_t n) { return lsetxattr(p, GUEST_NAME, v, n, 0); }
int dm_android_fs_remove_guest_name(const char *p) { return lremovexattr(p, GUEST_NAME); }

static int copy_name(int in, int out) {
    char name[0x301];
    ssize_t n = fgetxattr(in, GUEST_NAME, name, sizeof name);
    if (n < 0) return errno == ENODATA ? 0 : -1;
    return fsetxattr(out, GUEST_NAME, name, (size_t)n, 0);
}

static int copy_file(int in, int out, char *buf) {
    for (;;) {
        ssize_t n = read(in, buf, 65536);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (!n) return copy_name(in, out);
        size_t p = 0;
        while (p < (size_t)n) {
            ssize_t k = write(out, buf + p, (size_t)n - p);
            if (k < 0) { if (errno == EINTR) continue; return -1; }
            if (!k) { errno = ENOSPC; return -1; }
            p += (size_t)k;
        }
    }
}

static DIR *duplicate_dir(int fd) {
    int copy = dup(fd);
    if (copy < 0) return NULL;
    DIR *dir = fdopendir(copy);
    if (!dir) { int saved = errno; close(copy); errno = saved; }
    return dir;
}

static int copy_contents(int in, int out, char *scratch) {
    DIR *dir = duplicate_dir(in);
    if (!dir) return -1;
    int rc = 0, saved = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) { if (errno) { rc = -1; saved = errno; } break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        struct stat st;
        if (fstatat(in, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) { rc = -1; saved = errno; break; }
        int a = -1, b = -1;
        if (S_ISDIR(st.st_mode)) {
            a = openat(in, e->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (a >= 0 && !mkdirat(out, e->d_name, 0700))
                b = openat(out, e->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (a < 0 || b < 0 || copy_contents(a, b, scratch) || copy_name(a, b) || fchmod(b, st.st_mode & 0777)) rc = -1;
        } else if (S_ISREG(st.st_mode)) {
            a = openat(in, e->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            b = openat(out, e->d_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (a < 0 || b < 0 || copy_file(a, b, scratch) || fchmod(b, st.st_mode & 0777)) rc = -1;
        } else { errno = ELOOP; rc = -1; }
        saved = errno;
        if (a >= 0) close(a);
        if (b >= 0 && close(b) && !rc) { rc = -1; saved = errno; }
        if (rc) break;
    }
    closedir(dir);
    if (rc) errno = saved;
    return rc;
}

/* Directory traversal is descriptor-relative, so a child substituted with a
 * symlink cannot redirect removal or copying outside the application tree. */
static int remove_contents(int fd) {
    DIR *dir = duplicate_dir(fd);
    if (!dir) return -1;
    int rc = 0, saved = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) { if (errno) { rc = -1; saved = errno; } break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) { rc = -1; saved = errno; break; }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(fd, e->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0) rc = -1;
            else { rc = remove_contents(child); saved = errno; close(child); errno = saved; }
            if (!rc) rc = unlinkat(fd, e->d_name, AT_REMOVEDIR);
        } else rc = unlinkat(fd, e->d_name, 0); /* Unlink symlinks themselves. */
        if (rc) { saved = errno; break; }
    }
    closedir(dir);
    if (rc) errno = saved;
    return rc;
}

int dm_android_fs_remove_tree(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    int rc = remove_contents(fd), saved = errno;
    close(fd);
    if (!rc) return rmdir(path);
    errno = saved;
    return -1;
}

int dm_android_fs_clone_tree(const char *source, const char *destination) {
    /* HLE executes on the SDK-provided guest stack. A resource copy buffer
     * must never consume a 64 KiB frame there. One checked allocation serves
     * every file and recursive directory for this operation. */
    char *scratch = malloc(65536);
    if (!scratch) { errno = ENOMEM; return -1; }
    int in = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) { int saved = errno; free(scratch); errno = saved; return -1; }
    struct stat st;
    if (fstat(in, &st) || mkdir(destination, 0700)) { int saved = errno; close(in); free(scratch); errno = saved; return -1; }
    int out = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int rc = out < 0 ? -1 : copy_contents(in, out, scratch);
    if (!rc) rc = copy_name(in, out);
    if (!rc) rc = fchmod(out, st.st_mode & 0777);
    int saved = errno;
    close(in);
    if (out >= 0) close(out);
    free(scratch);
    if (rc) { dm_android_fs_remove_tree(destination); errno = saved; }
    return rc;
}

static int sync_contents(int fd) {
    DIR *dir = duplicate_dir(fd);
    if (!dir) return -1;
    int rc = 0, saved = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) { if (errno) { rc = -1; saved = errno; } break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) { rc = -1; saved = errno; break; }
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) { rc = -1; saved = ELOOP; break; }
        int child = openat(fd, e->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (S_ISDIR(st.st_mode) ? O_DIRECTORY : 0));
        if (child < 0) { rc = -1; saved = errno; break; }
        rc = S_ISDIR(st.st_mode) ? sync_contents(child) : fsync(child);
        saved = errno;
        close(child);
        if (rc) break;
    }
    closedir(dir);
    if (!rc) return fsync(fd);
    errno = saved;
    return -1;
}
int dm_android_fs_sync_tree(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    int rc = sync_contents(fd), saved = errno;
    close(fd); errno = saved; return rc;
}
int dm_android_fs_sync_parent(const char *path) {
    size_t n = strlen(path);
    if (!n || n >= 4096) { errno = ENAMETOOLONG; return -1; }
    char *parent = strdup(path);
    if (!parent) { errno = ENOMEM; return -1; }
    char *slash = strrchr(parent, '/');
    if (!slash) strcpy(parent, ".");
    else if (slash == parent) slash[1] = 0;
    else *slash = 0;
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno; free(parent); errno = saved;
    if (fd < 0) return -1;
    int rc = fsync(fd); saved = errno;
    close(fd); errno = saved; return rc;
}
int dm_android_fs_exchange(const char *a, const char *b) {
    /* Bionic's renameat2 symbol starts at API 30; the Linux syscall predates
     * API 29. ENOSYS/EOPNOTSUPP is a hard failure, never a two-rename fallback. */
    return (int)syscall(__NR_renameat2, AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE);
}
