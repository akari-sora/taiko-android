#pragma once
#include <stddef.h>
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
/* All tree operations reject symlinks and special files; destinations must not
 * exist. The only copied extended attribute is the HLE guest-name mapping. */
int dm_android_fs_clone_tree(const char *source, const char *destination);
int dm_android_fs_remove_tree(const char *path);
int dm_android_fs_sync_tree(const char *path);
int dm_android_fs_exchange(const char *a, const char *b);
int dm_android_fs_sync_parent(const char *path);
ssize_t dm_android_fs_get_guest_name(const char *path, void *out, size_t size);
int dm_android_fs_set_guest_name(const char *path, const void *value, size_t size);
int dm_android_fs_remove_guest_name(const char *path);
int dm_android_fs_has_open_handles(void);
/* Caller must first quiesce guest execution. EBUSY leaves all state unchanged. */
int dm_android_fs_reset(void);
#ifdef __cplusplus
}
#endif
