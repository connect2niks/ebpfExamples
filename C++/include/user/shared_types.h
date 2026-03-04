#ifndef USER_TYPES_H
#define USER_TYPES_H

#include <linux/types.h>

#define MAX_FILENAME_LEN 256

/* Event types */
#define CREATE_EVENT 0xcu
#define DELETE_EVENT 0xdu
#define WRITE_EVENT 0xeu
#define RENAME_EVENT 0xfu

/* ───────────────────────────────────────────── */

typedef struct {
  __u64 inode;
  __u64 dev;
} KEY;

typedef struct {
  __u64 dummy;
} VALUE;

struct dentry_ctx {
  __u64 inode;
  __u64 dev;
  __u8 filepath[MAX_FILENAME_LEN];
  __s64 before_size;
  __u8 change_type;
#ifdef CONFIG_RENAME
  bool is_dir;
  bool is_old_dir_mon;
  bool is_new_dir;
  __u64 target_ino;
  __u64 target_dev;
  __s64 target_size;
  bool unused;
  bool inode_mon;    // folder itself is monitored
  bool is_cross_dir; // old_dir != new_dir
  bool overwrite;
#endif
};

struct EVENT {
  __u64 giduid;
  __u64 bytes_written;
  __s64 file_size;
  struct dentry_ctx dentry_ctx;
};

#endif /* USER_TYPES_H */
