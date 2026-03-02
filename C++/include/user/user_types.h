#ifndef USER_TYPES_H
#define USER_TYPES_H

#include <linux/types.h>

#define MAX_FILENAME_LEN 255

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
};

typedef struct {
  __u64 giduid;
  __u8 change_type;
  __u32 bytes_written;
  __s64 file_size;
  struct dentry_ctx dentry_ctx;
} EVENT;

#endif /* USER_TYPES_H */
