#include "helpers.h"
#include "maps.h"
#include "shared_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef CONFIG_RENAME
SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename, struct renamedata *rd) {
  u64 pid = bpf_get_current_pid_tgid();

  struct inode *old_dir = BPF_CORE_READ(rd, old_dir);
  struct inode *new_dir = BPF_CORE_READ(rd, new_dir);
  struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
  struct inode *target_inode = BPF_CORE_READ(new_dentry, d_inode);

  if (!old_dentry)
    return 0;

  struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
  if (!old_inode)
    return 0;

  /* Safe directory check */
  umode_t mode = BPF_CORE_READ(old_inode, i_mode);
  bool is_dir = false;
  if ((mode & S_IFMT) == S_IFDIR)
    is_dir = true;

  /*
   * Monitoring checks are split by type:
   *
   *   FOLDER → check whether the folder's own inode is monitored.
   *            Parent dirs are irrelevant; the folder IS the unit of
   * monitoring.
   *
   *   FILE   → check parent directories (old and/or new).
   *            Files have no InodeMap entries of their own.
   *
   * We also capture is_cross_dir (old_dir != new_dir) so fexit can
   * distinguish a same-directory rename (inode unchanged → no InodeMap
   * update needed) from a genuine cross-directory move.
   */
  bool inode_mon = false;   /* folder itself is monitored            */
  bool old_dir_mon = false; /* file: source parent is monitored      */
  bool new_dir_mon = false; /* file/folder: dest parent is monitored */

  /* Cross-dir flag: compare the two parent inode pointers directly */
  bool is_cross_dir = (old_dir != new_dir);

  if (is_dir) {
    /* Folder: only the inode entry matters */
    if (is_monitored(old_inode))
      inode_mon = true;

    /* Also check new parent — needed to detect "moving into monitored dir" */
    if (new_dir && is_monitored(new_dir))
      new_dir_mon = true;
  } else {
    /* File: check both parent dirs */
    if (old_dir && is_monitored(old_dir))
      old_dir_mon = true;

    if (new_dir && is_monitored(new_dir))
      new_dir_mon = true;
  }

  if (!inode_mon && !old_dir_mon && !new_dir_mon)
    return 0;

  u32 key = 0;
  struct dentry_ctx *d_ctx;

  d_ctx = bpf_map_lookup_elem(&heap_map, &key);
  if (!d_ctx)
    return 0;

  /* optional: clear it */
  __builtin_memset(d_ctx, 0, sizeof(*d_ctx));
  /*
   * Store snapshot
   */

  /* detect overwrite */
  if (target_inode) {
    d_ctx->overwrite = true;
    d_ctx->target_ino = BPF_CORE_READ(target_inode, i_ino);
    d_ctx->target_dev = BPF_CORE_READ(target_inode, i_sb, s_dev);
    d_ctx->target_size = BPF_CORE_READ(target_inode, i_size);
  }

  d_ctx->is_dir = is_dir;
  d_ctx->inode_mon =
      inode_mon; /* NOTE: add bool inode_mon   to dentry_ctx in types.h */
  d_ctx->is_old_dir_mon =
      old_dir_mon; /* NOTE: add bool is_old_dir_mon to dentry_ctx in types.h */
  d_ctx->is_new_dir = new_dir_mon;
  d_ctx->is_cross_dir =
      is_cross_dir; /* NOTE: add bool is_cross_dir to dentry_ctx in types.h */
  d_ctx->inode = BPF_CORE_READ(old_inode, i_ino);
  d_ctx->dev = BPF_CORE_READ(old_inode, i_sb, s_dev);

  construct_path(old_dentry, d_ctx->filepath, &d_ctx->len);

  d_ctx->before_size = BPF_CORE_READ(old_inode, i_size);

  bpf_map_update_elem(&LruMap, &pid, d_ctx, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit_vfs_rename, struct renamedata *rd, int ret) {
  u64 key = bpf_get_current_pid_tgid();
  struct KEY k = {};
  struct VALUE v = {1};
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);

  struct dentry_ctx *old_ctx = bpf_map_lookup_elem(&LruMap, &key);

  if (!old_ctx)
    return 0;

  if (ret != 0)
    goto cleanup;

  struct EVENT *event_c, *event_d;

  event_d = bpf_ringbuf_reserve(&rb, sizeof(*event_d), 0);
  if (!event_d)
    goto cleanup;

  /* invariant fields */
  event_d->uid = bpf_get_current_uid_gid() >> 32;
  event_d->bytes_written = 0;
  event_d->file_size = old_ctx->before_size;
  getTTY(event_d);

  /*
   * 1️⃣  DELETE old path
   */
  event_d->before_size = old_ctx->before_size;
  event_d->change_type = RENAME_D_EVENT;

  /*
   * InodeMap DELETE — folders only, cross-dir move OUT of monitored area.
   *
   *   mv a b   (same dir, folder)  is_cross_dir=0               → skip (inode
   * unchanged) mv a ../b (folder)           is_cross_dir=1  inode_mon=1
   *                                               is_new_dir=0  → delete ✓
   *   mv ../b a (folder)           is_cross_dir=1  inode_mon=0  → skip (wasn't
   * tracked)
   *
   * Files never have InodeMap entries so no delete needed for them.
   */
  if (old_ctx->is_dir && old_ctx->is_cross_dir && old_ctx->inode_mon &&
      !old_ctx->is_new_dir) {
    k.inode = old_ctx->inode;
    k.dev = old_ctx->dev;
    bpf_map_delete_elem(&InodeMap, &k);
  }

  print_event("fexit_vfs_rename", event_d);
  bpf_ringbuf_submit(event_d, 0);

  event_c = bpf_ringbuf_reserve(&rb, sizeof(*event_c), 0);
  if (!event_c)
    goto cleanup;

  /* invariant fields */
  event_c->uid = bpf_get_current_uid_gid() >> 32;
  event_c->bytes_written = 0;
  event_c->file_size = old_ctx->before_size;
  getTTY(event_c);

  if (old_ctx->overwrite) {
    event_c->before_size = old_ctx->target_size;
    event_c->change_type = RENAME_OW_EVENT;

    construct_path(new_dentry, event_c->filepath, &event_c->len);
    print_event("fexit_vfs_rename", event_c);
    bpf_ringbuf_submit(event_c, 0);
    goto cleanup;
  }

  /*
   * 2️⃣  CREATE new path
   */

  if (!event_c)
    goto cleanup;

  event_c->change_type = RENAME_C_EVENT;

  /*
   * InodeMap ADD — folders only, cross-dir move INTO monitored area.
   *
   *   mv a b   (same dir, folder)  is_cross_dir=0               → skip
   *   mv a ../b (folder)           is_cross_dir=1  is_new_dir=0 → skip (dest
   * not monitored) mv ../b a (folder)           is_cross_dir=1  is_new_dir=1
   *                                               inode_mon=0   → add ✓
   *
   * Files: no InodeMap entry, events are sufficient.
   */
  if (old_ctx->is_dir && old_ctx->is_cross_dir && old_ctx->is_new_dir &&
      !old_ctx->inode_mon) {
    k.inode = old_ctx->inode;
    k.dev = old_ctx->dev;
    bpf_map_update_elem(&InodeMap, &k, &v, BPF_ANY);
  }

  bpf_probe_read_str(event_c->filepath, sizeof(event_c->filepath),
                     BPF_CORE_READ(new_dentry, d_name.name));

  print_event("fexit_vfs_rename", event_c);
  bpf_ringbuf_submit(event_c, 0);

cleanup:
  bpf_map_delete_elem(&LruMap, &key);
  return 0;
}

#endif