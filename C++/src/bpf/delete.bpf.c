#include "helpers.h"
#include "maps.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Unlink - file deletion
/* vfs_unlink - unlink a filesystem object
 * @idmap:	idmap of the mount the inode was found from
 * @dir:	parent directory
 * @dentry:	victim
 * @delegated_inode: returns victim inode, if the inode is delegated.
 */
SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, struct inode **delegated_inode) {

  // check if file is monitored or not
  struct inode *ino = BPF_CORE_READ(dentry, d_inode);
  if (!is_monitored(ino))
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  // populate the event and store in lru hash map
  struct dentry_ctx dentry_ctx = {};

  dentry_ctx.inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  dentry_ctx.dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  dentry_ctx.before_size = BPF_CORE_READ(dentry, d_inode, i_size);

  bpf_probe_read_str(dentry_ctx.filepath, sizeof(dentry_ctx.filepath),
                     BPF_CORE_READ(dentry, d_name.name));

  bpf_map_update_elem(&LruMap, &pid_tgid, &dentry_ctx, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, struct inode **delegated_inode, int ret) {

  struct EVENT *event;
  struct KEY key = {};
  struct dentry_ctx *dentry_ctx;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  if (ret < 0)
    goto out;

  // read the saved data at fentry
  dentry_ctx = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!dentry_ctx)
    goto out;

  // deletion is sucess full remove entry from inode map
  key.inode = dentry_ctx->inode;
  key.dev = dentry_ctx->dev;
  bpf_map_delete_elem(&InodeMap, &key);

  // reserve space in ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  // populate the event
  event->dentry_ctx = *dentry_ctx;
  event->change_type = DELETE_EVENT;
  event->giduid = bpf_get_current_uid_gid();
  event->bytes_written = 0;
  event->file_size = 0;

  print_event("fexit_vfs_unlink", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

/* ───────────────────────────────────────────── */
/* RMDIR                                        */
/* ───────────────────────────────────────────── */
/**
 * vfs_rmdir - remove directory
 * @idmap:	idmap of the mount the inode was found from
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 *
 * Remove a directory.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs @nop_mnt_idmap.
 */
SEC("fentry/vfs_rmdir")
int BPF_PROG(fentry_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry) {

  // check if folder is monitored
  if (!is_monitored(dir))
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  // populate the event and store in lru hash map
  struct dentry_ctx dentry_ctx = {};
  dentry_ctx.inode = BPF_CORE_READ(dir, i_ino);
  dentry_ctx.dev = BPF_CORE_READ(dir, i_sb, s_dev);
  dentry_ctx.before_size = BPF_CORE_READ(dir, i_size);

  bpf_probe_read_str(dentry_ctx.filepath, sizeof(dentry_ctx.filepath),
                     BPF_CORE_READ(dentry, d_name.name));

  bpf_map_update_elem(&LruMap, &pid_tgid, &dentry_ctx, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(fexit_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, int ret) {

  struct EVENT *event;
  struct KEY key = {};
  struct dentry_ctx *dentry_ctx;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  if (ret < 0)
    goto out;

  // read the saved data at fentry
  dentry_ctx = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!dentry_ctx)
    goto out;

  // deletion is sucess full remove entry from inode map
  key.inode = dentry_ctx->inode;
  key.dev = dentry_ctx->dev;
  bpf_map_delete_elem(&InodeMap, &key);

  // reserve space in ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  // populate the event
  event->dentry_ctx = *dentry_ctx;
  event->change_type = DELETE_EVENT;
  event->giduid = bpf_get_current_uid_gid();
  event->bytes_written = 0;
  event->file_size = 0;

  print_event("fexit_vfs_rmdir", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}
