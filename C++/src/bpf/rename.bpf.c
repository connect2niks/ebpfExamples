#include "helpers.h"
#include "maps.h"
#include "types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename, struct renamedata *rd) {
  u64 key = bpf_get_current_pid_tgid();
  struct EVENT ev = {};

  struct inode *old_dir = BPF_CORE_READ(rd, old_dir);
  struct inode *new_dir = BPF_CORE_READ(rd, new_dir);
  struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);

  if (!old_dir || !new_dir || !old_dentry || !new_dentry)
    return 0;

  struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
  if (!inode)
    return 0;

  ev.dentry_ctx.inode = BPF_CORE_READ(inode, i_ino);
  ev.dentry_ctx.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  ev.dentry_ctx.before_size = BPF_CORE_READ(inode, i_size);

  __u32 uid = BPF_CORE_READ(inode, i_uid.val);
  __u32 gid = BPF_CORE_READ(inode, i_gid.val);
  ev.giduid = ((__u64)gid << 32) | uid;

  bpf_probe_read_str(ev.dentry_ctx.filepath, sizeof(ev.dentry_ctx.filepath),
                     BPF_CORE_READ(old_dentry, d_name.name));

  struct inode *target = BPF_CORE_READ(new_dentry, d_inode);
  if (target)
    ev.bytes_written = 1;

  bpf_map_update_elem(&LruMap, &key, &ev, BPF_ANY);
  return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit_vfs_rename, struct renamedata *rd, int ret) {
  u64 key = bpf_get_current_pid_tgid();
  struct EVENT *ev = bpf_map_lookup_elem(&LruMap, &key);

  if (!ev)
    return 0;

  struct inode *old_dir = BPF_CORE_READ(rd, old_dir);
  struct inode *new_dir = BPF_CORE_READ(rd, new_dir);
  struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);

  if (ret != 0) {
    goto cleanup;
  }

  bool old_mon = old_dir && is_monitored(old_dir);
  bool new_mon = new_dir && is_monitored(new_dir);

  if (!old_mon && !new_mon) {
    goto cleanup;
  }

  /*
   * 1️⃣ DELETE old path
   */
  if (old_mon) {
    ev->change_type = DELETE_EVENT;

    print_event("Rename", ev);

    bpf_ringbuf_output(&rb, ev, sizeof(*ev), 0);
    update_dir_map(old_dentry, false);
  }

  /*
   * 2️⃣ DELETE overwritten target
   */
  if (new_mon && ev->bytes_written) {
    ev->change_type = DELETE_EVENT;
    print_event("Rename", ev);

    bpf_ringbuf_output(&rb, ev, sizeof(*ev), 0);
  }

  /*
   * 3️⃣ CREATE new path
   */
  if (new_mon) {
    ev->change_type = CREATE_EVENT;

    bpf_probe_read_str(ev->dentry_ctx.filepath, sizeof(ev->dentry_ctx.filepath),
                       BPF_CORE_READ(new_dentry, d_name.name));

    print_event("Rename", ev);

    bpf_ringbuf_output(&rb, ev, sizeof(*ev), 0);

    update_dir_map(new_dentry, true);
  }

cleanup:
  bpf_map_delete_elem(&LruMap, &key);
  return 0;
}