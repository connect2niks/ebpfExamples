// SPDX-License-Identifier: GPL-2.0
//
#include "maps.h"
#include "types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define MAY_WRITE 0x00000002

#ifdef CONFIG_MODIFY
// ─── lsm/file_permission ─────────────────────────────────────────────────────
//
// Fires before any read/write op. Filtered to MAY_WRITE only.
SEC("lsm/file_permission")
int BPF_PROG(fim_file_permission, struct file *file, int mask) {
  struct KEY inode_key = {};
  struct EVENT *event;
  __u64 fptr;
  __s64 size;

  if (!(mask & MAY_WRITE))
    return 0;

  if (!file)
    return 0;

  /* Check parent directory is monitored */
  inode_key.inode =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
  inode_key.dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);
  if (!bpf_map_lookup_elem(&InodeMap, &inode_key))
    return 0;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return 0;

  event->dentry_ctx.inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
  event->dentry_ctx.before_size = size;
  event->file_size = size; /* unknown until close */
  event->giduid = bpf_get_current_uid_gid();
  event->dentry_ctx.change_type = WRITE_EVENT;
  event->bytes_written = 0;

  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath),
                     BPF_CORE_READ(file, f_path.dentry, d_name.name));

  bpf_printk("file_permission: filename=%s before=%lld",
             event->dentry_ctx.filepath, size);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

#endif
