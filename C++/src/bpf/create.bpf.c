
#include "helpers.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/inode_create")
int BPF_PROG(lsm_inode_create, struct inode *inode, struct dentry *dentry) {

  struct dentry *parent_dentry;
  struct inode *parent_inode;

  parent_dentry = BPF_CORE_READ(dentry, d_parent);
  parent_inode = BPF_CORE_READ(parent_dentry, d_inode);

  if (!is_monitored(parent_inode))
    return 0;
  emit_event("lsm_inode_create", parent_inode, dentry, CREATE_EVENT);
  return 0;
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(fexit_vfs_mkdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, umode_t mode, int ret) {
  if (ret != 0 || !is_monitored(dir))
    return 0;

  update_dir_map(dentry, true);
  emit_event("fexit_vfs_mkdir", dir, dentry, CREATE_EVENT);
  return 0;
}
