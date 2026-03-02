

#include "helpers.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef CONFIG_CREATE

SEC("lsm/inode_create")
int BPF_PROG(lsm_inode_create, struct inode *inode, struct dentry *dentry) {

  struct inode *parent_inode;
  struct VALUE *value;

  parent_inode = BPF_CORE_READ(dentry, d_parent, d_inode);

  value = is_monitored(parent_inode);
  if (!value)
    return 0;

  emit_event("lsm_inode_create", parent_inode, dentry, CREATE_EVENT);
  return 0;
}

/**
 * vfs_mkdir - create directory
 * @idmap:	idmap of the mount the inode was found from
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 * @mode:	mode of the new directory
 *
 * Create a directory.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs @nop_mnt_idmap.
 */
SEC("fexit/vfs_mkdir")
int BPF_PROG(fexit_vfs_mkdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, umode_t mode, int ret) {
  struct VALUE *value;
  struct inode *parent_inode;
  struct inode *child_inode;

  if (ret != 0) {
    return 0;
  }

  parent_inode = dir;
  value = is_monitored(parent_inode);
  if (!value) {
    return 0;
  }

  child_inode = BPF_CORE_READ(dentry, d_inode);
  update_dir_map(child_inode, true);
  emit_event("fexit_vfs_mkdir", parent_inode, dentry, CREATE_EVENT);
  return 0;
}

#endif