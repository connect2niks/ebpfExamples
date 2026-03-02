// SPDX-License-Identifier: GPL-2.0
//
// vfs_write_track.bpf.c
//
// Write paths tracked:
//   1.  vfs_write           — write() / pwrite64()
//   2.  vfs_writev          — writev() / pwritev() / pwritev2()
//   3.  vfs_iocb_iter_write — io_uring IORING_OP_WRITE (bypasses vfs_write)
//   4.  __do_splice         — splice()
//   5.  do_splice_direct    — sendfile()
//   6.  vfs_copy_file_range — copy_file_range()  [fentry needed: may call #5]
//   7.  kernel_write        — overlayfs copy-up, coredump, securityfs
//   8.  __kernel_write      — nfsd, ksmbd, binfmt_misc
//   9.  do_page_mkwrite     — mmap MAP_SHARED|PROT_WRITE dirty (page cache)
//   10. dax_iomap_fault     — mmap on DAX/pmem (no page cache at all)
//   11. vfs_fallocate       — fallocate()
//   12. vfs_truncate        — truncate() / ftruncate()  [fentry needed: calls
//   do_truncate]
//   13. do_truncate         — O_TRUNC at open() time (direct path, not via
//   vfs_truncate)
//
// fentry is ONLY used where nesting prevention is required:
//   - vfs_copy_file_range + do_splice_direct  (cfr fallback path)
//   - vfs_truncate + do_truncate              (vfs_truncate calls do_truncate)
//
// NOTE: vfs_iter_write intentionally omitted — it is called internally by
// vfs_writev in some kernel versions, which would double-count those writes.
#include "maps.h"
#include "types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Per-cpu nesting counter — ONLY for the two call chains that nest:
//   vfs_copy_file_range → do_splice_direct
//   vfs_truncate        → do_truncate
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} call_depth SEC(".maps");

// Saves old i_size before truncate so fexit can compute the delta correctly
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);   // pid_tgid
  __type(value, __s64); // old i_size
} truncate_old_size SEC(".maps");

// ─── Nesting helpers (used only by the two bracketed pairs) ──────────────────

static __always_inline void depth_inc(void) {
  __u32 key = 0, *d = bpf_map_lookup_elem(&call_depth, &key);
  if (d)
    (*d)++;
}

static __always_inline void depth_dec(void) {
  __u32 key = 0, *d = bpf_map_lookup_elem(&call_depth, &key);
  if (d && *d > 0)
    (*d)--;
}

// 1 = outermost call on this cpu, 0 = nested
static __always_inline int is_outermost(void) {
  __u32 key = 0, *d = bpf_map_lookup_elem(&call_depth, &key);
  return !d || (*d == 1);
}

// ─── Core event emitter
// ───────────────────────────────────────────────────────

static __always_inline void account(struct file *file, __s64 bytes,
                                    __u8 change_type) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;

  if (bytes <= 0)
    return;

  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
  value = bpf_map_lookup_elem(&InodeMap, &key);
  if (!value)
    return;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return;

  event->dentry_ctx.inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = change_type;
  event->bytes_written = (__u32)bytes;
  event->dentry_ctx.before_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath),
                     BPF_CORE_READ(file, f_path.dentry, d_name.name));

  bpf_printk(
      "inode: %llu, dev: %llu, giduid: %llu, filename: %s, change_type: %u, "
      "bytes_written: %u, file_size: %lld",
      event->dentry_ctx.inode, event->dentry_ctx.dev, event->giduid,
      event->dentry_ctx.filepath, event->change_type, event->bytes_written,
      event->dentry_ctx.before_size);

  bpf_ringbuf_submit(event, 0);
}

// ─── 1. vfs_write  ─  write() / pwrite64() ───────────────────────────────────

SEC("fexit/vfs_write")
int BPF_PROG(fexit_vfs_write, struct file *file, const char *buf, size_t count,
             loff_t *pos, ssize_t ret) {
  account(file, ret, WRITE_EVENT);
  return 0;
}

// ─── 2. vfs_writev  ─  writev() / pwritev() / pwritev2() ─────────────────────
// vfs_iter_write intentionally NOT hooked — it's an internal helper called
// by vfs_writev; hooking both would double-count all writev writes.

SEC("fexit/vfs_writev")
int BPF_PROG(fexit_vfs_writev, struct file *file, const struct iovec *vec,
             unsigned long vlen, loff_t *pos, rwf_t flags, ssize_t ret) {
  account(file, ret, WRITE_EVENT);
  return 0;
}

// ─── 3. vfs_iocb_iter_write  ─  io_uring IORING_OP_WRITE ─────────────────────
// io_uring calls this directly, bypassing vfs_write entirely.

SEC("fexit/vfs_iocb_iter_write")
int BPF_PROG(fexit_vfs_iocb_iter_write, struct file *file, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  account(file, ret, WRITE_EVENT);
  return 0;
}

// ─── 4. __do_splice  ─  splice() syscall
// ──────────────────────────────────────

SEC("fexit/__do_splice")
int BPF_PROG(fexit_do_splice, struct file *in, loff_t *off_in, struct file *out,
             loff_t *off_out, size_t len, unsigned int flags, long ret) {
  account(out, (ssize_t)ret, WRITE_EVENT);
  return 0;
}

// ─── 5 + 6. do_splice_direct + vfs_copy_file_range ───────────────────────────
//
// NESTING: vfs_copy_file_range can fall back to do_splice_direct internally.
// fentry/fexit pairs on both functions + depth counter prevent double-counting.
//
//   sendfile() calls do_splice_direct directly → depth 1 → counted  ✓
//   copy_file_range() → vfs_copy_file_range (depth 1)
//     └─ fallback → do_splice_direct (depth 2) → suppressed         ✓
//     fexit vfs_copy_file_range (depth 1) → counted                 ✓

SEC("fentry/do_splice_direct")
int BPF_PROG(fentry_do_splice_direct, struct file *in, loff_t *ppos,
             struct file *out, loff_t *opos, size_t len, unsigned int flags) {
  depth_inc();
  return 0;
}

SEC("fexit/do_splice_direct")
int BPF_PROG(fexit_do_splice_direct, struct file *in, loff_t *ppos,
             struct file *out, loff_t *opos, size_t len, unsigned int flags,
             ssize_t ret) {
  if (is_outermost())
    account(out, ret, WRITE_EVENT);
  depth_dec();
  return 0;
}

SEC("fentry/vfs_copy_file_range")
int BPF_PROG(fentry_vfs_copy_file_range, struct file *file_in, loff_t pos_in,
             struct file *file_out, loff_t pos_out, size_t len,
             unsigned int flags) {
  depth_inc();
  return 0;
}

SEC("fexit/vfs_copy_file_range")
int BPF_PROG(fexit_vfs_copy_file_range, struct file *file_in, loff_t pos_in,
             struct file *file_out, loff_t pos_out, size_t len,
             unsigned int flags, ssize_t ret) {
  if (is_outermost())
    account(file_out, ret, WRITE_EVENT);
  depth_dec();
  return 0;
}

// ─── 7. kernel_write  ─  overlayfs copy-up / coredump / securityfs ───────────

SEC("fexit/kernel_write")
int BPF_PROG(fexit_kernel_write, struct file *file, const void *buf,
             size_t count, loff_t *pos, ssize_t ret) {
  account(file, ret, WRITE_EVENT);
  return 0;
}

// ─── 8. __kernel_write  ─  nfsd / ksmbd / binfmt_misc ────────────────────────

SEC("fexit/__kernel_write")
int BPF_PROG(fexit___kernel_write, struct file *file, const void *buf,
             size_t count, loff_t *pos, ssize_t ret) {
  account(file, ret, WRITE_EVENT);
  return 0;
}

// 9 -10 mmap based
SEC("lsm/mmap_file")
int BPF_PROG(fim_mmap_file, struct file *file, unsigned long prot,
             unsigned long flags) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (!file)
    return 0;

  /* Check monitored parent directory */
  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);
  if (!value)
    return 0;

  /* Reserve ring buffer event */
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return 0;

  /* Fill event */

  event->dentry_ctx.inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = 0; // mmap: exact byte count unknown
  event->dentry_ctx.before_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_printk(
      "inode: %llu, dev: %llu, giduid: %llu, filename: %s, change_type: %u, "
      "bytes_written: %u, file_size: %lld",
      event->dentry_ctx.inode, event->dentry_ctx.dev, event->giduid,
      event->dentry_ctx.filepath, event->change_type, event->bytes_written,
      event->dentry_ctx.before_size);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ─── 11. vfs_fallocate  ─  fallocate() ───────────────────────────────────────
// ret is int (0 = success), NOT ssize_t.
// bytes_written = len (bytes allocated), tagged FALLOCATE_EVENT.

SEC("fexit/vfs_fallocate")
int BPF_PROG(fexit_vfs_fallocate, struct file *file, int mode, loff_t offset,
             loff_t len, int ret) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;

  if (ret != 0)
    return 0;

  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
  value = bpf_map_lookup_elem(&InodeMap, &key);
  if (!value)
    return 0;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return 0;

  event->dentry_ctx.inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = WRITE_EVENT;
  event->bytes_written = (__u32)len;
  event->dentry_ctx.before_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath),
                     BPF_CORE_READ(file, f_path.dentry, d_name.name));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ─── 12 + 13. vfs_truncate + do_truncate
// ──────────────────────────────────────
//
// NESTING: vfs_truncate calls do_truncate internally — same depth-counter
// pattern as vfs_copy_file_range / do_splice_direct.
//
// Two distinct callers:
//   truncate() / ftruncate()  → vfs_truncate → do_truncate  (depth 1 → 2)
//   open(O_TRUNC)             → do_truncate directly         (depth 1)
//
// We save i_size in fentry (before the call) into truncate_old_size so fexit
// can compute the real delta. bytes_written = max(0, new_size - old_size).
// ret is int (0 = success) for both.

SEC("fentry/vfs_truncate")
int BPF_PROG(fentry_vfs_truncate, const struct path *path, loff_t length) {
  __u64 tid = bpf_get_current_pid_tgid();
  __s64 old = BPF_CORE_READ(path, dentry, d_inode, i_size);
  bpf_map_update_elem(&truncate_old_size, &tid, &old, BPF_ANY);
  depth_inc();
  return 0;
}

SEC("fexit/vfs_truncate")
int BPF_PROG(fexit_vfs_truncate, const struct path *path, loff_t length,
             int ret) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  __u64 tid = bpf_get_current_pid_tgid();
  __s64 *old_p, old_size = 0, diff;

  if (!is_outermost() || ret != 0)
    goto out;

  key.inode = BPF_CORE_READ(path, dentry, d_parent, d_inode, i_ino);
  value = bpf_map_lookup_elem(&InodeMap, &key);
  if (!value)
    goto out;

  old_p = bpf_map_lookup_elem(&truncate_old_size, &tid);
  if (old_p)
    old_size = *old_p;
  diff = length - old_size;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  event->dentry_ctx.inode = BPF_CORE_READ(path, dentry, d_inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(path, dentry, d_inode, i_sb, s_dev);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = WRITE_EVENT;
  event->bytes_written = (diff > 0) ? (__u32)diff : 0;
  event->dentry_ctx.before_size = length;

  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath),
                     BPF_CORE_READ(path, dentry, d_name.name));

  bpf_ringbuf_submit(event, 0);
out:
  bpf_map_delete_elem(&truncate_old_size, &tid);
  depth_dec();
  return 0;
}

SEC("fentry/do_truncate")
int BPF_PROG(fentry_do_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
             loff_t length, unsigned int time_attrs, struct file *filp) {
  __u64 tid = bpf_get_current_pid_tgid();
  __s64 old = BPF_CORE_READ(dentry, d_inode, i_size);
  bpf_map_update_elem(&truncate_old_size, &tid, &old, BPF_ANY);
  depth_inc();
  return 0;
}

SEC("fexit/do_truncate")
int BPF_PROG(fexit_do_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
             loff_t length, unsigned int time_attrs, struct file *filp,
             int ret) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  __u64 tid = bpf_get_current_pid_tgid();
  __s64 *old_p, old_size = 0, diff;

  if (!is_outermost() || ret != 0)
    goto out;

  key.inode = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);
  value = bpf_map_lookup_elem(&InodeMap, &key);
  if (!value)
    goto out;

  old_p = bpf_map_lookup_elem(&truncate_old_size, &tid);
  if (old_p)
    old_size = *old_p;
  diff = length - old_size;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  event->dentry_ctx.inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = WRITE_EVENT;
  event->bytes_written = (diff > 0) ? (__u32)diff : 0;
  event->dentry_ctx.before_size = length;

  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath),
                     BPF_CORE_READ(dentry, d_name.name));

  bpf_ringbuf_submit(event, 0);
out:
  bpf_map_delete_elem(&truncate_old_size, &tid);
  depth_dec();
  return 0;
}
