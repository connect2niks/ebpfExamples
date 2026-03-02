#ifndef __MAPS_H
#define __MAPS_H

#include "types.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct InodeMap_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __uint(key_size, sizeof(struct KEY));
  __uint(value_size, sizeof(struct VALUE));
};

struct RingbufMap_t {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 18);
};

struct LruMap_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __uint(key_size, sizeof(u64));
  __uint(value_size, sizeof(struct dentry_ctx));
};

extern struct InodeMap_t InodeMap SEC(".maps");
extern struct RingbufMap_t rb SEC(".maps");
extern struct LruMap_t LruMap SEC(".maps");

#endif