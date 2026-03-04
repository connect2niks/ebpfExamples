#ifndef EVENT_HPP
#define EVENT_HPP

#include "shared_types.h"
#include <bpf/libbpf.h>
#include <condition_variable>
#include <mutex>
#include <queue>

class Events {
public:
  Events(const struct bpf_map *map);
  ~Events();

  void producer();
  void consumer();
  void stop();

public:
  struct ring_buffer *rb;
  std::queue<EVENT> event_queue;

  std::mutex queue_mutex;
  std::condition_variable queue_cv;

  std::atomic<bool> stop_flag{false};
};

#endif