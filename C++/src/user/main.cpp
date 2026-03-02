#include <bpf/libbpf.h>
#include <csignal>
#include <cstdio>
#include <unistd.h>

#include "user_types.h"

extern "C" {
#include "fentry_bpf.skel.h"
}
using namespace std;

void example_map_insert(fentry_bpf *skel) {

  KEY k = {0};
  VALUE v = {0};

  k.inode = 5025202;
  k.dev = 271581196;

  v.dummy = 1;

  int err = bpf_map__update_elem(skel->maps.InodeMap, &k, sizeof(k), &v,
                                 sizeof(v), BPF_ANY);
  if (err) {
    fprintf(stderr, "Failed to update map\n");
    return;
  }
  fprintf(stderr, "Successfully updated map\n");
}

static volatile sig_atomic_t signal_received = 0;

void handle_signal(int) { signal_received = 1; }

int main(int argc, char **argv) {
  fentry_bpf *skel = fentry_bpf::open_and_load();

  if (!skel) {
    fprintf(stderr, "Failed to open skeleton\n");
    return 1;
  }

  int err = fentry_bpf::attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach skeleton\n");
    goto cleanup;
  }

  example_map_insert(skel);

  printf("Successfully started!\n");
  printf("Run: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

  signal(SIGINT, handle_signal);

  while (!signal_received) {
    sleep(1);
  }

cleanup:
  fentry_bpf::destroy(skel);
  printf("Successfully cleaned up\n");
  return err;
}