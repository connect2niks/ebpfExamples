#include <csignal>
#include <cstdio>
#include <unistd.h>

extern "C" {
#include "fentry_bpf.skel.h"
}
using namespace std;

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

  printf("Successfully started!\n");
  printf("Run: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

  signal(SIGINT, handle_signal);

  while (!signal_received) {
    sleep(1);
  }

cleanup:
  fentry_bpf::destroy(skel);
  return err;
}