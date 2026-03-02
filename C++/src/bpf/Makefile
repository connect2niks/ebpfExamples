BPF_INCLUDE_DIR = ../../include/bpf
USER_INCLUDE_DIR = ../../include/user

# Final combined object name
BPF_OBJ_NAME = fentry_bpf

# Find all .bpf.c files
BPF_SRCS := $(wildcard *.bpf.c)
# objects for everything
ALL_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# exclude maps.bpf.o from final link
BPF_OBJS := $(filter-out maps.bpf.o,$(ALL_OBJS))
# Convert to .bpf.o
BPF_MAPS := maps.bpf.o


all: SKEL_BUILD

# Step 1: Compile each .bpf.c into .bpf.o
%.bpf.o: %.bpf.c
	clang -g -O2 -target bpf -I$(BPF_INCLUDE_DIR) -c $< -o $@

# Step 2: Combine all .bpf.o into single BPF object
BPF_BUILD: $(ALL_OBJS) 
	bpftool gen object $(BPF_OBJ_NAME) $(BPF_MAPS) $(BPF_OBJS)

# Step 3: Generate skeleton from combined object
SKEL_BUILD: vmlinux BPF_BUILD 
	bpftool gen skeleton $(BPF_OBJ_NAME) > $(USER_INCLUDE_DIR)/$(BPF_OBJ_NAME).skel.h


vmlinux:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_INCLUDE_DIR)/vmlinux.h


clean:
	rm -f *.bpf.o
	rm -f $(BPF_OBJ_NAME)
	rm -f $(USER_INCLUDE_DIR)/$(BPF_OBJ_NAME).skel.h
	rm -f $(BPF_INCLUDE_DIR)/vmlinux.h