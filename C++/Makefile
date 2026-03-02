BPF_OBJ_NAME = fentry_bpf

all:
	@echo "Building eBPF program"
	cd src/bpf && $(MAKE) && cd ../..
	@echo "Building user space program"
	cd src/user && $(MAKE) && cd ../..


clean:
	cd src/bpf && $(MAKE) clean && cd ../..
	cd src/user && $(MAKE) clean && cd ../..


.PHONY: all
