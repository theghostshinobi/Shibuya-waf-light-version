# ebpf/Makefile

LLC ?= llc
CLANG ?= clang
CC := gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
# Try to include common Linux header paths
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS += -I/usr/include

TARGETS = xdp_filter.bpf.o tc_filter.bpf.o

all: $(TARGETS)

%.bpf.o: src/%.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o

.PHONY: all clean
