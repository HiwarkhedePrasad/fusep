# ═══════════════════════════════════════════════════════════════════════
#  eBPF Build System — FUSE Protocol Tracer
# ═══════════════════════════════════════════════════════════════════════

CLANG    ?= clang
ARCH     ?= x86
BPF_CFLAGS = -target bpf -g -O2 -D__TARGET_ARCH_$(ARCH) \
             -D__BPF__ -ffreestanding -I/usr/include/bpf \
             -Wall -Wextra

.PHONY: all clean

all: fuse_trace.bpf.o

fuse_trace.bpf.o: fuse_trace.bpf.c fuse_trace.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f fuse_trace.bpf.o
