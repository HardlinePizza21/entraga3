CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
BPF_ARCH ?= x86
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BUILD_DIR := build

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)

.PHONY: all clean test check-deps

all: $(BUILD_DIR)/mmap_guard $(BUILD_DIR)/mmap_guard_test

check-deps:
	@command -v $(CLANG) >/dev/null || { echo "clang no está instalado" >&2; exit 1; }
	@command -v $(BPFTOOL) >/dev/null || { echo "bpftool no está instalado" >&2; exit 1; }
	@$(PKG_CONFIG) --exists libbpf || { echo "faltan libbpf y sus encabezados" >&2; exit 1; }
	@test -r "$(VMLINUX_BTF)" || { echo "no está disponible el BTF del kernel" >&2; exit 1; }

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR) check-deps
	$(BPFTOOL) btf dump file "$(VMLINUX_BTF)" format c > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR)/mmap_guard.bpf.o: src/mmap_guard.bpf.c $(BUILD_DIR)/vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -O2 -g \
		-Wall -Werror -Wno-missing-declarations -I$(BUILD_DIR) $(LIBBPF_CFLAGS) \
		-c $< -o $@

$(BUILD_DIR)/mmap_guard.skel.h: $(BUILD_DIR)/mmap_guard.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR)/mmap_guard: src/loader.c $(BUILD_DIR)/mmap_guard.skel.h
	$(CC) -O2 -g -Wall -Wextra -Werror -I$(BUILD_DIR) \
		$(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

$(BUILD_DIR)/mmap_guard_test: src/mmap_guard_test.c | $(BUILD_DIR)
	$(CC) -O2 -g -Wall -Wextra -Werror -pthread $< -o $@

test: all
	sh ./scripts/test_guard.sh

clean:
	rm -rf $(BUILD_DIR)
