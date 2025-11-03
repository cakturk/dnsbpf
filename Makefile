# SPDX-License-Identifier: GPL-2.0
# Makefile for dnsbpf - DNS filtering using TC-BPF

# Compiler toolchain
CLANG		?= clang
LLC		?= llc
CC		?= gcc
LLVM_STRIP	:= $(shell command -v llvm-strip 2>/dev/null)
STRIP		?= $(LLVM_STRIP)

# Directories
SRC_DIR		:= src
OBJ_DIR		:= .
BUILD_DIR	:= build

# Target files
KERN_OBJ	:= dnsbpf_kern.o
USER_BIN	:= dnsbpf

# Source files
KERN_SRC	:= $(SRC_DIR)/dnsbpf_kern.c
USER_SRC	:= $(SRC_DIR)/dnsbpf_user.c

# BPF compiler flags
BPF_CFLAGS	:= -O2 -g
BPF_CFLAGS	+= -target bpf
BPF_CFLAGS	+= -D__BPF_TRACING__
BPF_CFLAGS	+= -I$(SRC_DIR)
BPF_CFLAGS	+= -I/usr/include
BPF_CFLAGS	+= -Wno-unknown-attributes

# User-space compiler flags
USER_CFLAGS	:= -O2 -g -Wall
USER_CFLAGS	+= -I$(SRC_DIR)

# Linker flags
USER_LDFLAGS	:= -lbpf -lelf

# Detect system architecture
ARCH		:= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Default target
.PHONY: all
all: $(KERN_OBJ) $(USER_BIN)

# Build BPF kernel object
$(KERN_OBJ): $(KERN_SRC) $(SRC_DIR)/common.h $(SRC_DIR)/dns_parser.h
	@echo "  CLANG    $@"
	@$(CLANG) $(BPF_CFLAGS) -c $(KERN_SRC) -o $@
	@if [ -n "$(strip $(STRIP))" ]; then \
		echo "  STRIP    $@"; \
		if ! $(STRIP) -g $@; then \
			echo "  WARN     strip failed for $@ (skipping)"; \
		fi; \
	else \
		echo "  STRIP    skip (llvm-strip not found)"; \
	fi

# Build user-space binary
$(USER_BIN): $(USER_SRC) $(SRC_DIR)/common.h
	@echo "  CC       $@"
	@$(CC) $(USER_CFLAGS) $(USER_SRC) -o $@ $(USER_LDFLAGS)

# Install targets
.PHONY: install
install: all
	@echo "  INSTALL  $(USER_BIN) -> /usr/local/bin/"
	@install -m 0755 $(USER_BIN) /usr/local/bin/
	@echo "  INSTALL  $(KERN_OBJ) -> /usr/local/lib/dnsbpf/"
	@install -d /usr/local/lib/dnsbpf
	@install -m 0644 $(KERN_OBJ) /usr/local/lib/dnsbpf/

.PHONY: uninstall
uninstall:
	@echo "  REMOVE   /usr/local/bin/$(USER_BIN)"
	@rm -f /usr/local/bin/$(USER_BIN)
	@echo "  REMOVE   /usr/local/lib/dnsbpf/"
	@rm -rf /usr/local/lib/dnsbpf

# Clean build artifacts
.PHONY: clean
clean:
	@echo "  CLEAN"
	@rm -f $(KERN_OBJ) $(USER_BIN)
	@rm -f *.o
	@rm -rf $(BUILD_DIR)

# Check dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking build dependencies..."
	@command -v $(CLANG) >/dev/null 2>&1 || \
		{ echo "Error: clang not found"; exit 1; }
	@command -v $(LLC) >/dev/null 2>&1 || \
		{ echo "Error: llc not found"; exit 1; }
	@command -v $(CC) >/dev/null 2>&1 || \
		{ echo "Error: gcc not found"; exit 1; }
	@echo "Checking for libbpf..."
	@pkg-config --exists libbpf 2>/dev/null || \
		{ echo "Error: libbpf not found (install libbpf-devel)"; exit 1; }
	@echo "All dependencies satisfied."

# Help target
.PHONY: help
help:
	@echo "dnsbpf Makefile targets:"
	@echo "  all         - Build BPF kernel object and user-space binary (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  install     - Install to /usr/local/{bin,lib}"
	@echo "  uninstall   - Remove installed files"
	@echo "  check-deps  - Verify build dependencies"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Build variables:"
	@echo "  CLANG       - Clang compiler ($(CLANG))"
	@echo "  CC          - C compiler ($(CC))"
	@echo "  ARCH        - Target architecture ($(ARCH))"
