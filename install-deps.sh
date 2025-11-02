#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Install build dependencies for dnsbpf on Fedora

set -e

echo "Installing dnsbpf build dependencies for Fedora..."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
	echo "This script requires root privileges."
	echo "Please run: sudo $0"
	exit 1
fi

# Install required packages
echo "Installing packages..."
dnf install -y \
	clang \
	llvm \
	gcc \
	make \
	libbpf-devel \
	elfutils-libelf-devel \
	zlib-devel \
	kernel-headers \
	kernel-devel \
	iproute-tc

echo ""
echo "Dependencies installed successfully!"
echo ""
echo "Verifying installation..."
command -v clang >/dev/null && echo "  ✓ clang found"
command -v llc >/dev/null && echo "  ✓ llc found"
command -v gcc >/dev/null && echo "  ✓ gcc found"
pkg-config --exists libbpf && echo "  ✓ libbpf found"
command -v tc >/dev/null && echo "  ✓ tc (iproute2) found"
echo ""
echo "You can now build dnsbpf with: make"
