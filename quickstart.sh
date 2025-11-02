#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Quick start script for dnsbpf

set -e

IFACE="${1:-wlp1s0}"

echo "=================================="
echo "  dnsbpf Quick Start"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
	echo "This script requires root privileges."
	echo "Please run: sudo $0 [interface]"
	exit 1
fi

# Check if built
if [ ! -f "./dnsbpf" ] || [ ! -f "./dnsbpf_kern.o" ]; then
	echo "Building dnsbpf..."
	make || { echo "Build failed. Run: sudo ./install-deps.sh"; exit 1; }
	echo ""
fi

echo "Interface: $IFACE"
echo ""

# Load program
echo "Step 1: Loading TC-BPF program on $IFACE..."
./dnsbpf load "$IFACE"
echo ""

# Add test domains
echo "Step 2: Adding test domains to blocklist..."
./dnsbpf add icanhazip.com
./dnsbpf add ftp.linux.org.tr
echo ""

# Show blocklist
echo "Step 3: Current blocklist:"
./dnsbpf list
echo ""

# Show stats
echo "Step 4: Initial statistics:"
./dnsbpf stats
echo ""

echo "=================================="
echo "  Setup Complete!"
echo "=================================="
echo ""
echo "Test with:"
echo "  dig @8.8.8.8 icanhazip.com      # Should be blocked"
echo "  dig @8.8.8.8 google.com         # Should work"
echo ""
echo "Manage blocklist:"
echo "  sudo ./dnsbpf add <domain>"
echo "  sudo ./dnsbpf remove <domain>"
echo "  sudo ./dnsbpf list"
echo "  sudo ./dnsbpf stats"
echo ""
echo "When done:"
echo "  sudo ./dnsbpf unload $IFACE"
echo ""
