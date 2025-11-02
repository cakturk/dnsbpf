#!/bin/bash
# Quick reload helper script

IFACE="${1:-wlp1s0}"

echo "Cleaning up old BPF state..."

# Unload TC filters
sudo tc filter del dev $IFACE egress 2>/dev/null || true
sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true

# Remove old pinned maps and program
sudo rm -f /sys/fs/bpf/dnsbpf_blocked_domains
sudo rm -f /sys/fs/bpf/dnsbpf_stats
sudo rm -f /sys/fs/bpf/dnsbpf_prog
sudo rm -f /sys/fs/bpf/blocked_domains
sudo rm -f /sys/fs/bpf/stats

echo "Loading fresh program..."
sudo ./dnsbpf load $IFACE

echo ""
echo "Ready! You can now add domains with:"
echo "  sudo ./dnsbpf add <domain>"
