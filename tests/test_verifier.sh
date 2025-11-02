#!/bin/sh

# Test if BPF program passes verifier
# Run with: sudo ./test_verifier.sh <iface>

set -e

IFACE="${1:-wlp1s0}"

echo "Testing BPF verifier with interface: $IFACE"
echo "========================================="

# Clean up any existing setup
echo "Cleaning up..."
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
rm -f /sys/fs/bpf/dnsbpf_* 2>/dev/null || true

# Load the BPF program
echo "Loading BPF program..."
if ./dnsbpf load "$IFACE"; then
	echo "SUCCESS: BPF program passed verifier and loaded!"

	# Show program info
	echo ""
	echo "BPF program info:"
	bpftool prog show | grep dnsbpf || true

	echo ""
	echo "TC filter info:"
	tc filter show dev "$IFACE" egress || true

	# Cleanup
	echo ""
	echo "Cleaning up..."
	./dnsbpf unload "$IFACE"

	echo "Test completed successfully"
else
	echo "FAILED: BPF program did not load"
	exit 1
fi
