#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Manual testing helper for dnsbpf

DNS_SERVER="${1:-8.8.8.8}"

echo "dnsbpf Manual Test Helper"
echo "========================="
echo "DNS Server: $DNS_SERVER"
echo ""
echo "Commands to test:"
echo ""

cat <<'EOF'
# 1. Test blocked domain (should fail or return NXDOMAIN):
dig @DNS_SERVER icanhazip.com

# 2. Test another blocked domain:
dig @DNS_SERVER ftp.linux.org.tr

# 3. Test allowed domain (should work):
dig @DNS_SERVER google.com

# 4. Test with different query types:
dig @DNS_SERVER icanhazip.com A
dig @DNS_SERVER icanhazip.com AAAA

# 5. Monitor DNS traffic:
sudo tcpdump -i wlp1s0 -n port 53

# 6. Watch BPF program in action:
sudo tc filter show dev wlp1s0 egress

# 7. Check BPF maps:
sudo bpftool map dump name blocked_domains
sudo bpftool map dump name stats

# 8. View debug output (if enabled):
sudo cat /sys/kernel/debug/tracing/trace_pipe
EOF

echo ""
echo "Replace DNS_SERVER with your DNS server: $DNS_SERVER"
