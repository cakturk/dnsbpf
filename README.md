# dnsbpf - DNS Filtering with eBPF/TC

An experimental DNS filtering project I put together while tinkering with TC-BPF (Traffic Control BPF) to see how DNS queries can be handled at the kernel level.

## Features

- **Kernel-level filtering**: Intercepts DNS queries using TC-BPF egress hooks
- **eBPF experiment**: Uses TC eBPF maps to explore DNS handling
- **Exact domain matching**: Blocks specific domains (A and AAAA queries)
- **Statistics tracking**: Surfaces basic counters for blocked and allowed queries
- **Simple CLI**: Straightforward command-line interface while I learn
- **Bounds checking focus**: Attempts safe packet parsing with basic guardrails

## Quick Start

### 1. Install Dependencies (Fedora 42)

```bash
sudo ./install-deps.sh
```

### 2. Build

```bash
make
```

### 3. Load and Test

```bash
# Load the BPF program on your network interface
sudo ./dnsbpf load wlp1s0

# Add domains to blocklist
sudo ./dnsbpf add icanhazip.com
sudo ./dnsbpf add ftp.linux.org.tr

# Test blocking (might return NXDOMAIN or timeout)
dig @8.8.8.8 icanhazip.com

# Test normal query (should still work)
dig @8.8.8.8 google.com

# View statistics
sudo ./dnsbpf stats

# List blocked domains
sudo ./dnsbpf list

# Unload when done
sudo ./dnsbpf unload wlp1s0
```

## Commands

```
load <iface>        Load TC-BPF program on interface
unload <iface>      Unload TC-BPF program from interface
add <domain>        Add domain to blocklist
remove <domain>     Remove domain from blocklist
list                List all blocked domains
stats               Show filtering statistics
clear               Clear all blocked domains
```

## How It Works

```
Outgoing packet -> TC Egress Hook -> Parse DNS Query ->
Check blocklist -> If blocked: Drop/NXDOMAIN | If allowed: Pass
```

1. TC-BPF hook intercepts outgoing packets on egress
2. Filters for UDP port 53 (DNS) traffic
3. Parses DNS query name safely with bounds checking
4. Looks up domain in BPF hash map
5. For blocked domains: packet is dropped or modified to NXDOMAIN
6. For allowed domains: packet passes through as-is

## Requirements

- Linux kernel 4.18+ (5.x+ recommended)
- Fedora 42 or similar distribution (only environment I’ve tried so far)
- Root/sudo privileges
- Network interface with TC support

## Troubleshooting

**Program won't load:**
```bash
# Check kernel version
uname -r

# Verify TC is available
tc -version

# Check BPF filesystem is mounted
mount | grep bpf
```

**Cannot add domains:**
```bash
# Make sure program is loaded first
sudo ./dnsbpf load wlp1s0

# Check map is accessible
ls -l /sys/fs/bpf/
```

## License

GPL-2.0
