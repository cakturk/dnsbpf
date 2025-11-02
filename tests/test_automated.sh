#!/bin/bash
# Automated test script for dnsbpf improvements
# Usage: sudo ./test_automated.sh [interface]
# Example: sudo ./test_automated.sh wlp1s0

set -e  # Exit on error (except where we handle it)

# Default interface
IFACE="${1:-wlp1s0}"
PROG="./dnsbpf"

# Colors - only use if stdout is a TTY
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Cleanup function - always runs on exit
cleanup() {
    local exit_code=$?

    # Only print cleanup message if we've started tests
    if [ -n "$CLEANUP_STARTED" ]; then
        echo
        echo -e "${YELLOW}>>> Cleaning up on exit...${NC}"

        # Unload program if loaded
        if [ -e "/sys/fs/bpf/dnsbpf_prog" ] && [ -n "$IFACE" ] && [ -x "$PROG" ]; then
            echo "  - Unloading BPF program from $IFACE..."
            $PROG unload "$IFACE" 2>/dev/null || true
        fi

        # Remove any leftover pinned maps/programs
        local cleaned=false
        if [ -e "/sys/fs/bpf/dnsbpf_blocked_domains" ]; then
            rm -f /sys/fs/bpf/dnsbpf_blocked_domains 2>/dev/null && cleaned=true
        fi
        if [ -e "/sys/fs/bpf/dnsbpf_stats" ]; then
            rm -f /sys/fs/bpf/dnsbpf_stats 2>/dev/null && cleaned=true
        fi
        if [ -e "/sys/fs/bpf/dnsbpf_prog" ]; then
            rm -f /sys/fs/bpf/dnsbpf_prog 2>/dev/null && cleaned=true
        fi

        if [ "$cleaned" = true ]; then
            echo "  - Removed pinned BPF objects"
        fi

        echo -e "${GREEN}  [OK] Cleanup complete${NC}"
    fi

    exit $exit_code
}

# Set trap to always cleanup on exit (success, failure, or interrupt)
trap cleanup EXIT INT TERM

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    echo "Usage: sudo $0 [interface]"
    exit 1
fi

# Check if program exists
if [ ! -f "$PROG" ]; then
    echo -e "${RED}Error: $PROG not found. Run 'make' first.${NC}"
    exit 1
fi

# Check if interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo -e "${YELLOW}Warning: Interface '$IFACE' not found${NC}"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "  - " $2}' | sed 's/:$//'
    echo
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${BLUE}==================================================="
echo "Automated Test Suite for dnsbpf Improvements"
echo "==================================================="
echo -e "Interface: ${GREEN}$IFACE${NC}"
echo -e "Program:   $PROG"
echo -e "===================================================${NC}"
echo

# Test counter
PASS=0
FAIL=0

# Test helper functions
test_start() {
    echo -e "${BLUE}> Test $1: $2${NC}"
}

test_pass() {
    echo -e "${GREEN}  [PASS]${NC}"
    PASS=$((PASS + 1))
    echo
}

test_fail() {
    echo -e "${RED}  [FAIL] $1${NC}"
    FAIL=$((FAIL + 1))
    echo
}

# Mark that cleanup should run on exit
CLEANUP_STARTED=1

# Clean slate (initial cleanup before tests)
echo -e "${YELLOW}>>> Cleaning up any existing state...${NC}"

# Silent cleanup - check if something is loaded first
if [ -e "/sys/fs/bpf/dnsbpf_prog" ]; then
    echo "  - Found existing BPF program, unloading..."
    $PROG unload "$IFACE" >/dev/null 2>&1 || true
fi

# Remove any leftover pinned objects
rm -f /sys/fs/bpf/dnsbpf_* 2>/dev/null || true

echo -e "${GREEN}  [OK] Initial cleanup done${NC}"
echo

# ============================================================
# Test 1: Invalid interface name (command injection protection)
# ============================================================
test_start "1" "Interface validation (should reject malformed name)"
if $PROG load "bad;name" 2>&1 | grep -q "invalid characters"; then
    test_pass
else
    test_fail "Should reject interface name with special characters"
fi

# ============================================================
# Test 2: Normal load
# ============================================================
test_start "2" "Normal program load"
if $PROG load "$IFACE" 2>&1 | grep -q "Program loaded successfully"; then
    test_pass
else
    test_fail "Failed to load program"
fi

# ============================================================
# Test 3: Double load prevention (idempotency)
# ============================================================
test_start "3" "Idempotency check (double load should fail)"
if $PROG load "$IFACE" 2>&1 | grep -q "already loaded"; then
    test_pass
else
    test_fail "Should prevent double loading"
fi

# ============================================================
# Test 4: Add domain
# ============================================================
test_start "4" "Add domain to blocklist"
if $PROG add "test.example.com" 2>&1 | grep -q "added to blocklist"; then
    test_pass
else
    test_fail "Failed to add domain"
fi

# ============================================================
# Test 5: Add duplicate domain detection
# ============================================================
test_start "5" "Duplicate domain detection"
if $PROG add "test.example.com" 2>&1 | grep -q "already in the blocklist"; then
    test_pass
else
    test_fail "Should detect duplicate domain"
fi

# ============================================================
# Test 6: List domains (should show 1 domain)
# ============================================================
test_start "6" "List blocked domains"
OUTPUT=$($PROG list 2>&1)
if echo "$OUTPUT" | grep -q "test.example.com" && echo "$OUTPUT" | grep -q "Total: 1 domain"; then
    test_pass
else
    test_fail "List should show 1 domain"
    echo "$OUTPUT"
fi

# ============================================================
# Test 7: Stats command
# ============================================================
test_start "7" "Statistics display"
if $PROG stats 2>&1 | grep -q "DNS Filtering Statistics"; then
    test_pass
else
    test_fail "Stats command failed"
fi

# ============================================================
# Test 8: Remove non-existent domain (should warn)
# ============================================================
test_start "8" "Remove non-existent domain (should warn)"
if $PROG remove "nonexistent.example.com" 2>&1 | grep -q "not in the blocklist"; then
    test_pass
else
    test_fail "Should warn about non-existent domain"
fi

# ============================================================
# Test 9: Remove existing domain
# ============================================================
test_start "9" "Remove existing domain"
if $PROG remove "test.example.com" 2>&1 | grep -q "removed from blocklist"; then
    test_pass
else
    test_fail "Failed to remove domain"
fi

# ============================================================
# Test 10: Add multiple domains
# ============================================================
test_start "10" "Add multiple domains"
$PROG add "domain1.example.com" >/dev/null 2>&1
$PROG add "domain2.example.com" >/dev/null 2>&1
$PROG add "domain3.example.com" >/dev/null 2>&1
OUTPUT=$($PROG list 2>&1)
if echo "$OUTPUT" | grep -q "Total: 3 domains"; then
    test_pass
else
    test_fail "Should have 3 domains"
fi

# ============================================================
# Test 11: Clear all domains
# ============================================================
test_start "11" "Clear all domains"
if $PROG clear 2>&1 | grep -q "Cleared 3 domains"; then
    test_pass
else
    test_fail "Failed to clear domains"
fi

# ============================================================
# Test 12: Clear empty list (should say already empty)
# ============================================================
test_start "12" "Clear empty list (should detect empty)"
if $PROG clear 2>&1 | grep -q "already empty"; then
    test_pass
else
    test_fail "Should detect empty list"
fi

# ============================================================
# Test 13: List empty blocklist
# ============================================================
test_start "13" "List empty blocklist"
if $PROG list 2>&1 | grep -q "No domains blocked"; then
    test_pass
else
    test_fail "Should show empty list message"
fi

# ============================================================
# Test 14: Reload command
# ============================================================
test_start "14" "Reload command (unload + load)"
if $PROG reload "$IFACE" 2>&1 | grep -q "Program reloaded successfully"; then
    test_pass
else
    test_fail "Reload command failed"
fi

# ============================================================
# Test 15: Unload with verbose feedback
# ============================================================
test_start "15" "Unload with detailed feedback"
OUTPUT=$($PROG unload "$IFACE" 2>&1)
if echo "$OUTPUT" | grep -q "Unload summary" && echo "$OUTPUT" | grep -q "succeeded"; then
    test_pass
else
    test_fail "Unload should show summary"
fi

# ============================================================
# Test 16: Unload when nothing loaded (should warn)
# ============================================================
test_start "16" "Unload when nothing loaded"
if $PROG unload "$IFACE" 2>&1 | grep -q "may not have been loaded"; then
    test_pass
else
    test_fail "Should warn when nothing is loaded"
fi

# ============================================================
# Test 17: Maps properly pinned
# ============================================================
test_start "17" "BPF maps pinning verification"
$PROG load "$IFACE" >/dev/null 2>&1
if [ -e "/sys/fs/bpf/dnsbpf_prog" ] && \
   [ -e "/sys/fs/bpf/dnsbpf_blocked_domains" ] && \
   [ -e "/sys/fs/bpf/dnsbpf_stats" ]; then
    test_pass
else
    test_fail "Maps not properly pinned"
fi

# ============================================================
# Test 18: Maps properly unpinned on unload
# ============================================================
test_start "18" "BPF maps unpinning verification"
$PROG unload "$IFACE" >/dev/null 2>&1
if [ ! -e "/sys/fs/bpf/dnsbpf_prog" ] && \
   [ ! -e "/sys/fs/bpf/dnsbpf_blocked_domains" ] && \
   [ ! -e "/sys/fs/bpf/dnsbpf_stats" ]; then
    test_pass
else
    test_fail "Maps not properly unpinned"
fi

# ============================================================
# Test 19: Cannot access maps when program not loaded
# ============================================================
test_start "19" "Map access fails when program not loaded"
if $PROG stats 2>&1 | grep -q "Cannot open"; then
    test_pass
else
    test_fail "Should fail to access maps"
fi

# ============================================================
# Summary
# ============================================================
echo -e "${BLUE}==================================================="
echo "Test Summary"
echo -e "===================================================${NC}"
echo -e "${GREEN}Passed: $PASS${NC}"
if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Failed: $FAIL${NC}"
else
    echo -e "${GREEN}Failed: $FAIL${NC}"
fi
echo -e "${BLUE}Total:  $((PASS + FAIL))${NC}"
echo -e "${BLUE}===================================================${NC}"
echo

# Exit with appropriate code (trap will handle cleanup)
if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
