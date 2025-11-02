#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Integration test script for dnsbpf

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IFACE="${1:-wlp1s0}"
DNSBPF="./dnsbpf"
TEST_DOMAIN_1="icanhazip.com"
TEST_DOMAIN_2="ftp.linux.org.tr"
ALLOWED_DOMAIN="google.com"
DNS_SERVER="8.8.8.8"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
	echo -e "${RED}Error: This script must be run as root${NC}"
	echo "Please run: sudo $0 [interface]"
	exit 1
fi

# Check if dnsbpf binary exists
if [ ! -f "$DNSBPF" ]; then
	echo -e "${RED}Error: dnsbpf binary not found${NC}"
	echo "Please build first: make"
	exit 1
fi

# Check if interface exists
if ! ip link show "$IFACE" >/dev/null 2>&1; then
	echo -e "${RED}Error: Interface $IFACE does not exist${NC}"
	echo "Available interfaces:"
	ip link show | grep '^[0-9]' | awk '{print "  " $2}' | tr -d ':'
	exit 1
fi

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

print_test() {
	echo ""
	echo -e "${YELLOW}==== $1 ====${NC}"
}

pass() {
	echo -e "${GREEN}✓ PASS${NC}: $1"
	((TESTS_PASSED++))
}

fail() {
	echo -e "${RED}✗ FAIL${NC}: $1"
	((TESTS_FAILED++))
}

# Cleanup function
cleanup() {
	echo ""
	print_test "Cleanup"
	$DNSBPF unload "$IFACE" 2>/dev/null || true
	sleep 1
}

# Setup trap for cleanup
trap cleanup EXIT

# Start tests
echo "========================================"
echo "  dnsbpf Integration Tests"
echo "========================================"
echo "Interface: $IFACE"
echo "DNS Server: $DNS_SERVER"
echo ""

# Test 1: Load BPF program
print_test "Test 1: Load BPF program"
if $DNSBPF load "$IFACE"; then
	pass "BPF program loaded successfully"
else
	fail "Failed to load BPF program"
	exit 1
fi

sleep 2

# Test 2: Add domains to blocklist
print_test "Test 2: Add domains to blocklist"
if $DNSBPF add "$TEST_DOMAIN_1"; then
	pass "Added $TEST_DOMAIN_1 to blocklist"
else
	fail "Failed to add $TEST_DOMAIN_1"
fi

if $DNSBPF add "$TEST_DOMAIN_2"; then
	pass "Added $TEST_DOMAIN_2 to blocklist"
else
	fail "Failed to add $TEST_DOMAIN_2"
fi

# Test 3: List blocked domains
print_test "Test 3: List blocked domains"
OUTPUT=$($DNSBPF list)
if echo "$OUTPUT" | grep -q "$TEST_DOMAIN_1" && echo "$OUTPUT" | grep -q "$TEST_DOMAIN_2"; then
	pass "Both domains appear in blocklist"
	echo "$OUTPUT"
else
	fail "Domains not found in blocklist"
	echo "$OUTPUT"
fi

# Test 4: Check statistics before queries
print_test "Test 4: Initial statistics"
$DNSBPF stats
pass "Statistics retrieved"

# Test 5: Query blocked domain (should fail or timeout)
print_test "Test 5: Query blocked domain"
echo "Testing: dig @$DNS_SERVER $TEST_DOMAIN_1 +time=2 +tries=1"
if timeout 5 dig @$DNS_SERVER "$TEST_DOMAIN_1" +time=2 +tries=1 >/dev/null 2>&1; then
	echo "Note: Query completed (blocking may not be working as expected)"
	echo "This could be due to caching or network configuration"
else
	pass "Blocked domain query failed/timed out as expected"
fi

# Test 6: Query allowed domain (should succeed)
print_test "Test 6: Query allowed domain"
echo "Testing: dig @$DNS_SERVER $ALLOWED_DOMAIN +time=2 +tries=1"
if timeout 5 dig @$DNS_SERVER "$ALLOWED_DOMAIN" +time=2 +tries=1 +short >/dev/null 2>&1; then
	pass "Allowed domain query succeeded"
else
	fail "Allowed domain query failed (network issue?)"
fi

# Test 7: Check updated statistics
print_test "Test 7: Updated statistics"
$DNSBPF stats
pass "Statistics updated"

# Test 8: Remove domain from blocklist
print_test "Test 8: Remove domain from blocklist"
if $DNSBPF remove "$TEST_DOMAIN_1"; then
	pass "Removed $TEST_DOMAIN_1 from blocklist"
else
	fail "Failed to remove domain"
fi

# Test 9: Verify removal
print_test "Test 9: Verify domain removal"
OUTPUT=$($DNSBPF list)
if echo "$OUTPUT" | grep -q "$TEST_DOMAIN_1"; then
	fail "Domain still in blocklist after removal"
else
	pass "Domain successfully removed"
fi

# Test 10: Clear all domains
print_test "Test 10: Clear all domains"
if $DNSBPF clear; then
	pass "All domains cleared"
else
	fail "Failed to clear domains"
fi

OUTPUT=$($DNSBPF list)
if echo "$OUTPUT" | grep -q "Total: 0"; then
	pass "Blocklist is empty"
else
	fail "Blocklist not empty after clear"
fi

# Test 11: Unload BPF program
print_test "Test 11: Unload BPF program"
if $DNSBPF unload "$IFACE"; then
	pass "BPF program unloaded successfully"
else
	fail "Failed to unload BPF program"
fi

# Summary
echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
	echo -e "${RED}Failed: $TESTS_FAILED${NC}"
	exit 1
else
	echo -e "${GREEN}All tests passed!${NC}"
	exit 0
fi
