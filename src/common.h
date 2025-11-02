/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common definitions for dnsbpf
 * Shared between kernel BPF program and user-space control program
 */

#ifndef __DNSBPF_COMMON_H
#define __DNSBPF_COMMON_H

#define MAX_DOMAIN_LEN		256
#define MAX_BLOCKED_DOMAINS	10000

/* Statistics counters */
struct dnsbpf_stats {
	__u64 total_packets;
	__u64 dns_queries;
	__u64 blocked_queries;
	__u64 allowed_queries;
	__u64 parse_errors;
};

/* Map indices for statistics */
enum stat_key {
	STAT_TOTAL_PACKETS = 0,
	STAT_DNS_QUERIES,
	STAT_BLOCKED_QUERIES,
	STAT_ALLOWED_QUERIES,
	STAT_PARSE_ERRORS,
	STAT_MAX,
};

#endif /* __DNSBPF_COMMON_H */
