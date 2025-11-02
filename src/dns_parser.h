/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DNS protocol definitions and parsing helpers
 */

#ifndef __DNS_PARSER_H
#define __DNS_PARSER_H

#include <linux/types.h>

/* DNS header structure - 12 bytes */
struct dnshdr {
	__u16 id;		/* Transaction ID */
	__u16 flags;		/* Flags */
	__u16 qdcount;		/* Number of questions */
	__u16 ancount;		/* Number of answers */
	__u16 nscount;		/* Number of authority records */
	__u16 arcount;		/* Number of additional records */
} __attribute__((packed));

/* DNS flags breakdown */
#define DNS_QR_MASK	0x8000	/* Query/Response flag */
#define DNS_QR_QUERY	0x0000
#define DNS_QR_RESPONSE	0x8000

#define DNS_OPCODE_MASK	0x7800	/* Operation code */
#define DNS_OPCODE_QUERY 0x0000

#define DNS_AA_MASK	0x0400	/* Authoritative answer */
#define DNS_TC_MASK	0x0200	/* Truncation */
#define DNS_RD_MASK	0x0100	/* Recursion desired */
#define DNS_RA_MASK	0x0080	/* Recursion available */
#define DNS_RCODE_MASK	0x000F	/* Response code */

/* DNS response codes */
#define DNS_RCODE_NOERROR	0
#define DNS_RCODE_NXDOMAIN	3

/* DNS query types */
#define DNS_QTYPE_A	1	/* IPv4 address */
#define DNS_QTYPE_AAAA	28	/* IPv6 address */

/* DNS query class */
#define DNS_QCLASS_IN	1	/* Internet */

/* Maximum DNS label length */
#define DNS_MAX_LABEL_LEN	63
#define DNS_MAX_NAME_LEN	253

/*
 * DNS question section structure (variable length)
 * Format: QNAME (variable) + QTYPE (2 bytes) + QCLASS (2 bytes)
 */
struct dns_question {
	__u16 qtype;
	__u16 qclass;
} __attribute__((packed));

#endif /* __DNS_PARSER_H */
