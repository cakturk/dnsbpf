/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dnsbpf - DNS filtering using TC-BPF egress hook
 *
 * This program intercepts outgoing DNS queries and blocks specific domains
 * by responding with NXDOMAIN.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "dns_parser.h"

char _license[] SEC("license") = "GPL";

/* BPF map: blocked domains (hash map) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_BLOCKED_DOMAINS);
	__type(key, char[MAX_DOMAIN_LEN]);
	__type(value, __u32);
} blocked_domains SEC(".maps");

/* BPF map: statistics (array) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Temporary storage to avoid stack limit issues */
struct temp_buf {
	char domain[MAX_DOMAIN_LEN];
};

/* BPF map: per-CPU temporary buffer */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct temp_buf);
} temp_storage SEC(".maps");

/* Helper function to update statistics */
static __always_inline void update_stat(enum stat_key key)
{
	__u32 idx = (__u32)key;
	__u64 *counter;

	counter = bpf_map_lookup_elem(&stats, &idx);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

/* Context for DNS label copy callback */
struct dns_copy_ctx {
	unsigned char *src;
	char *dst;
	const void *data_end;
	int *dst_len;
	unsigned char max_copy;
};

/* Helper to copy one label character - used by bpf_loop */
static long copy_one_label_char(__u32 index, void *ctx)
{
	struct dns_copy_ctx *copy_ctx = ctx;
	int dst_len;
	unsigned char ch;

	/* Check if we've copied enough */
	if (index >= copy_ctx->max_copy)
		return 1;

	/* Read and validate dst_len for verifier */
	dst_len = *copy_ctx->dst_len;
	if (dst_len < 0 || dst_len >= MAX_DOMAIN_LEN - 1)
		return 1;

	/* Bounds check source */
	if ((void *)(copy_ctx->src + index + 1) > copy_ctx->data_end)
		return 1;

	/* Copy character and normalize to lowercase */
	ch = copy_ctx->src[index];
	if (ch >= 'A' && ch <= 'Z')
		ch += 'a' - 'A';
	/* bpf_printk("ch: %c", ch); */
	copy_ctx->dst[dst_len] = ch;

	/* Update length */
	dst_len++;
	*copy_ctx->dst_len = dst_len;

	return 0;
}

/*
 * Parse DNS query name from packet
 * Returns: wire format length (bytes consumed), or -1 on error
 *
 * DNS names are encoded as labels: <len><data><len><data>...<0>
 * Example: "example.com" -> 7example3com0
 */
static int parse_dns_qname(void *data, const void *data_end,
			   struct dnshdr *dns,
			   char *domain_out)
{
	unsigned char *qname_start = (unsigned char *)(dns + 1);
	unsigned char *p = qname_start;
	unsigned char label_len;
	int i, domain_len = 0;
	struct dns_copy_ctx copy_ctx;

	/* Bounds check for starting position */
	if ((void *)(qname_start + 1) > data_end)
		return -1;

	/*
	 * Parse DNS labels - max 10 labels
	 * Using bpf_loop for inner character copying to reduce verifier
	 * complexity
	 */
	for (i = 0; i < 10; i++) {
		/* Bounds check */
		if ((void *)(p + 1) > data_end)
			return -1;

		label_len = *p++;

		/* End of domain name */
		if (label_len == 0)
			break;

		/* Check for DNS compression */
		if (label_len >= 192)
			return -1;

		/* Validate label length - limit to RFC-compliant 63 chars */
		if (label_len > DNS_MAX_LABEL_LEN)
			return -1;

		/* Check bounds for entire label */
		if ((void *)(p + label_len) > data_end)
			return -1;

		/* Add dot separator (except for first label) */
		if (domain_len > 0) {
			if (domain_len >= MAX_DOMAIN_LEN - 1)
				return -1;
			domain_out[domain_len++] = '.';
		}

		/* Ensure label fits in remaining buffer (account for terminator) */
		if (label_len > MAX_DOMAIN_LEN - 1 - domain_len)
			return -1;

		/* Use bpf_loop to copy label characters
		 * This reduces verifier complexity compared to nested for loops
		 */
		copy_ctx.src = p;
		copy_ctx.dst = domain_out;
		copy_ctx.data_end = data_end;
		copy_ctx.dst_len = &domain_len;
		copy_ctx.max_copy = label_len;

		bpf_loop(label_len, copy_one_label_char, &copy_ctx, 0);

		/* Re-validate domain_len bounds for verifier
		 * The callback modifies it via pointer, so verifier loses tracking
		 */
		if (domain_len < 0 || domain_len >= MAX_DOMAIN_LEN)
			return -1;

		p += label_len;
	}

	/* Null terminate */
	if (domain_len >= 0 && domain_len < MAX_DOMAIN_LEN)
		domain_out[domain_len] = '\0';

	/* Calculate wire format length */
	return (int)(p - qname_start);
}

/*
 * Modify DNS query packet to NXDOMAIN response
 * This swaps src/dst addresses and modifies DNS flags
 * Note: BPF only allows 5 function parameters, so we re-derive pointers
 */
static int craft_nxdomain_response(struct __sk_buff *skb, void *data,
				   const void *data_end)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct dnshdr *dns;
	__u8 tmp_mac[ETH_ALEN];
	__u32 old_saddr, old_daddr;
	__u16 old_sport, old_dport;
	__u16 old_flags, new_flags;
	int ip_csum_off;

	/* Re-parse headers - BPF verifier requires this */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;

	udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));
	if ((void *)(udp + 1) > data_end)
		return -1;

	dns = (struct dnshdr *)(udp + 1);
	if ((void *)(dns + 1) > data_end)
		return -1;

	/* Save old values for checksum updates */
	old_saddr = ip->saddr;
	old_daddr = ip->daddr;
	old_sport = udp->source;
	old_dport = udp->dest;
	old_flags = dns->flags;

	/* Calculate IP checksum offset */
	ip_csum_off = ETH_HLEN + offsetof(struct iphdr, check);

	/* Swap Ethernet addresses */
	__builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	/* Swap IP addresses */
	ip->saddr = old_daddr;
	ip->daddr = old_saddr;

	/* Swap UDP ports */
	udp->source = old_dport;
	udp->dest = old_sport;

	/* Modify DNS flags: QR=1 (response), RCODE=3 (NXDOMAIN) */
	new_flags = bpf_ntohs(old_flags);
	new_flags |= DNS_QR_RESPONSE;		/* Set QR bit */
	new_flags &= ~DNS_RCODE_MASK;		/* Clear RCODE */
	new_flags |= DNS_RCODE_NXDOMAIN;	/* Set NXDOMAIN */
	dns->flags = bpf_htons(new_flags);

	/* Update IP checksum for changed source address */
	bpf_l3_csum_replace(skb, ip_csum_off, old_saddr, old_daddr, 4);
	/* Update IP checksum for changed destination address */
	bpf_l3_csum_replace(skb, ip_csum_off, old_daddr, old_saddr, 4);

	/*
	 * Reload data pointers - BPF verifier invalidates them after helper calls
	 * that might modify the packet
	 */
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	/* Re-parse headers to satisfy verifier */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;

	udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));
	if ((void *)(udp + 1) > data_end)
		return -1;

	/*
	 * Update UDP checksum for changed IP addresses and ports
	 * For UDP over IPv4, checksum is optional so we can set it to 0
	 * to avoid complexity. The kernel will accept it.
	 */
	udp->check = 0;

	return 0;
}

SEC("tc")
int dnsbpf_egress(struct __sk_buff *skb)
{
	const void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	const struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct dnshdr *dns;
	struct dns_question *question;
	struct temp_buf *temp;
	int name_wire_len = 0;
	unsigned char *cursor;
	__u32 temp_key = 0;
	__u16 qtype;

	update_stat(STAT_TOTAL_PACKETS);

	/* Get temporary buffer from per-CPU map to avoid stack overflow */
	temp = bpf_map_lookup_elem(&temp_storage, &temp_key);
	if (!temp)
		return TC_ACT_OK;

	__builtin_memset(temp, 0, sizeof(*temp));

	/* Parse Ethernet header */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	/* Only process IPv4 packets */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP header */
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* Only process UDP packets */
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	/* Parse UDP header */
	udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;

	/* Only process DNS queries (destination port 53) */
	if (udp->dest != bpf_htons(53))
		return TC_ACT_OK;

	update_stat(STAT_DNS_QUERIES);

	/* Parse DNS header */
	dns = (struct dnshdr *)(udp + 1);
	if ((void *)(dns + 1) > data_end) {
		update_stat(STAT_PARSE_ERRORS);
		return TC_ACT_OK;
	}

	/* bpf_printk("response detected giving up! %x", bpf_htons(DNS_QR_MASK)); */
	/* Validate DNS query */
	if (dns->flags & bpf_htons(DNS_QR_MASK))
		return TC_ACT_OK;

	/* Must have at least one question */
	if (bpf_ntohs(dns->qdcount) < 1) {
		update_stat(STAT_PARSE_ERRORS);
		return TC_ACT_OK;
	}

	/* Parse DNS question name directly into temp buffer */
	name_wire_len = parse_dns_qname(data, data_end, dns, temp->domain);
	if (name_wire_len < 0) {
		update_stat(STAT_PARSE_ERRORS);
		return TC_ACT_OK;
	}

	/* Validate wire length */
	if (name_wire_len == 0 || name_wire_len > DNS_MAX_NAME_LEN) {
		update_stat(STAT_PARSE_ERRORS);
		return TC_ACT_OK;
	}

	/* Get question type and class
	 * Calculate cursor position and validate bounds before dereferencing
	 */
	cursor = (unsigned char *)(dns + 1);

	/* Add name_wire_len with bounds check for verifier */
	if (name_wire_len < 0 || name_wire_len > DNS_MAX_NAME_LEN)
		return TC_ACT_OK;

	cursor += name_wire_len;

	/* Verify cursor is within packet bounds before accessing question */
	if ((void *)cursor > data_end)
		return TC_ACT_OK;

	question = (struct dns_question *)cursor;
	if ((void *)(question + 1) > data_end) {
		update_stat(STAT_PARSE_ERRORS);
		return TC_ACT_OK;
	}
	/* bpf_printk("len: %s", temp->domain); */

	qtype = question->qtype;

	/* bpf_printk("qtype: %x A: %x", qtype, DNS_QTYPE_A); */
	/* Only filter A and AAAA queries */
	if (qtype != bpf_htons(DNS_QTYPE_A) &&
	    qtype != bpf_htons(DNS_QTYPE_AAAA)) {
		update_stat(STAT_ALLOWED_QUERIES);
		return TC_ACT_OK;
	}

	/* Lookup domain in blocked list */
	if (bpf_map_lookup_elem(&blocked_domains, temp->domain) == NULL) {
		/* Domain not blocked, allow */
		update_stat(STAT_ALLOWED_QUERIES);
		return TC_ACT_OK;
	}

	/* Domain is blocked - craft NXDOMAIN response */
	update_stat(STAT_BLOCKED_QUERIES);

	/* Craft NXDOMAIN response (re-parses headers internally) */
	if (craft_nxdomain_response(skb, data, data_end) < 0)
		return TC_ACT_SHOT;

	/* Redirect packet back to ingress so it reaches the application
	 * We're on egress, so TC_ACT_OK would send it OUT to the network.
	 * Instead, redirect to ingress using the same interface.
	 */
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}
