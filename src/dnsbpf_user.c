/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dnsbpf - User-space control program
 *
 * This program loads the TC-BPF egress hook and provides a CLI interface
 * for managing blocked domains.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>

#include "common.h"

#define PROG_NAME "dnsbpf_kern.o"
#define SEC_NAME "tc"

#define TC_FILTER_HANDLE 1
#define TC_FILTER_PRIORITY 1

static int blocked_domains_fd = -1;
static int stats_fd = -1;

static void normalize_domain_key(char *dst, const char *src)
{
	size_t i;

	for (i = 0; i < MAX_DOMAIN_LEN - 1 && src[i]; i++) {
		char c = src[i];
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
		dst[i] = c;
	}

	dst[i] = '\0';
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rl = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
		fprintf(stderr, "Error: Failed to raise RLIMIT_MEMLOCK limit: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %1$s <command> [options]\n\n"
		"Commands:\n"
		"  load <iface>        Load TC-BPF program on interface\n"
		"  unload <iface>      Unload TC-BPF program from interface\n"
		"  reload <iface>      Reload TC-BPF program (unload + load)\n"
		"  add <domain>        Add domain to blocklist\n"
		"  del <domain>        Remove domain from blocklist\n"
		"  list                List all blocked domains\n"
		"  stats               Show filtering statistics\n"
		"  clear               Clear all blocked domains\n\n"
		"Examples:\n"
		"  %1$s load wlp1s0\n"
		"  %1$s add example.com\n"
		"  %1$s add ftp.fu.example.org\n"
		"  %1$s stats\n"
		"  %1$s reload wlp1s0\n"
		"  %1$s unload wlp1s0\n",
		prog);
}

/*
 * Open BPF maps by pinned path
 * Maps are pinned in /sys/fs/bpf/ after loading
 */
static int open_maps(void)
{
	blocked_domains_fd = bpf_obj_get("/sys/fs/bpf/dnsbpf_blocked_domains");
	if (blocked_domains_fd < 0) {
		fprintf(stderr, "Error: Cannot open blocked_domains map\n");
		fprintf(stderr, "Make sure the BPF program is loaded with 'load' command\n");
		return -1;
	}

	stats_fd = bpf_obj_get("/sys/fs/bpf/dnsbpf_stats");
	if (stats_fd < 0) {
		fprintf(stderr, "Error: Cannot open stats map\n");
		close(blocked_domains_fd);
		return -1;
	}

	return 0;
}

static void close_maps(void)
{
	if (blocked_domains_fd >= 0)
		close(blocked_domains_fd);
	if (stats_fd >= 0)
		close(stats_fd);
}

/*
 * Validate interface name to prevent command injection
 * Returns 0 if valid, -1 if invalid
 */
static int validate_interface(const char *ifname)
{
	int i;
	size_t len;

	if (!ifname) {
		fprintf(stderr, "Error: Interface name is NULL\n");
		return -1;
	}

	len = strlen(ifname);
	if (len == 0 || len > IFNAMSIZ - 1) {
		fprintf(stderr, "Error: Invalid interface name length\n");
		return -1;
	}

	/* Only allow alphanumeric, dash, underscore */
	for (i = 0; i < len; i++) {
		char c = ifname[i];
		if (!((c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') ||
		      c == '-' || c == '_')) {
			fprintf(stderr, "Error: Interface name contains invalid characters\n");
			fprintf(stderr, "Only alphanumeric, dash, and underscore are allowed\n");
			return -1;
		}
	}

	return 0;
}

/*
 * Check if BPF program is already loaded
 * Returns 1 if loaded, 0 if not loaded
 */
static int is_already_loaded(void)
{
	return (access("/sys/fs/bpf/dnsbpf_prog", F_OK) == 0);
}

/*
 * Load TC-BPF program on interface egress
 */
static int cmd_load(const char *ifname)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	int prog_fd, ret;
	int ifindex;

	/* Check if already loaded */
	if (is_already_loaded()) {
		fprintf(stderr, "Error: BPF program is already loaded\n");
		fprintf(stderr, "Run '%s unload <interface>' first to unload the existing program\n",
			"dnsbpf");
		fprintf(stderr, "Or use '%s reload <interface>' to reload\n", "dnsbpf");
		return -1;
	}

	/* Validate interface name */
	if (validate_interface(ifname) < 0) {
		return -1;
	}

	if (bump_memlock_rlimit() < 0) {
		return -1;
	}

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr, "Error: Failed to resolve ifindex for %s: %s\n",
			ifname, strerror(errno));
		return -1;
	}

	/* Load BPF object file */
	obj = bpf_object__open_file(PROG_NAME, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Error: Failed to open BPF object file: %s\n",
			PROG_NAME);
		return -1;
	}

	/* Load BPF program into kernel */
	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "Error: Failed to load BPF program: %s\n",
			strerror(-ret));
		bpf_object__close(obj);
		return -1;
	}

	/* Find the TC program */
	prog = bpf_object__find_program_by_name(obj, "dnsbpf_egress");
	if (!prog) {
		fprintf(stderr, "Error: Cannot find program 'dnsbpf_egress'\n");
		bpf_object__close(obj);
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: Cannot get program fd\n");
		bpf_object__close(obj);
		return -1;
	}

	/* Pin maps for persistent access with custom names */
	struct bpf_map *map;

	/* Pin blocked_domains map */
	map = bpf_object__find_map_by_name(obj, "blocked_domains");
	if (!map) {
		fprintf(stderr, "Error: Cannot find blocked_domains map\n");
		bpf_object__close(obj);
		return -1;
	}
	ret = bpf_map__pin(map, "/sys/fs/bpf/dnsbpf_blocked_domains");
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to pin blocked_domains map: %s\n",
			strerror(-ret));
		bpf_object__close(obj);
		return -1;
	}
	printf("Pinned blocked_domains map to /sys/fs/bpf/dnsbpf_blocked_domains\n");

	/* Pin stats map */
	map = bpf_object__find_map_by_name(obj, "stats");
	if (!map) {
		fprintf(stderr, "Error: Cannot find stats map\n");
		unlink("/sys/fs/bpf/dnsbpf_blocked_domains");
		bpf_object__close(obj);
		return -1;
	}
	ret = bpf_map__pin(map, "/sys/fs/bpf/dnsbpf_stats");
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to pin stats map: %s\n",
			strerror(-ret));
		unlink("/sys/fs/bpf/dnsbpf_blocked_domains");
		bpf_object__close(obj);
		return -1;
	}
	printf("Pinned stats map to /sys/fs/bpf/dnsbpf_stats\n");

	/* Pin the program for TC to reference */
	ret = bpf_program__pin(prog, "/sys/fs/bpf/dnsbpf_prog");
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to pin program: %s\n",
			strerror(-ret));
		unlink("/sys/fs/bpf/dnsbpf_blocked_domains");
		unlink("/sys/fs/bpf/dnsbpf_stats");
		bpf_object__close(obj);
		return -1;
	}
	printf("Pinned program to /sys/fs/bpf/dnsbpf_prog\n");

	printf("BPF program loaded successfully (fd=%d)\n", prog_fd);
	printf("Setting up TC egress hook on interface %s...\n", ifname);

	/* Create clsact qdisc if needed */
	LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS,
	);
	ret = bpf_tc_hook_create(&hook);
	if (ret < 0 && ret != -EEXIST) {
		fprintf(stderr, "Error: Failed to create TC hook: %s\n",
			strerror(-ret));
		unlink("/sys/fs/bpf/dnsbpf_blocked_domains");
		unlink("/sys/fs/bpf/dnsbpf_stats");
		unlink("/sys/fs/bpf/dnsbpf_prog");
		bpf_object__close(obj);
		return -1;
	}

	/* Attach BPF program to TC egress using pinned program */
	LIBBPF_OPTS(bpf_tc_opts, opts,
		.handle = TC_FILTER_HANDLE,
		.priority = TC_FILTER_PRIORITY,
		.prog_fd = prog_fd,
	);
	ret = bpf_tc_attach(&hook, &opts);
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to attach TC filter: %s\n",
			strerror(-ret));
		fprintf(stderr, "Cleaning up pinned resources...\n");
		unlink("/sys/fs/bpf/dnsbpf_blocked_domains");
		unlink("/sys/fs/bpf/dnsbpf_stats");
		unlink("/sys/fs/bpf/dnsbpf_prog");
		bpf_object__close(obj);
		return -1;
	}

	bpf_object__close(obj);
	obj = NULL;

	printf("TC-BPF egress hook attached successfully on %s\n", ifname);
	printf("\nProgram loaded successfully!\n");
	printf("Use 'dnsbpf add <domain>' to add domains to the blocklist\n");

	return 0;
}

/*
 * Unload TC-BPF program from interface
 */
static int cmd_unload(const char *ifname)
{
	int ret;
	int error_count = 0;
	int success_count = 0;
	int ifindex;

	/* Validate interface name */
	if (validate_interface(ifname) < 0)
		return -1;

	printf("Unloading BPF program from %s...\n", ifname);

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr, "  [X] Failed to resolve ifindex for %s: %s\n",
			ifname, strerror(errno));
		return -1;
	}

	/* Remove TC filter */
	LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS,
	);
	LIBBPF_OPTS(bpf_tc_opts, opts,
		.handle = TC_FILTER_HANDLE,
		.priority = TC_FILTER_PRIORITY,
	);
	ret = bpf_tc_detach(&hook, &opts);
	if (ret == 0) {
		printf("  [OK] Removed TC egress filter\n");
		success_count++;
	} else {
		if (ret == -ENOENT) {
			fprintf(stderr, "  [!] TC egress filter not found (already removed)\n");
		} else {
			fprintf(stderr, "  [X] Failed to remove TC filter: %s\n",
				strerror(-ret));
			error_count++;
		}
	}

	/* Remove TC qdisc */
	LIBBPF_OPTS(bpf_tc_hook, qdisc_hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS,
	);
	ret = bpf_tc_hook_destroy(&qdisc_hook);
	if (ret == 0) {
		printf("  [OK] Removed TC clsact qdisc\n");
		success_count++;
	} else {
		if (ret == -ENOENT || ret == -ESRCH) {
			fprintf(stderr, "  [!] TC clsact qdisc not found (already removed)\n");
		} else {
			fprintf(stderr, "  [X] Failed to remove TC qdisc: %s\n",
				strerror(-ret));
			error_count++;
		}
	}

	/* Unpin blocked_domains map */
	if (unlink("/sys/fs/bpf/dnsbpf_blocked_domains") == 0) {
		printf("  [OK] Unpinned blocked_domains map\n");
		success_count++;
	} else {
		fprintf(stderr, "  [X] Failed to unpin blocked_domains map: %s\n",
			strerror(errno));
		error_count++;
	}

	/* Unpin stats map */
	if (unlink("/sys/fs/bpf/dnsbpf_stats") == 0) {
		printf("  [OK] Unpinned stats map\n");
		success_count++;
	} else {
		fprintf(stderr, "  [X] Failed to unpin stats map: %s\n",
			strerror(errno));
		error_count++;
	}

	/* Unpin program */
	if (unlink("/sys/fs/bpf/dnsbpf_prog") == 0) {
		printf("  [OK] Unpinned program\n");
		success_count++;
	} else {
		fprintf(stderr, "  [X] Failed to unpin program: %s\n",
			strerror(errno));
		error_count++;
	}

	printf("\nUnload summary: %d succeeded, %d failed\n",
	       success_count, error_count);

	if (error_count > 0 && success_count == 0) {
		fprintf(stderr, "Warning: Program may not have been loaded\n");
		return -1;
	}

	printf("TC-BPF program unloaded from %s\n", ifname);
	return 0;
}

/*
 * Reload TC-BPF program (unload + load)
 * This is useful when you've recompiled the program and want to reload it
 */
static int cmd_reload(const char *ifname)
{
	int ret;

	printf("Reloading BPF program on %s...\n\n", ifname);

	/* Try to unload first - ignore errors if not loaded */
	printf("Step 1: Unloading existing program (if any)...\n");
	ret = cmd_unload(ifname);
	if (ret != 0) {
		printf("Note: Unload had some failures (program may not have been loaded)\n");
		printf("Continuing with load...\n\n");
	} else {
		printf("\n");
	}

	/* Load the program */
	printf("Step 2: Loading program...\n");
	ret = cmd_load(ifname);
	if (ret != 0) {
		fprintf(stderr, "\nError: Failed to reload program\n");
		return -1;
	}

	printf("\n=================================\n");
	printf("Program reloaded successfully!\n");
	printf("=================================\n");

	return 0;
}

/*
 * Add domain to blocklist
 */
static int cmd_add(const char *domain)
{
	char key[MAX_DOMAIN_LEN] = {};
	__u32 value = 1;
	__u32 existing_value;
	int ret;

	if (!domain || strlen(domain) == 0) {
		fprintf(stderr, "Error: Domain name cannot be empty\n");
		return -1;
	}

	if (open_maps() < 0)
		return -1;

	if (strlen(domain) >= MAX_DOMAIN_LEN) {
		fprintf(stderr, "Error: Domain name too long (max %d chars)\n",
			MAX_DOMAIN_LEN - 1);
		fprintf(stderr, "Domain: '%s' (%zu chars)\n", domain, strlen(domain));
		close_maps();
		return -1;
	}

	normalize_domain_key(key, domain);

	/* Check if domain already exists */
	if (bpf_map_lookup_elem(blocked_domains_fd, key, &existing_value) == 0) {
		printf("Domain '%s' is already in the blocklist\n", domain);
		close_maps();
		return 0;
	}

	ret = bpf_map_update_elem(blocked_domains_fd, key, &value, BPF_ANY);
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to add domain: %s\n",
			strerror(errno));
		close_maps();
		return -1;
	}

	printf("[OK] Domain '%s' added to blocklist\n", domain);
	close_maps();
	return 0;
}

/*
 * Remove domain from blocklist
 */
static int cmd_del(const char *domain)
{
	char key[MAX_DOMAIN_LEN] = {};
	__u32 value;
	int ret;

	if (!domain || strlen(domain) == 0) {
		fprintf(stderr, "Error: Domain name cannot be empty\n");
		return -1;
	}

	if (open_maps() < 0)
		return -1;

	if (strlen(domain) >= MAX_DOMAIN_LEN) {
		fprintf(stderr, "Error: Domain name too long\n");
		close_maps();
		return -1;
	}

	normalize_domain_key(key, domain);

	/* Check if domain exists before trying to remove */
	if (bpf_map_lookup_elem(blocked_domains_fd, key, &value) != 0) {
		fprintf(stderr, "Warning: Domain '%s' is not in the blocklist\n", domain);
		close_maps();
		return 0;  /* Not an error, just a no-op */
	}

	ret = bpf_map_delete_elem(blocked_domains_fd, key);
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to remove domain: %s\n",
			strerror(errno));
		close_maps();
		return -1;
	}

	printf("[OK] Domain '%s' removed from blocklist\n", domain);
	close_maps();
	return 0;
}

/*
 * List all blocked domains
 */
static int cmd_list(void)
{
	char key[MAX_DOMAIN_LEN] = {};
	char next_key[MAX_DOMAIN_LEN] = {};
	__u32 value;
	int count = 0;
	int ret;

	if (open_maps() < 0)
		return -1;

	printf("Blocked Domains:\n");
	printf("================\n");

	ret = bpf_map_get_next_key(blocked_domains_fd, NULL, key);
	if (ret != 0) {
		printf("(No domains blocked)\n");
		printf("================\n");
		printf("Use 'dnsbpf add <domain>' to add domains\n");
		close_maps();
		return 0;
	}

	/* List all domains */
	while (1) {
		if (bpf_map_lookup_elem(blocked_domains_fd, key, &value) == 0) {
			key[MAX_DOMAIN_LEN - 1] = '\0';
			printf("  %3d. %s\n", count + 1, key);
			count++;
		}

		ret = bpf_map_get_next_key(blocked_domains_fd, key, next_key);
		if (ret != 0)
			break;

		memcpy(key, next_key, MAX_DOMAIN_LEN);
	}

	printf("================\n");
	printf("Total: %d domain%s blocked\n", count, count == 1 ? "" : "s");

	close_maps();
	return 0;
}

/*
 * Show statistics
 */
static int cmd_stats(void)
{
	__u32 key;
	__u64 total_packets = 0, dns_queries = 0;
	__u64 blocked = 0, allowed = 0, errors = 0;
	double block_rate = 0.0;

	if (open_maps() < 0)
		return -1;

	/* Read all statistics */
	key = STAT_TOTAL_PACKETS;
	bpf_map_lookup_elem(stats_fd, &key, &total_packets);

	key = STAT_DNS_QUERIES;
	bpf_map_lookup_elem(stats_fd, &key, &dns_queries);

	key = STAT_BLOCKED_QUERIES;
	bpf_map_lookup_elem(stats_fd, &key, &blocked);

	key = STAT_ALLOWED_QUERIES;
	bpf_map_lookup_elem(stats_fd, &key, &allowed);

	key = STAT_PARSE_ERRORS;
	bpf_map_lookup_elem(stats_fd, &key, &errors);

	/* Calculate block rate */
	if (dns_queries > 0)
		block_rate = (double)blocked / dns_queries * 100.0;

	printf("\n");
	printf("DNS Filtering Statistics\n");
	printf("=========================\n\n");

	printf("Packet Processing:\n");
	printf("  Total packets:        %12llu\n", total_packets);
	printf("  DNS queries:          %12llu\n", dns_queries);
	printf("  Parse errors:         %12llu\n\n", errors);

	printf("Filtering Results:\n");
	printf("  Blocked queries:      %12llu", blocked);
	if (dns_queries > 0)
		printf(" (%.1f%%)", block_rate);
	printf("\n");
	printf("  Allowed queries:      %12llu", allowed);
	if (dns_queries > 0)
		printf(" (%.1f%%)", 100.0 - block_rate);
	printf("\n\n");

	if (dns_queries == 0) {
		printf("Note: No DNS queries processed yet.\n");
		printf("Generate some DNS traffic to see filtering in action.\n\n");
	} else if (blocked == 0) {
		printf("Note: No queries blocked yet.\n");
		printf("Add domains to the blocklist with 'dnsbpf add <domain>'\n\n");
	}

	close_maps();
	return 0;
}

/*
 * Clear all blocked domains
 */
static int cmd_clear(void)
{
	char key[MAX_DOMAIN_LEN] = {};
	char next_key[MAX_DOMAIN_LEN] = {};
	int count = 0;
	int errors = 0;
	int ret;

	if (open_maps() < 0)
		return -1;

	/* Check if empty first */
	ret = bpf_map_get_next_key(blocked_domains_fd, NULL, key);
	if (ret != 0) {
		printf("Blocklist is already empty\n");
		close_maps();
		return 0;
	}

	printf("Clearing all blocked domains...\n");

	while (1) {
		ret = bpf_map_get_next_key(blocked_domains_fd, key, next_key);

		if (bpf_map_delete_elem(blocked_domains_fd, key) == 0) {
			count++;
		} else {
			errors++;
		}

		if (ret != 0)
			break;

		memcpy(key, next_key, MAX_DOMAIN_LEN);
	}

	if (errors > 0) {
		fprintf(stderr, "Warning: Failed to delete %d domains\n", errors);
	}

	printf("[OK] Cleared %d domain%s from blocklist\n", count,
	       count == 1 ? "" : "s");

	close_maps();
	return 0;
}

int main(int argc, char **argv)
{
	if (libbpf_set_strict_mode(LIBBPF_STRICT_ALL) != 0)
		fprintf(stderr, "Warning: Failed to enable libbpf strict mode\n");

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "load") == 0) {
		if (argc != 3) {
			fprintf(stderr, "Error: 'load' requires interface name\n");
			usage(argv[0]);
			return 1;
		}
		return cmd_load(argv[2]);
	} else if (strcmp(argv[1], "unload") == 0) {
		if (argc != 3) {
			fprintf(stderr, "Error: 'unload' requires interface name\n");
			usage(argv[0]);
			return 1;
		}
		return cmd_unload(argv[2]);
	} else if (strcmp(argv[1], "reload") == 0) {
		if (argc != 3) {
			fprintf(stderr, "Error: 'reload' requires interface name\n");
			usage(argv[0]);
			return 1;
		}
		return cmd_reload(argv[2]);
	} else if (strcmp(argv[1], "add") == 0) {
		if (argc != 3) {
			fprintf(stderr, "Error: 'add' requires domain name\n");
			usage(argv[0]);
			return 1;
		}
		return cmd_add(argv[2]);
	} else if (strcmp(argv[1], "del") == 0) {
		if (argc != 3) {
			fprintf(stderr, "Error: 'remove' requires domain name\n");
			usage(argv[0]);
			return 1;
		}
		return cmd_del(argv[2]);
	} else if (strcmp(argv[1], "list") == 0) {
		return cmd_list();
	} else if (strcmp(argv[1], "stats") == 0) {
		return cmd_stats();
	} else if (strcmp(argv[1], "clear") == 0) {
		return cmd_clear();
	} else {
		fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
		usage(argv[0]);
		return 1;
	}

	return 0;
}
