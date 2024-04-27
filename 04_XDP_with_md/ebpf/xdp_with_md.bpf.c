#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>

#include "xdp_metadata.h"

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
                                         __u64 *timestamp) __ksym;

/* This is the data record stored in the map */
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct datarec);
    __uint(max_entries, 1024);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_prog_map(struct xdp_md *ctx) {
    void *data, *data_meta, *data_end;
	struct ipv6hdr *ip6h = NULL;
	struct ethhdr *eth = NULL;
	struct udphdr *udp = NULL;
	struct iphdr *iph = NULL;
	struct xdp_meta *meta;
	__u64 rx_timestamp = -1;
	int ret;

    struct datarec *rec;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

    __u64 bytes = data_end - data;
    
	eth = data;
	if (eth + 1 < data_end) {
		if (eth->h_proto == bpf_htons(ETH_P_IP)) {
			iph = (void *)(eth + 1);
			if (iph + 1 < data_end && iph->protocol == IPPROTO_UDP)
				udp = (void *)(iph + 1);
		}
		if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
			ip6h = (void *)(eth + 1);
			if (ip6h + 1 < data_end && ip6h->nexthdr == IPPROTO_UDP)
				udp = (void *)(ip6h + 1);
		}
		if (udp && udp + 1 > data_end)
			udp = NULL;
	}

	if (!udp)
		return XDP_PASS;

	/* Reserve enough for all custom metadata. */

	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta));
	if (ret != 0)
		return XDP_DROP;

	data = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;

	if (data_meta + sizeof(struct xdp_meta) > data)
		return XDP_DROP;

	meta = data_meta;

	/* Export metadata. */

	/* We expect veth bpf_xdp_metadata_rx_timestamp to return 0 HW
	 * timestamp, so put some non-zero value into AF_XDP frame for
	 * the userspace.
	 */

    int err = bpf_xdp_metadata_rx_timestamp(ctx, &rx_timestamp);
    if (err) {
        bpf_printk("Failed to get rx timestamp: %d\n", err);
        rx_timestamp = bpf_ktime_get_coarse_ns();
        bpf_printk("Got rx timestamp: %llu\n", rx_timestamp);
    } else {
        bpf_printk("Got rx timestamp: %llu\n", rx_timestamp);
    }

    int key = 0;

    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec) {
        bpf_printk("Failed to lookup in xdp_stats_map\n");
        return XDP_ABORTED;
    }

    __sync_fetch_and_add(&rec->rx_packets, 1);
    __sync_fetch_and_add(&rec->rx_bytes, bytes);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";