#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/if_ether.h>

/* This is the data record stored in the map */
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

const volatile int redir_ifindex;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, struct datarec);
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");

static __always_inline void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

SEC("xdp")
int xdp_prog_map(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct datarec *rec;
    int key = 0;
    struct ethhdr *eth = data;
	__u64 nh_off;

    nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_ABORTED;

    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec) {
        return XDP_ABORTED;
    }

    __u64 bytes = data_end - data;
    __sync_fetch_and_add(&rec->rx_packets, 1);
    __sync_fetch_and_add(&rec->rx_bytes, bytes);

    swap_src_dst_mac(data);

    return bpf_redirect(redir_ifindex, 0);
}


SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";