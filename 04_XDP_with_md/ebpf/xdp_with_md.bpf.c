#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

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
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct datarec *rec;
    int key = 0;
    

    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec) {
        return XDP_ABORTED;
    }

    uint64_t rx_timestamp;

    int err = bpf_xdp_metadata_rx_timestamp(ctx, &rx_timestamp);
    if (err) {
        bpf_printk("Failed to get rx timestamp: %d\n", err);
        rx_timestamp = bpf_ktime_get_coarse_ns();
        bpf_printk("Got rx timestamp: %llu\n", rx_timestamp);
    } else {
        bpf_printk("Got rx timestamp: %llu\n", rx_timestamp);
    }

    __u64 bytes = data_end - data;
    __sync_fetch_and_add(&rec->rx_packets, 1);
    __sync_fetch_and_add(&rec->rx_bytes, bytes);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";