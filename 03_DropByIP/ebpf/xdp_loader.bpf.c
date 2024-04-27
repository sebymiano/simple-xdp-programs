#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";