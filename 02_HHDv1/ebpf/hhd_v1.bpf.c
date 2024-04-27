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

const volatile struct {
   int ifindex_if1;
   int ifindex_if2;
   int ifindex_if3;
   int ifindex_if4;
} hhdv1_cfg = {};

struct value_t {
   __u64 threshold;
   __u64 packets_rcvd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct value_t);
    __uint(max_entries, 1024);
} threshold_map SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, __u32);
   __type(value, __u32);
   __uint(max_entries, 16);
} ip_to_port SEC(".maps");

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
   struct iphdr *ip = (struct iphdr *)(data + *nh_off);
   int hdr_size = sizeof(*ip);

   /* Byte-count bounds check; check if current pointer + size of header
    * is after data_end.
    */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   hdr_size = ip->ihl * 4;
   if (hdr_size < sizeof(*ip))
      return -1;

   /* Variable-length IPv4 header, need to use byte-based arithmetic */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *iphdr = ip;

   return ip->protocol;
}

SEC("xdp")
int xdp_hhdv1(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   struct iphdr *ip;
   int eth_type, ip_type;
   int action = XDP_PASS;

   bpf_printk("Packet received from interface %d", ctx->ingress_ifindex);

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_htons(ETH_P_IP)) {
      bpf_printk("Packet is not an IPv4 packet");
      return XDP_DROP;
   }

   ip_type = parse_iphdr(data, data_end, &nf_off, &ip);

   if (ip_type < 0) {
      bpf_printk("Packet is not a valid IPv4 packet");
      return XDP_DROP;
   }

   if (ctx->ingress_ifindex != hhdv1_cfg.ifindex_if4) {
      struct value_t *val = bpf_map_lookup_elem(&threshold_map, &ip->saddr);
      if (!val) {
         bpf_printk("No threshold set for IP %d", ip->saddr);
         bpf_printk("Dropping packet");
         goto drop;
      }

      bpf_printk("Current # of packets received for IP %d: %d. Threshold is: %d", ip->saddr, val->packets_rcvd, val->threshold);
      __sync_fetch_and_add(&val->packets_rcvd, 1);
      if (val->packets_rcvd > val->threshold) {
         bpf_printk("Threshold exceeded for IP %d", ip->saddr);
         bpf_printk("Dropping packet");
         goto drop;
      }

      /* Forward packet to interface 4 */
      return bpf_redirect(hhdv1_cfg.ifindex_if4, 0);
   } else {
      bpf_printk("Packet received from interface %d", ctx->ingress_ifindex);

      // Check if IP is in map
      __u32 *port = bpf_map_lookup_elem(&ip_to_port, &ip->daddr);

      if (!port) {
         bpf_printk("IP %d not found in map", ip->daddr);
         goto drop;
      }

      bpf_printk("IP %d found in map. Forwarding packet to port %d", ip->daddr, *port);

      switch (*port) {
         case 1:
            return bpf_redirect(hhdv1_cfg.ifindex_if1, 0);
         case 2:
            return bpf_redirect(hhdv1_cfg.ifindex_if2, 0);
         case 3:
            return bpf_redirect(hhdv1_cfg.ifindex_if3, 0);
         default:
            bpf_printk("Port %d not found", *port);
            goto drop;
      }
      
      goto drop;
   }

drop:
   return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";