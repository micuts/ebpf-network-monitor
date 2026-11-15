#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // IPv4 nguồn (network byte order)
    __type(value, __u64); // Tổng số gói SYN của IP này
} syn_by_ip SEC(".maps");

SEC("xdp")
int xdp_syn_by_ip(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
        __u32 src_ip = ip->saddr;
        __u64 *count = bpf_map_lookup_elem(&syn_by_ip, &src_ip);

        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 init_val = 1;
            bpf_map_update_elem(&syn_by_ip, &src_ip, &init_val, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
