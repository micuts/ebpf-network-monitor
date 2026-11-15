#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include<linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syn_count SEC(".maps");

SEC("xdp")
int xdp_syn_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Kiểm tra Ethernet header
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Chỉ xử lý IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // 2. Kiểm tra IPv4 header
    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Tính vị trí TCP header theo độ dài IPv4 header
    struct tcphdr *tcp =
        (void *)ip + (ip->ihl * 4);

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // 3. Chỉ đếm SYN ban đầu: SYN=1, ACK=0
    if (tcp->syn && !tcp->ack) {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&syn_count, &key);

        if (count)
            (*count)++;
    }

    // 4. Không chặn packet
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
