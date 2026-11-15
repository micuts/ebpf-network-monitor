#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 1. Map đếm số gói SYN theo từng IP nguồn
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} syn_by_ip SEC(".maps");

// 2. Map danh sách IP bị chặn (value = thời điểm hết hạn hoặc cờ 1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} blocklist SEC(".maps");

// 3. Map danh sách IP được bảo vệ (không bao giờ bị chặn nhầm)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} whitelist SEC(".maps");

// 4. Map đếm tổng số gói tin đã bị XDP_DROP (PERCPU để đạt hiệu năng cao)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

SEC("xdp")
int xdp_syn_blocker(struct xdp_md *ctx)
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

    if (ip->ihl < 5)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Ưu tiên 1: Nếu thuộc whitelist -> cho qua ngay lập tức
    if (bpf_map_lookup_elem(&whitelist, &src_ip))
        return XDP_PASS;

    // Ưu tiên 2: Nếu nằm trong blocklist -> DROP ngay lập tức (chặn cả ICMP lẫn TCP)
    if (bpf_map_lookup_elem(&blocklist, &src_ip)) {
        __u32 zero = 0;
        __u64 *drops = bpf_map_lookup_elem(&drop_count, &zero);
        if (drops)
            (*drops)++;
        return XDP_DROP;
    }

    // Ưu tiên 3: Theo dõi gói TCP SYN ban đầu (SYN=1, ACK=0)
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
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
