# eBPF/XDP Network Monitor & TCP SYN Flood Mitigation

Hệ thống giám sát lưu lượng mạng và phòng chống tấn công từ chối dịch vụ **TCP SYN Flood** hiệu năng cao dựa trên công nghệ **eBPF / XDP (eXpress Data Path)** trên nhân Linux. Hệ thống cho phép lọc và loại bỏ gói tin độc hại (`XDP_DROP`) ngay tại tầng driver/card mạng trước khi gói tin đi sâu vào tầng mạng của hệ điều hành (Network Stack), giúp tiết kiệm tối đa tài nguyên CPU và duy trì kết nối ổn định cho người dùng hợp lệ.

---

## 1. Kiến trúc hệ thống & Mô hình thực nghiệm

### 1.1. Kiến trúc 2 tầng (Kernel Space & User Space)
* **Kernel Space (`bpf/`):** Các chương trình XDP viết bằng ngôn ngữ C bị giới hạn (Restricted C), biên dịch sang bytecode eBPF bằng `clang` và gắn trực tiếp vào giao diện mạng `ens160`. Giao tiếp dữ liệu tốc độ cao thông qua các cấu trúc **BPF Maps**.
* **User Space (`src/`):** Các chương trình điều khiển và giám sát viết bằng C sử dụng thư viện `libbpf`. Đọc thống kê theo thời gian thực mỗi giây, tính toán tốc độ gói tin (`SYN/s`), phát hiện bất thường vượt ngưỡng và cập nhật danh sách chặn (`blocklist`) xuống Kernel.

### 1.2. Mô hình mạng thử nghiệm 3 máy (Bridged LAN)
Tất cả các máy tham gia thực nghiệm được cấu hình ở chế độ **Bridged Network** để nằm ngang hàng trên cùng một lớp mạng nội bộ LAN (`192.168.1.0/24`), đảm bảo ghi nhận đúng địa chỉ IP nguồn thực tế của từng máy:

| Vai trò | Hệ điều hành / Nền tảng | Card mạng | Địa chỉ IP | Chức năng trong kịch bản |
| :--- | :--- | :--- | :--- | :--- |
| **Victim / Defender** | Ubuntu Server 24.04 (`victim1`) | `ens160` | `192.168.1.x` | Máy chủ mục tiêu chạy web service & gắn bộ lọc XDP/eBPF |
| **Legitimate Client** | Windows 11 (Host vật lý) | Wi-Fi / LAN | `192.168.1.14` | Người dùng hợp lệ gửi truy cập HTTP/TCP bình thường |
| **Attacker** | Kali Linux (VM trên máy vật lý 2) | `eth0` | `192.168.1.17` | Máy tấn công sử dụng `hping3` phát lưu lượng TCP SYN Flood |

---

## 2. Cấu trúc thư mục & Chi tiết mã nguồn (Source Code)

```text
ebpf-network-monitor/
├── bpf/                        # Mã nguồn Kernel Space (XDP Programs)
│   ├── xdp_pass.c              # Chương trình XDP tối giản kiểm thử luồng nhận gói tin
│   ├── xdp_syn_counter.c       # Bộ đếm tổng gói tin TCP SYN toàn cục (PERCPU_ARRAY)
│   ├── xdp_syn_by_ip.c         # Bộ đếm gói tin TCP SYN tách biệt theo từng IP nguồn (LRU_HASH)
│   └── xdp_syn_blocker.c       # Bộ lọc bảo vệ: Whitelist, Blocklist (XDP_DROP) & đếm SYN theo IP
├── src/                        # Mã nguồn User Space (Control Plane & Readers)
│   ├── map_reader.c            # Đọc tổng SYN và tính tốc độ SYN/giây toàn cục
│   ├── ip_reader.c             # Đọc và hiển thị bảng thống kê SYN/giây theo từng IP nguồn
│   └── syn_defender.c          # Bộ điều khiển phát hiện vượt ngưỡng, tự động chặn & gỡ chặn IP
└── README.md                   # Tài liệu kỹ thuật và nhật ký tiến độ dự án
```

### 2.1. Chi tiết các file trong Kernel Space (`bpf/`)

1. **`bpf/xdp_pass.c`**
   * **Mục đích:** Kiểm thử khả năng biên dịch bytecode eBPF, nạp (attach) và gỡ (detach) chương trình XDP trên card mạng `ens160`.
   * **Chức năng:** Chấp nhận mọi gói tin đi vào và trả về `XDP_PASS` để chuyển tiếp lên tầng mạng bình thường của Linux.
   * 
   victim1@victim:~$ cat ~/ebpf-network-monitor/bpf/xdp_pass.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

2. **`bpf/xdp_syn_counter.c`**
   * **Mục đích:** Xây dựng nền tảng phân tích header gói tin (Ethernet $\rightarrow$ IPv4 $\rightarrow$ TCP) và đếm lưu lượng TCP SYN tổng.
   * **Chức năng:** Kiểm tra cờ TCP (`tcp->syn == 1` và `tcp->ack == 0`). Nếu khớp, tăng bộ đếm trong map `syn_count` kiểu `BPF_MAP_TYPE_PERCPU_ARRAY` (mỗi nhân CPU ghi trên vùng nhớ riêng để tránh xung đột khóa lock).
   victim1@victim:~$ cat ~/ebpf-network-monitor/bpf/xdp_syn_counter.c
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


3. **`bpf/xdp_syn_by_ip.c`**
   * **Mục đích:** Phân tách lưu lượng theo từng nguồn gửi để nhận diện chính xác địa chỉ IP nào đang tạo lưu lượng bất thường.
   * **Chức năng:** Trích xuất trường IP nguồn (`ip->saddr`), tra cứu và cập nhật số lượng gói SYN vào map `syn_by_ip` kiểu `BPF_MAP_TYPE_LRU_HASH` (tối đa 10.000 IP, tự động giải phóng IP cũ ít hoạt động nhất khi bảng đầy).
   tim1@victim:~$ cat ~/ebpf-network-monitor/bpf/xdp_syn_by_ip.c
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

4. **`bpf/xdp_syn_blocker.c`**
   * **Mục đích:** Thực thi cơ chế ngăn chặn tấn công TCP SYN Flood trực tiếp tại tầng XDP với độ trễ cực thấp (phục vụ **Kịch bản 3**).
   * **Chức năng:** Sử dụng 4 BPF Maps phối hợp theo thứ tự ưu tiên:
     * `whitelist` (`HASH`): Cho phép IP tin cậy đi qua ngay lập tức (`XDP_PASS`), chống chặn nhầm quản trị viên.
     * `blocklist` (`HASH`): Nếu IP nguồn có mặt trong danh sách đen, tăng bộ đếm `drop_count` (`PERCPU_ARRAY`) và hủy gói tin ngay lập tức bằng **`XDP_DROP`** (chặn cả TCP lẫn ICMP ping từ kẻ tấn công).
     * `syn_by_ip` (`LRU_HASH`): Tiếp tục thống kê gói TCP SYN cho các IP chưa bị chặn để User Space giám sát.
     victim1@victim:~$ cat ~/ebpf-network-monitor/bpf/xdp_syn_by_ip.c
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

### 2.2. Chi tiết các file trong User Space (`src/`)

1. **`src/map_reader.c`**
   * **Mục đích:** Kiểm chứng khả năng đọc dữ liệu đa nhân (Per-CPU) từ Kernel lên User Space.
   * **Chức năng:** Tìm map `syn_count` bằng `libbpf`, cộng dồn giá trị trên toàn bộ số nhân CPU khả dụng (128 possible CPUs) mỗi giây và tính toán tốc độ `SYN/giây`.
   ictim1@victim:~$ cat ~/ebpf-network-monitor/bpf/xdp_syn_blocker.c
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

2. **`src/ip_reader.c`**
   * **Mục đích:** Giám sát trực quan lưu lượng SYN theo từng địa chỉ IP theo thời gian thực.
   * **Chức năng:** Duyệt toàn bộ danh sách khóa (`bpf_map_get_next_key`) trong `syn_by_ip`, chuyển đổi IP từ dạng nhị phân sang chuỗi IPv4 (`inet_ntop`), và in bảng thống kê gồm: `IP Nguồn`, `Tổng SYN`, và `Tốc độ (SYN/s)`.

3. **`src/syn_defender.c`**
   * **Mục đích:** Đóng vai trò bộ não tự động hóa (Control Plane) cho cơ chế phát hiện và giảm thiểu tấn công.
   * **Chức năng:**
     * Nạp danh sách IP bảo vệ vào `whitelist` qua tham số dòng lệnh.
     * Giám sát tốc độ `SYN/s` của từng IP mỗi giây; nếu vượt ngưỡng cảnh báo (**`> 50 SYN/s`**), tự động ghi IP đó vào `blocklist` trong Kernel.
     * Quản lý bộ đếm thời gian phạt (**`20 giây`**); tự động xóa IP khỏi `blocklist` (`bpf_map_delete_elem`) khi hết hạn để khôi phục kết nối.

---

## 3. Hướng dẫn biên dịch và vận hành

### 3.1. Biên dịch mã nguồn
```bash
# Biên dịch Kernel Space (eBPF bytecode)
clang -O2 -g -target bpf -c ~/ebpf-network-monitor/bpf/xdp_syn_blocker.c -o ~/ebpf-network-monitor/bpf/xdp_syn_blocker.o

# Biên dịch User Space (libbpf)
gcc -O2 -Wall ~/ebpf-network-monitor/src/syn_defender.c -o ~/ebpf-network-monitor/src/syn_defender -lbpf -lelf -lz
```

### 3.2. Gắn chương trình XDP và chạy bộ phòng thủ trên `victim1`
```bash
# Gỡ chương trình XDP cũ (nếu có) và nạp xdp_syn_blocker lên ens160
sudo ip link set dev ens160 xdpgeneric off 2>/dev/null || true
sudo ip link set dev ens160 xdpgeneric obj ~/ebpf-network-monitor/bpf/xdp_syn_blocker.o sec xdp

# Kiểm tra trạng thái attach và các BPF Maps
sudo ip -details link show ens160 | grep prog/xdp
sudo bpftool map show | grep -E "syn_by_ip|blocklist|whitelist|drop_count"

# Chạy syn_defender (có thể truyền kèm IP whitelist ở phía sau)
sudo ~/ebpf-network-monitor/src/syn_defender 192.168.1.14
```

### 3.3. Lệnh kiểm thử tấn công từ Kali Linux (Root Terminal)
```bash
# Tab 1: Theo dõi kết nối liên tục tới victim1
ping <IP_VICTIM1>

# Tab 2: Bắn TCP SYN Flood tốc độ 200 gói/giây (vượt ngưỡng 50 SYN/s)
hping3 -S -p 80 -i u5000 <IP_VICTIM1>
```

---

## 4. Tiến độ triển khai & Kết quả kiểm chứng

### Các hạng mục đã hoàn thành
- [x] **Giai đoạn 1 (Cơ sở hạ tầng & XDP cơ bản):** Cài đặt môi trường eBPF/libbpf trên Ubuntu 24.04, xây dựng và kiểm thử thành công `xdp_pass.c`.
- [x] **Giai đoạn 2 (Đếm lưu lượng tổng):** Hoàn thiện `xdp_syn_counter.c` và `map_reader.c`, xác minh cộng dồn chính xác số gói SYN trên 128 possible CPUs và tính tốc độ theo giây.
- [x] **Giai đoạn 3 (Phân tách theo IP nguồn):** Hoàn thiện `xdp_syn_by_ip.c` và `ip_reader.c` sử dụng `LRU_HASH`. Chuyển đổi mô hình mạng 3 máy sang **Bridged LAN**, phân tách thành công lưu lượng từ Windows (`192.168.1.14`) và Kali Linux (`192.168.1.17`).
- [x] **Giai đoạn 4 (Hoàn thiện code Kịch bản 3 - Phát hiện & Chặn IP):** Xây dựng hoàn chỉnh `xdp_syn_blocker.c` và `syn_defender.c` hỗ trợ `whitelist`, phát hiện ngưỡng `50 SYN/s`, tự động chặn bằng `XDP_DROP` và tự động gỡ chặn sau `20 giây`.

### Kế hoạch thực nghiệm tiếp theo (Benchmark & Đánh giá)
- [ ] **Kịch bản 3 (Nghiệm thu log thực tế):** Chạy kiểm thử đồng thời 3 máy (Windows truy cập HTTP, Kali bắn `hping3` và `ping`), ghi nhận thời điểm kích hoạt `[ALERT -> BLOCK]`, số gói `XDP_DROP` và thời điểm tự động `[UNBAN]`.
![alt text](<kịch bản 3-1.png>)

- [ ] **Kịch bản 1 (Hiệu năng bình thường):** Đo mức tiêu thụ CPU, độ trễ HTTP và thông lượng ở 3 chế độ: *Baseline* vs. *iptables* vs. *XDP*.
![alt text](<kịch bản 2-2.png>)
- [ ] **Kịch bản 2 (Giảm thiểu SYN Flood):** So sánh khả năng chịu tải và tỷ lệ phục vụ client hợp lệ khi hứng chịu SYN Flood cường độ cao (`--flood`).

![alt text](<kịch bản 2-1.png>)
- [ ] **Kịch bản 4 (Chặn nhầm & Độ bền):** Chạy tải HTTP hợp lệ cường độ cao song song với lưu lượng tấn công trong thời gian dài để kiểm tra tỷ lệ *False Positive* và độ ổn định bộ nhớ của `LRU_HASH`.
![alt text](<kịch bản 4-1.png>)
![alt text](<kịch bản 4.1-1.png>)
![alt text](<kịch bản 4.2-1.png>)
![alt text](<kịch bản 4.3-1.png>)
![alt text](<kịch bản 4.4-1.png>)
