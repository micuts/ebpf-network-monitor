#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_TRACKED_IPS   10000
#define SYN_THRESHOLD_PPS 50   // Ngưỡng phát hiện: > 50 SYN/giây sẽ bị chặn
#define BAN_DURATION_SEC  20   // Thời gian phạt chặn: 20 giây
#define METRICS_TMP_PATH  "/dev/shm/ebpf_metrics.tmp"
#define METRICS_OUT_PATH  "/dev/shm/ebpf_metrics.lp"

struct ip_stat {
    __u32 ip;
    __u64 count;
};

struct ban_entry {
    __u32 ip;
    time_t expire_time;
};

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int find_map_fd_by_name(const char *target_name) {
    __u32 id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            if (strcmp(info.name, target_name) == 0) {
                return fd;
            }
        }
        close(fd);
    }
    return -1;
}

static __u64 get_prev_count(struct ip_stat *prev_list, int prev_len, __u32 ip) {
    for (int i = 0; i < prev_len; i++) {
        if (prev_list[i].ip == ip) {
            return prev_list[i].count;
        }
    }
    return 0;
}

static __u64 get_total_drops(int drop_fd, int num_cpus, __u64 *cpu_vals) {
    __u32 zero = 0;
    if (bpf_map_lookup_elem(drop_fd, &zero, cpu_vals) != 0)
        return 0;
    __u64 total = 0;
    for (int i = 0; i < num_cpus; i++) {
        total += cpu_vals[i];
    }
    return total;
}

static bool is_ip_banned(struct ban_entry *bans, int ban_len, __u32 ip) {
    for (int i = 0; i < ban_len; i++) {
        if (bans[i].ip == ip) return true;
    }
    return false;
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int syn_fd   = find_map_fd_by_name("syn_by_ip");
    int block_fd = find_map_fd_by_name("blocklist");
    int white_fd = find_map_fd_by_name("whitelist");
    int drop_fd  = find_map_fd_by_name("drop_count");

    if (syn_fd < 0 || block_fd < 0 || white_fd < 0 || drop_fd < 0) {
        fprintf(stderr, "Thieu BPF map can thiet! Hay kiem tra xdp_syn_blocker da attach chua.\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        struct in_addr wl_addr;
        if (inet_pton(AF_INET, argv[i], &wl_addr) == 1) {
            __u8 flag = 1;
            bpf_map_update_elem(white_fd, &wl_addr.s_addr, &flag, BPF_ANY);
            printf("[WHITELIST] Da them IP bao ve: %s\n", argv[i]);
        }
    }

    int num_cpus = libbpf_num_possible_cpus();
    __u64 *drop_cpu_vals = calloc(num_cpus, sizeof(__u64));
    struct ip_stat *prev_stats = calloc(MAX_TRACKED_IPS, sizeof(struct ip_stat));
    struct ip_stat *curr_stats = calloc(MAX_TRACKED_IPS, sizeof(struct ip_stat));
    struct ban_entry *bans     = calloc(MAX_TRACKED_IPS, sizeof(struct ban_entry));

    int prev_len = 0;
    int ban_len = 0;
    __u64 prev_total_dropped = get_total_drops(drop_fd, num_cpus, drop_cpu_vals);

    printf("=== SYN DEFENDER + INFLUX METRICS (Nguong: %d SYN/s | Chan: %ds) ===\n",
           SYN_THRESHOLD_PPS, BAN_DURATION_SEC);

    while (!exiting) {
        time_t now = time(NULL);

        // 1. Gỡ chặn các IP đã hết hạn phạt
        for (int i = 0; i < ban_len; ) {
            if (now >= bans[i].expire_time) {
                char ip_str[INET_ADDRSTRLEN];
                struct in_addr addr = { .s_addr = bans[i].ip };
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

                bpf_map_delete_elem(block_fd, &bans[i].ip);
                printf("\n[UNBAN] Het han phat %ds -> Da go chan IP: %s\n", BAN_DURATION_SEC, ip_str);

                bans[i] = bans[ban_len - 1];
                ban_len--;
            } else {
                i++;
            }
        }

        // 2. Đọc bảng syn_by_ip
        __u32 key = 0, next_key = 0;
        __u32 *cur_key_ptr = NULL;
        int curr_len = 0;

        while (bpf_map_get_next_key(syn_fd, cur_key_ptr, &next_key) == 0) {
            __u64 val = 0;
            if (bpf_map_lookup_elem(syn_fd, &next_key, &val) == 0 && curr_len < MAX_TRACKED_IPS) {
                curr_stats[curr_len].ip = next_key;
                curr_stats[curr_len].count = val;
                curr_len++;
            }
            key = next_key;
            cur_key_ptr = &key;
        }

        __u64 total_dropped = get_total_drops(drop_fd, num_cpus, drop_cpu_vals);
        __u64 drop_pps = (total_dropped >= prev_total_dropped) ? (total_dropped - prev_total_dropped) : 0;
        prev_total_dropped = total_dropped;

        FILE *fp = fopen(METRICS_TMP_PATH, "w");
        if (fp) {
            fprintf(fp, "xdp_global tracked_ips=%di,banned_ips=%di,total_drops=%llui,drop_pps=%llui\n",
                    curr_len, ban_len, (unsigned long long)total_dropped, (unsigned long long)drop_pps);
        }

        printf("\n[Status] IP theo doi: %d | Dang chan: %d | Tong XDP_DROP: %llu (%llu pkt/s)\n",
               curr_len, ban_len, (unsigned long long)total_dropped, (unsigned long long)drop_pps);

        for (int i = 0; i < curr_len; i++) {
            __u32 ip = curr_stats[i].ip;
            __u64 prev_val = get_prev_count(prev_stats, prev_len, ip);
            __u64 rate = (curr_stats[i].count >= prev_val) ? (curr_stats[i].count - prev_val) : 0;

            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr = { .s_addr = ip };
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

            if (rate > 0) {
                printf("  -> %-16s | Tong SYN: %-8llu | Toc do: %llu SYN/s\n",
                       ip_str, (unsigned long long)curr_stats[i].count, (unsigned long long)rate);
            }

            if (rate > SYN_THRESHOLD_PPS) {
                bool already_banned = false;
                for (int b = 0; b < ban_len; b++) {
                    if (bans[b].ip == ip) {
                        bans[b].expire_time = now + BAN_DURATION_SEC;
                        already_banned = true;
                        break;
                    }
                }
                if (!already_banned && ban_len < MAX_TRACKED_IPS) {
                    __u64 ban_val = 1;
                    bpf_map_update_elem(block_fd, &ip, &ban_val, BPF_ANY);
                    bans[ban_len].ip = ip;
                    bans[ban_len].expire_time = now + BAN_DURATION_SEC;
                    ban_len++;
                    printf("  [ALERT -> BLOCK] IP %s vuot nguong (%llu > %d SYN/s)! Da chan trong %ds.\n",
                           ip_str, (unsigned long long)rate, SYN_THRESHOLD_PPS, BAN_DURATION_SEC);
                }
            }

            if (fp) {
                int banned_flag = is_ip_banned(bans, ban_len, ip) ? 1 : 0;
                fprintf(fp, "xdp_ip_stats,src_ip=%s total_syn=%llui,syn_pps=%llui,is_banned=%di\n",
                        ip_str, (unsigned long long)curr_stats[i].count, (unsigned long long)rate, banned_flag);
            }
        }

        if (fp) {
            fclose(fp);
            rename(METRICS_TMP_PATH, METRICS_OUT_PATH);
        }

        fflush(stdout);
        memcpy(prev_stats, curr_stats, curr_len * sizeof(struct ip_stat));
        prev_len = curr_len;
        sleep(1);
    }

    free(drop_cpu_vals);
    free(prev_stats);
    free(curr_stats);
    free(bans);
    close(syn_fd);
    close(block_fd);
    close(white_fd);
    close(drop_fd);
    return 0;
}
