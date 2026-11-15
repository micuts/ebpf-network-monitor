#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_TRACKED_IPS 10000

struct ip_stat {
    __u32 ip;
    __u64 count;
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

int main(void) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int map_fd = find_map_fd_by_name("syn_by_ip");
    if (map_fd < 0) {
        fprintf(stderr, "Khong tim thay map 'syn_by_ip'. Hay kiem tra xdp_syn_by_ip da attach chua!\n");
        return 1;
    }

    struct ip_stat *prev_stats = calloc(MAX_TRACKED_IPS, sizeof(struct ip_stat));
    struct ip_stat *curr_stats = calloc(MAX_TRACKED_IPS, sizeof(struct ip_stat));
    if (!prev_stats || !curr_stats) {
        fprintf(stderr, "Loi cap phat bo nho\n");
        close(map_fd);
        return 1;
    }

    int prev_len = 0;
    printf("Dang theo doi TCP SYN theo tung dia chi IP nguon (map 'syn_by_ip'). Nhan Ctrl+C de dung...\n");

    while (!exiting) {
        __u32 key = 0, next_key = 0;
        __u32 *cur_key_ptr = NULL;
        int curr_len = 0;

        while (bpf_map_get_next_key(map_fd, cur_key_ptr, &next_key) == 0) {
            __u64 val = 0;
            if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0 && curr_len < MAX_TRACKED_IPS) {
                curr_stats[curr_len].ip = next_key;
                curr_stats[curr_len].count = val;
                curr_len++;
            }
            key = next_key;
            cur_key_ptr = &key;
        }

        printf("\n--- Thong ke theo IP nguon (So IP ghi nhan: %d) ---\n", curr_len);
        if (curr_len == 0) {
            printf("Chua co goi tin TCP SYN nao...\n");
        } else {
            printf("%-18s | %-15s | %-15s\n", "IP Nguon", "Tong SYN", "Toc do (SYN/s)");
            printf("------------------------------------------------------\n");
            for (int i = 0; i < curr_len; i++) {
                char ip_str[INET_ADDRSTRLEN];
                struct in_addr addr = { .s_addr = curr_stats[i].ip };
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

                __u64 prev_val = get_prev_count(prev_stats, prev_len, curr_stats[i].ip);
                __u64 rate = (curr_stats[i].count >= prev_val) ? (curr_stats[i].count - prev_val) : 0;

                printf("%-18s | %-15llu | %-15llu\n",
                       ip_str,
                       (unsigned long long)curr_stats[i].count,
                       (unsigned long long)rate);
            }
        }
        fflush(stdout);

        memcpy(prev_stats, curr_stats, curr_len * sizeof(struct ip_stat));
        prev_len = curr_len;
        sleep(1);
    }

    free(prev_stats);
    free(curr_stats);
    close(map_fd);
    printf("\nDa dung ip_reader.\n");
    return 0;
}
