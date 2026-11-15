#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// Tìm BPF Map FD theo tên map đang hoạt động trong kernel
int find_map_fd_by_name(const char *target_name) {
    __u32 id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            if (strcmp(info.name, target_name) == 0) {
                return fd; // Trả về file descriptor của map tìm thấy
            }
        }
        close(fd);
    }
    return -1;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        fprintf(stderr, "Loi lay so luong CPU: %d\n", num_cpus);
        return 1;
    }

    int map_fd = find_map_fd_by_name("syn_count");
    if (map_fd < 0) {
        fprintf(stderr, "Khong tim thay map 'syn_count'. Hay kiem tra chuong trinh XDP da attach chua!\n");
        return 1;
    }

    __u64 *values = calloc(num_cpus, sizeof(__u64));
    if (!values) {
        fprintf(stderr, "Loi cap phat bo nho\n");
        close(map_fd);
        return 1;
    }

    __u32 key = 0;
    __u64 prev_total = 0;

    printf("Dang theo doi map 'syn_count' (%d possible CPUs). Nhan Ctrl+C de dung...\n\n", num_cpus);

    while (!exiting) {
        if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
            perror("Loi doc BPF map");
            break;
        }

        __u64 current_total = 0;
        for (int i = 0; i < num_cpus; i++) {
            current_total += values[i];
        }

        __u64 syn_per_sec = (prev_total == 0) ? 0 : (current_total - prev_total);
        printf("Tong TCP SYN: %-10llu | Toc do: %llu SYN/giay\n", current_total, syn_per_sec);

        prev_total = current_total;
        sleep(1);
    }

    free(values);
    close(map_fd);
    printf("\nDa dung theo doi.\n");
    return 0;
}
