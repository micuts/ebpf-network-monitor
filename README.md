# eBPF/XDP Network Monitoring & SYN Flood Defense

Hệ thống giám sát lưu lượng mạng và phòng thủ tấn công TCP SYN Flood hiệu năng cao chạy ở chế độ **Native XDP** trên nhân Linux (driver `vmxnet3`), kết hợp chương trình điều khiển User-space viết bằng C (`libbpf`) và trực quan hóa thời gian thực qua **InfluxDB v2 + Grafana**.

## Cấu trúc thư mục
- `bpf/`: Mã nguồn Kernel-space eBPF/XDP (`xdp_syn_blocker.c`, ...).
- `src/`: Mã nguồn User-space daemon điều khiển (`syn_defender.c`, ...).
- `scripts/`: Các kịch bản tự động hóa đẩy dữ liệu telemetry (`push_influx.sh`, `push_benchmarks_grafana.sh`).
