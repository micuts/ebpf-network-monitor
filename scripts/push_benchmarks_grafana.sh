#!/bin/bash
INFLUX_URL="http://localhost:8086/api/v2/write?org=UIT&bucket=eBPF_Monitor&precision=s"
INFLUX_TOKEN="ncKKyuI7tg9uRP09w82PZcNMmVzIqguXqyG_aLP7wK46jMGqfRhEqxrfYDaWxwZOzNcKAlxg05a21u4uUCoh1w=="
BASE="$HOME/ebpf-network-monitor/results"
NOW=$(date +%s)

send_lp() {
    curl -s -o /dev/null -w "HTTP %{http_code}: $1\n" -X POST "$INFLUX_URL" \
        --header "Authorization: Token $INFLUX_TOKEN" \
        --header "Content-Type: text/plain; charset=utf-8" \
        --data-binary "$1"
}

# 1. Đẩy Kịch bản 1 (CPU %)
for item in "1_Baseline:cpu_baseline.txt" "2_iptables:cpu_iptables.txt" "3_eBPF_XDP:cpu_xdp.txt"; do
    mode="${item%%:*}"; f="$BASE/kb1/${item##*:}"
    if [ -f "$f" ]; then
        read usr sys soft <<< $(grep "^Average:" "$f" | awk '{print $3, $5, $8}')
        total=$(awk "BEGIN {printf \"%.2f\", $usr + $sys + $soft}")
        send_lp "kb1_cpu,mode=${mode} usr=${usr},sys=${sys},soft=${soft},total=${total} ${NOW}"
    else
        echo "[SKIP] Khong tim thay file: $f"
    fi
done

# 2. Đẩy Kịch bản 2 (HTTP Requests/sec từ wrk)
for item in "1_Normal:wrk_normal.txt" "2_Attack_No_XDP:wrk_attack_no_xdp.txt" "3_Attack_With_XDP:wrk_attack_with_xdp.txt"; do
    case_name="${item%%:*}"; f="$BASE/kb2/${item##*:}"
    if [ -f "$f" ]; then
        rps=$(grep "Requests/sec:" "$f" | awk '{print $2}')
        [ -z "$rps" ] && rps="0.0"
        send_lp "kb2_http,scenario=${case_name} requests_per_sec=${rps} ${NOW}"
    fi
done
