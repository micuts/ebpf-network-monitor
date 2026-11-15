#!/bin/bash
INFLUX_URL="http://localhost:8086/api/v2/write?org=UIT&bucket=eBPF_Monitor&precision=s"
INFLUX_TOKEN="ncKKyuI7tg9uRP09w82PZcNMmVzIqguXqyG_aLP7wK46jMGqfRhEqxrfYDaWxwZOzNcKAlxg05a21u4uUCoh1w=="
METRICS_FILE="/dev/shm/ebpf_metrics.lp"

echo "Dang day metrics eBPF len InfluxDB (Org: UIT | Bucket: eBPF_Monitor)..."
while true; do
    if [ -f "$METRICS_FILE" ]; then
        curl -s -X POST "$INFLUX_URL" \
            --header "Authorization: Token $INFLUX_TOKEN" \
            --header "Content-Type: text/plain; charset=utf-8" \
            --data-binary @"$METRICS_FILE" > /dev/null
    fi
    sleep 1
done
