#!/bin/bash
# finetest.sh — fine-grained throughput sweep. Pulls at many closely-spaced
# target rates to characterize the gradient of trandomd's adaptive pacing.
set -u
cd "$(dirname "$0")"

SOCK=/tmp/trandom-finetest.sock
DURATION=${DURATION:-4}
export TRANDOM_SOCK=$SOCK
export LD_LIBRARY_PATH=$PWD

SOURCES=${1:-"tsc-phc,jitter,dram,irq-stat"}

# Dense geometric + linear sweep from 1 KB/s to 15 MB/s
RATES=(
    1024 2048 4096 8192 16384 32768
    65536 100000 150000 250000 400000
    600000 800000 1000000 1250000 1500000 1750000 2000000
    2500000 3000000 3500000 4000000 5000000 6000000 7000000
    8000000 9000000 10000000 11000000 12000000 13000000 14000000 15000000
)

printf "sources: %s  duration: %ds\n" "$SOURCES" "$DURATION"
printf "%11s  %11s  %9s  %6s  %7s\n" "request_bps" "bytes/${DURATION}s" "MB/s" "cpu%" "ratio"
printf "%11s  %11s  %9s  %6s  %7s\n" "-----------" "--------" "----" "----" "-----"

for req in "${RATES[@]}"; do
    rm -f "$SOCK"
    ./trandomd --sources="$SOURCES" --max-cpu=500 --sock="$SOCK" >/dev/null 2>&1 &
    DPID=$!
    sleep 0.4

    rm -f /tmp/ent.bin
    timeout "$DURATION" ./trctl "$req" >/tmp/ent.bin 2>/dev/null
    bytes=$(stat -c %s /tmp/ent.bin 2>/dev/null || echo 0)
    mbps=$(awk "BEGIN { printf \"%.3f\", $bytes / 1048576 / $DURATION }")
    ratio=$(awk "BEGIN { printf \"%.2f\", $bytes / $DURATION / $req }")
    cpu=$(ps -o pcpu= -p "$DPID" 2>/dev/null | tr -d ' ')
    [ -z "$cpu" ] && cpu="?"

    printf "%11d  %11d  %9s  %6s  %7s\n" "$req" "$bytes" "$mbps" "$cpu" "$ratio"

    kill -TERM "$DPID" 2>/dev/null || true
    for _ in 1 2 3; do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
done
rm -f "$SOCK" /tmp/ent.bin
