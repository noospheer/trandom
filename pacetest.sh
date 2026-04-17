#!/bin/bash
# pacetest.sh — verify CPU scales with requested throughput.
# For a fixed source set, request increasing rates; measure achieved MB/s and CPU%.
set -u
cd "$(dirname "$0")"

SOCK=/tmp/trandom-pacetest.sock
DURATION=3
export TRANDOM_SOCK=$SOCK
export LD_LIBRARY_PATH=$PWD

SOURCES=${1:-"tsc-phc,jitter,dram,irq-stat"}

printf "sources: %s\n" "$SOURCES"
printf "%12s  %10s  %8s  %10s  %6s\n" "request B/s" "bytes/${DURATION}s" "MB/s" "MB/s asked" "cpu%"
printf "%12s  %10s  %8s  %10s  %6s\n" "-----------" "--------" "----" "----------" "----"

# Rates: 1 KB/s, 10 KB/s, 100 KB/s, 500 KB/s, 1 MB/s, 2 MB/s, 5 MB/s, 10 MB/s, 20 MB/s, 50 MB/s
for req in 1024 10240 102400 512000 1048576 2097152 5242880 10485760 20971520 52428800; do
    rm -f "$SOCK"
    ./trandomd --sources="$SOURCES" --max-cpu=500 --sock="$SOCK" >/dev/null 2>&1 &
    DPID=$!
    sleep 0.5

    rm -f /tmp/ent.bin
    timeout "$DURATION" ./trctl "$req" >/tmp/ent.bin 2>/dev/null
    bytes=$(stat -c %s /tmp/ent.bin 2>/dev/null || echo 0)
    mbps=$(awk "BEGIN { printf \"%.3f\", $bytes / 1048576 / $DURATION }")
    asked_mb=$(awk "BEGIN { printf \"%.3f\", $req / 1048576 }")
    cpu=$(ps -o pcpu= -p "$DPID" 2>/dev/null | tr -d ' ')
    [ -z "$cpu" ] && cpu="?"

    printf "%12d  %10d  %8s  %10s  %6s\n" "$req" "$bytes" "$mbps" "$asked_mb" "$cpu"

    kill -TERM "$DPID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
done
rm -f "$SOCK" /tmp/ent.bin
