#!/bin/bash
# chartest.sh — characterize all 15 non-empty source combinations.
# Each combo: start daemon, pull for 3s wall time, record throughput/CPU/quality.
set -u
cd "$(dirname "$0")"

SOURCES=(tsc-phc jitter dram irq-stat)
SOCK=/tmp/trandom-chartest.sock
DURATION=3
export TRANDOM_SOCK=$SOCK
export LD_LIBRARY_PATH=$PWD

printf "%-28s  %10s  %9s  %7s  %7s  %7s\n" \
    "sources" "bytes/${DURATION}s" "MB/s" "cpu%" "chi2" "gzip"
printf "%-28s  %10s  %9s  %7s  %7s  %7s\n" \
    "-------" "-------" "----" "----" "----" "----"

for mask in $(seq 1 15); do
    combo=()
    for i in 0 1 2 3; do
        if (( (mask >> i) & 1 )); then combo+=("${SOURCES[$i]}"); fi
    done
    IFS=, ; combo_str="${combo[*]}" ; IFS=' '

    rm -f "$SOCK"
    ./trandomd --sources="$combo_str" --max-cpu=50 --sock="$SOCK" >/dev/null 2>&1 &
    DPID=$!
    sleep 0.4

    # pull for DURATION seconds as fast as daemon delivers (1 GB/s target = effectively unlimited)
    rm -f /tmp/ent.bin
    timeout "$DURATION" ./trctl 1000000000 >/tmp/ent.bin 2>/dev/null
    bytes=$(stat -c %s /tmp/ent.bin 2>/dev/null || echo 0)
    mbps=$(awk "BEGIN { printf \"%.2f\", $bytes / 1048576 / $DURATION }")

    cpu=$(ps -o pcpu= -p "$DPID" 2>/dev/null | tr -d ' ')
    [ -z "$cpu" ] && cpu="?"

    if [ "$bytes" -gt 4096 ]; then
        chi=$(python3 -c "
import collections
b=open('/tmp/ent.bin','rb').read()
h=collections.Counter(b)
print(f'{sum((v-len(b)/256)**2 for v in h.values())/(len(b)/256):.1f}')")
        gz=$(gzip -c /tmp/ent.bin | wc -c)
        gzratio=$(awk "BEGIN { printf \"%.3f\", $gz / $bytes }")
    else
        chi="-"
        gzratio="-"
    fi

    printf "%-28s  %10d  %9s  %7s  %7s  %7s\n" \
        "$combo_str" "$bytes" "$mbps" "$cpu" "$chi" "$gzratio"

    kill -TERM "$DPID" 2>/dev/null || true
    for i in 1 2 3 4 5; do
        kill -0 "$DPID" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
    sleep 0.1
done
rm -f "$SOCK" /tmp/ent.bin
