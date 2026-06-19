#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <libmai.so> <mai_access_pattern_benchmark>" >&2
    exit 2
fi

libmai=$1
benchmark=$2

if [ ! -f "$libmai" ] || [ ! -x "$benchmark" ]; then
    echo "benchmark inputs are missing; build benchmark targets first" >&2
    exit 2
fi

lib_dir=$(cd "$(dirname "$libmai")" && pwd)
bench_dir=$(cd "$(dirname "$benchmark")" && pwd)
scratch_dir=${MAI_BENCH_SCRATCH:-"$bench_dir/trace-heartbeat-scratch"}
allocation_size=${MAI_BENCH_ALLOCATION_SIZE:-128M}
chunks=${MAI_BENCH_TRACE_CHUNKS:-"4K 16K 64K 256K 1M 4M 16M 64M"}
observe_pages=${MAI_BENCH_OBSERVE_PAGES:-16}
passes=${MAI_BENCH_PASSES:-3}
min_mib_per_sec=${MAI_BENCH_MIN_MIB_PER_SEC:-0}

mkdir -p "$scratch_dir"

echo "suite=trace_heartbeat_matrix allocation_size=$allocation_size passes=$passes observe_pages=$observe_pages"
echo "note=trace_chunks_measures_mprotect_sigsegv_overhead;heartbeat_busy_must_report_zero_reclaimed_bytes"

for chunk in $chunks; do
    echo "mode=trace_chunks chunk=$chunk"
    MAI_ENABLE=1 \
        MAI_PATH="$scratch_dir" \
        MAI_THRESHOLD=4K \
        MAI_ARENA_SIZE=512M \
        MAI_MAX_RSS=off \
        MAI_RECLAIM_POLICY=none \
        MAI_ACCESS_TRACE_CHUNK="$chunk" \
        MAI_ACCESS_TRACE_PAGES="$observe_pages" \
        MAI_ACCESS_PASSES="$passes" \
        MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
        LD_PRELOAD="$lib_dir/libmai.so" \
        "$benchmark" trace_chunks "$allocation_size" |
        sed "s/^/chunk=$chunk /"

    echo "mode=heartbeat_busy chunk=$chunk"
    MAI_ENABLE=1 \
        MAI_PATH="$scratch_dir" \
        MAI_THRESHOLD=4K \
        MAI_ARENA_SIZE=512M \
        MAI_MAX_RSS=off \
        MAI_RECLAIM_POLICY=donthneed \
        MAI_HEARTBEAT_CHUNK="$chunk" \
        MAI_HEARTBEAT_OBSERVE_PAGES="$observe_pages" \
        MAI_ACCESS_PASSES="$passes" \
        MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
        LD_PRELOAD="$lib_dir/libmai.so" \
        "$benchmark" heartbeat_busy "$allocation_size" |
        sed "s/^/chunk=$chunk /"
done
