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
scratch_dir=${MAI_BENCH_SCRATCH:-"$bench_dir/mprotect-overhead-scratch"}
allocation_size=${MAI_BENCH_ALLOCATION_SIZE:-128M}
chunks=${MAI_BENCH_MPROTECT_CHUNKS:-"4K 16K 64K 256K 1M 4M 16M"}
mechanisms=${MAI_BENCH_MPROTECT_MECHANISMS:-"none trace heartbeat raw"}
orders=${MAI_BENCH_MPROTECT_ORDERS:-"sequential random"}
passes=${MAI_BENCH_PASSES:-3}
trace_pages=${MAI_BENCH_MPROTECT_TRACE_PAGES:-16}
heartbeat_epochs=${MAI_BENCH_HEARTBEAT_EPOCHS:-100}
heartbeat_threads=${MAI_BENCH_HEARTBEAT_THREADS:-4}
positions=${MAI_BENCH_CHUNK_POSITIONS:-"first middle last"}
position_epochs=${MAI_BENCH_CHUNK_POSITION_EPOCHS:-5}
min_mib_per_sec=${MAI_BENCH_MIN_MIB_PER_SEC:-0}

mkdir -p "$scratch_dir"

echo "suite=mprotect_overhead_matrix allocation_size=$allocation_size passes=$passes trace_pages=$trace_pages"
echo "note=logical_mib_per_sec_is_full_buffer_write_plus_read;touch_latency_is_representative_page_first_touch"

for mechanism in $mechanisms; do
    for order in $orders; do
        for chunk in $chunks; do
            echo "mechanism=$mechanism order=$order chunk=$chunk"
            if [ "$mechanism" = "raw" ]; then
                MAI_MPROTECT_MECHANISM=raw \
                    MAI_MPROTECT_ORDER="$order" \
                    MAI_MPROTECT_CHUNK="$chunk" \
                    MAI_MPROTECT_TRACE_PAGES="$trace_pages" \
                    MAI_ACCESS_PASSES="$passes" \
                    MAI_ACCESS_EXPECT_MANAGED=0 \
                    MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
                    "$benchmark" mprotect_overhead "$allocation_size" |
                    sed "s/^/mechanism=raw order=$order chunk=$chunk /"
            elif [ "$mechanism" = "none" ]; then
                MAI_ENABLE=1 \
                    MAI_PATH="$scratch_dir" \
                    MAI_THRESHOLD=4K \
                    MAI_ARENA_SIZE=512M \
                    MAI_MAX_RSS=off \
                    MAI_RECLAIM_POLICY=none \
                    MAI_MPROTECT_MECHANISM=none \
                    MAI_MPROTECT_ORDER="$order" \
                    MAI_MPROTECT_CHUNK="$chunk" \
                    MAI_MPROTECT_TRACE_PAGES="$trace_pages" \
                    MAI_ACCESS_PASSES="$passes" \
                    MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
                    LD_PRELOAD="$lib_dir/libmai.so" \
                    "$benchmark" mprotect_overhead "$allocation_size" |
                    sed "s/^/mechanism=none order=$order chunk=$chunk /"
            else
                MAI_ENABLE=1 \
                    MAI_PATH="$scratch_dir" \
                    MAI_THRESHOLD=4K \
                    MAI_ARENA_SIZE=512M \
                    MAI_MAX_RSS=off \
                    MAI_RECLAIM_POLICY=none \
                    MAI_MPROTECT_MECHANISM="$mechanism" \
                    MAI_MPROTECT_ORDER="$order" \
                    MAI_MPROTECT_CHUNK="$chunk" \
                    MAI_MPROTECT_TRACE_PAGES="$trace_pages" \
                    MAI_ACCESS_PASSES="$passes" \
                    MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
                    LD_PRELOAD="$lib_dir/libmai.so" \
                    "$benchmark" mprotect_overhead "$allocation_size" |
                    sed "s/^/mechanism=$mechanism order=$order chunk=$chunk /"
            fi
        done
    done
done

for chunk in $chunks; do
    echo "mode=heartbeat_concurrent chunk=$chunk epochs=$heartbeat_epochs threads=$heartbeat_threads"
    MAI_ENABLE=1 \
        MAI_PATH="$scratch_dir" \
        MAI_THRESHOLD=4K \
        MAI_ARENA_SIZE=512M \
        MAI_MAX_RSS=off \
        MAI_RECLAIM_POLICY=none \
        MAI_HEARTBEAT_CHUNK="$chunk" \
        MAI_HEARTBEAT_OBSERVE_PAGES="$trace_pages" \
        MAI_HEARTBEAT_EPOCHS="$heartbeat_epochs" \
        MAI_HEARTBEAT_THREADS="$heartbeat_threads" \
        MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
        LD_PRELOAD="$lib_dir/libmai.so" \
        "$benchmark" heartbeat_concurrent "$allocation_size" |
        sed "s/^/mode=heartbeat_concurrent chunk=$chunk /"
done

for chunk in $chunks; do
    echo "mode=heartbeat_idle chunk=$chunk epochs=$heartbeat_epochs"
    MAI_ENABLE=1 \
        MAI_PATH="$scratch_dir" \
        MAI_THRESHOLD=4K \
        MAI_ARENA_SIZE=512M \
        MAI_MAX_RSS=off \
        MAI_RECLAIM_POLICY=none \
        MAI_HEARTBEAT_CHUNK="$chunk" \
        MAI_HEARTBEAT_OBSERVE_PAGES="$trace_pages" \
        MAI_HEARTBEAT_EPOCHS="$heartbeat_epochs" \
        MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
        LD_PRELOAD="$lib_dir/libmai.so" \
        "$benchmark" heartbeat_idle "$allocation_size" |
        sed "s/^/mode=heartbeat_idle chunk=$chunk /"
done

for position in $positions; do
    for chunk in $chunks; do
        echo "mode=chunk_position position=$position chunk=$chunk epochs=$position_epochs"
        MAI_ENABLE=1 \
            MAI_PATH="$scratch_dir" \
            MAI_THRESHOLD=4K \
            MAI_ARENA_SIZE=512M \
            MAI_MAX_RSS=off \
            MAI_RECLAIM_POLICY=donthneed \
            MAI_HEARTBEAT_CHUNK="$chunk" \
            MAI_HEARTBEAT_OBSERVE_PAGES="$trace_pages" \
            MAI_CHUNK_TOUCH_POSITION="$position" \
            MAI_CHUNK_POSITION_EPOCHS="$position_epochs" \
            MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
            LD_PRELOAD="$lib_dir/libmai.so" \
            "$benchmark" chunk_position "$allocation_size" |
            sed "s/^/mode=chunk_position position=$position chunk=$chunk /"
    done
done
