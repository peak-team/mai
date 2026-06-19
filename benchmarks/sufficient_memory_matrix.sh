#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <libmai.so> <mai_benchmark> <mai_access_pattern_benchmark>" >&2
    exit 2
fi

libmai=$1
allocator_benchmark=$2
access_benchmark=$3

if [ ! -f "$libmai" ] || [ ! -x "$allocator_benchmark" ] || [ ! -x "$access_benchmark" ]; then
    echo "benchmark inputs are missing; build benchmark targets first" >&2
    exit 2
fi

lib_dir=$(cd "$(dirname "$libmai")" && pwd)
bench_dir=$(cd "$(dirname "$access_benchmark")" && pwd)
scratch_dir=${MAI_BENCH_SCRATCH:-"$bench_dir/sufficient-memory-scratch"}
trials=${MAI_BENCH_TRIALS:-6}
allocation_size=${MAI_BENCH_ALLOCATION_SIZE:-64M}
stream_allocation_size=${MAI_BENCH_STREAM_ALLOCATION_SIZE:-512M}
iterations=${MAI_BENCH_ALLOC_ITERATIONS:-5000}
allocator_sizes=${MAI_BENCH_ALLOC_SIZES:-"64 4096 65536"}
access_patterns=${MAI_BENCH_ACCESS_PATTERNS:-"stream_plain stream_bandwidth policy_stream_pipeline stride_plain sparse_plain random_hotset"}
min_mib_per_sec=${MAI_BENCH_MIN_MIB_PER_SEC:-0}
passthrough_threshold=${MAI_BENCH_PASSTHROUGH_THRESHOLD:-16T}

mkdir -p "$scratch_dir"

echo "suite=sufficient_memory_overhead trials=$trials allocation_size=$allocation_size stream_allocation_size=$stream_allocation_size passthrough_threshold=$passthrough_threshold"
echo "note=timing_rows_are_evidence_not_portable_guarantees"

run_native_allocator() {
    mode=$1
    size=$2
    "$allocator_benchmark" "$mode" "$iterations" "$size"
}

run_preloaded_allocator() {
    scenario=$1
    threshold=$2
    mode=$3
    size=$4
    MAI_ENABLE=1 \
        MAI_PATH="$scratch_dir" \
        MAI_THRESHOLD="$threshold" \
        MAI_ARENA_SIZE=512M \
        MAI_MAX_RSS=off \
        MAI_RECLAIM_POLICY=none \
        LD_PRELOAD="$lib_dir/libmai.so" \
        "$allocator_benchmark" "$mode" "$iterations" "$size" |
        sed "s/^/scenario=$scenario /"
}

run_access() {
    scenario=$1
    pattern=$2
    pattern_size=$allocation_size
    if [ "$pattern" = "stream_bandwidth" ] ||
       [ "$pattern" = "policy_stream_pipeline" ]; then
        pattern_size=$stream_allocation_size
    fi
    if [ "$scenario" = "native" ]; then
        MAI_ACCESS_EXPECT_MANAGED=0 \
            MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
            "$access_benchmark" "$pattern" "$pattern_size" |
            sed "s/^/scenario=native /"
    elif [ "$scenario" = "preload_disabled" ]; then
            MAI_ENABLE=0 \
            MAI_ACCESS_EXPECT_MANAGED=0 \
            MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
            LD_PRELOAD="$lib_dir/libmai.so" \
            "$access_benchmark" "$pattern" "$pattern_size" |
            sed "s/^/scenario=preload_disabled /"
    elif [ "$scenario" = "mai_passthrough" ]; then
            MAI_ENABLE=1 \
            MAI_PATH="$scratch_dir" \
            MAI_THRESHOLD="$passthrough_threshold" \
            MAI_ARENA_SIZE=512M \
            MAI_MAX_RSS=off \
            MAI_RECLAIM_POLICY=none \
            MAI_ACCESS_EXPECT_MANAGED=0 \
            MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
            LD_PRELOAD="$lib_dir/libmai.so" \
            "$access_benchmark" "$pattern" "$pattern_size" |
            sed "s/^/scenario=mai_passthrough /"
    elif [ "$scenario" = "mai_managed_file_backend" ]; then
        MAI_ENABLE=1 \
            MAI_PATH="$scratch_dir" \
            MAI_THRESHOLD=4K \
            MAI_ARENA_SIZE=512M \
            MAI_BACKEND=file \
            MAI_MAX_RSS=off \
            MAI_RECLAIM_POLICY=none \
            MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
            LD_PRELOAD="$lib_dir/libmai.so" \
            "$access_benchmark" "$pattern" "$pattern_size" |
            sed "s/^/scenario=mai_managed_file_backend /"
    else
        MAI_ENABLE=1 \
            MAI_PATH="$scratch_dir" \
            MAI_THRESHOLD=4K \
            MAI_ARENA_SIZE=512M \
            MAI_BACKEND=anon \
            MAI_MAX_RSS=off \
            MAI_RECLAIM_POLICY=none \
            MAI_ACCESS_MIN_MIB_PER_SEC="$min_mib_per_sec" \
            LD_PRELOAD="$lib_dir/libmai.so" \
            "$access_benchmark" "$pattern" "$pattern_size" |
            sed "s/^/scenario=mai_managed_sufficient /"
    fi
}

trial=1
while [ "$trial" -le "$trials" ]; do
    for size in $allocator_sizes; do
        for mode in single single_calloc threaded threaded_calloc; do
            echo "trial=$trial scenario=native_allocator size=$size"
            run_native_allocator "$mode" "$size" | sed "s/^/scenario=native_allocator /"
            echo "trial=$trial scenario=mai_passthrough_allocator size=$size"
            run_preloaded_allocator mai_passthrough_allocator "$passthrough_threshold" "$mode" "$size"
            echo "trial=$trial scenario=mai_managed_allocator size=$size"
            run_preloaded_allocator mai_managed_allocator 1 "$mode" "$size"
        done
    done

    for pattern in $access_patterns; do
        echo "trial=$trial access_pattern=$pattern"
        run_access native "$pattern"
        run_access preload_disabled "$pattern"
        run_access mai_passthrough "$pattern"
        run_access mai_managed_sufficient "$pattern"
        run_access mai_managed_file_backend "$pattern"
    done

    trial=$((trial + 1))
done
