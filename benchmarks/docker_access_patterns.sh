#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <libmai.so> <mai_access_pattern_benchmark>" >&2
    exit 2
fi

libmai=$1
benchmark=$2

if [ ! -f "$libmai" ] || [ ! -x "$benchmark" ]; then
    echo "libmai or benchmark binary is missing; build benchmarks first" >&2
    exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed" >&2
    exit 2
fi

if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is unavailable" >&2
    exit 2
fi

lib_dir=$(cd "$(dirname "$libmai")" && pwd)
bench_dir=$(cd "$(dirname "$benchmark")" && pwd)
scratch_dir=${MAI_BENCH_SCRATCH:-"$bench_dir/docker-benchmark-scratch"}
image=${MAI_BENCH_DOCKER_IMAGE:-ubuntu:24.04}
memory=${MAI_BENCH_DOCKER_MEMORY:-64m}
allocation_size=${MAI_BENCH_ALLOCATION_SIZE:-96M}
window=${MAI_BENCH_WINDOW:-4M}
hotset=${MAI_BENCH_HOTSET:-16M}
random_ops=${MAI_BENCH_RANDOM_OPS:-200000}
passes=${MAI_BENCH_PASSES:-1}
min_mib_per_sec=${MAI_BENCH_MIN_MIB_PER_SEC:-0}

mkdir -p "$scratch_dir"

docker run --rm \
    --memory="$memory" \
    --memory-swap="$memory" \
    --pids-limit=256 \
    -e "MAI_BENCH_DOCKER_IMAGE_LABEL=$image" \
    -e "MAI_BENCH_DOCKER_MEMORY=$memory" \
    -e "MAI_BENCH_ALLOCATION_SIZE=$allocation_size" \
    -e "MAI_ACCESS_WINDOW=$window" \
    -e "MAI_ACCESS_HOTSET=$hotset" \
    -e "MAI_ACCESS_RANDOM_OPS=$random_ops" \
    -e "MAI_ACCESS_PASSES=$passes" \
    -e "MAI_ACCESS_MIN_MIB_PER_SEC=$min_mib_per_sec" \
    -v "$lib_dir:/mai-lib:ro" \
    -v "$bench_dir:/mai-bench:ro" \
    -v "$scratch_dir:/mai-scratch" \
    -w /mai-bench \
    "$image" \
    /bin/sh -eu -c '
        export MAI_ENABLE=1
        export MAI_PATH=/mai-scratch
        export MAI_THRESHOLD=4K
        export MAI_ARENA_SIZE=128M
        export MAI_MAX_RSS=auto
        export MAI_RECLAIM_POLICY=donthneed
        export LD_PRELOAD=/mai-lib/libmai.so

        echo "docker_image=$MAI_BENCH_DOCKER_IMAGE_LABEL"
        echo "docker_memory=$MAI_BENCH_DOCKER_MEMORY"
        echo "allocation_size=$MAI_BENCH_ALLOCATION_SIZE"
        echo "window=$MAI_ACCESS_WINDOW hotset=$MAI_ACCESS_HOTSET random_ops=$MAI_ACCESS_RANDOM_OPS passes=$MAI_ACCESS_PASSES"

        MAI_ACCESS_EXPECT_RECLAIM=1 /mai-bench/mai_access_pattern_benchmark stream "$MAI_BENCH_ALLOCATION_SIZE"
        MAI_ACCESS_EXPECT_RECLAIM=1 MAI_ACCESS_STRIDE_PAGES=17 /mai-bench/mai_access_pattern_benchmark stride "$MAI_BENCH_ALLOCATION_SIZE"
        MAI_ACCESS_EXPECT_RECLAIM=1 MAI_ACCESS_STRIDE_PAGES=16 /mai-bench/mai_access_pattern_benchmark sparse "$MAI_BENCH_ALLOCATION_SIZE"
        MAI_ACCESS_STRIDE_PAGES=1 /mai-bench/mai_access_pattern_benchmark random_hotset "$MAI_BENCH_ALLOCATION_SIZE"
    '
