#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <libmai.so> <mai_runtime_test>" >&2
    exit 2
fi

libmai=$1
runtime_test=$2

if [ ! -f "$libmai" ] || [ ! -x "$runtime_test" ]; then
    echo "libmai or runtime test binary is missing; build the project first" >&2
    exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed; skipping cgroup memory-limit test" >&2
    exit 77
fi

if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is unavailable; skipping cgroup memory-limit test" >&2
    exit 77
fi

lib_dir=$(cd "$(dirname "$libmai")" && pwd)
test_dir=$(cd "$(dirname "$runtime_test")" && pwd)
scratch_dir=${MAI_DOCKER_SCRATCH:-"$test_dir/docker-memory-scratch"}
image=${MAI_DOCKER_IMAGE:-ubuntu:24.04}
memory=${MAI_DOCKER_MEMORY:-64m}

mkdir -p "$scratch_dir"

docker run --rm \
    --memory="$memory" \
    --memory-swap="$memory" \
    --pids-limit=256 \
    -v "$lib_dir:/mai-lib:ro" \
    -v "$test_dir:/mai-tests:ro" \
    -v "$scratch_dir:/mai-scratch" \
    -w /mai-tests \
    "$image" \
    /bin/sh -c 'MAI_ENABLE=1 \
        MAI_PATH=/mai-scratch \
        MAI_THRESHOLD=4K \
        MAI_ARENA_SIZE=128M \
        MAI_MAX_RSS=auto \
        MAI_RECLAIM_POLICY=donthneed \
        LD_PRELOAD=/mai-lib/libmai.so \
        /mai-tests/mai_runtime_test memory_cap_chunked_calloc'
