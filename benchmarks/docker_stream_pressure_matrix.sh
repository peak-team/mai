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
scratch_root=${MAI_BENCH_SCRATCH:-"$bench_dir/docker-stream-pressure-scratch"}
image=${MAI_BENCH_DOCKER_IMAGE:-ubuntu:24.04}
memories=${MAI_BENCH_DOCKER_MEMORIES:-"512m"}
scenarios=${MAI_BENCH_SCENARIOS:-"linux_mmap_pipeline linux_swap_pipeline mai_auto_pipeline mai_uffd_pipeline"}
trials=${MAI_BENCH_TRIALS:-6}
swap_memory_override=${MAI_BENCH_DOCKER_SWAP_MEMORY:-}
swap_swappiness_override=${MAI_BENCH_DOCKER_MEMORY_SWAPPINESS:-}
stream_size=${MAI_BENCH_STREAM_ALLOCATION_SIZE:-128M}
passes=${MAI_BENCH_STREAM_PASSES:-${MAI_STREAM_PASSES:-3}}
tile_size=${MAI_BENCH_STREAM_TILE:-${MAI_STREAM_TILE:-2M}}
resident_arrays=${MAI_BENCH_STREAM_RESIDENT_ARRAYS:-${MAI_STREAM_RESIDENT_ARRAYS:-auto}}
tile_prefetch=${MAI_BENCH_STREAM_TILE_PREFETCH:-${MAI_STREAM_TILE_PREFETCH:-1}}
tile_prepare_write=${MAI_BENCH_STREAM_TILE_PREPARE_WRITE:-${MAI_STREAM_TILE_PREPARE_WRITE:-1}}
tile_reclaim=${MAI_BENCH_STREAM_TILE_RECLAIM:-${MAI_STREAM_TILE_RECLAIM:-1}}
migration_chunk=${MAI_MIGRATION_CHUNK:-2M}
migration_policy=${MAI_MIGRATION_POLICY:-${MAI_POLICY:-legacy}}
policy_observe_prefetch_writes=${MAI_POLICY_OBSERVE_PREFETCH_WRITES:-0}
heartbeat_background=${MAI_HEARTBEAT_BACKGROUND:-0}
heartbeat_interval=${MAI_HEARTBEAT_BACKGROUND_INTERVAL_US:-1000}
heartbeat_observe=${MAI_HEARTBEAT_BACKGROUND_OBSERVE_PAGES:-64}
heartbeat_chunk=${MAI_HEARTBEAT_BACKGROUND_CHUNK:-2M}
heartbeat_migrate=${MAI_HEARTBEAT_BACKGROUND_MIGRATE:-0}
pipeline_group_iterations=${MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS:-${MAI_STREAM_PIPELINE_GROUP_ITERATIONS:-4}}
pipeline_order=${MAI_BENCH_STREAM_PIPELINE_ORDER:-${MAI_STREAM_PIPELINE_ORDER:-sequential}}
pipeline_seed=${MAI_BENCH_STREAM_PIPELINE_SEED:-${MAI_STREAM_PIPELINE_SEED:-1}}
pipeline_scalar=${MAI_BENCH_STREAM_PIPELINE_SCALAR:-${MAI_STREAM_PIPELINE_SCALAR:-0.25}}
passthrough_threshold=${MAI_BENCH_PASSTHROUGH_THRESHOLD:-16T}
mai_threshold=${MAI_THRESHOLD:-4K}
mai_arena_size=${MAI_ARENA_SIZE:-512M}
mai_max_rss=${MAI_MAX_RSS:-auto}
mai_file_dedicated_min=${MAI_FILE_DEDICATED_MIN:-64M}
mai_auto_large_alloc_cap_percent=${MAI_AUTO_LARGE_ALLOC_CAP_PERCENT:-12}
uffd_pager=${MAI_UFFD_PAGER:-required}
uffd_resident_limit=${MAI_UFFD_RESIDENT_LIMIT:-auto}
uffd_resident_low_limit=${MAI_UFFD_RESIDENT_LOW_LIMIT:-auto}
uffd_prefetch_chunks=${MAI_UFFD_PREFETCH_CHUNKS:-4}
fail_on_error=${MAI_BENCH_FAIL_ON_ERROR:-0}

mkdir -p "$scratch_root"

echo "suite=docker_stream_pressure_matrix image=$image trials=$trials stream_size=$stream_size passes=$passes tile_size=$tile_size resident_arrays=$resident_arrays tile_prefetch=$tile_prefetch tile_prepare_write=$tile_prepare_write tile_reclaim=$tile_reclaim migration_chunk=$migration_chunk migration_policy=$migration_policy policy_observe_prefetch_writes=$policy_observe_prefetch_writes heartbeat_background=$heartbeat_background heartbeat_interval_us=$heartbeat_interval heartbeat_observe_pages=$heartbeat_observe heartbeat_chunk=$heartbeat_chunk heartbeat_migrate=$heartbeat_migrate pipeline_group_iterations=$pipeline_group_iterations pipeline_order=$pipeline_order pipeline_seed=$pipeline_seed pipeline_scalar=$pipeline_scalar mai_threshold=$mai_threshold mai_arena_size=$mai_arena_size mai_file_dedicated_min=$mai_file_dedicated_min mai_auto_large_alloc_cap_percent=$mai_auto_large_alloc_cap_percent mai_max_rss=$mai_max_rss uffd_pager=$uffd_pager uffd_resident_limit=$uffd_resident_limit uffd_resident_low_limit=$uffd_resident_low_limit swap_memory_override=${swap_memory_override:-none} swap_swappiness_override=${swap_swappiness_override:-none}"
echo "memories=\"$memories\" scenarios=\"$scenarios\""
echo "note=classic_STREAM_uses_three_arrays; pipeline_STREAM_uses_nine_matrices_grouped_as_three_hot_triplets"

for memory in $memories; do
    for scenario in $scenarios; do
        trial=1
        while [ "$trial" -le "$trials" ]; do
            scratch_dir="$scratch_root/$memory/$scenario/$trial"
            mkdir -p "$scratch_dir"
            scenario_swap=$memory
            scenario_swappiness=${swap_swappiness_override:-0}
            case "$scenario" in
                linux_swap|linux_swap_pipeline|*_swap)
                    scenario_swap=${swap_memory_override:-2g}
                    scenario_swappiness=${swap_swappiness_override:-100}
                    ;;
            esac
            echo "run_scope=docker trial=$trial memory=$memory memory_swap=$scenario_swap memory_swappiness=$scenario_swappiness scenario=$scenario stream_size=$stream_size passes=$passes"

            set +e
            docker run --rm \
            --memory="$memory" \
            --memory-swap="$scenario_swap" \
            --memory-swappiness="$scenario_swappiness" \
            --pids-limit=256 \
            -e "MAI_BENCH_SCENARIO=$scenario" \
            -e "MAI_BENCH_STREAM_ALLOCATION_SIZE=$stream_size" \
            -e "MAI_BENCH_STREAM_PASSES=$passes" \
            -e "MAI_BENCH_STREAM_TILE=$tile_size" \
            -e "MAI_BENCH_STREAM_RESIDENT_ARRAYS=$resident_arrays" \
            -e "MAI_BENCH_STREAM_TILE_PREFETCH=$tile_prefetch" \
            -e "MAI_BENCH_STREAM_TILE_PREPARE_WRITE=$tile_prepare_write" \
            -e "MAI_BENCH_STREAM_TILE_RECLAIM=$tile_reclaim" \
            -e "MAI_MIGRATION_CHUNK=$migration_chunk" \
            -e "MAI_MIGRATION_POLICY=$migration_policy" \
            -e "MAI_POLICY_OBSERVE_PREFETCH_WRITES=$policy_observe_prefetch_writes" \
            -e "MAI_HEARTBEAT_BACKGROUND=$heartbeat_background" \
            -e "MAI_HEARTBEAT_BACKGROUND_INTERVAL_US=$heartbeat_interval" \
            -e "MAI_HEARTBEAT_BACKGROUND_OBSERVE_PAGES=$heartbeat_observe" \
            -e "MAI_HEARTBEAT_BACKGROUND_CHUNK=$heartbeat_chunk" \
            -e "MAI_HEARTBEAT_BACKGROUND_MIGRATE=$heartbeat_migrate" \
            -e "MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS=$pipeline_group_iterations" \
            -e "MAI_BENCH_STREAM_PIPELINE_ORDER=$pipeline_order" \
            -e "MAI_BENCH_STREAM_PIPELINE_SEED=$pipeline_seed" \
            -e "MAI_BENCH_STREAM_PIPELINE_SCALAR=$pipeline_scalar" \
            -e "MAI_BENCH_PASSTHROUGH_THRESHOLD=$passthrough_threshold" \
            -e "MAI_THRESHOLD=$mai_threshold" \
            -e "MAI_ARENA_SIZE=$mai_arena_size" \
            -e "MAI_FILE_DEDICATED_MIN=$mai_file_dedicated_min" \
            -e "MAI_AUTO_LARGE_ALLOC_CAP_PERCENT=$mai_auto_large_alloc_cap_percent" \
            -e "MAI_MAX_RSS=$mai_max_rss" \
            -e "MAI_BENCH_UFFD_PAGER=$uffd_pager" \
            -e "MAI_BENCH_UFFD_RESIDENT_LIMIT=$uffd_resident_limit" \
            -e "MAI_BENCH_UFFD_RESIDENT_LOW_LIMIT=$uffd_resident_low_limit" \
            -e "MAI_BENCH_UFFD_PREFETCH_CHUNKS=$uffd_prefetch_chunks" \
            -v "$lib_dir:/mai-lib:ro" \
            -v "$bench_dir:/mai-bench:ro" \
            -v "$scratch_dir:/mai-scratch" \
            -w /mai-bench \
            "$image" \
            /bin/sh -u -c '
                mkdir -p /mai-scratch/mai /mai-scratch/raw
                export MAI_BENCH_STREAM_BACKING_PATH=/mai-scratch/raw

                print_cgroup_metric() {
                    label=$1
                    name=$2
                    path=$3
                    if [ -r "$path" ]; then
                        value=$(cat "$path" 2>/dev/null || true)
                        if [ -n "$value" ]; then
                            printf "cgroup_%s_%s=%s\n" "$label" "$name" "$value"
                        fi
                    fi
                }

                print_cgroup_metrics() {
                    label=$1
                    print_cgroup_metric "$label" memory_max /sys/fs/cgroup/memory.max
                    print_cgroup_metric "$label" memory_current /sys/fs/cgroup/memory.current
                    print_cgroup_metric "$label" memory_peak /sys/fs/cgroup/memory.peak
                    print_cgroup_metric "$label" memory_events /sys/fs/cgroup/memory.events
                    print_cgroup_metric "$label" memory_swap_current \
                        /sys/fs/cgroup/memory.swap.current
                    print_cgroup_metric "$label" memory_swap_peak \
                        /sys/fs/cgroup/memory.swap.peak
                    print_cgroup_metric "$label" memory_swap_events \
                        /sys/fs/cgroup/memory.swap.events
                    print_cgroup_metric "$label" memory_stat /sys/fs/cgroup/memory.stat
                    print_cgroup_metric "$label" memory_limit_in_bytes \
                        /sys/fs/cgroup/memory/memory.limit_in_bytes
                    print_cgroup_metric "$label" memory_usage_in_bytes \
                        /sys/fs/cgroup/memory/memory.usage_in_bytes
                    print_cgroup_metric "$label" memory_max_usage_in_bytes \
                        /sys/fs/cgroup/memory/memory.max_usage_in_bytes
                    print_cgroup_metric "$label" memory_failcnt \
                        /sys/fs/cgroup/memory/memory.failcnt
                }

                print_cgroup_metrics before
                case "$MAI_BENCH_SCENARIO" in
                    native)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_bandwidth "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    native_pipeline)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    linux_mmap_pipeline)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline_shared_file "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    linux_mmap_private_pipeline)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline_private_file "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    linux_swap_pipeline)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    preload_disabled)
                        export MAI_ENABLE=0
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_bandwidth "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_passthrough)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_THRESHOLD="$MAI_BENCH_PASSTHROUGH_THRESHOLD"
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_bandwidth "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_auto|mai_anon|mai_file)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export LD_PRELOAD=/mai-lib/libmai.so
                        if [ "$MAI_BENCH_SCENARIO" = "mai_auto" ]; then
                            export MAI_BACKEND=auto
                        elif [ "$MAI_BENCH_SCENARIO" = "mai_anon" ]; then
                            export MAI_BACKEND=anon
                        else
                            export MAI_BACKEND=file
                        fi
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_bandwidth "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_anon_tiled)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=anon
                        export MAI_ACCESS_EXPECT_MANAGED=1
                        export MAI_ACCESS_EXPECT_MANAGED_DELTA=9
                        if [ "$MAI_BENCH_STREAM_TILE_RECLAIM" != "0" ]; then
                            export MAI_ACCESS_EXPECT_RECLAIM=1
                            export MAI_ACCESS_EXPECT_MIGRATED=1
                            export MAI_ACCESS_EXPECT_PROMOTED=1
                        fi
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_tiled_bandwidth "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_kernel_pipeline)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=anon
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_auto_pipeline)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=auto
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_uffd_pipeline)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=auto
                        export MAI_UFFD_PAGER="${MAI_BENCH_UFFD_PAGER:-required}"
                        if [ "${MAI_BENCH_UFFD_RESIDENT_LIMIT:-auto}" = "auto" ]; then
                            unset MAI_UFFD_RESIDENT_LIMIT
                        else
                            export MAI_UFFD_RESIDENT_LIMIT="$MAI_BENCH_UFFD_RESIDENT_LIMIT"
                        fi
                        if [ "${MAI_BENCH_UFFD_RESIDENT_LOW_LIMIT:-auto}" = "auto" ]; then
                            unset MAI_UFFD_RESIDENT_LOW_LIMIT
                        else
                            export MAI_UFFD_RESIDENT_LOW_LIMIT="$MAI_BENCH_UFFD_RESIDENT_LOW_LIMIT"
                        fi
                        export MAI_UFFD_PREFETCH_CHUNKS="${MAI_BENCH_UFFD_PREFETCH_CHUNKS:-4}"
                        export MAI_ACCESS_EXPECT_MANAGED=1
                        export MAI_ACCESS_EXPECT_MANAGED_DELTA=9
                        export MAI_ACCESS_EXPECT_UFFD=1
                        export MAI_ACCESS_EXPECT_UFFD_DELTA=9
                        export MAI_ACCESS_EXPECT_UFFD_FAULTS=1
                        export MAI_ACCESS_EXPECT_UFFD_EVICTIONS=1
                        export MAI_ACCESS_EXPECT_NO_UFFD_FALLBACK=1
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark                             stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_policy_pipeline|mai_policy_*_pipeline)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=auto
                        case "$MAI_BENCH_SCENARIO" in
                            mai_policy_*_pipeline)
                                policy_name=${MAI_BENCH_SCENARIO#mai_policy_}
                                policy_name=${policy_name%_pipeline}
                                ;;
                            *)
                                policy_name=${MAI_MIGRATION_POLICY:-legacy}
                                ;;
                        esac
                        export MAI_MIGRATION_POLICY="$policy_name"
                        export MAI_UFFD_PAGER="${MAI_BENCH_UFFD_PAGER:-required}"
                        if [ "${MAI_BENCH_UFFD_RESIDENT_LIMIT:-auto}" = "auto" ]; then
                            unset MAI_UFFD_RESIDENT_LIMIT
                        else
                            export MAI_UFFD_RESIDENT_LIMIT="$MAI_BENCH_UFFD_RESIDENT_LIMIT"
                        fi
                        if [ "${MAI_BENCH_UFFD_RESIDENT_LOW_LIMIT:-auto}" = "auto" ]; then
                            unset MAI_UFFD_RESIDENT_LOW_LIMIT
                        else
                            export MAI_UFFD_RESIDENT_LOW_LIMIT="$MAI_BENCH_UFFD_RESIDENT_LOW_LIMIT"
                        fi
                        export MAI_UFFD_PREFETCH_CHUNKS="${MAI_BENCH_UFFD_PREFETCH_CHUNKS:-4}"
                        export MAI_ACCESS_EXPECT_MANAGED=1
                        export MAI_ACCESS_EXPECT_MANAGED_DELTA=9
                        export MAI_ACCESS_EXPECT_UFFD=1
                        export MAI_ACCESS_EXPECT_UFFD_DELTA=9
                        export MAI_ACCESS_EXPECT_UFFD_FAULTS=1
                        export MAI_ACCESS_EXPECT_UFFD_EVICTIONS=1
                        export MAI_ACCESS_EXPECT_NO_UFFD_FALLBACK=1
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            policy_stream_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_heartbeat_pipeline)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=auto
                        export MAI_HEARTBEAT_BACKGROUND=1
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    mai_file_pipeline)
                        export MAI_ENABLE=1
                        export MAI_PATH=/mai-scratch/mai
                        export MAI_RECLAIM_POLICY=donthneed
                        export MAI_BACKEND=file
                        export MAI_ACCESS_EXPECT_MANAGED=1
                        export MAI_ACCESS_EXPECT_MANAGED_DELTA=9
                        export LD_PRELOAD=/mai-lib/libmai.so
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_kernel_pipeline "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    raw_shared)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_shared_file "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    raw_private)
                        export MAI_ACCESS_EXPECT_MANAGED=0
                        /mai-bench/mai_access_pattern_benchmark \
                            stream_private_file "$MAI_BENCH_STREAM_ALLOCATION_SIZE"
                        ;;
                    *)
                        echo "unknown MAI_BENCH_SCENARIO: $MAI_BENCH_SCENARIO" >&2
                        exit 2
                        ;;
                esac
                rc=$?
                print_cgroup_metrics after
                exit "$rc"
            '
            rc=$?
            set -e

            echo "run_scope=docker trial=$trial memory=$memory scenario=$scenario exit_code=$rc"
            if [ "$fail_on_error" = "1" ] && [ "$rc" -ne 0 ]; then
                exit "$rc"
            fi
            trial=$((trial + 1))
        done
    done
done
