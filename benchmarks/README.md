# MAI Benchmarks

Benchmarks are separate from correctness CI. They are intended to produce
performance evidence for storage-backed MAI allocations under different access
patterns, not to gate every commit with machine-dependent timing thresholds.

Build benchmark utilities with:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMAI_BUILD_BENCHMARKS=ON
cmake --build build --target mai mai_benchmark mai_access_pattern_benchmark
```

Run sufficient-memory overhead benchmarks with:

```
benchmarks/sufficient_memory_matrix.sh \
  build/src/libmai.so \
  build/tests/mai_benchmark \
  build/benchmarks/mai_access_pattern_benchmark
```

This compares native, preloaded-disabled, MAI pass-through, anonymous
MAI-managed sufficient-memory, and legacy `MAI_BACKEND=file` runs for allocator
microbenchmarks and access-pattern workloads. The default access-pattern set
includes `stream_bandwidth`, a STREAM-style three-array copy/scale/add/triad
benchmark that reports `stream_*_mib_per_sec` fields for sustained bandwidth.
It also reports `stream_first_pass_mib_per_sec`,
`stream_median_pass_mib_per_sec`, and `stream_last_pass_mib_per_sec` so a run
can distinguish first-touch/setup effects from repeated-kernel behavior.
`stream_bandwidth` uses `MAI_BENCH_STREAM_ALLOCATION_SIZE`, which defaults to
512 MiB so the three-array working set is well above typical CPU cache sizes.
These rows are timing evidence, not portable guarantees.

Raw backing-mode STREAM checks are available without MAI management:

```
MAI_ACCESS_EXPECT_MANAGED=0 MAI_BENCH_STREAM_PASSES=8 \
  build/benchmarks/mai_access_pattern_benchmark stream_anon_mmap 1G
MAI_ACCESS_EXPECT_MANAGED=0 MAI_BENCH_STREAM_PASSES=8 \
  build/benchmarks/mai_access_pattern_benchmark stream_shared_file 1G
MAI_ACCESS_EXPECT_MANAGED=0 MAI_BENCH_STREAM_PASSES=8 \
  build/benchmarks/mai_access_pattern_benchmark stream_private_file 1G
```

These modes run the same STREAM kernel with all three arrays backed by
anonymous mmap, unlinked `MAP_SHARED` files, or unlinked `MAP_PRIVATE` files.
They are useful for checking whether file-backed bandwidth loss persists across
repeated passes.

Run protected-page and heartbeat overhead sweeps with:

```
benchmarks/trace_heartbeat_matrix.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark
```

`trace_chunks` measures chunked mprotect/SIGSEGV tracing. `heartbeat_busy`
measures active-access heartbeat cost and verifies heartbeat-driven reclaim
stays at zero while sampled pages are busy.

Run phase-split mprotect overhead sweeps with:

```
benchmarks/mprotect_overhead_matrix.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark
```

This matrix compares `none`, direct MAI `trace`, MAI `heartbeat`, and raw
benchmark-local `mprotect` mechanisms with the same sample-page cap. It reports
observation setup time, representative-page first-touch latency percentiles,
finish/restore time, `getrusage()` fault/context-switch deltas, and a
post-observation full-buffer write/read bandwidth field
(`logical_mib_per_sec`). The existing `mib_per_sec` field remains page-touch
throughput and should not be read as sustained memory bandwidth.

The same runner also emits `heartbeat_idle` rows for controller-only overhead
and `chunk_position` rows for representative-page sensitivity. In
`chunk_position`, `first` touches the protected representative page, while
`middle` and `last` intentionally touch other pages in the chunk to show when
chunk-level sampling can miss recent activity and classify a chunk as quiet.
`MAI_BENCH_CHUNK_POSITION_EPOCHS` repeats that touch/observe pattern to verify
whether representative rotation catches systematic middle/tail access before
demotion.
`heartbeat_concurrent` rows run worker threads against the allocation while the
main thread calls `mai_heartbeat()` with migration disabled; these rows are for
controller overhead under live application access, not reclaim throughput.

Run the Docker access-pattern pressure benchmark with:

```
benchmarks/docker_access_patterns.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark
```

The Docker runner uses a cgroup memory limit and exercises these MAI-managed
patterns:

- `stream`: sequential windowed write, reclaim, read-back verification
- `stride`: nonsequential page order within each reclaim window
- `sparse`: sparse page touches across an allocation larger than the memory cap
- `random_hotset`: repeated random accesses inside a bounded hot set

Run true STREAM bandwidth under progressive cgroup pressure with:

```
benchmarks/docker_stream_pressure_matrix.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark
```

This runner keeps the STREAM matrix size fixed and sweeps Docker memory limits.
Most scenarios set `--memory-swap` equal to `--memory`, so there is no swap
cushion. The `linux_swap_pipeline` scenario raises `--memory-swap` to
`MAI_BENCH_DOCKER_SWAP_MEMORY` so native Linux swap can be measured directly.
The default no-oracle matrix is pipeline-only: Linux `MAP_SHARED`, Linux swap,
MAI auto, and MAI UFFD. Run `native_pipeline` separately under sufficient
memory for the upper-bound baseline. Classic three-array rows remain useful
controls, but they should not be mixed into the 9-matrix pressure comparison.
Use `end_to_end_logical_mib_per_sec` as the primary comparison metric; kernel
STREAM rates are secondary because they exclude allocation, first-touch, and
fault setup costs.

`stream_tiled_bandwidth` and the MAI range APIs remain useful assisted controls
for integration experiments, but they are not part of the default no-oracle
comparison matrix because they tell MAI which ranges will be read, written, or
reclaimed.

The `mai_kernel_pipeline` row runs `stream_kernel_pipeline`, a rotating
working-set STREAM benchmark over nine matrices grouped as `ABC`, `DEF`, and
`GHI`. The benchmark argument is the per-matrix size, so
`stream_kernel_pipeline 128M` allocates a 1152 MiB logical matrix set while each
active group touches only one 384 MiB triplet.

Each group visit runs `MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS` repetitions
of this classic four-kernel STREAM sequence on the active triplet:

```
A = B
B = scalar * A
C = A + B
A = B + scalar * C
```

The outer cycle can run sequentially (`ABC -> DEF -> GHI -> ABC`) or in a
deterministic pseudo-random order with `MAI_BENCH_STREAM_PIPELINE_ORDER`. The pipeline
benchmark does not call `mai_prefetch()`, `mai_prepare_write()`, or
`mai_reclaim_range()`, and it does not tell MAI which group comes next.
Autonomous MAI rows must therefore rely on allocation policy, cgroup/RSS
pressure, allocator-time demotion, page-fault-driven kernel cache behavior,
and optional runtime-owned background heartbeat observation. Background
heartbeat migration defaults to disabled; set `MAI_HEARTBEAT_BACKGROUND_MIGRATE`
only for explicit quiescent-boundary or unsafe experimental runs.

This is the intended pressure condition: `3 * matrix_bytes` should fit in
physical memory while `9 * matrix_bytes` does not. It verifies sampled final
values for all nine matrices against the STREAM recurrence.

Useful overrides:

```
MAI_BENCH_TRIALS=5
MAI_BENCH_DOCKER_MEMORIES="512m"
MAI_BENCH_DOCKER_SWAP_MEMORY=2g
MAI_BENCH_DOCKER_MEMORY_SWAPPINESS=100
MAI_BENCH_SCENARIOS="linux_mmap_pipeline linux_swap_pipeline mai_auto_pipeline mai_uffd_pipeline"
MAI_BENCH_TRACE_CHUNKS="4K 64K 4M 64M"
MAI_BENCH_MPROTECT_CHUNKS="4K 64K 1M 16M"
MAI_BENCH_MPROTECT_MECHANISMS="none trace heartbeat raw"
MAI_BENCH_MPROTECT_TRACE_PAGES=16
MAI_BENCH_HEARTBEAT_EPOCHS=100
MAI_BENCH_HEARTBEAT_THREADS=4
MAI_BENCH_CHUNK_POSITIONS="first middle last"
MAI_BENCH_CHUNK_POSITION_EPOCHS=5
MAI_BENCH_DOCKER_MEMORY=128m
MAI_BENCH_ALLOCATION_SIZE=192M
MAI_BENCH_STREAM_ALLOCATION_SIZE=128M
MAI_BENCH_PASSTHROUGH_THRESHOLD=16T
MAI_BENCH_STREAM_PASSES=6
MAI_BENCH_STREAM_TILE=2M
MAI_BENCH_STREAM_RESIDENT_ARRAYS=auto
MAI_BENCH_STREAM_TILE_PREFETCH=1
MAI_BENCH_STREAM_TILE_PREPARE_WRITE=1
MAI_BENCH_STREAM_TILE_RECLAIM=1
MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS=4
MAI_BENCH_STREAM_PIPELINE_ORDER=sequential
MAI_BENCH_STREAM_PIPELINE_SEED=1
MAI_BENCH_STREAM_PIPELINE_SCALAR=0.25
MAI_HEARTBEAT_BACKGROUND_INTERVAL_US=1000
MAI_HEARTBEAT_BACKGROUND_OBSERVE_PAGES=64
MAI_HEARTBEAT_BACKGROUND_CHUNK=2M
MAI_HEARTBEAT_BACKGROUND_MIGRATE=0
MAI_BACKEND=anon
MAI_FILE_DEDICATED_MIN=64M
MAI_AUTO_LARGE_ALLOC_CAP_PERCENT=12
MAI_MIGRATION_CHUNK=2M
MAI_UFFD_PREFETCH_CHUNKS=4
MAI_BENCH_WINDOW=8M
MAI_BENCH_HOTSET=32M
MAI_BENCH_RANDOM_OPS=500000
MAI_BENCH_MIN_MIB_PER_SEC=0.5
MAI_HEARTBEAT_MIN_QUIET_EPOCHS=3
```

By default the benchmarks fail on correctness errors, missing MAI management
where required, missing reclaim in reclaim-oriented pressure patterns, or
unexpected heartbeat reclaim during busy ticks. They only enforce a throughput
floor when `MAI_BENCH_MIN_MIB_PER_SEC` is set above zero.
