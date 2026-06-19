# MAI Benchmarks

Benchmarks are separate from correctness CI. They are intended to produce
performance evidence for storage-backed MAI allocations under different access
patterns, not to gate every commit with machine-dependent timing thresholds.
The latest retained local policy comparison is in
`docs/policy_benchmark_results.md`.

Build benchmark utilities with:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMAI_BUILD_BENCHMARKS=ON
cmake --build build --target mai mai_benchmark mai_access_pattern_benchmark
```

Run the retained no-oracle policy matrix with:

```
python3 benchmarks/policy_retained_matrix.py \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark \
  --output-dir policy-matrix-results
```

The runner writes `rows.ndjson`, `summary.csv`, and `summary.md`. Each row
records the git SHA, dirty state, host kernel, build type, workload, scenario,
policy, seed, repetition, runtime knobs, raw benchmark output, parsed metrics,
and validation reasons. The default matrix includes the primary
`policy_stream_pipeline` no-oracle workload plus long-tail admission,
recency/frequency, and signature-context guardrails. Default policies are
`legacy`, `markov`, `car`, `wtinylfu`, `hybrid`, `markov_adaptive`, and
`hybrid_adaptive`; default seeds are `1,7,13,29,31,43`. The default sizes are
developer guardrail sizes, not sufficient for memory-bandwidth claims.

For every workload/seed/repetition, the runner records native sufficient,
MAI pass-through, MAI managed sufficient, and policy-pressure rows. Pressure
ratios are computed against the matching `mai_managed_sufficient` row. It does
not call assisted range APIs or feed benchmark future-order variables into the
runtime. Write-protect useful-prefetch observation defaults to off because it
changes fault behavior; use `--observe-prefetch-writes 1` only when validating
observed accuracy/coverage counters.

For bandwidth claims, rerun the same matrix with working sets well beyond CPU
cache, for example:

```
python3 benchmarks/policy_retained_matrix.py \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark \
  --output-dir policy-matrix-results-large \
  --pipeline-matrix-size 128M \
  --allocation-size 512M \
  --resident-limit 384M \
  --resident-low-limit 320M
```

For `policy_stream_pipeline`, choose a resident limit where three active
matrices fit but all nine do not.

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

`policy_stream_pipeline` is the preferred no-oracle name for policy work. It
is an alias of the rotating nine-matrix STREAM workload used by
`stream_kernel_pipeline`, but the name keeps policy result tables separate from
older helper scenarios.

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

Runtime policy knobs are intentionally separate from benchmark knobs:

- `MAI_MIGRATION_POLICY` or `MAI_POLICY`: `legacy`, `lru`, `clock`, `fifo`,
  `random`, `stream`, `stride`, `2q`, `lfu`/`decayed-lfu`, or
  `lruk`/`lru-k`, `car`/`car-lite`, `markov`/`successor`, or
  `spatial`/`spatial-mask`, `tinylfu`/`tiny-lfu`,
  `wtinylfu`/`window-tinylfu`, or `signature`/`history-table`
- `MAI_UFFD_PREFETCH_CHUNKS`: maximum UFFD prefetch lookahead
- `MAI_UFFD_RESIDENT_LIMIT` and `MAI_UFFD_RESIDENT_LOW_LIMIT`: resident
  high/low watermarks for UFFD-managed chunks
- `MAI_MIGRATION_CHUNK`: chunk size used for migration and policy metadata
- `MAI_POLICY_SUCCESSOR_CHAIN_DEPTH`: opt-in chain lookahead depth for
  `markov`, `wtinylfu`, and `signature`; default 1 preserves one-step
  behavior
- `MAI_SPATIAL_REGION_CHUNKS`: chunk count per spatial region-mask group
- `MAI_SPATIAL_TABLE_SLOTS`: maximum active spatial region masks per
  allocation, default 64 and max 64
- `MAI_SPATIAL_LEARN_THRESHOLD` and `MAI_SPATIAL_ADMIT_THRESHOLD`: confidence
  thresholds for mask learning and pressure admission
- `MAI_POLICY_ADAPTIVE_CONTROL=1`: opt-in feedback control for prefetch
  window size and admission confidence
- `MAI_POLICY_ADAPTIVE_WINDOW_FAULTS` and
  `MAI_POLICY_ADAPTIVE_MIGRATION_BUDGET_CHUNKS`: adaptive feedback sensitivity
- `MAI_POLICY_OBSERVE_PREFETCH_WRITES=1`: opt-in write-protect observation for
  useful-prefetch metrics on write-heavy workloads
- `MAI_UFFD_CLEAN_SHADOW=1`: opt-in UFFD clean-shadow tracking that can skip
  demotion writes for restored chunks that were not written before demotion.
  Tracking requires atomic restore-with-write-protect; benchmark output
  reports tracked chunks, protect failures, skipped clean writes, and
  write-protect invalidation faults.

Policy pressure scenarios can use `mai_policy_pipeline` with
`MAI_MIGRATION_POLICY`, or a policy-specific scenario such as
`mai_policy_stream_pipeline`, `mai_policy_clock_pipeline`, or
`mai_policy_2q_pipeline`. The runtime accepts `legacy`, `lru`, `clock`,
`fifo`, `random`, `stream`, `stride`, `2q`, `lfu`/`decayed-lfu`,
`lruk`/`lru-k`, `car`/`car-lite`, `markov`/`successor`,
`spatial`/`spatial-mask`, `tinylfu`/`tiny-lfu`,
`wtinylfu`/`window-tinylfu`, `signature`/`history-table`, and
`best-offset`/`offset-prefetch`.

`policy_multistream_stride` is a focused no-oracle workload for stride
predictors. It walks fixed-size units inside one allocation as independent
strided streams, controlled by `MAI_BENCH_POLICY_STREAMS`,
`MAI_BENCH_POLICY_ACTIVE_STREAMS`, `MAI_BENCH_POLICY_PASSES`, and
`MAI_BENCH_POLICY_STRIDE_UNIT`. Set `MAI_BENCH_POLICY_ACTIVE_STREAMS=1` to
isolate non-unit stride prediction from adjacent forward prefetch. Its
throughput is a policy-event score, not a STREAM bandwidth claim, because each
unit touch samples the unit instead of sweeping every byte. Use
`policy_sampled_units_per_sec` and policy counters as the primary metrics for
this workload.

`policy_hotset_scan` is a policy-event workload for admission and eviction
pollution. It repeatedly touches a hot chunk set, scans a larger cold region,
then verifies the hot set. Control it with `MAI_BENCH_POLICY_HOTSET`,
`MAI_BENCH_POLICY_HOTSET_UNIT`, `MAI_BENCH_POLICY_HOT_ROUNDS`, and
`MAI_BENCH_POLICY_SCAN_PASSES`. Use it to compare `2q`, `lfu`, and `lruk` against
legacy prefetch admission under the same resident limit.
On the local 32M allocation / 8M resident-limit smoke shape, `lfu` with
write-protect observation reduced migration traffic versus `legacy`. In the
latest six-run policy matrix, observation-off `lfu` won the hotset scan
event-rate row and tied `legacy` on lowest demand faults. Treat `lfu` as a
frequency-admission baseline whose win is workload-specific, not a default
policy.

`policy_phase_shift_hotset` is a reuse-distance guardrail. It warms hotset A,
switches to hotset B, scans colder chunks, and verifies only the new hotset.
It does not give MAI phase hints. Control it with
`MAI_BENCH_POLICY_PHASE_HOTSET`, `MAI_BENCH_POLICY_PHASE_UNIT`,
`MAI_BENCH_POLICY_PHASE_WARM_ROUNDS`,
`MAI_BENCH_POLICY_PHASE_ACTIVE_ROUNDS`, and
`MAI_BENCH_POLICY_PHASE_SCAN_PASSES`. Use it to compare `lruk` with `lfu`:
LFU can preserve old high-frequency chunks too long, while LRU-K should prefer
chunks with more recent repeated demand references.

`policy_recency_frequency_pivot` is a no-oracle CAR/CLOCK-Pro guardrail. It
warms one frequent hotset, rotates through short-lived recent hotsets with cold
scans between phases, then returns to the original frequent hotset. Control it
with `MAI_BENCH_POLICY_PIVOT_HOTSET`,
`MAI_BENCH_POLICY_PIVOT_UNIT`,
`MAI_BENCH_POLICY_PIVOT_WARM_ROUNDS`,
`MAI_BENCH_POLICY_PIVOT_BURST_GROUPS`,
`MAI_BENCH_POLICY_PIVOT_BURST_ROUNDS`,
`MAI_BENCH_POLICY_PIVOT_RETURN_ROUNDS`, and
`MAI_BENCH_POLICY_PIVOT_SCAN_PASSES`. Use it to check whether `car` adapts
between recency and frequency instead of only throttling prefetches. Benchmark
output reports CAR resident state counts, ghost hits, target movement, and
second-chance scans.

`policy_long_tail_admission` is a no-oracle admission workload for TinyLFU-like
hot/cold classifiers. It warms a stable hotset, repeatedly mixes a
medium-frequency set with a full-permutation cold tail, then changes to a
second hotset. Control it with `MAI_BENCH_POLICY_LONGTAIL_HOTSET`,
`MAI_BENCH_POLICY_LONGTAIL_MEDIUM`,
`MAI_BENCH_POLICY_LONGTAIL_UNIT`,
`MAI_BENCH_POLICY_LONGTAIL_WARM_ROUNDS`,
`MAI_BENCH_POLICY_LONGTAIL_MEDIUM_ROUNDS`,
`MAI_BENCH_POLICY_LONGTAIL_COLD_PASSES`,
`MAI_BENCH_POLICY_LONGTAIL_PHASE_ROUNDS`, and
`MAI_BENCH_POLICY_LONGTAIL_SEED`. Use it to compare `tinylfu` with exact `lfu`
and `car`: the expected signal is lower cold-tail pollution and migration
traffic, not universal improvement on every phase-shift probe. Output includes
`stream_pipeline_unique_cold_visits`, which should equal the cold-tail unit
count times the number of cold-tail passes.

`wtinylfu` uses the same long-tail, hotset, and pivot guardrails as `tinylfu`
and `car`. Tune its recency window with `MAI_POLICY_WTINYLFU_WINDOW_PERCENT`.
Useful runs should show fewer unused-prefetch evictions and lower migration
bytes without a large increase in demand events, hot-evicted bytes, or tail
stall.

`policy_best_offset_lag` is a no-oracle workload for recurring non-adjacent
offset predictors. It shuffles a source range, touches each anchor now, then
touches a disjoint `anchor + offset` target after a configurable lookahead.
Control it with `MAI_BENCH_POLICY_OFFSET_UNIT`,
`MAI_BENCH_POLICY_OFFSET_CHUNKS`, `MAI_BENCH_POLICY_OFFSET_LOOKAHEAD`,
`MAI_BENCH_POLICY_OFFSET_PASSES`, `MAI_BENCH_POLICY_OFFSET_SEED`, and optional
`MAI_BENCH_POLICY_OFFSET_NOISE`. Runtime policy tuning can also set
`MAI_POLICY_BEST_OFFSET_MIN_CHUNKS` to keep nearby offsets in the stream/stride
domain. Use it to compare `best-offset` against `stream`, `stride`, `markov`,
and `spatial`: wins require lower demand events or stalls without higher
migration amplification or unused-prefetch evictions.

`policy_successor_cycle` is a no-oracle workload for repeated irregular
transitions. It walks fixed-size units through an affine successor cycle, so
next-chunk and constant-stride predictors should not be credited for the
pattern. Control it with `MAI_BENCH_POLICY_SUCCESSOR_UNIT`,
`MAI_BENCH_POLICY_SUCCESSOR_MULTIPLIER`,
`MAI_BENCH_POLICY_SUCCESSOR_ADDEND`, and `MAI_BENCH_POLICY_PASSES`.
On the local 64M allocation / 16M resident-limit smoke shape, `markov`
reduced demand faults versus `stride` and modestly improved sampled-unit rate
when write-protect observation was disabled. Enable observation only when you
need useful-prefetch accounting, because it changes fault behavior.

`policy_signature_context_cycle` is a no-oracle workload for history-table
predictors. Each eight-chunk region alternates two short contexts that share a
middle chunk but require different successors, so one-successor `markov` sees
an ambiguous transition and constant-stride predictors see no stable stream.
Control it with `MAI_BENCH_POLICY_SIGNATURE_UNIT`,
`MAI_BENCH_POLICY_SIGNATURE_REGION_UNITS`,
`MAI_BENCH_POLICY_SIGNATURE_PASSES`, and
`MAI_BENCH_POLICY_SIGNATURE_SEED`. With `MAI_MIGRATION_POLICY=hybrid`, the
same probe also reports source-attributed hybrid candidates, admitted
prefetches, and useful prefetches for signature, successor, and stream legs.

`policy_spatial_region_mask` is a policy-event workload for region-mask
predictors. It divides one allocation into eight-unit regions and repeatedly
touches the same sparse offset mask inside each region, while rotating and
reversing the in-region order so adjacent, stride, and one-successor predictors
do not receive the same signal. Control it with
`MAI_BENCH_POLICY_SPATIAL_UNIT`, `MAI_BENCH_POLICY_SPATIAL_REGION_UNITS`,
and `MAI_BENCH_POLICY_PASSES`. `policy_spatial_interleaved_mask` is the harder
guardrail: it interleaves regions and, at region widths of four chunks or
larger, gives alternating regions different masks so a single allocation-wide
mask would overfetch.

Spatial-mask learning sees demand faults and optional write-protect faults, not
all CPU reads. A resident prefetched read can help throughput without increasing
observed usefulness. Table capacity is also finite; run
`policy_spatial_interleaved_mask` with a deliberately small
`MAI_SPATIAL_TABLE_SLOTS` setting when checking region churn behavior.

These rows touch one byte per unit, so `logical_mib_per_sec` is synthetic
logical progress, not sustained memory bandwidth. On the local 64M allocation /
16M resident-limit shape with write-protect observation disabled, six-run
means on `policy_spatial_region_mask` were: `spatial` 73 demand faults,
170 MiB migration reads, 182 MiB migration writes, and 2204 logical MiB/s;
`stream` 96 faults, 168/180 MiB, and 3144 logical MiB/s; `markov` 95 faults,
174/186 MiB, and 2867 logical MiB/s. On
`policy_spatial_interleaved_mask`, `spatial` and `markov` both reduced demand
faults versus `stream` (67.0 and 67.3 versus 71.0), but `spatial` paid more
prefetch traffic. Treat this as evidence about fault reduction and pollution,
not a standalone throughput win.

Benchmark-only knobs keep the `MAI_BENCH_` prefix. Source policy tests reject
`MAI_BENCH_*` and `MAI_STREAM_*` references from runtime source files so MAI
cannot learn benchmark oracle variables.

Policy rows include mechanism-derived counters such as
`policy_prefetch_observation`, `policy_prefetch_accuracy_observed`,
`policy_prefetch_coverage_observed`,
`policy_migration_read_bytes`, `policy_migration_write_bytes`,
`policy_read_amplification`, `policy_write_amplification`,
`policy_demand_fault_stall_ns`, `policy_demand_fault_stall_p50_ns`,
`policy_demand_fault_stall_p90_ns`, `policy_demand_fault_stall_p99_ns`, and
unused-prefetch eviction bytes. Policy probe rows also include
`policy_sampled_units_per_sec`. Adaptive-control rows additionally include
`policy_adaptive_windows`, `policy_adaptive_level`,
`policy_adaptive_level_changes`, `policy_adaptive_prefetch_capped`, and
`policy_adaptive_admission_rejected`. Compare these against
sufficient-memory rows from the same host, seed, binary, and workload before
making performance claims. The observed prefetch metrics are lower bounds unless
`policy_prefetch_observation=write_protect`; Linux mmap and swap baselines do
not populate MAI migration-byte counters.
For `policy_stream_pipeline`, the
`stream_pipeline_max_cycle_policy_*` fields report the largest per-group-visit
delta after matrix initialization. They show whether faults, migration bytes,
demotions, hot evictions, or stall time concentrate at phase transitions even
when aggregate means look acceptable.

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
MAI_POLICY_ADAPTIVE_CONTROL=1
MAI_POLICY_ADAPTIVE_WINDOW_FAULTS=16
MAI_POLICY_ADAPTIVE_MIGRATION_BUDGET_CHUNKS=16
MAI_RECORD_PROTECT_EPOCHS=8
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
