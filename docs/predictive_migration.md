# Predictive Migration Design

MAI uses anonymous-first managed allocations by default. Predictive migration
is an experimental policy layer that decides when cold chunks should be
demoted to storage-backed mappings and when predicted-hot chunks should be
promoted back to anonymous memory. It is not a correctness requirement and not
a performance guarantee.

The policy unit is not "prefetch" alone. Every strategy is evaluated as an
integrated loop:

1. observe demand faults, sampled touches, hints, and residency pressure
2. predict a bounded set of future chunks
3. decide whether each predicted chunk should be admitted to DRAM
4. migrate admitted chunks only within the current bandwidth/stall budget
5. choose demotion victims when DRAM headroom falls below the policy target
6. feed accuracy, coverage, pollution, and stall metrics back into the next
   decision

This prevents a good predictor from degrading the application by polluting
DRAM, evicting hot demand-fetched chunks, or creating excessive storage
traffic.

In `MAI_BACKEND=auto`, new allocations stay anonymous while the projected live
managed footprint fits under the configured or auto-detected RSS budget. When
that projection approaches the budget, MAI allocates a chunk-tracked anonymous
record and demotes it to storage before returning the pointer. This keeps the
application pointer stable, avoids cgroup OOM on first touch, and leaves MAI
metadata available for explicit quiescent promotion later.

## Signals

- `mai_hint_range()` records application intent: sequential, sparse, hotset, or
  cold/reclaim-preferred.
- `mincore()` hotness sampling is a low-intrusion residency signal. It says
  whether sampled pages are resident now; it does not prove recent access.
- `mai_trace_access()` uses `mprotect(PROT_NONE)` plus `SIGSEGV` handling to
  observe sampled first touches. With `chunk_bytes`, MAI protects the first full
  page of each chunk instead of evenly spaced pages.

Trace cleanup restores sampled pages to read/write access. MAI does not track
application-imposed page protections inside managed allocations, so tracing is
not suitable for ranges whose protection state is part of application logic.

`userfaultfd` is available as an optional experimental pager. When
`MAI_UFFD_PAGER=auto|required` is enabled, pressure-selected allocations are
registered for missing and write-protect faults. The pager resolves missing
faults by restoring storage-backed chunks with `UFFDIO_COPY` or by zero-filling
never-written chunks with `UFFDIO_ZEROPAGE`. It can also populate a bounded
forward window of adjacent cold chunks with `MAI_UFFD_PREFETCH_CHUNKS`; this is
spatial locality, not workload-specific prediction.

## Heartbeat Policy

`mai_heartbeat()` is an explicit epoch tick. It observes the protected pages
from the previous epoch, restores/clears that trace, and arms a bounded trace
set for the next epoch.

During a busy heartbeat, MAI does not perform heartbeat-driven demotion. It
records that sampled pages were touched and re-arms a smaller observation set.
Normal Linux memory management may still reclaim file-backed cache or enforce
host/cgroup pressure policy, but MAI does not enable, require, or guarantee
Linux swap. If active managed pages remain hot and no other MAI reclaim path
runs, pressure can still become ordinary kernel stalls or OOM behavior.

During a quiet heartbeat, MAI may demote chunk-sized ranges whose sampled
representative page was armed and not touched, capped by `migrate_bytes`. This
should be used at an application-defined quiescent boundary or in an explicit
opt-in experiment; sampled quietness is coldness evidence, not a guarantee that
other threads are not reading or writing the chunk.
For anonymous-first managed allocations, demotion writes the chunk to an
unlinked backing file and replaces that virtual address range with a
storage-backed `MAP_SHARED` mapping before advising the kernel that the range
can be reclaimed. By default, demotion waits for three quiet heartbeat
observations
(`MAI_HEARTBEAT_MIN_QUIET_EPOCHS=3`) to reduce false-cold migrations when an
application touches a middle or tail page in a chunk whose first page is the
representative. Heartbeat observation also rotates the representative page
within each chunk across epochs (first, middle, last) while keeping demotion
ranges chunk-aligned. This is sampled first-touch evidence, not proof that every
page in the chunk is cold.

Repeated access is observed by re-arming in later epochs. A repeatedly hot range
keeps producing sampled touches across epochs; an untouched representative page
can become a cold demotion candidate. `mprotect`/`SIGSEGV` observation does not
park mutator threads or make live remap/copy safe; autonomous background
promotion should queue candidates unless paired with userfaultfd, stop-the-world
suspension, or an application quiescent point.

`mai_prefetch()` is the explicit promotion path. If a requested managed range
contains storage-backed cold chunks, MAI copies the data through a temporary
mapping, remaps the chunk as anonymous memory at the same virtual address, and
then issues `MADV_WILLNEED` when available. This keeps application pointers
stable while restoring hot chunks to anonymous-memory bandwidth.

`mai_prepare_write()` is the overwrite path. If a cold range is known to be
fully overwritten before any read, MAI remaps it as anonymous memory without
copying stale storage contents. This avoids wasting I/O on dead values and is
the right primitive for predicted write-only phases such as STREAM `c = a + b`.

## Granularity

For per-allocation behavior, set `chunk_bytes` at or above the allocation size
so only the first full page represents that allocation call. For very large
allocations, lower `chunk_bytes` so one sample represents a bounded migration
unit.

When memory is below the full active working set, the policy should keep as
many whole hot regions resident as the cap safely allows and tile the rest at
`chunk_bytes` granularity. Assisted integrations can use `mai_prefetch()`,
`mai_prepare_write()`, and `mai_reclaim_range()` when the application genuinely
knows future range intent, but those calls are not used by the primary
no-oracle STREAM pressure benchmark.

## Policy Framework

The internal policy framework keeps mechanism and strategy separate. UFFD and
`mmap` code still decides how to restore, zero-fill, write-protect, and remap
chunks. The migration policy decides only which chunks to prefetch, whether to
admit them, and which resident chunk is the best demotion victim.

`MAI_MIGRATION_POLICY` (or the shorter alias `MAI_POLICY`) selects the current
runtime strategy:

- `legacy`: preserves the original fixed forward UFFD prefetch window and
  oldest-touch eviction behavior.
- `lru`: oldest-touch eviction with prefetch-aware accounting.
- `clock`: second-chance style eviction using per-chunk reference bits.
- `fifo`: evicts the oldest resident chunk by admission time.
- `random`: baseline random victim selection.
- `stream`: adaptive sequential prefetch; it grows the window only after
  repeated positive chunk deltas.
- `stride`: multi-stream stride prefetch; it tracks repeated per-allocation
  chunk deltas and prefetches along the highest-confidence stream.
- `2q`: first prefetch-aware admission baseline; prefetched chunks enter
  probation and are rejected when admitting them would exceed the resident
  limit.
- `lfu` or `decayed-lfu`: exact per-chunk decayed-frequency admission and
  victim selection baseline.
- `markov`, `successor`, or `successor-table`: one-successor transition
  predictor for repeated irregular chunk order.
- `spatial`, `spatial-mask`, or `region-mask`: per-allocation region-mask
  predictor for stable sparse spatial access inside fixed chunk groups.

All policies share append-only `MaiStats` counters for prefetch requests,
admissions, completions, useful prefetches, late demand faults, unused-prefetch
evictions, migration read/write bytes, demand-fault stalls, demotions, and
promotions. These counters are mechanism-derived and do not depend on benchmark
scenario names.
`policy_throttle_events` and `policy_throttle_slept_ns` are reserved for the
next bandwidth/stall-budget throttle; current policies use resident limits and
migration chunk size but do not yet report active throttle sleeps.

Read-only usefulness of a UFFD-prefetched chunk is not directly observable
without adding another faulting mechanism, because a successful prefetch avoids
the later missing-page fault. `MAI_POLICY_OBSERVE_PREFETCH_WRITES=1` adds
write-protection to prefetched chunks so write-heavy workloads can report
observed useful prefetches through UFFD write-protect faults. Leave it off for
default performance comparisons unless the benchmark explicitly studies
observation overhead. Benchmark fields named `*_observed` are therefore
observed lower bounds unless the row says
`policy_prefetch_observation=write_protect`.

## Algorithm Designs

| Family | Integrated policy design | MAI priority |
| --- | --- | --- |
| LRU, CLOCK, FIFO, Random | Demand faults admit chunks. Prefetch enters probation. Eviction uses oldest touch, second-chance reference bit, admission order, or random victim. Throttling is fixed by resident limits and migration chunk size. | Implemented as baselines. |
| LFU and decayed LFU | Track exact per-chunk frequency with lazy decay and ghost scores after eviction. Admit a prefetch under pressure only if its score beats the current victim or ties an unused/probation victim. Evict unused prefetches first, then low-frequency chunks. Optional write-protect observation can add one resident reuse signal but also adds handler overhead. | Implemented as `lfu`/`decayed-lfu`; approximate TinyLFU sketches remain future work. |
| 2Q | New or prefetched chunks enter a probation queue. A second demand touch promotes them to the protected set. Eviction demotes probation before protected chunks. | Implemented as a conservative admission baseline; queue refinement remains future work. |
| ARC, CAR, CART | Maintain recent and frequent resident sets plus ghost histories. Ghost hits tune the split between recency and frequency. Prefetched chunks never enter the frequent set until a demand touch confirms them. | Design target; CAR/CLOCK-style approximations are preferred before exact ARC. |
| LIRS, LRU-K | Protect chunks with low inter-reference recency or repeated Kth references. Demote high inter-reference recency chunks even if they were touched recently by a scan. | Simulator/reference first; exact LIRS metadata is too heavy for the initial C runtime. |
| Sequential readahead | Detect monotonic chunk faults and adapt the forward window with additive increase and multiplicative decrease from accuracy feedback. Admit only while headroom and budget permit. | Implemented as `stream` in first form. |
| Stride and multi-stream | Track several `{last, delta, confidence, window}` streams per allocation. Admit only after repeated deltas. Evict chunks far behind active streams. | Implemented as `stride` in first form. |
| Best-offset and multi-lookahead offset | Score candidate offsets by later demand hits. Prefetch the highest-confidence offsets, not necessarily the next chunk. | Useful for blocked and stencil-like patterns after stream baselines. |
| Markov and delta-correlation | Keep one bounded successor edge per chunk. Admit only repeated high-confidence successors, and require stronger confidence under resident pressure. | Implemented as `markov`/`successor` in first form; no fanout or chaining yet. |
| Signature/history-table | Use rolling delta signatures to predict multi-step sequences. Confidence controls depth and admission. | Later; best paired with a global budget and quick decay. |
| Spatial region masks | Divide allocations into fixed chunk regions and learn stable touched masks. A small tagged region table lets interleaved regions keep separate masks. Under pressure, same-region transitions may prefetch a learned mask, while inter-region transitions prefetch conservatively to limit pollution. | Implemented as `spatial`/`spatial-mask`; tune width, table slots, and confidence with `MAI_SPATIAL_REGION_CHUNKS`, `MAI_SPATIAL_TABLE_SLOTS`, `MAI_SPATIAL_LEARN_THRESHOLD`, and `MAI_SPATIAL_ADMIT_THRESHOLD`. |
| TinyLFU and frequency sketches | Use a compact approximate frequency sketch for admission. Compare candidate score against victim score to prevent pollution. | Important for hot/cold classification under mixed scans. |
| TPP/AutoNUMA-style tiering | Maintain high/low DRAM watermarks. Proactively demote cold chunks during quiet epochs, promote on demand, and keep headroom for new hot allocations. | Core design principle for MAI pressure handling. |
| Nomad-style shadowing | Keep valid clean storage shadows after promotion until a write invalidates them. Clean demotion can then avoid rewriting the chunk. | High-value write-amplification reduction, not yet implemented. |
| Application hints | Treat `mai_hint_range()`, `mai_prefetch()`, and `mai_prepare_write()` as confidence and intent signals, not commands that bypass budgets. | Supported primitives; not used by no-oracle claims. |
| Queue-aware policies | Accept future ranges with deadlines from schedulers. Admission depends on whether migration can finish before the request executes. | Integration API candidate, separate from autonomous benchmarks. |
| ML or bandit selector | Prefer a contextual bandit over neural prediction at first: choose among stream, stride, spatial, and admission thresholds from online metrics. | Later meta-policy after several concrete policies exist. |
| Programmable predictors | Let applications propose candidate ranges and confidence, while MAI owns admission, eviction, and throttling. | Later, for graph/database runtimes. |
| Prefetch-aware replacement | Track source, confidence, usefulness, and deadline for each prefetched chunk. Evict unused prefetched chunks before demand-confirmed chunks. | Implemented in first form through sidecar metadata and counters. |

The rotating-triplet STREAM benchmark allocates nine matrices grouped as
`ABC`, `DEF`, and `GHI`. It runs repeated STREAM-like kernels on one triplet,
then switches to the next triplet in either sequential or deterministic random
order. Each triplet visit runs the same four kernels as classic STREAM:
copy, scale, add, and triad. The benchmark does not call MAI range APIs and
does not reveal the next triplet to MAI. This is the preferred pressure
benchmark for autonomous migration strategy work because it directly models the
target case: one hot three-matrix working set should fit in physical memory
while the full nine-matrix set does not.

The autonomous MAI strategies tested by this benchmark are allocation-time
`MAI_BACKEND=auto` placement, allocator-time pressure demotion, cgroup/RSS
cap reclaim, and optional runtime-owned background heartbeat observation. The heartbeat is
controlled by environment variables such as
`MAI_HEARTBEAT_BACKGROUND_INTERVAL_US`,
`MAI_HEARTBEAT_BACKGROUND_OBSERVE_PAGES`,
`MAI_HEARTBEAT_BACKGROUND_CHUNK`, and
`MAI_HEARTBEAT_BACKGROUND_MIGRATE`; these describe observation budget and
granularity, not future access order.

## Benchmark Metrics

Benchmark rows must report both throughput and policy quality:

- observed prefetch accuracy: fault-observed useful prefetches divided by
  completed prefetches
- observed prefetch coverage: fault-observed useful prefetches divided by
  demand faults
- timeliness: prefetches useful before demand without a late fault
- DRAM pollution: bytes of unused prefetched chunks evicted before demand
- migration bandwidth: storage read plus write bytes per second
- MAI read amplification: MAI migration read bytes divided by logical workload
  bytes
- MAI write amplification: MAI migration write bytes divided by logical
  workload bytes
- handler-time reduction: UFFD handler time versus baseline pressure rows
- handler-tail latency: `policy_demand_fault_stall_p50_ns`,
  `policy_demand_fault_stall_p90_ns`, `policy_demand_fault_stall_p99_ns`, and
  `policy_demand_fault_stall_max_ns`
- effective capacity gain: pressure performance relative to sufficient-memory
  performance for the same workload, seed, binary, and host

The preferred no-oracle workload name is `policy_stream_pipeline`; it is an
alias of the rotating nine-matrix STREAM pipeline and intentionally does not
call MAI range APIs or expose future group order to the runtime. Docker
scenarios named `mai_policy_<policy>_pipeline`, such as
`mai_policy_stream_pipeline` or `mai_policy_clock_pipeline`, run this workload
with the corresponding runtime `MAI_MIGRATION_POLICY`.
`policy_multistream_stride` is a focused no-oracle predictor workload that
walks several fixed-size streams inside one allocation with non-unit deltas; use
it to compare `legacy`, `stream`, and `stride` without giving future ranges to
MAI. Its throughput is a policy-event metric, not a DRAM bandwidth metric,
because each unit touch samples one byte rather than sweeping complete arrays.
Use `policy_sampled_units_per_sec` and migration counters for this workload.
Set `MAI_BENCH_POLICY_ACTIVE_STREAMS=1` when you need a negative control where
adjacent forward prefetches are never consumed.
`policy_hotset_scan` is the corresponding no-oracle admission workload: it
reuses a small hot chunk set, scans colder chunks, and verifies whether policy
counters show less prefetch pollution and migration traffic. It is the preferred
first check for `2q` and `lfu`/`decayed-lfu`.
Current local smoke results show `lfu` with write-protect observation reducing
migration traffic versus `legacy` on this workload, but still trailing `2q` on
this small shape. Without observation, this first exact per-chunk LFU roughly
ties or trails the simpler policies. That result is expected and does not make
`lfu` the default policy.
`policy_successor_cycle` is the no-oracle irregular-transition workload for
`markov`/`successor`. It uses a deterministic successor cycle so simple
next-chunk and constant-stride predictors do not receive the same signal.
Current local smoke results show `markov` reducing demand faults versus
`stride` on this workload without increasing migration volume, with the best
throughput when write-protect observation is disabled. Observation mode is
still useful for accuracy counters, but it changes the measured cost.
`policy_spatial_region_mask` is the no-oracle sparse-region workload for
`spatial`/`spatial-mask`. It touches a stable set of offsets inside each
eight-unit region, but rotates and reverses in-region order across passes and
regions so next-chunk, constant-stride, and one-successor predictors do not get
the same signal. `policy_spatial_interleaved_mask` is the harder guardrail:
regions are interleaved, and at region widths of four chunks or larger,
alternating regions use different masks so a single allocation-wide mask would
overfetch. These are policy-event probes;
`logical_mib_per_sec` is synthetic logical progress because each unit touch
samples one byte.

Spatial-mask learning uses observed demand faults and optional write-protect
faults, not every CPU load/store. A successful resident read hit may therefore
be useful to the application without adding fresh spatial evidence. The tagged
table also has finite capacity: if active regions exceed
`MAI_SPATIAL_TABLE_SLOTS` (default 64, maximum 64), older masks churn and
prefetch quality can fall sharply. Use the interleaved workload with a reduced
table-slot setting to expose this cliff before claiming robustness on large
allocations.

On the local 64M allocation / 16M resident-limit shape with write-protect
observation disabled, six-run means on `policy_spatial_region_mask` were:
`spatial` 73 demand faults, 170 MiB migration reads, 182 MiB migration writes,
and 2204 logical MiB/s; `stream` was 96 faults, 168/180 MiB, and 3144 logical
MiB/s; `markov` was 95 faults, 174/186 MiB, and 2867 logical MiB/s. On
`policy_spatial_interleaved_mask`, `spatial` and `markov` both reduced demand
faults versus `stream` (67.0 and 67.3 versus 71.0), but `spatial` paid more
prefetch traffic. This makes the interleaved workload a pollution/timeliness
guardrail rather than a spatial victory lap.

## Benchmarks

Correctness tests stay deterministic:

- sufficient-memory fast path must not move reclaim counters
- sufficient-memory fast path must use anonymous managed allocations and avoid
  storage migration counters
- busy heartbeat with a migration budget must report `reclaimed_bytes=0`
- quiet heartbeat reclaimed bytes must scale with `chunk_bytes`

Scheduled/manual benchmarks collect timing evidence:

- native, preload-disabled, MAI pass-through, anonymous MAI-managed
  sufficient-memory, and legacy `MAI_BACKEND=file` runs for allocator and
  access-pattern workloads
- `trace_chunks` chunk sweeps for mprotect/SIGSEGV overhead
- `mprotect_overhead` phase sweeps comparing no observation, MAI direct trace,
  MAI heartbeat observation, and raw benchmark-local `mprotect`
- `heartbeat_busy` chunk sweeps showing active-access heartbeat cost and zero
  heartbeat reclaim
- Docker cgroup pressure benchmarks for over-physical-memory behavior

`reclaimed_bytes` is an accounting counter for ranges that MAI advised to the
kernel. It is not, by itself, proof that physical RSS dropped by the same
amount. Benchmark artifacts include RSS fields where MAI stats are available;
use cgroup or process residency measurements when validating actual pressure
relief.

These benchmarks provide reproducible observations for selected access
patterns. They are not portable performance guarantees; use machine-specific
baselines, variance, and workload-specific tuning before making performance
claims.

## References

- ARC: Adaptive Replacement Cache, FAST 2003.
  <https://www.cs.cmu.edu/~natassa/courses/15-721/papers/arcfast.pdf>
- LIRS: Efficient replacement using inter-reference recency.
  <https://ranger.uta.edu/~sjiang/pubs/papers/jiang02_LIRS.pdf>
- Linux `readahead(2)` manual.
  <https://man7.org/linux/man-pages/man2/readahead.2.html>
- Linux `userfaultfd` kernel documentation.
  <https://docs.kernel.org/admin-guide/mm/userfaultfd.html>
- TPP: Transparent Page Placement for CXL-enabled tiered memory.
  <https://arxiv.org/abs/2206.02878>
- HybridTier: adaptive lightweight CXL-memory tiering.
  <https://arxiv.org/abs/2312.04789>
- TinyLFU: frequency-based cache admission.
  <https://arxiv.org/abs/1512.00727>
