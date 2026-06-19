# Predictive Migration Design

MAI uses anonymous-first managed allocations by default. Predictive migration
is an experimental policy layer that decides when cold chunks should be
demoted to storage-backed mappings and when predicted-hot chunks should be
promoted back to anonymous memory. It is not a correctness requirement and not
a performance guarantee.

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
