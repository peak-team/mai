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
`mai_prepare_write()`, `mai_reclaim_range()`, and advisory `mai_hint_range()`
when the application genuinely knows future range intent, but those calls are
not used by the primary no-oracle STREAM pressure benchmark.

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
- `lruk`, `lru-k`, `lru2`, or `lru-2`: compact LRU-2 reuse-distance
  replacement with ghost history across demotion.
- `irr`, `inter-reference-recency`, `lirs-lite`, `lirs_approx`, or
  `lirs-irr`: experimental LIRS-inspired inter-reference-recency replacement.
  It keeps compact two-touch history and demand-confirmed ghosts, protects
  low-interval chunks, and rejects immature pressured prefetches. It is not an
  exact LIRS stack implementation; the `lirs-*` aliases are compatibility
  labels for this approximation only.
- `arc`, `adaptive-replacement-cache`, or `adaptive_replacement_cache`:
  experimental bounded ARC replacement. Demand misses enter T1, demand
  confirmation promotes chunks to T2, B1/B2 ghost hits tune the target split,
  and prefetched chunks remain T1/probationary until a demand touch confirms
  them.
- `car`, `car-lite`, `clock-pro`, or `clockpro`: compact CAR/CLOCK-Pro-style
  adaptive replacement with recent/frequent ghost feedback.
- `markov`, `successor`, or `successor-table`: one-successor transition
  predictor for repeated irregular chunk order.
- `markov-phase`, `markov_phase`, `phase-hold-markov`, or
  `phase_hold_markov`: Markov successor prediction plus phase-transition
  learning and hold/protection. The raw runtime policy disables cross-record phase prefetch by default; set
  `MAI_POLICY_PHASE_PREFETCH=1` to measure Markov plus full phase prefetch.
- `markov-cohort`, `markov_cohort`, `successor-cohort`,
  `successor_cohort`, `phase-cohort`, or `phase_cohort`: experimental
  Markov-primary policy that may append one learned cross-allocation cohort
  lease after same-record successor candidates.
- `spatial`, `spatial-mask`, or `region-mask`: per-allocation region-mask
  predictor for stable sparse spatial access inside fixed chunk groups.
- `tinylfu`, `tiny-lfu`, or `sketch-lfu`: compact Count-Min-style admission
  classifier trained only by demand-observed chunk touches.
- `wtinylfu`, `w-tinylfu`, `window-tinylfu`, or `window-tiny-lfu`: W-TinyLFU
  approximation with demand-trained sketch admission, a small recency window,
  prefetch probation, and protected demand-confirmed chunks.
- `best-offset`, `bestoffset`, `offset`, or `offset-prefetch`: demand-trained
  top-offset prefetcher for recurring non-adjacent chunk offsets.
- `signature`, `delta-chain`, `history-table`, or `history`: rolling
  two-delta signature table for context-dependent successor prediction.
- `hybrid`, `meta`, `meta-prefetch`, `hybrid-wtinylfu`, or `predictor-meta`:
  experimental meta policy that ranks signature, successor, and stream
  candidates, then gates admission with W-TinyLFU-style frequency and victim
  checks.
- `hinted`, `hint`, `application-hinted`, `application_hinted`,
  `app-hinted`, or `app_hinted`: opt-in application-hinted policy. It currently
  interprets `MAI_HINT_SEQUENTIAL` ranges, emits bounded forward candidates
  inside the hinted range, and still applies adaptive migration-debt,
  resident-pressure, and victim-quality admission gates. It is not used in
  no-oracle comparisons.

For `wtinylfu`, `MAI_POLICY_WTINYLFU_WINDOW_PERCENT=N` controls the target
window share of resident capacity. The default is 25. Demand faults always
populate; speculative prefetches must carry Markov/stream confidence and, under
pressure, must beat the victim score unless the victim is unused/probationary.
For `markov`, `markov-cohort`, `wtinylfu`, `signature`, and `hybrid`,
`MAI_POLICY_SUCCESSOR_CHAIN_DEPTH=N` can follow high-confidence predicted edges
beyond the immediate next chunk. The default is 1, preserving one-step
behavior.
For `best-offset`, `MAI_POLICY_BEST_OFFSET_MIN_CHUNKS=N` can exclude nearby
offsets from training and candidate emission. The default `0` uses the current
`MAI_UFFD_PREFETCH_CHUNKS` window as the floor, keeping adjacent chunks in the
stream/stride policy domain.
For `phase` and `markov-phase`, `MAI_POLICY_PHASE_PREFETCH=0` keeps phase
learning and record-hold protection but suppresses cross-record phase
prefetches. `MAI_POLICY_PHASE_PREFETCH_BOUNDARY_ONLY=1` allows cross-record
phase prefetches only near the end of the current source allocation, controlled
by `MAI_POLICY_PHASE_BOUNDARY_CHUNKS`. The opt-in
`MAI_POLICY_PHASE_SHADOW_PROBE_CHUNKS=N` knob admits at most `N` otherwise
suppressed non-boundary phase candidates per demand-fault planning step. Adding
`MAI_POLICY_PHASE_SHADOW_PROBE_MIN_LATE=M` requires the same learned phase edge
to accumulate at least `M` late shadow confirmations before a non-boundary probe
is eligible. These knobs are experimental ablation controls.

All policies share append-only `MaiStats` counters for prefetch requests,
admissions, completions, useful prefetches, late demand faults, unused-prefetch
evictions, migration read/write bytes, demand-fault stalls, demotions, and
promotions. Boundary-only phase mode also reports `policy_phase_shadow_*`
counters for non-boundary phase candidates that were suppressed rather than
migrated: candidates, later useful touches, late demand-fault touches, shadows
retired by age, eviction, or free, overwritten shadow-edge metadata, emitted
edge-confirmed probes, edge-threshold rejections, edge confirmations, live top
late count, and cumulative max late count. These are counterfactual diagnostics;
only the explicit probe knobs can turn a confirmed shadow edge into a prefetch
candidate. Async UFFD policy work also
reports enqueued, completed, and dropped task counters. These counters are
mechanism-derived and do not depend on benchmark scenario names.
`policy_throttle_events` reports bounded-queue drops and resident-limit hard
reclaim events. When `MAI_POLICY_ADAPTIVE_CONTROL=1` is enabled, adaptive
behavior is also broken out into `policy_adaptive_windows`,
`policy_adaptive_level`, `policy_adaptive_level_changes`,
`policy_adaptive_prefetch_capped`, and
`policy_adaptive_admission_rejected`. Opt-in clean-shadow tracking reports
`policy_clean_shadow_tracked_chunks`,
`policy_clean_shadow_protect_failures`,
`policy_clean_shadow_write_skipped_bytes`,
`policy_clean_shadow_write_skipped_chunks`, and
`policy_clean_shadow_write_faults`. CAR-lite reports current recent/frequent
resident and ghost chunk counts, recent/frequent ghost hits, target movement,
and second-chance scans through `policy_car_*` counters. ARC uses separate
bounded T1/T2/B1/B2 metadata and reports target, ghost-hit, replacement,
pruning, and prefetch-promotion activity through `policy_arc_*` counters.
TinyLFU reports sketch updates, sketch decays, sketch admission rejects, and
the current minimum admission score through `policy_tinylfu_*` counters.
W-TinyLFU reuses the TinyLFU sketch counters and reports current
window/probation/protected chunk counts, window evictions, main-admission
rejects, and victim-score rejects through `policy_wtinylfu_*` counters.
Successor-chain lookahead reports emitted deeper-chain candidates, rejected
chain candidates, and configured depth through `policy_successor_chain_*`
counters.
Best-offset reports training samples, validated training hits, created offset
slots, score decays, emitted candidates, rejected candidates,
unused-prefetch penalties, and the top learned forward offset through
`policy_bestoffset_*` counters.
Signature/history-table reports training samples, validated hits, installed
signature slots, score decays, emitted candidates, depth-greater-than-one
chain candidates, pressure rejects, unused-prefetch penalties, rejected chain
candidates, configured depth, and the top learned delta through
`policy_signature_*` counters.
Hybrid/meta reports candidate sources, integrated admission rejects, and
source-attributed admitted/completed/useful prefetches through
`policy_hybrid_*` counters, including the cross-record cohort source used for
allocation-record tile transitions. The regular `policy_signature_*`,
`policy_tinylfu_*`, and `policy_wtinylfu_*` counters remain active because the
hybrid policy trains those components directly.
Hinted policy reports `policy_hint_candidates`, `policy_hint_admitted`,
`policy_hint_completed`, `policy_hint_useful`, and `policy_hint_rejected`.
These counters are source-attributed through the common prefetch-completion
path, so they can be compared with global accuracy, coverage, amplification,
and stall counters.
`policy_throttle_events` reports queue pressure, hard reclaim, adaptive
prefetch caps, and budget-gated admission rejects. `policy_throttle_slept_ns`
remains zero for the current UFFD policy path by design: MAI rejects or shrinks
speculative work instead of sleeping in the fault handler. When
`MAI_POLICY_ADAPTIVE_BUDGET_GATE=1` is enabled, MAI also exposes
`policy_adaptive_budget_gate`, `policy_adaptive_budget_bytes`, and
`policy_adaptive_window_migration_bytes` so benchmark rows can distinguish
ordinary adaptive control from an explicit migration-debt throttle.

`MAI_UFFD_ASYNC_PREFETCH=1` enables an experimental UFFD background policy
worker. Demand faults are still resolved synchronously. The worker only moves
speculative prefetch and follow-on reclaim work off the fault handler, bounded
by `MAI_UFFD_ASYNC_SLACK_CHUNKS` and the resident high/low watermarks. Async
tasks preserve per-candidate allocation identity, so hybrid cross-record cohort
targets are validated against live allocation sequence numbers before the
worker admits them. `MAI_UFFD_ASYNC_QUEUE_LIMIT=N` can cap the fixed async
queue below its compile-time capacity; `0` is useful for deterministic
saturation tests. If the async queue is saturated, MAI drops speculative async
prefetch for that access and performs only required reclaim instead of falling
back to synchronous speculative prefetch. `policy_async_prefetch_completed`
counts tasks that actually populate at least one prefetched chunk; reclaim-only
or stale tasks are counted as drops. Async is not a default policy because it
can help admission-heavy policies while hurting policies whose synchronous
forward prefetch is already cheap.

`MAI_RECORD_PROTECT_EPOCHS=N` enables an experimental record-aware eviction
bias for prefetch-aware policies. A record is an allocation call, so this
protects demand-confirmed chunks from allocations that recently faulted while
still letting unused prefetched chunks be reclaimed first. It is generic
allocation-level recency, not a benchmark group hint, and defaults to zero
because stale record protection can preserve scan pollution. The `legacy`
baseline is excluded so its oldest-touch behavior remains stable; `random`
does not use ordered victim classes, and CLOCK's fallback pass may bypass the
record bias after second-chance references are cleared.

`MAI_ACTIVE_RECORD_EPOCHS=N` enables a stronger active-working-set controller.
It treats allocation records with recent demand faults as the current active
set, raises the UFFD reclaim low watermark to active resident
demand-confirmed chunks plus `MAI_ACTIVE_RECORD_SLACK_CHUNKS`, prefers
inactive records as demotion victims, and rejects speculative prefetches if the
only available victims are demand-confirmed chunks from active records. This is
still workload-agnostic: the runtime only sees demand-fault recency, not
benchmark group names or future access order. It defaults to zero because long
active windows can preserve scan pollution and because raising the low
watermark uses more DRAM headroom.

`MAI_POLICY_ADAPTIVE_CONTROL=1` enables an opt-in feedback controller around
prefetch admission and window size. It watches recent demand faults,
unused-prefetch evictions, hot-evicted bytes, migration bytes, and
demand-fault stall time. When speculation appears harmful, it first trims the
prefetch window and then requires stronger predictor confidence before
admission. Cohort prefetches rejected only because adaptive pressure raised the
confidence threshold are counted in both hybrid and adaptive rejection counters.
Without write-protect observation, MAI cannot reliably prove that a resident
prefetched chunk was unused before eviction, so adaptive control treats
unused-prefetch evictions as pollution only when prefetch feedback is observable
and otherwise relies on late faults, hot evictions, and migration debt. This
keeps unobserved read/write hits from falsely throttling the predictor.
It does not act on the `legacy` baseline because fixed next-block prefetch has
no confidence model. Tune sensitivity with
`MAI_POLICY_ADAPTIVE_WINDOW_FAULTS` and
`MAI_POLICY_ADAPTIVE_MIGRATION_BUDGET_CHUNKS`.
`MAI_POLICY_ADAPTIVE_BUDGET_GATE=1` enables a stricter experimental gate for
adaptive policies. The gate treats migration-byte debt, hot evictions, and async
queue pressure as direct throttling inputs. It can cap speculative prefetch to a
single candidate or reject admission before a new prefetch is expected to exceed
the current migration budget; required demand population and required reclaim
still proceed. High-confidence Markov successor candidates get a narrow
timeliness credit: when two already-observed same-record successor edges are
both high confidence, MAI may append exactly one second-hop lead candidate even
when `MAI_POLICY_SUCCESSOR_CHAIN_DEPTH` remains at its default of `1`. The lead
candidate is still probationary, still needs admission/victim checks, and is
reported through `policy_markov_lead_candidates`,
`policy_markov_lead_admitted`, `policy_markov_lead_completed`, and
`policy_markov_lead_useful`. Retained-run aliases such as
`markov_budget_adaptive`,
`hybrid_budget_adaptive`, and `markov_cohort_budget_adaptive` enable this gate
through the benchmark runner. Aliases ending in `_lead_budget_adaptive`, such
as `markov_lead_budget_adaptive`, also force chain depth back to `1` so the
`policy_markov_lead_*` counters measure the single-slot lead mechanism instead
of ordinary opt-in successor-chain lookahead.

`MAI_MIGRATION_POLICY=phase` enables an experimental allocation-record phase
predictor. It learns immediate transitions between live UFFD allocation records
with the same chunk size, predicts the target chunk at the observed offset, and
admits only bounded cross-record companion prefetches through the normal
adaptive budget, active-record victim, and TinyLFU victim gates. Phase-prefetch
chunks carry their own source tag and counters:
`policy_phase_candidates`, `policy_phase_admitted`,
`policy_phase_completed`, `policy_phase_useful`,
`policy_phase_unused_evictions`, and rejection/table-health diagnostics. Under
pressure, phase candidates with observed conflicts are rejected, and a
dead-on-arrival gate suppresses the predictor after repeated completed
phase-prefetches are evicted unused. This keeps the policy workload-agnostic
while limiting DRAM pollution on random phase orders.

`MAI_MIGRATION_POLICY=hinted` enables the first implemented
application-hinted policy. A sequential hint does not directly migrate memory;
it only lets the policy build forward candidates inside the hinted range.
Admission remains pressure-aware: candidates can be rejected by adaptive
migration debt, high throttle level, lack of confidence, or inability to beat
the current victim class. This keeps hints from acting as an oracle that can
force DRAM pollution. Hinted rows must be reported separately from no-oracle
strategy rows.

Read-only usefulness of a UFFD-prefetched chunk is not directly observable
without adding another faulting mechanism, because a successful prefetch avoids
the later missing-page fault. `MAI_POLICY_OBSERVE_PREFETCH_WRITES=1` adds
write-protection to prefetched chunks so write-heavy workloads can report
observed useful prefetches through UFFD write-protect faults. Leave it off for
default performance comparisons unless the benchmark explicitly studies
observation overhead. Benchmark fields named `*_observed` are therefore
observed lower bounds unless the row says
`policy_prefetch_observation=write_protect`.

`MAI_UFFD_CLEAN_SHADOW=1` enables opt-in clean storage-shadow tracking for the
UFFD pager. When a cold chunk is restored from storage, MAI maps it
write-protected before waking the faulting thread. If the kernel cannot do the
restore and write-protect atomically, MAI records a protect failure and does
not mark that chunk clean. If a tracked chunk is demoted again without a
write-protect fault, MAI skips the storage write because the existing shadow is
still valid. The first write clears the clean bit and the next demotion writes
the dirty chunk normally. This can reduce write amplification for read-mostly
reuse, but it adds write-protect faults to write-heavy reuse and is not a
default performance mode.

## Benchmark And Planning Material

Retained benchmark results, benchmark protocols, and future strategy plans are
kept outside the implementation repository in the companion `mai_benchmark`
workspace. This document intentionally describes only the runtime mechanisms,
policy selectors, and exported counters that are implemented in MAI.
