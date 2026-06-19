# Policy Benchmark Results

These are local six-run means from the `predictive-migration-policy` branch on
June 19, 2026. They are evidence for this host and build, not portable
performance guarantees.

Component pressure rows use:

- `MAI_BACKEND=auto`
- `MAI_UFFD_PAGER=required`
- `MAI_UFFD_RESIDENT_LIMIT=16M`
- `MAI_UFFD_RESIDENT_LOW_LIMIT=12M`
- `MAI_MIGRATION_CHUNK=2M`
- `MAI_UFFD_PREFETCH_CHUNKS=4`
- `MAI_POLICY_OBSERVE_PREFETCH_WRITES=0`

The policy-event workloads touch one byte per unit and report synthetic
logical progress. Use their demand faults, migration bytes, prefetch counters,
and relative event rate. Use `stream_bandwidth` for pure sustained
memory-bandwidth claims, and the 9-matrix STREAM pipeline for end-to-end
STREAM-like migration throughput.

The component pressure matrix is evidence for individual predictors. The
9-matrix `policy_stream_pipeline` pressure rows below are the current
end-to-end no-oracle migration check and show that the full STREAM migration
goal is not solved yet.

## Sufficient Memory Baseline

These rows have no UFFD demand faults or MAI migration bytes. `stream_bandwidth`
uses a 128 MiB allocation argument; `policy_stream_pipeline` uses 32 MiB per
matrix; policy-event probes use 64 MiB.

| Workload | Native end-to-end MiB/s | MAI sufficient end-to-end MiB/s | MAI migration read/write MiB |
| --- | ---: | ---: | ---: |
| `stream_bandwidth` | 23996 | 30208 | 0 / 0 |
| `policy_stream_pipeline` | 29886 | 31878 | 0 / 0 |
| `policy_multistream_stride` | 211997 | 228259 | 0 / 0 |
| `policy_hotset_scan` | 121559 | 120604 | 0 / 0 |
| `policy_successor_cycle` | 232158 | 219497 | 0 / 0 |
| `policy_spatial_region_mask` | 252283 | 258138 | 0 / 0 |
| `policy_spatial_interleaved_mask` | 285182 | 246678 | 0 / 0 |

For the matching 9-matrix pipeline shape used below
(`policy_stream_pipeline 16M`, random no-repeat group order, four group
iterations), sufficient-memory means were:

| Scenario | End-to-end MiB/s | Kernel MiB/s | MAI migration read/write MiB |
| --- | ---: | ---: | ---: |
| native | 29409 | 39940 | 0 / 0 |
| MAI pass-through | 33359 | 42384 | 0 / 0 |
| MAI managed sufficient | 35551 | 43228 | 0 / 0 |

## Pressure Matrix

| Workload | Policy | Events/s | Demand faults | Read MiB | Write MiB | Unused prefetch evictions |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `policy_multistream_stride` | `legacy` | 428 | 64 | 448 | 500 | 187 |
| `policy_multistream_stride` | `stream` | 74622 | 8 | 0 | 0 | 0 |
| `policy_multistream_stride` | `stride` | 107562 | 5 | 0 | 0 | 0 |
| `policy_multistream_stride` | `2q` | 13356 | 9 | 2 | 24 | 9 |
| `policy_multistream_stride` | `lfu` | 420 | 64 | 448 | 500 | 189 |
| `policy_multistream_stride` | `markov` | 63988 | 8 | 0 | 0 | 0 |
| `policy_multistream_stride` | `spatial` | 74923 | 8 | 0 | 0 | 0 |
| `policy_hotset_scan` | `legacy` | 2582 | 25 | 136 | 188 | 70 |
| `policy_hotset_scan` | `stream` | 2429 | 63 | 138 | 190 | 36 |
| `policy_hotset_scan` | `stride` | 2608 | 54 | 140 | 192 | 45 |
| `policy_hotset_scan` | `2q` | 2538 | 65 | 140 | 191 | 37 |
| `policy_hotset_scan` | `lfu` | 2736 | 25 | 136 | 188 | 72 |
| `policy_hotset_scan` | `markov` | 2436 | 89 | 138 | 186 | 11 |
| `policy_hotset_scan` | `spatial` | 2245 | 59 | 156 | 208 | 49 |
| `policy_successor_cycle` | `legacy` | 639 | 192 | 1216 | 1268 | 445 |
| `policy_successor_cycle` | `stream` | 1406 | 256 | 448 | 498 | 0 |
| `policy_successor_cycle` | `stride` | 1391 | 256 | 448 | 498 | 0 |
| `policy_successor_cycle` | `2q` | 1208 | 238 | 636 | 684 | 112 |
| `policy_successor_cycle` | `lfu` | 627 | 192 | 1182 | 1234 | 429 |
| `policy_successor_cycle` | `markov` | 1656 | 193 | 450 | 498 | 63 |
| `policy_successor_cycle` | `spatial` | 816 | 231 | 940 | 988 | 267 |
| `policy_spatial_region_mask` | `legacy` | 748 | 61 | 368 | 420 | 151 |
| `policy_spatial_region_mask` | `stream` | 1488 | 96 | 168 | 180 | 0 |
| `policy_spatial_region_mask` | `stride` | 1444 | 96 | 170 | 180 | 1 |
| `policy_spatial_region_mask` | `2q` | 1255 | 94 | 240 | 276 | 51 |
| `policy_spatial_region_mask` | `lfu` | 693 | 67 | 402 | 454 | 164 |
| `policy_spatial_region_mask` | `markov` | 1327 | 95 | 174 | 186 | 4 |
| `policy_spatial_region_mask` | `spatial` | 1518 | 73 | 170 | 182 | 22 |
| `policy_spatial_interleaved_mask` | `legacy` | 446 | 93 | 632 | 682 | 250 |
| `policy_spatial_interleaved_mask` | `stream` | 1998 | 71 | 118 | 126 | 0 |
| `policy_spatial_interleaved_mask` | `stride` | 1973 | 70 | 134 | 148 | 9 |
| `policy_spatial_interleaved_mask` | `2q` | 1451 | 75 | 180 | 216 | 39 |
| `policy_spatial_interleaved_mask` | `lfu` | 472 | 92 | 602 | 652 | 238 |
| `policy_spatial_interleaved_mask` | `markov` | 2117 | 67 | 116 | 125 | 3 |
| `policy_spatial_interleaved_mask` | `spatial` | 1755 | 67 | 144 | 156 | 15 |

## 9-Matrix Pipeline Pressure

These rows use `policy_stream_pipeline 16M`, random no-repeat group order,
four group iterations, 64 MiB resident high watermark, and 48 MiB resident low
watermark. The active triplet is 48 MiB and the full nine-matrix set is
144 MiB.

| Policy | End-to-end MiB/s | E2E SD | Kernel MiB/s | E2E/kernel | Demand faults | Read MiB | Write MiB | Unused prefetch evictions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `legacy` | 8133 | 691 | 24277 | 0.34 | 48 | 240 | 336 | 126 |
| `stream` | 7746 | 258 | 20539 | 0.38 | 158 | 280 | 364 | 54 |
| `stride` | 6894 | 257 | 17626 | 0.39 | 138 | 346 | 432 | 107 |
| `2q` | 6024 | 261 | 16479 | 0.37 | 137 | 534 | 630 | 202 |
| `lfu` | 6957 | 206 | 14448 | 0.48 | 94 | 402 | 491 | 176 |
| `markov` | 7825 | 473 | 23207 | 0.34 | 175 | 246 | 342 | 20 |
| `spatial` | 7355 | 454 | 22477 | 0.33 | 113 | 296 | 380 | 86 |

### Low-Watermark Slack Probe

These rows keep the same workload, resident high watermark, seed, and chunk
size, but raise the low watermark from 48 MiB to 64 MiB. This preserves more
headroom around the active 48 MiB triplet instead of reclaiming immediately
back to the triplet size.

| Policy | End-to-end MiB/s | E2E SD | Kernel MiB/s | E2E/kernel | Demand faults | Read MiB | Write MiB | Unused prefetch evictions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `legacy` | 8255 | 851 | 23477 | 0.35 | 48 | 240 | 320 | 120 |
| `stream` | 6118 | 411 | 23523 | 0.26 | 186 | 592 | 672 | 179 |
| `stride` | 6040 | 524 | 20804 | 0.29 | 182 | 642 | 722 | 206 |
| `2q` | 8239 | 326 | 24475 | 0.34 | 168 | 240 | 320 | 24 |
| `lfu` | 7527 | 377 | 19115 | 0.39 | 156 | 308 | 388 | 86 |
| `markov` | 8452 | 427 | 25839 | 0.33 | 192 | 240 | 320 | 0 |
| `spatial` | 5140 | 339 | 10629 | 0.48 | 443 | 970 | 1050 | 259 |

### Async UFFD Policy Worker Probe

These rows use the original 64 MiB high / 48 MiB low watermark pressure shape.
`MAI_UFFD_ASYNC_PREFETCH=1` moves speculative prefetch and follow-on reclaim to
a bounded background worker; demand faults are still resolved synchronously.
The async counters verify that the worker actually executed.

| Async | Policy | End-to-end MiB/s | Kernel MiB/s | Demand faults | Read MiB | Write MiB | Stall ms | Async tasks completed |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| off | `legacy` | 7719 | 23408 | 48 | 240 | 336 | 154 | 0 |
| on | `legacy` | 7524 | 23224 | 109 | 288 | 373 | 110 | 105 |
| off | `markov` | 7792 | 22743 | 175 | 246 | 342 | 131 | 0 |
| on | `markov` | 6836 | 19728 | 190 | 244 | 337 | 123 | 74 |
| off | `2q` | 5635 | 15986 | 137 | 534 | 630 | 231 | 0 |
| on | `2q` | 7105 | 17865 | 147 | 337 | 427 | 140 | 137 |

### Record-Aware Eviction Probe

`MAI_RECORD_PROTECT_EPOCHS` biases eviction away from demand-confirmed chunks
in allocation records that recently faulted, while still letting unused
prefetched chunks be evicted first. These rows keep async prefetch disabled.
`legacy` is excluded from the record bias so it remains a stable baseline; its
row movement below reflects run variance because the migration counters do not
change.

| Low watermark | Policy | Protect epochs | End-to-end MiB/s | Kernel MiB/s | Demand faults | Read MiB | Write MiB | Unused evictions | Stall ms |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 48 MiB | `legacy` | 0 | 7695 | 23634 | 48 | 240 | 336 | 126 | 155 |
| 48 MiB | `legacy` | 32 | 8527 | 26014 | 48 | 240 | 336 | 126 | 145 |
| 48 MiB | `markov` | 0 | 7140 | 21651 | 175 | 246 | 342 | 20 | 147 |
| 48 MiB | `markov` | 32 | 7570 | 22478 | 175 | 246 | 342 | 20 | 137 |
| 48 MiB | `2q` | 0 | 5568 | 15320 | 137 | 534 | 630 | 202 | 232 |
| 48 MiB | `2q` | 8 | 5709 | 15826 | 138 | 534 | 630 | 201 | 225 |
| 64 MiB | `legacy` | 0 | 7861 | 22896 | 48 | 240 | 320 | 120 | 134 |
| 64 MiB | `legacy` | 32 | 7738 | 23241 | 48 | 240 | 320 | 120 | 137 |
| 64 MiB | `markov` | 0 | 8190 | 24829 | 192 | 240 | 320 | 0 | 119 |
| 64 MiB | `markov` | 32 | 6814 | 20799 | 192 | 240 | 320 | 0 | 151 |
| 64 MiB | `2q` | 0 | 7904 | 22798 | 168 | 240 | 320 | 24 | 131 |
| 64 MiB | `2q` | 8 | 7940 | 23852 | 168 | 240 | 320 | 24 | 128 |

With async prefetch enabled on the 48 MiB low-watermark shape, `2q` improved
from 6700 MiB/s at protect 0 to 7328 MiB/s at protect 8, then regressed to
6314 MiB/s at protect 32. The two knobs can compose, but the useful range is
narrow.

### Active-Record Working-Set Probe

`MAI_ACTIVE_RECORD_EPOCHS` coordinates admission, eviction, and the UFFD
reclaim floor around allocation records that recently had demand faults. These
rows use the same no-oracle 9-matrix pressure shape as above, async prefetch
disabled, `MAI_MAX_RSS=128M`, and a valid `MAI_RECLAIM_POLICY=donthneed`.
The first benchmark attempt used the invalid spelling `dontneed`; those rows
were discarded because MAI reported zero managed allocations and zero migration.

| Policy | Active epochs | Slack chunks | End-to-end MiB/s | E2E SD | Kernel MiB/s | Demand faults | Read MiB | Write MiB | Stall ms | Stall p99 ns | Unused evictions | Hot-evicted MiB | Admission rejects |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `legacy` | 0 | 0 | 6040 | 734 | 12479 | 54 | 288 | 384 | 166 | 8388608 | 144 | 96 | 0 |
| `legacy` | 8 | 4 | 6295 | 232 | 13017 | 54 | 288 | 384 | 161 | 9786709 | 144 | 96 | 0 |
| `markov` | 0 | 0 | 5672 | 301 | 11185 | 201 | 310 | 396 | 153 | 4194304 | 26 | 344 | 6 |
| `markov` | 32 | 4 | 6161 | 306 | 12748 | 216 | 288 | 368 | 140 | 1048576 | 0 | 368 | 63 |

This is a useful opt-in control, not a default. It improves the corrected local
six-run `legacy` and `markov` rows, but still reaches only about 17-18% of the
matching MAI-managed sufficient-memory end-to-end baseline. For `markov`, the
controller trades unused-prefetch evictions for more demand-confirmed hot
evictions while reducing migration bytes and tail stall; that tradeoff needs
broader seed and pressure sweeps before it can be promoted.

### Adaptive Admission/Throttle Probe

`MAI_POLICY_ADAPTIVE_CONTROL=1` adds a closed-loop admission and prefetch-window
controller around confidence-bearing predictors. It is intentionally opt-in and
does not act on the `legacy` baseline, because fixed next-block prefetch has no
confidence signal to raise or lower. The current default uses a 16-fault
feedback window and a 16-chunk migration-debt budget. These rows use
`markov`, `MAI_ACTIVE_RECORD_EPOCHS=32`, `MAI_ACTIVE_RECORD_SLACK_CHUNKS=4`,
a 64 MiB resident high watermark, a 48 MiB low watermark, 16 MiB matrices,
random-no-repeat seeds `1,7,13,29,31,43`, 12 outer cycles, and four group
iterations.

| Adaptive | End-to-end MiB/s | Kernel MiB/s | Demand faults | Prefetches | Unused evictions | Read MiB | Write MiB | Hot-evicted MiB | Max-cycle stall ms | Max-cycle read MiB | Max-cycle write MiB | Adaptive windows | Adaptive rejects |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| off | 9818 | 12504 | 416.7 | 63.2 | 62.2 | 815.7 | 895.7 | 771.3 | 28.2 | 71.0 | 77.0 | 0.0 | 0.0 |
| on | 10106 | 12865 | 418.3 | 35.7 | 35.7 | 764.0 | 844.0 | 772.7 | 25.1 | 68.7 | 76.7 | 25.5 | 62.0 |

This is a modest, variance-sensitive result: end-to-end throughput improved by
about 3% on this slice, while migration reads and writes each fell by about
52 MiB and max-cycle stall fell by about 3 ms. Hot-evicted bytes were nearly
flat. The row supports the narrow claim that migration-debt feedback can reduce
admitted useless prefetches and phase-transition traffic for `markov`; it is
not proof that MAI is close to the sufficient-memory baseline.

### Clean-Shadow Smoke Check

`MAI_UFFD_CLEAN_SHADOW=1` keeps valid storage shadows for restored chunks and
uses UFFD write-protect to invalidate the shadow on first write. This local
smoke check used six runs of `policy_successor_cycle 16M`,
`MAI_UFFD_RESIDENT_LIMIT=2M`, `MAI_UFFD_RESIDENT_LOW_LIMIT=2M`,
`MAI_UFFD_PREFETCH_CHUNKS=1`, and `MAI_MIGRATION_CHUNK=2M`. It is a mechanism
check, not a broad performance claim.

| Clean shadow | End-to-end MiB/s | Read MiB | Write MiB | Write amplification | Tracked chunks | Skipped write MiB | Write faults | Protect failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| off | 4109 | 80 | 94 | 0.979 | 0 | 0 | 0 | 0 |
| on | 4879 | 80 | 48 | 0.500 | 24 | 46 | 0 | 0 |

The result confirms the intended accounting: clean-shadow did not reduce read
traffic, but it skipped 23 clean demotion writes and cut write amplification by
about half on this read-mostly reuse pattern. Write-heavy reuse still needs a
separate benchmark because its first post-restore write pays a UFFD
write-protect fault.

A three-seed spot check on the write-heavy 9-matrix STREAM pipeline with
`markov`, active-record control, adaptive admission, 64 MiB high / 48 MiB low
watermarks, and 12 random-no-repeat cycles reduced migration writes but did not
improve throughput. Mean end-to-end throughput was about 9356 MiB/s with
clean-shadow off and 9038 MiB/s with it on. That supports keeping clean-shadow
off by default for STREAM-like write-heavy workloads.

### LRU-K Reuse-Distance Probe

`MAI_MIGRATION_POLICY=lruk` is an opt-in LRU-2 approximation. It keeps compact
two-reference history across demotion and uses that Kth-reference epoch for
admission and eviction. The phase-shift workload warms hotset A, switches to
hotset B, scans colder chunks, and verifies only the new hotset. These six-run
means use `policy_phase_shift_hotset 64M`, 2 MiB units, 8 MiB hotsets, an 8 MiB
resident high watermark, and a 6 MiB low watermark.

| Workload | Policy | Events/s | Demand faults | Read MiB | Write MiB | Admission rejects | Unused evictions | Hot-evicted MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `policy_hotset_scan` | `legacy` | 2505 | 50 | 136 | 194 | 0 | 48 | 98 |
| `policy_hotset_scan` | `2q` | 2299 | 98 | 136 | 192 | 93 | 2 | 188 |
| `policy_hotset_scan` | `lfu` | 2292 | 67 | 138 | 194 | 31 | 34 | 126 |
| `policy_hotset_scan` | `lruk` | 2401 | 98 | 136 | 192 | 93 | 2 | 188 |
| `policy_phase_shift_hotset` | `legacy` | 3297 | 46 | 120 | 178 | 0 | 44 | 90 |
| `policy_phase_shift_hotset` | `2q` | 3248 | 90 | 120 | 176 | 85 | 2 | 172 |
| `policy_phase_shift_hotset` | `lfu` | 3212 | 50 | 124 | 182 | 3 | 44 | 94 |
| `policy_phase_shift_hotset` | `lruk` | 2700 | 90 | 120 | 176 | 85 | 2 | 172 |

The result is intentionally not promoted as a win. `lruk` behaves as a
conservative reuse-distance baseline: it sharply rejects one-reference
prefetch pollution, but in these pressure shapes that also increases demand
faults and hot evictions versus `legacy` and `lfu`. Keep it benchmark-gated;
its value is as a reference point for future LIRS or exact ARC-style policies,
not as a default policy.

### CAR-Lite Adaptive Replacement Probe

`MAI_MIGRATION_POLICY=car` is a compact CAR/CLOCK-Pro approximation. Chunks are
tracked as recent, frequent, or recent/frequent ghosts. Demand ghost hits move
the recent target with an ARC-style delta, prefetched chunks remain recent
probation until a demand touch confirms them, and unused prefetched chunks do
not train ghosts. The pivot workload warms one frequent hotset, rotates through
short recent hotsets with cold scans, then returns to the frequent hotset.

These six-run means use 64 MiB workloads, 2 MiB chunks, an 8 MiB resident high
watermark, a 6 MiB low watermark, and `MAI_MAX_RSS=16M`.

| Workload | Policy | Events/s | Demand faults | Read MiB | Write MiB | Admission rejects | Unused evictions | Hot-evicted MiB | CAR recent ghost hits | CAR frequent ghost hits | CAR target + | CAR target - |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `policy_hotset_scan` | `legacy` | 3886 | 50 | 136 | 194 | 0 | 48 | 98 | 0 | 0 | 0 | 0 |
| `policy_hotset_scan` | `2q` | 3620 | 98 | 136 | 192 | 93 | 2 | 188 | 0 | 0 | 0 | 0 |
| `policy_hotset_scan` | `lfu` | 3582 | 67 | 138 | 194 | 31 | 34 | 126 | 0 | 0 | 0 | 0 |
| `policy_hotset_scan` | `lruk` | 3708 | 98 | 136 | 192 | 93 | 2 | 188 | 0 | 0 | 0 | 0 |
| `policy_hotset_scan` | `car` | 3936 | 55 | 143 | 201 | 3 | 48 | 106 | 4 | 7 | 4 | 4 |
| `policy_phase_shift_hotset` | `legacy` | 3549 | 46 | 120 | 178 | 0 | 44 | 90 | 0 | 0 | 0 | 0 |
| `policy_phase_shift_hotset` | `2q` | 3207 | 90 | 120 | 176 | 85 | 2 | 172 | 0 | 0 | 0 | 0 |
| `policy_phase_shift_hotset` | `lfu` | 3818 | 50 | 124 | 182 | 3 | 44 | 94 | 0 | 0 | 0 | 0 |
| `policy_phase_shift_hotset` | `lruk` | 3549 | 90 | 120 | 176 | 85 | 2 | 172 | 0 | 0 | 0 | 0 |
| `policy_phase_shift_hotset` | `car` | 3382 | 52 | 129 | 187 | 3 | 44 | 100 | 4 | 7 | 4 | 4 |
| `policy_recency_frequency_pivot` | `legacy` | 2673 | 98 | 328 | 386 | 0 | 96 | 194 | 0 | 0 | 0 | 0 |
| `policy_recency_frequency_pivot` | `2q` | 2585 | 194 | 328 | 384 | 184 | 2 | 380 | 0 | 0 | 0 | 0 |
| `policy_recency_frequency_pivot` | `lfu` | 2571 | 201 | 370 | 427 | 174 | 16 | 395 | 0 | 0 | 0 | 0 |
| `policy_recency_frequency_pivot` | `lruk` | 2407 | 155 | 377 | 435 | 77 | 65 | 306 | 0 | 0 | 0 | 0 |
| `policy_recency_frequency_pivot` | `car` | 2776 | 116 | 348 | 406 | 14 | 90 | 227 | 18 | 54 | 11 | 11 |

CAR-lite is useful as an adaptive replacement reference, not a default. It wins
the hotset and pivot event-rate rows in this local run and substantially
reduces pivot hot-evicted bytes versus `2q`, `lfu`, and `lruk`, but it still
trails `legacy` on demand faults and migration volume. Ghost feedback and
target movement are observed, but the policy still needs better prefetch
admission or migration traffic control before it can be promoted.

### TinyLFU Long-Tail Admission Probe

`MAI_MIGRATION_POLICY=tinylfu` is an experimental sketch-backed admission
classifier. It uses a fixed global Count-Min-style sketch keyed by allocation
sequence and chunk index, trains only on demand-observed touches, and gates
speculative prefetch admission under pressure. Demand faults still populate;
TinyLFU is not a new prefetch predictor.

These six-run means use 64 MiB workloads, 2 MiB chunks, an 8 MiB resident high
watermark, a 6 MiB low watermark, and `MAI_MAX_RSS=16M`. The
`policy_long_tail_admission` row uses a full cold-tail permutation per pass;
earlier modulo-LCG runs accidentally revisited only part of the cold tail and
are intentionally superseded.

| Workload | Policy | Events/s | Demand faults | Read MiB | Write MiB | Admission rejects | Unused evictions | Hot-evicted MiB | TinyLFU updates | TinyLFU rejects |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `policy_hotset_scan` | `legacy` | 2373 | 50 | 136 | 194 | 0 | 48 | 98 | 0 | 0 |
| `policy_hotset_scan` | `lfu` | 2284 | 67 | 138 | 194 | 31 | 34 | 126 | 0 | 0 |
| `policy_hotset_scan` | `car` | 2507 | 55 | 144 | 202 | 2 | 48 | 106 | 0 | 0 |
| `policy_hotset_scan` | `lruk` | 2473 | 98 | 136 | 192 | 93 | 2 | 188 | 0 | 0 |
| `policy_hotset_scan` | `tinylfu` | 2313 | 98 | 136 | 192 | 93 | 2 | 188 | 98 | 93 |
| `policy_phase_shift_hotset` | `legacy` | 3277 | 46 | 120 | 178 | 0 | 44 | 90 | 0 | 0 |
| `policy_phase_shift_hotset` | `lfu` | 2737 | 50 | 124 | 182 | 3 | 44 | 94 | 0 | 0 |
| `policy_phase_shift_hotset` | `car` | 2786 | 52 | 130 | 188 | 2 | 44 | 100 | 0 | 0 |
| `policy_phase_shift_hotset` | `lruk` | 2670 | 90 | 120 | 176 | 85 | 2 | 172 | 0 | 0 |
| `policy_phase_shift_hotset` | `tinylfu` | 2828 | 90 | 120 | 176 | 85 | 2 | 172 | 90 | 85 |
| `policy_recency_frequency_pivot` | `legacy` | 2382 | 98 | 328 | 386 | 0 | 96 | 194 | 0 | 0 |
| `policy_recency_frequency_pivot` | `lfu` | 2375 | 201 | 370 | 426 | 175 | 16 | 394 | 0 | 0 |
| `policy_recency_frequency_pivot` | `car` | 2020 | 118 | 347 | 405 | 21 | 86 | 232 | 0 | 0 |
| `policy_recency_frequency_pivot` | `lruk` | 1884 | 156 | 379 | 437 | 77 | 65 | 308 | 0 | 0 |
| `policy_recency_frequency_pivot` | `tinylfu` | 1895 | 218 | 419 | 477 | 185 | 23 | 432 | 218 | 185 |
| `policy_long_tail_admission` | `legacy` | 1668 | 124 | 310 | 368 | 0 | 61 | 246 | 0 | 0 |
| `policy_long_tail_admission` | `lfu` | 1992 | 153 | 277 | 335 | 67 | 18 | 299 | 0 | 0 |
| `policy_long_tail_admission` | `car` | 1849 | 132 | 308 | 366 | 5 | 53 | 260 | 0 | 0 |
| `policy_long_tail_admission` | `lruk` | 1803 | 152 | 295 | 351 | 59 | 28 | 296 | 0 | 0 |
| `policy_long_tail_admission` | `tinylfu` | 1910 | 161 | 294 | 350 | 75 | 18 | 314 | 161 | 75 |

The corrected result is intentionally modest. TinyLFU is a poor fit for the
small phase-shift and recency/frequency pivot probes because it rejects useful
speculation until demand history exists. On the corrected long-tail admission
workload, it matches exact `lfu` on unused-prefetch evictions and reduces
migration bytes versus `legacy`, but it does not beat exact `lfu` on throughput,
demand faults, or hot-evicted bytes. Keep it experimental: this slice validates
sketch-backed admission plumbing, not a production default.

### Best-Offset Lag Probe

`MAI_MIGRATION_POLICY=best-offset` is an experimental top-1 offset prefetcher.
It trains only from demand-observed chunk order, emits at most the highest-score
forward offset, and penalizes unused offset-prefetch evictions. The
`policy_best_offset_lag` workload shuffles disjoint anchor chunks and touches
`anchor + offset` after a configurable lookahead; the benchmark does not reveal
the next target to MAI or expose target chunks as ordinary anchors.

These six-run means use `policy_best_offset_lag 128M`, 2 MiB chunks,
`MAI_BENCH_POLICY_OFFSET_CHUNKS=16`, lookahead 4, a 32 MiB resident high
watermark, a 24 MiB low watermark, `MAI_MAX_RSS=64M`, and the default
best-offset floor. With `MAI_UFFD_PREFETCH_CHUNKS=4`, that floor ignores
offsets below four chunks.

| Policy | Events/s | Demand events | Prefetch completed | Useful | Accuracy | Coverage | Late events | Unused evictions | Read MiB | Write MiB | Hot-evicted MiB | Offset slots | Best-offset candidates | Top offset | Top score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `legacy` | 290 | 56 | 139 | 0 | 0.000 | 0.000 | 56 | 128 | 320 | 358 | 102 | 0 | 0 | `0` | 0 |
| `stream` | 728 | 84 | 0 | 0 | 0.000 | 0.000 | 84 | 0 | 104 | 140 | 140 | 0 | 0 | `0` | 0 |
| `stride` | 643 | 85 | 20 | 0 | 0.000 | 0.000 | 85 | 20 | 138 | 184 | 144 | 0 | 0 | `0` | 0 |
| `markov` | 657 | 84 | 0 | 0 | 0.000 | 0.000 | 84 | 0 | 104 | 140 | 140 | 0 | 0 | `0` | 0 |
| `spatial` | 429 | 70 | 41 | 0 | 0.000 | 0.000 | 70 | 34 | 158 | 192 | 124 | 0 | 0 | `0` | 0 |
| `car` | 304 | 66 | 134 | 0 | 0.000 | 0.000 | 66 | 130 | 329 | 370 | 109 | 0 | 0 | `0` | 0 |
| `tinylfu` | 308 | 70 | 102 | 0 | 0.000 | 0.000 | 70 | 101 | 278 | 320 | 118 | 0 | 0 | `0` | 0 |
| `best-offset` | 569 | 76 | 36 | 0 | 0.000 | 0.000 | 76 | 33 | 144 | 192 | 126 | 486 | 58 | `+8` | 52 |

The result is useful but not promotable. Best-offset is expected to learn the
intended `+16` chunk offset on this guardrail, but the corrected disjoint-source
runs learned nearby incidental offsets instead and produced no useful
prefetches. It cuts migration traffic relative to legacy-style speculative
prefetching, but it does not beat conservative `stream` or `markov` rows on
event rate, demand events, or migration volume. Keep it as a guardrail for
future offset/window designs rather than a recommended policy.

A separate spot check with `MAI_POLICY_BEST_OFFSET_MIN_CHUNKS=16` still
produced zero useful prefetches and learned `+17`, so the remaining issue is
not only the default floor; the top-1 scorer needs better temporal alignment
or multi-lookahead scoring before this policy can be promoted.

## Interpretation

- Sufficient-memory MAI does not trigger migration in these runs; faster
  managed rows should be treated as run-order/cache variance, not proof that
  MAI is faster than native allocation.
- `stride` is the best fit for the single-active-stream stride probe and is
  the only pressure row here that approaches its sufficient-memory baseline.
- `markov` is the best current irregular-transition policy on
  `policy_successor_cycle`.
- `spatial` reduces demand faults on both spatial workloads, but the
  interleaved mixed-mask case shows higher prefetch traffic than `markov`.
- `lfu` wins the current hotset scan event-rate row and ties `legacy` on lowest
  demand faults, but this remains workload-specific.
- `car` is the first adaptive recency/frequency replacement slice. It wins the
  local hotset and pivot event-rate rows and avoids the worst `2q`/`lruk`
  pivot hot evictions, but it still does not beat `legacy` on demand faults or
  migration volume.
- `tinylfu` is the first sketch-backed admission slice. It is not competitive
  on the small phase-shift probes. On the corrected long-tail workload, it
  reduces cold-tail prefetch pollution versus `legacy` but does not beat exact
  `lfu`; use it as infrastructure for future W-TinyLFU-style policies.
- `best-offset` is an experimental offset-learning guardrail. It should not be
  treated as successful unless the disjoint-source benchmark shows both the
  expected top offset and competitive stall/migration metrics.
- On the local six-run 9-matrix pressure shape, `legacy` has the highest mean
  end-to-end rate among the low-watermark 48 MiB rows. It reaches only 22.9%
  of the matching MAI-managed sufficient-memory end-to-end baseline, while its
  kernel-only loop reaches 56.2%. Because kernel rates exclude setup,
  first-touch, and fault/migration costs, the largest visible gap is outside
  the measured kernel loop. Demand-fault stall counters and migration counters
  should be used before attributing the full gap to one policy mechanism.
- Raising the low watermark to 64 MiB is a sensitivity probe, not a solved
  policy or replacement headline.
  It improves the best end-to-end row from `legacy` at 8133 MiB/s to `markov`
  at 8452 MiB/s, and reduces the best write volume from 336 MiB to 320 MiB,
  but the best tuned row still reaches only 23.8% of the MAI-managed
  sufficient-memory end-to-end baseline. It also hurts `stream`, `stride`, and
  `spatial`, so fixed extra slack is not enough without better admission,
  eviction, and migration throttling.
- The opt-in async UFFD policy worker is a mechanism improvement, not a global
  strategy win. On this slice it improves `2q` end-to-end throughput by moving
  speculative work off the fault path and reducing migration bytes, but it
  hurts `legacy` and `markov`. It should stay policy-selected or experimental
  until admission and worker scheduling can avoid that regression.
- Record-aware eviction is also a tuning control, not a default strategy. It
  gives small selected `markov` and `2q` gains in the 48 MiB low-watermark
  shape, but it regresses `markov` in the 64 MiB low-watermark shape and has no
  stable dose response. The `legacy` baseline is deliberately excluded from the
  record bias.
- Active-record working-set control is stronger than record protection because
  it also shapes admission and the reclaim floor. In this local slice it helps
  the best tested `legacy` and `markov` rows, but the absolute gap to
  sufficient-memory STREAM remains large, so the next work should target
  reduced write/read amplification and phase-transition stalls rather than
  adding another standalone predictor.
- Clean-shadow write-amplification is now an opt-in UFFD feature
  (`MAI_UFFD_CLEAN_SHADOW=1`) with targeted correctness tests for clean
  demotion skips and dirty write-protect invalidation. It should still be
  benchmarked separately before being used in performance claims: read-mostly
  reuse can save demotion writes, while write-heavy reuse pays extra
  write-protect faults.
- Write-protect observation is useful for lower-bound usefulness counters, but
  it changes fault behavior and should not be mixed with default performance
  rows.
