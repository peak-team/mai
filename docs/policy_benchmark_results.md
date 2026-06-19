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

| Policy | End-to-end MiB/s | Kernel MiB/s | Demand faults | Read MiB | Write MiB | Unused prefetch evictions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `legacy` | 8133 | 24277 | 48 | 240 | 336 | 126 |
| `stream` | 7746 | 20539 | 158 | 280 | 364 | 54 |
| `stride` | 6894 | 17626 | 138 | 346 | 432 | 107 |
| `2q` | 6024 | 16479 | 137 | 534 | 630 | 202 |
| `lfu` | 6957 | 14448 | 94 | 402 | 491 | 176 |
| `markov` | 7825 | 23207 | 175 | 246 | 342 | 20 |
| `spatial` | 7355 | 22477 | 113 | 296 | 380 | 86 |

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
- On the local six-run 9-matrix pressure shape, `legacy` is still the best of
  the tested policies. It reaches only 22.9% of the matching MAI-managed
  sufficient-memory end-to-end baseline. Its kernel throughput is higher, at
  56.2% of the matching sufficient-memory kernel rate, so the main remaining
  loss is end-to-end migration/fault overhead. That is the next design target.
- Write-protect observation is useful for lower-bound usefulness counters, but
  it changes fault behavior and should not be mixed with default performance
  rows.
