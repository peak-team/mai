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
- A clean-shadow write-amplification experiment was attempted but rejected:
  retaining storage shadows and using UFFD write-protect to avoid clean
  write-back corrupted the successor-policy correctness workload. Any future
  shadow-copy design needs explicit dirty-state tests before performance
  benchmarking.
- Write-protect observation is useful for lower-bound usefulness counters, but
  it changes fault behavior and should not be mixed with default performance
  rows.
