# MAI

MAI is a user-space, privilege-free, anonymous-first large-allocation tiering
runtime for HPC workloads. It tracks large heap allocations while memory is
sufficient, then can demote cold chunks to storage-backed mappings when reclaim
policy or pressure requires it. It is intended for programs whose large heap
allocations can exceed physical memory but are accessed sparsely or
infrequently.

MAI's default path does not rely on Linux swap, kernel modules, DAMON, cgroup
privileges, userfaultfd paging, or site-wide installation. It is used with
`LD_PRELOAD` for dynamically linked applications. An optional experimental
`userfaultfd` pager can be enabled for fault-driven migration experiments on
hosts that allow unprivileged userfaultfd. Normal allocator interception uses
direct `LD_PRELOAD` symbols; Frida/Gum remains available internally for
diagnostics and best-effort patching of allocator entry points that appear
outside normal preload resolution.

## Current Scope

This version focuses on a correct managed allocator with reclaim, diagnostics,
profiling, sampled hotness support, and storage demotion:

- `MAI_ENABLE=1` opt-in runtime activation.
- Small heap allocations pass through to the original allocator.
- Allocations at or above `MAI_THRESHOLD` are routed to MAI-managed anonymous
  mappings by default. This keeps sufficient-memory bandwidth close to normal
  anonymous memory.
- Cold managed chunks can be demoted to unlinked storage-backed `MAP_SHARED`
  mappings during explicit or policy reclaim, and `mai_prefetch()` can promote
  those chunks back to anonymous mappings at the same virtual addresses.
- `MAI_UFFD_PAGER=auto|required` enables the experimental userfaultfd pager for
  pressure-selected allocations. Missing faults populate anonymous chunks
  directly, and a bounded adjacent-chunk prefetch window reduces repeated
  fault overhead for spatial scans.
- `MAI_BACKEND=file` keeps the legacy direct file-backed arena mode available
  for experiments and storage-pressure comparisons.
- Arena metadata is stored outside the managed arena and does not use the
  MAI-managed allocator.
- Legacy file-backed mode uses one large backing file per arena segment.
  Anonymous-first mode creates a backing file only for allocations that are
  actually demoted.
- Backing files are unlinked immediately after mapping to avoid stale files.
- Basic stats, diagnostics counters, manual reclaim, and target-driven reclaim
  are available.
- Allocation call-site profiling is available for MAI-managed allocations.
- Optional live-allocation hotness sampling uses `mincore()` on bounded samples
  of MAI-managed pages. This reports resident-page estimates, not exact access
  frequency.
- Successful pinning/registration calls for visible `mlock`, CUDA/HIP host
  memory, CUDA/HIP managed memory, MPI allocated memory, and libibverbs memory
  regions are tracked as excluded ranges. Excluded ranges are not selected for
  MAI reclaim.
- `dlopen`/`dlmopen` are monitored so newly loaded shared objects, including
  Python extension modules, get a best-effort allocator hook refresh.
  This is mainly for DSOs that introduce their own exported allocator entry
  points after MAI starts. Normal calls from a dlopened DSO into preloaded MAI
  symbols do not need a dlopen refresh.

MAI currently intercepts:

- `malloc`
- `calloc`
- `realloc`
- `free`
- `aligned_alloc`
- `posix_memalign`
- `memalign`
- `valloc`
- `pvalloc`
- `malloc_usable_size`
- C++ `operator new/delete` and `new[]/delete[]`, including sized, nothrow,
  and aligned forms where supported by the compiler/runtime

Language/runtime coverage:

- C and C++ large heap allocations are covered through the malloc-family
  interceptors and C++ global `new`/`delete` wrappers.
- Fortran programs are covered when the compiler/runtime implements
  allocatable arrays and heap allocation through the process allocator
  symbols. MAI does not depend on a compiler-specific Fortran ABI.
- Python raw allocator calls and NumPy data buffers can be managed when they
  ultimately allocate through malloc-family APIs. MAI does not install a
  Python or NumPy allocator policy by default; this remains an extension on
  top of the core storage-backed heap tiering model.

MAI also hooks the following functions for diagnostics only:

- `mmap`
- `munmap`
- `mremap`
- `brk`
- `sbrk`

MAI hooks the following APIs for safety/exclusion tracking. The `mlock` family
is exposed through normal `LD_PRELOAD` symbol interposition. CUDA/HIP, MPI, and
libibverbs APIs are also included in MAI's best-effort `dlopen` refresh for
newly loaded DSOs that define their own exported runtime entry points:

- `mlock`, `mlock2`, `mlockall`, `munlock`, `munlockall`
- CUDA host and managed memory APIs: `cudaHostAlloc`, `cudaMallocHost`,
  `cudaHostRegister`, `cudaHostUnregister`, `cudaFreeHost`,
  `cudaMallocManaged`, `cudaFree`
- HIP host and managed memory APIs: `hipHostMalloc`, `hipHostRegister`,
  `hipHostUnregister`, `hipHostFree`, `hipMallocManaged`, `hipFree`
- MPI memory APIs: `MPI_Alloc_mem`, `MPI_Free_mem`
- libibverbs registration APIs: `ibv_reg_mr`, `ibv_reg_mr_iova`,
  `ibv_dereg_mr`

These hooks are conservative. MAI marks ranges only after the underlying API
reports success. If a driver, MPI implementation, or RDMA stack rejects a
MAI-managed buffer, MAI cannot force that registration to succeed. Once a range is
marked excluded, MAI will skip it during manual and target-RSS reclaim.
Successful `mlockall(MCL_FUTURE)` also prevents future large allocations from
being routed into MAI arenas until `munlockall()` succeeds.

## Non-Goals And Exclusions

MAI cannot make arbitrary programs survive all memory pressure. It helps only
when large pageable heap allocations are a good fit for storage-backed paging.

MAI does not currently manage:

- stack memory
- static or global memory
- executable mappings
- thread-local storage
- signal stacks
- `mlock`ed, MPI/RDMA registered, GPU, or pinned host ranges beyond marking
  visible successful registrations as excluded from reclaim
- allocator metadata pages
- arbitrary stripped static binaries
- hidden or private allocator entry points in newly loaded modules

## Configuration

MAI is disabled unless `MAI_ENABLE=1` is set.

```
MAI_ENABLE=1
MAI_PATH=/path/to/node-local-or-scratch-storage
MAI_THRESHOLD=64M
MAI_ARENA_SIZE=1G
MAI_TARGET_RSS=0
MAI_MAX_RSS=auto
MAI_RECLAIM_POLICY=none
MAI_RECLAIM_SELECTION=oldest
MAI_BACKEND=auto
MAI_MIGRATION_CHUNK=2M
MAI_UFFD_PAGER=off
MAI_UFFD_RESIDENT_LIMIT=auto
MAI_UFFD_RESIDENT_LOW_LIMIT=auto
MAI_UFFD_PREFETCH_CHUNKS=4
MAI_PROFILE=1
MAI_HOTNESS=1
MAI_HOTNESS_SAMPLE_PAGES=64
MAI_VERBOSE=1
MAI_STATS=1
MAI_ALLOCATOR_HOOKS=auto
MAI_PATH_STATS=0
```

`MAI_PATH` is preferred. If it is not set, MAI attempts to discover a scratch
path from HPC-like environment variables such as `SLURM_TMPDIR`, `PBS_JOBFS`,
`TMPDIR`, `LOCAL_SCRATCH`, `SCRATCH`, or `JOBSCRATCH`. MAI does not silently
default to the current working directory. If an explicit `MAI_PATH` is invalid,
MAI disables itself.

Supported size suffixes for `MAI_THRESHOLD`, `MAI_ARENA_SIZE`,
`MAI_FILE_DEDICATED_MIN`, `MAI_MIGRATION_CHUNK`,
`MAI_UFFD_RESIDENT_LIMIT`, and `MAI_UFFD_RESIDENT_LOW_LIMIT` are `K`, `M`, `G`,
and `T`.

`MAI_BACKEND=anon` forces anonymous-first managed allocations.
`MAI_BACKEND=file` uses the legacy direct file-backed arena path.
`MAI_BACKEND=auto` uses anonymous memory while the projected live managed
footprint fits comfortably inside `MAI_MAX_RSS`; when a large allocation or the
projected footprint approaches that cap, MAI demotes the new allocation to
storage before returning the pointer so first-touch application code does not
outrun the allocator-time RSS check. `MAI_AUTO_LARGE_ALLOC_CAP_PERCENT` controls
the large-allocation cutoff as a percentage of the detected RSS cap;
`MAI_FILE_DEDICATED_MIN` controls when direct file-backed allocations receive
dedicated segments instead of sharing an arena.
`MAI_MIGRATION_CHUNK` controls the demotion/promotion unit for anonymous-first
allocations and defaults to 2 MiB for huge-page-friendly placement.
`MAI_UFFD_PAGER=auto` tries the experimental userfaultfd pager for allocations
that `MAI_BACKEND=auto` would otherwise demote under pressure; `required`
turns an unavailable pager into a configuration error. `MAI_UFFD_PREFETCH_CHUNKS`
is the total number of adjacent chunks to populate per missing fault, including
the faulting chunk. Set it to `1` to disable spatial prefetch.
`MAI_UFFD_CLEAN_SHADOW=1` is an opt-in UFFD mode that preserves valid storage
shadows after a chunk is restored and uses write-protect faults to invalidate
the shadow on the first write. Clean demotion can then skip the storage write;
tracking only activates when the kernel can restore the chunk write-protected
atomically. Write-heavy reuse pays the extra write-protect fault and should
benchmark this mode explicitly before enabling it.

`MAI_ALLOCATOR_HOOKS` controls whether MAI also patches libc allocator entry
points with Frida/Gum:

- `auto` or unset uses direct `LD_PRELOAD` allocator symbols when available
  and skips redundant libc allocator patches.
- `preload` forces direct preload mode and skips libc allocator patches.
- `frida` additionally patches libc allocator symbols with Frida/Gum.

Even in preload mode, MAI still uses Frida/Gum for `dlopen` refreshes and
diagnostic hooks.

`MAI_PATH_STATS=1` enables diagnostic counters that distinguish direct
preload allocator entries from Frida/Gum replacement entries. It is intended
for tests and troubleshooting; leave it disabled for performance measurements.

`MAI_STATS=1` prints a shutdown summary and enables pass-through allocation
byte/count counters. Managed allocation counters are always maintained, but
small pass-through allocation counters are disabled by default to keep the
common below-threshold path lightweight. The stats summary also reports
excluded range counts/bytes, exclusion mark/release events, skipped reclaim
counts for excluded ranges, and safety hook patch counts.

`MAI_RECLAIM_POLICY` may be:

- `none`
- `donthneed`
- `pageout` when supported by the platform, otherwise it falls back to
  `donthneed`

`MAI_TARGET_RSS` is an optional soft process-RSS target. On Linux, MAI samples
`/proc/self/statm` after managed allocations and asks the reclaim policy to
drop selected managed ranges when observed RSS is above the target. It is a
best-effort policy trigger, not a hard cgroup limit.

`MAI_MAX_RSS` is a process-RSS safety cap for MAI-managed allocation activity.
The default is `auto`, which uses unprivileged cgroup memory files, physical
memory, and `/proc/meminfo` `MemAvailable` when available, with conservative
headroom. It can also be set to an explicit size or to `off`. Before MAI returns
`ENOMEM` because of this cap, it first tries the configured reclaim selection
and then an exhaustive reclaim pass over every live, non-excluded managed
allocation. This does not let MAI control stack, static, pinned, GPU, RDMA, or
other non-managed memory, and it does not install or rely on system swap.

`MAI_RECLAIM_SELECTION` controls which allocations are selected when
`MAI_TARGET_RSS` triggers reclaim:

- `oldest`
- `largest`
- `all`
- `adaptive`

`adaptive` uses bounded `mincore()` sampling on live, non-excluded managed
allocations and prefers the candidate with the largest estimated resident
footprint, with allocation size and age as tie-breakers. It is intended for
target-RSS reclaim where dropping already nonresident pages is unlikely to
reduce RSS. The sampling budget is controlled by `MAI_HOTNESS_SAMPLE_PAGES`;
hotness reporting does not need to be enabled for adaptive reclaim to use the
same low-overhead residency sampler.

Manual reclaim is available through `mai_reclaim_all()`. Reclaim uses
`msync()` followed by `madvise()` on managed ranges. `donthneed` uses
`MADV_DONTNEED`; `pageout` uses `MADV_PAGEOUT` when available and falls back to
`MADV_DONTNEED` if the running kernel rejects it. Re-access is handled by the
kernel reloading from the backing file.

`MAI_PROFILE=1` records allocation call-site counters in metadata outside the
managed arena and prints a call-site report at shutdown.

`MAI_HOTNESS=1` enables optional sampled hotness reporting for live MAI-managed
allocations. MAI samples at most `MAI_HOTNESS_SAMPLE_PAGES` pages per live
allocation with `mincore()` and reports how many sampled pages are resident.
This is a low-overhead residency proxy, not precise page access-frequency
tracking. `mai_sample_hotness()` can be called by tests or tools to trigger a
manual sample before shutdown.

### Experimental predictive migration APIs

MAI includes an experimental performance-oriented substrate for predictive
migration policies:

- `mai_hint_range(ptr, len, kind, opts)` records advisory application intent,
  such as sequential, sparse, random hotset, or cold/reclaim-preferred ranges.
- `mai_reclaim_range(ptr, len)` explicitly demotes a page-aligned subrange of a
  managed allocation with the configured reclaim policy.
- `mai_prefetch(ptr, len)` issues a bounded `MADV_WILLNEED` hint for a managed
  range.
- `mai_prepare_write(ptr, len)` promotes cold chunks to anonymous memory
  without copying stale storage contents when the caller will overwrite the
  whole range before reading it.
- `mai_trace_access(ptr, len, opts)` intrusively samples first touches by
  protecting a bounded number of full pages or chunk heads and handling the
  resulting `SIGSEGV` faults. This can provide stronger access evidence for
  performance-tuning runs, but it is intentionally intrusive and should not be
  treated as transparent allocator behavior.
- `mai_heartbeat(opts, snapshot)` advances one adaptive observation epoch. It
  reduces observation and skips migration when sampled accesses are busy, then
  demotes untouched sampled chunks within a caller-supplied migration budget
  during quiet epochs.

These APIs are best-effort, never bypass safety exclusions, and do not make
performance guarantees. The strategy is documented in
`docs/predictive_migration.md`.

## Build

```
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$HOME ..
make
ctest --output-on-failure
```

To exercise behavior when a managed allocation is larger than the available
physical/cgroup memory, enable the Docker-backed test:

```
cmake -S . -B build -DMAI_ENABLE_DOCKER_TESTS=ON
cmake --build build
ctest --test-dir build -R mai_docker_cgroup_memory_limit --output-on-failure
```

The Docker test runs with `--memory` and `--memory-swap` set to the same limit
and validates that `MAI_MAX_RSS=auto` detects the container cgroup cap while a
larger chunked allocation is backed by MAI scratch storage and reclaimed
without an OOM kill. `MAI_DOCKER_MEMORY`, `MAI_DOCKER_IMAGE`, and
`MAI_DOCKER_SCRATCH` can be set to override the default `64m`,
`ubuntu:24.04`, and build-local scratch directory.

GitHub Actions separates correctness from performance:

- `.github/workflows/ci.yml` runs the correctness suite on pushes, pull
  requests, and manual dispatch.
- `.github/workflows/benchmarks.yml` runs non-gating benchmark jobs on a
  weekly schedule or manual dispatch and uploads measurements as workflow
  artifacts. Retained benchmark results, detailed protocols, and future
  strategy plans are kept in the companion `mai_benchmark` workspace.

See `benchmarks/README.md` for the in-tree benchmark harness entry points.

## Use

```
MAI_ENABLE=1 \
MAI_PATH=/scratch/$USER/$SLURM_JOB_ID \
MAI_THRESHOLD=256M \
MAI_ARENA_SIZE=64G \
LD_PRELOAD=/path/to/libmai.so \
./target_application
```
