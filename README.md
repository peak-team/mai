# MAI

MAI is a user-space, privilege-free, storage-backed large-allocation tiering
runtime for HPC workloads. It is intended for programs whose large heap
allocations can exceed physical memory but are accessed sparsely or
infrequently.

MAI does not rely on Linux swap, kernel modules, DAMON, cgroup privileges,
userfaultfd paging, or site-wide installation. It is used with `LD_PRELOAD`
for dynamically linked applications. Normal allocator interception uses direct
`LD_PRELOAD` symbols; Frida/Gum remains available internally for diagnostics
and best-effort patching of allocator entry points that appear outside normal
preload resolution.

## Current Scope

This version focuses on a correct storage-backed allocator with reclaim,
diagnostics, profiling, and sampled hotness support:

- `MAI_ENABLE=1` opt-in runtime activation.
- Small heap allocations pass through to the original allocator.
- Allocations at or above `MAI_THRESHOLD` are routed to MAI-managed
  file-backed `MAP_SHARED` arena segments.
- Managed allocations are page-isolated inside arenas so page-granular reclaim
  does not discard data from unrelated live allocations.
- Arena metadata is stored outside the managed arena and does not use the
  MAI-managed allocator.
- One large backing file is used per arena segment, not per allocation.
- Backing files are unlinked immediately after mapping to avoid stale files.
- Basic stats, diagnostics counters, manual reclaim, and target-driven reclaim
  are available.
- Allocation call-site profiling is available for MAI-managed allocations.
- Optional live-allocation hotness sampling uses `mincore()` on bounded samples
  of MAI-managed pages. This reports resident-page estimates, not exact access
  frequency.
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

MAI also hooks the following functions for diagnostics only:

- `mmap`
- `munmap`
- `mremap`
- `brk`
- `sbrk`

## Non-Goals And Exclusions

MAI cannot make arbitrary programs survive all memory pressure. It helps only
when large pageable heap allocations are a good fit for storage-backed paging.

MAI does not currently manage:

- stack memory
- static or global memory
- executable mappings
- thread-local storage
- signal stacks
- `mlock`ed memory
- MPI/RDMA registered buffers
- GPU allocations or pinned host memory
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
MAI_RECLAIM_POLICY=none
MAI_RECLAIM_SELECTION=oldest
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

Supported size suffixes for `MAI_THRESHOLD` and `MAI_ARENA_SIZE` are `K`, `M`,
`G`, and `T`.

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

`MAI_RECLAIM_POLICY` may be:

- `none`
- `donthneed`
- `pageout` when supported by the platform, otherwise it falls back to
  `donthneed`

`MAI_TARGET_RSS` is an optional soft process-RSS target. On Linux, MAI samples
`/proc/self/statm` after managed allocations and asks the reclaim policy to
drop selected managed ranges when observed RSS is above the target. It is a
best-effort policy trigger, not a hard cgroup limit.

`MAI_RECLAIM_SELECTION` controls which allocations are selected when
`MAI_TARGET_RSS` triggers reclaim:

- `oldest`
- `largest`
- `all`

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

## Build

```
mkdir build
cd build
cmake --install-prefix=$HOME ..
make
ctest --output-on-failure
```

## Use

```
MAI_ENABLE=1 \
MAI_PATH=/scratch/$USER/$SLURM_JOB_ID \
MAI_THRESHOLD=256M \
MAI_ARENA_SIZE=64G \
LD_PRELOAD=/path/to/libmai.so \
./target_application
```

## Development Direction

The next phases are:

1. Extend runtime support for Fortran runtimes and optional Python/NumPy-specific
   integration.
2. Add exclusion hooks for pinned, mlocked, MPI/RDMA, and GPU memory.
