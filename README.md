# MAI

MAI is a user-space, privilege-free, storage-backed large-allocation tiering
runtime for HPC workloads. It is intended for programs whose large heap
allocations can exceed physical memory but are accessed sparsely or
infrequently.

MAI does not rely on Linux swap, kernel modules, DAMON, cgroup privileges,
userfaultfd paging, or site-wide installation. It is used with `LD_PRELOAD`
for dynamically linked applications and uses Frida/Gum internally to patch
allocator entry points.

## Current Scope

This version focuses on a correct storage-backed allocator with initial reclaim,
diagnostics, and profiling support:

- `MAI_ENABLE=1` opt-in runtime activation.
- Small heap allocations pass through to the original allocator.
- Allocations at or above `MAI_THRESHOLD` are routed to MAI-managed
  file-backed `MAP_SHARED` arena segments.
- Arena metadata is stored outside the managed arena and does not use the
  MAI-managed allocator.
- One large backing file is used per arena segment, not per allocation.
- Backing files are unlinked immediately after mapping to avoid stale files.
- Basic stats, diagnostics counters, manual reclaim, and target-driven reclaim
  are available.
- `dlopen`/`dlmopen` are monitored so newly loaded shared objects, including
  Python extension modules, get a best-effort allocator hook refresh.

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
MAI_VERBOSE=1
MAI_STATS=1
```

`MAI_PATH` is preferred. If it is not set, MAI attempts to discover a scratch
path from HPC-like environment variables such as `SLURM_TMPDIR`, `PBS_JOBFS`,
`TMPDIR`, `LOCAL_SCRATCH`, `SCRATCH`, or `JOBSCRATCH`. MAI does not silently
default to the current working directory. If an explicit `MAI_PATH` is invalid,
MAI disables itself.

Supported size suffixes for `MAI_THRESHOLD` and `MAI_ARENA_SIZE` are `K`, `M`,
`G`, and `T`.

`MAI_RECLAIM_POLICY` may be:

- `none`
- `donthneed`
- `pageout` when supported by the platform, otherwise it falls back to
  `donthneed`

`MAI_TARGET_RSS` is an optional soft target for managed live bytes. It is not a
kernel RSS reading; it is a policy trigger that asks MAI to reclaim selected
managed ranges after allocations push the managed live-byte estimate above the
target.

`MAI_RECLAIM_SELECTION` controls which allocations are selected when
`MAI_TARGET_RSS` triggers reclaim:

- `oldest`
- `largest`
- `all`

Manual reclaim is available through `mai_reclaim_all()`. Reclaim uses
`msync()` followed by `madvise()` on managed ranges. Re-access is handled by
the kernel reloading from the backing file.

`MAI_PROFILE=1` records allocation call-site counters in metadata outside the
managed arena. When `MAI_STATS=1` is also set, MAI prints a call-site report at
shutdown. This is an allocation/reclaim heuristic aid, not precise page hotness
tracking.

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

1. Improve `MAI_TARGET_RSS` by comparing policy decisions against measured
   process RSS, not only MAI-managed live bytes.
2. Add sampled page-hotness estimation.
3. Extend runtime support for Fortran runtimes and optional Python/NumPy-specific
   integration.
4. Add exclusion hooks for pinned, mlocked, MPI/RDMA, and GPU memory.
