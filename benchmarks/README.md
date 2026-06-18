# MAI Benchmarks

Benchmarks are separate from correctness CI. They are intended to produce
performance evidence for storage-backed MAI allocations under different access
patterns, not to gate every commit with machine-dependent timing thresholds.

Build benchmark utilities with:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMAI_BUILD_BENCHMARKS=ON
cmake --build build --target mai mai_access_pattern_benchmark
```

Run the Docker access-pattern benchmark with:

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

Useful overrides:

```
MAI_BENCH_DOCKER_MEMORY=128m
MAI_BENCH_ALLOCATION_SIZE=192M
MAI_BENCH_WINDOW=8M
MAI_BENCH_HOTSET=32M
MAI_BENCH_RANDOM_OPS=500000
MAI_BENCH_MIN_MIB_PER_SEC=0.5
```

By default the benchmark fails on correctness errors, missing MAI management,
or missing reclaim in reclaim-oriented patterns. It only enforces a throughput
floor when `MAI_BENCH_MIN_MIB_PER_SEC` is set above zero.
