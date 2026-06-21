# MAI Benchmark Harness

This directory contains benchmark source and runner scripts that are useful for
local performance investigations. Retained benchmark results, detailed protocol
notes, and strategy-planning documents are intentionally kept outside this
implementation repository in the companion `mai_benchmark` workspace.

Build the benchmark utilities with:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMAI_BUILD_BENCHMARKS=ON
cmake --build build --target mai mai_benchmark mai_access_pattern_benchmark
```

Common local entry points are:

```sh
python3 benchmarks/policy_retained_matrix.py \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark \
  --output-dir /path/to/benchmark-output

benchmarks/sufficient_memory_matrix.sh \
  build/src/libmai.so \
  build/tests/mai_benchmark \
  build/benchmarks/mai_access_pattern_benchmark

benchmarks/trace_heartbeat_matrix.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark

benchmarks/mprotect_overhead_matrix.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark

benchmarks/docker_access_patterns.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark

benchmarks/docker_stream_pressure_matrix.sh \
  build/src/libmai.so \
  build/benchmarks/mai_access_pattern_benchmark
```

Generated `rows.ndjson`, `summary.csv`, `summary.md`, and retained result
analysis should be written to the external benchmark workspace, not committed to
MAI.
