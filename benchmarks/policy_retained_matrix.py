#!/usr/bin/env python3
"""Run retained MAI policy benchmark rows and write machine-readable artifacts."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import platform
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_SEEDS = "1,7,13,29,31,43"
DEFAULT_WORKLOADS = ",".join(
    [
        "policy_stream_pipeline",
        "policy_long_tail_admission",
        "policy_recency_frequency_pivot",
        "policy_signature_context_cycle",
    ]
)
DEFAULT_POLICIES = ",".join(
    [
        "legacy",
        "markov",
        "car",
        "wtinylfu",
        "hybrid",
        "markov_adaptive",
        "hybrid_adaptive",
    ]
)
KEY_METRICS = [
    "end_to_end_logical_mib_per_sec",
    "logical_mib_per_sec",
    "policy_demand_faults",
    "policy_migration_read_bytes",
    "policy_migration_write_bytes",
    "policy_prefetch_completed",
    "policy_prefetch_useful",
    "policy_prefetch_late",
    "policy_prefetch_unused_evictions",
    "policy_evicted_hot_bytes",
    "policy_demand_fault_stall_p50_ns",
    "policy_demand_fault_stall_p90_ns",
    "policy_demand_fault_stall_p99_ns",
    "stream_pipeline_max_cycle_policy_demand_faults",
    "stream_pipeline_max_cycle_policy_read_bytes",
    "stream_pipeline_max_cycle_policy_write_bytes",
    "stream_pipeline_max_cycle_policy_stall_ns",
]
SANITIZED_ENV_KEYS = {
    "LD_PRELOAD",
}
SANITIZED_ENV_PREFIXES = (
    "MAI_",
)
SUMMARY_METRICS = [
    "end_to_end_logical_mib_per_sec",
    "ratio_to_mai_sufficient_e2e",
    "policy_demand_faults",
    "policy_migration_read_bytes",
    "policy_migration_write_bytes",
    "policy_prefetch_unused_evictions",
    "policy_evicted_hot_bytes",
    "policy_demand_fault_stall_p90_ns",
]


def output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def parse_value(value: str) -> Any:
    if value == "":
        return ""
    try:
        if value.lower().startswith(("0x", "-0x")):
            return int(value, 16)
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def parse_key_value_line(line: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for token in shlex.split(line):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = parse_value(value)
    return fields


def run_text(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        args,
        cwd=str(cwd),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout.strip()


def git_sha(cwd: Path) -> str:
    value = run_text(["git", "rev-parse", "HEAD"], cwd)
    return value if value else "unknown"


def git_dirty(cwd: Path) -> bool:
    value = run_text(
        ["git", "status", "--porcelain"],
        cwd=str(cwd),
    )
    return bool(value)


def cmake_build_type(binary: Path) -> str:
    for parent in [binary.parent, *binary.parents]:
        cache = parent / "CMakeCache.txt"
        if not cache.exists():
            continue
        for line in cache.read_text(errors="replace").splitlines():
            if line.startswith("CMAKE_BUILD_TYPE:"):
                return line.split("=", 1)[1] or "unknown"
    return "unknown"


def policy_config(name: str) -> tuple[str, dict[str, str]]:
    if name.endswith("_adaptive"):
        return name[: -len("_adaptive")], {"MAI_POLICY_ADAPTIVE_CONTROL": "1"}
    return name, {"MAI_POLICY_ADAPTIVE_CONTROL": "0"}


def workload_size(workload: str, allocation_size: str, pipeline_size: str) -> str:
    if workload in {"policy_stream_pipeline", "stream_kernel_pipeline"}:
        return pipeline_size
    return allocation_size


def expected_managed_allocations(workload: str) -> float | None:
    if workload in {"policy_stream_pipeline", "stream_kernel_pipeline"}:
        return 9.0
    if workload == "stream_bandwidth":
        return 3.0
    if workload.startswith("policy_"):
        return 1.0
    return None


def benchmark_env(base: dict[str, str], updates: dict[str, str]) -> dict[str, str]:
    env = {}
    for key, value in base.items():
        if key in SANITIZED_ENV_KEYS:
            continue
        if any(key.startswith(prefix) for prefix in SANITIZED_ENV_PREFIXES):
            continue
        env[key] = value
    env.update({key: str(value) for key, value in updates.items()})
    return env


def run_case(
    *,
    args: argparse.Namespace,
    metadata: dict[str, Any],
    scenario: str,
    workload: str,
    policy_name: str,
    migration_policy: str,
    seed: int,
    repetition: int,
    env_updates: dict[str, str],
) -> dict[str, Any]:
    size = workload_size(workload, args.allocation_size, args.pipeline_matrix_size)
    scratch = (
        Path(args.output_dir)
        / "scratch"
        / scenario
        / workload
        / policy_name
        / f"rep-{repetition}"
        / f"seed-{seed}"
    )
    scratch.mkdir(parents=True, exist_ok=True)
    env_updates = dict(env_updates)
    if env_updates.get("MAI_ENABLE") == "1":
        env_updates.setdefault("MAI_PATH", str(scratch))
    env = benchmark_env(
        os.environ,
        {
            "MAI_BENCH_POLICY_SIGNATURE_SEED": str(seed),
            "MAI_BENCH_STREAM_PIPELINE_SEED": str(seed),
            "MAI_BENCH_STREAM_PIPELINE_ORDER": args.pipeline_order,
            "MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS": str(
                args.pipeline_group_iterations
            ),
            **env_updates,
        },
    )
    command = [str(args.benchmark), workload, size]
    timed_out = False
    row_timeout = args.row_timeout_sec if args.row_timeout_sec > 0.0 else None
    try:
        completed = subprocess.run(
            command,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=row_timeout,
        )
        exit_code = completed.returncode
        raw_stdout = output_text(completed.stdout).strip()
        raw_stderr = output_text(completed.stderr).strip()
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        raw_stdout = output_text(exc.stdout).strip()
        raw_stderr = output_text(exc.stderr).strip()
    metrics: dict[str, Any] = {}
    for line in raw_stdout.splitlines():
        parsed = parse_key_value_line(line)
        if parsed.get("mode") == workload:
            metrics.update(parsed)
        elif parsed:
            metrics.update(parsed)

    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        **metadata,
        "scenario": scenario,
        "workload": workload,
        "policy": policy_name,
        "migration_policy": migration_policy,
        "seed": seed,
        "repetition": repetition,
        "size": size,
        "command": command,
        "scratch_path": str(scratch),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "row_timeout_sec": args.row_timeout_sec,
        "observation_mode": env.get("MAI_POLICY_OBSERVE_PREFETCH_WRITES", "0"),
        "uffd_resident_limit": env.get("MAI_UFFD_RESIDENT_LIMIT", ""),
        "uffd_resident_low_limit": env.get("MAI_UFFD_RESIDENT_LOW_LIMIT", ""),
        "migration_chunk": env.get("MAI_MIGRATION_CHUNK", ""),
        "uffd_prefetch_chunks": env.get("MAI_UFFD_PREFETCH_CHUNKS", ""),
        "adaptive_control": env.get("MAI_POLICY_ADAPTIVE_CONTROL", "0"),
        "async_prefetch": env.get("MAI_UFFD_ASYNC_PREFETCH", "0"),
        "active_record_epochs": env.get("MAI_ACTIVE_RECORD_EPOCHS", ""),
        "clean_shadow": env.get("MAI_UFFD_CLEAN_SHADOW", "0"),
        "raw_stdout": raw_stdout,
        "raw_stderr": raw_stderr,
        "metrics": metrics,
        "invalid_reasons": [],
    }
    validate_row(row)
    return row


def metric_number(row: dict[str, Any], key: str) -> float | None:
    value = row.get("metrics", {}).get(key, row.get(key))
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def metric_any(row: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = metric_number(row, key)
        if value is not None:
            return value
    return None


def validate_row(row: dict[str, Any]) -> None:
    reasons: list[str] = []
    metrics = row["metrics"]
    if row["exit_code"] != 0:
        reasons.append("nonzero_exit")
    if row.get("timed_out"):
        reasons.append("timeout")
    if not metrics:
        reasons.append("missing_metrics")
    managed_delta = metric_number(row, "managed_delta")
    read_bytes = metric_number(row, "policy_migration_read_bytes") or 0.0
    write_bytes = metric_number(row, "policy_migration_write_bytes") or 0.0
    demand_faults = metric_number(row, "policy_demand_faults") or 0.0
    uffd_alloc_delta = metric_number(row, "uffd_alloc_delta") or 0.0
    uffd_fault_delta = metric_number(row, "uffd_fault_delta") or 0.0
    uffd_eviction_delta = metric_number(row, "uffd_eviction_delta") or 0.0
    expected_managed = expected_managed_allocations(row["workload"])
    if row["scenario"] in {"native_sufficient", "mai_passthrough"}:
        if managed_delta not in (None, 0.0):
            reasons.append("unexpected_managed_allocation")
        if read_bytes + write_bytes + demand_faults != 0.0:
            reasons.append("unexpected_pressure_activity")
    elif row["scenario"] == "mai_managed_sufficient":
        if managed_delta in (None, 0.0):
            reasons.append("no_managed_allocation")
        elif expected_managed is not None and managed_delta != expected_managed:
            reasons.append("wrong_managed_allocation_count")
        if (
            read_bytes
            + write_bytes
            + demand_faults
            + uffd_alloc_delta
            + uffd_fault_delta
            + uffd_eviction_delta
            != 0.0
        ):
            reasons.append("unexpected_pressure_activity")
    elif row["scenario"] == "policy_pressure":
        if managed_delta in (None, 0.0):
            reasons.append("no_managed_allocation")
        elif expected_managed is not None and managed_delta != expected_managed:
            reasons.append("wrong_managed_allocation_count")
        if metric_any(row, "uffd_pager_available", "uffd_available") != 1.0:
            reasons.append("uffd_unavailable")
        if metric_number(row, "uffd_fallback_delta") not in (None, 0.0):
            reasons.append("uffd_fallback")
        if uffd_alloc_delta == 0.0:
            reasons.append("no_uffd_allocation")
        elif expected_managed is not None and uffd_alloc_delta != expected_managed:
            reasons.append("wrong_uffd_allocation_count")
        if read_bytes + write_bytes == 0.0 and demand_faults == 0.0:
            reasons.append("no_pressure_activity")
    row["invalid_reasons"] = reasons


def make_metadata(repo: Path, args: argparse.Namespace) -> dict[str, Any]:
    uname = platform.uname()
    return {
        "git_sha": git_sha(repo),
        "git_dirty": git_dirty(repo),
        "build_type": args.build_type or cmake_build_type(Path(args.benchmark)),
        "host_system": uname.system,
        "host_release": uname.release,
        "host_machine": uname.machine,
        "docker_image": "",
        "docker_image_id": "",
        "memory_limit": "",
        "swap_limit": "",
    }


def write_ndjson(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def append_ndjson(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def record_row(rows: list[dict[str, Any]], partial_path: Path, row: dict[str, Any]) -> None:
    rows.append(row)
    append_ndjson(partial_path, row)


def attach_baseline_ratios(rows: list[dict[str, Any]]) -> None:
    baselines: dict[tuple[str, int, int, str], float] = {}
    for row in rows:
        if row["scenario"] != "mai_managed_sufficient":
            continue
        e2e = metric_number(row, "end_to_end_logical_mib_per_sec")
        if e2e and e2e > 0.0:
            key = (row["workload"], row["seed"], row["repetition"], row["size"])
            baselines[key] = e2e
    for row in rows:
        e2e = metric_number(row, "end_to_end_logical_mib_per_sec")
        key = (row["workload"], row["seed"], row["repetition"], row["size"])
        baseline = baselines.get(key)
        if e2e is not None and baseline:
            row["ratio_to_mai_sufficient_e2e"] = e2e / baseline
        else:
            row["ratio_to_mai_sufficient_e2e"] = None


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["scenario"], row["workload"], row["policy"])].append(row)
    summary: list[dict[str, Any]] = []
    for (scenario, workload, policy), group_rows in sorted(groups.items()):
        item: dict[str, Any] = {
            "scenario": scenario,
            "workload": workload,
            "policy": policy,
            "runs": len(group_rows),
            "valid_runs": sum(1 for row in group_rows if not row["invalid_reasons"]),
            "invalid_runs": sum(1 for row in group_rows if row["invalid_reasons"]),
        }
        valid_rows = [row for row in group_rows if not row["invalid_reasons"]]
        for metric in SUMMARY_METRICS:
            values = []
            for row in valid_rows:
                if metric == "ratio_to_mai_sufficient_e2e":
                    value = row.get(metric)
                else:
                    value = metric_number(row, metric)
                if isinstance(value, (int, float)):
                    values.append(float(value))
            item[f"mean_{metric}"] = sum(values) / len(values) if values else ""
        summary.append(item)
    return summary


def write_summary_csv(path: Path, summary: list[dict[str, Any]]) -> None:
    if not summary:
        path.write_text("", encoding="utf-8")
        return
    columns = list(summary[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(summary)


def write_summary_markdown(path: Path, summary: list[dict[str, Any]]) -> None:
    columns = [
        "scenario",
        "workload",
        "policy",
        "valid_runs",
        "mean_end_to_end_logical_mib_per_sec",
        "mean_ratio_to_mai_sufficient_e2e",
        "mean_policy_demand_faults",
        "mean_policy_migration_read_bytes",
        "mean_policy_migration_write_bytes",
    ]
    lines = [
        "# Retained Policy Matrix Summary",
        "",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in summary:
        values = []
        for column in columns:
            value = row.get(column, "")
            if isinstance(value, float):
                if "ratio" in column:
                    values.append(f"{value:.3f}")
                else:
                    values.append(f"{value:.1f}")
            else:
                values.append(str(value))
        lines.append("| " + " | ".join(values) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libmai", type=Path)
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("policy-matrix-results"))
    parser.add_argument("--workloads", default=os.environ.get("MAI_BENCH_WORKLOADS", DEFAULT_WORKLOADS))
    parser.add_argument("--policies", default=os.environ.get("MAI_BENCH_POLICIES", DEFAULT_POLICIES))
    parser.add_argument("--seeds", default=os.environ.get("MAI_BENCH_SEEDS", DEFAULT_SEEDS))
    parser.add_argument("--repetitions", type=int, default=int(os.environ.get("MAI_BENCH_REPETITIONS", "1")))
    parser.add_argument("--allocation-size", default=os.environ.get("MAI_BENCH_ALLOCATION_SIZE", "64M"))
    parser.add_argument("--pipeline-matrix-size", default=os.environ.get("MAI_BENCH_PIPELINE_MATRIX_SIZE", "16M"))
    parser.add_argument("--pipeline-order", default=os.environ.get("MAI_BENCH_STREAM_PIPELINE_ORDER", "random"))
    parser.add_argument("--pipeline-group-iterations", type=int, default=int(os.environ.get("MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS", "4")))
    parser.add_argument("--mai-threshold", default=os.environ.get("MAI_THRESHOLD", "4K"))
    parser.add_argument("--mai-arena-size", default=os.environ.get("MAI_ARENA_SIZE", "256M"))
    parser.add_argument("--mai-max-rss", default=os.environ.get("MAI_MAX_RSS", "32M"))
    parser.add_argument("--resident-limit", default=os.environ.get("MAI_UFFD_RESIDENT_LIMIT", "16M"))
    parser.add_argument("--resident-low-limit", default=os.environ.get("MAI_UFFD_RESIDENT_LOW_LIMIT", "12M"))
    parser.add_argument("--prefetch-chunks", default=os.environ.get("MAI_UFFD_PREFETCH_CHUNKS", "4"))
    parser.add_argument("--migration-chunk", default=os.environ.get("MAI_MIGRATION_CHUNK", "2M"))
    parser.add_argument("--successor-chain-depth", default=os.environ.get("MAI_POLICY_SUCCESSOR_CHAIN_DEPTH", "2"))
    parser.add_argument("--observe-prefetch-writes", default=os.environ.get("MAI_POLICY_OBSERVE_PREFETCH_WRITES", "0"))
    parser.add_argument("--row-timeout-sec", type=float, default=float(os.environ.get("MAI_BENCH_ROW_TIMEOUT_SEC", "0")))
    parser.add_argument("--run-baselines", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--fail-on-error", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--build-type", default=os.environ.get("MAI_BENCH_BUILD_TYPE", ""))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    args.libmai = args.libmai.expanduser().resolve()
    args.benchmark = args.benchmark.expanduser().resolve()
    args.output_dir = args.output_dir.expanduser().resolve()
    if not args.libmai.is_file() or not args.benchmark.is_file():
        print("libmai or benchmark binary is missing", file=sys.stderr)
        return 2
    if not os.access(args.benchmark, os.X_OK):
        print("benchmark binary is not executable", file=sys.stderr)
        return 2
    args.output_dir.mkdir(parents=True, exist_ok=True)

    repo = Path(__file__).resolve().parents[1]
    metadata = make_metadata(repo, args)
    workloads = split_csv(args.workloads)
    policies = split_csv(args.policies)
    seeds = [int(seed) for seed in split_csv(args.seeds)]

    rows: list[dict[str, Any]] = []
    partial_path = args.output_dir / "partial_rows.ndjson"
    partial_path.write_text("", encoding="utf-8")
    for repetition in range(1, args.repetitions + 1):
        for seed in seeds:
            for workload in workloads:
                if args.run_baselines:
                    record_row(
                        rows,
                        partial_path,
                        run_case(
                            args=args,
                            metadata=metadata,
                            scenario="native_sufficient",
                            workload=workload,
                            policy_name="baseline",
                            migration_policy="",
                            seed=seed,
                            repetition=repetition,
                            env_updates={"MAI_ACCESS_EXPECT_MANAGED": "0"},
                        ),
                    )
                    record_row(
                        rows,
                        partial_path,
                        run_case(
                            args=args,
                            metadata=metadata,
                            scenario="mai_passthrough",
                            workload=workload,
                            policy_name="baseline",
                            migration_policy="",
                            seed=seed,
                            repetition=repetition,
                            env_updates={
                                "MAI_ENABLE": "1",
                                "MAI_THRESHOLD": "16T",
                                "MAI_ARENA_SIZE": args.mai_arena_size,
                                "MAI_MAX_RSS": "off",
                                "MAI_RECLAIM_POLICY": "none",
                                "MAI_ACCESS_EXPECT_MANAGED": "0",
                                "LD_PRELOAD": str(args.libmai),
                            },
                        ),
                    )
                    record_row(
                        rows,
                        partial_path,
                        run_case(
                            args=args,
                            metadata=metadata,
                            scenario="mai_managed_sufficient",
                            workload=workload,
                            policy_name="baseline",
                            migration_policy="",
                            seed=seed,
                            repetition=repetition,
                            env_updates={
                                "MAI_ENABLE": "1",
                                "MAI_THRESHOLD": args.mai_threshold,
                                "MAI_ARENA_SIZE": args.mai_arena_size,
                                "MAI_BACKEND": "anon",
                                "MAI_MAX_RSS": "off",
                                "MAI_RECLAIM_POLICY": "none",
                                "LD_PRELOAD": str(args.libmai),
                            },
                        ),
                    )
                for policy_name in policies:
                    migration_policy, extra_env = policy_config(policy_name)
                    record_row(
                        rows,
                        partial_path,
                        run_case(
                            args=args,
                            metadata=metadata,
                            scenario="policy_pressure",
                            workload=workload,
                            policy_name=policy_name,
                            migration_policy=migration_policy,
                            seed=seed,
                            repetition=repetition,
                            env_updates={
                                "MAI_ENABLE": "1",
                                "MAI_THRESHOLD": args.mai_threshold,
                                "MAI_ARENA_SIZE": args.mai_arena_size,
                                "MAI_BACKEND": "auto",
                                "MAI_MAX_RSS": args.mai_max_rss,
                                "MAI_UFFD_PAGER": "required",
                                "MAI_UFFD_RESIDENT_LIMIT": args.resident_limit,
                                "MAI_UFFD_RESIDENT_LOW_LIMIT": args.resident_low_limit,
                                "MAI_UFFD_PREFETCH_CHUNKS": args.prefetch_chunks,
                                "MAI_MIGRATION_CHUNK": args.migration_chunk,
                                "MAI_MIGRATION_POLICY": migration_policy,
                                "MAI_POLICY_SUCCESSOR_CHAIN_DEPTH": args.successor_chain_depth,
                                "MAI_POLICY_OBSERVE_PREFETCH_WRITES": args.observe_prefetch_writes,
                                "LD_PRELOAD": str(args.libmai),
                                **extra_env,
                            },
                        ),
                    )

    attach_baseline_ratios(rows)
    summary = summarize(rows)
    write_ndjson(args.output_dir / "rows.ndjson", rows)
    write_summary_csv(args.output_dir / "summary.csv", summary)
    write_summary_markdown(args.output_dir / "summary.md", summary)

    invalid = [row for row in rows if row["invalid_reasons"]]
    print(f"wrote {len(rows)} rows to {args.output_dir / 'rows.ndjson'}")
    print(f"wrote summary to {args.output_dir / 'summary.csv'}")
    if invalid:
        print(f"invalid_rows={len(invalid)}", file=sys.stderr)
        for row in invalid[:10]:
            print(
                "invalid "
                f"scenario={row['scenario']} workload={row['workload']} "
                f"policy={row['policy']} seed={row['seed']} "
                f"repetition={row['repetition']} "
                f"reasons={','.join(row['invalid_reasons'])}",
                file=sys.stderr,
            )
        if args.fail_on_error:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
