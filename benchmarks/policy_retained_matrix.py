#!/usr/bin/env python3
"""Run retained MAI policy benchmark rows and write machine-readable artifacts."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
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
        "policy_stream_pipeline_phase_decoy",
        "policy_long_tail_admission",
        "policy_recency_frequency_pivot",
        "policy_arc_adaptation_pivot",
        "policy_irr_scan_return",
        "policy_phase_shift_hotset",
        "policy_signature_context_cycle",
    ]
)
DEFAULT_POLICIES = ",".join(
    [
        "legacy",
        "markov",
        "car",
        "arc",
        "irr",
        "wtinylfu",
        "hybrid",
        "phase",
        "markov_cohort",
        "markov_adaptive",
        "hybrid_adaptive",
        "phase_adaptive",
        "phase_budget_adaptive",
        "phase_boundary_budget_adaptive",
        "phase_shadow_probe_budget_adaptive",
        "phase_edge_probe_budget_adaptive",
        "markov_phase_budget_adaptive",
        "markov_cohort_adaptive",
    ]
)
KEY_METRICS = [
    "end_to_end_logical_mib_per_sec",
    "logical_mib_per_sec",
    "policy_demand_faults",
    "policy_migration_read_bytes",
    "policy_migration_write_bytes",
    "policy_read_amplification",
    "policy_write_amplification",
    "policy_prefetch_completed",
    "policy_prefetch_useful",
    "policy_prefetch_late",
    "policy_prefetch_unused_evictions",
    "policy_async_prefetch_enqueued",
    "policy_async_prefetch_completed",
    "policy_async_prefetch_dropped",
    "policy_async_completed_without_prefetch",
    "policy_async_drop_rate",
    "policy_throttle_events",
    "policy_adaptive_prefetch_capped",
    "policy_adaptive_admission_rejected",
    "policy_adaptive_budget_gate",
    "policy_adaptive_budget_bytes",
    "policy_adaptive_window_migration_bytes",
    "policy_markov_lead_candidates",
    "policy_markov_lead_admitted",
    "policy_markov_lead_completed",
    "policy_markov_lead_useful",
    "policy_phase_candidates",
    "policy_phase_admitted",
    "policy_phase_completed",
    "policy_phase_useful",
    "policy_phase_conflicts",
    "policy_phase_confidence_rejected",
    "policy_phase_budget_rejected",
    "policy_phase_safe_victim_rejected",
    "policy_phase_victim_rejected",
    "policy_phase_duplicate_candidates",
    "policy_phase_target_hot_skipped",
    "policy_phase_active_slots",
    "policy_phase_top_score",
    "policy_phase_unused_evictions",
    "policy_phase_boundary_prefetches",
    "policy_phase_hold_activations",
    "policy_phase_shadow_candidates",
    "policy_phase_shadow_useful",
    "policy_phase_shadow_late",
    "policy_phase_shadow_expired",
    "policy_phase_shadow_overwritten",
    "policy_phase_shadow_probe_candidates",
    "policy_phase_shadow_edge_rejected",
    "policy_phase_shadow_edge_confirmed",
    "policy_phase_shadow_top_late",
    "policy_phase_shadow_max_late",
    "policy_hint_candidates",
    "policy_hint_admitted",
    "policy_hint_completed",
    "policy_hint_useful",
    "policy_hint_rejected",
    "policy_arc_t1_chunks",
    "policy_arc_t2_chunks",
    "policy_arc_b1_chunks",
    "policy_arc_b2_chunks",
    "policy_arc_p_chunks",
    "policy_arc_b1_hits",
    "policy_arc_b2_hits",
    "policy_arc_target_increases",
    "policy_arc_target_decreases",
    "policy_arc_t1_hits",
    "policy_arc_t2_hits",
    "policy_arc_t1_to_t2_promotions",
    "policy_arc_replace_t1",
    "policy_arc_replace_t2",
    "policy_arc_b1_pruned",
    "policy_arc_b2_pruned",
    "policy_arc_prefetch_admitted_t1",
    "policy_arc_prefetch_rejected_pressure",
    "policy_arc_prefetch_promoted_to_t2",
    "policy_irr_resident_chunks",
    "policy_irr_protected_chunks",
    "policy_irr_ghost_chunks",
    "policy_irr_target_protected_chunks",
    "policy_irr_ghost_hits",
    "policy_irr_promotions",
    "policy_irr_demotions",
    "policy_irr_pressure_rejected",
    "policy_irr_immature_rejected",
    "policy_irr_max_interval_epochs",
    "policy_evicted_hot_bytes",
    "policy_hybrid_cohort_candidates",
    "policy_hybrid_cohort_admitted",
    "policy_hybrid_cohort_completed",
    "policy_hybrid_cohort_useful",
    "run_minor_faults_delta",
    "run_major_faults_delta",
    "run_inblock_delta",
    "run_oublock_delta",
    "run_voluntary_ctxt_delta",
    "run_involuntary_ctxt_delta",
    "run_user_cpu_us_delta",
    "run_sys_cpu_us_delta",
    "run_maxrss_kib",
    "cgroup_memory_max_bytes",
    "cgroup_memory_max_available",
    "cgroup_memory_max_unbounded",
    "cgroup_memory_max_is_max_token",
    "cgroup_memory_current_before",
    "cgroup_memory_current_after",
    "cgroup_memory_events_high_delta",
    "cgroup_memory_events_max_delta",
    "cgroup_memory_events_oom_delta",
    "cgroup_swap_max_bytes",
    "cgroup_swap_max_available",
    "cgroup_swap_max_unbounded",
    "cgroup_swap_max_is_max_token",
    "cgroup_swap_current_before",
    "cgroup_swap_current_after",
    "stream_backing_fs_type",
    "stream_backing_is_tmpfs",
    "policy_demand_fault_stall_p50_ns",
    "policy_demand_fault_stall_p90_ns",
    "policy_demand_fault_stall_p99_ns",
    "stream_pipeline_max_cycle_policy_demand_faults",
    "stream_pipeline_max_cycle_policy_read_bytes",
    "stream_pipeline_max_cycle_policy_write_bytes",
    "stream_pipeline_max_cycle_policy_stall_ns",
    "stream_pipeline_cycle_policy_demand_faults_p50",
    "stream_pipeline_cycle_policy_demand_faults_p90",
    "stream_pipeline_cycle_policy_demand_faults_p99",
    "stream_pipeline_cycle_policy_read_bytes_p50",
    "stream_pipeline_cycle_policy_read_bytes_p90",
    "stream_pipeline_cycle_policy_read_bytes_p99",
    "stream_pipeline_cycle_policy_write_bytes_p50",
    "stream_pipeline_cycle_policy_write_bytes_p90",
    "stream_pipeline_cycle_policy_write_bytes_p99",
    "stream_pipeline_cycle_policy_stall_ns_p50",
    "stream_pipeline_cycle_policy_stall_ns_p90",
    "stream_pipeline_cycle_policy_stall_ns_p99",
    "stream_pipeline_cycle_policy_unused_prefetch_evictions_p50",
    "stream_pipeline_cycle_policy_unused_prefetch_evictions_p90",
    "stream_pipeline_cycle_policy_unused_prefetch_evictions_p99",
    "stream_pipeline_group_visit_0",
    "stream_pipeline_group_visit_1",
    "stream_pipeline_group_visit_2",
    "stream_pipeline_transition_00",
    "stream_pipeline_transition_01",
    "stream_pipeline_transition_02",
    "stream_pipeline_transition_10",
    "stream_pipeline_transition_11",
    "stream_pipeline_transition_12",
    "stream_pipeline_transition_20",
    "stream_pipeline_transition_21",
    "stream_pipeline_transition_22",
    "stream_pipeline_unique_transitions",
    "stream_pipeline_worst_cycle_index",
    "stream_pipeline_worst_cycle_group",
    "stream_pipeline_worst_cycle_prev_group",
    "stream_pipeline_phase_chunks",
    "stream_pipeline_phase_return_cycles",
    "stream_pipeline_phase_return_policy_demand_faults",
    "stream_pipeline_phase_return_policy_read_bytes",
    "stream_pipeline_phase_return_policy_write_bytes",
    "stream_pipeline_phase_return_policy_stall_ns",
    "stream_pipeline_phase_return_policy_hot_evicted_bytes",
    "stream_pipeline_phase_return_policy_unused_prefetch_evictions",
    "stream_pipeline_phase_return_estimated_hits",
    "stream_pipeline_phase_return_estimated_hit_ratio",
    "stream_pipeline_phase_warm_return_cycles",
    "stream_pipeline_phase_warm_return_policy_demand_faults",
    "stream_pipeline_phase_warm_return_policy_read_bytes",
    "stream_pipeline_phase_warm_return_policy_write_bytes",
    "stream_pipeline_phase_warm_return_policy_stall_ns",
    "stream_pipeline_phase_warm_return_policy_hot_evicted_bytes",
    "stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions",
    "stream_pipeline_phase_warm_return_estimated_hits",
    "stream_pipeline_phase_warm_return_estimated_hit_ratio",
    "stream_pipeline_phase_decoy_cycles",
    "stream_pipeline_phase_decoy_policy_demand_faults",
    "stream_pipeline_phase_decoy_policy_read_bytes",
    "stream_pipeline_phase_decoy_policy_write_bytes",
    "stream_pipeline_phase_decoy_policy_stall_ns",
    "stream_pipeline_phase_decoy_policy_hot_evicted_bytes",
    "stream_pipeline_phase_decoy_policy_unused_prefetch_evictions",
    "policy_pivot_return_faults",
    "policy_pivot_return_touches",
    "policy_pivot_return_hits",
    "policy_pivot_hot_return_hit_ratio",
    "policy_pivot_adaptation_lag_touches",
    "policy_irr_hot_return_faults",
    "policy_irr_hot_return_touches",
    "policy_irr_hot_return_hits",
    "policy_irr_hot_return_hit_ratio",
    "policy_irr_decoy_return_faults",
    "policy_irr_decoy_return_touches",
    "policy_irr_decoy_return_hits",
    "policy_irr_decoy_return_hit_ratio",
    "policy_irr_discrimination_score",
    "policy_irr_adaptation_lag_touches",
    "policy_irr_scan_faults",
    "policy_irr_scan_read_bytes",
    "policy_irr_scan_write_bytes",
    "policy_irr_scan_hot_evicted_bytes",
    "policy_irr_scan_unused_prefetch_evictions",
    "policy_irr_scan_stall_ns",
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
    "policy_read_amplification",
    "policy_write_amplification",
    "policy_prefetch_unused_evictions",
    "policy_prefetch_completed",
    "policy_prefetch_useful",
    "policy_prefetch_late",
    "policy_prefetch_unused_evicted_bytes",
    "policy_prefetch_accuracy_observed",
    "policy_prefetch_coverage_observed",
    "policy_async_prefetch_enqueued",
    "policy_async_prefetch_completed",
    "policy_async_prefetch_dropped",
    "policy_async_completed_without_prefetch",
    "policy_async_drop_rate",
    "policy_throttle_events",
    "policy_adaptive_prefetch_capped",
    "policy_adaptive_admission_rejected",
    "policy_adaptive_budget_gate",
    "policy_adaptive_budget_bytes",
    "policy_adaptive_window_migration_bytes",
    "policy_markov_lead_candidates",
    "policy_markov_lead_admitted",
    "policy_markov_lead_completed",
    "policy_markov_lead_useful",
    "policy_phase_candidates",
    "policy_phase_admitted",
    "policy_phase_completed",
    "policy_phase_useful",
    "policy_phase_conflicts",
    "policy_phase_confidence_rejected",
    "policy_phase_budget_rejected",
    "policy_phase_safe_victim_rejected",
    "policy_phase_victim_rejected",
    "policy_phase_duplicate_candidates",
    "policy_phase_target_hot_skipped",
    "policy_phase_active_slots",
    "policy_phase_top_score",
    "policy_phase_unused_evictions",
    "policy_phase_boundary_prefetches",
    "policy_phase_hold_activations",
    "policy_phase_shadow_candidates",
    "policy_phase_shadow_useful",
    "policy_phase_shadow_late",
    "policy_phase_shadow_expired",
    "policy_phase_shadow_overwritten",
    "policy_phase_shadow_probe_candidates",
    "policy_phase_shadow_edge_rejected",
    "policy_phase_shadow_edge_confirmed",
    "policy_phase_shadow_top_late",
    "policy_phase_shadow_max_late",
    "policy_hint_candidates",
    "policy_hint_admitted",
    "policy_hint_completed",
    "policy_hint_useful",
    "policy_hint_rejected",
    "policy_arc_t1_chunks",
    "policy_arc_t2_chunks",
    "policy_arc_b1_chunks",
    "policy_arc_b2_chunks",
    "policy_arc_p_chunks",
    "policy_arc_b1_hits",
    "policy_arc_b2_hits",
    "policy_arc_target_increases",
    "policy_arc_target_decreases",
    "policy_arc_t1_hits",
    "policy_arc_t2_hits",
    "policy_arc_t1_to_t2_promotions",
    "policy_arc_replace_t1",
    "policy_arc_replace_t2",
    "policy_arc_b1_pruned",
    "policy_arc_b2_pruned",
    "policy_arc_prefetch_admitted_t1",
    "policy_arc_prefetch_rejected_pressure",
    "policy_arc_prefetch_promoted_to_t2",
    "policy_irr_resident_chunks",
    "policy_irr_protected_chunks",
    "policy_irr_ghost_chunks",
    "policy_irr_target_protected_chunks",
    "policy_irr_ghost_hits",
    "policy_irr_promotions",
    "policy_irr_demotions",
    "policy_irr_pressure_rejected",
    "policy_irr_immature_rejected",
    "policy_irr_max_interval_epochs",
    "policy_evicted_hot_bytes",
    "policy_hybrid_cohort_candidates",
    "policy_hybrid_cohort_admitted",
    "policy_hybrid_cohort_completed",
    "policy_hybrid_cohort_useful",
    "ratio_to_native_sufficient_e2e",
    "ratio_to_mai_passthrough_sufficient_e2e",
    "ratio_to_best_sufficient_e2e",
    "ratio_to_linux_shared_pipeline_e2e",
    "ratio_to_linux_anon_pipeline_e2e",
    "run_minor_faults_delta",
    "run_major_faults_delta",
    "run_inblock_delta",
    "run_oublock_delta",
    "run_maxrss_kib",
    "cgroup_memory_max_bytes",
    "cgroup_memory_max_available",
    "cgroup_memory_max_unbounded",
    "cgroup_memory_max_is_max_token",
    "cgroup_memory_events_high_delta",
    "cgroup_memory_events_max_delta",
    "cgroup_memory_events_oom_delta",
    "cgroup_swap_max_available",
    "cgroup_swap_max_unbounded",
    "cgroup_swap_max_is_max_token",
    "cgroup_swap_current_after",
    "stream_backing_fs_type",
    "stream_backing_is_tmpfs",
    "policy_demand_fault_stall_p90_ns",
    "policy_demand_fault_stall_p99_ns",
    "stream_pipeline_max_cycle_policy_demand_faults",
    "stream_pipeline_max_cycle_policy_read_bytes",
    "stream_pipeline_max_cycle_policy_write_bytes",
    "stream_pipeline_max_cycle_policy_stall_ns",
    "stream_pipeline_cycle_policy_demand_faults_p90",
    "stream_pipeline_cycle_policy_demand_faults_p99",
    "stream_pipeline_cycle_policy_read_bytes_p90",
    "stream_pipeline_cycle_policy_read_bytes_p99",
    "stream_pipeline_cycle_policy_write_bytes_p90",
    "stream_pipeline_cycle_policy_write_bytes_p99",
    "stream_pipeline_cycle_policy_stall_ns_p90",
    "stream_pipeline_cycle_policy_stall_ns_p99",
    "stream_pipeline_cycle_policy_unused_prefetch_evictions_p90",
    "stream_pipeline_cycle_policy_unused_prefetch_evictions_p99",
    "stream_pipeline_unique_transitions",
    "stream_pipeline_phase_return_policy_demand_faults",
    "stream_pipeline_phase_return_policy_read_bytes",
    "stream_pipeline_phase_return_policy_write_bytes",
    "stream_pipeline_phase_return_policy_stall_ns",
    "stream_pipeline_phase_return_policy_hot_evicted_bytes",
    "stream_pipeline_phase_return_policy_unused_prefetch_evictions",
    "stream_pipeline_phase_return_estimated_hit_ratio",
    "stream_pipeline_phase_warm_return_policy_demand_faults",
    "stream_pipeline_phase_warm_return_policy_read_bytes",
    "stream_pipeline_phase_warm_return_policy_write_bytes",
    "stream_pipeline_phase_warm_return_policy_stall_ns",
    "stream_pipeline_phase_warm_return_policy_hot_evicted_bytes",
    "stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions",
    "stream_pipeline_phase_warm_return_estimated_hit_ratio",
    "stream_pipeline_phase_decoy_policy_demand_faults",
    "stream_pipeline_phase_decoy_policy_read_bytes",
    "stream_pipeline_phase_decoy_policy_write_bytes",
    "stream_pipeline_phase_decoy_policy_stall_ns",
    "stream_pipeline_phase_decoy_policy_hot_evicted_bytes",
    "stream_pipeline_phase_decoy_policy_unused_prefetch_evictions",
    "policy_pivot_return_faults",
    "policy_pivot_return_touches",
    "policy_pivot_return_hits",
    "policy_pivot_hot_return_hit_ratio",
    "policy_pivot_adaptation_lag_touches",
    "policy_irr_hot_return_faults",
    "policy_irr_hot_return_touches",
    "policy_irr_hot_return_hits",
    "policy_irr_hot_return_hit_ratio",
    "policy_irr_decoy_return_faults",
    "policy_irr_decoy_return_touches",
    "policy_irr_decoy_return_hits",
    "policy_irr_decoy_return_hit_ratio",
    "policy_irr_discrimination_score",
    "policy_irr_adaptation_lag_touches",
    "policy_irr_scan_faults",
    "policy_irr_scan_read_bytes",
    "policy_irr_scan_write_bytes",
    "policy_irr_scan_hot_evicted_bytes",
    "policy_irr_scan_unused_prefetch_evictions",
    "policy_irr_scan_stall_ns",
]
SUMMARY_SPREAD_METRICS = [
    "end_to_end_logical_mib_per_sec",
    "ratio_to_mai_sufficient_e2e",
    "ratio_to_best_sufficient_e2e",
    "policy_demand_faults",
    "policy_migration_read_bytes",
    "policy_migration_write_bytes",
    "policy_prefetch_unused_evictions",
    "policy_evicted_hot_bytes",
    "stream_pipeline_phase_return_policy_demand_faults",
    "stream_pipeline_phase_return_policy_read_bytes",
    "stream_pipeline_phase_return_policy_write_bytes",
    "stream_pipeline_phase_return_policy_stall_ns",
    "stream_pipeline_phase_return_estimated_hit_ratio",
    "stream_pipeline_phase_warm_return_policy_demand_faults",
    "stream_pipeline_phase_warm_return_policy_read_bytes",
    "stream_pipeline_phase_warm_return_policy_write_bytes",
    "stream_pipeline_phase_warm_return_policy_stall_ns",
    "stream_pipeline_phase_warm_return_estimated_hit_ratio",
    "stream_pipeline_phase_decoy_policy_demand_faults",
    "stream_pipeline_phase_decoy_policy_read_bytes",
    "stream_pipeline_phase_decoy_policy_write_bytes",
    "stream_pipeline_phase_decoy_policy_stall_ns",
    "policy_pivot_hot_return_hit_ratio",
    "policy_irr_hot_return_hit_ratio",
    "policy_irr_decoy_return_hit_ratio",
    "policy_irr_discrimination_score",
    "policy_irr_adaptation_lag_touches",
    "policy_irr_scan_hot_evicted_bytes",
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


def parse_size_bytes(value: str) -> int:
    text = value.strip().lower()
    if not text:
        raise ValueError("empty size")
    multipliers = {
        "kib": 1024,
        "kb": 1024,
        "k": 1024,
        "mib": 1024**2,
        "mb": 1024**2,
        "m": 1024**2,
        "gib": 1024**3,
        "gb": 1024**3,
        "g": 1024**3,
        "tib": 1024**4,
        "tb": 1024**4,
        "t": 1024**4,
        "b": 1,
    }
    for suffix, multiplier in sorted(
        multipliers.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if text.endswith(suffix):
            number = text[: -len(suffix)]
            if not number:
                raise ValueError(f"invalid size: {value}")
            return int(number) * multiplier
    return int(text)


def size_arg(value: str, auto_bytes: int) -> str:
    if value.strip().lower() == "auto":
        return str(auto_bytes)
    return value


def scenario_is_policy_pressure(scenario: str) -> bool:
    return scenario == "policy_pressure" or scenario.startswith("policy_pressure_")


def scenario_token(value: str) -> str:
    token = value.strip().lower()
    out = []
    for char in token:
        if char.isalnum():
            out.append(char)
        elif char in {".", "-", "_"}:
            out.append(char)
        else:
            out.append("_")
    return "".join(out).strip("_") or "auto"


def resident_limit_points(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    sweep = getattr(args, "resident_limit_sweep", "")
    if not sweep:
        return [("policy_pressure", args.resident_limit, args.resident_low_limit)]

    points: list[tuple[str, str, str]] = []
    for item in split_csv(sweep):
        if ":" in item:
            high, low = item.split(":", 1)
            high = high.strip()
            low = low.strip()
        else:
            high = item.strip()
            high_bytes = parse_size_bytes(high)
            low = str(max((high_bytes * 3) // 4, 4096))
        if not high or not low:
            raise ValueError(f"invalid resident-limit sweep point: {item}")
        scenario = f"policy_pressure_limit_{scenario_token(high)}"
        points.append((scenario, high, low))
    return points


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


def policy_config_finalize(base: str, env: dict[str, str]) -> tuple[str, dict[str, str]]:
    if base == "markov_phase":
        env["MAI_POLICY_PHASE_PREFETCH"] = "0"
    elif base == "phase_boundary":
        base = "phase"
        env["MAI_POLICY_PHASE_PREFETCH_BOUNDARY_ONLY"] = "1"
    elif base == "phase_shadow_probe":
        base = "phase"
        env["MAI_POLICY_PHASE_PREFETCH_BOUNDARY_ONLY"] = "1"
        env["MAI_POLICY_PHASE_SHADOW_PROBE_CHUNKS"] = "1"
    elif base == "phase_edge_probe":
        base = "phase"
        env["MAI_POLICY_PHASE_PREFETCH_BOUNDARY_ONLY"] = "1"
        env["MAI_POLICY_PHASE_SHADOW_PROBE_CHUNKS"] = "1"
        env["MAI_POLICY_PHASE_SHADOW_PROBE_MIN_LATE"] = "8"
    elif base.startswith("phase_edge_probe"):
        suffix = base[len("phase_edge_probe"):]
        if suffix and suffix.isdigit():
            base = "phase"
            env["MAI_POLICY_PHASE_PREFETCH_BOUNDARY_ONLY"] = "1"
            env["MAI_POLICY_PHASE_SHADOW_PROBE_CHUNKS"] = "1"
            env["MAI_POLICY_PHASE_SHADOW_PROBE_MIN_LATE"] = suffix
    return base, env


def policy_config(name: str) -> tuple[str, dict[str, str]]:
    if name.endswith("_lead_budget_adaptive"):
        base = name[: -len("_lead_budget_adaptive")]
        env = {
            "MAI_POLICY_ADAPTIVE_CONTROL": "1",
            "MAI_POLICY_ADAPTIVE_BUDGET_GATE": "1",
            "MAI_POLICY_SUCCESSOR_CHAIN_DEPTH": "1",
        }
        return policy_config_finalize(base, env)
    if name.endswith("_budget_adaptive"):
        base = name[: -len("_budget_adaptive")]
        env = {
            "MAI_POLICY_ADAPTIVE_CONTROL": "1",
            "MAI_POLICY_ADAPTIVE_BUDGET_GATE": "1",
        }
        return policy_config_finalize(base, env)
    if name.endswith("_adaptive"):
        base = name[: -len("_adaptive")]
        env = {"MAI_POLICY_ADAPTIVE_CONTROL": "1"}
        return policy_config_finalize(base, env)
    env = {"MAI_POLICY_ADAPTIVE_CONTROL": "0"}
    return policy_config_finalize(name, env)


def workload_size(workload: str, allocation_size: str, pipeline_size: str) -> str:
    if workload in {
        "policy_stream_pipeline",
        "policy_stream_pipeline_phase_decoy",
        "stream_kernel_pipeline",
    }:
        return pipeline_size
    return allocation_size


def workload_auto_resident_bytes(workload: str, size: str) -> tuple[int, int]:
    size_bytes = parse_size_bytes(size)
    if workload in {
        "policy_stream_pipeline",
        "policy_stream_pipeline_phase_decoy",
        "stream_kernel_pipeline",
    }:
        return size_bytes * 4, size_bytes * 3
    high = max(size_bytes // 4, 4096)
    low = max((high * 3) // 4, 4096)
    return high, low


def workload_auto_active_record_epochs(workload: str, value: str) -> str:
    if value.strip().lower() != "auto":
        return value
    if workload in {
        "policy_stream_pipeline",
        "policy_stream_pipeline_phase_decoy",
        "stream_kernel_pipeline",
    }:
        return "2"
    return "0"


def expected_managed_allocations(workload: str) -> float | None:
    if workload in {
        "policy_stream_pipeline",
        "policy_stream_pipeline_phase_decoy",
        "stream_kernel_pipeline",
    }:
        return 9.0
    if workload == "stream_bandwidth":
        return 3.0
    if workload.startswith("policy_"):
        return 1.0
    return None


def workload_uses_pipeline_baselines(workload: str) -> bool:
    return workload in {
        "policy_stream_pipeline",
        "policy_stream_pipeline_phase_decoy",
        "stream_kernel_pipeline",
    }


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
    benchmark_mode: str | None = None,
) -> dict[str, Any]:
    mode = benchmark_mode or workload
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
    if mode in {
        "stream_shared_file",
        "stream_private_file",
        "stream_kernel_pipeline_shared_file",
        "stream_kernel_pipeline_private_file",
    }:
        env_updates.setdefault("MAI_BENCH_STREAM_BACKING_PATH", str(scratch))
    if workload == "policy_hinted_sequential":
        hinted_aliases = {
            "hinted",
            "hint",
            "application-hinted",
            "application_hinted",
            "app-hinted",
            "app_hinted",
        }
        env_updates.setdefault(
            "MAI_BENCH_HINT_ENABLE",
            "1"
            if scenario_is_policy_pressure(scenario)
            and migration_policy in hinted_aliases
            else "0",
        )
    if workload == "policy_stream_pipeline_phase_decoy":
        env_updates.setdefault("MAI_BENCH_STREAM_PIPELINE_ORDER", "phase_decoy")
        if args.pipeline_cycles == 3:
            env_updates.setdefault("MAI_BENCH_STREAM_PIPELINE_CYCLES", "6")
    if scenario_is_policy_pressure(scenario):
        auto_high, auto_low = workload_auto_resident_bytes(workload, size)
        requested_high = env_updates.get("MAI_UFFD_RESIDENT_LIMIT", args.resident_limit)
        requested_low = env_updates.get(
            "MAI_UFFD_RESIDENT_LOW_LIMIT", args.resident_low_limit
        )
        resolved_high = size_arg(requested_high, auto_high)
        resolved_low = size_arg(requested_low, auto_low)
        resolved_max_rss = args.mai_max_rss
        if resolved_max_rss.strip().lower() == "auto":
            resolved_max_rss = resolved_high
        env_updates["MAI_UFFD_RESIDENT_LIMIT"] = resolved_high
        env_updates["MAI_UFFD_RESIDENT_LOW_LIMIT"] = resolved_low
        env_updates["MAI_MAX_RSS"] = resolved_max_rss
    env = benchmark_env(
        os.environ,
        {
            "MAI_BENCH_POLICY_SIGNATURE_SEED": str(seed),
            "MAI_BENCH_STREAM_PIPELINE_SEED": str(seed),
            "MAI_BENCH_STREAM_PIPELINE_ORDER": args.pipeline_order,
            "MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS": str(
                args.pipeline_group_iterations
            ),
            "MAI_BENCH_STREAM_PIPELINE_CYCLES": str(args.pipeline_cycles),
            "MAI_BENCH_HINT_WINDOW": args.hint_window,
            **env_updates,
        },
    )
    command = [str(args.benchmark), mode, size]
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
        if parsed.get("mode") == mode:
            metrics.update(parsed)
        elif parsed:
            metrics.update(parsed)

    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        **metadata,
        "scenario": scenario,
        "pressure_class": "uffd_resident_pressure"
        if scenario_is_policy_pressure(scenario)
        else "sufficient",
        "workload": workload,
        "benchmark_mode": mode,
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
        "async_slack_chunks": env.get("MAI_UFFD_ASYNC_SLACK_CHUNKS", ""),
        "async_queue_limit": env.get("MAI_UFFD_ASYNC_QUEUE_LIMIT", ""),
        "record_protect_epochs": env.get("MAI_RECORD_PROTECT_EPOCHS", ""),
        "active_record_epochs": env.get("MAI_ACTIVE_RECORD_EPOCHS", ""),
        "active_record_slack_chunks": env.get("MAI_ACTIVE_RECORD_SLACK_CHUNKS", ""),
        "pipeline_cycles": env.get("MAI_BENCH_STREAM_PIPELINE_CYCLES", ""),
        "hint_window": env.get("MAI_BENCH_HINT_WINDOW", ""),
        "hint_enabled": env.get("MAI_BENCH_HINT_ENABLE", ""),
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
    uffd_fallback_delta = metric_number(row, "uffd_fallback_delta") or 0.0
    run_major_faults = metric_number(row, "run_major_faults_delta") or 0.0
    run_inblock = metric_number(row, "run_inblock_delta") or 0.0
    run_oublock = metric_number(row, "run_oublock_delta") or 0.0
    cgroup_oom = metric_number(row, "cgroup_memory_events_oom_delta") or 0.0
    cgroup_max = metric_number(row, "cgroup_memory_max_bytes") or 0.0
    total_pipeline_bytes = metric_number(row, "stream_pipeline_total_matrix_bytes")
    stream_mapping_kind = str(metrics.get("stream_mapping_kind", ""))
    stream_backing_fs_type = metric_number(row, "stream_backing_fs_type") or 0.0
    expected_managed = expected_managed_allocations(row["workload"])
    if row["scenario"] in {
        "native_sufficient",
        "mai_passthrough",
        "linux_shared_pipeline",
        "linux_anon_pipeline",
    }:
        if managed_delta not in (None, 0.0):
            reasons.append("unexpected_managed_allocation")
        if (
            read_bytes
            + write_bytes
            + demand_faults
            + uffd_alloc_delta
            + uffd_fault_delta
            + uffd_eviction_delta
            + uffd_fallback_delta
            != 0.0
        ):
            reasons.append("unexpected_pressure_activity")
        if row["scenario"].startswith("linux_"):
            if row["workload"] not in {
                "policy_stream_pipeline",
                "policy_stream_pipeline_phase_decoy",
                "stream_kernel_pipeline",
            }:
                reasons.append("linux_baseline_for_non_pipeline")
            if row["benchmark_mode"] not in {
                "stream_kernel_pipeline_shared_file",
                "stream_kernel_pipeline_anon_mmap",
            }:
                reasons.append("wrong_linux_baseline_mode")
        if row["scenario"] in {
            "native_sufficient",
            "mai_passthrough",
            "linux_anon_pipeline",
        } and (run_major_faults != 0.0 or run_inblock != 0.0 or run_oublock != 0.0):
            reasons.append("unexpected_sufficient_os_activity")
        if (
            row["scenario"] == "linux_anon_pipeline"
            and stream_mapping_kind
            and stream_mapping_kind != "anon_mmap"
        ):
            reasons.append("wrong_linux_anon_mapping_kind")
        if row["scenario"] == "linux_shared_pipeline":
            if stream_mapping_kind and stream_mapping_kind != "shared_file":
                reasons.append("wrong_linux_shared_mapping_kind")
            if stream_backing_fs_type == 0.0:
                reasons.append("missing_linux_shared_backing_fs")
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
        if run_major_faults != 0.0 or run_inblock != 0.0 or run_oublock != 0.0:
            reasons.append("unexpected_sufficient_os_activity")
    elif scenario_is_policy_pressure(row["scenario"]):
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
        if cgroup_oom != 0.0:
            reasons.append("cgroup_oom_event")
    if row["workload"] in {
        "policy_stream_pipeline",
        "policy_stream_pipeline_phase_decoy",
        "stream_kernel_pipeline",
    }:
        pressure_limit = row.get("uffd_resident_limit") or row.get("memory_limit") or ""
        limit_bytes = parse_size_bytes(pressure_limit) if pressure_limit else 0
        group_bytes = metric_number(row, "stream_pipeline_group_bytes")
        total_bytes = metric_number(row, "stream_pipeline_total_matrix_bytes")
        if (
            scenario_is_policy_pressure(row["scenario"])
            and group_bytes is not None
            and total_bytes is not None
            and limit_bytes > 0
            and not (group_bytes <= limit_bytes < total_bytes)
        ):
            reasons.append("pipeline_pressure_shape_invalid")
        if (
            not scenario_is_policy_pressure(row["scenario"])
            and cgroup_max > 0.0
            and total_pipeline_bytes is not None
            and cgroup_max < total_pipeline_bytes
        ):
            reasons.append("unexpected_cgroup_pressure")
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
    mai_baselines: dict[tuple[str, int, int, str], float] = {}
    native_baselines: dict[tuple[str, int, int, str], float] = {}
    passthrough_baselines: dict[tuple[str, int, int, str], float] = {}
    best_sufficient_baselines: dict[tuple[str, int, int, str], float] = {}
    linux_shared_baselines: dict[tuple[str, int, int, str], float] = {}
    linux_anon_baselines: dict[tuple[str, int, int, str], float] = {}
    for row in rows:
        e2e = metric_number(row, "end_to_end_logical_mib_per_sec")
        if not e2e or e2e <= 0.0:
            continue
        key = (row["workload"], row["seed"], row["repetition"], row["size"])
        if row["scenario"] == "mai_managed_sufficient":
            mai_baselines[key] = e2e
        elif row["scenario"] == "native_sufficient":
            native_baselines[key] = e2e
        elif row["scenario"] == "mai_passthrough":
            passthrough_baselines[key] = e2e
        elif row["scenario"] == "linux_shared_pipeline":
            linux_shared_baselines[key] = e2e
        elif row["scenario"] == "linux_anon_pipeline":
            linux_anon_baselines[key] = e2e
        if row["scenario"] in {
            "mai_managed_sufficient",
            "native_sufficient",
            "mai_passthrough",
            "linux_shared_pipeline",
            "linux_anon_pipeline",
        }:
            best = best_sufficient_baselines.get(key)
            if best is None or e2e > best:
                best_sufficient_baselines[key] = e2e
    for row in rows:
        e2e = metric_number(row, "end_to_end_logical_mib_per_sec")
        key = (row["workload"], row["seed"], row["repetition"], row["size"])
        comparison_sources = [mai_baselines, native_baselines, passthrough_baselines]
        if workload_uses_pipeline_baselines(row["workload"]):
            comparison_sources.extend([linux_shared_baselines, linux_anon_baselines])
        row["comparison_ready"] = all(key in source for source in comparison_sources)
        for field, baselines in [
            ("ratio_to_mai_sufficient_e2e", mai_baselines),
            ("ratio_to_native_sufficient_e2e", native_baselines),
            ("ratio_to_mai_passthrough_sufficient_e2e", passthrough_baselines),
            ("ratio_to_best_sufficient_e2e", best_sufficient_baselines),
            ("ratio_to_linux_shared_pipeline_e2e", linux_shared_baselines),
            ("ratio_to_linux_anon_pipeline_e2e", linux_anon_baselines),
        ]:
            baseline = baselines.get(key)
            if e2e is not None and baseline:
                row[field] = e2e / baseline
            else:
                row[field] = None
        if (
            scenario_is_policy_pressure(row["scenario"])
            and not row["comparison_ready"]
            and "missing_required_baseline" not in row["invalid_reasons"]
        ):
                row["invalid_reasons"].append("missing_required_baseline")


def numeric_values(rows: list[dict[str, Any]], metric: str) -> list[float]:
    values = []
    for row in rows:
        if metric.startswith("ratio_to_"):
            value = row.get(metric)
        else:
            value = metric_number(row, metric)
        if isinstance(value, (int, float)):
            values.append(float(value))
    return values


def sample_stddev(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


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
            "comparison_ready_runs": sum(
                1 for row in group_rows if row.get("comparison_ready")
            ),
            "invalid_runs": sum(1 for row in group_rows if row["invalid_reasons"]),
        }
        valid_rows = [row for row in group_rows if not row["invalid_reasons"]]
        for metric in SUMMARY_METRICS:
            values = numeric_values(valid_rows, metric)
            mean = sum(values) / len(values) if values else ""
            item[f"mean_{metric}"] = mean
            if metric in SUMMARY_SPREAD_METRICS:
                item[f"min_{metric}"] = min(values) if values else ""
                item[f"max_{metric}"] = max(values) if values else ""
                item[f"stddev_{metric}"] = (
                    sample_stddev(values, mean) if values else ""
                )
        summary.append(item)
    return summary


def capacity_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if (
            not scenario_is_policy_pressure(row["scenario"])
            or row["workload"]
            not in {
                "policy_stream_pipeline",
                "policy_stream_pipeline_phase_decoy",
                "stream_kernel_pipeline",
            }
            or row["invalid_reasons"]
            or not row.get("comparison_ready")
        ):
            continue
        ratio = row.get("ratio_to_mai_sufficient_e2e")
        limit = parse_size_bytes(str(row.get("uffd_resident_limit", "") or "0"))
        total = metric_number(row, "stream_pipeline_total_matrix_bytes") or 0.0
        if not isinstance(ratio, (int, float)) or ratio <= 0.0 or limit <= 0:
            continue
        row["effective_capacity_ratio"] = total / float(limit) if total else None
        groups[(row["workload"], row["policy"])].append(row)

    summary: list[dict[str, Any]] = []
    for (workload, policy), group_rows in sorted(groups.items()):
        best = max(
            group_rows,
            key=lambda row: row.get("ratio_to_mai_sufficient_e2e") or 0.0,
        )
        item: dict[str, Any] = {
            "workload": workload,
            "policy": policy,
            "valid_pressure_rows": len(group_rows),
            "max_ratio_to_mai_sufficient_e2e": best.get(
                "ratio_to_mai_sufficient_e2e"
            ),
            "resident_limit_at_max_ratio": best.get("uffd_resident_limit", ""),
            "effective_capacity_ratio_at_max_ratio": best.get(
                "effective_capacity_ratio"
            ),
        }
        for target in (0.8, 0.9):
            reached = [
                row
                for row in group_rows
                if (row.get("ratio_to_mai_sufficient_e2e") or 0.0) >= target
            ]
            field = f"min_resident_limit_for_{int(target * 100)}pct_mai"
            if reached:
                winner = min(
                    reached,
                    key=lambda row: parse_size_bytes(
                        str(row.get("uffd_resident_limit", "") or "0")
                    ),
                )
                item[field] = winner.get("uffd_resident_limit", "")
                item[f"effective_capacity_ratio_at_{int(target * 100)}pct"] = (
                    winner.get("effective_capacity_ratio")
                )
            else:
                item[field] = "not_achieved"
                item[f"effective_capacity_ratio_at_{int(target * 100)}pct"] = ""
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
        "comparison_ready_runs",
        "mean_end_to_end_logical_mib_per_sec",
        "min_end_to_end_logical_mib_per_sec",
        "max_end_to_end_logical_mib_per_sec",
        "stddev_end_to_end_logical_mib_per_sec",
        "mean_ratio_to_mai_sufficient_e2e",
        "min_ratio_to_mai_sufficient_e2e",
        "max_ratio_to_mai_sufficient_e2e",
        "stddev_ratio_to_mai_sufficient_e2e",
        "mean_ratio_to_best_sufficient_e2e",
        "mean_ratio_to_linux_shared_pipeline_e2e",
        "mean_ratio_to_linux_anon_pipeline_e2e",
        "mean_policy_demand_faults",
        "stddev_policy_demand_faults",
        "mean_policy_migration_read_bytes",
        "stddev_policy_migration_read_bytes",
        "mean_policy_migration_write_bytes",
        "stddev_policy_migration_write_bytes",
        "mean_policy_read_amplification",
        "mean_policy_write_amplification",
        "mean_policy_prefetch_accuracy_observed",
        "mean_policy_prefetch_coverage_observed",
        "mean_policy_prefetch_completed",
        "mean_policy_prefetch_useful",
        "mean_policy_prefetch_late",
        "mean_policy_prefetch_unused_evictions",
        "mean_policy_async_prefetch_enqueued",
        "mean_policy_async_prefetch_completed",
        "mean_policy_async_prefetch_dropped",
        "mean_policy_async_completed_without_prefetch",
        "mean_policy_throttle_events",
        "mean_policy_adaptive_prefetch_capped",
        "mean_policy_adaptive_admission_rejected",
        "mean_policy_adaptive_budget_gate",
        "mean_policy_adaptive_budget_bytes",
        "mean_policy_adaptive_window_migration_bytes",
        "mean_policy_markov_lead_candidates",
        "mean_policy_markov_lead_admitted",
        "mean_policy_markov_lead_completed",
        "mean_policy_markov_lead_useful",
        "mean_policy_phase_candidates",
        "mean_policy_phase_admitted",
        "mean_policy_phase_completed",
        "mean_policy_phase_useful",
        "mean_policy_phase_conflicts",
        "mean_policy_phase_confidence_rejected",
        "mean_policy_phase_budget_rejected",
        "mean_policy_phase_safe_victim_rejected",
        "mean_policy_phase_victim_rejected",
        "mean_policy_phase_duplicate_candidates",
        "mean_policy_phase_target_hot_skipped",
        "mean_policy_phase_active_slots",
        "mean_policy_phase_top_score",
        "mean_policy_phase_unused_evictions",
        "mean_policy_phase_boundary_prefetches",
        "mean_policy_phase_hold_activations",
        "mean_policy_phase_shadow_candidates",
        "mean_policy_phase_shadow_useful",
        "mean_policy_phase_shadow_late",
        "mean_policy_phase_shadow_expired",
        "mean_policy_phase_shadow_overwritten",
        "mean_policy_phase_shadow_probe_candidates",
        "mean_policy_phase_shadow_edge_rejected",
        "mean_policy_phase_shadow_edge_confirmed",
        "mean_policy_phase_shadow_top_late",
        "mean_policy_phase_shadow_max_late",
        "mean_policy_hint_candidates",
        "mean_policy_hint_admitted",
        "mean_policy_hint_completed",
        "mean_policy_hint_useful",
        "mean_policy_hint_rejected",
        "mean_policy_arc_t1_chunks",
        "mean_policy_arc_t2_chunks",
        "mean_policy_arc_b1_chunks",
        "mean_policy_arc_b2_chunks",
        "mean_policy_arc_p_chunks",
        "mean_policy_arc_b1_hits",
        "mean_policy_arc_b2_hits",
        "mean_policy_arc_target_increases",
        "mean_policy_arc_target_decreases",
        "mean_policy_arc_replace_t1",
        "mean_policy_arc_replace_t2",
        "mean_policy_arc_prefetch_rejected_pressure",
        "mean_run_major_faults_delta",
        "mean_run_inblock_delta",
        "mean_run_oublock_delta",
        "mean_run_maxrss_kib",
        "mean_policy_demand_fault_stall_p99_ns",
        "mean_stream_pipeline_max_cycle_policy_demand_faults",
        "mean_stream_pipeline_max_cycle_policy_read_bytes",
        "mean_stream_pipeline_max_cycle_policy_write_bytes",
        "mean_stream_pipeline_max_cycle_policy_stall_ns",
        "mean_stream_pipeline_cycle_policy_demand_faults_p90",
        "mean_stream_pipeline_cycle_policy_demand_faults_p99",
        "mean_stream_pipeline_cycle_policy_read_bytes_p90",
        "mean_stream_pipeline_cycle_policy_read_bytes_p99",
        "mean_stream_pipeline_cycle_policy_write_bytes_p90",
        "mean_stream_pipeline_cycle_policy_write_bytes_p99",
        "mean_stream_pipeline_cycle_policy_stall_ns_p90",
        "mean_stream_pipeline_cycle_policy_stall_ns_p99",
        "mean_stream_pipeline_cycle_policy_unused_prefetch_evictions_p90",
        "mean_stream_pipeline_cycle_policy_unused_prefetch_evictions_p99",
        "mean_stream_pipeline_unique_transitions",
        "mean_stream_pipeline_phase_return_policy_demand_faults",
        "mean_stream_pipeline_phase_return_policy_read_bytes",
        "mean_stream_pipeline_phase_return_policy_write_bytes",
        "mean_stream_pipeline_phase_return_policy_stall_ns",
        "mean_stream_pipeline_phase_return_policy_hot_evicted_bytes",
        "mean_stream_pipeline_phase_return_policy_unused_prefetch_evictions",
        "mean_stream_pipeline_phase_return_estimated_hit_ratio",
        "stddev_stream_pipeline_phase_return_estimated_hit_ratio",
        "mean_stream_pipeline_phase_warm_return_policy_demand_faults",
        "mean_stream_pipeline_phase_warm_return_policy_read_bytes",
        "mean_stream_pipeline_phase_warm_return_policy_write_bytes",
        "mean_stream_pipeline_phase_warm_return_policy_stall_ns",
        "mean_stream_pipeline_phase_warm_return_policy_hot_evicted_bytes",
        "mean_stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions",
        "mean_stream_pipeline_phase_warm_return_estimated_hit_ratio",
        "stddev_stream_pipeline_phase_warm_return_estimated_hit_ratio",
        "mean_stream_pipeline_phase_decoy_policy_demand_faults",
        "mean_stream_pipeline_phase_decoy_policy_read_bytes",
        "mean_stream_pipeline_phase_decoy_policy_write_bytes",
        "mean_stream_pipeline_phase_decoy_policy_stall_ns",
        "mean_stream_pipeline_phase_decoy_policy_hot_evicted_bytes",
        "mean_stream_pipeline_phase_decoy_policy_unused_prefetch_evictions",
        "mean_policy_pivot_return_faults",
        "mean_policy_pivot_return_touches",
        "mean_policy_pivot_return_hits",
        "mean_policy_pivot_hot_return_hit_ratio",
        "stddev_policy_pivot_hot_return_hit_ratio",
        "mean_policy_pivot_adaptation_lag_touches",
        "mean_policy_irr_hot_return_hit_ratio",
        "stddev_policy_irr_hot_return_hit_ratio",
        "mean_policy_irr_decoy_return_hit_ratio",
        "stddev_policy_irr_decoy_return_hit_ratio",
        "mean_policy_irr_discrimination_score",
        "stddev_policy_irr_discrimination_score",
        "mean_policy_irr_adaptation_lag_touches",
        "stddev_policy_irr_adaptation_lag_touches",
        "mean_policy_irr_scan_hot_evicted_bytes",
        "stddev_policy_irr_scan_hot_evicted_bytes",
        "mean_policy_irr_ghost_hits",
        "mean_policy_irr_promotions",
        "mean_policy_irr_pressure_rejected",
        "mean_cgroup_memory_events_high_delta",
        "mean_cgroup_memory_events_max_delta",
        "mean_cgroup_memory_events_oom_delta",
        "mean_cgroup_memory_max_available",
        "mean_cgroup_memory_max_unbounded",
        "mean_cgroup_memory_max_is_max_token",
        "mean_cgroup_swap_max_available",
        "mean_cgroup_swap_max_unbounded",
        "mean_cgroup_swap_max_is_max_token",
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


def write_capacity_markdown(path: Path, summary: list[dict[str, Any]]) -> None:
    if not summary:
        path.write_text("# Effective Capacity Summary\n\nNo capacity sweep rows.\n",
                        encoding="utf-8")
        return
    columns = list(summary[0].keys())
    lines = [
        "# Effective Capacity Summary",
        "",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in summary:
        values = []
        for column in columns:
            value = row.get(column, "")
            if isinstance(value, float):
                values.append(f"{value:.3f}")
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
    parser.add_argument("--pipeline-cycles", type=int, default=int(os.environ.get("MAI_BENCH_STREAM_PIPELINE_CYCLES", "3")))
    parser.add_argument("--hint-window", default=os.environ.get("MAI_BENCH_HINT_WINDOW", "8M"))
    parser.add_argument("--mai-threshold", default=os.environ.get("MAI_THRESHOLD", "4K"))
    parser.add_argument("--mai-arena-size", default=os.environ.get("MAI_ARENA_SIZE", "256M"))
    parser.add_argument("--mai-max-rss", default=os.environ.get("MAI_MAX_RSS", "auto"))
    parser.add_argument("--resident-limit", default=os.environ.get("MAI_UFFD_RESIDENT_LIMIT", "auto"))
    parser.add_argument("--resident-low-limit", default=os.environ.get("MAI_UFFD_RESIDENT_LOW_LIMIT", "auto"))
    parser.add_argument("--resident-limit-sweep", default=os.environ.get("MAI_BENCH_RESIDENT_LIMIT_SWEEP", ""))
    parser.add_argument("--prefetch-chunks", default=os.environ.get("MAI_UFFD_PREFETCH_CHUNKS", "4"))
    parser.add_argument("--async-prefetch", default=os.environ.get("MAI_UFFD_ASYNC_PREFETCH", "0"))
    parser.add_argument("--async-slack-chunks", default=os.environ.get("MAI_UFFD_ASYNC_SLACK_CHUNKS", "2"))
    parser.add_argument("--async-queue-limit", default=os.environ.get("MAI_UFFD_ASYNC_QUEUE_LIMIT", ""))
    parser.add_argument("--migration-chunk", default=os.environ.get("MAI_MIGRATION_CHUNK", "2M"))
    parser.add_argument("--record-protect-epochs", default=os.environ.get("MAI_RECORD_PROTECT_EPOCHS", "0"))
    parser.add_argument("--active-record-epochs", default=os.environ.get("MAI_ACTIVE_RECORD_EPOCHS", "auto"))
    parser.add_argument("--active-record-slack-chunks", default=os.environ.get("MAI_ACTIVE_RECORD_SLACK_CHUNKS", "8"))
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
                    if workload_uses_pipeline_baselines(workload):
                        record_row(
                            rows,
                            partial_path,
                            run_case(
                                args=args,
                                metadata=metadata,
                                scenario="linux_shared_pipeline",
                                workload=workload,
                                benchmark_mode="stream_kernel_pipeline_shared_file",
                                policy_name="baseline",
                                migration_policy="",
                                seed=seed,
                                repetition=repetition,
                                env_updates={
                                    "MAI_ACCESS_EXPECT_MANAGED": "0",
                                },
                            ),
                        )
                        record_row(
                            rows,
                            partial_path,
                            run_case(
                                args=args,
                                metadata=metadata,
                                scenario="linux_anon_pipeline",
                                workload=workload,
                                benchmark_mode="stream_kernel_pipeline_anon_mmap",
                                policy_name="baseline",
                                migration_policy="",
                                seed=seed,
                                repetition=repetition,
                                env_updates={
                                    "MAI_ACCESS_EXPECT_MANAGED": "0",
                                },
                            ),
                        )
                for policy_name in policies:
                    migration_policy, extra_env = policy_config(policy_name)
                    for scenario, resident_limit, resident_low_limit in resident_limit_points(args):
                        record_row(
                            rows,
                            partial_path,
                            run_case(
                                args=args,
                                metadata=metadata,
                                scenario=scenario,
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
                                    "MAI_UFFD_RESIDENT_LIMIT": resident_limit,
                                    "MAI_UFFD_RESIDENT_LOW_LIMIT": resident_low_limit,
                                    "MAI_UFFD_PREFETCH_CHUNKS": args.prefetch_chunks,
                                    "MAI_UFFD_ASYNC_PREFETCH": args.async_prefetch,
                                    "MAI_UFFD_ASYNC_SLACK_CHUNKS": args.async_slack_chunks,
                                    "MAI_MIGRATION_CHUNK": args.migration_chunk,
                                    "MAI_MIGRATION_POLICY": migration_policy,
                                    "MAI_RECORD_PROTECT_EPOCHS": args.record_protect_epochs,
                                    "MAI_ACTIVE_RECORD_EPOCHS": workload_auto_active_record_epochs(
                                        workload, args.active_record_epochs
                                    ),
                                    "MAI_ACTIVE_RECORD_SLACK_CHUNKS": args.active_record_slack_chunks,
                                    "MAI_POLICY_SUCCESSOR_CHAIN_DEPTH": args.successor_chain_depth,
                                    "MAI_POLICY_OBSERVE_PREFETCH_WRITES": args.observe_prefetch_writes,
                                    "LD_PRELOAD": str(args.libmai),
                                    **(
                                        {"MAI_UFFD_ASYNC_QUEUE_LIMIT": args.async_queue_limit}
                                        if args.async_queue_limit
                                        else {}
                                    ),
                                    **extra_env,
                                },
                            ),
                        )

    attach_baseline_ratios(rows)
    summary = summarize(rows)
    capacity = capacity_summary(rows)
    write_ndjson(args.output_dir / "rows.ndjson", rows)
    write_summary_csv(args.output_dir / "summary.csv", summary)
    write_summary_markdown(args.output_dir / "summary.md", summary)
    write_summary_csv(args.output_dir / "capacity_summary.csv", capacity)
    write_capacity_markdown(args.output_dir / "capacity_summary.md", capacity)

    invalid = [row for row in rows if row["invalid_reasons"]]
    print(f"wrote {len(rows)} rows to {args.output_dir / 'rows.ndjson'}")
    print(f"wrote summary to {args.output_dir / 'summary.csv'}")
    print(f"wrote capacity summary to {args.output_dir / 'capacity_summary.csv'}")
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
