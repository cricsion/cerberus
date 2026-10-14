"""Partitioning: the algorithm that decides which files each hunter sees.

Package layout:
    config — policy knobs (env-overridable, call-time reads), one home for every tunable
    graph  — graphify graph.json -> communities + file-coupling edges (import graph
             augmented with framework edges the importer cannot see)
    units  — the deterministic algorithm (vendor/small-repo universe -> grouping ->
             byte budget -> misc policy) and its invariants
    llm    — the Deep-Agent proposer + invariant enforcement over its output
    prompts — the proposer's wording (reviewable without reading plumbing)

Callers import the deterministic surface from here:
    from harness.partitioning import partition_units, verify_partition
"""
from harness.partitioning.config import max_units, min_files
from harness.partitioning.units import (_balance_units, _file_weights,
                                        _normalize_units, _split_over_budget,
                                        _units_from_dirs, _units_from_graphify,
                                        isolate_vendor, partition_target,
                                        partition_units, small_repo_unit,
                                        verify_partition)

__all__ = [
    "max_units", "min_files",
    "partition_units", "partition_target", "verify_partition",
    "isolate_vendor", "small_repo_unit",
    "_balance_units", "_file_weights", "_normalize_units",
    "_split_over_budget", "_units_from_dirs", "_units_from_graphify",
]
