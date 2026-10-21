"""Partitioning - deep-agent proposer with deterministic + Graphify baseline."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import PurePosixPath

from harness.config import get_model_kwargs
from harness.fallback import run_fail_open
from harness.partitioning import partition_units as _det_partition_units
from harness.partitioning.config import max_units, vendor_unit_enabled
from harness.partitioning.units import (
    _file_weights,
    _load_partition_edges,
    _normalize_units,
    _vendor_unit,
    isolate_vendor,
    partition_target,
    single_unit_enabled,
    small_repo_unit,
)

_logger = logging.getLogger(__name__)


def _structure_context(repo: str, files: list[str],
                       cands: list[dict] | None = None,
                       threat_md: str = "") -> str:
    lines = [f"Repository: {repo}", f"Files ({len(files)}):"]
    lines.extend(f"  {f}" for f in files)
    if cands:
        lines.append("\nDETERMINISTIC SIGNALS (prefilter, not a partition hint):")
        for c in cands[:40]:
            title = c.get("title") or c.get("id") or "signal"
            lines.append(f"  [{c.get('severity', 'info')}] {title} ({c.get('path', '')})")
    if threat_md and threat_md.strip():
        lines.append("\nTHREAT MODEL:")
        lines.append(threat_md.strip())
    return "\n".join(lines)


def _enforce_coverage(units, files, repo=None) -> list[dict]:
    valid = [f for f in (files or []) if isinstance(f, str) and f]
    if not valid:
        return []
    if vendor_unit_enabled():
        app_files, vendor_files = isolate_vendor(valid, repo)
    else:
        app_files, vendor_files = list(valid), []

    weights = _file_weights(repo, app_files) if repo is not None else {}
    pt = partition_target(weights) if weights else 0

    if single_unit_enabled() and app_files:
        single = small_repo_unit(app_files, weights, pt, repo or ".")
        if single is not None:
            out = [single]
            if vendor_files and vendor_unit_enabled():
                out.append(_vendor_unit(vendor_files, {single["name"]}))
            return out

    app_set = set(app_files)
    seen: set[str] = set()
    app_units: list[dict] = []
    for u in units or []:
        if not isinstance(u, dict):
            continue
        ufiles = [f for f in (u.get("files") or []) if f in app_set and f not in seen]
        if ufiles:
            seen.update(ufiles)
            # Accept both 'reason' and 'rationale' (prompts.py defines 'rationale')
            reason = u.get("reason") or u.get("rationale") or ""
            app_units.append({
                "name": u.get("name") or "unit",
                "files": sorted(ufiles),
                "reason": reason,
            })

    # Missing app files attach by parent-dir match, then core/platform/config.
    missing = [f for f in app_files if f not in seen]
    edges = _load_partition_edges(repo, app_files) if repo is not None else {}
    if missing and app_units:
        unit_parents = []
        core_idx = 0
        for i, u in enumerate(app_units):
            name_l = (u.get("name") or "").lower()
            if any(k in name_l for k in ("core", "platform", "bootstrap", "config", "root", "infra")):
                core_idx = i
                break
        for u in app_units:
            parents = set(str(PurePosixPath(str(f).replace("\\", "/")).parent) for f in u.get("files") or [])
            unit_parents.append(parents)

        max_ceiling = int(pt * 1.25) if pt > 0 else 0
        for f in missing:
            f_norm = str(f).replace("\\", "/")
            f_parent = str(PurePosixPath(f_norm).parent)
            fw = weights.get(f, 0) if weights else 0

            # 1. Look for a unit sharing the exact parent directory
            best_u = None
            for i, u in enumerate(app_units):
                if f_parent in unit_parents[i]:
                    uw = sum(weights.get(x, 0) for x in u.get("files", [])) if weights else 0
                    if max_ceiling == 0 or uw + fw <= max_ceiling:
                        best_u = u
                        break

            # 2. Look for core/platform/config unit
            if best_u is None and core_idx < len(app_units):
                cu = app_units[core_idx]
                uw = sum(weights.get(x, 0) for x in cu.get("files", [])) if weights else 0
                if max_ceiling == 0 or uw + fw <= max_ceiling:
                    best_u = cu

            # 3. Lightest unit with headroom
            if best_u is None:
                cands = [u for u in app_units if not u.get("budget_exempt")]
                if cands:
                    best_u = min(cands, key=lambda u: sum(weights.get(x, 0) for x in u.get("files", [])) if weights else 0)

            if best_u is not None:
                best_u["files"] = sorted(set(best_u.get("files", [])) | {f})
                prev = best_u.get("reason", "")
                if "orphan" not in prev:
                    best_u["reason"] = f"{prev}+orphan" if prev else "orphan"
            else:
                app_units.append({"name": f"orphan/{f}", "files": [f], "reason": "orphan"})
    elif missing:
        for f in missing:
            app_units.append({"name": f"orphan/{f}", "files": [f], "reason": "orphan"})

    out = _normalize_units(app_units, weights or None, pt, edges=edges)

    if vendor_files and vendor_unit_enabled():
        out = list(out) + [_vendor_unit(vendor_files, set(u.get("name", "") for u in out))]

    return out


def _files_signature(repo: str, files: list[str]) -> str:
    """Content-signature for the deterministic partition cache."""
    h = hashlib.sha256()
    for f in sorted(files or []):
        pth = os.path.join(repo, f)
        try:
            st = os.stat(pth)
            h.update(str(f).encode())
            h.update(str(st.st_size).encode())
        except OSError:
            h.update(str(f).encode())
    return h.hexdigest()


def _deterministic_baseline(repo: str, files: list[str],
                            candidates: list[dict]) -> list[dict]:
    """Compute, cache, and return the deterministic partition baseline."""
    cache_dir = os.path.join(repo, ".harness")
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError:
        cache_dir = None
    cache_path = os.path.join(cache_dir, "partition-baseline.json") if cache_dir else None
    sig = _files_signature(repo, files)

    if cache_path and os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if isinstance(cached, dict) and cached.get("files_sig") == sig:
                cached_units = cached.get("units")
                if isinstance(cached_units, list):
                    return cached_units
        except (OSError, json.JSONDecodeError):
            pass

    baseline = run_fail_open(
        "partition-baseline",
        lambda: _det_partition_units(repo, files),
        default=[], logger=_logger)
    if cache_path:
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump({"files_sig": sig, "units": baseline}, f, indent=2)
        except OSError:
            pass
    return baseline


def _build_partition_message(ctx: str, baseline: list[dict]) -> str:
    """Task prompt for the LLM partitioner."""
    from harness.partitioning.prompts import build_partition_task

    msg = build_partition_task(ctx, max_units())
    baseline_lines = []
    for u in baseline:
        uname = u.get("name") or "unit"
        ufiles = u.get("files") or []
        baseline_lines.append(f"- Unit '{uname}' ({len(ufiles)} files):")
        for f in ufiles:
            baseline_lines.append(f"    {f}")

    return msg + (
        "\n\nDeterministic baseline (Graphify-promoted, cached, complete, "
        "byte-bounded) — refine it:\n"
        "- Keep every file assigned exactly as in the baseline unless there "
        "is a strong semantic reason to move it.\n"
        "- Merge tiny support/config/test shards into the nearest owning "
        "feature unit; avoid any 1-3 file unit.\n"
        "- Do not create `misc`, orphans, or `part-*` buckets; use semantic "
        "names.\n"
        "- Return only improved JSON matching the schema.\n\n"
        "Baseline Groupings:\n" + "\n".join(baseline_lines)
    )


def _agent_units(mk: dict, msg: str, repo: str, timeout: int,
                 backend: Any = None) -> list[dict]:
    """Run the Deep-Agent partitioner with hunter tools and extract parsed units;
    an empty result falls back to deterministic grouping in `units._units_from_dirs`."""
    from harness.agents.deep import DEFAULT_RECURSION_LIMIT, run_structured
    from harness.agents.toolsets import graph_tools
    from harness.llmjson import structured_items
    from harness.partitioning.prompts import PARTITIONER_SYSTEM, UnitList

    def _partition_llm() -> list[dict]:
        parsed, _ = run_structured(
            mk, UnitList, PARTITIONER_SYSTEM, msg,
            tools=graph_tools(), timeout=timeout, name="partitioner",
            backend=backend, root_dir=repo,
            recursion_limit=DEFAULT_RECURSION_LIMIT)
        return structured_items(parsed, field="units")

    return run_fail_open("partitioner-llm", _partition_llm, default=[],
                         logger=_logger)


def run_partitioner_agent(repo: str, files: list[str], candidates: list[dict],
                          cfg: dict, threat_md: str = "") -> list[dict]:
    valid = [f for f in (files or []) if isinstance(f, str) and f]
    if not valid:
        return []

    # Separate vendor files first so dependencies never skew code analysis
    if vendor_unit_enabled():
        app_files, vendor_files = isolate_vendor(valid, repo)
    else:
        app_files, vendor_files = list(valid), []

    weights = _file_weights(repo, app_files) if repo is not None else {}
    pt = partition_target(weights) if weights else 0

    # Small-repo collapse skips the LLM call entirely.
    if single_unit_enabled() and app_files:
        single = small_repo_unit(app_files, weights, pt, repo or ".")
        if single is not None:
            out = [single]
            if vendor_files and vendor_unit_enabled():
                out.append(_vendor_unit(vendor_files, {single["name"]}))
            return out

    # Imported here so tests can monkeypatch harness.config.get_model_kwargs.
    from harness.config import get_harness_timeout, get_model_kwargs

    model_kwargs = get_model_kwargs(cfg, "hunter", agent="partitioner")
    mk = dict(model_kwargs or {})
    if not mk.get("api_key") or not mk.get("model"):
        raise ValueError("no model configured")

    timeout = get_harness_timeout(mk.get("timeout", 60) or 60)

    ctx = _structure_context(repo, files, candidates, threat_md=threat_md)
    baseline = _deterministic_baseline(repo, files, candidates)
    msg = _build_partition_message(ctx, baseline)

    from harness.sandbox.local_backend import RepoLocalBackend
    from pathlib import Path

    root = Path(repo).resolve() if repo else Path(".").resolve()
    backend = None
    try:
        backend = RepoLocalBackend(repo_path=root)
    except Exception:
        backend = None

    units = _agent_units(mk, msg, repo=repo or ".", timeout=timeout,
                         backend=backend)

    if not units:
        raise ValueError("agent returned no parseable units")

    units = _enforce_coverage(units, files, repo)
    if not units:
        raise ValueError("no units after coverage enforcement")
    return units
