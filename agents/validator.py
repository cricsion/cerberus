from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import logging
import sys
import time
from typing import Any

from harness.agents.deep import is_fatal_error, sanitize_model_kwargs
from harness.config import get_default_config, int_setting
from harness.progress import AgentState
from harness.fallback import (EMPTY_STRUCTURED, _append_note,
                              needs_review_verdicts, runner)
from harness.schemas import structured_items
from harness.prompts.validation import (OMITTED_NOTE, REFUTE_METHOD,
                                        ROUND_FAILED_NOTE, VALIDATOR_SYSTEM)

_logger = logging.getLogger(__name__)


def _stage_line(text: str) -> None:
    """Print a ``[validator]`` progress line, routed through the UI stage sink
    (``pipeline._stage_detail``) when one is installed so the reporter folds
    # these lines into the stage line instead of double-printing.
    """
    try:
        from harness import pipeline as _pipeline
    except Exception:
        _pipeline = None
    sd = getattr(_pipeline, "_stage_detail", None)
    if sd is not None:
        sd("validator", text)
        return
    print(text, file=sys.stderr, flush=True)


def _merge_verdict(base: dict, data: dict) -> dict:
    merged = dict(base)
    # Preserve the hunter's original record before validator fields land. Both
    # fields survive the vote merge (it copies the winning dict) but are never
    # sent back to the validator or used by the report writers.
    for src, dst in (("evidence", "hunter_evidence"),
                     ("snippet", "hunter_snippet")):
        if base.get(src) and not merged.get(dst):
            merged[dst] = base[src]
    if isinstance(data, dict):
        for k in ("status", "confidence", "severity",
                  "cwe", "fix_suggestion", "control_type"):
            if k in data and data[k] not in (None, ""):
                merged[k] = data[k]
        vsnip = data.get("snippet")
        if vsnip not in (None, ""):
            merged["snippet"] = vsnip
        vev = str(data.get("evidence", "") or "").strip()
        if vev:
            prev = str(merged.get("evidence") or "")
            merged["evidence"] = _append_note(prev, f"validator: {vev}")
        note = str(data.get("fallback_note", "") or "")
        if not note:
            reason = str(data.get("refute_reason", "") or "")
            note = f"refute: {reason}" if reason else ""
        if note:
            prev = str(merged.get("evidence") or "")
            merged["evidence"] = _append_note(prev, note)
    if not merged.get("taint") and base.get("taint"):
        merged["taint"] = base["taint"]
    if merged.get("status") not in ("confirmed", "fp", "needs-review"):
        merged["status"] = "needs-review"
    try:
        merged["confidence"] = max(0.0, min(1.0, float(merged.get("confidence", 0))))
    except (TypeError, ValueError):
        merged["confidence"] = float(base.get("confidence", 0) or 0)
    if merged.get("severity") not in ("critical", "high", "medium", "low", "info"):
        merged["severity"] = base.get("severity", "medium")
    if merged.get("status") == "fp" and not merged.get("evidence"):
        merged["evidence"] = (
            f"validator falsified: {base.get('title','')} "
            f"at {base.get('path','')}"
        )
    return merged


def evidence_gate(finding: dict) -> bool:
    try:
        refs = finding.get("refs") or []
        if any(isinstance(r, dict) and r.get("file")
               and int(r.get("line") or 0) > 0
               for r in refs):
            return True
        taint = finding.get("taint") or {}
        if not isinstance(taint, dict):
            taint = {}
        return bool(finding.get("path") and finding.get("snippet")
                    and (taint.get("sink") or finding.get("evidence")))
    except Exception:
        return True  # fail-open: never drop on gate error


def _resolve_votes(cfg: dict | None, override: int | None = None) -> int:
    if override is not None:
        try:
            return min(5, max(1, int(override)))
        except (TypeError, ValueError):
            pass
    return int_setting(cfg, "verification.votes",
                       fallback_path="verification.votes", minimum=1, maximum=5)


def _majority_verdict(base: dict, votes: list[dict]) -> dict:
    n = len(votes) or 1
    counts = {"confirmed": 0, "fp": 0, "needs-review": 0}
    by_status: dict[str, dict] = {}
    for v in votes:
        s = v.get("status") if isinstance(v, dict) else None
        if s not in counts:
            s = "needs-review"
        counts[s] += 1
        by_status.setdefault(s, v if isinstance(v, dict) else dict(base))
    for winner in ("confirmed", "fp"):
        if counts[winner] > n / 2:
            g = dict(by_status[winner])
            g["status"] = winner
            if winner == "fp":
                # Deterministic control_type: the strictest claim among the
                # winning votes wins, so vote order can never hide an
                # auth-only acquittal from the guardrail.
                for vv in votes:
                    if (isinstance(vv, dict) and vv.get("status") == "fp"
                            and vv.get("control_type") == "auth_check"):
                        g["control_type"] = "auth_check"
                        break
            prev = str(g.get("evidence") or "")
            tag = f"consensus: {counts[winner]}/{n} {winner}"
            g["evidence"] = _append_note(prev, tag)
            return g
    g = dict(by_status.get("needs-review") or by_status.get("confirmed")
             or by_status.get("fp") or base)
    g["status"] = "needs-review"
    prev = str(g.get("evidence") or "")
    tag = (f"consensus: tie/no-majority "
           f"({counts['confirmed']}c/{counts['fp']}f/{counts['needs-review']}n of {n})")
    g["evidence"] = _append_note(prev, tag)
    return g


def _cell_size(cfg: dict | None) -> int:
    """Findings per validator cell (clamped 1-100)."""
    return int_setting(cfg, "verification.cell_size",
                       fallback_path="verification.cell_size", minimum=1,
                       maximum=100)

CELL_SIZE = int(get_default_config("verification.cell_size"))

def _route_finding(f: dict) -> tuple[str, dict]:
    if (f.get("status") == "fp"
            and (f.get("gated")
                 or "evidence_gate" in str(f.get("evidence", "")))):
        return "passthrough", f
    # Info context without a CWE is scan context, not a vulnerability claim.
    if not f.get("cwe") and f.get("severity", "medium") == "info":
        return "passthrough", f
    return "llm", f


def _group_by_unit(findings: list[dict],
                   units: list[dict] | None
                   ) -> list[tuple[str, list[dict], list[int]]]:
    """Group findings by partition unit, tracking each item's origin index in
    ``findings`` so reassembly never needs object identity."""
    file_to_unit: dict[str, str] = {}
    try:
        for u in (units or []):
            if not isinstance(u, dict):
                continue
            name = str(u.get("name") or u.get("unit") or "")
            if not name:
                continue
            for fp in (u.get("files") or []):
                file_to_unit.setdefault(str(fp), name)
    except (TypeError, AttributeError):
        pass
    groups: dict[str, list[dict]] = {}
    origins: dict[str, list[int]] = {}
    order: list[str] = []

    def _key(f: dict) -> str:
        stamped = str(f.get("unit") or "").strip()
        if stamped:
            return stamped
        p = str(f.get("path", "") or "")
        if p in file_to_unit:
            return file_to_unit[p]
        base = p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        for fp, name in file_to_unit.items():
            if fp.endswith("/" + base) or base == fp.rsplit("/", 1)[-1]:
                return name
        return "global"

    for oi, f in enumerate(findings):
        k = _key(f) if isinstance(f, dict) else "global"
        if k not in groups:
            groups[k] = []
            origins[k] = []
            order.append(k)
        groups[k].append(f)
        origins[k].append(oi)
    return [(k, groups[k], origins[k]) for k in order]


def _compact_finding(f: dict) -> dict:
    """Key filter, not a compactor: every listed field is sent in full.

    ``rationale`` is deliberately absent — the validator must re-derive the
    claim without the hunter's reasoning (see ``REFUTE_METHOD``).
    """
    try:
        d = dict(f)
        taint = d.get("taint")
        if isinstance(taint, dict):
            path = taint.get("path")
            if path is None:
                path = []
            elif not isinstance(path, list):
                path = [path]
            d["taint"] = {
                "source": str(taint.get("source", "")),
                "sink": str(taint.get("sink", "")),
                "path": [str(p) for p in path],
            }
        return {k: d.get(k) for k in (
            "id", "title", "cwe", "severity", "confidence", "path",
            "start_line", "end_line", "snippet", "taint", "refs",
            "evidence")}
    except TypeError:
        return {"id": f.get("id", ""), "title": f.get("title", "")}


def _validate_unit_batch(group_name: str, items: list[dict], cfg: dict,
                          threat_md: str = "", n_votes: int = 1,
                          repo: str | None = None,
                          cell_no: int = 0,
                          agent_registry: Any = None) -> list[dict]:
    from harness.config import (get_model_kwargs, resolve_call_retries,
                                resolve_call_timeout)

    if not items:
        return []
    try:
        cell_no = max(0, int(cell_no or 0))
    except (TypeError, ValueError):
        cell_no = 0
    cell_scope = f"{group_name}:c{cell_no + 1}"
    model_kwargs = get_model_kwargs(cfg, "validator")
    mk = sanitize_model_kwargs(model_kwargs)
    _timeout = resolve_call_timeout(mk, cfg)
    _max_retries = resolve_call_retries(mk, cfg)

    ballots: dict[str, list[dict]] = {str(f.get("id")): [] for f in items
                                       if isinstance(f, dict)}
    n_votes = max(1, min(5, int(n_votes or 1)))
    # Cells are split upstream at cell_size; there is no further chunking:
    # each cell is exactly one LLM call.
    chunks = [items]

    # Backend resolved once like hunters._run_unit (fail-soft).
    from harness.agents.toolsets import graph_tools
    from harness.sandbox import _acquire_backend, close_backend
    backend = (_acquire_backend(cfg, repo,
                                label=f"validator-{group_name}") if repo else None)
    tools = graph_tools()
    tool_names = [getattr(t, "name", None) or getattr(t, "__name__", "tool")
                  for t in tools]
    # One agent build for every vote/chunk of this cell group.
    from harness.agents.deep import build_deep_agent, make_llm, run_structured
    from harness.prompts.validation import VerdictBatch
    agent = runner(
        f"agent validator-{group_name}",
        lambda: build_deep_agent(
            make_llm(mk, timeout=_timeout, max_retries=_max_retries),
            system_prompt=VALIDATOR_SYSTEM, tools=tools,
            response_format=VerdictBatch,
            name=f"validator-{group_name}"[:60],
            backend=backend, root_dir=repo,
            scratchpad=True),
        default=None, logger=_logger)
    try:
        for _round in range(n_votes):
            _vote = _round + 1
            for chunk in chunks:
                payload = [_compact_finding(f) for f in chunk]
                from harness.prompts.validation import build_batch_task
                msg = build_batch_task(group_name, threat_md, payload,
                                       repo=repo, tools=tool_names)
                _stage_line(f"[validator] unit '{group_name}' cell {cell_no + 1}: "
                            f"{len(payload)} findings, "
                            f"{len(msg.encode('utf-8')) // 1024} KB, "
                            f"vote {_vote}/{n_votes}...")
                # One registry handle per LLM call: validator:<unit>:cN:vM —
                # mirrors trace_suffix so UI/trace use the same identity.
                _aid = f"validator:{cell_scope}:v{_vote}"
                if agent_registry is not None:
                    agent_registry.transition(
                        _aid, AgentState.running, role="validator",
                        unit=group_name, parent_stage="validation",
                        model=mk.get("model"))

                def _call_validator_structured() -> tuple[Any, str]:
                    return run_structured(
                        mk, VerdictBatch, VALIDATOR_SYSTEM, msg,
                        timeout=_timeout,
                        max_retries=_max_retries,
                        name=f"validator-{group_name}"[:60],
                        root_dir=repo, tools=tools, backend=backend,
                        trace_suffix=f"{cell_scope}:v{_vote}",
                        meta_extra={"unit": str(group_name),
                                    "cell": str(cell_no + 1),
                                    "vote": str(_vote)},
                        agent=agent)

                parsed: Any = None
                verdicts: list[dict] = []
                try:
                    parsed, _ = runner(
                        "validator batch", _call_validator_structured,
                        default=EMPTY_STRUCTURED, logger=_logger)
                    verdicts = [v for v in structured_items(parsed, field="verdicts")
                                if v.get("id")]
                except Exception as e:
                    if agent_registry is not None:
                        agent_registry.transition(
                            _aid, AgentState.failed, role="validator",
                            unit=group_name, parent_stage="validation",
                            error=type(e).__name__)
                    raise
                if agent_registry is not None:
                    if verdicts:
                        agent_registry.transition(
                            _aid, AgentState.succeeded, role="validator",
                            unit=group_name, parent_stage="validation",
                            message=f"{len(verdicts)} verdicts")
                    else:
                        agent_registry.transition(
                            _aid, AgentState.failed, role="validator",
                            unit=group_name, parent_stage="validation",
                            error=("no structured output" if parsed is None
                                   else "no verdicts"))
                covered: set[str] = set()
                for v in verdicts:
                    vid = str(v.get("id", ""))
                    if vid in ballots:
                        ballots[vid].append(v)
                        covered.add(vid)

                # An omitted id is a partial reply, never an implicit confirmed/fp.
                # No structured response at all is a failed round, not an empty
                # verdict set.
                if verdicts or parsed is not None:
                    note = OMITTED_NOTE
                else:
                    note = ROUND_FAILED_NOTE
                missing = [f for f in chunk
                           if str(f.get("id", "")) not in covered]
                for ballot in needs_review_verdicts(missing, note):
                    vid = str(ballot.get("id", ""))
                    if vid in ballots:
                        ballots[vid].append(ballot)
    finally:
        close_backend(backend)
    out: list[dict] = []
    for f in items:
        vid = str(f.get("id"))
        votes = ballots.get(vid, [])
        if not votes:
            # Batch reply omitted this id: fail open, never crash.
            out.append(_degraded_finding(f, "no validator verdicts"))
            continue
        merged_votes = []
        for v in votes:
            merged_votes.append(_merge_verdict(dict(f), v))
        out.append(_majority_verdict(f, merged_votes))
    return out


def _degraded_finding(f: dict, note: str) -> dict:
    fb = dict(f) if isinstance(f, dict) else {}
    fb["status"] = "needs-review"
    prev = str(fb.get("evidence") or "")
    fb["evidence"] = _append_note(prev, note)
    return fb


def _evidence_gate_findings(findings: list[dict]) -> list[dict]:
    gated: list[dict] = []
    for f in findings:
        # evidence_gate is total (its own `except` returns True): cannot raise.
        if evidence_gate(f):
            gated.append(f)
            continue
        g = dict(f)
        # needs-review without evidence stays needs-review (no-API-key smoke path).
        if g.get("status") == "needs-review" and not g.get("evidence"):
            gated.append(g)
        else:
            g["status"] = "fp"
            g["gated"] = True
            prev = str(g.get("evidence") or "")
            reason = "evidence_gate: missing path/snippet/sink evidence"
            g["evidence"] = _append_note(prev, reason)
            gated.append(g)
    return gated


def _classify_group(pair: tuple[str, list[dict], list[int]],
                    cell_size: int = CELL_SIZE
                    ) -> tuple[str, list[dict], list[int], dict[int, dict],
                               list[tuple[list[int], list[dict]]]]:
    name, items, origins = pair
    batch_idx: list[int] = []
    direct: dict[int, dict] = {}
    for i, f in enumerate(items):
        action, g = _route_finding(f)
        if action == "llm":
            batch_idx.append(i)
        else:
            direct[i] = g
    cells = [([batch_idx[k] for k in range(s, min(s + cell_size, len(batch_idx)))],
               [items[batch_idx[k]] for k in range(s, min(s + cell_size, len(batch_idx)))])
             for s in range(0, len(batch_idx), cell_size)]
    return name, items, origins, direct, [(c, ci) for c, ci in cells if c]


def _plan_validation_cells(
    groups: list[tuple[str, list[dict], list[int]]],
    cell_size: int = CELL_SIZE,
) -> list[tuple[str, list[dict], list[int], dict[int, dict], list[tuple[list[int], list[dict]]]]]:
    """Plan validation cells across partition units and pooled remainders.

    When there is only a single unit, findings are chunked into cells of up to
    ``cell_size`` under that unit's name (preserving backward compatibility).

    When there are multiple units/hunters:
      1. Extract full cells of size ``cell_size`` per unit (e.g. 52 -> two 25-item cells).
      2. Pool all remaining items (< cell_size) across hunters into a shared remainder pool.
      3. Chunk the pooled remainders into cells of up to ``cell_size`` under
         'cross-unit-remainder' (or the unit name if only one unit contributed).

    This eliminates 1-item straggler cells and dramatically cuts verification wall-clock time.
    Every finding in ``gated`` is validated in exactly one cell with zero drops or duplicates.
    """
    if len(groups) <= 1:
        return [_classify_group(pair, cell_size) for pair in groups]

    planned = []
    pooled_remainders: list[tuple[dict, int, str]] = []
    used_names: set[str] = set()

    for name, items, origins in groups:
        direct_items: list[tuple[int, dict]] = []
        llm_indices: list[int] = []
        for i, f in enumerate(items):
            action, g = _route_finding(f)
            if action == "llm":
                llm_indices.append(i)
            else:
                direct_items.append((i, g))

        n_full = len(llm_indices) // cell_size
        full_cutoff = n_full * cell_size
        unit_llm_indices = llm_indices[:full_cutoff]
        rem_indices = llm_indices[full_cutoff:]

        for idx in rem_indices:
            pooled_remainders.append((items[idx], origins[idx], name))

        kept_indices = sorted([i for i, _ in direct_items] + unit_llm_indices)
        if kept_indices:
            idx_map = {old_i: new_i for new_i, old_i in enumerate(kept_indices)}
            unit_items = [items[i] for i in kept_indices]
            unit_origins = [origins[i] for i in kept_indices]
            unit_direct = {idx_map[old_i]: g for old_i, g in direct_items}
            unit_cells = [
                ([idx_map[unit_llm_indices[k]] for k in range(s, s + cell_size)],
                 [items[unit_llm_indices[k]] for k in range(s, s + cell_size)])
                for s in range(0, len(unit_llm_indices), cell_size)
            ]
            if unit_cells:
                used_names.add(name)
            planned.append((name, unit_items, unit_origins, unit_direct, unit_cells))

    if pooled_remainders:
        for s in range(0, len(pooled_remainders), cell_size):
            chunk = pooled_remainders[s : s + cell_size]
            chunk_units = {u for _, _, u in chunk}
            if len(chunk_units) == 1 and list(chunk_units)[0] not in used_names:
                rem_name = list(chunk_units)[0]
                used_names.add(rem_name)
            else:
                rem_name = "cross-unit-remainder"
            rem_items = [f for f, _, _ in chunk]
            rem_origins = [oi for _, oi, _ in chunk]
            rem_direct: dict[int, dict] = {}
            rem_cells = [
                (list(range(len(chunk))), rem_items)
            ]
            planned.append((rem_name, rem_items, rem_origins, rem_direct, rem_cells))

    return planned


def _run_cell(name: str, cell_items: list[dict], ci: int,
              n_cells: int, *, cfg: dict, n_votes: int, threat_md: str,
              repo: str | None, cell_offset: int = 0,
              agent_registry: Any = None) -> list[dict]:
    _stage_line(f"[validator] unit '{name}' cell {ci + 1}/{n_cells}: "
                f"{len(cell_items)} findings, {n_votes} vote(s)...")
    try:
        # repo passed only when known; 5-arg test fakes keep the shorter form.
        res = _validate_unit_batch(name, cell_items, cfg, threat_md,
                                   n_votes, repo=repo,
                                   cell_no=ci + cell_offset,
                                   agent_registry=agent_registry)
        if not isinstance(res, list) or len(res) != len(cell_items):
            raise ValueError("misaligned batch result")
        return res
    except Exception as e:
        if is_fatal_error(e):
            raise
        # Batch failed and its own retries are exhausted: the cell fails open
        # to needs-review per finding (never dropped)
        return [_degraded_finding(f, f"cell fallback ({type(e).__name__})")
                for f in cell_items]


def _run_validation_cells(planned, workers: int, *, cfg: dict, n_votes: int,
                          threat_md: str, repo: str | None,
                          cell_offset: int = 0,
                          agent_registry: Any = None
                          ) -> dict[tuple[int, int], list[dict]]:
    tasks = [(gi, cidx)
             for gi, g in enumerate(planned)
             for cidx in range(len(g[4]))]
    if not tasks:
        return {}

    def _fallback(gi: int, cidx: int) -> list[dict]:
        _n, items, _o, _d, cells = planned[gi]
        idx = cells[cidx][0]
        return [_degraded_finding(items[i], "validator fail-open")
                for i in idx]

    def _safe(key: tuple[int, int]) -> list[dict]:
        gi, cidx = key
        _name, _items, _origins, _direct, cells = planned[gi]
        idx, cell_items = cells[cidx]
        try:
            res = _run_cell(_name, cell_items, cidx, len(cells),
                            cfg=cfg, n_votes=n_votes, threat_md=threat_md,
                            repo=repo, cell_offset=cell_offset,
                            agent_registry=agent_registry)
            if not isinstance(res, list) or len(res) != len(idx):
                raise ValueError("misaligned cell result")
            return res
        except Exception as e:
            if is_fatal_error(e):
                raise
            return _fallback(gi, cidx)

    try:
        max_workers = max(1, int(workers))
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_safe, t) for t in tasks]
            for fut in futures:
                try:
                    results.append(fut.result())
                except Exception as e:
                    if is_fatal_error(e):
                        raise
                    results.append(e)
    except Exception as e:
        if is_fatal_error(e):
            raise
        results = [_safe(t) for t in tasks]

    cell_out: dict[tuple[int, int], list[dict]] = {}
    for key, res in zip(tasks, results):
        if isinstance(res, BaseException):
            if is_fatal_error(res):
                raise res
            cell_out[key] = _fallback(*key)
            continue
        cell_out[key] = res if isinstance(res, list) else _fallback(*key)
    return cell_out


def _reassemble_validation(planned, gated: list[dict],
                           cell_out: dict[tuple[int, int], list[dict]]
                           ) -> list[dict]:
    """Rebuild the gated list positionally: cell results overwrite their item
    slots, then direct (passthrough) routes land. Every gated index belongs to
    exactly one group, so ``out`` is fully covered without object identity."""
    out = list(gated)
    for gi, (_name, items, origins, direct, cells) in enumerate(planned):
        results = list(items)
        for cidx, (idx, _cell_items) in enumerate(cells):
            for i, r in zip(idx, cell_out.get((gi, cidx), [])):
                results[i] = r
        for i, r in direct.items():
            results[i] = r
        for oi, r in zip(origins, results):
            out[oi] = r
    return out


def run_validation(findings: list[dict], cfg: dict, threat_md: str = "",
                   votes: int | None = None,
                   units: list[dict] | None = None,
                   max_workers: int | None = None,
                   repo: str | None = None,
                   cell_offset: int = 0,
                   agent_registry: Any = None) -> list[dict]:
    cfg = cfg or {}
    threat_md = threat_md or ""
    n_votes = _resolve_votes(cfg, votes)
    findings = [dict(f) for f in (findings or [])]
    if not findings:
        return []
    gated = _evidence_gate_findings(findings)
    if not gated:
        return []
    # No API key: fail open, return gated as-is.
    from harness.config import api_key_present
    if not api_key_present(cfg):
        return gated
    todo = list(gated)

    try:
        from harness.config import get_concurrency as _gc
        _vw = int(max_workers or _gc(cfg))
    except Exception:
        _vw = 4
    groups = _group_by_unit(todo, units)
    _stage_line(f"[validator] {len(todo)} findings across "
                f"{len(groups)} partition(s)")

    _cs = _cell_size(cfg)
    planned = _plan_validation_cells(groups, _cs)
    cell_out = _run_validation_cells(
        planned, _vw, cfg=cfg, n_votes=n_votes, threat_md=threat_md,
        repo=repo, cell_offset=cell_offset, agent_registry=agent_registry)
    return _reassemble_validation(planned, gated, cell_out)
