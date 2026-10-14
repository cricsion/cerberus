"""Triage: dedup by root cause, rank by exploitability rubric (plan-1345 M4).

Pipeline position: aggregator -> validator -> triage -> scorer.

Stage A (deterministic, always): group by normalized path + CWE-family.
  Same group -> provisional duplicates (duplicate_of=primary id, primary = max
  confidence). Info context without a CWE is never grouped. Status untouched,
  nothing dropped.
Stage B+C (LLM, batched over eligible findings, default 30/call): the model
  confirms/splits each provisional group per root-cause rules AND assigns
  severity from evidence (rubric answers first, singletons included). Fail-open:
  any error keeps the Stage-A verdict for dedup and the heuristic severity.

Cost note: exactly one triage call per scan (plus N validator votes per finding
from M3). Counts are logged (triage_llm_calls/n_duplicates) for the log-only
observability follow-up; nothing gates on them.
"""
from __future__ import annotations

import logging as _logging
from typing import Any

_logger = _logging.getLogger(__name__)

from harness.agents.deep import is_fatal_error
from harness.agents.pool import worker_pool
from harness.fallback import EMPTY_STRUCTURED, run_fail_open
from harness.llmjson import extract_structured_items
from harness.schemas import safe_int


def _norm_path(path: str) -> str:
    try:
        return str(path or "").strip().lower().replace("\\", "/").lstrip("./")
    except (AttributeError, TypeError):
        return str(path or "")


def _family(cwe: str) -> str:
    return str(cwe or "").strip().upper()


# Same file + same class groups only when the sinks are close: distant sinks
# are distinct instances, so they stay distinct primaries. Fixed policy, not
# an operator knob: no env override, no config key.
_LINE_GAP = 1


def _line_of(f: dict) -> int:
    return safe_int(f.get("start_line", 0))


def _group_key(f: dict) -> tuple[str, str] | None:
    """Stage-A key, or None when the finding must never be grouped (info
    context without a CWE claim)."""
    try:
        if not f.get("cwe") and str(f.get("severity", "medium")) == "info":
            return None
        return (_norm_path(f.get("path", "")), _family(f.get("cwe", "")))
    except (AttributeError, TypeError):
        return None


def _elect_primary(out: list[dict], idxs: list[int]) -> None:
    """Highest confidence wins the subgroup; rest point at it. Never drops."""
    if not idxs:
        return
    try:
        primary = max(idxs, key=lambda i: float(out[i].get("confidence", 0) or 0))
    except (TypeError, ValueError):
        primary = idxs[0]
    pid = str(out[primary].get("id", ""))
    for i in idxs:
        out[i]["duplicate_of"] = "" if i == primary else pid


def stage_a(findings: list[dict]) -> list[dict]:
    """Deterministic grouping. Returns new list; primaries get duplicate_of="",
    rest duplicate_of=<primary id>. Original order preserved."""
    out = [dict(f) for f in (findings or [])]
    for f in out:
        f.setdefault("duplicate_of", "")
    groups: dict[tuple[str, str], list[int]] = {}
    for i, f in enumerate(out):
        key = _group_key(f)
        if key is None:
            continue
        groups.setdefault(key, []).append(i)
    for idxs in groups.values():
        if len(idxs) < 2:
            continue
        # Split by line proximity: same file + same class at distant lines
        # are distinct sinks, not one instance.
        ordered = sorted(idxs, key=lambda i: _line_of(out[i]))
        run = [ordered[0]]
        for i in ordered[1:]:
            if abs(_line_of(out[i]) - _line_of(out[run[-1]])) > _LINE_GAP:
                _elect_primary(out, run)
                run = [i]
            else:
                run.append(i)
        _elect_primary(out, run)
    return out


def _slim_for_triage(f: dict) -> dict:
    taint = f.get("taint")
    if isinstance(taint, dict):
        trace = taint.get("path")
        if not isinstance(trace, list):
            trace = []
        taint = {
            "source": str(taint.get("source", ""))[:300],
            "sink": str(taint.get("sink", ""))[:300],
            "path": [str(step)[:300] for step in trace[:12]],
        }
    elif taint is not None:
        taint = str(taint)[:800]
    return {"id": f.get("id"), "path": f.get("path"),
            "title": str(f.get("title", ""))[:300],
            "cwe": f.get("cwe"),
            "start_line": f.get("start_line"), "end_line": f.get("end_line"),
            "severity": f.get("severity"), "confidence": f.get("confidence"),
            "status": f.get("status"), "duplicate_of": f.get("duplicate_of", ""),
            "snippet": str(f.get("snippet", ""))[:2000],
            "rationale": str(f.get("rationale", ""))[:1000],
            "taint": taint,
            "evidence": str(f.get("evidence", ""))[:2000]}


def _triage_all_call(findings: list[dict], threat_md: str, cfg: dict) -> list[dict]:
    """One LLM call over ALL eligible findings: confirm/split every provisional
    group per root-cause rules + severity rubric for each finding (singletons
    included — dedup is vacuous for them but the rubric still applies).
    Returns verdict dicts; [] on any failure (caller keeps Stage-A)."""
    from harness.agents.deep import sanitize_model_kwargs
    from harness.config import get_model_kwargs

    eligible = [f for f in (findings or [])
                if isinstance(f, dict) and _group_key(f) is not None]
    if len(eligible) < 1:
        return []
    model_kwargs = get_model_kwargs(cfg, "validator")
    mk = sanitize_model_kwargs(model_kwargs)
    try:
        try:
            _timeout = max(int(mk.get("timeout", 180) or 180), 180)
        except (TypeError, ValueError):
            _timeout = 180
        import json as _json
        slim = [_slim_for_triage(f) for f in eligible]
        scope = (("[THREAT MODEL]\n" + threat_md.strip() + "\n\n")
                 if (threat_md or "").strip() else "")
        from harness.agents.deep import run_structured
        from harness.prompts.triage import (TRIAGE_SYSTEM, TriageBatch,
                                            build_triage_batch_task)
        msg = build_triage_batch_task(
            scope, _json.dumps(slim, default=str))
        def _call_triage_structured() -> tuple[Any, str, Any]:
            from harness.agents.deep import run_structured

            return run_structured(
                mk, TriageBatch, TRIAGE_SYSTEM, msg, timeout=_timeout,
                max_retries=3, name="triage")

        parsed, raw_text, _ = run_fail_open(
            "triage batch", _call_triage_structured,
            default=EMPTY_STRUCTURED + ({},))

        verdicts: list[dict] = extract_structured_items(
            parsed, raw_text, field="verdicts", require_id=True)
        return verdicts
    except Exception as e:
        if is_fatal_error(e):
            raise
        _logger.debug("triage LLM call failed, keeping Stage-A: %s", e)
        return []


def _apply_verdicts(findings: list[dict], verdicts: list[dict]) -> int:
    """Merge LLM verdicts into findings by id. Returns count applied. Never drops."""
    by_id = {str(f.get("id")): f for f in findings}
    applied = 0
    valid_sev = ("critical", "high", "medium", "low")
    for v in verdicts:
        try:
            target = by_id.get(str(v.get("id", "")))
            if target is None:
                continue
            dup = v.get("duplicate_of")
            if dup is None:
                target["duplicate_of"] = ""
            elif str(dup) in by_id and str(dup) != str(target.get("id")):
                target["duplicate_of"] = str(dup)
            # else: unknown id — ignore, keep Stage-A verdict.
            sev = str(v.get("severity", "") or "").strip().lower()
            if sev in valid_sev:
                target["severity"] = sev
            tri = v.get("triage")
            if isinstance(tri, dict) and tri:
                target["triage"] = {k: tri[k] for k in
                                    ("reachable", "control", "preconditions",
                                     "auth", "rw", "blast", "rationale") if k in tri}
            reason = str(v.get("reason", "") or "").strip()
            if reason:
                prev = str(target.get("evidence") or "")
                target["evidence"] = (prev + f" | triage: {reason}")[:4000] if prev else reason
            applied += 1
        except Exception:
            continue
    return applied


def _resolve_batch(cfg: dict | None) -> int:
    """Max findings per triage LLM call. Default 30, env TRIAGE_BATCH via
    config interpolation. 0 = unlimited (codebase convention), clamped to
    1–200 otherwise. Never raises."""
    try:
        raw = ((cfg or {}).get("triage") or {}).get("batch_size", 30)
        n = int(str(raw).strip() or 30)
        if n <= 0:
            return 10**9
        return min(200, max(1, n))
    except (TypeError, ValueError):
        return 30


def _log_entry(f: dict, batch: int) -> dict:
    """One written-log row per finding (reference-harness style audit trail)."""
    try:
        tri = f.get("triage") if isinstance(f.get("triage"), dict) else {}
        return {"id": str(f.get("id", "")), "batch": batch,
                "path": str(f.get("path", "")),
                "lines": f"{f.get('start_line', 0)}-{f.get('end_line', 0)}",
                "cwe": str(f.get("cwe", "")), "severity": str(f.get("severity", "")),
                "status": str(f.get("status", "")),
                "duplicate_of": str(f.get("duplicate_of", "") or ""),
                "triage": dict(tri),
                "evidence_tail": str(f.get("evidence", ""))[-500:]}
    except Exception:
        return {"id": str((f or {}).get("id", "") if isinstance(f, dict) else ""),
                "batch": batch}


def render_triage_log(log: list[dict], n_calls: int = 0,
                      batch_size: int = 30) -> str:
    """Render the written audit trail (reference-harness style): one row per
    finding with verdict + reason + rubric, plus run totals. Pure function."""
    try:
        log = [e for e in (log or []) if isinstance(e, dict)]
        n_dupe = sum(1 for e in log if e.get("duplicate_of"))
        lines = ["# Triage log", "",
                 f"Rows: {len(log)} | duplicates: {n_dupe} "
                 f"| primaries: {len(log) - n_dupe} | LLM calls: {n_calls} "
                 f"(batches of <={batch_size})", ""]
        current = 0
        for e in log:
            try:
                if e.get("batch", 0) != current:
                    current = e.get("batch", 0)
                    lines += [f"## Batch {current}", ""]
                head = (f"- [{e.get('id', '')}] {e.get('path', '')}:"
                        f"{e.get('lines', '')} {e.get('cwe', '')} "
                        f"{e.get('severity', '')}/{e.get('status', '')}")
                if e.get("duplicate_of"):
                    head += f" -> duplicate of {e['duplicate_of']}"
                lines.append(head)
                tri = e.get("triage") if isinstance(e.get("triage"), dict) else {}
                if tri:
                    rub = " ".join(f"{k}={tri[k]}" for k in
                                   ("reachable", "control", "preconditions",
                                    "auth", "rw", "blast") if k in tri)
                    rat = str(tri.get("rationale", "") or "").strip()
                    if rub:
                        lines.append(f"  rubric: {rub}")
                    if rat:
                        lines.append(f"  rationale: {rat}")
                tail = str(e.get("evidence_tail", "") or "").strip()
                if tail:
                    lines.append(f"  evidence: ...{tail[-300:]}")
            except Exception:
                continue
        return "\n".join(lines).rstrip() + "\n"
    except Exception:
        return "# Triage log\n\n(unavailable)\n"


def run_triage(findings: list[dict], cfg: dict, threat_md: str = "") -> dict:
    """Stage A always; Stage B+C as LLM calls over batches of eligible findings.

    Batching: eligible findings sort by (CWE-family, path, line) so same-family
    items share a batch when possible, then chunk to batch_size (default 30).
    Returns {"findings": [...], "triage_llm_calls": int, "n_duplicates": int,
    "triage_log": [...]} — the log is the written audit trail (one row per
    finding: verdict + reason + rubric). Never drops findings; fail-open keeps
    Stage-A on any LLM error.
    """
    staged = stage_a(findings)
    stats: dict = {"triage_llm_calls": 0, "n_duplicates": 0, "triage_log": []}
    if not staged:
        return {"findings": staged, **stats}
    stats["triage_log"] = [_log_entry(f, 0) for f in staged]
    from harness.config import api_key_present
    if not api_key_present(cfg):
        stats["n_duplicates"] = sum(1 for f in staged if f.get("duplicate_of"))
        return {"findings": staged, **stats}
    eligible = [f for f in staged if _group_key(f) is not None]
    if not eligible:
        return {"findings": staged, **stats}
    try:
        order = sorted(eligible,
                       key=lambda f: (_family(f.get("cwe", "")),
                                      _norm_path(f.get("path", "")),
                                      safe_int(f.get("start_line", 0))))
    except Exception:
        order = list(eligible)
    batch_size = _resolve_batch(cfg)
    log: list[dict] = []
    try:
        from harness.config import get_concurrency as _gc
        _tw = _gc(cfg)
    except Exception:
        _tw = 4
    chunks = [order[i:i + batch_size]
              for i in range(0, len(order), batch_size)]
    completed: list[int] = []
    try:
        import sys as _sys
        print(f"[triage] {len(order)} findings in {len(chunks)} batch(es)...",
              file=_sys.stderr, flush=True)
    except Exception:
        pass

    def _run_batch(args: tuple[int, list[dict]]) -> tuple[int, list[dict]]:
        b, chunk = args
        try:
            verdicts = _triage_all_call(chunk, threat_md or "", cfg or {})
            try:
                import sys as _s2
                print(f"[triage] batch {b} done ({len(chunk)} findings)",
                      file=_s2.stderr, flush=True)
            except Exception:
                pass
            return b, verdicts if isinstance(verdicts, list) else []
        except Exception as e:
            if is_fatal_error(e):
                raise
            return b, []

    try:
        # Bounded concurrency, no stage-wide hard timeout. Work is bounded by
        # ModelCallLimitMiddleware, recursion_limit, and provider timeouts.
        with worker_pool(_tw) as ex:
            futs = [ex.submit(_run_batch, (b, chunk))
                    for b, chunk in enumerate(chunks, start=1)]
            for i, fut in enumerate(futs):
                b = i + 1
                try:
                    bb, verdicts = fut.result()
                    completed.append(bb)  # call succeeded (verdicts may be empty)
                    if verdicts:
                        _apply_verdicts(staged, verdicts)
                except Exception as e:
                    if is_fatal_error(e):
                        raise
                # Log every batch, failed or not: a failed batch's findings
                # keep their Stage-A verdicts in the audit trail.
                for f in chunks[b - 1]:
                    try:
                        target = next(s for s in staged
                                      if str(s.get("id")) == str(f.get("id")))
                        log.append(_log_entry(target, b))
                    except Exception:
                        continue
    except Exception as e:
        if is_fatal_error(e):
            raise
        pass
    stats["triage_llm_calls"] = len(completed)
    if not log:
        log = [_log_entry(f, 0) for f in staged]
    stats["triage_log"] = log
    stats["n_duplicates"] = sum(1 for f in staged if f.get("duplicate_of"))
    return {"findings": staged, **stats}
