"""Triage: dedup by root cause, rank by exploitability rubric.

Stage A is deterministic (normalized path + CWE family); Stage B+C is batched
LLM. Nothing is dropped."""
from __future__ import annotations

import logging as _logging

_logger = _logging.getLogger(__name__)

from harness.agents.deep import is_fatal_error
from harness.llmjson import extract_structured_items
from harness.schemas import safe_int


def _norm_path(path: str) -> str:
    return str(path or "").strip().lower().replace("\\", "/").lstrip("./")


def _family(cwe: str) -> str:
    return str(cwe or "").strip().upper()


# Same file + same class groups only when the sinks are close; distant sinks
# stay distinct primaries. Fixed policy: no env override, no config key.
_LINE_GAP = 1


def _line_of(f: dict) -> int:
    return safe_int(f.get("start_line", 0))


def _group_key(f: dict) -> tuple[str, str] | None:
    """Stage-A key, or None when the finding must never be grouped."""
    if not f.get("cwe") and str(f.get("severity", "medium")) == "info":
        return None
    return (_norm_path(f.get("path", "")), _family(f.get("cwe", "")))


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
    """Deterministic grouping: primaries keep duplicate_of="", the rest point at
    their id. Never drops."""
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


def _capped_view(text: str, limit: int) -> str:
    """Bound a display view, marking the cut so no truncation is silent."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


def _slim_for_triage(f: dict) -> dict:
    taint = f.get("taint")
    if isinstance(taint, dict):
        trace = taint.get("path")
        if trace is None:
            trace = []
        elif not isinstance(trace, list):
            trace = [trace]
        taint = {
            "source": str(taint.get("source", "")),
            "sink": str(taint.get("sink", "")),
            "path": [str(step) for step in trace],
        }
    elif taint is not None:
        taint = str(taint)
    return {"id": f.get("id"),
            "unit": f.get("unit", ""),
            "path": f.get("path"),
            "start_line": f.get("start_line"), "end_line": f.get("end_line"),
            "cwe": f.get("cwe"),
            "title": str(f.get("title", "")),
            "severity": f.get("severity"), "confidence": f.get("confidence"),
            "status": f.get("status"),
            "control_type": f.get("control_type", ""),
            "duplicate_of": f.get("duplicate_of", ""),
            "snippet": str(f.get("snippet", "")),
            "rationale": _capped_view(str(f.get("rationale", "")), 2_000),
            "taint": taint,
            "evidence": _capped_view(str(f.get("evidence", "")), 2000)}


def _triage_messages(chunks: list[list[dict]], threat_md: str) -> list[str]:
    """One prompt per chunk: threat-model scope prefix + the slimmed findings."""
    import json as _json

    scope = (("[THREAT MODEL]\n" + threat_md.strip() + "\n\n")
             if (threat_md or "").strip() else "")
    from harness.prompts.triage import build_triage_batch_task

    return [build_triage_batch_task(
                scope, _json.dumps([_slim_for_triage(f) for f in chunk],
                                   default=str))
            for chunk in chunks]


def _apply_verdicts(findings: list[dict], verdicts: list[dict]) -> int:
    """Merge LLM verdicts into findings by id. Returns count applied. Never drops."""
    by_id = {str(f.get("id")): f for f in findings}
    applied = 0
    valid_sev = ("critical", "high", "medium", "low")
    for v in verdicts:
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
            target["evidence"] = (prev + f" | triage: {reason}") if prev else reason
        applied += 1
    return applied


def _resolve_batch(cfg: dict | None) -> int:
    """Max findings per triage LLM call (TRIAGE_BATCH, default 30; 0 = unlimited,
    else clamped to 1-200). Never raises."""
    try:
        raw = ((cfg or {}).get("triage") or {}).get("batch_size", 30)
        n = int(str(raw).strip() or 30)
        if n <= 0:
            return 10**9
        return min(200, max(1, n))
    except (TypeError, ValueError):
        return 30


def _log_entry(f: dict, batch: int) -> dict:
    """One written-log row per finding."""
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
    """Render the audit trail: one row per finding plus run totals. Pure function."""
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


def run_triage(findings: list[dict], cfg: dict, threat_md: str = "",
               repo: str = "") -> dict:
    """Stage A always; Stage B+C as per-chunk agent calls (each chunk's agent
    may re-read the contested code it is judging). Returns findings +
    triage_llm_calls + n_duplicates + triage_log; never drops, fails open to Stage A."""
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
    order = sorted(eligible,
                   key=lambda f: (_family(f.get("cwe", "")),
                                  _norm_path(f.get("path", "")),
                                  safe_int(f.get("start_line", 0))))
    batch_size = _resolve_batch(cfg)
    log: list[dict] = []
    from harness.config import get_concurrency as _gc
    _tw = _gc(cfg)
    chunks = [order[i:i + batch_size]
              for i in range(0, len(order), batch_size)]
    completed = 0
    import sys

    print(f"[triage] {len(order)} findings in {len(chunks)} batch(es)...",
          file=sys.stderr, flush=True)

    from harness.agents.deep import run_structured, sanitize_model_kwargs
    from harness.config import get_model_kwargs
    from harness.prompts.triage import TRIAGE_SYSTEM, TriageBatch

    try:
        mk = sanitize_model_kwargs(
            get_model_kwargs(cfg, "validator", agent="triager"))
        try:
            _timeout = max(int(mk.get("timeout", 180) or 180), 180)
        except (TypeError, ValueError):
            _timeout = 180
    except Exception as e:
        if is_fatal_error(e):
            raise
        _logger.debug("triage model config failed; Stage-A retained: %s", e)
        stats["n_duplicates"] = sum(1 for f in staged if f.get("duplicate_of"))
        return {"findings": staged, **stats}
    messages = _triage_messages(chunks, threat_md or "")
    for b, (chunk, message) in enumerate(zip(chunks, messages), start=1):
        print(f"[triage] batch {b}/{len(messages)}: {len(chunk)} findings, "
              f"{len(message.encode('utf-8')) // 1024} KB",
              file=sys.stderr, flush=True)
    by_id: dict[str, dict] = {}
    for s in staged:
        by_id.setdefault(str(s.get("id")), s)  # first match, like the old lookup

    from harness.agents.toolsets import graph_tools
    from harness.sandbox.local_backend import RepoLocalBackend
    from pathlib import Path

    tools = graph_tools()
    backend = None
    if repo:
        try:
            root = Path(repo).resolve()
            backend = RepoLocalBackend(repo_path=root)
        except Exception as e:
            if is_fatal_error(e):
                raise
            backend = None

    try:
        try:
            from langchain_core.runnables import RunnableLambda

            def _one(message):
                parsed, _ = run_structured(
                    mk, TriageBatch, TRIAGE_SYSTEM, message,
                    tools=tools, timeout=_timeout, max_retries=3,
                    name="triage", backend=backend, root_dir=repo or None)
                return parsed

            results = RunnableLambda(_one).batch(
                messages,
                config={"max_concurrency": _tw} if _tw else None,
                return_exceptions=True)
        except Exception as e:
            if is_fatal_error(e):
                raise
            _logger.debug("triage batch failed; Stage-A retained: %s", e)
            results = []
            chunks = []

        for b, chunk in enumerate(chunks, start=1):
            res = (results[b - 1] if b - 1 < len(results)
                   else RuntimeError("no batch result"))
            verdicts: list[dict] = []
            if isinstance(res, BaseException):
                if is_fatal_error(res):
                    raise res
                _logger.debug("triage batch %s failed; Stage-A retained: %s: %s",
                              b, type(res).__name__, res)
            else:
                completed += 1
                try:
                    verdicts = extract_structured_items(
                        res, "", field="verdicts", require_id=True)
                except Exception as e:
                    if is_fatal_error(e):
                        raise
                    _logger.debug("triage batch %s unparseable: %s", b, e)
            try:
                if verdicts:
                    _apply_verdicts(staged, verdicts)
                for f in chunk:
                    log.append(_log_entry(by_id.get(str(f.get("id")), f), b))
            except Exception as e:
                if is_fatal_error(e):
                    raise
                _logger.debug("triage batch %s apply/log failed: %s", b, e)
            print(f"[triage] batch {b} done ({len(chunk)} findings)",
                  file=sys.stderr, flush=True)
    finally:
        if backend is not None:
            from harness.sandbox import close_backend
            close_backend(backend)

    stats["triage_llm_calls"] = completed
    if not log:
        log = [_log_entry(f, 0) for f in staged]
    stats["triage_log"] = log
    stats["n_duplicates"] = sum(1 for f in staged if f.get("duplicate_of"))
    return {"findings": staged, **stats}
