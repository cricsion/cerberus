from __future__ import annotations

import logging
import os
import sys
from typing import Any

# Prompt text lives in harness/prompts/validation.py; re-exported for `v.<name>` imports.
from harness.agents.deep import is_fatal_error, sanitize_model_kwargs
from harness.agents.pool import worker_pool
from harness.fallback import (EMPTY_STRUCTURED, _append_note,
                              needs_review_verdicts, run_fail_open)
from harness.llmjson import extract_structured_items
from harness.prompts.validation import (OMITTED_NOTE, REFUTE_METHOD,
                                        ROUND_FAILED_NOTE, UNPARSEABLE_NOTE,
                                        VALIDATOR_SYSTEM)

_logger = logging.getLogger(__name__)


def _int_setting(mk: dict, key: str, default: int) -> int:
    try:
        return int(mk.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def _merge_verdict(base: dict, data: dict) -> dict:
    merged = dict(base)
    if isinstance(data, dict):
        for k in ("status", "confidence", "severity", "evidence",
                  "cwe", "fix_suggestion", "snippet"):
            if k in data and data[k] not in (None, ""):
                merged[k] = data[k]
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
        )[:4000]
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
            n = int(override)
            return min(5, max(1, n))
        except (TypeError, ValueError):
            pass
    try:
        raw = ((cfg or {}).get("verification") or {}).get("votes", 1)
        return min(5, max(1, int(str(raw).strip() or 1)))
    except (TypeError, ValueError):
        return 1


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


# findings per validator cell; _validate_unit_batch chunks by the same size so
# one LLM call never grows unbounded.
CELL_SIZE = 10

# Byte budget for one validator prompt's JSON: without it findings get
# byte-sliced into invalid JSON, dropping trailing findings.
MAX_BATCH_JSON_BYTES = 16000

# fp verdict stands only with a named control; auth-guard-only acquittals are downgraded.
_SANITIZER_RES = (
    r"paramet", r"\bbound\b", r"prepared", r"escap", r"saniti", r"quot",
    r"\bcast\b", r"allowlist", r"allow-list", r"realpath", r"safe_join",
    r"csrf", r"ownership", r"neutraliz", r"validat.*input", r"encod",
)
_AUTH_GUARD_RES = (
    r"log ?in.{0,40}(decorator|required|check|guard)",
    r"requires?\s+login",
    r"trusted",
    # threat-model scope language: a model row can prioritize, never acquit
    r"threat[- ]model",
    r"out[- ]of[- ]scope",
    r"not (a |an )?(modelled|modeled|listed)",
    r"section\s*[45]\b",
    r"deprioriti",
    r"prioriti[sz]ation only",
)


def _apply_fp_guardrail(verdict: dict) -> dict:
    if not isinstance(verdict, dict) or verdict.get("status") != "fp":
        return verdict
    import re as _re
    ev = str(verdict.get("evidence") or "").lower()
    if any(_re.search(p, ev) for p in _SANITIZER_RES):
        return verdict
    if any(_re.search(p, ev) for p in _AUTH_GUARD_RES):
        g = dict(verdict)
        g["status"] = "needs-review"
        prev = str(g.get("evidence") or "")
        note = "guardrail: auth-only acquittal, no sanitizer proof"
        g["evidence"] = _append_note(prev, note)
        return g
    return verdict


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
                   units: list[dict] | None) -> list[tuple[str, list[dict]]]:
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

    for f in findings:
        k = _key(f) if isinstance(f, dict) else "global"
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)
    return [(k, groups[k]) for k in order]


def _compact_finding(f: dict) -> dict:
    try:
        d = dict(f)
        for k in ("title", "snippet", "evidence"):
            v = d.get(k)
            if isinstance(v, str) and len(v) > 800:
                d[k] = v[:800]
        taint = d.get("taint")
        if isinstance(taint, dict):
            path = taint.get("path")
            d["taint"] = {
                "source": str(taint.get("source", ""))[:300],
                "sink": str(taint.get("sink", ""))[:300],
                "path": [str(p)[:300] for p in (path or [])][:20],
            }
        return {k: d.get(k) for k in (
            "id", "title", "cwe", "severity", "confidence", "path",
            "start_line", "end_line", "snippet", "taint", "refs",
            "evidence")}
    except TypeError:
        return {"id": f.get("id", ""), "title": f.get("title", "")}


def _batch_chunks(items: list[dict]) -> list[list[dict]]:
    import json as _json

    chunks: list[list[dict]] = []
    cur: list[dict] = []
    cur_bytes = 2  # JSON array brackets
    for f in items:
        one = len(_json.dumps(_compact_finding(f), default=str))
        if cur and (len(cur) >= CELL_SIZE
                    or cur_bytes + one + 1 > MAX_BATCH_JSON_BYTES):
            chunks.append(cur)
            cur = []
            cur_bytes = 2
        cur.append(f)
        cur_bytes += one + 1
    if cur:
        chunks.append(cur)
    return chunks


def _validate_unit_batch(group_name: str, items: list[dict], cfg: dict,
                          threat_md: str = "", n_votes: int = 1,
                          repo: str | None = None,
                          cell_no: int = 0) -> list[dict]:
    from harness.config import get_model_kwargs

    if not items:
        return []
    try:
        cell_no = max(0, int(cell_no or 0))
    except (TypeError, ValueError):
        cell_no = 0
    cell_scope = f"{group_name}:c{cell_no + 1}"
    model_kwargs = get_model_kwargs(cfg, "validator")
    mk = sanitize_model_kwargs(model_kwargs)

    ballots: dict[str, list[dict]] = {str(f.get("id")): [] for f in items
                                       if isinstance(f, dict)}
    n_votes = max(1, min(5, int(n_votes or 1)))
    chunks = _batch_chunks(items)

    # Backend resolved once like hunters._run_unit (fail-soft).
    from harness.agents.toolsets import graph_tools
    from harness.sandbox import close_backend, resolve_backend
    import uuid
    backend = (run_fail_open(
        f"backend validator-{group_name}",
        lambda: resolve_backend(
            cfg, repo,
            agent_id=f"validator-{group_name[:30]}_{uuid.uuid4().hex[:6]}"),
        default=None, logger=_logger) if repo else None)
    tools = graph_tools()
    tool_names = [getattr(t, "name", None) or getattr(t, "__name__", "tool")
                  for t in tools]
    try:
        for _round in range(n_votes):
            _vote = _round + 1
            for chunk in chunks:
                payload = [_compact_finding(f) for f in chunk]
                from harness.prompts.validation import build_batch_task
                msg = build_batch_task(group_name, threat_md, payload,
                                       repo=repo, tools=tool_names)

                def _call_validator_structured() -> tuple[Any, str, Any]:
                    from harness.agents.deep import run_structured
                    from harness.prompts.validation import VerdictBatch

                    return run_structured(
                        mk, VerdictBatch, VALIDATOR_SYSTEM, msg,
                        timeout=_int_setting(mk, "timeout", 60),
                        max_retries=_int_setting(mk, "max_retries", 3),
                        name=f"validator-{group_name}"[:60],
                        root_dir=repo, tools=tools, backend=backend,
                        trace_suffix=f"{cell_scope}:v{_vote}",
                        meta_extra={"unit": str(group_name),
                                    "cell": str(cell_no + 1),
                                    "vote": str(_vote)})

                parsed, raw_text, _ = run_fail_open(
                    "validator batch", _call_validator_structured,
                    default=EMPTY_STRUCTURED + ({},), logger=_logger)
                verdicts: list[dict] = extract_structured_items(
                    parsed, raw_text, field="verdicts", require_id=True)
                covered: set[str] = set()
                for v in verdicts:
                    vid = str(v.get("id", ""))
                    if vid in ballots:
                        ballots[vid].append(v)
                        covered.add(vid)

                # An omitted id is a partial reply, never an implicit confirmed/fp.
                if verdicts:
                    note = OMITTED_NOTE
                elif not str(raw_text or "").strip():
                    note = ROUND_FAILED_NOTE
                else:
                    note = UNPARSEABLE_NOTE
                missing = [f for f in chunk
                           if str(f.get("id", "")) not in covered]
                for ballot in needs_review_verdicts(missing, note):
                    vid = str(ballot.get("id", ""))
                    if vid in ballots:
                        ballots[vid].append(ballot)
    finally:
        if backend is not None:
            close_backend(backend)
    out: list[dict] = []
    for f in items:
        vid = str(f.get("id"))
        votes = ballots.get(vid, [])
        if not votes:
            # Batch reply omitted this id: fail open, never crash.
            out.append(_one_fallback(f, "no validator verdicts"))
            continue
        merged_votes = []
        for v in votes:
            merged_votes.append(_merge_verdict(dict(f), v))
        out.append(_apply_fp_guardrail(_majority_verdict(f, merged_votes)))
    return out


def _one_fallback(f: dict, note: str) -> dict:
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


def _classify_group(pair: tuple[str, list[dict]]
                    ) -> tuple[str, list[dict], dict[int, dict],
                               list[tuple[list[int], list[dict]]]]:
    name, items = pair
    batch_idx: list[int] = []
    direct: dict[int, dict] = {}
    for i, f in enumerate(items):
        action, g = _route_finding(f)
        if action == "llm":
            batch_idx.append(i)
        else:
            direct[i] = g
    cells = [([batch_idx[k] for k in range(s, min(s + CELL_SIZE, len(batch_idx)))],
               [items[batch_idx[k]] for k in range(s, min(s + CELL_SIZE, len(batch_idx)))])
             for s in range(0, len(batch_idx), CELL_SIZE)]
    return name, items, direct, [(c, ci) for c, ci in cells if c]


def _run_cell(name: str, cell_items: list[dict], ci: int,
              n_cells: int, *, cfg: dict, n_votes: int, threat_md: str,
              repo: str | None) -> list[dict]:
    print(f"[validator] unit '{name}' chunk {ci + 1}/{n_cells}: "
          f"{len(cell_items)} findings, {n_votes} vote(s)...",
          file=sys.stderr, flush=True)
    try:
        # repo passed only when known; 5-arg test fakes keep the shorter form.
        res = _validate_unit_batch(name, cell_items, cfg, threat_md,
                                   n_votes, repo=repo, cell_no=ci)
        if not isinstance(res, list) or len(res) != len(cell_items):
            raise ValueError("misaligned batch result")
        return res
    except Exception as e:
        if is_fatal_error(e):
            raise
        # Batch failed and its own retries are exhausted: the cell fails open
        # to needs-review per finding (never dropped)
        return [_one_fallback(f, f"cell fallback ({type(e).__name__})")
                for f in cell_items]


def _run_validation_cells(planned, workers: int, *, cfg: dict, n_votes: int,
                          threat_md: str, repo: str | None
                          ) -> dict[tuple[int, int], list[dict]]:
    cell_out: dict[tuple[int, int], list[dict]] = {}

    def _run_one(gi: int, cidx: int) -> list[dict]:
        _name, _items, _direct, cells = planned[gi]
        idx, cell_items = cells[cidx]
        return _run_cell(_name, cell_items, cidx, len(cells),
                         cfg=cfg, n_votes=n_votes, threat_md=threat_md,
                         repo=repo)

    def _fallback(gi: int, cidx: int) -> list[dict]:
        _name, items, _direct, cells = planned[gi]
        idx = cells[cidx][0]
        return [_one_fallback(items[i], "validator fail-open") for i in idx]

    try:
        with worker_pool(workers) as ex:
            pending = [
                ((gi, cidx), ex.submit(_run_one, gi, cidx))
                for gi, (_n, _i, _d, cells) in enumerate(planned)
                for cidx in range(len(cells))
            ]
            for (gi, cidx), fut in pending:
                try:
                    res = fut.result()
                    idx = planned[gi][3][cidx][0]
                    if not isinstance(res, list) or len(res) != len(idx):
                        raise ValueError("misaligned cell result")
                    cell_out[(gi, cidx)] = res
                except Exception as e:
                    if is_fatal_error(e):
                        raise
                    cell_out[(gi, cidx)] = _fallback(gi, cidx)
    except Exception as e:
        if is_fatal_error(e):
            raise
        # Pool-level failure: only the cells with no collected result are
        # re-run, sequentially and still fail-open (completed work is kept).
        for gi, (_name, _items, _direct, cells) in enumerate(planned):
            for cidx in range(len(cells)):
                if (gi, cidx) in cell_out:
                    continue
                try:
                    cell_out[(gi, cidx)] = _run_one(gi, cidx)
                except Exception as e:
                    if is_fatal_error(e):
                        raise
                    cell_out[(gi, cidx)] = _fallback(gi, cidx)
    return cell_out


def _reassemble_validation(planned, gated: list[dict],
                           cell_out: dict[tuple[int, int], list[dict]]
                           ) -> list[dict]:
    pos: dict[int, dict] = {}
    for gi, (_name, items, direct, cells) in enumerate(planned):
        for cidx, (idx, _cell_items) in enumerate(cells):
            for i, r in zip(idx, cell_out.get((gi, cidx), [])):
                pos[id(items[i])] = r
        for i, f in enumerate(items):
            if id(f) not in pos and i in direct:
                pos[id(f)] = direct[i]
    return [pos.get(id(f), f) for f in gated]


def run_validation(findings: list[dict], cfg: dict, threat_md: str = "",
                   votes: int | None = None,
                   units: list[dict] | None = None,
                   max_workers: int | None = None,
                   repo: str | None = None) -> list[dict]:
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
    key_env = str(cfg.get("api_key_env", "API_KEY"))
    if not os.environ.get(key_env) and not os.environ.get("API_KEY"):
        return gated
    todo = list(gated)

    try:
        from harness.config import get_concurrency as _gc
        _vw = int(max_workers or _gc(cfg))
    except Exception:
        _vw = 4
    groups = _group_by_unit(todo, units)
    print(f"[validator] {len(todo)} findings across {len(groups)} partition(s)",
          file=sys.stderr, flush=True)

    planned = [_classify_group(pair) for pair in groups]
    cell_out = _run_validation_cells(
        planned, _vw, cfg=cfg, n_votes=n_votes, threat_md=threat_md,
        repo=repo)
    return _reassemble_validation(planned, gated, cell_out)
