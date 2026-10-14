"""Validator: evidence gate + adversarial falsify (different model than hunter)."""
from __future__ import annotations

import os
import sys
from typing import Any

# Prompt text lives in harness/prompts/validation.py; re-exported here so
# existing `v.<name>` imports keep working.
from harness.agents.deep import is_fatal_error, sanitize_model_kwargs
from harness.agents.pool import worker_pool
from harness.fallback import (EMPTY_STRUCTURED, needs_review_verdicts,
                              run_fail_open)
from harness.llmjson import extract_structured_items, parse_verdict_array
from harness.prompts.validation import (FALSIFY_INSTRUCTIONS,
                                        REFUTE_METHOD, VALIDATOR_SYSTEM,
                                        _validator_message)


def _int_setting(mk: dict, key: str, default: int) -> int:
    """Coerce a model kwarg to int (config may resolve ${VAR:-180} as text)."""
    try:
        return int(mk.get(key, default) or default)
    except (TypeError, ValueError):
        return default



def _merge_verdict(base: dict, data: dict) -> dict:
    """Merge an LLM verdict dict into the finding; clamp + validate enums."""
    merged = dict(base)
    if isinstance(data, dict):
        for k in ("status", "confidence", "severity", "evidence",
                  "cwe", "fix_suggestion", "snippet"):
            if k in data and data[k] not in (None, ""):
                merged[k] = data[k]
        note = str(data.get("fallback_note", "") or "")
        if note:
            prev = str(merged.get("evidence") or "")
            merged["evidence"] = (
                (prev + " | " + note) if prev else note
            )[:4000]
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


def _validate_single(finding: dict, cfg: dict, instructions: str | None = None,
                     threat_md: str = "") -> dict:
    """Validate one finding first-principles; fail-open to needs-review.

    Two rungs, not four: the structured (ToolStrategy-backed) call, then a
    single prose fallback that parses a JSON verdict array out of the same
    reply's final text. The bespoke ``STATUS=`` line protocol and its keyword
    ladder were re-implementations of the framework's structured-output
    handling; a reply that yields neither a parsed schema nor a JSON array
    fail-opens directly.
    """
    from harness.config import get_model_kwargs

    base = dict(finding)
    if instructions is None:
        instructions = FALSIFY_INSTRUCTIONS
    model_kwargs = get_model_kwargs(cfg, "validator")
    mk = sanitize_model_kwargs(model_kwargs)
    reason = "no structured verdict"
    try:
        from harness.agents.deep import run_structured
        from harness.prompts.validation import VerdictUpdate
        msg = _validator_message(base, instructions, threat_md)
        parsed, raw_text, _ = run_structured(
            mk, VerdictUpdate, VALIDATOR_SYSTEM, msg,
            timeout=_int_setting(mk, "timeout", 60),
            max_retries=_int_setting(mk, "max_retries", 3), name="validator")
        data = parsed.model_dump() if hasattr(parsed, "model_dump") else dict(parsed or {})
        if not isinstance(data, dict) or not data or not data.get("status"):
            # Structured path refused the schema: parse the prose fallback
            # from the SAME reply (no second LLM call).
            data = _verdict_from_text(base, raw_text)
        if data:
            return _merge_verdict(dict(base), data)
    except Exception as e:
        if is_fatal_error(e):
            raise
        reason = type(e).__name__
    fail = dict(base)
    fail["status"] = "needs-review"
    note = f"validator fail-open ({reason})"
    prev = str(fail.get("evidence") or "")
    fail["evidence"] = (prev + f" | {note}")[:4000] if prev else note
    return fail


def _verdict_from_text(base: dict, raw_text: str) -> dict:
    """One prose-fallback verdict from a reply's final text, or {}.

    Reuses the shared JSON-array parser; prefers the item whose id matches the
    finding, and accepts a single unnamed item. Never raises.
    """
    try:
        items = parse_verdict_array(raw_text, require_id=False)
    except Exception:
        return {}
    if not items:
        return {}
    fid = str(base.get("id", ""))
    for it in items:
        if fid and str(it.get("id", "")) == fid:
            return it
    return items[0] if len(items) == 1 else {}



def evidence_gate(finding: dict) -> bool:
    """Deterministic pre-filter before LLM validation (precision)."""
    try:
        taint = finding.get("taint") or {}
        if not isinstance(taint, dict):
            taint = {}
        return bool(finding.get("path") and finding.get("snippet")
                    and (taint.get("sink") or finding.get("evidence")))
    except Exception:
        return True  # fail-open: never drop on gate error


def _resolve_votes(cfg: dict | None, override: int | None = None) -> int:
    """Configured verifier count N. Default 1, env VERIFIER_VOTES via config
    interpolation, CLI --votes override wins. Clamped to 1–5. Never raises."""
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
    """Majority-or-tie is final (plan-1345 M3). No judge, ever.

    Strict majority (>N/2) for confirmed/fp wins; anything else (exact tie,
    no-majority split, all fail-open) is a valid terminal needs-review.
    Never drops: always returns a finding.
    """
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
            g["evidence"] = (prev + f" | {tag}")[:4000] if prev else tag
            return g
    g = dict(by_status.get("needs-review") or by_status.get("confirmed")
             or by_status.get("fp") or base)
    g["status"] = "needs-review"
    prev = str(g.get("evidence") or "")
    tag = (f"consensus: tie/no-majority "
           f"({counts['confirmed']}c/{counts['fp']}f/{counts['needs-review']}n of {n})")
    g["evidence"] = (prev + f" | {tag}")[:4000] if prev else tag
    return g


# Findings per validator run. Cells of this size run in parallel, and the
# batch call inside _validate_unit_batch chunks by the same size, so one LLM
# call never grows unbounded even when the cell-splitting fallback fires.
CELL_SIZE = 10

# Byte budget for the JSON payload embedded in one validator prompt. The
# prompt's outer instructions are bounded; without this the serialized
# findings can be silently byte-sliced into invalid JSON, dropping the last
# findings in the chunk from the model's view.
MAX_BATCH_JSON_BYTES = 16000

# fp verdict stands only with a named control; auth-guard-only acquittals
# (the observed failure mode: "requires login … trusted") are downgraded.
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
    """Downgrade fp -> needs-review when the acquittal cites only auth/login
    trust with no sanitizer proof. Sanitizer-backed and sink-absence fps
    stand untouched. Never raises, never drops."""
    try:
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
            g["evidence"] = (prev + f" | {note}")[:4000] if prev else note
            return g
        return verdict
    except Exception:
        return verdict


def _route_finding(f: dict) -> tuple[str, dict]:
    """Classify a gated finding: ("llm", f) needs an LLM verdict,
    ("passthrough", f) needs none. Every vulnerability claim faces the LLM —
    hunter findings, custom taint rules, registry Semgrep, template heuristics.
    Only gate-killed fps (already dead) and claim-less info context pass through.
    Never drops: always returns the finding."""
    if f.get("status") == "fp" and "evidence_gate" in str(f.get("evidence", "")):
        return "passthrough", f
    # Info context without a CWE is scan context, not a vulnerability claim.
    if not f.get("cwe") and f.get("severity", "medium") == "info":
        return "passthrough", f
    return "llm", f


def _group_by_unit(findings: list[dict],
                   units: list[dict] | None) -> list[tuple[str, list[dict]]]:
    """Group findings by partition for one-validator-per-partition.

    Uses the stamped `unit` field, else maps files via the unit file lists.
    Unmapped findings form a single "global" group (never dropped).
    Order: first-seen group order is preserved.
    """
    file_to_unit: dict[str, str] = {}
    try:
        for u in (units or []):
            if not isinstance(u, dict):
                continue
            name = str(u.get("name") or u.get("unit") or "")
            if not name:
                continue
            for fp in (u.get("files") or []):
                try:
                    file_to_unit.setdefault(str(fp), name)
                except Exception:
                    continue
    except Exception:
        pass
    groups: dict[str, list[dict]] = {}
    order: list[str] = []

    def _key(f: dict) -> str:
        try:
            stamped = str(f.get("unit") or "").strip()
            if stamped:
                return stamped
            p = str(f.get("path", "") or "")
            if p in file_to_unit:
                return file_to_unit[p]
            base = p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            for fp, name in file_to_unit.items():
                try:
                    if fp.endswith("/" + base) or base == fp.rsplit("/", 1)[-1]:
                        return name
                except Exception:
                    continue
        except Exception:
            pass
        return "global"

    for f in findings:
        k = _key(f) if isinstance(f, dict) else "global"
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)
    return [(k, groups[k]) for k in order]


def _parse_verdict_array(text: str) -> list[dict]:
    """Best-effort parse of a JSON verdict array from an LLM reply."""
    return parse_verdict_array(text, require_id=True)


def _compact_finding(f: dict) -> dict:
    """Small prompt payload for one finding; never raises."""
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
            "start_line", "end_line", "snippet", "taint", "evidence")}
    except Exception:
        return {"id": f.get("id", ""), "title": f.get("title", "")}


def _batch_chunks(items: list[dict]) -> list[list[dict]]:
    """Chunk findings by both CELL_SIZE and serialized prompt byte budget."""
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
                          repo: str | None = None) -> list[dict]:
    """One validator run for a whole partition: a single batched LLM call per
    vote round over up to CELL_SIZE findings at a time.

    Items missing from a batch reply fall back to a per-finding
    needs-review verdict. Fail-open throughout: unparseable rounds keep
    needs-review.
    """
    from harness.config import get_model_kwargs

    if not items:
        return []
    model_kwargs = get_model_kwargs(cfg, "validator")
    mk = sanitize_model_kwargs(model_kwargs)

    ballots: dict[str, list[dict]] = {str(f.get("id")): [] for f in items
                                       if isinstance(f, dict)}
    n_votes = max(1, min(5, int(n_votes or 1)))
    chunks = _batch_chunks(items)

    # Validator tool surface: full hunter code-intelligence parity plus the
    # reachability helper (plan.md §6). The backend is resolved once, the same
    # way hunters._run_unit does, so the backend-dependent SAST wrappers match
    # the hunter's; fail-soft to None (the builder then resolves its own).
    from harness.agents.toolsets import validator_tools
    from harness.sandbox import close_backend, resolve_backend
    try:
        import uuid
        backend = (resolve_backend(
            cfg, repo,
            agent_id=f"validator-{group_name[:30]}_{uuid.uuid4().hex[:6]}")
            if repo else None)
    except Exception:
        backend = None
    tools = validator_tools(backend)
    try:
        for _round in range(n_votes):
            for chunk in chunks:
                payload = [_compact_finding(f) for f in chunk]
                from harness.prompts.validation import build_batch_task
                msg = build_batch_task(group_name, threat_md, payload)
                note = "validator round fail-open"

                def _call_validator_structured() -> tuple[Any, str, Any]:
                    from harness.agents.deep import run_structured
                    from harness.prompts.validation import VerdictBatch

                    return run_structured(
                        mk, VerdictBatch, VALIDATOR_SYSTEM, msg,
                        timeout=_int_setting(mk, "timeout", 60),
                        max_retries=_int_setting(mk, "max_retries", 3),
                        name=f"validator-{group_name}"[:60],
                        root_dir=repo, tools=tools, backend=backend)

                parsed, raw_text, _ = run_fail_open(
                    "validator batch", _call_validator_structured,
                    default=EMPTY_STRUCTURED + ({},))
                verdicts: list[dict] = extract_structured_items(
                    parsed, raw_text, field="verdicts", require_id=True)
                covered: set[str] = set()
                for v in verdicts:
                    vid = str(v.get("id", ""))
                    if vid in ballots:
                        ballots[vid].append(v)
                        covered.add(vid)

                # Any omitted id is a partial reply, not an implicit
                # confirmed/fp: it gets a conservative needs-review ballot so
                # later rounds cannot manufacture consensus from silence.
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
            try:
                merged_votes.append(_merge_verdict(dict(f), v))
            except Exception:
                fb = dict(f)
                fb["status"] = "needs-review"
                merged_votes.append(fb)
        out.append(_apply_fp_guardrail(_majority_verdict(f, merged_votes)))
    return out


def _one_fallback(f: dict, note: str) -> dict:
    fb = dict(f) if isinstance(f, dict) else {}
    fb["status"] = "needs-review"
    prev = str(fb.get("evidence") or "")
    fb["evidence"] = (prev + f" | {note}")[:4000] if prev else note
    return fb


def _evidence_gate_findings(findings: list[dict]) -> list[dict]:
    """Apply the deterministic validator gate, never dropping a finding."""
    gated: list[dict] = []
    for f in findings:
        # evidence_gate is total: its body ends in `except Exception: return
        # True`, so a gate error is already fail-opened inside the callee and
        # nothing reachable here can raise out of the call.
        if evidence_gate(f):
            gated.append(f)
            continue
        g = dict(f)
        # needs-review items without evidence stay needs-review so the
        # no-API-key smoke path is unaffected (they pass gate anyway).
        if g.get("status") == "needs-review" and not g.get("evidence"):
            gated.append(g)
        else:
            g["status"] = "fp"
            prev = str(g.get("evidence") or "")
            reason = "evidence_gate: missing path/snippet/sink evidence"
            g["evidence"] = (prev + f" | {reason}")[:4000] if prev else reason
            gated.append(g)
    return gated


def _classify_group(pair: tuple[str, list[dict]]
                    ) -> tuple[str, list[dict], dict[int, dict],
                               list[tuple[list[int], list[dict]]]]:
    """Split a partition into direct results + CELL_SIZE validator cells."""
    name, items = pair
    batch_idx: list[int] = []
    direct: dict[int, dict] = {}
    for i, f in enumerate(items):
        try:
            action, g = _route_finding(f)
        except Exception:
            action, g = "llm", f
        if action == "llm":
            batch_idx.append(i)
        else:
            direct[i] = g
    cells = [([batch_idx[k] for k in range(s, min(s + CELL_SIZE, len(batch_idx)))],
               [items[batch_idx[k]] for k in range(s, min(s + CELL_SIZE, len(batch_idx)))])
             for s in range(0, len(batch_idx), CELL_SIZE)]
    return name, items, direct, [(c, ci) for c, ci in cells if c]


def _run_cell(name: str, idx: list[int], cell_items: list[dict], ci: int,
              n_cells: int, *, cfg: dict, n_votes: int, threat_md: str,
              repo: str | None) -> list[dict]:
    """Run one validator cell, falling back per finding when the batch fails."""
    try:
        print(f"[validator] unit '{name}' chunk {ci + 1}/{n_cells}: "
              f"{len(cell_items)} findings, {n_votes} vote(s)...",
              file=sys.stderr, flush=True)
    except Exception:
        pass
    try:
        # repo is only passed when known: callers that predate the
        # parameter (and the tests' 5-arg fakes) keep the shorter form.
        res = _validate_unit_batch(name, cell_items, cfg, threat_md,
                                   n_votes, repo=repo)
        if not isinstance(res, list) or len(res) != len(cell_items):
            raise ValueError("misaligned batch result")
        return res
    except Exception as e:
        if is_fatal_error(e):
            raise
        # Batch failed: per-finding singles, fail-open each.
        out = []
        for f in cell_items:
            try:
                out.append(_validate_single(f, cfg, None, threat_md))
            except Exception as e2:
                if is_fatal_error(e2):
                    raise
                out.append(_one_fallback(
                    f, f"cell fallback ({type(e2).__name__})"))
        return out


def _plan_validation_groups(groups: list[tuple[str, list[dict]]]
                            ) -> list[tuple[str, list[dict], dict[int, dict],
                                           list[tuple[list[int], list[dict]]]]]:
    """Turn partitions into validator cells; malformed partitions degrade."""
    planned: list[tuple[str, list[dict], dict[int, dict],
                        list[tuple[list[int], list[dict]]]]] = []
    for pair in groups:
        try:
            planned.append(_classify_group(pair))
        except Exception:
            name, items = pair
            planned.append((name, items, {},
                            [([i for i in range(len(items))], list(items))]))
    return planned


def _run_validation_cells(planned, workers: int, *, cfg: dict, n_votes: int,
                          threat_md: str, repo: str | None
                          ) -> dict[tuple[int, int], list[dict]]:
    """Run validator cells in bounded concurrency, then fail open leftovers."""
    cell_out: dict[tuple[int, int], list[dict]] = {}

    def _run_one(gi: int, cidx: int) -> list[dict]:
        _name, _items, _direct, cells = planned[gi]
        idx, cell_items = cells[cidx]
        return _run_cell(_name, idx, cell_items, cidx, len(cells),
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
        # No parallel bonus: rerun cells sequentially, still fail-open.
        cell_out = {}
        for gi, (_name, _items, _direct, cells) in enumerate(planned):
            for cidx in range(len(cells)):
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
    """Put cells back into gated order using object identity, not ids."""
    pos: dict[int, dict] = {}
    for gi, (_name, items, direct, cells) in enumerate(planned):
        for cidx, (idx, _cell_items) in enumerate(cells):
            for i, r in zip(idx, cell_out.get((gi, cidx), [])):
                try:
                    pos[id(items[i])] = r
                except Exception:
                    continue
        for i, f in enumerate(items):
            try:
                if id(f) not in pos and i in direct:
                    pos[id(f)] = direct[i]
            except Exception:
                continue
    return [pos.get(id(f), f) for f in gated]


def run_validation(findings: list[dict], cfg: dict, threat_md: str = "",
                   votes: int | None = None,
                   units: list[dict] | None = None,
                   max_workers: int | None = None,
                   repo: str | None = None) -> list[dict]:
    """Deterministic evidence_gate + one batched validator run per partition.

    (a) Applies evidence_gate deterministically first.
    (b) Groups findings by partition (stamped unit, else file map, else
        global) and runs ONE batched validator per group with N vote rounds
        each; majority-or-tie per finding is final, no judge call.
    (c) On any error/missing key, keeps status=needs-review (never drops).

    max_workers caps the cell pool. It defaults to the single global
    concurrency knob; pipelined callers (one pool per hunter worker) pass a
    small number so N concurrent workers do not oversubscribe the API N-fold.

    Confirmed false positives are recorded in the threat model's
    "Known false positives" section (threat-update stage), not a database.
    """
    cfg = cfg or {}
    threat_md = threat_md or ""
    n_votes = _resolve_votes(cfg, votes)
    findings = [dict(f) for f in (findings or [])]
    if not findings:
        return []
    gated = _evidence_gate_findings(findings)
    if not gated:
        return []
    # (c) Fail-open when no API key: return gated as-is.
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
    try:
        print(f"[validator] {len(todo)} findings across {len(groups)} partition(s)",
              file=sys.stderr, flush=True)
    except Exception:
        pass

    planned = _plan_validation_groups(groups)
    cell_out = _run_validation_cells(
        planned, _vw, cfg=cfg, n_votes=n_votes, threat_md=threat_md,
        repo=repo)
    return _reassemble_validation(planned, gated, cell_out)
