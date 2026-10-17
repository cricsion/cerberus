from __future__ import annotations

import logging

# Prompt text lives in harness/prompts/discovery.py (re-exported for `h.<name>`).
from harness.agents.deep import is_fatal_error, sanitize_model_kwargs
from harness.fallback import EMPTY_STRUCTURED, run_fail_open
from harness.schemas import safe_float, safe_int
from harness.prompts.discovery import (DiscoveryResult, SYSTEM_PASS_SYSTEM,
                                       build_discovery_task,
                                       build_unit_system_prompt,
                                       build_system_pass_task,
                                       sandbox_system_section)

_logger = logging.getLogger(__name__)

try:
    from harness import observability as _obs
except Exception:  # observability module unavailable → tracing disabled (fail-open)
    _obs = None

def focus_hint(focus: list[str] | str | None) -> str:
    if isinstance(focus, str):
        focus = [f.strip() for f in focus.split(",")]
    fs = [str(f).strip() for f in (focus or []) if str(f).strip()]
    return "; ".join(fs)


def _norm_refs(raw) -> list:
    out: list = []
    try:
        for r in (raw or [])[:50]:
            if not isinstance(r, dict):
                continue
            out.append({"file": str(r.get("file") or ""),
                        "line": max(0, safe_int(r.get("line"))),
                        "note": str(r.get("note") or "")[:2000]})
    except Exception:
        return []
    return out


def _normalize_finding(raw: dict, hunter: str, idx: int, fallback_path: str = "") -> dict:
    d = dict(raw or {})
    taint = d.get("taint") or {}
    if not isinstance(taint, dict):
        taint = {"source": str(taint), "sink": "", "path": []}
    tpath = taint.get("path") or []
    if not isinstance(tpath, list):
        tpath = [str(tpath)]
    out = {
        "id": str(d.get("id") or f"{hunter}-{idx}"),
        "title": str(d.get("title") or f"{hunter} suspicious pattern"),
        "cwe": str(d.get("cwe") or ""),
        "severity": str(d.get("severity") or "medium"),
        "confidence": d.get("confidence", 0.3),
        "path": str(d.get("path") or fallback_path or ""),
        "start_line": safe_int(d.get("start_line")),
        "end_line": safe_int(d.get("end_line"), safe_int(d.get("start_line"))),
        "snippet": str(d.get("snippet") or d.get("evidence") or "")[:4000],
        "taint": {
            "source": str(taint.get("source") or ""),
            "sink": str(taint.get("sink") or ""),
            "path": [str(x) for x in tpath][:20],
        },
        "refs": _norm_refs(d.get("refs")),
        "evidence": str(d.get("evidence") or d.get("snippet") or f"{hunter} hunter")[:4000],
        "rationale": str(d.get("rationale") or "")[:2000],
        "status": "needs-review",
    }
    try:
        out["confidence"] = float(out["confidence"])
    except (TypeError, ValueError):
        out["confidence"] = 0.3
    out["confidence"] = max(0.0, min(1.0, out["confidence"]))
    if out["severity"] not in ("critical", "high", "medium", "low", "info"):
        out["severity"] = "medium"
    # path/evidence need no repair: fallback_path and the `or` defaults above keep them non-empty.
    if not out["snippet"]:
        out["snippet"] = out["evidence"][:4000] or f"{hunter} needs review"
    return out


def _fallback_finding(hunter: str, repo: str, files: list, reason: str) -> dict:
    path = (files[0] if files else repo) or repo or "."
    return {
        "id": f"{hunter}-fallback",
        "title": f"{hunter}: manual review needed",
        "cwe": "",
        "severity": "info",
        "confidence": 0.0,
        "path": str(path),
        "start_line": 0,
        "end_line": 0,
        "snippet": f"LLM hunter '{hunter}' unavailable: {reason[:500]}",
        "taint": {"source": "", "sink": "", "path": []},
        "evidence": f"{hunter} fail-open: {reason[:1000]}",
        "status": "needs-review",
    }


def _cand_ctx(candidates: list[dict], cfg: dict | None = None,
              threat_md: str = "") -> str:
    real_cands = [c for c in (candidates or [])
                  if isinstance(c, dict) and c.get("id") != "prefilter" and c.get("severity") != "info"]
    slim = _slim_candidates(real_cands) if real_cands else ""
    # The threat model reaches the task via build_discovery_task's labeled section.
    return f"[CANDIDATES]\n{slim}" if slim else ""


def _slim_candidates(candidates: list[dict]) -> str:
    import json as _json

    slim = [{"id": c.get("id"), "title": c.get("title"), "cwe": c.get("cwe"),
             "severity": c.get("severity"), "path": c.get("path"),
             "start_line": c.get("start_line"), "end_line": c.get("end_line")}
            for c in (candidates or []) if isinstance(c, dict)]
    return _json.dumps(slim, default=str)


def _findings_from_discovery(parsed: object, hunter: str,
                               files: list[str], repo: str) -> list[dict]:
    try:
        items = getattr(parsed, "findings", None) or []
        norm = []
        for i, it in enumerate(items):
            d = it.model_dump() if hasattr(it, "model_dump") else dict(it)
            norm.append(_normalize_finding(d, hunter, i, files[0] if files else repo))
        return norm
    except Exception:
        return []


def _extract_agent_text(result) -> str:
    from harness.agents.deep import final_text

    return final_text(result, sep="\n")


def _agent_tools_used(result) -> list[str]:
    used: list[str] = []
    try:
        msgs = result.get("messages", []) if isinstance(result, dict) else []
        for m in msgs:
            for tc in (getattr(m, "tool_calls", None) or []):
                name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "")
                if name and name not in used:
                    used.append(str(name))
            if getattr(m, "type", "") == "tool":
                name = getattr(m, "name", "") or ""
                if name and name not in used:
                    used.append(str(name))
    except Exception:
        pass
    return used


def _parse_findings_json(text: str, hunter: str, files: list[str], repo: str) -> list[dict]:
    norm, _ok = _parse_findings_with_status(text, hunter, files, repo)
    return norm


def _parse_findings_with_status(text: str, hunter: str, files: list[str], repo: str) -> tuple[list[dict], bool]:
    import json as _json
    import re as _re

    if not text or not text.strip():
        return [], False
    parsed = None
    for candidate in (text.strip(), *(_re.findall(r"```(?:json)?\s*(.+?)\s*```",
                                                text, _re.DOTALL) or [])):
        try:
            parsed = _json.loads(candidate)
            break
        except Exception:
            continue
    if isinstance(parsed, dict):
        parsed = parsed.get("findings")
    if parsed is None:
        from harness.llmjson import extract_json_array
        arr = extract_json_array(text)
        if arr is None:
            return [], False
        parsed = arr
    if not isinstance(parsed, list):
        return [], False
    norm = []
    for i, it in enumerate(parsed):
        if isinstance(it, dict):
            norm.append(_normalize_finding(it, hunter, i, files[0] if files else repo))
    return norm, True


def build_unit_hunter_agent(unit_name: str, model_kwargs: dict,
                            focus: list[str] | str | None = None,
                            repo: str = ".", backend=None):
    from harness.agents.deep import build_deep_agent, make_llm
    from harness.agents.toolsets import graph_tools

    mk = sanitize_model_kwargs(model_kwargs)
    try:
        _timeout = max(int(mk.get("timeout", 180) or 180), 180)
    except (TypeError, ValueError):
        _timeout = 180
    llm = make_llm(mk, timeout=_timeout)
    prompt = build_unit_system_prompt(focus_hint(focus), backend=backend)
    tools = graph_tools()
    return build_deep_agent(llm, system_prompt=prompt, tools=tools,
                            response_format=DiscoveryResult,
                            name=f"hunter-{unit_name}"[:60],
                            root_dir=repo, backend=backend)


def _run_unit(unit: dict, repo: str, files: list[str], candidates: list[dict],
              cfg: dict, threat_md: str = "",
              focus: list[str] | str | None = None,
              _tools_out: list | None = None) -> list[dict]:
    from harness.config import get_model_kwargs

    name = str(unit.get("name", "unit"))
    model_kwargs = get_model_kwargs(cfg, "hunter")
    cand_ctx = _cand_ctx(candidates, cfg)
    task = build_discovery_task(name, repo, files or [], cand_ctx, threat_md,
                                focus=focus_hint(focus))
    from harness.sandbox import close_backend, resolve_backend
    # One backend per unit: local = no shell; docker/sbx = shared-container shell. Fail-soft.
    import uuid
    backend = run_fail_open(
        f"backend unit-{name}",
        lambda: resolve_backend(cfg, repo,
                                agent_id=f"unit-{name[:36]}_{uuid.uuid4().hex[:6]}"),
        default=None, logger=_logger)
    if backend is None:
        print(f"[hunters] {name}: no sandbox backend; "
              "falling back to the builder default")
    # Parse the recursion limit outside the agent try: a bad cfg value is a
    # config parse failure, not a unit hunt failure.
    try:
        rec_lim = int(cfg.get("hunter_recursion_limit", 1000) or 1000)
    except (TypeError, ValueError):
        rec_lim = 1000
    try:
        agent = build_unit_hunter_agent(name, model_kwargs, focus, repo=repo,
                                        backend=backend)
        invoke_config = {"recursion_limit": rec_lim}
        if _obs is not None:
            _handler = _obs.get_handler()
            _cbs = list(getattr(agent, "_visibility_callbacks", []) or [])
            if _handler is not None and _cbs:
                invoke_config["callbacks"] = _cbs
                _meta = _obs.scan_metadata(stage="hunters", role="hunter", unit=name)
                if _meta:
                    invoke_config["metadata"] = _meta
                    _scope = _obs.scope_path(name)
                    invoke_config["run_name"] = (
                        f"hunter:{_scope}" if _scope else "hunter")
        res = agent.invoke({"messages": [{"role": "user", "content": task}]},
                           config=invoke_config)
        if _tools_out is not None:
            _tools_out.extend(_agent_tools_used(res))
        sr = res.get("structured_response") if isinstance(res, dict) else None
        if sr is not None and hasattr(sr, "findings"):
            norm = _findings_from_discovery(sr, f"unit-{name}", files or [], repo)
            return sorted(norm, key=lambda f: -safe_float(f.get("confidence", 0)))
        text = _extract_agent_text(res)
        norm, ok = _parse_findings_with_status(text, f"unit-{name}", files or [], repo)
        if ok:
            return sorted(norm, key=lambda f: -safe_float(f.get("confidence", 0)))
    except Exception as e:
        # Config-class failures must fail the scan loudly, not degrade to a fallback.
        if is_fatal_error(e):
            raise
        print(f"[hunters] {name} error: {type(e).__name__}: {e}")
        return [_fallback_finding(f"unit-{name}", repo, files,
                                  f"unit hunt produced no parseable findings "
                                  f"({type(e).__name__})")]
    finally:
        # End this agent's sandbox session; the run container is torn down at scan teardown.
        if backend is not None:
            close_backend(backend)
    return [_fallback_finding(f"unit-{name}", repo, files,
                              "unparseable reply")]


def _run_system_pass(repo: str, files: list[str], findings: list[dict],
                     threat_md: str, cfg: dict,
                     focus: list[str] | str | None = None,
                     _tools_out: list | None = None) -> list[dict]:
    from harness.config import get_model_kwargs
    from harness.agents.toolsets import graph_tools
    from harness.sandbox import close_backend, resolve_backend

    findings = [f for f in (findings or []) if isinstance(f, dict)]
    model_kwargs = get_model_kwargs(cfg, "hunter")
    mk = sanitize_model_kwargs(model_kwargs)
    try:
        _timeout = max(int(mk.get("timeout", 180) or 180), 180)
    except (TypeError, ValueError):
        _timeout = 180
    # Same agent posture as a unit hunter: graph tools bound explicitly, an
    # explicitly resolved backend (sandbox shell + skills when supported) and
    # the sandbox scan-surface section folded into the system prompt.
    import uuid
    backend = run_fail_open(
        "backend system-pass",
        lambda: resolve_backend(cfg, repo,
                                agent_id=f"system-pass_{uuid.uuid4().hex[:6]}"),
        default=None, logger=_logger)
    if backend is None:
        print("[system-pass] no sandbox backend; "
              "falling back to the builder default")
    sys_prompt = SYSTEM_PASS_SYSTEM + sandbox_system_section(backend)
    import json as _json
    signals = []
    for finding in findings[:200]:
        taint = finding.get("taint")
        if isinstance(taint, dict):
            trace = taint.get("path")
            if not isinstance(trace, list):
                trace = []
            taint = {
                "source": str(taint.get("source", ""))[:300],
                "sink": str(taint.get("sink", ""))[:300],
                "path": [str(p)[:300] for p in trace[:12]],
            }
        signals.append({
            "id": finding.get("id"),
            "title": str(finding.get("title", ""))[:300],
            "cwe": finding.get("cwe"),
            "path": finding.get("path"),
            "start_line": finding.get("start_line"),
            "end_line": finding.get("end_line"),
            "rationale": str(finding.get("rationale", ""))[:800],
            "evidence": str(finding.get("evidence", ""))[:800],
            "taint": taint,
        })
    slim = _json.dumps(signals, default=str)
    scope = focus_hint(focus) or "ALL vulnerability classes in scope"
    ctx = (("[THREAT MODEL]\n" + threat_md.strip() + "\n\n") if (threat_md or "").strip()
           else "") + f"[UNIT FINDINGS]\n{slim}"
    from harness.agents.deep import run_structured
    msg = build_system_pass_task(repo, scope, ctx, files)
    try:
        parsed, raw_text = run_fail_open(
            "system pass",
            lambda: run_structured(
                mk, DiscoveryResult, sys_prompt, msg,
                tools=graph_tools(), timeout=_timeout,
                name="system-pass", backend=backend, root_dir=repo),
            default=EMPTY_STRUCTURED, logger=_logger)
    finally:
        # End this agent's sandbox session; the run container is torn down at scan teardown.
        if backend is not None:
            close_backend(backend)
    if _tools_out is not None:
        _tools_out.append("deep-agent")
    norm = _findings_from_discovery(parsed, "system", files or [], repo)
    if not norm and raw_text.strip():
        norm = _parse_findings_json(raw_text, "system", files or [], repo)
    seen = {(str(f.get("path", "")).lower(),
            str(f.get("cwe", "")).upper(),
            safe_int(f.get("start_line", 0))) for f in findings}
    fresh = [f for f in norm
             if (str(f.get("path", "")).lower(),
                 str(f.get("cwe", "")).upper(),
                 safe_int(f.get("start_line", 0))) not in seen]
    return sorted(fresh, key=lambda f: -safe_float(f.get("confidence", 0)))
