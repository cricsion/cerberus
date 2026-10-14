"""Unit hunters: one per logical unit, all vulnerability classes (recall)."""
from __future__ import annotations

# Prompt text lives in harness/prompts/discovery.py; re-exported here so
# existing `h.<name>` imports keep working.
from harness.agents.deep import is_fatal_error, sanitize_model_kwargs
from harness.schemas import safe_float, safe_int
from harness.prompts.discovery import (DiscoveryResult, SYSTEM_PASS_SYSTEM,
                                       UNIT_SYSTEM,
                                       build_discovery_task,
                                       build_unit_system_prompt,
                                       build_system_pass_task)

# No per-class hunting instructions: prompts carry goal + context, not a
# scanning playbook. Class scope comes from the threat model and --focus.
def focus_hint(focus: list[str] | str | None) -> str:
    """User --focus hint for prompts, passed through verbatim.

    A bare class name or CWE is not expanded into instructions.
    """
    if isinstance(focus, str):
        focus = [f.strip() for f in focus.split(",")]
    fs = [str(f).strip() for f in (focus or []) if str(f).strip()]
    return "; ".join(fs)


def _normalize_finding(raw: dict, hunter: str, idx: int, fallback_path: str = "") -> dict:
    """Coerce one finding to the required schema; fail-open to needs-review."""
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
    # path/evidence need no post-normalization repair: line 48 already falls
    # back to fallback_path (a str, so empty only when it is itself empty),
    # and line 57's `or f"{hunter} hunter"` keeps evidence non-empty.
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
    """Prompt candidate context: FULL threat model + slim coverage signals.
    Excludes prefilter info candidates so hunters are not anchored to regex hits.
    """
    real_cands = [c for c in (candidates or [])
                  if isinstance(c, dict) and c.get("id") != "prefilter" and c.get("severity") != "info"]
    slim = _slim_candidates(real_cands) if real_cands else ""
    # The threat model reaches the task through build_discovery_task's
    # labeled section; embedding it here too doubled the document into every
    # unit prompt (cost x N units, and it landed under a "Prefilter signals"
    # label that mis-framed §4 as confirmed sink sites).
    return f"[CANDIDATES]\n{slim}" if slim else ""


def _slim_candidates(candidates: list[dict]) -> str:
    """Full coverage signals for prompts: every candidate's id/title/cwe/
    severity/path/lines, WITHOUT bulk snippet text (agents fetch detail
    with read_file/grep on demand). Nothing is hidden, prompts stay sane.
    """
    import json as _json

    slim = [{"id": c.get("id"), "title": c.get("title"), "cwe": c.get("cwe"),
             "severity": c.get("severity"), "path": c.get("path"),
             "start_line": c.get("start_line"), "end_line": c.get("end_line")}
            for c in (candidates or []) if isinstance(c, dict)]
    try:
        return _json.dumps(slim, default=str)
    except Exception:
        return str(slim)


def _findings_from_discovery(parsed: object, hunter: str,
                               files: list[str], repo: str) -> list[dict]:
    """Structured DiscoveryResult -> normalized findings; [] when empty."""
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
    """Pull the final AI message text from a create_agent invoke result.

    Same extraction as ``run_structured``'s ``final_text`` — backwards scan,
    skip tool results — with the discovery agents' multi-block separator.
    """
    from harness.agents.deep import final_text

    return final_text(result, sep="\n")


def _agent_tools_used(result) -> list[str]:
    """Tool names actually invoked during a ReAct run (for scan_meta tools_used).

    Reads tool calls off AI messages + tool results. Never raises.
    """
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
    """Best-effort parse of an agent's final message; [] if unparseable."""
    norm, _ok = _parse_findings_with_status(text, hunter, files, repo)
    return norm


def _parse_findings_with_status(text: str, hunter: str, files: list[str], repo: str) -> tuple[list[dict], bool]:
    """Parse agent message; returns (findings, success_flag).

    success_flag distinguishes ""unparseable"" (a fail-open fallback finding
    is warranted) from a valid empty answer (the hunter reviewed and found
    nothing).

    Accepts the findings object ("findings": [...]) as well as a bare array,
    with or without surrounding prose. The object is tried whole first; if
    prose surrounds it, the array fallback extracts the findings payload.
    """
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
    """Lazy import so pytest/--help work without API keys/network.

    The hunter runs on deepagents against a backend resolved per unit
    (``sandbox.backend``). The SAST surface is backend-dependent: a sandbox
    backend (docker/sbx) satisfies ``SandboxBackendProtocol``, so
    ``harness.agents.deep`` materializes ``execute`` — a shell inside the
    scan container — and the agent runs the preinstalled semgrep/opengrep
    binaries directly (the prompt names them and the offline rules dir).
    The capped wrappers are deliberately NOT offered there: they would be a
    third, weaker scan path competing with the shell. Without a sandbox
    (local backend) there is no shell at all, so the wrappers are the only
    scanner surface and stay. Common to both: the built-in filesystem tools
    (read_file, grep, glob, ls) plus our code-graph / AST tools. No
    subagent recursion by construction (the shared factory's HarnessProfile
    disables ``task``).
    """
    from harness.agents.deep import build_deep_agent, make_llm
    from harness.agents.deep import _fallback_models
    from harness.agents.toolsets import code_intel_tools

    mk = sanitize_model_kwargs(model_kwargs)
    try:
        _timeout = max(int(mk.get("timeout", 180) or 180), 180)
    except (TypeError, ValueError):
        _timeout = 180
    llm = make_llm(mk, timeout=_timeout)
    # Configured provider-outage fallbacks (docs: ModelFallbackMiddleware):
    # same base_url/api_key as the primary, only the model id differs.
    fallbacks = _fallback_models(mk, timeout=_timeout, max_retries=None,
                                 reasoning=True)
    prompt = build_unit_system_prompt(focus_hint(focus), backend=backend)
    # Shared surface (harness.agents.toolsets): the exact list validators also
    # get, so the two roles cannot drift. Backend-dependent SAST wrappers live
    # there (omitted when a sandbox shell is present).
    tools = code_intel_tools(backend)
    return build_deep_agent(llm, system_prompt=prompt, tools=tools,
                            response_format=DiscoveryResult,
                            name=f"hunter-{unit_name}"[:60],
                            root_dir=repo, backend=backend,
                            fallbacks=fallbacks)


def _run_unit(unit: dict, repo: str, files: list[str], candidates: list[dict],
              cfg: dict, threat_md: str = "",
              focus: list[str] | str | None = None,
              _tools_out: list | None = None) -> list[dict]:
    """Hunt ALL classes inside one logical unit with a deep agent.

    `files` is the unit's file list (partitioned upstream). Fail-open, no caps:
    an agent error or an unparseable reply yields one needs-review fallback.
    """
    from harness.config import get_model_kwargs

    name = str(unit.get("name", "unit"))
    model_kwargs = get_model_kwargs(cfg, "hunter")
    cand_ctx = _cand_ctx(candidates, cfg)
    task = build_discovery_task(name, repo, files or [], cand_ctx, threat_md,
                                focus=focus_hint(focus))
    from harness.sandbox import close_backend, resolve_backend
    # One backend per unit (config sandbox.backend): local = repo-confined,
    # no shell; docker/sbx = shell inside the run's shared container, egress
    # posture per sandbox.network (bridge = full egress, NOT network-less by
    # default). All agents share the runtime and receive agent-specific
    # scratch paths, not separate filesystem permissions.
    # Fail-soft: a backend that cannot be built degrades to the builder's
    # own validation error (a fallback finding), never a killed scan.
    try:
        import uuid
        backend = resolve_backend(cfg, repo, agent_id=f"unit-{name[:36]}_{uuid.uuid4().hex[:6]}")
    except Exception as e:
        backend = None
        print(f"[hunters] {name}: no sandbox backend ({type(e).__name__}: {e}); "
              "falling back to the builder default")
    try:
        agent = build_unit_hunter_agent(name, model_kwargs, focus, repo=repo,
                                        backend=backend)
        rec_lim = int(cfg.get("hunter_recursion_limit", 1000) or 1000)
        res = agent.invoke({"messages": [{"role": "user", "content": task}]},
                           config={"recursion_limit": rec_lim})
        if _tools_out is not None:
            _tools_out.extend(_agent_tools_used(res))
        # response_format carries a validated structured_response; fall back
        # to parsing the final message when the backend ignored the schema.
        sr = res.get("structured_response") if isinstance(res, dict) else None
        if sr is not None and hasattr(sr, "findings"):
            norm = _findings_from_discovery(sr, f"unit-{name}", files or [], repo)
            return sorted(norm, key=lambda f: -safe_float(f.get("confidence", 0)))
        text = _extract_agent_text(res)
        norm, ok = _parse_findings_with_status(text, f"unit-{name}", files or [], repo)
        if ok:
            return sorted(norm, key=lambda f: -safe_float(f.get("confidence", 0)))
    except Exception as e:
        # Provider config-class failures (bad key, wrong model) must fail the
        # scan loudly, not silently degrade into a fallback finding.
        if is_fatal_error(e):
            raise
        # Name the failure mode: a recursion/loop cutoff is infra, not "clean".
        print(f"[hunters] {name} error: {type(e).__name__}: {e}")
        return [_fallback_finding(f"unit-{name}", repo, files,
                                  f"unit hunt produced no parseable findings "
                                  f"({type(e).__name__})")]
    finally:
        # End this agent's sandbox session. The shared run container itself
        # is removed by shutdown_run_sandbox() at scan teardown.
        if backend is not None:
            close_backend(backend)
    return [_fallback_finding(f"unit-{name}", repo, files,
                              "unparseable reply")]


def _run_system_pass(repo: str, files: list[str], findings: list[dict],
                     threat_md: str, cfg: dict,
                     focus: list[str] | str | None = None,
                     _tools_out: list | None = None) -> list[dict]:
    """System-level pass: cross-unit chains + missed global issues ONLY.

    One source-reading deep-agent run guided by the repository inventory,
    threat model, and any merged per-unit evidence. It runs when unit findings
    are empty too. Unit findings are preserved downstream regardless; this only
    ADDS cross-unit or global findings. Fail-open [] (never a fallback finding
    — silence here is not a claim).
    """
    from harness.config import get_model_kwargs

    findings = [f for f in (findings or []) if isinstance(f, dict)]
    model_kwargs = get_model_kwargs(cfg, "hunter")
    mk = sanitize_model_kwargs(model_kwargs)
    try:
        try:
            _timeout = max(int(mk.get("timeout", 180) or 180), 180)
        except (TypeError, ValueError):
            _timeout = 180
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
            parsed, raw_text, _ = run_structured(
                mk, DiscoveryResult, SYSTEM_PASS_SYSTEM, msg,
                timeout=_timeout, max_retries=1, name="system-pass",
                root_dir=repo)
        except Exception as e:
            if is_fatal_error(e):
                raise
            parsed, raw_text = None, ""
        if _tools_out is not None:
            _tools_out.append("deep-agent")
        norm = _findings_from_discovery(parsed, "system", files or [], repo)
        if not norm and raw_text.strip():
            norm = _parse_findings_json(raw_text, "system", files or [], repo)
        # Drop repeats of unit findings (same path+CWE+line already claimed).
        # Every item here is a dict (isinstance filter above): dict.get with
        # a literal key, str()/upper()/lower() on the result, and safe_int
        # (total) all cannot raise, and (str, str, int) is always hashable.
        # The same key tuple is built unguarded in the `fresh` filter below.
        seen = {(str(f.get("path", "")).lower(),
                str(f.get("cwe", "")).upper(),
                safe_int(f.get("start_line", 0))) for f in findings}
        fresh = [f for f in norm
                 if (str(f.get("path", "")).lower(),
                     str(f.get("cwe", "")).upper(),
                     safe_int(f.get("start_line", 0))) not in seen]
        return sorted(fresh, key=lambda f: -safe_float(f.get("confidence", 0)))
    except Exception as e:
        if is_fatal_error(e):
            raise
        return []
