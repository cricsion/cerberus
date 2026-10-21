from __future__ import annotations

import logging as _logging
from typing import Any as _Any

from .assemble import _merge_plan
from .floor import _bug_shapes, _measured_blocks, bootstrap_threat
from .render import (FPS_HEADING, OBSERVED_HEADING, PROPOSALS_HEADING,
                     _coverage_gaps, _replace_section, _section,
                     validate_threat_md)
from .util import (CACHE_DIRNAME, CACHE_HEADER, FILENAME, _coerce_timeout,
                   _now_iso, _repo_root)

_logger = _logging.getLogger(__name__)


INTERVIEW_QUESTIONS: tuple[tuple[str, str], ...] = (
    ("building", "What are we building? (system context, assets)"),
    ("wrong", "What can go wrong? (top threats, past bug shapes)"),
    ("doing", "What are we doing about it? (existing controls)"),
    ("good_job", "Did we do a good job? (residual risk, threats to park in "
     "section 5 + why)"),
)


def apply_interview(md: str, answers: dict[str, str]) -> str:
    stamp = _now_iso()
    lines = [(md or "").rstrip(), "", f"## Owner notes (interview {stamp})", ""]
    for key, question in INTERVIEW_QUESTIONS:
        ans = (answers.get(key) or "").strip()
        lines += [f"### {question}", "", ans or "_no answer_", ""]
    return "\n".join(lines).rstrip() + "\n"


def _threat_mk(cfg: dict) -> dict:
    from harness.agents.deep import sanitize_model_kwargs
    from harness.config import get_model_kwargs

    return sanitize_model_kwargs(
        get_model_kwargs(cfg or {}, "hunter", agent="threat"))



def _threat_timeout(cfg: dict) -> int:
    from harness.config import get_harness_timeout

    # _threat_mk resolves operator config and raises config-shaped ValueErrors
    # loudly; HARNESS_TIMEOUT is authoritative, with _coerce_timeout keeping
    # the result numeric and at least 1 second.
    return _coerce_timeout(
        get_harness_timeout(_threat_mk(cfg).get("timeout", 60) or 60))


def _llm_structured(cfg: dict, model: Any, system: str, human: str) -> Any:
    from harness.prompts.threat import (SwarmHistory, SwarmPlan,
                                        SwarmResearch)
    agent_names = {SwarmResearch: "threat:researcher",
                   SwarmHistory: "threat:historian",
                   SwarmPlan: "threat:synthesizer"}
    agent_name = agent_names.get(model)
    if agent_name is None:
        raise ValueError("unknown threat-stage schema")

    prefix = "Repository (read-only): "
    first_line = (human or "").splitlines()[0] if human else ""
    if not first_line.startswith(prefix):
        raise ValueError(f"{agent_name} task is missing its repository root")
    root = _repo_root(first_line[len(prefix):])
    if root is None or not root.is_dir():
        raise ValueError("threat-stage repository is not a directory")

    from harness.agents.deep import is_fatal_error, run_structured
    from harness.config import load_config
    from harness.sandbox import close_backend, resolve_backend
    from harness.sandbox.local_backend import RepoLocalBackend
    from deepagents.backends.protocol import SandboxBackendProtocol

    # Same configured backend the Deep Agent factory uses: `execute` only for Docker/sbx, never local.
    try:
        backend = resolve_backend(load_config(), root)
    except Exception as e:
        if is_fatal_error(e):
            raise
        backend = RepoLocalBackend(repo_path=root)

    runtime_note = "No shell tool is available; continue with static analysis."
    if agent_name != "threat:synthesizer" and isinstance(backend, SandboxBackendProtocol):
        network = str(getattr(backend, "network", "unknown")).lower()
        if network == "none":
            egress = (
                "Network egress is disabled, so short, focused local "
                "dynamic checks may run after inspecting their exact command."
            )
        elif network == "balanced":
            egress = (
                "Network egress is policy-restricted; do not run repository "
                "code, scripts, or tests. Use only read-only/static checks."
            )
        else:
            egress = (
                "Network egress is full or unknown; do not run repository "
                "code, scripts, or tests. Use only read-only/static checks."
            )
        runtime_note = (
            "A sandboxed `execute` tool is available. The repository mount is "
            "read-only, with scratch space available for generated output. "
            f"{egress} Never make network requests, install packages, "
            "download code, or send repository data externally."
        )
    system = f"{system}\n\nRUNTIME EXECUTION POSTURE: {runtime_note}"

    try:
        _mk = _threat_mk(cfg or {})
        _retries = int(_mk.get("max_retries", 5))
        if agent_name == "threat:synthesizer":
            from harness.agents.deep import run_structured_batch
            out = run_structured_batch(
                _mk, model, system, [human],
                timeout=_threat_timeout(cfg or {}), max_retries=_retries,
                name=agent_name)
            parsed = out[0] if out else RuntimeError("empty synth batch")
            if isinstance(parsed, BaseException):
                raise parsed
            return parsed
        parsed, _ = run_structured(
            _mk, model, system, human,
            timeout=_threat_timeout(cfg or {}), max_retries=_retries,
            name=agent_name, backend=backend, root_dir=root)
        return parsed
    finally:
        # Closes only this stage's session, not the shared run sandbox.
        close_backend(backend)


def _llm_text(cfg: dict, system: str, human: str,
              root_dir: str | None = None) -> str:
    from harness.agents.deep import run_structured
    from harness.config import get_harness_max_retries

    _, text = run_structured(
        _threat_mk(cfg), None, system, human, timeout=_threat_timeout(cfg),
        max_retries=get_harness_max_retries(1), name="threat",
        root_dir=root_dir)
    return str(text or "")


def _history_text(history: list[tuple[str, str]]) -> str:
    if not history:
        return "(no answers yet)"
    return "\n".join(f"Q: {q}\nA: {a or '_no answer_'}"
                     for q, a in history)


def interview_questions(draft_md: str, history: list[tuple[str, str]],
                        cfg: dict, max_questions: int = 5) -> list | None:
    from harness.agents.deep import run_structured_batch
    from harness.fallback import run_fail_open
    from harness.prompts.threat import (INTERVIEWER_SYSTEM, QuestionList,
                                        build_interview_task)
    human = build_interview_task(draft_md, _history_text(history),
                                 max_questions)

    def _ask() -> list:
        out = run_structured_batch(
            _threat_mk(cfg or {}), QuestionList, INTERVIEWER_SYSTEM, [human],
            timeout=_threat_timeout(cfg or {}), max_retries=1,
            name="threat:interviewer")
        parsed = out[0] if out else RuntimeError("empty interview batch")
        if isinstance(parsed, BaseException):
            raise parsed
        return parsed.questions[:max_questions]

    return run_fail_open("threat:interviewer", _ask, default=None,
                         logger=_logger)


def finalize_threat(draft_md: str, history: list[tuple[str, str]], cfg: dict,
                    root_dir: str | None = None) -> str:
    from harness.prompts.threat import FINALIZE_SYSTEM, build_finalize_task
    text = _llm_text(
        cfg,
        FINALIZE_SYSTEM,
        build_finalize_task(draft_md, _history_text(history)),
        root_dir=root_dir)
    if not text.strip() or "## " not in text or text.count("## ") < 3:
        raise ValueError("thin finalize output")
    return text.strip() + "\n"


def conduct_interview(repo: str, files: list[str], candidates: list[dict],
                      summary: str, cfg: dict, ask, say,
                      max_rounds: int = 3, max_questions: int = 5) -> str:
    # bootstrap_threat is deterministic floor code; a failure here is a harness
    # defect and propagates (the interactive callers own any fallback).
    draft = bootstrap_threat(repo, files, candidates, summary)
    history: list[tuple[str, str]] = []
    for _ in range(max(1, max_rounds)):
        qs = interview_questions(draft, history, cfg or {}, max_questions)
        if qs is None:
            if history:
                break
            qs = [q for _, q in INTERVIEW_QUESTIONS]
        if not qs:
            break
        for q in qs[:max_questions]:
            try:
                say(f"Q: {q}")
            except Exception:
                pass
            try:
                ans = ask(q) or ""
            except Exception:
                ans = ""
            history.append((str(q), str(ans).strip()))
        if len(history) >= max(1, max_rounds) * max(1, max_questions):
            break
    if history:
        try:
            finalized = finalize_threat(draft, history, cfg or {},
                                        root_dir=repo)
            # Only schema-valid output ships; else floor + Q&A appendix.
            if not validate_threat_md(finalized):
                return finalized
        except Exception as e:
            from harness.fallback import is_fatal_error
            if is_fatal_error(e):
                raise
            _logger.debug("threat finalize failed, keeping draft: %s", e)
        appendix = "\n\n".join(f"Q: {q}\nA: {a or '_no answer_'}"
                               for q, a in history)
        return (draft.rstrip()
                + f"\n\n## Owner notes (interview)\n\n{appendix}\n")
    return draft


def _json_default(obj: Any) -> str:
    return str(obj)


def _model_dump(parsed: Any) -> dict:
    if parsed is None:
        return {}
    try:
        if hasattr(parsed, "model_dump"):
            return dict(parsed.model_dump())
        return dict(parsed)
    except TypeError:
        return {}


def _swarm_stage_open(action: str, build) -> tuple[dict, str]:
    """One fail-open for the swarm's LLM stages (research/history/plan): a
    fatal-class error (bad key, wrong model, harness defect) re-raises via
    run_fail_open's is_fatal_error gate; anything else degrades to
    `({}, "failed (error)")` with a debug log. The "failed (" prefix is
    load-bearing: enrich_threat's swarm-unreachable check keys on it."""
    from harness.fallback import run_fail_open

    return run_fail_open(action, build, default=({}, "failed (error)"),
                         logger=_logger)


def _swarm_research(repo: str, files: list[str], draft: str,
                    cfg: dict) -> tuple[dict, str]:
    from harness.prompts.threat import (RESEARCHER_SYSTEM, SwarmResearch,
                                        build_research_task)

    def _build() -> tuple[dict, str]:
        parsed = _llm_structured(cfg or {}, SwarmResearch, RESEARCHER_SYSTEM,
                                 build_research_task(repo, draft, files))
        data = _model_dump(parsed)
        if not data:
            return {}, "failed"
        return data, "ok"

    return _swarm_stage_open("threat researcher", _build)


def _swarm_history(repo: str, draft: str, cfg: dict,
                    vulns: list[dict] | None = None) -> tuple[dict, str]:
    from harness.prompts.threat import (HISTORIAN_SYSTEM, SwarmHistory,
                                        build_historian_task)

    def _build() -> tuple[dict, str]:
        parsed = _llm_structured(cfg or {}, SwarmHistory, HISTORIAN_SYSTEM,
                                 build_historian_task(repo, _bug_shapes(repo),
                                                      draft, vulns))
        data = _model_dump(parsed)
        if not data:
            return {}, "failed"
        return data, "ok"

    return _swarm_stage_open("threat historian", _build)


def _bound_json(data: Any, max_len: int = 12000) -> str:
    import json as _json

    def _truncate_lists(obj: Any, cap: int) -> Any:
        if isinstance(obj, dict):
            return {k: _truncate_lists(v, cap) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_truncate_lists(item, cap) for item in obj[:cap]]
        if isinstance(obj, str) and len(obj) > 2000:
            return obj[:2000] + "... (truncated)"
        return obj

    try:
        for cap in (25, 15, 8, 4, 1):
            bounded = _truncate_lists(data or {}, cap)
            dumped = _json.dumps(bounded, default=_json_default)
            if len(dumped) <= max_len:
                return dumped
        return _json.dumps(_truncate_lists(data or {}, 1), default=_json_default)
    except ValueError:
        return "{}"


def _synth_task(repo, draft, research, history, measured_facts, narrow=False):
    from harness.prompts.threat import build_synth_task

    return build_synth_task(repo, draft or "", research or "", history or "",
                            measured_facts or "", narrow=bool(narrow))


def _swarm_plan(repo: str, draft: str, research: dict, history: dict,
                cfg: dict, measured_facts: str = "",
                narrow: bool = False) -> dict:
    # Planner returns a judgment payload; code renders every deterministic cell — LLM-written markdown never ships (no phrasing slip can corrupt a measured fact).
    from harness.prompts.threat import SYNTH_SYSTEM, SwarmPlan

    def _build() -> tuple[dict, str]:
        parsed = _llm_structured(cfg or {}, SwarmPlan, SYNTH_SYSTEM,
                                 _synth_task(
                                     repo, draft or "",
                                     _bound_json(research or {}, max_len=12000),
                                     _bound_json(history or {}, max_len=12000),
                                     measured_facts or "",
                                     narrow=narrow))
        return _model_dump(parsed), "ok"

    return _swarm_stage_open("threat planner", _build)[0]


def enrich_threat(repo: str, files: list[str], candidates: list[dict],
                  summary: str, draft: str, cfg: dict,
                  vulns: list[dict] | None = None,
                  vulns_path: str = "",
                  measured_facts: str = "") -> tuple[str, dict]:
    meta: dict[str, _Any] = {"agents": {}}
    try:
        research: dict = {}
        history: dict = {}
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = {
                "researcher": ex.submit(_swarm_research, repo, files,
                                        draft or "", cfg or {}),
                "historian": ex.submit(_swarm_history, repo, draft or "",
                                       cfg or {}, vulns),
            }
            for name, fut in futs.items():
                # Stage workers fail open internally (run_fail_open); an
                # escape here is a fatal-class error and must propagate.
                payload, status = fut.result()
                meta["agents"][name] = status
                if status == "ok":
                    if name == "researcher":
                        research = payload
                    else:
                        history = payload
        if not research and not history:
            # Empty context agents are not the swarm being unreachable; skip planning only when no call was possible.
            reachable = any(s.startswith("failed (") is False
                            for s in meta["agents"].values())
            if not reachable:
                meta["error"] = "swarm unreachable"
                return "", meta
        blocks = _measured_blocks(repo, files, candidates, summary or "",
                                  vulns)
        plan = _swarm_plan(repo, draft or "", research, history, cfg or {},
                           measured_facts or blocks.get("context_facts", ""))
        def _judgment(p: dict) -> int:
            return ((1 if p.get("threats") else 0)
                    + (1 if p.get("mitigations") else 0))

        if plan and (not (plan.get("threats") or [])
                     or not (plan.get("mitigations") or [])):
            # Valid-but-hollow payload (no threat rows or no mitigations, i.e. empty §4/§8): retry once with the narrowed brief before accepting.
            base = _judgment(plan)
            retry = _swarm_plan(repo, draft or "", research, history, cfg or {},
                                measured_facts or blocks.get("context_facts", ""),
                                narrow=True)
            if retry and _judgment(retry) > base:
                plan = retry
                meta["judgment_retry"] = "narrowed"
            # A retry that brought LESS judgment never replaces the first payload (already the better of the two).
            if not (plan.get("threats") or []):
                meta["judgment_empty"] = True
            if not (plan.get("mitigations") or []):
                meta["mitigations_empty"] = True
        if not plan:
            meta["error"] = "planner produced no structured payload"
            return "", meta
        md, merge_meta = _merge_plan(repo, blocks, plan, vulns, vulns_path,
                                     draft or "")
        failures = validate_threat_md(md)
        if failures:
            meta["error"] = "; ".join(failures[:3])
            return "", meta
        meta.update(merge_meta)
        meta["coverage_gaps"] = _coverage_gaps(md)
        return md.strip() + "\n", meta
    except Exception as e:
        from harness.fallback import is_fatal_error

        if is_fatal_error(e):
            raise
        _logger.debug("threat enrichment failed: %s", e)
        return "", {"error": f"{type(e).__name__}: {e}"}


def persist_threat(repo: str, md: str) -> str:
    try:
        import os as _os
        body = (md or "").strip()
        if not body:
            return ""
        # Idempotent: never stack a second machine-managed header.
        while body.startswith(CACHE_HEADER):
            body = body[len(CACHE_HEADER):].strip()
        root = _repo_root(repo)
        if root is None:
            return ""
        root_resolved = root.resolve()
        cache_dir = root / CACHE_DIRNAME
        if cache_dir.is_symlink() or (cache_dir.exists() and not cache_dir.resolve().is_relative_to(root_resolved)):
            return ""
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest = cache_dir / FILENAME
        if dest.is_symlink() or (dest.exists() and not dest.resolve().is_relative_to(root_resolved)):
            return ""
        tmp = cache_dir / f"{FILENAME}.tmp.{_os.getpid()}"
        tmp.write_text(CACHE_HEADER + "\n" + body + "\n", encoding="utf-8")
        tmp.replace(dest)
        return str(dest)
    except OSError:
        return ""


def update_threat_with_findings(md: str, findings: list[dict], repo: str = "") -> str:
    items = [f for f in (findings or []) if isinstance(f, dict)]
    claims = [f for f in items
              if not f.get("duplicate_of")
              and f.get("status") == "confirmed"
              and f.get("severity") != "info"
              and f.get("cwe")]
    fps = [f for f in items
           if f.get("status") == "fp" and f.get("cwe")]
    if not claims and not fps:
        return md or ""
    stamp = _now_iso()
    by_cwe: dict[str, int] = {}
    by_path: dict[str, int] = {}
    for f in claims:
        cwe = str(f.get("cwe", "")).strip().upper()
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
        p = str(f.get("path", "") or "").strip()
        if p:
            by_path[p] = by_path.get(p, 0) + 1
    top_cwe = ", ".join(f"{c} x{n}" for c, n in
                        sorted(by_cwe.items(), key=lambda kv: -kv[1])[:15])
    top_paths = ", ".join(f"{p} x{n}" for p, n in
                          sorted(by_path.items(), key=lambda kv: -kv[1])[:15])
    in_model = (_section(md or "", "4. Threats")
                + _section(md or "", "5. Deprioritized")).upper()
    novel = [c for c in sorted(by_cwe) if c and c not in in_model]
    lines = [OBSERVED_HEADING, "",
             f"Last validator-confirmed scan: {stamp} ({repo or 'repo'}).",
             f"Confirmed primary claims: {len(claims)}.", ""]
    if top_cwe:
        lines += [f"By class: {top_cwe}", ""]
    if top_paths:
        lines += [f"Affected paths: {top_paths}", ""]
    out = _replace_section(md or "", "Observed findings",
                           "\n".join(lines).rstrip() + "\n")
    prop_lines = [PROPOSALS_HEADING, "",
                  "Machine-generated candidates from verified findings — "
                  "promote by adding a threat row above; scans never "
                  "apply these themselves.", ""]
    if novel:
        prop_lines += ["Consider adding a threat row for: "
                       + ", ".join(f"{c} x{by_cwe[c]}" for c in novel), ""]
    if novel or fps:
        out = _replace_section(out, "Scope proposals",
                               "\n".join(prop_lines).rstrip() + "\n")
    else:
        out = _replace_section(out, "Scope proposals", "")
    if fps:
        by_fp: dict[str, list[dict]] = {}
        for f in fps:
            by_fp.setdefault(str(f.get("cwe", "")).strip().upper(), []).append(f)
        fp_lines = [FPS_HEADING, "",
                    "Disproven in past scans — do not re-report without new evidence.", ""]
        for cwe in sorted(by_fp, key=lambda c: -len(by_fp[c]))[:15]:
            group = by_fp[cwe]
            ex = group[0]
            why = " ".join(str(ex.get("evidence", "") or "").split())[:200]
            where = ", ".join(sorted({str(f.get("path", "")) for f in group
                                      if f.get("path")})[:5])
            row = f"- {cwe} x{len(group)}"
            if where:
                row += f" at {where}"
            if why:
                row += f" — {why}"
            fp_lines.append(row)
        fp_lines.append("")
        out = _replace_section(out, "Known false positives",
                               "\n".join(fp_lines).rstrip() + "\n")
    else:
        out = _replace_section(out, "Known false positives", "")
    return out
