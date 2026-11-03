from __future__ import annotations

import logging as _logging
from typing import Any

from .assemble import _merge_plan
from .floor import _bug_shapes, _measured_blocks, bootstrap_threat
from .render import (
    FPS_HEADING,
    OBSERVED_HEADING,
    PROPOSALS_HEADING,
    THREAT_COLUMNS,
    _cell,
    _coverage_gaps,
    _parse_threats,
    _replace_section,
    _section,
    validate_threat_md,
)
from .util import CACHE_DIRNAME, CACHE_HEADER, FILENAME, _now_iso, _repo_root

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
    from cerberus.agents.deep import sanitize_model_kwargs
    from cerberus.config import get_model_kwargs

    return sanitize_model_kwargs(
        get_model_kwargs(cfg or {}, "hunter", agent="threat"))


def _llm_structured(cfg: dict, model: Any, system: str, human: str) -> Any:
    from cerberus.prompts.threat import SwarmHistory, SwarmPlan, SwarmResearch
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

    from deepagents.backends.protocol import SandboxBackendProtocol

    from cerberus.agents.deep import run_structured
    from cerberus.config import effective_config
    from cerberus.sandbox import _acquire_backend, close_backend

    cfg = effective_config(cfg)
    backend = None
    if agent_name != "threat:synthesizer":
        # A refused sandbox falls back to the repo-confined local backend.
        backend = _acquire_backend(cfg, root, label=agent_name,
                                   fallback="local")

    runtime_note = "No shell tool is available; continue with static analysis."
    if isinstance(backend, SandboxBackendProtocol):
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
        _mk = _threat_mk(cfg)
        _timeout = int(cfg["timeout"])
        _retries = int(cfg["max_retries"])
        if agent_name == "threat:synthesizer":
            from cerberus.agents.deep import run_structured_batch
            out = run_structured_batch(
                _mk, model, system, [human],
                timeout=_timeout, max_retries=_retries,
                name=agent_name)
            parsed = out[0] if out else RuntimeError("empty synth batch")
            if isinstance(parsed, BaseException):
                raise parsed
            return parsed
        parsed, _ = run_structured(
            _mk, model, system, human,
            timeout=_timeout, max_retries=_retries,
            name=agent_name, backend=backend, root_dir=root)
        return parsed
    finally:
        # Closes only this stage's session, not the shared run sandbox.
        close_backend(backend)


def _llm_text(cfg: dict, system: str, human: str,
              root_dir: str | None = None) -> str:
    from cerberus.agents.deep import run_structured
    from cerberus.config import effective_config
    from cerberus.sandbox import _acquire_backend, close_backend

    cfg = effective_config(cfg)
    _mk = _threat_mk(cfg)
    backend = None
    if root_dir:
        backend = _acquire_backend(cfg, root_dir, label="threat",
                                   fallback="local")
    try:
        _, text = run_structured(
            _mk, None, system, human, timeout=int(cfg["timeout"]),
            max_retries=int(cfg["max_retries"]), name="threat",
            backend=backend, root_dir=root_dir)
    finally:
        close_backend(backend)
    return str(text or "")


def _history_text(history: list[tuple[str, str]]) -> str:
    if not history:
        return "(no answers yet)"
    return "\n".join(f"Q: {q}\nA: {a or '_no answer_'}"
                     for q, a in history)


def interview_questions(draft_md: str, history: list[tuple[str, str]],
                        cfg: dict, max_questions: int = 5) -> list | None:
    from cerberus.agents.deep import run_structured_batch
    from cerberus.fallback import runner
    from cerberus.prompts.threat import INTERVIEWER_SYSTEM, QuestionList, build_interview_task
    human = build_interview_task(draft_md, _history_text(history),
                                 max_questions)

    def _ask() -> list:
        from cerberus.config import effective_config

        cfg_full = effective_config(cfg or {})
        _mk = _threat_mk(cfg_full)
        out = run_structured_batch(
            _mk, QuestionList, INTERVIEWER_SYSTEM, [human],
            timeout=int(cfg_full["timeout"]),
            max_retries=int(cfg_full["max_retries"]),
            name="threat:interviewer")
        parsed = out[0] if out else RuntimeError("empty interview batch")
        if isinstance(parsed, BaseException):
            raise parsed
        return parsed.questions[:max_questions]

    return runner("threat:interviewer", _ask, default=None,
                  logger=_logger)


def finalize_threat(draft_md: str, history: list[tuple[str, str]], cfg: dict,
                    root_dir: str | None = None) -> str:
    from cerberus.prompts.threat import FINALIZE_SYSTEM, build_finalize_task
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
            from cerberus.fallback import is_fatal_error
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


def _swarm_research(repo: str, files: list[str], draft: str,
                    cfg: dict) -> tuple[dict, str]:
    from cerberus.fallback import runner
    from cerberus.prompts.threat import RESEARCHER_SYSTEM, SwarmResearch, build_research_task

    def _build() -> tuple[dict, str]:
        parsed = _llm_structured(cfg or {}, SwarmResearch, RESEARCHER_SYSTEM,
                                 build_research_task(repo, draft, files))
        data = _model_dump(parsed)
        if not data:
            return {}, "failed"
        return data, "ok"

    return runner("threat researcher", _build,
                  default=({}, "failed (error)"), logger=_logger)


def _swarm_history(repo: str, draft: str, cfg: dict,
                    vulns: list[dict] | None = None) -> tuple[dict, str]:
    from cerberus.fallback import runner
    from cerberus.prompts.threat import HISTORIAN_SYSTEM, SwarmHistory, build_historian_task

    def _build() -> tuple[dict, str]:
        parsed = _llm_structured(cfg or {}, SwarmHistory, HISTORIAN_SYSTEM,
                                 build_historian_task(repo, _bug_shapes(repo),
                                                      draft, vulns))
        data = _model_dump(parsed)
        if not data:
            return {}, "failed"
        return data, "ok"

    return runner("threat historian", _build,
                  default=({}, "failed (error)"), logger=_logger)


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
    from cerberus.prompts.threat import build_synth_task

    return build_synth_task(repo, draft or "", research or "", history or "",
                            measured_facts or "", narrow=bool(narrow))


def _swarm_plan(repo: str, draft: str, research: dict, history: dict,
                cfg: dict, measured_facts: str = "",
                narrow: bool = False) -> dict:
    # Planner returns a judgment payload; code renders every deterministic cell — LLM-written markdown never ships (no phrasing slip can corrupt a measured fact).
    from cerberus.fallback import runner
    from cerberus.prompts.threat import SYNTH_SYSTEM, SwarmPlan

    def _build() -> tuple[dict, str]:
        parsed = _llm_structured(cfg or {}, SwarmPlan, SYNTH_SYSTEM,
                                 _synth_task(
                                     repo, draft or "",
                                     _bound_json(research or {}, max_len=12000),
                                     _bound_json(history or {}, max_len=12000),
                                     measured_facts or "",
                                     narrow=narrow))
        return _model_dump(parsed), "ok"

    return runner("threat planner", _build,
                  default=({}, "failed (error)"), logger=_logger)[0]


def enrich_threat(repo: str, files: list[str], candidates: list[dict],
                  summary: str, draft: str, cfg: dict,
                  vulns: list[dict] | None = None,
                  vulns_path: str = "",
                  measured_facts: str = "") -> tuple[str, dict]:
    meta: dict[str, Any] = {"agents": {}}
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
        from cerberus.fallback import is_fatal_error

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


_CWE_THREAT_KEYWORDS: dict[str, list[str]] = {
    "CWE-915": ["mass assignment", "parameter binding", "object injection", "parameter tampering"],
    "CWE-347": ["jwt", "token", "signature", "none algorithm", "algorithm confusion", "token validation"],
    "CWE-287": ["authentication", "auth bypass", "credential", "login bypass", "identity"],
    "CWE-384": ["session fixation", "session hijacking", "session"],
    "CWE-613": ["insufficient session expiration", "session timeout", "session"],
    "CWE-89": ["sql injection", "sqli", "sql query", "database injection", "raw query"],
    "CWE-78": ["command injection", "os command", "shell command", "remote code execution", "rce", "exec"],
    "CWE-79": ["cross-site scripting", "xss", "script injection", "html injection"],
    "CWE-94": ["code injection", "eval", "dynamic execution", "rce"],
    "CWE-22": ["path traversal", "directory traversal", "arbitrary file", "lfi", "file read"],
    "CWE-23": ["path traversal", "relative path"],
    "CWE-918": ["ssrf", "server-side request forgery", "request forgery", "out-of-band"],
    "CWE-601": ["open redirect", "url redirect", "redirection", "phishing"],
    "CWE-117": ["log injection", "improper output neutralization for logs", "log forging", "crlf log"],
    "CWE-90": ["ldap injection", "ldap query", "directory injection"],
    "CWE-502": ["deserialization", "untrusted deserialization", "object deserialization", "pickle"],
    "CWE-352": ["csrf", "cross-site request forgery", "request forgery"],
    "CWE-862": ["missing authorization", "authorization bypass", "access control"],
    "CWE-863": ["incorrect authorization", "privilege escalation", "access control"],
    "CWE-639": ["idor", "insecure direct object", "authorization"],
    "CWE-776": ["xxe", "xml external entity", "xml entity"],
    "CWE-611": ["xxe", "xml external entity"],
    "CWE-200": ["information disclosure", "sensitive data", "data exposure", "leak"],
}

_CWE_CANONICAL_THREATS: dict[str, str] = {
    "CWE-915": "Privilege escalation or unauthorized state tampering via mass assignment",
    "CWE-347": "Authentication bypass via unverified JWT signatures or 'none' algorithm acceptance",
    "CWE-287": "Authentication bypass via flawed credential or identity validation",
    "CWE-89": "Database compromise and sensitive data exfiltration via SQL injection",
    "CWE-78": "Remote code execution via untrusted operating system command injection",
    "CWE-79": "Client-side session hijacking or defacement via cross-site scripting (XSS)",
    "CWE-94": "Arbitrary code execution via dynamic code evaluation",
    "CWE-22": "Arbitrary file disclosure or tampering via path traversal",
    "CWE-918": "Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF)",
    "CWE-601": "Phishing or credential theft via unvalidated open URL redirection",
    "CWE-117": "Audit log tampering or log injection via unneutralized log input",
    "CWE-90": "Directory query manipulation via LDAP injection",
    "CWE-502": "Remote code execution via untrusted object deserialization",
    "CWE-352": "Unauthorized state change via cross-site request forgery (CSRF)",
    "CWE-862": "Unauthorized access via missing authorization checks",
    "CWE-863": "Privilege escalation via incorrect authorization enforcement",
    "CWE-639": "Horizontal privilege escalation via Insecure Direct Object References (IDOR)",
    "CWE-776": "Denial of service or file disclosure via XML entity expansion (XXE)",
    "CWE-611": "Arbitrary file disclosure via XML External Entity (XXE) injection",
    "CWE-200": "Information disclosure of sensitive application or configuration data",
}


def _format_finding_evidence(f: dict) -> str:
    path = str(f.get("path") or f.get("file") or "").strip()
    line = f.get("start_line") or f.get("line") or ""
    loc = f"{path}:{line}" if path and line else (path or "")
    title = str(f.get("title") or "").strip()
    cwe = str(f.get("cwe") or "").strip().upper()
    if loc and title:
        return f"{loc} [{title}]"
    if loc and cwe:
        return f"{loc} [{cwe}]"
    if title:
        return title
    return cwe or "verified finding"


def _score_finding_threat_match(f: dict, t: dict) -> int:
    score = 0
    cwe = str(f.get("cwe") or "").upper().strip()
    threat_text = str(t.get("threat", "")).lower()
    surface_text = str(t.get("surface", "")).lower()
    ev_text = str(t.get("evidence", "")).lower()

    if cwe and (cwe.lower() in threat_text or cwe.lower() in ev_text):
        score += 10
    if cwe in _CWE_THREAT_KEYWORDS:
        for kw in _CWE_THREAT_KEYWORDS[cwe]:
            if kw in threat_text:
                score += 5
            elif kw in surface_text:
                score += 2

    import re as _re
    title_words = [w for w in _re.findall(r"[a-zA-Z]{4,}", str(f.get("title", "")).lower())
                   if w not in {"across", "every", "into", "with", "site", "units", "from", "user", "data"}]
    for w in title_words:
        if w in threat_text:
            score += 2

    path = str(f.get("path", "")).lower()
    for seg in path.replace("/", " ").replace(".", " ").replace("-", " ").replace("_", " ").split():
        if len(seg) >= 4 and seg in threat_text:
            score += 2

    return score


def _update_threat_table_with_claims(md: str, claims: list[dict]) -> str:
    if "## 4. Threats" not in (md or ""):
        return md or ""
    threat_rows = _parse_threats(md) or []

    novel_groups: dict[str, list[dict]] = {}

    for f in claims:
        best_idx = None
        best_score = 0
        for i, t in enumerate(threat_rows):
            s = _score_finding_threat_match(f, t)
            if s > best_score:
                best_score = s
                best_idx = i

        if best_score >= 4 and best_idx is not None:
            t = threat_rows[best_idx]
            ev = _format_finding_evidence(f)
            cur = str(t.get("evidence") or "").strip()
            loc_key = f"{f.get('path', '')}:{f.get('start_line', '')}".strip(":")
            if not cur or cur.lower() in ("none", "-"):
                t["evidence"] = ev
            elif ev not in cur and (not loc_key or loc_key not in cur):
                t["evidence"] = f"{cur.rstrip(';')}; {ev}"

            t["status"] = "unmitigated"
            t["likelihood"] = "almost_certain"

            sev = str(f.get("severity") or "").lower()
            if sev == "critical" and t.get("impact", "").lower() in ("low", "medium", "high"):
                t["impact"] = "critical"
            elif sev == "high" and t.get("impact", "").lower() in ("low", "medium"):
                t["impact"] = "high"
        else:
            cwe = str(f.get("cwe") or "").strip().upper() or "NOVEL"
            novel_groups.setdefault(cwe, []).append(f)

    # Add new threat rows for novel findings that do not map to any existing row
    existing_ids = []
    for r in threat_rows:
        tid = str(r.get("id", ""))
        if tid.startswith("T") and tid[1:].isdigit():
            existing_ids.append(int(tid[1:]))
    next_id_num = (max(existing_ids) + 1) if existing_ids else (len(threat_rows) + 1)

    for cwe, grp in novel_groups.items():
        tid = f"T{next_id_num}"
        next_id_num += 1

        threat_desc = _CWE_CANONICAL_THREATS.get(
            cwe, f"Security compromise via {grp[0].get('title', cwe)}")
        actor = "remote_auth" if cwe in ("CWE-915", "CWE-862", "CWE-863", "CWE-639") else "remote_unauth"

        paths = sorted({str(f.get("path", "")).strip() for f in grp if f.get("path")})
        surface = ", ".join(paths[:3]) if paths else "application endpoints"

        sevs = {str(f.get("severity", "")).lower() for f in grp}
        impact = "critical" if "critical" in sevs else ("high" if "high" in sevs else "medium")

        ev_str = "; ".join(_format_finding_evidence(f) for f in grp)

        threat_rows.append({
            "id": tid,
            "threat": threat_desc,
            "actor": actor,
            "surface": surface,
            "asset": "application data and system state",
            "impact": impact,
            "likelihood": "almost_certain",
            "status": "unmitigated",
            "controls": "none",
            "evidence": ev_str,
        })

    lines = [
        "| " + " | ".join(THREAT_COLUMNS) + " |",
        "|" + "|".join(["---"] * len(THREAT_COLUMNS)) + "|",
    ]
    for r in threat_rows:
        cells = [_cell(r.get(col, "")) for col in THREAT_COLUMNS]
        lines.append("| " + " | ".join(cells) + " |")

    table_text = "## 4. Threats\n\n" + "\n".join(lines).rstrip() + "\n"
    return _replace_section(md, "4. Threats", table_text)


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

    # First, update Section 4 Threats with mapped evidence and new novel threat rows
    out = _update_threat_table_with_claims(md, claims) if claims else (md or "")

    lines = [OBSERVED_HEADING, "",
             f"Last validator-confirmed scan: {stamp} ({repo or 'repo'}).",
             f"Confirmed primary claims: {len(claims)}.", ""]
    if top_cwe:
        lines += [f"By class: {top_cwe}", ""]
    if top_paths:
        lines += [f"Affected paths: {top_paths}", ""]
    out = _replace_section(out, "Observed findings",
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
