from __future__ import annotations

import inspect
import logging
import os
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypedDict

from langgraph.types import Overwrite

from harness.schemas import SEVERITY_ORDER, safe_float, safe_int
from harness.progress import AgentRegistry, AgentState

try:
    from harness import observability as _obs
except Exception:  # observability module unavailable → tracing disabled (fail-open)
    _obs = None

CVSS_BASE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

# Channels that accumulate across stages (everything else is last-writer-wins).
_ADD_KEYS = ("candidates", "findings", "tools_used", "hunter_coverage")

logger = logging.getLogger(__name__)


def _verified_reducer(left: list[dict] | None,
                      right: list[dict] | None) -> list[dict]:
    # Plain-list updates append; triage/scorer bypasses the reducer via Overwrite(...).
    return list(left or []) + list(right or [])


class ScanState(TypedDict, total=False):
    repo: str
    files: list[str]
    threat_model: str
    threat_model_md: str
    threat_model_source: str
    threat_model_override: str
    vulns_file: str
    threat_quality: dict
    threat_verified: dict
    threat_enrich: dict
    focus: list[str]
    votes_override: int
    triage_log: list[dict]
    tools_used: list[str]
    confirm_critical: bool
    fanout_payloads: list[dict]
    candidates: list[dict]
    findings: list[dict]
    # Two writers (hunter workers, then validator_node); append-only — aggregator joins against it so nothing validates twice.
    verified: list[dict]
    pending: list[dict]
    hunter_coverage: list[str]


def apply_update(state: dict, update: dict | None) -> dict:
    for key, val in (update or {}).items():
        if isinstance(val, Overwrite):
            state[key] = list(val.value or [])
        elif key in _ADD_KEYS:
            state[key] = list(state.get(key) or []) + list(val or [])
        elif key == "verified":
            state[key] = _verified_reducer(state.get(key), val)
        else:
            state[key] = val
    return state


def _call_node(node, state, **kwargs):
    # Introspect once and pass only the kwargs the node declares (upstream
    # callers pass optional params such as agent_registry). TypeError raised
    # *inside* a node is a harness bug (fatal class) and must propagate, so
    # the call itself is never retried here.
    try:
        params = inspect.signature(node).parameters
    except (TypeError, ValueError):  # C callables etc. — cannot introspect.
        return node(state, **kwargs)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return node(state, **kwargs)
    accepted = {k: v for k, v in kwargs.items() if k in params}
    if not accepted:
        return node(state)
    return node(state, **accepted)


def _call_tool(tool_fn, **kwargs) -> str:
    try:
        if hasattr(tool_fn, "func"):
            return str(tool_fn.func(**kwargs))
    except Exception as e:
        logger.debug("tool %s unavailable via .func: %s", tool_fn, e)
        return f"(unavailable: {e})"
    try:
        if hasattr(tool_fn, "invoke"):
            return str(tool_fn.invoke(kwargs))
    except Exception as e:
        logger.debug("tool %s unavailable via .invoke: %s", tool_fn, e)
        return f"(unavailable: {e})"
    try:
        return str(tool_fn(**kwargs))  # plain function (langchain missing)
    except Exception as e:
        logger.debug("tool %s unavailable via direct call: %s", tool_fn, e)
        return f"(unavailable: {e})"


def _info_candidate(cid: str, title: str, path: str, body: str) -> dict:
    return {"id": cid, "title": title, "cwe": "", "severity": "info",
            "confidence": 0.0, "path": path, "start_line": 0, "end_line": 0,
            "snippet": body[:4000], "taint": {"source": "", "sink": "", "path": []},
            "evidence": body[:4000], "status": "needs-review"}


_INVENTORY_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
                   ".c", ".cpp", ".h", ".hpp", ".cc", ".rs", ".cs", ".tf", ".yml", ".yaml", ".dockerfile",
                   ".html", ".htm", ".j2", ".jinja", ".jinja2", ".ejs", ".erb", ".twig", ".vue"}
_SHEBANG_INTERPRETERS = ("python", "node", "ruby", "perl", "php", "bash", "sh", "zsh")
_SHEBANG_MAX_BYTES = 262_144


def _graphify_ignore_predicate(root: Path):
    try:
        from graphify.detect import ignored_predicate
    except ImportError:
        # Minimal dev envs lack the graphify package; the repo vendors its source under ./graphify.
        source_pkg = Path(__file__).resolve().parents[1] / "graphify" / "graphify"
        if not (source_pkg / "detect.py").is_file():
            return None

        package = sys.modules.get("graphify")
        if package is None:
            sys.path.insert(0, str(source_pkg.parent))
        elif not getattr(package, "__file__", None):
            package_path = getattr(package, "__path__", None)
            if package_path is None:
                return None
            local_path = str(source_pkg)
            if local_path not in package_path:
                package_path.append(local_path)
        else:
            return None
        try:
            from graphify.detect import ignored_predicate
        except ImportError:
            return None

    # graphify's ignored_predicate is a factory: ignored_predicate(root)
    # returns the per-path predicate. Call it once, then guard each use.
    try:
        predicate = ignored_predicate(root)
    except Exception:
        return None

    def _safe_ignored(p) -> bool:
        # The vendored predicate can throw on odd paths; skipping the skip is safe.
        try:
            return bool(predicate(p))
        except Exception:
            return False

    return _safe_ignored


def _is_shebang_script(path: Path) -> bool:
    try:
        if path.suffix or path.stat().st_size > _SHEBANG_MAX_BYTES:
            return False
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
            if not first.startswith("#!"):
                return False
            head = (first + fh.readline()).lower()
        return any(interp in head for interp in _SHEBANG_INTERPRETERS)
    except OSError:
        return False


def _inventory_files(base: Path) -> list[str]:
    from harness.tools.graphify import GRAPHIFY_SKIP_DIRS
    if base.is_file():
        graphify_ignored = _graphify_ignore_predicate(base.parent)
        if graphify_ignored is not None and graphify_ignored(base):
            return []
        return [str(base)]
    if not base.is_dir():
        return []
    graphify_ignored = _graphify_ignore_predicate(base)

    files: list[str] = []
    for root, dirs, names in os.walk(base, topdown=True, followlinks=False):
        root_path = Path(root)
        kept_dirs = []
        for name in sorted(dirs):
            directory = root_path / name
            if name in GRAPHIFY_SKIP_DIRS or directory.is_symlink():
                continue
            if graphify_ignored is not None and graphify_ignored(directory):
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(names):
            f = root_path / name
            if f.is_symlink():
                continue
            if not (f.suffix.lower() in _INVENTORY_EXTS
                    or f.name.lower().startswith("dockerfile")
                    or _is_shebang_script(f)):
                continue
            if graphify_ignored is not None and graphify_ignored(f):
                continue
            try:
                files.append(str(f.relative_to(base)))
            except ValueError:
                files.append(str(f))
    return sorted(files)


def indexer_node(state: ScanState) -> dict:
    from harness.fallback import run_fail_open
    from harness.tools.sast import (iac_check, sca_scan, secrets_scan,
                                    regex_prefilter)
    repo = state.get("repo", ".")
    # No file-count cap; per-agent work is bounded by the partition budget (harness/units.py partition_target).
    base = Path(repo)
    files = _inventory_files(base)
    cands = [_info_candidate(
        "prefilter", "deterministic prefilter hits", repo,
        _call_tool(regex_prefilter, target=repo))]
    _tools_used = ["regex_prefilter"]

    def _template_stage() -> list[dict]:
        from harness.tools.sast import template_reflect_candidates

        _tpl = template_reflect_candidates(repo)
        for c in _tpl:
            c.setdefault("status", "needs-review")
        return _tpl

    _tpl = run_fail_open("template_reflect", _template_stage,
                         default=[], logger=logger)
    if _tpl:
        _tools_used.append("template_reflect")
        cands.extend(_tpl)

    # No whole-repo Semgrep/OpenGrep: hunters scan their own unit files; the indexer keeps fast signals only.
    for cid, title, raw in (
            ("secrets", "secrets scan raw", _call_tool(secrets_scan, target=repo)),
            ("sca", "SCA scan raw", _call_tool(sca_scan, target=repo)),
            ("iac", "IaC scan raw", _call_tool(iac_check, target=repo))):
        compact = raw.replace(" ", "")
        if "binarynotfound" not in compact.lower() and '"skipped":true' not in compact:
            cands.append(_info_candidate(cid, title, repo, raw))
            _tools_used.append({"secrets": "secrets_scan", "sca": "sca_scan",
                                "iac": "iac_check"}[cid])

    def _codegraph_stage() -> tuple[list[dict], list[str]]:
        from harness.tools.codegraph import framework_routes, manifest_parse

        extra: list[dict] = []
        used: list[str] = []
        man = _call_tool(manifest_parse, root=repo)
        if man and "(no manifests found)" not in man and "(unavailable" not in man:
            extra.append(_info_candidate("manifest", "repo manifest summary", repo, man))
            used.append("manifest_parse")
        routes = _call_tool(framework_routes, root=repo)
        if routes and "(no matches)" not in routes and "(unavailable" not in routes:
            extra.append(_info_candidate("routes", "framework routes", repo, routes))
            used.append("framework_routes")
        return extra, used

    _extra, _used = run_fail_open("codegraph_signals", _codegraph_stage,
                                  default=([], []), logger=logger)
    cands.extend(_extra)
    _tools_used.extend(_used)

    def _graphify_stage() -> tuple[list[dict], list[str]]:
        from harness.config import load_config_safe
        from harness.tools import graphify as _gf

        _gcfg, _gcfg_err = load_config_safe()
        if _gcfg_err is not None:
            logger.debug("graphify config load failed; defaulting to enabled: %s",
                         _gcfg_err)
        _gen = str(((_gcfg.get("graphify") or {}).get("enabled", "1"))).lower()
        if _gen in ("1", "true", "yes") and base.is_dir():
            _gpath = _gf.graphify_build(repo)
            if _gpath:
                return [_info_candidate(
                    "graphify", "code-graph structural summary", repo,
                    _gf.graphify_summary(repo))], ["graphify_build"]
        return [], []

    _extra, _used = run_fail_open("graphify_build", _graphify_stage,
                                  default=([], []), logger=logger)
    cands.extend(_extra)
    _tools_used.extend(_used)
    return {"files": files, "candidates": cands, "tools_used": sorted(set(_tools_used))}


def threat_model_node(state: ScanState, agent_registry: Any = None) -> dict:
    repo = state.get("repo", ".") or "."
    cands = [c for c in (state.get("candidates") or []) if isinstance(c, dict)]
    files = [f for f in (state.get("files") or []) if f]
    pre = next((c.get("snippet", "") for c in cands if c.get("id") == "prefilter"), "")
    classes = [line[3:] for line in str(pre).splitlines() if line.startswith("## ")]
    routes = next((c.get("snippet", "") for c in cands if c.get("id") == "routes"), "")
    n_routes = len([l for l in str(routes).splitlines() if l.strip()]) if routes else 0
    man = next((c.get("snippet", "") for c in cands if c.get("id") == "manifest"), "")
    stack = (str(man).splitlines() or ["unknown stack"])[0][:200]
    summary = (
        f"Threat model for {repo} | stack: {stack} | entry points: ~{n_routes} routes | "
        f"prefilter signal classes: {', '.join(classes) or 'none'} | "
        "STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), "
        "info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR)."
    )
    out: dict = {"threat_model": summary,
                 "candidates": [_info_candidate("threat-model", "STRIDE-lite threat model", repo, summary)]}
    if agent_registry is not None:
        for _r in ("threat:researcher", "threat:historian", "threat:synthesizer"):
            agent_registry.create(_r, _r, parent_stage="threat_model",
                                  state=AgentState.queued)
            agent_registry.transition(_r, AgentState.running,
                                      parent_stage="threat_model")
    # Artifact writing stays in the CLI (single writer).

    def _threat_doc_stage() -> dict:
        from harness import threat as _th
        from harness.config import load_config_safe

        _cfg2, _cfg2_err = load_config_safe()
        if _cfg2_err is not None:
            logger.debug("threat model config load failed; using defaults: %s",
                         _cfg2_err)
        override = state.get("threat_model_override") or ""
        vulns_path = state.get("vulns_file") or ""
        try:
            vulns = _th.parse_vulns_file(vulns_path) if vulns_path else []
        except Exception:
            vulns = []
        source, md = _th.load_threat(repo, override=override or None, cfg=_cfg2)
        # Stale-cache guard: cached doc must pass the 8-section schema; --vulns invalidates the cache (no supplied evidence base).
        if (source == "repo-cache" and md.strip()
                and (_th.validate_threat_md(md) or vulns)):
            source = "repo-cache-stale"
        if not md.strip() or source == "repo-cache-stale":
            try:
                md = _th.bootstrap_threat(repo, files, cands, summary,
                                          vulns=vulns, vulns_path=vulns_path)
                source = "bootstrap" if md.strip() else "summary"
            except Exception:
                md, source = "", "summary"
        if vulns_path and not vulns:
            print(f"warning: --vulns {vulns_path} parsed to 0 rows "
                  "(missing or unrecognized format); continuing on git history",
                  file=sys.stderr)
        enrich_meta: dict = {}
        if (source not in ("override", "repo-file")
                and _th.threat_enabled(_cfg2, "llm_enrich", True)):
            try:
                enriched, enrich_meta = _th.enrich_threat(
                    repo, files, cands, summary, md, _cfg2,
                    vulns=vulns, vulns_path=vulns_path,
                    measured_facts=_th.measured_facts(
                        repo, files, cands, summary, vulns))
                if enriched.strip():
                    md = enriched
            except Exception as e:
                enrich_meta = {"error": f"{type(e).__name__}: {e}"}
        stage_out: dict = {"threat_model_source": source}
        if md.strip():
            stage_out["threat_model_md"] = md
            if enrich_meta:
                stage_out["threat_enrich"] = enrich_meta
            from harness.agents.deep import is_fatal_error

            try:
                stage_out["threat_quality"] = _th.threat_quality(md, files, cands)
            except Exception as e:
                # Absence of a score is a valid degrade; a harness bug must not hide.
                if is_fatal_error(e):
                    raise
                logger.warning("threat quality check failed: %s", e)
            try:
                stage_out["threat_verified"] = _th.verify_threat(repo, md, files, cands)
            except Exception as e:
                if is_fatal_error(e):
                    raise
                logger.warning("threat verification failed: %s", e)
        return stage_out

    stage_err: dict = {}

    def _threat_doc_probe() -> dict:
        nonlocal stage_err
        try:
            return _threat_doc_stage()
        except Exception as e:
            stage_err["exc"] = e
            raise

    from harness.fallback import run_fail_open

    _stage_updates = run_fail_open("threat_model.doc", _threat_doc_probe,
                                   default={}, logger=logger)
    out.update(_stage_updates)
    if stage_err.get("exc") is not None:
        e = stage_err["exc"]
        if agent_registry is not None:
            for _r in ("threat:researcher", "threat:historian", "threat:synthesizer"):
                agent_registry.transition(_r, AgentState.failed,
                                          parent_stage="threat_model",
                                          error=str(e))
        out["threat_model_source"] = "summary"
    else:
        if agent_registry is not None:
            for _r in ("threat:researcher", "threat:historian", "threat:synthesizer"):
                agent_registry.transition(_r, AgentState.succeeded,
                                          parent_stage="threat_model")
    return out


def hunters_router(state: ScanState, agent_registry: Any = None) -> dict:
    from harness.config import api_key_present, load_config_safe

    cfg, cfg_err = load_config_safe()
    if cfg_err is not None:
        # Operator error at the user-fixable layer: degrade gracefully but LOUDLY.
        print(f"warning: config load failed ({cfg_err}); the LLM layer is "
              "unconfigured — continuing in degraded no-key mode",
              file=sys.stderr, flush=True)
        cfg = {"concurrency": 8}
    if not api_key_present(cfg):
        out = []
        for i, f in enumerate(state.get("files", [])):
            out.append({"id": f"review-{i}", "title": f"manual review: {f}",
                        "cwe": "", "path": f,
                        "start_line": 0, "end_line": 0,
                        "snippet": "LLM hunters skipped (no API_KEY).",
                        "taint": {"source": "", "sink": "", "path": []},
                        "status": "needs-review", "severity": "info",
                        "confidence": 0.0, "evidence": "phase-1 scaffold without API key"})
        return {"findings": out, "fanout_payloads": []}
    payload_files = list(state.get("files", []))
    payload_cands = list(state.get("candidates", []))
    threat_md = state.get("threat_model_md", "") or ""
    _focus = state.get("focus", []) or []
    if isinstance(_focus, str):
        _focus = [f.strip() for f in _focus.split(",") if f.strip()]
    units: list[dict] = []
    if agent_registry is not None:
        agent_registry.create("partitioner", "partitioner", parent_stage="partition",
                              state=AgentState.queued)
        agent_registry.transition("partitioner", AgentState.running,
                                  parent_stage="partition")

    _partition_exc: dict = {}

    def _partition_probe() -> list[dict]:
        from harness.partitioning.llm import run_partitioner_agent

        try:
            return run_partitioner_agent(
                state.get("repo", "."), payload_files, payload_cands, cfg,
                threat_md=threat_md)
        except Exception as e:
            _partition_exc["exc"] = e
            raise

    from harness.fallback import run_fail_open

    units = run_fail_open("partitioner", _partition_probe, default=[],
                          logger=logger)
    _partition_failed = _partition_exc.get("exc") is not None
    if agent_registry is not None:
        if _partition_failed:
            agent_registry.transition("partitioner", AgentState.failed,
                                      parent_stage="partition")
        else:
            agent_registry.transition("partitioner", AgentState.succeeded,
                                      parent_stage="partition")
    if not units:
        from harness.partitioning import partition_units
        units = partition_units(state.get("repo", "."), payload_files)
    if not units:
        return {"findings": [], "fanout_payloads": []}
    from harness.partitioning import verify_partition
    try:
        verify_partition(units, payload_files)
    except Exception as e:
        logger.warning("Partition verification failed: %s", e)
    return {"findings": [],
            "fanout_payloads": [
                {"unit": u["name"], "repo": state.get("repo", "."),
                 "files": u["files"], "candidates": payload_cands, "cfg": cfg,
                 "threat_model_md": threat_md, "focus": list(_focus),
                 "votes_override": state.get("votes_override"),
                 "reason": u.get("reason", "")}
                for u in units]}


def _validate_inline(findings: list[dict], cfg: dict, threat_md: str,
                     votes: int | None, label: str,
                     repo: str | None = None) -> list[dict]:
    from harness.agents.validator import run_validation

    try:
        return run_validation(findings, cfg or {}, threat_md or "", votes,
                              units=[{"name": str(label)}], max_workers=3,
                              repo=repo)
    except Exception as e:
        from harness.agents.deep import is_fatal_error

        # Fail-open for infra noise; a config-class failure must sink the scan.
        if is_fatal_error(e):
            raise
        out = []
        for f in (findings or []):
            g = dict(f) if isinstance(f, dict) else {"title": str(f)}
            g.setdefault("status", "needs-review")
            out.append(g)
        return out


def hunter_worker(state: dict) -> dict:
    import time as _time

    from harness.agents.hunters import _fallback_finding, _run_unit

    repo = state.get("repo", ".")
    files = list(state.get("files", []))
    candidates = list(state.get("candidates", []))
    cfg = dict(state.get("cfg", {}) or {})
    threat_md = state.get("threat_model_md", "") or ""
    focus = state.get("focus", []) or []
    _tools: list = []
    _coverage: list = []
    t0 = _time.time()
    label = state.get("unit") or "unit"
    try:
        out = _run_unit({"name": label}, repo, files, candidates, cfg,
                        threat_md=threat_md, focus=focus, _tools_out=_tools,
                        _coverage_out=_coverage)
        # Stamp the partition so validation runs one validator per unit.
        for f in out:
            if isinstance(f, dict) and not f.get("unit"):
                f["unit"] = str(label)
        print(f"[hunters] {label}: {len(out)} findings in {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        validated = _validate_inline(out, cfg, threat_md,
                                     state.get("votes_override"), label,
                                     repo=repo)
        ret = {"findings": out, "verified": validated,
               "tools_used": sorted(set(str(t) for t in _tools))}
        if _coverage:
            ret["hunter_coverage"] = _coverage
        return ret
    except Exception as e:
        # A config error must sink the scan, not become a unit fallback finding.
        from harness.agents.deep import is_fatal_error

        if is_fatal_error(e):
            raise
        print(f"[hunters] {label}: ERROR {type(e).__name__} after {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        fb = _fallback_finding(str(label), repo, files, str(e))
        fb["unit"] = str(label)
        return {"findings": [fb]}


def _norm_key(f: dict) -> str:
    try:
        fid = str(f.get("id", "") or "").strip()
        if fid:
            return f"id:{fid}"
        path = (str(f.get("path", "")).strip().lower()
                .replace("\\", "/").lstrip("./"))
        return (f"{path}|{safe_int(f.get('start_line'))}"
                f"|{safe_int(f.get('end_line'))}")
    except (AttributeError, TypeError, ValueError):
        # Non-dict payloads: the fallback must hold the same never-raises
        # contract as the body above it.
        if hasattr(f, "get"):
            return f"{f.get('path')}|{f.get('title')}"
        return str(f)


def _merge_dup(a: dict, b: dict) -> dict:
    prio = {"confirmed": 2, "needs-review": 1, "fp": 0}
    keep, drop = (a, b) if prio.get(a.get("status"), 1) >= prio.get(b.get("status"), 1) else (b, a)
    g = dict(keep)
    try:
        g["confidence"] = max(float(keep.get("confidence", 0) or 0),
                              float(drop.get("confidence", 0) or 0))
    except (TypeError, ValueError):
        pass
    ev = str(g.get("evidence") or "")
    extra = str(drop.get("evidence") or "")
    if extra and extra not in ev:
        g["evidence"] = (ev + f" | alt: {extra}")[:4000]
    return g


def system_pass_node(state: ScanState) -> dict:
    findings = [f for f in list(state.get("findings", [])) if isinstance(f, dict)]
    from harness.config import api_key_present, load_config_safe

    _cfg_sys, _cfg_err = load_config_safe()
    if _cfg_err is not None:
        logger.debug("system_pass config load failed; using defaults: %s",
                     _cfg_err)
    if not api_key_present(_cfg_sys):
        return {}
    _enabled = str(((_cfg_sys.get("discovery") or {}).get("system_pass", True))).lower()
    if _enabled not in ("1", "true", "yes"):
        return {}
    import time as _time
    t0 = _time.time()

    _sysfail: dict = {}

    def _system_pass_probe() -> tuple[list[dict], list[str]]:
        try:
            from harness.agents.hunters import _run_system_pass

            focus = state.get("focus", []) or []
            _tools: list = []
            out = _run_system_pass(state.get("repo", "."),
                                   list(state.get("files", [])),
                                   findings,
                                   state.get("threat_model_md", "") or "",
                                   _cfg_sys, focus, _tools)
            print(f"[system-pass] +{len(out)} cross-unit findings in {_time.time()-t0:.0f}s",
                  file=sys.stderr, flush=True)
            return out, sorted(set(str(t) for t in _tools))
        except Exception as e:
            print(f"[system-pass] ERROR {type(e).__name__} after {_time.time()-t0:.0f}s",
                  file=sys.stderr, flush=True)
            _sysfail["fail"] = True
            raise

    from harness.fallback import run_fail_open

    out, _sys_tools = run_fail_open("system_pass", _system_pass_probe,
                                    default=([], []), logger=logger)
    if _sysfail.get("fail"):
        return {}
    ret: dict = {"findings": out or []}
    if _sys_tools:
        ret["tools_used"] = _sys_tools
    return ret


def aggregator_node(state: ScanState) -> dict:
    seen: dict[str, dict] = {}
    for f in list(state.get("candidates", [])) + list(state.get("findings", [])):
        key = _norm_key(f)
        seen[key] = _merge_dup(seen[key], f) if key in seen else f
    out: list[dict] = list(seen.values())
    # Pipelined validation: queue only findings with no validated counterpart (same norm-key); never validated twice.
    done_keys = {_norm_key(f) for f in (state.get("verified", []) or [])}
    pending = [f for f in out if _norm_key(f) not in done_keys]
    return {"pending": pending}


def validator_node(state: ScanState, agent_registry: Any = None) -> dict:
    from harness.agents.validator import run_validation

    pending = [dict(f) for f in (state.get("pending", []) or [])]
    if agent_registry is not None:
        agent_registry.create("validator", "validator", parent_stage="validation",
                              state=AgentState.queued)
        agent_registry.transition("validator", AgentState.running,
                                  parent_stage="validation")
    from harness.config import load_config_safe

    cfg, cfg_err = load_config_safe()
    if cfg_err is not None:
        logger.debug("validator config load failed; using defaults: %s", cfg_err)
    import time as _time
    t0 = _time.time()
    print(f"[validator] validating {len(pending)} remaining findings "
          f"({len(state.get('verified', []) or [])} already validated)...",
          file=sys.stderr, flush=True)
    try:
        units = []
        for p in (state.get("fanout_payloads", []) or []):
            if isinstance(p, dict) and p.get("unit"):
                units.append({"name": str(p["unit"]),
                              "files": list(p.get("files", []))})
        validated = run_validation(
            pending, cfg, state.get("threat_model_md", "") or "",
            state.get("votes_override"), units=units,
            repo=state.get("repo"))
        if agent_registry is not None:
            agent_registry.transition("validator", AgentState.succeeded,
                                      parent_stage="validation")
    except Exception as e:
        from harness.agents.deep import is_fatal_error

        # Never drop on validator error, unless it is the operator's config.
        if is_fatal_error(e):
            if agent_registry is not None:
                agent_registry.transition("validator", AgentState.failed,
                                          parent_stage="validation", error=str(e))
            raise
        if agent_registry is not None:
            agent_registry.transition("validator", AgentState.failed,
                                      parent_stage="validation", error=str(e))
        validated = []
        for f in pending:
            fb = dict(f)
            fb.setdefault("status", "needs-review")
            validated.append(fb)
    from collections import Counter as _Counter
    print(f"[validator] done: {len(validated)} in {_time.time()-t0:.0f}s "
          f"{dict(_Counter(f.get('status') for f in validated))}",
          file=sys.stderr, flush=True)
    return {"verified": validated}


def _is_hot(f: dict) -> bool:
    return f.get("severity") in ("critical", "high") and f.get("status") == "confirmed"


def confirm_critical_step(state: ScanState,
                          confirm: Callable[[dict], bool] | None) -> dict:
    # No confirm callback => HOLD: hot findings are demoted to needs-review, never released unreviewed.
    verified = list(state.get("verified", []) or [])
    hot = [f for f in verified if isinstance(f, dict) and _is_hot(f)]
    if not hot:
        return {}
    payload = {
        "question": "confirmed critical/high findings — proceed?",
        "findings": [{"id": f.get("id"), "title": f.get("title"),
                      "path": f.get("path"),
                      "start_line": f.get("start_line")} for f in hot[:20]],
    }
    try:
        approved = bool(confirm(payload)) if confirm is not None else False
    except Exception as e:
        # Hold direction is the safe failure: never release unreviewed hot findings.
        logger.warning("confirm callback failed (%s: %s); holding hot findings",
                       type(e).__name__, e)
        approved = False
    if approved:
        return {}
    out = []
    for f in verified:
        g = dict(f) if isinstance(f, dict) else f
        if isinstance(g, dict) and _is_hot(g):
            g["status"] = "needs-review"
            g["evidence"] = (str(g.get("evidence") or "")
                             + " | held for human review (HIL declined)")[:4000]
        out.append(g)
    return {"verified": Overwrite(out)}


def triage_node(state: ScanState, agent_registry: Any = None) -> dict:
    import time as _time
    t0 = _time.time()
    verified = list(state.get("verified", []))
    if not verified:
        return {}
    if agent_registry is not None:
        agent_registry.create("triage:1", "triage:1", parent_stage="triage",
                              state=AgentState.queued)
        agent_registry.transition("triage:1", AgentState.running,
                                  parent_stage="triage")
    from harness.config import load_config_safe

    _cfg4, _cfg4_err = load_config_safe()
    if _cfg4_err is not None:
        logger.debug("triage config load failed; using defaults: %s", _cfg4_err)
    try:
        from harness.agents.triage import run_triage
        res = run_triage(verified, _cfg4, state.get("threat_model_md", "") or "")
        out = res.get("findings", verified)
        if agent_registry is not None:
            agent_registry.transition("triage:1", AgentState.succeeded,
                                      parent_stage="triage")
        print(f"[triage] {len(out)} findings, "
              f"{res.get('n_duplicates', 0)} duplicates, "
              f"{res.get('triage_llm_calls', 0)} LLM calls in {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        ret: dict = {"verified": Overwrite(out)}
        if res.get("triage_log"):
            ret["triage_log"] = res["triage_log"]
        return ret
    except Exception as e:
        from harness.agents.deep import is_fatal_error

        if is_fatal_error(e):
            if agent_registry is not None:
                agent_registry.transition("triage:1", AgentState.failed,
                                          parent_stage="triage", error=str(e))
            raise
        if agent_registry is not None:
            agent_registry.transition("triage:1", AgentState.failed,
                                      parent_stage="triage", error=str(e))
        print(f"[triage] ERROR {type(e).__name__} after {_time.time()-t0:.0f}s "
              "(verified untouched)", file=sys.stderr, flush=True)
        return {}


def threat_update_node(state: ScanState) -> dict:
    # State only; the CLI is the single file writer.
    md = state.get("threat_model_md", "") or ""
    if not md.strip():
        return {}
    from harness.fallback import run_fail_open

    def _threat_update_stage() -> dict:
        from harness import threat as _th5

        updated = _th5.update_threat_with_findings(
            md, list(state.get("verified", [])), state.get("repo", "."))
        if updated.strip() and updated != md:
            return {"threat_model_md": updated}
        return {}

    return run_fail_open("threat_update", _threat_update_stage,
                         default={}, logger=logger)


def scorer_node(state: ScanState) -> dict:
    out = []
    for f in state.get("verified", []):
        g = dict(f)
        conf = safe_float(g.get("confidence"))
        base = CVSS_BASE.get(g.get("severity", "medium"), 5.0)
        g["cvss"] = round(base * (0.5 + 0.5 * max(0.0, min(1.0, conf))), 1)
        out.append(g)
    out.sort(key=lambda f: (-float(f.get("cvss", 0)),
                            SEVERITY_ORDER.get(f.get("severity", "medium"), 2)))
    for i, f in enumerate(out):
        f["rank"] = i + 1
    # Replace, not append: this is the same set, annotated.
    return {"verified": Overwrite(out)}


def _safe_max_concurrency() -> int:
    from harness.config import get_concurrency, load_config_safe

    cfg, cfg_err = load_config_safe()
    if cfg_err is not None:
        logger.debug("concurrency config load failed; using default: %s", cfg_err)
    return get_concurrency(cfg)


def _reset_agent_scratch_phase(repo: str) -> None:
    # Hygiene only: config-gated, best-effort — NOT a security boundary.
    try:
        from harness.config import load_config
        from harness.sandbox import reset_agent_scratch

        # NOTE: load_config() must stay a zero-arg call here — tests pin a
        # zero-arg mock for harness.config.load_config (load_config_safe
        # forwards a path argument and would break that contract).
        try:
            cfg = load_config()
        except Exception:
            cfg = {}
        sandbox = cfg.get("sandbox")
        sandbox = sandbox if isinstance(sandbox, dict) else {}
        if str(sandbox.get("reset_agent_scratch", 1)).strip().lower() not in (
                "1", "true", "yes"):
            return
        for err in reset_agent_scratch(repo):
            print(f"[sandbox] {err}", file=sys.stderr)
    except Exception:
        pass


def _sweep_orphan_sandboxes() -> None:
    try:
        from harness.config import load_config
        from harness.sandbox import sweep_orphans

        # Zero-arg load_config() — see note in _reset_agent_scratch_phase.
        try:
            cfg = load_config()
        except Exception:
            cfg = {}
        sandbox = cfg.get("sandbox")
        sandbox = sandbox if isinstance(sandbox, dict) else {}
        if str(sandbox.get("sweep_orphans", 1)).strip().lower() not in (
                "1", "true", "yes"):
            return
        removed = sweep_orphans()
        if removed:
            print(f"[sandbox] reaped {len(removed)} sandbox(es) left by a "
                  f"killed run: {', '.join(sorted(removed))}", file=sys.stderr)
    except Exception:
        pass


def _fan_out_hunters(state: dict, max_workers: int, agent_registry: Any = None) -> None:
    payloads = list(state.get("fanout_payloads", []) or [])
    if not payloads:
        return
    shared = {k: state.get(k) for k in ("repo", "threat_model_md", "focus",
                                        "votes_override")}

    if agent_registry is not None:
        for p in payloads:
            unit = str(p.get("unit", "unit"))
            cfg = p.get("cfg") or state.get("cfg") or {}
            model = cfg.get("hunter_model") if isinstance(cfg, dict) else None
            agent_registry.create("hunter:" + unit, "hunter", unit=unit,
                                  parent_stage="hunters", model=model,
                                  state=AgentState.queued)

    def _one(p: dict) -> dict:
        unit = str(p.get("unit", "unit"))
        aid = "hunter:" + unit
        cfg = p.get("cfg") or state.get("cfg") or {}
        model = cfg.get("hunter_model") if isinstance(cfg, dict) else None
        if agent_registry is not None:
            agent_registry.transition(aid, AgentState.running,
                                      parent_stage="hunters", model=model,
                                      message="unit started")
        try:
            merged = dict(p)
            for k, v in shared.items():
                merged.setdefault(k, v)
            res = hunter_worker(merged)
            if agent_registry is not None:
                agent_registry.transition(aid, AgentState.succeeded,
                                         parent_stage="hunters",
                                         message="completed",
                                         model=model)
            return res
        except Exception as e:  # pragma: no cover - hunter_worker is fail-open
            from harness.agents.deep import is_fatal_error

            # Operator config errors must sink the scan, not become fallbacks.
            if is_fatal_error(e):
                if agent_registry is not None:
                    agent_registry.transition(aid, AgentState.failed,
                                              parent_stage="hunters",
                                              model=model, error=str(e))
                raise
            from harness.agents.hunters import _fallback_finding
            fb = _fallback_finding(str(p.get("unit", "unit")), p.get("repo", "."),
                                   list(p.get("files", [])), str(e))
            fb["unit"] = str(p.get("unit", "unit"))
            if agent_registry is not None:
                agent_registry.transition(aid, AgentState.failed,
                                          parent_stage="hunters",
                                          model=model, error=str(e))
            return {"findings": [fb]}

    with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as ex:
        futures = [ex.submit(_one, p) for p in payloads]
        for fut in futures:
            apply_update(state, fut.result())


def run_scan(repo: str, confirm_critical: bool = False,
             threat_model_override: str | None = None,
             focus: list[str] | str | None = None,
             votes: int | None = None,
             vulns_file: str | None = None,
             confirm: Callable[[dict], bool] | None = None,
             agent_events_path: Any = None,
             ) -> dict[str, Any]:
    os.environ["TARGET_REPO"] = str(repo)
    _sweep_orphan_sandboxes()
    state: dict[str, Any] = {"repo": repo}
    if _obs is not None:
        _scan_id = _obs.start_scan(repo)
        if _scan_id:
            state["scan_id"] = _scan_id

    try:
        _agent_registry = AgentRegistry(run_id=str(repo), events_path=agent_events_path)
    except Exception:
        _agent_registry = None
    if confirm_critical:
        state["confirm_critical"] = True
    if threat_model_override:
        state["threat_model_override"] = threat_model_override
    if vulns_file:
        state["vulns_file"] = vulns_file
    if isinstance(focus, str):
        focus = [f.strip() for f in focus.split(",") if f.strip()]
    if focus:
        state["focus"] = list(focus)
    if votes is not None:
        state["votes_override"] = votes

    import time as _stage_time
    stage_timings = {}
    def _stage(name, fn):
        print(f"[pipeline] >>> Stage '{name}' starting...", file=sys.stderr, flush=True)
        _t0 = _stage_time.time()
        try:
            res = fn()
            elapsed = round(_stage_time.time() - _t0, 3)
            print(f"[pipeline] <<< Stage '{name}' completed in {elapsed}s", file=sys.stderr, flush=True)
            return res
        except Exception as exc:
            elapsed = round(_stage_time.time() - _t0, 3)
            print(f"[pipeline] !!! Stage '{name}' failed after {elapsed}s: {exc}", file=sys.stderr, flush=True)
            raise
        finally:
            stage_timings[name] = round(_stage_time.time() - _t0, 3)

    _stage("indexer", lambda: apply_update(state, indexer_node(state)))
    _stage("threat_model", lambda: apply_update(state, _call_node(threat_model_node, state, agent_registry=_agent_registry)))
    _stage("hunters_router", lambda: apply_update(state, _call_node(hunters_router, state, agent_registry=_agent_registry)))
    if state.get("fanout_payloads"):
        _stage("hunters", lambda: _fan_out_hunters(state, _safe_max_concurrency(), agent_registry=_agent_registry))
    _stage("system_pass", lambda: apply_update(state, system_pass_node(state)))
    _stage("aggregator", lambda: apply_update(state, aggregator_node(state)))
    _reset_agent_scratch_phase(state.get("repo", "."))
    _stage("validator", lambda: apply_update(state, _call_node(validator_node, state, agent_registry=_agent_registry)))
    if state.get("confirm_critical"):
        _stage("confirm_critical", lambda: apply_update(state, confirm_critical_step(state, confirm)))
    _stage("triage", lambda: apply_update(state, _call_node(triage_node, state, agent_registry=_agent_registry)))
    _stage("threat_update", lambda: apply_update(state, threat_update_node(state)))
    _stage("scorer", lambda: apply_update(state, scorer_node(state)))
    try:
        if _agent_registry is not None:
            state["agent_events"] = [e.to_dict() if hasattr(e, "to_dict") else dict(e)
                                     for e in getattr(_agent_registry, "events", [])]
            state["agent_handles"] = _agent_registry.dump()
            state["agent_summary"] = _agent_registry.summary()
        state["stage_timings"] = dict(stage_timings)
    except Exception:
        pass
    if _obs is not None:
        _obs.finish_scan()
    return dict(state)
