from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, TypedDict

from cerberus.paths import canonical_repo
from cerberus.progress import AgentRegistry, AgentState
from cerberus.schemas import MERGE_PRIO, SEVERITY_ORDER, coerce_findings, safe_float, safe_int

try:
    from cerberus import observability as _obs
except Exception:
    _obs = None


class Overwrite:
    """Explicit value container to replace rather than append a channel list."""
    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"Overwrite({self.value!r})"


CVSS_BASE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

# Channels that accumulate across stages (everything else is last-writer-wins).
_ADD_KEYS = ("candidates", "findings", "tools_used")

logger = logging.getLogger(__name__)

_THREAD_LOCAL = threading.local()
_PROGRESS: Any = None


def _get_progress() -> Any:
    return getattr(_THREAD_LOCAL, "progress", None) or _PROGRESS


def _stage_detail(stage: str, text: str) -> None:
    """Route a node's completion detail to the UI sink, else print as before."""
    prog = _get_progress()
    if prog is None:
        print(text, file=sys.stderr, flush=True)
        return
    try:
        prog.detail(stage, text)
    except Exception:
        pass


def _verified_reducer(left: list[dict] | None,
                      right: list[dict] | None) -> list[dict]:
    # Plain-list updates append; triage/scorer bypasses the reducer via Overwrite(...).
    return list(left or []) + list(right or [])


class ScanState(TypedDict, total=False):
    repo: str
    files: list[str]
    record_signals: bool
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
    signals: list[dict]
    findings: list[dict]
    # Two writers (hunter workers, then validator_node); append-only — aggregator joins against it so nothing validates twice.
    verified: list[dict]
    pending: list[dict]


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


def _call_tool(tool_fn, **kwargs) -> str:
    try:
        if hasattr(tool_fn, "func"):
            return str(tool_fn.func(**kwargs))
    except Exception as e:
        logger.debug("tool %s unavailable via .func: %s", tool_fn, e)
        return f"(unavailable: {e})"
    try:
        return str(tool_fn(**kwargs))  # plain function (langchain missing)
    except Exception as e:
        logger.debug("tool %s unavailable via direct call: %s", tool_fn, e)
        return f"(unavailable: {e})"


_INVENTORY_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
                   ".c", ".cpp", ".h", ".hpp", ".cc", ".rs", ".cs", ".tf", ".yml", ".yaml", ".dockerfile",
                   ".html", ".htm", ".j2", ".jinja", ".jinja2", ".ejs", ".erb", ".twig", ".vue"}
_SHEBANG_INTERPRETERS = ("python", "node", "ruby", "perl", "php", "bash", "sh", "zsh")
_SHEBANG_MAX_BYTES = 262_144


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
    from cerberus.tools.code import is_skipped_dir

    if base.is_file():
        return [str(base)]
    if not base.is_dir():
        return []

    files: list[str] = []
    for root, dirs, names in os.walk(base, topdown=True, followlinks=False):
        root_path = Path(root)
        kept_dirs = []
        for name in sorted(dirs):
            directory = root_path / name
            if directory.is_symlink() or is_skipped_dir(directory):
                continue
            if name == "plugins" and root_path.name == "public":
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
            try:
                files.append(str(f.relative_to(base)))
            except ValueError:
                files.append(str(f))
    return sorted(files)


def _node_cfg(state: dict) -> dict:
    """The cfg ``run_scan`` threaded into ``state``; nodes never re-parse the file.

    A direct caller that invokes a node without the threaded cfg (tests) still
    gets a config: one load, with no per-node log (run_scan owns the one report).
    """
    cfg = state.get("cfg") if isinstance(state, dict) else None
    if isinstance(cfg, dict):
        return cfg
    from cerberus.config import get_config

    return get_config()


def indexer_node(state: ScanState) -> dict:
    from cerberus.fallback import runner
    from cerberus.tools.sast import iac_check, regex_prefilter, sca_scan, secrets_scan
    repo = state.get("repo", ".")
    record_signals = state.get("record_signals", True)
    # No file-count cap; per-agent work is bounded by the partition budget.
    base = Path(repo)
    files = _inventory_files(base)
    cands: list[dict] = []
    signals_out: list[dict] = []

    def _add_signal(cid: str, body: str, keep_text: bool = False) -> None:
        from cerberus.signals import signal_stats, write_signal

        count, summary = signal_stats(body)
        entry: dict = {"id": cid, "count": count, "summary": summary}
        if record_signals:
            entry["path"] = write_signal(repo, cid, body)
        if keep_text:
            entry["text"] = body
        signals_out.append(entry)

    _tools_used = ["regex_prefilter"]
    _add_signal("prefilter",
                _call_tool(regex_prefilter, target=repo), keep_text=True)

    def _template_stage() -> list[dict]:
        from cerberus.tools.sast import template_reflect_candidates

        _tpl = template_reflect_candidates(repo)
        for c in _tpl:
            c.setdefault("status", "needs-review")
        return _tpl

    _tpl = runner("template_reflect", _template_stage,
                  default=[], logger=logger)
    if _tpl:
        _tools_used.append("template_reflect")
        cands.extend(_tpl)

    # No whole-repo Semgrep/OpenGrep: hunters scan their own unit files; the indexer keeps fast signals only.
    for cid, scanner in (("secrets", secrets_scan), ("sca", sca_scan),
                         ("iac", iac_check)):
        raw = _call_tool(scanner, target=repo)
        compact = raw.replace(" ", "")
        if "binarynotfound" not in compact.lower() and '"skipped":true' not in compact:
            _add_signal(cid, raw)
            _tools_used.append({"secrets": "secrets_scan", "sca": "sca_scan",
                                "iac": "iac_check"}[cid])

    def _codegraph_stage() -> tuple[list[tuple[str, str, bool]], list[str]]:
        from cerberus.codegraph._index import index_build, index_summary
        from cerberus.tools.codegraph import framework_routes, get_routing_manifest

        extra: list[tuple[str, str, bool]] = []
        used: list[str] = []
        db_path = index_build(repo)
        if db_path:
            extra.append(("codegraph-index", index_summary(repo), False))
            used.append("codegraph_index")
        routes = _call_tool(framework_routes, root=repo)
        # "(no …" covers "(no matches)" and the no-index guidance string the
        # gate returns now that the grep fallback is gone; real route output
        # always starts with a "file:line: [route]" line.
        if routes and not routes.startswith("(no ") and "(unavailable" not in routes:
            extra.append(("routes", routes, True))
            used.append("framework_routes")
        else:
            n_routes = _call_tool(get_routing_manifest)
            if (n_routes and not n_routes.startswith("ERROR")
                    and "(no framework routes declared)" not in n_routes
                    and "None" not in n_routes
                    and "(unavailable" not in n_routes):
                extra.append(("routes", n_routes, True))
                used.append("get_routing_manifest")
        return extra, used

    _extra, _used = runner("codegraph_signals", _codegraph_stage,
                           default=([], []), logger=logger)
    for cid, body, keep in _extra:
        _add_signal(cid, body, keep_text=keep)
    _tools_used.extend(_used)

    return {"files": files, "candidates": cands, "signals": signals_out,
            "tools_used": sorted(set(_tools_used))}


def threat_summary(repo: str, signals: list[dict] | None) -> str:
    """One-line STRIDE summary from indexer signals. Shared by the scan's
    threat_model_node and `cerberus threat-model` so the CLI bootstrap sees the
    same stack/route context the scan path does."""
    from cerberus.threat.util import signal_text
    signals = [s for s in (signals or []) if isinstance(s, dict)]
    pre = signal_text(signals, "prefilter")
    classes = [line[3:] for line in pre.splitlines() if line.startswith("## ")]
    routes = signal_text(signals, "routes")
    n_routes = len([ln for ln in routes.splitlines() if ln.strip()]) if routes else 0
    return (
        f"Threat model for {repo} | stack: unknown stack | entry points: ~{n_routes} routes | "
        f"prefilter signal classes: {', '.join(classes) or 'none'} | "
        "STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), "
        "info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR)."
    )


def threat_model_node(state: ScanState, agent_registry: Any = None) -> dict:
    from cerberus.config import effective_model

    repo = state.get("repo", ".") or "."
    signals = [s for s in (state.get("signals") or []) if isinstance(s, dict)]
    files = [f for f in (state.get("files") or []) if f]
    summary = threat_summary(repo, signals)
    out: dict = {}
    if agent_registry is not None:
        _model = effective_model(state.get("cfg") or {}, "hunter", "threat")
        for _r in ("threat:researcher", "threat:historian", "threat:synthesizer"):
            agent_registry.create(_r, _r, parent_stage="threat_model",
                                  model=_model, state=AgentState.queued)
            agent_registry.transition(_r, AgentState.running,
                                      parent_stage="threat_model")
    # Artifact writing stays in the CLI (single writer).

    def _threat_doc_stage() -> dict:
        from cerberus import threat as _th
        from cerberus.config import api_key_present, effective_config

        _cfg2 = _node_cfg(state)
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
                md = _th.bootstrap_threat(repo, files, signals, summary,
                                          vulns=vulns, vulns_path=vulns_path)
                source = "bootstrap" if md.strip() else "summary"
            except Exception:
                md, source = "", "summary"
        if vulns_path and not vulns:
            print(f"warning: --vulns {vulns_path} parsed to 0 rows "
                  "(missing or unrecognized format); continuing on git history",
                  file=sys.stderr)
        enrich_meta: dict = {}
        _enrich_wanted = (
            source not in ("override", "repo-file")
            and bool(effective_config(_cfg2)["threat"]["llm_enrich"]))
        if _enrich_wanted and not api_key_present(_cfg2):
            enrich_meta = {"skipped": "API_KEY not set"}
        elif _enrich_wanted:
            try:
                enriched, enrich_meta = _th.enrich_threat(
                    repo, files, signals, summary, md, _cfg2,
                    vulns=vulns, vulns_path=vulns_path,
                    measured_facts=_th.measured_facts(
                        repo, files, signals, summary, vulns))
                if enriched.strip():
                    md = enriched
            except Exception as e:
                enrich_meta = {"error": f"{type(e).__name__}: {e}"}
        stage_out: dict = {"threat_model_source": source}
        if md.strip():
            if source not in ("override", "repo-file"):
                md = _th.attach_signal_paths(md, signals)
            stage_out["threat_model_md"] = md
            if enrich_meta:
                stage_out["threat_enrich"] = enrich_meta
            from cerberus.agents.deep import is_fatal_error

            try:
                stage_out["threat_quality"] = _th.threat_quality(md, files, signals)
            except Exception as e:
                # Absence of a score is a valid degrade; a harness bug must not hide.
                if is_fatal_error(e):
                    raise
                logger.warning("threat quality check failed: %s", e)
            try:
                stage_out["threat_verified"] = _th.verify_threat(repo, md, files, signals)
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

    from cerberus.fallback import runner

    _stage_updates = runner("threat_model.doc", _threat_doc_probe,
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
    from cerberus.config import api_key_present, effective_config, effective_model

    cfg = _node_cfg(state)
    if not api_key_present(cfg):
        _stage_detail("hunters",
                      "[hunters] skipped: no API_KEY — files need manual review")
        return {"findings": [], "fanout_payloads": []}
    payload_files = list(state.get("files", []))
    payload_cands = list(state.get("candidates", []))
    threat_md = state.get("threat_model_md", "") or ""
    _focus = state.get("focus", []) or []
    if isinstance(_focus, str):
        _focus = [f.strip() for f in _focus.split(",") if f.strip()]
    units: list[dict] = []
    _enable_agent = effective_config(cfg).get("partition", {}).get("enable_agent", False)
    if _enable_agent:
        if agent_registry is not None:
            agent_registry.create("partitioner", "partitioner", parent_stage="partition",
                                  model=effective_model(cfg, "hunter", "partitioner"),
                                  state=AgentState.queued)
            agent_registry.transition("partitioner", AgentState.running,
                                      parent_stage="partition")

        _partition_exc: dict = {}

        def _partition_probe() -> list[dict]:
            from cerberus.partitioning.llm import run_partitioner_agent

            try:
                return run_partitioner_agent(
                    state.get("repo", "."), payload_files, payload_cands, cfg,
                    threat_md=threat_md)
            except Exception as e:
                _partition_exc["exc"] = e
                raise

        from cerberus.fallback import runner

        units = runner("partitioner", _partition_probe, default=[],
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
        from cerberus.partitioning import partition_units
        units = partition_units(state.get("repo", "."), payload_files, cfg)
    if not units:
        return {"findings": [], "fanout_payloads": []}
    from cerberus.partitioning import verify_partition
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
                for u in units if not u.get("name", "").startswith("vendor")]}


def _validate_inline(findings: list[dict], cfg: dict, threat_md: str,
                     votes: int | None, label: str,
                     repo: str | None = None,
                     cell_offset: int = 0,
                     agent_registry: Any = None) -> list[dict]:
    from cerberus.agents.validator import run_validation

    try:
        return run_validation(findings, cfg or {}, threat_md or "", votes,
                              units=[{"name": str(label)}], max_workers=1,
                              repo=repo, cell_offset=cell_offset,
                              agent_registry=agent_registry)
    except Exception as e:
        from cerberus.agents.deep import is_fatal_error

        # Fail-open for infra noise; a config-class failure must sink the scan.
        if is_fatal_error(e):
            raise
        return [{"status": "needs-review", **f} for f in (findings or [])]


def hunter_worker(state: dict) -> dict:
    import time as _time

    from cerberus.agents.hunters import _fallback_finding, _run_unit

    repo = state.get("repo", ".")
    files = list(state.get("files", []))
    candidates = list(state.get("candidates", []))
    cfg = dict(state.get("cfg", {}) or {})
    threat_md = state.get("threat_model_md", "") or ""
    focus = state.get("focus", []) or []
    prior = state.get("prior_findings")
    _tools: list = []
    t0 = _time.time()
    label = state.get("unit") or "unit"
    try:
        out = _run_unit({"name": label}, repo, files, candidates, cfg,
                        threat_md=threat_md, focus=focus,
                        prior_findings=(prior
                                        if isinstance(prior, list) else None),
                        _tools_out=_tools)
        # Stamp the partition so validation runs one validator per unit.
        for f in out:
            if not f.get("unit"):
                f["unit"] = str(label)
        _stage_detail("hunters",
                      f"[hunters] {label}: {len(out)} findings in "
                      f"{_time.time()-t0:.0f}s")
        ret = {"findings": out,
               "tools_used": sorted({str(t) for t in _tools})}
        return ret
    except Exception as e:
        # A config error must sink the scan, not become a unit fallback finding.
        from cerberus.agents.deep import is_fatal_error

        if is_fatal_error(e):
            raise
        _stage_detail("hunters",
                      f"[hunters] {label}: ERROR {type(e).__name__} after "
                      f"{_time.time()-t0:.0f}s")
        fb = _fallback_finding(str(label), repo, files, str(e))
        fb["unit"] = str(label)
        return {"findings": [fb]}


def _norm_key(f: dict) -> str:
    fid = str(f.get("id", "") or "").strip()
    if fid:
        return f"id:{fid}"
    path = (str(f.get("path", "")).strip().lower()
            .replace("\\", "/").lstrip("./"))
    return (f"{path}|{safe_int(f.get('start_line'))}"
            f"|{safe_int(f.get('end_line'))}")


def _merge_dup(a: dict, b: dict) -> dict:
    prio = MERGE_PRIO
    # Unknown/missing status ranks as needs-review (-1): a graded "confirmed"
    # verdict must never lose an unmergeable-title to an ungraded row. This
    # arm is load-bearing — status is not guaranteed on every producer path.
    a_stat = prio.get(a.get("status"), -1)
    b_stat = prio.get(b.get("status"), -1)
    if a_stat > b_stat:
        keep, drop = a, b
    elif b_stat > a_stat:
        keep, drop = b, a
    else:
        # Tie-breaker: prioritize finding with proven PoC receipt
        a_succ = safe_int(((a.get("poc") or {}).get("receipt") or {}).get("successes", 0))
        b_succ = safe_int(((b.get("poc") or {}).get("receipt") or {}).get("successes", 0))
        keep, drop = (a, b) if a_succ >= b_succ else (b, a)
    g = dict(keep)
    drop_poc = drop.get("poc") if isinstance(drop.get("poc"), dict) else {}
    keep_poc = g.get("poc") if isinstance(g.get("poc"), dict) else {}
    if drop_poc.get("status") == "proven" and keep_poc.get("status") != "proven":
        g["poc"] = drop_poc
        if g.get("status") != "fp":
            g["status"] = "confirmed"
    elif not keep_poc and drop_poc:
        g["poc"] = drop_poc
    try:
        g["confidence"] = max(float(keep.get("confidence", 0) or 0),
                              float(drop.get("confidence", 0) or 0))
    except (TypeError, ValueError):
        pass
    ev = str(g.get("evidence") or "")
    extra = str(drop.get("evidence") or "")
    if extra:
        segments = ev.split(" | alt: ")
        if extra not in segments:
            g["evidence"] = f"{ev} | alt: {extra}" if ev else extra
    return g


def system_pass_node(state: ScanState, agent_registry: Any = None) -> dict:
    findings = list(state.get("findings", []))
    from cerberus.config import api_key_present, as_bool, effective_model

    _cfg_sys = _node_cfg(state)
    if not as_bool((_cfg_sys.get("hunter") or {}).get("system_pass", True)):
        return {}
    if not api_key_present(_cfg_sys):
        return {}
    if agent_registry is not None:
        agent_registry.create(
            "system-pass", "system-pass", parent_stage="system_pass",
            model=effective_model(_cfg_sys, "hunter"), state=AgentState.queued)
        agent_registry.transition("system-pass", AgentState.running,
                                  parent_stage="system_pass")
    import time as _time
    t0 = _time.time()

    _sysfail: dict = {}
    _sysstats: dict = {}

    def _system_pass_probe() -> tuple[list[dict], list[str]]:
        try:
            from cerberus.agents.hunters import _run_system_pass

            focus = state.get("focus", []) or []
            _tools: list = []
            out = _run_system_pass(state.get("repo", "."),
                                   list(state.get("files", [])),
                                   findings,
                                   state.get("threat_model_md", "") or "",
                                   _cfg_sys, focus, _tools,
                                   stats_out=_sysstats,
                                   agent_registry=agent_registry)
            detail = (f"[system-pass] +{len(out)} cross-unit findings in "
                      f"{_time.time()-t0:.0f}s · "
                      f"{int(_sysstats.get('passes', 1))} pass(es)")
            if _sysstats.get("early_stop"):
                detail += " · early-stop"
            _stage_detail("system_pass", detail)
            return out, sorted({str(t) for t in _tools})
        except Exception as e:
            _stage_detail("system_pass",
                          f"[system-pass] ERROR {type(e).__name__} after "
                          f"{_time.time()-t0:.0f}s")
            _sysfail["fail"] = True
            raise

    from cerberus.fallback import runner

    try:
        out, _sys_tools = runner("system_pass", _system_pass_probe,
                                 default=([], []), logger=logger)
    except Exception as e:
        if agent_registry is not None:
            agent_registry.transition("system-pass", AgentState.failed,
                                      parent_stage="system_pass", error=str(e))
        raise
    if _sysfail.get("fail"):
        if agent_registry is not None:
            agent_registry.transition("system-pass", AgentState.failed,
                                      parent_stage="system_pass",
                                      error="system pass failed open")
        return {}
    if agent_registry is not None:
        msg = f"{int(_sysstats.get('passes', 1))} pass(es)"
        if _sysstats.get("early_stop"):
            msg += " · early-stop"
        agent_registry.transition("system-pass", AgentState.succeeded,
                                  parent_stage="system_pass", message=msg)
    ret: dict = {"findings": out or []}
    if _sys_tools:
        ret["tools_used"] = _sys_tools
    return ret


def aggregator_node(state: ScanState) -> dict:
    rows = (coerce_findings(list(state.get("candidates", [])))
            + coerce_findings(list(state.get("findings", []))))
    seen: dict[str, dict] = {}
    for f in rows:
        key = _norm_key(f)
        seen[key] = _merge_dup(seen[key], f) if key in seen else f
    out: list[dict] = list(seen.values())
    # Concurrent window: queue only findings with no validated counterpart (same norm-key); never validated twice.
    done_keys = {_norm_key(f) for f in (state.get("verified", []) or [])}
    pending = [f for f in out if _norm_key(f) not in done_keys]
    return {"pending": pending}


def validator_node(state: ScanState, agent_registry: Any = None) -> dict:
    from cerberus.agents.validator import run_validation
    from cerberus.config import effective_model

    cfg = _node_cfg(state)
    pending = [dict(f) for f in (state.get("pending", []) or [])]
    if agent_registry is not None:
        agent_registry.create("validator", "validator", parent_stage="validation",
                              model=effective_model(cfg, "validator"),
                              state=AgentState.queued)
        agent_registry.transition("validator", AgentState.running,
                                  parent_stage="validation")
    import time as _time
    t0 = _time.time()
    _stage_detail("validator",
                  f"[validator] validating {len(pending)} remaining findings "
                  f"({len(state.get('verified', []) or [])} already "
                  f"validated)...")
    try:
        units = []
        for p in (state.get("fanout_payloads", []) or []):
            if isinstance(p, dict) and p.get("unit"):
                units.append({"name": str(p["unit"]),
                              "files": list(p.get("files", []))})
        validated = run_validation(
            pending, cfg, state.get("threat_model_md", "") or "",
            state.get("votes_override"), units=units,
            repo=state.get("repo"), agent_registry=agent_registry)
        if agent_registry is not None:
            agent_registry.transition("validator", AgentState.succeeded,
                                      parent_stage="validation")
    except Exception as e:
        from cerberus.agents.deep import is_fatal_error

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
    _stage_detail("validator",
                  f"[validator] done: {len(validated)} in "
                  f"{_time.time()-t0:.0f}s "
                  f"{dict(_Counter(f.get('status') for f in validated))}")
    return {"verified": validated}


def _is_hot(f: dict) -> bool:
    return f.get("severity") in ("critical", "high") and f.get("status") == "confirmed"


def confirm_critical_step(state: ScanState,
                          confirm: Callable[[dict], bool] | None) -> dict:
    verified = list(state.get("verified", []) or [])
    hot = [f for f in verified if _is_hot(f)]
    if not hot:
        return {}
    payload = {
        "question": "confirmed critical/high findings — proceed?",
        "findings": [{"id": f.get("id"), "title": f.get("title"),
                      "path": f.get("path"),
                      "start_line": f.get("start_line")} for f in hot[:20]],
    }
    # If a confirmation callback is explicitly provided, invoke it
    if confirm is not None:
        try:
            confirm(payload)
        except Exception as e:
            logger.warning("confirm callback error: %s", e)
    # Never demote findings: preserve verified state as confirmed
    return {}


def triage_node(state: ScanState, agent_registry: Any = None) -> dict:
    import time as _time

    from cerberus.config import effective_model

    t0 = _time.time()
    verified = list(state.get("verified", []))
    if not verified:
        return {}
    _cfg4 = _node_cfg(state)
    if agent_registry is not None:
        agent_registry.create("triage:1", "triage:1", parent_stage="triage",
                              model=effective_model(_cfg4, "validator", "triager"),
                              state=AgentState.queued)
        agent_registry.transition("triage:1", AgentState.running,
                                  parent_stage="triage")
    try:
        from cerberus.agents.triage import run_triage
        res = run_triage(verified, _cfg4, state.get("threat_model_md", "") or "",
                         repo=state.get("repo", "."))
        out = res.get("findings", verified)
        if agent_registry is not None:
            agent_registry.transition("triage:1", AgentState.succeeded,
                                      parent_stage="triage")
        _stage_detail("triage",
                      f"[triage] {len(out)} findings, "
                      f"{res.get('n_duplicates', 0)} duplicates, "
                      f"{res.get('triage_llm_calls', 0)} LLM calls in "
                      f"{_time.time()-t0:.0f}s")
        ret: dict = {"verified": Overwrite(out)}
        if res.get("triage_log"):
            ret["triage_log"] = res["triage_log"]
        return ret
    except Exception as e:
        from cerberus.agents.deep import is_fatal_error

        if is_fatal_error(e):
            if agent_registry is not None:
                agent_registry.transition("triage:1", AgentState.failed,
                                          parent_stage="triage", error=str(e))
            raise
        if agent_registry is not None:
            agent_registry.transition("triage:1", AgentState.failed,
                                      parent_stage="triage", error=str(e))
        _stage_detail("triage",
                      f"[triage] ERROR {type(e).__name__} after "
                      f"{_time.time()-t0:.0f}s (verified untouched)")
        return {}


def poc_node(state: ScanState, agent_registry: Any = None) -> dict:
    """Dedicated post-triage PoC generation stage on canonical non-FP findings."""
    import time as _time

    from cerberus.config import as_bool

    t0 = _time.time()
    verified = list(state.get("verified", []))
    if not verified:
        return {}

    _cfg = _node_cfg(state)
    poc_cfg = _cfg.get("poc") if isinstance(_cfg.get("poc"), dict) else {}
    if not as_bool(poc_cfg.get("enabled", True)):
        return {}

    repo = state.get("repo", ".")
    try:
        from cerberus.agents.poc_generator import run_poc_generation
        from cerberus.sandbox import acquired_backend

        with acquired_backend(_cfg, repo, label="poc-generator") as backend:
            if backend is None:
                return {}
            out = run_poc_generation(
                verified, cfg=_cfg, backend=backend, repo=repo,
                threat_md=state.get("threat_model_md", "") or "",
                agent_registry=agent_registry,
            )
        proven = sum(1 for f in out if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "proven")
        total_pocs = sum(1 for f in out if f.get("poc"))
        elapsed = _time.time() - t0
        detail_msg = f"{proven}/{total_pocs} proven ({elapsed:.0f}s)" if total_pocs else f"completed in {elapsed:.0f}s"
        _stage_detail("poc_generator", detail_msg)
        return {"verified": Overwrite(out)}
    except Exception as exc:
        from cerberus.agents.deep import is_fatal_error
        if is_fatal_error(exc):
            raise
        logger.warning("PoC generation node encountered error (failing open): %s", exc)
        return {}


def threat_update_node(state: ScanState) -> dict:
    # State only; the CLI is the single file writer.
    md = state.get("threat_model_md", "") or ""
    if not md.strip():
        return {}
    from cerberus.fallback import runner

    def _threat_update_stage() -> dict:
        from cerberus import threat as _th5

        updated = _th5.update_threat_with_findings(
            md, list(state.get("verified", [])), state.get("repo", "."))
        if updated.strip() and updated != md:
            return {"threat_model_md": updated}
        return {}

    return runner("threat_update", _threat_update_stage,
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


def _reset_agent_scratch_phase(repo: str) -> None:
    # Hygiene only: config-gated, best-effort — NOT a security boundary.
    try:
        from cerberus.config import as_bool, get_config
        from cerberus.sandbox import reset_agent_scratch

        cfg = get_config()
        sandbox = cfg.get("sandbox")
        sandbox = sandbox if isinstance(sandbox, dict) else {}
        enabled = sandbox.get("reset_agent_scratch", True)
        if not as_bool(enabled):
            return
        for err in reset_agent_scratch(repo):
            print(f"[sandbox] {err}", file=sys.stderr)
    except Exception:
        pass


def _sweep_orphan_sandboxes() -> None:
    try:
        from cerberus.config import as_bool, get_config
        from cerberus.sandbox import sweep_orphans

        cfg = get_config()
        sandbox = cfg.get("sandbox")
        sandbox = sandbox if isinstance(sandbox, dict) else {}
        enabled = sandbox.get("sweep_orphans", True)
        if not as_bool(enabled):
            return
        removed = sweep_orphans()
        if removed:
            print(f"[sandbox] reaped {len(removed)} sandbox(es) left by a "
                  f"killed run: {', '.join(sorted(removed))}", file=sys.stderr)
    except Exception:
        pass


def _fan_out_hunters(state: dict, max_workers: int,
                     agent_registry: Any = None,
                     stats_out: dict | None = None) -> dict[str, float]:
    import time as _time

    from cerberus.agents.validator import _evidence_gate_findings, _route_finding
    from cerberus.config import effective_config, effective_model

    payloads = list(state.get("fanout_payloads", []) or [])
    busy = {"hunt": 0.0, "validation": 0.0, "system_pass": 0.0}
    if not payloads:
        return busy
    shared = {k: state.get(k) for k in ("repo", "threat_model_md", "focus",
                                        "votes_override")}
    from cerberus.agents.hunters import _EMPTY_PASS_STREAK

    seen_units: dict[str, int] = {}
    for seq, p in enumerate(payloads):
        unit = str(p.get("unit", "unit"))
        n = seen_units.get(unit, 0)
        seen_units[unit] = n + 1
        p["_ukey"] = unit if n == 0 else f"{unit}:{n}"
        p["_seq"] = seq

    if agent_registry is not None:
        for p in payloads:
            unit = str(p.get("unit", "unit"))
            cfg = p.get("cfg") or state.get("cfg") or {}
            model = effective_model(cfg, "hunter")
            agent_registry.create("hunter:" + p["_ukey"], "hunter", unit=unit,
                                  parent_stage="hunters", model=model,
                                  state=AgentState.queued)

    def _hunt_one_unit(p: dict) -> dict:
        aid = "hunter:" + p["_ukey"]
        cfg = p.get("cfg") or state.get("cfg") or {}
        model = effective_model(cfg, "hunter")
        if agent_registry is not None:
            agent_registry.transition(aid, AgentState.running,
                                      parent_stage="hunters", model=model,
                                      message="unit started")
        all_findings: list = []
        tools_all: set = set()
        passes_run = 0
        stopped_early = False
        try:
            merged = dict(p)
            for k, v in shared.items():
                merged.setdefault(k, v)
            reruns = max(0, int(
                effective_config(cfg)["hunter"].get("reruns", 0)))
            passes = 1 + reruns
            empty_streak = 0
            for attempt in range(passes):
                passes_run = attempt + 1
                if attempt:
                    merged_pass = dict(merged)
                    merged_pass["prior_findings"] = [
                        f for f in all_findings
                        if not str(f.get("id", "")).endswith("-fallback")]
                else:
                    merged_pass = merged
                if agent_registry is not None:
                    agent_registry.transition(
                        aid, AgentState.running, parent_stage="hunters",
                        model=model,
                        message=f"pass {attempt + 1}/{passes}"
                                + (" · rerun" if attempt else ""))
                res = hunter_worker(merged_pass)
                res = res if isinstance(res, dict) else {}
                tools_all.update(res.get("tools_used") or [])
                pass_findings = list(res.get("findings") or [])
                all_findings.extend(pass_findings)
                _submit_bundles(p, pass_findings, final=False)
                if pass_findings:
                    empty_streak = 0
                else:
                    empty_streak += 1
                    if empty_streak >= _EMPTY_PASS_STREAK:
                        stopped_early = True
                        break
            _submit_bundles(p, [], final=True)
            if agent_registry is not None:
                msg = f"completed · {passes_run} pass(es)"
                if stopped_early:
                    msg += " · early-stop"
                agent_registry.transition(aid, AgentState.succeeded,
                                          parent_stage="hunters",
                                          message=msg,
                                          model=model,
                                          findings_produced=len(all_findings))
            if stats_out is not None:
                stats_out[p["_ukey"]] = {"passes": passes_run,
                                         "early_stop": stopped_early,
                                         "findings": len(all_findings)}
            return {"findings": all_findings,
                    "tools_used": sorted(tools_all)}
        except Exception as e:  # pragma: no cover - hunter_worker is fail-open
            from cerberus.agents.deep import is_fatal_error

            # Operator config errors must sink the scan, not become fallbacks.
            if is_fatal_error(e):
                if agent_registry is not None:
                    agent_registry.transition(aid, AgentState.failed,
                                              parent_stage="hunters",
                                              model=model, error=str(e))
                raise
            from cerberus.agents.hunters import _fallback_finding
            fb = _fallback_finding(str(p.get("unit", "unit")), p.get("repo", "."),
                                   list(p.get("files", [])), str(e))
            fb["unit"] = str(p.get("unit", "unit"))
            if agent_registry is not None:
                agent_registry.transition(aid, AgentState.failed,
                                          parent_stage="hunters",
                                          model=model, error=str(e))
            try:
                _submit_bundles(p, [], final=True)
            except Exception:
                pass
            if stats_out is not None:
                stats_out[p["_ukey"]] = {"passes": max(1, passes_run),
                                         "early_stop": False,
                                         "findings": len(all_findings) + 1}
            return {"findings": all_findings + [fb],
                    "tools_used": sorted(tools_all)}

    def _ctx(p: dict) -> dict:
        merged = dict(p)
        for k, v in shared.items():
            merged.setdefault(k, v)
        return merged

    def _timed(fn, *a, _on_start=None, **kw):
        if _on_start is not None:
            try:
                _on_start()
            except Exception:
                pass
        t0 = _time.perf_counter()
        out = fn(*a, **kw)
        return out, _time.perf_counter() - t0

    def _flip_unit_running(unit_key: str) -> None:
        if agent_registry is not None:
            agent_registry.transition("validator:" + unit_key,
                                      AgentState.running,
                                      parent_stage="validation",
                                      if_changed=True)

    def _route_findings(findings: list, cfg: dict) -> tuple[list, list]:
        try:
            gated = _evidence_gate_findings(list(findings))
            if len(gated) != len(findings):
                raise ValueError("gate/cardinality drift")
            llm_items = [f for f, g in zip(findings, gated)
                         if _route_finding(g)[0] == "llm"]
            passthrough = [f for f, g in zip(findings, gated)
                           if _route_finding(g)[0] != "llm"]
        except Exception:
            llm_items, passthrough = list(findings), []
        return llm_items, passthrough

    _bundle_lock = threading.Lock()
    bundles_buf: dict = {}
    chunk_offsets: dict = {}
    validators_created: set = set()

    def _submit_chunk(p: dict, chunk: list, cell_offset: int,
                      merged: dict, cfg: dict) -> None:
        ukey = p["_ukey"]
        unit = str(p.get("unit", "unit"))
        aid = "validator:" + ukey
        threat_md = merged.get("threat_model_md") or ""
        votes = merged.get("votes_override")
        repo = merged.get("repo") or state.get("repo", ".")
        with _bundle_lock:
            if agent_registry is not None and ukey not in validators_created:
                agent_registry.create(aid, "validator", unit=unit,
                                      parent_stage="validation",
                                      model=effective_model(cfg, "validator"),
                                      state=AgentState.queued)
                validators_created.add(ukey)
            remaining_bundles[ukey] = remaining_bundles.get(ukey, 0) + 1
        fut = executor.submit(_timed, _validate_inline, chunk, cfg,
                              threat_md, votes, unit, repo=repo,
                              cell_offset=cell_offset,
                              agent_registry=agent_registry,
                              _on_start=lambda _u=ukey: _flip_unit_running(_u))
        with _bundle_lock:
            pending[fut] = ("validation", p, cell_offset)

    def _submit_bundles(p: dict, findings: list, *, final: bool = False) -> None:
        """Buffer this pass's findings and submit every full cell_size chunk
        now; ``final`` also flushes the remainder.

        One call per unit with all its findings (reruns = 0) reproduces the
        pre-rerun chunking exactly; with reruns the full cells stream to
        validation while the unit's later passes keep hunting."""
        merged = _ctx(p)
        cfg = merged.get("cfg") or state.get("cfg") or {}
        efcfg = effective_config(cfg)
        size = int(efcfg["verification"]["cell_size"])
        couple = bool(efcfg["verification"]["couple_remainders"])
        llm_items, passthrough = _route_findings(findings, cfg)
        buf = bundles_buf.setdefault(p["_ukey"], {"llm": [], "pt": []})
        buf["llm"].extend(llm_items)
        buf["pt"].extend(passthrough)
        offset = chunk_offsets.get(p["_ukey"], 0)
        while len(buf["llm"]) >= size:
            chunk = buf["llm"][:size]
            del buf["llm"][:size]
            if buf["pt"] and not couple:
                chunk = chunk + list(buf["pt"])
                buf["pt"].clear()
            _submit_chunk(p, chunk, offset, merged, cfg)
            offset += 1
        if final:
            tail = list(buf["llm"]) + list(buf["pt"])
            buf["llm"].clear()
            buf["pt"].clear()
            if tail and not couple:
                _submit_chunk(p, tail, offset, merged, cfg)
                offset += 1
        chunk_offsets[p["_ukey"]] = offset

    executor = ThreadPoolExecutor(max_workers=max(1, int(max_workers)))
    pending: dict = {}
    remaining_bundles: dict[str, int] = {}
    hunt_buf: dict[int, dict] = {}
    hunt_next = 0

    def _flush_hunts() -> None:
        nonlocal hunt_next
        while hunt_next in hunt_buf:
            apply_update(state, hunt_buf.pop(hunt_next))
            hunt_next += 1

    try:
        for p in payloads:
            fut = executor.submit(_timed, _hunt_one_unit, p)
            with _bundle_lock:
                pending[fut] = ("hunt", p, None)
        while pending:
            with _bundle_lock:
                snapshot = set(pending)
            done, _ = wait(snapshot, return_when=FIRST_COMPLETED)
            for fut in done:
                with _bundle_lock:
                    kind, p, _k = pending.pop(fut)
                try:
                    res, elapsed = fut.result()
                except BaseException as e:
                    if kind == "validation" and agent_registry is not None:
                        agent_registry.transition(
                            "validator:" + p["_ukey"],
                            AgentState.failed, parent_stage="validation",
                            error=str(e))
                    for r in hunt_buf.values():
                        apply_update(state, r)
                    hunt_buf.clear()
                    executor.shutdown(wait=True, cancel_futures=True)
                    raise
                busy[kind] += elapsed
                if kind == "hunt":
                    res = res if isinstance(res, dict) else {}
                    hunt_buf[p["_seq"]] = res
                    _flush_hunts()
                    if hunt_next == len(payloads):
                        sfut = executor.submit(
                            _timed, system_pass_node, state,
                            agent_registry=agent_registry)
                        with _bundle_lock:
                            pending[sfut] = ("system_pass", p, None)
                elif kind == "validation":
                    apply_update(state, {"verified": res or []})
                    ukey = p["_ukey"]
                    with _bundle_lock:
                        done = False
                        if ukey in remaining_bundles:
                            remaining_bundles[ukey] -= 1
                            done = remaining_bundles[ukey] <= 0
                            if done:
                                del remaining_bundles[ukey]
                    if done and agent_registry is not None:
                        agent_registry.transition(
                            "validator:" + ukey, AgentState.succeeded,
                            parent_stage="validation", message="completed")
                else:
                    apply_update(state, res)
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    return busy


def run_scan(repo: str, confirm_critical: bool = False,
             threat_model_override: str | None = None,
             focus: list[str] | str | None = None,
             votes: int | None = None,
             vulns_file: str | None = None,
             confirm: Callable[[dict], bool] | None = None,
             agent_events_path: Any = None,
             progress: Any = None,
             cfg: dict | None = None,
             ) -> dict[str, Any]:
    global _PROGRESS

    _prev_progress = _get_progress()
    _PROGRESS = progress
    _THREAD_LOCAL.progress = progress
    _prev_target_repo = os.environ.get("TARGET_REPO")
    try:
        repo = str(canonical_repo(repo))
        os.environ["TARGET_REPO"] = repo
        from cerberus.config import get_config, set_config

        if cfg is None:
            try:
                cfg = get_config()
            except Exception as cfg_err:
                print(f"warning: config load failed ({type(cfg_err).__name__}: "
                      f"{cfg_err}); continuing with packaged defaults",
                      file=sys.stderr, flush=True)
                logger.debug("config load failed; using defaults: %s", cfg_err)
                try:
                    cfg = set_config({})
                except Exception as cfg_err2:
                    logger.debug("defaults degrade failed: %s", cfg_err2)
                    cfg = {}
        else:
            cfg = set_config(cfg)
        _sweep_orphan_sandboxes()
        state: dict[str, Any] = {"repo": repo, "cfg": cfg}
        if _obs is not None:
            _scan_id = _obs.start_scan(repo, cfg=cfg)
            if _scan_id:
                state["scan_id"] = _scan_id

        try:
            _agent_registry = AgentRegistry(run_id=str(repo), sink=progress,
                                            events_path=agent_events_path)
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
            _t0 = _stage_time.time()
            try:
                res = fn()
                elapsed = round(_stage_time.time() - _t0, 3)
                prog = _get_progress()
                if prog is not None:
                    try:
                        prog.stage_done(name, elapsed, ok=True)
                    except Exception:
                        pass
                else:
                    print(f"[pipeline] <<< Stage '{name}' completed in {elapsed}s", file=sys.stderr, flush=True)
                return res
            except Exception as exc:
                elapsed = round(_stage_time.time() - _t0, 3)
                prog = _get_progress()
                if prog is not None:
                    try:
                        prog.stage_done(name, elapsed, ok=False,
                                        error=f"{type(exc).__name__}: {exc}")
                    except Exception:
                        pass
                else:
                    print(f"[pipeline] !!! Stage '{name}' failed after {elapsed}s: {exc}", file=sys.stderr, flush=True)
                raise
            finally:
                stage_timings[name] = round(_stage_time.time() - _t0, 3)

        def _hunters_stage():
            from cerberus.config import effective_config

            hunt_stats: dict = {}
            result = _fan_out_hunters(
                state, int(effective_config(_node_cfg(state))["concurrency"]),
                agent_registry=_agent_registry, stats_out=hunt_stats)
            prog = _get_progress()
            if prog is not None:
                try:
                    units = len(state.get("fanout_payloads") or [])
                    produced = len(state.get("findings") or [])
                    detail = f"{units} units · {produced} findings"
                    if hunt_stats:
                        total_passes = sum(
                            int(s.get("passes", 1)) for s in hunt_stats.values())
                        extra = total_passes - len(hunt_stats)
                        early = sum(1 for s in hunt_stats.values()
                                    if s.get("early_stop"))
                        if extra > 0:
                            detail += f" · {total_passes} pass(es) (incl. " \
                                      f"{extra} rerun" \
                                      f"{'s' if extra != 1 else ''}"
                            if early:
                                detail += (f", {early} early-stop"
                                           f"{'s' if early != 1 else ''}")
                            detail += ")"
                        elif early:
                            detail += (f" · {early} early-stop"
                                       f"{'s' if early != 1 else ''}")
                    _stage_detail("hunters", detail)
                except Exception:
                    pass
            return result

        _stage("indexer", lambda: apply_update(state, indexer_node(state)))
        _stage("threat_model", lambda: apply_update(state, threat_model_node(state, agent_registry=_agent_registry)))
        _stage("hunters_router", lambda: apply_update(state, hunters_router(state, agent_registry=_agent_registry)))
        if state.get("fanout_payloads"):
            _hunt_timings = _stage("hunters", _hunters_stage)
            for _flavor in ("hunt", "validation", "system_pass"):
                stage_timings[f"hunters:busy_{_flavor}"] = round(
                    float((_hunt_timings or {}).get(_flavor, 0.0)), 3)
        else:
            _stage("system_pass", lambda: apply_update(
                state, system_pass_node(state,
                                        agent_registry=_agent_registry)))
        _stage("aggregator", lambda: apply_update(state, aggregator_node(state)))
        _reset_agent_scratch_phase(state.get("repo", "."))
        _stage("validator", lambda: apply_update(state, validator_node(state, agent_registry=_agent_registry)))
        if state.get("confirm_critical"):
            _stage("confirm_critical", lambda: apply_update(state, confirm_critical_step(state, confirm)))
        _stage("triage", lambda: apply_update(state, triage_node(state, agent_registry=_agent_registry)))
        _stage("poc_generator", lambda: apply_update(state, poc_node(state, agent_registry=_agent_registry)))
        _stage("threat_update", lambda: apply_update(state, threat_update_node(state)))
        _stage("scorer", lambda: apply_update(state, scorer_node(state)))
        try:
            if _agent_registry is not None:
                state["agent_summary"] = _agent_registry.summary()
            state["stage_timings"] = dict(stage_timings)
        except Exception:
            pass
        if _obs is not None:
            _obs.finish_scan()
        return dict(state)
    finally:
        _PROGRESS = _prev_progress
        _THREAD_LOCAL.progress = _prev_progress
        if _prev_target_repo is None:
            os.environ.pop("TARGET_REPO", None)
        else:
            os.environ["TARGET_REPO"] = _prev_target_repo
