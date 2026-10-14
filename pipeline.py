"""Scan pipeline driver: indexer -> threat_model -> hunters(fan-out) -> system_pass
-> aggregator -> validator -> [confirm] -> triage -> threat_update -> scorer.

Plain Python, no graph runtime. Deterministic stages are functions of the
scan state; every LLM stage runs as a Deep Agent (harness/agents/deep.py).
The driver owns three things the old StateGraph did implicitly:

- state merging (append-only channels + explicit Overwrite),
- bounded parallel fan-out of hunter workers (the CONCURRENCY knob),
- the human confirm step: when `confirm_critical` is set and confirmed
  critical/high findings exist, the driver pauses between validation and
  triage and asks via a plain callback (the CLI prompts on stdin). A decline
  demotes those findings to needs-review; nothing is ever dropped.

Stage summary:
- indexer: deterministic file inventory + SAST (secrets/sca/iac, all graceful
  when binaries missing) + regex prefilter + codegraph context.
- threat_model: deterministic STRIDE-lite summary + THREAT_MODEL.md resolution
  (override > owner file > machine cache > deterministic floor) + LLM swarm
  enrichment on every scan (researcher + historian in parallel, then a
  synthesizer; owner files and overrides never rewritten).
- hunters: router partitions into logical units; one hunter_worker per unit
  hunts ALL classes (deep agent, fail-open). Without API_KEY the router emits
  per-file review tasks (fail-open for recall).
- aggregator: normalized-path + CWE + snippet-hash dedup + merge.
- validator: evidence gate + adversarial verdicts (other model). Confirmed
  false positives are recorded in the threat model's "Known false
  positives" section at the threat-update stage, not in a database.
- scorer: heuristic CVSS + rank (documented heuristic, static analysis only).
"""
from __future__ import annotations

import hashlib
import inspect
import logging
import os
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypedDict

from langgraph.types import Overwrite

from harness.schemas import SEVERITY_ORDER
from harness.progress import AgentRegistry, AgentState
CVSS_BASE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

# Channels that accumulate across stages (everything else is last-writer-wins).
_ADD_KEYS = ("candidates", "findings", "tools_used")

logger = logging.getLogger(__name__)


def _verified_reducer(left: list[dict] | None,
                      right: list[dict] | None) -> list[dict]:
    """Append-only accumulation.

    Pipelined writers (hunter workers, validator_node) return plain lists that
    accumulate. triage_node and scorer_node return Overwrite(out), which
    bypasses this reducer entirely (see apply_update) and swaps the channel.
    """
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
    # verified accumulates from two writers at different times: hunter
    # workers validate their own unit inline, and validator_node covers the
    # remainder (deterministic candidates + system-pass findings). Appends
    # only; aggregator joins raw findings against this list so nothing is
    # validated twice.
    verified: list[dict]
    # Raw merged findings not yet validated (single writer: aggregator).
    pending: list[dict]


def apply_update(state: dict, update: dict | None) -> dict:
    """Merge one stage's returned update into the scan state (in place).

    Mirrors the old channel semantics: candidates/findings/tools_used append,
    verified appends unless the stage returned Overwrite(...), and any other
    key is last-writer-wins.
    """
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
    """Call a pipeline node while tolerating test mocks that do not accept
    the agent-visibility keyword arguments."""
    try:
        signature = inspect.signature(node)
        params = signature.parameters
        has_var_keyword = any(p.kind == inspect.Parameter.VAR_KEYWORD
                              for p in params.values())
        if has_var_keyword:
            accepted = dict(kwargs)
        else:
            accepted = {k: v for k, v in kwargs.items() if k in params}
        return node(state, **accepted)
    except (TypeError, ValueError):
        try:
            return node(state, **kwargs)
        except TypeError:
            return node(state)


def _call_tool(tool_fn, **kwargs) -> str:
    """Call a @tool function directly (bypasses agent loop). Never raises."""
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
    """Return Graphify's live ignore predicate when its helper is available."""
    try:
        from graphify.detect import ignored_predicate
    except Exception:
        # The repository carries Graphify's source under ./graphify, while
        # minimal dev environments may not have the graphifyy package
        # installed. Load that source for its lightweight ignore helper when
        # the top-level name is currently only a namespace package.
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
        except Exception:
            return None
    try:
        return ignored_predicate(root)
    except Exception:
        return None


def _is_shebang_script(path: Path) -> bool:
    """True when an extensionless file is executable code, by shebang.

    Reads the head of the file (binary-safe, at most two lines, never raises)
    and answers True only when line 1 starts with "#!" and names a known
    interpreter. Only meaningful for files with no suffix and at most 256KB;
    anything else (or an unreadable file) is not a script.
    """
    try:
        if path.suffix or path.stat().st_size > _SHEBANG_MAX_BYTES:
            return False
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
            if not first.startswith("#!"):
                return False
            head = (first + fh.readline()).lower()
        return any(interp in head for interp in _SHEBANG_INTERPRETERS)
    except Exception:
        return False


def _inventory_files(base: Path) -> list[str]:
    """Inventory of repo-relative file paths under `base` (sorted, dedup-free).

    No file-count cap: large codebases are a supported target. Per-agent work
    is bounded downstream by the partition budget (harness/units.py
    partition_target), not by truncating the inventory. A `base` that is a
    plain file returns that path unless Graphify ignores it; a directory is
    walked recursively, pruning Graphify's ignored paths and symlinks, then
    skipping anything that is neither a known extension (or a Dockerfile) nor
    an extensionless shebang script -- entry points such as bin/www or manage
    would otherwise never reach a partition unit. If Graphify's Python ignore
    helper is unavailable, the shared skip-directory set still applies.
    """
    from harness.tools.graphify import GRAPHIFY_SKIP_DIRS
    if base.is_file():
        graphify_ignored = _graphify_ignore_predicate(base.parent)
        if graphify_ignored is not None:
            try:
                if graphify_ignored(base):
                    return []
            except Exception:
                pass
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
            if graphify_ignored is not None:
                try:
                    if graphify_ignored(directory):
                        continue
                except Exception:
                    pass
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
            if graphify_ignored is not None:
                try:
                    if graphify_ignored(f):
                        continue
                except Exception:
                    pass
            try:
                files.append(str(f.relative_to(base)))
            except ValueError:
                files.append(str(f))
    return sorted(files)


def indexer_node(state: ScanState) -> dict:
    from harness.tools.sast import (iac_check, sca_scan, secrets_scan,
                                    regex_prefilter)
    repo = state.get("repo", ".")
    # File inventory — no file-count cap: large codebases are a supported
    # target. Per-agent work is bounded downstream by the partition budget
    # (harness/units.py partition_target), not by truncating the inventory.
    base = Path(repo)
    files = _inventory_files(base)
    cands = [_info_candidate(
        "prefilter", "deterministic prefilter hits", repo,
        _call_tool(regex_prefilter, target=repo))]
    _tools_used = ["regex_prefilter"]
    # No whole-repo Semgrep/OpenGrep here: hunters run those scans themselves
    # on their own unit files (per-unit beats whole-repo: no git-filtering
    # surprises, no duplicated work). The indexer keeps fast signals +
    # context: prefilter, secrets/SCA/IaC envelopes, manifests, routes, and
    # template hints below.
    try:
        from harness.tools.sast import template_reflect_candidates
        _tpl = template_reflect_candidates(repo)
        if _tpl:
            _tools_used.append("template_reflect")
        for c in (_tpl):
            c.setdefault("status", "needs-review")
            cands.append(c)
    except Exception:
        pass
    # Secrets + SCA + IaC (raw envelope as one info candidate each when not skipped).
    for cid, title, raw in (
            ("secrets", "secrets scan raw", _call_tool(secrets_scan, target=repo)),
            ("sca", "SCA scan raw", _call_tool(sca_scan, target=repo)),
            ("iac", "IaC scan raw", _call_tool(iac_check, target=repo))):
        try:
            compact = raw.replace(" ", "")
            if "binarynotfound" not in compact.lower() and '"skipped":true' not in compact:
                cands.append(_info_candidate(cid, title, repo, raw))
                _tools_used.append({"secrets": "secrets_scan", "sca": "sca_scan",
                                    "iac": "iac_check"}[cid])
        except Exception:
            pass
    # Code graph context: manifest summary + framework routes as info candidates.
    try:
        from harness.tools.codegraph import framework_routes, manifest_parse
        man = _call_tool(manifest_parse, root=repo)
        if man and "(no manifests found)" not in man and "(unavailable" not in man:
            cands.append(_info_candidate("manifest", "repo manifest summary", repo, man))
            _tools_used.append("manifest_parse")
        routes = _call_tool(framework_routes, root=repo)
        if routes and "(no matches)" not in routes and "(unavailable" not in routes:
            cands.append(_info_candidate("routes", "framework routes", repo, routes))
            _tools_used.append("framework_routes")
    except Exception:
        pass
    # Graphify structural pass (opt-in, local Tree-sitter, graceful when absent).
    # Skipped at low effort. Complements grep: AST-proven structure, not sinks.
    try:
        from harness.tools import graphify as _gf
        try:
            from harness.config import load_config as _lc
            _gcfg = _lc()
        except Exception:
            _gcfg = {}
        _gen = str(((_gcfg.get("graphify") or {}).get("enabled", "1"))).lower()
        if (_gen in ("1", "true", "yes") and base.is_dir()):
            _gpath = _gf.graphify_build(repo)
            if _gpath:
                cands.append(_info_candidate(
                    "graphify", "code-graph structural summary", repo,
                    _gf.graphify_summary(repo)))
                _tools_used.append("graphify_build")
    except Exception:
        pass
    return {"files": files, "candidates": cands, "tools_used": sorted(set(_tools_used))}


def threat_model_node(state: ScanState, agent_registry: Any = None) -> dict:
    """Threat summary + full THREAT_MODEL.md resolution + LLM swarm enrichment.

    Summary candidate (id=threat-model) is unchanged for backward compat.
    Full text resolves: --threat-model override > <repo>/THREAT_MODEL.md >
    deterministic bootstrap floor. The bootstrap floor (and the machine cache
    from a prior scan) is then enriched by the LLM swarm on EVERY scan —
    enrichment is skipped only for owner-authored files and explicit
    overrides, which are authoritative human input. `--vulns <file>` rows are
    deterministic past-vulnerability evidence for section 4. Never raises;
    every stage degrades to the floor.
    """
    try:
        repo = state.get("repo", ".") or "."
        cands = [c for c in (state.get("candidates") or []) if isinstance(c, dict)]
        files = [f for f in (state.get("files") or []) if f]
    except Exception:
        repo, cands, files = ".", [], []
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
        for _r in ("threat-researcher", "threat-historian", "threat-synthesizer"):
            try:
                agent_registry.create(_r, _r, parent_stage="threat_model",
                                     state=AgentState.queued)
                agent_registry.transition(_r, AgentState.running,
                                         parent_stage="threat_model")
            except Exception:
                pass
    # Full-text resolution (plan-1345 M1). Artifact writing stays in CLI (single writer).
    try:
        from harness import threat as _th

        try:
            from harness.config import load_config as _lc2
            _cfg2 = _lc2()
        except Exception:
            _cfg2 = {}
        override = state.get("threat_model_override") or ""
        vulns_path = state.get("vulns_file") or ""
        try:
            vulns = _th.parse_vulns_file(vulns_path) if vulns_path else []
        except Exception:
            vulns = []
        source, md = _th.load_threat(repo, override=override or None, cfg=_cfg2)
        # STALE CACHE GUARD: a loaded document must satisfy the 8-section
        # schema. 50 pre-migration caches still carry the old "In-scope
        # classes" headings and would otherwise be fed to every consumer
        # while the gates score them 9/100. --vulns invalidates the cache
        # too (the cached doc lacks the supplied evidence base).
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
        # LLM swarm enrichment (default on). Owner files and explicit
        # overrides are authoritative: never rewrite human-authored input.
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
        if agent_registry is not None:
            for _r in ("threat-researcher", "threat-historian", "threat-synthesizer"):
                try:
                    agent_registry.transition(_r, AgentState.succeeded,
                                             parent_stage="threat_model")
                except Exception:
                    pass
        out["threat_model_source"] = source
        if md.strip():
            out["threat_model_md"] = md
            if enrich_meta:
                out["threat_enrich"] = enrich_meta
            try:
                out["threat_quality"] = _th.threat_quality(md, files, cands)
            except Exception:
                pass
            try:
                out["threat_verified"] = _th.verify_threat(repo, md, files, cands)
            except Exception:
                pass
    except Exception as _e:
        if agent_registry is not None:
            for _r in ("threat-researcher", "threat-historian", "threat-synthesizer"):
                try:
                    agent_registry.transition(_r, AgentState.failed,
                                             parent_stage="threat_model",
                                             error=str(_e))
                except Exception:
                    pass
        out["threat_model_source"] = "summary"
    return out


def hunters_router(state: ScanState, agent_registry: Any = None) -> dict:
    """Fan-out plan: no key -> fail-open review tasks; else payloads per unit."""
    try:
        from harness.config import api_key_present, load_config
        cfg = load_config()
    except Exception:
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
    # Partition by LOGICAL UNIT: partitioning AGENT first (reads structure,
    # groups by business logic), deterministic fallback (graphify/dir).
    # Each hunter owns one coherent unit across ALL classes.
    units: list[dict] = []
    _partition_failed = False
    if agent_registry is not None:
        try:
            agent_registry.create("partitioner", "partitioner", parent_stage="partition",
                                 state=AgentState.queued)
            agent_registry.transition("partitioner", AgentState.running,
                                     parent_stage="partition")
        except Exception:
            pass
    try:
        from harness.partitioning.llm import run_partitioner_agent
        units = run_partitioner_agent(
            state.get("repo", "."), payload_files, payload_cands, cfg,
            threat_md=threat_md)
    except Exception:
        _partition_failed = True
        units = []
    if agent_registry is not None:
        try:
            if _partition_failed:
                agent_registry.transition("partitioner", AgentState.failed,
                                         parent_stage="partition")
            else:
                agent_registry.transition("partitioner", AgentState.succeeded,
                                         parent_stage="partition")
        except Exception:
            pass
    if not units:
        from harness.partitioning import partition_units
        units = partition_units(state.get("repo", "."), payload_files, payload_cands)
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
    """Validate one worker's own outputs immediately (pipelined validation).

    Same verdict path as the post-hunt pool (run_validation: evidence gate +
    per-partition cells + fp guardrail), but scoped to this worker's findings
    with a small pool so concurrent workers do not oversubscribe the API.
    Fail-open: on catastrophic error the raw findings pass through as
    needs-review and the aggregator join re-queues anything unvalidated.
    """
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
            try:
                g = dict(f) if isinstance(f, dict) else {"title": str(f)}
                g.setdefault("status", "needs-review")
                out.append(g)
            except Exception:
                continue
        return out


def hunter_worker(state: dict) -> dict:
    """One logical unit, all vulnerability classes."""
    import time as _time

    from harness.agents.hunters import _fallback_finding, _run_unit

    repo = state.get("repo", ".")
    files = list(state.get("files", []))
    candidates = list(state.get("candidates", []))
    cfg = dict(state.get("cfg", {}) or {})
    threat_md = state.get("threat_model_md", "") or ""
    focus = state.get("focus", []) or []
    _tools: list = []
    t0 = _time.time()
    label = state.get("unit") or "unit"
    try:
        out = _run_unit({"name": label}, repo, files, candidates, cfg,
                        threat_md=threat_md, focus=focus, _tools_out=_tools)
        # Stamp the partition so validation runs one validator per unit.
        for f in out:
            try:
                if isinstance(f, dict) and not f.get("unit"):
                    f["unit"] = str(label)
            except Exception:
                pass
        print(f"[hunters] {label}: {len(out)} findings in {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        validated = _validate_inline(out, cfg, threat_md,
                                     state.get("votes_override"), label,
                                     repo=repo)
        return {"findings": out, "verified": validated,
                "tools_used": sorted(set(str(t) for t in _tools))}
    except Exception as e:
        # A bad key or an unknown model must fail the scan: letting each unit
        # emit a fallback finding would turn a config error into a "clean"
        # scan with zero real verdicts.
        from harness.agents.deep import is_fatal_error

        if is_fatal_error(e):
            raise
        print(f"[hunters] {label}: ERROR {type(e).__name__} after {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        fb = _fallback_finding(str(label), repo, files, str(e))
        try:
            fb["unit"] = str(label)
        except Exception:
            pass
        return {"findings": [fb]}


def _norm_key(f: dict) -> str:
    try:
        path = str(f.get("path", "")).strip().lower().replace("\\", "/").lstrip("./")
        cwe = str(f.get("cwe", "")).strip().upper()
        try:
            line = int(f.get("start_line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        if not cwe and line == 0:
            # Context items (prefilter/routes/threat-model/manifest): keep distinct.
            title = str(f.get("title", "")).strip().lower()
            snip = " ".join(str(f.get("snippet", "")).split())[:500]
            digest = hashlib.sha256(snip.encode()).hexdigest()[:12]
            return f"{path}|{cwe}|{line}|{title[:80]}|{digest}"
        return f"{path}|{cwe}|{line}"
    except (AttributeError, TypeError, ValueError):
        return f"{f.get('path')}|{f.get('title')}"


def _merge_dup(a: dict, b: dict) -> dict:
    """Merge two findings on the same (path, cwe, line): keep max confidence,
    union evidence, status priority confirmed > needs-review > fp."""
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
    """System-level pass after unit hunting (plan-1345 M2).

    Adds cross-unit chains + global gaps only; unit findings are preserved
    regardless of whether hunters found anything. Skipped without API key or
    when discovery.system_pass is off.
    Fail-open: any error (or empty result) contributes nothing.
    """
    findings = [f for f in list(state.get("findings", [])) if isinstance(f, dict)]
    try:
        from harness.config import api_key_present, load_config
        _cfg_sys = load_config()
    except Exception:
        _cfg_sys = {}
    if not api_key_present(_cfg_sys):
        return {}
    try:
        from harness.config import load_config as _lc3
        _cfg3 = _lc3()
    except Exception:
        _cfg3 = {}
    try:
        _enabled = str(((_cfg3.get("discovery") or {}).get("system_pass", True))).lower()
        if _enabled not in ("1", "true", "yes"):
            return {}
    except Exception:
        pass
    import time as _time
    t0 = _time.time()
    try:
        from harness.agents.hunters import _run_system_pass
        focus = state.get("focus", []) or []
        _tools: list = []
        out = _run_system_pass(state.get("repo", "."),
                               list(state.get("files", [])),
                               findings,
                               state.get("threat_model_md", "") or "",
                               _cfg3, focus, _tools)
        print(f"[system-pass] +{len(out)} cross-unit findings in {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        ret: dict = {"findings": out or []}
        if _tools:
            ret["tools_used"] = sorted(set(str(t) for t in _tools))
        return ret
    except Exception as e:
        print(f"[system-pass] ERROR {type(e).__name__} after {_time.time()-t0:.0f}s",
              file=sys.stderr, flush=True)
        return {}


def aggregator_node(state: ScanState) -> dict:
    seen: dict[str, dict] = {}
    for f in list(state.get("candidates", [])) + list(state.get("findings", [])):
        key = _norm_key(f)
        seen[key] = _merge_dup(seen[key], f) if key in seen else f
    out: list[dict] = list(seen.values())
    # Pipelined validation: hunter workers already validated their own
    # outputs into `verified`. Only queue what has no validated counterpart
    # (same norm-key), so nothing is validated twice and anything a worker
    # failed to validate is re-queued here, never dropped.
    try:
        done_keys = {_norm_key(f) for f in (state.get("verified", []) or [])}
    except Exception:
        done_keys = set()
    pending = [f for f in out if _norm_key(f) not in done_keys]
    return {"pending": pending}


def validator_node(state: ScanState, agent_registry: Any = None) -> dict:
    """Validate the remainder: raw findings with no validated counterpart.

    Hunter workers validate their own unit inline; this pool covers
    everything else (deterministic candidates + system-pass findings).
    Appends to `verified`; never rewrites what earlier writers appended.
    The human confirm step lives in the driver (`confirm_critical_step`).
    """
    from harness.agents.validator import run_validation

    pending = [dict(f) for f in (state.get("pending", []) or [])]
    if agent_registry is not None:
        try:
            agent_registry.create("validator", "validator", parent_stage="validation",
                                 state=AgentState.queued)
            agent_registry.transition("validator", AgentState.running,
                                     parent_stage="validation")
        except Exception:
            pass
    try:
        from harness.config import load_config

        try:
            cfg = load_config()
        except Exception:
            cfg = {}
    except Exception:
        cfg = {}
    import time as _time
    t0 = _time.time()
    print(f"[validator] validating {len(pending)} remaining findings "
          f"({len(state.get('verified', []) or [])} already validated)...",
          file=sys.stderr, flush=True)
    try:
        units = []
        for p in (state.get("fanout_payloads", []) or []):
            try:
                if isinstance(p, dict) and p.get("unit"):
                    units.append({"name": str(p["unit"]),
                                  "files": list(p.get("files", []))})
            except Exception:
                continue
        validated = run_validation(
            pending, cfg, state.get("threat_model_md", "") or "",
            state.get("votes_override"), units=units,
            repo=state.get("repo"))
        if agent_registry is not None:
            try:
                agent_registry.transition("validator", AgentState.succeeded,
                                         parent_stage="validation")
            except Exception:
                pass
    except Exception as e:
        from harness.agents.deep import is_fatal_error

        # Fail-open: never drop on validator error — unless it is the
        # operator's configuration, which must fail loudly.
        if is_fatal_error(e):
            if agent_registry is not None:
                try:
                    agent_registry.transition("validator", AgentState.failed,
                                             parent_stage="validation", error=str(e))
                except Exception:
                    pass
            raise
        if agent_registry is not None:
            try:
                agent_registry.transition("validator", AgentState.failed,
                                         parent_stage="validation", error=str(e))
            except Exception:
                pass
        # Fail-open: never drop on validator error.
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
    """Human confirm between validation and triage.

    Considers every validated finding (pipelined + remainder). With no
    confirm callback the safe default is to HOLD: hot findings are demoted to
    needs-review rather than released unreviewed. A decline demotes every
    confirmed critical/high finding; an approval changes nothing. Returns a
    state update (Overwrite of `verified`) or {} when there is nothing to ask.
    """
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
    except Exception:
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
    """Dedup by root cause + severity rubric (plan-1345 M4).

    Runs after validation, before scoring. Annotates duplicate_of/triage in
    place; never drops. Fail-open: any error leaves verified untouched.
    """
    import time as _time
    t0 = _time.time()
    verified = list(state.get("verified", []))
    if not verified:
        return {}
    if agent_registry is not None:
        try:
            agent_registry.create("triage:1", "triage:1", parent_stage="triage",
                                 state=AgentState.queued)
            agent_registry.transition("triage:1", AgentState.running,
                                     parent_stage="triage")
        except Exception:
            pass
    try:
        from harness.config import load_config as _lc4
        _cfg4 = _lc4()
    except Exception:
        _cfg4 = {}
    try:
        from harness.agents.triage import run_triage
        res = run_triage(verified, _cfg4, state.get("threat_model_md", "") or "")
        out = res.get("findings", verified)
        if agent_registry is not None:
            try:
                agent_registry.transition("triage:1", AgentState.succeeded,
                                         parent_stage="triage")
            except Exception:
                pass
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
                try:
                    agent_registry.transition("triage:1", AgentState.failed,
                                             parent_stage="triage", error=str(e))
                except Exception:
                    pass
            raise
        if agent_registry is not None:
            try:
                agent_registry.transition("triage:1", AgentState.failed,
                                         parent_stage="triage", error=str(e))
            except Exception:
                pass
        print(f"[triage] ERROR {type(e).__name__} after {_time.time()-t0:.0f}s "
              "(verified untouched)", file=sys.stderr, flush=True)
        return {}


def threat_update_node(state: ScanState) -> dict:
    """Fold validator-confirmed findings back into the threat model (feedback
    loop, so CLI and eval paths both get it). Pure state update —
    file writing stays in CLI (single writer). Fail-open: any error (or no
    confirmed findings) leaves the model untouched."""
    md = state.get("threat_model_md", "") or ""
    if not md.strip():
        return {}
    try:
        from harness import threat as _th5
        updated = _th5.update_threat_with_findings(
            md, list(state.get("verified", [])), state.get("repo", "."))
        if updated.strip() and updated != md:
            return {"threat_model_md": updated}
        return {}
    except Exception:
        return {}


def scorer_node(state: ScanState) -> dict:
    """Heuristic CVSS (static-analysis-only): severity base scaled by confidence.

    Documented estimate, not a substitute for analyst scoring: analysts should
    re-score with exploitability/impact context before acting.
    """
    out = []
    for f in state.get("verified", []):
        g = dict(f)
        try:
            conf = float(g.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            conf = 0.0
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
    """get_concurrency(load_config()), falling back to the 4-way default."""
    try:
        from harness.config import get_concurrency, load_config

        return get_concurrency(load_config())
    except Exception:
        return 4


def _reset_agent_scratch_phase(repo: str) -> None:
    """Wipe the run sandbox's per-agent scratchpads between phases.

    Best-effort phase hygiene, not a security boundary. This clears the
    conventional per-agent scratch paths to reduce accidental carryover.
    Agents share a runtime identity, and shell processes can write elsewhere
    or continue in the background; use a fresh sandbox for strong separation.

    Gated on ``sandbox.reset_agent_scratch`` (default on) and never fatal:
    a failed reset is reported once on stderr and the scan continues, since
    a hygiene step must not cost the whole run. No-op in local mode.
    """
    try:
        from harness.config import load_config
        from harness.sandbox import reset_agent_scratch

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
    """Reap sandboxes a killed run left behind, before this run starts.

    A SIGKILL'd harness (kill -9, host OOM-kill, power loss) cannot reap its
    own sandbox: atexit never fires and the SIGTERM handler never sees the
    signal. Teardown paths cover the graceful cases, so this covers the
    remaining one -- and it can only ever run at the START of a scan, when
    nothing of this run exists yet.

    Gated on ``sandbox.sweep_orphans`` (default on) and never fatal: the
    sweep is best-effort housekeeping and must not cost a scan. Only
    sandboxes this harness created are candidates, and a run still alive on
    this machine (any harness process) is never touched. No-op in local mode.
    """
    try:
        from harness.config import load_config
        from harness.sandbox import sweep_orphans

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
    """Run one hunter_worker per payload, at most `max_workers` at a time.

    Results are applied in payload order (deterministic regardless of which
    worker finishes first). hunter_worker is fail-open by itself; the guard
    here covers anything it did not catch so one unit can never sink the scan.
    """
    payloads = list(state.get("fanout_payloads", []) or [])
    if not payloads:
        return
    shared = {k: state.get(k) for k in ("repo", "threat_model_md", "focus",
                                        "votes_override")}

    if agent_registry is not None:
        for p in payloads:
            unit = str(p.get("unit", "unit"))
            cfg = p.get("cfg") or state.get("cfg") or {}
            model = None
            try:
                model = cfg.get("hunter_model") if isinstance(cfg, dict) else None
            except Exception:
                model = None
            try:
                agent_registry.create("hunter:" + unit, "hunter", unit=unit,
                                      parent_stage="hunters", model=model,
                                      state=AgentState.queued)
            except Exception:
                pass

    def _one(p: dict) -> dict:
        unit = str(p.get("unit", "unit"))
        aid = "hunter:" + unit
        cfg = p.get("cfg") or state.get("cfg") or {}
        model = cfg.get("hunter_model") if isinstance(cfg, dict) else None
        if agent_registry is not None:
            try:
                agent_registry.transition(aid, AgentState.running,
                                         parent_stage="hunters", model=model,
                                         message="unit started")
            except Exception:
                pass
        try:
            merged = dict(p)
            for k, v in shared.items():
                merged.setdefault(k, v)
            res = hunter_worker(merged)
            if agent_registry is not None:
                try:
                    # update stats from worker? leave coarse.
                    agent_registry.transition(aid, AgentState.succeeded,
                                             parent_stage="hunters",
                                             message="completed",
                                             model=model)
                except Exception:
                    pass
            return res
        except Exception as e:  # pragma: no cover - hunter_worker is fail-open
            from harness.agents.deep import is_fatal_error

            # Config-class failures are the operator's setup, not one bad
            # unit: they must sink the scan instead of becoming fallbacks.
            if is_fatal_error(e):
                if agent_registry is not None:
                    try:
                        agent_registry.transition(aid, AgentState.failed,
                                                 parent_stage="hunters",
                                                 model=model, error=str(e))
                    except Exception:
                        pass
                raise
            from harness.agents.hunters import _fallback_finding
            fb = _fallback_finding(str(p.get("unit", "unit")), p.get("repo", "."),
                                   list(p.get("files", [])), str(e))
            fb["unit"] = str(p.get("unit", "unit"))
            if agent_registry is not None:
                try:
                    agent_registry.transition(aid, AgentState.failed,
                                             parent_stage="hunters",
                                             model=model, error=str(e))
                except Exception:
                    pass
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
             agent_registry: Any = None,
             progress_sink: Any = None,
             on_event: Any = None,
             agent_events: Any = None,
             agent_events_path: Any = None,
             events_path: Any = None,
             ) -> dict[str, Any]:
    """Run the full scan and return the final state.

    `confirm` is called with the hot-findings payload when `confirm_critical`
    is set and confirmed critical/high findings exist; it returns True to
    release them. Without a callback they are held (see confirm_critical_step).
    """
    os.environ["TARGET_REPO"] = str(repo)
    _sweep_orphan_sandboxes()
    state: dict[str, Any] = {"repo": repo}

    _events_path = agent_events_path if agent_events_path is not None else events_path
    if agent_registry is None:
        try:
            agent_registry = AgentRegistry(run_id=str(repo), sink=progress_sink,
                                           on_event=on_event,
                                           progress_sink=progress_sink,
                                           events_path=_events_path)
        except Exception:
            agent_registry = None
    else:
        try:
            if _events_path is not None and getattr(agent_registry, "events_path", None) is None:
                agent_registry.events_path = _events_path
        except Exception:
            pass
        try:
            if progress_sink is not None and getattr(agent_registry, "sink", None) is None:
                agent_registry.sink = progress_sink
            if on_event is not None and getattr(agent_registry, "on_event", None) is None:
                agent_registry.on_event = on_event
        except Exception:
            pass
    _agent_registry = agent_registry
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
            return fn()
        finally:
            stage_timings[name] = round(_stage_time.time() - _t0, 3)

    _stage("indexer", lambda: apply_update(state, indexer_node(state)))
    _stage("threat_model", lambda: apply_update(state, _call_node(threat_model_node, state, agent_registry=_agent_registry)))
    _stage("hunters_router", lambda: apply_update(state, _call_node(hunters_router, state, agent_registry=_agent_registry)))
    if state.get("fanout_payloads"):
        _stage("hunters", lambda: _fan_out_hunters(state, _safe_max_concurrency(), agent_registry=_agent_registry))
    _stage("system_pass", lambda: apply_update(state, system_pass_node(state)))
    _stage("aggregator", lambda: apply_update(state, aggregator_node(state)))
    # Phase boundary: clear conventional scratch paths to reduce accidental
    # carryover (config-gated, best-effort; not a fresh sandbox).
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
    if agent_events is not None:
        try:
            agent_events.extend(state.get("agent_events", []))
        except Exception:
            pass
    return dict(state)
