"""Native CodeGraph integration bridging high-order code intelligence capabilities.

Exposes CodeGraph's native features:
- 1-shot exploration (``explore``): verbatim source + dynamic call paths + blast radius.
- Shortest-path graph search (``find_path``): traces calls across interprocedural/dynamic hops.
- Multi-hop blast-radius analysis (``impact``): transitive dependencies.
- Framework routing manifest (``routing_manifest``): native framework route tables.
- Graph topological hygiene (``circular_and_dead_code``): cycles & orphaned components.
- Task-focused context assembly (``build_context``): relevant symbols, relationships & entry points.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess

_logger = logging.getLogger(__name__)

_RUNNER_PATH = Path(__file__).resolve().parent / "native_runner.cjs"


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "CODEGRAPH_NO_DAEMON": "1",
        "CODEGRAPH_TELEMETRY": "0",
        "CODEGRAPH_NO_UPDATE_CHECK": "1",
        "DO_NOT_TRACK": "1",
    })
    return env


def _resolve_repo(repo: str | Path | None = None) -> str:
    if repo is not None and str(repo).strip():
        return str(Path(repo).resolve())
    target = os.environ.get("TARGET_REPO")
    if target and target.strip():
        return str(Path(target).resolve())
    cwd = Path.cwd().resolve()
    if (cwd / ".codegraph").is_dir():
        return str(cwd)
    if (cwd / "harness" / ".codegraph").is_dir():
        return str((cwd / "harness").resolve())
    return str(cwd)


def _run_node_runner(cmd: str, repo: str, *args: str, timeout: int = 30) -> dict:
    node = shutil.which("node")
    if not node:
        return {"error": "NODE_NOT_FOUND"}
    repo_path = _resolve_repo(repo)
    if not (Path(repo_path) / ".codegraph").is_dir():
        return {"error": "NOT_INITIALIZED"}

    full_cmd = [node, str(_RUNNER_PATH), cmd, repo_path, *args]
    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(),
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or f"EXIT_{proc.returncode}"}
        stdout = proc.stdout.strip()
        # Filter experimental warnings if present in stdout
        for line in stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    return json.loads(line_str)
                except Exception:
                    pass
        return json.loads(stdout)
    except Exception as exc:
        _logger.warning("CodeGraph native runner failed (%s): %s", cmd, exc)
        return {"error": str(exc)}


def explore(query: str, repo: str | None = None, max_files: int = 5, timeout: int = 30) -> str:
    """1-shot exploration: relevant symbols' source + call paths + blast radius."""
    codegraph_bin = shutil.which("codegraph")
    repo_path = _resolve_repo(repo)
    if not codegraph_bin or not (Path(repo_path) / ".codegraph").is_dir():
        return f"(codegraph index unavailable for query: {query})"

    cmd = [codegraph_bin, "explore", "-p", repo_path, "--max-files", str(max_files), query]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(),
        )
        if proc.returncode != 0:
            return f"(codegraph explore failed: {proc.stderr.strip() or proc.stdout.strip()})"
        return proc.stdout.strip()
    except Exception as exc:
        return f"(codegraph explore error: {exc})"


def find_path(from_symbol: str, to_symbol: str, repo: str | None = None) -> list[dict] | dict | None:
    """Graph shortest-path search tracing calls across interprocedural and dynamic-dispatch hops."""
    res = _run_node_runner("findPath", _resolve_repo(repo), from_symbol, to_symbol)
    if "error" in res:
        return {"path": None, "error": res["error"]}
    return res.get("path")


def impact(symbol: str, depth: int = 2, repo: str | None = None) -> dict:
    """Multi-hop blast-radius analysis (calculates downstream transitive dependencies)."""
    res = _run_node_runner("impact", _resolve_repo(repo), symbol, str(depth))
    if "error" in res:
        return {"symbol": symbol, "affected": [], "error": res["error"]}
    nodes = res.get("nodes", [])
    edges = res.get("edges", [])
    return {
        "symbol": symbol,
        "depth": depth,
        "affected_count": len(nodes),
        "nodes": nodes,
        "edges": edges,
    }


def routing_manifest(repo: str | None = None) -> dict:
    """Native framework detection and route table compilation."""
    res = _run_node_runner("routingManifest", _resolve_repo(repo))
    if "error" in res:
        return {"frameworks": [], "manifest": None, "error": res["error"]}
    return {
        "frameworks": res.get("frameworks", []),
        "manifest": res.get("manifest"),
    }


def circular_and_dead_code(repo: str | None = None) -> dict:
    """Graph topological analysis to locate orphaned components or circular imports."""
    res = _run_node_runner("circularAndDead", _resolve_repo(repo))
    if "error" in res:
        return {"circular_dependencies": [], "dead_code": [], "error": res["error"]}
    return {
        "circular_dependencies": res.get("circular", []),
        "dead_code": res.get("dead", []),
    }


def build_context(task: str, repo: str | None = None, max_nodes: int = 20, timeout: int = 30) -> dict:
    """Task-focused context assembly that pulls relevant definitions, relationships, and entry points."""
    codegraph_bin = shutil.which("codegraph")
    repo_path = _resolve_repo(repo)
    if not codegraph_bin or not (Path(repo_path) / ".codegraph").is_dir():
        return {"error": "INDEX_NOT_AVAILABLE", "query": task}

    cmd = [codegraph_bin, "context", "-p", repo_path, "-f", "json", "-n", str(max_nodes), "--no-code", task]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(),
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or "CONTEXT_FAILED", "query": task}
        return json.loads(proc.stdout.strip())
    except Exception as exc:
        return {"error": str(exc), "query": task}


def callers_json(func_name: str, repo: str | None = None, limit: int = 100, timeout: int = 30) -> dict:
    """Retrieve callers as structured JSON with enriched metadata (confidence, column, target ID)."""
    codegraph_bin = shutil.which("codegraph")
    repo_path = _resolve_repo(repo)
    if not codegraph_bin or not (Path(repo_path) / ".codegraph").is_dir():
        return {"error": "INDEX_NOT_AVAILABLE", "symbol": func_name}

    cmd = [codegraph_bin, "callers", "-p", repo_path, "-j", "-l", str(limit), func_name]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(),
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or "CALLERS_FAILED", "symbol": func_name}
        return json.loads(proc.stdout.strip())
    except Exception as exc:
        return {"error": str(exc), "symbol": func_name}


def callees_json(func_name: str, repo: str | None = None, limit: int = 100, timeout: int = 30) -> dict:
    """Retrieve callees as structured JSON with enriched metadata (confidence, column, target ID)."""
    codegraph_bin = shutil.which("codegraph")
    repo_path = _resolve_repo(repo)
    if not codegraph_bin or not (Path(repo_path) / ".codegraph").is_dir():
        return {"error": "INDEX_NOT_AVAILABLE", "symbol": func_name}

    cmd = [codegraph_bin, "callees", "-p", repo_path, "-j", "-l", str(limit), func_name]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(),
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or "CALLEES_FAILED", "symbol": func_name}
        return json.loads(proc.stdout.strip())
    except Exception as exc:
        return {"error": str(exc), "symbol": func_name}


def call_graph(symbol: str, depth: int = 2, repo: str | None = None) -> dict:
    """Retrieve the multi-hop call graph (callers + callees) for a function/method."""
    res = _run_node_runner("callGraph", _resolve_repo(repo), symbol, str(depth))
    if "error" in res:
        return {"symbol": symbol, "nodes": [], "edges": [], "error": res["error"]}
    return {
        "symbol": symbol,
        "nodes": res.get("nodes", []),
        "edges": res.get("edges", []),
    }


def type_hierarchy(symbol: str, repo: str | None = None) -> dict:
    """Retrieve type hierarchy (ancestors + descendants, extends + implements) for a class/interface."""
    res = _run_node_runner("typeHierarchy", _resolve_repo(repo), symbol)
    if "error" in res:
        return {"symbol": symbol, "nodes": [], "edges": [], "error": res["error"]}
    return {
        "symbol": symbol,
        "nodes": res.get("nodes", []),
        "edges": res.get("edges", []),
    }


def node_metrics(symbol: str, repo: str | None = None) -> dict | None:
    """Retrieve complexity metrics (fan-in, fan-out, callCount, callerCount, depth) for a symbol."""
    res = _run_node_runner("metrics", _resolve_repo(repo), symbol)
    if "error" in res:
        return {"error": res["error"]}
    return res.get("metrics")


def usages(symbol: str, repo: str | None = None) -> list[dict] | dict:
    """Find all usages and references to a symbol across the knowledge graph."""
    res = _run_node_runner("usages", _resolve_repo(repo), symbol)
    if "error" in res:
        return {"error": res["error"]}
    return res.get("usages", [])


def node_context(symbol: str, repo: str | None = None) -> dict | None:
    """Retrieve complete structural context (ancestors, children, incoming/outgoing refs, types) for a symbol."""
    res = _run_node_runner("context", _resolve_repo(repo), symbol)
    if "error" in res:
        return {"error": res["error"]}
    return res.get("context")


__all__ = [
    "explore",
    "find_path",
    "impact",
    "routing_manifest",
    "circular_and_dead_code",
    "build_context",
    "call_graph",
    "type_hierarchy",
    "node_metrics",
    "usages",
    "node_context",
    "callers_json",
    "callees_json",
]
