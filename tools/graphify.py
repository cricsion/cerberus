from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ._compat import run_cli, tool
from .code import _resolve_limit


_graph_cache: dict[str, tuple[float, object]] = {}

# Kept in sync with the scan inventory: excluded from Graphify's source graph.
GRAPHIFY_SKIP_DIRS = frozenset({
    ".venv", "venv", "node_modules", ".git", "__pycache__",
    "graphify-out", ".graphify", "dist", "build",
})


def _cmd() -> list[str] | None:
    try:
        import graphify  # noqa: F401
        return [sys.executable, "-m", "graphify"]
    except ImportError:
        pass
    import shutil
    if shutil.which("graphify"):
        return ["graphify"]
    return None


def graph_path_for(root: str) -> Path:
    from harness.tools.code import _safe_path
    base = _safe_path(root)
    if base.is_file():
        base = base.parent
    return base / "graphify-out" / "graph.json"


def _graph_chars() -> int:
    import os as _os
    try:
        v = int(_os.environ.get("GRAPH_CHARS", "20000") or 20000)
        return v if v >= 0 else 20000
    except (TypeError, ValueError):
        return 20000


def _truncate(s: str) -> str:
    lim = _graph_chars()
    if lim <= 0 or len(s) <= lim:
        return s
    return s[:lim] + f"\n… +{len(s) - lim} more chars (total {len(s)})"


def _source_files(root: str) -> list[Path]:
    # No file-count cap: a capped staleness walk can miss newer files.
    from harness.tools.code import _safe_path as _sp
    base = _sp(root)
    if base.is_file():
        return [base]
    out: list[Path] = []
    resolved_base = base.resolve()
    for f in sorted(base.rglob("*")):
        if not f.is_file() or f.is_symlink():
            continue
        try:
            if any(p in GRAPHIFY_SKIP_DIRS for p in f.relative_to(base).parts):
                continue
            # rglob descends through symlink dirs; re-check each file.
            f.resolve().relative_to(resolved_base)
        except ValueError:
            continue
        out.append(f)
    return out


def needs_rebuild(root: str) -> bool:
    gp = graph_path_for(root)
    if not gp.is_file():
        return True
    try:
        gmt = gp.stat().st_mtime
    except OSError:
        return True
    # A filesystem error mid-walk would underreport staleness; fail toward
    # rebuilding (stale is never served as fresh).
    try:
        for f in _source_files(root):
            try:
                if f.stat().st_mtime > gmt:
                    return True
            except OSError:
                continue
    except OSError:
        return True
    return False


def graphify_build(root: str, timeout: int = 600) -> str:
    from harness.tools._compat import scrubbed_env
    cmd = _cmd()
    if cmd is None:
        return ""
    from harness.tools.code import _safe_path as _sp
    root = str(_sp(root))
    if Path(root).is_file():
        return ""
    if not needs_rebuild(root):
        p = graph_path_for(root)
        return str(p) if p.is_file() else ""
    try:
        proc = subprocess.run(cmd + [root, "--code-only", "--no-viz"],
                              capture_output=True, text=True, timeout=timeout,
                              env=scrubbed_env())
    except (subprocess.TimeoutExpired, OSError):
        return ""
    p = graph_path_for(root)
    if p.is_file():
        _graph_cache.pop(str(p), None)  # rebuilt: drop cached graph object
        return str(p)
    return ""


def graphify_summary(root: str) -> str:
    import json
    gp = graph_path_for(root)
    try:
        g = json.loads(gp.read_text())
    except Exception:
        return "(no graph)"
    try:
        nodes = g.get("nodes", [])
        links = g.get("links", [])
        deg: dict[str, int] = {}
        for l in links:
            for k in ("source", "target"):
                v = str(l.get(k, ""))
                if v:
                    deg[v] = deg.get(v, 0) + 1
        top = sorted(deg.items(), key=lambda kv: -kv[1])[:20]
        by_id = {str(n.get("id")): n for n in nodes if isinstance(n, dict)}
        hubs = []
        for nid, d in top:
            n = by_id.get(nid, {})
            hubs.append(f"{n.get('label', nid)}@{n.get('source_file', '?')}:{n.get('source_location', '?')}({d})")
        return _truncate(f"graph: {len(nodes)} nodes, {len(links)} edges. "
                f"Hubs: {'; '.join(hubs) if hubs else 'n/a'}")
    except Exception:
        return "(graph unreadable)"


def _load_nx(root: str):
    gp = graph_path_for(root)
    try:
        if not gp.is_file():
            return None
        mtime = gp.stat().st_mtime
    except OSError:
        return None
    key = str(gp)
    hit = _graph_cache.get(key)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        from graphify.serve import _load_graph
        G = _load_graph(str(gp))
    except Exception:
        return None
    _graph_cache[key] = (mtime, G)
    return G


def _no_graph_msg() -> str:
    return ("(no graph for this repo: indexer builds it when enabled — "
            "use grep codegraph instead)")


def _run_graph(args: list[str], root: str, timeout: int = 120) -> str:
    cmd = _cmd()
    if cmd is None:
        return "(graphify not available — use grep/glob codegraph instead)"
    try:
        gp = graph_path_for(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not gp.is_file():
        return _no_graph_msg()
    res = run_cli(cmd + args + ["--graph", str(gp)], timeout=timeout)
    if res.get("skipped"):
        return f"(graph query failed: {res.get('reason', 'unavailable')})"
    out = (res.get("stdout") or "").strip()
    return _truncate(out) or "(no graph results)"


@tool(parse_docstring=True)
def graph_neighbors(node: str, root: str = ".", limit: int | None = None) -> str:
    """Graph neighbors of a symbol: AST-proven imports/calls/containment edges. Paginated via limit (0=unlimited).

    Args:
        node: Symbol/function name.
        root: Root path for the graph.
        limit: Max neighbors. 0 = unlimited.
    """
    name = (node or "").strip()[:200]
    if not name:
        return "(no results)"
    G = _load_nx(root)
    if G is None:
        return _run_graph(["explain", name], root)
    try:
        from graphify.affected import resolve_seed
        seed = resolve_seed(G, name)
        if seed is None:
            return f"No unique node match for {name}"
        lines = [f"Neighbors of {G.nodes[seed].get('label', seed)}:"]
        _limn = _resolve_limit(limit, "GRAPH_NEIGHBORS", 100)
        try:
            out_edges = list(G.out_edges(seed, data=True))
            in_edges = list(G.in_edges(seed, data=True))
        except AttributeError:
            out_edges = [(s, t, d) for s, t, d in G.edges(data=True) if s == seed]
            in_edges = [(s, t, d) for s, t, d in G.edges(data=True) if t == seed]
        oe = out_edges if _limn <= 0 else out_edges[:_limn]
        ie = in_edges if _limn <= 0 else in_edges[:_limn]
        for _s, t, d in oe:
            nd = G.nodes[t]
            lines.append(f"- [{d.get('relation', '?')}] -> {nd.get('label', t)} "
                         f"({nd.get('source_file', '?')}:{nd.get('source_location', '?')})")
        for s, _t, d in ie:
            nd = G.nodes[s]
            lines.append(f"- [{d.get('relation', '?')}] <- {nd.get('label', s)} "
                         f"({nd.get('source_file', '?')}:{nd.get('source_location', '?')})")
        if _limn > 0 and (len(out_edges) > len(oe) or len(in_edges) > len(ie)):
            lines.append(f"… +{len(out_edges) - len(oe) + len(in_edges) - len(ie)} more edges (total {len(out_edges) + len(in_edges)})")
        return _truncate("\n".join(lines))
    except (ImportError, KeyError, AttributeError, ValueError):
        # In-process graph quirk (or graphify python pkg absent): re-query
        # through the CLI, which has its own error handling.
        return _run_graph(["explain", name], root)


@tool(parse_docstring=True)
def graph_path(source: str, sink: str, root: str = ".") -> str:
    """Shortest AST-proven caller->callee path (taint-route check, directed).

    Args:
        source: Start symbol.
        sink: Target symbol.
        root: Root path for the graph.
    """
    a, b = (source or "").strip()[:500], (sink or "").strip()[:500]
    if not a or not b:
        return "(no results)"
    G = _load_nx(root)
    if G is None:
        return _run_graph(["path", a, b], root)
    try:
        from graphify.serve import _shortest_path_text
        return _truncate(_shortest_path_text(G, {"source": a, "target": b}))
    except (ImportError, KeyError, AttributeError, ValueError):
        # In-process graph quirk (or graphify python pkg absent): re-query
        # through the CLI, which has its own error handling.
        return _run_graph(["path", a, b], root)


@tool(parse_docstring=True)
def graph_query(question: str, root: str = ".", budget: int | None = None) -> str:
    """BFS subgraph for a plain-language structural question. Paginated via budget (0=unlimited).

    Args:
        question: Plain-language structural question.
        root: Root path for the graph.
        budget: Max nodes returned. 0 = unlimited.
    """
    q = (question or "").strip()[:2000]
    if not q:
        return "(no results)"
    _b = _resolve_limit(budget, "GRAPH_BUDGET", 4000)
    if _b <= 0:
        _b = 100000
    G = _load_nx(root)
    if G is None:
        return _run_graph(["query", q, "--budget", str(_b)], root)
    try:
        from graphify.serve import _query_graph_text
        gp = graph_path_for(root)
        return _truncate(_query_graph_text(G, q, mode="bfs", depth=3,
                                 token_budget=_b,
                                 graph_path=str(gp)))
    except (ImportError, KeyError, AttributeError, ValueError):
        # In-process graph quirk (or graphify python pkg absent): re-query
        # through the CLI, which has its own error handling.
        return _run_graph(["query", q, "--budget", str(_b)], root)


@tool(parse_docstring=True)
def graph_affected(node: str, root: str = ".", limit: int | None = None) -> str:
    """Reverse traversal: who CAN reach this function (callers up to depth 2); call-site lines prove REACHABILITY only, not taint flow. Paginated via limit (0=unlimited).

    Args:
        node: Symbol to trace backwards from.
        root: Root path for the graph.
        limit: Max affected nodes. 0 = unlimited.
    """
    name = (node or "").strip()[:500]
    if not name:
        return "(no results)"
    _lima = _resolve_limit(limit, "GRAPH_AFFECTED", 100)
    G = _load_nx(root)
    if G is None:
        return _run_graph(["affected", name], root)
    try:
        from graphify.affected import affected_nodes, resolve_seed
        seed = resolve_seed(G, name)
        if seed is None:
            return f"No unique node match for {name}"
        hits = affected_nodes(G, seed, depth=2)
        if not hits:
            return "No affected nodes found."
        lines = [f"Affected nodes for {G.nodes[seed].get('label', seed)} (total {len(hits)}):"]
        page = hits if _lima <= 0 else hits[:_lima]
        for h in page:
            nd = G.nodes[h.node_id]
            loc = f"{h.via_file or nd.get('source_file') or '-'}:{h.via_location or nd.get('source_location') or '?'}"
            lines.append(f"- {nd.get('label', h.node_id)} [{h.via_relation}] {loc}")
        if len(hits) > len(page):
            lines.append(f"… +{len(hits) - len(page)} more")
        return _truncate("\n".join(lines))
    except (ImportError, KeyError, AttributeError, ValueError):
        # In-process graph quirk (or graphify python pkg absent): re-query
        # through the CLI, which has its own error handling.
        return _run_graph(["affected", name], root)
