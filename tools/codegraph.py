"""Code-intelligence tools bound on the shared agent surface (plan § D3, D4).

This is the ONE binding module for the code-intelligence family. Three groups
live here:

- **The native graph tools** — :func:`callers`, :func:`callees`,
  :func:`framework_routes`, :func:`affected`. Each answers from the prebuilt
  CodeGraph index via the native CodeGraph SDK when present AND the
  build gate passes (``pendingRefs`` is zero); otherwise — and whenever the
  index yields nothing for the query — it fails closed with clean guidance /
  ``(no matches)`` sentinels.
- **The native high-order tools** — :func:`codegraph_explore`, :func:`find_path`,
  :func:`impact_radius`, :func:`build_context`,
  :func:`detect_circular_and_dead_code`, :func:`get_routing_manifest`,
  :func:`type_hierarchy`.
- **The 9 ``cerberus.codegraph`` tools** (navigation / authz / contracts /
  supply / effects). They answer ``_db``-first internally;
  they are re-exported here so ``cerberus/agents/toolsets.py`` binds the whole
  code-intelligence surface from one place (:func:`codegraph_tools`).

Import law: this module imports only ``cerberus.codegraph`` (the 9 +
``_db``), stdlib, and the existing harness tool helpers
(``cerberus.tools.code``) — no new dependencies. Nothing here shells
``codegraph``; the CLI is the indexer's tool, never an agent's.
"""
from __future__ import annotations

import re
from pathlib import Path

from cerberus.codegraph import (
    compare_sibling_route_security,
    find_shared_state_readers_writers,
    get_ast_slice,
    inspect_type_contract,
    resolve_blind_spot,
    trace_effect_category,
    trace_egress_and_ssrf_targets,
    trace_interprocedural_hop,
    trace_state_machine_transitions,
)
from cerberus.codegraph import _db

from ._compat import tool
from .code import _resolve_limit

# The 9 cerberus.codegraph tools, in the package's own order. Kept as names so
# codegraph_tools() stays a single source of truth and __all__ is derived.
CODEGRAPH_TOOL_NAMES: tuple[str, ...] = (
    "get_ast_slice",
    "trace_interprocedural_hop",
    "resolve_blind_spot",
    "compare_sibling_route_security",
    "find_shared_state_readers_writers",
    "trace_state_machine_transitions",
    "inspect_type_contract",
    "trace_egress_and_ssrf_targets",
    "trace_effect_category",
)

# CodeGraph's uncertainty boundary (src/graph/dynamic-boundary-report.ts): below
# it an edge is a name-only guess, not a proven call — a hop to follow only with
# explicit scepticism.
UNCERTAIN_BELOW = 0.6

# The pinned route line:
#     <route_file>:<route_line>: [route] <url> -> <handler> (<handler_file>:<handler_line>)
ROUTE_LINE_RE = re.compile(
    r"^(?P<route_file>.+?):(?P<route_line>\d+): \[route\] "
    r"(?P<url>.+?) -> (?P<handler>\S+) "
    r"\((?P<handler_file>.+?):(?P<handler_line>\d+)\)$"
)


def codegraph_tools() -> list:
    """The 9 ``cerberus.codegraph`` tools, in a stable order.

    ``cerberus/agents/toolsets.py`` binds this list beside the ``_db``-first graph
    tools, so the whole code-intelligence surface is defined once and the roles
    cannot drift apart (plan § D3).
    """
    return [globals()[name] for name in CODEGRAPH_TOOL_NAMES]


def _safe_root(root: str) -> Path:
    from cerberus.tools.code import _safe_path
    return _safe_path(root)


# ---------------------------------------------------------------------------
# index presence + the DB-visible half of the build gate (plan § D2/D4)
# ---------------------------------------------------------------------------

def _index_gate(root: str):
    """(conn, ok): the read-only index handle and whether it may be trusted.

    ``ok`` is False when the index is absent/unreadable OR when the DB-visible
    half of CodeGraph's build gate fails — ``unresolved_refs`` still has
    ``pending`` rows, i.e. the resolution pass has not finished. That mirrors
    the fail-closed contract: a build/gate failure returns guidance instead
    of answering from a half-resolved graph.

    ``conn`` is None whenever the index is unusable; callers only act on it when
    ``ok`` is True. Never raises.
    """
    try:
        if not (Path(root) / ".codegraph").is_dir():
            return None, False
        state = _db.index_state(root)
    except Exception:  # pragma: no cover - index_state already degrades
        return None, False
    if not state.get("available"):
        return None, False
    conn = _db.connect(root)
    if conn is None:
        return None, False
    if int(state.get("refs_pending") or 0) > 0:
        return conn, False
    return conn, True


def _contained_file(root: str, file_path: str) -> Path | None:
    """Resolve an index-relative path under the repo root, or None."""
    if not file_path:
        return None
    try:
        base = _safe_root(root)
        target = (base / file_path).resolve()
        target.relative_to(base.resolve())
    except (ValueError, OSError):
        return None
    try:
        if target.is_file() and not target.is_symlink():
            return target
    except OSError:
        return None
    return None


def _source_line(root: str, file_path: str, line: int) -> str:
    """The raw source line (no newline, capped at 1000 chars) or ''."""
    if line <= 0:
        return ""
    path = _contained_file(root, file_path)
    if path is None:
        return ""
    try:
        if path.stat().st_size > 5_000_000:
            return ""
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if 0 < line <= len(lines):
        return lines[line - 1][:1000]
    return ""


def _paginate(lines: list[str], limit, offset, env_key: str, default: int) -> str:
    """The shared footer: ``… showing a-b of N (use offset=… to page)``."""
    lim = _resolve_limit(limit, env_key, default)
    off = max(int(offset or 0), 0)
    total = len(lines)
    page = lines[off:] if lim <= 0 else lines[off: off + lim]
    body = "\n".join(page)[:20000]
    if total > len(page) or off > 0:
        body += (f"\n… showing {off + 1}-{off + len(page)} of {total} "
                 f"(use offset={off + len(page)} to page)")
    return body


def _cap_section(lines: list[str], lim: int) -> list[str]:
    return lines if lim <= 0 else lines[:lim]


# ---------------------------------------------------------------------------
# framework_routes: route nodes from the index
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def framework_routes(root: str = ".", limit: int | None = None, offset: int = 0) -> str:
    """Index-backed web-framework routes (URL + handler file:line). Paginated via limit/offset.

    Args:
        root: Directory to scan for route declarations.
        limit: Max routes per page. 0 = unlimited.
        offset: Route index to start from, for paging.
    """
    conn, ok = _index_gate(root)
    if not ok:
        return _db.guidance_no_db(root)
    try:
        from cerberus.codegraph import native
        res = native.routing_manifest(root)
        manifest = res.get("manifest") if isinstance(res, dict) else None
        entries = manifest.get("entries") if isinstance(manifest, dict) else (manifest if isinstance(manifest, list) else [])
        if entries:
            lines = []
            for r in entries:
                url = r.get("url") or r.get("path") or "/"
                handler = r.get("handler") or r.get("name") or "handler"
                rf = r.get("routeFile") or r.get("filePath") or "routes"
                rl = r.get("routeLine") or r.get("startLine") or 1
                hf = r.get("handlerFile") or rf
                hl = r.get("handlerLine") or rl
                lines.append(f"{rf}:{rl}: [route] {url} -> {handler} ({hf}:{hl})")
            if lines:
                return _paginate(lines, limit, offset, "ROUTES_LIMIT", 500)
    except Exception:
        pass
    return "(no matches)"


# ---------------------------------------------------------------------------
# callers / callees: edge tables from the index
# ---------------------------------------------------------------------------

def _sanitize_func_name(func_name: str) -> str:
    name = str(func_name or "").strip()
    if not name or len(name) > 200:
        return ""
    if not re.match(r"^[\w.]+$", name):
        return ""
    return name


@tool(parse_docstring=True)
def callers(func_name: str, root: str = ".", file: str | None = None,
            limit: int | None = None, as_json: bool = False) -> str:
    """Find call sites of func_name from the CodeGraph index. Paginated via limit (0=unlimited).

    Args:
        func_name: Function name whose call sites to find.
        root: Directory to search.
        file: Optional file path to disambiguate same-named definitions.
        limit: Max call sites per section. 0 = unlimited.
        as_json: Return structured JSON with enriched metadata (confidence, column, target ID).
    """
    name = _sanitize_func_name(func_name)
    if not name:
        return "(no matches)"
    conn, ok = _index_gate(root)
    if not ok:
        return _db.guidance_no_db(root)
    try:
        from cerberus.codegraph import native
        limit_arg = 100 if limit is None else limit
        res = native.callers_json(name, repo=root, file=file, limit=limit_arg)
        if as_json:
            import json
            return json.dumps(res, indent=2)
        defs = res.get("definitions") or []
        calls = res.get("callers") or []
        if not defs and not calls:
            return "(no matches)"
        _lim = _resolve_limit(limit, "CALLERS_LIMIT", 100)
        out: list[str] = []
        def_lines: list[str] = []
        for d in defs:
            line = int(d.get("startLine") or 0)
            src = _source_line(root, d.get("filePath") or "", line)
            text = src or str(d.get("signature") or d.get("name") or name)
            def_lines.append(f"{d.get('filePath')}:{line}: {text}")
        call_lines: list[str] = []
        for c in calls:
            fp = c.get("filePath") or ""
            line = int(c.get("line") or 0)
            src = _source_line(root, fp, line)
            call_lines.append(f"{fp}:{line}: {src or c.get('name') or ''}")
        if def_lines:
            out.append("## def")
            out.extend(_cap_section(def_lines, _lim))
        if call_lines:
            out.append("## calls")
            out.extend(_cap_section(call_lines, _lim))
        return "\n".join(out)[:20000] or "(no matches)"
    except Exception:
        pass
    return "(no matches)"


@tool(parse_docstring=True)
def callees(func_name: str, root: str = ".", file: str | None = None,
            limit: int | None = None, as_json: bool = False) -> str:
    """Find what func_name calls from the CodeGraph index. Paginated via limit (0=unlimited).

    Args:
        func_name: Function name whose body to scan.
        root: Directory to search.
        file: Optional file path to disambiguate same-named definitions.
        limit: Max callees. 0 = unlimited.
        as_json: Return structured JSON with enriched metadata (confidence, column, target ID).
    """
    name = _sanitize_func_name(func_name)
    if not name:
        return "(no matches)"
    conn, ok = _index_gate(root)
    if not ok:
        return _db.guidance_no_db(root)
    try:
        from cerberus.codegraph import native
        limit_arg = 100 if limit is None else limit
        res = native.callees_json(name, repo=root, file=file, limit=limit_arg)
        if as_json:
            import json
            return json.dumps(res, indent=2)
        callees_list = res.get("callees") or []
        if not callees_list:
            return "(no matches)"
        seen = [c.get("label") or f"{c.get('filePath')}:{c.get('name')}()" for c in callees_list]
        return _paginate(seen, limit, 0, "CALLERS_LIMIT", 100)
    except Exception:
        pass
    return "(no matches)"


# ---------------------------------------------------------------------------
# affected: getImpactRadius semantics over the index (no grep equivalent)
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def affected(node: str, root: str = ".", file: str | None = None,
             depth: int = 3, limit: int | None = None) -> str:
    """Who CAN reach this symbol: reverse BFS over call edges (proves reachability, not taint). Paginated via limit (0=unlimited).

    Implements CodeGraph's getImpactRadius semantics: reverse BFS over ALL
    incoming edges with kind != 'contains', container kinds additionally walked
    down into their children, depth-capped (default 3). Call-site lines prove
    REACHABILITY only, never taint flow — open the code and verify the argument.

    Args:
        node: Symbol to trace backwards from.
        root: Repo root holding the index.
        file: Optional file path to disambiguate same-named definitions.
        depth: Max reverse hops (clamped to 1..10).
        limit: Max affected nodes. 0 = unlimited.
    """
    name = _sanitize_func_name(node) or str(node or "").strip()[:200]
    if not name:
        return "(no matches)"
    conn, ok = _index_gate(root)
    if not ok:
        return _db.guidance_no_db(root)
    try:
        depth_cap = int(depth)
    except (TypeError, ValueError):
        depth_cap = 3
    depth_cap = min(max(depth_cap, 1), 10)
    try:
        from cerberus.codegraph import native
        res = native.impact(name, depth=depth_cap, repo=root, file=file)
        results = res.get("results") or []
        roots = res.get("roots") or []
        if not results and not roots:
            return "(no matches)"
        seed_label = ", ".join(f"{n.get('filePath')}:{n.get('startLine')}" for n in roots[:5]) if roots else name
        lines = [f"Affected nodes for {name} (depth<={depth_cap}, total {len(results)}; seeds: {seed_label})"]
        _lim = _resolve_limit(limit, "AFFECTED_LIMIT", 100)
        page = results if _lim <= 0 else results[:_lim]
        for r in page:
            node_info = r.get("node") or {}
            loc = f"{node_info.get('filePath')}:{r.get('viaLine') or node_info.get('startLine')}"
            flag = ""
            conf = float(r.get("confidence", 1.0))
            if r.get("kind") != "contains" and conf < UNCERTAIN_BELOW:
                flag = " UNCERTAIN (name-only guess; do not follow)"
            lines.append(f"- {node_info.get('name')} [{node_info.get('kind')}] {loc} "
                         f"(hop {r.get('hop', 1)}, {r.get('kind', 'calls')}, "
                         f"confidence {conf:.2f}){flag}")
        if not results:
            lines.append("- (nothing reaches this symbol within the depth cap)")
        elif len(results) > len(page):
            lines.append(f"… +{len(results) - len(page)} more")
        return "\n".join(lines)[:20000]
    except Exception:
        pass
    return "(no matches)"


# ---------------------------------------------------------------------------
# Native CodeGraph High-Order Tools (1-shot explore, impact, path & context)
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def codegraph_explore(query: str, max_files: int = 5) -> str:
    """1-shot code exploration over the CodeGraph index.

    Returns the verbatim, line-numbered source code of relevant symbols across
    files, PLUS the call path connecting them (including dynamic-dispatch hops),
    PLUS the blast-radius summary of dependents. Reach for this BEFORE reading
    files or running multi-step greps — ONE call usually provides the complete flow.

    Args:
        query: Natural language question or symbol/file names (e.g. 'auth verify_token').
        max_files: Maximum number of files to include verbatim source from (default: 5).
    """
    from cerberus.codegraph import native
    return native.explore(query, max_files=max_files)


@tool(parse_docstring=True)
def find_path(from_symbol: str, to_symbol: str) -> str:
    """Find the shortest call path between two symbols across the codebase.

    Traces calls across interprocedural hops and dynamic dispatch, returning each
    step's file, line, call site, and edge confidence.

    Args:
        from_symbol: Starting function or method name (e.g. 'handle_request').
        to_symbol: Target function or sink name (e.g. 'execute_query').
    """
    from cerberus.codegraph import native
    res = native.find_path(from_symbol, to_symbol)
    if isinstance(res, dict) and res.get("error"):
        return f"ERROR: call-path search unavailable: {res['error']}"
    path = res if isinstance(res, list) else None
    if not path:
        return f"No call path found from {from_symbol} to {to_symbol}."
    lines = [f"Call path from {from_symbol} to {to_symbol} ({len(path)} steps):"]
    for i, step in enumerate(path):
        node = step.get("node", {})
        edge = step.get("edge")
        node_desc = f"[{node.get('kind', 'symbol')}] {node.get('name')} ({node.get('filePath')}:{node.get('startLine')})"
        if edge:
            conf = edge.get("metadata", {}).get("confidence", 1.0)
            lines.append(f"  --({edge.get('kind', 'calls')}, conf: {conf})--> {node_desc}")
        else:
            lines.append(f"  1. {node_desc}")
    return "\n".join(lines)


@tool(parse_docstring=True)
def impact_radius(symbol: str, depth: int = 2) -> str:
    """Analyze the downstream transitive blast radius of a symbol across files.

    Args:
        symbol: Function, class, or variable name.
        depth: Traversal depth (default: 2).
    """
    from cerberus.codegraph import native
    res = native.impact(symbol, depth=depth)
    if "error" in res:
        return f"Error computing impact for {symbol}: {res['error']}"
    nodes = res.get("nodes", [])
    if not nodes:
        return f"No impacted symbols found for {symbol} at depth {depth}."
    lines = [f"Impact radius of {symbol} (depth {depth}): {len(nodes)} affected symbols:"]
    for n in nodes[:40]:
        lines.append(f"  - [{n.get('kind')}] {n.get('name')} ({n.get('filePath')}:{n.get('startLine')})")
    if len(nodes) > 40:
        lines.append(f"  ... ({len(nodes) - 40} more symbols)")
    return "\n".join(lines)


@tool(parse_docstring=True)
def type_hierarchy(symbol: str) -> str:
    """Map a class/interface's ancestors and descendants via extends/implements.

    Use this for inherited auth guards, base-class validators, interface
    implementers, and subclasses of a permissive base parser/deserializer.

    Args:
        symbol: Class, interface, struct, or trait name.
    """
    from cerberus.codegraph import native
    res = native.type_hierarchy(symbol)
    if res.get("error"):
        return f"ERROR: type hierarchy unavailable: {res['error']}"
    nodes = res.get("nodes", [])
    edges = res.get("edges", [])
    if not nodes:
        return f"No type hierarchy found for {symbol}."

    by_id = {n.get("id"): n for n in nodes}
    type_word = "type" if len(nodes) == 1 else "types"
    relation_word = "relation" if len(edges) == 1 else "relations"
    lines = [
        f"Type hierarchy for {symbol} "
        f"({len(nodes)} {type_word}, {len(edges)} {relation_word}):"
    ]
    for n in nodes[:40]:
        lines.append(
            f"  [{n.get('kind', 'type')}] {n.get('name')} "
            f"({n.get('filePath')}:{n.get('startLine')})"
        )
    if len(nodes) > 40:
        lines.append(f"  ... ({len(nodes) - 40} more types)")

    if edges:
        lines.append("Relations:")
        for edge in edges[:40]:
            src = by_id.get(edge.get("source"), {}).get("name") or edge.get("source")
            dst = by_id.get(edge.get("target"), {}).get("name") or edge.get("target")
            lines.append(f"  {src} -[{edge.get('kind', 'relation')}]-> {dst}")
        if len(edges) > 40:
            lines.append(f"  ... ({len(edges) - 40} more relations)")
    return "\n".join(lines)


@tool(parse_docstring=True)
def build_context(task: str, max_nodes: int = 20) -> str:
    """Assemble focused context for a task, identifying key entry points, related files, and symbols.

    Args:
        task: Security task or focus description (e.g. 'investigate SSRF in webhook handler').
        max_nodes: Maximum symbols to include (default: 20).
    """
    from cerberus.codegraph import native
    res = native.build_context(task, max_nodes=max_nodes)
    if "error" in res:
        return f"Context assembly error: {res['error']}"
    summary = res.get("summary", "")
    entry_points = res.get("entryPoints", [])
    related_files = res.get("relatedFiles", [])
    lines = [summary]
    if entry_points:
        lines.append("\nKey Entry Points:")
        for ep in entry_points:
            lines.append(f"  - [{ep.get('kind')}] {ep.get('name')} ({ep.get('filePath')}:{ep.get('startLine')})")
    if related_files:
        lines.append(f"\nRelated Files: {', '.join(related_files)}")
    return "\n".join(lines)


@tool(parse_docstring=True)
def detect_circular_and_dead_code() -> str:
    """Find circular dependencies and unreferenced dead code in the repository."""
    from cerberus.codegraph import native
    res = native.circular_and_dead_code()
    if res.get("error"):
        return f"ERROR: circular/dead analysis unavailable: {res['error']}"
    circular = res.get("circular_dependencies", [])
    dead = res.get("dead_code", [])
    lines = []
    if circular:
        lines.append(f"Circular Dependencies ({len(circular)} cycles):")
        for cyc in circular[:10]:
            lines.append(f"  - {' -> '.join(cyc)}")
    else:
        lines.append("No circular dependencies detected.")
    if dead:
        lines.append(f"\nUnreferenced/Dead Code ({len(dead)} symbols):")
        for d in dead[:20]:
            lines.append(f"  - [{d.get('kind')}] {d.get('name')} ({d.get('filePath')}:{d.get('startLine')})")
    return "\n".join(lines)


@tool(parse_docstring=True)
def get_routing_manifest() -> str:
    """Retrieve the native framework routing manifest and detected web frameworks (Next.js, Express, Django, FastAPI, Rails, etc.)."""
    import json
    from cerberus.codegraph import native
    res = native.routing_manifest()
    if res.get("error"):
        return f"ERROR: routing manifest unavailable: {res['error']}"
    frameworks = res.get("frameworks", [])
    manifest = res.get("manifest")
    lines = []
    if frameworks:
        lines.append(f"Detected Frameworks: {', '.join(frameworks)}")
    else:
        lines.append("Detected Frameworks: None")
    if manifest:
        lines.append(f"Routing Manifest:\n{json.dumps(manifest, indent=2)}")
    else:
        lines.append("Routing Manifest: (no framework routes declared)")
    return "\n".join(lines)


__all__ = [
    "framework_routes",
    "callers",
    "callees",
    "affected",
    "codegraph_explore",
    "find_path",
    "impact_radius",
    "type_hierarchy",
    "build_context",
    "detect_circular_and_dead_code",
    "get_routing_manifest",
    "codegraph_tools",
    "CODEGRAPH_TOOL_NAMES",
    "ROUTE_LINE_RE",
    "UNCERTAIN_BELOW",
    *CODEGRAPH_TOOL_NAMES,
]
