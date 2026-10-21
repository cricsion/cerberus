"""Code-intelligence tools bound on the shared agent surface (plan § D3, D4).

This is the ONE binding module for the code-intelligence family. Two groups
live here:

- **The ``_db``-first graph tools** — :func:`callers`, :func:`callees`,
  :func:`framework_routes`, :func:`affected`. Each answers from the prebuilt
  CodeGraph index (``<root>/.codegraph/codegraph.db``, read-only) when it is
  present AND the DB-visible half of the build gate passes (``pendingRefs`` is
  zero); otherwise — and whenever the index yields nothing for the query — it
  falls back to the deterministic grep implementation in the *same output
  format* (``path:line:`` prefixes; ``## def`` / ``## calls`` markers; the
  ``(no matches)`` sentinel). That format is load-bearing: ``threat_model_node``
  counts lines and the pipeline's routes stage greps the text.
- **The 18 ``harness.codegraph`` tools** (navigation / authz / contracts /
  variants / supply / polyglot). They already answer ``_db``-first internally;
  they are re-exported here so ``harness/agents/toolsets.py`` binds the whole
  code-intelligence surface from one place (:func:`codegraph_tools`).

Import law: this module imports only ``harness.codegraph`` (the 18 + ``_db``),
stdlib, and the existing harness tool helpers (``harness.tools.code``) — no new
dependencies. Nothing here shells ``codegraph``; the CLI is the indexer's tool,
never an agent's.
"""
from __future__ import annotations

import re
from collections import deque
from pathlib import Path

from harness.codegraph import (
    audit_llm_and_mcp_tool_sinks,
    compare_sibling_route_security,
    find_shared_state_readers_writers,
    get_ast_slice,
    get_function_security_summary,
    inspect_config_and_secret_hygiene,
    inspect_cross_language_bridge,
    inspect_type_contract,
    query_historical_triage_memory,
    record_function_security_summary,
    resolve_blind_spot,
    synthesize_and_sweep_variant_rule,
    trace_egress_and_ssrf_targets,
    trace_interprocedural_hop,
    trace_state_machine_transitions,
    validate_remediation_patch,
    verify_cve_symbol_reachability,
    verify_exploit_poc_in_harness,
)
from harness.codegraph import _db
from harness.config import get_default_config

from ._compat import tool
from .code import _resolve_limit, grep_files

# The 18 harness.codegraph tools, in the package's own order. Kept as names so
# codegraph_tools() stays a single source of truth and __all__ is derived.
CODEGRAPH_TOOL_NAMES: tuple[str, ...] = (
    "get_ast_slice",
    "trace_interprocedural_hop",
    "resolve_blind_spot",
    "compare_sibling_route_security",
    "find_shared_state_readers_writers",
    "trace_state_machine_transitions",
    "inspect_type_contract",
    "record_function_security_summary",
    "get_function_security_summary",
    "validate_remediation_patch",
    "synthesize_and_sweep_variant_rule",
    "query_historical_triage_memory",
    "verify_cve_symbol_reachability",
    "inspect_config_and_secret_hygiene",
    "trace_egress_and_ssrf_targets",
    "inspect_cross_language_bridge",
    "audit_llm_and_mcp_tool_sinks",
    "verify_exploit_poc_in_harness",
)

# CodeGraph's uncertainty boundary (src/graph/dynamic-boundary-report.ts): below
# it an edge is a name-only guess, not a proven call — a hop to follow only with
# explicit scepticism.
UNCERTAIN_BELOW = float(get_default_config("codegraph.partition.uncertain_below"))

# Container kinds whose children count as affected when the container is reached
# (getImpactRadius semantics: a class reaching its methods counts).
_CONTAINER_KINDS = frozenset({
    "file", "class", "interface", "struct", "trait", "enum", "union",
    "module", "namespace", "object", "record", "protocol", "impl",
})

# Definition kinds ``callers`` / ``callees`` will treat as the target symbol.
_CALLABLE_KINDS = ("function", "method", "constructor", "macro")

# The pinned route line, emitted by the ``_db``-first framework_routes path:
#     <route_file>:<route_line>: [route] <url> -> <handler> (<handler_file>:<handler_line>)
ROUTE_LINE_RE = re.compile(
    r"^(?P<route_file>.+?):(?P<route_line>\d+): \[route\] "
    r"(?P<url>.+?) -> (?P<handler>\S+) "
    r"\((?P<handler_file>.+?):(?P<handler_line>\d+)\)$"
)


def codegraph_tools() -> list:
    """The 18 ``harness.codegraph`` tools, in a stable order.

    ``harness/agents/toolsets.py`` binds this list beside the ``_db``-first grep
    tools, so the whole code-intelligence surface is defined once and the roles
    cannot drift apart (plan § D3).
    """
    return [globals()[name] for name in CODEGRAPH_TOOL_NAMES]


def _safe_root(root: str) -> Path:
    from harness.tools.code import _safe_path
    return _safe_path(root)


# ---------------------------------------------------------------------------
# index presence + the DB-visible half of the build gate (plan § D2/D4)
# ---------------------------------------------------------------------------

def _index_gate(root: str):
    """(conn, ok): the read-only index handle and whether it may be trusted.

    ``ok`` is False when the index is absent/unreadable OR when the DB-visible
    half of CodeGraph's build gate fails — ``unresolved_refs`` still has
    ``pending`` rows, i.e. the resolution pass has not finished. That mirrors
    D2's fail-open contract: a build/gate failure sends the agents to the grep
    tools instead of answering from a half-resolved graph.

    ``conn`` is None whenever the index is unusable; callers only act on it when
    ``ok`` is True. Never raises.
    """
    try:
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
    """The raw source line (no newline, capped at 1000 chars) or ''.

    The grep fallback emits ``rel:line: <raw text>``; the ``_db`` path reads the
    same text back so the two paths share one line format.
    """
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


def _file_matches(node_file, want: str) -> bool:
    nf = str(node_file or "").replace("\\", "/")
    w = str(want or "").replace("\\", "/").lstrip("./")
    if not w:
        return True
    return (nf == want or nf == w or nf.endswith("/" + w)
            or Path(nf).name == Path(w).name)


def _def_nodes(conn, name: str, file: str | None, limit: int = 500) -> list[dict]:
    """Definition nodes for ``name`` (tail), optionally disambiguated by ``file``.

    Same-named symbols are common in scans, so ``file`` (the MCP-schema
    disambiguator) narrows to one definition before the call edges are read.
    """
    tail = str(name).split(".")[-1]
    if not tail:
        return []
    nodes = _db.find_nodes(conn, name=tail, limit=limit)
    if not nodes:
        return []
    callables = [n for n in nodes if str(n.get("kind")) in _CALLABLE_KINDS]
    if callables:
        nodes = callables
    if file:
        matched = [n for n in nodes if _file_matches(n.get("file_path"), file)]
        if matched:
            nodes = matched
    return nodes


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
# manifest_parse (unchanged: filesystem-only, no index)
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def manifest_parse(root: str = ".", limit: int | None = None) -> str:
    """Summarize dependency manifests + container/IaC files under root. Paginated via limit (0=unlimited).

    Args:
        root: Directory containing manifests/IaC files.
        limit: Max files to summarize. 0 = unlimited.
    """
    try:
        base = _safe_root(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not base.exists():
        return "(no manifests found)"
    lines: list[str] = []
    known = [
        "package.json", "package-lock.json", "requirements.txt",
        "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
        "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
        "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
        "Cargo.toml", "Cargo.lock", "packages.config",
        "CMakeLists.txt", "Makefile",
    ]
    for proj in sorted(base.glob("*.csproj")):
        try:
            if proj.is_file():
                lines.append(f"{proj.name} (.NET)")
        except OSError:
            continue
    for name in known:
        p = base / name
        if p.is_file():
            try:
                size = p.stat().st_size
            except OSError:
                size = -1
            try:
                preview = p.read_text(errors="replace")[:1500].strip().replace("\n", " ")[:500]
            except OSError:
                preview = "(unreadable)"
            lines.append(f"{name} ({size} bytes): {preview}")
    for f in sorted(base.glob("requirements*.txt")):
        if f.name == "requirements.txt":
            continue
        if len(lines) >= 20:
            break
        try:
            if f.is_file():
                lines.append(f"{f.name} ({f.stat().st_size} bytes)")
        except OSError:
            continue
    for f in sorted(base.rglob("*")):
        if len(lines) >= 30:
            break
        try:
            if not f.is_file():
                continue
            n = f.name.lower()
            if n == "dockerfile" or n.startswith("dockerfile.") or n == "docker-compose.yml" or n == "docker-compose.yaml":
                try:
                    rel = f.relative_to(base)
                except ValueError:
                    rel = f
                lines.append(f"{rel} (docker)")
            elif f.suffix.lower() == ".tf":
                try:
                    rel = f.relative_to(base)
                except ValueError:
                    rel = f
                lines.append(f"{rel} (terraform)")
        except OSError:
            continue
    if not lines:
        return "(no manifests found)"
    _lim = _resolve_limit(limit, "MANIFEST_LINES", 200)
    total = len(lines)
    page = lines if _lim <= 0 else lines[:_lim]
    body = "\n".join(page)[:20000]
    if total > len(page):
        body += f"\n… +{total - len(page)} more manifests (total {total})"
    return body


# ---------------------------------------------------------------------------
# framework_routes: route nodes from the index, regex elsewhere
# ---------------------------------------------------------------------------

def _routes_db(conn, limit, offset) -> str | None:
    """The index's routing manifest in the pinned route format, or None.

    None means "the index has no routes" — the caller then greps, so an
    unindexed framework still shows up.
    """
    rows = _db.routing_manifest(conn, limit=5000)
    if not rows:
        return None
    lines = []
    for r in rows:
        lines.append(
            f"{r.get('route_file')}:{r.get('route_line')}: [route] {r.get('url')} "
            f"-> {r.get('handler')} ({r.get('handler_file')}:{r.get('handler_line')})"
        )
    return _paginate(lines, limit, offset, "ROUTES_LIMIT", 500)


def _routes_grep(root: str, limit, offset: int) -> str:
    """The deterministic regex route scan (today's implementation, verbatim)."""
    pattern = (
        r"(@(app|router|api)\.(get|post|put|delete|patch|route)\b"
        r"|@app\.route\b"
        r"|app\.(get|post|put|delete|route)\s*\("
        r"|router\.(get|post|put|delete|use)\s*\("
        r"|@(?:Get|Post|Put|Delete|Patch|Route|Controller|RestController|RequestMapping)\b"
        r"|express\s*\.\s*(get|post)"
        r"|\.get\s*\(\s*['\"]/"
        r"|Route\s*::"
        r"|^\s*(get|post|put|patch|delete)\s+['\"][^'\"]*['\"]\s*(=>|do|,)"
        r"|^\s*resources\s+:\w+"
        r"|\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b"
        r"|Map(Get|Post|Put|Delete)\s*\("
        r"|http\.HandleFunc\s*\("
        r"|\b(gin|echo)\.(GET|POST|PUT|DELETE)\s*\("
        r"|^\s*(path|re_path|url)\s*\("
        r"|\(\s*r?['\"]/[^'\"]*['\"]\s*,\s*\w+Handler\b"
        r"|\badd_url_rule\s*\("
        r"|^\s{2}(/[a-zA-Z0-9_{}/-]+):"
        r")"
    )
    # Ask grep for a large window; we page locally for stable offsets.
    res = grep_files(regex=pattern, include="*", root=root, limit=5000)
    raw_lines = [l for l in res.splitlines() if l.strip() and not l.startswith("… ")] if res and "(no matches)" not in res else []
    valid_exts = (
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java",
        ".cs", ".rs", ".kt", ".scala", ".yml", ".yaml", ".json"
    )
    skip_parts = (
        "/tests/", "/test/", "/spec/", "/specs/", "/fixtures/",
        "/codefixes/", "static/font-awesome/", "node_modules/"
    )
    all_lines = []
    for line in raw_lines:
        path_part = line.split(":", 1)[0].replace("\\", "/").lower()
        if not path_part.startswith("/"):
            path_part = "/" + path_part
        if any(path_part.endswith(ext) for ext in valid_exts):
            if not any(sp in path_part for sp in skip_parts):
                if path_part.endswith((".yml", ".yaml", ".json")):
                    if not any(k in path_part for k in ("openapi", "swagger", "api")):
                        continue
                all_lines.append(line)

    try:
        from pathlib import Path as _Path
        base = _Path(root)
        for pages_dir_name in ("pages", "src/pages"):
            p_dir = base / pages_dir_name
            if p_dir.is_dir():
                for f in sorted(p_dir.rglob("*")):
                    if f.is_file() and f.suffix in (".js", ".ts", ".jsx", ".tsx"):
                        name = f.name
                        if not name.startswith(("_app.", "_document.", "_error.")):
                            rel = f.relative_to(base)
                            all_lines.append(f"{rel}:1: [page route] {rel}")
    except OSError:
        pass

    if not all_lines:
        return "(no matches)"
    return _paginate(all_lines, limit, offset, "ROUTES_LIMIT", 500)


@tool(parse_docstring=True)
def framework_routes(root: str = ".", limit: int | None = None, offset: int = 0) -> str:
    """Index-first web-framework routes (URL + handler file:line); regex fallback. Paginated via limit/offset.

    Args:
        root: Directory to scan for route declarations.
        limit: Max routes per page. 0 = unlimited.
        offset: Route index to start from, for paging.
    """
    conn, ok = _index_gate(root)
    if ok:
        db_out = _routes_db(conn, limit, offset)
        if db_out is not None:
            return db_out
    return _routes_grep(root, limit, offset)


# ---------------------------------------------------------------------------
# callers / callees: edge tables first, regex elsewhere
# ---------------------------------------------------------------------------

def _sanitize_func_name(func_name: str) -> str:
    name = str(func_name or "").strip()
    if not name or len(name) > 200:
        return ""
    if not re.match(r"^[\w.]+$", name):
        return ""
    return name


def _callers_db(conn, root: str, name: str, file: str | None, limit) -> str | None:
    """Call sites from incoming ``calls`` edges, or None when no def is indexed."""
    defs = _def_nodes(conn, name, file)
    if not defs:
        return None
    _lim = _resolve_limit(limit, "CALLERS_LIMIT", 100)
    out: list[str] = []
    def_lines: list[str] = []
    for n in defs:
        line = int(n.get("start_line") or 0)
        src = _source_line(root, n.get("file_path") or "", line)
        text = src or str(n.get("signature") or n.get("name") or name)
        def_lines.append(f"{n.get('file_path')}:{line}: {text}")
    call_lines: list[str] = []
    seen: set[tuple] = set()
    for n in defs:
        for e in _db.incoming_edges(conn, n["id"], kinds=["calls"], limit=500):
            caller = _db.get_node(conn, e.get("source"))
            if caller is None:
                continue
            fp = caller.get("file_path") or ""
            line = int(e.get("line") or caller.get("start_line") or 0)
            key = (fp, line)
            if key in seen:
                continue
            seen.add(key)
            src = _source_line(root, fp, line)
            call_lines.append(f"{fp}:{line}: {src or caller.get('name') or ''}")
    if def_lines:
        out.append("## def")
        out.extend(_cap_section(def_lines, _lim))
    if call_lines:
        out.append("## calls")
        out.extend(_cap_section(call_lines, _lim))
    return "\n".join(out)[:20000] or "(no matches)"


def _callers_grep(name: str, root: str, limit) -> str:
    """The deterministic grep call-site scan (today's implementation, verbatim)."""
    esc = re.escape(name)
    _lim = _resolve_limit(limit, "CALLERS_LIMIT", 100)
    out: list[str] = []
    def_res = grep_files(regex=rf"^\s*(def|function|func|fn)\s+{esc}\b", include="*", root=root, limit=5000)
    if (not def_res or "(no matches)" in def_res) and "." not in name:
        # C-family definitions: `<type> name(` — looser, may over-match.
        c_res = grep_files(regex=rf"^\s*[A-Za-z_][\w\s\*&:<>]*\b{esc}\s*\(", include="*", root=root)
        if c_res and "(no matches)" not in c_res:
            def_res = c_res if not def_res or "(no matches)" in def_res else def_res + "\n" + c_res
    call_res = grep_files(regex=rf"\b{esc}\s*\(", include="*", root=root, limit=5000)
    if def_res and "(no matches)" not in def_res:
        out.append("## def")
        def_lines = [l for l in def_res.splitlines() if l.strip() and not l.startswith("… ")]
        out.extend(def_lines if _lim <= 0 else def_lines[:_lim])
    if call_res and "(no matches)" not in call_res:
        out.append("## calls")
        call_lines = [l for l in call_res.splitlines() if l.strip() and not l.startswith("… ")]
        out.extend(call_lines if _lim <= 0 else call_lines[:_lim])
    return "\n".join(out)[:20000] or "(no matches)"


@tool(parse_docstring=True)
def callers(func_name: str, root: str = ".", file: str | None = None,
            limit: int | None = None) -> str:
    """Find call sites of func_name (index edges first, grep fallback). Paginated via limit (0=unlimited).

    Args:
        func_name: Function name whose call sites to find.
        root: Directory to search.
        file: Optional file path to disambiguate same-named definitions.
        limit: Max call sites per section. 0 = unlimited.
    """
    name = _sanitize_func_name(func_name)
    if not name:
        return "(no matches)"
    conn, ok = _index_gate(root)
    if ok:
        db_out = _callers_db(conn, root, name, file, limit)
        if db_out is not None:
            return db_out
    return _callers_grep(name, root, limit)


def _callees_db(conn, root: str, name: str, file: str | None, limit) -> str | None:
    """Callees from outgoing ``calls`` edges, or None when no def is indexed."""
    defs = _def_nodes(conn, name, file)
    if not defs:
        return None
    _lim = _resolve_limit(limit, "CALLERS_LIMIT", 100)
    seen: list[str] = []
    seen_set: set[str] = set()
    for n in defs:
        for e in _db.outgoing_edges(conn, n["id"], kinds=["calls"], limit=500):
            target = _db.get_node(conn, e.get("target"))
            if target is None:
                continue
            rel = target.get("file_path") or ""
            label = f"{rel}:{target.get('name')}()"
            if label in seen_set:
                continue
            seen_set.add(label)
            seen.append(label)
            if _lim > 0 and len(seen) >= _lim:
                break
        if _lim > 0 and len(seen) >= _lim:
            break
    if not seen:
        return None
    return _paginate(seen, limit, 0, "CALLERS_LIMIT", 100)


def _callees_grep(name: str, root: str, limit) -> str:
    """The deterministic grep callee scan (today's implementation, verbatim)."""
    try:
        base = _safe_root(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not base.exists():
        return "(no matches)"
    esc = re.escape(name)
    def_res = grep_files(regex=rf"^\s*def\s+{esc}\s*\(", include="*.py", root=root)
    if def_res and "(no matches)" in def_res:
        def_res = ""
    if not def_res:
        def_res = grep_files(regex=rf"^\s*(def|function|func)\s+{esc}\b", include="*", root=root)
        if def_res and "(no matches)" in def_res:
            return "(no matches)"
    if not def_res:
        return "(no matches)"
    call_pat = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    _lim2 = _resolve_limit(limit, "CALLERS_LIMIT", 100)
    seen: list[str] = []
    seen_set: set[str] = set()
    for line in def_res.splitlines()[:10]:
        try:
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            rel, num = parts[0], parts[1]
            lineno = int(num)
        except (ValueError, IndexError):
            continue
        try:
            fpath = (base / rel).resolve()
            # Re-check after resolving: rel may traverse a symlink dir.
            fpath.relative_to(base.resolve())
            if not fpath.is_file() or fpath.is_symlink():
                continue
            text = fpath.read_text(errors="replace").splitlines()
        except OSError:
            continue
        except ValueError:
            continue
        body = text[lineno - 1: lineno - 1 + 200]
        for bline in body[1:]:
            # Stop at next top-level def to avoid bleeding into sibling funcs.
            if re.match(r"^(def|class)\s+\w+", bline):
                break
            for m in call_pat.finditer(bline):
                callee = m.group(1)
                if callee == name.split(".")[-1]:
                    continue
                if callee not in seen_set:
                    seen_set.add(callee)
                    seen.append(f"{rel}:{callee}()")
                if _lim2 > 0 and len(seen) >= _lim2:
                    break
        if _lim2 > 0 and len(seen) >= _lim2:
            break
    if not seen:
        return "(no callees found)"
    page = seen if _lim2 <= 0 else seen[:_lim2]
    body_out = "\n".join(page)[:20000]
    if len(seen) > len(page):
        body_out += f"\n… +{len(seen) - len(page)} more"
    return body_out


@tool(parse_docstring=True)
def callees(func_name: str, root: str = ".", file: str | None = None,
            limit: int | None = None) -> str:
    """Find what func_name calls (index edges first, grep fallback). Paginated via limit (0=unlimited).

    Args:
        func_name: Function name whose body to scan.
        root: Directory to search.
        file: Optional file path to disambiguate same-named definitions.
        limit: Max callees. 0 = unlimited.
    """
    name = _sanitize_func_name(func_name)
    if not name:
        return "(no matches)"
    conn, ok = _index_gate(root)
    if ok:
        db_out = _callees_db(conn, root, name, file, limit)
        if db_out is not None:
            return db_out
    return _callees_grep(name, root, limit)


# ---------------------------------------------------------------------------
# affected: getImpactRadius semantics over the index (no grep equivalent)
# ---------------------------------------------------------------------------

def _edge_confidence(edge: dict) -> float:
    meta = edge.get("metadata") or {}
    try:
        return float(meta.get("confidence", 1.0))
    except (TypeError, ValueError):
        return 1.0


def _affected_db(conn, root: str, name: str, file: str | None, depth: int, limit) -> str | None:
    seeds = _def_nodes(conn, name, file)
    if not seeds:
        return None
    try:
        depth_cap = int(depth)
    except (TypeError, ValueError):
        depth_cap = 3
    depth_cap = min(max(depth_cap, 1), 10)
    seed_label = ", ".join(f"{n.get('file_path')}:{n.get('start_line')}" for n in seeds[:5])
    seen: set[str] = {n["id"] for n in seeds}
    results: list[dict] = []
    queue: deque = deque((n["id"], 0) for n in seeds)
    while queue:
        nid, hop = queue.popleft()
        if hop >= depth_cap:
            continue
        for e in _db.incoming_edges(conn, nid, limit=500):
            if e.get("kind") == "contains":
                continue
            src = _db.get_node(conn, e.get("source"))
            if src is None or src["id"] in seen:
                continue
            seen.add(src["id"])
            results.append({"node": src, "hop": hop + 1, "kind": e.get("kind"),
                            "confidence": _edge_confidence(e),
                            "via_line": e.get("line")})
            queue.append((src["id"], hop + 1))
            # getImpactRadius: a container reached by an incoming edge also
            # contributes its children (class -> its methods count).
            if str(src.get("kind")) in _CONTAINER_KINDS:
                for child in _db.node_children(conn, src["id"], limit=200):
                    if child["id"] in seen:
                        continue
                    seen.add(child["id"])
                    results.append({"node": child, "hop": hop + 1, "kind": "contains",
                                    "confidence": 1.0,
                                    "via_line": child.get("start_line")})
                    queue.append((child["id"], hop + 1))
    header = (f"Affected nodes for {name} (depth<={depth_cap}, total {len(results)}; "
              f"seeds: {seed_label})")
    lines = [header]
    _lim = _resolve_limit(limit, "AFFECTED_LIMIT", 100)
    page = results if _lim <= 0 else results[:_lim]
    for r in page:
        node = r["node"]
        loc = f"{node.get('file_path')}:{r.get('via_line') or node.get('start_line')}"
        flag = ""
        if r["kind"] != "contains" and float(r["confidence"]) < UNCERTAIN_BELOW:
            flag = " UNCERTAIN (name-only guess; do not follow)"
        lines.append(f"- {node.get('name')} [{node.get('kind')}] {loc} "
                     f"(hop {r['hop']}, {r['kind']}, confidence {float(r['confidence']):.2f}){flag}")
    if not results:
        lines.append("- (nothing reaches this symbol within the depth cap)")
    elif len(results) > len(page):
        lines.append(f"… +{len(results) - len(page)} more")
    return "\n".join(lines)[:20000]


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
        # No grep equivalent for reachability: this is the success-shaped
        # guidance the un-indexed contract uses everywhere else.
        return _db.guidance_no_db(root)
    db_out = _affected_db(conn, root, name, file, depth, limit)
    if db_out is None:
        return "(no matches)"
    return db_out


__all__ = [
    "manifest_parse",
    "framework_routes",
    "callers",
    "callees",
    "affected",
    "codegraph_tools",
    "CODEGRAPH_TOOL_NAMES",
    "ROUTE_LINE_RE",
    "UNCERTAIN_BELOW",
    *CODEGRAPH_TOOL_NAMES,
]
