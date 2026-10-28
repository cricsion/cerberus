"""GraphQL surface mapping for CodeGraph.

``graphql_surface`` maps the GraphQL face of a repo, the parts
``framework_routes`` cannot see: SDL schema files, code-first schema
definitions, resolver wiring, and the ``/graphql``-shaped endpoints the
server mounts. The offensive-graphql and offensive-idor skills use it to
plan field-level abuse (BOLA through field resolvers, mutations without
auth).

LAWS
- A surface map is scope for hunting, not a vulnerability list: it carries no
  findings, only recognized wiring.
- Scans stay bounded (files walked, grounded per-file text cap) and pure
  text/pattern-driven; every failure is a success-shaped string.

FORMAT LAW: section titles and truncation tails follow the package's pinned
shapes. No network, subprocess, or writes occur.
"""
from __future__ import annotations

import os
import re

from harness.codegraph import _common, _db
from harness.tools._compat import tool

# ---------------------------------------------------------------------------
# caps — the package-wide env idiom; values frozen
# ---------------------------------------------------------------------------

ENV_FILES = "CODEGRAPH_GRAPHQL_FILES_LIMIT"

DEFAULT_FILES = 300         # files inspected per scan
MAX_ROW = 120

_SKIP_DIRS = frozenset({
    ".git", ".codegraph", ".venv", "venv", "env", "node_modules", "vendor",
    "__pycache__", "dist", "build", "target", "out", ".idea",
    "testdata", "fixtures",
})

_SDL_EXTS = frozenset({".graphql", ".graphqls", ".gql"})
_CODE_EXTS: dict = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
}

SDL_ROOT_FIELDS_RE = re.compile(
    r"^\s*type\s+(Query|Mutation|Subscription)\s+(?:implements\s+[\w,&\s]+)?\{([^}]*)\}",
    re.MULTILINE | re.DOTALL)
SDL_FIELD_LINE_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*[(:]", re.MULTILINE)

CODE_ROOT_BLOCK_RE = re.compile(
    r"(?:typeDefs|@|gql|SDL|schema)\b[^\n]*[\"']{1,3}[^\"']{0,400}(?:type\s+"
    r"(?:Query|Mutation|Subscription)\b)", re.IGNORECASE | re.DOTALL)
CODE_RESOLVER_RE = re.compile(
    r"\b(?:Query|Mutation|Subscription)\s*:\s*\{"
    r"|@(?:strawberry\.)?(?:query|mutation|subscription)\b"
    r"|\bclass\s+(?:Query|Mutation|Subscription)\b"
    r"|\bfields\s*:\s*\{[^{}]*\bresolve\b"
    r"|\bvariable\s+\[(?:Query|Mutation|Subscription)\]"
    r"|\bAdd(?:Query|Mutation|Subscription)Field\b"
    r"|\bObject\b.*\b(?:query|mutation)\b", re.IGNORECASE)
ENDPOINT_RE = re.compile(
    r"[\"'`](/?(?:graphql|graphql/|gql|api/gql)[A-Za-z0-9/_\-]*)[\"'`]"
    r"|\bpath\s*[:=]\s*[\"']/graphql[^\"']*[\"']"
    r"|\bpath\s*[:=]\s*[\"']/gql[^\"']*[\"']", re.IGNORECASE)


@tool(parse_docstring=True)
def graphql_surface(root: str = ".", limit: int | None = None) -> str:
    """
    Map the GraphQL face of a repo: SDL files, root fields, resolver wire-up
    and mounted endpoints.

    A planning view for field-level hunting (``offensive-graphql``, BOLA in
    ``offensive-idor``), not a vulnerability list: it carries no findings,
    only recognized wiring, and degrades honestly (SPA-only or none).

    Args:
        root: Repo root to inspect (no index required).
        limit: Files inspected; 0 means unlimited up to the hard cap.

    Returns:
        Bounded sections: SDL files + root fields, code-first schema spots,
        resolver wiring, and recognized /graphql-shaped endpoints.
    """
    try:
        root = _common._safe_path(root)
    except ValueError as e:
        return f"ERROR: {e}"
    file_cap = _common._cap_rows(limit, ENV_FILES, DEFAULT_FILES)
    files = _walk(root, file_cap)

    out: list[str] = ["# graphql surface",
                      f"root: {root}",
                      f"files inspected: {len(files)} (cap {file_cap})"]
    if not files:
        out += ["", "no production files walked: nothing outside "
                    "test/generated dirs"]
        return _common._cap_chars("\n".join(out))

    sdl_files: list[dict] = []
    code_spots: list[dict] = []
    resolver_spots: list[dict] = []
    endpoints: list[dict] = []
    for rel, path, ext in files:
        text = _read_head(path)
        if not text:
            continue
        if ext in _SDL_EXTS:
            sdl = _sdl_file(rel, path, text)
            if sdl:
                sdl_files.append(sdl)
        if ext in _CODE_EXTS:
            roots_hit = CODE_ROOT_BLOCK_RE.search(text)
            if roots_hit:
                code_spots.append({"rel": rel, "line": 1,
                                   "what": "code-first schema block "
                                           "(typeDefs/gql shape)"})
            for match in CODE_RESOLVER_RE.finditer(text):
                resolver_spots.append({
                    "rel": rel, "line": 1 + text[:match.start()].count("\n"),
                    "what": match.group(0)[:60]})
            for match in ENDPOINT_RE.finditer(text):
                endpoints.append({
                    "rel": rel, "line": 1 + text[:match.start()].count("\n"),
                    "path": match.group(1) or "path assignment"})

    _render_files(out, sdl_files, code_spots, resolver_spots, endpoints)
    return _common._cap_chars("\n".join(out))


def _walk(root: str, cap: int) -> list[tuple[str, str, str]]:
    """``(rel, path, ext)`` of production files, SDL first, capped."""
    out: list[tuple[str, str, str]] = []
    extra: list[tuple[str, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _SKIP_DIRS and not _is_test_dir(d))
        for name in sorted(filenames):
            base_ext = os.path.splitext(name)[1].lower()
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if _db.is_test_file(path):
                continue
            if base_ext in _SDL_EXTS:
                out.append((rel, path, base_ext))
                if len(out) >= cap:
                    return out
            elif base_ext in _CODE_EXTS:
                extra.append((rel, path, base_ext))
    return (out + extra)[:cap]


def _is_test_dir(name: str) -> bool:
    low = name.lower()
    return low == "tests" or low.startswith("test_") or low.endswith("_tests")


def _read_head(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(200_000)
    except OSError:
        return ""


def _sdl_file(rel: str, path: str, text: str) -> dict | None:
    """Root-type fields of one SDL; None when no Query/Mutation/Subscription."""
    roots: list[dict] = []
    for match in SDL_ROOT_FIELDS_RE.finditer(text):
        fields = [f for f in SDL_FIELD_LINE_RE.findall(match.group(2))][:20]
        roots.append({"type": match.group(1), "fields": fields,
                      "line": 1 + text[:match.start()].count("\n")})
    if not roots:
        return None
    return {"rel": rel, "roots": roots}


def _render_files(out: list, sdl_files: list, code_spots: list,
                  resolver_spots: list, endpoints: list) -> None:
    """Bounded section rendering, pinned shapes."""
    out += ["", f"--- SDL schema files ({len(sdl_files)})"]
    if not sdl_files:
        out.append("none: no Query/Mutation/Subscription found in "
                   ".graphql(-shaped) files; check code-first sections")
    for sdl in sdl_files[:20]:
        out.append(f"  {sdl['rel']}")
        for root in sdl["roots"]:
            fields = ", ".join(root["fields"])[:160]
            out.append(f"    {root['type']} @ {root['line']}: "
                       f"{fields or '(no fields visible)'}")

    out += ["", f"--- code-first schema spots ({len(code_spots)})"]
    if not code_spots:
        out.append("none: no typeDefs/gql schema-shaped blocks recognized")
    for spot in code_spots[:20]:
        out.append(f"  {spot['rel']}:{spot['line']}  {spot['what']}")

    out += ["", f"--- resolver wiring ({len(resolver_spots)})"]
    if not resolver_spots:
        out.append("none: no resolver-shaped wiring recognized (Apollo "
                   "resolvers, strawberry @query, graphene classes)")
    for spot in resolver_spots[:30]:
        out.append(f"  {spot['rel']}:{spot['line']}  "
                   f"{_common._truncate_line(spot['what'], MAX_ROW)}")

    out += ["", f"--- endpoints ({len(endpoints)})"]
    if not endpoints:
        out.append("none: no /graphql-shaped endpoint in the walked files; "
                   "the mount may live behind a framework decorator the "
                   "regex does not read")
    for endpoint in endpoints[:20]:
        out.append(f"  {endpoint['rel']}:{endpoint['line']}  "
                   f"{_common._truncate_line(endpoint['path'], MAX_ROW)}")
    out += ["",
            "hint: pair the roots with the auth checks around them — "
            "compare_sibling_route_security and the offensive-idor skill's "
            "field-level BOLA workflow"]


__all__ = ["graphql_surface"]
