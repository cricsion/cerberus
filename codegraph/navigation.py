"""Navigation tools for the Taint & Injection micro-agent.

The graph answers WHO is connected to WHOM; these tools answer "what does the
code around a hop actually look like, and what did the argument become once it
crossed the boundary". Three read-only tools, all bounded, all deterministic:

- :func:`get_ast_slice` — a token-bounded source view of one node. A small
  function comes back verbatim with its line numbers, decorators and signature;
  a 400-line handler does NOT come back verbatim, it comes back as its
  signature, its variable declarations, its control-flow guards and — when a
  ``focus_line`` is given — only the statements that reference the identifiers
  on that line. That is the shape a def-use question needs and a raw dump is
  not.
- :func:`trace_interprocedural_hop` — ONE call hop between two node ids, with
  the argument-to-parameter map Python's own tree-sitter def gives us. CodeGraph
  models no argument-level dataflow (no ``arguments`` edges, ``type_of`` and
  ``returns`` are dead kinds), so this tool reconstructs that mapping locally
  from the call site and the callee's own definition.
- :func:`resolve_blind_spot` — CodeGraph's ``unresolved_refs`` table is an
  explicit "an edge may be missing here" warning (``status='failed'`` rows are
  kept on purpose so a later sync can retry them). This turns those rows into a
  ranked candidate list, because a failed reference is exactly where dynamic
  dispatch, reflection and keyed registries hide.

Everything here is read-only against the target repo: the index is opened
``mode=ro`` by :func:`harness.codegraph._db.connect` and the only writes in the
whole package are the summary sidecar's. No LLM, no network, no subprocess.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from harness.codegraph import _db, _ts, summaries
from harness.config import get_default_config
from harness.tools.code import _safe_path

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover - langchain absent
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco


# ---------------------------------------------------------------------------
# caps — the same shape as _db's, so one env idiom covers the whole package
# ---------------------------------------------------------------------------

HARD_MAX_SECTION = 200   # per-section ceiling before HARD_MAX_ROWS is reached


def _env_int(key: str, default: int) -> int:
    try:
        v = os.environ.get(key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _cap_rows(limit, env_key: str, default: int) -> int:
    """Explicit arg wins, then env, ``<=0`` means unlimited, hard-clamped.

    Mirrors ``_db._resolve_rows`` (private to the foundation module on purpose)
    so navigation.py does not reach into it; the clamp is still
    :data:`_db.HARD_MAX_ROWS`, the one ceiling the whole package shares.
    """
    if limit is None:
        n = _env_int(env_key, default)
    else:
        try:
            n = int(limit)
        except (TypeError, ValueError):
            n = default
    if n <= 0:
        return _db.HARD_MAX_ROWS
    return min(n, _db.HARD_MAX_ROWS)


def _cap_chars(text: str) -> str:
    """The overall character budget. ``CODEGRAPH_CHARS``, 0 = unlimited."""
    lim = _env_int("CODEGRAPH_CHARS",
                   int(get_default_config("codegraph.chars")))
    if lim <= 0 or len(text) <= lim:
        return text
    return text[:lim] + f"\n… +{len(text) - lim} more chars (total {len(text)})"


# ---------------------------------------------------------------------------
# source access
# ---------------------------------------------------------------------------

def _contained_file(root: str, file_path: str) -> Path | None:
    """Resolve a repo-relative ``nodes.file_path`` under ``root``.

    Returns ``None`` — never raises — when the path escapes the repo boundary,
    does not exist, is unreadable, or is above the 1 MB per-file cap the
    indexer applies (a file CodeGraph skipped has no symbols here either, so
    parsing one would invent spans the graph disagrees with).

    A path the host cannot even ADDRESS (a NUL byte, a component past NAME_MAX)
    raises ``OSError``/``ValueError`` out of ``resolve()`` rather than out of
    the containment check, so every step below is guarded for both.
    """
    rel = str(file_path or "").strip().replace("\\", "/")
    if not rel:
        return None
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent  # a tool may point at one file, not a tree
        except (OSError, ValueError):
            return None
    except (OSError, ValueError):
        return None
    try:
        candidates = [(base / rel).resolve()]
    except (OSError, ValueError):
        return None
    if rel.startswith("/"):
        # A leading slash may be the repo's own virtual path ("/app.py").
        try:
            candidates.append(_safe_path(rel))
        except (OSError, ValueError):
            pass
    for cand in candidates:
        try:
            cand.relative_to(base)  # re-check after resolving symlinks
        except ValueError:
            continue
        try:
            if not cand.is_file():
                continue
        except (OSError, ValueError):
            continue
        try:
            if cand.stat().st_size > _ts.MAX_FILE_BYTES:
                continue
            cand.read_bytes()  # readability probe: an unreadable file is a miss
        except (OSError, ValueError):
            continue
        return cand
    return None


def _read_source(root: str, file_path: str):
    """``(source_bytes, path)`` for a node's file, or ``(None, None)``."""
    path = _contained_file(root, file_path)
    if path is None:
        return None, None
    try:
        return path.read_bytes(), path
    except OSError:
        return None, None


# ---------------------------------------------------------------------------
# tree-sitter walk helpers (same pre-order contract as _ts._walk)
# ---------------------------------------------------------------------------

def _walk(node):
    """Depth-first, parent before children."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            children = list(current.children)
        except Exception:
            continue
        stack.extend(reversed(children))


def _line_of(node) -> int:
    try:
        return int(node.start_point[0]) + 1
    except Exception:
        return 0


def _end_line_of(node) -> int:
    try:
        return int(node.end_point[0]) + 1
    except Exception:
        return 0


def _as_int(value, default: int = 0) -> int:
    """A DB column coerced to int without raising.

    ``nodes.start_line``/``edges.line`` are declared INTEGER, but SQLite column
    types are advisory and an index written by another producer can hold
    anything; a tool that promises never to raise cannot assume otherwise.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate_line(text: str, cap: int = 160) -> str:
    flat = " ".join(str(text or "").split())
    if len(flat) <= cap:
        return flat
    return flat[:cap] + " …"


# ---------------------------------------------------------------------------
# node-kind groupings used by the slice
# ---------------------------------------------------------------------------

# Languages spell "this binding introduces a name" many ways; the suffix rule
# catches the rest (``something_declaration`` / ``something_declarator``) while
# the function/class exclusion keeps a nested ``def`` out of the list.
_DECLARATION_TYPES = frozenset({
    "assignment", "augmented_assignment", "named_expression", "assignment_expression",
    "augmented_assignment_expression", "assignment_statement", "local_variable_declaration",
    "field_declaration", "init_declarator", "short_var_declaration", "var_declaration",
    "const_declaration", "variable_declaration", "lexical_declaration",
})
_DECLARATION_SUFFIXES = ("_declaration", "_declarator")

# The condition text a taint check cares about: if / switch / try / ternary.
_GUARD_TYPES = frozenset({
    "if_statement", "elif_clause", "else_clause", "if_expression",
    "switch_statement", "switch_expression",
    "try_statement", "catch_clause", "finally_clause",
    "conditional_expression", "ternary_expression", "match_statement",
})

_ID_LEAF_TYPES = frozenset({
    "identifier", "field_identifier", "property_identifier", "type_identifier",
    "shorthand_property_identifier", "shorthand_property_identifier_pattern",
    "simple_identifier",
})

# ``Type name`` spellings: the parameter NAME is the last identifier in the clause.
_NAME_LAST_PARAM_TYPES = frozenset({
    "formal_parameter", "parameter", "parameter_spec", "fixed_parameter",
})

_PY_KEYWORDS = frozenset({
    "False", "None", "True", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
})

_SLICE_MODES = ("full_or_window", "body", "def_use_slice")
_SMALL_SPAN_LINES = 60          # <= this many lines comes back verbatim
# Per-section cap when the span is sliced. 24 rather than a dozen: a controller
# handler that spends 12 rows on its guards no longer spends the rest of the
# budget on the reassignments around them, and the guard that actually answers
# "is this caller authorized" stops falling off the end of the section.
_SECTION_LINES = 24             # per-section cap when the span is sliced
_POLYMORPHIC_AT = 8             # CodeGraph's type-hierarchy threshold
_MAX_DECORATORS = 12            # a node with 40 decorators is not an answer
_MAX_RENDERED_REFS = 20         # blind-spot blocks per call, rest is marked

# What a call_site_basis reads when the edge is a synthesizer's but carries no
# ``metadata.registeredAt`` to fall back on: the line/col below then belongs to
# nobody, and an agent must be told that rather than trusting the coordinate.
SUSPECT_LINE_BASIS = (
    "edge line/col (suspect — synthesized edge with no registeredAt, so the "
    "coordinate is a placeholder, not a resolved call site)"
)

# Condition names that make a control-flow guard SECURITY-relevant rather than
# merely structural. A taint/authorization question is answered by these rows
# and not by the loop bounds around them, so when a capped section has to drop
# rows these are the ones that stay.
_GUARD_NAME_MARKERS = (
    "authorize", "auth", "permission", "ownership", "is_", "has_", "can_",
    "assert", "check", "validate", "allow", "deny", "role", "login", "admin",
    "owner",
)

# A guard clause: the test's FIRST statement leaves the function (``return`` /
# ``raise`` / ``throw``). ``break``/``continue`` are loop control, not the
# guard-clause idiom, and they are deliberately absent — classifying them here
# would make every ``for``-body validation look like an early return.
_EARLY_EXIT_TYPES = frozenset({
    "return_statement", "raise_statement", "throw_statement", "return",
    "throw", "return_expression", "yield_statement",
})
_BLOCK_TYPES = frozenset({
    "block", "statement_block", "suite", "_suite", "statements", "compound_statement",
})


def _is_declaration(node) -> bool:
    if node.type in _ts.FUNCTION_NODE_TYPES or node.type in _ts.CLASS_NODE_TYPES:
        return False
    return node.type in _DECLARATION_TYPES or node.type.endswith(_DECLARATION_SUFFIXES)


def _def_node(tree, start: int, end: int):
    """The innermost function/class whose span covers ``[start, end]``."""
    try:
        root = tree.root_node
    except Exception:
        return None
    best = None
    best_key = None
    for node in _walk(root):
        if node.type not in _ts.FUNCTION_NODE_TYPES and node.type not in _ts.CLASS_NODE_TYPES:
            continue
        s, e = _line_of(node), _end_line_of(node)
        if not s or e < end or s > start:
            continue
        key = (e - s, node.end_byte - node.start_byte)
        if best is None or key < best_key:
            best, best_key = node, key
    return best


def _def_header(node, src: bytes) -> str:
    """``def f(a, b):`` / ``function f(a) {`` — the signature, not the body."""
    if node is None:
        return ""
    body = node.child_by_field_name("body")
    if body is None:
        body = node.child_by_field_name("statement_block")
    if body is None:
        body = node.child_by_field_name("block")
    if body is not None:
        try:
            raw = src[node.start_byte:body.start_byte]
        except Exception:
            raw = b""
        text = raw.decode("utf-8", errors="replace").strip()
        text = text.rstrip("{").strip() if text else ""
        if text:
            return _truncate_line(text, 800)
    return _truncate_line(_ts.node_text(node, src).splitlines()[0]
                          if _ts.node_text(node, src) else "")


def _guard_condition(node, src: bytes) -> str:
    """The guard's test, not its body."""
    for field in ("condition", "value", "subject"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _truncate_line(_ts.node_text(child, src), 200)
    text = _ts.node_text(node, src)
    return _truncate_line(text.splitlines()[0] if text else "")


def _block_leaves_early(block) -> bool:
    """True when ``block``'s first statement returns or raises."""
    if block is None:
        return False
    if block.type in _EARLY_EXIT_TYPES:
        return True
    if block.type not in _BLOCK_TYPES:
        return False
    for child in block.named_children:
        if child.type in ("comment", "line_comment", "block_comment"):
            continue
        return child.type in _EARLY_EXIT_TYPES
    return False


def _guard_is_security_shaped(node, src: bytes) -> bool:
    """Is this guard row one an authorization/validation question needs?

    Two shapes count, and both are about the row's RELEVANCE rather than its
    syntax: a condition that names authorization, permission, ownership, a
    state predicate or validation (``if (!isAuthorized)``,
    ``if not has_scope(...)``), and a guard CLAUSE — a test whose first
    statement leaves the function, which is the idiom every access check and
    input validation is written in.

    Everything else (``if index >= 100``, ``if retries > 3``, a ``for``-body
    dedupe check) is control flow: it stays in the section while the budget
    allows it and is the correct thing to drop when it does not.
    """
    try:
        condition = _guard_condition(node, src).lower()
    except Exception:
        condition = ""
    if any(marker in condition for marker in _GUARD_NAME_MARKERS):
        return True
    for field in ("consequence", "body", "statement_block", "block"):
        if _block_leaves_early(node.child_by_field_name(field)):
            return True
    # Grammars that do not name the consequence: the last named child of an
    # if/elif/else/except clause is its body.
    if node.type.endswith(("_clause", "_statement")):
        named = [c for c in node.children
                 if c.is_named and c.type not in ("comment", "line_comment",
                                                  "block_comment")]
        if named and _block_leaves_early(named[-1]):
            return True
    return False


def _identifiers_on_line(def_node, line: int, src: bytes, line_text: str) -> list[str]:
    """The names written on ``line`` — the def-use keys for the focus section."""
    names: list[str] = []
    seen: set[str] = set()
    if def_node is not None:
        for node in _walk(def_node):
            if _line_of(node) != line or node.type not in _ID_LEAF_TYPES:
                continue
            text = _ts.node_text(node, src).strip()
            if text and text not in seen:
                seen.add(text)
                names.append(text)
    if not names:
        # No parse (or the line is outside the def): a word-boundary fallback.
        for token in re.findall(r"[A-Za-z_$][\w$]*", line_text or ""):
            if token in _PY_KEYWORDS or token in seen:
                continue
            seen.add(token)
            names.append(token)
    return [n for n in names if len(n) >= 2]


# ---------------------------------------------------------------------------
# 1. get_ast_slice
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def get_ast_slice(node_id: str, focus_line: int | None = None,
                  mode: str = "full_or_window", root: str = ".",
                  limit: int | None = None) -> str:
    """What is the source of this CodeGraph node, without flooding the context?

    Shows the exact numbered span (with decorators and signature, prefixed by
    any cached security summary) when the node is small, and a def-use slice —
    signature, variable declarations, control-flow guards and only the
    statements referencing the identifiers on ``focus_line`` — when it is not.

    Use this when a finding cites a node id and you need the code, when you are
    deciding whether an argument is attacker-controlled, or before claiming a
    guard is missing. Do NOT use it on a whole file (pass the file node only if
    you really want its symbols) and do NOT use ``mode='body'`` on a
    thousand-line handler: that returns the raw source and pays for it.

    Args:
        node_id: CodeGraph node id (a content hash) to read.
        focus_line: Line the identifiers of interest sit on. In a sliced view
            only statements referencing those identifiers are returned; the
            focus line itself is left out, since the caller already has it.
        mode: ``full_or_window`` (verbatim when <= 60 lines, else sliced),
            ``body`` (always verbatim, span text only), or ``def_use_slice``
            (name the def-use question; it slices a long span exactly like
            ``full_or_window`` and is a no-op on a small one, where the exact
            body already answers it).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Per-section cap for declarations/guards/focus rows. 0 = unlimited.

    Returns:
        A bounded, numbered source view, or an ``ERROR:``/guidance string when
        the repo is not indexed, the node is missing, or the file is unreadable.

    Note:
        When a capped guard section has to drop rows it drops the least
        security-relevant ones: guard-shaped conditions — authorization,
        permission, ownership, validation, and the guard clauses that leave the
        function early — are kept first, and the note under the section names
        exactly which line numbers were withheld.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    node = _db.get_node(conn, node_id)
    if node is None:
        return _cap_chars(f"ERROR: node not found: {node_id}")

    chosen = str(mode or "").strip().lower() or "full_or_window"
    if chosen not in _SLICE_MODES:
        return _cap_chars(f"ERROR: unknown mode {mode!r} "
                          f"(use one of {', '.join(_SLICE_MODES)})")

    # focus_line arrives as an int through the tool schema, but a direct call
    # can hand over anything; a malformed one degrades to "no focus" instead of
    # raising out of a tool that promises never to.
    focus: int | None = None
    if focus_line is not None:
        try:
            focus = int(focus_line)
        except (TypeError, ValueError):
            focus = None

    file_path = str(node.get("file_path") or "")
    kind = str(node.get("kind") or "node")
    name = str(node.get("name") or node_id)
    try:
        start, end = int(node.get("start_line")), int(node.get("end_line"))
    except (TypeError, ValueError):
        return _cap_chars(f"ERROR: node has no usable line span: {node_id}")
    if end < start:
        start, end = end, start
    span_lines = (end - start + 1) if end >= start else 0

    header = f"# {file_path}:{start}-{end} ({kind} {name})"
    hint = summaries.cache_hint(conn, node_id)
    src, _path = _read_source(root, file_path)
    decorators = node.get("decorators") or []
    signature = str(node.get("signature") or "")

    meta: list[str] = [header]
    if hint:
        meta.append(hint)
    if decorators:
        shown_dec = list(decorators)[:_MAX_DECORATORS]
        meta.append("decorators: " + ", ".join(str(d) for d in shown_dec)
                    + (f", … +{len(decorators) - len(shown_dec)} more"
                       if len(decorators) > len(shown_dec) else ""))
    if signature:
        meta.append("signature: " + _truncate_line(signature, 800))
    if focus_line is not None and focus is None:
        meta.append(f"note: focus_line {focus_line!r} is not a line number — ignored")

    if src is None:
        meta.append("(source file not readable through this root — showing graph "
                    "metadata only; node_modules/vendor are never indexed)")
        return _cap_chars("\n".join(meta))

    text_lines = src.decode("utf-8", errors="replace").splitlines()
    tree = _ts.parse_source(src.decode("utf-8", errors="replace"),
                            str(node.get("language") or ""))

    if span_lines <= _SMALL_SPAN_LINES or chosen == "body":
        body = "\n".join(
            f"{n}: {text_lines[n - 1]}" for n in range(start, min(end, len(text_lines)) + 1))
        if focus is not None and span_lines > _SMALL_SPAN_LINES:
            meta.append(f"note: focus_line {focus} ignored — full span shown")
        elif focus is not None and not (start <= focus <= end):
            meta.append(f"note: focus_line {focus} is outside node span "
                        f"{start}-{end} — full span shown")
        out = "\n".join(meta + ([body] if body else []))
        return _cap_chars(out)

    # --- sliced: signature + declarations + guards + focus -------------
    cap = _cap_rows(limit, "CODEGRAPH_SLICE_LIMIT", _SECTION_LINES)
    cap = min(cap, HARD_MAX_SECTION)
    def_node = _def_node(tree, start, end)
    header_text = _def_header(def_node, src) or signature
    if header_text:
        meta.append("--- def header")
        meta.append(header_text)
    meta.append(f"note: span is {span_lines} lines — sliced (mode={chosen}); "
                f"pass mode='body' for the exact span")

    sections: list[tuple[str, list[str], int, str]] = []

    # variable declarations
    decls: dict[int, str] = {}
    if def_node is not None:
        for node in _walk(def_node):
            if not _is_declaration(node):
                continue
            line = _line_of(node)
            if line < start or line > end or line in decls:
                continue
            decls[line] = _truncate_line(_ts.node_text(node, src))
    decl_lines = sorted(decls)
    sections.append(("declarations", [
        f"{line}: {decls[line]}" for line in decl_lines[:cap]], len(decl_lines), ""))

    # control-flow guards
    guards: dict[int, str] = {}
    guard_priority: dict[int, int] = {}
    if def_node is not None:
        for node in _walk(def_node):
            if node.type not in _GUARD_TYPES:
                continue
            line = _line_of(node)
            if line < start or line > end or line in guards:
                continue
            guards[line] = _guard_condition(node, src)
            guard_priority[line] = (2 if _guard_is_security_shaped(node, src) else 1)
    guard_lines = sorted(guards)
    # When the section has to be capped, the security-shaped rows survive and
    # the generic control flow is what gets dropped: a truncated guard list must
    # not silently lose the row that answers "is this caller authorized?". The
    # rows themselves stay in source order, so the section still reads top-down
    # and the marker below names exactly which lines were withheld.
    if cap < len(guard_lines):
        ranked = sorted(guard_lines, key=lambda l: (-guard_priority.get(l, 1), l))
        kept = set(ranked[:cap])
    else:
        kept = set(guard_lines)
    shown_guards = [line for line in guard_lines if line in kept]
    dropped_guards = [line for line in guard_lines if line not in kept]
    guard_note = ""
    if dropped_guards:
        guard_note = (
            f"note: the guard section is capped at {cap} row(s) of "
            f"{len(guard_lines)} — guard-shaped conditions (authorization, "
            f"permission, ownership, validation and early-return guards) are "
            f"kept first, so the least security-relevant rows were dropped: "
            f"{', '.join(str(l) for l in dropped_guards)}; pass limit=0 (or "
            f"mode='body') for the rest")
    sections.append(("guards", [
        f"{line}: {guards[line]}" for line in shown_guards], len(guard_lines),
        guard_note))

    # focus: statements referencing the identifiers on focus_line
    focus_rows: list[str] = []
    focus_total = 0
    focus_keys: list[str] = []
    if focus is not None:
        if 1 <= focus <= len(text_lines):
            focus_keys = _identifiers_on_line(def_node, focus, src,
                                              text_lines[focus - 1])
        if not (start <= focus <= end):
            meta.append(f"note: focus_line {focus} is outside node span {start}-{end}")
        if focus_keys:
            for n in range(start, min(end, len(text_lines)) + 1):
                if n == focus:
                    continue
                line_text = text_lines[n - 1]
                if any(re.search(rf"\b{re.escape(k)}\b", line_text) for k in focus_keys):
                    focus_rows.append(f"{n}: {_truncate_line(line_text)}")
                    focus_total += 1
        elif focus:
            meta.append(f"note: no identifiers parsed on focus_line {focus}")
    sections.append((f"focus (line {focus}: {', '.join(focus_keys[:6])})",
                     focus_rows[:cap], focus_total, ""))

    for title, rows, total, section_note in sections:
        if not rows and not total:
            continue
        meta.append(f"--- {title} ({len(rows)} of {total})")
        meta.extend(rows)
        if total > len(rows):
            meta.append(f"… +{total - len(rows)} more {title.split(' (')[0]} "
                        f"(total {total})")
            if section_note:
                meta.append(section_note)

    shown = (2 if header_text else 0) + sum(len(r) for _t, r, _n, _note in sections)
    meta.append(f"sliced: {span_lines} lines -> {shown} shown "
                f"(declarations {min(len(decl_lines), cap)}/{len(decl_lines)}, "
                f"guards {len(shown_guards)}/{len(guard_lines)}, "
                f"focus {min(len(focus_rows), cap)}/{focus_total})")
    return _cap_chars("\n".join(meta))


# ---------------------------------------------------------------------------
# 2. trace_interprocedural_hop
# ---------------------------------------------------------------------------

def _params_from_def(tree, line: int, src: bytes, language: str) -> list[dict]:
    """The callee's parameters from ITS OWN tree-sitter definition.

    Returns ``[{"name", "type", "index", "variadic"}]``. A leading
    ``self``/``cls`` IS kept here: the caller drops it only when the call site
    spells the receiver out (``svc.handle(x)``), because a method's receiver is
    implicit at the call site — the mistake that silently shifts every
    positional argument by one.
    """
    node = _ts.enclosing_function(tree, line)
    if node is None:
        node = _ts.enclosing_node(tree, line)
    if node is None:
        return []
    params = node.child_by_field_name("parameters")
    if params is None:
        params = node.child_by_field_name("formal_parameters")
    if params is None:
        return []
    out: list[dict] = []
    index = 0
    for child in params.named_children:
        if child.type in ("comment", "line_comment", "block_comment"):
            continue
        leaves = [n for n in _walk(child) if n.type in _ID_LEAF_TYPES]
        name = ""
        if child.type in _ID_LEAF_TYPES:
            name = _ts.node_text(child, src).strip()
        elif leaves:
            wanted = leaves[-1] if child.type in _NAME_LAST_PARAM_TYPES else leaves[0]
            name = _ts.node_text(wanted, src).strip()
        type_text = ""
        type_node = child.child_by_field_name("type")
        if type_node is not None:
            type_text = _ts.node_text(type_node, src).strip()
        elif len(leaves) > 1:
            type_text = _ts.node_text(leaves[-1], src).strip()
            if type_text == name:
                type_text = ""
        variadic = child.type in ("list_splat_pattern", "dictionary_splat_pattern",
                                 "rest_parameter", "spread_parameter",
                                 "variadic_parameter")
        name = re.sub(r"^[*.$\s]+", "", name).strip()
        if not name:
            continue
        out.append({"name": name, "type": type_text, "index": index,
                    "variadic": variadic})
        index += 1
    return out


def _callee_tail(text: str) -> str:
    """``db.run_query`` -> ``run_query`` — the segment a name match uses."""
    tail = str(text or "").strip().rsplit(".", 1)[-1]
    return tail.lstrip("?!").strip()


def _args_node(call_node):
    """The bracketed argument list of a call, whatever the grammar calls it."""
    for field in ("arguments", "argument_list", "arguments_list", "parameter_list"):
        child = call_node.child_by_field_name(field)
        if child is not None:
            return child
    for child in reversed(list(call_node.children)):
        if child.is_named and "argument" in child.type:
            return child
    return None


def _call_args(call_node, src: bytes) -> list[str]:
    """Top-level argument expressions, exactly as written."""
    args = _args_node(call_node)
    if args is None:
        return []
    out = []
    for child in args.named_children:
        if child.type in ("comment", "line_comment", "block_comment"):
            continue
        text = _ts.node_text(child, src).strip()
        if text:
            out.append(" ".join(text.split()))
    return out


def _find_call(tree, src: bytes, line: int, col: int | None, name: str,
               span=None):
    """``(call_node, basis, callee_text)`` for the call to ``name``.

    CodeGraph records the line/col of the callee text, so a matching col is the
    strongest signal; the caller's whole span is the fallback for a synthesized
    edge whose coordinates are placeholders. The callee text comes back with it
    because a member call (``svc.handle``) is what tells the argument map that
    the receiver is implicit.
    """
    if tree is None:
        return None, "", ""
    candidates = _ts.calls_in_span(tree, line, line, src)
    exact = [c for c in candidates if _callee_tail(c["text"]) == name]
    if exact:
        if col:
            for call in exact:
                if call["col"] == col:
                    return call["node"], "edge line/col", _callee_text(call["node"], src)
        return exact[0]["node"], "edge line/col", _callee_text(exact[0]["node"], src)
    if span:
        lo, hi = span
        wider = [c for c in _ts.calls_in_span(tree, lo, hi, src)
                 if _callee_tail(c["text"]) == name]
        if wider:
            return (wider[0]["node"],
                    f"caller span (line {wider[0]['line']}, not the edge's line)",
                    _callee_text(wider[0]["node"], src))
    return None, "", ""


def _iter_candidate_params(node: dict, root: str, src_cache: dict):
    """Parameters for a callee: its own def, else ``nodes.signature``."""
    language = str(node.get("language") or "")
    file_path = str(node.get("file_path") or "")
    start = _as_int(node.get("start_line"), 0)
    if file_path not in src_cache:
        src_cache[file_path] = _read_source(root, file_path)
    src, _path = src_cache[file_path]
    tree = None
    if src is not None:
        tree = _ts.parse_source(src.decode("utf-8", errors="replace"), language)
    if tree is not None and start:
        params = _params_from_def(tree, start, src, language)
        if params:
            return params, "tree-sitter def"
    return _ts.parse_signature_params(str(node.get("signature") or ""), language), \
        "nodes.signature"


def _callee_text(call_node, src: bytes) -> str:
    """The callee exactly as written: ``svc.handle`` for a member call."""
    if call_node is None:
        return ""
    for field in ("function", "callee", "method", "name"):
        child = call_node.child_by_field_name(field)
        if child is not None:
            text = _ts.node_text(child, src).strip()
            if text:
                return text
    named = [c for c in call_node.children if c.is_named]
    return _ts.node_text(named[0], src).strip() if named else ""


# A written-out receiver: ``svc.handle(x)`` never passes ``self`` as an
# argument, so a leading receiver parameter must not consume index 0.
_RECEIVER_SEPARATORS = (".", "::", "->", "\\")


def _receiver_is_implicit(callee_text: str) -> bool:
    """True when the call site spells the receiver out (a bound/static call)."""
    return any(sep in str(callee_text or "") for sep in _RECEIVER_SEPARATORS)


def _arg_param_map(call_args: list[str], params: list[dict],
                   receiver_implicit: bool = False) -> list[dict]:
    """Positional (and keyword) alignment of the call's arguments to parameters.

    ``receiver_implicit`` drops a leading ``self``/``cls``: the argument list of
    ``svc.handle(x)`` has one entry and the definition has two parameters, and
    without the shift ``x`` would be bound to the receiver — silently wrong
    for every argument after it.
    """
    if receiver_implicit and params and params[0]["name"] in ("self", "cls"):
        params = params[1:]
    by_name = {p["name"]: p for p in params}
    out: list[dict] = []
    for index, raw in enumerate(call_args):
        keyword = None
        target = params[index] if index < len(params) else None
        match = re.match(r"^([A-Za-z_$][\w$]*)\s*=(?!=)", raw)
        if match and match.group(1) in by_name:
            keyword = match.group(1)
            target = by_name[keyword]
        expr = raw if len(raw) <= 80 else raw[:80] + "…"
        out.append({
            "call_arg_index": index,
            "call_expr": expr,
            "callee_param": target["name"] if target else None,
            "param_type": target.get("type") or "" if target else None,
            "keyword": keyword,
        })
    return out


@tool(parse_docstring=True)
def trace_interprocedural_hop(source_node_id: str, target_node_id: str,
                              root: str = ".") -> str:
    """Where exactly does one call hop happen, and what argument crossed it?

    Resolves the ``calls`` edge (falling back to any edge kind) between two
    CodeGraph node ids and reports the call site, the provenance and wiring
    site, the edge confidence, an argument-to-parameter map, and a numbered
    window around the call.

    Use this when a taint path needs the argument-to-parameter binding (the
    graph has no argument-level edges at all), when a hop came from a SYNTHESIZED
    edge and you must know where the synthesizer registered it
    (``metadata.registeredAt`` — the edge's own line/col are usually
    placeholders, because ``idx_edges_identity`` must stay unique), or when the
    hop is missing entirely and you want to know whether it is a resolution
    blind spot. Do NOT use it for multi-hop paths: call it once per hop, or
    use the graph tools for the route.

    Args:
        source_node_id: Caller node id.
        target_node_id: Callee node id.
        root: Repo root holding ``.codegraph/codegraph.db``.

    Returns:
        A JSON block with ``call_site``, ``provenance``, ``wiring_site``,
        ``confidence``, ``arg_to_param_map`` and ``caller_window``, plus a
        guidance string naming ``resolve_blind_spot`` when no edge exists.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    source = _db.get_node(conn, source_node_id)
    target = _db.get_node(conn, target_node_id)
    if source is None:
        return _cap_chars(f"ERROR: node not found: {source_node_id}")
    if target is None:
        return _cap_chars(f"ERROR: node not found: {target_node_id}")

    edges = _db.get_edges(conn, source=source_node_id, target=target_node_id)
    edge = None
    if edges:
        for preferred in ("calls", "instantiates", "references", "navigates"):
            edge = next((e for e in edges if e.get("kind") == preferred), None)
            if edge is not None:
                break
        if edge is None:
            edge = edges[0]

    if edge is None:
        return _no_edge_guidance(conn, source, target)

    meta = edge.get("metadata") or {}
    kind = str(edge.get("kind") or "")
    provenance = edge.get("provenance")
    synthesized_by = meta.get("synthesizedBy")
    registered_at = meta.get("registeredAt")
    line, col = edge.get("line"), edge.get("col")
    # SQLite column types are advisory: coerce once here rather than at each use.
    line = _as_int(line, 0) if line is not None else 0
    col = _as_int(col, 0) if col is not None else 0
    source_file = str(source.get("file_path") or "")
    target_name = str(target.get("name") or "")
    notes: list[str] = []

    provenance_text = str(provenance or "").strip().lower()
    # A synthesizer's edge carries coordinates it does not really own: the
    # identity index forces a placeholder when the wiring site is not a line in
    # the caller's file. That extends past ``synthesizedBy`` to the provenance
    # value itself, which is what the extractor records for a heuristic hop.
    suspect = (bool(synthesized_by)
               or provenance_text in ("heuristic", "synthesized", "inferred")
               or not line)
    if suspect and registered_at:
        call_site = str(registered_at)
        basis = ("metadata.registeredAt — the edge is synthesized, so its own "
                 "line/col are suspect (idx_edges_identity uniqueness often "
                 "forces a placeholder); this is the synthesizer's wiring site")
    elif line:
        call_site = f"{source_file}:{line}"
        if suspect:
            basis = SUSPECT_LINE_BASIS
        else:
            basis = "edge line/col"
    else:
        call_site = ""
        basis = "unknown"
        notes.append("the edge carries no line/col at all and no wiring site: "
                      "no call site can be reported")

    confidence = meta.get("confidence")
    if confidence is None:
        confidence = "not recorded"
    else:
        try:
            confidence = float(confidence)
            if confidence < 0.6:
                notes.append("confidence is below CodeGraph's UNCERTAIN_BELOW=0.6: "
                             "a name-only guess, not a call")
        except (TypeError, ValueError):
            confidence = "not recorded"
    if synthesized_by:
        notes.append(f"synthesized edge ({synthesized_by}); provenance is "
                     f"{provenance!r}, not a resolved call")
    if kind != "calls":
        notes.append(f"no calls edge for this pair; falling back to kind={kind!r}")

    # --- the call site, parsed locally ---------------------------------
    src, _path = _read_source(root, source_file)
    tree = None
    if src is not None:
        tree = _ts.parse_source(src.decode("utf-8", errors="replace"),
                                str(source.get("language") or ""))
    call_node, found_by, callee_text = (None, "", "")
    if tree is not None and line:
        call_node, found_by, callee_text = _find_call(
            tree, src, line, col or None, target_name)
        if call_node is None:
            s_span = (_as_int(source.get("start_line"), 1) or 1,
                      _as_int(source.get("end_line"), 1) or 1)
            call_node, found_by, callee_text = _find_call(
                tree, src, 0, None, target_name, span=s_span)

    arg_map: list[dict] = []
    call_exprs: list[str] = []
    if call_node is not None:
        call_exprs = _call_args(call_node, src)
        params, param_basis = _iter_candidate_params(target, root, {})
        bound = _receiver_is_implicit(callee_text)
        effective = params
        if bound and params and params[0]["name"] in ("self", "cls"):
            effective = params[1:]
            notes.append("receiver is implicit at this call site: the callee's "
                         "leading self/cls parameter is not an argument")
        if not effective and call_exprs:
            notes.append(f"callee parameters unavailable ({param_basis}); "
                         "arguments are listed without a parameter binding")
        arg_map = _arg_param_map(call_exprs, params, bound)
        if found_by.startswith("caller span"):
            notes.append(f"call located at {found_by}, not at the edge's line/col")
        if effective and len(call_exprs) != len(effective):
            notes.append(f"arity differs: call passes {len(call_exprs)} argument(s), "
                         f"callee declares {len(effective)} parameter(s) "
                         f"({param_basis})")
    else:
        if suspect:
            notes.append("no textual call to this target in the caller: the "
                         "connection is a synthesizer's, so the argument that "
                         "crosses it is not visible at the call site")
        else:
            notes.append("no matching call parsed at the edge's call site; "
                         "arg_to_param_map is empty")

    caller_window = ""
    call_line = line
    if src is not None and call_line:
        caller_window = _ts.window(src, call_line, 3)
        if suspect and registered_at:
            notes.append(f"caller_window is centred on the edge's own (suspect) "
                         f"line {call_line} in {source_file}, not on the wiring site")
    elif registered_at:
        caller_window = f"(caller window unavailable: {call_site} is a wiring site, not a line in {source_file})"

    payload = {
        "source": source_node_id,
        "target": target_node_id,
        "edge_kind": kind,
        "call_site": call_site,
        "call_site_basis": basis,
        "edge_line_col": {"line": line, "col": col} if line or col else None,
        "provenance": provenance,
        "synthesized_by": synthesized_by,
        "wiring_site": registered_at if synthesized_by else None,
        "confidence": confidence,
        "arg_to_param_map": arg_map,
        "caller_window": caller_window,
        "notes": notes,
    }
    return _cap_chars(json.dumps(payload, indent=2, sort_keys=False))


def _no_edge_guidance(conn, source: dict, target: dict) -> str:
    """No edge between the pair: is it a blind spot, or just unrelated?"""
    source_id = str(source.get("id") or "")
    source_file = str(source.get("file_path") or "")
    target_name = str(target.get("name") or "")
    refs = _db.unresolved_refs(conn, node_id=source_id, limit=0)
    matches = [r for r in refs if str(r.get("name_tail") or "") == target_name
               or str(r.get("reference_name") or "") == target_name]
    lines = [f"# no edge from {source_id} to {target.get('id')} in the index"]
    if matches:
        for ref in matches[:5]:
            lines.append(
                f"unresolved ref: {ref.get('reference_name')} at "
                f"{ref.get('file_path')}:{ref.get('line')} "
                f"(kind {ref.get('reference_kind')}, status {ref.get('status')})")
        lines.append(f"the resolver saw this reference and failed on it "
                     f"({len(refs)} unresolved ref(s) for the caller)")
    else:
        lines.append(f"no unresolved ref matching {target_name!r} either "
                     f"({len(refs)} unresolved ref(s) for the caller) — the two "
                     "nodes are genuinely unconnected in this index")
    lines.append(f"hint: call resolve_blind_spot(node_id={source_id!r}) for "
                 "candidate targets of the caller's failed references")
    return _cap_chars("\n".join(lines))


# ---------------------------------------------------------------------------
# 3. resolve_blind_spot
# ---------------------------------------------------------------------------

_SCORE_EXACT_NAME = 3
_SCORE_TAIL = 2
_SCORE_SAME_FILE = 2
_SCORE_SAME_LANGUAGE = 1
_SCORE_ARITY = 2
_SCORE_ARITY_NEAR = 1
_SCORE_IMPLEMENTERS = 1
_TOP_CANDIDATES = 5

# CodeGraph ``nodes.kind`` values that own implementers. NOT the same vocabulary
# as ``_ts.CLASS_NODE_TYPES`` (tree-sitter node types): ``nodes.kind`` says
# ``class``/``interface``/``struct``, and matching those against tree-sitter's
# type names silently never matches.
_CLASS_KINDS = frozenset({
    "class", "interface", "trait", "protocol", "struct", "record", "enum",
    "object", "contract", "annotation", "mixin", "module", "namespace", "type",
})

# ... and the kinds whose implementers are reached through their ``contains``
# parent, the way ``_db.node_parent`` walks it.
_CALLABLE_KINDS = frozenset({
    "function", "method", "constructor", "component", "property", "field",
})


def _candidate_pool(conn, ref: dict, cap: int) -> list[dict]:
    """Every node that could be the target of one unresolved reference."""
    reference_name = str(ref.get("reference_name") or "").strip()
    name_tail = str(ref.get("name_tail") or "").strip()
    if not name_tail:
        name_tail = reference_name.rsplit(".", 1)[-1]
    pool: dict[str, dict] = {}
    for name in (reference_name, name_tail):
        if not name:
            continue
        for node in _db.find_nodes(conn, name=name, limit=cap):
            pool.setdefault(str(node.get("id")), node)
    if len(pool) < cap and name_tail:
        for node in _db.find_nodes(conn, name_like=f"%{name_tail}%", limit=cap):
            pool.setdefault(str(node.get("id")), node)
    return list(pool.values())


def _score_candidate(candidate: dict, ref: dict, call_arity, conn,
                     root: str, src_cache: dict) -> tuple[int, list[str]]:
    """Weight a candidate against one unresolved reference.

    The weights follow CodeGraph's own resolution ladder (exact name beats a
    tail match, locality beats language) and add the two signals that matter
    for a blind spot: whether the arity fits, and whether the candidate is
    behind an interface with many implementers (the fan-out risk CodeGraph
    flags as ``polymorphic`` at >= 8).
    """
    reference_name = str(ref.get("reference_name") or "").strip()
    name_tail = str(ref.get("name_tail") or "").strip()
    if not name_tail:
        name_tail = reference_name.rsplit(".", 1)[-1]
    cand_name = str(candidate.get("name") or "")
    cand_tail = cand_name.rsplit(".", 1)[-1]
    cand_qualified = str(candidate.get("qualified_name") or "")

    score = 0
    why: list[str] = []
    if reference_name and cand_name == reference_name:
        score += _SCORE_EXACT_NAME
        why.append("exact name")
    elif reference_name and cand_qualified == reference_name:
        score += _SCORE_EXACT_NAME
        why.append("exact qualified name")
    if name_tail and cand_tail == name_tail:
        score += _SCORE_TAIL
        why.append("name_tail")
    if ref.get("file_path") and candidate.get("file_path") == ref.get("file_path"):
        score += _SCORE_SAME_FILE
        why.append("same file")
    if ref.get("language") and candidate.get("language") == ref.get("language"):
        score += _SCORE_SAME_LANGUAGE
        why.append("same language")

    params, _basis = _iter_candidate_params(candidate, root, src_cache)
    if params and params[0]["name"] in ("self", "cls"):
        params = params[1:]  # a method's receiver is implicit at the call site
    variadic = any(p.get("variadic") for p in params)
    if call_arity is not None and params:
        if call_arity == len(params) or variadic:
            score += _SCORE_ARITY
            why.append(f"arity {call_arity}/{len(params)}")
        elif abs(call_arity - len(params)) <= 1:
            score += _SCORE_ARITY_NEAR
            why.append(f"arity {call_arity}~{len(params)}")
        else:
            why.append(f"arity {call_arity}!={len(params)}")
        if variadic:
            why.append("variadic")
    elif call_arity is not None:
        why.append(f"arity {call_arity}/? (callee params unparsed)")

    implementers = _implementer_count(conn, candidate)
    if implementers:
        score += _SCORE_IMPLEMENTERS
        note = f"{implementers} implementer(s)"
        if implementers >= _POLYMORPHIC_AT:
            note += " — polymorphic (dynamic dispatch decides)"
        why.append(note)
    return score, why


def _implementer_count(conn, candidate: dict) -> int:
    """Incoming ``implements`` edges to the candidate's class (0 for none).

    Two vocabularies are in play and they are NOT interchangeable: ``_ts``
    exposes tree-sitter node TYPES (``class_definition``, ``interface_declaration``),
    while ``nodes.kind`` holds CodeGraph's NodeKind strings — a class is simply
    ``"class"`` there. Matching a kind against ``_ts.CLASS_NODE_TYPES`` can
    therefore never hit, which is why this helper keeps its own :data:`_CLASS_KINDS`.
    """
    if conn is None:
        return 0
    kind = str(candidate.get("kind") or "")
    owner_id = None
    if kind in _CLASS_KINDS:
        owner_id = candidate.get("id")
    elif kind in _CALLABLE_KINDS:
        parent = _db.node_parent(conn, str(candidate.get("id")))
        if parent and str(parent.get("kind") or "") in _CLASS_KINDS:
            owner_id = parent.get("id")
    if not owner_id:
        return 0
    return len(_db.incoming_edges(conn, str(owner_id), kinds=["implements"], limit=0))


def _call_arity_at(tree, src: bytes, line: int, names: tuple[str, ...]):
    """Arguments in the call on ``line`` whose callee tail matches ``names``."""
    if tree is None or not line:
        return None
    for call in _ts.calls_in_span(tree, line, line, src):
        if _callee_tail(call["text"]) in names:
            args = _call_args(call["node"], src)
            return len(args)
    return None


@tool(parse_docstring=True)
def resolve_blind_spot(node_id: str, root: str = ".", limit: int | None = None) -> str:
    """Which repo symbol could an unresolved reference actually be pointing at?

    CodeGraph keeps every reference its resolver failed on (``status='failed'``
    rows survive on purpose so a later sync can retry them). Each row is turned
    into a ranked candidate list — exact name, name tail, same file, same
    language, arity fit, and the number of implementers behind the candidate's
    interface, with a ``polymorphic`` note at >= 8 — so a dynamic-dispatch,
    reflection or keyed-registry call can be recovered without guessing.

    Use this when :func:`trace_interprocedural_hop` reports no edge, when a
    sink call cannot be resolved to a definition, or before claiming code is
    unreachable. Do NOT use it to prove a call: candidates are ranked
    hypotheses, and the ``polymorphic`` ones are precisely the ones a static
    receiver type cannot settle.

    Args:
        node_id: Node whose unresolved references to recover.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Unresolved references to read from the index (0 = unlimited).
            At most 20 blocks are rendered per call; the rest is marked, so a
            pathological re-index cannot flood the context.

    Returns:
        A bounded recovery list: one block per reference with up to five
        ranked candidates (node_id, kind, file:line, reason).
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    node = _db.get_node(conn, node_id)
    if node is None:
        return _cap_chars(f"ERROR: node not found: {node_id}")
    node_file = str(node.get("file_path") or "")

    cap = _cap_rows(limit, "CODEGRAPH_REFS_LIMIT", 50)
    refs = _db.unresolved_refs(conn, node_id=node_id, limit=cap)
    seen_keys = {(str(r.get("reference_name")), r.get("line")) for r in refs}
    file_fallback = False
    if not refs and node_file:
        # The node id may be stale after a re-index: the file's rows still count.
        file_fallback = True
        for ref in _db.unresolved_refs(conn, file_path=node_file, limit=cap):
            key = (str(ref.get("reference_name")), ref.get("line"))
            if key not in seen_keys:
                seen_keys.add(key)
                refs.append(ref)

    if not refs:
        return _cap_chars(f"# no unresolved references for {node_id} "
                          f"({node_file or 'no file'}) — nothing to recover")

    src_cache: dict[str, tuple] = {}
    tree_cache: dict[str, tuple] = {}
    out: list[str] = [f"# blind spot recovery: {node_id} ({node_file})"]
    if file_fallback:
        # The node id matched nothing on its own, so every block below came from
        # a FILE-level scan: a sibling function's reference is in this list and
        # must not be attributed to the queried node.
        out.append("file-level fallback — references near this node, not "
                   "necessarily inside it (the node id matched no unresolved "
                   "reference of its own)")
    out.append(f"{len(refs)} unresolved reference(s) for this node")
    # The blocks are rendered in order and STOPPED at _MAX_RENDERED_REFS, so the
    # "+N more" marker below counts what is genuinely not shown.
    for position, ref in enumerate(refs[:_MAX_RENDERED_REFS], start=1):
        out.append("")
        out.extend(_render_ref(conn, position, ref, root, src_cache, tree_cache))

    if len(refs) > _MAX_RENDERED_REFS:
        out.append("")
        out.append(f"… +{len(refs) - _MAX_RENDERED_REFS} more references "
                   f"(total {len(refs)}; pass a larger limit to expand more)")
    out.append("")
    out.append("hint: pick a candidate node_id and call "
               "trace_interprocedural_hop(source_node_id=..., target_node_id=...) "
               "to confirm the hop and its argument binding")
    return _cap_chars("\n".join(out))


def _render_ref(conn, position: int, ref: dict, root: str, src_cache: dict,
                tree_cache: dict) -> list[str]:
    """One reference block: what is unresolved, then its ranked candidates."""
    from_path = str(ref.get("file_path") or "")
    reference_name = str(ref.get("reference_name") or "")
    name_tail = str(ref.get("name_tail") or "") or reference_name.rsplit(".", 1)[-1]
    lines = [
        f"## {position}. {reference_name} @ {from_path}:{ref.get('line')}",
        f"   reference_name: {reference_name}  name_tail: {name_tail}  "
        f"kind: {ref.get('reference_kind')}  status: {ref.get('status')}",
    ]
    stored = ref.get("candidates") or []
    if stored:
        lines.append(f"   index candidates: {', '.join(str(c)[:40] for c in stored[:5])}")

    # call-site arity, when the line parses to a call to this name
    call_arity = None
    key = (from_path, str(ref.get("language") or ""))
    if key not in tree_cache:
        src, _path = _read_source(root, from_path)
        tree_cache[key] = None
        if src is not None:
            text = src.decode("utf-8", errors="replace")
            tree_cache[key] = (_ts.parse_source(text, key[1]), src)
    parsed = tree_cache[key]
    if parsed is not None:
        tree, src = parsed
        call_arity = _call_arity_at(tree, src, _as_int(ref.get("line"), 0),
                                    (reference_name, name_tail))
    if call_arity is not None:
        lines.append(f"   call-site arity: {call_arity} (parsed from "
                     f"{from_path}:{ref.get('line')})")

    cap = min(_env_int("CODEGRAPH_CANDIDATES",
                       int(get_default_config("codegraph.candidates"))),
              _db.HARD_MAX_ROWS)
    pool = [c for c in _candidate_pool(conn, ref, cap)
            if str(c.get("id")) != str(ref.get("from_node_id"))]
    scored: list[tuple[int, int, str, dict, list[str]]] = []
    for index, candidate in enumerate(pool):
        score, why = _score_candidate(candidate, ref, call_arity, conn,
                                      root, src_cache)
        scored.append((score, index, str(candidate.get("id") or ""), candidate, why))
    scored.sort(key=lambda row: (-row[0], str(row[3].get("file_path") or ""),
                                 _as_int(row[3].get("start_line"), 0), row[2]))

    top = scored[:_TOP_CANDIDATES]
    if not top:
        lines.append(f"   candidates: none found for {name_tail!r} "
                     "(vendor/node_modules are never indexed)")
        return lines
    lines.append(f"   candidates ({len(top)} of {len(scored)}):")
    for rank, (score, _idx, _cid, candidate, why) in enumerate(top, start=1):
        try:
            start_line = int(candidate.get("start_line") or 0)
        except (TypeError, ValueError):
            start_line = 0
        lines.append(f"   {rank}. score {score}  {candidate.get('file_path')}:"
                     f"{start_line}  {candidate.get('kind')} {candidate.get('name')}")
        lines.append(f"      node_id: {candidate.get('id')}")
        lines.append(f"      why: {'; '.join(why) if why else 'name match only'}")
    return lines
